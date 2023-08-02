#![allow(dead_code)]

use super::Property;
use anyhow::{bail, Result};
use io::block::Block;
use std::io::{Error, ErrorKind};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub const NBD_REP_ACK: u32 = 1;
pub const NBD_REP_SERVER: u32 = 2;
pub const NBD_REP_INFO: u32 = 3;

pub const NBD_INFO_EXPORT: u16 = 0;
pub const NBD_INFO_NAME: u16 = 1;
pub const NBD_INFO_DESCRIPTION: u16 = 2;
pub const NBD_INFO_BLOCK_SIZE: u16 = 3;

const NBD_IHAVEOPT: u64 = 0x49484156454F5054;
const NBG_REPLY_MAGIC: u64 = 0x3E889045565A9;
const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x67446698;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    struct HandshakeFlags: u16 {
        const FIXED_NEWSTYLE = 1;
        const NO_ZEROES = 2;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    struct ClientFlags: u32 {
        const FIXED_NEWSTYLE = 1;
        const NO_ZEROES = 2;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    struct TransmissionFlags: u16 {
        const HAS_FLAGS = 1;
        const READ_ONLY = 2;
        const SEND_FLUSH = 4;
        const SEND_FUA = 8;
        const ROTATIONAL = 16;
        const SEND_TRIM = 32;
        const SEND_WRITE_ZEROES = 64;
        const SEND_DF = 128;
        const CAN_MULTI_CONN = 256;
        const SEND_RESIZE = 512;
        const SEND_CACHE = 1024;
        const SEND_FAST_ZERO = 2048;
        const BLOCK_STATUS_PAYLOAD = 4096;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Options(pub u32);

#[allow(non_upper_case_globals)]
impl Options {
    pub const ExportName: Self = Self(1);
    pub const Abort: Self = Self(2);
    pub const List: Self = Self(3);
    pub const Starttls: Self = Self(5);
    pub const Info: Self = Self(6);
    pub const Go: Self = Self(7);
    pub const StructuredReply: Self = Self(8);
    pub const ListMetaContext: Self = Self(9);
    pub const SetMetaContext: Self = Self(10);
    pub const ExtendedHeaders: Self = Self(11);
}

#[derive(Debug)]
struct OptionError(pub u32);

#[allow(non_upper_case_globals)]
impl OptionError {
    pub const Unsup: Self = Self(1);
    pub const Policy: Self = Self(2);
    pub const Invalid: Self = Self(3);
    pub const Platform: Self = Self(4);
    pub const TlsReqd: Self = Self(5);
    pub const Unknown: Self = Self(6);
    pub const BlockSizeReqd: Self = Self(8);
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    struct CommandFlags: u16 {}
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Command(pub u16);

#[allow(non_upper_case_globals)]
impl Command {
    pub const Read: Self = Self(0);
    pub const Write: Self = Self(1);
    pub const Disc: Self = Self(2);
    pub const Flush: Self = Self(3);
    pub const Trim: Self = Self(4);
    pub const Cache: Self = Self(5);
    pub const WriteZeroes: Self = Self(6);
    pub const Resize: Self = Self(8);
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Command::Read => write!(f, "Read"),
            Command::Write => write!(f, "Write"),
            Command::Disc => write!(f, "Disc"),
            Command::Flush => write!(f, "Flush"),
            Command::Trim => write!(f, "Trim"),
            Command::Cache => write!(f, "Cache"),
            Command::WriteZeroes => write!(f, "WriteZeroes"),
            Command::Resize => write!(f, "Resize"),
            _ => write!(f, "Command({:#x})", self.0),
        }
    }
}

#[derive(Debug)]
struct CommandError(pub NonZeroU32);

#[allow(non_upper_case_globals)]
impl CommandError {
    pub const Perm: Self = Self(unsafe { NonZeroU32::new_unchecked(1) });
    pub const Io: Self = Self(unsafe { NonZeroU32::new_unchecked(5) });
    pub const Nomem: Self = Self(unsafe { NonZeroU32::new_unchecked(12) });
    pub const Inval: Self = Self(unsafe { NonZeroU32::new_unchecked(22) });
    pub const Nospc: Self = Self(unsafe { NonZeroU32::new_unchecked(28) });
    pub const Overflow: Self = Self(unsafe { NonZeroU32::new_unchecked(75) });
    pub const Notsup: Self = Self(unsafe { NonZeroU32::new_unchecked(95) });
    pub const Shutdown: Self = Self(unsafe { NonZeroU32::new_unchecked(108) });
}

async fn option_reply<TX: AsyncWrite>(
    mut tx: Pin<&mut TX>,
    option: Options,
    ty: u32,
    data: &[u8],
) -> Result<()> {
    tx.write_u64(NBG_REPLY_MAGIC).await?;
    tx.write_u32(option.0).await?;
    tx.write_u32(ty).await?;
    tx.write_u32(data.len() as u32).await?;
    tx.write_all(data).await?;
    tx.flush().await?;
    Ok(())
}

async fn option_reply_error<TX: AsyncWrite>(
    tx: Pin<&mut TX>,
    option: Options,
    error: OptionError,
    message: std::fmt::Arguments<'_>,
) -> Result<()> {
    log::warn!("{}", message);
    match message.as_str() {
        Some(v) => option_reply(tx, option, error.0 | (1 << 31), v.as_bytes()).await,
        None => {
            option_reply(
                tx,
                option,
                error.0 | (1 << 31),
                message.to_string().as_bytes(),
            )
            .await
        }
    }
}

pub(crate) async fn handshake<RX: AsyncRead, TX: AsyncWrite, B: Block>(
    mut rx: Pin<&mut RX>,
    mut tx: Pin<&mut TX>,
    property: &Property,
    block: &B,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024];

    let handshake_flags = HandshakeFlags::FIXED_NEWSTYLE | HandshakeFlags::NO_ZEROES;
    tx.write_all(b"NBDMAGIC").await?;
    tx.write_u64(NBD_IHAVEOPT).await?;
    tx.write_u16(handshake_flags.bits()).await?;
    tx.flush().await?;

    let client_flags = ClientFlags::from_bits_retain(rx.read_u32().await?);

    if !client_flags.difference(ClientFlags::all()).is_empty() {
        bail!("Unrecognized client flags {:?}", client_flags);
    }

    if !client_flags.contains(ClientFlags::FIXED_NEWSTYLE) {
        bail!("Client does not support fixed newstyle");
    }

    loop {
        let magic = rx.read_u64().await?;
        if magic != NBD_IHAVEOPT {
            bail!("Unexpected magic {:x}, expecting IHAVEOPT", magic);
        }

        let option = Options(rx.read_u32().await?);
        let length = rx.read_u32().await? as usize;

        if length > buffer.len() {
            bail!("Option length {} is too big", length);
        }

        let buffer = &mut buffer[..length];
        rx.read_exact(buffer).await?;

        match option {
            Options::ExportName => {
                let Ok(name) = std::str::from_utf8(buffer) else {
                    option_reply_error(
                        tx.as_mut(),
                        option,
                        OptionError::Invalid,
                        format_args!("export name must be UTF-8"),
                    )
                    .await?;
                    continue;
                };

                if name != "rust" && !name.is_empty() {
                    option_reply_error(
                        tx.as_mut(),
                        option,
                        OptionError::Invalid,
                        format_args!("export name does not exist"),
                    )
                    .await?;
                    continue;
                }

                tx.write_u64(block.len()).await?;
                let mut flags = TransmissionFlags::HAS_FLAGS;
                if property.readonly {
                    flags |= TransmissionFlags::READ_ONLY;
                }
                if !property.readonly {
                    flags |= TransmissionFlags::SEND_FLUSH;
                }
                if property.rotational {
                    flags |= TransmissionFlags::ROTATIONAL;
                }
                if block.capability().discard {
                    flags |= TransmissionFlags::SEND_TRIM;
                };
                tx.write_u16(flags.bits()).await?;
                if !client_flags.contains(ClientFlags::NO_ZEROES) {
                    tx.write_all(&[0; 124]).await?;
                }
                tx.flush().await?;
                return Ok(());
            }
            Options::Abort => {
                option_reply(tx.as_mut(), option, NBD_REP_ACK, &[]).await?;
                bail!("Client aborted connection");
            }
            Options::List => {
                if length != 0 {
                    log::warn!("LIST comes with data");
                    option_reply_error(
                        tx.as_mut(),
                        option,
                        OptionError::Invalid,
                        format_args!("LIST comes with data"),
                    )
                    .await?;
                    continue;
                }

                option_reply(tx.as_mut(), option, NBD_REP_SERVER, b"\x00\x00\x00\x04rust").await?;
                option_reply(tx.as_mut(), option, NBD_REP_ACK, &[]).await?;
            }
            Options::Starttls => {
                option_reply_error(
                    tx.as_mut(),
                    option,
                    OptionError::Unsup,
                    format_args!("STARTTLS not supported"),
                )
                .await?;
            }
            Options::Info => {
                // TODO!
                option_reply_error(
                    tx.as_mut(),
                    option,
                    OptionError::Unsup,
                    format_args!("INFO not supported"),
                )
                .await?;
            }
            Options::Go => {
                // TODO!
                option_reply_error(
                    tx.as_mut(),
                    option,
                    OptionError::Unsup,
                    format_args!("GO not supported"),
                )
                .await?;
            }
            Options::StructuredReply => {
                option_reply_error(
                    tx.as_mut(),
                    option,
                    OptionError::Unsup,
                    format_args!("STRUCTURED_REPLY not supported"),
                )
                .await?;
            }
            _ => {
                option_reply_error(
                    tx.as_mut(),
                    option,
                    OptionError::Unsup,
                    format_args!("unrecognized option type {:x?}", option),
                )
                .await?;
            }
        }
    }
}

async fn command_reply<TX: AsyncWrite>(
    mut tx: Pin<&mut TX>,
    error: Result<(), CommandError>,
    cookie: u64,
) -> Result<()> {
    tx.write_u32(NBD_SIMPLE_REPLY_MAGIC).await?;
    tx.write_u32(match error {
        Ok(()) => 0,
        Err(err) => err.0.get(),
    })
    .await?;
    tx.write_u64(cookie).await?;
    Ok(())
}

async fn command_reply_error<TX: AsyncWrite>(
    mut tx: Pin<&mut TX>,
    error: Error,
    handle: u64,
) -> Result<()> {
    log::error!("error processing command: {error}");

    let mut code = Ok(());

    // Pass the error code through, but only for Linux.
    #[cfg(linux)]
    if let Some(e) = error.raw_os_error() {
        if e != 0 {
            code = Err(e as u32);
        }
    }

    if code.is_ok() {
        code = Err(match error.kind() {
            ErrorKind::PermissionDenied => CommandError::Perm,
            ErrorKind::OutOfMemory => CommandError::Nomem,
            ErrorKind::InvalidInput => CommandError::Inval,
            ErrorKind::Unsupported => CommandError::Notsup,
            _ => CommandError::Io,
        });
    }

    command_reply(tx.as_mut(), code, handle).await?;
    tx.flush().await?;
    Ok(())
}

pub async fn transmission<RX, TX, B>(
    rx: Pin<&mut RX>,
    tx: Pin<&mut TX>,
    block: Arc<B>,
) -> Result<()>
where
    RX: AsyncRead,
    TX: AsyncWrite,
    B: Block + Send + Sync + 'static,
{
    let (sender, recv) = tokio::sync::mpsc::unbounded_channel();
    tokio::try_join! {
        transmission_request(rx, sender, block.clone()),
        transmission_reply(tx, recv),
    }?;
    Ok(())
}

pub async fn transmission_reply<TX>(
    mut tx: Pin<&mut TX>,
    mut replies: UnboundedReceiver<(u64, std::io::Result<Vec<u8>>)>,
) -> Result<()>
where
    TX: AsyncWrite,
{
    while let Some((cookie, reply)) = replies.recv().await {
        match reply {
            Ok(data) => {
                command_reply(tx.as_mut(), Ok(()), cookie).await?;
                tx.write_all(&data).await?;
                tx.flush().await?;
            }
            Err(err) => {
                command_reply_error(tx.as_mut(), err, cookie).await?;
                return Ok(());
            }
        }
    }

    Ok(())
}

pub async fn transmission_request<RX: AsyncRead, B>(
    mut rx: Pin<&mut RX>,
    replies: UnboundedSender<(u64, std::io::Result<Vec<u8>>)>,
    block: Arc<B>,
) -> Result<()>
where
    B: Block + Send + Sync + 'static,
{
    loop {
        // Get a reference to the block device to be passed into sync code.
        let block = block.clone();
        let replies = replies.clone();

        let magic = rx.read_u32().await?;
        if magic != NBD_REQUEST_MAGIC {
            bail!("Unexpected magic {:x}, expecting REQUEST_MAGIC", magic);
        }

        let _flags = CommandFlags::from_bits_retain(rx.read_u16().await?);
        let ty = Command(rx.read_u16().await?);
        let cookie = rx.read_u64().await?;
        let offset = rx.read_u64().await?;
        let length = rx.read_u32().await? as usize;

        log::trace!("ty={ty:?}, cookie={cookie:x}, offset={offset:#x}, length={length:#x}");

        match ty {
            Command::Read => {
                tokio::task::spawn_blocking(move || {
                    let mut buffer = Vec::with_capacity(length);
                    unsafe {
                        buffer.set_len(length);
                    }
                    let res = block.read_exact_at(&mut buffer, offset).map(|_| buffer);
                    let _ = replies.send((cookie, res));
                });
            }
            Command::Write => {
                let mut buffer = Vec::with_capacity(length);
                unsafe {
                    buffer.set_len(length);
                }
                rx.read_exact(&mut buffer).await?;

                tokio::task::spawn_blocking(move || {
                    let res = block.write_all_at(&buffer, offset).map(|_| Vec::new());
                    let _ = replies.send((cookie, res));
                });
            }
            Command::Disc => {
                return Ok(());
            }
            Command::Flush => {
                tokio::task::spawn_blocking(move || {
                    let res = block.flush().map(|_| Vec::new());
                    let _ = replies.send((cookie, res));
                });
            }
            Command::Trim => {
                tokio::task::spawn_blocking(move || {
                    let res = block.discard(offset, length).map(|_| Vec::new());
                    let _ = replies.send((cookie, res));
                });
            }
            Command::Cache => {
                replies.send((cookie, Ok(Vec::new())))?;
            }
            Command::WriteZeroes => {
                tokio::task::spawn_blocking(move || {
                    let res = block.write_zero_at(offset, length).map(|_| Vec::new());
                    let _ = replies.send((cookie, res));
                });
            }
            _ => {
                replies.send((
                    cookie,
                    Err(Error::new(
                        ErrorKind::Unsupported,
                        format!("unrecognized command {ty:?}"),
                    )),
                ))?;
            }
        }
    }
}
