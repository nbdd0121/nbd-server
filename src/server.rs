#![allow(dead_code)]

use super::Property;
use anyhow::{bail, Result};
use byteorder::{BigEndian as BE, ReadBytesExt, WriteBytesExt};
use io::block::Block;
use std::io::{Error, ErrorKind, Read, Write};
use std::num::NonZeroU32;

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

fn option_reply<TX: Write>(tx: &mut TX, option: Options, ty: u32, data: &[u8]) -> Result<()> {
    tx.write_u64::<BE>(NBG_REPLY_MAGIC)?;
    tx.write_u32::<BE>(option.0)?;
    tx.write_u32::<BE>(ty)?;
    tx.write_u32::<BE>(data.len() as u32)?;
    tx.write_all(data)?;
    tx.flush()?;
    Ok(())
}

fn option_reply_error<TX: Write>(
    tx: &mut TX,
    option: Options,
    error: OptionError,
    message: std::fmt::Arguments<'_>,
) -> Result<()> {
    log::warn!("{}", message);
    match message.as_str() {
        Some(v) => option_reply(tx, option, error.0 | (1 << 31), v.as_bytes()),
        None => option_reply(
            tx,
            option,
            error.0 | (1 << 31),
            message.to_string().as_bytes(),
        ),
    }
}

pub(crate) fn handshake<RX: Read, TX: Write, B: Block>(
    rx: &mut RX,
    tx: &mut TX,
    property: &Property,
    block: &mut B,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024];

    let handshake_flags = HandshakeFlags::FIXED_NEWSTYLE | HandshakeFlags::NO_ZEROES;
    tx.write_all(b"NBDMAGIC")?;
    tx.write_u64::<BE>(NBD_IHAVEOPT)?;
    tx.write_u16::<BE>(handshake_flags.bits())?;
    tx.flush()?;

    let client_flags = ClientFlags::from_bits_retain(rx.read_u32::<BE>()?);

    if !client_flags.difference(ClientFlags::all()).is_empty() {
        bail!("Unrecognized client flags {:?}", client_flags);
    }

    if !client_flags.contains(ClientFlags::FIXED_NEWSTYLE) {
        bail!("Client does not support fixed newstyle");
    }

    loop {
        let magic = rx.read_u64::<BE>()?;
        if magic != NBD_IHAVEOPT {
            bail!("Unexpected magic {:x}, expecting IHAVEOPT", magic);
        }

        let option = Options(rx.read_u32::<BE>()?);
        let length = rx.read_u32::<BE>()? as usize;

        if length > buffer.len() {
            bail!("Option length {} is too big", length);
        }

        let buffer = &mut buffer[..length];
        rx.read_exact(buffer)?;

        match option {
            Options::ExportName => {
                let Ok(name) = std::str::from_utf8(buffer) else {
                    option_reply_error(
                        tx,
                        option,
                        OptionError::Invalid,
                        format_args!("export name must be UTF-8"),
                    )?;
                    continue;
                };

                if name != "rust" && !name.is_empty() {
                    option_reply_error(
                        tx,
                        option,
                        OptionError::Invalid,
                        format_args!("export name does not exist"),
                    )?;
                    continue;
                }

                tx.write_u64::<BE>(block.len())?;
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
                tx.write_u16::<BE>(flags.bits())?;
                if !client_flags.contains(ClientFlags::NO_ZEROES) {
                    tx.write_all(&[0; 124])?;
                }
                tx.flush()?;
                return Ok(());
            }
            Options::Abort => {
                option_reply(tx, option, NBD_REP_ACK, &[])?;
                bail!("Client aborted connection");
            }
            Options::List => {
                if length != 0 {
                    log::warn!("LIST comes with data");
                    option_reply_error(
                        tx,
                        option,
                        OptionError::Invalid,
                        format_args!("LIST comes with data"),
                    )?;
                    continue;
                }

                option_reply(tx, option, NBD_REP_SERVER, b"\x00\x00\x00\x04rust")?;
                option_reply(tx, option, NBD_REP_ACK, &[])?;
            }
            Options::Starttls => {
                option_reply_error(
                    tx,
                    option,
                    OptionError::Unsup,
                    format_args!("STARTTLS not supported"),
                )?;
            }
            Options::Info => {
                // TODO!
                option_reply_error(
                    tx,
                    option,
                    OptionError::Unsup,
                    format_args!("INFO not supported"),
                )?;
            }
            Options::Go => {
                // TODO!
                option_reply_error(
                    tx,
                    option,
                    OptionError::Unsup,
                    format_args!("GO not supported"),
                )?;
            }
            Options::StructuredReply => {
                option_reply_error(
                    tx,
                    option,
                    OptionError::Unsup,
                    format_args!("STRUCTURED_REPLY not supported"),
                )?;
            }
            _ => {
                option_reply_error(
                    tx,
                    option,
                    OptionError::Unsup,
                    format_args!("unrecognized option type {:x?}", option),
                )?;
            }
        }
    }
}

fn command_reply<TX: Write>(
    tx: &mut TX,
    error: Result<(), CommandError>,
    cookie: u64,
) -> Result<()> {
    tx.write_u32::<BE>(NBD_SIMPLE_REPLY_MAGIC)?;
    tx.write_u32::<BE>(match error {
        Ok(()) => 0,
        Err(err) => err.0.get(),
    })?;
    tx.write_u64::<BE>(cookie)?;
    Ok(())
}

fn command_reply_error<TX: Write>(tx: &mut TX, error: Error, handle: u64) -> Result<()> {
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

    command_reply(tx, code, handle)?;
    tx.flush()?;
    Ok(())
}

pub fn transmission<RX: Read, TX: Write, B: Block>(
    rx: &mut RX,
    tx: &mut TX,
    block: &mut B,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024];
    'outer: loop {
        let magic = rx.read_u32::<BE>()?;
        if magic != NBD_REQUEST_MAGIC {
            bail!("Unexpected magic {:x}, expecting REQUEST_MAGIC", magic);
        }

        let _flags = CommandFlags::from_bits_retain(rx.read_u16::<BE>()?);
        let ty = Command(rx.read_u16::<BE>()?);
        let cookie = rx.read_u64::<BE>()?;
        let mut offset = rx.read_u64::<BE>()?;
        let mut length = rx.read_u32::<BE>()? as usize;

        log::trace!("ty={ty:?}, cookie={cookie:x}, offset={offset:#x}, length={length:#x}");

        match ty {
            Command::Read => {
                let mut first = true;
                while length > 0 {
                    let len = std::cmp::min(length, buffer.len());
                    if let Err(err) = block.read_exact_at(&mut buffer[..len], offset) {
                        if first {
                            command_reply_error(tx, err, cookie)?;
                            continue 'outer;
                        }

                        // We have already replied that this is successful,
                        // so the only way is to terminate the connection
                        log::error!("error processing READ, aborting: {err}");
                        Err(err)?;
                    };

                    if first {
                        command_reply(tx, Ok(()), cookie)?;
                        first = false;
                    }
                    tx.write_all(&buffer[..len])?;
                    offset += len as u64;
                    length -= len;
                }
            }
            Command::Write => {
                while length > 0 {
                    let len = length.min(buffer.len());
                    rx.read_exact(&mut buffer[..len])?;

                    if let Err(err) = block.write_all_at(&buffer[..len], offset) {
                        command_reply_error(tx, err, cookie)?;
                        continue 'outer;
                    };
                    offset += len as u64;
                    length -= len;
                }

                command_reply(tx, Ok(()), cookie)?;
            }
            Command::Disc => {
                return Ok(());
            }
            Command::Flush => {
                if let Err(err) = block.flush() {
                    command_reply_error(tx, err, cookie)?;
                    continue;
                }
                command_reply(tx, Ok(()), cookie)?;
            }
            Command::Trim => {
                if let Err(err) = block.discard(offset, length) {
                    command_reply_error(tx, err, cookie)?;
                    continue;
                }
                command_reply(tx, Ok(()), cookie)?;
            }
            Command::Cache => {
                command_reply(tx, Ok(()), cookie)?;
            }
            Command::WriteZeroes => {
                if let Err(err) = block.write_zero_at(offset, length) {
                    command_reply_error(tx, err, cookie)?;
                    continue;
                }
                command_reply(tx, Ok(()), cookie)?;
            }
            _ => {
                command_reply_error(
                    tx,
                    Error::new(
                        ErrorKind::Unsupported,
                        format!("unrecognized command {ty:?}"),
                    ),
                    cookie,
                )?;
                continue;
            }
        }
        tx.flush()?;
    }
}
