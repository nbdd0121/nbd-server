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

use crate::proto::*;

pub(crate) async fn handshake<RX: AsyncRead, TX: AsyncWrite, B: ?Sized + Block>(
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
                    option_reply(
                        tx.as_mut(),
                        option,
                        OptionReply::Err {
                            code: OptionError::Invalid,
                            message: "export name must be UTF-8",
                        },
                    )
                    .await?;
                    continue;
                };

                if name != "rust" && !name.is_empty() {
                    option_reply(
                        tx.as_mut(),
                        option,
                        OptionReply::Err {
                            code: OptionError::Invalid,
                            message: "export name does not exist",
                        },
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
                option_reply(tx.as_mut(), option, OptionReply::Ack).await?;
                bail!("Client aborted connection");
            }
            Options::List => {
                if length != 0 {
                    log::warn!("LIST comes with data");
                    option_reply(
                        tx.as_mut(),
                        option,
                        OptionReply::Err {
                            code: OptionError::Invalid,
                            message: "LIST comes with data",
                        },
                    )
                    .await?;
                    continue;
                }

                option_reply(tx.as_mut(), option, OptionReply::Server { name: "rust" }).await?;
                option_reply(tx.as_mut(), option, OptionReply::Ack).await?;
            }
            Options::Starttls => {
                option_reply(
                    tx.as_mut(),
                    option,
                    OptionReply::Err {
                        code: OptionError::Unsup,
                        message: "STARTTLS not supported",
                    },
                )
                .await?;
            }
            Options::Info => {
                // TODO!
                option_reply(
                    tx.as_mut(),
                    option,
                    OptionReply::Err {
                        code: OptionError::Unsup,
                        message: "INFO not supported",
                    },
                )
                .await?;
            }
            Options::Go => {
                // TODO!
                option_reply(
                    tx.as_mut(),
                    option,
                    OptionReply::Err {
                        code: OptionError::Unsup,
                        message: "GO not supported",
                    },
                )
                .await?;
            }
            Options::StructuredReply => {
                option_reply(
                    tx.as_mut(),
                    option,
                    OptionReply::Err {
                        code: OptionError::Unsup,
                        message: "STRUCTURED_REPLY not supported",
                    },
                )
                .await?;
            }
            _ => {
                option_reply(
                    tx.as_mut(),
                    option,
                    OptionReply::Err {
                        code: OptionError::Unsup,
                        message: &format!("unrecognized option type {:x?}", option),
                    },
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
    #[cfg(target_os = "linux")]
    if let Some(e) = error.raw_os_error() {
        if e != 0 {
            code = Err(CommandError(NonZeroU32::new(e as u32).unwrap()));
        }
    }

    if code.is_ok() {
        code = Err(match error.kind() {
            ErrorKind::PermissionDenied => CommandError::Perm,
            ErrorKind::OutOfMemory => CommandError::Nomem,
            ErrorKind::InvalidInput => CommandError::Inval,
            ErrorKind::StorageFull => CommandError::Nospc,
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
    B: ?Sized + Block + Send + Sync + 'static,
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
    B: ?Sized + Block + Send + Sync + 'static,
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
