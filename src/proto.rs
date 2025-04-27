#![allow(dead_code)]

use anyhow::{Context, Result};
use std::num::NonZeroU32;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NBD_IHAVEOPT: u64 = 0x49484156454F5054;
pub const NBD_REQUEST_MAGIC: u32 = 0x25609513;
pub const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x67446698;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct HandshakeFlags: u16 {
        const FIXED_NEWSTYLE = 1;
        const NO_ZEROES = 2;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct ClientFlags: u32 {
        const FIXED_NEWSTYLE = 1;
        const NO_ZEROES = 2;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct TransmissionFlags: u16 {
        const HAS_FLAGS = 1;
        const READ_ONLY = 2;
        const SEND_FLUSH = 4;
        const SEND_FUA = 8;
        const ROTATIONAL = 16;
        const SEND_TRIM = 32;
        const SEND_WRITE_ZEROES = 64;
        const SEND_DF = 128;
        const CAN_MULTI_CONN = 256;
        // Experimental RESIZE extension
        // const SEND_RESIZE = 512;
        const SEND_CACHE = 1024;
        const SEND_FAST_ZERO = 2048;
        // Experimental EXTENDED_HEADERS extension
        // const BLOCK_STATUS_PAYLOAD = 4096;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options(pub u32);

#[allow(non_upper_case_globals)]
impl Options {
    pub const ExportName: Self = Self(1);
    pub const Abort: Self = Self(2);
    pub const List: Self = Self(3);
    // Withdrawn experimental PEEK_EXPORT extension
    // pub const PeekExport: Self = Self(4);
    pub const Starttls: Self = Self(5);
    pub const Info: Self = Self(6);
    pub const Go: Self = Self(7);
    pub const StructuredReply: Self = Self(8);
    pub const ListMetaContext: Self = Self(9);
    pub const SetMetaContext: Self = Self(10);
    // Experimental EXTENDED_HEADERS extension
    // pub const ExtendedHeaders: Self = Self(11);
}

#[derive(Debug)]
pub struct OptionError(pub u32);

#[allow(non_upper_case_globals)]
impl OptionError {
    pub const Unsup: Self = Self(1);
    pub const Policy: Self = Self(2);
    pub const Invalid: Self = Self(3);
    pub const Platform: Self = Self(4);
    pub const TlsReqd: Self = Self(5);
    pub const Unknown: Self = Self(6);
    pub const Shutdown: Self = Self(7);
    pub const BlockSizeReqd: Self = Self(8);
    pub const TooBig: Self = Self(9);
    // Experimental EXTENDED_HEADERS extension
    // pub const ExtHeaderReqd: Self = Self(10);
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct CommandFlags: u16 {
        const FUA = 1;
        const NO_HOLE = 2;
        const DF = 4;
        const REQ_ONE = 8;
        const FAST_ZERO = 16;
        // Experimental EXTENDED_HEADERS extension
        // const PAYLOAD_LEN = 32;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Command(pub u16);

#[allow(non_upper_case_globals)]
impl Command {
    pub const Read: Self = Self(0);
    pub const Write: Self = Self(1);
    pub const Disc: Self = Self(2);
    pub const Flush: Self = Self(3);
    pub const Trim: Self = Self(4);
    pub const Cache: Self = Self(5);
    pub const WriteZeroes: Self = Self(6);
    pub const BlockStatus: Self = Self(7);
    // Experimental RESIZE extension
    // pub const Resize: Self = Self(8);
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
            Command::BlockStatus => write!(f, "BlockStatus"),
            _ => write!(f, "Command({:#x})", self.0),
        }
    }
}

#[derive(Debug)]
pub struct CommandError(pub NonZeroU32);

#[allow(non_upper_case_globals)]
impl CommandError {
    pub const Perm: Self = Self(NonZeroU32::new(1).unwrap());
    pub const Io: Self = Self(NonZeroU32::new(5).unwrap());
    pub const Nomem: Self = Self(NonZeroU32::new(12).unwrap());
    pub const Inval: Self = Self(NonZeroU32::new(22).unwrap());
    pub const Nospc: Self = Self(NonZeroU32::new(28).unwrap());
    pub const Overflow: Self = Self(NonZeroU32::new(75).unwrap());
    pub const Notsup: Self = Self(NonZeroU32::new(95).unwrap());
    pub const Shutdown: Self = Self(NonZeroU32::new(108).unwrap());
}

/// Information about an export.
pub struct ExportInfo {
    pub size: u64,
    pub flags: TransmissionFlags,
}

#[non_exhaustive]
pub enum Info<'a> {
    Export(ExportInfo),
    Name(&'a str),
    Description(&'a str),
    BlockSize {
        minimum_block_size: u32,
        preferred_block_size: u32,
        maximum_payload_size: u32,
    },
}

impl Info<'_> {
    fn serialized_len(&self) -> Result<u32> {
        Ok(match self {
            Info::Export(_) => 12,
            Info::Name(name) => u32::try_from(name.len())
                .context("Name is too large")?
                .checked_add(2)
                .context("Name is too large")?,
            Info::Description(desc) => u32::try_from(desc.len())
                .context("Description is too large")?
                .checked_add(2)
                .context("Description is too large")?,
            Info::BlockSize { .. } => 14,
        })
    }

    async fn serialize<W: AsyncWrite>(&self, mut w: Pin<&mut W>) -> Result<()> {
        const NBD_INFO_EXPORT: u16 = 0;
        const NBD_INFO_NAME: u16 = 1;
        const NBD_INFO_DESCRIPTION: u16 = 2;
        const NBD_INFO_BLOCK_SIZE: u16 = 3;

        match self {
            Info::Export(export) => {
                w.write_u16(NBD_INFO_EXPORT).await?;
                w.write_u64(export.size).await?;
                w.write_u16(export.flags.bits()).await?;
            }
            Info::Name(name) => {
                w.write_u16(NBD_INFO_NAME).await?;
                w.write_all(name.as_bytes()).await?;
            }
            Info::Description(desc) => {
                w.write_u16(NBD_INFO_DESCRIPTION).await?;
                w.write_all(desc.as_bytes()).await?;
            }
            &Info::BlockSize {
                minimum_block_size,
                preferred_block_size,
                maximum_payload_size,
            } => {
                w.write_u16(NBD_INFO_BLOCK_SIZE).await?;
                w.write_u32(minimum_block_size).await?;
                w.write_u32(preferred_block_size).await?;
                w.write_u32(maximum_payload_size).await?;
            }
        }
        Ok(())
    }
}

#[non_exhaustive]
pub enum OptionReply<'a> {
    /// Server accepts the option and no further information is available.
    Ack,
    #[non_exhaustive]
    Server {
        name: &'a str,
    },
    Info(Info<'a>),
    MetaContext {
        id: u32,
        name: &'a str,
    },
    Err {
        code: OptionError,
        message: &'a str,
    },
}

impl OptionReply<'_> {
    async fn serialize<W: AsyncWrite>(&self, mut w: Pin<&mut W>) -> Result<()> {
        pub const NBD_REP_ACK: u32 = 1;
        pub const NBD_REP_SERVER: u32 = 2;
        pub const NBD_REP_INFO: u32 = 3;
        pub const NBD_REP_META_CONTEXT: u32 = 4;

        match self {
            OptionReply::Ack => {
                w.write_u32(NBD_REP_ACK).await?;
                w.write_u32(0).await?;
            }
            OptionReply::Server { name } => {
                w.write_u32(NBD_REP_SERVER).await?;
                let name_len: u32 = name.len().try_into().context("Name is too large")?;
                w.write_u32(name_len.checked_add(4).context("Name is too large")?)
                    .await?;
                w.write_u32(name_len).await?;
                w.write_all(name.as_bytes()).await?;
            }
            OptionReply::Info(info) => {
                w.write_u32(NBD_REP_INFO).await?;
                let len = info.serialized_len()?;
                w.write_u32(len).await?;
                info.serialize(w.as_mut()).await?;
            }
            OptionReply::MetaContext { id, name } => {
                w.write_u32(NBD_REP_META_CONTEXT).await?;
                w.write_u32(
                    u32::try_from(name.len())
                        .context("Name is too large")?
                        .checked_add(4)
                        .context("Name is too large")?,
                )
                .await?;
                w.write_u32(*id).await?;
                w.write_all(name.as_bytes()).await?;
            }
            OptionReply::Err { code, message } => {
                w.write_u32(code.0 | (1 << 31)).await?;
                w.write_u32(message.len().try_into().context("Message is too large")?)
                    .await?;
                w.write_all(message.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

pub async fn option_reply<W: AsyncWrite>(
    mut w: Pin<&mut W>,
    option: Options,
    reply: OptionReply<'_>,
) -> Result<()> {
    const NBD_REPLY_MAGIC: u64 = 0x3E889045565A9;

    w.write_u64(NBD_REPLY_MAGIC).await?;
    w.write_u32(option.0).await?;
    reply.serialize(w.as_mut()).await?;
    w.flush().await?;
    Ok(())
}
