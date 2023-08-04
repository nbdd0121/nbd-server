mod block;
mod server;

use anyhow::Result;
use clap::Parser;
use io::block::Block;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs::OpenOptions, pin::Pin};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Parser)]
struct Opt {
    /// Address to listen on.
    #[arg(short, long, default_value = "127.0.0.1")]
    addr: String,

    /// TCP port to listen on.
    #[arg(short, long, default_value_t = 10809)]
    port: u16,

    /// Readonly.
    #[arg(short, long)]
    readonly: bool,

    /// Expose as a rotational device.
    #[arg(long)]
    rotational: bool,

    #[command(subcommand)]
    backend: Backend,
}

#[derive(Debug, clap::Subcommand)]
enum Backend {
    File {
        /// File or device to serve.
        file: PathBuf,
    },
    Memory {
        /// Size of the block device (in MiB).
        #[arg(long)]
        size: usize,
    },
}

struct Property {
    readonly: bool,
    rotational: bool,
}

async fn handle_client<B>(mut stream: TcpStream, property: &Property, block: Arc<B>) -> Result<()>
where
    B: ?Sized + Block + Send + Sync + 'static,
{
    let (rx, tx) = stream.split();
    let mut rx = tokio::io::BufReader::new(rx);
    let mut tx = tokio::io::BufWriter::new(tx);
    server::handshake(Pin::new(&mut rx), Pin::new(&mut tx), property, &*block).await?;
    server::transmission(Pin::new(&mut rx), Pin::new(&mut tx), block).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let opt = Opt::parse();

    let blk: Arc<dyn Block + Send + Sync> = match opt.backend {
        Backend::File { file } => {
            let mut open_opt = OpenOptions::new();
            open_opt.read(true);

            if !opt.readonly {
                open_opt.write(true);
            }

            let file = open_opt.open(file)?;
            Arc::new(io::block::File::new(file)?)
        }
        Backend::Memory { size } => Arc::new(block::memory::Memory::new(size * 1024 * 1024)),
    };

    let size = blk.len();
    log::info!("Size of disk {size}");

    let listener = TcpListener::bind((&*opt.addr, opt.port)).await?;

    log::info!("Listening on {}:{}", opt.addr, opt.port);

    loop {
        let (stream, addr) = listener.accept().await?;
        log::info!("Connection accepted from {addr}");

        match handle_client(
            stream,
            &Property {
                readonly: opt.readonly,
                rotational: opt.rotational,
            },
            blk.clone(),
        )
        .await
        {
            Ok(_) => {
                log::info!("client {addr} exited");
            }
            Err(e) => {
                log::error!("error handling client {addr}: {e}");
            }
        }
    }
}
