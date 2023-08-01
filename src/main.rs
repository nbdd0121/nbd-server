mod server;

use anyhow::Result;
use clap::Parser;
use io::block::Block;
use std::fs::OpenOptions;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

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

    /// File or device to serve.
    file: PathBuf,
}

struct Property {
    readonly: bool,
    rotational: bool,
}

fn handle_client<B: Block>(stream: TcpStream, property: &Property, block: &mut B) -> Result<()> {
    let mut rx = std::io::BufReader::new(&stream);
    let mut tx = std::io::BufWriter::new(&stream);
    server::handshake(&mut rx, &mut tx, property, block)?;
    server::transmission(&mut rx, &mut tx, block)?;
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let opt = Opt::parse();

    let mut open_opt = OpenOptions::new();
    open_opt.read(true);

    if !opt.readonly {
        open_opt.write(true);
    }

    let file = open_opt.open(opt.file)?;
    let mut blk = io::block::File::new(file)?;

    let size = blk.len();
    log::info!("Size of disk {size}");

    let listener = TcpListener::bind((&*opt.addr, opt.port))?;

    log::info!("Listening on {}:{}", opt.addr, opt.port);

    loop {
        let (stream, addr) = listener.accept()?;
        log::info!("Connection accepted from {addr}");

        match handle_client(
            stream,
            &Property {
                readonly: opt.readonly,
                rotational: opt.rotational,
            },
            &mut blk,
        ) {
            Ok(_) => {
                log::info!("client {addr} exited");
            }
            Err(e) => {
                log::error!("error handling client {addr}: {e}");
            }
        }
    }
}
