use anyhow::Result;
use io::block::{Block, Capability};
use rocksdb::{DBCompressionType, Options, DB};
use std::path::Path;

pub struct RocksBlock {
    db: DB,
    size: u64,
}

impl RocksBlock {
    pub fn new(path: &Path, size: u64) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(DBCompressionType::None);
        opts.set_manual_wal_flush(true);

        let db = DB::open(&opts, path)?;
        Ok(RocksBlock { db, size })
    }
}

fn convert_error(error: rocksdb::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error)
}

impl Block for RocksBlock {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        assert!(buf.len() % 4096 == 0 && offset % 4096 == 0);
        let mut blk = (offset / 4096) as usize;
        for chunk in buf.chunks_mut(4096) {
            let data = self
                .db
                .get_pinned(&blk.to_le_bytes())
                .map_err(convert_error)?;
            if let Some(data) = data {
                chunk.copy_from_slice(&data);
            } else {
                chunk.fill(0);
            }
            blk += 1;
        }
        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> std::io::Result<()> {
        assert!(buf.len() % 4096 == 0 && offset % 4096 == 0);
        let mut blk = (offset / 4096) as usize;
        for chunk in buf.chunks(4096) {
            self.db
                .put(blk.to_le_bytes(), chunk)
                .map_err(convert_error)?;
            blk += 1;
        }
        Ok(())
    }

    fn write_zero_at(&self, offset: u64, len: usize) -> std::io::Result<()> {
        assert!(len % 4096 == 0 && offset % 4096 == 0);
        let mut blk = (offset / 4096) as usize;
        for _ in (0..len).step_by(4096) {
            self.db.delete(blk.to_le_bytes()).map_err(convert_error)?;
            blk += 1;
        }
        Ok(())
    }

    fn discard(&self, offset: u64, len: usize) -> std::io::Result<()> {
        self.write_zero_at(offset, len)
    }

    fn flush(&self) -> std::io::Result<()> {
        self.db.flush_wal(true).map_err(convert_error)
    }

    fn len(&self) -> u64 {
        self.size
    }

    fn capability(&self) -> Capability {
        let mut cap = Capability::default();
        cap.blksize = 4096;
        cap.discard = true;
        cap
    }
}
