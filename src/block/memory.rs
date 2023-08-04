use std::sync::RwLock;

use io::block::Block;

pub struct Memory {
    blocks: Vec<RwLock<Box<[u8]>>>,
}

impl Memory {
    pub fn new(size: usize) -> Self {
        let num_blk = size / 512;
        let mut blocks = Vec::with_capacity(num_blk);
        for _ in 0..num_blk {
            blocks.push(RwLock::new(vec![0u8; 512].into()));
        }
        Self { blocks }
    }
}

impl Block for Memory {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        let mut blk = (offset / 512) as usize;
        for chunk in buf.chunks_mut(512) {
            chunk.copy_from_slice(&self.blocks[blk].read().unwrap());
            blk += 1;
        }
        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> std::io::Result<()> {
        let mut blk = (offset / 512) as usize;
        for chunk in buf.chunks(512) {
            self.blocks[blk].write().unwrap().copy_from_slice(chunk);
            blk += 1;
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        self.blocks.len() as u64 * 512
    }
}
