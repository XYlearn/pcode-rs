use std::fmt::Display;

use serde::Serialize;

use crate::sleigh::PcodeOp;

/// Basic block
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct Blk {
    /// Physical address of the block (i.e., offset in the file)
    pub offset: u64,
    /// Virtual address of the block (i.e., address in the program)
    pub address: u64,
    /// Size of the block in bytes
    pub size: usize,
    /// List of Pcode operations in the block
    pub ops: Vec<PcodeOp>,
}

impl Display for Blk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:#x}:", self.address)?;
        for op in &self.ops {
            writeln!(f, "  {}", op)?;
        }
        Ok(())
    }
}

impl Blk {
    pub fn new(offset: u64, address: u64, size: usize, ops: Vec<PcodeOp>) -> Self {
        Blk {
            offset,
            address,
            size,
            ops,
        }
    }
}
