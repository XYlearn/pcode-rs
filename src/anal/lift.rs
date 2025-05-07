use std::collections::HashSet;

use anyhow::{Ok, Result};

use crate::{
    il::{blk::Blk, cfg::ControlFlowGraph},
    sleigh::{Context, OpCode, TranslationFlags, VarnodeData},
};

pub trait Reader: std::io::Read + std::io::Seek + std::io::BufRead {}
impl<T: std::io::Read + std::io::Seek + std::io::BufRead> Reader for T {}

#[derive(Debug)]
pub struct Lifter<R: Reader + ?Sized> {
    context: Context,
    reader: Box<R>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LiftTask {
    pub address: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SuccInfo<'a> {
    pub blk: &'a Blk,
    pub concrete: Vec<u64>,
    pub symbolic: Vec<VarnodeData>,
}

impl<R: Reader + ?Sized> Lifter<R> {
    pub fn new(context: Context, reader: R) -> Self
    where
        R: Sized,
    {
        Lifter {
            context,
            reader: Box::new(reader),
            cfg: ControlFlowGraph::new(),
        }
    }

    /// Recursively lift function block
    pub fn lift(&mut self, address: u64, offset: u64) -> Result<()> {
        if offset > address {
            return Err(anyhow::anyhow!("Offset is greater than address"));
        }
        let base_address = address - offset;

        let mut worklist: Vec<LiftTask> = vec![LiftTask { address, offset }];
        let mut visited_address: HashSet<u64> = HashSet::new();

        while let Some(LiftTask { address, offset }) = worklist.pop() {
            if visited_address.contains(&address) {
                continue;
            }
            visited_address.insert(address);

            let blk = self.lift_blk(address, offset)?;
            println!("{}", blk);

            let succ_info = self.calc_succs(&blk)?;
            worklist.extend(
                succ_info
                    .concrete
                    .iter()
                    .map(|addr| LiftTask {
                        address: *addr,
                        offset: addr - base_address,
                    })
                    .collect::<Vec<_>>(),
            );
        }

        Ok(())
    }

    fn lift_blk(&mut self, address: u64, offset: u64) -> Result<Blk> {
        let mut curr_offset = offset;
        let mut blk_size = 0;
        let mut blk_ops = Vec::new();
        loop {
            self.reader.seek(std::io::SeekFrom::Start(curr_offset))?;

            let bytes = {
                let mut buffer = vec![0u8; 512];
                let read_size = self.reader.read(&mut buffer)?;
                buffer.truncate(read_size);
                buffer
            };

            let (num_bytes, ops) = self.context.translate(
                &bytes,
                address,
                0, // No limit on instructions
                TranslationFlags::TerminateBlockEnding,
            )?;

            let terminating = ops.last().unwrap().is_blk_end();

            blk_ops.extend(ops);
            blk_size += num_bytes;
            curr_offset += num_bytes as u64;

            if terminating {
                break;
            }
        }
        let blk = Blk::new(offset, address, blk_size, blk_ops);
        Ok(blk)
    }

    fn calc_succs<'a, 'b>(&self, blk: &'b Blk) -> Result<SuccInfo<'a>>
    where
        'b: 'a,
    {
        let last_op = blk.ops.last().expect("Block has no ops");

        let targets = match last_op.opcode {
            OpCode::Branch
            | OpCode::CBranch
            | OpCode::BranchInd
            | OpCode::Return
            | OpCode::Call
            | OpCode::CallInd => &last_op.inputs,
            _ => {
                return Err(anyhow::anyhow!(
                    "Block does not end with a branch instruction"
                ));
            }
        };

        let mut concrete = Vec::new();
        let mut symbolic = Vec::new();
        targets
            .into_iter()
            .for_each(|target| match target.get_constant() {
                Some(constant) => concrete.push(constant),
                None => {
                    symbolic.push(target.clone());
                }
            });

        Ok(SuccInfo::new(blk, concrete, symbolic))
    }
}

impl LiftTask {
    pub fn new(address: u64, offset: u64) -> Self {
        LiftTask { address, offset }
    }
}

impl<'a> SuccInfo<'a> {
    pub fn new(blk: &'a Blk, concrete: Vec<u64>, symbolic: Vec<VarnodeData>) -> Self {
        SuccInfo {
            blk,
            concrete,
            symbolic,
        }
    }
}
