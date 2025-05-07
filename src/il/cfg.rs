use petgraph::graph::DiGraph;

use super::blk::Blk;

/// Control flow graph using petgraph
pub type ControlFlowGraph = DiGraph<Blk, ()>;
