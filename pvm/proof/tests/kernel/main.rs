#![cfg(feature = "prover")]

//! Kernels: their shapes, the window kernel's run, its leaves, folds and
//! wrap, the golden fixtures, program identity and chains.

#[path = "../common/mod.rs"]
mod common;

#[global_allocator]
static ALLOCATOR: common::Counting = common::Counting;

mod balance;
mod chain_standalone;
mod cut;
mod fixtures;
mod kernel_shape;
mod program_identity;
mod prove_chain;
mod reads;
mod recursion_seams;
mod window_kernel;
