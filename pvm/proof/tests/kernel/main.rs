#![cfg(feature = "prover")]

//! Kernels: their shapes, the window kernel's run, its leaves, folds and
//! wrap, the golden fixtures and program identity.

#[path = "../common/mod.rs"]
mod common;

#[global_allocator]
static ALLOCATOR: common::Counting = common::Counting;

mod balance;
mod constants;
mod cut;
mod device_kernel;
mod fixtures;
mod kernel_shape;
mod poseidon2_kernel;
mod program_identity;
mod reads;
mod recursion_seams;
mod throughput;
mod window_kernel;
mod wrap_files;
