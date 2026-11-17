//! The agent's kernels: their shapes, the window kernel's run, its leaves,
//! folds and wrap, the balance's, the device kernels, reads at a cut, the
//! known programs' ids and the prover worker's throughput.

mod common;

#[global_allocator]
static ALLOCATOR: common::Counting = common::Counting;

mod balance;
mod constants;
mod cut;
mod device_kernel;
mod kernel_shape;
mod reads;
mod throughput;
mod window_kernel;
