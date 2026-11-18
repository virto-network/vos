#![cfg(feature = "prover")]

//! Kernels on the prover alone: an install's shape refused, the
//! Poseidon2-M31 kernel, the recursion's seams, program identity, the
//! golden fixtures, the circuits' constants and a run's windows at their
//! cuts. The agent's kernels, run on its reference model, are
//! `vos-kernel-tests`'.

#[path = "../common/mod.rs"]
mod common;

#[global_allocator]
static ALLOCATOR: common::Counting = common::Counting;

mod constants;
mod fixtures;
mod install;
mod poseidon2_kernel;
mod program_identity;
mod recursion_seams;
mod windows;
