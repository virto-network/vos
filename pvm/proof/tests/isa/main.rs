#![cfg(feature = "prover")]

//! The instruction set proved and verified: each family's honest runs, the
//! chips in isolation and the precompiles.

#[path = "../common/mod.rs"]
mod common;

mod add64_e2e;
mod alu;
mod bitmanip;
mod chip_isolated;
mod control_flow;
mod cpu_completeness;
mod host_call_pc;
mod loads_signed;
mod memory;
mod precompiles;
