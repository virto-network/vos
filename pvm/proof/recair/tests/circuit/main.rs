//! The recursion AIR's circuits: the gate VM, its gates and modes, and the
//! gate compiler on every chip of the segment AIR.

#[path = "../common/mod.rs"]
mod common;

mod compiler;
mod gate_vm;
mod gates;
mod leakage;
mod masked;
mod masked_gates;
mod masked_prover;
mod modes;
