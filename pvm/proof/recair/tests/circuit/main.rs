//! The recursion AIR's circuits: the gate VM, its gates and modes, and the
//! gate compiler on every chip of the segment AIR.

#[path = "../common/mod.rs"]
mod common;
#[path = "../support/masked_verifier.rs"]
mod masked_verifier;

mod compiler;
mod gate_vm;
mod gates;
mod masked;
mod masked_prover;
mod modes;
