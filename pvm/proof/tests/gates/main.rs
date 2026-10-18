#![cfg(feature = "prover")]

//! The soundness gates: a forged trace, a chip or a lookup's refusal of it.
//! Each module forges what one part of the AIR binds; the forgeries a chip's
//! constraints refuse run in a child process ([`in_child!`]).

#[path = "../common/mod.rs"]
mod common;

#[macro_use]
mod forge;

mod alu_negative;
mod arith_gate;
mod blake2b_boundary_gate;
mod blake2b_gate;
mod boundary_binding;
mod control_flow_negative;
mod cpu_halt_gate;
mod cpu_memory_zone_gate;
mod cpu_soundness_gate;
mod cpu_ts_chain_gate;
mod host_call_dispatch_gate;
mod host_verify_boundary_gate;
mod jump_table_gate;
mod ledger_readconsistency_gate;
mod memory_ledger_gate;
mod memory_ledger_padding_gate;
mod memory_merkle_gate;
mod memory_negative;
mod memory_root_boundary_gate;
mod operand_binding_gate;
mod page_permission_gate;
mod register_ledger_gate;
mod register_ledger_negative;
mod witness_input_gate;
