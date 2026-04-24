//! Blake2bCall: a compression invocation to be proven.
//!
//! Populated by the tracer (`TracingPvm::handle_blake2b_ecall`) and consumed by
//! `SideNote.blake2b_calls`.

/// A single blake2b compression call to be proven.
#[derive(Clone, Debug)]
pub struct Blake2bCall {
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: u128,
    pub f: bool,
}
