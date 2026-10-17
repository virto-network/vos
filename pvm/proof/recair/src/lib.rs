//! The recursion AIR's prover (`docs/design/recursion-air.md` §1–2, §10 step
//! 1): the gate VM.
//!
//! - [`Context`] builds a circuit: witness values flow through the wiring,
//!   constants are fixed by gates, outputs are yielded at reserved addresses.
//! - [`Circuit::check_wiring`] is the static check the `Gate` relation's
//!   soundness rests on (`vos_recair_air::gate`): each used address yielded
//!   exactly once, and the multiplicities' absolute sum below `p`.
//! - [`trace`] lays out the three components' preprocessed, main and
//!   interaction columns; a `p2` padding row holds the permutation of zero.
//! - [`prove()`] and [`verify()`] run natively on the Poseidon2-M31 channel
//!   under format 32; a circuit is pinned by its hash.
//! - [`gadgets`] are the Poseidon2 modes as the circuit uses them: the leaf
//!   sponge, the Merkle node and the transcript.
//! - [`compile`] turns a component's constraints into `qm31` rows that
//!   evaluate them at the OODS point, as the native verifier does.

pub mod circuit;
pub mod compile;
pub mod context;
pub mod gadgets;
pub mod prove;
pub mod trace;
pub mod value;

pub use circuit::{Circuit, Entry, Qm31Op, WiringError};
pub use context::{Context, Finalized, Message, P2Handle, P2Row, Var, Witness};
pub use prove::{
    ProveError, RecairProof, VerifyError, circuit_commitment, circuit_hash_of, prove, verify,
};
pub use value::{NoValue, Value};
pub use vos_recair_air::p2::P2Mode;
