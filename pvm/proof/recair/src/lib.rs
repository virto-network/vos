//! The recursion AIR's prover (`docs/design/recursion-air.md` §1–2): the
//! gate VM.
//!
//! - [`Context`] builds a circuit: witness values flow through the wiring,
//!   constants are fixed by gates, outputs are yielded at reserved addresses.
//! - [`Circuit::check_wiring`] is the static check the `Gate` relation's
//!   soundness rests on (`vos_pvm_recair_air::gate`): each used address yielded
//!   exactly once, and the multiplicities' absolute sum below `p`.
//! - [`trace`] lays out the three components' preprocessed, main and
//!   interaction columns; a `p2` padding row holds the permutation of zero.
//! - [`prove()`] and [`verify()`] run natively on the Poseidon2-M31 channel
//!   under format 32; a circuit is pinned by its hash.
//! - [`gadgets`] are the Poseidon2 modes as the circuit uses them: the leaf
//!   sponge, the Merkle node and the transcript.
//! - [`compile`] turns a component's constraints into `qm31` rows that
//!   evaluate them at the OODS point, as the native verifier does.
//! - [`verifier`] verifies a proof in a circuit, piece by piece: the
//!   channel, Merkle openings, FRI, DEEP, OODS and the logup sums; a segment
//!   proof's prefix, and what every AIR's verifier shares.
//! - [`leaf`] is a kernel leaf: a segment verified, its boundary states
//!   digested and flagged, and the node output it states.
//! - [`fold`] is a fold node: two children of the padded shape, leaves or
//!   folds, verified, their circuits, program and run checked, and the node
//!   output their run states.
//! - [`wrap`] is the final wrap: a tree's root verified, its circuit,
//!   program and run checked, the program id and io-hash its public words,
//!   proved masked under format 39 on the Blake2b-256 channel, or unmasked
//!   under format 28.
//! - [`masked`] is the masked prover (masking variant (c)), over any
//!   component set and Merkle channel: the masks, salts, blinding and FRI
//!   mask in pin B's order, R1 checked on the transcript, the randomness
//!   hedged.
//! - [`tree`] proves a run's tree node by node: leaves, folds, the wrap.

pub mod circuit;
pub mod compile;
pub mod context;
pub mod fold;
pub mod gadgets;
pub mod leaf;
pub mod masked;
pub mod prove;
pub mod trace;
pub mod tree;
pub mod value;
pub mod verifier;
pub mod wrap;

pub use circuit::{Circuit, Entry, Qm31Op, WiringError};
pub use context::{Bit, Context, Finalized, Message, Mismatch, P2Handle, P2Row, Var, Witness};
pub use prove::{
    ProveError, RecairProof, VerifyError, circuit_commitment, circuit_hash_of, prove, verify,
};
pub use value::{NoValue, Value};
pub use vos_pvm_recair_air::p2::P2Mode;
