//! The final wrap's verifier (`recursion-air.md` §8, `proving.md` §3.6).
//!
//! It will hold the wrap's constants, Stwo's core verifier, the Blake2b-256
//! Merkle hasher and channel, the public logup sum from the program id and
//! the io-hash, and the statement's decode. Today it holds only the
//! dependency graph it is built on: the recursion AIR's constraint bodies
//! ([`vos_recair_air`]) and Stwo's verifier, without std and without nightly
//! features, so it builds on stable for x86 and wasm32 and on the pinned
//! nightly with build-std for the PVM.

#![no_std]

pub use vos_recair_air;

/// The format the wrap's proofs carry (`vos_pvm_proof::format`'s registry).
pub const WRAP_FORMAT: u32 = 28;

/// The recursion AIR's components over a proof's log sizes and claimed sums,
/// as the verifier will build them: the dependency graph's check that the
/// AIR's bodies reach this crate's targets.
pub fn wrap_components(
    relation: &vos_recair_air::GateRelation,
    log_sizes: &vos_recair_air::LogSizes,
    claimed_sums: &[stwo::core::fields::qm31::SecureField; 3],
) -> vos_recair_air::Components {
    vos_recair_air::Components::new(relation, log_sizes, claimed_sums)
}
