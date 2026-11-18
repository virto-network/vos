//! Poseidon2 over M31, width 16: the permutation, its parameters, and the
//! modes the proofs use it in.
//!
//! **The permutation** is the reference Poseidon2 arrangement (eprint
//! 2023/323) with Plonky3's width-16 M31 parameters, as Plonky3 defines them at
//! revision `f98331687e47106a64ab82a77e2e1d0d66c9161b`
//! (`mersenne-31/src/poseidon2.rs`, `poseidon2/src/`):
//! - the S-box `x^5`, 4 + 4 full rounds and 14 partial rounds;
//! - the Grain round constants ([`EXTERNAL_ROUND_CONSTS`],
//!   [`INTERNAL_ROUND_CONSTS`]);
//! - the external matrix `circ(2·M4, M4, M4, M4)` ([`apply_m4`]), applied once
//!   before the first round;
//! - the internal matrix `1 + diag(V)`, `V` the diagonal of
//!   [`apply_internal_round_matrix`].
//!
//! The tests check it against Plonky3's vectors bit for bit. The linear layers
//! are generic over the word, so a constraint body applies them to its
//! expressions.
//!
//! **The modes:**
//! - a Merkle leaf is a sponge over its row ([`LeafSponge`]), a node the
//!   compression of its children ([`compress`]);
//! - the Fiat-Shamir transcript is a duplex ([`Transcript`]).
//!
//! **Its users** are the prover and every verifier of a proof on the
//! Poseidon2-M31 channel: each adapts these modes to its proof system's traits.
//! The crate is `no_std`, allocates nothing and depends on nothing.
//!
//! **The `packed` feature** adds sixteen permutations at once on the widest
//! SIMD the build targets ([`packed`]), for the prover's hashing; the scalar
//! [`permute`] is the reference, and the packed code equals it lane for lane.
//!
//! **No input panics it:** outside its tests, an index, a slice, an
//! `unwrap`, an `expect`, a `panic!` or an arithmetic that can overflow is a
//! lint error, each one left allowed in place with the reason it cannot
//! fail, as in the final verifier, which links it; the
//! packed code, the prover's alone, is allowed as a whole. `unsafe` code is
//! a compile error outside `packed`.

#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

mod field;
#[cfg(feature = "packed")]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the prover's hashing, on no verify path: its lanes' arithmetic is M31's, and the packed permutation equals the scalar one lane for lane"
)]
#[allow(
    unsafe_code,
    reason = "the prover's SIMD intrinsics, behind `packed`: no verify path links them"
)]
pub mod packed;
mod permutation;
mod sponge;
mod transcript;

pub use field::{M31, P};
pub use permutation::{
    EXTERNAL_ROUND_CONSTS, FULL_ROUNDS, INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS,
    N_PARTIAL_ROUNDS, N_STATE, apply_external_round_matrix, apply_internal_round_matrix, apply_m4,
    permute, permute_with,
};
pub use sponge::{Digest, LeafSponge, RATE, compress, digest_of};
pub use transcript::{
    DRAW_DOMAIN, Observer, PermKind, Transcript, pow_passes, u32_limbs, u64_limbs,
};
