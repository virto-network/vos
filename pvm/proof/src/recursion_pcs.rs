//! Per-build PCS selection for native-recursion Stage-0.
//!
//! `prove`/`verify`/`proof`/`program_id` and the standalone verifier name the
//! PCS hash/channel/backend through the aliases here, so swapping the whole
//! commit+transcript stack from production Blake2s to the M31-algebraic
//! Poseidon2-M31 stack ([`crate::poseidon2`]) is a single feature toggle
//! (`--features poseidon2-channel`) rather than an edit at every call site.
//!
//! Why aliases and not generics: stwo's `draw_lookup_elements` /
//! `draw_all_lookup_elements` are object-safe trait methods taking a *concrete*
//! `&mut Channel`; making them generic over `C: Channel` breaks dyn-dispatch.
//! One concrete channel per build (the alias) keeps the vtable monomorphic.
//!
//! Backend note: both stacks prove on `SimdBackend`. The Poseidon2-M31 PCS
//! satisfies `BackendForChannel<P2MerkleChannel>` on `SimdBackend` via the
//! orphan-legal impls in [`crate::poseidon2`] (their `MerkleOpsLifted` /
//! `GrindOps` bodies move columns to `CpuBackend` only for the scalar merkle
//! hash), so the whole prove — FRI, quotients, twiddles — stays vectorized
//! under either PCS. Retargeting the entire commit+prove to `CpuBackend`
//! instead forfeits SIMD across the board and proves an order of magnitude
//! slower, so only the leaf hash, which has no SIMD form here, runs on CPU.

// ── Production stack: Blake2s commit + Blake2s Fiat-Shamir on SimdBackend ──
#[cfg(not(feature = "poseidon2-channel"))]
mod selected {
    pub use stwo::core::channel::Blake2sChannel as ProverChannel;
    pub use stwo::core::vcs::blake2_hash::Blake2sHash as ProverMerkleHash;
    pub use stwo::core::vcs_lifted::blake2_merkle::{
        Blake2sMerkleChannel as ProverMerkleChannel, Blake2sMerkleHasher as ProverMerkleHasher,
    };

    #[cfg(feature = "prover")]
    pub use stwo::prover::backend::simd::SimdBackend as ProverBackend;
}

// ── Recursion stack: Poseidon2-M31 commit + transcript on SimdBackend ──────
#[cfg(feature = "poseidon2-channel")]
mod selected {
    pub use crate::poseidon2::{
        P2Hash as ProverMerkleHash, P2MerkleChannel as ProverMerkleChannel,
        P2MerkleHasher as ProverMerkleHasher, Poseidon2M31Channel as ProverChannel,
    };

    #[cfg(feature = "prover")]
    pub use stwo::prover::backend::simd::SimdBackend as ProverBackend;
}

pub use selected::*;

/// The canonical 32-byte serialization of a program commitment, channel-agnostic
/// (`Blake2sHash` → its `[u8; 32]`; `P2Hash` → its 8 little-endian `u32` limbs).
/// The inverse is `ProverMerkleHash::from(&[u8])`. The program-commitment
/// allowlist (bake + drift guard) uses this so the recipe is identical under
/// either PCS — the wire form stays a fixed 32 bytes.
#[cfg(not(feature = "poseidon2-channel"))]
pub fn commitment_bytes(h: &ProverMerkleHash) -> [u8; 32] {
    h.0
}
#[cfg(feature = "poseidon2-channel")]
pub fn commitment_bytes(h: &ProverMerkleHash) -> [u8; 32] {
    h.to_bytes()
}

// ── The trace-column transplant at the commit boundary (prover only) ───────
//
// Trace + interaction generation always ride `SimdBackend` (the framework's
// `ComponentTrace` / `LogupTraceGenerator` are SimdBackend-typed), and both
// stacks now commit on `SimdBackend`, so the committed columns already match
// the commitment scheme's backend: `for_commit` is identity under either PCS.
// (It is retained as the seam where a future SIMD Poseidon2-M31 column packing
// would live, should the merkle hash itself need vectorizing.)
#[cfg(feature = "prover")]
mod transplant {
    use alloc::vec::Vec;
    use stwo::core::fields::m31::BaseField;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::BitReversedOrder;
    use stwo::prover::poly::circle::CircleEvaluation;

    pub fn for_commit(
        evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        evals
    }
}

#[cfg(feature = "prover")]
pub use transplant::for_commit;
