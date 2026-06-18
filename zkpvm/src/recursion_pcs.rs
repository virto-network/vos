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
//! Backend note (D1): the production stack proves on `SimdBackend`, but the
//! Poseidon2-M31 hasher only implements `BackendForChannel<P2MerkleChannel>` on
//! `CpuBackend`. So the Poseidon2 build retargets the commit+prove backend to
//! `CpuBackend` (D1-A) and transplants the SimdBackend-generated trace columns
//! into `CpuBackend` columns at the commit boundary via [`for_commit`] (the
//! `to_cpu` pattern de-risked in `tests/cross_chip_logup.rs`). Trace + logup
//! interaction generation still ride `SimdBackend` (the framework as-is);
//! only the committed columns move.

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

// ── Recursion stack: Poseidon2-M31 commit + transcript on CpuBackend ───────
#[cfg(feature = "poseidon2-channel")]
mod selected {
    pub use crate::poseidon2::{
        P2Hash as ProverMerkleHash, P2MerkleChannel as ProverMerkleChannel,
        P2MerkleHasher as ProverMerkleHasher, Poseidon2M31Channel as ProverChannel,
    };

    #[cfg(feature = "prover")]
    pub use stwo::prover::backend::CpuBackend as ProverBackend;
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
// `ComponentTrace` / `LogupTraceGenerator` are SimdBackend-typed). The
// committed columns must match the commitment scheme's backend:
//   - production (`SimdBackend`): identity, zero cost;
//   - recursion (`CpuBackend`): `.to_cpu()` each column (pure value copy,
//     order/domain preserved).
#[cfg(feature = "prover")]
mod transplant {
    use alloc::vec::Vec;
    use stwo::core::fields::m31::BaseField;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::BitReversedOrder;
    use stwo::prover::poly::circle::CircleEvaluation;

    #[cfg(not(feature = "poseidon2-channel"))]
    pub fn for_commit(
        evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        evals
    }

    #[cfg(feature = "poseidon2-channel")]
    pub fn for_commit(
        evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) -> Vec<CircleEvaluation<stwo::prover::backend::CpuBackend, BaseField, BitReversedOrder>> {
        evals.iter().map(|e| e.to_cpu()).collect()
    }
}

#[cfg(feature = "prover")]
pub use transplant::for_commit;
