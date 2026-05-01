//! Proof and segment-state data types — shared between prover and verifier.
//!
//! Pure data: no execution semantics live here, so the no_std verifier build
//! can reach them without pulling in the prover stack.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use stwo::core::{
    fields::qm31::SecureField,
    pcs::PcsConfig,
    proof::StarkProof,
    vcs::blake2_merkle::Blake2sMerkleHasher,
};

/// Current proof format version.  Bumped whenever the AIR shape (number
/// of components, column counts, lookup-tuple shapes, flag layouts) or
/// the proof struct layout changes in a way that would make an older
/// verifier silently accept the wrong thing.
///
/// Verifiers MUST reject proofs whose `format_version` does not match
/// the constant they were compiled against — see the bounds check in
/// `zkpvm::verify` and `zkpvm_verifier::verify_standalone`.
///
/// History:
///   1 — Phases 32-41 wrap (Rotate / BitManip / 32-bit-shift / Sbrk
///       all bound; PROG_MEMORY_N_FLAGS = 48; 14 components).
pub const PROOF_FORMAT_VERSION: u32 = 1;

/// Execution state at a segment boundary (initial or final).
/// Maps to VOS's ContinuationHeader for checkpoint integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentState {
    pub pc: u32,
    pub timestamp: u64,
    pub registers: [u64; 13],
    pub memory_commitment: [u8; 32], // blake2b-256(flat_mem)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Format-shape version — must equal `PROOF_FORMAT_VERSION` of the
    /// verifier crate this proof is presented to.  Mismatches are
    /// rejected with `VerificationError::InvalidStructure` before any
    /// cryptographic work happens.
    #[serde(default = "proof_format_version_default")]
    pub format_version: u32,
    pub stark_proof: StarkProof<Blake2sMerkleHasher>,
    pub claimed_sums: Vec<SecureField>,
    pub log_sizes: Vec<u32>,
    pub num_components: usize,
    pub pcs_config: PcsConfig,
    /// State at segment start (publicly committed)
    pub initial_state: SegmentState,
    /// State at segment end (publicly committed)
    pub final_state: SegmentState,
}

/// Serde default for `format_version` so older serialized proofs (which
/// pre-date the field) deserialize as version 0 → guaranteed reject.
fn proof_format_version_default() -> u32 {
    0
}
