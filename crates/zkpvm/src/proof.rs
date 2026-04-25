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
