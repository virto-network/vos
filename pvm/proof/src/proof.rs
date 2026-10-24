//! Proof and segment-state data types — shared between prover and verifier.
//!
//! Pure data: no execution semantics live here, so the no_std verifier build
//! can reach them without pulling in the prover stack.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use stwo::core::{fields::qm31::SecureField, pcs::PcsConfig};

use crate::format::Format;
use crate::pcs::StarkProofAny;

mod transcript;
#[cfg(feature = "prover")]
pub use transcript::{
    check_format_security, check_interaction_pow, format_security_bits, mix_boundary_states,
    mix_statement_header, replay_prefix, statement_header_words,
};
mod preflight;
pub use preflight::{
    ProofProtocolShape, derive_protocol_degree_shape, expected_fiat_shamir_query_count,
    preflight_proof_dimensions, preflight_proof_structure, preflight_proof_structure_readonly,
    proof_owned_bytes, stark_fields_are_canonical,
};

/// The format the default prover produces: the segment format of
/// [`crate::format`]. A proof's `format_version` names its entry there, and
/// verifiers refuse a number the registry does not admit.
///
/// What each format number changed: `docs/status.md`, "Proof format
/// history".
pub const PROOF_FORMAT_VERSION: u32 = crate::format::SEGMENT.number;

/// Whether consecutive segments chain: each one's final state is the next
/// one's initial state.
pub fn check_continuity(proofs: &[Proof]) -> Result<(), stwo::core::verifier::VerificationError> {
    match proofs
        .windows(2)
        .find(|pair| pair[0].final_state != pair[1].initial_state)
    {
        Some(pair) => Err(stwo::core::verifier::VerificationError::InvalidStructure(
            alloc::format!(
                "segment chain broken: final state at ts={} does not match next initial at ts={}",
                pair[0].final_state.timestamp,
                pair[1].initial_state.timestamp,
            ),
        )),
        None => Ok(()),
    }
}

/// Exact number of commitment trees in this generation of the Stwo proof:
/// preprocessed, main, interaction, and split composition.
pub const PROOF_COMMITMENT_TREE_COUNT: usize = 4;
/// The component mask is a `u32`; accepting more components would make its
/// shape ambiguous before any cryptographic check.
pub const MAX_PROOF_COMPONENTS: usize = u32::BITS as usize;
/// SIMD trace builders use 16 lanes and index rows with
/// `log_size - LOG_N_LANES`; smaller claimed components are structurally
/// impossible and can otherwise reach an unchecked subtraction.
pub const MIN_PROOF_LOG_SIZE: u32 = 4;
/// Hard transport-independent cap for every proof-owned column vector. The
/// full segment AIR commits 4,882 columns in its widest tree (8,039 in all);
/// the next power of two leaves narrowly audited generation-local headroom.
pub const MAX_PROOF_COLUMNS_PER_TREE: usize = 1 << 13;
/// Hard cap for OODS samples attached to one committed column.
pub const MAX_PROOF_SAMPLES_PER_COLUMN: usize = 64;
/// Stwo's current query protocol has no useful production shape above this.
pub const MAX_FRI_QUERIES: usize = 256;
/// M31's canonical circle coset supports log sizes only through 30.
pub const MAX_EXTENDED_LOG_SIZE: u32 = 30;
/// Proof-side verification regenerates the preprocessed tree from a trusted
/// SideNote. Larger blowups turn a small hostile proof into exponential local
/// recommitment work; the segment format uses 2.
pub const MAX_RECOMMIT_LOG_BLOWUP: u32 = 4;
/// Protocol cap for a component's unextended trace, and every verifier's
/// default cap. At 24 each chip's main trace has 2^24 ≈ 16M rows: well
/// above the largest trace a kernel's run produces and well below the size
/// where verification's CPU and memory become onerous.
pub const MAX_PROOF_LOG_SIZE: u32 = 24;
/// Bound proof-owned Merkle witnesses before hashing or allocation-heavy work.
pub const MAX_MERKLE_WITNESS_HASHES: usize = MAX_FRI_QUERIES * MAX_EXTENDED_LOG_SIZE as usize;
/// Maximum aggregate heap payload cloned from one hostile proof after decode.
/// This covers every nested sampled/query/witness/FRI vector, not only each
/// vector in isolation.
pub const MAX_PROOF_OWNED_BYTES: usize = 16 * 1024 * 1024;

/// Execution state at a segment boundary (initial or final).
/// Maps to VOS's ContinuationHeader for checkpoint integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentState {
    pub pc: u32,
    pub timestamp: u64,
    pub registers: [u64; 13],
    pub memory_commitment: [u8; 32], // blake3(flat_mem); computed outside the circuit, unbound
    /// Page-Merkle root of the RAM image AT THIS boundary:
    /// bound in-circuit by the boundary multiproof + `MemoryRootBoundaryChip`,
    /// so cross-segment continuity (`final_state == next.initial_state`)
    /// genuinely forces memory continuity.  A segment binds `initial_state
    /// .memory_root` (entering image) and `final_state.memory_root` (exit
    /// image); the two are equal across a chain boundary by struct-eq.
    #[serde(default)]
    pub memory_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// The proof's format, an entry of [`crate::format`]'s registry: it
    /// decides the channel `stark_proof` must be in, the parameters and the
    /// encodings. A number the registry does not admit is rejected with
    /// `VerificationError::InvalidStructure` before any cryptographic work.
    #[serde(default = "proof_format_version_default")]
    pub format_version: u32,
    pub stark_proof: StarkProofAny,
    /// The interaction PoW nonce (A.1's fourth item).
    #[serde(default)]
    pub interaction_pow: u64,
    pub claimed_sums: Vec<SecureField>,
    pub log_sizes: Vec<u32>,
    pub num_components: usize,
    /// Bit i set ⇔ chip i in BASE_COMPONENTS was active for
    /// this proof.  Allows the standalone verifier (no SideNote) to
    /// reconstruct the exact active-chip selection the prover used.
    /// `0` reads as every chip: a chip-isolated proof's, which only
    /// `verify_with_explicit_components` takes.
    #[serde(default)]
    pub component_mask: u32,
    pub pcs_config: PcsConfig,
    /// State at segment start. pc/timestamp, registers, and `memory_root`
    /// are bound to the committed boundary columns (boundary-binding check):
    /// pc/ts pinned to the trace via CpuChip chaining, registers via
    /// register-ledger read-consistency, `memory_root` via the in-AIR
    /// page-Merkle trie. `memory_commitment` is unbound/vestigial metadata
    /// (see `SegmentState`).
    pub initial_state: SegmentState,
    /// State at segment end. Same binding scope as `initial_state`.
    pub final_state: SegmentState,
}

/// Serde default for `format_version` so older serialized proofs (which
/// pre-date the field) deserialize as version 0 → guaranteed reject.
fn proof_format_version_default() -> u32 {
    0
}

impl Proof {
    /// Reconstruct the 32-byte actor-IO binding hash from
    /// the final-state register window φ[9..13].
    ///
    /// A binding actor places `H = compute_io_hash(public, return)` (see
    /// `vos::zk`) into φ[9..12] as part of its Gray Paper halt jump — the four
    /// hash words are passed as inline-asm `in` operands (`a2..a5`), so
    /// the compiler materialises them via real instructions immediately
    /// before halt. No host/tracer cooperation is involved: the binding
    /// is just ordinary register state at halt.  The verifier's
    /// boundary-binding check (`boundary_binding`) equates this field to
    /// the closing chip's committed RegVal column, which is pinned to the
    /// trace's true final registers by `RegisterMemoryChip` read-consistency
    /// (masked `prev_value` + `(reg, ts)` sortedness + the `is_write` limb).
    /// So this hash is bound to the genuine halting register state, sound
    /// against a from-scratch prover. The host verifier (the `prover`
    /// extension's `verify`) additionally checks it against a locally
    /// recomputed `vos::zk::compute_io_hash`, composed with the STARK-validity
    /// check against the trusted program commitment — so the io-binding can't
    /// be checked without validity.
    ///
    /// Decoding is the exact inverse of the guest-side encoding: word
    /// φ\[9\] → bytes 0..8, φ\[10\] → 8..16, φ\[11\] → 16..24, φ\[12\] → 24..32,
    /// each little-endian.  `registers[9..13]` is statically in bounds
    /// (registers is `[u64; 13]`).
    ///
    /// Proofs from non-binding actors leave φ[9..13] at their cold-start
    /// zero, so this returns `[0u8; 32]` — which fails any real
    /// `compute_io_hash` equality check, the intended "unbound proof"
    /// rejection.
    pub fn public_io_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (bytes, word) in out
            .chunks_exact_mut(8)
            .zip(&self.final_state.registers[9..13])
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// The program commitment: the preprocessed tree's root.
    pub fn preprocessed_commitment(&self) -> Option<crate::pcs::Commitment> {
        self.stark_proof.commitment(0)
    }
}

/// The admitted format a proof names, with its Stwo proof in that format's
/// channel.
pub fn proof_format(proof: &Proof) -> Result<&'static Format, alloc::string::String> {
    let format = crate::format::admitted_segment(proof.format_version)?;
    if proof.stark_proof.channel() != format.channel {
        return Err(alloc::format!(
            "proof format {} runs on the {:?} channel, but its Stark proof is on {:?}",
            format.number,
            format.channel,
            proof.stark_proof.channel()
        ));
    }
    Ok(format)
}

#[cfg(all(test, feature = "prover"))]
mod query_replay_tests;
#[cfg(test)]
mod transcript_tests;
