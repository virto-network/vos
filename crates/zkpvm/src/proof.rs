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
    vcs_lifted::blake2_merkle::Blake2sMerkleHasher,
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
    /// Phase 60: bit i set ⇔ chip i in BASE_COMPONENTS was active for
    /// this proof.  Allows the standalone verifier (no SideNote) to
    /// reconstruct the exact active-chip selection the prover used.
    /// Defaults to `0` for back-compat with older proofs (the verifier
    /// then falls back to count-based inference: full set if count =
    /// BASE_COMPONENTS.len(), Blake2b-skipped if count = len-1).
    #[serde(default)]
    pub component_mask: u32,
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

/// Minimum FRI proof-of-work bits the production verifier requires.
///
/// `production_pcs_config()` sets `pow_bits = 20`; this constant is
/// the policy floor used by `verify_*_with_min_pow_bits` and the
/// default `verify_*` (≈96-bit conjectured security).  A deployer
/// who needs more (e.g. to defend against a stronger adversary)
/// can raise the bar; a deployer who needs less for testing can
/// reach for the explicit `*_with_min_pow_bits` variants with a
/// lower floor.  See SECURITY.md "Proof shape" for the rationale.
pub const STANDARD_MIN_POW_BITS: u32 = 20;

/// Minimum FRI query count the production verifier requires.
/// Production config uses 19; lower counts trade soundness for
/// proof size.
pub const STANDARD_MIN_FRI_QUERIES: usize = 19;

/// Minimum FRI log-blowup-factor the production verifier requires.
/// Production config uses 4 (= blowup 16).  Higher means more
/// security per query at the cost of larger committed traces.
pub const STANDARD_MIN_FRI_LOG_BLOWUP: u32 = 4;

// ── Mobile / low-latency policy ────────────────────────────────────
// Track B (Phase 58 followup): trades proof size for prove speed.
// Target: low-power devices where the prove-time-vs-proof-size
// curve favours faster prove.  ~2.5× faster than STANDARD on the
// reference bench at log14, ~1.4× larger proof.

/// PoW bits floor for the mobile policy (same as STANDARD —
/// PoW-grind cost is fixed per prove and doesn't help mobile when
/// raised, so we keep it at the standard 20).
pub const MOBILE_MIN_POW_BITS: u32 = 20;

/// FRI queries floor for the mobile policy.  At log_blowup=2 we
/// need 2× the queries of STANDARD (which uses log_blowup=4) to
/// hit the same security: 20 + 38·2 = 96.
pub const MOBILE_MIN_FRI_QUERIES: usize = 38;

/// FRI log-blowup floor for the mobile policy.  Halves the
/// FRI-prove-domain size vs STANDARD (blowup 4 vs 16) at the cost
/// of 2× more queries.  Net: ~2.5× faster prove on the bench.
pub const MOBILE_MIN_FRI_LOG_BLOWUP: u32 = 2;

/// PCS-config policy: a deployer-friendly bundle of the three
/// security knobs the verifier checks against `proof.pcs_config`.
///
/// `STANDARD` matches what `production_pcs_config()` sets, so the
/// default `verify` and `verify_standalone` paths use it
/// transparently.  Build a custom policy with `PcsPolicy { ... }`
/// and pass to the `*_with_pcs_policy` variants for stricter or
/// looser deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcsPolicy {
    /// Minimum acceptable `proof.pcs_config.pow_bits`.
    pub min_pow_bits: u32,
    /// Minimum acceptable `proof.pcs_config.fri_config.n_queries`.
    pub min_fri_queries: usize,
    /// Minimum acceptable `proof.pcs_config.fri_config.log_blowup_factor`.
    pub min_fri_log_blowup: u32,
}

impl PcsPolicy {
    /// Production policy — the floor `verify` / `verify_standalone`
    /// enforce by default.  Mirrors the values that
    /// `production_pcs_config()` produces.
    pub const STANDARD: Self = Self {
        min_pow_bits: STANDARD_MIN_POW_BITS,
        min_fri_queries: STANDARD_MIN_FRI_QUERIES,
        min_fri_log_blowup: STANDARD_MIN_FRI_LOG_BLOWUP,
    };

    /// Mobile / low-latency policy.  Mirrors
    /// `production_pcs_config_mobile()` — same 96-bit security as
    /// STANDARD, but at a different point on the prove-time vs
    /// proof-size curve (~2.5× faster, ~1.4× larger).  Verifiers
    /// that accept mobile-shape proofs should pass this policy
    /// (or a stricter custom one) to the `*_with_pcs_policy`
    /// variants.
    pub const MOBILE: Self = Self {
        min_pow_bits: MOBILE_MIN_POW_BITS,
        min_fri_queries: MOBILE_MIN_FRI_QUERIES,
        min_fri_log_blowup: MOBILE_MIN_FRI_LOG_BLOWUP,
    };
}

/// Validate `proof.pcs_config` against a policy.  Used by both
/// `zkpvm::verify` and `zkpvm_verifier::verify_standalone` so the
/// prover-side and verifier-only paths reject at the same threshold.
///
/// Returns a string description of the first failure for the caller
/// to wrap into `VerificationError::InvalidStructure`.
pub fn check_pcs_policy(
    config: &stwo::core::pcs::PcsConfig,
    policy: &PcsPolicy,
) -> Result<(), alloc::string::String> {
    use alloc::format;
    if config.pow_bits < policy.min_pow_bits {
        return Err(format!(
            "pcs_config.pow_bits {} < policy minimum {}",
            config.pow_bits, policy.min_pow_bits
        ));
    }
    if config.fri_config.n_queries < policy.min_fri_queries {
        return Err(format!(
            "pcs_config.fri_config.n_queries {} < policy minimum {}",
            config.fri_config.n_queries, policy.min_fri_queries
        ));
    }
    if config.fri_config.log_blowup_factor < policy.min_fri_log_blowup {
        return Err(format!(
            "pcs_config.fri_config.log_blowup_factor {} < policy minimum {}",
            config.fri_config.log_blowup_factor, policy.min_fri_log_blowup
        ));
    }
    Ok(())
}
