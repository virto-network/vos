//! The PCS and security policy a verifier holds a proof's parameters to.

use stwo::core::pcs::PcsConfig;

use crate::format::Format;

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
// Trades proof size for prove speed, for low-power devices: about 2.5×
// faster than STANDARD at log14, for a proof about 1.4× larger.

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
/// `vos_pvm_proof::verify` and `vos_pvm_proof_verifier::verify_standalone` so the
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

/// The FRI-shape check every verify path runs before any cryptographic work.
/// With a policy, its per-field floors, under every format. Without one,
/// format 36's conjectured-security floor ([`check_min_security`]); every
/// other format fixes its parameters, checked with its floors
/// ([`check_format_security`](super::check_format_security)) once the proof's shape is known.
pub fn check_shape_policy(
    format: &Format,
    config: &PcsConfig,
    policy: Option<&PcsPolicy>,
) -> Result<(), alloc::string::String> {
    match policy {
        Some(policy) => check_pcs_policy(config, policy),
        None if format.encoding == crate::format::Encoding::Legacy => check_min_security(config),
        None => Ok(()),
    }
}

/// Minimum conjectured FRI security (bits) the DEFAULT verify paths require.
///
/// Both named policies hit exactly this floor — STANDARD (20 + 19·4 = 96) and
/// MOBILE (20 + 38·2 = 96) — so the default `verify` / `verify_standalone`
/// accept EITHER shape without the caller naming a policy. The two policies
/// are incomparable per-field (STANDARD high-blowup/low-queries, MOBILE
/// low-blowup/high-queries), so a per-field policy floor can only ever accept
/// one of them; this single conjectured-security floor accepts both while
/// still rejecting degenerate FRI shapes. See SECURITY.md "Proof shape".
pub const MIN_CONJECTURED_SECURITY_BITS: u32 = 96;

/// Conjectured FRI soundness (bits) of a `PcsConfig`: `pow_bits +
/// n_queries · log_blowup_factor`. This is the standard heuristic the named
/// policies are tuned to (STANDARD and MOBILE both yield 96) — NOT a proven
/// bound; it exists so the default verify paths can gate on a single number
/// that both shapes satisfy.
pub fn conjectured_security_bits(config: &stwo::core::pcs::PcsConfig) -> u32 {
    checked_conjectured_security_bits(config).unwrap_or(u32::MAX)
}

/// Checked form of [`conjectured_security_bits`]. Wire-facing validation uses
/// this form so a hostile `usize` query count can never truncate to `u32` or
/// wrap the multiplication/addition into a passing security estimate.
pub fn checked_conjectured_security_bits(config: &stwo::core::pcs::PcsConfig) -> Option<u32> {
    let queries = u32::try_from(config.fri_config.n_queries).ok()?;
    let fri_bits = queries.checked_mul(config.fri_config.log_blowup_factor)?;
    config.pow_bits.checked_add(fri_bits)
}

/// Validate `proof.pcs_config` against the conjectured-security floor the
/// DEFAULT `verify` / `verify_standalone` paths enforce. Unlike
/// [`check_pcs_policy`] (an exact per-field pin), this accepts ANY shape
/// meeting the floor — so both STANDARD and MOBILE proofs verify by default —
/// while still rejecting degenerate FRI shapes. Returns `Err` (mirroring
/// `check_pcs_policy`'s style) if ANY of:
///   - `pow_bits < MOBILE_MIN_POW_BITS` (the shared PoW floor),
///   - `log_blowup_factor < MOBILE_MIN_FRI_LOG_BLOWUP` (rejects the
///     degenerate rate-1 / blowup-1 shapes, whose per-query soundness is nil),
///   - [`conjectured_security_bits`] `< MIN_CONJECTURED_SECURITY_BITS`.
///
/// STANDARD (20, 19, 4) and MOBILE (20, 38, 2) both pass (each is 96 bits);
/// a blowup-1 or a 95-bit config fails.
pub fn check_min_security(
    config: &stwo::core::pcs::PcsConfig,
) -> Result<(), alloc::string::String> {
    use alloc::format;
    if config.pow_bits < MOBILE_MIN_POW_BITS {
        return Err(format!(
            "pcs_config.pow_bits {} < security-floor minimum {}",
            config.pow_bits, MOBILE_MIN_POW_BITS
        ));
    }
    if config.fri_config.log_blowup_factor < MOBILE_MIN_FRI_LOG_BLOWUP {
        return Err(format!(
            "pcs_config.fri_config.log_blowup_factor {} < security-floor minimum {} \
             (degenerate FRI rate)",
            config.fri_config.log_blowup_factor, MOBILE_MIN_FRI_LOG_BLOWUP
        ));
    }
    let bits = checked_conjectured_security_bits(config).ok_or_else(|| {
        alloc::string::String::from("pcs_config conjectured-security arithmetic overflows")
    })?;
    if bits < MIN_CONJECTURED_SECURITY_BITS {
        return Err(format!(
            "pcs_config conjectured security {bits} bits < minimum {MIN_CONJECTURED_SECURITY_BITS}"
        ));
    }
    Ok(())
}
