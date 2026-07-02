//! The pure, dependency-free hash-chain and VRF-combine derivations —
//! recomputable by any holder of the domain (and, for the committee
//! derivations, the public proof material) without touching actor state.

use alloc::vec::Vec;

use crate::consts::{ALPHA_DOMAIN_TAG, BEACON_DOMAIN_TAG, COMBINE_DOMAIN_TAG, ENTROPY_LEN};
use crate::rows::{BeaconRound, RoundProofSet};

/// The canonical beacon derivation. Pure and dependency-free so any consumer
/// (in any language/target) can recompute it: `H(domain ‖ prev ‖ round_le ‖
/// slot_le ‖ entropy)` under [`BEACON_DOMAIN_TAG`]. On riscv64 this routes
/// through the blake2b host trap; everywhere else through `vos::crypto`'s
/// software impl.
///
/// `H` is **unkeyed BLAKE2b with a 32-byte digest length** (the BLAKE2b-256
/// parameterization — fanout/depth 1, no key), NOT BLAKE2b-512 truncated to 32:
/// the output length is mixed into the IV, so the two differ. The inputs are a
/// plain left-to-right concatenation; the parse is unambiguous because every
/// field after the leading variable-length `domain` is fixed-width (`prev` 32,
/// `round_le` 8, `slot_le` 8, `entropy` 32). An external re-implementer must
/// match this exactly, including the field order.
pub fn derive_beacon(
    domain: &[u8],
    prev: &[u8; 32],
    round: u64,
    slot: u64,
    entropy: &[u8; 32],
) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        BEACON_DOMAIN_TAG,
        &[
            domain,
            prev,
            &round.to_le_bytes(),
            &slot.to_le_bytes(),
            entropy,
        ],
    )
}

/// Verify a round's `beacon` is the correct hash of its inputs. Linkage to the
/// previous round is checked by the caller comparing `round.prev` against the
/// predecessor's `beacon`.
pub fn verify_round(domain: &[u8], round: &BeaconRound) -> bool {
    derive_beacon(domain, &round.prev, round.round, round.slot, &round.entropy) == round.beacon
}

/// Verify a contiguous, ascending slice of rounds: every round hashes correctly,
/// each links to its predecessor (`rounds[i].round == rounds[i-1].round + 1`,
/// `rounds[i].prev == rounds[i-1].beacon`, and `rounds[i].slot > rounds[i-1].slot`),
/// and any `round == 0` element is the canonical genesis (`prev`, `entropy`, and
/// `slot` all zero). Encoding the linkage check here keeps consumers from
/// re-deriving a round in isolation and missing that an attacker could splice a
/// valid-looking round out of sequence — including a fabricated round 0
/// (`H(domain‖X‖0‖S‖Y)` with non-zero `X`/`S`/`Y` is a valid hash of its inputs
/// but is NOT the chain's genesis). The registry/replicated state is not trusted,
/// so anchoring round 0 makes a window that starts at genesis self-authenticating
/// against the recomputable genesis. An empty slice is vacuously valid; a window
/// that does not start at round 0 authenticates only relative linkage — a
/// consumer pins its first element to a trusted checkpoint.
pub fn verify_chain(domain: &[u8], rounds: &[BeaconRound]) -> bool {
    let mut i = 0;
    while i < rounds.len() {
        if !verify_round(domain, &rounds[i]) {
            return false;
        }
        if rounds[i].round == 0
            && (rounds[i].prev != [0u8; 32]
                || rounds[i].entropy != [0u8; 32]
                || rounds[i].slot != 0)
        {
            return false; // a round-0 element must be the canonical genesis
        }
        if i > 0 {
            let prev = &rounds[i - 1];
            if rounds[i].round != prev.round + 1
                || rounds[i].prev != prev.beacon
                || rounds[i].slot <= prev.slot
            {
                return false;
            }
        }
        i += 1;
    }
    true
}

/// The public VRF input `α` a round's committee proves over:
/// `H(domain ‖ prev ‖ round)` under [`ALPHA_DOMAIN_TAG`], where `prev` is the
/// chain head beacon at the moment the round opened. Fixed at open time and the
/// same for every voter, so a reveal for one round can never be replayed for
/// another (the `round` is bound in). Voters read the canonical `α` straight
/// from [`crate::Chronos::open_rounds`] rather than recomputing it, so this is
/// provided for verification, not as a recompute contract — it only needs
/// determinism and per-round separation, not agreement with
/// [`crate::Chronos::current`].
pub fn derive_alpha(domain: &[u8], prev: &[u8; 32], round: u64) -> [u8; 32] {
    vos::crypto::blake2b_hash(ALPHA_DOMAIN_TAG, &[domain, prev, &round.to_le_bytes()])
}

/// Fold a committee's VRF outputs into the 32-byte round entropy:
/// `H(domain ‖ XOR(β_i))` under [`COMBINE_DOMAIN_TAG`]. The XOR is
/// order-independent (so replicas combining the same reveal set in any order
/// agree) and a single honest, unpredictable `β_i` randomises the whole result
/// — the round is unbiased as long as one committee member is honest. Each
/// `β` is a [`vrf::OUTPUT_LEN`]-byte VRF output; a shorter slice contributes
/// only its prefix (callers always pass full outputs).
///
/// Commit-reveal over a committee like this is a strict improvement over a lone
/// grinding leader but does not eliminate bias: it leaves a residual **1-bit
/// last-revealer** choice (the last voter sees the others and selects between
/// reveal-or-withhold). The lagged finalized read blunts it; fully closing it
/// needs either a pairing-based threshold VRF (e.g. drand's BLS — ruled out
/// here, no pairing precompile) or a VDF binding the commit before any reveal is
/// observed. Both are out of scope for this combine.
pub fn combine_betas(domain: &[u8], betas: &[Vec<u8>]) -> [u8; 32] {
    let mut acc = [0u8; vrf::OUTPUT_LEN];
    for b in betas {
        for (a, x) in acc.iter_mut().zip(b.iter()) {
            *a ^= x;
        }
    }
    vos::crypto::blake2b_hash(COMBINE_DOMAIN_TAG, &[domain, &acc])
}

/// Independently verify a folded **committee round** ([`RoundProofSet`] from
/// [`crate::Chronos::round_proofs`] alongside the [`BeaconRound`] from
/// [`crate::Chronos::round_at`]/[`crate::Chronos::range`]): that the round's
/// entropy is the genuine XOR-combine of valid VRF outputs over the round's
/// input `α`, by the keys named in `proofs`, and that the beacon commits that
/// entropy. Returns `true` iff every reveal's proof verifies under its key over
/// `α`, their [`combine_betas`] equals `round.entropy`, and `round` hashes
/// correctly ([`verify_round`]).
///
/// **What this proves and what it does not.** It proves each `β` is a real VRF
/// output that *no party could choose* (the bias-resistance property), bound to
/// this exact round via `α`, and that the beacon commits their combine — so a
/// single honest reveal makes the round unbiasable. It does **not** by itself
/// prove the keys were the *authorized* committee, nor that `α` was honestly
/// derived: those rest on the Raft consensus that admitted the reveals and
/// opened the round (an untrusted server replaying a self-consistent set still
/// cannot fabricate a biased `β`). A **degraded** round (no reveals — folded on
/// the leader entropy, which is fairness-trusted) has nothing committee-verifiable and
/// returns `false`; its tamper-evidence is [`verify_round`] / [`verify_chain`],
/// unchanged.
pub fn verify_combine(domain: &[u8], round: &BeaconRound, proofs: &RoundProofSet) -> bool {
    if round.round != proofs.round || proofs.reveals.is_empty() {
        return false;
    }
    let mut betas: Vec<Vec<u8>> = Vec::with_capacity(proofs.reveals.len());
    for r in &proofs.reveals {
        let Some(pk) = vrf::PublicKey::from_bytes(&r.pubkey) else {
            return false;
        };
        let Ok(bytes) = <[u8; vrf::PROOF_LEN]>::try_from(r.proof.as_slice()) else {
            return false;
        };
        let Some(proof) = vrf::Proof::from_bytes(&bytes) else {
            return false;
        };
        let Some(beta) = vrf::verify(&pk, &proofs.alpha, &proof) else {
            return false;
        };
        betas.push(beta.to_vec());
    }
    combine_betas(domain, &betas) == round.entropy && verify_round(domain, round)
}

pub(crate) fn to_entropy(bytes: &[u8]) -> Option<[u8; ENTROPY_LEN]> {
    bytes.try_into().ok()
}

/// Validate and canonicalize a 32-byte VRF public key: it must be exactly 32
/// bytes **and** decompress to a valid Ristretto point ([`vrf::PublicKey`] /
/// RFC 9381 over ristretto255). A non-canonical encoding is rejected so a
/// voter can never enrol a key that later fails every proof check silently.
pub(crate) fn to_pubkey(bytes: &[u8]) -> Option<[u8; 32]> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    vrf::PublicKey::from_bytes(&arr)?;
    Some(arr)
}
