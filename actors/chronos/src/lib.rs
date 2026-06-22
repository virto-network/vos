//! Per-space deterministic clock + verifiable randomness — the **public**
//! time/randomness plane of VOS, kept strictly apart from any secret key
//! material.
//!
//! A pure PVM actor has no wall clock and no entropy: its only primitive is
//! blake2b, and every value it sees is a caller-supplied argument. `chronos` is
//! the well-known per-space service that closes that gap without breaking
//! determinism. It **holds** a monotone slot clock and an entropy accumulator
//! and **serves** them over a stable pull API; it never *originates* time or
//! randomness. The single feeder — the raft leader at the sequencing boundary —
//! samples the wall-clock and OS entropy once, commits them via `advance`, and
//! every replica replays the committed values identically. This is JAM's model
//! (sample once at the proposer, commit, replay; the wall-clock only *gates*
//! acceptance) and drand's architecture (a known committee produces, everyone
//! pulls), without drand's crypto.
//!
//! Derived from the JAM Gray Paper: time is an integer timeslot the block
//! author writes into the signed header (`H_t`), and state advances by a pure
//! *copy* (`τ' ≡ H_t`) — the local wall-clock only bounds acceptance
//! (`parent_t < H_t ≤ w/6`), never feeds execution. Entropy is a rotating
//! 4-slot buffer (`η₀..η₃`, `η₀' = blake(η₀ ‖ VRF_out)`); the load-bearing
//! principle is the refine/accumulate split: the in-consensus accumulate phase
//! may read the live entropy, but the parallel re-auditable refine phase is
//! *denied* fresh time and randomness (its entropy slot is hard-wired to zero)
//! so a replayer can never re-sample. VOS mirrors this — the raft leader is the
//! block-author analog and the effect log is the replay oracle, so consumers
//! read pinned committed values, never fresh samples.
//!
//! Two randomness planes never mix: the SECRET plane is a per-device seed that
//! never replicates and is the only confidentiality root; this PUBLIC beacon is
//! a normal replicated actor supplying shared, publicly-recomputable values for
//! operational fairness — fair ordering, sampling, freshness / domain
//! separation. A consumer may *hedge* a beacon value into a key derivation only
//! as HKDF `info`, never as keying material; confidentiality must always hold on
//! the secret seed alone (RFC 9180 §9.7.5).
//!
//! ## The clock
//!
//! Time is an integer **slot** counted from a fixed global VOS Common Era anchor
//! (the anchor lives in the feeder, `vosx`, so slots are comparable across
//! spaces). A fast clock (default 250 ms per slot) is decoupled from coarse
//! **epochs** ([`SLOTS_PER_EPOCH`] slots each, ~1 s by default): `advance` stamps
//! the slot on every call but folds entropy into a new beacon round only when it
//! crosses an epoch boundary, so randomness stays cheap while the clock stays
//! fresh. The slot is **bounded, not trusted**: `advance` enforces strict
//! monotonicity and caps how far a single non-establishing call may leap
//! ([`MAX_SLOT_JUMP`]) — the honest feeder never trips the cap because it derives
//! the slot from its own wall-clock.
//!
//! Cadence tradeoff: every state-changing `advance` is a raft commit, so feeding
//! the clock at the full slot rate (4 Hz at 250 ms) would cost 4 commits/s/space
//! — too heavy for a chat workload. The feeder therefore advances on a coarser
//! idle-keepalive cadence (~1 s), *decoupled* from the fine slot resolution, and
//! folds entropy only on epoch boundaries; clock freshness is bounded by that
//! keepalive, which is the deliberate price for a cheap raft. The fine slot rate
//! still matters because a piggyback path (stamping the current slot onto raft
//! traffic that is already happening, e.g. msg-ctl commits) can give sub-second
//! freshness for free, firing a dedicated advance only when the space is idle.
//!
//! ## Base randomness: a blake2b hash-chain of contributed entropy
//!
//! Each folded epoch chains caller-contributed entropy:
//! `beaconₙ = H(domain ‖ beaconₙ₋₁ ‖ n ‖ slotₙ ‖ entropyₙ)`, with the genesis
//! round 0 anchored at `H(domain ‖ 0 ‖ 0 ‖ 0 ‖ 0)` (slot 0 = the era; the clock
//! is not yet established). Running on Raft, the chain is a single agreed
//! sequence; every round stores `(round, slot, prev, entropy, beacon)` so any
//! holder can recompute it and verify linkage ([`verify_round`]) — the chain is
//! **tamper-evident**.
//!
//! The bare hash-chain does NOT by itself provide bias-resistance or public
//! verifiability *of the entropy's fairness*. When no committee is configured,
//! the feeder contributes the entropy and could grind it (try values, pick a
//! favourable beacon) before committing; grinding-sensitive consumers must
//! therefore read the **lagged/finalized** value ([`Chronos::latest_final`] /
//! [`Chronos::randomness_at`]), never the live head ([`Chronos::current`]) — the
//! head is biasable by a last-revealer, exactly as JAM reads the lagged buffer
//! η₂ rather than the live η₀. Bias resistance comes from the committee layer:
//! ECVRF over Ristretto255 with a committee XOR-combine ([`combine_betas`]),
//! folded behind this same API so a consumer reads the same rows whether or not
//! a committee is active. (A Bandersnatch RingVRF for JAM interop fits the same
//! shape.)
//!
//! State is rkyv-serialized as a whole struct with no on-disk version tag, so a
//! struct-layout change fails to decode old persisted state and resets the actor
//! to a fresh genesis — and the reset is then persisted. Any layout change (e.g.
//! adding fields) MUST therefore be a deliberate re-init or carry an explicit
//! migration/version byte.

use vos::prelude::*;

// ── Constants ─────────────────────────────────────────────────────

/// Domain tag separating chronos beacon hashes from every other blake2b use in
/// VOS. The `/v2` suffix pins the current derivation input layout
/// ([`derive_beacon`], which folds the per-round `slot`), so an external
/// re-implementer of a different layout is not silently accepted.
pub const BEACON_DOMAIN_TAG: &[u8] = b"vos-beacon/v2";

/// Domain tag for a round's VRF input `α` ([`derive_alpha`]) — kept distinct
/// from the beacon hash so the two derivations can never collide.
pub const ALPHA_DOMAIN_TAG: &[u8] = b"vos-chronos-alpha/v1";

/// Domain tag for the committee combine ([`combine_betas`]) — the hash that
/// folds the XOR of the voters' VRF outputs down to the 32-byte round entropy.
pub const COMBINE_DOMAIN_TAG: &[u8] = b"vos-chronos-combine/v1";

/// Bound on the operator-chosen per-space domain label. Replicated to every
/// node, so cap it.
pub const MAX_DOMAIN_BYTES: usize = 128;

/// Each round's contributed entropy is exactly 32 bytes.
pub const ENTROPY_LEN: usize = 32;

/// Slots per epoch — entropy is folded at most once per epoch, so this sets the
/// randomness cadence relative to the clock. Default 4 ≈ 1 s at the feeder's
/// default 250 ms slot. The clock advances every slot regardless; only beacon
/// rounds are gated to epoch boundaries.
pub const SLOTS_PER_EPOCH: u64 = 4;

/// How many folded epochs behind the live head a value must be before it is
/// considered **finalized** (the JAM η₂ lesson: the live head η₀ is biasable by
/// a last-revealer, so grinding-sensitive consumers read a lagged buffer). A lag
/// of 2 matches JAM's η₂. [`Chronos::latest_final`] / [`Chronos::randomness_at`]
/// never return a round newer than this; [`Chronos::current`] is the un-lagged
/// head, documented low-stakes-only.
pub const FINALIZED_LAG: usize = 2;

/// How many epochs a committee round stays open for reveals before it folds. A
/// round opened at epoch `N` folds at epoch `N + REVEAL_WINDOW_EPOCHS`,
/// combining whatever committee reveals were committed by then — the fold is at
/// a deterministic clock boundary, so the leader cannot pick the moment. A round
/// opened with an **empty** committee (no enrolled voters to wait for) folds
/// immediately, so an unconfigured space folds the leader entropy at the epoch
/// boundary. This is the reveal-window half of the head-lag; consumers read a
/// value `REVEAL_WINDOW_EPOCHS + FINALIZED_LAG` epochs behind the clock.
pub const REVEAL_WINDOW_EPOCHS: u64 = 2;

/// Cap on how far a single **non-establishing** `advance` may move the slot
/// forward — the future-drift bound (invariant: time is bounded, not trusted).
/// ~1 hour at the default 250 ms slot. The honest feeder derives the slot from
/// its own wall-clock and pre-clamps to `now() + MAX_SLOT_JUMP`, so it never
/// trips this; the cap defends against a glitched/oversized single commit. The
/// *establishing* advance (from the slot-0 era anchor, before the clock has
/// moved) is exempt so the clock can jump from the era to the present in one
/// step. The initial slot itself is feeder-trusted; the committee commit-reveal
/// hardens the entropy that rides on it.
pub const MAX_SLOT_JUMP: u64 = 14_400;

/// Most-recent rounds retained for `round_at`/`randomness_at` lookups. Older
/// rounds are pruned from the front; the chain head ([`Chronos::current`]) is
/// always available. Bounds the replicated state regardless of how long the
/// service runs. One entry per folded epoch, so this is ~1024 epochs of history,
/// not 1024 slots.
pub const MAX_HISTORY: usize = 1024;

/// Cap on rounds returned by one `range` call — a soft response-size budget so
/// one reply stays modest (~14 KiB at ~112 bytes per [`BeaconRound`]). The reply
/// payload is heap-grown host-side, not bounded by the incoming-fetch buffer, so
/// this is a courtesy cap, not a correctness limit.
pub const MAX_RANGE: u32 = 128;

// ── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
/// Entropy was not exactly [`ENTROPY_LEN`] bytes, or the domain was too large.
pub const STATUS_INVALID_INPUT: u8 = 1;
/// `advance` was called before `init`.
pub const STATUS_NOT_INITIALIZED: u8 = 2;
/// `init` was called on an already-initialised service (one-shot).
pub const STATUS_ALREADY_INITIALIZED: u8 = 3;
/// The proposed slot did not move the clock strictly forward (`slot <= now`).
pub const STATUS_STALE_SLOT: u8 = 4;
/// The proposed slot leapt more than [`MAX_SLOT_JUMP`] past the current slot on
/// a non-establishing advance (the future-drift cap).
pub const STATUS_SLOT_JUMP_TOO_LARGE: u8 = 5;
/// Reserved, unused. The committee handlers are authenticated cryptographically
/// (a chronos handler runs on the raft apply path, where the originating caller
/// is not preserved), so no handler returns a caller-based authorization error.
pub const STATUS_UNAUTHORIZED: u8 = 6;
/// An `enrol_voter` tried to bind a *different* key to a voter that already has
/// one. The first key wins; there is no key rotation (see [`Chronos::enrol_voter`]).
pub const STATUS_KEY_LOCKED: u8 = 10;
/// The voter is not in the authorized committee ([`Chronos::set_committee`]) —
/// enrolment and reveals are only accepted from registry voters.
pub const STATUS_NOT_A_VOTER: u8 = 7;
/// A reveal named a round that is not currently open — it was never opened, or
/// its reveal window already closed and it folded.
pub const STATUS_NO_SUCH_ROUND: u8 = 8;
/// A reveal's VRF proof did not verify against the voter's enrolled key over the
/// round's input `α`.
pub const STATUS_BAD_PROOF: u8 = 9;

// ── Roles ─────────────────────────────────────────────────────────

/// Reads (`now`/`epoch`/`current`/`latest_final`/`randomness_at`/`round_at`/
/// `round`/`range`) are **public** — bare `#[msg]` handlers carry no role check,
/// so any caller past the libp2p auth gate may read, by design: chronos exposes
/// only publicly-recomputable values. Advancing the clock/chain (`init`/
/// `advance`) is the privileged feeder operation, gated to `Advancer`; in
/// production the Raft leader's node drives it (a `System` caller bypasses the
/// gate). `default_role` only labels intent here — it is not consulted for the
/// unguarded read handlers.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum ChronosRole {
    None = 0,
    Reader = 1,
    Advancer = 2,
}

impl vos::RoleByte for ChronosRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Advancer),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const CHRONOS_SPACE_ROLE_MAP: vos::SpaceRoleMap<ChronosRole> = vos::SpaceRoleMap {
    admin: Some(ChronosRole::Advancer),
    developer: Some(ChronosRole::Reader),
    member: Some(ChronosRole::Reader),
    guest: None,
};

// ── Rows ──────────────────────────────────────────────────────────

/// One committed round of the beacon chain — one folded epoch. Self-verifying:
/// recomputing `H(domain ‖ prev ‖ round ‖ slot ‖ entropy)` must equal `beacon`
/// ([`verify_round`]).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BeaconRound {
    /// Dense round index: `+1` per folded epoch, contiguous, genesis is 0. The
    /// linkage anchor for [`verify_chain`]. (Distinct from `slot / SLOTS_PER_EPOCH`,
    /// the wall-epoch, which is sparse when the clock skips epochs.)
    pub round: u64,
    /// The slot at which this round **opened** — when its input `α` was fixed
    /// (for a committee-less round this is also the fold slot, since it opens and
    /// folds in one `advance`). The clock context of the round; its wall-epoch is
    /// `slot / SLOTS_PER_EPOCH`. `0` for genesis. Strictly ascending across
    /// rounds (one round opens per crossed epoch), and bound into `beacon` so it
    /// cannot be relabelled against an untrusted server.
    pub slot: u64,
    /// The previous round's beacon (`[0; 32]` for the genesis round 0).
    pub prev: [u8; 32],
    /// The entropy folded in this round (`[0; 32]` for the genesis round 0).
    pub entropy: [u8; 32],
    pub beacon: [u8; 32],
}

/// One committee member's enrolled VRF public key. `voter` is the node's
/// `peer_id` multihash bytes — the same identity the registry stores as a
/// `MemberRow.key` for a `NODE_ROLE_VOTER` node, and the same bytes a libp2p
/// inbound carries as [`vos::Caller::Peer`]. `pubkey` is a canonical
/// Ristretto255 VRF public key ([`vrf::PublicKey`]); it is **public** — chronos
/// holds no secret key material.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct VoterKey {
    pub voter: Vec<u8>,
    pub pubkey: [u8; 32],
}

/// One committee member's reveal collected in an open round. `beta` is the
/// VRF output cached at acceptance (the proof is verified once, on arrival, not
/// re-verified at fold time). `proof` is the 80-byte wire proof, retained so the
/// folded round stays publicly re-verifiable ([`RoundProofSet`]).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct StoredReveal {
    voter: Vec<u8>,
    pubkey: [u8; 32],
    proof: Vec<u8>,
    beta: Vec<u8>,
}

/// An open round collecting committee reveals before it folds. Held in
/// [`Chronos::pending`] from the epoch it opens until its reveal window closes.
/// The `snapshot` fixes the authorized+enrolled committee **at open time**, so a
/// voter cannot re-enrol a favourable key once `alpha` is known (anti
/// key-shopping); reveals are verified against this snapshot, not the live keys.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct RoundDraft {
    round: u64,
    open_slot: u64,
    /// The epoch at/after which this round folds: its open epoch for an empty
    /// committee (fold immediately), else open epoch + [`REVEAL_WINDOW_EPOCHS`].
    fold_epoch: u64,
    alpha: [u8; 32],
    snapshot: Vec<VoterKey>,
    reveals: Vec<StoredReveal>,
}

/// One reveal's public verification material in a folded round.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RevealProof {
    pub voter: Vec<u8>,
    pub pubkey: [u8; 32],
    pub proof: Vec<u8>,
}

/// The committee proof material for a folded round — everything needed to
/// re-derive its entropy independently ([`verify_combine`]): the round's `alpha`
/// and each counted reveal's `(pubkey, proof)`. Empty `reveals` marks a degraded
/// round folded on the leader entropy (no committee reveal arrived). Retained in
/// lockstep with the beacon history.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RoundProofSet {
    pub round: u64,
    pub alpha: [u8; 32],
    pub reveals: Vec<RevealProof>,
}

/// A round currently open for reveals, as surfaced by [`Chronos::open_rounds`].
/// A voter proves over `alpha` and posts a [`Chronos::reveal`] before the clock
/// reaches `fold_epoch`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct OpenRound {
    pub round: u64,
    pub alpha: [u8; 32],
    pub open_slot: u64,
    pub fold_epoch: u64,
}

/// Result of an `advance`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AdvanceOutcome {
    pub status: u8,
    /// The clock after the advance (the freshly-stamped slot on success).
    pub slot: u64,
    /// The head round number after the advance — bumped iff `folded`.
    pub round: u64,
    /// The head beacon after the advance — changed iff `folded`.
    pub beacon: [u8; 32],
    /// Whether this advance crossed an epoch boundary and folded a new round.
    /// A plain clock tick within the current epoch stamps the slot with
    /// `folded == false` and leaves the chain untouched.
    pub folded: bool,
}

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
/// from [`Chronos::open_rounds`] rather than recomputing it, so this is provided
/// for verification, not as a recompute contract — it only needs determinism and
/// per-round separation, not agreement with [`Chronos::current`].
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
/// [`Chronos::round_proofs`] alongside the [`BeaconRound`] from
/// [`Chronos::round_at`]/[`Chronos::range`]): that the round's entropy is the
/// genuine XOR-combine of valid VRF outputs over the round's input `α`, by the
/// keys named in `proofs`, and that the beacon commits that entropy. Returns
/// `true` iff every reveal's proof verifies under its key over `α`, their
/// [`combine_betas`] equals `round.entropy`, and `round` hashes correctly
/// ([`verify_round`]).
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

fn to_entropy(bytes: &[u8]) -> Option<[u8; ENTROPY_LEN]> {
    if bytes.len() != ENTROPY_LEN {
        return None;
    }
    let mut out = [0u8; ENTROPY_LEN];
    out.copy_from_slice(bytes);
    Some(out)
}

/// Validate and canonicalize a 32-byte VRF public key: it must be exactly 32
/// bytes **and** decompress to a valid Ristretto point ([`vrf::PublicKey`] /
/// RFC 9381 over ristretto255). A non-canonical encoding is rejected so a
/// voter can never enrol a key that later fails every proof check silently.
fn to_pubkey(bytes: &[u8]) -> Option<[u8; 32]> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    vrf::PublicKey::from_bytes(&arr)?;
    Some(arr)
}

/// Upper bound on committee size and per-voter id length, so a malformed
/// [`encode_committee`] blob can never drive an unbounded allocation. A voter
/// id is a `peer_id` multihash (tens of bytes); 256 is comfortably generous.
pub const MAX_COMMITTEE: usize = 1024;
const MAX_VOTER_ID_LEN: usize = 256;

/// Wire codec for the voter list passed to [`Chronos::set_committee`]. A handler
/// parameter must map to a [`vos::Value`] variant and there is no `Vec<Vec<u8>>`
/// variant, so the variable-length `peer_id` list is flattened into one
/// length-prefixed blob: a `u16` count, then per voter a `u16` length and that
/// many bytes, all little-endian. Exported so the feeder encodes identically.
pub fn encode_committee(voters: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(voters.len() as u16).to_le_bytes());
    for v in voters {
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// Inverse of [`encode_committee`]. Returns `None` on a malformed blob: a bad
/// length prefix, trailing garbage, an over-long voter id, or more than
/// [`MAX_COMMITTEE`] entries.
pub fn decode_committee(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut p = 0usize;
    let count = u16::from_le_bytes(bytes.get(p..p + 2)?.try_into().ok()?) as usize;
    p += 2;
    if count > MAX_COMMITTEE {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16::from_le_bytes(bytes.get(p..p + 2)?.try_into().ok()?) as usize;
        p += 2;
        if len > MAX_VOTER_ID_LEN {
            return None;
        }
        out.push(bytes.get(p..p + len)?.to_vec());
        p += len;
    }
    if p != bytes.len() {
        return None; // trailing garbage
    }
    Some(out)
}

// ── Actor ─────────────────────────────────────────────────────────

#[actor(
    role = ChronosRole,
    default_role = ChronosRole::Reader,
    space_role_map = CHRONOS_SPACE_ROLE_MAP
)]
pub struct Chronos {
    /// Operator-chosen per-space domain label, bound into every hash so two
    /// spaces' chains can never alias. Empty until `init`.
    domain: Vec<u8>,
    initialized: bool,
    /// The live clock, in VOS Common Era slots. `0` = the era anchor (the clock
    /// is not yet established); strictly increasing once the feeder advances it.
    current_slot: u64,
    /// Head round number = number of folded epochs (genesis is round 0).
    current_round: u64,
    current_beacon: [u8; 32],
    /// Most-recent rounds (oldest pruned past [`MAX_HISTORY`]), ascending by
    /// `round` and by `slot`; the genesis round 0 is the first entry after
    /// `init`. One entry per folded epoch.
    history: Vec<BeaconRound>,
    /// The authorized voter set — the Sybil gate for the committee. Each
    /// entry is a voter's `peer_id` multihash bytes; sorted, so membership is a
    /// binary search. The raft leader's feeder mirrors the registry's
    /// `NODE_ROLE_VOTER` set here via [`Chronos::set_committee`]. Only these
    /// voters may enrol a key or have a reveal counted.
    authorized: Vec<Vec<u8>>,
    /// Enrolled VRF public keys, sorted by `voter` — an invariant subset of
    /// [`Self::authorized`] (enrolment rejects non-voters; `set_committee`
    /// prunes dropped voters). Each voter self-enrols its own public key
    /// ([`Chronos::enrol_voter`]); the secret never leaves the owning node.
    pubkeys: Vec<VoterKey>,
    /// Rounds currently open for committee reveals, ascending by `round` and
    /// contiguous (`current_round+1 ..= current_round+pending.len()`). A round is
    /// opened on each epoch crossing and removed when it folds; with no committee
    /// it opens and folds in the same `advance`, so this stays empty for a
    /// committee-less space. Structurally bounded by [`REVEAL_WINDOW_EPOCHS`] in
    /// steady state.
    pending: Vec<RoundDraft>,
    /// Committee proof material for folded rounds, parallel to [`Self::history`]
    /// and pruned with it. One entry per folded round (empty `reveals` for a
    /// degraded round); the basis for [`Chronos::round_proofs`] / [`verify_combine`].
    proofs: Vec<RoundProofSet>,
}

#[messages]
impl Chronos {
    pub fn new() -> Self {
        Self {
            domain: Vec::new(),
            initialized: false,
            current_slot: 0,
            current_round: 0,
            current_beacon: [0u8; 32],
            history: Vec::new(),
            authorized: Vec::new(),
            pubkeys: Vec::new(),
            pending: Vec::new(),
            proofs: Vec::new(),
        }
    }

    /// Anchor the chain under `domain` (one-shot). The genesis round 0 is
    /// `H(domain ‖ 0 ‖ 0 ‖ 0 ‖ 0)` at slot 0 — public and recomputable, carrying
    /// no entropy and no established clock yet. Returns
    /// `STATUS_ALREADY_INITIALIZED` on a second call.
    #[msg(role = ChronosRole::Advancer)]
    async fn init(&mut self, domain: Vec<u8>) -> u8 {
        if self.initialized {
            return STATUS_ALREADY_INITIALIZED;
        }
        if domain.len() > MAX_DOMAIN_BYTES {
            return STATUS_INVALID_INPUT;
        }
        let genesis = derive_beacon(&domain, &[0u8; 32], 0, 0, &[0u8; 32]);
        self.domain = domain;
        self.initialized = true;
        self.current_slot = 0;
        self.current_round = 0;
        self.current_beacon = genesis;
        self.history.push(BeaconRound {
            round: 0,
            slot: 0,
            prev: [0u8; 32],
            entropy: [0u8; 32],
            beacon: genesis,
        });
        STATUS_OK
    }

    /// Stamp the clock at `slot` and drive the round protocol: crossing into a
    /// new epoch **opens** a fresh round for committee reveals, and any open
    /// round whose reveal window has elapsed **folds** into the beacon chain.
    ///
    /// `slot` must move the clock strictly forward (`> now`) and — once the
    /// clock is established (not the first advance off the slot-0 era anchor) —
    /// may not leap more than [`MAX_SLOT_JUMP`] past it. A call that stays within
    /// the current epoch just stamps the slot (`folded == false`), keeping the
    /// fast clock cheap.
    ///
    /// A round folds by combining the committee's revealed VRF outputs
    /// ([`combine_betas`]) — no party can choose its contribution, so the leader
    /// cannot grind the entropy. With **no** committee the round folds
    /// immediately on the `entropy` argument (the leader's entropy, fairness
    /// trusted; see the module docs). A committee round with no reveals by its
    /// deadline likewise folds the leader entropy — a degraded round, protected
    /// by the lagged read. `folded == true` iff at least one round folded in this
    /// call.
    ///
    /// On Raft this is leader-driven and quorum-committed.
    #[msg(role = ChronosRole::Advancer)]
    async fn advance(&mut self, slot: u64, entropy: Vec<u8>) -> AdvanceOutcome {
        if !self.initialized {
            return AdvanceOutcome {
                status: STATUS_NOT_INITIALIZED,
                slot: 0,
                round: 0,
                beacon: [0u8; 32],
                folded: false,
            };
        }
        let unchanged = |status: u8, this: &Self| AdvanceOutcome {
            status,
            slot: this.current_slot,
            round: this.current_round,
            beacon: this.current_beacon,
            folded: false,
        };

        // Strict monotonicity (anti-rewind / anti-replay of the clock).
        if slot <= self.current_slot {
            return unchanged(STATUS_STALE_SLOT, self);
        }
        // Future-drift cap. Exempt the establishing advance (current_slot == 0),
        // which legitimately jumps from the era anchor to the present in one step.
        if self.current_slot != 0 && slot > self.current_slot.saturating_add(MAX_SLOT_JUMP) {
            return unchanged(STATUS_SLOT_JUMP_TOO_LARGE, self);
        }
        let Some(entropy) = to_entropy(&entropy) else {
            return unchanged(STATUS_INVALID_INPUT, self);
        };

        // Always stamp the clock.
        let prev_epoch = self.current_slot / SLOTS_PER_EPOCH;
        let new_epoch = slot / SLOTS_PER_EPOCH;
        self.current_slot = slot;

        // OPEN one round per crossing advance (a multi-epoch jump still opens a
        // single round; skipped epochs share no round). Open before fold so a
        // committee-less round can fold in the very same call.
        if new_epoch > prev_epoch {
            self.open_round(slot, new_epoch);
        }

        // FOLD every open round whose reveal window has closed, in round order.
        // `pending` is ascending, so the front is always the earliest-due round.
        let mut folded = false;
        while self
            .pending
            .first()
            .is_some_and(|d| new_epoch >= d.fold_epoch)
        {
            let draft = self.pending.remove(0);
            self.fold_round(draft, &entropy);
            folded = true;
        }

        AdvanceOutcome {
            status: STATUS_OK,
            slot,
            round: self.current_round,
            beacon: self.current_beacon,
            folded,
        }
    }

    /// The current slot (the live clock). `0` before the feeder's first advance
    /// (the era anchor).
    #[msg]
    async fn now(&self) -> u64 {
        self.current_slot
    }

    /// The current epoch (`now / SLOTS_PER_EPOCH`).
    #[msg]
    async fn epoch(&self) -> u64 {
        self.current_slot / SLOTS_PER_EPOCH
    }

    /// The live chain head — the η₀ analog. **Low-stakes use only:** the head is
    /// biasable by a last-revealer, so grinding-sensitive consumers MUST read
    /// [`Self::latest_final`] / [`Self::randomness_at`] instead. `None` before
    /// `init`.
    #[msg]
    async fn current(&self) -> Option<BeaconRound> {
        self.history.last().cloned()
    }

    /// The latest **finalized** round — the head lagged by [`FINALIZED_LAG`]
    /// folds (the JAM η₂ analog). This is the read grinding-sensitive consumers
    /// and the messenger hedge use. `None` until at least `FINALIZED_LAG + 1`
    /// rounds exist (so right after `init`, a consumer gets `None` ⇒ no hedge ⇒
    /// no behavior change). Note round 0 (genesis) carries no entropy and is
    /// fully predictable; a consumer requiring unpredictable randomness ignores
    /// `round == 0`.
    #[msg]
    async fn latest_final(&self) -> Option<BeaconRound> {
        let len = self.history.len();
        len.checked_sub(1 + FINALIZED_LAG)
            .and_then(|idx| self.history.get(idx).cloned())
    }

    /// The **finalized** beacon for wall-epoch `epoch`: the most recent round
    /// folded at or before `epoch` (the floor — epochs the clock skipped share
    /// no round of their own), but only if that round is finalized (at least
    /// [`FINALIZED_LAG`] folds behind the head). Returns `None` if no finalized
    /// round exists yet or if the floor round is too fresh to be final. Use this
    /// to bind to a specific past epoch; use [`Self::latest_final`] for "the
    /// latest safe value".
    #[msg]
    async fn randomness_at(&self, epoch: u64) -> Option<BeaconRound> {
        let len = self.history.len();
        let finalized_hi = len.checked_sub(1 + FINALIZED_LAG)?; // no finalized round yet
        // The true floor for `epoch` is the most recent round whose wall-epoch
        // is <= epoch — found by scanning from the head (history ascends by
        // slot). Return it only when it is finalized (index within the lagged
        // head); a too-fresh true floor yields None, so a near-current epoch
        // settles only after FINALIZED_LAG folds. Once it returns Some, the
        // answer is stable: a finalized floor implies a later round already
        // sits above `epoch`, so the clock has moved past `epoch` and no future
        // fold can change the floor.
        let mut idx = len - 1;
        loop {
            let r = &self.history[idx];
            if r.slot / SLOTS_PER_EPOCH <= epoch {
                return if idx <= finalized_hi {
                    Some(r.clone())
                } else {
                    None // the true floor is too fresh to be finalized
                };
            }
            if idx == 0 {
                return None; // epoch predates the oldest retained round
            }
            idx -= 1;
        }
    }

    /// The round numbered `round`, if still retained (recent rounds only —
    /// older than [`MAX_HISTORY`] back from the head are pruned). `None` before
    /// `init` or once pruned. Indexed by the dense round number, not the epoch.
    #[msg]
    async fn round_at(&self, round: u64) -> Option<BeaconRound> {
        // history is ascending by round and contiguous, so index directly off
        // the head when the requested round is in range.
        let head = self.history.last()?;
        if round > head.round {
            return None;
        }
        let behind = head.round - round;
        if behind as usize >= self.history.len() {
            return None; // pruned
        }
        let idx = self.history.len() - 1 - behind as usize;
        self.history.get(idx).cloned()
    }

    /// The current head round number (0 right after `init`) — the number of
    /// folded epochs.
    #[msg]
    async fn round(&self) -> u64 {
        self.current_round
    }

    /// Up to `limit` consecutive retained rounds starting at round `from`,
    /// ascending — a consumer fetches a window in one call and validates it with
    /// [`verify_chain`]. `limit` is clamped to [`MAX_RANGE`]; rounds below the
    /// retained window (pruned) or past the head are simply omitted, so an empty
    /// result means nothing in `[from, from+limit)` is currently retained.
    #[msg]
    async fn range(&self, from: u64, limit: u32) -> Vec<BeaconRound> {
        let limit = limit.min(MAX_RANGE) as u64;
        let Some(head) = self.history.last() else {
            return Vec::new();
        };
        if limit == 0 || from > head.round {
            return Vec::new();
        }
        // history is contiguous ascending by round, so round r sits at index
        // r - oldest.
        let oldest = self.history[0].round;
        let start = from.max(oldest);
        // saturating: `from <= head.round` and `limit <= MAX_RANGE`, so this
        // can't overflow at any reachable round count, but stay defensive since
        // the release ELF builds without overflow checks.
        let end = from.saturating_add(limit - 1).min(head.round);
        if start > end {
            return Vec::new();
        }
        let lo = (start - oldest) as usize;
        let hi = (end - oldest) as usize;
        self.history[lo..=hi].to_vec()
    }

    // ── Committee (bias resistance) ────────────────────────────────

    /// Replace the **authorized voter set** — the Sybil gate for the committee.
    /// Each entry is a voter's `peer_id` multihash bytes (the registry's
    /// `MemberRow.key` for a `NODE_ROLE_VOTER` node). The raft leader's feeder
    /// reads the registry voters and pushes them here; a trusted `System` caller
    /// (the local feeder, on the leader) passes the [`ChronosRole::Advancer`]
    /// gate. Replacing the set prunes enrolled keys for voters that dropped out,
    /// so a removed node's reveals stop counting from the next opened round.
    ///
    /// This is the *membership* half of the committee; the *key* half is each
    /// voter's own [`Self::enrol_voter`]. Splitting them keeps a single
    /// authority for "who may vote" (the registry, via the leader) separate from
    /// "which key is theirs" (the voter itself, libp2p-authenticated).
    #[msg(role = ChronosRole::Advancer)]
    async fn set_committee(&mut self, voters: Vec<u8>) -> u8 {
        if !self.initialized {
            return STATUS_NOT_INITIALIZED;
        }
        let Some(mut authorized) = decode_committee(&voters) else {
            return STATUS_INVALID_INPUT;
        };
        authorized.sort();
        authorized.dedup();
        // Drop enrolled keys for voters no longer authorized (membership
        // shrank). Keeps `pubkeys ⊆ authorized` as an invariant.
        self.pubkeys
            .retain(|vk| authorized.binary_search(&vk.voter).is_ok());
        self.authorized = authorized;
        STATUS_OK
    }

    /// Enrol a voter's VRF public key into the committee. `voter_id` is the
    /// node's `peer_id` (its registry identity); `pubkey` is its VRF public key
    /// (a canonical Ristretto255 point). The voter must already be authorized via
    /// [`Self::set_committee`].
    ///
    /// **Authentication is cryptographic, not caller-based.** A chronos handler
    /// runs on the raft apply path, where the originating invoke's caller is not
    /// preserved — a cross-node `Caller::Peer` is lost through the committed log
    /// (it surfaces as `Unauthenticated`), so the voter cannot be derived from
    /// `ctx.caller()`. Soundness rests instead on three things: (a) the
    /// leader-pushed **authorized set** (the Sybil gate — only registry voters);
    /// (b) **first-wins** binding — a voter_id's key is set once; re-enrolling a
    /// *different* key is refused ([`STATUS_KEY_LOCKED`]), so an honest voter that
    /// enrols its deterministic node-key-derived key cannot be silently overridden
    /// (a same-key re-enrol is an idempotent no-op, as the feeder re-fires it);
    /// and (c) the VRF proof on every [`Self::reveal`], which only the key holder
    /// can forge. **Residual limitation:** a malicious party that
    /// front-runs an authorized voter's *first* enrol can bind its own key to that
    /// slot. The bias-resistance core is unaffected (no β can be forged), but it
    /// is committee griefing/Sybil within the authorized set; binding the pubkey
    /// in the registry at admit time (authenticated by the admin) closes it.
    #[msg]
    async fn enrol_voter(&mut self, voter_id: Vec<u8>, pubkey: Vec<u8>) -> u8 {
        if !self.initialized {
            return STATUS_NOT_INITIALIZED;
        }
        if self.authorized.binary_search(&voter_id).is_err() {
            return STATUS_NOT_A_VOTER;
        }
        let Some(pubkey) = to_pubkey(&pubkey) else {
            return STATUS_INVALID_INPUT;
        };
        match self
            .pubkeys
            .binary_search_by(|vk| vk.voter.as_slice().cmp(voter_id.as_slice()))
        {
            Ok(i) => {
                if self.pubkeys[i].pubkey != pubkey {
                    return STATUS_KEY_LOCKED; // first-wins: no silent override
                }
                // same key — idempotent (the feeder re-fires until it observes
                // its key replicated into the committee).
            }
            Err(i) => self.pubkeys.insert(
                i,
                VoterKey {
                    voter: voter_id,
                    pubkey,
                },
            ),
        }
        STATUS_OK
    }

    /// The live committee: authorized voters that have enrolled a key, as
    /// `(peer_id, vrf_pubkey)` pairs (sorted by voter). These are the keys whose
    /// reveals are counted into a round. Public/diagnostic — every value here is
    /// already public.
    #[msg]
    async fn committee(&self) -> Vec<VoterKey> {
        self.pubkeys.clone()
    }

    /// Post a committee **reveal** for an open round: `voter_id`'s VRF proof over
    /// the round's input `α`. State-changing, so on Raft it is sequenced in the
    /// committed log — load-bearing for bias resistance, since a reveal in the log
    /// can no longer be selectively dropped after the leader has seen the value.
    ///
    /// Authenticated by the **proof, not the caller** (a chronos handler can't see
    /// the originating caller through the raft log — see [`Self::enrol_voter`]):
    /// `voter_id` selects this round's snapshot key and `vrf::verify` accepts only
    /// a proof that voter could have produced over `α`. The snapshot key is fixed
    /// when the round opened, so a late re-enrol cannot shop a favourable key. A
    /// duplicate reveal is an idempotent no-op (a voter's `β` is deterministic),
    /// which also bounds re-verification work once a slot is filled.
    #[msg]
    async fn reveal(&mut self, voter_id: Vec<u8>, round: u64, proof: Vec<u8>) -> u8 {
        if !self.initialized {
            return STATUS_NOT_INITIALIZED;
        }
        let Some(draft) = self.pending.iter_mut().find(|d| d.round == round) else {
            return STATUS_NO_SUCH_ROUND;
        };
        // The voter must be in THIS round's committee snapshot (Sybil gate +
        // anti key-shopping, fixed when the round opened). Copy the pubkey out so
        // the snapshot borrow ends before we touch `reveals`.
        let Some(pubkey) = draft
            .snapshot
            .iter()
            .find(|vk| vk.voter == voter_id)
            .map(|vk| vk.pubkey)
        else {
            return STATUS_NOT_A_VOTER;
        };
        // Idempotent: a filled slot short-circuits before the VRF verify.
        if draft.reveals.iter().any(|r| r.voter == voter_id) {
            return STATUS_OK;
        }
        let Some(pk) = vrf::PublicKey::from_bytes(&pubkey) else {
            return STATUS_INVALID_INPUT; // snapshot key was validated at enrol; defensive
        };
        let Ok(proof_arr) = <[u8; vrf::PROOF_LEN]>::try_from(proof.as_slice()) else {
            return STATUS_INVALID_INPUT;
        };
        let Some(parsed) = vrf::Proof::from_bytes(&proof_arr) else {
            return STATUS_INVALID_INPUT;
        };
        let Some(beta) = vrf::verify(&pk, &draft.alpha, &parsed) else {
            return STATUS_BAD_PROOF;
        };
        let entry = StoredReveal {
            voter: voter_id,
            pubkey,
            proof,
            beta: beta.to_vec(),
        };
        match draft
            .reveals
            .binary_search_by(|r| r.voter.as_slice().cmp(entry.voter.as_slice()))
        {
            Ok(_) => {} // already present (guarded above)
            Err(i) => draft.reveals.insert(i, entry),
        }
        STATUS_OK
    }

    /// Rounds currently open for reveals — what a voter polls to know which `α`
    /// to prove over and by when. Ascending by `round`. Empty when no committee
    /// round is in flight (including the entire no-committee case).
    #[msg]
    async fn open_rounds(&self) -> Vec<OpenRound> {
        self.pending
            .iter()
            .map(|d| OpenRound {
                round: d.round,
                alpha: d.alpha,
                open_slot: d.open_slot,
                fold_epoch: d.fold_epoch,
            })
            .collect()
    }

    /// The committee proof material for a folded round, if still retained — the
    /// inputs to [`verify_combine`]. `None` before the round folded, once pruned,
    /// or for the genesis round (which carries no committee). Empty `reveals`
    /// marks a degraded round (folded on the leader entropy).
    #[msg]
    async fn round_proofs(&self, round: u64) -> Option<RoundProofSet> {
        self.proofs.iter().find(|p| p.round == round).cloned()
    }
}

impl Chronos {
    /// Open a fresh round for committee reveals at an epoch boundary. The
    /// authorized+enrolled committee is **snapshotted now**, before `α` is
    /// consumable, so a voter cannot re-enrol a favourable key once the input is
    /// known. An empty snapshot ⇒ `fold_epoch == epoch` (fold immediately);
    /// otherwise the round waits [`REVEAL_WINDOW_EPOCHS`].
    fn open_round(&mut self, slot: u64, epoch: u64) {
        let round = self.current_round + self.pending.len() as u64 + 1;
        let prev = self.current_beacon;
        let alpha = derive_alpha(&self.domain, &prev, round);
        let snapshot: Vec<VoterKey> = self
            .pubkeys
            .iter()
            .filter(|vk| self.authorized.binary_search(&vk.voter).is_ok())
            .cloned()
            .collect();
        let fold_epoch = if snapshot.is_empty() {
            epoch
        } else {
            epoch + REVEAL_WINDOW_EPOCHS
        };
        self.pending.push(RoundDraft {
            round,
            open_slot: slot,
            fold_epoch,
            alpha,
            snapshot,
            reveals: Vec::new(),
        });
    }

    /// Fold a due round into the beacon chain: combine its committee reveals
    /// ([`combine_betas`]) into the round entropy, or fall back to the leader
    /// `fallback_entropy` for a degraded (zero-reveal) round. The round's `slot`
    /// is its open slot — strictly ascending across rounds, so [`verify_chain`]
    /// holds. By the contiguity invariant the draft's `round` equals
    /// `current_round + 1`.
    fn fold_round(&mut self, draft: RoundDraft, fallback_entropy: &[u8; ENTROPY_LEN]) {
        let round = self.current_round + 1;
        let prev = self.current_beacon;
        let (entropy, reveals) = if draft.reveals.is_empty() {
            (*fallback_entropy, Vec::new())
        } else {
            let betas: Vec<Vec<u8>> = draft.reveals.iter().map(|r| r.beta.clone()).collect();
            let reveals = draft
                .reveals
                .iter()
                .map(|r| RevealProof {
                    voter: r.voter.clone(),
                    pubkey: r.pubkey,
                    proof: r.proof.clone(),
                })
                .collect();
            (combine_betas(&self.domain, &betas), reveals)
        };
        let slot = draft.open_slot;
        let beacon = derive_beacon(&self.domain, &prev, round, slot, &entropy);
        self.current_round = round;
        self.current_beacon = beacon;
        self.history.push(BeaconRound {
            round,
            slot,
            prev,
            entropy,
            beacon,
        });
        if self.history.len() > MAX_HISTORY {
            self.history.remove(0);
        }
        self.proofs.push(RoundProofSet {
            round,
            alpha: draft.alpha,
            reveals,
        });
        if self.proofs.len() > MAX_HISTORY {
            self.proofs.remove(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    fn chronos() -> Chronos {
        Chronos::new()
    }

    /// Handler futures never await anything external, so a single poll with a
    /// no-op waker resolves them (this crate is its own workspace, so the
    /// std-gated `vos::block_on` isn't available).
    fn run<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            fn noop(_: *const ()) {}
            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, noop, noop, noop),
            )
        }
        let waker = unsafe { Waker::from_raw(raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("actor handler future was not immediately ready"),
        }
    }

    fn dispatch<M>(c: &mut Chronos, msg: M) -> <Chronos as Message<M>>::Output
    where
        Chronos: Message<M>,
    {
        let mut ctx: vos::Context<Chronos> = vos::Context::new(ServiceId(0));
        run(<Chronos as Message<M>>::handle(c, msg, &mut ctx))
    }

    /// A valid VRF public key for a test seed, as wire bytes.
    fn pk_bytes(seed: u8) -> [u8; 32] {
        let (_sk, pk) = vrf::keypair_from_seed(&[seed; 32]);
        pk.to_bytes()
    }

    const VOTER_A: &[u8] = b"peer-A-multihash";
    const VOTER_B: &[u8] = b"peer-B-multihash";

    const DOMAIN: &[u8] = b"space-42";

    fn init(c: &mut Chronos) -> u8 {
        dispatch(
            c,
            Init {
                domain: DOMAIN.to_vec(),
            },
        )
    }

    fn advance_to(c: &mut Chronos, slot: u64, entropy: [u8; 32]) -> AdvanceOutcome {
        dispatch(
            c,
            Advance {
                slot,
                entropy: entropy.to_vec(),
            },
        )
    }

    /// Fold epoch `n` by advancing to its first slot — a clean one-round-per-fold
    /// helper for the chain tests (round `n` lands at slot `n * SLOTS_PER_EPOCH`).
    fn fold(c: &mut Chronos, n: u64, entropy: [u8; 32]) -> AdvanceOutcome {
        advance_to(c, n * SLOTS_PER_EPOCH, entropy)
    }

    #[test]
    fn genesis_is_a_verifiable_public_anchor() {
        let mut c = chronos();
        assert_eq!(init(&mut c), STATUS_OK);
        let g = dispatch(&mut c, Current).expect("genesis round exists");
        assert_eq!(g.round, 0);
        assert_eq!(g.slot, 0);
        assert_eq!(g.prev, [0u8; 32]);
        assert_eq!(g.entropy, [0u8; 32]);
        assert!(verify_round(DOMAIN, &g), "genesis must verify");
        assert_eq!(dispatch(&mut c, Now), 0, "clock starts at the era anchor");
        // Recomputable by any holder of the domain alone.
        assert_eq!(g.beacon, derive_beacon(DOMAIN, &[0u8; 32], 0, 0, &[0u8; 32]));
    }

    #[test]
    fn init_is_one_shot() {
        let mut c = chronos();
        assert_eq!(init(&mut c), STATUS_OK);
        assert_eq!(init(&mut c), STATUS_ALREADY_INITIALIZED);
    }

    #[test]
    fn advance_before_init_is_rejected() {
        let mut c = chronos();
        let out = advance_to(&mut c, 1, [1u8; 32]);
        assert_eq!(out.status, STATUS_NOT_INITIALIZED);
    }

    #[test]
    fn advance_rejects_wrong_length_entropy() {
        let mut c = chronos();
        init(&mut c);
        let out = dispatch(
            &mut c,
            Advance {
                slot: SLOTS_PER_EPOCH,
                entropy: vec![1u8; 16],
            },
        );
        assert_eq!(out.status, STATUS_INVALID_INPUT);
        // Neither the clock nor the chain moved.
        assert_eq!(dispatch(&mut c, Now), 0);
        assert_eq!(dispatch(&mut c, Round), 0);
    }

    #[test]
    fn now_advances_and_is_strictly_monotone() {
        let mut c = chronos();
        init(&mut c);
        let out = advance_to(&mut c, 1, [1u8; 32]);
        assert_eq!(out.status, STATUS_OK);
        assert_eq!(dispatch(&mut c, Now), 1);

        // A backward or equal slot is rejected and changes nothing.
        assert_eq!(advance_to(&mut c, 1, [2u8; 32]).status, STATUS_STALE_SLOT);
        assert_eq!(advance_to(&mut c, 0, [2u8; 32]).status, STATUS_STALE_SLOT);
        assert_eq!(dispatch(&mut c, Now), 1);
    }

    #[test]
    fn advance_within_an_epoch_stamps_the_clock_without_folding() {
        let mut c = chronos();
        init(&mut c);
        // The establishing advance into a fresh epoch folds round 1.
        let first = advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
        assert!(first.folded);
        assert_eq!(first.round, 1);

        // Subsequent slots within the same epoch only move the clock.
        let head_before = dispatch(&mut c, Current).unwrap();
        for s in 1..SLOTS_PER_EPOCH {
            let out = advance_to(&mut c, SLOTS_PER_EPOCH + s, [9u8; 32]);
            assert_eq!(out.status, STATUS_OK);
            assert!(!out.folded, "within-epoch advance must not fold");
            assert_eq!(out.round, 1, "round unchanged within the epoch");
        }
        assert_eq!(dispatch(&mut c, Now), 2 * SLOTS_PER_EPOCH - 1);
        // The chain head is untouched by the within-epoch ticks.
        assert_eq!(dispatch(&mut c, Current).unwrap(), head_before);

        // Crossing into the next epoch folds round 2.
        let next = advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [2u8; 32]);
        assert!(next.folded);
        assert_eq!(next.round, 2);
    }

    #[test]
    fn establishing_advance_may_leap_then_cap_applies() {
        let mut c = chronos();
        init(&mut c);
        // From the slot-0 era anchor, a single advance may jump arbitrarily far.
        let far = 10 * MAX_SLOT_JUMP;
        let out = advance_to(&mut c, far, [1u8; 32]);
        assert_eq!(out.status, STATUS_OK);
        assert_eq!(dispatch(&mut c, Now), far);

        // Now the clock is established: a leap beyond the cap is rejected.
        let over = far + MAX_SLOT_JUMP + 1;
        assert_eq!(
            advance_to(&mut c, over, [2u8; 32]).status,
            STATUS_SLOT_JUMP_TOO_LARGE
        );
        assert_eq!(dispatch(&mut c, Now), far, "a rejected leap changes nothing");

        // Exactly at the cap is accepted.
        let at_cap = far + MAX_SLOT_JUMP;
        assert_eq!(advance_to(&mut c, at_cap, [2u8; 32]).status, STATUS_OK);
        assert_eq!(dispatch(&mut c, Now), at_cap);
    }

    #[test]
    fn chain_advances_and_links_and_verifies() {
        let mut c = chronos();
        init(&mut c);
        let mut prev = dispatch(&mut c, Current).unwrap().beacon;
        for i in 1..=5u64 {
            let entropy = [i as u8; 32];
            let out = fold(&mut c, i, entropy);
            assert_eq!(out.status, STATUS_OK);
            assert!(out.folded);
            assert_eq!(out.round, i);
            let row = dispatch(&mut c, RoundAt { round: i }).unwrap();
            assert_eq!(row.prev, prev, "each round must link to its predecessor");
            assert_eq!(row.slot, i * SLOTS_PER_EPOCH);
            assert!(verify_round(DOMAIN, &row), "round {i} must verify");
            assert_eq!(out.beacon, row.beacon);
            prev = row.beacon;
        }
        assert_eq!(dispatch(&mut c, Round), 5);
    }

    #[test]
    fn same_domain_and_inputs_is_deterministic_distinct_domain_diverges() {
        let mut a = chronos();
        let mut b = chronos();
        init(&mut a);
        init(&mut b);
        let e = [7u8; 32];
        assert_eq!(fold(&mut a, 1, e).beacon, fold(&mut b, 1, e).beacon);

        // A different domain forks the whole chain from genesis.
        let mut d = chronos();
        dispatch(
            &mut d,
            Init {
                domain: b"other-space".to_vec(),
            },
        );
        assert_ne!(
            dispatch(&mut d, Current).unwrap().beacon,
            dispatch(&mut a, Current).unwrap().beacon,
        );
    }

    #[test]
    fn tampering_with_a_stored_round_is_detectable() {
        let mut c = chronos();
        init(&mut c);
        fold(&mut c, 1, [3u8; 32]);
        let mut row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        assert!(verify_round(DOMAIN, &row));
        // Flip the entropy: the stored beacon no longer matches its inputs.
        row.entropy[0] ^= 0xFF;
        assert!(
            !verify_round(DOMAIN, &row),
            "a tampered round must fail verification"
        );
        // Relabelling the slot is equally detectable (slot is bound into the hash).
        let mut row2 = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        row2.slot ^= 0xFF;
        assert!(!verify_round(DOMAIN, &row2), "a relabelled slot must fail");
    }

    #[test]
    fn latest_final_lags_the_live_head() {
        let mut c = chronos();
        init(&mut c);
        // Before enough rounds accumulate, there is no finalized value yet —
        // a consumer gets None (⇒ no hedge ⇒ no behavior change). latest_final
        // becomes Some only once history is deeper than FINALIZED_LAG, i.e.
        // after FINALIZED_LAG folds beyond genesis.
        assert!(dispatch(&mut c, LatestFinal).is_none());
        for k in 1..FINALIZED_LAG as u64 {
            fold(&mut c, k, [k as u8; 32]);
            assert!(
                dispatch(&mut c, LatestFinal).is_none(),
                "still within the lag window"
            );
        }
        // The FINALIZED_LAG-th fold makes genesis the finalized head.
        fold(&mut c, FINALIZED_LAG as u64, [42u8; 32]);
        assert_eq!(
            dispatch(&mut c, LatestFinal).unwrap().round,
            0,
            "the first finalized round is genesis"
        );

        // From here on latest_final trails the live head by exactly the lag.
        for i in (FINALIZED_LAG as u64 + 1)..=(FINALIZED_LAG as u64 + 3) {
            fold(&mut c, i, [i as u8; 32]);
            let f = dispatch(&mut c, LatestFinal).unwrap();
            let head = dispatch(&mut c, Current).unwrap();
            assert_eq!(
                f.round,
                head.round - FINALIZED_LAG as u64,
                "latest_final lags the head by exactly FINALIZED_LAG folds"
            );
        }
    }

    #[test]
    fn randomness_at_returns_the_finalized_epoch_floor() {
        let mut c = chronos();
        init(&mut c);
        // Fold a contiguous run of epochs 1..=8 (round n at epoch n).
        for i in 1..=8u64 {
            fold(&mut c, i, [i as u8; 32]);
        }
        // A well-buried epoch returns its own round.
        let r = dispatch(&mut c, RandomnessAt { epoch: 3 }).unwrap();
        assert_eq!(r.round, 3);
        assert_eq!(r.slot / SLOTS_PER_EPOCH, 3);
        assert!(verify_round(DOMAIN, &r));

        // The freshest epochs (within the lag) are not yet final → None.
        let head_epoch = dispatch(&mut c, Epoch);
        assert!(
            dispatch(&mut c, RandomnessAt { epoch: head_epoch }).is_none(),
            "the live head epoch is not finalized"
        );

        // An epoch the clock skipped floors to the most recent earlier round.
        let mut d = chronos();
        init(&mut d);
        fold(&mut d, 1, [1u8; 32]); // epoch 1
        fold(&mut d, 5, [5u8; 32]); // epoch 5 (skipped 2,3,4)
        fold(&mut d, 6, [6u8; 32]);
        fold(&mut d, 7, [7u8; 32]); // pushes epoch 5 behind the lag
        let floored = dispatch(&mut d, RandomnessAt { epoch: 3 }).unwrap();
        assert_eq!(floored.slot / SLOTS_PER_EPOCH, 1, "epoch 3 floors to epoch 1");

        // Epoch 0 (genesis) is retained and finalized here.
        assert!(dispatch(&mut d, RandomnessAt { epoch: 0 }).is_some());
    }

    #[test]
    fn history_is_bounded_and_keeps_the_head() {
        let mut c = chronos();
        init(&mut c);
        for i in 1..=(MAX_HISTORY as u64 + 50) {
            fold(&mut c, i, [(i % 251) as u8; 32]);
        }
        // The chain head is always available and correct.
        let head = dispatch(&mut c, Current).unwrap();
        assert_eq!(head.round, MAX_HISTORY as u64 + 50);
        assert!(verify_round(DOMAIN, &head));
        // The earliest rounds were pruned.
        assert!(
            dispatch(&mut c, RoundAt { round: 0 }).is_none(),
            "genesis should be pruned"
        );
        // A recent round is still retained and verifies.
        let recent = dispatch(
            &mut c,
            RoundAt {
                round: head.round - 1,
            },
        )
        .unwrap();
        assert!(verify_round(DOMAIN, &recent));
    }

    #[test]
    fn at_returns_none_past_the_head() {
        let mut c = chronos();
        init(&mut c);
        fold(&mut c, 1, [1u8; 32]);
        assert!(dispatch(&mut c, RoundAt { round: 99 }).is_none());
    }

    #[test]
    fn range_returns_an_ascending_verifiable_window() {
        let mut c = chronos();
        init(&mut c);
        for i in 1..=10u64 {
            fold(&mut c, i, [i as u8; 32]);
        }
        let window = dispatch(&mut c, Range { from: 3, limit: 4 });
        let rounds: Vec<u64> = window.iter().map(|r| r.round).collect();
        assert_eq!(rounds, alloc::vec![3, 4, 5, 6]);
        assert!(verify_chain(DOMAIN, &window), "a fetched window must verify");

        // From genesis through the head, clamped to MAX_RANGE.
        let all = dispatch(
            &mut c,
            Range {
                from: 0,
                limit: 1000,
            },
        );
        assert_eq!(all.first().unwrap().round, 0);
        assert_eq!(all.last().unwrap().round, 10);
        assert!(verify_chain(DOMAIN, &all));
    }

    #[test]
    fn range_is_clamped_and_empty_past_the_head() {
        let mut c = chronos();
        init(&mut c);
        for i in 1..=5u64 {
            fold(&mut c, i, [i as u8; 32]);
        }
        assert_eq!(
            dispatch(
                &mut c,
                Range {
                    from: 99,
                    limit: 10
                }
            )
            .len(),
            0
        );
        assert_eq!(dispatch(&mut c, Range { from: 0, limit: 0 }).len(), 0);
        assert!(
            dispatch(
                &mut c,
                Range {
                    from: 0,
                    limit: u32::MAX
                }
            )
            .len()
                <= MAX_RANGE as usize
        );
    }

    #[test]
    fn verify_chain_rejects_tamper_break_and_gaps() {
        let mut c = chronos();
        init(&mut c);
        for i in 1..=4u64 {
            fold(&mut c, i, [i as u8; 32]);
        }
        let good = dispatch(&mut c, Range { from: 1, limit: 4 });
        assert!(verify_chain(DOMAIN, &good));

        // Tampered beacon bytes in the middle.
        let mut tampered = good.clone();
        tampered[1].beacon[0] ^= 0xFF;
        assert!(!verify_chain(DOMAIN, &tampered), "tamper must fail");

        // Broken linkage: a valid-on-its-own round spliced out of sequence.
        let mut broken = good.clone();
        broken[2].prev[0] ^= 0xFF; // no longer points at rounds[1].beacon
        // recompute its own beacon so verify_round passes in isolation...
        broken[2].beacon = derive_beacon(
            DOMAIN,
            &broken[2].prev,
            broken[2].round,
            broken[2].slot,
            &broken[2].entropy,
        );
        assert!(
            verify_round(DOMAIN, &broken[2]),
            "the spliced round verifies alone"
        );
        assert!(
            !verify_chain(DOMAIN, &broken),
            "but the chain linkage must fail"
        );

        // Non-contiguous round numbers.
        let gapped = alloc::vec![good[0].clone(), good[2].clone()];
        assert!(
            !verify_chain(DOMAIN, &gapped),
            "a round-number gap must fail"
        );

        // Empty and singleton.
        assert!(verify_chain(DOMAIN, &[]));
        assert!(verify_chain(DOMAIN, &good[0..1]));
    }

    #[test]
    fn verify_chain_anchors_round_zero_to_genesis() {
        // A fabricated round-0 row whose beacon correctly hashes its own
        // (non-zero) inputs passes verify_round in isolation, but must NOT pass
        // verify_chain: round 0 is only ever the canonical genesis. Without the
        // anchor an untrusted server could hand a consumer a whole chain hanging
        // off a forged origin.
        let forged_prev = [9u8; 32];
        let forged_entropy = [7u8; 32];
        let forged_slot = 99u64;
        let forged = BeaconRound {
            round: 0,
            slot: forged_slot,
            prev: forged_prev,
            entropy: forged_entropy,
            beacon: derive_beacon(DOMAIN, &forged_prev, 0, forged_slot, &forged_entropy),
        };
        assert!(
            verify_round(DOMAIN, &forged),
            "the forged origin verifies alone"
        );
        assert!(
            !verify_chain(DOMAIN, &[forged]),
            "but verify_chain must reject a non-genesis round 0",
        );

        // The real genesis still passes.
        let mut c = chronos();
        init(&mut c);
        let genesis = dispatch(&mut c, Current).unwrap();
        assert!(verify_chain(DOMAIN, &[genesis]));
    }

    // ── Committee enrolment ────────────────────────────────────────

    fn set_committee(c: &mut Chronos, voters: &[&[u8]]) -> u8 {
        let encoded = encode_committee(&voters.iter().map(|v| v.to_vec()).collect::<Vec<_>>());
        dispatch(c, SetCommittee { voters: encoded })
    }

    /// Enrol `voter`'s key derived from `seed`.
    fn enrol(c: &mut Chronos, voter: &[u8], seed: u8) -> u8 {
        dispatch(
            c,
            EnrolVoter {
                voter_id: voter.to_vec(),
                pubkey: pk_bytes(seed).to_vec(),
            },
        )
    }

    /// Compute and post `voter`'s reveal for `round` over `alpha`, using the key
    /// derived from `seed`.
    fn reveal_as(c: &mut Chronos, voter: &[u8], round: u64, seed: u8, alpha: [u8; 32]) -> u8 {
        let (sk, pk) = vrf::keypair_from_seed(&[seed; 32]);
        let proof = vrf::prove(&sk, &pk, &alpha);
        dispatch(
            c,
            Reveal {
                voter_id: voter.to_vec(),
                round,
                proof: proof.to_bytes().to_vec(),
            },
        )
    }

    /// The `alpha` of the single currently-open round (panics if not exactly one).
    fn open_alpha(c: &mut Chronos) -> [u8; 32] {
        let open = dispatch(c, OpenRounds);
        assert_eq!(open.len(), 1, "expected exactly one open round");
        open[0].alpha
    }

    /// An authorized voter enrols its key; the committee then exposes it.
    #[test]
    fn authorized_voter_enrols_and_appears_in_committee() {
        let mut c = chronos();
        init(&mut c);
        assert_eq!(set_committee(&mut c, &[VOTER_A]), STATUS_OK);
        assert_eq!(enrol(&mut c, VOTER_A, 1), STATUS_OK);
        let committee = dispatch(&mut c, Committee);
        assert_eq!(committee.len(), 1);
        assert_eq!(committee[0].voter, VOTER_A);
        assert_eq!(committee[0].pubkey, pk_bytes(1));
    }

    /// Enrolment is refused for a voter the leader has not authorized.
    #[test]
    fn enrol_rejects_unauthorized_voter() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        assert_eq!(enrol(&mut c, VOTER_B, 2), STATUS_NOT_A_VOTER);
        assert!(dispatch(&mut c, Committee).is_empty());
    }

    /// A non-canonical / wrong-length public key is rejected.
    #[test]
    fn enrol_rejects_invalid_pubkey() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        assert_eq!(
            dispatch(
                &mut c,
                EnrolVoter {
                    voter_id: VOTER_A.to_vec(),
                    pubkey: alloc::vec![0xFFu8; 32], // not a canonical Ristretto point
                },
            ),
            STATUS_INVALID_INPUT
        );
        assert_eq!(
            dispatch(
                &mut c,
                EnrolVoter {
                    voter_id: VOTER_A.to_vec(),
                    pubkey: alloc::vec![1u8; 31], // wrong length
                },
            ),
            STATUS_INVALID_INPUT
        );
    }

    /// First-wins binding: a same-key re-enrol is idempotent, but binding a
    /// different key to an already-enrolled voter is refused (no silent override).
    #[test]
    fn enrol_is_first_wins() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        assert_eq!(enrol(&mut c, VOTER_A, 1), STATUS_OK);
        // Re-enrol the SAME key — idempotent (the feeder re-fires this).
        assert_eq!(enrol(&mut c, VOTER_A, 1), STATUS_OK);
        assert_eq!(dispatch(&mut c, Committee).len(), 1);
        // A DIFFERENT key is locked out.
        assert_eq!(enrol(&mut c, VOTER_A, 9), STATUS_KEY_LOCKED);
        assert_eq!(
            dispatch(&mut c, Committee)[0].pubkey,
            pk_bytes(1),
            "the first key stands"
        );
    }

    /// Dropping a voter from the authorized set prunes its enrolled key.
    #[test]
    fn set_committee_prunes_dropped_voters() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);
        assert_eq!(dispatch(&mut c, Committee).len(), 2);
        // Drop B: its key is pruned from the committee.
        set_committee(&mut c, &[VOTER_A]);
        let committee = dispatch(&mut c, Committee);
        assert_eq!(committee.len(), 1);
        assert_eq!(committee[0].voter, VOTER_A);
    }

    // ── Committee round protocol ───────────────────────────────────

    /// With a committee configured, a round opens on the epoch boundary, stays
    /// open across its reveal window collecting reveals, and folds the XOR-
    /// combine of the revealed VRF outputs — no party chose the entropy.
    #[test]
    fn committee_round_collects_reveals_and_folds_the_combine() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);

        // Crossing into epoch 1 opens round 1 — but a committee round does NOT
        // fold immediately; it waits the reveal window.
        advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
        let alpha = open_alpha(&mut c);
        assert_eq!(dispatch(&mut c, OpenRounds)[0].round, 1);
        assert_eq!(
            dispatch(&mut c, OpenRounds)[0].fold_epoch,
            1 + REVEAL_WINDOW_EPOCHS
        );
        assert_eq!(dispatch(&mut c, Round), 0, "round 1 has not folded yet");

        // Both voters reveal while the window is open.
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), STATUS_OK);
        assert_eq!(reveal_as(&mut c, VOTER_B, 1, 2, alpha), STATUS_OK);

        // Drive the clock to the fold epoch.
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [9u8; 32]);
        let out = advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [9u8; 32]);
        assert!(out.folded);
        assert_eq!(dispatch(&mut c, Round), 1);

        // The round entropy is exactly the committee combine of the two βs.
        let (ska, pka) = vrf::keypair_from_seed(&[1u8; 32]);
        let (skb, pkb) = vrf::keypair_from_seed(&[2u8; 32]);
        let ba = vrf::output(&vrf::prove(&ska, &pka, &alpha)).to_vec();
        let bb = vrf::output(&vrf::prove(&skb, &pkb, &alpha)).to_vec();
        let expected = combine_betas(DOMAIN, &[ba, bb]);
        let row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        assert_eq!(row.entropy, expected, "round folds the committee XOR-combine");
        assert!(verify_round(DOMAIN, &row), "the folded round still verifies");

        // round_proofs carries both reveals for independent verification.
        let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
        assert_eq!(proofs.alpha, alpha);
        assert_eq!(proofs.reveals.len(), 2);
    }

    /// A single honest, unpredictable reveal already randomises the round — the
    /// security floor of the committee combine. (The residual is the **1-bit
    /// last-revealer**: the last voter to reveal sees the others and may withhold
    /// its own fixed contribution, choosing between two outcomes — bounded, and
    /// blunted by the lagged read. It cannot grind beyond that one bit because no
    /// β can be *chosen*.)
    #[test]
    fn one_honest_reveal_randomises_the_round() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        enrol(&mut c, VOTER_A, 5);
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
        let alpha = open_alpha(&mut c);
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 5, alpha), STATUS_OK);
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]);
        let row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        // The entropy is the VRF-derived combine, NOT the leader's zero input.
        assert_ne!(row.entropy, [0u8; 32]);
        let (sk, pk) = vrf::keypair_from_seed(&[5u8; 32]);
        let beta = vrf::output(&vrf::prove(&sk, &pk, &alpha)).to_vec();
        assert_eq!(row.entropy, combine_betas(DOMAIN, &[beta]));
    }

    /// The committee key is snapshotted when a round opens: re-enrolling a
    /// different key afterward cannot change which key that round verifies
    /// against (anti key-shopping — a voter cannot wait to see `α` then pick a
    /// favourable key).
    #[test]
    fn open_round_snapshots_the_committee_key() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        enrol(&mut c, VOTER_A, 1); // K1
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]); // opens round 1, snapshots K1
        let alpha = open_alpha(&mut c);

        // First-wins already refuses to rebind a different key K2...
        assert_eq!(enrol(&mut c, VOTER_A, 7), STATUS_KEY_LOCKED);
        // ...and independently, the round is pinned to its OPEN-TIME snapshot key
        // K1: a reveal computed under K2 (seed 7) fails to verify, while a reveal
        // under the snapshot key K1 (seed 1) succeeds.
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 7, alpha), STATUS_BAD_PROOF);
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), STATUS_OK);
    }

    /// A committee round that collects no reveals by its deadline folds the
    /// leader's entropy — a degraded round (fairness-trusted), marked by an empty
    /// `round_proofs` set and protected by the lagged read.
    #[test]
    fn committee_round_with_no_reveals_folds_the_fallback() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        enrol(&mut c, VOTER_A, 1);
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]); // open r1 (waits)
        assert_eq!(dispatch(&mut c, Round), 0);
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        let fallback = [0x42u8; 32];
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, fallback); // folds r1 with this entropy
        assert_eq!(dispatch(&mut c, Round), 1);
        let row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        assert_eq!(row.entropy, fallback, "zero-reveal round folds the leader entropy");
        let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
        assert!(proofs.reveals.is_empty(), "a degraded round carries no reveals");
    }

    /// Reveals are rejected for an unopened/folded round, for a non-committee
    /// caller, and a bad proof; a duplicate reveal is an idempotent no-op.
    #[test]
    fn reveal_rejections_and_idempotence() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        enrol(&mut c, VOTER_A, 1);

        // No round open yet.
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, [0u8; 32]), STATUS_NO_SUCH_ROUND);

        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
        let alpha = open_alpha(&mut c);

        // A voter not in the round's committee snapshot.
        assert_eq!(
            dispatch(
                &mut c,
                Reveal {
                    voter_id: VOTER_B.to_vec(),
                    round: 1,
                    proof: alloc::vec![0u8; vrf::PROOF_LEN],
                },
            ),
            STATUS_NOT_A_VOTER
        );
        // A wrong-length / malformed proof from a real committee member.
        assert_eq!(
            dispatch(
                &mut c,
                Reveal {
                    voter_id: VOTER_A.to_vec(),
                    round: 1,
                    proof: alloc::vec![0u8; 10],
                },
            ),
            STATUS_INVALID_INPUT
        );

        // Valid reveal, then a duplicate (idempotent OK, no second β counted).
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), STATUS_OK);
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), STATUS_OK);

        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]); // folds r1
        let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
        assert_eq!(proofs.reveals.len(), 1, "a duplicate reveal is not double-counted");
        // After the fold the round is gone.
        assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), STATUS_NO_SUCH_ROUND);
    }

    /// Removing a node from the committee (registry voter dropped) stops its
    /// reveals from the next opened round, because the snapshot is taken fresh
    /// each open.
    #[test]
    fn dropping_a_voter_excludes_it_from_future_rounds() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);
        // Round 1 snapshots {A, B}.
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
        // Drop B before round 2 opens.
        set_committee(&mut c, &[VOTER_A]);
        // Round 2 opens at epoch 2 snapshotting {A} only.
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        let r2_alpha = dispatch(&mut c, OpenRounds)
            .iter()
            .find(|o| o.round == 2)
            .unwrap()
            .alpha;
        // B can no longer reveal for round 2.
        assert_eq!(reveal_as(&mut c, VOTER_B, 2, 2, r2_alpha), STATUS_NOT_A_VOTER);
        // A still can.
        assert_eq!(reveal_as(&mut c, VOTER_A, 2, 1, r2_alpha), STATUS_OK);
    }

    // ── Independent combine verification ───────────────────────────

    /// Build and fold committee round 1 with voters A (seed 1) and B (seed 2)
    /// both revealing; return its `(BeaconRound, RoundProofSet)`.
    fn folded_round_ab() -> (BeaconRound, RoundProofSet) {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
        let alpha = open_alpha(&mut c);
        reveal_as(&mut c, VOTER_A, 1, 1, alpha);
        reveal_as(&mut c, VOTER_B, 1, 2, alpha);
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]);
        let round = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
        (round, proofs)
    }

    /// A genuine committee round verifies against its proof set.
    #[test]
    fn verify_combine_accepts_a_genuine_committee_round() {
        let (round, proofs) = folded_round_ab();
        assert_eq!(proofs.reveals.len(), 2);
        assert!(verify_combine(DOMAIN, &round, &proofs));
    }

    /// A forged proof byte breaks verification (the proof fails to verify, or its
    /// β changes so the combine no longer matches).
    #[test]
    fn verify_combine_rejects_a_forged_proof() {
        let (round, mut proofs) = folded_round_ab();
        proofs.reveals[0].proof[0] ^= 0xFF;
        assert!(!verify_combine(DOMAIN, &round, &proofs));
    }

    /// Tampering the stored combine (round entropy) is detectable.
    #[test]
    fn verify_combine_rejects_a_tampered_combine() {
        let (mut round, proofs) = folded_round_ab();
        round.entropy[0] ^= 0xFF;
        assert!(!verify_combine(DOMAIN, &round, &proofs));
    }

    /// Relabelling the round's `α` invalidates every proof (they were made over
    /// the real α), so the round no longer verifies.
    #[test]
    fn verify_combine_rejects_a_wrong_alpha() {
        let (round, mut proofs) = folded_round_ab();
        proofs.alpha[0] ^= 0xFF;
        assert!(!verify_combine(DOMAIN, &round, &proofs));
    }

    /// Swapping in a *different but individually valid* reveal (a real VRF proof
    /// under another key over the same α) still fails: its β differs, so the
    /// combine no longer equals the committed entropy. A self-consistent forgery
    /// cannot reproduce the round's value.
    #[test]
    fn verify_combine_rejects_a_swapped_valid_reveal() {
        let (round, mut proofs) = folded_round_ab();
        let (sk_c, pk_c) = vrf::keypair_from_seed(&[99u8; 32]);
        let proof_c = vrf::prove(&sk_c, &pk_c, &proofs.alpha);
        assert!(
            vrf::verify(&pk_c, &proofs.alpha, &proof_c).is_some(),
            "the swapped-in proof is itself valid"
        );
        proofs.reveals[0].pubkey = pk_c.to_bytes();
        proofs.reveals[0].proof = proof_c.to_bytes().to_vec();
        assert!(
            !verify_combine(DOMAIN, &round, &proofs),
            "a valid-but-different reveal still breaks the committed combine"
        );
    }

    /// A degraded (zero-reveal) round has nothing committee-verifiable —
    /// `verify_combine` returns false — but its hash linkage still holds.
    #[test]
    fn verify_combine_rejects_a_degraded_round_but_verify_round_holds() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A]);
        enrol(&mut c, VOTER_A, 1);
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]); // open r1 (no reveals come)
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0x42u8; 32]); // fold degraded
        let round = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
        let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
        assert!(proofs.reveals.is_empty());
        assert!(
            !verify_combine(DOMAIN, &round, &proofs),
            "no committee combine to verify for a degraded round"
        );
        assert!(
            verify_round(DOMAIN, &round),
            "but the round's hash linkage still holds (hash-chain tamper-evidence)"
        );
    }

    /// Fold round 1 (committee {A, B}) with exactly `revealers` revealing; return
    /// the folded round entropy.
    fn fold_with_revealers(revealers: &[(&[u8], u8)]) -> [u8; 32] {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);
        advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
        let alpha = open_alpha(&mut c);
        for (v, seed) in revealers {
            reveal_as(&mut c, v, 1, *seed, alpha);
        }
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]);
        dispatch(&mut c, RoundAt { round: 1 }).unwrap().entropy
    }

    /// The raft soft-restart re-commits the rebuilt state and short-circuits
    /// only when its bytes are UNCHANGED. So the state encoding must be
    /// byte-deterministic for the same logical value — otherwise every commit
    /// triggers a soft-restart that commits a "different" state, looping forever
    /// (unzeroed rkyv padding between mixed-size fields is the classic cause).
    #[test]
    fn state_encoding_is_byte_deterministic() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);
        advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
        let alpha = open_alpha(&mut c);
        reveal_as(&mut c, VOTER_A, 1, 1, alpha);
        reveal_as(&mut c, VOTER_B, 1, 2, alpha);
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [9u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [9u8; 32]);

        let a = vos::Encode::encode(&c);
        let b = vos::Encode::encode(&c);
        assert_eq!(a, b, "same state must encode to identical bytes");
        // And a decode→re-encode must reproduce the exact bytes (the soft-restart
        // replay path: rebuild state, re-encode, compare).
        let back = <Chronos as vos::Decode>::try_decode(&a).expect("round-trips");
        assert_eq!(vos::Encode::encode(&back), a, "decode→encode must be stable");
    }

    /// The runtime persists actor state with `Encode::encode` and reloads it
    /// through the **validating** `try_decode` (`lifecycle::load_or_create`); a
    /// decode failure silently resets the actor to genesis — and the runtime
    /// reloads on every committed raft index. So a fully-populated state
    /// (committee, an open draft with reveals, and folded proofs) MUST round-trip
    /// through that exact path, or the live actor wipes itself every commit.
    #[test]
    fn populated_state_round_trips_through_the_validating_codec() {
        let mut c = chronos();
        init(&mut c);
        set_committee(&mut c, &[VOTER_A, VOTER_B]);
        enrol(&mut c, VOTER_A, 1);
        enrol(&mut c, VOTER_B, 2);
        // Open round 1 (committee), collect reveals, then fold it so BOTH the
        // `pending` (still-open later rounds) and `proofs` (folded round 1) are
        // populated, plus `committee` + `history`.
        advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
        let alpha = open_alpha(&mut c);
        reveal_as(&mut c, VOTER_A, 1, 1, alpha);
        reveal_as(&mut c, VOTER_B, 1, 2, alpha);
        advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [9u8; 32]);
        advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [9u8; 32]); // folds round 1
        assert!(!dispatch(&mut c, OpenRounds).is_empty(), "expected open drafts");
        assert!(dispatch(&mut c, RoundProofs { round: 1 }).is_some(), "expected folded proofs");

        let bytes = vos::Encode::encode(&c);
        let mut back = <Chronos as vos::Decode>::try_decode(&bytes)
            .expect("populated state must survive the validating decode");

        assert_eq!(dispatch(&mut back, Now), dispatch(&mut c, Now));
        assert_eq!(dispatch(&mut back, Round), dispatch(&mut c, Round));
        assert_eq!(dispatch(&mut back, Committee).len(), 2);
        assert_eq!(
            dispatch(&mut back, RoundProofs { round: 1 }),
            dispatch(&mut c, RoundProofs { round: 1 }),
        );
        assert_eq!(
            dispatch(&mut back, OpenRounds),
            dispatch(&mut c, OpenRounds),
        );
    }

    /// The honest residual, made explicit. The combine of {A} differs from the
    /// combine of {A, B}, so the **last revealer** B — who sees the others'
    /// reveals and whose own β is fixed — can compute both outcomes and, by
    /// choosing to reveal or withhold, select between exactly **two** values:
    /// a one-bit last-revealer bias. It is *bounded*: B cannot reach any third
    /// value, because no β can be chosen (each is a deterministic VRF output).
    /// This residual is what the lagged finalized read (FINALIZED_LAG) blunts;
    /// removing the bit entirely needs threshold crypto or a VDF.
    #[test]
    fn last_revealer_has_a_one_bit_choice() {
        let only_a = fold_with_revealers(&[(VOTER_A, 1)]);
        let a_and_b = fold_with_revealers(&[(VOTER_A, 1), (VOTER_B, 2)]);
        assert_ne!(
            only_a, a_and_b,
            "the last revealer selects between exactly two outcomes"
        );
        // Order-independence: {A,B} and {B,A} reach the SAME value, so the last
        // revealer's lever is purely the include/withhold bit, not ordering.
        let b_and_a = fold_with_revealers(&[(VOTER_B, 2), (VOTER_A, 1)]);
        assert_eq!(a_and_b, b_and_a, "the combine is order-independent");
    }
}
