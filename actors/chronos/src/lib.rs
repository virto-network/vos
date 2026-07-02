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
//!
//! ## Module layout
//!
//! - [`consts`] — domain tags, cadence, and retention tunables.
//! - [`roles`] — the [`ChronosRole`] gate + [`CHRONOS_SPACE_ROLE_MAP`].
//! - [`rows`] — wire/state row types (`BeaconRound`, `VoterKey`,
//!   `AdvanceOutcome`, …).
//! - [`beacon`] — the pure hash-chain and VRF-combine derivations.
//! - [`committee`] — the voter-list wire codec.
//!
//! `Status` — the handler return type — lives here rather than in its own
//! module: every `#[msg]` handler below returns it, so it reads best kept next
//! to the actor it gates.
//!
//! Re-exports at the crate root keep the public ABI flat: callers
//! `use chronos::{ChronosRef, BeaconRound, Status, …}` without caring about
//! the internal module split.

pub mod beacon;
pub mod committee;
pub mod consts;
pub mod roles;
pub mod rows;

#[cfg(test)]
mod tests;

pub use beacon::{combine_betas, derive_alpha, derive_beacon, verify_chain, verify_combine, verify_round};
use beacon::{to_entropy, to_pubkey};
pub use committee::{MAX_COMMITTEE, decode_committee, encode_committee};
pub use consts::*;
pub use roles::{CHRONOS_SPACE_ROLE_MAP, ChronosRole};
pub use rows::{AdvanceOutcome, BeaconRound, OpenRound, RevealProof, RoundProofSet, VoterKey};
use rows::{RoundDraft, StoredReveal};

use vos::prelude::*;

// ── Status ────────────────────────────────────────────────────────

/// Return type for every `#[msg]` handler below. The `#[repr(u8)]`
/// discriminants are wire-stable — bumping the type or reordering variants
/// WILL shift the rkyv archive bytes and break peer nodes running older
/// builds.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// Entropy was not exactly [`ENTROPY_LEN`] bytes, or the domain was too
    /// large.
    InvalidInput = 1,
    /// `advance` was called before `init`.
    NotInitialized = 2,
    /// `init` was called on an already-initialised service (one-shot).
    AlreadyInitialized = 3,
    /// The proposed slot did not move the clock strictly forward (`slot <= now`).
    StaleSlot = 4,
    /// The proposed slot leapt more than [`MAX_SLOT_JUMP`] past the current
    /// slot on a non-establishing advance (the future-drift cap).
    SlotJumpTooLarge = 5,
    /// Reserved, unused. The committee handlers are authenticated
    /// cryptographically (a chronos handler runs on the raft apply path,
    /// where the originating caller is not preserved), so no handler
    /// returns a caller-based authorization error.
    Unauthorized = 6,
    /// The voter is not in the authorized committee ([`Chronos::set_committee`])
    /// — enrolment and reveals are only accepted from registry voters.
    NotAVoter = 7,
    /// A reveal named a round that is not currently open — it was never
    /// opened, or its reveal window already closed and it folded.
    NoSuchRound = 8,
    /// A reveal's VRF proof did not verify against the voter's enrolled key
    /// over the round's input `α`.
    BadProof = 9,
    /// An `enrol_voter` tried to bind a *different* key to a voter that
    /// already has one. The first key wins; there is no key rotation (see
    /// [`Chronos::enrol_voter`]).
    KeyLocked = 10,
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
    /// `Status::AlreadyInitialized` on a second call.
    #[msg(role = ChronosRole::Advancer)]
    async fn init(&mut self, domain: Vec<u8>) -> Status {
        if self.initialized {
            return Status::AlreadyInitialized;
        }
        if domain.len() > MAX_DOMAIN_BYTES {
            return Status::InvalidInput;
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
        Status::Ok
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
                status: Status::NotInitialized,
                slot: 0,
                round: 0,
                beacon: [0u8; 32],
                folded: false,
            };
        }
        let unchanged = |status: Status, this: &Self| AdvanceOutcome {
            status,
            slot: this.current_slot,
            round: this.current_round,
            beacon: this.current_beacon,
            folded: false,
        };

        // Strict monotonicity (anti-rewind / anti-replay of the clock).
        if slot <= self.current_slot {
            return unchanged(Status::StaleSlot, self);
        }
        // Future-drift cap. Exempt the establishing advance (current_slot == 0),
        // which legitimately jumps from the era anchor to the present in one step.
        if self.current_slot != 0 && slot > self.current_slot.saturating_add(MAX_SLOT_JUMP) {
            return unchanged(Status::SlotJumpTooLarge, self);
        }
        let Some(entropy) = to_entropy(&entropy) else {
            return unchanged(Status::InvalidInput, self);
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
            status: Status::Ok,
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
    async fn set_committee(&mut self, voters: Vec<u8>) -> Status {
        if !self.initialized {
            return Status::NotInitialized;
        }
        let Some(mut authorized) = decode_committee(&voters) else {
            return Status::InvalidInput;
        };
        authorized.sort();
        authorized.dedup();
        // Drop enrolled keys for voters no longer authorized (membership
        // shrank). Keeps `pubkeys ⊆ authorized` as an invariant.
        self.pubkeys
            .retain(|vk| authorized.binary_search(&vk.voter).is_ok());
        self.authorized = authorized;
        Status::Ok
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
    /// *different* key is refused ([`Status::KeyLocked`]), so an honest voter that
    /// enrols its deterministic node-key-derived key cannot be silently overridden
    /// (a same-key re-enrol is an idempotent no-op, as the feeder re-fires it);
    /// and (c) the VRF proof on every [`Self::reveal`], which only the key holder
    /// can forge. **Residual limitation:** a malicious party that
    /// front-runs an authorized voter's *first* enrol can bind its own key to that
    /// slot. The bias-resistance core is unaffected (no β can be forged), but it
    /// is committee griefing/Sybil within the authorized set; binding the pubkey
    /// in the registry at admit time (authenticated by the admin) closes it.
    #[msg]
    async fn enrol_voter(&mut self, voter_id: Vec<u8>, pubkey: Vec<u8>) -> Status {
        if !self.initialized {
            return Status::NotInitialized;
        }
        if self.authorized.binary_search(&voter_id).is_err() {
            return Status::NotAVoter;
        }
        let Some(pubkey) = to_pubkey(&pubkey) else {
            return Status::InvalidInput;
        };
        match self
            .pubkeys
            .binary_search_by(|vk| vk.voter.as_slice().cmp(voter_id.as_slice()))
        {
            Ok(i) => {
                if self.pubkeys[i].pubkey != pubkey {
                    return Status::KeyLocked; // first-wins: no silent override
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
        Status::Ok
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
    async fn reveal(&mut self, voter_id: Vec<u8>, round: u64, proof: Vec<u8>) -> Status {
        if !self.initialized {
            return Status::NotInitialized;
        }
        let Some(draft) = self.pending.iter_mut().find(|d| d.round == round) else {
            return Status::NoSuchRound;
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
            return Status::NotAVoter;
        };
        // Idempotent: a filled slot short-circuits before the VRF verify.
        if draft.reveals.iter().any(|r| r.voter == voter_id) {
            return Status::Ok;
        }
        let Some(pk) = vrf::PublicKey::from_bytes(&pubkey) else {
            return Status::InvalidInput; // snapshot key was validated at enrol; defensive
        };
        let Ok(proof_arr) = <[u8; vrf::PROOF_LEN]>::try_from(proof.as_slice()) else {
            return Status::InvalidInput;
        };
        let Some(parsed) = vrf::Proof::from_bytes(&proof_arr) else {
            return Status::InvalidInput;
        };
        let Some(beta) = vrf::verify(&pk, &draft.alpha, &parsed) else {
            return Status::BadProof;
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
        Status::Ok
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
