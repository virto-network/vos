//! cipher-clerk `LedgerState` over vos [`WitnessedLedger`]s — the
//! witness bridge the `#[provable]` clerk arc runs on
//! (`docs/plans/provable.md` W4).
//!
//! A provable clerk transition is a PURE VERIFIER: it receives, in its
//! witness, the touched leaves of the six committed clerk sub-trees
//! plus a [`BatchProof`] per tree, reconstructs each sub-root (binding
//! every input, present or absent, in-circuit), folds the app-named
//! composite `root_before`, re-executes the real cipher-clerk kernel
//! over exactly those leaves, and folds `root_after`. This crate owns
//! that shape once, for all three consumers:
//!
//! - the **clerk-apply Task** (`actors/clerk-apply`) — the transition
//!   verifier a clerk-ledger parent invokes with a record tag;
//! - the **voucher-check guest** — the same verification behind a
//!   voucher's `(state_root_before, state_root_after)` binding;
//! - the **clerk-ledger parent** — [`discover_touched`] +
//!   `CommittedMap::batch_proof` build the [`ClerkTransitionWitness`]
//!   it ships (the host-side test builder [`witness_from_leaves`]
//!   mirrors it from full leaf sets).
//!
//! cipher-clerk deliberately doesn't depend on vos and vos doesn't
//! depend on cipher-clerk; this crate is the one place the two meet.
//! The SMT math is identical by construction (vos::zk::state pins
//! cipher-clerk parity byte-for-byte in its own tests); the leaf
//! contents are cipher-clerk's canonical `tag ‖ payload` encodings,
//! reproduced here via the PUBLIC `*_leaf_content` encoders and
//! re-encode asserts — a doctored tag or non-canonical payload is
//! rejected even though the tag constants themselves are private.

#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use core::cell::RefCell;

use alloc::collections::BTreeSet;
use cipher_clerk::crypto::Amount;
use cipher_clerk::error::EventStatus;
use cipher_clerk::ids::{AccountId, ExternalId, JournalId, TransferId};
use cipher_clerk::refine::apply_batch_refine;
use cipher_clerk::snapshot::OpeningsOracle;
use cipher_clerk::state::{LedgerState, Oracle, PendingStatus};
use cipher_clerk::state_root::{
    account_leaf_content, composite_root_from_subroots, external_id_key,
    external_id_leaf_content, journal_leaf_content, pending_leaf_content,
    transfer_leaf_content, voided_leaf_content,
};
use cipher_clerk::types::{Account, Direction, Journal, Transfer};
use vos::rkyv;
use vos::zk::state::{BatchProof, LedgerWitness, SmtParams, WitnessedLedger, root_of_sorted};

/// The six clerk sub-trees' shape: cipher-clerk hash domains over
/// 16-byte keys (depth 128) — the exact parameters clerk-ledger's
/// `#[storage(committed, leaf_domain = …, node_domain = …)]` fields
/// commit under, so roots reproduce byte-for-byte.
pub const CC_SMT_PARAMS: SmtParams = SmtParams {
    leaf_domain: cipher_clerk::merkle::SMT_LEAF,
    node_domain: cipher_clerk::merkle::SMT_NODE,
    width: 16,
};

/// One provable clerk transition's complete witness: the touched
/// leaves + proof of each of the six committed sub-trees (each
/// [`LedgerWitness`] carries its own sub-`root_before`), the
/// commitment openings the kernel's range checks reveal through, and
/// the batch itself. rkyv-archivable — it rides the Task msg (or the
/// voucher-check witness buffer's secret half) as opaque bytes.
///
/// The composite `root_before` is NOT a field: it is FOLDED from the
/// six sub-roots in [`apply_witnessed`], after each sub-tree's proof
/// verified its own root — a forged sub-root fails its tree, a lying
/// composite fails the caller's comparison against the fold.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
#[rkyv(crate = rkyv)]
pub struct ClerkTransitionWitness {
    pub accounts: LedgerWitness,
    pub transfers: LedgerWitness,
    pub journals: LedgerWitness,
    pub external_ids: LedgerWitness,
    pub voided: LedgerWitness,
    pub pending: LedgerWitness,
    /// Commitment openings (secret) — the kernel's zero-sum/overdraft
    /// checks reveal through these.
    pub oracle: OpeningsOracle,
    /// The batch to prove.
    pub events: Vec<Transfer>,
    /// Per-batch timestamp seed (event timestamps derive from it).
    pub batch_seed_timestamp: u64,
}

impl ClerkTransitionWitness {
    pub fn encode(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .expect("ClerkTransitionWitness rkyv-encodes")
            .to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes).ok()
    }
}

/// The verified outcome of [`apply_witnessed`]: the app-named roots
/// the caller binds (`bind_public` leading with `root_before` — the
/// framework's expected-root convention) plus the applied batch for
/// statement-level checks ([`Self::has_debit_commit`],
/// [`Self::batch_digest`]).
pub struct AppliedTransition {
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
    pub events: Vec<Transfer>,
}

impl AppliedTransition {
    /// True iff some applied transfer carries a **debit** entry of
    /// exactly `amount` — the voucher tie (mirrors cipher-clerk's
    /// `SuccinctTransitionWitness::has_debit_commit`): it blocks
    /// passing an unrelated valid transition off as a given voucher,
    /// and closes the empty-batch `root_before == root_after` mint.
    pub fn has_debit_commit(&self, amount: &Amount) -> bool {
        self.events.iter().any(|t| {
            t.entries
                .iter()
                .any(|e| e.direction == Direction::Debit && &e.amount == amount)
        })
    }

    /// Domain-tagged digest of the applied batch — what a provable
    /// Task folds into `app_public` after the two roots, binding the
    /// proven transition to THIS batch (rkyv re-encoding of the
    /// decoded events is byte-stable for these plain structs).
    pub fn batch_digest(&self) -> [u8; 32] {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&self.events)
            .expect("events rkyv-encode")
            .to_vec();
        vos::crypto::blake2b_hash::<32>(b"clerk-witness/batch/v1", &[&bytes])
    }
}

/// Verify-and-apply one witnessed transition — the whole pure-verifier
/// body (`docs/plans/provable.md`, the load-bearing insight):
///
/// 1. each sub-tree's [`WitnessedLedger`] construction asserts
///    `proof.root(touched) == sub_root_before` (inclusion AND
///    non-inclusion — a swapped value or lying-absent shifts the root);
/// 2. the composite `root_before` folds from the six verified
///    sub-roots;
/// 3. the REAL cipher-clerk kernel re-executes the batch over exactly
///    the witnessed leaves (an unwitnessed access panics — inside a
///    zkVM, "the proof won't verify"); every event must apply cleanly;
/// 4. the kernel's delta applies back onto the witnessed leaves and
///    `root_after` folds from the six post-state roots, reusing the
///    same frontiers the `root_before` check pinned.
///
/// Panics on any violation — the provable-guest failure mode. Returns
/// the roots + batch for the caller to bind.
pub fn apply_witnessed(witness: ClerkTransitionWitness) -> AppliedTransition {
    let ClerkTransitionWitness {
        accounts,
        transfers,
        journals,
        external_ids,
        voided,
        pending,
        oracle,
        events,
        batch_seed_timestamp,
    } = witness;
    let mut state = WitnessedClerkState {
        accounts: accounts.into_ledger(CC_SMT_PARAMS),
        transfers: transfers.into_ledger(CC_SMT_PARAMS),
        journals: journals.into_ledger(CC_SMT_PARAMS),
        external_ids: external_ids.into_ledger(CC_SMT_PARAMS),
        voided: voided.into_ledger(CC_SMT_PARAMS),
        pending: pending.into_ledger(CC_SMT_PARAMS),
    };
    let root_before = state.root();

    let mut probe_oracle = oracle.clone();
    let refined = apply_batch_refine(&state, &events, &mut probe_oracle, batch_seed_timestamp);
    for r in &refined.results {
        assert!(
            r.status == EventStatus::Created,
            "witnessed batch event did not apply cleanly (status != Created)"
        );
    }

    let mut accumulate_oracle = oracle;
    refined.delta.apply(&mut state, &mut accumulate_oracle);
    let root_after = state.root();

    AppliedTransition {
        root_before,
        root_after,
        events,
    }
}

/// The six witnessed sub-trees as one cipher-clerk [`LedgerState`] —
/// the typed adapter the kernel runs over. Reads decode the canonical
/// `tag ‖ payload` leaf contents (re-encode-asserted against the
/// PUBLIC encoders, so a doctored tag or non-canonical payload rejects
/// even though the tag constants are private); writes re-encode
/// through the same encoders. Unproven access panics inside
/// [`WitnessedLedger`] — the pure-verifier backstop.
pub struct WitnessedClerkState {
    accounts: WitnessedLedger,
    transfers: WitnessedLedger,
    journals: WitnessedLedger,
    external_ids: WitnessedLedger,
    voided: WitnessedLedger,
    pending: WitnessedLedger,
}

/// Decode a `tag ‖ rkyv(T)` leaf via its public canonical encoder:
/// deserialize the payload, re-encode with `encode`, and require
/// byte-equality with the stored content — so a doctored tag or a
/// non-canonical (padded / re-ordered) payload is rejected even
/// though the tag constants themselves are private to cipher-clerk.
///
/// The payload is copied into an 8-aligned buffer first: the 1-byte
/// tag prefix misaligns the archive in the leaf-content slice, and
/// rkyv's zero-copy access requires alignment.
fn decode_canonical<T, F>(content: &[u8], encode: F, what: &str) -> T
where
    T: rkyv::Archive,
    T::Archived: rkyv::Deserialize<T, rkyv::rancor::Strategy<rkyv::de::Pool, rkyv::rancor::Error>>
        + for<'a> rkyv::bytecheck::CheckBytes<
            rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
        >,
    F: Fn(&T) -> Vec<u8>,
{
    assert!(!content.is_empty(), "empty {what} leaf content");
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(&content[1..]);
    let value: T = match rkyv::from_bytes::<T, rkyv::rancor::Error>(&aligned) {
        Ok(v) => v,
        Err(e) => panic!("corrupt {what} leaf payload: {e}"),
    };
    assert!(
        encode(&value) == content,
        "{what} leaf content is not the canonical encoding"
    );
    value
}

impl LedgerState for WitnessedClerkState {
    fn root(&self) -> [u8; 32] {
        composite_root_from_subroots(
            &self.accounts.root(),
            &self.transfers.root(),
            &self.journals.root(),
            &self.external_ids.root(),
            &self.voided.root(),
            &self.pending.root(),
        )
    }

    fn get_account(&self, id: &AccountId, _o: &mut dyn Oracle) -> Option<Account> {
        self.accounts
            .get(&id.0)
            .map(|c| decode_canonical(c, account_leaf_content, "account"))
    }
    fn put_account(&mut self, a: Account, _o: &mut dyn Oracle) {
        let content = account_leaf_content(&a);
        self.accounts.insert(&a.id.0, content);
    }

    fn get_transfer(&self, id: &TransferId, _o: &mut dyn Oracle) -> Option<Transfer> {
        self.transfers
            .get(&id.0)
            .map(|c| decode_canonical(c, transfer_leaf_content, "transfer"))
    }
    fn put_transfer(&mut self, t: Transfer, _o: &mut dyn Oracle) {
        let content = transfer_leaf_content(&t);
        self.transfers.insert(&t.id.0, content);
    }

    fn external_id_seen(&self, eid: &ExternalId, _o: &mut dyn Oracle) -> bool {
        let key = external_id_key(&eid.0);
        match self.external_ids.get(&key) {
            None => false,
            Some(content) => {
                assert!(content.len() == 33, "corrupt external-id leaf");
                let mut stored = [0u8; 32];
                stored.copy_from_slice(&content[1..33]);
                assert!(
                    external_id_leaf_content(&stored) == content,
                    "external-id leaf content is not the canonical encoding"
                );
                // A different id occupying this slot can only come
                // from a 2^64-hard key collision (or a corrupt
                // witness): reject rather than mis-answer for either
                // id — mirrors cipher-clerk's SparseLedger.
                assert!(stored == eid.0, "external-id key collision");
                true
            }
        }
    }
    fn mark_external_id(&mut self, eid: &ExternalId, o: &mut dyn Oracle) {
        // The seen-check enforces the collision rule on the slot's
        // current occupant (and the unproven-slot panic).
        let _ = self.external_id_seen(eid, o);
        let key = external_id_key(&eid.0);
        self.external_ids.insert(&key, external_id_leaf_content(&eid.0));
    }

    fn transfer_voided(&self, id: &TransferId, _o: &mut dyn Oracle) -> bool {
        match self.voided.get(&id.0) {
            None => false,
            Some(content) => {
                assert!(
                    voided_leaf_content(&id.0) == content,
                    "voided leaf content is not the canonical encoding"
                );
                true
            }
        }
    }
    fn mark_transfer_voided(&mut self, id: &TransferId, _o: &mut dyn Oracle) {
        self.voided.insert(&id.0, voided_leaf_content(&id.0));
    }

    fn get_journal(&self, id: &JournalId, _o: &mut dyn Oracle) -> Option<Journal> {
        self.journals
            .get(&id.0)
            .map(|c| decode_canonical(c, journal_leaf_content, "journal"))
    }
    fn put_journal(&mut self, j: Journal, _o: &mut dyn Oracle) {
        let content = journal_leaf_content(&j);
        self.journals.insert(&j.id.0, content);
    }

    fn pending_status(&self, id: &TransferId, _o: &mut dyn Oracle) -> Option<PendingStatus> {
        self.pending.get(&id.0).map(|content| {
            assert!(content.len() == 18, "corrupt pending-status leaf");
            let code = content[17];
            let status = PendingStatus::from_code(code)
                .unwrap_or_else(|| panic!("unknown pending-status code {code}"));
            assert!(
                pending_leaf_content(&id.0, code) == content,
                "pending leaf content is not the canonical encoding"
            );
            status
        })
    }
    fn mark_pending_status(&mut self, id: &TransferId, status: PendingStatus, _o: &mut dyn Oracle) {
        self.pending
            .insert(&id.0, pending_leaf_content(&id.0, status.code()));
    }
}

// ── Producer side: touched-key discovery + witness builders ─────────

/// The touched key set of one batch, per sub-tree (external ids
/// already mapped to their 16-byte SMT keys) — what the parent feeds
/// `CommittedMap::batch_proof` per field.
#[derive(Default, Clone, Debug)]
pub struct TouchedKeys {
    pub accounts: BTreeSet<[u8; 16]>,
    pub transfers: BTreeSet<[u8; 16]>,
    pub journals: BTreeSet<[u8; 16]>,
    pub external_ids: BTreeSet<[u8; 16]>,
    pub voided: BTreeSet<[u8; 16]>,
    pub pending: BTreeSet<[u8; 16]>,
}

/// Discover every key `events` will touch against `snapshot`: run the
/// refine-pure kernel over a read-recording adapter and union the
/// delta's writes (mirrors cipher-clerk's `from_full` discovery, made
/// generic so a clerk-ledger parent probes its own live state). The
/// probe's event statuses ride back so the caller can refuse a batch
/// that would not apply cleanly before paying for proofs.
pub fn discover_touched<S: LedgerState>(
    snapshot: &S,
    events: &[Transfer],
    oracle: &OpeningsOracle,
    batch_seed_timestamp: u64,
) -> (TouchedKeys, Vec<EventStatus>) {
    let rec = RecordingState::new(snapshot);
    let mut probe_oracle = oracle.clone();
    let refined = apply_batch_refine(&rec, events, &mut probe_oracle, batch_seed_timestamp);
    let mut t = TouchedKeys {
        accounts: rec.accounts.into_inner(),
        transfers: rec.transfers.into_inner(),
        journals: rec.journals.into_inner(),
        external_ids: rec.external_ids.into_inner(),
        voided: rec.voided.into_inner(),
        pending: rec.pending.into_inner(),
    };
    t.accounts.extend(refined.delta.accounts.keys().copied());
    t.transfers.extend(refined.delta.transfers.keys().copied());
    t.journals.extend(refined.delta.journals.keys().copied());
    t.external_ids
        .extend(refined.delta.external_ids.iter().map(external_id_key));
    t.voided
        .extend(refined.delta.voided_transfers.iter().copied());
    t.pending
        .extend(refined.delta.pending_statuses.keys().copied());
    let statuses = refined.results.iter().map(|r| r.status).collect();
    (t, statuses)
}

/// Read-recording [`LedgerState`] adapter over any snapshot — records
/// which keys the kernel touches, forwards every read, and buffers
/// writes nowhere (the refine staging layer above it holds them).
struct RecordingState<'a, S: LedgerState> {
    inner: &'a S,
    accounts: RefCell<BTreeSet<[u8; 16]>>,
    transfers: RefCell<BTreeSet<[u8; 16]>>,
    journals: RefCell<BTreeSet<[u8; 16]>>,
    external_ids: RefCell<BTreeSet<[u8; 16]>>,
    voided: RefCell<BTreeSet<[u8; 16]>>,
    pending: RefCell<BTreeSet<[u8; 16]>>,
}

impl<'a, S: LedgerState> RecordingState<'a, S> {
    fn new(inner: &'a S) -> Self {
        Self {
            inner,
            accounts: RefCell::new(BTreeSet::new()),
            transfers: RefCell::new(BTreeSet::new()),
            journals: RefCell::new(BTreeSet::new()),
            external_ids: RefCell::new(BTreeSet::new()),
            voided: RefCell::new(BTreeSet::new()),
            pending: RefCell::new(BTreeSet::new()),
        }
    }
}

impl<'a, S: LedgerState> LedgerState for RecordingState<'a, S> {
    fn root(&self) -> [u8; 32] {
        self.inner.root()
    }
    fn get_account(&self, id: &AccountId, o: &mut dyn Oracle) -> Option<Account> {
        self.accounts.borrow_mut().insert(id.0);
        self.inner.get_account(id, o)
    }
    fn put_account(&mut self, a: Account, _o: &mut dyn Oracle) {
        self.accounts.borrow_mut().insert(a.id.0);
    }
    fn get_transfer(&self, id: &TransferId, o: &mut dyn Oracle) -> Option<Transfer> {
        self.transfers.borrow_mut().insert(id.0);
        self.inner.get_transfer(id, o)
    }
    fn put_transfer(&mut self, t: Transfer, _o: &mut dyn Oracle) {
        self.transfers.borrow_mut().insert(t.id.0);
    }
    fn external_id_seen(&self, eid: &ExternalId, o: &mut dyn Oracle) -> bool {
        self.external_ids.borrow_mut().insert(external_id_key(&eid.0));
        self.inner.external_id_seen(eid, o)
    }
    fn mark_external_id(&mut self, eid: &ExternalId, _o: &mut dyn Oracle) {
        self.external_ids.borrow_mut().insert(external_id_key(&eid.0));
    }
    fn transfer_voided(&self, id: &TransferId, o: &mut dyn Oracle) -> bool {
        self.voided.borrow_mut().insert(id.0);
        self.inner.transfer_voided(id, o)
    }
    fn mark_transfer_voided(&mut self, id: &TransferId, _o: &mut dyn Oracle) {
        self.voided.borrow_mut().insert(id.0);
    }
    fn get_journal(&self, id: &JournalId, o: &mut dyn Oracle) -> Option<Journal> {
        self.journals.borrow_mut().insert(id.0);
        self.inner.get_journal(id, o)
    }
    fn put_journal(&mut self, j: Journal, _o: &mut dyn Oracle) {
        self.journals.borrow_mut().insert(j.id.0);
    }
    fn pending_status(&self, id: &TransferId, o: &mut dyn Oracle) -> Option<PendingStatus> {
        self.pending.borrow_mut().insert(id.0);
        self.inner.pending_status(id, o)
    }
    fn mark_pending_status(&mut self, id: &TransferId, _s: PendingStatus, _o: &mut dyn Oracle) {
        self.pending.borrow_mut().insert(id.0);
    }
}

/// One sub-tree's full content as sorted `(key, canonical leaf
/// content)` pairs — the producer-side input to
/// [`witness_from_leaves`] when the whole tree is in hand (test
/// builders, host tooling). A clerk-ledger parent extracts proofs from
/// its stored trees via `CommittedMap::batch_proof` instead.
pub type FullLeaves = Vec<([u8; 16], Vec<u8>)>;

/// Build one sub-tree's [`LedgerWitness`] from its full sorted leaf
/// set: `root_before` + [`BatchProof::build`] over the touched keys +
/// the touched `(key, Option<content>)` pairs (absent = proven
/// non-inclusion).
pub fn ledger_witness_from_leaves(
    leaves: &FullLeaves,
    touched: &BTreeSet<[u8; 16]>,
) -> LedgerWitness {
    let hashed: Vec<([u8; 16], [u8; 32])> = leaves
        .iter()
        .map(|(k, c)| (*k, vos::zk::state::leaf_hash(&CC_SMT_PARAMS, c)))
        .collect();
    let root_before = root_of_sorted(&CC_SMT_PARAMS, &hashed);
    let touched_refs: Vec<&[u8]> = touched.iter().map(|k| k.as_slice()).collect();
    let proof = BatchProof::build(&CC_SMT_PARAMS, &hashed, &touched_refs);
    let touched_leaves = touched
        .iter()
        .map(|k| {
            let content = leaves
                .iter()
                .find(|(lk, _)| lk == k)
                .map(|(_, c)| c.clone());
            (k.to_vec(), content)
        })
        .collect();
    LedgerWitness {
        root_before,
        proof,
        touched: touched_leaves,
    }
}

/// The six sub-trees of a [`VecLedger`](cipher_clerk::snapshot::VecLedger)
/// as [`FullLeaves`] — each `(key, canonical leaf content)` pair the
/// cipher-clerk SMT commits, in the six-tuple order the witness
/// builders take (accounts, transfers, journals, external_ids, voided,
/// pending). Producer/test tooling: a `VecLedger` holds the whole
/// ledger, so this walks every leaf; a live clerk-ledger parent
/// extracts touched-only proofs via `CommittedMap::batch_proof`
/// instead.
pub fn vec_ledger_full_leaves(
    l: &cipher_clerk::snapshot::VecLedger,
) -> [FullLeaves; 6] {
    let accounts = l.accounts.iter().map(|a| (a.id.0, account_leaf_content(a))).collect();
    let transfers = l.transfers.iter().map(|t| (t.id.0, transfer_leaf_content(t))).collect();
    let journals = l.journal.iter().map(|j| (j.id.0, journal_leaf_content(j))).collect();
    let external_ids = l
        .external_ids
        .iter()
        .map(|eid| (external_id_key(eid), external_id_leaf_content(eid)))
        .collect();
    let voided = l.voided_transfers.iter().map(|id| (*id, voided_leaf_content(id))).collect();
    let pending = l
        .pending_statuses
        .iter()
        .map(|e| (e.id, pending_leaf_content(&e.id, e.status)))
        .collect();
    [accounts, transfers, journals, external_ids, voided, pending]
}

/// Assemble a full [`ClerkTransitionWitness`] from the six trees'
/// complete leaf sets — the host/test producer (the e2e conservation
/// builder). `touched` normally comes from [`discover_touched`].
#[allow(clippy::too_many_arguments)]
pub fn witness_from_leaves(
    accounts: &FullLeaves,
    transfers: &FullLeaves,
    journals: &FullLeaves,
    external_ids: &FullLeaves,
    voided: &FullLeaves,
    pending: &FullLeaves,
    touched: &TouchedKeys,
    oracle: OpeningsOracle,
    events: Vec<Transfer>,
    batch_seed_timestamp: u64,
) -> ClerkTransitionWitness {
    ClerkTransitionWitness {
        accounts: ledger_witness_from_leaves(accounts, &touched.accounts),
        transfers: ledger_witness_from_leaves(transfers, &touched.transfers),
        journals: ledger_witness_from_leaves(journals, &touched.journals),
        external_ids: ledger_witness_from_leaves(external_ids, &touched.external_ids),
        voided: ledger_witness_from_leaves(voided, &touched.voided),
        pending: ledger_witness_from_leaves(pending, &touched.pending),
        oracle,
        events,
        batch_seed_timestamp,
    }
}

/// One-call producer over a [`VecLedger`](cipher_clerk::snapshot::VecLedger):
/// discover the touched keys, extract the full-leaf witness, and return
/// it — the host/test path (the federation e2e + the W4 gate). Panics
/// if the probe batch would not apply cleanly (a caller should never
/// prove a rejected batch). A live clerk-ledger parent instead probes
/// its own committed state and extracts per-field `batch_proof`s.
pub fn witness_from_vec_ledger(
    ledger: &cipher_clerk::snapshot::VecLedger,
    events: Vec<Transfer>,
    oracle: OpeningsOracle,
    batch_seed_timestamp: u64,
) -> ClerkTransitionWitness {
    let (touched, statuses) = discover_touched(ledger, &events, &oracle, batch_seed_timestamp);
    for s in &statuses {
        assert!(*s == EventStatus::Created, "probe batch does not apply cleanly");
    }
    let [accounts, transfers, journals, external_ids, voided, pending] =
        vec_ledger_full_leaves(ledger);
    witness_from_leaves(
        &accounts,
        &transfers,
        &journals,
        &external_ids,
        &voided,
        &pending,
        &touched,
        oracle,
        events,
        batch_seed_timestamp,
    )
}
