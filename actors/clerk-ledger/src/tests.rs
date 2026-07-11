//! Host-side LedgerView + composite-root unit tests.
//!
//! Pins the `LedgerState` impl over the committed maps against
//! cipher-clerk's expected contract (key-ordered iteration, in-place
//! overwrites on duplicate keys, idempotent mark/seen) and — the
//! load-bearing pin — the *incrementally maintained* composite root
//! against `compute_state_root`'s from-scratch rebuild over the same
//! content, byte for byte. The integration test in
//! `vos/tests/elf_integration.rs` exercises the kernel paths
//! end-to-end; these tests exercise the view in isolation so a
//! regression in the storage shape surfaces here without a PVM
//! rebuild.

use cipher_clerk::crypto::AuthKey;
use cipher_clerk::ids::{
    AccountId as CcAccountId, ExternalId as CcExternalId, JournalId as CcJournalId,
    TransferId as CcTransferId,
};
use cipher_clerk::state::{LedgerState, PendingStatus};
use cipher_clerk::state_root::journal_leaf_content;
use cipher_clerk::types::{
    Account as CcAccount, Direction, Journal as CcJournal, Transfer as CcTransfer,
};
use vos::storage::CommittedMap;

use crate::oracle::NoopOracle;
use crate::smt::compute_state_root;
use crate::view::LedgerView;

const LEAF_DOMAIN: &[u8] = b"cipher-clerk/smt/leaf/v1";
const NODE_DOMAIN: &[u8] = b"cipher-clerk/smt/node/v1";

fn mk_account(id_byte: u8) -> CcAccount {
    CcAccount::new(
        CcAccountId([id_byte; 16]),
        CcJournalId([0; 16]),
        AuthKey([0; 32]),
        1u32,
        1u16,
        Direction::Debit,
    )
}

fn mk_transfer(id_byte: u8) -> CcTransfer {
    let mut t = CcTransfer::default();
    t.id = CcTransferId([id_byte; 16]);
    t.journal_id = CcJournalId([0; 16]);
    t
}

/// The actor's committed maps, freshly initialized over a clean mock
/// keyspace — what `__init_storage` produces after a create/decode.
struct Maps {
    accounts: CommittedMap<[u8; 16], CcAccount>,
    transfers: CommittedMap<[u8; 16], CcTransfer>,
    journal: CommittedMap<[u8; 16], CcJournal>,
    external_ids: CommittedMap<[u8; 16], [u8; 32]>,
    voided: CommittedMap<[u8; 16], u8>,
    pending: CommittedMap<[u8; 16], u8>,
}

impl Maps {
    fn fresh() -> Self {
        vos::storage::mock::reset();
        Self::over_the_same_keyspace(0)
    }

    /// A second (or nth) instance over live rows — distinct prefixes
    /// per generation let one test hold independent ledgers.
    fn over_the_same_keyspace(generation: u8) -> Self {
        let mut m = Maps {
            accounts: Default::default(),
            transfers: Default::default(),
            journal: Default::default(),
            external_ids: Default::default(),
            voided: Default::default(),
            pending: Default::default(),
        };
        let g = generation;
        m.accounts
            .__init_with_domains(format!("s/a{g}/").as_bytes(), LEAF_DOMAIN, NODE_DOMAIN);
        m.transfers
            .__init_with_domains(format!("s/t{g}/").as_bytes(), LEAF_DOMAIN, NODE_DOMAIN);
        m.journal
            .__init_with_domains(format!("s/j{g}/").as_bytes(), LEAF_DOMAIN, NODE_DOMAIN);
        m.external_ids
            .__init_with_domains(format!("s/e{g}/").as_bytes(), LEAF_DOMAIN, NODE_DOMAIN);
        m.voided
            .__init_with_domains(format!("s/v{g}/").as_bytes(), LEAF_DOMAIN, NODE_DOMAIN);
        m.pending
            .__init_with_domains(format!("s/p{g}/").as_bytes(), LEAF_DOMAIN, NODE_DOMAIN);
        m
    }

    fn view(&mut self) -> LedgerView<'_> {
        LedgerView::new(
            &mut self.accounts,
            &mut self.transfers,
            &self.journal,
            &mut self.external_ids,
            &mut self.voided,
            &mut self.pending,
        )
    }

    fn set_journal(&mut self, j: &CcJournal) {
        let content = journal_leaf_content(j);
        self.journal.insert_with_leaf(&j.id.0, j, &content);
    }
}

#[test]
fn account_put_get_round_trip_and_miss() {
    let mut m = Maps::fresh();
    let mut view = m.view();
    view.put_account(mk_account(0x42), &mut NoopOracle);
    let got = view.get_account(&CcAccountId([0x42; 16]), &mut NoopOracle);
    let miss = view.get_account(&CcAccountId([0xFF; 16]), &mut NoopOracle);
    assert_eq!(got, Some(mk_account(0x42)));
    assert_eq!(miss, None);
}

#[test]
fn account_iteration_is_key_ordered_and_duplicate_overwrites() {
    let mut m = Maps::fresh();
    {
        let mut view = m.view();
        for byte in [0x03, 0x01, 0x05, 0x02, 0x04] {
            view.put_account(mk_account(byte), &mut NoopOracle);
        }
        // Re-put existing id with a mutated payload — must
        // overwrite, not duplicate-insert.
        let mut updated = mk_account(0x03);
        updated.timestamp = 999;
        view.put_account(updated, &mut NoopOracle);
    }
    let ids: Vec<u8> = m.accounts.iter().map(|(k, _)| k[0]).collect();
    assert_eq!(ids, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(m.accounts.len(), 5, "duplicate id must overwrite in place");
    assert_eq!(
        m.accounts.get(&[0x03; 16]).unwrap().timestamp,
        999,
        "the overwrite must be the stored payload"
    );
}

#[test]
fn transfer_put_get_round_trip() {
    let mut m = Maps::fresh();
    let (hit, miss) = {
        let mut view = m.view();
        view.put_transfer(mk_transfer(0x10), &mut NoopOracle);
        view.put_transfer(mk_transfer(0x01), &mut NoopOracle);
        (
            view.get_transfer(&CcTransferId([0x10; 16]), &mut NoopOracle),
            view.get_transfer(&CcTransferId([0xAB; 16]), &mut NoopOracle),
        )
    };
    let ids: Vec<u8> = m.transfers.iter().map(|(k, _)| k[0]).collect();
    assert_eq!(ids, vec![0x01, 0x10], "iteration must be key-ordered");
    assert_eq!(hit.map(|x| x.id.0[0]), Some(0x10));
    assert!(miss.is_none());
}

#[test]
fn external_id_mark_is_idempotent() {
    let mut m = Maps::fresh();
    let (seen_a, seen_zero) = {
        let mut view = m.view();
        let eid_b = CcExternalId([0xBB; 32]);
        let eid_a = CcExternalId([0xAA; 32]);
        view.mark_external_id(&eid_b, &mut NoopOracle);
        view.mark_external_id(&eid_a, &mut NoopOracle);
        view.mark_external_id(&eid_a, &mut NoopOracle); // double-mark
        (
            view.external_id_seen(&eid_a, &mut NoopOracle),
            view.external_id_seen(&CcExternalId([0; 32]), &mut NoopOracle),
        )
    };
    assert_eq!(m.external_ids.len(), 2, "duplicate mark must be no-op");
    assert!(seen_a);
    assert!(!seen_zero);
}

#[test]
fn transfer_voided_round_trip() {
    let mut m = Maps::fresh();
    let (before, after) = {
        let mut view = m.view();
        let id = CcTransferId([0x77; 16]);
        let before = view.transfer_voided(&id, &mut NoopOracle);
        view.mark_transfer_voided(&id, &mut NoopOracle);
        view.mark_transfer_voided(&id, &mut NoopOracle); // idempotent
        (before, view.transfer_voided(&id, &mut NoopOracle))
    };
    assert!(!before);
    assert!(after);
    assert_eq!(m.voided.len(), 1, "double-mark must not duplicate");
}

#[test]
fn pending_status_transitions() {
    let mut m = Maps::fresh();
    let (s0, s1, s2) = {
        let mut view = m.view();
        let id = CcTransferId([0x55; 16]);
        let s0 = view.pending_status(&id, &mut NoopOracle);
        view.mark_pending_status(&id, PendingStatus::Pending, &mut NoopOracle);
        let s1 = view.pending_status(&id, &mut NoopOracle);
        view.mark_pending_status(&id, PendingStatus::Posted, &mut NoopOracle);
        (s0, s1, view.pending_status(&id, &mut NoopOracle))
    };
    assert!(s0.is_none());
    assert_eq!(s1, Some(PendingStatus::Pending));
    assert_eq!(s2, Some(PendingStatus::Posted));
    assert_eq!(
        m.pending.len(),
        1,
        "status transition must overwrite, not duplicate"
    );
}

#[test]
fn get_journal_filters_by_id() {
    let mut m = Maps::fresh();
    let journal = CcJournal::new(CcJournalId([0xCA; 16]), AuthKey([0; 32]), 1);
    m.set_journal(&journal);
    let view = m.view();
    let hit = view.get_journal(&CcJournalId([0xCA; 16]), &mut NoopOracle);
    let miss = view.get_journal(&CcJournalId([0xFF; 16]), &mut NoopOracle);
    assert_eq!(hit.as_ref(), Some(&journal));
    assert_eq!(miss, None);
}

/// THE parity pin: the incrementally-maintained composite root must
/// equal cipher-clerk's from-scratch `composite_state_root` rebuild
/// over the same content, byte for byte — this is what keeps vouchers
/// in flight verifying across the storage retype. Runs a mixed
/// workload over every sub-SMT, checking after each phase.
#[test]
fn incremental_composite_root_matches_full_rebuild() {
    let mut m = Maps::fresh();
    let journal = CcJournal::new(CcJournalId([0xCA; 16]), AuthKey([0xAA; 32]), 1);
    m.set_journal(&journal);

    // Reference content mirrors, kept sorted the way the rebuild wants.
    let mut accounts: Vec<CcAccount> = Vec::new();
    let mut transfers: Vec<CcTransfer> = Vec::new();
    let mut eids: Vec<[u8; 32]> = Vec::new();
    let mut voided: Vec<[u8; 16]> = Vec::new();
    let mut pending: Vec<([u8; 16], u8)> = Vec::new();

    let check = |m: &mut Maps,
                 accounts: &[CcAccount],
                 transfers: &[CcTransfer],
                 eids: &[[u8; 32]],
                 voided: &[[u8; 16]],
                 pending: &[([u8; 16], u8)],
                 phase: &str| {
        let incremental = m.view().root();
        let rebuilt =
            compute_state_root(accounts, transfers, Some(&journal), eids, voided, pending);
        assert_eq!(
            incremental, rebuilt,
            "incremental composite diverged from the full rebuild after {phase}"
        );
    };

    check(&mut m, &accounts, &transfers, &eids, &voided, &pending, "bootstrap");

    for byte in [0x07, 0x02, 0x0e, 0x0b] {
        m.view().put_account(mk_account(byte), &mut NoopOracle);
        accounts.push(mk_account(byte));
    }
    accounts.sort_by_key(|a| a.id.0);
    check(&mut m, &accounts, &transfers, &eids, &voided, &pending, "account creation");

    // Overwrite one account (a balance-mutating transfer's effect).
    let mut updated = mk_account(0x02);
    updated.timestamp = 4242;
    m.view().put_account(updated.clone(), &mut NoopOracle);
    accounts[0] = updated;
    check(&mut m, &accounts, &transfers, &eids, &voided, &pending, "account overwrite");

    for byte in [0x60, 0x21] {
        m.view().put_transfer(mk_transfer(byte), &mut NoopOracle);
        transfers.push(mk_transfer(byte));
    }
    transfers.sort_by_key(|t| t.id.0);
    check(&mut m, &accounts, &transfers, &eids, &voided, &pending, "transfers");

    m.view()
        .mark_external_id(&CcExternalId([0xE1; 32]), &mut NoopOracle);
    eids.push([0xE1; 32]);
    m.view()
        .mark_transfer_voided(&CcTransferId([0x21; 16]), &mut NoopOracle);
    voided.push([0x21; 16]);
    m.view()
        .mark_pending_status(&CcTransferId([0x60; 16]), PendingStatus::Pending, &mut NoopOracle);
    pending.push(([0x60; 16], 0));
    check(&mut m, &accounts, &transfers, &eids, &voided, &pending, "bookkeeping marks");

    m.view()
        .mark_pending_status(&CcTransferId([0x60; 16]), PendingStatus::Posted, &mut NoopOracle);
    pending[0].1 = 1;
    check(&mut m, &accounts, &transfers, &eids, &voided, &pending, "pending transition");

    assert_ne!(
        m.view().root(),
        [0u8; 32],
        "non-trivial state must NOT hash to the all-zero root"
    );
}

#[test]
fn composite_root_is_insertion_order_invariant() {
    let journal = CcJournal::new(CcJournalId([0xCA; 16]), AuthKey([0xAA; 32]), 1);

    let build = |account_order: &[u8], transfer_order: &[u8]| -> [u8; 32] {
        let mut m = Maps::fresh();
        m.set_journal(&journal);
        let mut view = m.view();
        for &byte in account_order {
            view.put_account(mk_account(byte), &mut NoopOracle);
        }
        for &byte in transfer_order {
            view.put_transfer(mk_transfer(byte), &mut NoopOracle);
        }
        view.root()
    };

    let forward = build(&[0x01, 0x02, 0x03], &[0x10, 0x20]);
    let reverse = build(&[0x03, 0x02, 0x01], &[0x20, 0x10]);
    assert_eq!(forward, reverse, "composite root must be order-invariant");
}
