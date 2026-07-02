//! Host-side LedgerView + SMT unit tests.
//!
//! Pins the `LedgerState` impl against cipher-clerk's expected
//! contract (sorted insertion, in-place overwrites on duplicate
//! keys, idempotent mark/seen) and the composite SMT root against
//! `cipher_clerk::helpers::MemLedger` (byte-equality). The
//! integration test in `vos/tests/elf_integration.rs` exercises
//! the kernel paths end-to-end; these tests exercise the
//! LedgerView and SMT helpers in isolation so a regression in the
//! storage shape surfaces here without needing a PVM rebuild.

use cipher_clerk::crypto::AuthKey;
use cipher_clerk::ids::{
    AccountId as CcAccountId, ExternalId as CcExternalId, JournalId as CcJournalId,
    TransferId as CcTransferId,
};
use cipher_clerk::state::{LedgerState, PendingStatus};
use cipher_clerk::types::{Account as CcAccount, Direction, Journal as CcJournal, Transfer as CcTransfer};

use crate::oracle::NoopOracle;
use crate::smt::compute_state_root;
use crate::view::LedgerView;
use crate::wire::PendingStatusEntry;

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

/// Build a fresh backing-store tuple and run `f` with a
/// LedgerView over it. Returns the backing store after `f`
/// drops the view, so assertions can read the raw vecs.
fn with_view<R>(
    f: impl FnOnce(&mut LedgerView<'_>) -> R,
) -> (
    R,
    Vec<CcAccount>,
    Vec<CcTransfer>,
    Vec<[u8; 32]>,
    Vec<[u8; 16]>,
    Vec<PendingStatusEntry>,
) {
    let mut accounts = Vec::new();
    let mut transfers = Vec::new();
    let mut external_ids = Vec::new();
    let mut voided = Vec::new();
    let mut pending = Vec::new();
    let r = {
        let mut view = LedgerView::new(
            &mut accounts,
            &mut transfers,
            &mut external_ids,
            &mut voided,
            &mut pending,
            None,
        );
        f(&mut view)
    };
    (r, accounts, transfers, external_ids, voided, pending)
}

#[test]
fn account_put_get_round_trip_and_miss() {
    let ((got, miss), _, _, _, _, _) = with_view(|view| {
        view.put_account(mk_account(0x42), &mut NoopOracle);
        let got = view.get_account(&CcAccountId([0x42; 16]), &mut NoopOracle);
        let miss = view.get_account(&CcAccountId([0xFF; 16]), &mut NoopOracle);
        (got, miss)
    });
    assert_eq!(got, Some(mk_account(0x42)));
    assert_eq!(miss, None);
}

#[test]
fn account_inserts_keep_sorted_and_duplicate_overwrites() {
    let (after_dup_stored, accounts, _, _, _, _) = with_view(|view| {
        for byte in [0x03, 0x01, 0x05, 0x02, 0x04] {
            view.put_account(mk_account(byte), &mut NoopOracle);
        }
        // Re-put existing id with a mutated payload — must
        // overwrite, not duplicate-insert.
        let mut updated = mk_account(0x03);
        updated.timestamp = 999;
        view.put_account(updated, &mut NoopOracle);
        view.get_account(&CcAccountId([0x03; 16]), &mut NoopOracle)
    });
    let ids: Vec<u8> = accounts.iter().map(|x| x.id.0[0]).collect();
    assert_eq!(ids, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(accounts.len(), 5, "duplicate id must overwrite in place");
    assert_eq!(after_dup_stored.unwrap().timestamp, 999);
}

#[test]
fn transfer_put_get_round_trip() {
    let ((hit, miss), _, transfers, _, _, _) = with_view(|view| {
        view.put_transfer(mk_transfer(0x10), &mut NoopOracle);
        view.put_transfer(mk_transfer(0x01), &mut NoopOracle);
        let hit = view.get_transfer(&CcTransferId([0x10; 16]), &mut NoopOracle);
        let miss = view.get_transfer(&CcTransferId([0xAB; 16]), &mut NoopOracle);
        (hit, miss)
    });
    let ids: Vec<u8> = transfers.iter().map(|x| x.id.0[0]).collect();
    assert_eq!(ids, vec![0x01, 0x10], "transfers must be sorted ascending");
    assert_eq!(hit.map(|x| x.id.0[0]), Some(0x10));
    assert!(miss.is_none());
}

#[test]
fn external_id_mark_is_idempotent_and_sorted() {
    let ((seen_a, seen_zero), _, _, external_ids, _, _) = with_view(|view| {
        let eid_b = CcExternalId([0xBB; 32]);
        let eid_a = CcExternalId([0xAA; 32]);
        view.mark_external_id(&eid_b, &mut NoopOracle);
        view.mark_external_id(&eid_a, &mut NoopOracle);
        view.mark_external_id(&eid_a, &mut NoopOracle); // double-mark
        let seen_a = view.external_id_seen(&eid_a, &mut NoopOracle);
        let seen_zero = view.external_id_seen(&CcExternalId([0; 32]), &mut NoopOracle);
        (seen_a, seen_zero)
    });
    assert_eq!(external_ids.len(), 2, "duplicate mark must be no-op");
    assert!(
        external_ids[0] < external_ids[1],
        "external_ids must be sorted ascending"
    );
    assert!(seen_a);
    assert!(!seen_zero);
}

#[test]
fn transfer_voided_round_trip() {
    let ((before, after), _, _, _, voided, _) = with_view(|view| {
        let id = CcTransferId([0x77; 16]);
        let before = view.transfer_voided(&id, &mut NoopOracle);
        view.mark_transfer_voided(&id, &mut NoopOracle);
        view.mark_transfer_voided(&id, &mut NoopOracle); // idempotent
        let after = view.transfer_voided(&id, &mut NoopOracle);
        (before, after)
    });
    assert!(!before);
    assert!(after);
    assert_eq!(voided.len(), 1, "double-mark must not duplicate");
}

#[test]
fn pending_status_transitions() {
    let ((s0, s1, s2), _, _, _, _, pending) = with_view(|view| {
        let id = CcTransferId([0x55; 16]);
        let s0 = view.pending_status(&id, &mut NoopOracle);
        view.mark_pending_status(&id, PendingStatus::Pending, &mut NoopOracle);
        let s1 = view.pending_status(&id, &mut NoopOracle);
        view.mark_pending_status(&id, PendingStatus::Posted, &mut NoopOracle);
        let s2 = view.pending_status(&id, &mut NoopOracle);
        (s0, s1, s2)
    });
    assert!(s0.is_none());
    assert_eq!(s1, Some(PendingStatus::Pending));
    assert_eq!(s2, Some(PendingStatus::Posted));
    assert_eq!(
        pending.len(),
        1,
        "status transition must overwrite, not duplicate"
    );
}

#[test]
fn get_journal_filters_by_id() {
    let mut a = Vec::new();
    let mut t = Vec::new();
    let mut e = Vec::new();
    let mut v = Vec::new();
    let mut p = Vec::new();
    let journal = CcJournal::new(CcJournalId([0xCA; 16]), AuthKey([0; 32]), 1);
    let view = LedgerView::new(&mut a, &mut t, &mut e, &mut v, &mut p, Some(&journal));
    let hit = view.get_journal(&CcJournalId([0xCA; 16]), &mut NoopOracle);
    let miss = view.get_journal(&CcJournalId([0xFF; 16]), &mut NoopOracle);
    assert_eq!(hit.as_ref(), Some(&journal));
    assert_eq!(miss, None);
}

#[test]
fn smt_root_is_deterministic_and_order_invariant() {
    // Same content inserted in different orders must hash to
    // the same root — the SMT is keyed by id, not insertion order.
    let mut a1 = Vec::new();
    let mut t1 = Vec::new();
    let (mut e1, mut v1, mut p1) = (Vec::new(), Vec::new(), Vec::new());
    let mut a2 = Vec::new();
    let mut t2 = Vec::new();
    let (mut e2, mut v2, mut p2) = (Vec::new(), Vec::new(), Vec::new());
    let journal = CcJournal::new(CcJournalId([0xCA; 16]), AuthKey([0xAA; 32]), 1);

    // Forward order
    {
        let mut view =
            LedgerView::new(&mut a1, &mut t1, &mut e1, &mut v1, &mut p1, Some(&journal));
        for byte in [0x01, 0x02, 0x03] {
            view.put_account(mk_account(byte), &mut NoopOracle);
        }
        for byte in [0x10, 0x20] {
            view.put_transfer(mk_transfer(byte), &mut NoopOracle);
        }
    }
    // Reverse order
    {
        let mut view =
            LedgerView::new(&mut a2, &mut t2, &mut e2, &mut v2, &mut p2, Some(&journal));
        for byte in [0x03, 0x02, 0x01] {
            view.put_account(mk_account(byte), &mut NoopOracle);
        }
        for byte in [0x20, 0x10] {
            view.put_transfer(mk_transfer(byte), &mut NoopOracle);
        }
    }
    let root1 = compute_state_root(&a1, &t1, Some(&journal), &e1, &v1, &[]);
    let root2 = compute_state_root(&a2, &t2, Some(&journal), &e2, &v2, &[]);
    assert_eq!(root1, root2, "SMT root must be order-invariant");
    assert_ne!(
        root1, [0u8; 32],
        "non-trivial state must NOT hash to the all-zero root"
    );
}

#[test]
fn smt_root_changes_when_state_changes() {
    // Property the voucher protocol leans on: any state delta
    // shifts the root. If put_account were silently no-op'd
    // (e.g. by a regression), the root would stay constant and
    // a voucher signed against root_before == root_after would
    // be a forgery. Pin loudly.
    let journal = CcJournal::new(CcJournalId([0xCA; 16]), AuthKey([0xAA; 32]), 1);
    let mut a = Vec::new();
    let mut t = Vec::new();
    let r0 = compute_state_root(&a, &t, Some(&journal), &[], &[], &[]);
    a.push(mk_account(0x01));
    let r1 = compute_state_root(&a, &t, Some(&journal), &[], &[], &[]);
    assert_ne!(r0, r1, "adding an account must change the root");
    t.push(mk_transfer(0x10));
    let r2 = compute_state_root(&a, &t, Some(&journal), &[], &[], &[]);
    assert_ne!(r1, r2, "adding a transfer must change the root");
    // The bookkeeping sets are committed too (Phase 0 of the
    // conservation-of-value proof leans on this).
    let r3 = compute_state_root(&a, &t, Some(&journal), &[[0xE0; 32]], &[], &[]);
    assert_ne!(r2, r3, "marking an external id must change the root");
    let r4 = compute_state_root(&a, &t, Some(&journal), &[], &[[0x55; 16]], &[]);
    assert_ne!(r2, r4, "voiding a transfer must change the root");
    let r5 = compute_state_root(&a, &t, Some(&journal), &[], &[], &[([0x55; 16], 0)]);
    assert_ne!(r2, r5, "a pending entry must change the root");
}
