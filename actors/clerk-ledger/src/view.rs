//! `LedgerView` — the borrowed mutable view over `ClerkLedger`'s
//! committed storage maps that implements
//! `cipher_clerk::state::LedgerState`. The kernel reads from / writes
//! to the actor's state through this trait surface; the actor never
//! hands the kernel direct access.
//!
//! Every operation is a point read or a point write plus the touched
//! key's SMT branch path — the collections never materialize. Leaf
//! contents are cipher-clerk's canonical encodings
//! (`state_root::*_leaf_content`), so the per-field roots — and the
//! composite [`root`](LedgerState::root) — stay byte-identical to a
//! from-scratch `composite_state_root` rebuild over the same content.
//!
//! Field-targeted construction (rather than `&mut ClerkLedger`)
//! keeps the borrow narrow — the handler can still touch
//! `transfer_roots` / `note_commitments` / other state-tracking
//! fields while the kernel runs.

use cipher_clerk::ids::{
    AccountId as CcAccountId, ExternalId as CcExternalId, JournalId as CcJournalId,
    TransferId as CcTransferId,
};
use cipher_clerk::state::{LedgerState, Oracle, PendingStatus};
use cipher_clerk::state_root::{
    account_leaf_content, composite_root_from_subroots, external_id_key, external_id_leaf_content,
    pending_leaf_content, transfer_leaf_content, voided_leaf_content,
};
use cipher_clerk::types::{Account as CcAccount, Journal as CcJournal, Transfer as CcTransfer};
use vos::storage::CommittedMap;

use crate::wire::{PENDING_STATUS_PENDING, PENDING_STATUS_POSTED, PENDING_STATUS_VOIDED};

/// Mutable view over the actor's committed maps that implements
/// cipher-clerk's `LedgerState`.
pub(crate) struct LedgerView<'a> {
    accounts: &'a mut CommittedMap<[u8; 16], CcAccount>,
    transfers: &'a mut CommittedMap<[u8; 16], CcTransfer>,
    journal: &'a CommittedMap<[u8; 16], CcJournal>,
    external_ids: &'a mut CommittedMap<[u8; 16], [u8; 32]>,
    voided_transfers: &'a mut CommittedMap<[u8; 16], u8>,
    pending_statuses: &'a mut CommittedMap<[u8; 16], u8>,
}

impl<'a> LedgerView<'a> {
    /// Field-targeted constructor — takes disjoint borrows of the
    /// committed maps the kernel might touch. The journal map is
    /// read-only here: bootstrap owns journal writes.
    pub(crate) fn new(
        accounts: &'a mut CommittedMap<[u8; 16], CcAccount>,
        transfers: &'a mut CommittedMap<[u8; 16], CcTransfer>,
        journal: &'a CommittedMap<[u8; 16], CcJournal>,
        external_ids: &'a mut CommittedMap<[u8; 16], [u8; 32]>,
        voided_transfers: &'a mut CommittedMap<[u8; 16], u8>,
        pending_statuses: &'a mut CommittedMap<[u8; 16], u8>,
    ) -> Self {
        Self {
            accounts,
            transfers,
            journal,
            external_ids,
            voided_transfers,
            pending_statuses,
        }
    }
}

impl LedgerState for LedgerView<'_> {
    fn root(&self) -> [u8; 32] {
        composite_root_from_subroots(
            &self.accounts.root(),
            &self.transfers.root(),
            &self.journal.root(),
            &self.external_ids.root(),
            &self.voided_transfers.root(),
            &self.pending_statuses.root(),
        )
    }

    fn get_account(&self, id: &CcAccountId, _o: &mut dyn Oracle) -> Option<CcAccount> {
        self.accounts.get(&id.0)
    }

    fn put_account(&mut self, a: CcAccount, _o: &mut dyn Oracle) {
        let content = account_leaf_content(&a);
        self.accounts.insert_with_leaf(&a.id.0, &a, &content);
    }

    fn get_journal(&self, id: &CcJournalId, _o: &mut dyn Oracle) -> Option<CcJournal> {
        self.journal.get(&id.0)
    }

    fn put_journal(&mut self, _j: CcJournal, _o: &mut dyn Oracle) {
        // Bootstrap owns journal writes — the kernel never reaches
        // here in the create_account / apply_batch paths.
        unimplemented!("clerk-ledger: put_journal called outside bootstrap")
    }

    fn get_transfer(&self, id: &CcTransferId, _o: &mut dyn Oracle) -> Option<CcTransfer> {
        self.transfers.get(&id.0)
    }

    fn put_transfer(&mut self, t: CcTransfer, _o: &mut dyn Oracle) {
        let content = transfer_leaf_content(&t);
        self.transfers.insert_with_leaf(&t.id.0, &t, &content);
    }

    fn external_id_seen(&self, eid: &CcExternalId, _o: &mut dyn Oracle) -> bool {
        // The slot is keyed by the id's 16-byte hash; the stored value
        // pins the full 32-byte id. A different id occupying the slot
        // (a 2^64 birthday collision) also reports "seen" so the
        // kernel REJECTS — a collision must never alias one id's
        // presence into another's acceptance.
        self.external_ids.get(&external_id_key(&eid.0)).is_some()
    }

    fn mark_external_id(&mut self, eid: &CcExternalId, _o: &mut dyn Oracle) {
        let key = external_id_key(&eid.0);
        debug_assert!(
            self.external_ids
                .get(&key)
                .is_none_or(|stored| stored == eid.0),
            "external-id slot collision — seen-check must have rejected first",
        );
        let content = external_id_leaf_content(&eid.0);
        self.external_ids.insert_with_leaf(&key, &eid.0, &content);
    }

    fn transfer_voided(&self, id: &CcTransferId, _o: &mut dyn Oracle) -> bool {
        self.voided_transfers.contains(&id.0)
    }

    fn mark_transfer_voided(&mut self, id: &CcTransferId, _o: &mut dyn Oracle) {
        let content = voided_leaf_content(&id.0);
        self.voided_transfers
            .insert_with_leaf(&id.0, &1u8, &content);
    }

    fn pending_status(&self, id: &CcTransferId, _o: &mut dyn Oracle) -> Option<PendingStatus> {
        self.pending_statuses.get(&id.0).map(|status| match status {
            PENDING_STATUS_PENDING => PendingStatus::Pending,
            PENDING_STATUS_POSTED => PendingStatus::Posted,
            PENDING_STATUS_VOIDED => PendingStatus::Voided,
            _ => unreachable!("PendingStatusEntry.status only stored via mark_pending_status"),
        })
    }

    fn mark_pending_status(
        &mut self,
        id: &CcTransferId,
        status: PendingStatus,
        _o: &mut dyn Oracle,
    ) {
        let val = match status {
            PendingStatus::Pending => PENDING_STATUS_PENDING,
            PendingStatus::Posted => PENDING_STATUS_POSTED,
            PendingStatus::Voided => PENDING_STATUS_VOIDED,
        };
        let content = pending_leaf_content(&id.0, val);
        self.pending_statuses
            .insert_with_leaf(&id.0, &val, &content);
    }
}
