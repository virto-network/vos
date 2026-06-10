//! `LedgerView` — the borrowed mutable slice over `ClerkLedger`'s
//! state that implements `cipher_clerk::state::LedgerState`. The
//! kernel reads from / writes to the actor's fields through this
//! trait surface; the actor never hands the kernel direct access.
//!
//! Field-targeted construction (rather than `&mut ClerkLedger`)
//! keeps the borrow narrow — the handler can still touch
//! `transfer_roots` / `note_commitments` / other state-tracking
//! Vecs while the kernel runs.

use alloc::vec::Vec;
use cipher_clerk::ids::{
    AccountId as CcAccountId, ExternalId as CcExternalId, JournalId as CcJournalId,
    TransferId as CcTransferId,
};
use cipher_clerk::state::{LedgerState, Oracle, PendingStatus};
use cipher_clerk::types::{Account as CcAccount, Journal as CcJournal, Transfer as CcTransfer};

use crate::smt::compute_state_root;
use crate::wire::{
    PENDING_STATUS_PENDING, PENDING_STATUS_POSTED, PENDING_STATUS_VOIDED, PendingStatusEntry,
};

/// Mutable view over the actor's persistent state that implements
/// cipher-clerk's `LedgerState`. The kernel reads from / writes to
/// the actor's fields through this trait surface; the actor never
/// hands the kernel direct access.
pub(crate) struct LedgerView<'a> {
    accounts: &'a mut Vec<CcAccount>,
    transfers: &'a mut Vec<CcTransfer>,
    external_ids: &'a mut Vec<[u8; 32]>,
    voided_transfers: &'a mut Vec<[u8; 16]>,
    pending_statuses: &'a mut Vec<PendingStatusEntry>,
    journal: Option<&'a CcJournal>,
}

impl<'a> LedgerView<'a> {
    /// Field-targeted constructor — takes disjoint `&mut`s of the
    /// state vectors the kernel might mutate plus a shared borrow
    /// of the journal. Avoids the over-broad `&mut ClerkLedger`
    /// borrow that would prevent the handler from touching any
    /// other part of `self` while the view is alive.
    pub(crate) fn new(
        accounts: &'a mut Vec<CcAccount>,
        transfers: &'a mut Vec<CcTransfer>,
        external_ids: &'a mut Vec<[u8; 32]>,
        voided_transfers: &'a mut Vec<[u8; 16]>,
        pending_statuses: &'a mut Vec<PendingStatusEntry>,
        journal: Option<&'a CcJournal>,
    ) -> Self {
        Self {
            accounts,
            transfers,
            external_ids,
            voided_transfers,
            pending_statuses,
            journal,
        }
    }
}

impl LedgerState for LedgerView<'_> {
    fn root(&self) -> [u8; 32] {
        let pending: Vec<([u8; 16], u8)> = self
            .pending_statuses
            .iter()
            .map(|p| (p.id, p.status))
            .collect();
        compute_state_root(
            self.accounts,
            self.transfers,
            self.journal,
            self.external_ids,
            self.voided_transfers,
            &pending,
        )
    }

    fn get_account(&self, id: &CcAccountId, _o: &mut dyn Oracle) -> Option<CcAccount> {
        self.accounts
            .binary_search_by_key(&id.0, |a| a.id.0)
            .ok()
            .map(|i| self.accounts[i].clone())
    }

    fn put_account(&mut self, a: CcAccount, _o: &mut dyn Oracle) {
        let id = a.id.0;
        match self
            .accounts
            .binary_search_by_key(&id, |existing| existing.id.0)
        {
            Ok(i) => self.accounts[i] = a,
            Err(i) => self.accounts.insert(i, a),
        }
    }

    fn get_journal(&self, id: &CcJournalId, _o: &mut dyn Oracle) -> Option<CcJournal> {
        self.journal.filter(|j| &j.id == id).cloned()
    }

    fn put_journal(&mut self, _j: CcJournal, _o: &mut dyn Oracle) {
        // Bootstrap owns journal writes — the kernel never reaches
        // here in the create_account / apply_batch paths.
        unimplemented!("clerk-ledger: put_journal called outside bootstrap")
    }

    fn get_transfer(&self, id: &CcTransferId, _o: &mut dyn Oracle) -> Option<CcTransfer> {
        self.transfers
            .binary_search_by_key(&id.0, |t| t.id.0)
            .ok()
            .map(|i| self.transfers[i].clone())
    }

    fn put_transfer(&mut self, t: CcTransfer, _o: &mut dyn Oracle) {
        let id = t.id.0;
        match self
            .transfers
            .binary_search_by_key(&id, |existing| existing.id.0)
        {
            Ok(i) => self.transfers[i] = t,
            Err(i) => self.transfers.insert(i, t),
        }
    }

    fn external_id_seen(&self, eid: &CcExternalId, _o: &mut dyn Oracle) -> bool {
        self.external_ids.binary_search(&eid.0).is_ok()
    }

    fn mark_external_id(&mut self, eid: &CcExternalId, _o: &mut dyn Oracle) {
        if let Err(i) = self.external_ids.binary_search(&eid.0) {
            self.external_ids.insert(i, eid.0);
        }
    }

    fn transfer_voided(&self, id: &CcTransferId, _o: &mut dyn Oracle) -> bool {
        self.voided_transfers.binary_search(&id.0).is_ok()
    }

    fn mark_transfer_voided(&mut self, id: &CcTransferId, _o: &mut dyn Oracle) {
        if let Err(i) = self.voided_transfers.binary_search(&id.0) {
            self.voided_transfers.insert(i, id.0);
        }
    }

    fn pending_status(&self, id: &CcTransferId, _o: &mut dyn Oracle) -> Option<PendingStatus> {
        self.pending_statuses
            .binary_search_by_key(&id.0, |e| e.id)
            .ok()
            .map(|i| match self.pending_statuses[i].status {
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
        match self.pending_statuses.binary_search_by_key(&id.0, |e| e.id) {
            Ok(i) => self.pending_statuses[i].status = val,
            Err(i) => self.pending_statuses.insert(
                i,
                PendingStatusEntry {
                    id: id.0,
                    status: val,
                },
            ),
        }
    }
}
