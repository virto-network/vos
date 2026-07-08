//! Clerk ledger — per-bank stateful agent wrapping cipher-clerk's
//! confidential double-entry kernel.
//!
//! ## Role in the federation
//!
//! One `clerk-ledger` agent runs per bank's space, Raft-replicated
//! across that bank's nodes. It is the only stateful clerk-* agent —
//! everything else (clerk-bridge, settle, disclosure) is stateless
//! and reads from this one via `apply_batch_refine` (eventually).
//!
//! ## Module layout
//!
//! - [`status`] — handler `Status` enum + kernel `EventStatus`
//!   mapping.
//! - [`wire`] — public rkyv-archivable wire types (`Opening`,
//!   `PendingStatusEntry`, `TransferRootEntry`).
//! - [`smt`] — composite SMT root computation (allocation-free,
//!   PVM-heap-friendly).
//! - [`view`] — `LedgerView` borrow over the actor state that
//!   implements `cipher_clerk::state::LedgerState`.
//! - [`oracle`] — `NoopOracle` and `StatefulOracle` for the
//!   account-creation and transfer kernel paths.
//!
//! Re-exports at the crate root keep the public ABI flat: callers
//! `use clerk_ledger::{ClerkLedgerRef, Status, Opening, …}` without
//! caring about the internal module split.
//!
//! ## State
//!
//! - `journal`: the single `cipher_clerk::types::Journal` this
//!   ledger is anchored to.
//! - `accounts`: sorted-by-id `Vec<Account>`.
//! - `transfers`: sorted-by-id `Vec<Transfer>`. Accepted transfers
//!   accumulate here; the kernel reads them for void-of /
//!   pending-finalization lookups.
//! - `external_ids`: sorted `Vec<[u8; 32]>` — idempotency set.
//! - `voided_transfers`: sorted `Vec<[u8; 16]>` — TransferIds that
//!   have been voided; second-void is rejected.
//! - `pending_statuses`: sorted-by-id `Vec<PendingStatusEntry>` —
//!   two-phase lifecycle (Pending / Posted / Voided).
//! - `transfer_roots`: per-accepted-transfer (root_before,
//!   root_after) anchor pair. Read by voucher emission.
//! - `note_commitments`: append-only L3 shielded-note pool.
//!
//! Cipher-clerk types embed in the actor's rkyv archive (the two
//! rkyv namespaces unify at the shared 0.8 version), so the kernel
//! reads from / writes to this state via the `LedgerState` trait
//! without any encode/decode-per-access overhead.
//!
//! ## How transfers work
//!
//! The host-side caller builds a signed `cipher_clerk::types::Transfer`
//! and, for each `Amount` commitment in its entries, an `Opening`
//! containing the plaintext value + blinding scalar. Both encode as
//! rkyv archives and arrive at the handler as `Vec<u8>`. The actor
//! decodes, hands the transfer to `cipher_clerk::kernel::apply_batch`
//! through a `LedgerView` over its own state and a `StatefulOracle`
//! that reveals openings on demand.

pub mod oracle;
pub mod smt;
pub mod status;
pub mod view;
pub mod wire;

#[cfg(test)]
mod tests;

use cipher_clerk::crypto::{AuthKey, verify_signature};
use cipher_clerk::ids::{AccountId as CcAccountId, JournalId as CcJournalId};
use cipher_clerk::kernel::{
    CreateAccount as CcCreateAccount, apply_account_creations, apply_batch,
};
use cipher_clerk::types::{
    Account as CcAccount, Direction, Journal as CcJournal, Transfer as CcTransfer, TransferFlags,
};
use vos::prelude::*;

pub use status::Status;
pub use wire::{Opening, PendingStatusEntry, TransferRootEntry};

use oracle::{NoopOracle, StatefulOracle};
use smt::compute_state_root;
use status::map_event_status;
use view::LedgerView;

// ── Decode helpers ──────────────────────────────────────────────

/// Convert a `Vec<u8>` to a fixed-size byte array. Returns `None`
/// (which callers fold to `Status::BadInput`) when the length
/// doesn't match `N`. Lets handler bodies stay terse — no need
/// to spell `: Option<[u8; N]>` on the destructuring pattern.
fn try_array<const N: usize>(bytes: Vec<u8>) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

/// Decode an rkyv archive or short-circuit with `Status::BadInput`.
/// Macro form rather than a generic function because rkyv's
/// `from_bytes` carries non-trivial where-clauses
/// (`T::Archived: CheckBytes<…> + Deserialize<T, Strategy<Pool,
/// _>>`) — replicating them in every wrapper would be more
/// boilerplate than the macro replaces.
macro_rules! decode_or_bad_input {
    ($bytes:expr, $T:ty) => {
        match vos::rkyv::from_bytes::<$T, vos::rkyv::rancor::Error>($bytes) {
            Ok(v) => v,
            Err(_) => return $crate::Status::BadInput,
        }
    };
}

// ── Actor ───────────────────────────────────────────────────────

pub mod roles;
pub use roles::{CLERK_LEDGER_SPACE_ROLE_MAP, ClerkLedgerRole};

#[actor(
    role = ClerkLedgerRole,
    default_role = ClerkLedgerRole::None,
    space_role_map = CLERK_LEDGER_SPACE_ROLE_MAP,
)]
pub struct ClerkLedger {
    journal: Option<CcJournal>,
    /// Sorted by `id` ascending; lookups via `binary_search_by_key`.
    /// BTreeMap-ergonomics deferred until either the grey transpiler
    /// supports the codegen it emits or `docs/design/table.md`'s
    /// Table primitive lands.
    accounts: Vec<CcAccount>,
    transfers: Vec<CcTransfer>,
    /// Sorted ascending.
    external_ids: Vec<[u8; 32]>,
    /// Sorted ascending — voided TransferIds.
    voided_transfers: Vec<[u8; 16]>,
    /// Sorted by `id` ascending.
    pending_statuses: Vec<PendingStatusEntry>,
    /// Per-accepted-transfer `(root_before, root_after)` pair.
    /// Sorted by `id` ascending. Populated by `apply_transfer` at
    /// the moment the kernel accepts the transfer — `root_before`
    /// is the composite state root just before the kernel runs,
    /// `root_after` is the composite state root just after the
    /// kernel's state mutations land. Voucher emission anchors to
    /// these two values; the host-side caller queries
    /// `transfer_state_roots` immediately after `apply_transfer`
    /// returns `Status::Ok`.
    transfer_roots: Vec<TransferRootEntry>,
    /// L3 shielded-note commitments (Pedersen points,
    /// `cipher_clerk::crypto::Amount` bytes). Append-only — the
    /// Merkle-tree leaf order is the insertion order, and
    /// inclusion proofs against historical anchors rely on the
    /// position being stable. The (value, blinding, owner, rho)
    /// opening is held off-ledger by the recipient; this actor
    /// only sees the commitment. Outgoing-side spends would later
    /// publish nullifiers — the spent-set is a follow-up slice.
    note_commitments: Vec<[u8; 32]>,
}

impl ClerkLedger {
    /// Composite SMT root over the actor's full kernel-checked state —
    /// accounts/transfers/journal plus the bookkeeping sets (external
    /// ids, voided transfers, pending statuses), per cipher-clerk's
    /// state-root format.
    fn composite_root(&self) -> [u8; 32] {
        let pending: Vec<([u8; 16], u8)> = self
            .pending_statuses
            .iter()
            .map(|p| (p.id, p.status))
            .collect();
        compute_state_root(
            &self.accounts,
            &self.transfers,
            self.journal.as_ref(),
            &self.external_ids,
            &self.voided_transfers,
            &pending,
        )
    }
}

#[messages]
impl ClerkLedger {
    fn new() -> Self {
        Self {
            journal: None,
            accounts: Vec::new(),
            transfers: Vec::new(),
            external_ids: Vec::new(),
            voided_transfers: Vec::new(),
            pending_statuses: Vec::new(),
            transfer_roots: Vec::new(),
            note_commitments: Vec::new(),
        }
    }

    /// Diagnostic — this clerk-ledger's own `ServiceId` packed as u32.
    #[msg]
    async fn ping(&self, ctx: &mut Context<Self>) -> u32 {
        ctx.id().0
    }

    /// One-time initialization. Records the journal id, registrar
    /// pubkey, and journal type code. Idempotent in identical
    /// arguments.
    #[msg(role = ClerkLedgerRole::Operator)]
    async fn bootstrap(
        &mut self,
        journal_id: [u8; 16],
        registrar_pubkey: [u8; 32],
        code: u32,
    ) -> Status {
        if code > u16::MAX as u32 {
            return Status::BadInput;
        }
        let proposed = CcJournal::new(
            CcJournalId(journal_id),
            AuthKey(registrar_pubkey),
            code as u16,
        );
        match &self.journal {
            None => {
                self.journal = Some(proposed);
                Status::Ok
            }
            Some(existing) if *existing == proposed => Status::Ok,
            Some(_) => Status::AlreadyBootstrapped,
        }
    }

    #[msg]
    async fn journal_id(&self) -> Vec<u8> {
        self.journal
            .as_ref()
            .map(|j| j.id.0.to_vec())
            .unwrap_or_default()
    }

    #[msg]
    async fn registrar_pubkey(&self) -> Vec<u8> {
        self.journal
            .as_ref()
            .map(|j| j.registrar_auth_key.0.to_vec())
            .unwrap_or_default()
    }

    /// Accept a registrar-signed `CreateAccount`. Signature gate
    /// before any state-dependent rejection so attackers can't
    /// probe state by submitting junk-signed creates.
    #[msg(role = ClerkLedgerRole::Operator)]
    async fn create_account(
        &mut self,
        create_account_bytes: Vec<u8>,
        batch_seed_timestamp: u64,
    ) -> Status {
        if self.journal.is_none() {
            return Status::NotBootstrapped;
        }

        let create: CcCreateAccount = decode_or_bad_input!(&create_account_bytes, CcCreateAccount);

        let registrar_key = self
            .journal
            .as_ref()
            .map(|j| j.registrar_auth_key)
            .expect("bootstrap check above ensures journal is Some");
        let payload = create.account.signing_payload();
        if !verify_signature(&registrar_key, &payload, &create.signature) {
            return Status::SignatureInvalid;
        }

        let mut view = LedgerView::new(
            &mut self.accounts,
            &mut self.transfers,
            &mut self.external_ids,
            &mut self.voided_transfers,
            &mut self.pending_statuses,
            self.journal.as_ref(),
        );
        let mut oracle = NoopOracle;
        let results = apply_account_creations(
            &mut view,
            core::slice::from_ref(&create),
            &mut oracle,
            batch_seed_timestamp,
        );
        map_event_status(results[0].status)
    }

    /// Accept a signed `cipher_clerk::types::Transfer` plus the
    /// commitment openings (`Vec<Opening>`) needed by the kernel
    /// to verify each entry's `Amount`. Dispatches to
    /// `apply_batch` against the actor's state.
    ///
    /// The caller is responsible for:
    ///   - Building a syntactically-valid Transfer (correct entries,
    ///     signatures by every distinct debited account)
    ///   - Providing one `Opening` per distinct `Amount` commitment
    ///     in the transfer
    ///   - Stamping `transfer.timestamp` as 0 (kernel will stamp)
    ///
    /// Returns the kernel's `EventStatus` mapped to the
    /// clerk-ledger `Status` taxonomy. On `Status::Ok` the transfer
    /// is recorded in state and the touched accounts' balance
    /// commits are updated via the Pedersen homomorphism.
    #[msg(role = ClerkLedgerRole::Operator)]
    async fn apply_transfer(
        &mut self,
        transfer_bytes: Vec<u8>,
        openings_bytes: Vec<u8>,
        batch_seed_timestamp: u64,
    ) -> Status {
        if self.journal.is_none() {
            return Status::NotBootstrapped;
        }
        let transfer: CcTransfer = decode_or_bad_input!(&transfer_bytes, CcTransfer);
        let openings: Vec<Opening> = decode_or_bad_input!(&openings_bytes, Vec<Opening>);

        // Signature pre-verify gate. The kernel also verifies, but
        // only after touching state (account existence, CLOSED flag)
        // — which lets a caller probe state by submitting transfers
        // with junk signatures and observing whether the rejection
        // is Status::AccountNotFound / Status::AccountClosed vs
        // Status::SignatureInvalid. We collapse every signature-side
        // failure (count mismatch, account missing, bad sig) into a
        // single Status::SignatureInvalid bucket BEFORE any
        // state-dependent rejection runs.
        //
        // Pending-finalization transfers skip this gate because
        // their debited set lives in the referenced pending
        // transfer, not in `transfer.entries`. We detect them by
        // FLAGS (POST_PENDING_TRANSFER or VOID_PENDING_TRANSFER),
        // matching the kernel's own dispatch in `apply_batch`.
        //
        // Why not `pending_id.is_some() && entries.is_empty()`?
        // That admitted a state-info-leak path: an attacker
        // submitting `flags=POST_PENDING, entries non-empty,
        // pending_id set, valid signatures` would clear pre-verify
        // (entries-based check runs, sigs verify), then the kernel
        // would dispatch to apply_pending_finalize which probes
        // state for `get_transfer(pending_id)` and returns
        // TransferNotFound → Status::AccountNotFound vs
        // PendingFinalizationMustHaveNoEntries depending on whether
        // pending_id was real. Flag-based detection routes the
        // attacker's transfer to the finalize path immediately, and
        // apply_pending_finalize's first two checks
        // (PendingIdMustBeSet / PendingFinalizationMustHaveNoEntries)
        // return without touching state.
        //
        // The remaining narrower leak: an attacker who CORRECTLY
        // constructs a finalize transfer (proper flags, empty
        // entries, pending_id set) can still probe whether that
        // pending_id is on file via the TransferNotFound code path.
        // Acceptable for v1: a caller able to name a specific
        // pending_id is already operator-adjacent.
        let is_pending_finalize = transfer.flags.contains(TransferFlags::POST_PENDING_TRANSFER)
            || transfer.flags.contains(TransferFlags::VOID_PENDING_TRANSFER);
        if !is_pending_finalize {
            let mut distinct_debits: Vec<CcAccountId> = Vec::new();
            for e in &transfer.entries {
                if e.direction == Direction::Debit && !distinct_debits.contains(&e.account_id) {
                    distinct_debits.push(e.account_id);
                }
            }
            if transfer.signatures.len() != distinct_debits.len() {
                return Status::SignatureInvalid;
            }
            let msg = transfer.signing_payload();
            for (acct_id, sig) in distinct_debits.iter().zip(transfer.signatures.iter()) {
                let acct = match self.accounts.binary_search_by_key(&acct_id.0, |a| a.id.0) {
                    Ok(i) => &self.accounts[i],
                    Err(_) => return Status::SignatureInvalid,
                };
                if !verify_signature(&acct.auth_key, &msg, sig) {
                    return Status::SignatureInvalid;
                }
            }
        }

        // Snapshot the composite SMT root BEFORE the kernel runs.
        // If the kernel accepts (`Status::Ok`), we'll snapshot again
        // after and store both alongside the transfer id. Voucher
        // emission anchors to this pair so the receiver can verify
        // the transfer happened "between" two known ledger states.
        let root_before = self.composite_root();

        let mut view = LedgerView::new(
            &mut self.accounts,
            &mut self.transfers,
            &mut self.external_ids,
            &mut self.voided_transfers,
            &mut self.pending_statuses,
            self.journal.as_ref(),
        );
        let mut oracle = StatefulOracle {
            openings: &openings,
        };
        let results = apply_batch(
            &mut view,
            core::slice::from_ref(&transfer),
            &mut oracle,
            batch_seed_timestamp,
        );
        let status = map_event_status(results[0].status);
        // Only record root anchors on a clean accept. Failed
        // dispatches don't mutate state, so root_after == root_before
        // would be a degenerate anchor with no value; the caller can
        // detect failure via the returned status.
        if status == Status::Ok {
            let root_after = self.composite_root();
            let entry = TransferRootEntry {
                id: transfer.id.0,
                root_before,
                root_after,
            };
            match self
                .transfer_roots
                .binary_search_by_key(&entry.id, |e| e.id)
            {
                // A duplicate id at this point means the kernel
                // accepted twice — replay protection should have
                // caught it. Defensively overwrite rather than
                // silently double-insert (which would break
                // binary_search invariants).
                Ok(i) => self.transfer_roots[i] = entry,
                Err(i) => self.transfer_roots.insert(i, entry),
            }
        }
        status
    }

    /// Read an account by id.
    #[msg(role = ClerkLedgerRole::Member)]
    async fn account(&self, id: [u8; 16]) -> Option<CcAccount> {
        self.accounts
            .binary_search_by_key(&id, |a| a.id.0)
            .ok()
            .map(|i| self.accounts[i].clone())
    }

    /// Read a transfer by id.
    #[msg(role = ClerkLedgerRole::Member)]
    async fn transfer(&self, id: [u8; 16]) -> Option<CcTransfer> {
        self.transfers
            .binary_search_by_key(&id, |t| t.id.0)
            .ok()
            .map(|i| self.transfers[i].clone())
    }

    /// Read the `(state_root_before, state_root_after)` anchor pair
    /// captured at the moment `apply_transfer` accepted this
    /// transfer. Returns `None` if the id was never accepted (or
    /// failed mid-dispatch). Each Vec is exactly 32 bytes when
    /// present.
    ///
    /// This is the host-side voucher builder's entry point: after
    /// `apply_transfer` returns `Status::Ok`, query the two roots,
    /// then construct a `cipher_clerk::voucher::Voucher` with
    /// `state_root_before` / `state_root_after` set from this pair
    /// and `signature` produced by the bank's clerk-key off-actor.
    /// Keeping the signing key out of replicated actor state.
    #[msg(role = ClerkLedgerRole::Member)]
    async fn transfer_state_roots(&self, id: [u8; 16]) -> Option<(Vec<u8>, Vec<u8>)> {
        self.transfer_roots
            .binary_search_by_key(&id, |e| e.id)
            .ok()
            .map(|i| {
                (
                    self.transfer_roots[i].root_before.to_vec(),
                    self.transfer_roots[i].root_after.to_vec(),
                )
            })
    }

    #[msg(role = ClerkLedgerRole::Member)]
    async fn account_count(&self) -> u32 {
        self.accounts.len() as u32
    }

    #[msg(role = ClerkLedgerRole::Member)]
    async fn transfer_count(&self) -> u32 {
        self.transfers.len() as u32
    }

    /// Composite SMT root over the full kernel-checked state (accounts,
    /// transfers, journal + the external-id / voided / pending
    /// bookkeeping sub-SMTs) — see [`ClerkLedger::composite_root`]. This
    /// is the 32-byte state anchor every voucher / disclosure proof /
    /// cross-clerk message commits to. Returns an empty `Vec` if the
    /// ledger isn't bootstrapped — the all-zero root would be a
    /// forgeable anchor, so callers must distinguish "no root" from
    /// "this is the root".
    ///
    /// Runtime cost: O(N · log N) per call (rebuilds sorted leaf
    /// hashes then walks 128 SMT levels). Allocation-free recursion
    /// — each call allocates O(N) for the leaf vec and frees it on
    /// return; no persistent SMT state. The picky-fast path
    /// (incremental cached sub-SMTs) is a follow-up optimisation;
    /// today's demo scale doesn't pressure it.
    #[msg(role = ClerkLedgerRole::Member)]
    async fn state_root(&self) -> Vec<u8> {
        match self.journal.as_ref() {
            Some(_) => self.composite_root().to_vec(),
            None => Vec::new(),
        }
    }

    /// Append a shielded-note commitment (a 32-byte Pedersen point)
    /// to the L3 notes pool. The leaf order is the insertion order
    /// — append-only — because future inclusion-proof verification
    /// against historical Merkle anchors needs the position to be
    /// stable.
    ///
    /// The actor never sees the (value, blinding, owner, rho)
    /// opening; the recipient holds it off-ledger in a wallet.
    /// This is what makes the L3 receive path "shielded" — anyone
    /// reading bank B's clerk-ledger sees the Pedersen point but
    /// can't read the value or correlate it to bank A's
    /// `amount_commit` without one of the two banks' help.
    ///
    /// Returns `Status::Ok` on append, `Status::BadInput` if the
    /// commitment isn't 32 bytes. (Pedersen-point validity beyond
    /// length is the kernel's / verifier's concern; clerk-ledger
    /// just stores bytes.)
    #[msg(role = ClerkLedgerRole::Operator)]
    async fn submit_note_commitment(&mut self, commitment: Vec<u8>) -> Status {
        let Some(bytes) = try_array::<32>(commitment) else {
            return Status::BadInput;
        };
        self.note_commitments.push(bytes);
        Status::Ok
    }

    /// Number of note commitments in the L3 pool.
    #[msg(role = ClerkLedgerRole::Member)]
    async fn note_commitment_count(&self) -> u32 {
        self.note_commitments.len() as u32
    }

    /// Read a note commitment by its insertion index. Returns an
    /// empty `Vec` for out-of-range indices.
    #[msg(role = ClerkLedgerRole::Member)]
    async fn note_commitment_at(&self, index: u32) -> Vec<u8> {
        self.note_commitments
            .get(index as usize)
            .map(|c| c.to_vec())
            .unwrap_or_default()
    }
}
