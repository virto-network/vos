//! Clerk bridge — per-bank cross-clerk voucher ingress actor.
//!
//! Each bank space runs ONE clerk-bridge agent. It's the
//! verify-and-dedup gateway for incoming vouchers from peer banks:
//! resolve which peer signed, check the signature against that
//! peer's clerk pubkey, open the sealed envelope to recover the
//! (value, blinding) opening, dedup against previously-seen
//! vouchers, and hand the opening back to the host caller. The
//! caller (a bank operator) decides whether to credit the local
//! recipient via an L0 inflow transfer on clerk-ledger or via an
//! L3 note-pool submit — clerk-bridge is verify-only and stays
//! out of the kernel-transfer-building business.
//!
//! ## Role in the federation
//!
//! Pairs with `clerk-ledger`:
//!   - clerk-ledger holds confidential per-bank state (accounts,
//!     transfers, notes pool, state roots).
//!   - clerk-bridge holds the cross-bank trust state (peer clerk
//!     pubkeys, bank's IVK secret, dedup set).
//!
//! Splitting them serves two purposes:
//!   - **Concern isolation.** clerk-ledger's surface is "the
//!     kernel's wire shape". clerk-bridge's surface is "what bank
//!     B's operator decides to accept from bank A". They can
//!     evolve independently.
//!   - **Future ACL boundary.** When admission lands at the VOS
//!     layer (signed cross-bank envelopes, allowed-peer lists),
//!     clerk-bridge is where it sits. clerk-ledger keeps its
//!     "trust the operator, verify the kernel" stance.
//!
//! ## State (persisted as actor rkyv archive)
//!
//! - `local_ledger_id`: ServiceId of this bank's clerk-ledger.
//!   `0` means not-bootstrapped. Carried for diagnostics + future
//!   cross-actor dispatch (which this slice does not yet do).
//! - `ivk_secret_bytes`: this bank's incoming-viewing-key secret,
//!   canonical 32-byte Ristretto scalar. Used per-call to
//!   reconstruct an `IncomingViewingKey` and open envelopes.
//! - `peers`: sorted-by-name `(peer_name, peer_clerk_pubkey)`
//!   entries. Pre-shared at federation join time via
//!   `register_peer`.
//! - `received`: sorted dedup set of voucher transfer-triples
//!   (`blake2b_256(amount_commit || root_before || root_after)`).
//!
//! ## Security caveats
//!
//! - **IVK secret in actor state.** Persisted in the rkyv archive
//!   means any compromised replica leaks it. Production should
//!   back this with an HSM and pass the unsealed secret in per
//!   ECALL — or run clerk-bridge in a single non-replicated
//!   process. Documented to flag the gap rather than ship it
//!   silently.
//! - **Verify-only.** This slice does NOT credit the local
//!   recipient. The host caller takes the returned (value,
//!   blinding) and builds an inflow transfer or note submit on
//!   clerk-ledger. A future slice will add cross-actor dispatch
//!   so the bridge owns the full ingress flow.

use cipher_clerk::crypto::{AuthKey, blake2b_256};
use cipher_clerk::types::Transfer as CcTransfer;
use cipher_clerk::viewing_keys::IncomingViewingKey;
use cipher_clerk::voucher::Voucher;
use clerk_ledger::ClerkLedgerRef;
use vos::abi::service::ServiceId;
use vos::prelude::*;

// ── Handler status ──────────────────────────────────────────────

/// Return type for `bootstrap` / `register_peer` /
/// `submit_voucher.status` / `redeem_voucher.status`. Each variant
/// classifies a distinct failure mode (or success). Callers
/// `match` instead of comparing raw byte codes.
///
/// `#[repr(u8)]` keeps the wire bytes stable — reordering
/// variants breaks any peer running an older build.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// Input bytes had the wrong length or rkyv shape.
    BadInput = 1,
    /// `bootstrap` called twice with conflicting arguments.
    /// Identical re-calls return `Ok`.
    AlreadyBootstrapped = 2,
    /// Caller invoked a non-bootstrap handler before bootstrap.
    NotBootstrapped = 3,
    /// Voucher parse / signature verify / state-root anchor check
    /// failed. State-hiding bucket: covers every voucher-rejection
    /// path that touched state to look something up.
    VoucherInvalid = 4,
    /// No peer registered under the supplied `peer_name`.
    UnknownPeer = 5,
    /// `EncryptedEnvelope` failed to open with the bootstrap IVK
    /// (truncated ciphertext, MAC mismatch, or non-canonical
    /// blinding bytes inside the plaintext).
    EnvelopeUnreadable = 6,
    /// Voucher's `(amount_commit, root_before, root_after)` triple
    /// was already redeemed against this bridge. Bob is NOT
    /// double-credited.
    VoucherReplayed = 7,
    /// `redeem_voucher`: caller-supplied inflow transfer doesn't
    /// match the voucher. Either the credit-side amount commitment
    /// disagrees with `voucher.amount_commit`, or the
    /// `external_id` doesn't equal the voucher-triple dedup key
    /// the bridge would have computed. The bridge enforces this
    /// link so the operator can't accidentally credit the wrong
    /// amount or skip the per-journal idempotency check.
    InflowInconsistent = 8,
    /// `redeem_voucher`: clerk-ledger.apply_transfer rejected the
    /// inflow. The reason is in `RedeemReply.ledger_status`. The
    /// voucher is NOT marked redeemed — caller can rebuild the
    /// inflow correctly and retry.
    LedgerRejected = 9,
}

// ── Wire types ──────────────────────────────────────────────────

/// rkyv-archivable peer entry. Sorted by `name` ascending in
/// the actor's `peers` Vec; lookups via `partition_point`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PeerEntry {
    /// Federation-visible peer name (e.g. "bank-a"). Bytes are
    /// the operator's choice; the bridge treats them as opaque
    /// keys.
    pub name: Vec<u8>,
    /// Peer bank's clerk pubkey — the issuer's `Voucher`
    /// signature is verified against this.
    pub clerk_pubkey: AuthKey,
}

/// Reply envelope for `submit_voucher`. Same shape pattern as
/// `space_bridge::ForwardReply` — a status byte plus a
/// status-conditional payload. On Status::Ok the caller has the
/// (value, blinding) opening it needs to credit the recipient.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SubmitVoucherReply {
    /// One of `Status::Ok` / `Status::NotBootstrapped` /
    /// `Status::BadInput` / `Status::UnknownPeer` /
    /// `Status::VoucherInvalid` / `Status::EnvelopeUnreadable` /
    /// `Status::VoucherReplayed`.
    pub status: Status,
    /// Recovered cleartext `value` when status is `Status::Ok`;
    /// `0` for every non-OK status. Callers MUST gate on `status`
    /// before reading.
    pub value: u64,
    /// Recovered blinding (canonical 32-byte Ristretto scalar)
    /// when status is `Status::Ok`; empty `Vec` for every non-OK
    /// status.
    pub blinding: Vec<u8>,
}

/// Reply envelope for `redeem_voucher`. Carries the bridge's
/// own status plus the clerk-ledger status code from the
/// dispatched inflow transfer when the bridge made it that far.
///
/// `status` is the bridge's verdict (one of the STATUS_* codes
/// declared in this crate). `ledger_status` is meaningful only
/// when `status == Status::Ok` (the bridge accepted and the
/// ledger accepted) or `status == Status::LedgerRejected` (the
/// bridge accepted but the ledger rejected — `ledger_status` is
/// the clerk-ledger `STATUS_*` code mapping the rejection). For
/// every other bridge status, `ledger_status` is `255` (a
/// sentinel chosen to match clerk-ledger's
/// `STATUS_KERNEL_UNEXPECTED` — also a "you should not have read
/// this byte" indicator).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RedeemReply {
    /// Bridge's own verdict. See `Status` for variants.
    pub status: Status,
    /// clerk-ledger's `Status` code from the dispatched inflow
    /// transfer, encoded as the wire `u8`. Meaningful when
    /// `status == Status::Ok` (== `clerk_ledger::Status::Ok as u8`)
    /// or `status == Status::LedgerRejected` (carries the
    /// specific ledger rejection). `255` for every other bridge
    /// status — the sentinel matches clerk-ledger's
    /// `Status::KernelUnexpected` ("you should not have read this
    /// byte"). Kept as `u8` rather than `clerk_ledger::Status` so
    /// clerk-bridge's public ABI doesn't drag clerk-ledger's
    /// enum into every downstream consumer.
    pub ledger_status: u8,
}

// ── Decode helpers ──────────────────────────────────────────────

/// Convert a `Vec<u8>` to a fixed-size byte array. Returns `None`
/// (caller folds to `Status::BadInput`) on length mismatch.
fn try_array<const N: usize>(bytes: Vec<u8>) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

/// Decode an rkyv archive or short-circuit with the given
/// expression. Used from `redeem_voucher` to keep the inflow-decode
/// site to one line. Macro rather than a generic fn because rkyv's
/// `from_bytes` carries non-trivial where-clauses
/// (`T::Archived: CheckBytes<…> + Deserialize<T, Strategy<Pool,
/// _>>`) — wrapping those is more boilerplate than the macro
/// replaces.
macro_rules! decode_or_else {
    ($bytes:expr, $T:ty, $on_err:expr) => {
        match vos::rkyv::from_bytes::<$T, vos::rkyv::rancor::Error>($bytes) {
            Ok(v) => v,
            Err(_) => return $on_err,
        }
    };
}

// ── Actor ───────────────────────────────────────────────────────

#[actor]
pub struct ClerkBridge {
    /// Local clerk-ledger ServiceId, packed as u32. `0` means
    /// not-yet-bootstrapped — every non-bootstrap handler
    /// short-circuits with Status::NotBootstrapped.
    local_ledger_id: u32,
    /// This bank's IVK secret, raw canonical-scalar bytes. The
    /// `IncomingViewingKey` type itself isn't rkyv-archivable
    /// (it wraps a curve scalar), so we keep the bytes and
    /// reconstruct per call.
    ivk_secret_bytes: [u8; 32],
    /// Sorted-by-`name` ascending. Lookups via `partition_point`.
    peers: Vec<PeerEntry>,
    /// Sorted dedup set of voucher transfer-triples. Each entry
    /// is `blake2b_256("clerk-bridge/voucher-redemption/v1",
    /// amount_commit || root_before || root_after)`. Anchoring
    /// on the underlying kernel-transfer triple (rather than on
    /// voucher bytes or signing_payload) is robust to issuer
    /// re-signing OR re-sealing the envelope — see
    /// vos/tests/elf_integration.rs's voucher-replay coverage
    /// for the rationale.
    received: Vec<[u8; 32]>,
}

#[messages]
impl ClerkBridge {
    fn new() -> Self {
        Self {
            local_ledger_id: 0,
            ivk_secret_bytes: [0u8; 32],
            peers: Vec::new(),
            received: Vec::new(),
        }
    }

    /// One-time initialisation. `local_ledger_id` is the ServiceId
    /// of this bank's clerk-ledger (carried for diagnostics + a
    /// future cross-actor-dispatch slice). `ivk_secret` is the
    /// canonical 32-byte Ristretto scalar this bank uses to open
    /// envelopes sealed by peers.
    ///
    /// Returns:
    ///   - `Status::Ok` on a fresh bootstrap or an idempotent
    ///     re-call with byte-identical arguments.
    ///   - `Status::BadInput` if `ivk_secret.len() != 32` OR if
    ///     the bytes don't decode to a canonical Ristretto
    ///     scalar. Catching non-canonical bytes at bootstrap
    ///     beats deferring the failure to every `submit_voucher`
    ///     call — without this check, a non-canonical secret
    ///     would cause `IncomingViewingKey::from_bytes(...)` to
    ///     return None inside the hot path, and the caller would
    ///     see a confusing Status::NotBootstrapped even though
    ///     bootstrap "succeeded".
    ///   - `Status::AlreadyBootstrapped` if conflicting arguments
    ///     are supplied to a re-call.
    #[msg]
    async fn bootstrap(&mut self, local_ledger_id: u32, ivk_secret: Vec<u8>) -> Status {
        let Some(secret_bytes) = try_array::<32>(ivk_secret) else {
            return Status::BadInput;
        };
        // Canonicality check: reject at bootstrap rather than at
        // every submit_voucher call. IncomingViewingKey::from_bytes
        // returns None on non-canonical scalar bytes.
        if IncomingViewingKey::from_bytes(&secret_bytes).is_none() {
            return Status::BadInput;
        }
        if self.local_ledger_id == 0 {
            self.local_ledger_id = local_ledger_id;
            self.ivk_secret_bytes = secret_bytes;
            Status::Ok
        } else if self.local_ledger_id == local_ledger_id && self.ivk_secret_bytes == secret_bytes {
            Status::Ok
        } else {
            Status::AlreadyBootstrapped
        }
    }

    /// Register a peer bank's clerk pubkey under a federation-
    /// visible name. The bridge looks up by `peer_name` on each
    /// `submit_voucher` call to find the pubkey to verify
    /// against. Re-registering the same name with the same key
    /// is idempotent; with a different key, the entry is
    /// overwritten (the operator is asserting that the peer
    /// rotated its key — there's no separate "rotate" handler in
    /// this slice).
    #[msg]
    async fn register_peer(&mut self, peer_name: Vec<u8>, clerk_pubkey: Vec<u8>) -> Status {
        if self.local_ledger_id == 0 {
            return Status::NotBootstrapped;
        }
        let Some(pk_bytes) = try_array::<32>(clerk_pubkey) else {
            return Status::BadInput;
        };
        if peer_name.is_empty() {
            return Status::BadInput;
        }
        let entry = PeerEntry {
            name: peer_name,
            clerk_pubkey: AuthKey(pk_bytes),
        };
        match self.peers.binary_search_by(|e| e.name.cmp(&entry.name)) {
            Ok(i) => self.peers[i] = entry,
            Err(i) => self.peers.insert(i, entry),
        }
        Status::Ok
    }

    /// Diagnostic — number of registered peers.
    #[msg]
    async fn peer_count(&self) -> u32 {
        self.peers.len() as u32
    }

    /// Diagnostic — number of distinct vouchers redeemed.
    #[msg]
    async fn redeemed_count(&self) -> u32 {
        self.received.len() as u32
    }

    /// Verify + open a voucher. Walks the full ingress check chain
    /// in fail-fast order:
    ///
    ///   1. Bootstrap state present.
    ///   2. Peer registered under `peer_name`.
    ///   3. Voucher bytes parse via `Voucher::from_bytes`.
    ///   4. Voucher signature verifies against the peer's clerk
    ///      pubkey.
    ///   5. Transfer-triple dedup-key not previously redeemed.
    ///   6. EncryptedEnvelope opens with the bootstrap IVK
    ///      secret.
    ///
    /// Only on (6) does the bridge record the voucher in the
    /// dedup set — earlier rejection paths leave state untouched
    /// so a malformed-but-not-replayed voucher can be re-submitted
    /// after being fixed.
    #[msg]
    async fn submit_voucher(&mut self, voucher_bytes: Vec<u8>, peer_name: Vec<u8>) -> SubmitVoucherReply {
        if self.local_ledger_id == 0 {
            return reply(Status::NotBootstrapped);
        }

        let peer = match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => &self.peers[i],
            Err(_) => return reply(Status::UnknownPeer),
        };

        let voucher = match Voucher::from_bytes(&voucher_bytes) {
            Some(v) => v,
            None => return reply(Status::VoucherInvalid),
        };

        if voucher.verify_signature(&peer.clerk_pubkey).is_err() {
            return reply(Status::VoucherInvalid);
        }

        // Dedup BEFORE opening the envelope. A replayed voucher
        // has already been credited by the operator on a prior
        // call; opening again would just leak ciphertext analysis
        // surface to anyone monitoring the bridge.
        let dedup_key = blake2b_256(
            b"clerk-bridge/voucher-redemption/v1",
            &[
                &voucher.amount_commit.0,
                &voucher.state_root_before,
                &voucher.state_root_after,
            ],
        );
        if self.received.binary_search(&dedup_key).is_ok() {
            return reply(Status::VoucherReplayed);
        }

        // SAFETY: bootstrap validates canonicality on entry, so
        // from_bytes never returns None once `local_ledger_id != 0`
        // (which we already gated on above). The expect message
        // calls out the invariant for future readers.
        let ivk = IncomingViewingKey::from_bytes(&self.ivk_secret_bytes)
            .expect("bootstrap guarantees canonical IVK secret");
        let (value, blinding) = match voucher.envelope.open(&ivk) {
            Some(opened) => opened,
            None => return reply(Status::EnvelopeUnreadable),
        };

        // Commit to the dedup set after a successful open. From
        // here the host caller has the opening and can credit the
        // recipient; a second submit with the same triple would
        // hit the replay check above.
        match self.received.binary_search(&dedup_key) {
            Ok(_) => { /* unreachable — checked above */ }
            Err(i) => self.received.insert(i, dedup_key),
        }

        SubmitVoucherReply {
            status: Status::Ok,
            value,
            blinding: blinding.0.to_vec(),
        }
    }

    /// End-to-end atomic ingress: verify the voucher, validate the
    /// caller-supplied inflow Transfer is consistent with it,
    /// dispatch to clerk-ledger.apply_transfer, and mark the
    /// voucher redeemed only on Status::Ok from the ledger.
    ///
    /// Why pass a pre-built inflow rather than have the bridge
    /// construct one? Two reasons. First, building the inflow
    /// needs the inflow-account auth secret to sign, plus the
    /// recipient Account record (for journal_id, ledger, code,
    /// layer details on entries). Keeping the auth secret out of
    /// the bridge's replicated state matches the security posture
    /// of clerk-ledger's `apply_transfer` (signing keys stay
    /// off-actor). Second, fetching the recipient Account would
    /// require an extra cross-actor round trip to clerk-ledger;
    /// having the caller pre-build the inflow avoids that
    /// without losing safety because:
    ///
    /// What the bridge enforces, even on a caller-supplied
    /// inflow:
    ///   - The inflow's `external_id` MUST equal the
    ///     voucher-triple dedup key. The caller can't bypass
    ///     clerk-ledger's external_id dedup; the bridge requires
    ///     the link to be set correctly.
    ///   - The inflow's first entry's `amount` MUST equal the
    ///     voucher's `amount_commit`. Caller can't credit a
    ///     different value than the voucher attests to.
    ///   - The ledger must accept the inflow. Otherwise the
    ///     bridge returns Status::LedgerRejected with the
    ///     clerk-ledger status in `ledger_status`, AND keeps the
    ///     voucher available for retry (no dedup mark).
    ///
    /// On Status::Ok: bridge adds the voucher-triple to its
    /// `received` set atomically with the ledger's accept. A
    /// second redeem_voucher with the same voucher hits the
    /// bridge dedup at step 4 before the ledger is touched a
    /// second time.
    #[msg]
    async fn redeem_voucher(
        &mut self,
        ctx: &mut Context<Self>,
        voucher_bytes: Vec<u8>,
        peer_name: Vec<u8>,
        inflow_transfer_bytes: Vec<u8>,
        inflow_openings_bytes: Vec<u8>,
        batch_seed_timestamp: u64,
    ) -> RedeemReply {
        if self.local_ledger_id == 0 {
            return early_redeem(Status::NotBootstrapped);
        }
        let peer = match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => &self.peers[i],
            Err(_) => return early_redeem(Status::UnknownPeer),
        };
        let Some(voucher) = Voucher::from_bytes(&voucher_bytes) else {
            return early_redeem(Status::VoucherInvalid);
        };
        if voucher.verify_signature(&peer.clerk_pubkey).is_err() {
            return early_redeem(Status::VoucherInvalid);
        }
        let dedup_key = blake2b_256(
            b"clerk-bridge/voucher-redemption/v1",
            &[
                &voucher.amount_commit.0,
                &voucher.state_root_before,
                &voucher.state_root_after,
            ],
        );
        if self.received.binary_search(&dedup_key).is_ok() {
            return early_redeem(Status::VoucherReplayed);
        }

        // Decode the inflow Transfer (host-side rkyv archive) and
        // enforce the voucher-link shape:
        //   1. external_id == blake2b_256(voucher-triple)
        //   2. exactly 2 entries — 1 debit + 1 credit, both
        //      carrying voucher.amount_commit. The kernel's
        //      zero-sum check would catch a multi-entry inflow
        //      that nets out, but the bridge could let a malicious
        //      operator slip phantom entries past us if we only
        //      validated the first one. Tighter rule = less attack
        //      surface; legitimate cross-bank inflows are always
        //      this 1-debit-1-credit shape (the voucher carries
        //      one Amount).
        let inflow: CcTransfer = decode_or_else!(
            &inflow_transfer_bytes,
            CcTransfer,
            early_redeem(Status::BadInput)
        );
        let expected_eid = cipher_clerk::ids::ExternalId(dedup_key);
        if inflow.external_id != Some(expected_eid) {
            return early_redeem(Status::InflowInconsistent);
        }
        if inflow.entries.len() != 2 {
            return early_redeem(Status::InflowInconsistent);
        }
        use cipher_clerk::types::Direction;
        let (debits, credits): (Vec<_>, Vec<_>) = inflow
            .entries
            .iter()
            .partition(|e| matches!(e.direction, Direction::Debit));
        if debits.len() != 1 || credits.len() != 1 {
            return early_redeem(Status::InflowInconsistent);
        }
        if debits[0].amount != voucher.amount_commit
            || credits[0].amount != voucher.amount_commit
        {
            return early_redeem(Status::InflowInconsistent);
        }

        // Envelope open. We don't strictly need the recovered
        // opening here (the caller provided it in
        // inflow_openings_bytes for the kernel's StatefulOracle),
        // BUT we still do the open so the bridge can refuse
        // truncated / MAC-failed envelopes before consulting the
        // ledger. Same defense-in-depth as submit_voucher.
        let ivk = IncomingViewingKey::from_bytes(&self.ivk_secret_bytes)
            .expect("bootstrap guarantees canonical IVK secret");
        if voucher.envelope.open(&ivk).is_none() {
            return early_redeem(Status::EnvelopeUnreadable);
        }

        // Cross-actor dispatch: invoke clerk-ledger's
        // apply_transfer handler on the same node. The mailbox
        // routes by ServiceId; clerk-bridge and clerk-ledger run
        // on the same node so this is a local dispatch (no libp2p
        // hop).
        let ledger = ClerkLedgerRef::at(ServiceId(self.local_ledger_id));
        let Ok(ledger_status) = ledger
            .apply_transfer(
                ctx,
                inflow_transfer_bytes,
                inflow_openings_bytes,
                batch_seed_timestamp,
            )
            .await
        else {
            return early_redeem(Status::LedgerRejected);
        };

        // Convert the typed clerk-ledger Status to a u8 for the
        // reply field. We don't expose clerk_ledger::Status in
        // clerk-bridge's public ABI to avoid pulling clerk-ledger
        // into every consumer of clerk-bridge's reply type.
        let ledger_status_byte = ledger_status as u8;
        if matches!(ledger_status, clerk_ledger::Status::Ok) {
            // Atomic: only mark redeemed if the ledger accepted.
            // Failed dispatches leave the voucher available for
            // retry with a corrected inflow.
            match self.received.binary_search(&dedup_key) {
                Ok(_) => { /* unreachable — checked above */ }
                Err(i) => self.received.insert(i, dedup_key),
            }
            RedeemReply {
                status: Status::Ok,
                ledger_status: ledger_status_byte,
            }
        } else {
            RedeemReply {
                status: Status::LedgerRejected,
                ledger_status: ledger_status_byte,
            }
        }
    }
}

/// Build an error reply with empty value+blinding.
fn reply(status: Status) -> SubmitVoucherReply {
    SubmitVoucherReply {
        status,
        value: 0,
        blinding: Vec::new(),
    }
}

/// Build a `redeem_voucher` reply for paths that rejected before
/// reaching the ledger. `ledger_status = 255` matches
/// `clerk_ledger::Status::KernelUnexpected` as a "you should not
/// have read this byte" sentinel — the caller MUST gate on
/// `status` first.
fn early_redeem(status: Status) -> RedeemReply {
    RedeemReply {
        status,
        ledger_status: 255,
    }
}
