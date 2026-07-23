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
//! - `peers`: sorted-by-name `(peer_name, peer_clerk_pubkey,
//!   node_prefix, last_root_after)` entries. Pre-shared at
//!   federation join time via `register_peer`; `last_root_after`
//!   is the receiver-side state-root anchor cursor (see caveats).
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
//! - **Verify-only (`submit_voucher`).** This path does NOT credit
//!   the local recipient — the host caller takes the returned
//!   (value, blinding) and builds an inflow transfer or note submit
//!   on clerk-ledger. (`redeem_voucher` DOES own the full ingress:
//!   it validates the inflow and dispatches to
//!   `clerk-ledger.apply_transfer` atomically.)
//! - **Receiver-side state-root anchor (best-effort, not finality).**
//!   Each peer entry carries `last_root_after`: once the bridge
//!   accepts a voucher from a peer, that peer's NEXT voucher must
//!   declare `state_root_before == last_root_after`, forcing a
//!   single linear voucher chain per peer (the first voucher is
//!   unanchored). This blocks replay, reordering, and forking of
//!   the voucher sequence *as this receiver sees it*. It does NOT
//!   prove the roots reflect real ledger state — in Signature-mode
//!   the stored `root_after` is merely what the peer signed; only
//!   an External proof or Wave-2 on-chain settlement grounds them.
//!   It also fails CLOSED: a peer whose ledger legitimately advances
//!   off this channel (a voucher to a different receiver, or any
//!   non-vouchered transfer) declares a `state_root_before` this
//!   bridge never observed and is rejected — and because rejections
//!   don't advance the cursor, that channel can wedge until
//!   settlement. Best-effort linearization, not settlement finality.

use cipher_clerk::crypto::AuthKey;
use cipher_clerk::types::Transfer as CcTransfer;
use cipher_clerk::viewing_keys::IncomingViewingKey;
use cipher_clerk::voucher::Voucher;
use clerk_ledger::ClerkLedgerRef;
use vos::abi::service::ServiceId;
use vos::prelude::*;
use vos::storage::{StorageMap, StorageSet};

mod window;

pub mod roles;
pub use roles::{CLERK_BRIDGE_SPACE_ROLE_MAP, ClerkBridgeRole};

/// The fixed demo settlement currency (ISO-4217 USD). Vouchers carry no
/// currency (`cipher-clerk/src/voucher/mod.rs`), so the bridge stamps this
/// into the receiver-term accumulator key. Multi-currency federation would
/// instead carry a per-peer currency on `register_peer`; the accumulator is
/// keyed by currency from the start so commitments never silently mix under
/// one claim.
pub const DEMO_CURRENCY: u32 = 840;

// ── Handler status ──────────────────────────────────────────────

/// Return type for `bootstrap` / `register_peer` /
/// `submit_voucher.status` / `redeem_voucher.status`. Each variant
/// classifies a distinct failure mode (or success). Callers
/// `match` instead of comparing raw byte codes.
///
/// `#[repr(u8)]` keeps the wire bytes stable — reordering
/// variants breaks any peer running an older build.
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
    /// Voucher carries `proof.mode == Mode::External` and the
    /// configured general `prover` extension rejected the proof —
    /// either STARK validity against the trusted program commitment
    /// or the io-binding to the voucher's `(public, return)` failed
    /// (or the proof bytes weren't fetchable). Distinguishes a
    /// cryptographically-invalid External proof from a malformed
    /// voucher or a bad signature (those still map to
    /// `VoucherInvalid`). Only reachable when `set_prover` has
    /// been called with a non-zero id; without a configured prover,
    /// External-mode vouchers fall through the signature check
    /// (same trust model as Signature-mode vouchers).
    ProofInvalid = 10,
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
    /// Peer's libp2p `node_prefix` (upper 16 bits of a ServiceId).
    /// Used as a hint when dispatching `verify_voucher_proof` so
    /// the host's `EFFECT_BLOB_GET` can fetch proof bytes
    /// directly from the issuing peer rather than fanning out to
    /// every connected node. `0` means "no hint" — pre-existing
    /// peers registered before the prefix field landed default
    /// to this and stay correct (just less efficient).
    pub node_prefix: u16,
    /// Last `state_root_after` this bridge ACCEPTED from this peer
    /// (a `submit_voucher` that opened the envelope, or a
    /// `redeem_voucher` the ledger accepted). `None` until the
    /// first accepted voucher — the first voucher from a peer is
    /// never anchored (there is no prior observed root). On every
    /// subsequent voucher the bridge requires
    /// `voucher.state_root_before == last_root_after`, forcing a
    /// single linear voucher chain per peer. This is best-effort
    /// linearization, not settlement finality — see the actor-level
    /// "receiver-side state-root anchor" doc for the exact
    /// guarantee and its limits.
    pub last_root_after: Option<[u8; 32]>,
    /// Current settlement window (operational bracket) for this peer.
    /// Starts at `0`; `window_rotate` advances it. The receiver-term
    /// accumulator (`window_nets`) is keyed by this value, so rotating
    /// closes the current bracket and opens the next. Vouchers carry no
    /// window id — the bracket is bank-operator authority, not wire data.
    pub window: u64,
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

#[actor(
    role = ClerkBridgeRole,
    default_role = ClerkBridgeRole::None,
    space_role_map = CLERK_BRIDGE_SPACE_ROLE_MAP,
)]
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
    ///
    /// A `#[storage]` set: each redeemed triple is its own KV row, so the
    /// dedup set grows past the guest heap and a submit/redeem touches a
    /// constant handful of rows (one contains, one insert) however many
    /// vouchers have been settled. Membership is the only query.
    #[storage]
    received: StorageSet<[u8; 32]>,
    /// ServiceId of the general `prover` extension this bridge
    /// dispatches `Mode::External` voucher-proof verification
    /// against. `0` means "no prover wired" — External-mode
    /// vouchers then fall through the wire-signature check
    /// (same trust model as Signature-mode). Set via
    /// `set_prover`; persisted across actor restarts as part of
    /// the rkyv archive.
    prover_id: u32,
    /// Trusted canonical commitment ALLOWLIST for the `voucher-check`
    /// program — the concatenation of the accepted 32-byte
    /// preprocessed-trace Merkle roots (`32·N` bytes) the bridge hands
    /// the general prover's `verify_chain` as the program-identity
    /// anchor. It is voucher-check provenance, supplied out-of-band by
    /// the operator via `set_prover` (the general prover is
    /// program-agnostic). Empty ⇒ External-mode dispatch is rejected by the
    /// prover (no accepted commitment) — a misconfigured allowlist can
    /// never silently accept.
    allowlist: Vec<u8>,
    /// Receiver-term accumulators, one per `(peer, currency, window)`. Each
    /// holds the negated sum of the `amount_commit`s this bridge has
    /// accepted from that peer in that window — the mandatory receiver half
    /// of the peer's settlement claim.
    ///
    /// A `#[storage]` map keyed by `window::window_key(peer, currency,
    /// window)` (a 32-byte fold of the operator-opaque, variable-length
    /// triple) → the running `neg_sum`. Accumulation is a point
    /// get-or-insert, so it costs one read + one write regardless of how
    /// many windows the bridge has ever tracked.
    #[storage]
    window_nets: StorageMap<[u8; 32], [u8; 32]>,
}

#[messages]
impl ClerkBridge {
    fn new() -> Self {
        Self {
            local_ledger_id: 0,
            ivk_secret_bytes: [0u8; 32],
            peers: Vec::new(),
            received: StorageSet::default(),
            prover_id: 0,
            allowlist: Vec::new(),
            window_nets: StorageMap::default(),
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

    /// Configure the general `prover` extension to dispatch
    /// Mode::External voucher proofs to, together with the trusted
    /// canonical commitment `allowlist` (the concatenation of the
    /// accepted 32-byte program-identity anchors for `voucher-check`,
    /// `32·N` bytes — voucher-check provenance the operator holds).
    /// Setting `prover_id = 0` disables prover dispatch (External-mode
    /// vouchers then fall through the wire-signature check, same as
    /// Signature-mode).
    ///
    /// The allowlist is the SOLE cross-program soundness anchor the
    /// bridge supplies to `verify_chain`; a wrong/empty one makes the
    /// prover reject every External proof (deny-by-default) rather than
    /// silently accept.
    ///
    /// Idempotent in identical arguments. Separate from `bootstrap` so
    /// the wire ABI stays additive: existing callers that don't know
    /// about prover dispatch keep working with `prover_id` defaulted to
    /// 0.
    #[msg]
    async fn set_prover(&mut self, prover_id: u32, allowlist: Vec<u8>) -> Status {
        if self.local_ledger_id == 0 {
            return Status::NotBootstrapped;
        }
        self.prover_id = prover_id;
        self.allowlist = allowlist;
        Status::Ok
    }

    /// Diagnostic — current prover ServiceId, or `0` if none.
    #[msg]
    async fn prover(&self) -> u32 {
        self.prover_id
    }

    /// Register a peer bank's clerk pubkey under a federation-
    /// visible name. The bridge looks up by `peer_name` on each
    /// `submit_voucher` call to find the pubkey to verify
    /// against. Re-registering the same name with the same key
    /// is idempotent; with a different key, the entry is
    /// overwritten (the operator is asserting that the peer
    /// rotated its key — there's no separate "rotate" handler in
    /// this slice).
    ///
    /// `node_prefix` is the peer's libp2p prefix — passed through
    /// to the prover extension as a fetch hint so it knows which
    /// node to ask for proof blobs before fanning out. `0` means
    /// "unknown" and is the right value for in-process tests
    /// without a network; the host falls back to broadcast.
    #[msg]
    async fn register_peer(
        &mut self,
        peer_name: Vec<u8>,
        clerk_pubkey: Vec<u8>,
        node_prefix: u32,
    ) -> Status {
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
            node_prefix: (node_prefix & 0xFFFF) as u16,
            last_root_after: None,
            window: 0,
        };
        match self.peers.binary_search_by(|e| e.name.cmp(&entry.name)) {
            // Re-register (idempotent refresh OR key rotation): update
            // the pubkey/prefix but PRESERVE the state-root anchor. The
            // chain tracks the peer's ledger progression, orthogonal to
            // its signing key; rewinding to None on a rotation would
            // reopen the fork/replay window the anchor closes.
            Ok(i) => {
                self.peers[i].clerk_pubkey = entry.clerk_pubkey;
                self.peers[i].node_prefix = entry.node_prefix;
            }
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
    ///   6. State-root anchor: `voucher.state_root_before` equals
    ///      the last `state_root_after` accepted from this peer
    ///      (skipped for the peer's first voucher).
    ///   7. EncryptedEnvelope opens with the bootstrap IVK
    ///      secret.
    ///
    /// Only on (7) does the bridge record the voucher in the dedup
    /// set and advance the peer's anchor — earlier rejection paths
    /// leave state untouched so a malformed-but-not-replayed voucher
    /// can be re-submitted after being fixed.
    #[msg]
    async fn submit_voucher(
        &mut self,
        ctx: &mut Context<Self>,
        voucher_bytes: Vec<u8>,
        peer_name: Vec<u8>,
    ) -> SubmitVoucherReply {
        if self.local_ledger_id == 0 {
            return reply(Status::NotBootstrapped);
        }

        let (peer_clerk_pubkey, peer_prefix, expected_root) =
            match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
                Ok(i) => (
                    self.peers[i].clerk_pubkey,
                    self.peers[i].node_prefix,
                    self.peers[i].last_root_after,
                ),
                Err(_) => return reply(Status::UnknownPeer),
            };

        let voucher = match Voucher::from_bytes(&voucher_bytes) {
            Some(v) => v,
            None => return reply(Status::VoucherInvalid),
        };

        // E5: consumer-facing signature check. Passing `None` keeps this
        // to `verify_signature`; the state-root anchor is a distinct check
        // applied below (after external-proof dispatch + dedup) so a bad
        // signature collapses to `VoucherInvalid` here and a non-chaining
        // root does the same at the anchor.
        if voucher.verify(&peer_clerk_pubkey, None).is_err() {
            return reply(Status::VoucherInvalid);
        }

        // Dispatch Mode::External proofs to the configured prover
        // BEFORE dedup so a rejected proof doesn't poison the dedup
        // set; same posture as the UnknownPeer rejection above. The
        // dispatch is a no-op when prover_id == 0 or the voucher's
        // proof is Signature-mode.
        if dispatch_external_proof(
            ctx,
            self.prover_id,
            &self.allowlist,
            &voucher,
            &peer_clerk_pubkey,
            peer_prefix,
        )
        .await
            == Status::ProofInvalid
        {
            return reply(Status::ProofInvalid);
        }

        // Dedup BEFORE opening the envelope. A replayed voucher
        // has already been credited by the operator on a prior
        // call; opening again would just leak ciphertext analysis
        // surface to anyone monitoring the bridge.
        let dedup_key = voucher.redemption_key();
        if self.received.contains(&dedup_key) {
            return reply(Status::VoucherReplayed);
        }

        // Receiver-side state-root anchor. Placed AFTER the external-proof
        // dispatch and the dedup check so a bad proof still reports
        // ProofInvalid and a replay still reports VoucherReplayed; a
        // genuine non-chaining voucher collapses to VoucherInvalid.
        // `expected_root == None` (first voucher from this peer) skips it.
        if let Some(expected) = expected_root
            && voucher.state_root_before != expected
        {
            return reply(Status::VoucherInvalid);
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

        // Bind the credited opening to the settled commitment. The value
        // the operator credits comes from the envelope; the amount folded
        // into the settlement net flow comes from `amount_commit`. Nothing
        // upstream ties them together — the issuer signs both independently
        // — so without this check a malicious issuer could seal value 100
        // while committing to 10 (the receiver credits 100 but the window
        // settles for 10), or ship a non-canonical `amount_commit` that the
        // receiver term folds as the identity. Byte equality against a
        // freshly recomputed canonical commitment forces the two to agree
        // AND forces `amount_commit` to be a valid Ristretto point. The
        // blinding is canonical (envelope.open returns it via
        // Blinding::from_bytes), so `commit` cannot panic.
        if cipher_clerk::crypto::Amount::commit(value, &blinding) != voucher.amount_commit {
            return reply(Status::VoucherInvalid);
        }

        // Commit to the dedup set after a successful open. From
        // here the host caller has the opening and can credit the
        // recipient; a second submit with the same triple would
        // hit the replay check above.
        // Idempotent: the replay check above already returned, so this is
        // a fresh triple; `insert` returns whether it was new.
        self.received.insert(&dedup_key);
        // Advance the per-peer anchor to this voucher's post-state, and
        // fold the accepted commit into the current window's receiver term
        // — the two move together so the settlement sum and the anchor
        // never diverge. Only here, on the acceptance path — a rejected
        // voucher leaves both where the last accepted one left them.
        // Re-resolve by name: the earlier lookup's borrow is gone and its
        // index may be stale after the await.
        if let Ok(pi) = self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            self.peers[pi].last_root_after = Some(voucher.state_root_after);
            let window = self.peers[pi].window;
            window::accumulate_neg(
                &mut self.window_nets,
                &peer_name,
                DEMO_CURRENCY,
                window,
                &voucher.amount_commit,
            );
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
        let (peer_clerk_pubkey, peer_prefix, expected_root) =
            match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
                Ok(i) => (
                    self.peers[i].clerk_pubkey,
                    self.peers[i].node_prefix,
                    self.peers[i].last_root_after,
                ),
                Err(_) => return early_redeem(Status::UnknownPeer),
            };
        let Some(voucher) = Voucher::from_bytes(&voucher_bytes) else {
            return early_redeem(Status::VoucherInvalid);
        };
        // E5: signature-only check (same as submit_voucher); the state-root
        // anchor is applied below, after external-proof dispatch + dedup.
        if voucher.verify(&peer_clerk_pubkey, None).is_err() {
            return early_redeem(Status::VoucherInvalid);
        }
        if dispatch_external_proof(
            ctx,
            self.prover_id,
            &self.allowlist,
            &voucher,
            &peer_clerk_pubkey,
            peer_prefix,
        )
        .await
            == Status::ProofInvalid
        {
            return early_redeem(Status::ProofInvalid);
        }
        let dedup_key = voucher.redemption_key();
        if self.received.contains(&dedup_key) {
            return early_redeem(Status::VoucherReplayed);
        }

        // Receiver-side state-root anchor (see submit_voucher). After the
        // external-proof dispatch + dedup so bad proofs stay ProofInvalid
        // and replays stay VoucherReplayed; a non-chaining voucher
        // collapses to VoucherInvalid. Skipped for the peer's first voucher.
        if let Some(expected) = expected_root
            && voucher.state_root_before != expected
        {
            return early_redeem(Status::VoucherInvalid);
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
        // The voucher owns the inflow-link policy (external_id ==
        // redemption_key; exactly 1 debit + 1 credit; both amounts ==
        // amount_commit). See `cipher_clerk::voucher::Voucher::validate_inflow`.
        if voucher.validate_inflow(&inflow).is_err() {
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
        // Reject a non-canonical `amount_commit` before it reaches the
        // ledger or the receiver term. `validate_inflow` above pins the
        // inflow amounts to `amount_commit` byte-for-byte, and the ledger
        // checks the openings, so the value path is already bound here;
        // this guard closes the degenerate-commit route symmetrically with
        // submit_voucher and makes the receiver-term fold total.
        if voucher.amount_commit.to_point().is_none() {
            return early_redeem(Status::VoucherInvalid);
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
            // retry with a corrected inflow. The replay check above
            // already returned, so this triple is fresh.
            self.received.insert(&dedup_key);
            // Advance the per-peer anchor to this voucher's post-state and
            // fold the accepted commit into the current window's receiver
            // term, atomically with the ledger accept (the rejection paths
            // above never reach here, so both only move on acceptance).
            if let Ok(pi) = self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
                self.peers[pi].last_root_after = Some(voucher.state_root_after);
                let window = self.peers[pi].window;
                window::accumulate_neg(
                    &mut self.window_nets,
                    &peer_name,
                    DEMO_CURRENCY,
                    window,
                    &voucher.amount_commit,
                );
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

    /// Rotate the settlement window for a peer: close the current bracket
    /// and open the next (`window += 1`). The next window's receiver term
    /// starts empty; the closed window's `window_net` stays queryable for
    /// claim production. Operator-gated — bracketing a window is bank-
    /// operator authority, the same authority as S4's `anchor_reset`.
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn window_rotate(&mut self, peer_name: Vec<u8>) -> Status {
        if self.local_ledger_id == 0 {
            return Status::NotBootstrapped;
        }
        match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => {
                self.peers[i].window += 1;
                Status::Ok
            }
            Err(_) => Status::UnknownPeer,
        }
    }

    /// The peer's current settlement window (operational bracket), or
    /// `u64::MAX` if the peer is unknown.
    #[msg]
    async fn current_window(&self, peer_name: Vec<u8>) -> u64 {
        match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => self.peers[i].window,
            Err(_) => u64::MAX,
        }
    }

    /// The receiver term for `(peer, currency, window)` — the negated sum
    /// of accepted vouchers' `amount_commit` as a 32-byte Pedersen point.
    /// Empty `Vec` when nothing has accumulated there (a window with no
    /// accepted vouchers contributes the identity/zero term to the claim).
    #[msg]
    async fn window_net(&self, peer_name: Vec<u8>, currency: u32, window: u64) -> Vec<u8> {
        window::window_net(&self.window_nets, &peer_name, currency, window)
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }

    /// Post-settlement wedge recovery. The F2 receiver-side anchor fails
    /// CLOSED: a peer whose ledger legitimately advanced off this channel
    /// (or across a settled window boundary) declares a `state_root_before`
    /// this bridge never observed, is rejected, and — because rejections
    /// don't advance the cursor — that channel wedges. `anchor_reset`
    /// re-anchors the peer's `last_root_after` to `root` (the settled
    /// window's closing root), so the peer's next voucher chains cleanly
    /// again. This makes settlement the *sanctioned* recovery for the wedge
    /// the anchor deliberately leaves open. Operator-gated — the operator
    /// asserts the settlement occurred (the bridge, on the bank's space,
    /// can't see the venue's settled log); same authority as
    /// `window_rotate`.
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn anchor_reset(&mut self, peer_name: Vec<u8>, root: [u8; 32]) -> Status {
        if self.local_ledger_id == 0 {
            return Status::NotBootstrapped;
        }
        match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => {
                self.peers[i].last_root_after = Some(root);
                Status::Ok
            }
            Err(_) => Status::UnknownPeer,
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

/// Dispatch a Mode::External voucher's proof to the configured general
/// `prover` extension for verification. Returns:
///   - `Status::Ok` if the voucher is Signature-mode, OR if
///     `prover_id == 0`, OR if the prover accepted the proof.
///   - `Status::ProofInvalid` on any rejection path (prover replied
///     0, prover panicked, prover not found, prover reply was
///     non-u8). The bridge collapses every prover-side failure into
///     a single bucket so the caller can't distinguish "prover
///     unreachable" from "proof rejected" — same state-hiding
///     posture as `VoucherInvalid`.
///
/// The prover's `verify_chain` composes three checks: every segment's
/// program commitment is in the caller-supplied `allowlist` (which program),
/// chain continuity + entering-image anchoring across the segments, AND the
/// tagless io-binding on the FINAL segment `public_io_hash() ==
/// compute_io_hash(public_bytes, return_bytes)` (which I/O). So the bridge
/// must hand it:
///   - `allowlist`: the trusted canonical commitment allowlist configured
///     via `set_prover` (the concatenation of accepted 32-byte
///     commitments) — the verifier's program-identity anchor.
///   - `public_bytes`: cipher-clerk's explicit, domain-separated
///     `voucher::proof::public_bytes(&public)` — THE canonical
///     proof-input encoding, byte-identical to what voucher-check's
///     guest bound via `vos::zk::bind_io_bytes(&public_bytes, &[1u8])`
///     (both sides call the same `public_bytes`, so they agree by
///     construction). The `issuer` MUST be the peer's clerk pubkey, the
///     same field the producer proved over (the voucher signature covers
///     it), which is why the bridge reconstructs `Public` here rather
///     than trusting the extension to.
///   - `return_bytes`: voucher-check's `1` success return as a raw byte
///     (`vec![1u8]`).
///
/// `voucher.proof.bytes` is the 32-byte content address of the chain MANIFEST
/// (the list of per-segment proof CAS hashes) in the producer node's proof-blob
/// store (unchanged wire shape — one hash); the extension fetches the manifest
/// via `ctx.blob_get` (with `peer_prefix` as a fan-out hint) and then each
/// per-segment proof the same way, rather than the bridge shipping multi-MB
/// through PVM dispatch. Per-segment delivery keeps every cross-node blob under
/// the 8 MiB frame cap, which the single concatenated chain blob exceeds.
async fn dispatch_external_proof(
    ctx: &mut vos::Context<ClerkBridge>,
    prover_id: u32,
    allowlist: &[u8],
    voucher: &Voucher,
    peer_clerk_pubkey: &AuthKey,
    peer_prefix: u16,
) -> Status {
    if prover_id == 0 {
        return Status::Ok;
    }
    if voucher.proof.mode != cipher_clerk::proof::Mode::External {
        return Status::Ok;
    }
    // The voucher attests to a `proof::Public`; cipher-clerk owns which
    // one (field set + order) — see `Voucher::proof_public`. `issuer` is
    // the peer's clerk pubkey (the field the producer proved over and the
    // signature covers), so the bridge no longer hand-mirrors the guest's
    // binding layout.
    let public = voucher.proof_public(peer_clerk_pubkey);
    // cipher-clerk's explicit, domain-separated `public_bytes` (THE
    // canonical proof-input encoding) + the raw `1` success return —
    // exactly the bytes voucher-check's `bind_io_bytes(&public_bytes,
    // &[1u8])` hashed into the proof's STARK-bound io-hash. The prover
    // recomputes `compute_io_hash(public_bytes, return_bytes)` and checks
    // equality. The two sides agree by construction (both call the same
    // `public_bytes`, no rkyv-layout / cross-crate coupling); the
    // federation e2e is the guest↔bridge agreement gate.
    let public_bytes = cipher_clerk::voucher::proof::public_bytes(&public);
    let return_bytes = vec![1u8];
    // The proof is a canonical-shape SEGMENT CHAIN: `proof.bytes` addresses a
    // manifest of per-segment proof blobs, and the extension verifies the
    // chain against the caller-supplied canonical commitment `allowlist`.
    // Wire shape is unchanged — still one 32-byte hash.
    let msg = vos::value::Msg::new("verify_chain")
        .with("allowlist", allowlist.to_vec())
        .with("proof_hash", voucher.proof.bytes.clone())
        .with("public_bytes", public_bytes)
        .with("return_bytes", return_bytes)
        .with("peer_prefix", peer_prefix as u32);
    match ctx.ask(ServiceId(prover_id), &msg).await {
        Ok(value) => {
            if value.as_u8() == Some(1) {
                Status::Ok
            } else {
                Status::ProofInvalid
            }
        }
        Err(_) => Status::ProofInvalid,
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
