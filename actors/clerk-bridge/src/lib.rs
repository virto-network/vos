//! Clerk bridge — per-bank cross-clerk voucher ingress actor.
//!
//! Each bank space runs one clerk-bridge actor. It is both sides of the
//! cross-bank boundary:
//! - issuer: bind the root's host-private device key, confirm an accepted
//!   transfer through the authenticated clerk-ledger handle, sign exactly one
//!   voucher, and accumulate the positive settlement term;
//! - receiver: verify/open/deduplicate peer vouchers, optionally redeem them
//!   into clerk-ledger, and accumulate the negative settlement term;
//! - close: combine both terms for a closed window and DEVICE_SIGN the
//!   canonical bilateral settlement claim.
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
//! - `local_ledger_id`: compatibility/diagnostic ServiceId. Production issuer
//!   dispatch uses the signed package's `clerk-ledger` external binding.
//! - `device_signer_pubkey`: guest-owned public identity for the host-private
//!   DEVICE_SIGN capability. The secret never enters actor state.
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
//! - **Recipient encryption remains caller-built.** `issue_voucher` accepts a
//!   zero-signature voucher template because the recipient-specific envelope
//!   requires its public viewing key and fresh encryption randomness. The
//!   bridge does not trust its financial fields: it rebinds the amount and
//!   before/after roots to immutable ledger state before signing.
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

use cipher_clerk::crypto::{Amount, AuthKey, Signature, verify_signature};
use cipher_clerk::settlement::SettlementClaim;
use cipher_clerk::types::{Layer, Transfer as CcTransfer, TransferFlags};
use cipher_clerk::viewing_keys::IncomingViewingKey;
use cipher_clerk::voucher::Voucher;
use clerk_ledger::ClerkLedgerRef;
use vos::abi::service::ServiceId;
use vos::prelude::*;
use vos::storage::{StorageMap, StorageSet};

mod window;

pub mod roles;
pub use roles::{CLERK_BRIDGE_SPACE_ROLE_MAP, ClerkBridgeRole};

/// This bridge package's configured settlement currency (ISO-4217 USD).
/// Vouchers carry no currency (`cipher-clerk/src/voucher/mod.rs`), so issuer
/// anchors and receiver inflows must prove this ledger identifier before a
/// commitment enters a settlement accumulator. Multi-currency federation can
/// later make this package configuration per-peer; the accumulator is already
/// keyed by currency so commitments cannot silently mix under one claim.
pub const SETTLEMENT_CURRENCY: u32 = 840;
/// Compatibility name retained for existing callers and fixtures.
pub const DEMO_CURRENCY: u32 = SETTLEMENT_CURRENCY;

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
    /// match the voucher or settlement policy. The exact debit/credit
    /// commitments and external-id must match, every row must use the
    /// configured currency on `Layer::Settled`, and pending/void semantics
    /// are forbidden. The bridge enforces this link so an operator cannot
    /// credit or settle the wrong accounting partition.
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
    /// This root was opened without the host-private device signer required
    /// to issue vouchers and settlement claims.
    DeviceSignerUnavailable = 11,
    /// The active host-private signer does not match the guest-owned bank key
    /// bound by `bind_device_signer`.
    DeviceSignerMismatch = 12,
    /// This transfer was already issued under a different peer, window, or
    /// voucher template. One accepted transfer can contribute to settlement
    /// exactly once.
    IssuanceConflict = 13,
    /// Settlement claims may be signed only after `window_rotate` has closed
    /// the requested window.
    WindowOpen = 14,
    /// The authenticated clerk-ledger binding was missing, unreachable, or
    /// did not confirm a final settled transfer with the voucher's exact
    /// commitment, roots, and configured currency.
    LedgerUnavailable = 15,
    /// A peer-key rotation conflicts with the key already pinned by activity
    /// in the current settlement window.
    PeerKeyConflict = 16,
    /// The caller is neither the host system nor an authenticated bank
    /// operator. Same-node actors deliberately receive no signing-control
    /// bypass.
    Unauthorized = 17,
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

/// Result of turning an accepted ledger transfer plus caller-built encrypted
/// envelope into a bank-signed voucher.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct IssueVoucherReply {
    pub status: Status,
    /// Canonical `Voucher::to_bytes()` on success; empty on rejection.
    pub voucher: Vec<u8>,
    /// Stable receiver-side dedup identity on success; all zero on rejection.
    pub redemption_key: [u8; 32],
    /// Settlement window receiving the issuer term.
    pub window: u64,
}

/// Result of signing one closed bilateral settlement window.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SignClaimReply {
    pub status: Status,
    /// Canonical `SettlementClaim::to_bytes()` on success; empty otherwise.
    pub claim: Vec<u8>,
}

/// Durable exactly-once voucher issuance record. The request hash binds the
/// transfer, peer, and complete zero-signature template; retaining the exact
/// signed bytes makes response-loss retries independent of current signer
/// availability or later peer-key rotation.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct IssuedVoucherEntry {
    pub request_hash: [u8; 32],
    pub voucher: Vec<u8>,
    pub redemption_key: [u8; 32],
    pub window: u64,
}

// ── Decode helpers ──────────────────────────────────────────────

/// Convert a `Vec<u8>` to a fixed-size byte array. Returns `None`
/// (caller folds to `Status::BadInput`) on length mismatch.
fn try_array<const N: usize>(bytes: Vec<u8>) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

/// The receiver-side counterpart to clerk-ledger's voucher anchor policy.
/// Only ordinary, settled rows in this bridge package's configured currency
/// may turn an incoming voucher into local ledger state and a settlement
/// receiver term.
fn settlement_inflow_is_eligible(transfer: &CcTransfer) -> bool {
    transfer.void_of.is_none()
        && transfer.pending_id.is_none()
        && !transfer.flags.contains(TransferFlags::PENDING)
        && !transfer
            .flags
            .contains(TransferFlags::POST_PENDING_TRANSFER)
        && !transfer
            .flags
            .contains(TransferFlags::VOID_PENDING_TRANSFER)
        && !transfer.entries.is_empty()
        && transfer
            .entries
            .iter()
            .all(|entry| entry.layer == Layer::Settled && entry.ledger == SETTLEMENT_CURRENCY)
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
    /// not-yet-bootstrapped. Retained for compatibility/diagnostics; issuer
    /// dispatch resolves only the authenticated `clerk-ledger` binding.
    local_ledger_id: u32,
    /// This bank's IVK secret, raw canonical-scalar bytes. The
    /// `IncomingViewingKey` type itself isn't rkyv-archivable
    /// (it wraps a curve scalar), so we keep the bytes and
    /// reconstruct per call.
    ivk_secret_bytes: [u8; 32],
    /// Guest-owned bank signing identity. The secret remains in the root host;
    /// every signing operation compares the host-returned public key with this
    /// immutable binding before accepting its signature.
    device_signer_pubkey: Option<AuthKey>,
    /// Sorted-by-`name` ascending. Lookups via `partition_point`.
    peers: Vec<PeerEntry>,
    /// Sorted dedup set of voucher transfer-triples. Each entry
    /// is `blake2b_256("clerk-bridge/voucher-redemption",
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
    /// Issuer-term accumulators: the positive sum of vouchers this bank
    /// issued to `(peer, currency, window)`. Combined with `window_nets`
    /// (the negative receiver term) when signing a settlement claim.
    #[storage]
    issuer_nets: StorageMap<[u8; 32], [u8; 32]>,
    /// Peer signing key pinned when the first issuer or receiver term enters a
    /// window. Historical claims remain bound to that key even if the peer is
    /// rotated at the start of a later empty window.
    #[storage]
    window_peer_keys: StorageMap<[u8; 32], [u8; 32]>,
    /// Exactly-once issuance record keyed by accepted ledger transfer id.
    #[storage]
    issued_vouchers: StorageMap<[u8; 16], IssuedVoucherEntry>,
}

impl ClerkBridge {
    const DEVICE_BINDING_PROBE: &'static [u8] = b"clerk-bridge/device-binding";

    /// Signer configuration controls the bank identity used on external
    /// vouchers and settlement claims. Do not inherit the legacy same-node
    /// Actor role bypass: only System or an authenticated operator member may
    /// establish it.
    fn authorize_signer_operator(ctx: &mut Context<Self>) -> bool {
        let allowed = match ctx.origin() {
            Origin::System => true,
            Origin::Member(_) => ctx.has_role(ClerkBridgeRole::Operator),
            Origin::Anonymous | Origin::Actor(_) => false,
        };
        if !allowed {
            ctx.__mark_forbidden();
        }
        allowed
    }

    fn device_signature(
        &self,
        ctx: &mut Context<Self>,
        payload: &[u8],
    ) -> core::result::Result<Signature, Status> {
        let expected = self
            .device_signer_pubkey
            .ok_or(Status::DeviceSignerUnavailable)?;
        let signed = ctx
            .device_sign(payload)
            .ok_or(Status::DeviceSignerUnavailable)?;
        if signed.public_key != expected.0 {
            return Err(Status::DeviceSignerMismatch);
        }
        let signature = Signature {
            r: signed.signature_r,
            s: signed.signature_s,
        };
        if !verify_signature(&expected, payload, &signature) {
            return Err(Status::DeviceSignerMismatch);
        }
        Ok(signature)
    }

    fn issuance_request_hash(
        peer_name: &[u8],
        transfer_id: &[u8; 16],
        voucher_template: &[u8],
    ) -> [u8; 32] {
        vos::crypto::blake2b_hash::<32>(
            b"clerk-bridge/issue-voucher",
            &[
                &(peer_name.len() as u64).to_le_bytes(),
                peer_name,
                transfer_id,
                voucher_template,
            ],
        )
    }

    fn pinned_peer_key(&self, peer_name: &[u8], currency: u32, window: u64) -> Option<AuthKey> {
        self.window_peer_keys
            .get(&window::peer_key_key(peer_name, currency, window))
            .map(AuthKey)
    }

    fn peer_key_compatible(
        &self,
        peer_name: &[u8],
        currency: u32,
        window: u64,
        peer_key: AuthKey,
    ) -> bool {
        self.pinned_peer_key(peer_name, currency, window)
            .is_none_or(|pinned| pinned == peer_key)
    }

    fn pin_peer_key(&mut self, peer_name: &[u8], currency: u32, window: u64, peer_key: AuthKey) {
        self.window_peer_keys.insert(
            &window::peer_key_key(peer_name, currency, window),
            &peer_key.0,
        );
    }
}

#[messages]
impl ClerkBridge {
    fn new() -> Self {
        Self {
            local_ledger_id: 0,
            ivk_secret_bytes: [0u8; 32],
            device_signer_pubkey: None,
            peers: Vec::new(),
            received: StorageSet::default(),
            prover_id: 0,
            allowlist: Vec::new(),
            window_nets: StorageMap::default(),
            issuer_nets: StorageMap::default(),
            window_peer_keys: StorageMap::default(),
            issued_vouchers: StorageMap::default(),
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
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn bootstrap(
        &mut self,
        ctx: &mut Context<Self>,
        local_ledger_id: u32,
        ivk_secret: Vec<u8>,
    ) -> Status {
        if !Self::authorize_signer_operator(ctx) {
            return Status::Unauthorized;
        }
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

    /// Bind this bank actor to the public half of its host-private device
    /// signer. The live signer must prove the same key during binding and on
    /// every later voucher/claim signature. Identical replays are idempotent;
    /// changing the bank identity requires an explicit actor/package upgrade.
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn bind_device_signer(
        &mut self,
        ctx: &mut Context<Self>,
        public_key: [u8; 32],
    ) -> Status {
        if !Self::authorize_signer_operator(ctx) {
            return Status::Unauthorized;
        }
        let Some(signed) = ctx.device_sign(Self::DEVICE_BINDING_PROBE) else {
            return Status::DeviceSignerUnavailable;
        };
        let signature = Signature {
            r: signed.signature_r,
            s: signed.signature_s,
        };
        if signed.public_key != public_key
            || !verify_signature(&AuthKey(public_key), Self::DEVICE_BINDING_PROBE, &signature)
        {
            return Status::DeviceSignerMismatch;
        }
        match self.device_signer_pubkey {
            None => {
                self.device_signer_pubkey = Some(AuthKey(public_key));
                Status::Ok
            }
            Some(existing) if existing.0 == public_key => Status::Ok,
            Some(_) => Status::DeviceSignerMismatch,
        }
    }

    /// Public discovery of the active host signer identity. This does not
    /// configure guest state; operators compare it with their provisioned
    /// key and then call `bind_device_signer` through authenticated ingress.
    #[msg]
    async fn device_signer_public_key(&self, ctx: &mut Context<Self>) -> Vec<u8> {
        ctx.device_sign(Self::DEVICE_BINDING_PROBE)
            .map(|signature| signature.public_key.to_vec())
            .unwrap_or_default()
    }

    /// Guest-owned bank identity currently bound for vouchers and claims.
    #[msg]
    async fn bound_device_signer_public_key(&self) -> Vec<u8> {
        self.device_signer_pubkey
            .map(|key| key.0.to_vec())
            .unwrap_or_default()
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
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn set_prover(
        &mut self,
        ctx: &mut Context<Self>,
        prover_id: u32,
        allowlist: Vec<u8>,
    ) -> Status {
        if !Self::authorize_signer_operator(ctx) {
            return Status::Unauthorized;
        }
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
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn register_peer(
        &mut self,
        ctx: &mut Context<Self>,
        peer_name: Vec<u8>,
        clerk_pubkey: Vec<u8>,
        node_prefix: u32,
    ) -> Status {
        if !Self::authorize_signer_operator(ctx) {
            return Status::Unauthorized;
        }
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
                if self.peers[i].clerk_pubkey != entry.clerk_pubkey
                    && !self.peer_key_compatible(
                        &entry.name,
                        SETTLEMENT_CURRENCY,
                        self.peers[i].window,
                        entry.clerk_pubkey,
                    )
                {
                    return Status::PeerKeyConflict;
                }
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

    /// Whether this bridge has durably accepted one exact voucher identity.
    /// The demo's quiescence barrier checks every issuer-returned redemption
    /// key at the peer before closing the window.
    #[msg]
    async fn voucher_received(&self, redemption_key: [u8; 32]) -> bool {
        self.received.contains(&redemption_key)
    }

    /// Number of accepted ledger transfers turned into signed vouchers.
    #[msg]
    async fn issued_count(&self) -> u32 {
        self.issued_vouchers.len() as u32
    }

    /// Sign a caller-built, recipient-encrypted voucher template only after
    /// the bound clerk-ledger confirms its commitment and state-root pair.
    ///
    /// `voucher_template` is canonical `Voucher::to_bytes()` with an all-zero
    /// signature. The caller owns envelope encryption because it has the
    /// opening and recipient IVK; it cannot choose the signed roots or an
    /// unrelated commitment. One accepted transfer may be issued exactly
    /// once. Exact response-loss retries return the stored voucher without
    /// consulting the current signer or ledger again.
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn issue_voucher(
        &mut self,
        ctx: &mut Context<Self>,
        transfer_id: [u8; 16],
        peer_name: Vec<u8>,
        voucher_template: Vec<u8>,
    ) -> IssueVoucherReply {
        if !Self::authorize_signer_operator(ctx) {
            return issue_reply(Status::Unauthorized);
        }
        if self.local_ledger_id == 0 {
            return issue_reply(Status::NotBootstrapped);
        }
        if self.device_signer_pubkey.is_none() {
            return issue_reply(Status::DeviceSignerUnavailable);
        }
        let request_hash = Self::issuance_request_hash(&peer_name, &transfer_id, &voucher_template);
        if let Some(existing) = self.issued_vouchers.get(&transfer_id) {
            return if existing.request_hash == request_hash {
                IssueVoucherReply {
                    status: Status::Ok,
                    voucher: existing.voucher,
                    redemption_key: existing.redemption_key,
                    window: existing.window,
                }
            } else {
                issue_reply(Status::IssuanceConflict)
            };
        }

        let Some(mut voucher) = Voucher::from_bytes(&voucher_template) else {
            return issue_reply(Status::BadInput);
        };
        if voucher.signature != Signature::ZERO || voucher.amount_commit.to_point().is_none() {
            return issue_reply(Status::BadInput);
        }

        // The package's authenticated external-actor directory, not the
        // legacy route integer, selects the ledger root. A missing binding is
        // a clean denial rather than a fallback to an arbitrary same-node
        // service.
        let anchor = {
            let Ok(mut ledger) = ctx.actor::<ClerkLedgerRef>("clerk-ledger").await else {
                return issue_reply(Status::LedgerUnavailable);
            };
            match ledger
                .voucher_anchor(transfer_id, voucher.amount_commit.0)
                .await
            {
                Ok(Some(anchor)) => anchor,
                _ => return issue_reply(Status::LedgerUnavailable),
            }
        };
        if voucher.state_root_before != anchor.root_before
            || voucher.state_root_after != anchor.root_after
            || voucher.amount_commit.0 != anchor.amount_commit
            || anchor.currency != SETTLEMENT_CURRENCY
        {
            return issue_reply(Status::LedgerUnavailable);
        }

        // The ledger query may have suspended. Select and pin the peer/window
        // only after resumption so the voucher cannot be inserted into a
        // window that was concurrently closed while awaiting the anchor.
        let (peer_key, window) = match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => (self.peers[i].clerk_pubkey, self.peers[i].window),
            Err(_) => return issue_reply(Status::UnknownPeer),
        };
        if !self.peer_key_compatible(&peer_name, SETTLEMENT_CURRENCY, window, peer_key) {
            return issue_reply(Status::PeerKeyConflict);
        }

        let payload = voucher.signing_payload();
        voucher.signature = match self.device_signature(ctx, &payload) {
            Ok(signature) => signature,
            Err(status) => return issue_reply(status),
        };
        let expected = self
            .device_signer_pubkey
            .expect("the signer binding was checked above");
        if voucher.verify_signature(&expected).is_err() {
            return issue_reply(Status::DeviceSignerMismatch);
        }

        let voucher_bytes = voucher.to_bytes();
        let redemption_key = voucher.redemption_key();
        self.pin_peer_key(&peer_name, SETTLEMENT_CURRENCY, window, peer_key);
        window::accumulate_pos(
            &mut self.issuer_nets,
            &peer_name,
            SETTLEMENT_CURRENCY,
            window,
            &voucher.amount_commit,
        );
        self.issued_vouchers.insert(
            &transfer_id,
            &IssuedVoucherEntry {
                request_hash,
                voucher: voucher_bytes.clone(),
                redemption_key,
                window,
            },
        );
        IssueVoucherReply {
            status: Status::Ok,
            voucher: voucher_bytes,
            redemption_key,
            window,
        }
    }

    /// Sign the net-flow claim for one closed settlement window.
    ///
    /// The claim is derived entirely from guest-owned state:
    /// `issuer_net + receiver_net`, the bank's bound device key, and the peer
    /// key pinned by the first voucher activity in that window. The canonical
    /// bracket is `[window, window + 1]`; callers cannot substitute claim
    /// fields or a different peer identity.
    #[msg(role = ClerkBridgeRole::Operator)]
    async fn sign_claim(
        &self,
        ctx: &mut Context<Self>,
        peer_name: Vec<u8>,
        currency: u32,
        window: u64,
    ) -> SignClaimReply {
        if !Self::authorize_signer_operator(ctx) {
            return claim_reply(Status::Unauthorized);
        }
        if currency != SETTLEMENT_CURRENCY {
            return claim_reply(Status::BadInput);
        }
        let current_window = match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i) => self.peers[i].window,
            Err(_) => return claim_reply(Status::UnknownPeer),
        };
        if window >= current_window {
            return claim_reply(Status::WindowOpen);
        }
        let Some(window_end) = window.checked_add(1) else {
            return claim_reply(Status::BadInput);
        };
        let Some(claimant) = self.device_signer_pubkey else {
            return claim_reply(Status::DeviceSignerUnavailable);
        };
        let Some(peer) = self.pinned_peer_key(&peer_name, currency, window) else {
            return claim_reply(Status::BadInput);
        };
        let issuer = self
            .issuer_nets
            .get(&window::window_key(&peer_name, currency, window))
            .map(Amount)
            .unwrap_or(Amount::ZERO);
        let receiver = window::window_net(&self.window_nets, &peer_name, currency, window)
            .map(Amount)
            .unwrap_or(Amount::ZERO);
        let Some(net_flow) = window::checked_add(&issuer, &receiver) else {
            return claim_reply(Status::BadInput);
        };
        let mut claim = SettlementClaim {
            claimant_clerk: claimant,
            peer_clerk: peer,
            currency,
            window_start: window,
            window_end,
            net_flow,
            signature: Signature::ZERO,
        };
        claim.signature = match self.device_signature(ctx, &claim.signing_payload()) {
            Ok(signature) => signature,
            Err(status) => return claim_reply(status),
        };
        if claim.verify_signature().is_err() {
            return claim_reply(Status::DeviceSignerMismatch);
        }
        SignClaimReply {
            status: Status::Ok,
            claim: claim.to_bytes(),
        }
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

        // External proof dispatch may have suspended this workflow. Re-read
        // the peer and require that neither its key nor current window changed
        // before committing acceptance under the values verified above.
        let (peer_index, window) = match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
            Ok(i)
                if self.peers[i].clerk_pubkey == peer_clerk_pubkey
                    && self.peer_key_compatible(
                        &peer_name,
                        SETTLEMENT_CURRENCY,
                        self.peers[i].window,
                        peer_clerk_pubkey,
                    ) =>
            {
                (i, self.peers[i].window)
            }
            _ => return reply(Status::VoucherInvalid),
        };

        // Commit to the dedup set after a successful open. From
        // here the host caller has the opening and can credit the
        // recipient; a second submit with the same triple would
        // hit the replay check above.
        // Idempotent: the replay check above already returned, so this is
        // a fresh triple; `insert` returns whether it was new.
        self.received.insert(&dedup_key);
        self.pin_peer_key(&peer_name, SETTLEMENT_CURRENCY, window, peer_clerk_pubkey);
        // Advance the per-peer anchor to this voucher's post-state, and
        // fold the accepted commit into the current window's receiver term
        // — the two move together so the settlement sum and the anchor
        // never diverge. Only here, on the acceptance path — a rejected
        // voucher leaves both where the last accepted one left them.
        // Re-resolve by name: the earlier lookup's borrow is gone and its
        // index may be stale after the await.
        self.peers[peer_index].last_root_after = Some(voucher.state_root_after);
        window::accumulate_neg(
            &mut self.window_nets,
            &peer_name,
            SETTLEMENT_CURRENCY,
            window,
            &voucher.amount_commit,
        );

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
    ///   - Both inflow entries' `amount` MUST equal the voucher's
    ///     `amount_commit`, and both must use `Layer::Settled` in this
    ///     bridge package's configured currency. Caller can't credit or
    ///     settle a different value, ledger, or accounting partition.
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
        let (peer_clerk_pubkey, peer_prefix, expected_root, redemption_window) =
            match self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
                Ok(i) => (
                    self.peers[i].clerk_pubkey,
                    self.peers[i].node_prefix,
                    self.peers[i].last_root_after,
                    self.peers[i].window,
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
        if !settlement_inflow_is_eligible(&inflow) {
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
        if !self.peer_key_compatible(
            &peer_name,
            SETTLEMENT_CURRENCY,
            redemption_window,
            peer_clerk_pubkey,
        ) {
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
            self.pin_peer_key(
                &peer_name,
                SETTLEMENT_CURRENCY,
                redemption_window,
                peer_clerk_pubkey,
            );
            // Advance the per-peer anchor to this voucher's post-state and
            // fold the accepted commit into the current window's receiver
            // term, atomically with the ledger accept (the rejection paths
            // above never reach here, so both only move on acceptance).
            if let Ok(pi) = self.peers.binary_search_by(|e| e.name.cmp(&peer_name)) {
                self.peers[pi].last_root_after = Some(voucher.state_root_after);
                window::accumulate_neg(
                    &mut self.window_nets,
                    &peer_name,
                    SETTLEMENT_CURRENCY,
                    redemption_window,
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
    async fn window_rotate(&mut self, ctx: &mut Context<Self>, peer_name: Vec<u8>) -> Status {
        if !Self::authorize_signer_operator(ctx) {
            return Status::Unauthorized;
        }
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
    async fn anchor_reset(
        &mut self,
        ctx: &mut Context<Self>,
        peer_name: Vec<u8>,
        root: [u8; 32],
    ) -> Status {
        if !Self::authorize_signer_operator(ctx) {
            return Status::Unauthorized;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use cipher_clerk::crypto::Amount;
    use cipher_clerk::ids::{AccountId, EntryId, JournalId, TransferId};
    use cipher_clerk::types::Entry;
    use vos::Caller;
    use vos::actors::context::ServiceId;

    fn settlement_inflow(layer: Layer, currency: u32) -> CcTransfer {
        let mut transfer = CcTransfer::default();
        transfer.id = TransferId([0x61; 16]);
        transfer.journal_id = JournalId([0x62; 16]);
        transfer.entries = vec![
            Entry::debit(
                EntryId([0x63; 16]),
                transfer.id,
                transfer.journal_id,
                AccountId([0x64; 16]),
                layer,
                Amount::ZERO,
                currency,
                1,
            ),
            Entry::credit(
                EntryId([0x65; 16]),
                transfer.id,
                transfer.journal_id,
                AccountId([0x66; 16]),
                layer,
                Amount::ZERO,
                currency,
                1,
            ),
        ];
        transfer
    }

    #[test]
    fn inflows_must_match_the_configured_settled_currency() {
        let settled = settlement_inflow(Layer::Settled, SETTLEMENT_CURRENCY);
        assert!(settlement_inflow_is_eligible(&settled));
        assert!(!settlement_inflow_is_eligible(&settlement_inflow(
            Layer::Settled,
            978,
        )));
        assert!(!settlement_inflow_is_eligible(&settlement_inflow(
            Layer::Pending,
            SETTLEMENT_CURRENCY,
        )));

        for flag in [
            TransferFlags::PENDING,
            TransferFlags::POST_PENDING_TRANSFER,
            TransferFlags::VOID_PENDING_TRANSFER,
        ] {
            let mut flagged = settled.clone();
            flagged.flags = flag;
            assert!(!settlement_inflow_is_eligible(&flagged));
        }

        let mut pending_finalizer = settled.clone();
        pending_finalizer.pending_id = Some(TransferId([0x67; 16]));
        assert!(!settlement_inflow_is_eligible(&pending_finalizer));

        let mut void = settled;
        void.void_of = Some(TransferId([0x68; 16]));
        assert!(!settlement_inflow_is_eligible(&void));
    }

    #[test]
    fn signing_controls_reject_the_legacy_actor_bypass() {
        let mut actor = Context::<ClerkBridge>::new(ServiceId(7));
        actor.set_caller(Caller::Actor(ServiceId(9)));
        actor.set_caller_roles(None, Some(ClerkBridgeRole::Operator as u8));
        assert!(
            !ClerkBridge::authorize_signer_operator(&mut actor),
            "a same-node actor must not configure or use the bank signer"
        );

        let mut anonymous = Context::<ClerkBridge>::new(ServiceId(7));
        assert!(!ClerkBridge::authorize_signer_operator(&mut anonymous));

        let mut member = Context::<ClerkBridge>::new(ServiceId(7));
        member.set_caller(Caller::Peer(vec![0xA5; 32]));
        member.set_caller_roles(None, Some(ClerkBridgeRole::Operator as u8));
        assert!(ClerkBridge::authorize_signer_operator(&mut member));

        let mut system = Context::<ClerkBridge>::new(ServiceId(7));
        system.set_caller(Caller::System);
        assert!(ClerkBridge::authorize_signer_operator(&mut system));
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

/// Build a rejected issuance reply without leaving stale success fields.
fn issue_reply(status: Status) -> IssueVoucherReply {
    IssueVoucherReply {
        status,
        voucher: Vec::new(),
        redemption_key: [0u8; 32],
        window: u64::MAX,
    }
}

/// Build a rejected settlement-claim reply.
fn claim_reply(status: Status) -> SignClaimReply {
    SignClaimReply {
        status,
        claim: Vec::new(),
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
