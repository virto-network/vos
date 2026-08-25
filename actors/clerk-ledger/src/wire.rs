//! Public rkyv-archivable wire types used in handler signatures.
//!
//! These cross the actor boundary — host callers encode them via
//! `vos::rkyv::to_bytes` and pass the bytes through the macro-
//! generated Ref. The PVM-side handlers decode them via
//! `vos::rkyv::from_bytes`. Keep the field shapes stable; reordering
//! fields or changing types breaks anything persisted or sent over
//! the wire by an older build.

/// One commitment opening — what value + blinding produce a given
/// `Amount`. The transfer handler decodes a `Vec<Opening>` from
/// rkyv-archived bytes and feeds each to the kernel's `Oracle`.
///
/// D7: the library owns this wire type now
/// ([`cipher_clerk::state::Opening`]) so consumers don't re-spell it.
/// Re-export rather than redeclare — the rkyv layout is byte-identical
/// (unified rkyv 0.8: `vos::rkyv` IS cipher-clerk's `rkyv`), so the
/// on-wire format is unchanged.
pub use cipher_clerk::state::Opening;

/// rkyv-archivable rendering of `cipher_clerk::state::PendingStatus`.
/// Two-phase lifecycle: a transfer with `PENDING` flag enters
/// state in `Pending`; `POST_PENDING` moves it to `Posted`;
/// `VOID_PENDING` moves it to `Voided`. Once Posted or Voided
/// the transfer's lifecycle is terminal.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PendingStatusEntry {
    pub id: [u8; 16],
    /// 0 = Pending, 1 = Posted, 2 = Voided.
    pub status: u8,
}

pub(crate) const PENDING_STATUS_PENDING: u8 = 0;
pub(crate) const PENDING_STATUS_POSTED: u8 = 1;
pub(crate) const PENDING_STATUS_VOIDED: u8 = 2;

/// Per-transfer state-root anchor. `id` is the TransferId; the two
/// 32-byte fields are the composite SMT roots just before and just
/// after the kernel applied the transfer.
///
/// These are the bytes a `cipher_clerk::voucher::Voucher` signs over.
/// `voucher_anchor` additionally binds the
/// single amount commitment before `clerk-bridge` signs through DEVICE_SIGN.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct TransferRootEntry {
    pub id: [u8; 16],
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
}

/// Public, opaque evidence that one accepted transfer moved exactly one
/// amount commitment on one settled currency across all of its double-entry
/// rows. This is the narrow cross-root surface used by `clerk-bridge` when it
/// turns a caller-built, recipient-encrypted voucher template into a
/// bank-signed voucher.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct LedgerVoucherAnchor {
    pub amount_commit: [u8; 32],
    /// ISO-4217 / ledger identifier shared by every eligible transfer row.
    pub currency: u32,
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
}
