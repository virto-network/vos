//! Public rkyv-archivable wire types used in handler signatures.
//!
//! These cross the actor boundary — host callers encode them via
//! `vos::rkyv::to_bytes` and pass the bytes through the macro-
//! generated Ref. The PVM-side handlers decode them via
//! `vos::rkyv::from_bytes`. Keep the field shapes stable; reordering
//! fields or changing types breaks anything persisted or sent over
//! the wire by an older build.

use cipher_clerk::crypto::{Amount, Blinding};

/// One commitment opening — what value + blinding produce a given
/// `Amount`. The transfer handler decodes a `Vec<Opening>` from
/// rkyv-archived bytes and feeds it to the kernel's `Oracle`.
///
/// Uses cipher-clerk's typed `Amount` / `Blinding` rather than raw
/// `[u8; 32]` byte fields — the unified rkyv 0.8 crate makes the
/// types embed cleanly in the actor's rkyv archive (same property
/// we use for `accounts: Vec<Account>`), so the wire format gains
/// type safety at no cost.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct Opening {
    pub amount: Amount,
    pub value: u64,
    pub blinding: Blinding,
}

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
/// These are the bytes a `cipher_clerk::voucher::Voucher` signs
/// over — a downstream host-side voucher builder reads them via
/// the `transfer_state_roots` handler immediately after
/// `apply_transfer` returns `Status::Ok`, then constructs + signs
/// a Voucher off-actor.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct TransferRootEntry {
    pub id: [u8; 16],
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
}
