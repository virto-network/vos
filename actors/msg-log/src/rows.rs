//! Wire types: the envelope kind/row, poll reply shape, and the
//! content-derived envelope id.

use alloc::vec::Vec;

use crate::consts::ENVELOPE_ID_DOMAIN_TAG;

/// Envelope kinds. The data plane carries `App` envelopes;
/// control-plane kinds live in `msg-ctl` and are listed here so
/// the discriminant space is allocated in one place. The
/// discriminant is the over-the-wire byte (and the byte hashed into
/// [`envelope_id`]).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum EnvelopeKind {
    App = 0,
    Proposal = 1,
    Commit = 2,
    Welcome = 3,
}

/// One envelope in the log. `body` is an opaque MLS message —
/// this actor validates only shape (length bounds + the MLS
/// PrivateMessage framing prefix, see [`crate::MLS_PRIVATE_MESSAGE_PREFIX`]),
/// never content; a body that fails MLS processing is discarded by
/// the messenger extension at the edge.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct EnvelopeRow {
    /// Content-derived id — see [`envelope_id`].
    pub id: [u8; 32],
    /// Envelope discriminant.
    pub kind: EnvelopeKind,
    /// MLS epoch hint, in plaintext so receivers pick a
    /// decryption key without trial-decrypting every cached
    /// epoch. Leaks membership-change cadence to anyone holding
    /// the replicated log — an accepted v1 trade-off.
    pub epoch: u64,
    /// Sender-chosen Lamport stamp: `max(lamport seen) + 1` at
    /// send time. Primary sort key; ties broken by `id`.
    pub lamport: u64,
    /// Sender wall clock, display only — never trusted for
    /// ordering or membership decisions.
    pub ts_ms: u64,
    /// Recipient hint for directed envelopes (32 bytes), zeroed
    /// otherwise.
    pub to_hint: [u8; 32],
    /// Opaque ciphertext.
    pub body: Vec<u8>,
}

/// Reply shape for `stats` — enough for a poller to decide
/// whether anything new exists without paging.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct LogStats {
    pub count: u64,
    pub max_lamport: u64,
}

/// Content-derived envelope id. All fields participate so two
/// envelopes differing anywhere get distinct ids, and identical
/// re-posts deduplicate to one row.
pub fn envelope_id(
    kind: u8,
    epoch: u64,
    lamport: u64,
    ts_ms: u64,
    to_hint: &[u8; 32],
    body: &[u8],
) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        ENVELOPE_ID_DOMAIN_TAG,
        &[
            &[kind],
            &epoch.to_le_bytes(),
            &lamport.to_le_bytes(),
            &ts_ms.to_le_bytes(),
            to_hint,
            body,
        ],
    )
}
