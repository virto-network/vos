//! Msg-log actor — the data plane of one messaging channel.
//!
//! An append-only log of **end-to-end-encrypted message
//! envelopes**. One agent instance = one channel. The actor never
//! sees plaintext: envelope bodies are MLS messages produced and
//! consumed by the native messenger extension on each member's
//! node; this log only stores, orders, and serves ciphertext.
//! Installed with `consistency = "crdt"`, so the log replicates
//! leaderlessly via the merkle-CRDT machinery and converges in
//! any delivery order.
//!
//! Ordering: every envelope carries a sender-chosen `lamport`
//! stamp; the log sorts by `(lamport, id)` where `id` is the
//! blake2b-256 of the envelope's content. The sort key is
//! intrinsic to the envelope, so it is identical on every replica
//! and stable under merge — a late-arriving envelope slots in
//! without shifting any other envelope's position, which is what
//! makes `history` cursors safe across replicas.
//!
//! Membership changes (MLS Commits / Welcomes) do NOT travel
//! through this log — they need a total order that eventual
//! consistency cannot give (one Commit must win per MLS epoch).
//! They go through the channel's companion `msg-ctl` actor, which
//! runs with strong consistency. This log carries application
//! messages only; `kind` keeps room for future envelope types.

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

use vos::prelude::*;

// ── Constants ─────────────────────────────────────────────────────

/// Envelope kinds. The data plane carries `App` envelopes;
/// control-plane kinds live in `msg-ctl` and are listed here so
/// the discriminant space is allocated in one place.
pub const ENVELOPE_KIND_APP: u8 = 0;
pub const ENVELOPE_KIND_PROPOSAL: u8 = 1;
pub const ENVELOPE_KIND_COMMIT: u8 = 2;
pub const ENVELOPE_KIND_WELCOME: u8 = 3;

/// Domain tag for envelope ids: `blake2b("vos-msg-envelope/v1" ‖
/// fields)`. Content-derived, so equal envelopes deduplicate and
/// every replica computes the same id without coordination.
pub const ENVELOPE_ID_DOMAIN_TAG: &[u8] = b"vos-msg-envelope/v1";

/// Upper bound on one envelope's ciphertext body. Keeps a single
/// envelope well under the dispatch reply cap and the 8 MiB
/// replication frame; attachments belong in a blob store, not
/// the message log.
pub const MAX_BODY_BYTES: usize = 48 * 1024;

/// Leading bytes of a TLS-serialized MLS `MLSMessage` carrying an
/// application message: `ProtocolVersion::Mls10` (u16 = 1) followed
/// by `WireFormat::PrivateMessage` (u16 = 2). The data plane carries
/// only these. The actor can't decrypt (all crypto is at the edge),
/// but rejecting bodies that aren't even MLS PrivateMessage framing
/// keeps junk out of the grow-only replicated log — a malformed body
/// can never deduplicate against a real one or waste every replica's
/// storage. Real MLS validation still happens in the messenger.
pub const MLS_PRIVATE_MESSAGE_PREFIX: [u8; 4] = [0x00, 0x01, 0x00, 0x02];

/// Soft byte budget for one `history` page. The host's hard reply
/// ceiling is much higher (8 MiB producer cap), so this is a
/// pagination-ergonomics target, not a correctness bound — it keeps
/// pages small and predictable. A single envelope larger than the
/// budget is still returned alone (progress is never starved).
pub const HISTORY_BYTE_BUDGET: usize = 12 * 1024;

/// Hard cap on rows per `history` page, independent of size.
pub const HISTORY_MAX_ROWS: u32 = 64;

// ── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
pub const STATUS_INVALID_INPUT: u8 = 1;
pub const STATUS_BODY_TOO_LARGE: u8 = 2;

// ── Wire types ────────────────────────────────────────────────────

/// One envelope in the log. `body` is an opaque MLS message —
/// this actor validates only shape (length bounds + the MLS
/// PrivateMessage framing prefix, see [`MLS_PRIVATE_MESSAGE_PREFIX`]),
/// never content; a body that fails MLS processing is discarded by
/// the messenger extension at the edge.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct EnvelopeRow {
    /// Content-derived id — see [`envelope_id`].
    pub id: [u8; 32],
    /// `ENVELOPE_KIND_*` discriminant.
    pub kind: u8,
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

// ── Roles ─────────────────────────────────────────────────────────

/// Local role hierarchy. `Reader` can page ciphertext; `Poster`
/// can append. Confidentiality does not depend on `Reader` —
/// bodies are E2E-encrypted — but gating writes keeps the log
/// from being a spam sink for anyone below space-Member.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum MsgLogRole {
    None = 0,
    Reader = 1,
    Poster = 2,
}

impl vos::RoleByte for MsgLogRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Poster),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Space-tier mapping: every enrolled space member may post to
/// channels (channel membership proper is enforced by MLS — a
/// non-member's envelope is undecryptable noise); guests get
/// nothing.
pub const MSG_LOG_SPACE_ROLE_MAP: vos::SpaceRoleMap<MsgLogRole> = vos::SpaceRoleMap {
    admin: Some(MsgLogRole::Poster),
    developer: Some(MsgLogRole::Poster),
    member: Some(MsgLogRole::Poster),
    guest: None,
};

// ── Actor ─────────────────────────────────────────────────────────

#[actor(
    role = MsgLogRole,
    default_role = MsgLogRole::Reader,
    space_role_map = MSG_LOG_SPACE_ROLE_MAP
)]
pub struct MsgLog {
    /// Sorted by `(lamport, id)` — the channel's convergent
    /// total order.
    envelopes: Vec<EnvelopeRow>,
}

#[messages]
impl MsgLog {
    pub fn new() -> Self {
        Self {
            envelopes: Vec::new(),
        }
    }

    /// Append one envelope. Idempotent: re-posting identical
    /// content (same id) is a no-op, which is exactly what a
    /// CRDT merge replaying the same event needs.
    #[allow(clippy::too_many_arguments)]
    #[msg(role = MsgLogRole::Poster)]
    async fn post(
        &mut self,
        kind: u8,
        epoch: u64,
        lamport: u64,
        ts_ms: u64,
        to_hint: Vec<u8>,
        body: Vec<u8>,
    ) -> u8 {
        if kind != ENVELOPE_KIND_APP {
            // Control-plane envelopes belong in msg-ctl; rejecting
            // them here keeps the two planes from drifting together.
            return STATUS_INVALID_INPUT;
        }
        if body.is_empty() || lamport == 0 {
            return STATUS_INVALID_INPUT;
        }
        if body.len() > MAX_BODY_BYTES {
            return STATUS_BODY_TOO_LARGE;
        }
        // Reject anything that isn't MLS PrivateMessage framing before
        // it lands in the replicated log (see the prefix const).
        if !body.starts_with(&MLS_PRIVATE_MESSAGE_PREFIX) {
            return STATUS_INVALID_INPUT;
        }
        let to_hint = match hint_to_32(&to_hint) {
            Some(h) => h,
            None => return STATUS_INVALID_INPUT,
        };
        let id = envelope_id(kind, epoch, lamport, ts_ms, &to_hint, &body);
        let pos = match self
            .envelopes
            .binary_search_by(|e| sort_key(e.lamport, &e.id, lamport, &id))
        {
            Ok(_) => return STATUS_OK,
            Err(p) => p,
        };
        self.envelopes.insert(
            pos,
            EnvelopeRow {
                id,
                kind,
                epoch,
                lamport,
                ts_ms,
                to_hint,
                body,
            },
        );
        STATUS_OK
    }

    /// Page envelopes strictly after the `(after_lamport,
    /// after_id)` cursor, in log order. Pass `(0, empty)` to read
    /// from the start. The page ends at `limit` rows,
    /// [`HISTORY_MAX_ROWS`], or [`HISTORY_BYTE_BUDGET`] —
    /// whichever bites first — so the reply always fits the
    /// dispatch cap; callers continue from the last row's
    /// `(lamport, id)`.
    #[msg]
    async fn history(&self, after_lamport: u64, after_id: Vec<u8>, limit: u32) -> Vec<EnvelopeRow> {
        let after_id: [u8; 32] = match hint_to_32(&after_id) {
            Some(h) => h,
            None => return Vec::new(),
        };
        let start = match self
            .envelopes
            .binary_search_by(|e| sort_key(e.lamport, &e.id, after_lamport, &after_id))
        {
            Ok(i) => i + 1,
            Err(i) => i,
        };
        let max_rows = limit.min(HISTORY_MAX_ROWS) as usize;
        let mut out = Vec::new();
        let mut budget = HISTORY_BYTE_BUDGET;
        let mut idx = start;
        while idx < self.envelopes.len() && out.len() < max_rows {
            let row = &self.envelopes[idx];
            // Fixed fields ≈ 96 bytes per row in the archive;
            // body dominates.
            let cost = 96 + row.body.len();
            if cost > budget && !out.is_empty() {
                break;
            }
            budget = budget.saturating_sub(cost);
            out.push(row.clone());
            idx += 1;
        }
        out
    }

    /// Cheap poll target: row count + highest lamport stamp.
    #[msg]
    async fn stats(&self) -> LogStats {
        LogStats {
            count: self.envelopes.len() as u64,
            max_lamport: match self.envelopes.last() {
                Some(e) => e.lamport,
                None => 0,
            },
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Normalise a wire hint: empty means "none" (all-zero), anything
/// else must be exactly 32 bytes.
fn hint_to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.is_empty() {
        return Some([0u8; 32]);
    }
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
}

/// Total order on `(lamport, id)` for `binary_search_by`.
fn sort_key(
    a_lamport: u64,
    a_id: &[u8; 32],
    b_lamport: u64,
    b_id: &[u8; 32],
) -> core::cmp::Ordering {
    match a_lamport.cmp(&b_lamport) {
        core::cmp::Ordering::Equal => a_id.cmp(b_id),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    fn log() -> MsgLog {
        MsgLog::new()
    }

    /// Handler futures never await anything external, so a single
    /// poll with a no-op waker resolves them — no executor (or
    /// vos `std` feature) needed in this crate's unit tests.
    fn run<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            fn noop(_: *const ()) {}
            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, noop, noop, noop),
            )
        }
        let waker = unsafe { Waker::from_raw(raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("actor handler future was not immediately ready"),
        }
    }

    fn dispatch<M>(l: &mut MsgLog, msg: M) -> <MsgLog as Message<M>>::Output
    where
        MsgLog: Message<M>,
    {
        let mut ctx: vos::Context<MsgLog> = vos::Context::new(ServiceId(0));
        run(<MsgLog as Message<M>>::handle(l, msg, &mut ctx))
    }

    /// Wrap a test payload in the minimal MLS PrivateMessage framing
    /// the `post` validator requires (version + wire-format prefix).
    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut b = MLS_PRIVATE_MESSAGE_PREFIX.to_vec();
        b.extend_from_slice(payload);
        b
    }

    fn post(l: &mut MsgLog, lamport: u64, body: &[u8]) -> u8 {
        dispatch(
            l,
            Post {
                kind: ENVELOPE_KIND_APP,
                epoch: 1,
                lamport,
                ts_ms: 1000 + lamport,
                to_hint: Vec::new(),
                body: framed(body),
            },
        )
    }

    #[test]
    fn post_then_history_round_trips() {
        let mut l = log();
        assert_eq!(post(&mut l, 1, b"ciphertext-a"), STATUS_OK);
        assert_eq!(post(&mut l, 2, b"ciphertext-b"), STATUS_OK);
        let rows = dispatch(
            &mut l,
            History {
                after_lamport: 0,
                after_id: Vec::new(),
                limit: 10,
            },
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].body, framed(b"ciphertext-a"));
        assert_eq!(rows[1].body, framed(b"ciphertext-b"));
    }

    #[test]
    fn post_rejects_non_mls_framed_body() {
        let mut l = log();
        // A rejected post returns before insertion, so probing several
        // bad bodies against the same log leaves it empty.
        let mut bad = |body: Vec<u8>| {
            dispatch(
                &mut l,
                Post {
                    kind: ENVELOPE_KIND_APP,
                    epoch: 1,
                    lamport: 1,
                    ts_ms: 1,
                    to_hint: Vec::new(),
                    body,
                },
            )
        };
        // Arbitrary bytes with no MLS framing are refused.
        assert_eq!(bad(b"not-mls-at-all".to_vec()), STATUS_INVALID_INPUT);
        // Right version but the wrong wire format (Welcome = 3, not the
        // PrivateMessage = 2 the data plane carries) is refused.
        assert_eq!(
            bad(vec![0x00, 0x01, 0x00, 0x03, 0xAB]),
            STATUS_INVALID_INPUT
        );
        // A body shorter than the prefix is refused.
        assert_eq!(bad(vec![0x00, 0x01]), STATUS_INVALID_INPUT);
        assert_eq!(dispatch(&mut l, Stats).count, 0);
        // The same payload under valid framing is accepted and stored.
        assert_eq!(post(&mut l, 1, b"real"), STATUS_OK);
        assert_eq!(dispatch(&mut l, Stats).count, 1);
    }

    #[test]
    fn post_is_idempotent_by_content() {
        // A CRDT merge can replay the same event on a replica
        // that already holds it — the log must not duplicate.
        let mut l = log();
        assert_eq!(post(&mut l, 1, b"same"), STATUS_OK);
        assert_eq!(post(&mut l, 1, b"same"), STATUS_OK);
        assert_eq!(dispatch(&mut l, Stats).count, 1);
    }

    #[test]
    fn order_converges_regardless_of_arrival() {
        // Two replicas receiving the same envelopes in different
        // orders must serve identical history pages.
        let mut a = log();
        let mut b = log();
        post(&mut a, 2, b"two");
        post(&mut a, 1, b"one");
        post(&mut a, 3, b"three");
        post(&mut b, 3, b"three");
        post(&mut b, 1, b"one");
        post(&mut b, 2, b"two");
        let page = |l: &mut MsgLog| {
            dispatch(
                l,
                History {
                    after_lamport: 0,
                    after_id: Vec::new(),
                    limit: 10,
                },
            )
        };
        assert_eq!(page(&mut a), page(&mut b));
    }

    #[test]
    fn equal_lamport_ties_break_by_id() {
        // Concurrent senders legitimately pick the same lamport;
        // the id tiebreak keeps the order total and replica-
        // independent.
        let mut l = log();
        post(&mut l, 1, b"x");
        post(&mut l, 1, b"y");
        let rows = dispatch(
            &mut l,
            History {
                after_lamport: 0,
                after_id: Vec::new(),
                limit: 10,
            },
        );
        assert_eq!(rows.len(), 2);
        assert!(rows[0].id < rows[1].id);
    }

    #[test]
    fn history_cursor_pages_without_overlap() {
        let mut l = log();
        for i in 1..=5u64 {
            post(&mut l, i, format!("m{i}").as_bytes());
        }
        let first = dispatch(
            &mut l,
            History {
                after_lamport: 0,
                after_id: Vec::new(),
                limit: 2,
            },
        );
        assert_eq!(first.len(), 2);
        let cursor = first.last().unwrap();
        let rest = dispatch(
            &mut l,
            History {
                after_lamport: cursor.lamport,
                after_id: cursor.id.to_vec(),
                limit: 10,
            },
        );
        assert_eq!(rest.len(), 3);
        assert_eq!(rest[0].body, framed(b"m3"));
    }

    #[test]
    fn history_respects_byte_budget_but_returns_progress() {
        // Oversized-page protection must still hand back at least
        // one row, or a paging client would spin forever.
        let mut l = log();
        let big = vec![0xAAu8; 8 * 1024];
        post(&mut l, 1, &big);
        post(&mut l, 2, &big);
        let rows = dispatch(
            &mut l,
            History {
                after_lamport: 0,
                after_id: Vec::new(),
                limit: 10,
            },
        );
        assert_eq!(rows.len(), 1, "two 8 KiB bodies exceed the 12 KiB budget");
    }

    #[test]
    fn post_validates_shape() {
        let mut l = log();
        // Empty body (dispatched raw — the `post` helper would frame it
        // into a non-empty body).
        assert_eq!(
            dispatch(
                &mut l,
                Post {
                    kind: ENVELOPE_KIND_APP,
                    epoch: 1,
                    lamport: 1,
                    ts_ms: 0,
                    to_hint: Vec::new(),
                    body: Vec::new(),
                },
            ),
            STATUS_INVALID_INPUT
        );
        // Zero lamport.
        assert_eq!(post(&mut l, 0, b"x"), STATUS_INVALID_INPUT);
        // Oversized body.
        let huge = vec![0u8; MAX_BODY_BYTES + 1];
        assert_eq!(post(&mut l, 1, &huge), STATUS_BODY_TOO_LARGE);
        // Control-plane kind on the data plane.
        assert_eq!(
            dispatch(
                &mut l,
                Post {
                    kind: ENVELOPE_KIND_COMMIT,
                    epoch: 1,
                    lamport: 1,
                    ts_ms: 0,
                    to_hint: Vec::new(),
                    body: b"c".to_vec(),
                },
            ),
            STATUS_INVALID_INPUT,
        );
        // Malformed hint length.
        assert_eq!(
            dispatch(
                &mut l,
                Post {
                    kind: ENVELOPE_KIND_APP,
                    epoch: 1,
                    lamport: 1,
                    ts_ms: 0,
                    to_hint: vec![1, 2, 3],
                    body: b"c".to_vec(),
                },
            ),
            STATUS_INVALID_INPUT,
        );
        assert_eq!(dispatch(&mut l, Stats).count, 0);
    }

    #[test]
    fn stats_reports_count_and_max_lamport() {
        let mut l = log();
        assert_eq!(
            dispatch(&mut l, Stats),
            LogStats {
                count: 0,
                max_lamport: 0
            }
        );
        post(&mut l, 7, b"x");
        post(&mut l, 3, b"y");
        assert_eq!(
            dispatch(&mut l, Stats),
            LogStats {
                count: 2,
                max_lamport: 7
            }
        );
    }
}
