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
//!
//! ## Module layout
//!
//! - [`consts`] — the envelope-id domain tag, MLS framing prefix, and
//!   sizing/paging bounds.
//! - [`rows`] — wire types (`EnvelopeKind`, `EnvelopeRow`, `LogStats`)
//!   + the content-derived envelope id.
//! - [`roles`] — the [`MsgLogRole`] gate + [`MSG_LOG_SPACE_ROLE_MAP`].
//!
//! `Status` — the handler return type — lives here rather than in its own
//! module: every `#[msg]` handler below returns it, so it reads best kept
//! next to the actor it gates.

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod consts;
pub mod roles;
pub mod rows;

#[cfg(test)]
mod tests;

pub use consts::*;
pub use roles::{MSG_LOG_SPACE_ROLE_MAP, MsgLogRole};
pub use rows::{EnvelopeKind, EnvelopeRow, LogStats, envelope_id};

use vos::prelude::*;

// ── Status codes ──────────────────────────────────────────────────

/// Status returned by a log mutation handler. `Ok` is `0`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// An argument was empty, malformed, or not an App envelope.
    InvalidInput = 1,
    /// The body exceeded [`MAX_BODY_BYTES`].
    BodyTooLarge = 2,
}

impl Status {
    /// Decode a status byte (the over-the-wire discriminant) back into a
    /// `Status`. `None` for an unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidInput),
            2 => Some(Self::BodyTooLarge),
            _ => None,
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::InvalidInput => "invalid input",
            Status::BodyTooLarge => "body too large",
        })
    }
}

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
    ) -> Status {
        if kind != EnvelopeKind::App as u8 {
            // Control-plane envelopes belong in msg-ctl; rejecting
            // them here keeps the two planes from drifting together.
            return Status::InvalidInput;
        }
        if body.is_empty() || lamport == 0 {
            return Status::InvalidInput;
        }
        if body.len() > MAX_BODY_BYTES {
            return Status::BodyTooLarge;
        }
        // Reject anything that isn't MLS PrivateMessage framing before
        // it lands in the replicated log (see the prefix const).
        if !body.starts_with(&MLS_PRIVATE_MESSAGE_PREFIX) {
            return Status::InvalidInput;
        }
        let to_hint = match hint_to_32(&to_hint) {
            Some(h) => h,
            None => return Status::InvalidInput,
        };
        let id = envelope_id(kind, epoch, lamport, ts_ms, &to_hint, &body);
        let pos = match self
            .envelopes
            .binary_search_by(|e| sort_key(e.lamport, &e.id, lamport, &id))
        {
            Ok(_) => return Status::Ok,
            Err(p) => p,
        };
        self.envelopes.insert(
            pos,
            EnvelopeRow {
                id,
                // `post` accepts only App envelopes (checked above).
                kind: EnvelopeKind::App,
                epoch,
                lamport,
                ts_ms,
                to_hint,
                body,
            },
        );
        Status::Ok
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
            max_lamport: self.envelopes.last().map_or(0, |e| e.lamport),
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
    a_lamport.cmp(&b_lamport).then_with(|| a_id.cmp(b_id))
}
