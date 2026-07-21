//! Effect log for CRDT/Raft replay.
//!
//! When an actor runs under a replicating commit strategy (CRDT,
//! Raft), the host captures the bytes of every reply the handler
//! observes via `ctx.ask`. These captured replies are stored
//! alongside the incoming message in the replica's DAG node so
//! other replicas — and the same replica on restart — can rebuild
//! the same state deterministically without re-issuing the asks.
//!
//! The log is ordered by `ctx.ask` call order within a single
//! dispatch. On replay, a cursor walks the log in the same order,
//! handing back each reply as the handler re-issues its asks.
//!
//! The module is intentionally decoupled from merkle-crdt — it only
//! needs `alloc`. The `merkle-crdt` crate provides the `Encode` and
//! `Decode` implementations for `EffectLog`.

#![allow(clippy::len_without_is_empty)]

use alloc::vec::Vec;

/// `anchor_kind` sentinel for a recording session which has not yet been
/// completed. Durable logs must be stamped before commit. Distinct from
/// `ANCHOR_GENESIS` (0x00), which is a real, comparable anchor.
pub const ANCHOR_UNRECORDED: u8 = 0xFF;

/// Caller-prefix bytes recorded per dispatch — the wire the host
/// prepends so the guest's dispatch gate sees the caller's trust flag
/// and role grants: `[trust_flag, has_space_role, space_role,
/// has_actor_local_role, actor_local_role]`. Recording them makes
/// replay re-run each dispatch under the ORIGINAL caller's authority,
/// so a role-refused dispatch replays as refused — replaying everything
/// as trusted-System would re-admit refused calls and diverge the
/// rebuilt state from the committed history.
pub type CallerPrefix = [u8; 5];

/// Default caller prefix for a recording session before the authenticated
/// dispatch identity is stamped.
pub const CALLER_SYSTEM: CallerPrefix = [1, 0, 0, 0, 0];

/// Default size cap for a single `ctx.ask` reply, in bytes.
///
/// Replies from workers or other actors that exceed this cap are
/// replaced with an error-reply marker by the host before being
/// delivered to the handler — and before being logged. This nudges
/// workers toward compact, rkyv-encoded summaries rather than raw
/// payloads. Configurable per-node and per-worker.
pub const DEFAULT_REPLY_CAP: usize = 16 * 1024;

/// Side effects an invoked child folded into the journal while the
/// enclosing depth-1 invoke ran — a Task child's rows/transfers fold
/// into the invoking parent's keyspace, a peer child's into its own.
/// Replay short-circuits the child to its recorded output, so these
/// must be re-absorbed when that output is popped: without them a
/// replica rebuild silently drops every effect a child produced, and
/// the post-replay whole-table persistence then makes the loss
/// durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeEffects {
    /// Index into [`EffectLog::replies`] of the depth-1 invoke output
    /// these effects accompanied.
    pub reply_idx: u64,
    /// The service scope the live run absorbed them into.
    pub svc_id: u32,
    /// The effects, in the `RefinePayload` effect wire encoding
    /// (`refine_payload::encode_effects`).
    pub effects: Vec<u8>,
}

/// Ordered log of reply bytes captured during one dispatch.
///
/// Stored inside a CRDT actor's DAG node together with the incoming
/// message bytes. Used both for recording (append replies as they
/// arrive) and replay (pop replies in order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectLog {
    /// The incoming dispatch message — rkyv-encoded bytes exactly
    /// as the host would hand them to the actor's dispatch entry.
    pub msg: Vec<u8>,
    /// Reply bytes in `ctx.ask` call order. Empty for pure actors
    /// and read-only dispatches.
    pub replies: Vec<Vec<u8>>,
    /// `(kind, anchor)` of the work-result this dispatch applied
    /// against — NORMATIVE, not just audit: replay divergence detection
    /// compares each re-emitted work-result's anchor against this
    /// recorded value (the self-check against effective state passes by
    /// construction during replay and detects nothing).
    /// [`ANCHOR_UNRECORDED`] when the dispatch carried no anchor.
    pub anchor_kind: u8,
    /// The recorded anchor bytes; zero-filled when unrecorded.
    pub anchor: [u8; 32],
    /// The caller-prefix bytes this dispatch ran under; replay wraps
    /// the message with exactly these so gate decisions reproduce
    /// (see [`CallerPrefix`]).
    pub caller_prefix: CallerPrefix,
    /// Side effects invoked children absorbed into the journal, keyed
    /// to the reply they rode with. Empty for dispatches whose invokes
    /// produced no effects (and for every ask reply).
    pub invoke_effects: Vec<InvokeEffects>,
}

impl EffectLog {
    /// Start a new log wrapping the given incoming dispatch message.
    pub fn for_msg(msg: Vec<u8>) -> Self {
        Self {
            msg,
            replies: Vec::new(),
            anchor_kind: ANCHOR_UNRECORDED,
            anchor: [0u8; 32],
            caller_prefix: CALLER_SYSTEM,
            invoke_effects: Vec::new(),
        }
    }

    /// Record the `(kind, anchor)` the dispatch's first work-result
    /// declared (and the runtime verified). Stamped by the host after
    /// the dispatch completes, before the log is committed.
    pub fn set_anchor(&mut self, kind: u8, anchor: [u8; 32]) {
        self.anchor_kind = kind;
        self.anchor = anchor;
    }

    /// Record the caller-prefix bytes the dispatch ran under. Stamped
    /// by the host alongside the anchor, before the log commits.
    pub fn set_caller_prefix(&mut self, prefix: CallerPrefix) {
        self.caller_prefix = prefix;
    }

    /// Append the next reply captured during dispatch.
    pub fn record_reply(&mut self, reply: Vec<u8>) {
        self.replies.push(reply);
    }

    /// Did the handler observe any replies? `false` is indistinguishable
    /// from a pure-actor dispatch.
    pub fn is_effectful(&self) -> bool {
        !self.replies.is_empty()
    }

    /// Number of replies recorded.
    pub fn reply_count(&self) -> usize {
        self.replies.len()
    }

    /// Start a cursor for replaying the recorded replies in order.
    pub fn replay(&self) -> EffectCursor<'_> {
        EffectCursor {
            replies: &self.replies,
            pos: 0,
        }
    }

    /// Serialize to bytes for storage in a merkle-crdt DAG node.
    ///
    /// Format:
    /// ```text
    /// [msg_len:u64 LE][msg][n_replies:u64 LE]
    /// ( [reply_len:u64 LE][reply] )*
    /// [anchor_kind:u8][anchor:32B][caller_prefix:5B]
    /// [n_invoke_effects:u64 LE]
    /// ( [reply_idx:u64 LE][svc_id:u32 LE][len:u64 LE][effects] )*
    /// ```
    ///
    /// The encoding is deterministic and unambiguous, so two
    /// replicas observing the same dispatch produce the same bytes
    /// (and thus the same CID) without coordination.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            16 + 33 + self.msg.len() + self.replies.iter().map(|r| 8 + r.len()).sum::<usize>(),
        );
        buf.extend_from_slice(&(self.msg.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.msg);
        buf.extend_from_slice(&(self.replies.len() as u64).to_le_bytes());
        for reply in &self.replies {
            buf.extend_from_slice(&(reply.len() as u64).to_le_bytes());
            buf.extend_from_slice(reply);
        }
        buf.push(self.anchor_kind);
        buf.extend_from_slice(&self.anchor);
        buf.extend_from_slice(&self.caller_prefix);
        buf.extend_from_slice(&(self.invoke_effects.len() as u64).to_le_bytes());
        for rec in &self.invoke_effects {
            buf.extend_from_slice(&rec.reply_idx.to_le_bytes());
            buf.extend_from_slice(&rec.svc_id.to_le_bytes());
            buf.extend_from_slice(&(rec.effects.len() as u64).to_le_bytes());
            buf.extend_from_slice(&rec.effects);
        }
        buf
    }

    /// Deserialize from bytes produced by [`to_bytes`]. Returns
    /// `None` if the buffer is malformed, truncated, has trailing garbage,
    /// or uses a retired pre-anchor/pre-invoke-effects encoding.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let msg_len = read_u64(bytes, &mut pos)? as usize;
        let msg = take(bytes, &mut pos, msg_len)?.to_vec();

        let n_replies = read_u64(bytes, &mut pos)? as usize;
        let mut replies = Vec::with_capacity(n_replies);
        for _ in 0..n_replies {
            let len = read_u64(bytes, &mut pos)? as usize;
            replies.push(take(bytes, &mut pos, len)?.to_vec());
        }

        let anchor_kind = *bytes.get(pos)?;
        pos += 1;
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(take(bytes, &mut pos, 32)?);
        let mut caller_prefix = [0u8; 5];
        caller_prefix.copy_from_slice(take(bytes, &mut pos, 5)?);
        let n = read_u64(bytes, &mut pos)? as usize;
        let mut invoke_effects = Vec::with_capacity(n);
        for _ in 0..n {
            let reply_idx = read_u64(bytes, &mut pos)?;
            let svc_bytes = take(bytes, &mut pos, 4)?;
            let svc_id = u32::from_le_bytes(svc_bytes.try_into().ok()?);
            let len = read_u64(bytes, &mut pos)? as usize;
            let effects = take(bytes, &mut pos, len)?.to_vec();
            invoke_effects.push(InvokeEffects {
                reply_idx,
                svc_id,
                effects,
            });
        }
        if pos != bytes.len() {
            return None;
        }
        Some(Self {
            msg,
            replies,
            anchor_kind,
            anchor,
            caller_prefix,
            invoke_effects,
        })
    }
}

/// One CRDT-replicated event: an [`EffectLog`] tagged with the
/// replica that produced it and a per-origin sequence number.
///
/// `(origin, seq)` is the authoritative identity of the event. Two
/// replicas independently producing byte-identical `EffectLog`s
/// (e.g. both calling `counter.inc()`) end up with distinct
/// `CrdtEvent`s because their origins differ. The DAG-node CID
/// hashes the event bytes — origin/seq included — so the merkle
/// DAG stores both as separate nodes that merge cleanly across
/// replicas. Replays preserve each event's recorded `(origin, seq)`,
/// so a replicated DAG round-trips through any replica without
/// re-numbering.
///
/// Replay reads `event.log` and feeds it through the runtime
/// exactly as the originating replica did; `origin` and `seq` are
/// metadata for the merkle layer, not visible to handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrdtEvent {
    /// Replica id of the producer — typically the CRDT
    /// replication-id the agent is registered under.
    pub origin: [u8; 32],
    /// Per-origin monotone counter. Allocated by the producing
    /// replica's [`CrdtCommit`](crate::commit::CrdtCommit) on
    /// each state-changing dispatch and persisted alongside the
    /// new DAG node.
    pub seq: u64,
    /// The recorded effect log — incoming dispatch + observed
    /// replies. Replays feed this through the runtime to rebuild
    /// state.
    pub log: EffectLog,
}

/// Wire format version byte at the head of [`CrdtEvent::to_bytes`].
/// Reserved for future additions (e.g. embedding a parent-vector
/// or a deletion tombstone). Bumping invalidates existing CIDs;
/// downstream stores must be drained on upgrade.
pub const CRDT_EVENT_VERSION: u8 = 1;

impl CrdtEvent {
    /// Build a fresh event tagged with the producing replica's
    /// id and a freshly allocated `seq`.
    pub fn new(origin: [u8; 32], seq: u64, log: EffectLog) -> Self {
        Self { origin, seq, log }
    }

    /// Serialize for storage in a merkle-crdt DAG node.
    ///
    /// Format:
    /// ```text
    /// [version:u8][origin:32B][seq:u64 LE][effect_log_bytes…]
    /// ```
    ///
    /// The encoding is deterministic — replicas with identical
    /// origins, seqs, and logs produce identical bytes. Different
    /// origins or seqs produce different bytes (and thus different
    /// CIDs), which is the whole point.
    pub fn to_bytes(&self) -> Vec<u8> {
        let log_bytes = self.log.to_bytes();
        let mut buf = Vec::with_capacity(1 + 32 + 8 + log_bytes.len());
        buf.push(CRDT_EVENT_VERSION);
        buf.extend_from_slice(&self.origin);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&log_bytes);
        buf
    }

    /// Deserialize from bytes produced by [`to_bytes`]. Returns
    /// `None` on a version mismatch, malformed prefix, or any
    /// EffectLog decode failure.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 + 32 + 8 {
            return None;
        }
        if bytes[0] != CRDT_EVENT_VERSION {
            return None;
        }
        let mut origin = [0u8; 32];
        origin.copy_from_slice(&bytes[1..33]);
        let seq = u64::from_le_bytes(bytes[33..41].try_into().ok()?);
        let log = EffectLog::from_bytes(&bytes[41..])?;
        Some(Self { origin, seq, log })
    }
}

/// Side-channel state for one dispatch under a CRDT/Raft strategy.
///
/// Exactly one mode is active at a time — a dispatch is either
/// observed for the first time (`Recording`) or being replayed from
/// a stored log (`Replaying`). `Inactive` means the actor is under
/// a `LocalCommit` (or `NoCommit`) strategy and the invoke handler
/// runs in the same way it always has.
///
/// The runtime holds one of these per tick and threads a
/// mutable reference down through the refine/invoke call chain.
#[derive(Default)]
pub enum EffectMode {
    /// No recording or replay — the default.
    #[default]
    Inactive,
    /// The host captures every top-level invoke output so the
    /// finished log can be attached to the commit.
    Recording(EffectSession),
    /// The host short-circuits every top-level invoke, replaying
    /// the observed output bytes from the log instead of running
    /// the child.
    Replaying(EffectReplay),
}

impl EffectMode {
    /// `true` when actively recording. Mainly for tests and host
    /// diagnostics; user code generally shouldn't need to peek.
    #[doc(hidden)]
    pub fn is_recording(&self) -> bool {
        matches!(self, EffectMode::Recording(_))
    }

    /// `true` when actively replaying. Mainly for tests and host
    /// diagnostics.
    #[doc(hidden)]
    pub fn is_replaying(&self) -> bool {
        matches!(self, EffectMode::Replaying(_))
    }
}

/// In-flight recording state for one dispatch.
///
/// The host creates a session when a CRDT/Raft actor is about to
/// dispatch a message, passes it through the invoke handler so
/// each observed reply gets appended, then takes back the finished
/// [`EffectLog`] to attach to the commit.
///
/// Only used on the recording side; replay reads directly from a
/// stored [`EffectLog`] via [`EffectCursor`].
pub struct EffectSession {
    log: EffectLog,
    cap: usize,
}

impl EffectSession {
    /// Start a session for the given incoming dispatch message.
    pub fn new(msg: Vec<u8>) -> Self {
        Self {
            log: EffectLog::for_msg(msg),
            cap: DEFAULT_REPLY_CAP,
        }
    }

    /// Override the default per-reply size cap.
    pub fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap;
        self
    }

    /// Current per-reply size cap in bytes.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Append an observed reply.
    ///
    /// Cap enforcement (replacing over-size replies with an error
    /// marker before calling this) is the caller's responsibility —
    /// the session stores whatever bytes it is given.
    pub fn record(&mut self, reply: Vec<u8>) {
        self.log.record_reply(reply);
    }

    /// Record side effects an invoked child absorbed into the journal
    /// under `svc_id` (`effects` in the `RefinePayload` wire encoding).
    /// Attaches to the NEXT reply to be recorded — the absorb sites
    /// run before the invoke's output envelope is appended, including
    /// nested absorbs inside a still-running depth-1 child.
    pub fn record_invoke_effects(&mut self, svc_id: u32, effects: Vec<u8>) {
        let reply_idx = self.log.replies.len() as u64;
        self.log.invoke_effects.push(InvokeEffects {
            reply_idx,
            svc_id,
            effects,
        });
    }

    /// Number of replies recorded so far.
    pub fn reply_count(&self) -> usize {
        self.log.reply_count()
    }

    /// Consume the session and return the finished log.
    pub fn into_log(self) -> EffectLog {
        self.log
    }
}

/// Replay state for one dispatch: owns the log and walks it in
/// order as the handler re-issues its asks.
///
/// `EffectReplay::next_reply` returns the next recorded output.
/// If the handler asks more than was recorded, `next_reply`
/// returns `None` and marks the replay as exhausted — callers
/// should treat this as a non-determinism failure and surface a
/// PANICKED status back to the PVM.
pub struct EffectReplay {
    log: EffectLog,
    pos: usize,
    exhausted: bool,
}

impl EffectReplay {
    /// Wrap a stored [`EffectLog`] for replay.
    pub fn new(log: EffectLog) -> Self {
        Self {
            log,
            pos: 0,
            exhausted: false,
        }
    }

    /// The incoming dispatch message associated with this log.
    pub fn msg(&self) -> &[u8] {
        &self.log.msg
    }

    /// Consume the next recorded reply. `None` means the log is
    /// exhausted — the handler is asking more than was recorded.
    pub fn next_reply(&mut self) -> Option<&[u8]> {
        if self.pos >= self.log.replies.len() {
            self.exhausted = true;
            return None;
        }
        let r = &self.log.replies[self.pos];
        self.pos += 1;
        Some(r.as_slice())
    }

    /// Number of replies already consumed.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The invoke-effects records attached to the reply at `idx`
    /// (the reply [`next_reply`](Self::next_reply) just returned is
    /// index `position() - 1`). The replaying invoke short-circuit
    /// re-absorbs these — the child never re-runs, but its journal
    /// effects are recorded history.
    pub fn effects_for(&self, idx: usize) -> impl Iterator<Item = &InvokeEffects> {
        self.log
            .invoke_effects
            .iter()
            .filter(move |rec| rec.reply_idx as usize == idx)
    }

    /// Did the replay consume every recorded reply?
    pub fn is_complete(&self) -> bool {
        !self.exhausted && self.pos == self.log.replies.len()
    }

    /// Did the handler ask for more replies than were recorded?
    pub fn was_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Recover the original log (e.g. if the dispatch failed and
    /// you want to retry).
    pub fn into_log(self) -> EffectLog {
        self.log
    }
}

/// Walks the reply log in dispatch order during replay.
///
/// The handler is expected to consume replies at the same
/// `ctx.ask` call sites as the recording run. Exhaustion before
/// the handler finishes means the handler became non-deterministic
/// (extra asks after recording) — callers should treat this as a
/// replay failure.
pub struct EffectCursor<'a> {
    replies: &'a [Vec<u8>],
    pos: usize,
}

impl<'a> EffectCursor<'a> {
    /// Next recorded reply, or `None` if the cursor is exhausted.
    pub fn next_reply(&mut self) -> Option<&'a [u8]> {
        let r = self.replies.get(self.pos)?;
        self.pos += 1;
        Some(r.as_slice())
    }

    /// Number of replies already consumed.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Has every recorded reply been consumed?
    pub fn is_exhausted(&self) -> bool {
        self.pos >= self.replies.len()
    }
}

fn read_u64(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let end = *pos + 8;
    if end > buf.len() {
        return None;
    }
    let v = u64::from_le_bytes(buf[*pos..end].try_into().ok()?);
    *pos = end;
    Some(v)
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = *pos + n;
    if end > buf.len() {
        return None;
    }
    let s = &buf[*pos..end];
    *pos = end;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_replay_roundtrip() {
        let mut log = EffectLog::for_msg(b"hello".to_vec());
        log.record_reply(b"one".to_vec());
        log.record_reply(b"two".to_vec());
        log.record_reply(b"three".to_vec());

        assert_eq!(log.reply_count(), 3);
        assert!(log.is_effectful());

        let mut c = log.replay();
        assert_eq!(c.next_reply(), Some(&b"one"[..]));
        assert_eq!(c.next_reply(), Some(&b"two"[..]));
        assert_eq!(c.next_reply(), Some(&b"three"[..]));
        assert_eq!(c.next_reply(), None);
        assert!(c.is_exhausted());
    }

    #[test]
    fn pure_log_has_no_replies() {
        let log = EffectLog::for_msg(b"pure-msg".to_vec());
        assert!(!log.is_effectful());
        assert_eq!(log.reply_count(), 0);
        let mut c = log.replay();
        assert_eq!(c.next_reply(), None);
    }

    #[test]
    fn bytes_roundtrip_with_replies() {
        let mut log = EffectLog::for_msg(b"dispatch".to_vec());
        log.record_reply(b"a".to_vec());
        log.record_reply(Vec::new()); // empty reply is a valid observation
        log.record_reply(b"lots of bytes here".to_vec());

        let bytes = log.to_bytes();
        let decoded = EffectLog::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, log);
    }

    #[test]
    fn bytes_roundtrip_pure() {
        let log = EffectLog::for_msg(b"just-a-msg".to_vec());
        let bytes = log.to_bytes();
        let decoded = EffectLog::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, log);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let log = EffectLog::for_msg(b"x".to_vec());
        let mut bytes = log.to_bytes();
        bytes.push(0xff);
        assert!(EffectLog::from_bytes(&bytes).is_none());
    }

    #[test]
    fn invoke_effects_roundtrip_and_replay_lookup() {
        // A session recording two invokes: the first absorbed effects
        // into two scopes (a nested absorb plus the depth-1 child's),
        // the second none, and a plain ask reply in between.
        let mut s = EffectSession::new(b"dispatch".to_vec());
        s.record_invoke_effects(7, b"fx-a".to_vec());
        s.record_invoke_effects(9, b"fx-b".to_vec());
        s.record(b"task-output".to_vec()); // reply 0 — both records attach here
        s.record(b"ask-reply".to_vec()); // reply 1 — no effects
        s.record(b"invoke-2".to_vec()); // reply 2 — no effects
        let log = s.into_log();

        let bytes = log.to_bytes();
        let decoded = EffectLog::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, log);

        let mut replay = EffectReplay::new(decoded);
        assert_eq!(replay.next_reply(), Some(&b"task-output"[..]));
        let recs: Vec<(u32, &[u8])> = replay
            .effects_for(replay.position() - 1)
            .map(|r| (r.svc_id, r.effects.as_slice()))
            .collect();
        assert_eq!(recs, vec![(7, &b"fx-a"[..]), (9, &b"fx-b"[..])]);
        assert_eq!(replay.next_reply(), Some(&b"ask-reply"[..]));
        assert_eq!(replay.effects_for(replay.position() - 1).count(), 0);
        assert_eq!(replay.next_reply(), Some(&b"invoke-2"[..]));
        assert_eq!(replay.effects_for(replay.position() - 1).count(), 0);
        assert!(replay.is_complete());
    }

    #[test]
    fn invoke_effects_count_is_always_present() {
        let mut log = EffectLog::for_msg(b"m".to_vec());
        log.record_reply(b"r".to_vec());
        let plain = log.to_bytes();
        assert_eq!(&plain[plain.len() - 8..], &0u64.to_le_bytes());
        log.invoke_effects.push(InvokeEffects {
            reply_idx: 0,
            svc_id: 3,
            effects: b"fx".to_vec(),
        });
        let extended = log.to_bytes();
        assert!(extended.len() > plain.len());
        assert!(EffectLog::from_bytes(&extended[..extended.len() - 1]).is_none());
    }

    #[test]
    fn decode_rejects_truncated() {
        let mut log = EffectLog::for_msg(b"xx".to_vec());
        log.record_reply(b"yy".to_vec());
        let bytes = log.to_bytes();
        for cut in 0..bytes.len() {
            assert!(
                EffectLog::from_bytes(&bytes[..cut]).is_none(),
                "truncated at {cut} should fail",
            );
        }
    }

    #[test]
    fn deterministic_encoding() {
        // Two independent logs with the same contents encode to
        // identical bytes — required for CID stability across
        // replicas.
        let mut a = EffectLog::for_msg(b"m".to_vec());
        a.record_reply(b"r1".to_vec());
        a.record_reply(b"r2".to_vec());

        let mut b = EffectLog::for_msg(b"m".to_vec());
        b.record_reply(b"r1".to_vec());
        b.record_reply(b"r2".to_vec());

        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn anchor_roundtrips() {
        let mut log = EffectLog::for_msg(b"m".to_vec());
        assert_eq!(log.anchor_kind, ANCHOR_UNRECORDED);
        log.set_anchor(0x01, [7u8; 32]);
        let decoded = EffectLog::from_bytes(&log.to_bytes()).expect("decode");
        assert_eq!(decoded, log);
        assert_eq!(decoded.anchor_kind, 0x01);
        assert_eq!(decoded.anchor, [7u8; 32]);
    }

    #[test]
    fn pre_anchor_encoding_requires_reset_and_reinstall() {
        let mut log = EffectLog::for_msg(b"legacy".to_vec());
        log.record_reply(b"r".to_vec());
        let with_suffix = log.to_bytes();
        let pre_anchor_len = 8 + log.msg.len() + 8 + 8 + log.replies[0].len();
        assert!(EffectLog::from_bytes(&with_suffix[..pre_anchor_len]).is_none());
        assert!(EffectLog::from_bytes(&with_suffix[..with_suffix.len() - 8]).is_none());
    }

    #[test]
    fn default_cap_is_16k() {
        assert_eq!(DEFAULT_REPLY_CAP, 16 * 1024);
    }

    #[test]
    fn session_defaults_and_records() {
        let mut s = EffectSession::new(b"dispatch".to_vec());
        assert_eq!(s.cap(), DEFAULT_REPLY_CAP);
        assert_eq!(s.reply_count(), 0);

        s.record(b"r1".to_vec());
        s.record(b"r2".to_vec());
        assert_eq!(s.reply_count(), 2);

        let log = s.into_log();
        assert_eq!(log.msg, b"dispatch");
        assert_eq!(log.replies, alloc::vec![b"r1".to_vec(), b"r2".to_vec()]);
    }

    #[test]
    fn session_with_cap_override() {
        let s = EffectSession::new(Vec::new()).with_cap(1024);
        assert_eq!(s.cap(), 1024);
    }
}
