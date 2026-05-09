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
//! needs `alloc`. Phase 4 adds the merkle-crdt `Encode`/`Decode`
//! trait impls.

#![allow(clippy::len_without_is_empty)]

use alloc::vec::Vec;

/// Default size cap for a single `ctx.ask` reply, in bytes.
///
/// Replies from workers or other actors that exceed this cap are
/// replaced with an error-reply marker by the host before being
/// delivered to the handler — and before being logged. This nudges
/// workers toward compact, rkyv-encoded summaries rather than raw
/// payloads. Configurable per-node and per-worker.
pub const DEFAULT_REPLY_CAP: usize = 16 * 1024;

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
}

impl EffectLog {
    /// Start a new log wrapping the given incoming dispatch message.
    pub fn for_msg(msg: Vec<u8>) -> Self {
        Self {
            msg,
            replies: Vec::new(),
        }
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
    /// ```
    ///
    /// The encoding is deterministic and unambiguous, so two
    /// replicas observing the same dispatch produce the same bytes
    /// (and thus the same CID) without coordination.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            16 + self.msg.len() + self.replies.iter().map(|r| 8 + r.len()).sum::<usize>(),
        );
        buf.extend_from_slice(&(self.msg.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.msg);
        buf.extend_from_slice(&(self.replies.len() as u64).to_le_bytes());
        for reply in &self.replies {
            buf.extend_from_slice(&(reply.len() as u64).to_le_bytes());
            buf.extend_from_slice(reply);
        }
        buf
    }

    /// Deserialize from bytes produced by [`to_bytes`]. Returns
    /// `None` if the buffer is malformed, truncated, or has
    /// trailing garbage.
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

        if pos != bytes.len() {
            return None;
        }
        Some(Self { msg, replies })
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
