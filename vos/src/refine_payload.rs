//! Wire format for refine-stage output — the work-result contract.
//!
//! Refine cannot mutate state. The guest's refine entry captures the
//! queued side effects — **including its post-dispatch actor state, as an
//! ordinary [`Effect::Write`] on [`STATE_KEY`](crate::lifecycle::STATE_KEY_BYTES)
//! emitted only when the state bytes changed** — encodes them into a single
//! byte blob, and halts with that blob as its output. Every consumer
//! applies the identical byte-defined semantic: the VOS host drain, the
//! child-invoke conversion, a guest APPLY on a JAM host, and any
//! prover/verifier (see `docs/design/work-result-contract.md`).
//!
//! This module is `no_std` so the same constants and helpers are visible
//! to both the guest framework (encoding) and the host runtime (parsing).
//!
//! ## Wire layout (version 3)
//!
//! ```text
//! [version: u8 = 0x03]
//! [flags: u8]              // bit 0 = continue_next, bit 1 = forbidden
//! [anchor_kind: u8]        // see the anchor section below
//! [anchor: 32 bytes]       // zero-filled when anchor_kind = 0x00
//! [reply_len: u32 LE][reply_bytes]
//! [effects_count: u16 LE]
//!   for each effect:
//!     [tag: u8]
//!     [payload_len: u32 LE]
//!     [payload_bytes]
//! ```
//!
//! The v3 decode is **strictly canonical**: an effect whose payload is not
//! exactly consumed by its fields, or trailing bytes after the last
//! effect, reject the whole payload. That makes "the wire bytes"
//! well-defined for the transition digest.
//!
//! Effects apply in wire order; duplicate keys are legal and later wins
//! per key. The guest framework appends the state write last within the
//! Write batch.
//!
//! ## The anchor
//!
//! The anchor commits to the state this refine ran against:
//!
//! - [`ANCHOR_GENESIS`] (`0x00`) — refine observed no prior state; apply
//!   asserts `STATE_KEY` is absent or empty.
//! - [`ANCHOR_STATE_HASH`] (`0x01`) — `anchor = blake2b-256(prior
//!   STATE_KEY blob bytes)`; apply asserts the current *effective* state
//!   (the journal-overlay view — see `crate::runtime`) hashes to it.
//! - [`ANCHOR_SMT_ROOT`] (`0x02`) — reserved for SMT state roots; not
//!   emitted yet, rejected on decode until it is.
//!
//! ## Version 2 (legacy decode)
//!
//! Already-installed actor blobs emit the v2 layout, which carries the
//! state as an explicit `[state_len: u32 LE][state_bytes]` field between
//! the flags and the reply. The v2 decoder synthesizes that field into a
//! final `Effect::Write { STATE_KEY }` (when non-empty) so every consumer
//! applies one semantic; anchor checks are skipped ([`RefinePayload::version`]
//! tells the host which rules apply). v2 keeps its inherited lax decode.
//!
//! `continue_next` is set by the guest framework when a handler called
//! `ctx.yield_now()` / `ctx.sleep(_)` — scheduling metadata only; the
//! suspended task itself is data, never execution state.
//!
//! ## Effect tags
//!
//! - `0x01` WRITE   — `[key_len: u16 LE][key][value_len: u32 LE][value]`
//! - `0x02` TRANSFER — `[target: u32 LE][memo_bytes]` (memo length is the
//!   remainder of the payload)
//! - `0x03` PROVIDE — `[hash: 32 bytes][data_bytes]`
//! - `0x04` NEW     — `[code_hash: 32 bytes]`
//! - `0x05` is reserved for a future delete effect; not emitted (Write
//!   always carries a value).

use alloc::vec::Vec;

/// Legacy wire version accepted for already-installed actor blobs.
pub const REFINE_PAYLOAD_V2: u8 = 0x02;

/// Current wire version — what the guest framework emits.
pub const REFINE_PAYLOAD_VERSION: u8 = 0x03;

/// Flag bit: guest yielded; host should re-queue this service next tick.
pub const FLAG_CONTINUE_NEXT: u8 = 0x01;

/// Flag bit: the M6 macro-emitted role check refused the call.
/// Host produces a `STATUS_FORBIDDEN` invoke envelope so vosx
/// surfaces "permission denied" instead of treating the empty
/// reply as `Value::Unit`. Wire-additive — older hosts that
/// don't know this bit see `FORBIDDEN` payloads as empty-reply
/// `STATUS_DONE` calls (same as today).
pub const FLAG_FORBIDDEN: u8 = 0x02;

/// Anchor kind: refine observed no prior state. `anchor` is zero-filled.
pub const ANCHOR_GENESIS: u8 = 0x00;

/// Anchor kind: `anchor = blake2b-256(prior STATE_KEY blob bytes)`.
pub const ANCHOR_STATE_HASH: u8 = 0x01;

/// Anchor kind reserved for SMT state roots (`vos::zk::state`). The kind
/// byte reserves the slot so the wire doesn't change; rejected on decode
/// until the SMT generalization emits it.
pub const ANCHOR_SMT_ROOT: u8 = 0x02;

pub const EFFECT_WRITE: u8 = 0x01;
pub const EFFECT_TRANSFER: u8 = 0x02;
pub const EFFECT_PROVIDE: u8 = 0x03;
pub const EFFECT_NEW: u8 = 0x04;

/// Domain separator for [`RefinePayload::transition_digest`].
pub const TRANSITION_DOMAIN: &[u8] = b"vos/transition/v1";

/// The state anchor: plain blake2b-256 over the exact serialized state
/// blob bytes. Shared guest/host definition — the guest computes it via
/// the blake2b precompile before deserializing its state; apply-side
/// consumers recompute it over the effective `STATE_KEY` bytes.
pub fn state_anchor(state: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(&[], &[state])
}

/// `(anchor_kind, anchor)` for the given prior state. Absent or empty
/// state is genesis (`ServiceStorage` stores empty-value writes as
/// present, so both mean "no prior state" to the anchor).
pub fn anchor_for(state: Option<&[u8]>) -> (u8, [u8; 32]) {
    match state {
        Some(bytes) if !bytes.is_empty() => (ANCHOR_STATE_HASH, state_anchor(bytes)),
        _ => (ANCHOR_GENESIS, [0u8; 32]),
    }
}

/// One side effect the host applies natively at commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Write { key: Vec<u8>, value: Vec<u8> },
    Transfer { target: u32, memo: Vec<u8> },
    Provide { hash: [u8; 32], data: Vec<u8> },
    New { code_hash: [u8; 32] },
}

/// A complete refine output ready to encode/decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinePayload {
    /// Wire version this payload was decoded from (or will encode as —
    /// [`encode`](Self::encode) always emits v3). The host dispatches
    /// apply rules on it: anchor checks and the effect-bearing
    /// durable-node rule apply to v3; v2 gets legacy handling.
    pub version: u8,
    /// Commitment kind for the state this refine ran against.
    pub anchor_kind: u8,
    /// The commitment bytes; zero-filled for [`ANCHOR_GENESIS`].
    pub anchor: [u8; 32],
    /// Reply to the *caller*, not to storage — excluded from the
    /// transition digest and bound instead as the io-hash return half.
    pub reply: Vec<u8>,
    /// Effects in wire order. Post-dispatch state travels here as a final
    /// `Write{STATE_KEY}`, emitted only when the state bytes changed.
    pub effects: Vec<Effect>,
    /// Guest requested to be re-scheduled next tick (yield_now / sleep).
    pub continue_next: bool,
    /// M6 — the macro-emitted pre-dispatch role check refused the call.
    pub forbidden: bool,
}

impl Default for RefinePayload {
    fn default() -> Self {
        Self {
            version: REFINE_PAYLOAD_VERSION,
            anchor_kind: ANCHOR_GENESIS,
            anchor: [0u8; 32],
            reply: Vec::new(),
            effects: Vec::new(),
            continue_next: false,
            forbidden: false,
        }
    }
}

impl RefinePayload {
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode to the v3 wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(REFINE_PAYLOAD_VERSION);
        let mut flags: u8 = 0;
        if self.continue_next {
            flags |= FLAG_CONTINUE_NEXT;
        }
        if self.forbidden {
            flags |= FLAG_FORBIDDEN;
        }
        out.push(flags);
        out.push(self.anchor_kind);
        out.extend_from_slice(&self.anchor);
        push_u32(&mut out, self.reply.len() as u32);
        out.extend_from_slice(&self.reply);
        push_u16(&mut out, self.effects.len() as u16);
        for eff in &self.effects {
            encode_effect(&mut out, eff);
        }
        out
    }

    /// Decode from the wire, dispatching on the leading version byte:
    /// v3 with the strict canonical rules, v2 with legacy handling (the
    /// explicit state field is synthesized into a final `Write{STATE_KEY}`
    /// when non-empty). Returns `None` on malformed input or an unknown
    /// version — callers must treat that as a hard failure, not fall
    /// through to defaults.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.first()? {
            &REFINE_PAYLOAD_VERSION => Self::decode_v3(bytes),
            &REFINE_PAYLOAD_V2 => Self::decode_v2(bytes),
            _ => None,
        }
    }

    fn decode_v3(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let version = c.read_u8()?;
        let flags = c.read_u8()?;
        let anchor_kind = c.read_u8()?;
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(c.read_bytes(32)?);
        match anchor_kind {
            ANCHOR_GENESIS => {
                // Genesis carries no commitment; a non-zero anchor is a
                // malformed encoder, not a differently-keyed genesis.
                if anchor != [0u8; 32] {
                    return None;
                }
            }
            ANCHOR_STATE_HASH => {}
            // ANCHOR_SMT_ROOT is reserved: rejecting it now means an SMT
            // emitter can't silently pass an unprepared host later.
            _ => return None,
        }
        let reply_len = c.read_u32()? as usize;
        let reply = c.read_bytes(reply_len)?.to_vec();
        let effects_count = c.read_u16()? as usize;
        let mut effects = Vec::with_capacity(effects_count);
        for _ in 0..effects_count {
            effects.push(decode_effect(&mut c, true)?);
        }
        // Strict canonical: the payload is exactly its fields.
        if !c.is_exhausted() {
            return None;
        }
        Some(RefinePayload {
            version,
            anchor_kind,
            anchor,
            reply,
            effects,
            continue_next: flags & FLAG_CONTINUE_NEXT != 0,
            forbidden: flags & FLAG_FORBIDDEN != 0,
        })
    }

    /// Legacy v2 decode. Keeps the inherited lax rules (no cursor
    /// exhaustion checks) so already-installed blobs keep working, and
    /// synthesizes the explicit state field into a final
    /// `Write{STATE_KEY}` — order-equivalent to the old host's
    /// absorb-then-push — so consumers apply one semantic.
    fn decode_v2(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let version = c.read_u8()?;
        let flags = c.read_u8()?;
        let state_len = c.read_u32()? as usize;
        let state = c.read_bytes(state_len)?.to_vec();
        let reply_len = c.read_u32()? as usize;
        let reply = c.read_bytes(reply_len)?.to_vec();
        let effects_count = c.read_u16()? as usize;
        let mut effects = Vec::with_capacity(effects_count);
        for _ in 0..effects_count {
            effects.push(decode_effect(&mut c, false)?);
        }
        if !state.is_empty() {
            effects.push(Effect::Write {
                key: crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                value: state,
            });
        }
        Some(RefinePayload {
            version,
            anchor_kind: ANCHOR_GENESIS,
            anchor: [0u8; 32],
            reply,
            effects,
            continue_next: flags & FLAG_CONTINUE_NEXT != 0,
            forbidden: flags & FLAG_FORBIDDEN != 0,
        })
    }

    /// Extract the final `Write{STATE_KEY}` value and strip every
    /// `STATE_KEY` write from the effects. Used by the host's
    /// child-invoke conversion: child state travels to the *parent*
    /// envelope, never to a child storage row.
    pub fn take_state_write(&mut self) -> Option<Vec<u8>> {
        let key = crate::lifecycle::STATE_KEY_BYTES;
        let mut state = None;
        // Iterate forward so the LAST state write wins (last-wins per key).
        for eff in &self.effects {
            if let Effect::Write { key: k, value } = eff
                && k.as_slice() == key
            {
                state = Some(value.clone());
            }
        }
        self.effects.retain(
            |eff| !matches!(eff, Effect::Write { key: k, .. } if k.as_slice() == key),
        );
        state
    }

    /// The transition digest — the proving seam's binding over exactly
    /// the bytes every consumer applies:
    ///
    /// ```text
    /// blake2b-256( b"vos/transition/v1"
    ///     || version || anchor_kind || anchor
    ///     || effects_count (u16 LE) || effect_bytes )
    /// ```
    ///
    /// A splice of the wire bytes that skips flags and reply (the reply
    /// is bound as the io-hash return half instead). Byte-different but
    /// semantically-equal encodings digest differently *by design*:
    /// every consumer applies exactly the bytes it digests, so
    /// digest-equal ⇒ byte-equal ⇒ apply-equal. Normative for v3 —
    /// strict canonical decode is what makes the preimage unambiguous.
    pub fn transition_digest(&self) -> [u8; 32] {
        let mut pre = Vec::new();
        pre.push(self.version);
        pre.push(self.anchor_kind);
        pre.extend_from_slice(&self.anchor);
        push_u16(&mut pre, self.effects.len() as u16);
        for eff in &self.effects {
            encode_effect(&mut pre, eff);
        }
        crate::crypto::blake2b::blake2b_hash::<32>(TRANSITION_DOMAIN, &[&pre])
    }
}

/// The folded public layout for provable Tasks (frozen with this wire):
///
/// ```text
/// public' = anchor_kind (1) || anchor (32) || transition_digest (32)
///           || app_public_bytes
/// ```
///
/// The fixed-width prefix makes the fold injective. Guests bind
/// `io_hash(public', reply)` at halt; verifiers reconstruct `public'`
/// identically before the io-hash equality check. Sound only when
/// composed with the entering-memory-image root check — the state
/// anchor and the image root do different jobs and neither subsumes
/// the other.
///
/// Not yet wired into the halt path: the witness-delivered Task ABI
/// (A9) establishes byte-identical live/traced images and work-results,
/// but composing this fold into the io-hash at halt is the `#[provable]`
/// pipeline's job (B2). This helper is the frozen wire it will call;
/// until then a Task binds only its handler's `bind_io` (or the empty
/// default), so a Task's proof does not yet commit to its state
/// transition. See `work-result-contract.md` §5.
pub fn folded_public(
    anchor_kind: u8,
    anchor: &[u8; 32],
    transition_digest: &[u8; 32],
    app_public: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(65 + app_public.len());
    out.push(anchor_kind);
    out.extend_from_slice(anchor);
    out.extend_from_slice(transition_digest);
    out.extend_from_slice(app_public);
    out
}

/// Encode the legacy v2 wire. The guest framework no longer emits it;
/// this pins the format already-installed blobs speak so host-compat
/// paths (version dispatch, state-field synthesis) stay testable.
pub fn encode_v2(
    state: &[u8],
    reply: &[u8],
    effects: &[Effect],
    continue_next: bool,
    forbidden: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(REFINE_PAYLOAD_V2);
    let mut flags: u8 = 0;
    if continue_next {
        flags |= FLAG_CONTINUE_NEXT;
    }
    if forbidden {
        flags |= FLAG_FORBIDDEN;
    }
    out.push(flags);
    push_u32(&mut out, state.len() as u32);
    out.extend_from_slice(state);
    push_u32(&mut out, reply.len() as u32);
    out.extend_from_slice(reply);
    push_u16(&mut out, effects.len() as u16);
    for eff in effects {
        encode_effect(&mut out, eff);
    }
    out
}

fn encode_effect(out: &mut Vec<u8>, eff: &Effect) {
    match eff {
        Effect::Write { key, value } => {
            out.push(EFFECT_WRITE);
            // payload = [key_len:u16][key][value_len:u32][value]
            let payload_len = 2 + key.len() + 4 + value.len();
            push_u32(out, payload_len as u32);
            push_u16(out, key.len() as u16);
            out.extend_from_slice(key);
            push_u32(out, value.len() as u32);
            out.extend_from_slice(value);
        }
        Effect::Transfer { target, memo } => {
            out.push(EFFECT_TRANSFER);
            let payload_len = 4 + memo.len();
            push_u32(out, payload_len as u32);
            push_u32(out, *target);
            out.extend_from_slice(memo);
        }
        Effect::Provide { hash, data } => {
            out.push(EFFECT_PROVIDE);
            let payload_len = 32 + data.len();
            push_u32(out, payload_len as u32);
            out.extend_from_slice(hash);
            out.extend_from_slice(data);
        }
        Effect::New { code_hash } => {
            out.push(EFFECT_NEW);
            push_u32(out, 32);
            out.extend_from_slice(code_hash);
        }
    }
}

/// Decode one effect. With `strict` (v3), the payload must be exactly
/// consumed by the effect's fields; without (v2), inner slack is
/// tolerated as inherited behavior.
fn decode_effect(c: &mut Cursor<'_>, strict: bool) -> Option<Effect> {
    let tag = c.read_u8()?;
    let payload_len = c.read_u32()? as usize;
    let payload = c.read_bytes(payload_len)?;
    let mut pc = Cursor::new(payload);
    let eff = match tag {
        EFFECT_WRITE => {
            let key_len = pc.read_u16()? as usize;
            let key = pc.read_bytes(key_len)?.to_vec();
            let value_len = pc.read_u32()? as usize;
            let value = pc.read_bytes(value_len)?.to_vec();
            Effect::Write { key, value }
        }
        EFFECT_TRANSFER => {
            let target = pc.read_u32()?;
            let memo = pc.remaining().to_vec();
            pc.consume_remaining();
            Effect::Transfer { target, memo }
        }
        EFFECT_PROVIDE => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(pc.read_bytes(32)?);
            let data = pc.remaining().to_vec();
            pc.consume_remaining();
            Effect::Provide { hash, data }
        }
        EFFECT_NEW => {
            let mut code_hash = [0u8; 32];
            code_hash.copy_from_slice(pc.read_bytes(32)?);
            Effect::New { code_hash }
        }
        _ => return None,
    };
    if strict && !pc.is_exhausted() {
        return None;
    }
    Some(eff)
}

// --- Cursor / encoding helpers ---

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_bytes(2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.read_bytes(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    fn consume_remaining(&mut self) {
        self.pos = self.buf.len();
    }
    fn is_exhausted(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;

    fn state_key() -> Vec<u8> {
        crate::lifecycle::STATE_KEY_BYTES.to_vec()
    }

    #[test]
    fn roundtrip_empty() {
        let p = RefinePayload::new();
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn roundtrip_anchor_and_reply() {
        let p = RefinePayload {
            anchor_kind: ANCHOR_STATE_HASH,
            anchor: state_anchor(b"prior-state"),
            reply: vec![0xAA, 0xBB],
            continue_next: true,
            ..RefinePayload::new()
        };
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn roundtrip_all_effects() {
        let p = RefinePayload {
            effects: vec![
                Effect::Write {
                    key: b"k1".to_vec(),
                    value: vec![1, 2, 3],
                },
                Effect::Transfer {
                    target: 42,
                    memo: b"hello".to_vec(),
                },
                Effect::Provide {
                    hash: [9; 32],
                    data: vec![0xFF, 0xEE],
                },
                Effect::New { code_hash: [7; 32] },
            ],
            ..RefinePayload::new()
        };
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = RefinePayload::new().encode();
        bytes[0] = 0xFF;
        assert!(RefinePayload::decode(&bytes).is_none());
    }

    #[test]
    fn rejects_truncated() {
        let bytes = RefinePayload {
            reply: vec![1, 2, 3],
            ..RefinePayload::new()
        }
        .encode();
        assert!(RefinePayload::decode(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn rejects_trailing_bytes() {
        // Strict canonical: anything after the last effect rejects.
        let mut bytes = RefinePayload {
            effects: vec![Effect::Write {
                key: b"k".to_vec(),
                value: vec![1],
            }],
            ..RefinePayload::new()
        }
        .encode();
        bytes.push(0x00);
        assert!(RefinePayload::decode(&bytes).is_none());
    }

    #[test]
    fn rejects_effect_payload_slack() {
        // A Write whose declared payload_len exceeds its fields must
        // reject under v3 — the digest preimage would be ambiguous.
        let mut bytes = Vec::new();
        bytes.push(REFINE_PAYLOAD_VERSION);
        bytes.push(0); // flags
        bytes.push(ANCHOR_GENESIS);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // reply_len
        bytes.extend_from_slice(&1u16.to_le_bytes()); // effects_count
        bytes.push(EFFECT_WRITE);
        // payload = key_len(2) + "k"(1) + value_len(4) + value(1) = 8,
        // declared 9 with one slack byte inside the payload.
        bytes.extend_from_slice(&9u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(b'k');
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0xAB);
        bytes.push(0x00); // slack
        assert!(RefinePayload::decode(&bytes).is_none());
    }

    #[test]
    fn rejects_nonzero_genesis_anchor() {
        let mut bytes = RefinePayload::new().encode();
        // anchor bytes start after version+flags+anchor_kind.
        bytes[3] = 1;
        assert!(RefinePayload::decode(&bytes).is_none());
    }

    #[test]
    fn rejects_reserved_smt_anchor_kind() {
        let mut bytes = RefinePayload::new().encode();
        bytes[2] = ANCHOR_SMT_ROOT;
        assert!(RefinePayload::decode(&bytes).is_none());
    }

    #[test]
    fn v2_decode_synthesizes_state_write() {
        // The v2 state field becomes the FINAL effect — a Write on
        // STATE_KEY — so one apply semantic covers both versions.
        let bytes = encode_v2(
            b"legacy-state",
            b"reply",
            &[Effect::Transfer {
                target: 9,
                memo: b"m".to_vec(),
            }],
            false,
            false,
        );
        let p = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p.version, REFINE_PAYLOAD_V2);
        assert_eq!(p.reply, b"reply");
        assert_eq!(p.effects.len(), 2);
        assert_eq!(
            p.effects[1],
            Effect::Write {
                key: state_key(),
                value: b"legacy-state".to_vec(),
            }
        );
    }

    #[test]
    fn v2_decode_empty_state_synthesizes_nothing() {
        // v2 guests emit empty state for "nothing changed"; that must
        // not become an empty STATE_KEY write (which would wipe state
        // under last-wins).
        let bytes = encode_v2(b"", b"", &[], true, false);
        let p = RefinePayload::decode(&bytes).unwrap();
        assert!(p.effects.is_empty());
        assert!(p.continue_next);
    }

    #[test]
    fn roundtrip_forbidden_flag() {
        let p = RefinePayload {
            forbidden: true,
            ..RefinePayload::new()
        };
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
        assert!(decoded.forbidden);
    }

    #[test]
    fn take_state_write_strips_and_returns_last() {
        let mut p = RefinePayload {
            effects: vec![
                Effect::Write {
                    key: state_key(),
                    value: b"first".to_vec(),
                },
                Effect::Write {
                    key: b"other".to_vec(),
                    value: b"kept".to_vec(),
                },
                Effect::Write {
                    key: state_key(),
                    value: b"last".to_vec(),
                },
            ],
            ..RefinePayload::new()
        };
        assert_eq!(p.take_state_write(), Some(b"last".to_vec()));
        assert_eq!(
            p.effects,
            vec![Effect::Write {
                key: b"other".to_vec(),
                value: b"kept".to_vec(),
            }]
        );
        assert_eq!(p.take_state_write(), None);
    }

    #[test]
    fn transition_digest_skips_flags_and_reply() {
        let base = RefinePayload {
            anchor_kind: ANCHOR_STATE_HASH,
            anchor: state_anchor(b"s"),
            effects: vec![Effect::Write {
                key: b"k".to_vec(),
                value: vec![1],
            }],
            ..RefinePayload::new()
        };
        let with_reply = RefinePayload {
            reply: b"different-reply".to_vec(),
            continue_next: true,
            ..base.clone()
        };
        assert_eq!(base.transition_digest(), with_reply.transition_digest());

        let different_effects = RefinePayload {
            effects: vec![Effect::Write {
                key: b"k".to_vec(),
                value: vec![2],
            }],
            ..base.clone()
        };
        assert_ne!(
            base.transition_digest(),
            different_effects.transition_digest()
        );

        let different_anchor = RefinePayload {
            anchor: state_anchor(b"other"),
            ..base.clone()
        };
        assert_ne!(
            base.transition_digest(),
            different_anchor.transition_digest()
        );
    }

    #[test]
    fn anchor_for_matches_contract() {
        assert_eq!(anchor_for(None), (ANCHOR_GENESIS, [0u8; 32]));
        assert_eq!(anchor_for(Some(b"")), (ANCHOR_GENESIS, [0u8; 32]));
        let (kind, anchor) = anchor_for(Some(b"state"));
        assert_eq!(kind, ANCHOR_STATE_HASH);
        assert_eq!(anchor, state_anchor(b"state"));
    }
}
