//! Wire format for refine-stage output.
//!
//! Refine cannot mutate state. Instead, the guest's `run_refine_service`
//! captures the new actor state and the queued side effects, encodes them
//! into a single byte blob, and halts with that blob as its output. The
//! runtime puts the blob into a `WorkResult::Ok(_)` operand and hands it
//! to the accumulate stage via `FETCH`. The guest's
//! `run_accumulate_service` decodes the blob and replays each effect via
//! a real accumulate hostcall.
//!
//! This module is `no_std` so the same constants and helpers are visible
//! to both the guest framework (encoding) and the host runtime (parsing,
//! when needed for tests or tracing).
//!
//! ## Wire layout (version 2)
//!
//! ```text
//! [version: u8 = 0x02]
//! [flags: u8]              // bit 0 = continue_next
//! [state_len: u32 LE][state_bytes]
//! [reply_len:  u32 LE][reply_bytes]
//! [effects_count: u16 LE]
//!   for each effect:
//!     [tag: u8]
//!     [payload_len: u32 LE]
//!     [payload_bytes]
//! ```
//!
//! `continue_next` is set by the guest framework when a handler called
//! `ctx.yield_now()` or `ctx.sleep(_)` — the host re-queues the service
//! for the next tick so the actor can make progress.
//!
//! ## Effect tags
//!
//! - `0x01` WRITE   — `[key_len: u16 LE][key][value_len: u32 LE][value]`
//! - `0x02` TRANSFER — `[target: u32 LE][memo_bytes]` (memo length is the
//!   remainder of the payload)
//! - `0x03` PROVIDE — `[hash: 32 bytes][data_bytes]`
//! - `0x04` NEW     — `[code_hash: 32 bytes]`

use alloc::vec::Vec;

pub const REFINE_PAYLOAD_VERSION: u8 = 0x02;

/// Flag bit: guest yielded; host should re-queue this service next tick.
pub const FLAG_CONTINUE_NEXT: u8 = 0x01;

pub const EFFECT_WRITE: u8 = 0x01;
pub const EFFECT_TRANSFER: u8 = 0x02;
pub const EFFECT_PROVIDE: u8 = 0x03;
pub const EFFECT_NEW: u8 = 0x04;

/// One side effect to be replayed by accumulate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Write { key: Vec<u8>, value: Vec<u8> },
    Transfer { target: u32, memo: Vec<u8> },
    Provide { hash: [u8; 32], data: Vec<u8> },
    New { code_hash: [u8; 32] },
}

/// A complete refine output ready to encode/decode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefinePayload {
    pub state: Vec<u8>,
    pub reply: Vec<u8>,
    pub effects: Vec<Effect>,
    /// Guest requested to be re-scheduled next tick (yield_now / sleep).
    pub continue_next: bool,
}

impl RefinePayload {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replay all buffered effects via accumulate-phase hostcalls.
    ///
    /// This is the default accumulate commit path: each effect queued
    /// during refine is applied via the corresponding real hostcall
    /// (WRITE, TRANSFER, PROVIDE, NEW). Also handles self-scheduling
    /// when `continue_next` is set.
    #[cfg(feature = "service")]
    pub fn replay_effects(&self) {
        use crate::abi::pvm::hostcalls;
        use crate::abi::service::ServiceId;
        use crate::actors::lifecycle;

        for eff in &self.effects {
            match eff {
                Effect::Write { key, value } => {
                    hostcalls::write(key, value);
                }
                Effect::Transfer { target, memo } => {
                    hostcalls::transfer(ServiceId(*target), 0, 0, memo);
                }
                Effect::Provide { hash, data } => {
                    hostcalls::provide(hash, data);
                }
                Effect::New { code_hash } => {
                    hostcalls::new_service(code_hash);
                }
            }
        }

        if self.continue_next && !self.state.is_empty() {
            hostcalls::write(lifecycle::STATE_KEY_BYTES, &self.state);
            let self_id = lifecycle::service_id();
            hostcalls::transfer(ServiceId(self_id), 0, 0, &[]);
        }
    }

    /// Encode to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(REFINE_PAYLOAD_VERSION);
        let mut flags: u8 = 0;
        if self.continue_next { flags |= FLAG_CONTINUE_NEXT; }
        out.push(flags);
        push_u32(&mut out, self.state.len() as u32);
        out.extend_from_slice(&self.state);
        push_u32(&mut out, self.reply.len() as u32);
        out.extend_from_slice(&self.reply);
        push_u16(&mut out, self.effects.len() as u16);
        for eff in &self.effects {
            encode_effect(&mut out, eff);
        }
        out
    }

    /// Decode from the wire format. Returns `None` on malformed input.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let version = c.read_u8()?;
        if version != REFINE_PAYLOAD_VERSION {
            return None;
        }
        let flags = c.read_u8()?;
        let continue_next = flags & FLAG_CONTINUE_NEXT != 0;
        let state_len = c.read_u32()? as usize;
        let state = c.read_bytes(state_len)?.to_vec();
        let reply_len = c.read_u32()? as usize;
        let reply = c.read_bytes(reply_len)?.to_vec();
        let effects_count = c.read_u16()? as usize;
        let mut effects = Vec::with_capacity(effects_count);
        for _ in 0..effects_count {
            effects.push(decode_effect(&mut c)?);
        }
        Some(RefinePayload { state, reply, effects, continue_next })
    }
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

fn decode_effect(c: &mut Cursor<'_>) -> Option<Effect> {
    let tag = c.read_u8()?;
    let payload_len = c.read_u32()? as usize;
    let payload = c.read_bytes(payload_len)?;
    let mut pc = Cursor::new(payload);
    match tag {
        EFFECT_WRITE => {
            let key_len = pc.read_u16()? as usize;
            let key = pc.read_bytes(key_len)?.to_vec();
            let value_len = pc.read_u32()? as usize;
            let value = pc.read_bytes(value_len)?.to_vec();
            Some(Effect::Write { key, value })
        }
        EFFECT_TRANSFER => {
            let target = pc.read_u32()?;
            let memo = pc.remaining().to_vec();
            Some(Effect::Transfer { target, memo })
        }
        EFFECT_PROVIDE => {
            let mut hash = [0u8; 32];
            let h = pc.read_bytes(32)?;
            hash.copy_from_slice(h);
            let data = pc.remaining().to_vec();
            Some(Effect::Provide { hash, data })
        }
        EFFECT_NEW => {
            let mut code_hash = [0u8; 32];
            let h = pc.read_bytes(32)?;
            code_hash.copy_from_slice(h);
            Some(Effect::New { code_hash })
        }
        _ => None,
    }
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
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_empty() {
        let p = RefinePayload::new();
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn roundtrip_state_and_reply() {
        let p = RefinePayload {
            state: vec![1, 2, 3, 4],
            reply: vec![0xAA, 0xBB],
            effects: vec![],
            continue_next: true,
        };
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn roundtrip_all_effects() {
        let p = RefinePayload {
            state: vec![],
            reply: vec![],
            effects: vec![
                Effect::Write { key: b"k1".to_vec(), value: vec![1, 2, 3] },
                Effect::Transfer { target: 42, memo: b"hello".to_vec() },
                Effect::Provide { hash: [9; 32], data: vec![0xFF, 0xEE] },
                Effect::New { code_hash: [7; 32] },
            ],
            continue_next: false,
        };
        let bytes = p.encode();
        let decoded = RefinePayload::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = RefinePayload::new().encode();
        bytes[0] = 0xFF;
        assert!(RefinePayload::decode(&bytes).is_none());
    }

    #[test]
    fn rejects_truncated() {
        let bytes = RefinePayload {
            state: vec![1, 2, 3],
            reply: vec![],
            effects: vec![],
            continue_next: false,
        }
        .encode();
        // Lop off the last state byte
        assert!(RefinePayload::decode(&bytes[..bytes.len() - 1]).is_none());
    }
}
