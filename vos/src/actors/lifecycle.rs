//! Lifecycle building blocks for VOS actors.
//!
//! Composable functions that implement the JAM actor lifecycle.
//! Used by the default `run_refine_service` and `run_refine` implementations,
//! and exported for custom lifecycle composition.
//!
//! Persistence methods are feature-gated internally: on services they
//! write to storage as a side effect, on invoked actors they just return
//! the data for the caller to handle. Higher-level code uses the same API
//! regardless.

#[cfg(feature = "pvm")]
use super::{
    Actor, Context,
    codec::Decode,
    run::RunResult,
    value::{FromDynamic, TAG_DYNAMIC},
};
#[cfg(feature = "pvm")]
use alloc::vec::Vec;

/// Buffer size for guest hostcall data exchange — the fixed buffer the actor
/// dispatch loop reads each queued FETCH item into. A host that enqueues an
/// item larger than this cannot deliver it (the guest's `fetch_raw` reports
/// truncation and drops it; see `node::send_if_deliverable`), so this is shared
/// host/guest ABI rather than gated to the guest (`pvm`) build.
pub(crate) const BUF_SIZE: usize = 4096;

/// Well-known storage key for actor constructor arguments.
/// The host writes rkyv-encoded init args here before first run.
pub const INIT_KEY: &[u8] = b"__vos_init";

/// Per-service storage key under which the runtime records a
/// suspended PVM's `ContinuationHeader`. Written by the host runtime
/// (`save_continuation`) into the tick's journal when refine sets
/// `continue_next = true`; read at the start of the next tick to
/// warm-restart the kernel.
///
/// The leading NUL keeps this key disjoint from any guest-chosen
/// key: guest keys originate from `Encode`d Rust types whose rkyv
/// prefixes never begin with `\0`.
pub const CONTINUATION_HEADER_KEY: &[u8] = b"\0__vos_cont";

/// Storage key for persisted actor state.
#[cfg(feature = "service")]
const STATE_KEY: &[u8] = b"__vos_actor_state";

/// Public alias of `STATE_KEY` so the refine framework and host code can
/// reference it without re-declaring the constant. Always available — even
/// without the `service` feature — so non-service callers can interpret
/// refine output payloads.
pub const STATE_KEY_BYTES: &[u8] = b"__vos_actor_state";

/// Result of dispatching a single message.
pub enum DispatchResult {
    /// Message processed, continue with next.
    Continue,
    /// Handler yielded (wants re-invocation).
    Yielded,
    /// Handler requested stop.
    Stopped,
    /// Dynamic message didn't match any handler — safely ignored.
    Skipped,
}

// ── State lifecycle ───────────────────────────────────────────────

/// Deserialize an actor from state bytes, or create a fresh instance.
///
/// This is the first step of any actor lifecycle — both services and
/// invoked actors use it. The caller provides state bytes from wherever
/// they came (storage, input protocol, etc.).
///
/// Uses validating `try_decode` so a hand-corrupted, truncated, or
/// schema-drifted persisted blob falls back to `A::create()` instead
/// of decoding silently to garbage. The probe in
/// `crdt_counter_survives_corrupted_persisted_state` exercises this.
#[cfg(feature = "pvm")]
pub fn load_or_create<A: Actor>(state: Option<&[u8]>) -> A {
    match state {
        Some(bytes) if !bytes.is_empty() => A::try_decode(bytes).unwrap_or_else(A::create),
        _ => A::create(),
    }
}

/// Persist actor state.
///
/// Serializes the current (mutated) actor state. On service builds,
/// also writes it to storage via hostcall. Returns the serialized bytes.
#[cfg(feature = "pvm")]
pub fn save_state<A: Actor>(actor: &A, _ctx: &Context<A>) -> Vec<u8> {
    let state = actor.encode();

    #[cfg(feature = "service")]
    {
        use crate::abi::pvm::hostcalls;
        hostcalls::write(STATE_KEY, &state);
    }

    state
}

// ── I/O helpers ───────────────────────────────────────────────────

/// Get the current service ID.
#[cfg(feature = "service")]
pub fn service_id() -> u32 {
    crate::abi::pvm::hostcalls::info() as u32
}

/// Read persisted state from service storage.
/// Returns the number of state bytes read.
#[cfg(feature = "service")]
pub fn read_persisted_state(state_buf: &mut [u8]) -> usize {
    use crate::abi::pvm::hostcalls;

    let state_read = hostcalls::read(STATE_KEY, state_buf);
    // See `fetch_raw` for why this is `<=`, not `<`.
    if state_read > 0 && state_read <= state_buf.len() as u64 {
        state_read as usize
    } else {
        0
    }
}

/// Read persisted state, growing onto the heap when it exceeds the
/// stack probe buffer. The READ hostcall copies `min(len, buf)` and
/// returns the FULL value length, so one retry with an exact-size
/// buffer always lands it.
///
/// This is the cold-start state loader. The fixed-buffer variant
/// above treats a too-long value as missing — correct for callers
/// with a hard cap, but fatal as a state loader: an actor whose
/// serialized state outgrows the buffer would silently resurrect as
/// `A::create()` and persist that wipe on its next save.
#[cfg(feature = "service")]
pub fn read_persisted_state_owned() -> Option<alloc::vec::Vec<u8>> {
    use crate::abi::error::HOST_NONE;
    use crate::abi::pvm::hostcalls;

    let mut probe = [0u8; BUF_SIZE];
    let n = hostcalls::read(STATE_KEY, &mut probe);
    if n == 0 || n == HOST_NONE {
        return None;
    }
    if n <= BUF_SIZE as u64 {
        return Some(probe[..n as usize].to_vec());
    }
    let mut full = alloc::vec![0u8; n as usize];
    let m = hostcalls::read(STATE_KEY, &mut full);
    // A different length on the re-read means the value changed
    // under us — impossible within one dispatch, so treat it as
    // corruption and let the caller fall back to a fresh actor.
    (m == n).then_some(full)
}

/// Fetch the next raw message from the transfer queue.
/// Returns the number of bytes, or 0 if no more messages.
#[cfg(feature = "pvm")]
pub fn fetch_raw(buf: &mut [u8]) -> usize {
    use crate::abi::pvm::ecall;
    let n = ecall::ecall2(
        crate::abi::hostcall::FETCH,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    );
    // The host returns the *full* value length, so n > buf.len()
    // signals the value was truncated to fit our buffer — treat
    // as missing rather than decode garbage. n == buf.len() is a
    // legitimate exact fit.
    if n > 0 && n <= buf.len() as u64 {
        n as usize
    } else {
        0
    }
}

/// Build exit status bytes from context state.
#[cfg(feature = "pvm")]
pub fn exit_status<A: Actor>(ctx: &Context<A>) -> Vec<u8> {
    use super::run::{STATUS_DONE, STATUS_FORBIDDEN, STATUS_YIELDED};
    // M6 — the macro-emitted role check flagged this dispatch
    // as refused. `STATUS_FORBIDDEN` propagates through the wire
    // envelope so vosx surfaces "permission denied" without any
    // handler-body side effects.
    if ctx.was_forbidden() {
        return alloc::vec![STATUS_FORBIDDEN];
    }
    if ctx.self_scheduled() {
        alloc::vec![STATUS_YIELDED]
    } else {
        alloc::vec![STATUS_DONE]
    }
}

/// Emit exit status via YIELD hostcall.
#[cfg(feature = "service")]
pub fn emit_status<A: Actor>(ctx: &Context<A>) {
    crate::abi::pvm::hostcalls::yield_output(&exit_status::<A>(ctx));
}

// ── Storage ───────────────────────────────────────────────────────

/// Read a raw value from per-service storage.
/// Returns the number of bytes read, or 0 if key not found.
#[cfg(feature = "service")]
pub fn read_storage(key: &[u8], buf: &mut [u8]) -> usize {
    let n = crate::abi::pvm::hostcalls::read(key, buf);
    // See `fetch_raw` for why this is `<=`, not `<`.
    if n > 0 && n <= buf.len() as u64 {
        n as usize
    } else {
        0
    }
}

/// Read and decode a typed value from per-service storage.
#[cfg(feature = "service")]
pub fn load<T: super::codec::Decode>(key: &[u8]) -> Option<T> {
    let mut buf = [0u8; BUF_SIZE];
    let n = read_storage(key, &mut buf);
    if n > 0 {
        Some(T::decode(&buf[..n]))
    } else {
        None
    }
}

// ── Invoke ────────────────────────────────────────────────────────

/// Result of invoking a child actor.
#[cfg(feature = "pvm")]
pub enum InvokeResult {
    /// Actor completed normally.
    Done { state: Vec<u8>, reply: Vec<u8> },
    /// Actor yielded (wants re-invocation).
    Yielded { state: Vec<u8>, reply: Vec<u8> },
    /// Actor panicked.
    Panicked,
    /// Target service not found.
    NotFound,
    /// Actor ran out of gas.
    OutOfGas,
    /// Child's reply exceeded the caller's output buffer.
    TooBig,
    /// Unknown error status byte.
    Error(u8),
}

/// Invoke a child actor with a dynamic message.
///
/// Encodes the `Msg` with the wire tag and delegates to `invoke_raw`.
/// This is the preferred API for agents — no need to handle TAG_DYNAMIC manually.
#[cfg(feature = "pvm")]
pub fn invoke(service_id: u32, message: &super::value::Msg, state: &[u8]) -> InvokeResult {
    let encoded = super::codec::Encode::encode(message);
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(super::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    invoke_raw(service_id, &payload, state)
}

/// Invoke a child actor with pre-encoded message bytes.
///
/// Packs the invoke input `[state_len:4][state][message]`,
/// calls the invoke hostcall, and unpacks the output.
#[cfg(feature = "pvm")]
pub fn invoke_raw(service_id: u32, message: &[u8], state: &[u8]) -> InvokeResult {
    invoke_hash(&super::run::service_code_hash(service_id), message, state)
}

/// Invoke a child by its full 32-byte code hash — the Task shape
/// (`vos::agent::Child::Task`): the host runs the content-addressed
/// blob witness-delivered, with no ServiceId and no storage row.
/// Same input packing and output envelope as [`invoke_raw`].
#[cfg(feature = "pvm")]
pub fn invoke_hash(code_hash: &[u8; 32], message: &[u8], state: &[u8]) -> InvokeResult {
    let total = 4 + state.len() + message.len();
    let mut input = alloc::vec![0u8; total];
    input[0..4].copy_from_slice(&(state.len() as u32).to_le_bytes());
    input[4..4 + state.len()].copy_from_slice(state);
    input[4 + state.len()..].copy_from_slice(message);

    let hash = *code_hash;
    // Reply buffer. Kept on the stack at BUF_SIZE: heap-allocating a
    // larger one corrupts the guest heap of actors that already use most
    // of the fixed 256 KiB arena (the clerk ledger), and GROW_HEAP is a
    // host no-op, so the reply ceiling cannot be raised without first
    // growing the guest heap. A reply past BUF_SIZE still surfaces as
    // STATUS_TOO_BIG (below) rather than a truncated crash.
    let mut output = [0u8; BUF_SIZE];
    let n = crate::abi::pvm::hostcalls::invoke(&hash, &input, 0, &mut output) as usize;

    use super::run::{
        STATUS_DONE, STATUS_NOT_FOUND, STATUS_OOG, STATUS_PANICKED, STATUS_TOO_BIG, STATUS_YIELDED,
    };

    // Short output = error status byte only (no state/reply envelope)
    if n < 5 {
        if n >= 1 {
            return match output[0] {
                STATUS_PANICKED => InvokeResult::Panicked,
                STATUS_NOT_FOUND => InvokeResult::NotFound,
                STATUS_OOG => InvokeResult::OutOfGas,
                STATUS_TOO_BIG => InvokeResult::TooBig,
                STATUS_DONE => InvokeResult::Done {
                    state: Vec::new(),
                    reply: Vec::new(),
                },
                STATUS_YIELDED => InvokeResult::Yielded {
                    state: Vec::new(),
                    reply: Vec::new(),
                },
                other => InvokeResult::Error(other),
            };
        }
        return InvokeResult::Done {
            state: Vec::new(),
            reply: Vec::new(),
        };
    }

    let state_len = u32::from_le_bytes([output[1], output[2], output[3], output[4]]) as usize;
    let state_end = (5 + state_len).min(n);
    let state = if state_len > 0 && state_end <= n {
        output[5..state_end].to_vec()
    } else {
        Vec::new()
    };
    let reply = if state_end < n {
        output[state_end..n].to_vec()
    } else {
        Vec::new()
    };

    match output[0] {
        STATUS_YIELDED => InvokeResult::Yielded { state, reply },
        STATUS_PANICKED => InvokeResult::Panicked,
        STATUS_NOT_FOUND => InvokeResult::NotFound,
        STATUS_OOG => InvokeResult::OutOfGas,
        _ => InvokeResult::Done { state, reply },
    }
}

// ── Message dispatch ──────────────────────────────────────────────

/// Wire-marker the host prepends to dispatch messages so the
/// PVM agent can populate `Context::caller` + the role bytes
/// before each handler runs. Layout:
///
///   raw[0] = TAG_CALLER_PREFIX (0xFE)
///   raw[1] = trust_flag (0 = external, 1 = trusted-bypass)
///   raw[2] = has_space_role (0 / 1)
///   raw[3] = space_role byte (only meaningful if has_space_role)
///   raw[4] = has_actor_local_role (0 / 1)
///   raw[5] = actor_local_role byte
///   raw[6..] = the original message (TAG_DYNAMIC / typed bytes)
///
/// Hosts that don't know about this prefix (and the legacy
/// dispatch path that doesn't need role info) send `raw` without
/// the header — `dispatch_one` then leaves Context::caller at
/// its previous value.
pub const TAG_CALLER_PREFIX: u8 = 0xFE;

/// Dispatch a single message to the actor.
///
/// Decodes raw bytes to `A::Message` and calls `actor.dispatch()` once.
/// `ctx.ask()` resolves synchronously inside the handler via the
/// `INVOKE` hostcall, so there is no ask-replay loop and no actor
/// snapshot — a `Yielded` result here always means a real
/// `yield_now` / `sleep` commit, not an in-flight query.
#[cfg(feature = "pvm")]
pub fn dispatch_one<A: Actor>(raw: &[u8], actor: &mut A, ctx: &mut Context<A>) -> DispatchResult {
    // Reset the per-invocation forbidden flag so a prior refused
    // call doesn't poison this dispatch. Context lives across
    // invocations on the warm-restart path.
    ctx.__reset_forbidden();

    // Strip the M7 caller-info prefix if present. The host
    // packs the caller's role bytes here so the macro-emitted
    // role check can run without an extra hostcall.
    let raw = if raw.len() >= 6 && raw[0] == TAG_CALLER_PREFIX {
        use super::auth::Caller;
        let trust_flag = raw[1];
        let has_space = raw[2] != 0;
        let space_byte = raw[3];
        let has_actor_local = raw[4] != 0;
        let actor_local_byte = raw[5];
        ctx.set_caller(if trust_flag == 1 {
            Caller::System
        } else {
            Caller::Unauthenticated
        });
        ctx.set_caller_roles(
            if has_space { Some(space_byte) } else { None },
            if has_actor_local {
                Some(actor_local_byte)
            } else {
                None
            },
        );
        &raw[6..]
    } else {
        raw
    };

    // Decode message: if first byte is TAG_DYNAMIC, decode as dynamic Msg → FromDynamic;
    // otherwise decode as typed A::Message directly.
    let msg = if !raw.is_empty() && raw[0] == TAG_DYNAMIC {
        let dynamic: super::value::Msg = Decode::decode(&raw[1..]);
        match A::Message::from_dynamic(&dynamic) {
            Some(m) => m,
            None => return DispatchResult::Skipped,
        }
    } else {
        A::Message::decode(raw)
    };

    match actor.dispatch(msg, ctx) {
        RunResult::Yielded => {
            ctx.flush_effects();
            DispatchResult::Yielded
        }
        RunResult::Complete(stop) => {
            ctx.flush_effects();
            if stop {
                DispatchResult::Stopped
            } else {
                DispatchResult::Continue
            }
        }
    }
}
