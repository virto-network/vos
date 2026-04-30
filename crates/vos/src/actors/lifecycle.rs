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
use super::{Actor, Context, run::RunResult, codec::Decode, value::{TAG_DYNAMIC, FromDynamic}};
#[cfg(feature = "pvm")]
use alloc::vec::Vec;

/// Buffer size for hostcall data exchange.
#[cfg(feature = "pvm")]
pub(crate) const BUF_SIZE: usize = 4096;

/// Well-known storage key for actor constructor arguments.
/// The host writes rkyv-encoded init args here before first run.
pub const INIT_KEY: &[u8] = b"__vos_init";

/// Per-service storage key under which the runtime records a
/// suspended PVM's `ContinuationHeader`. Written by the framework's
/// `run_accumulate_service` via a real `WRITE` hostcall when refine
/// set `continue_next = true`; read by the runtime at the start of
/// the next tick to rehydrate.
///
/// The leading NUL keeps this key disjoint from any guest-chosen
/// key: guest keys originate from `Encode`d Rust types whose rkyv
/// prefixes never begin with `\0`.
pub const CONTINUATION_HEADER_KEY: &[u8] = b"\0__vos_cont";

/// Storage key for persisted actor state.
#[cfg(feature = "service")]
const STATE_KEY: &[u8] = b"__vos_actor_state";

/// Public alias of `STATE_KEY` so the refine/accumulate framework code can
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
#[cfg(feature = "pvm")]
pub fn load_or_create<A: Actor>(state: Option<&[u8]>) -> A {
    match state {
        Some(bytes) if !bytes.is_empty() => A::decode(bytes),
        _ => A::create(),
    }
}

/// Persist actor state.
///
/// Serializes the current (mutated) actor state. On service builds,
/// also writes it to storage via hostcall. Returns the serialized bytes.
#[cfg(feature = "pvm")]
pub fn save_state<A: Actor>(
    actor: &A,
    _ctx: &Context<A>,
) -> Vec<u8> {
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

/// Fetch the next raw message from the transfer queue.
/// Returns the number of bytes, or 0 if no more messages.
#[cfg(feature = "pvm")]
pub fn fetch_raw(buf: &mut [u8]) -> usize {
    use crate::abi::pvm::ecall;
    let n = ecall::ecall2(crate::abi::hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
    // The host returns the *full* value length, so n > buf.len()
    // signals the value was truncated to fit our buffer — treat
    // as missing rather than decode garbage. n == buf.len() is a
    // legitimate exact fit.
    if n > 0 && n <= buf.len() as u64 { n as usize } else { 0 }
}

/// Build exit status bytes from context state.
#[cfg(feature = "pvm")]
pub fn exit_status<A: Actor>(ctx: &Context<A>) -> Vec<u8> {
    use super::run::{STATUS_DONE, STATUS_YIELDED};
    if ctx.self_scheduled() {
        let ticks = ctx.sleep_ticks();
        if ticks > 0 {
            let mut s = alloc::vec![STATUS_YIELDED];
            s.extend_from_slice(&ticks.to_le_bytes());
            s
        } else {
            alloc::vec![STATUS_YIELDED]
        }
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
    if n > 0 && n <= buf.len() as u64 { n as usize } else { 0 }
}

/// Read and decode a typed value from per-service storage.
#[cfg(feature = "service")]
pub fn load<T: super::codec::Decode>(key: &[u8]) -> Option<T> {
    let mut buf = [0u8; BUF_SIZE];
    let n = read_storage(key, &mut buf);
    if n > 0 { Some(T::decode(&buf[..n])) } else { None }
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
    /// Unknown error status byte.
    Error(u8),
}

/// Invoke a child actor with a dynamic message.
///
/// Encodes the `Msg` with the wire tag and delegates to `invoke_raw`.
/// This is the preferred API for agents — no need to handle TAG_DYNAMIC manually.
#[cfg(feature = "pvm")]
pub fn invoke(
    service_id: u32,
    message: &super::value::Msg,
    state: &[u8],
) -> InvokeResult {
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
pub fn invoke_raw(
    service_id: u32,
    message: &[u8],
    state: &[u8],
) -> InvokeResult {
    let total = 4 + state.len() + message.len();
    let mut input = alloc::vec![0u8; total];
    input[0..4].copy_from_slice(&(state.len() as u32).to_le_bytes());
    input[4..4 + state.len()].copy_from_slice(state);
    input[4 + state.len()..].copy_from_slice(message);

    let hash = super::run::service_code_hash(service_id);
    let mut output = [0u8; BUF_SIZE];
    let n = crate::abi::pvm::hostcalls::invoke(&hash, &input, 0, &mut output) as usize;

    use super::run::{STATUS_DONE, STATUS_YIELDED, STATUS_PANICKED, STATUS_NOT_FOUND, STATUS_OOG};

    // Short output = error status byte only (no state/reply envelope)
    if n < 5 {
        if n >= 1 {
            return match output[0] {
                STATUS_PANICKED => InvokeResult::Panicked,
                STATUS_NOT_FOUND => InvokeResult::NotFound,
                STATUS_OOG => InvokeResult::OutOfGas,
                STATUS_DONE => InvokeResult::Done { state: Vec::new(), reply: Vec::new() },
                STATUS_YIELDED => InvokeResult::Yielded { state: Vec::new(), reply: Vec::new() },
                other => InvokeResult::Error(other),
            };
        }
        return InvokeResult::Done { state: Vec::new(), reply: Vec::new() };
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

/// Dispatch a single message to the actor.
///
/// Decodes raw bytes to `A::Message` and calls `actor.dispatch()` once.
/// `ctx.ask()` resolves synchronously inside the handler via the
/// `INVOKE` hostcall, so there is no ask-replay loop and no actor
/// snapshot — a `Yielded` result here always means a real
/// `yield_now` / `sleep` commit, not an in-flight query.
#[cfg(feature = "pvm")]
pub fn dispatch_one<A: Actor>(
    raw: &[u8],
    actor: &mut A,
    ctx: &mut Context<A>,
) -> DispatchResult {
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
            if stop { DispatchResult::Stopped } else { DispatchResult::Continue }
        }
    }
}
