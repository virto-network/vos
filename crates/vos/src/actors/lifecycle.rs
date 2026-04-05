//! Lifecycle building blocks for VOS actors.
//!
//! Composable functions that implement the JAM actor lifecycle.
//! Used by the default `run_accumulate` and `run_refine` implementations,
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

/// Storage key for persisted actor state.
#[cfg(feature = "service")]
const STATE_KEY: &[u8] = b"__vos_actor_state";

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
/// Always saves the current (mutated) state — no replay needed across
/// invocations. On services, also writes to storage as a side effect.
/// Returns the serialized state bytes.
#[cfg(feature = "pvm")]
pub fn save_state<A: Actor>(
    actor: &A,
    ctx: &Context<A>,
) -> Vec<u8> {
    let state = if ctx.self_scheduled() {
        // Yielded — save current state for next invocation
        actor.encode()
    } else {
        // Done — save current state
        actor.encode()
    };

    #[cfg(feature = "service")]
    {
        use vos_abi::pvm::hostcalls;
        hostcalls::write(STATE_KEY, &state);
    }

    state
}

// ── I/O helpers ───────────────────────────────────────────────────

/// Get the current service ID.
#[cfg(feature = "service")]
pub fn service_id() -> u32 {
    vos_abi::pvm::hostcalls::info() as u32
}

/// Read persisted state from service storage.
/// Returns the number of state bytes read.
#[cfg(feature = "service")]
pub fn read_persisted_state(state_buf: &mut [u8]) -> usize {
    use vos_abi::pvm::hostcalls;

    let state_read = hostcalls::read(STATE_KEY, state_buf);
    if state_read > 0 && state_read < state_buf.len() as u64 {
        state_read as usize
    } else {
        0
    }
}

/// Fetch the next raw message from the transfer queue.
/// Returns the number of bytes, or 0 if no more messages.
#[cfg(feature = "pvm")]
pub fn fetch_raw(buf: &mut [u8]) -> usize {
    use vos_abi::pvm::ecall;
    let n = ecall::ecall2(vos_abi::hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
    if n > 0 && n < buf.len() as u64 { n as usize } else { 0 }
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
    vos_abi::pvm::hostcalls::yield_output(&exit_status::<A>(ctx));
}

// ── Storage ───────────────────────────────────────────────────────

/// Read a raw value from per-service storage.
/// Returns the number of bytes read, or 0 if key not found.
#[cfg(feature = "service")]
pub fn read_storage(key: &[u8], buf: &mut [u8]) -> usize {
    let n = vos_abi::pvm::hostcalls::read(key, buf);
    if n > 0 && n < buf.len() as u64 { n as usize } else { 0 }
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
pub struct InvokeResult {
    pub status: u8,
    pub state: Vec<u8>,
    pub reply: Vec<u8>,
}

/// Invoke a child actor via the refine protocol.
///
/// Packs the invoke input `[state_len:4][state][message]`,
/// calls the invoke hostcall, and unpacks the output.
#[cfg(feature = "pvm")]
pub fn invoke(
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
    let n = vos_abi::pvm::hostcalls::invoke(&hash, &input, 0, &mut output) as usize;

    if n < 5 {
        return InvokeResult { status: 0, state: Vec::new(), reply: Vec::new() };
    }

    let state_len = u32::from_le_bytes([output[1], output[2], output[3], output[4]]) as usize;
    let state_end = (5 + state_len).min(n);
    InvokeResult {
        status: output[0],
        state: if state_len > 0 && state_end <= n {
            output[5..state_end].to_vec()
        } else {
            Vec::new()
        },
        reply: if state_end < n {
            output[state_end..n].to_vec()
        } else {
            Vec::new()
        },
    }
}

// ── Message dispatch ──────────────────────────────────────────────

/// Dispatch a single message to the actor, with ask resolution.
///
/// Decodes raw bytes to `A::Message`, calls `actor.dispatch()`.
/// If the handler calls `ask()`, resolves it via `invoke()` and replays.
#[cfg(feature = "pvm")]
pub fn dispatch_one<A: Actor>(
    raw: &[u8],
    actor: &mut A,
    ctx: &mut Context<A>,
) -> DispatchResult {
    // Decode message: if first byte is TAG_DYNAMIC, decode as dynamic Msg → FromDynamic;
    // otherwise decode as typed A::Message directly.
    let decode_msg = |raw: &[u8]| -> Option<A::Message> {
        if !raw.is_empty() && raw[0] == TAG_DYNAMIC {
            let dynamic: super::value::Msg = Decode::decode(&raw[1..]);
            A::Message::from_dynamic(&dynamic)
        } else {
            Some(A::Message::decode(raw))
        }
    };

    // Snapshot actor state before dispatch. If ask-replay is needed,
    // we restore the snapshot so mutations don't accumulate across replays.
    let snapshot = actor.encode();

    // Dispatch + ask resolution loop.
    // When the handler awaits `ask()`, it yields Pending with a pending_ask set.
    // We resolve the ask, push the result, restore state, and replay. This
    // repeats until the handler either completes or yields for a real reason.
    loop {
        let msg = match decode_msg(raw) {
            Some(m) => m,
            None => return DispatchResult::Skipped,
        };
        match actor.dispatch(msg, ctx) {
            RunResult::Yielded => {
                // Check if this yield was caused by an ask() suspension
                if let Some(pending) = ctx.take_pending_ask() {
                    let r = invoke(pending.target.0, &pending.payload, &[]);
                    ctx.push_call_result_and_reset(r.reply);
                    // Restore actor state to pre-dispatch snapshot
                    *actor = A::decode(&snapshot);
                    continue; // replay handler with cached result
                }
                // Real yield (yield_now / sleep)
                ctx.flush_effects();
                return DispatchResult::Yielded;
            }
            RunResult::Complete(stop) => {
                ctx.flush_effects();
                return if stop { DispatchResult::Stopped } else { DispatchResult::Continue };
            }
        }
    }
}
