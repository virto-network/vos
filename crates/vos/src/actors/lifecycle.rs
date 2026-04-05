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
use super::{Actor, Context, run::RunResult, codec::Decode};
#[cfg(feature = "pvm")]
use alloc::vec::Vec;

/// Buffer size for hostcall data exchange.
#[cfg(feature = "pvm")]
pub(crate) const BUF_SIZE: usize = 4096;

/// Storage key for persisted actor state.
#[cfg(feature = "service")]
const STATE_KEY: &[u8] = b"__vos_actor_state";

/// Storage key for the yield replay index.
#[cfg(feature = "service")]
const YIELD_INDEX_KEY: &[u8] = b"__vos_yield_index";

/// Result of dispatching a single message.
pub enum DispatchResult {
    /// Message processed, continue with next.
    Continue,
    /// Handler yielded (wants re-invocation).
    Yielded,
    /// Handler requested stop.
    Stopped,
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

/// Persist actor state and yield index.
///
/// Returns `(state_bytes, yield_index)` for the caller to use (e.g. in
/// refine output packing). On services, also writes to storage as a
/// side effect — the caller doesn't need to know.
#[cfg(feature = "pvm")]
pub fn save_state<A: Actor>(
    actor: &A,
    ctx: &Context<A>,
    initial_state: &[u8],
) -> (Vec<u8>, u32) {
    let (state, yi) = if ctx.self_scheduled() && !ctx.should_continue_as_new() {
        // Yielded — save initial state snapshot for replay
        (initial_state.to_vec(), ctx.yield_index())
    } else {
        // Done — save current (mutated) state
        (actor.encode(), 0u32)
    };

    #[cfg(feature = "service")]
    {
        use vos_abi::pvm::hostcalls;
        hostcalls::write(STATE_KEY, &state);
        hostcalls::write(YIELD_INDEX_KEY, &yi.to_le_bytes());
    }

    (state, yi)
}

// ── I/O helpers ───────────────────────────────────────────────────

/// Get the current service ID.
#[cfg(feature = "service")]
pub fn service_id() -> u32 {
    vos_abi::pvm::hostcalls::info() as u32
}

/// Read persisted state and yield index from service storage.
/// Returns `(state_bytes_len, yield_index)`.
#[cfg(feature = "service")]
pub fn read_persisted_state(state_buf: &mut [u8]) -> (usize, u32) {
    use vos_abi::pvm::hostcalls;

    let state_read = hostcalls::read(STATE_KEY, state_buf);
    let state_len = if state_read > 0 && state_read < state_buf.len() as u64 {
        state_read as usize
    } else {
        0
    };

    let mut yi_buf = [0u8; 4];
    let yi_read = hostcalls::read(YIELD_INDEX_KEY, &mut yi_buf);
    let yield_index = if yi_read == 4 {
        u32::from_le_bytes(yi_buf)
    } else {
        0
    };

    (state_len, yield_index)
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
    let msg = A::Message::decode(raw);
    match actor.dispatch(msg, ctx) {
        RunResult::Yielded => {
            ctx.flush_effects();
            return DispatchResult::Yielded;
        }
        RunResult::Complete(stop) => {
            ctx.flush_effects();
            if stop {
                return DispatchResult::Stopped;
            }
        }
    }

    // Ask resolution loop: invoke target, cache result, replay handler
    while let Some(pending) = ctx.take_pending_ask() {
        let mut invoke_buf = [0u8; BUF_SIZE];
        let result_len = vos_abi::pvm::hostcalls::invoke(
            &super::run::service_code_hash(pending.target.0),
            &pending.payload,
            0,
            &mut invoke_buf,
        );
        let result = if result_len > 0 && result_len < BUF_SIZE as u64 {
            invoke_buf[..result_len as usize].to_vec()
        } else {
            Vec::new()
        };
        ctx.push_call_result_and_reset(result);

        let msg = A::Message::decode(raw);
        match actor.dispatch(msg, ctx) {
            RunResult::Yielded => {
                ctx.flush_effects();
                return DispatchResult::Yielded;
            }
            RunResult::Complete(stop) => {
                ctx.flush_effects();
                if stop {
                    return DispatchResult::Stopped;
                }
            }
        }
    }

    DispatchResult::Continue
}
