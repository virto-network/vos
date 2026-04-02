//! Cooperative single-threaded executor for VOS actor programs.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn noop_raw_waker() -> RawWaker {
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

/// Result of a single poll: either the future completed or it yielded.
pub enum RunResult<T> {
    Complete(T),
    Yielded,
}

/// Poll a future exactly once. Returns `Complete(val)` if ready, `Yielded` if pending.
pub fn try_poll<F: Future>(mut fut: F) -> RunResult<F::Output> {
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => RunResult::Complete(val),
        Poll::Pending => RunResult::Yielded,
    }
}

/// A future that yields once then completes.
pub struct Yield {
    yielded: bool,
}

impl Yield {
    /// Returns Pending once, then Ready — real suspension.
    pub fn once() -> Self {
        Self { yielded: false }
    }
    /// Returns Ready immediately — used during replay to fast-forward past
    /// yield points that already executed in a previous invocation.
    pub fn skip() -> Self {
        Self { yielded: true }
    }
}

impl Future for Yield {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.yielded {
            Poll::Ready(())
        } else {
            this.yielded = true;
            Poll::Pending
        }
    }
}

/// Halt the PVM (no output). Used by main_loop (service mode).
#[cfg(all(feature = "service", target_arch = "riscv64"))]
fn halt() -> ! {
    unsafe {
        core::arch::asm!(
            "lui t1, 0x10",       // t1 = 0x10000
            "addi t1, t1, -1",    // t1 = 0xFFFF
            "slli t1, t1, 16",    // t1 = 0xFFFF0000
            "jalr x0, t1, 0",    // djump → halt
            options(noreturn),
        );
    }
}

/// Halt with output data in registers a0 (ptr) and a1 (len).
/// The invoke() host handler reads these to copy output to the caller.
#[cfg(target_arch = "riscv64")]
fn halt_with_output(data: &[u8]) -> ! {
    unsafe {
        core::arch::asm!(
            "lui t1, 0x10",
            "addi t1, t1, -1",
            "slli t1, t1, 16",
            "jalr x0, t1, 0",
            in("a0") data.as_ptr() as u64,
            in("a1") data.len() as u64,
            options(noreturn),
        );
    }
}

#[cfg(all(feature = "service", not(target_arch = "riscv64")))]
fn halt() -> ! {
    panic!("halt is only supported on RISC-V targets");
}

#[cfg(all(feature = "pvm", not(target_arch = "riscv64")))]
fn halt_with_output(_data: &[u8]) -> ! {
    panic!("halt_with_output is only supported on RISC-V targets");
}

/// Buffer size for hostcall data exchange.
#[cfg(feature = "pvm")]
const BUF_SIZE: usize = 4096;

/// Storage key for persisted actor state (service mode only).
#[cfg(feature = "service")]
const STATE_KEY: &[u8] = b"__vos_actor_state";

/// Storage key for the yield replay index (service mode only).
#[cfg(feature = "service")]
const YIELD_INDEX_KEY: &[u8] = b"__vos_yield_index";

/// Exit status: actor processed all messages normally.
pub const STATUS_DONE: u8 = 0x00;
/// Exit status: actor handler yielded (wants re-invocation).
pub const STATUS_YIELDED: u8 = 0x01;

/// Service actor lifecycle — JAR-aligned fresh-PVM model (accumulate phase).
///
/// Each invocation:
/// 1. Try loading existing state from storage via `read(STATE_KEY)`
/// 2. If no state, construct fresh actor (from init payload if needed)
/// 3. Process all pending items (transfers delivered via `fetch()`)
/// 4. Flush effects after each handler
/// 5. Persist state via `write()`, output exit status via YIELD, halt
///
/// Requires the `service` feature — uses accumulate-phase hostcalls
/// (READ, WRITE, YIELD, INFO) that are not available to refine-only actors.
#[cfg(feature = "service")]
pub fn main_loop<A: super::Actor>(
    needs_init_payload: bool,
    init: impl FnOnce(Option<&[u8]>) -> A,
    dispatch: impl Fn(&[u8], &mut A, &mut super::Context<A>) -> RunResult<bool>,
    save: impl Fn(&A) -> alloc::vec::Vec<u8>,
    load: impl Fn(&[u8]) -> A,
) {
    use vos_abi::pvm::hostcalls;
    use vos_abi::pvm::ecall;
    use vos_abi::hostcall::accumulate;

    let self_id = hostcalls::info() as u32;

    let mut ctx = super::Context::new(
        super::context::ServiceId(self_id),
    );

    // Step 1: Try loading existing state from storage
    let mut buf = [0u8; BUF_SIZE];
    let state_read = hostcalls::read(STATE_KEY, &mut buf);
    let mut actor = if state_read > 0 && state_read < BUF_SIZE as u64 {
        load(&buf[..state_read as usize])
    } else if needs_init_payload {
        // Constructor needs arguments — fetch init payload.
        // FETCH before YIELD so invoke() callers get immediate service.
        loop {
            let n = ecall::ecall2(vos_abi::hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
            if n > 0 && n < BUF_SIZE as u64 {
                break init(Some(&buf[..n as usize]));
            }
            ecall::ecall0(accumulate::YIELD);
        }
    } else {
        // Parameterless constructor — construct immediately
        init(None)
    };

    // Step 2: Load yield replay index from storage
    let mut yield_buf = [0u8; 4];
    let yi_read = hostcalls::read(YIELD_INDEX_KEY, &mut yield_buf);
    let yield_index = if yi_read == 4 {
        u32::from_le_bytes(yield_buf)
    } else {
        0
    };
    ctx.set_replay_until(yield_index);

    // Step 3: Save initial state for durable replay.
    // On yield, we persist this snapshot (not the mutated state) so the
    // next invocation replays the handler from the same starting point.
    let initial_state = save(&actor);

    // Step 4: Process all pending items
    loop {
        let n = ecall::ecall2(vos_abi::hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
        if n == 0 || n >= BUF_SIZE as u64 {
            break; // No more items
        }
        // Copy payload so we can replay if ask() suspends
        let payload_len = n as usize;
        let mut payload_buf = [0u8; BUF_SIZE];
        payload_buf[..payload_len].copy_from_slice(&buf[..payload_len]);

        match dispatch(&payload_buf[..payload_len], &mut actor, &mut ctx) {
            RunResult::Yielded => { ctx.flush_effects(); break; }
            RunResult::Complete(stop) => { ctx.flush_effects(); if stop { break; } }
        }

        // Resolve pending asks: call invoke(), cache result, replay handler
        while let Some(pending) = ctx.take_pending_ask() {
            let mut invoke_buf = [0u8; BUF_SIZE];
            let result_len = hostcalls::invoke(
                &target_code_hash(pending.target.0),
                &pending.payload,
                0, // 0 = use default gas
                &mut invoke_buf,
            );
            let result = if result_len > 0 && result_len < BUF_SIZE as u64 {
                invoke_buf[..result_len as usize].to_vec()
            } else {
                alloc::vec::Vec::new()
            };
            ctx.push_call_result_and_reset(result);

            // Replay: re-dispatch the same message with cached results
            match dispatch(&payload_buf[..payload_len], &mut actor, &mut ctx) {
                RunResult::Yielded => { ctx.flush_effects(); break; }
                RunResult::Complete(stop) => { ctx.flush_effects(); if stop { break; } }
            }
        }
    }

    // Step 5: Persist state + yield index
    if ctx.self_scheduled() && !ctx.should_continue_as_new() {
        // Yielded: save initial state (for replay) and increment yield index.
        // The next invocation will replay from this state, fast-forwarding
        // through completed yields until it hits the new one.
        hostcalls::write(STATE_KEY, &initial_state);
        let new_yi = ctx.yield_index().to_le_bytes();
        hostcalls::write(YIELD_INDEX_KEY, &new_yi);
    } else {
        // Complete or continue_as_new: save final mutated state, reset yield index.
        let state_bytes = save(&actor);
        hostcalls::write(STATE_KEY, &state_bytes);
        hostcalls::write(YIELD_INDEX_KEY, &0u32.to_le_bytes());
    }

    // Step 6: Output exit status via YIELD, then halt.
    let status = if ctx.self_scheduled() {
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
    };
    hostcalls::yield_output(&status);
    halt();
}

/// Refine-only actor lifecycle — stateless guest program invoked by the agent.
///
/// Guest actors receive their state and message as invoke input, run the
/// handler, and return mutated state as invoke output. No storage access —
/// the agent manages state on their behalf.
///
/// Input protocol:  `[yield_index:u32 LE][state_len:u32 LE][state_bytes][message_bytes]`
/// Output protocol: `[status:u8][yield_index:u32 LE][state_len:u32 LE][state_bytes]`
#[cfg(feature = "pvm")]
pub fn refine_loop<A: super::Actor>(
    _needs_init_payload: bool,
    init: impl FnOnce(Option<&[u8]>) -> A,
    dispatch: impl Fn(&[u8], &mut A, &mut super::Context<A>) -> RunResult<bool>,
    save: impl Fn(&A) -> alloc::vec::Vec<u8>,
    load: impl Fn(&[u8]) -> A,
) {
    use vos_abi::pvm::ecall;

    let mut buf = [0u8; BUF_SIZE];

    // Step 1: FETCH input
    let n = ecall::ecall2(vos_abi::hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
    if n == 0 || n >= BUF_SIZE as u64 {
        halt_with_output(&[STATUS_DONE]);
    }
    let input = &buf[..n as usize];

    // Step 2: Unpack [yield_index:u32][state_len:u32][state...][message...]
    if input.len() < 8 {
        halt_with_output(&[STATUS_DONE]);
    }
    let yield_index = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let state_len = u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as usize;
    if input.len() < 8 + state_len {
        halt_with_output(&[STATUS_DONE]);
    }
    let state_bytes = &input[8..8 + state_len];
    let message = &input[8 + state_len..];

    // Step 3: Load or construct actor
    let mut ctx = super::Context::new(super::context::ServiceId(0));
    let mut actor = if state_len > 0 {
        load(state_bytes)
    } else {
        init(None)
    };

    // Step 4: Set durable replay state
    ctx.set_replay_until(yield_index);
    let initial_state = save(&actor);

    // Step 5: Dispatch message
    let yielded = match dispatch(message, &mut actor, &mut ctx) {
        RunResult::Yielded => true,
        RunResult::Complete(_) => false,
    };

    // Step 6: Pack output and halt
    if yielded && !ctx.should_continue_as_new() {
        // Yielded: return initial state (for replay) + new yield index
        let yi = ctx.yield_index().to_le_bytes();
        let sl = (initial_state.len() as u32).to_le_bytes();
        let total = 1 + 4 + 4 + initial_state.len();
        let mut out = alloc::vec![0u8; total];
        out[0] = STATUS_YIELDED;
        out[1..5].copy_from_slice(&yi);
        out[5..9].copy_from_slice(&sl);
        out[9..].copy_from_slice(&initial_state);
        halt_with_output(&out);
    } else {
        // Complete or continue_as_new: return final mutated state
        let final_state = save(&actor);
        let sl = (final_state.len() as u32).to_le_bytes();
        let total = 1 + 4 + 4 + final_state.len();
        let mut out = alloc::vec![0u8; total];
        out[0] = STATUS_DONE;
        out[1..5].copy_from_slice(&[0; 4]);
        out[5..9].copy_from_slice(&sl);
        out[9..].copy_from_slice(&final_state);
        halt_with_output(&out);
    }
}

/// Derive a code hash from a service ID for invoke() lookup.
///
/// Convention: the first 4 bytes are the service ID in LE, rest zeroed.
/// The vosx runtime recognizes this pattern and looks up the service's blob
/// by ID instead of by hash.
#[cfg(feature = "service")]
fn target_code_hash(service_id: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&service_id.to_le_bytes());
    hash
}

/// Build a code hash from a service ID (public, for agent use).
pub fn service_code_hash(service_id: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&service_id.to_le_bytes());
    hash
}
