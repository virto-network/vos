//! Cooperative single-threaded executor for VOS actor programs.
//!
//! Two-phase JAM lifecycle:
//! - **Refine (PC=0)**: Dispatch message, handle yields/asks, produce output.
//! - **Accumulate (PC=5)**: Service-only. Load state from storage, dispatch
//!   messages, persist state. Uses lifecycle building blocks.

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
    /// Returns Ready immediately — used during ask-replay to skip past
    /// yield points while the framework re-executes the handler.
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

/// A future returned by `ctx.ask()`.
///
/// On first invocation: returns `Pending` (triggers ask resolution in `dispatch_one`).
/// On replay: returns `Ready(Ok(Value))` or `Ready(Err(InvokeError))`.
pub struct Ask {
    /// Raw reply bytes or error. Deserialized lazily in poll().
    result: Option<Result<alloc::vec::Vec<u8>, super::value::InvokeError>>,
}

impl Ask {
    pub fn ready(result: alloc::vec::Vec<u8>) -> Self {
        Self { result: Some(Ok(result)) }
    }
    pub fn ready_err(err: super::value::InvokeError) -> Self {
        Self { result: Some(Err(err)) }
    }
    pub fn pending() -> Self {
        Self { result: None }
    }
}

impl Future for Ask {
    type Output = Result<super::value::Value, super::value::InvokeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(result) = this.result.take() {
            match result {
                Ok(bytes) => {
                    let value = if bytes.is_empty() {
                        super::value::Value::Unit
                    } else {
                        <super::value::Value as super::codec::Decode>::decode(&bytes)
                    };
                    Poll::Ready(Ok(value))
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        } else {
            Poll::Pending
        }
    }
}

// ── I/O suppression (ask-replay) ─────────────────────────────────────

/// Global flag: suppress I/O (println! etc) during ask-replay re-dispatch.
/// Safe because PVM is single-threaded.
#[cfg(feature = "pvm")]
static mut SUPPRESSING_IO: bool = false;

/// Set the I/O suppression flag (framework-internal).
#[cfg(feature = "pvm")]
pub fn set_suppressing_io(v: bool) {
    unsafe { SUPPRESSING_IO = v; }
}

/// Check if I/O is currently suppressed (ask-replay in progress).
#[cfg(feature = "pvm")]
pub fn is_suppressing_io() -> bool {
    unsafe { SUPPRESSING_IO }
}

// ── Halt ──────────────────────────────────────────────────────────────

/// Halt the PVM (no output). Used by accumulate (service mode).
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

/// Exit status: actor processed all messages normally.
pub const STATUS_DONE: u8 = 0x00;
/// Exit status: actor handler yielded (wants re-invocation).
pub const STATUS_YIELDED: u8 = 0x01;
/// Exit status: child actor panicked during invoke.
pub const STATUS_PANICKED: u8 = 0x02;
/// Exit status: target service not found during invoke.
pub const STATUS_NOT_FOUND: u8 = 0x03;
/// Exit status: child actor ran out of gas during invoke.
pub const STATUS_OOG: u8 = 0x04;

// ── Accumulate phase (service actors) ─────────────────────────────────

/// Service actor lifecycle — JAR accumulate phase (PC=5).
///
/// Composed from lifecycle building blocks:
/// 1. `load_or_create` — state from storage
/// 2. `fetch_raw` + `dispatch_one` — message loop
/// 3. `save_state` — persist current state
/// 4. `emit_status` — output exit status, halt
#[cfg(feature = "service")]
pub fn run_accumulate<A: super::Actor>() {
    use super::lifecycle::{self, DispatchResult, BUF_SIZE};
    use super::context::ServiceId;

    let id = lifecycle::service_id();
    let mut ctx = super::Context::new(ServiceId(id));

    // Read persisted state from storage
    let mut buf = [0u8; BUF_SIZE];
    let state_len = lifecycle::read_persisted_state(&mut buf);
    let state = if state_len > 0 { Some(&buf[..state_len]) } else { None };
    let mut actor = lifecycle::load_or_create::<A>(state);

    // Dispatch messages
    loop {
        let n = lifecycle::fetch_raw(&mut buf);
        if n == 0 { break; }
        let result = lifecycle::dispatch_one::<A>(&buf[..n], &mut actor, &mut ctx);
        if matches!(result, DispatchResult::Yielded | DispatchResult::Stopped) {
            break;
        }
    }

    lifecycle::save_state::<A>(&actor, &ctx);
    lifecycle::emit_status::<A>(&ctx);
    halt();
}

// ── Refine phase (all actors) ─────────────────────────────────────────

/// Refine-only actor lifecycle — JAR refine phase (PC=0).
///
/// The runtime splits invoke input into separate FETCH items:
///   FETCH 1: `[state_bytes]` (empty on first invocation)
///   FETCH 2+: message bytes
///
/// Output: `[status:u8][state_len:u32 LE][state_bytes]`
#[cfg(feature = "pvm")]
pub fn run_refine<A: super::Actor>() {
    use super::lifecycle::{self, DispatchResult, BUF_SIZE};
    use super::context::ServiceId;

    // FETCH 1: state
    let mut buf = [0u8; BUF_SIZE];
    let n = lifecycle::fetch_raw(&mut buf);
    let state = if n > 0 { Some(&buf[..n]) } else { None };
    let mut actor = lifecycle::load_or_create::<A>(state);

    let mut ctx = super::Context::new(ServiceId(0));

    // FETCH 2+: messages (same loop as accumulate)
    loop {
        let n = lifecycle::fetch_raw(&mut buf);
        if n == 0 { break; }
        let result = lifecycle::dispatch_one::<A>(&buf[..n], &mut actor, &mut ctx);
        if matches!(result, DispatchResult::Yielded | DispatchResult::Stopped) {
            break;
        }
    }

    let state = lifecycle::save_state::<A>(&actor, &ctx);
    let status = lifecycle::exit_status::<A>(&ctx);
    let reply_bytes = ctx.take_reply_bytes();

    // Pack output: [status:u8][state_len:u32][state...][reply...]
    let sl = (state.len() as u32).to_le_bytes();
    let mut out = alloc::vec![0u8; 1 + 4 + state.len() + reply_bytes.len()];
    out[0] = status[0];
    out[1..5].copy_from_slice(&sl);
    out[5..5 + state.len()].copy_from_slice(&state);
    out[5 + state.len()..].copy_from_slice(&reply_bytes);
    halt_with_output(&out);
}

// ── Utilities ─────────────────────────────────────────────────────────

/// Build a code hash from a service ID (public, for agent use).
pub fn service_code_hash(service_id: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&service_id.to_le_bytes());
    hash
}
