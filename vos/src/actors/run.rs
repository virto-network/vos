//! Cooperative single-threaded executor for VOS actor programs.
//!
//! ## JAM lifecycle entry points
//!
//! Services built with the actor framework expose two distinct entries
//! that map onto the JAM refine→accumulate split:
//!
//! - [`run_refine_service`] (`_start`, PC=0): the **pure** refine body.
//!   Reads persisted state via the read-only `READ` hostcall, dispatches
//!   incoming FETCH messages, may issue child `INVOKE`s, and halts with
//!   a [`crate::refine_payload::RefinePayload`] blob in `a0`/`a1`.
//!   Side-effecting hostcalls are *forbidden* at this stage — the
//!   framework's `Context` honours an internal refine-mode flag and
//!   buffers `WRITE`/`TRANSFER`/`PROVIDE`/`NEW` into the payload's
//!   effects list instead of issuing them.
//!
//! - [`run_accumulate_service`] (`accumulate`, PC=5): the **commit**
//!   body. The host hands the refine payload back as a single FETCH
//!   item; this function decodes it and replays each effect via the
//!   real accumulate-phase hostcall. `INVOKE` is unavailable here —
//!   accumulate is structurally a state-mutating commit pass.
//!
//! Invoked actors (no `service` feature) use [`run_refine`] instead:
//! one PVM at PC=0 with state delivered as the first FETCH item and the
//! resulting state returned in the reply envelope rather than written
//! to storage.

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

/// Create a no-op [`Waker`]. Used by the single-threaded executor and
/// worker entry points to satisfy the `poll` API.
pub fn noop_waker() -> Waker {
    // SAFETY: noop_raw_waker returns a valid RawWaker with a static
    // vtable whose methods are all no-ops (no resources to manage).
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

/// Result of a single poll: either the future completed or it yielded.
pub enum RunResult<T> {
    Complete(T),
    Yielded,
}

/// Poll a future exactly once. Returns `Complete(val)` if ready, `Yielded` if pending.
pub fn try_poll<F: Future>(mut fut: F) -> RunResult<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local that we never move after pinning; it
    // lives until the function returns and is not accessed again.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => RunResult::Complete(val),
        Poll::Pending => RunResult::Yielded,
    }
}

/// Poll a future to completion. Used by worker mode where handlers
/// run natively and can block.
///
/// # Panics
/// Panics if the future yields (`Pending`). Worker handlers should
/// not use `ctx.yield_now()` — yielding is a PVM concept.
pub fn run_blocking<F: Future>(mut fut: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // SAFETY: same as try_poll — local fut, never moved after pin.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!("worker handler yielded — use an async runtime for I/O"),
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
/// Two modes:
/// - **PVM**: `Ready` from the first poll — the synchronous `INVOKE`
///   hostcall has already populated the reply bytes.
/// - **Worker**: wraps a `HostIo` future — yields `Pending` on first
///   poll so the host can fulfill the request, then `Ready` on re-poll.
pub struct Ask {
    inner: AskInner,
}

enum AskInner {
    /// Immediate result (PVM path or error).
    Immediate(Result<alloc::vec::Vec<u8>, super::value::InvokeError>),
    /// Deferred host I/O (worker path).
    HostIo(HostIo),
}

impl Ask {
    pub fn ready(result: alloc::vec::Vec<u8>) -> Self {
        Self {
            inner: AskInner::Immediate(Ok(result)),
        }
    }
    pub fn ready_err(err: super::value::InvokeError) -> Self {
        Self {
            inner: AskInner::Immediate(Err(err)),
        }
    }
    pub fn host_io(io: HostIo) -> Self {
        Self {
            inner: AskInner::HostIo(io),
        }
    }
}

fn decode_reply(bytes: alloc::vec::Vec<u8>) -> super::value::Value {
    if bytes.is_empty() {
        super::value::Value::Unit
    } else {
        <super::value::Value as super::codec::Decode>::decode(&bytes)
    }
}

impl Future for Ask {
    type Output = Result<super::value::Value, super::value::InvokeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match &mut this.inner {
            AskInner::Immediate(result) => {
                let result = core::mem::replace(result, Err(super::value::InvokeError::Panicked));
                match result {
                    Ok(bytes) => Poll::Ready(Ok(decode_reply(bytes))),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            AskInner::HostIo(io) => match Pin::new(io).poll(cx) {
                Poll::Ready(bytes) => Poll::Ready(Ok(decode_reply(bytes))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// A future that yields once to let the host fulfill an I/O request,
/// then returns the result on re-poll.
///
/// Used by workers for async host calls (ask, fs_read, etc.).
/// The request is stored in `Context::host_io_request` before this
/// future is created. The host reads it, performs the I/O, writes
/// the result to the result slot, then re-polls.
pub struct HostIo {
    polled: bool,
    result_slot: *mut Option<alloc::vec::Vec<u8>>,
}

impl HostIo {
    /// Create a new HostIo future that reads its result from `result_slot`.
    ///
    /// # Safety contract (enforced by caller, not by this function):
    /// - `result_slot` must point to a valid `Option<Vec<u8>>` that
    ///   outlives this future (guaranteed: it lives in `Context` which
    ///   is owned by `WorkerState` alongside the future).
    /// - The host must write `Some(bytes)` to the slot before the
    ///   second poll (guaranteed: `provide_result` does this).
    /// - Only one `HostIo` is in flight per context at a time
    ///   (guaranteed: single-threaded, one dispatch at a time).
    pub(crate) fn new(result_slot: *mut Option<alloc::vec::Vec<u8>>) -> Self {
        Self {
            polled: false,
            result_slot,
        }
    }
}

impl Unpin for HostIo {}

impl Future for HostIo {
    type Output = alloc::vec::Vec<u8>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<alloc::vec::Vec<u8>> {
        if self.polled {
            // Second poll: host has provided the result.
            // SAFETY: result_slot points into Context which outlives
            // this future (both owned by WorkerState). The host called
            // provide_result before re-polling.
            let result = unsafe { &mut *self.result_slot };
            Poll::Ready(result.take().unwrap_or_default())
        } else {
            // First poll: yield so the host can fulfill the request
            self.polled = true;
            Poll::Pending
        }
    }
}

/// Future returned by [`super::context::Context::resolve`].
///
/// Wraps a registry `Ask`, decoding the reply into a u32.
/// Returns 0 for **both** "not installed" and any failure path
/// (invoke error, unexpected reply variant) — callers can't
/// distinguish them from the return value alone. Failure paths
/// emit a `log::warn!` so the cause is visible in actor logs;
/// callers that need to branch on the error should use
/// [`super::context::Context::ask`] against `ServiceId::REGISTRY`
/// directly.
pub struct Resolve {
    ask: Ask,
}

impl Resolve {
    pub(crate) fn new(ask: Ask) -> Self {
        Self { ask }
    }
}

impl Unpin for Resolve {}

impl Future for Resolve {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u32> {
        match Pin::new(&mut self.ask).poll(cx) {
            Poll::Ready(Ok(super::value::Value::U32(n))) => Poll::Ready(n),
            Poll::Ready(Ok(other)) => {
                crate::log::warn!(
                    "Context::resolve: registry returned non-U32 reply ({other:?}); treating as not-found",
                );
                Poll::Ready(0)
            }
            Poll::Ready(Err(e)) => {
                crate::log::warn!(
                    "Context::resolve: registry invoke failed: {e}; treating as not-found",
                );
                Poll::Ready(0)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── Refine-mode flag (service framework) ──────────────────────────────

/// Global flag: are we currently inside `run_refine_service`?
///
/// In refine the JAM-pure hostcall table forbids state-mutating calls
/// (`WRITE`, `TRANSFER`, `PROVIDE`, `NEW`). The framework's
/// `Context::flush_effects` checks this flag and, when set, *buffers*
/// effects in the context's pending vectors instead of issuing hostcalls
/// — `run_refine_service` then drains them into the refine output payload.
/// `run_accumulate_service` clears the flag and applies the same effects
/// via real hostcalls.
///
/// Safe because PVM is single-threaded.
#[cfg(feature = "service")]
static mut IN_REFINE: bool = false;

#[cfg(feature = "service")]
pub fn set_refine_mode(v: bool) {
    // SAFETY: PVM is single-threaded; no concurrent access to IN_REFINE.
    unsafe {
        IN_REFINE = v;
    }
}

#[cfg(feature = "service")]
pub fn is_refine_mode() -> bool {
    // SAFETY: PVM is single-threaded; read of static mut bool is sound.
    unsafe { IN_REFINE }
}

/// Stub for non-service builds so framework code can call it unconditionally.
#[cfg(not(feature = "service"))]
pub fn is_refine_mode() -> bool {
    false
}

// ── Halt ──────────────────────────────────────────────────────────────

/// Halt the PVM (no output). Used by accumulate (service mode).
#[cfg(all(feature = "service", target_arch = "riscv64"))]
fn halt() -> ! {
    // SAFETY: terminal PVM hostcall. `noreturn` — no liveness after.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") 0u64, // IPC_SLOT = REPLY → RootHalt
            options(noreturn),
        );
    }
}

/// Halt with output data in registers a0 (ptr) and a1 (len).
#[cfg(target_arch = "riscv64")]
fn halt_with_output(data: &[u8]) -> ! {
    // SAFETY: terminal PVM hostcall. The host reads `len` bytes from
    // `data.as_ptr()` before we lose control; the slice is owned by
    // the caller until then. `noreturn` — no liveness after.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") data.as_ptr() as u64,
            in("a1") data.len() as u64,
            in("t0") 0u64, // IPC_SLOT = REPLY → RootHalt
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
/// Refusal status: the dispatch-layer auth gate denied the call
/// before the target actor ran. Distinct from `STATUS_PANICKED`
/// so a refused remote caller surfaces "permission denied" rather
/// than colliding with a real actor panic.
pub const STATUS_FORBIDDEN: u8 = 0x05;

// ── Service refine phase (PC=0, JAM-pure) ─────────────────────────────

/// JAM-pure refine entry for service actors.
///
/// Runs at PC=0. Cannot mutate state — issues only read-only hostcalls.
/// Side effects produced by handlers are buffered in the `Context` and
/// then encoded into a `RefinePayload` which is emitted as the refine
/// output bytes (registers a0/a1).
///
/// Lifecycle:
/// 1. Read persisted state via `READ(STATE_KEY)` (allowed in refine).
/// 2. `load_or_create::<A>(state)`.
/// 3. FETCH and dispatch each pending message; handler effects buffer
///    into `Context::pending_*` because `is_refine_mode() == true`.
/// 4. Encode the new actor state, the buffered effects, and any reply
///    bytes into a `RefinePayload`.
/// 5. `halt_with_output(payload)`.
#[cfg(feature = "service")]
pub fn run_refine_service<A: super::Actor>() {
    use super::context::ServiceId;
    use super::lifecycle::{self, BUF_SIZE, DispatchResult};
    use alloc::boxed::Box;
    use core::ptr::addr_of_mut;

    // Install the PVM `log::Log` impl on the first refine call.
    // `set_logger` returns Err on duplicate install — we ignore it
    // so warm restarts (which re-enter `_start` without flat_mem
    // reset) don't trip on the second call.
    crate::log_impl::install_pvm_logger();

    set_refine_mode(true);

    let id = lifecycle::service_id();
    let mut ctx = super::Context::new(ServiceId(id));

    // Warm-restart actor holder. Lives in static rw_data, which sits
    // inside the PVM's flat_mem; VOS preserves flat_mem across ticks
    // via `new_warm`, so on a warm restart this pointer still references
    // a valid heap-allocated `A` and we skip cold init entirely.
    //
    // Cold start (ACTOR_HOLDER == 0): reads STATE_KEY via READ hostcall
    // and deserializes the actor. This is the JAM-compatible path that
    // works on any conformant host without flat_mem support.
    //
    // Per-service uniqueness: each service has its own PVM instance
    // with its own flat_mem, so each one gets its own copy of this
    // static — even when two services share the same blob. Type-erased
    // as `usize` because `A` differs per service; safe because PVM is
    // single-threaded.
    static mut ACTOR_HOLDER: usize = 0;
    let holder_ptr = addr_of_mut!(ACTOR_HOLDER);
    let mut cold_start = false;
    // SAFETY: PVM is single-threaded; the static-mut access goes via
    // a raw pointer (no shared/exclusive ref conflict). The cast from
    // `usize` back to `*mut A` is sound because we stamped the slot
    // with a `Box::into_raw(Box::<A>::new(..))` value of the same A.
    let actor_ref: &mut A = unsafe {
        if *holder_ptr == 0 {
            cold_start = true;
            // Cold start: try to restore from persisted state in storage.
            // This is the JAM-compatible path — the guest reads its own
            // serialized state via READ (legal in refine) without any
            // host cooperation. On VOS, this path is skipped because
            // ACTOR_HOLDER is warm from the flat_mem overlay.
            let mut state_buf = [0u8; BUF_SIZE];
            let n = lifecycle::read_persisted_state(&mut state_buf);
            let state = if n > 0 { Some(&state_buf[..n]) } else { None };
            let boxed = Box::new(lifecycle::load_or_create::<A>(state));
            *holder_ptr = Box::into_raw(boxed) as usize;
        }
        &mut *(*holder_ptr as *mut A)
    };
    let mut buf = [0u8; BUF_SIZE];

    // On cold start, run the on_start lifecycle hook before the message
    // loop. If on_start yields, the actor self-schedules and we skip
    // the message loop (same as a yielded dispatch).
    let mut started = true;
    if cold_start {
        match try_poll(actor_ref.on_start(&mut ctx)) {
            RunResult::Yielded => {
                ctx.flush_effects();
                started = false;
            }
            RunResult::Complete(Ok(())) => {}
            RunResult::Complete(Err(e)) => {
                actor_ref.on_error(&e);
                started = false;
            }
        }
    }

    // Dispatch messages. flush_effects() inside dispatch_one is a no-op
    // in refine mode — effects accumulate in the context's pending_* vecs.
    if started {
        loop {
            let n = lifecycle::fetch_raw(&mut buf);
            if n == 0 {
                break;
            }
            let result = lifecycle::dispatch_one::<A>(&buf[..n], actor_ref, &mut ctx);
            if matches!(result, DispatchResult::Yielded | DispatchResult::Stopped) {
                break;
            }
        }
    }

    // Pack: state-bytes-from-actor + buffered effects + reply →
    // RefinePayload. Drop temporaries eagerly before halt_with_output
    // (which is `-> !` and never runs destructors).
    //
    // The output buffer is a static Vec reused across warm restarts to
    // avoid leaking a fresh allocation on every halt (the `-> !` ecall
    // never runs destructors).
    static mut OUTPUT_BUF: usize = 0;
    let out_ptr = addr_of_mut!(OUTPUT_BUF);
    // SAFETY: same single-threaded PVM invariant as ACTOR_HOLDER —
    // the slot holds a `Box::into_raw(Vec<u8>)` value we stamped on
    // first use.
    let out_buf: &mut alloc::vec::Vec<u8> = unsafe {
        if *out_ptr == 0 {
            *out_ptr = Box::into_raw(Box::new(alloc::vec::Vec::<u8>::new())) as usize;
        }
        &mut *(*out_ptr as *mut alloc::vec::Vec<u8>)
    };
    {
        let new_state_bytes = super::codec::Encode::encode(&*actor_ref);
        let reply_bytes = ctx.take_reply_bytes();
        let payload = ctx.drain_into_refine_payload(new_state_bytes, reply_bytes);
        drop(ctx);
        let encoded = payload.encode();
        out_buf.clear();
        out_buf.extend_from_slice(&encoded);
        // encoded, new_state_bytes, reply_bytes, payload dropped here
    }
    halt_with_output(out_buf);
}

// ── Service accumulate phase (PC=5, JAM-pure commit) ──────────────────

/// JAM-pure accumulate entry for service actors.
///
/// Runs at PC=5. The only stage allowed to mutate state. Receives one
/// `RefinePayload` per work item via FETCH and replays each effect via
/// the corresponding accumulate-phase hostcall. Does **not** run user
/// handlers — accumulate is purely structural.
#[cfg(feature = "service")]
pub fn run_accumulate_service<A: super::Actor>() {
    use super::lifecycle::{self, BUF_SIZE};
    use crate::refine_payload::RefinePayload;

    set_refine_mode(false);

    // FETCH each refine output operand. The runtime hands one
    // `RefinePayload`-encoded blob per FETCH call.
    //
    // NB: this is a slimmed encoding — the full JAM operand layout
    // (`encode_operand` from grey-state) wraps these bytes with package
    // headers, an accumulate_gas field, and a `WorkResult` tag. The
    // host-side runtime constructs that wrapper today; this guest body
    // currently consumes the inner refine payload directly. A follow-up
    // commit will switch the FETCH layout to include the full operand
    // header so the same blob is bit-identical with on-chain accumulate.
    // FETCH 1: the refine output payload (effects to replay).
    let mut buf = [0u8; BUF_SIZE];
    let n = lifecycle::fetch_raw(&mut buf);
    if n > 0 {
        if let Some(payload) = RefinePayload::decode(&buf[..n]) {
            // Deserialize the actor from refine state for on_commit.
            // With rkyv this is essentially zero-copy (pointer cast).
            let actor = lifecycle::load_or_create::<A>(if payload.state.is_empty() {
                None
            } else {
                Some(&payload.state)
            });
            actor.on_commit(&payload);
        }
    }

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
    use super::context::ServiceId;
    use super::lifecycle::{self, BUF_SIZE, DispatchResult};

    // FETCH 1: state
    let mut buf = [0u8; BUF_SIZE];
    let n = lifecycle::fetch_raw(&mut buf);
    let state = if n > 0 { Some(&buf[..n]) } else { None };
    let mut actor = lifecycle::load_or_create::<A>(state);

    let mut ctx = super::Context::new(ServiceId(0));

    // FETCH 2+: messages (same loop as accumulate)
    loop {
        let n = lifecycle::fetch_raw(&mut buf);
        if n == 0 {
            break;
        }
        let result = lifecycle::dispatch_one::<A>(&buf[..n], &mut actor, &mut ctx);
        if matches!(result, DispatchResult::Yielded | DispatchResult::Stopped) {
            break;
        }
    }

    let status = lifecycle::exit_status::<A>(&ctx);

    // Pack output: [status:u8][state_len:u32][state...][reply...]
    // Drop temporaries and ctx eagerly — halt_with_output is `-> !`
    // so destructors never run; without explicit drops the Vecs leak
    // on every warm-restart iteration.
    let out = {
        let state = lifecycle::save_state::<A>(&actor, &ctx);
        let reply_bytes = ctx.take_reply_bytes();
        drop(ctx);
        let sl = (state.len() as u32).to_le_bytes();
        let mut out = alloc::vec![0u8; 1 + 4 + state.len() + reply_bytes.len()];
        out[0] = status[0];
        out[1..5].copy_from_slice(&sl);
        out[5..5 + state.len()].copy_from_slice(&state);
        out[5 + state.len()..].copy_from_slice(&reply_bytes);
        out
        // state, reply_bytes dropped here
    };
    halt_with_output(&out);
}

// ── Utilities ─────────────────────────────────────────────────────────

/// Build a code hash from a service ID (public, for agent use).
pub fn service_code_hash(service_id: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&service_id.to_le_bytes());
    hash
}
