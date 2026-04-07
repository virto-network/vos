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
    unsafe { IN_REFINE = v; }
}

#[cfg(feature = "service")]
pub fn is_refine_mode() -> bool {
    unsafe { IN_REFINE }
}

/// Stub for non-service builds so framework code can call it unconditionally.
#[cfg(not(feature = "service"))]
pub fn is_refine_mode() -> bool { false }

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

/// Service actor lifecycle.
///
/// Historically this was the JAM accumulate-phase entry (PC=5). In the
/// current runtime model, top-level services run at PC=0 (refine) and the
/// host journals side effects, committing them after the refine round
/// without re-entering the PVM at PC=5. This function is the actual body
/// the guest executes — it reads state via `READ` (which the runtime
/// overlays with the refine journal), dispatches messages, and writes
/// state back via `WRITE` (which the runtime stages into the journal).
/// The PC=5 entry remains present in the blob for dual-entry layout but
/// is unreachable from the runtime today.
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
    use super::lifecycle::{self, DispatchResult, BUF_SIZE};
    use super::context::ServiceId;

    set_refine_mode(true);

    let id = lifecycle::service_id();
    let mut ctx = super::Context::new(ServiceId(id));

    // Read persisted state via the read-only READ hostcall.
    let mut buf = [0u8; BUF_SIZE];
    let state_len = lifecycle::read_persisted_state(&mut buf);
    let state = if state_len > 0 { Some(&buf[..state_len]) } else { None };
    let mut actor = lifecycle::load_or_create::<A>(state);

    // Dispatch messages. flush_effects() inside dispatch_one is a no-op
    // in refine mode — effects accumulate in the context's pending_* vecs.
    loop {
        let n = lifecycle::fetch_raw(&mut buf);
        if n == 0 { break; }
        let result = lifecycle::dispatch_one::<A>(&buf[..n], &mut actor, &mut ctx);
        if matches!(result, DispatchResult::Yielded | DispatchResult::Stopped) {
            break;
        }
    }

    // Pack: new state + buffered effects + reply → RefinePayload bytes.
    // Note: under the new model the framework also writes STATE_KEY as a
    // WRITE effect (added below) so the accumulate stage persists it.
    let new_state_bytes = super::codec::Encode::encode(&actor);
    let reply_bytes = ctx.take_reply_bytes();
    let mut payload = ctx.drain_into_refine_payload(new_state_bytes.clone(), reply_bytes);

    // Always include a STATE_KEY write so accumulate persists the new
    // state. We use the same well-known key the lifecycle helpers use.
    payload.effects.insert(
        0,
        crate::refine_payload::Effect::Write {
            key: lifecycle::STATE_KEY_BYTES.to_vec(),
            value: new_state_bytes,
        },
    );

    let encoded = payload.encode();
    halt_with_output(&encoded);
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
    use crate::refine_payload::{Effect, RefinePayload};
    use vos_abi::pvm::hostcalls;
    use vos_abi::service::ServiceId;

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
    let mut buf = [0u8; BUF_SIZE];
    loop {
        let n = lifecycle::fetch_raw(&mut buf);
        if n == 0 { break; }
        let payload = match RefinePayload::decode(&buf[..n]) {
            Some(p) => p,
            None => continue, // skip malformed operand
        };
        for eff in payload.effects {
            match eff {
                Effect::Write { key, value } => {
                    hostcalls::write(&key, &value);
                }
                Effect::Transfer { target, memo } => {
                    hostcalls::transfer(ServiceId(target), 0, 0, &memo);
                }
                Effect::Provide { hash, data } => {
                    hostcalls::provide(&hash, &data);
                }
                Effect::New { code_hash } => {
                    hostcalls::new_service(&code_hash);
                }
            }
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
