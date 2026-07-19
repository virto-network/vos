//! Cooperative single-threaded executor for VOS actor programs.
//!
//! ## Lifecycle entry point
//!
//! Services built with the actor framework expose a single entry at
//! PC=0 — the JAR refine body:
//!
//! - [`run_refine_service`] (`_start`, PC=0): the **pure** refine body.
//!   Reads persisted state via the read-only `READ` hostcall, dispatches
//!   incoming FETCH messages, may issue child `INVOKE`s, and halts with
//!   a [`crate::refine_payload::RefinePayload`] blob in `a0`/`a1`.
//!   Side-effecting hostcalls are *forbidden* at this stage — the
//!   framework's `Context` honours an internal refine-mode flag and
//!   buffers `WRITE`/`TRANSFER`/`PROVIDE`/`NEW` into the payload's
//!   effects list instead of issuing them. The host absorbs that
//!   payload and applies the effects natively (`crate::runtime`); there
//!   is no second PVM invocation.
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

    /// Construct the source-level await state after a VOS suspension call.
    /// A restored PVM has already crossed the durable boundary, so its first
    /// poll is immediately ready; the transition-finalization fork still
    /// returns pending and unwinds into its refine output.
    #[cfg(feature = "pvm")]
    pub(crate) fn after_checkpoint(restored: bool) -> Self {
        Self { yielded: restored }
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

/// In an **extension** build, `HostIo` is the executor-backed [`ExecIo`]
/// future: it carries the request bytes and registers them with the
/// per-instance `Exec` (reached via the task waker) instead of a ctx slot, so
/// many tasks can each have an op in flight. The single-slot future below is
/// used for the WASM / plain-host builds, which stay single-task.
#[cfg(feature = "extension")]
pub use crate::actors::exec::ExecIo as HostIo;

/// A future that yields once to let the host fulfill an I/O request,
/// then returns the result on re-poll.
///
/// Used by workers for async host calls (ask, fs_read, etc.).
/// The request is stored in `Context::host_io_request` before this
/// future is created. The host reads it, performs the I/O, writes
/// the result to the result slot, then re-polls.
#[cfg(not(feature = "extension"))]
pub struct HostIo {
    polled: bool,
    result_slot: *mut Option<alloc::vec::Vec<u8>>,
}

#[cfg(not(feature = "extension"))]
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

#[cfg(not(feature = "extension"))]
impl Unpin for HostIo {}

#[cfg(not(feature = "extension"))]
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

// `Resolve` future removed in favour of `Context::resolve` being an
// `async fn` directly — see context.rs for the local-then-hyperspace
// fallthrough chain. `super::value::Value` matching now lives next
// to the call site.

// ── Refine-mode flag (service framework) ──────────────────────────────

/// Global flag: are we currently inside `run_refine_service`?
///
/// In refine the JAM-pure hostcall table forbids state-mutating calls
/// (`WRITE`, `TRANSFER`, `PROVIDE`, `NEW`). The framework's
/// `Context::flush_effects` checks this flag and, when set, *buffers*
/// effects in the context's pending vectors instead of issuing hostcalls
/// — `run_refine_service` then drains them into the refine output payload,
/// which the host absorbs and applies natively. Service actors run
/// exclusively in refine, so the flag stays set for their whole life.
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

/// Gray Paper dynamic-jump halt address (2^32 - 2^16).
#[cfg(target_arch = "riscv64")]
const PVM_HALT_ADDR: u64 = 0xFFFF_0000;

/// Halt with output data in registers a0 (ptr) and a1 (len).
#[cfg(target_arch = "riscv64")]
fn halt_with_output(data: &[u8]) -> ! {
    // SAFETY: terminal PVM dynamic jump. The host reads `len` bytes from
    // `data.as_ptr()` after observing the GP halt address; the slice is owned
    // by the caller until then. Root REPLY (ecalli 0) is not a halt in JAR:
    // it is reserved for returning from a nested CALL and panics at the root.
    unsafe {
        core::arch::asm!(
            "jr t0",
            in("a0") data.as_ptr() as u64,
            in("a1") data.len() as u64,
            in("t0") PVM_HALT_ADDR,
            options(noreturn),
        );
    }
}

/// Halt with output (a0=ptr, a1=len) AND bind a 32-byte ZK actor-IO
/// hash into the final-state register window φ[9..12] (RISC-V a2-a5).
///
/// This is the ZK actor-IO ABI binding mechanism (see [`crate::zk`]).
/// The four little-endian hash words are passed as `in` operands on the
/// halting `ecall`, so the compiler materialises them into a2-a5 via
/// real instructions immediately before the ecall.  Because the halt
/// (`t0=0`, RootHalt) only reads a0/a1, a2-a5 persist unchanged into
/// `final_state.registers`, where Phase Z0's closing chip pins the
/// columns and the verifier's boundary-binding check equates the
/// metadata to them (`zkpvm::Proof::public_io_hash`).  No new ECALL, no
/// tracer/prover cooperation, no register-ledger surgery: it is ordinary
/// register state at halt.  The closing-read column binds to the true
/// final register via the register-ledger read-consistency (v6: cross-row
/// `prev_value` + `(reg, ts)` sortedness + `is_write` limb), which is
/// sound against a from-scratch prover (gate
/// `zkpvm/tests/ledger_readconsistency_gate.rs`) — see `crate::zk` and
/// `zkpvm::chips::register_memory_closing`.
///
/// a2→φ[9], a3→φ[10], a4→φ[11], a5→φ[12] per grey-transpiler's RISC-V→PVM
/// mapping — the exact window `public_io_hash` reconstructs.
#[cfg(target_arch = "riscv64")]
fn halt_with_output_bound(data: &[u8], io_hash: &[u8; 32]) -> ! {
    let w0 = u64::from_le_bytes([
        io_hash[0], io_hash[1], io_hash[2], io_hash[3], io_hash[4], io_hash[5], io_hash[6],
        io_hash[7],
    ]);
    let w1 = u64::from_le_bytes([
        io_hash[8],
        io_hash[9],
        io_hash[10],
        io_hash[11],
        io_hash[12],
        io_hash[13],
        io_hash[14],
        io_hash[15],
    ]);
    let w2 = u64::from_le_bytes([
        io_hash[16],
        io_hash[17],
        io_hash[18],
        io_hash[19],
        io_hash[20],
        io_hash[21],
        io_hash[22],
        io_hash[23],
    ]);
    let w3 = u64::from_le_bytes([
        io_hash[24],
        io_hash[25],
        io_hash[26],
        io_hash[27],
        io_hash[28],
        io_hash[29],
        io_hash[30],
        io_hash[31],
    ]);
    // SAFETY: terminal PVM dynamic jump. The host reads `len` bytes from
    // `data.as_ptr()` after observing the GP halt address; a2-a5 carry the
    // io-hash (φ[9..12]) and are captured in `final_state`.
    unsafe {
        core::arch::asm!(
            "jr t0",
            in("a0") data.as_ptr() as u64,
            in("a1") data.len() as u64,
            in("a2") w0,
            in("a3") w1,
            in("a4") w2,
            in("a5") w3,
            in("t0") PVM_HALT_ADDR,
            options(noreturn),
        );
    }
}

#[cfg(all(feature = "pvm", not(target_arch = "riscv64")))]
fn halt_with_output(_data: &[u8]) -> ! {
    panic!("halt_with_output is only supported on RISC-V targets");
}

#[cfg(all(feature = "service", not(target_arch = "riscv64")))]
fn halt_with_output_bound(_data: &[u8], _io_hash: &[u8; 32]) -> ! {
    panic!("halt_with_output_bound is only supported on RISC-V targets");
}

/// First byte of a refine exit status / INVOKE reply envelope.
/// Wire-stable discriminants — do not renumber.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeStatus {
    /// Actor processed all messages normally.
    Done = 0x00,
    /// Handler yielded (wants re-invocation).
    Yielded = 0x01,
    /// Child actor trapped (panic / page fault) during invoke.
    Panicked = 0x02,
    /// Target service not found during invoke.
    NotFound = 0x03,
    /// Child actor ran out of gas during invoke.
    OutOfGas = 0x04,
    /// Dispatch-layer auth gate denied the call before the target
    /// ran. Distinct from `Panicked` so a refused caller surfaces
    /// "permission denied" rather than colliding with a real panic.
    Forbidden = 0x05,
    /// Child's reply exceeded the caller's output buffer. Distinct
    /// from `Panicked` so an oversize reply is not misreported as a
    /// crash.
    TooBig = 0x06,
}

pub const STATUS_DONE: u8 = InvokeStatus::Done as u8;
pub const STATUS_YIELDED: u8 = InvokeStatus::Yielded as u8;
pub const STATUS_PANICKED: u8 = InvokeStatus::Panicked as u8;
pub const STATUS_NOT_FOUND: u8 = InvokeStatus::NotFound as u8;
pub const STATUS_OOG: u8 = InvokeStatus::OutOfGas as u8;
pub const STATUS_FORBIDDEN: u8 = InvokeStatus::Forbidden as u8;
pub const STATUS_TOO_BIG: u8 = InvokeStatus::TooBig as u8;

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
    // because an exact continuation retains the already-installed logger.
    crate::log_impl::install_pvm_logger();

    set_refine_mode(true);

    let id = lifecycle::service_id();
    let mut ctx = super::Context::new(ServiceId(id));

    // Actor holder. It lives in the PVM's mutable memory, so an exact kernel
    // continuation preserves both this pointer and the referenced allocation.
    // A fresh invocation starts with a zero slot and rehydrates from storage.
    //
    // Cold start (ACTOR_HOLDER == 0): reads STATE_KEY via READ hostcall
    // and deserializes the actor. This is the portable fresh-invocation path.
    //
    // Per-service uniqueness: each service has its own PVM instance
    // with its own mutable memory, so each one gets its own copy of this
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
            // host cooperation. Exact continuation restore skips it because
            // it resumes the existing call stack after the await boundary.
            //
            // The read grows onto the heap when the state outgrew the
            // probe buffer — a fixed-buffer read here would treat a
            // large state as missing and silently resurrect the actor
            // as default, persisting the wipe on the next save.
            let state = lifecycle::read_persisted_state_owned();
            let boxed = Box::new(lifecycle::load_or_create::<A>(state.as_deref()));
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
    // for service builds — effects accumulate in the context's pending_* vecs.
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
    // The output buffer is a static Vec reused across exact restores to
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
        // Emit the post-dispatch state as the final Write{STATE_KEY}
        // effect only when the blob changed from the anchored state.
        // Genesis always emits: there is no prior blob to be equal to,
        // and the first work-result is what materializes the actor's
        // row.
        // The exact suspension snapshot is captured before the finalize fork
        // drains a checkpoint and advances its anchor. On resume, derive the
        // base from durable storage instead of retaining the pre-commit anchor
        // in VM memory. Non-reentrancy guarantees this is precisely the state
        // committed for the suspended workflow's previous slice.
        let prior_state = lifecycle::read_persisted_state_owned();
        let (plain_anchor_kind, plain_anchor) =
            crate::refine_payload::anchor_for(prior_state.as_deref());
        let prior_state_hash = match &prior_state {
            Some(bytes) if !bytes.is_empty() => crate::refine_payload::state_anchor(bytes),
            _ => [0u8; 32],
        };
        let (anchor_kind, anchor) =
            match A::COMMITTED.then(lifecycle::read_committed_root).flatten() {
                Some(root) => (crate::refine_payload::ANCHOR_SMT_ROOT, root),
                None => (plain_anchor_kind, plain_anchor),
            };
        let new_hash = crate::refine_payload::state_anchor(&new_state_bytes);
        // Empty state is genesis, not a hash anchor — the host's overlay
        // computes `anchor_for(Some(empty)) == GENESIS`, so a fieldless
        // (empty-encoding) actor must carry genesis forward or its next
        // self-message iteration would AnchorMismatch and silently drop.
        let new_is_empty = new_state_bytes.is_empty();
        let state_changed = anchor_kind == crate::refine_payload::ANCHOR_GENESIS
            || new_hash != prior_state_hash;

        // Committed actors: recompute the composite AFTER the handler
        // (the field root rows are current through the overlay) and
        // record it as an ordinary framework row — the host's
        // expected-anchor check reads it next dispatch. Written only
        // when the composite moved, so a pure read stays effect-free
        // (the durable-node rule). Must precede the drain: one drain
        // carries the handles' rows AND this one.
        let (next_kind, next_anchor) = match actor_ref.__committed_root(&new_hash) {
            Some(root) => (crate::refine_payload::ANCHOR_SMT_ROOT, root),
            None if new_is_empty => (crate::refine_payload::ANCHOR_GENESIS, [0u8; 32]),
            None => (crate::refine_payload::ANCHOR_STATE_HASH, new_hash),
        };
        if next_kind == crate::refine_payload::ANCHOR_SMT_ROOT
            && (next_kind, next_anchor) != (anchor_kind, anchor)
        {
            super::storage::store_raw(
                lifecycle::COMMITTED_ROOT_KEY.to_vec(),
                next_anchor.to_vec(),
            );
        }

        let payload = ctx.drain_into_refine_payload(
            anchor_kind,
            anchor,
            super::storage::end_dispatch(),
            state_changed.then_some(new_state_bytes),
            reply_bytes,
        );
        drop(ctx);
        let encoded = payload.encode();
        out_buf.clear();
        out_buf.extend_from_slice(&encoded);
        // encoded, new_state_bytes, reply_bytes, payload dropped here
    }
    // ZK actor-IO ABI: bind this execution's (public, return) into the
    // final-state register window φ[9..12] as part of the halt (see
    // `crate::zk` and `halt_with_output_bound`).  A handler that called
    // `vos::zk::bind_io` stashed the real `(public, return)` hash; drain
    // it.  Otherwise fall back to the tagless empty-public/empty-return
    // default, so every proof carries a well-defined io-hash (the program
    // commitment, not the io-hash, is what ties a proof to its actor).
    let io_hash =
        crate::zk::__take_pending_io_hash().unwrap_or_else(|| crate::zk::compute_io_hash(&[], &[]));
    halt_with_output_bound(out_buf, &io_hash);
}

// ── Task refine (witness-delivered input, always cold) ───────────────

/// Refine entry for **Task** blobs — anonymous, code-hash-identified
/// pure children (`vos::agent::Tasks`, `Child::Task`).
///
/// Input arrives exclusively through the witness buffer patched into
/// the initial memory image at `witness_ptr` (see [`crate::task_abi`]):
/// no `READ`, no `FETCH` — refine-pure by construction, so the live
/// invocation and a traced re-execution start from byte-identical
/// images and every Task is one `#[provable]` away from being a proof
/// guest.
///
/// Tasks are always cold: no `ACTOR_HOLDER`, no warm restart — a
/// suspended Task is its serialized state in the parent's TaskRecord,
/// and resume is a fresh invocation with that state patched back in.
/// One `(state, msg)` in, one work-result out:
///
/// 1. Decode `(state, msg)` from the witness buffer; anchor over the
///    exact state bytes (genesis when empty).
/// 2. `load_or_create::<A>(state)` and dispatch the single message
///    (effects buffer into the context — refine mode).
/// 3. Halt with the v3 `RefinePayload`: state as the final
///    `Write{STATE_KEY}` when changed, reply, effects, `continue_next`
///    from `yield_now`/`sleep`.
///
/// An unpatched buffer panics (fail loud): a Task blob is only
/// meaningful under a witness-delivering invoker — running one as a
/// registry service or bare refine is a deployment error, not a case
/// to limp through.
#[cfg(feature = "service")]
pub fn run_task_service<A: super::Actor>(witness_ptr: *const u8, witness_cap: usize) {
    use super::context::ServiceId;
    use super::lifecycle;

    crate::log_impl::install_pvm_logger();
    set_refine_mode(true);

    // SAFETY: the macro-emitted `__VOS_WITNESS` static spans exactly
    // `witness_cap` readable bytes.
    let (state, msg) = unsafe { crate::task_abi::read_task_input(witness_ptr, witness_cap) }
        .expect("task input not patched — Task blobs run only under a witness-delivering invoker");
    // SAFETY: same buffer, same bounds.
    let rows = unsafe { crate::task_abi::read_task_rows(witness_ptr, witness_cap) }
        .expect("task witness rows section malformed");
    // Always seed — even empty. A Task has no live storage (STORAGE_R
    // is an echo stub under the task hostcall table), so an
    // unwitnessed handle read must panic as unproven, never misread
    // the stub.
    super::storage::seed_witness_rows(rows.into_iter().collect());

    let (anchor_kind, anchor) = crate::refine_payload::anchor_for(Some(&state));
    let mut actor = lifecycle::load_or_create::<A>(Some(&state));
    let mut ctx = super::Context::new(ServiceId(0));

    let _ = lifecycle::dispatch_one::<A>(&msg, &mut actor, &mut ctx);

    let new_state_bytes = super::codec::Encode::encode(&actor);
    let reply_bytes = ctx.take_reply_bytes();
    let new_hash = crate::refine_payload::state_anchor(&new_state_bytes);
    let state_changed =
        anchor_kind == crate::refine_payload::ANCHOR_GENESIS || new_hash != anchor;
    let payload = ctx.drain_into_refine_payload(
        anchor_kind,
        anchor,
        super::storage::end_dispatch(),
        state_changed.then_some(new_state_bytes),
        reply_bytes,
    );
    // Provable-Task io-binding (work-result-contract.md §5): the framework
    // — not the handler — composes the io-hash, over the state TRANSITION.
    //   public' = folded_public(anchor_kind, anchor, transition_digest, app_public)
    //   io_hash = H(public', reply)
    // So a Task's proof commits to the anchored input state and the exact
    // applied effects (via the transition digest), plus any app-level
    // public bytes the handler designated with `vos::zk::bind_public`, plus
    // the reply. A verifier reconstructs `public'` identically from the
    // recorded (anchor, digest, app_public) and checks the bound io-hash.
    // bind_io's finished-hash form is not honored for Task blobs — drained
    // so it can't leak — because the handler does not own the composition.
    let _ = crate::zk::__take_pending_io_hash();
    let app_public = crate::zk::__take_pending_public().unwrap_or_default();
    let transition_digest = payload.transition_digest();
    let public_prime = crate::refine_payload::folded_public(
        payload.anchor_kind,
        &payload.anchor,
        &transition_digest,
        &app_public,
    );
    let io_hash = crate::zk::compute_io_hash(&public_prime, &payload.reply);
    let encoded = payload.encode();
    halt_with_output_bound(&encoded, &io_hash);
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

    // FETCH 2+: messages
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
    // on every invocation.
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
