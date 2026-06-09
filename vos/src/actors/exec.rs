//! Per-task future machinery for native extensions.
//!
//! This module lives **inside** the extension `.so` (the `vos` crate is
//! `no_std + alloc` in an extension build, so it uses only `core` + `alloc` —
//! no `std`, no `thread_local`, no `catch_unwind`). The **scheduler lives
//! host-side** (`smol::LocalExecutor` in `node.rs`): the host owns *when* each
//! task runs. This module owns only the irreducible per-task machinery the host
//! cannot touch across the FFI:
//!
//! - [`TaskState`] — one handler future plus its request / result / out byte
//!   slots. Boxed in the [`TaskTable`] so its address is stable (the host
//!   reaches it by a `*mut TaskState` raw pointer; slab reallocs never move it).
//! - [`ExecIo`] — the host-I/O future. It reaches *its own* [`TaskState`] via
//!   the task [`Waker`]'s data pointer ([`task_waker`]); no TLS, no static.
//! - [`TaskTable`] — a slab of `Box<TaskState>`. **Storage, not scheduling**:
//!   install a future, look up its stable pointer, drop it. No ready queue, no
//!   parked map — the host's executor decides what runs next.
//!
//! ## Why the host can't poll a `.so` future directly
//!
//! A `dyn Future` is a `(data, vtable)` fat pointer, and `dyn Trait` vtable
//! layout is **not** a stable ABI across separately-compiled artifacts. So the
//! host must never `.poll()` a `.so`-built future itself — it calls the
//! `extern "C" vos_extension_task_poll` the `.so` exports, which polls using
//! its own vtable. That C function (emitted by the glue in the user crate,
//! which *has* `std`) wraps each bare poll in a `catch_unwind` and drives the
//! per-task state via the small `TaskState` methods below.
//!
//! ## The across-poll aliasing discipline (load-bearing — see also the glue)
//!
//! `ExecIo::poll` reconstructs `&mut *(*mut TaskState)` from the waker, and the
//! handler future reconstructs `&mut *actor_ptr` from a raw pointer captured at
//! task-build time. For this to be sound, the C `task_poll` glue MUST hold **no**
//! Rust reference (`&` or `&mut`) to the `WorkerState`, the `TaskTable` slab, or
//! the `Box<TaskState>` across the bare `fut.poll(cx)` — only raw pointers may be
//! live, and the future is *taken out* of the slot ([`TaskState::take_fut`])
//! before the poll so no `&mut` to it is alive either. Because the actor and
//! each `TaskState` are boxed (own allocations, disjoint from `WorkerState`),
//! the brief `&mut WorkerState` the glue uses to *find* the slot cannot alias
//! those raw pointers under any borrow model.
//!
//! ## v1 simplification
//!
//! One outstanding host-I/O op per task (linear `await`-one-then-the-next).
//! `join!`-ing two host-I/O futures in one task is unsupported in v1; concurrency
//! comes from *separate* tasks the host runs on its executor.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Poll, RawWaker, RawWakerVTable, Waker};

/// A task's future. Output is the reply bytes (empty for spawned tasks), so the
/// non-generic per-task machinery never has to touch the generic per-task
/// `Context` to extract a reply — the glue's future builder does
/// `ctx.take_reply_bytes()` as its tail.
pub type TaskFut = Pin<Box<dyn Future<Output = Vec<u8>>>>;

/// One in-flight handler task. Boxed in the [`TaskTable`] so its address is
/// stable: the host reaches it by a raw `*mut TaskState` that must survive slab
/// reallocs and stay valid across the bare future poll.
///
/// The four byte slots split cleanly by direction:
/// - `request`: written by [`ExecIo`] on its first poll (the effect the handler
///   wants the host to fulfil); read out by [`TaskState::step_pending`].
/// - `result`: written by the glue before each poll (the host's fulfilment of
///   the previous request); consumed by [`ExecIo`] on its re-poll.
/// - `out`: the **stable buffer** a `TaskPoll.ptr` points at — the completed
///   reply (TASK_READY) or a moved-out copy of `request` (TASK_PENDING). Valid
///   until the next `task_poll` / `task_drop` on this state; the host copies it
///   immediately. Kept distinct from `result` (which `ExecIo` consumes) so a
///   re-poll can never `take()` the bytes out from under a returned pointer.
pub struct TaskState {
    fut: Option<TaskFut>,
    request: Option<Vec<u8>>,
    result: Option<Vec<u8>>,
    out: Option<Vec<u8>>,
}

impl TaskState {
    fn new(fut: TaskFut) -> Self {
        Self {
            fut: Some(fut),
            request: None,
            result: None,
            out: None,
        }
    }

    /// Install the host's fulfilment of the previous `TASK_PENDING` (empty on
    /// the first poll). Consumed by [`ExecIo`] on its re-poll.
    pub fn set_result(&mut self, bytes: Vec<u8>) {
        self.result = Some(bytes);
    }

    /// Take the future out so it can be polled with **no** `&mut` to this
    /// `TaskState` alive (the waker hands `ExecIo` the only live `&mut`). Returns
    /// `None` if the future was already consumed (completed/panicked) — a buggy
    /// double-poll, surfaced as `TASK_PANIC` rather than UB.
    pub fn take_fut(&mut self) -> Option<TaskFut> {
        self.fut.take()
    }

    /// File a completed reply into the stable `out` slot and return its pointer
    /// for the `TaskPoll`. The future is **not** put back (it finished), so the
    /// caller drops it.
    pub fn finish_ready(&mut self, reply: Vec<u8>) -> (*const u8, usize) {
        self.out = Some(reply);
        let b = self.out.as_ref().unwrap();
        (b.as_ptr(), b.len())
    }

    /// Hand the still-pending future back and decide what the host should do:
    /// - `Some(ptr,len)` — the handler filed a host-I/O `request`; it is moved
    ///   into the stable `out` slot and its pointer returned (`TASK_PENDING`).
    /// - `None` — no request was filed this poll (a bare cooperative yield); the
    ///   glue re-polls without involving the host.
    ///
    /// Moving `request` → `out` means the returned pointer never aliases the
    /// `request` slot while [`ExecIo`] might still touch it.
    pub fn step_pending(&mut self, fut: TaskFut) -> Option<(*const u8, usize)> {
        self.fut = Some(fut);
        match self.request.take() {
            Some(req) => {
                self.out = Some(req);
                let b = self.out.as_ref().unwrap();
                Some((b.as_ptr(), b.len()))
            }
            None => None,
        }
    }
}

/// A slab of `Box<TaskState>` — **storage, not scheduling**. One per extension
/// instance (lives in the glue's `WorkerState`); never shared across threads.
///
/// Handles are `slab index + 1`, so `0` is reserved for "no task" (the
/// `vos_extension_task_new` "couldn't build a handler" sentinel and the
/// `vos_extension_take_spawned` "nothing spawned" sentinel).
pub struct TaskTable {
    slots: Vec<Option<Box<TaskState>>>,
    free: Vec<usize>,
    /// Futures spawned by a running task (`ctx.spawn_task`), drained by the
    /// host via `vos_extension_take_spawned`. Currently never populated (no
    /// `ctx.spawn_task` yet).
    spawned: VecDeque<TaskFut>,
}

impl Default for TaskTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskTable {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            spawned: VecDeque::new(),
        }
    }

    /// Box a freshly-built future into a free (or new) slot. Returns its stable
    /// handle (`index + 1`, never `0`).
    pub fn install(&mut self, fut: TaskFut) -> u64 {
        let ts = Box::new(TaskState::new(fut));
        let idx = if let Some(i) = self.free.pop() {
            self.slots[i] = Some(ts);
            i
        } else {
            self.slots.push(Some(ts));
            self.slots.len() - 1
        };
        (idx as u64) + 1
    }

    /// Raw pointer to the boxed `TaskState` for `handle`, or null if the handle
    /// is `0` / out of range / already dropped. **Mutable provenance**: derived
    /// from a `&mut Box<TaskState>` so the glue may write through it. The caller
    /// must drop every borrow of `self` before using the pointer across a poll.
    pub fn ptr(&mut self, handle: u64) -> *mut TaskState {
        if handle == 0 {
            return core::ptr::null_mut();
        }
        let idx = (handle - 1) as usize;
        match self.slots.get_mut(idx) {
            Some(Some(boxed)) => core::ptr::addr_of_mut!(**boxed),
            _ => core::ptr::null_mut(),
        }
    }

    /// Drop the future + free the slot. A `0` / absent / double handle is a
    /// no-op (never UB on a bad handle from a buggy host).
    pub fn drop_task(&mut self, handle: u64) {
        if handle == 0 {
            return;
        }
        let idx = (handle - 1) as usize;
        if let Some(slot) = self.slots.get_mut(idx)
            && slot.is_some()
        {
            *slot = None;
            self.free.push(idx);
        }
    }

    /// Enqueue a spawned (fire-and-forget) child future. Drained by
    /// [`TaskTable::take_spawned`]. Currently unused (no `ctx.spawn_task` yet);
    /// kept so the ABI surface is complete and unit-testable now.
    pub fn push_spawned(&mut self, fut: TaskFut) {
        self.spawned.push_back(fut);
    }

    /// Install the next spawned child (FIFO) into the slab and return its handle,
    /// or `0` if none are queued. The host wraps the returned handle in its own
    /// `run_ext_task`.
    pub fn take_spawned(&mut self) -> u64 {
        match self.spawned.pop_front() {
            Some(fut) => self.install(fut),
            None => 0,
        }
    }

    /// Drop every task + queued spawn. Called by `vos_extension_drop` before the
    /// actor is freed, so no future can be polled after the actor is gone.
    /// Dropping a future never polls it, so a captured actor pointer is merely
    /// released, not dereferenced.
    pub fn clear(&mut self) {
        self.slots.clear();
        self.free.clear();
        self.spawned.clear();
    }

    /// Test/inspection: number of live tasks.
    #[cfg(test)]
    fn live_tasks(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

// ── The waker that carries `*mut TaskState` to ExecIo ─────────────────

/// Build a [`Waker`] whose data pointer is `ts` (a `*mut TaskState` cast to
/// `*const ()`). The glue rebuilds this every poll from the live, boxed
/// `TaskState`. All vtable ops are no-ops: the task is driven manually by the
/// host (never woken via the waker), so clone preserves the pointer and
/// wake/drop do nothing.
///
/// # Safety
/// `ts` must point at a live `TaskState` for the duration of the poll that uses
/// the returned waker, and the caller must hold no other reference to that
/// `TaskState` (or its enclosing `WorkerState`) across that poll.
pub fn task_waker(ts: *const ()) -> Waker {
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable's functions are valid for any data pointer (clone just
    // re-wraps it; the rest are no-ops). The caller upholds the liveness
    // contract documented above.
    unsafe { Waker::from_raw(RawWaker::new(ts, &VTABLE)) }
}

// ── The worker-mode host-I/O future ───────────────────────────────────

/// The future returned by `Context::host_call` in an extension build. It carries
/// the request bytes; on its first poll it moves them into its [`TaskState`]'s
/// `request` slot (reached via the task waker) and parks; on its re-poll it
/// returns the host-provided `result` once available. Used on the extension
/// path; the single-slot `HostIo` is still used for the WASM / plain-host
/// builds, which are single-task.
pub struct ExecIo {
    request: Option<Vec<u8>>,
    /// `false` until the first poll has filed `request`; thereafter the future
    /// is waiting for `result`. Mirrors the linear one-op-per-task model.
    armed: bool,
}

impl ExecIo {
    /// Construct from the pre-encoded effect-request bytes.
    pub fn new(request: Vec<u8>) -> Self {
        Self {
            request: Some(request),
            armed: false,
        }
    }
}

impl Unpin for ExecIo {}

impl Future for ExecIo {
    type Output = Vec<u8>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Vec<u8>> {
        let data = cx.waker().data();
        if data.is_null() {
            // Polled outside the executor (e.g. `run_blocking(on_start)` uses the
            // noop waker, whose data is null). No TaskState to talk to → stay
            // Pending; `run_blocking` turns that into the same "handler yielded"
            // panic as before, instead of dereferencing null. (Guard FIRST, before any
            // cast, so a null waker-data pointer is never dereferenced.)
            return Poll::Pending;
        }
        // SAFETY: the glue builds the task waker with data set to a `*mut
        // TaskState` taken from the live, boxed `TaskState`, and holds no other
        // reference to that state (or its `WorkerState`) across this poll.
        // Single-threaded, so this is the only live reference for the call.
        let ts = unsafe { &mut *(data as *mut TaskState) };
        if !self.armed {
            ts.request = Some(self.request.take().unwrap_or_default());
            self.armed = true;
            Poll::Pending
        } else {
            match ts.result.take() {
                Some(r) => Poll::Ready(r),
                None => Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror the glue's `vos_extension_task_poll`: inject `result`, then loop
    /// polling the bare future under `catch_unwind` (handling bare cooperative
    /// yields internally) until the task is READY / PENDING / PANIC. Drives the
    /// real `TaskState` methods + `ExecIo` + `task_waker`, so it exercises the
    /// exact field-logic the glue uses (the glue adds only the FFI marshalling).
    enum Step {
        Ready(Vec<u8>),
        Pending(Vec<u8>),
        Panic,
    }

    fn task_poll(table: &mut TaskTable, handle: u64, result: &[u8]) -> Step {
        // Find the stable pointer, then drop the table borrow before polling.
        let ts_ptr = table.ptr(handle);
        if ts_ptr.is_null() {
            return Step::Panic;
        }
        // SAFETY (test mirror of the glue contract): ts_ptr points at a live,
        // boxed TaskState; no borrow of `table` is held across the poll below.
        unsafe { (*ts_ptr).set_result(result.to_vec()) };
        loop {
            let mut fut = match unsafe { (*ts_ptr).take_fut() } {
                Some(f) => f,
                None => return Step::Panic,
            };
            let waker = task_waker(ts_ptr as *const ());
            let mut cx = core::task::Context::from_waker(&waker);
            let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fut.as_mut().poll(&mut cx)
            }));
            match polled {
                Ok(Poll::Ready(reply)) => {
                    let (p, l) = unsafe { (*ts_ptr).finish_ready(reply) };
                    let bytes = unsafe { core::slice::from_raw_parts(p, l) }.to_vec();
                    return Step::Ready(bytes);
                }
                Ok(Poll::Pending) => match unsafe { (*ts_ptr).step_pending(fut) } {
                    Some((p, l)) => {
                        let req = unsafe { core::slice::from_raw_parts(p, l) }.to_vec();
                        return Step::Pending(req);
                    }
                    None => continue, // bare cooperative yield — re-poll
                },
                Err(_) => return Step::Panic,
            }
        }
    }

    /// Drive a single task to completion, fulfilling each PENDING via `responder`.
    fn drive(
        table: &mut TaskTable,
        handle: u64,
        mut responder: impl FnMut(&[u8]) -> Vec<u8>,
    ) -> (&'static str, Vec<u8>) {
        let mut result = Vec::new();
        loop {
            match task_poll(table, handle, &result) {
                Step::Ready(r) => {
                    table.drop_task(handle);
                    return ("done", r);
                }
                Step::Panic => {
                    table.drop_task(handle);
                    return ("err", Vec::new());
                }
                Step::Pending(req) => result = responder(&req),
            }
        }
    }

    #[test]
    fn single_task_completes_without_io() {
        let mut table = TaskTable::new();
        let h = table.install(Box::pin(async { b"hello".to_vec() }));
        let (kind, reply) = drive(&mut table, h, |_| Vec::new());
        assert_eq!(kind, "done");
        assert_eq!(reply, b"hello");
        assert_eq!(table.live_tasks(), 0);
    }

    #[test]
    fn task_parks_on_one_op_then_provide_wakes_it() {
        let mut table = TaskTable::new();
        let h = table.install(Box::pin(async {
            let got = ExecIo::new(b"REQ".to_vec()).await;
            let mut out = b"got:".to_vec();
            out.extend_from_slice(&got);
            out
        }));
        let mut seen_req = Vec::new();
        let (kind, reply) = drive(&mut table, h, |eff| {
            seen_req = eff.to_vec();
            b"RES".to_vec()
        });
        assert_eq!(seen_req, b"REQ");
        assert_eq!(kind, "done");
        assert_eq!(reply, b"got:RES");
        assert_eq!(table.live_tasks(), 0);
    }

    #[test]
    fn two_sequential_ops_in_one_task() {
        let mut table = TaskTable::new();
        let h = table.install(Box::pin(async {
            let a = ExecIo::new(b"a".to_vec()).await;
            let b = ExecIo::new(b"b".to_vec()).await;
            let mut out = a;
            out.extend_from_slice(&b);
            out
        }));
        // Echo each request back uppercased so we can tell them apart.
        let (kind, reply) = drive(&mut table, h, |eff| eff.to_ascii_uppercase());
        assert_eq!(kind, "done");
        assert_eq!(reply, b"AB");
        assert_eq!(table.live_tasks(), 0);
    }

    #[test]
    fn panicking_task_surfaces_panic_without_killing_a_sibling() {
        let mut table = TaskTable::new();
        // Task A panics; task B (a separate slab slot) completes normally —
        // proving the per-task catch_unwind isolates failures.
        let a = table.install(Box::pin(async { panic!("boom") }));
        let b = table.install(Box::pin(async { b"ok".to_vec() }));

        let (ka, _) = drive(&mut table, a, |_| Vec::new());
        let (kb, rb) = drive(&mut table, b, |_| Vec::new());
        assert_eq!(ka, "err", "panicking task should surface PANIC");
        assert_eq!(kb, "done");
        assert_eq!(rb, b"ok", "sibling task unaffected");
        assert_eq!(table.live_tasks(), 0);
    }

    #[test]
    fn absent_handle_is_panic_not_ub() {
        let mut table = TaskTable::new();
        // Never-installed handle, and handle 0, both return PANIC defensively.
        assert!(matches!(task_poll(&mut table, 42, &[]), Step::Panic));
        assert!(matches!(task_poll(&mut table, 0, &[]), Step::Panic));
        // Double-drop is a no-op.
        table.drop_task(42);
        table.drop_task(0);
    }

    #[test]
    fn spawned_task_installs_and_runs() {
        // The spawn mechanism: a future pushed to the spawn queue is
        // drained into the slab by take_spawned and runs like any root task.
        let mut table = TaskTable::new();
        table.push_spawned(Box::pin(async {
            let _ = ExecIo::new(b"child".to_vec()).await;
            b"child-done".to_vec()
        }));
        let h = table.take_spawned();
        assert_ne!(h, 0, "a queued spawn yields a handle");
        let mut seen = Vec::new();
        let (kind, reply) = drive(&mut table, h, |eff| {
            seen = eff.to_vec();
            Vec::new()
        });
        assert_eq!(seen, b"child");
        assert_eq!(kind, "done");
        assert_eq!(reply, b"child-done");
        assert_eq!(table.take_spawned(), 0, "queue is now empty");
        assert_eq!(table.live_tasks(), 0);
    }

    #[test]
    fn handles_are_nonzero_and_reused_after_drop() {
        let mut table = TaskTable::new();
        let h1 = table.install(Box::pin(async { Vec::new() }));
        assert_ne!(h1, 0);
        table.drop_task(h1);
        // Freed slot is reused; still non-zero.
        let h2 = table.install(Box::pin(async { Vec::new() }));
        assert_eq!(h1, h2, "freed slab index is reused");
        assert_ne!(h2, 0);
        table.drop_task(h2);
        assert_eq!(table.live_tasks(), 0);
    }
}
