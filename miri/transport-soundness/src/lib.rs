//! Miri soundness gate for the transport-mode `handle_connection(&self, …)`
//! model.
//!
//! The host spawns **N concurrent** connection tasks that each reconstruct
//! `&*actor_ptr` (SHARED) from the SAME `*const actor` and run a `&self`
//! handler, while the host's per-poll bookkeeping briefly reconstructs `&mut
//! WorkerState` to find each task's stable slot. The soundness rests on **three
//! disjoint allocations**: the boxed `WorkerState`, each boxed `TaskState`, and
//! the boxed actor. Because they are separate allocations, the brief `&mut
//! WorkerState` a poll takes can NOT invalidate a parked task's `&actor` (a
//! different allocation) under any borrow model.
//!
//! This crate copies the minimal `vos::actors::exec` machinery (so it builds on
//! the Miri nightly without vos's `stwo` dev-dep) and models the glue's
//! `vos_extension_conn_new` / `vos_extension_task_poll` / `vos_extension_task_drop`
//! over a shared instance, then interleaves two connection tasks. Run it under
//! both Stacked and Tree Borrows.
//!
//! Everything is exercised only from `#[cfg(test)]`, so the model fns read as
//! dead code to a plain `cargo build`.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// ── Copied exec machinery (faithful to vos/src/actors/exec.rs) ────────────

type TaskFut = Pin<Box<dyn Future<Output = Vec<u8>>>>;

/// One in-flight handler task. Boxed in the [`TaskTable`] so its address is
/// stable across slab reallocs and across the bare future poll.
struct TaskState {
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
    fn set_result(&mut self, bytes: Vec<u8>) {
        self.result = Some(bytes);
    }
    fn take_fut(&mut self) -> Option<TaskFut> {
        self.fut.take()
    }
    fn finish_ready(&mut self, reply: Vec<u8>) -> (*const u8, usize) {
        self.out = Some(reply);
        let b = self.out.as_ref().unwrap();
        (b.as_ptr(), b.len())
    }
    fn step_pending(&mut self, fut: TaskFut) -> Option<(*const u8, usize)> {
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

/// A slab of `Box<TaskState>` — storage, not scheduling. Handles are
/// `slab index + 1` (0 = "no task").
struct TaskTable {
    slots: Vec<Option<Box<TaskState>>>,
    free: Vec<usize>,
    #[allow(dead_code)]
    spawned: VecDeque<TaskFut>,
}

impl TaskTable {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            spawned: VecDeque::new(),
        }
    }
    fn install(&mut self, fut: TaskFut) -> u64 {
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
    /// Raw pointer to the boxed `TaskState` (mutable provenance, into the
    /// `TaskState`'s OWN box allocation — disjoint from `WorkerState`).
    fn ptr(&mut self, handle: u64) -> *mut TaskState {
        if handle == 0 {
            return std::ptr::null_mut();
        }
        let idx = (handle - 1) as usize;
        match self.slots.get_mut(idx) {
            Some(Some(boxed)) => std::ptr::addr_of_mut!(**boxed),
            _ => std::ptr::null_mut(),
        }
    }
    fn drop_task(&mut self, handle: u64) {
        if handle == 0 {
            return;
        }
        let idx = (handle - 1) as usize;
        if let Some(slot) = self.slots.get_mut(idx) {
            if slot.is_some() {
                *slot = None;
                self.free.push(idx);
            }
        }
    }
    fn live_tasks(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

/// Build a [`Waker`] whose data pointer is a `*mut TaskState`. All vtable ops
/// are no-ops (the task is driven manually, never woken).
fn task_waker(ts: *const ()) -> Waker {
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable functions are valid for any data pointer; the caller
    // upholds the liveness contract (ts points at a live TaskState for the poll).
    unsafe { Waker::from_raw(RawWaker::new(ts, &VTABLE)) }
}

/// The per-task host-I/O future (mirrors `Context::host_call`'s `ExecIo`): on
/// first poll it files `request` into its `TaskState` (reached via the waker)
/// and parks; on re-poll it returns the host's `result`.
struct ExecIo {
    request: Option<Vec<u8>>,
    armed: bool,
}
impl ExecIo {
    fn new(request: Vec<u8>) -> Self {
        Self {
            request: Some(request),
            armed: false,
        }
    }
}
impl Unpin for ExecIo {}
impl Future for ExecIo {
    type Output = Vec<u8>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        let data = cx.waker().data();
        if data.is_null() {
            return Poll::Pending;
        }
        // SAFETY: the waker carries a `*mut TaskState` taken from the live boxed
        // TaskState; the future was taken OUT of that TaskState before this poll
        // (so no `&mut` to it is otherwise live), and we're single-threaded.
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

// ── Shared-actor instance model ───────────────────────────────────────────

/// The actor. Interior mutability via `RefCell` (a transport actor is shared
/// `&self` across concurrent conn tasks — single-threaded, no `Mutex`/`Arc`).
struct Actor {
    hits: RefCell<u64>,
}

/// The `.so` instance state. Field order matters: `tasks` is declared BEFORE
/// `actor`, so on `Drop` the slab (all parked futures, each holding `&actor`)
/// is dropped before the actor box — the "futures-before-actor" guarantee. The
/// actor is BOXED: `&*actor` points into the actor's own allocation, disjoint
/// from this `WorkerState` and from every `TaskState` box.
struct WorkerState {
    tasks: TaskTable,
    actor: Box<Actor>,
}

/// The handler — `&self` (shared), held across each `.await`, exactly like a
/// real `handle_connection`. Each "read" parks via `ExecIo`; between reads it
/// mutates shared state through the shared ref + `RefCell`.
async fn handle_connection(actor: &Actor, reads: u64) {
    for _ in 0..reads {
        let _ = ExecIo::new(b"read".to_vec()).await;
        *actor.hits.borrow_mut() += 1;
    }
}

/// A buggy handler that holds a `RefCell` borrow ACROSS an await — the
/// documented hazard. Under interleaving a second task's `borrow_mut`
/// panics (a runtime panic, NOT UB).
async fn handle_connection_holds_borrow(actor: &Actor) {
    let mut guard = actor.hits.borrow_mut();
    let _ = ExecIo::new(b"read".to_vec()).await;
    *guard += 1;
}

/// Mirror of the glue's `vos_extension_conn_new`: capture a SHARED `*const
/// Actor` into the actor's own box, build the `handle_connection` future, and
/// install it into the slab. The `&mut WorkerState` borrow ends when this
/// returns; the future holds only the raw `*const Actor`.
fn conn_new(state: *mut (), reads: u64) -> u64 {
    // SAFETY: `state` is a live `*mut WorkerState` on this thread.
    let ws = unsafe { &mut *(state as *mut WorkerState) };
    // SHARED `*const` into the actor's OWN box (disjoint from WorkerState) —
    // matches `&*ws.actor as *const $actor_name` in the real glue.
    let actor_ptr = &*ws.actor as *const Actor;
    let fut: TaskFut = Box::pin(async move {
        // SAFETY: shared (&), single-threaded, no `&mut Actor` exists for a
        // transport instance; the actor outlives every conn task.
        let actor = unsafe { &*actor_ptr };
        handle_connection(actor, reads).await;
        Vec::new()
    });
    ws.tasks.install(fut)
}

/// Like `conn_new` but builds the borrow-across-await handler (negative test).
fn conn_new_bad(state: *mut ()) -> u64 {
    let ws = unsafe { &mut *(state as *mut WorkerState) };
    let actor_ptr = &*ws.actor as *const Actor;
    let fut: TaskFut = Box::pin(async move {
        let actor = unsafe { &*actor_ptr };
        handle_connection_holds_borrow(actor).await;
        Vec::new()
    });
    ws.tasks.install(fut)
}

#[derive(Debug, PartialEq)]
enum Step {
    Ready,
    Pending,
    Panic,
}

/// Mirror of the glue's `vos_extension_task_poll` driven by `SharedInstance`
/// (`&self`, raw `state`): reconstruct `&mut WorkerState` ONLY to find the
/// stable `*mut TaskState` + inject `result`, DROP that borrow, then poll the
/// bare future. No `&mut WorkerState` is live across the poll — so a parked
/// sibling task's `&actor` (a disjoint allocation) is untouched.
fn task_poll(state: *mut (), handle: u64, result: &[u8]) -> Step {
    let ts_ptr = {
        // SAFETY: live `*mut WorkerState`; the borrow is confined to this block.
        let ws = unsafe { &mut *(state as *mut WorkerState) };
        let p = ws.tasks.ptr(handle);
        if p.is_null() {
            return Step::Panic;
        }
        // SAFETY: p is a live boxed TaskState; no other borrow of it is held.
        unsafe { (*p).set_result(result.to_vec()) };
        p
    }; // <- &mut WorkerState dropped here, BEFORE the bare poll
    loop {
        let mut fut = match unsafe { (*ts_ptr).take_fut() } {
            Some(f) => f,
            None => return Step::Panic,
        };
        let waker = task_waker(ts_ptr as *const ());
        let mut cx = Context::from_waker(&waker);
        let polled =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.as_mut().poll(&mut cx)));
        match polled {
            Ok(Poll::Ready(reply)) => {
                let _ = unsafe { (*ts_ptr).finish_ready(reply) };
                return Step::Ready;
            }
            Ok(Poll::Pending) => match unsafe { (*ts_ptr).step_pending(fut) } {
                Some(_) => return Step::Pending,
                None => continue, // bare cooperative yield — re-poll
            },
            Err(_) => return Step::Panic, // `fut` dropped here
        }
    }
}

fn drop_task(state: *mut (), handle: u64) {
    let ws = unsafe { &mut *(state as *mut WorkerState) };
    ws.tasks.drop_task(handle);
}

/// Allocate a boxed `WorkerState` and return a `*mut ()` to it (mirrors
/// `create_state`). The caller frees it via `drop_state`.
fn create_state() -> *mut () {
    let ws = Box::new(WorkerState {
        tasks: TaskTable::new(),
        actor: Box::new(Actor {
            hits: RefCell::new(0),
        }),
    });
    Box::into_raw(ws) as *mut ()
}

/// Free a `WorkerState` previously created by `create_state` (mirrors
/// `drop_state`). Dropping it drops `tasks` (every parked future, each holding
/// `&actor`) BEFORE the actor box.
unsafe fn drop_state(state: *mut ()) {
    drop(unsafe { Box::from_raw(state as *mut WorkerState) });
}

// ── Tests (the Miri gate) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The core gate: two connection tasks, each reconstructing
    /// `&*actor_ptr` from the SAME `*const Actor` and mutating the shared
    /// `RefCell`, interleaved step-by-step — task A is parked (holding `&actor`
    /// across its await) while task B is polled (reconstructing `&mut
    /// WorkerState` to find its slot, then its own `&actor`), and vice-versa.
    /// Clean under both Stacked and Tree Borrows iff the three allocations
    /// (WorkerState / each TaskState box / the actor box) are disjoint, so the
    /// boxed actor is reached only through the shared-`&self` access.
    #[test]
    fn two_conn_tasks_interleave_sharing_actor() {
        let state = create_state();

        const READS: u64 = 3;
        let a = conn_new(state, READS);
        let b = conn_new(state, READS);
        assert_ne!(a, 0);
        assert_ne!(b, 0);

        // Prime both: first poll files the read request and parks (each future
        // now holds its own `&actor` in its suspended state).
        assert_eq!(task_poll(state, a, &[]), Step::Pending);
        assert_eq!(task_poll(state, b, &[]), Step::Pending);

        // Drive both to completion, round-robin. Each step feeds a read result to
        // A, then to B — so when A re-parks (Pending) with B not yet done, BOTH
        // are parked at the same instant, each holding its own `&actor`: genuine
        // interleaving, the soundness surface. (`a_parked_while_b_live` records
        // having observed both simultaneously parked.)
        let mut a_done = false;
        let mut b_done = false;
        let mut interleaved = false;
        for _ in 0..(2 * READS + 4) {
            if !a_done {
                match task_poll(state, a, b"ok") {
                    Step::Pending => {
                        if !b_done {
                            interleaved = true; // A re-parked while B is also parked
                        }
                    }
                    Step::Ready => {
                        drop_task(state, a);
                        a_done = true;
                    }
                    Step::Panic => panic!("conn task a panicked"),
                }
            }
            if !b_done {
                match task_poll(state, b, b"ok") {
                    Step::Pending => {
                        if !a_done {
                            interleaved = true;
                        }
                    }
                    Step::Ready => {
                        drop_task(state, b);
                        b_done = true;
                    }
                    Step::Panic => panic!("conn task b panicked"),
                }
            }
            if a_done && b_done {
                break;
            }
        }
        assert!(a_done && b_done, "both conn tasks must complete");
        assert!(
            interleaved,
            "tasks must genuinely interleave (both parked, sharing the actor, at once)"
        );

        // Shared actor saw EVERY mutation from BOTH tasks — no lost update, no
        // aliasing corruption. (An aliasing/UB bug could drop or double writes.)
        // SAFETY: state is still live (not yet dropped).
        let ws = unsafe { &*(state as *const WorkerState) };
        assert_eq!(*ws.actor.hits.borrow(), 2 * READS);
        assert_eq!(ws.tasks.live_tasks(), 0);

        unsafe { drop_state(state) };
    }

    /// Drop-ordering gate: drop the instance while TWO conn tasks are still
    /// PARKED (each holding `&actor`). `drop_state` drops `tasks` (the futures,
    /// releasing their `&actor` — a no-op, references have no Drop) BEFORE the
    /// actor box. Mirrors the host's `drop(ex)`-before-`drop_state` shutdown:
    /// no parked task's `&actor` is ever dereferenced after the actor is freed,
    /// so there is no use-after-free. Miri's allocator + borrow tracker prove it.
    #[test]
    fn drop_state_frees_parked_tasks_before_actor_no_uaf() {
        let state = create_state();
        let a = conn_new(state, 5);
        let b = conn_new(state, 5);
        // Park both (each now holds `&actor` in its suspended state).
        assert_eq!(task_poll(state, a, &[]), Step::Pending);
        assert_eq!(task_poll(state, b, &[]), Step::Pending);
        // Drop the whole instance with both tasks mid-flight. The futures drop
        // (releasing `&actor`) before the actor box drops. No UAF, no leak.
        unsafe { drop_state(state) };
    }

    /// Negative gate: a `handle_connection` that holds a `RefCell` borrow ACROSS
    /// an await is a documented hazard. Under interleaving, task A parks
    /// holding the borrow; task B's `borrow_mut` then PANICS at runtime
    /// (`already borrowed`) — caught by the per-poll `catch_unwind`, surfaced as
    /// `Step::Panic`. This is a clean panic, NOT undefined behaviour: Miri stays
    /// happy, and the host would drop the panicked conn task.
    #[test]
    fn refcell_borrow_held_across_await_panics_not_ub() {
        let state = create_state();
        let a = conn_new_bad(state);
        let b = conn_new_bad(state);

        // A: first poll takes `borrow_mut`, parks holding the guard across await.
        assert_eq!(task_poll(state, a, &[]), Step::Pending);
        // B: first poll tries `borrow_mut` while A's borrow is live → panic,
        // caught and surfaced as Panic (not UB).
        assert_eq!(task_poll(state, b, &[]), Step::Panic);
        drop_task(state, b);

        // Resume A to completion so nothing leaks (its borrow releases on the
        // final mutate + return).
        assert_eq!(task_poll(state, a, b"ok"), Step::Ready);
        drop_task(state, a);

        unsafe { drop_state(state) };
    }
}
