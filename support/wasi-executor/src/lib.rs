//! WASI executor with pollable-aware I/O integration.
//!
//! This module provides an executor designed specifically for WASI environments
//! that integrates with WASI's pollable-based I/O system. It manages a registry
//! of pending pollables and provides mechanisms for both async operations and
//! synchronous bridging scenarios.
//!
//! # Context Management
//!
//! The executor uses context IDs to track which pollables belong to which execution
//! context. The main executor runs in context 0, while each `block_on` call gets
//! its own unique context ID. This ensures that `block_on` only waits on pollables
//! that were registered by the specific future being blocked on.

use embassy_executor::{Spawner, raw};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::poll_fn,
    task::{Poll, Waker},
};
use wasi::io::poll::Pollable;

// Context ID for tracking which execution context owns which pollables
const MAIN_EXECUTOR_CONTEXT: u64 = 0;

thread_local! {
    static IO: RefCell<WasiIo> = const { RefCell::new(WasiIo::new()) };
    static CURRENT_CONTEXT: RefCell<u64> = const { RefCell::new(MAIN_EXECUTOR_CONTEXT) };
    static NEXT_CONTEXT_ID: RefCell<u64> = const { RefCell::new(1) };
}

// RAII guard to manage context switching
struct ContextGuard {
    previous_context: u64,
}

impl ContextGuard {
    fn new(context_id: u64) -> Self {
        let previous_context = CURRENT_CONTEXT.with_borrow_mut(|ctx| {
            let prev = *ctx;
            *ctx = context_id;
            prev
        });
        Self { previous_context }
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        CURRENT_CONTEXT.with_borrow_mut(|ctx| *ctx = self.previous_context);
    }
}

#[unsafe(export_name = "__pender")]
fn __pender(_context: *mut ()) {
    println!("pender...")
}

pub fn run(init: impl FnOnce(Spawner)) {
    let exec = Box::leak(Box::new(raw::Executor::new(&mut ())));
    init(exec.spawner());
    loop {
        println!("...polling");
        unsafe { exec.poll() };

        // Check if we have any pollables to wait on for the main executor context
        let has_pollables = IO.with_borrow(|io| {
            io.pollables
                .values()
                .any(|(_, ctx)| *ctx == MAIN_EXECUTOR_CONTEXT)
        });

        if has_pollables {
            IO.with_borrow_mut(|io| io.wait())
        } else {
            // No pollables and executor finished polling - exit
            println!("No pollables, exiting");
            break;
        }
    }
}

pub async fn wait_pollable(pollable: &Pollable) {
    poll_fn(|cx| {
        if pollable.ready() {
            println!("pollable ready");
            return Poll::Ready(());
        }
        let context_id = CURRENT_CONTEXT.with_borrow(|ctx| *ctx);
        IO.with_borrow_mut(|io| {
            io.pollables
                .insert(pollable, (cx.waker().clone(), context_id))
        });
        Poll::Pending
    })
    .await
}

/// Block on an async operation until it completes.
///
/// This function allows synchronous code to execute async operations by polling
/// the future until completion and integrating with the WASI pollable system.
/// When a future is pending, it only processes pollables that belong to this
/// specific block_on context, avoiding interference with the main executor.
///
/// This is particularly useful for bridging sync/async boundaries, such as
/// in logging implementations that need to perform async I/O from sync contexts.
///
/// # Examples
///
/// ```rust
/// use wasi_executor::block_on;
/// use some_async_crate::async_operation;
///
/// let result = block_on(async {
///     async_operation().await
/// });
/// ```
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // Assign a unique context ID for this block_on call
    let context_id = NEXT_CONTEXT_ID.with_borrow_mut(|next_id| {
        let id = *next_id;
        *next_id += 1;
        id
    });

    // Set the current context for any pollables registered during this block_on
    let _guard = ContextGuard::new(context_id);

    // Simple no-op waker for single-threaded WASI environment
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE), // clone
        |_| {},                                       // wake
        |_| {},                                       // wake_by_ref
        |_| {},                                       // drop
    );

    let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut context = Context::from_waker(&waker);

    let mut future = std::pin::Pin::from(Box::new(future));

    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => {
                // Clean up any remaining pollables from this context
                IO.with_borrow_mut(|io| io.cleanup_context(context_id));
                return result;
            }
            Poll::Pending => {
                // Only wait on pollables that belong to this block_on context
                IO.with_borrow_mut(|io| io.wait_context(context_id));
            }
        }
    }
}

struct WasiIo {
    pollables: BTreeMap<*const Pollable, (Waker, u64)>,
}

impl WasiIo {
    const fn new() -> Self {
        Self {
            pollables: BTreeMap::new(),
        }
    }

    fn wait(&mut self) {
        self.wait_context(MAIN_EXECUTOR_CONTEXT);
    }

    fn wait_context(&mut self, context_id: u64) {
        let pollables_for_context: Vec<(*const Pollable, &Pollable)> = unsafe {
            self.pollables
                .iter()
                .filter(|(_, (_, ctx))| *ctx == context_id)
                .map(|(&ptr, _)| (ptr, &*ptr))
                .collect()
        };

        if pollables_for_context.is_empty() {
            println!("~~ no pollables to wait on for context {}", context_id);
            return;
        }

        let pollables: Vec<&Pollable> = pollables_for_context.iter().map(|(_, p)| *p).collect();
        println!("waiting {} ~~ for context {}", pollables.len(), context_id);

        let ready = wasi::io::poll::poll(pollables.as_slice());
        let len = ready.len();
        for i in ready {
            let (ptr, _) = pollables_for_context[i as usize];
            if let Some((waker, _)) = self.pollables.remove(&ptr) {
                waker.wake();
            }
        }
        println!("~~ waited {} for context {}", len, context_id);
    }

    fn cleanup_context(&mut self, context_id: u64) {
        self.pollables.retain(|_, (_, ctx)| *ctx != context_id);
    }
}
