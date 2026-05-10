//! Tiny test helpers used across the crate's unit tests.
//!
//! Lives in its own module rather than each test file's `mod tests`
//! so the storage tests, transport tests, and worker tests share a
//! single `block_on` instead of pulling in `pollster` or `tokio` as
//! a dev-dep.

#![cfg(test)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// Drive a future to completion on the current thread. Mirrors
/// `pollster::block_on` but defined inline so the crate stays
/// dev-dep-free.
///
/// Spins between polls — fine for unit tests where the future
/// never genuinely yields (the storage / transport impls used in
/// tests resolve immediately). Real hosts use a real executor
/// (tokio::runtime, embassy's `block_on`, etc.).
pub fn block_on<F: Future>(mut fut: F) -> F::Output {
    // Safety: `fut` is owned and never moved after this point.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => {
                // The futures the worker emits in tests resolve
                // immediately; if a future genuinely needs to yield
                // (e.g. `futures_timer::Delay`), we spin until it's
                // ready. That's wasteful in production but fine for
                // the bounded test workload.
                core::hint::spin_loop();
            }
        }
    }
}

fn noop_waker() -> Waker {
    use core::task::{RawWaker, RawWakerVTable};
    static VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    // Safety: the vtable functions are all no-ops on a null
    // pointer; nothing dereferences the data field.
    unsafe { Waker::from_raw(raw) }
}
