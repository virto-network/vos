//! Cooperative single-threaded executor for PVM actor programs.
//!
//! Each `.await` point becomes a yield to the host scheduler, letting
//! other actors run. The host resumes this actor on the next tick.

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

/// Drive a future to completion, yielding to the PVM host on each `Pending`.
///
/// Every `.await` that returns `Pending` triggers a PVM yield syscall,
/// giving other actors a chance to run. When the host resumes this actor,
/// polling continues.
pub fn block_on<F: Future>(mut fut: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => yield_to_host(),
        }
    }
}

/// A future that yields once then completes.
///
/// Used after message handlers to turn each `.await` into a cooperative
/// yield point. First poll returns `Pending`, second returns `Ready`.
pub struct Yield {
    yielded: bool,
}

impl Yield {
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

/// Yield to the PVM host via the Yield syscall.
#[cfg(target_arch = "riscv64")]
fn yield_to_host() {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") 31u64, // Syscall::Yield = 31
            lateout("a0") _,
            options(nostack),
        );
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn yield_to_host() {
    // No-op on non-PVM targets (tests, host-side usage)
}
