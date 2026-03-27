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

/// Drive a future to completion, yielding to the PVM host on each `Pending`.
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

/// Yield to the PVM host via the Yield hostcall.
#[cfg(target_arch = "riscv64")]
fn yield_to_host() {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") vos_abi::hostcall::YIELD as u64,
            lateout("a0") _,
            options(nostack),
        );
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn yield_to_host() {
    // No-op on non-PVM targets (tests, host-side usage)
}

/// Recv buffer size for the standard actor message loop.
#[cfg(feature = "guest")]
const RECV_BUF_SIZE: usize = 4096;

/// Standard actor lifecycle for JAR-aligned execution.
///
/// Per invocation:
/// 1. Try loading existing state from storage via `read()`
/// 2. If no state, receive init payload and construct fresh actor
/// 3. Process pending items (transfers)
/// 4. Persist state via `write()` and halt
///
/// For now (Phase 1), preserves the yield-recv loop to keep existing
/// tests and examples working. Phase 2 will switch to the full
/// storage-based model.
#[cfg(feature = "guest")]
pub fn main_loop<A: crate::Actor>(
    init: impl FnOnce(&[u8]) -> A,
    dispatch: impl Fn(&[u8], &mut A, &mut crate::Context<A>),
) {
    use vos_abi::guest::hostcalls;
    use vos_abi::hostcall;
    use vos_abi::guest::ecall;

    let self_id = hostcalls::info() as u32;
    let mut ctx = crate::Context::new(crate::context::ServiceId(self_id));

    let mut buf = [0u8; RECV_BUF_SIZE];

    // Wait for constructor message — yield then check for incoming transfer
    let mut actor = loop {
        // Yield to let the host deliver work
        ecall::ecall0(hostcall::YIELD);
        // Try to receive via FETCH (check for pending items)
        let n = ecall::ecall2(hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
        if n > 0 && n < RECV_BUF_SIZE as u64 {
            let payload = &buf[..n as usize];
            break init(payload);
        }
    };

    // Message loop — process incoming items
    loop {
        ecall::ecall0(hostcall::YIELD);
        let n = ecall::ecall2(hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64);
        if n > 0 && n < RECV_BUF_SIZE as u64 {
            let payload = &buf[..n as usize];
            dispatch(payload, &mut actor, &mut ctx);
        }
        if ctx.stop_requested() {
            break;
        }
    }
}
