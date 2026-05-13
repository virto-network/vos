//! POSIX signal → graceful daemon shutdown.
//!
//! `vosx space up` blocks on `node.run_forever()` until something
//! flips the node's shutdown flag. In a container the natural
//! "stop" signal is SIGTERM (`docker stop`, k8s preStop); from a
//! tty it's SIGINT (Ctrl-C). Without a handler the daemon ignores
//! both and the supervisor falls back to SIGKILL — losing
//! in-flight commits, leaking the endpoint file, dropping
//! agent state mid-tick.
//!
//! Wire shape:
//!
//! 1. Caller installs handlers with `install(node.shutdown_handle())`
//!    before `run_forever`.
//! 2. The handler is async-signal-safe: a single
//!    `AtomicBool::store(true, Relaxed)` through a raw pointer
//!    captured from a leaked `Arc`. No allocator calls, no locks.
//! 3. `run_forever`'s 50 ms poll sees the flag flip on the next
//!    tick and exits its loop. The function returns to `space up`
//!    which then collects agent results, deletes the endpoint
//!    file, and exits 0.
//!
//! Linux/macOS only — Windows isn't a deployment target today.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// Stable global pointer to the daemon's shutdown flag. Set once
/// by [`install`]; the signal handler loads from it. `Acquire` /
/// `Release` ordering pairs the install-time write with the
/// signal-time read.
static SHUTDOWN_FLAG: AtomicPtr<AtomicBool> = AtomicPtr::new(std::ptr::null_mut());

/// Idempotency guard. Once true, subsequent `install` calls are
/// no-ops. Daemons only run one `run_forever`, but tests that
/// instantiate multiple nodes in-process would otherwise reset
/// the pointer mid-shutdown.
static HANDLERS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install SIGINT + SIGTERM handlers that flip the supplied
/// shutdown flag. Idempotent: subsequent calls are no-ops.
///
/// The handler is async-signal-safe — it dereferences a raw
/// pointer to an `AtomicBool` (always non-null after the first
/// successful install, because we leak the `Arc` to give the
/// pointer `'static` lifetime) and performs one atomic store.
/// No allocation, no locking, no library calls beyond
/// `AtomicPtr::load` and `AtomicBool::store`.
pub fn install(flag: Arc<AtomicBool>) {
    if HANDLERS_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    // Leak the Arc to give the AtomicBool 'static lifetime. The
    // daemon process owns it until termination; reclaiming it
    // would race with the signal handler.
    let leaked: *mut AtomicBool = Arc::into_raw(flag) as *mut AtomicBool;
    SHUTDOWN_FLAG.store(leaked, Ordering::Release);

    #[cfg(unix)]
    unsafe {
        // SAFETY: libc::signal is the POSIX way to set a signal
        // handler. Our handler is async-signal-safe (one atomic
        // store, no other work). We ignore the previous handler;
        // the daemon doesn't chain signal handlers.
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
    }
}

#[cfg(unix)]
extern "C" fn signal_handler(_signum: libc::c_int) {
    // SAFETY: After `install`, SHUTDOWN_FLAG points at a leaked
    // AtomicBool that lives for the rest of the process. The
    // initial null is guarded explicitly. AtomicBool::store is
    // a single atomic op — async-signal-safe.
    let ptr = SHUTDOWN_FLAG.load(Ordering::Acquire);
    if !ptr.is_null() {
        unsafe {
            (*ptr).store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signal handler stores into the leaked AtomicBool, and the
    /// install path tolerates a second call without panicking or
    /// changing the pointer.
    #[test]
    fn install_is_idempotent_and_flips_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        install(flag.clone());
        install(flag.clone()); // no-op

        // Drive the handler directly; can't SIGTERM the test
        // runner without flaking the whole suite.
        #[cfg(unix)]
        signal_handler(libc::SIGTERM);

        assert!(
            flag.load(Ordering::Relaxed),
            "shutdown flag should flip when the signal handler fires"
        );
    }
}
