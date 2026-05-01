//! Clock + entropy abstractions.
//!
//! The Raft worker needs three things from its surroundings:
//!
//! 1. A monotonic clock (election timeout deadlines, heartbeat
//!    cadence).
//! 2. An async sleep (so the loop can wake on a timer without
//!    pinning a thread).
//! 3. A bit of entropy (jittered timeouts so peers don't time out
//!    in lockstep).
//!
//! Std hosts get [`StdClock`] / [`StdRng`] for free behind the
//! `std` feature. Embedded hosts implement these themselves
//! against their async runtime — Embassy / `embassy-time::Timer`,
//! a UART-derived RNG, etc. The trait shapes are intentionally
//! small so a consumer pulls in nothing it doesn't need.
//!
//! ## Why we don't pin a runtime
//!
//! `tokio::time::sleep` would lock the crate to tokio.
//! `futures-timer` would lock the crate to std (it pulls in
//! `std::time::Instant` internally). Defining `Clock` ourselves
//! lets the same worker code run unchanged on a tokio host, an
//! `async-std` host, an Embassy firmware, or a deterministic
//! simulator that ticks a virtual clock forward.

use core::future::Future;
use core::time::Duration;

/// Monotonic clock + async sleep.
///
/// Implementations must be cheap to clone or share — the worker
/// holds one and helper futures borrow it. The `Instant`
/// associated type is whatever the host uses to represent a
/// point in time; the worker only ever computes `now() +
/// duration` and `sleep_until(deadline)` over it.
pub trait Clock: Send + Sync + 'static {
    /// Host-defined moment in time. Must be totally ordered so
    /// the worker can compare deadlines, and `Copy + Send + Sync`
    /// so it can be passed across `await` points.
    type Instant: Copy + Ord + Send + Sync + 'static;

    /// Sleep future returned by [`sleep_until`](Self::sleep_until).
    /// Carries no value — completion is the signal.
    type Sleep: Future<Output = ()> + Send + 'static;

    /// Read the current instant. Cheap.
    fn now(&self) -> Self::Instant;

    /// Compute `instant + duration` in the host's time
    /// representation. Saturates on overflow (the worker never
    /// advances time backwards, so saturating is the right
    /// failure mode).
    fn add(&self, instant: Self::Instant, duration: Duration) -> Self::Instant;

    /// Async sleep until `deadline`. Returning a future means
    /// the host's executor decides how to park the task — we
    /// don't spawn anything.
    fn sleep_until(&self, deadline: Self::Instant) -> Self::Sleep;
}

/// 64-bit RNG. The worker only uses it to jitter election
/// timeouts within `[lo, hi)` ms; quality requirements are mild
/// (a `xorshift` is fine, a `getentropy` call is fine, neither
/// is required to be cryptographically secure).
pub trait Rng: Send + 'static {
    /// Produce the next pseudo-random `u64`. The worker hashes
    /// over this together with `me` + `current_term` before
    /// reducing into a millisecond range, so adjacent values
    /// don't need to be uniformly distributed by themselves.
    fn next_u64(&mut self) -> u64;
}

/// Sink that receives `commit_index` advances. The worker calls
/// [`notify`](Self::notify) every time `commit_index` moves
/// forward — either because a leader's quorum-match advanced it
/// or a follower received a heartbeat with a higher
/// `leader_commit`.
///
/// Provided so embedded hosts can plug in whatever channel
/// primitive their executor offers (Embassy's
/// `embassy_sync::channel`, a custom MPMC, an inline closure)
/// without depending on `std::sync::mpsc`. Std hosts can pass
/// `std::sync::mpsc::Sender<u64>` directly via the blanket impl
/// below; embedded users with no apply-side consumer can pass
/// `()` and the notifications are silently dropped.
pub trait ApplySink: Send + 'static {
    /// Called by the worker after every commit-index advance.
    /// Implementations should be cheap — the call happens
    /// inside the worker's hot loop. Errors are not propagated
    /// (a closed channel is not a worker failure).
    fn notify(&self, commit_index: u64);
}

/// No-op sink. Embedded users with no apply-side consumer can
/// pass `()` to suppress the notifications entirely.
impl ApplySink for () {
    fn notify(&self, _commit_index: u64) {}
}

/// Wire `std::sync::mpsc::Sender<u64>` straight into the worker
/// — vos's `RaftCommit::Multi` uses this path.
#[cfg(feature = "std")]
impl ApplySink for std::sync::mpsc::Sender<u64> {
    fn notify(&self, commit_index: u64) {
        let _ = self.send(commit_index);
    }
}

// ── Std-feature defaults ─────────────────────────────────────

/// Standard-library [`Clock`] implementation. Wraps
/// [`std::time::Instant`] for `now` / `add`. The sleep future
/// uses a per-`Delay` helper thread that calls
/// [`std::thread::sleep`] and wakes the registered task.
///
/// We deliberately don't use `futures-timer`'s global timer
/// thread: under heavy `cargo test` parallelism (50+ workers
/// spawning `Delay`s every few ms) the wake latency on the
/// shared timer wheel becomes the bottleneck and election
/// timers fire late. Per-`Delay` threads cost a thread spawn
/// each tick but isolate each worker's timing from every
/// other one.
///
/// Cheap to clone; carries no state.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, Default)]
pub struct StdClock;

#[cfg(feature = "std")]
impl Clock for StdClock {
    type Instant = std::time::Instant;
    type Sleep = StdSleep;

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn add(&self, instant: Self::Instant, duration: Duration) -> Self::Instant {
        instant.checked_add(duration).unwrap_or(instant)
    }

    fn sleep_until(&self, deadline: Self::Instant) -> Self::Sleep {
        StdSleep::new(deadline)
    }
}

/// Future returned by [`StdClock::sleep_until`]. On first poll
/// spawns a helper thread that sleeps for the remaining duration
/// and wakes the parent task; subsequent polls just check the
/// shared flag.
#[cfg(feature = "std")]
pub struct StdSleep {
    deadline: std::time::Instant,
    state: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    spawned: bool,
}

#[cfg(feature = "std")]
impl StdSleep {
    fn new(deadline: std::time::Instant) -> Self {
        Self {
            deadline,
            state: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
            spawned: false,
        }
    }
}

#[cfg(feature = "std")]
impl core::future::Future for StdSleep {
    type Output = ();

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        if self.state.load(core::sync::atomic::Ordering::Acquire) {
            return core::task::Poll::Ready(());
        }
        let now = std::time::Instant::now();
        if now >= self.deadline {
            return core::task::Poll::Ready(());
        }
        if !self.spawned {
            self.spawned = true;
            let dur = self.deadline.saturating_duration_since(now);
            let flag = self.state.clone();
            let waker = cx.waker().clone();
            std::thread::spawn(move || {
                std::thread::sleep(dur);
                flag.store(true, core::sync::atomic::Ordering::Release);
                waker.wake();
            });
        }
        core::task::Poll::Pending
    }
}

/// Standard-library [`Rng`] implementation. Seeds from the
/// system clock at construction and walks a `xorshift64*`
/// sequence on each `next_u64` call. Not cryptographically
/// secure — the worker only uses it for timer jitter.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct StdRng {
    state: u64,
}

#[cfg(feature = "std")]
impl Default for StdRng {
    fn default() -> Self {
        Self::from_entropy()
    }
}

#[cfg(feature = "std")]
impl StdRng {
    /// Seed from the system clock. The exact entropy source
    /// doesn't matter — we just need something different
    /// per-process so a multi-replica test doesn't have every
    /// worker drawing the same jitter.
    pub fn from_entropy() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xDEADBEEFCAFEBABE);
        let pid = std::process::id() as u64;
        // Mix the pid in so two processes started in the same
        // nanosecond don't collide.
        let seed = nanos.wrapping_mul(0x9E3779B97F4A7C15) ^ pid;
        // xorshift breaks if seeded with 0; replace with a
        // canned constant.
        let state = if seed == 0 { 0x1234567890ABCDEF } else { seed };
        Self { state }
    }
}

#[cfg(feature = "std")]
impl Rng for StdRng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64* — fast, decent distribution for jitter.
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

// ── Tokio-feature adapter ────────────────────────────────────

/// Tokio-native [`Clock`] implementation. Wraps
/// [`tokio::time::Instant`] for `now` / `add` and
/// [`tokio::time::sleep_until`] for the sleep future.
///
/// Recommended for tokio-native hosts: avoids the thread-spawn
/// overhead of [`StdClock::sleep_until`]. The clock has no state;
/// the timer driver is provided by the host's tokio runtime.
///
/// Requires the `tokio` feature.
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioClock;

#[cfg(feature = "tokio")]
impl Clock for TokioClock {
    type Instant = tokio::time::Instant;
    type Sleep = tokio::time::Sleep;

    fn now(&self) -> Self::Instant {
        tokio::time::Instant::now()
    }

    fn add(&self, instant: Self::Instant, duration: Duration) -> Self::Instant {
        instant.checked_add(duration).unwrap_or(instant)
    }

    fn sleep_until(&self, deadline: Self::Instant) -> Self::Sleep {
        tokio::time::sleep_until(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn std_rng_produces_distinct_values() {
        let mut r = StdRng::from_entropy();
        let a = r.next_u64();
        let b = r.next_u64();
        let c = r.next_u64();
        assert!(a != b || b != c, "xorshift sequence stuck on a single value");
    }

    #[cfg(feature = "std")]
    #[test]
    fn std_clock_now_is_monotonic() {
        let c = StdClock;
        let t1 = c.now();
        let t2 = c.now();
        assert!(t2 >= t1);
    }
}
