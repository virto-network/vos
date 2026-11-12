// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a proof pays once, paid before the sign-in: each enrolled stock
//! kernel's program, computed once and kept while a guard proves with it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use sha2::Digest as _;
use vos_light::{DeviceError, DeviceProgram};

/// A kernel's key: its release artifact's SHA-256.
pub(crate) type Key = [u8; 32];

pub(crate) fn key(kernel: &[u8]) -> Key {
    sha2::Sha256::digest(kernel).into()
}

/// Computed values by key, each computed once however many ask: a caller
/// arriving while another computes it waits for that one.
pub(crate) struct Programs<P = DeviceProgram> {
    slots: Mutex<HashMap<Key, Arc<Slot<P>>>>,
}

struct Slot<P> {
    state: Mutex<State<P>>,
    ready: Condvar,
}

enum State<P> {
    Empty,
    Computing,
    Done(Result<Arc<P>, DeviceError>),
}

/// Puts a slot whose computation unwound back to empty, for the next
/// caller to compute.
struct Unwind<'a, P>(&'a Slot<P>);

impl<P> Drop for Unwind<'_, P> {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        if matches!(*state, State::Computing) {
            *state = State::Empty;
            self.0.ready.notify_all();
        }
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<P> Default for Programs<P> {
    fn default() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }
}

impl<P> Programs<P> {
    /// The value for `key`, `compute`d here only when no one computed it
    /// yet and no one is computing it. A failure is kept as a value is: a
    /// kernel's program fails the same way each time.
    pub(crate) fn get(
        &self,
        key: Key,
        compute: impl FnOnce() -> Result<P, DeviceError>,
    ) -> Result<Arc<P>, DeviceError> {
        let slot = Arc::clone(lock(&self.slots).entry(key).or_insert_with(|| {
            Arc::new(Slot {
                state: Mutex::new(State::Empty),
                ready: Condvar::new(),
            })
        }));
        let mut state = lock(&slot.state);
        loop {
            match &*state {
                State::Done(done) => return done.clone(),
                State::Computing => {
                    state = slot.ready.wait(state).unwrap_or_else(|e| e.into_inner())
                }
                State::Empty => break,
            }
        }
        *state = State::Computing;
        drop(state);
        let unwind = Unwind(&slot);
        let done = compute().map(Arc::new);
        std::mem::forget(unwind);
        *lock(&slot.state) = State::Done(done.clone());
        slot.ready.notify_all();
        done
    }

    /// Only the values of `keys` kept: a kernel no longer enrolled has its
    /// program dropped.
    pub(crate) fn retain(&self, keys: &HashSet<Key>) {
        lock(&self.slots).retain(|key, _| keys.contains(key));
    }

    /// Whether `key`'s value is computed.
    #[cfg(test)]
    pub(crate) fn holds(&self, key: &Key) -> bool {
        lock(&self.slots)
            .get(key)
            .is_some_and(|slot| matches!(*lock(&slot.state), State::Done(_)))
    }
}

/// A warm-up under way, which [`Warming::cancel`] stops before its next
/// step: a step begun runs to its end.
#[derive(Debug)]
pub struct Warming {
    cancelled: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Warming {
    pub(crate) fn spawn(work: impl FnOnce(&AtomicBool) + Send + 'static) -> Option<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let thread = std::thread::Builder::new()
            .name("s4-credential-warm".into())
            .spawn(move || {
                lower_priority();
                work(&flag);
            })
            .ok()?;
        Some(Self { cancelled, thread })
    }

    /// Stop before the next step.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether it ended.
    pub fn is_finished(&self) -> bool {
        self.thread.is_finished()
    }

    /// Wait for its end.
    pub fn join(self) {
        let _ = self.thread.join();
    }
}

/// The heap's free pages handed back to the system, a proof's half
/// a gigabyte among them.
pub(crate) fn release_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: glibc's own call, of no pointer.
    unsafe {
        libc::malloc_trim(0);
    }
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn mallopt(param: libc::c_int, value: libc::c_int) -> libc::c_int;
        }
        /// Bionic's `M_PURGE`: the allocator's cached free memory released.
        const M_PURGE: libc::c_int = -101;
        // SAFETY: bionic's own call, of no pointer.
        unsafe {
            mallopt(M_PURGE, 0);
        }
    }
}

/// The calling thread at a lower priority than the app's own: nice 10.
fn lower_priority() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: the calling thread's own priority (`who` 0), no pointer.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS as _, 0, 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn a_program_is_computed_once_and_a_later_ask_hits() {
        let programs = Programs::<u32>::default();
        let computed = AtomicUsize::new(0);
        let compute = || {
            computed.fetch_add(1, Ordering::SeqCst);
            Ok(7)
        };
        assert!(!programs.holds(&[1; 32]));
        assert_eq!(*programs.get([1; 32], compute).unwrap(), 7);
        assert!(programs.holds(&[1; 32]));
        assert_eq!(*programs.get([1; 32], || unreachable!()).unwrap(), 7);
        assert_eq!(computed.load(Ordering::SeqCst), 1);
        // Another kernel misses.
        assert_eq!(*programs.get([2; 32], || Ok(8)).unwrap(), 8);
    }

    #[test]
    fn a_failure_is_kept_and_an_unwound_computation_left_to_the_next() {
        let programs = Programs::<u32>::default();
        assert_eq!(
            programs.get([1; 32], || Err(DeviceError::Prove)),
            Err(DeviceError::Prove)
        );
        assert_eq!(
            programs.get([1; 32], || unreachable!()),
            Err(DeviceError::Prove)
        );
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            programs.get([2; 32], || panic!("the install stopped"))
        }));
        assert!(unwound.is_err());
        assert_eq!(*programs.get([2; 32], || Ok(9)).unwrap(), 9);
    }

    #[test]
    fn a_kernel_no_longer_enrolled_has_its_program_dropped() {
        let programs = Programs::<u32>::default();
        programs.get([1; 32], || Ok(1)).unwrap();
        programs.get([2; 32], || Ok(2)).unwrap();
        programs.retain(&HashSet::from([[2; 32]]));
        assert!(!programs.holds(&[1; 32]));
        assert!(programs.holds(&[2; 32]));
        // Enrolled again, it is computed again.
        assert_eq!(*programs.get([1; 32], || Ok(3)).unwrap(), 3);
    }

    #[test]
    fn a_caller_during_a_computation_waits_for_it() {
        let programs = Arc::new(Programs::<u32>::default());
        let computed = Arc::new(AtomicUsize::new(0));
        let (started, wait_started) = mpsc::channel();
        let (finish, finished) = mpsc::channel::<()>();
        let warm = {
            let (programs, computed) = (Arc::clone(&programs), Arc::clone(&computed));
            std::thread::spawn(move || {
                *programs
                    .get([1; 32], || {
                        computed.fetch_add(1, Ordering::SeqCst);
                        started.send(()).unwrap();
                        finished.recv().unwrap();
                        Ok(5)
                    })
                    .unwrap()
            })
        };
        wait_started.recv().unwrap();
        let sign_in = {
            let (programs, computed) = (Arc::clone(&programs), Arc::clone(&computed));
            std::thread::spawn(move || {
                *programs
                    .get([1; 32], || {
                        computed.fetch_add(1, Ordering::SeqCst);
                        Ok(6)
                    })
                    .unwrap()
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(!sign_in.is_finished());
        finish.send(()).unwrap();
        assert_eq!(warm.join().unwrap(), 5);
        assert_eq!(sign_in.join().unwrap(), 5);
        assert_eq!(computed.load(Ordering::SeqCst), 1);
    }
}
