//! Hooks a test gives a node: a gate that holds what passes it, its
//! commits by default, and a sync that fails once.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};

use vos_node::Hooks;

/// Holds whoever passes while it is closed, counting them. As a node's
/// hooks, it holds the node's commits.
#[derive(Default)]
pub struct Gate {
    closed: Mutex<bool>,
    opened: Condvar,
    reached: AtomicU64,
}

impl Gate {
    pub fn pass(&self) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            self.reached.fetch_add(1, Ordering::SeqCst);
        }
        while *closed {
            closed = self.opened.wait(closed).unwrap();
        }
    }

    /// Close the gate until what this gives back is dropped, a failing
    /// test's included.
    #[must_use = "the gate opens when this is dropped"]
    pub fn close(&self) -> Closed<'_> {
        *self.closed.lock().unwrap() = true;
        Closed(self)
    }

    /// How many reached it while it was closed.
    pub fn reached(&self) -> u64 {
        self.reached.load(Ordering::SeqCst)
    }

    fn open(&self) {
        *self.closed.lock().unwrap() = false;
        self.opened.notify_all();
    }
}

impl Hooks for Gate {
    fn before_commit(&self) {
        self.pass();
    }
}

/// A closed gate, which opens when this is dropped.
pub struct Closed<'a>(&'a Gate);

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        self.0.open();
    }
}

/// Fails the sync of the next synced flush once armed, as a failed fsync
/// does.
#[derive(Default)]
pub struct FailNextSync(AtomicBool);

impl FailNextSync {
    pub fn arm(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Hooks for FailNextSync {
    fn fail_sync(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}
