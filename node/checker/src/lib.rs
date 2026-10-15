//! Exactly once, through failures: the model the node suites share, run
//! on nodes in one process or on node processes.
//!
//! Clients increment counters, each request resent with its sequence
//! until answered, in sessions they start every few dozen requests. Every
//! answer must be its client's running total: no request applied twice,
//! none skipped. Readers check every read against what was answered, by
//! read index and at the floor answers give. Requests captured while their
//! sessions live are sent again once every session is collected, and none
//! runs. At the end, what each client sent says what every replica holds.
//!
//! The suite says what the clients see of its nodes through [`Nodes`], and
//! drives its faults its own way.
//!
//! Beside the model, what the node's tests and benches share:
//! [`programs`], the guest programs; [`calls`], a call's total and signed
//! queries; [`hooks`], what a test gives a node to hold or fail it;
//! [`spaces`], nodes in one process and free ports; [`crash`], the crash
//! tests' rounds; [`processes`], node processes and the relay between
//! them; [`rounds`], the workflows the checker starts and their reads.

pub mod calls;
mod client;
pub mod crash;
pub mod hooks;
mod model;
pub mod processes;
pub mod rounds;
pub mod spaces;

pub use vos_testkit::programs;

pub use client::Client;
pub use client::tours::{Touring, check_tallies};
pub use model::{ANSWERED, ATTEMPT, COUNTER, INBOX, Log, Methods, Mode, Nodes, SECOND};

use std::time::{Duration, Instant};

/// A small seeded generator, so a failing run can be run again.
pub struct Random(pub u64);

impl Random {
    pub fn draw(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        self.draw() % bound
    }
}

/// Wait until `done`, checking every 5 ms, for at most `within`.
#[track_caller]
pub fn wait_until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The median and the 99th percentile of `samples`, by nearest rank, in
/// `unit`s: both zero without samples.
pub fn percentiles(mut samples: Vec<Duration>, unit: Duration) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    samples.sort();
    let at = |fraction: f64| {
        let rank = (samples.len() as f64 * fraction).ceil() as usize;
        samples[rank.max(1) - 1].div_duration_f64(unit)
    };
    (at(0.5), at(0.99))
}
