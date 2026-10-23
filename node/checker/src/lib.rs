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
//! [`programs`], the guest programs; [`calls`], the calls, installs and
//! queries tests make, and what their answers carry; [`hooks`], what a
//! test gives a node to hold or fail it;
//! [`spaces`], nodes in one process and free ports; [`carriers`], the
//! carrier audit; [`crash`], the crash
//! tests' rounds; [`processes`], node processes and the relay between
//! them; [`rounds`], the workflows the checker starts and their reads.

pub mod calls;
pub mod carriers;
mod client;
pub mod crash;
pub mod hooks;
mod model;
pub mod processes;
pub mod rounds;
pub mod spaces;

pub use vos_testkit::programs;

pub use client::tours::{Touring, check_tallies};
pub use client::{Client, PAUSING, clients};
pub use model::{ANSWERED, ATTEMPT, COUNTER, INBOX, Log, Methods, Mode, Nodes, SECOND};

use std::time::{Duration, Instant};

use vos_node::store::Fjall;
use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::records::unstored;

/// A small seeded generator, so a failing run can be run again.
pub struct Random(pub u64);

impl Random {
    /// The generator from `seed`, made odd: a state of zero never moves.
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

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

/// Whether `done` holds within `within`, checking every 5 ms.
pub fn poll(within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + within;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Wait until `done`, checking every 5 ms, for at most `within`.
#[track_caller]
pub fn wait_until(what: &str, within: Duration, done: impl FnMut() -> bool) {
    assert!(poll(within, done), "timed out: {what}");
}

/// A value of `agent`'s applied state in `store`, decoded: `None` while
/// it holds none.
pub fn applied<T: Decode>(store: &Fjall, agent: AgentId, key: &[u8]) -> Option<T> {
    let bytes = store.snapshot().get(agent, key).unwrap()?;
    Some(
        T::decode(unstored(&bytes).expect("a stored value"))
            .unwrap()
            .0,
    )
}

/// A pair's mark, or any count `agent`'s applied state in `store` keeps:
/// 0 while it holds none.
pub fn mark(store: &Fjall, agent: AgentId, key: &[u8]) -> u64 {
    applied(store, agent, key).unwrap_or(0)
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
