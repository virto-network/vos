//! The faults the test gives the nodes: pauses, faults files and clock
//! jumps, each in force once the node says so.

use std::process::Command;
use std::sync::atomic::Ordering;

use super::{PROCESS_WAIT, Processes, Running, read_log};
use crate::wait_until;

impl Processes {
    /// Pause node `number` (SIGSTOP).
    pub fn stop(&self, number: usize) {
        if self.signal(number, "-STOP") {
            self.slot(number).paused.store(true, Ordering::SeqCst);
        }
    }

    /// Let node `number` go on (SIGCONT), once it takes the faults written
    /// while it was paused.
    pub fn resume(&self, number: usize) {
        if self.signal(number, "-CONT") {
            self.slot(number).paused.store(false, Ordering::SeqCst);
            self.taken(number, self.slot(number).written.load(Ordering::SeqCst));
        }
    }

    /// Send node `number` `signal`, as `kill` names it: whether it runs.
    pub(super) fn signal(&self, number: usize, signal: &str) -> bool {
        let running = self.slot(number).running.lock().unwrap();
        let Some(pid) = running.as_ref().map(Running::pid) else {
            return false;
        };
        drop(running);
        let _ = Command::new("kill")
            .args([signal, &pid.to_string()])
            .status();
        true
    }

    /// Node `number`'s own faults, as lines of its faults file: in force
    /// once this returns, if the node runs and is not paused, as it says;
    /// else once it starts or goes on.
    pub fn set_faults(&self, number: usize, lines: &str) {
        *self.slot(number).faults.lock().unwrap() = lines.to_string();
        self.write_faults(number);
    }

    /// Run node `number`'s clock `jump` milliseconds ahead of every
    /// node's, or behind.
    pub fn jump_clock(&self, number: usize, jump: i64) {
        self.slot(number).jump.store(jump, Ordering::SeqCst);
        self.write_faults(number);
    }

    /// Move every node's clock on by `by` milliseconds, one node after
    /// another; then clients take the agents' time to have moved too.
    pub fn jump_every_clock(&self, by: i64) {
        self.moving.store(true, Ordering::SeqCst);
        self.clocks.fetch_add(by, Ordering::SeqCst);
        for number in 1..=self.count {
            self.write_faults(number);
        }
        self.offset.fetch_add(by, Ordering::SeqCst);
        self.moving.store(false, Ordering::SeqCst);
    }

    /// Write node `number`'s faults file whole, headed by a new
    /// generation, and wait for the node to take it if it runs and is not
    /// paused.
    pub(super) fn write_faults(&self, number: usize) {
        let slot = self.slot(number);
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let clock = self.clocks.load(Ordering::SeqCst) + slot.jump.load(Ordering::SeqCst);
        let text = format!(
            "generation {generation}\n{}clock {clock}\n{}",
            self.options.settings,
            slot.faults.lock().unwrap()
        );
        let file = self.faults_file(number);
        let staged = file.with_extension("staged");
        std::fs::write(&staged, text).unwrap();
        std::fs::rename(&staged, &file).unwrap();
        slot.written.store(generation, Ordering::SeqCst);
        if self.is_running(number) && !slot.paused.load(Ordering::SeqCst) {
            self.taken(number, generation);
        }
    }

    /// Wait until node `number` says the faults of `generation`, or later
    /// ones, are in force.
    fn taken(&self, number: usize, generation: u64) {
        let taken = self.faults_file(number).with_extension("taken");
        wait_until("the node takes its faults", PROCESS_WAIT, || {
            let mut running = self.slot(number).running.lock().unwrap();
            if let Some(status) = running.as_mut().and_then(Running::exited) {
                panic!(
                    "node {number} exited by itself: {status}\n{}",
                    read_log(&self.log_path(number))
                );
            }
            drop(running);
            std::fs::read_to_string(&taken)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .is_some_and(|taken| taken >= generation)
        });
    }
}
