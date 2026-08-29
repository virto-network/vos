//! Adversarial fixture: a Merge method tries to mutate fresh Linear state.

use vos::prelude::*;

#[actor(agent)]
pub struct LaneEscape {
    linear: u64,
    changes: crdt::Counter,
    #[state(local)]
    private: u64,
}

#[messages(agent)]
impl LaneEscape {
    fn new() -> Self {
        Self {
            linear: 0,
            changes: crdt::Counter::default(),
            private: 7,
        }
    }

    #[msg]
    fn leak_local_from_shared_query(&self) -> u64 {
        self.private
    }

    #[msg(merge)]
    fn escape(&mut self) {
        self.linear = 1;
        self.changes
            .increment(1)
            .expect("one stable operation per slice");
    }
}
