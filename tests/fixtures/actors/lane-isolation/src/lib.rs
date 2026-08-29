//! Adversarial fixture: a Merge method tries to mutate fresh Linear state.

use vos::prelude::*;

#[actor]
pub struct LaneEscape {
    linear: u64,
    changes: crdt::Counter,
}

#[messages]
impl LaneEscape {
    fn new() -> Self {
        Self {
            linear: 0,
            changes: crdt::Counter::default(),
        }
    }

    #[msg(merge)]
    fn escape(&mut self) {
        self.linear = 1;
        self.changes
            .increment(1)
            .expect("one stable operation per slice");
    }
}
