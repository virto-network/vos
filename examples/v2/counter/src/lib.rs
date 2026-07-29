//! Ordinary state uses Local or Raft consistency without CRDT overhead.

use vos::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

fn increment_value(value: u64, by: u64) -> u64 {
    value.saturating_add(by)
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { value: 0 }
    }

    #[msg]
    fn increment(&mut self, by: u64) -> u64 {
        self.value = increment_value(self.value, by);
        self.value
    }

    #[msg]
    fn value(&self) -> u64 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_is_deterministic_at_the_numeric_limit() {
        assert_eq!(increment_value(u64::MAX, 1), u64::MAX);
    }
}
