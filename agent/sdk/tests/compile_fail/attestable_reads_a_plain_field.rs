use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// A `&self` attestable method reads its view, which holds the
    /// committed maps alone.
    #[attestable]
    pub fn reads_state(&self, by: u64) -> u64 {
        self.value + by
    }
}

fn main() {}
