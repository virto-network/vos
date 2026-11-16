use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    /// A `&self` attestable method reads its view, which holds the
    /// committed maps alone.
    #[attestable]
    pub fn reads_state(&self, by: u64) -> u64 {
        self.value.get_or_default() + by
    }
}

fn main() {}
