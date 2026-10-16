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

    #[attestable(role = "minter")]
    pub fn doubled(by: u64) -> u64 {
        2 * by
    }
}

fn main() {}
