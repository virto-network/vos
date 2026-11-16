use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    #[attestable(role = "minter")]
    pub fn doubled(by: u64) -> u64 {
        2 * by
    }
}

fn main() {}
