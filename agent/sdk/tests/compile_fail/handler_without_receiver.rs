use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    #[msg]
    pub async fn free(by: u64) -> u64 {
        by
    }
}

fn main() {}
