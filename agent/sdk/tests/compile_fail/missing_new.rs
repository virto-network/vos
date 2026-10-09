use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

#[messages]
impl Counter {
    #[msg]
    pub async fn value(&self) -> u64 {
        self.value
    }
}

fn main() {}
