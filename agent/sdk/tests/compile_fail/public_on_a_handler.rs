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

    #[msg]
    pub async fn add(&mut self, #[public] by: u64) -> u64 {
        self.value += by;
        self.value
    }
}

fn main() {}
