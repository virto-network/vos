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

    /// A command runs through the log: only a query takes `linearizable`.
    #[msg(linearizable)]
    pub async fn increment(&mut self, by: u64) -> u64 {
        self.value += by;
        self.value
    }
}

fn main() {}
