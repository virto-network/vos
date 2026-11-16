use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    /// A command runs through the log: only a query takes `linearizable`.
    #[msg(linearizable)]
    pub async fn increment(&mut self, by: u64) -> u64 {
        self.value.set(&(self.value.get_or_default() + by));
        self.value.get_or_default()
    }
}

fn main() {}
