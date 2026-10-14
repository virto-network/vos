use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    orders: u64,
}

#[messages]
impl Shop {
    pub fn new() -> Self {
        Self { orders: 0 }
    }

    #[workflow]
    pub fn checkout(&mut self, items: u64) -> u64 {
        self.orders += 1;
        items
    }
}

fn main() {}
