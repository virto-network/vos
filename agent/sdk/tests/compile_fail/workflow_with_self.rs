use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    orders: Cell<u64>,
}

#[messages]
impl Shop {
    #[workflow]
    pub fn checkout(&mut self, items: u64) -> u64 {
        self.orders.set(&(self.orders.get_or_default() + 1));
        items
    }
}

fn main() {}
