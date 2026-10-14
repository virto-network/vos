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

    /// A handler runs to completion: it never awaits another agent.
    #[msg]
    pub async fn checkout(&mut self, ctx: &mut Workflow<Self>, items: u64) -> u64 {
        self.orders += items;
        self.orders
    }
}

fn main() {}
