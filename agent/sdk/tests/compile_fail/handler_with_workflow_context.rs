use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    orders: Cell<u64>,
}

#[messages]
impl Shop {
    /// A handler runs to completion: it never awaits another agent.
    #[msg]
    pub async fn checkout(&mut self, ctx: &mut Workflow<Self>, items: u64) -> u64 {
        self.orders.set(&(self.orders.get_or_default() + items));
        self.orders.get_or_default()
    }
}

fn main() {}
