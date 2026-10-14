use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    orders: Table<u64, u64>,
}

#[messages]
impl Shop {
    pub fn new() -> Self {
        Self {
            orders: Table::default(),
        }
    }

    /// A workflow holds no state of its own: it reaches its instance's
    /// state only in sections, and has no `self` to read tables through.
    #[workflow]
    pub async fn checkout(ctx: &mut Workflow<Self>, order: u64) -> u64 {
        self.orders.get(&order).unwrap_or(0)
    }
}

fn main() {}
