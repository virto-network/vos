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

    /// A workflow's context is its own: it has no command's state.
    #[workflow]
    pub async fn checkout(ctx: &mut Command<Self>, items: u64) -> u64 {
        items
    }
}

fn main() {}
