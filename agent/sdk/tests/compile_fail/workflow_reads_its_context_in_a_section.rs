use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    sales: u64,
}

#[messages]
impl Shop {
    pub fn new() -> Self {
        Self { sales: 0 }
    }

    /// A read borrows the context whole: its closure reaches none of it,
    /// not even what only reads.
    #[workflow]
    pub async fn audit(ctx: &mut Workflow<Self>) -> u64 {
        ctx.read(|shop: &Shop| {
            let _ = ctx.now();
            shop.sales
        })
    }
}

fn main() {}
