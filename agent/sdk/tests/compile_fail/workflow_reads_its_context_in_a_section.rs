use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    sales: Cell<u64>,
}

#[messages]
impl Shop {
    /// A read borrows the context whole: its closure reaches none of it,
    /// not even what only reads.
    #[workflow]
    pub async fn audit(ctx: &mut Workflow<Self>) -> u64 {
        ctx.read(|shop: &Shop| {
            let _ = ctx.now();
            shop.sales.get_or_default()
        })
    }
}

fn main() {}
