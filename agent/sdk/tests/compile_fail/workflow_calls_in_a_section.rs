use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    sales: Cell<u64>,
}

#[messages]
impl Shop {
    #[msg]
    pub async fn sell(&mut self, amount: u64) -> u64 {
        self.sales.set(&(self.sales.get_or_default() + amount));
        self.sales.get_or_default()
    }

    /// A section's closure holds no context: it can neither call nor
    /// await, so a section never spans a pause.
    #[workflow]
    pub async fn checkout(ctx: &mut Workflow<Self>, amount: u64) -> u64 {
        ctx.update(|shop: &mut Shop| {
            let me = Ref::<Shop>::new(InstanceId(1));
            let _ = ctx.call(me, shop::Sell { amount });
            shop.sales.get_or_default()
        })
    }
}

fn main() {}
