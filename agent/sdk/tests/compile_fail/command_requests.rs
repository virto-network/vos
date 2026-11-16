use vos_sdk::prelude::*;

#[actor]
pub struct Shop {
    orders: Cell<u64>,
}

#[messages]
impl Shop {
    #[msg]
    pub async fn count(&mut self) -> u64 {
        self.orders.set(&(self.orders.get_or_default() + 1));
        self.orders.get_or_default()
    }

    /// Only a workflow awaits another agent.
    #[msg]
    pub async fn ask(&mut self, ctx: &mut Command<Self>) -> u64 {
        ctx.request(AgentId(2), Ref::<Shop>::new(InstanceId(1)), shop::Count {})
            .await
            .unwrap_or(0)
    }
}

fn main() {}
