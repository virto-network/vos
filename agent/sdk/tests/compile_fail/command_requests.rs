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

    #[msg]
    pub async fn count(&mut self) -> u64 {
        self.orders += 1;
        self.orders
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
