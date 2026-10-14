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

    /// Only a workflow method starts a workflow: `count` is a handler.
    #[workflow]
    pub async fn delegate(ctx: &mut Workflow<Self>) -> u64 {
        let to = Ref::<Shop>::new(InstanceId(1));
        match ctx.start(AgentId(2), to, shop::Count {}).await {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}

fn main() {}
