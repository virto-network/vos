use vos::prelude::*;
use vos::value::Value;

#[actor]
pub struct WorkflowV2 {
    value: u32,
}

#[messages]
impl WorkflowV2 {
    fn new() -> Self {
        Self { value: 0 }
    }

    #[msg]
    fn increment(&mut self, amount: u32) -> u32 {
        self.value += amount;
        self.value
    }

    #[msg]
    async fn call_child(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.value += 10;
        if let Ok(mut child) = ctx.child::<WorkflowV2Ref>("child").await
            && let Ok(value) = child.increment(1).await
        {
            self.value += value;
        }
        self.value
    }

    #[msg]
    async fn child_await_peer(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.value += 1;
        if let Ok(Value::U32(value)) = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), Some(100))
            .await
        {
            self.value += value;
        }
        self.value
    }

    #[msg]
    async fn root_child_await(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.value += 10;
        if let Ok(mut child) = ctx.child::<WorkflowV2Ref>("child").await
            && let Ok(value) = child.child_await_peer().await
        {
            self.value += value;
        }
        self.value
    }

    #[msg]
    async fn child_two_awaits(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.value += 1;
        for _ in 0..2 {
            if let Ok(Value::U32(value)) = ctx
                .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), Some(100))
                .await
            {
                self.value += value;
            }
        }
        self.value
    }

    #[msg]
    async fn root_child_two_awaits(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.value += 10;
        if let Ok(mut child) = ctx.child::<WorkflowV2Ref>("child").await
            && let Ok(value) = child.child_two_awaits().await
        {
            self.value += value;
        }
        self.value
    }
}
