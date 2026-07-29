use vos::prelude::*;
use vos::value::Value;

#[actor(crdt)]
pub struct CrdtCounterV2 {
    count: crdt::Counter,
}

#[messages]
impl CrdtCounterV2 {
    fn new() -> Self {
        Self {
            count: crdt::Counter::default(),
        }
    }

    #[msg]
    fn increment(&mut self, amount: u64) -> i64 {
        self.count
            .increment(amount)
            .expect("actor dispatch establishes a CRDT change scope");
        self.count.value()
    }

    #[msg]
    async fn increment_child_twice(&mut self, ctx: &mut Context<Self>, amount: u64) -> i64 {
        let mut value = 0;
        for _ in 0..2 {
            if let Ok(Value::I64(next)) = ctx
                .ask_actor(
                    ActorId([36; 32]),
                    &Msg::new("increment").with("amount", amount),
                    None,
                )
                .await
            {
                value = next;
            }
        }
        value
    }

    #[msg]
    async fn call_yielding_child(&mut self, ctx: &mut Context<Self>, amount: u64) -> i64 {
        match ctx
            .ask_actor(
                ActorId([36; 32]),
                &Msg::new("increment_around_yield").with("amount", amount),
                None,
            )
            .await
        {
            Ok(Value::I64(value)) => value,
            _ => 0,
        }
    }

    #[msg]
    async fn increment_around_yield(
        &mut self,
        ctx: &mut Context<Self>,
        amount: u64,
    ) -> i64 {
        self.count
            .increment(amount)
            .expect("actor dispatch establishes a CRDT change scope");
        ctx.yield_now().await;
        self.count
            .increment(amount)
            .expect("restored actor rebinds its CRDT change scope");
        self.count.value()
    }
}
