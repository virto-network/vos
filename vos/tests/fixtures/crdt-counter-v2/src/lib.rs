use vos::prelude::*;

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
