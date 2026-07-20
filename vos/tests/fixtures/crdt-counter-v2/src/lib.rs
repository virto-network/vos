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
    async fn increment_child_twice(&mut self, amount: u64, ctx: &mut Context<Self>) -> i64 {
        let mut value = 0;
        let Ok(mut child) = ctx.child::<CrdtCounterV2Ref>("child").await else {
            return value;
        };
        for _ in 0..2 {
            if let Ok(next) = child.increment(amount).await {
                value = next;
            }
        }
        value
    }

    #[msg]
    async fn increment_around_peer(
        &mut self,
        before: u64,
        after: u64,
        ctx: &mut Context<Self>,
    ) -> i64 {
        self.count
            .increment(before)
            .expect("actor dispatch establishes a CRDT change scope");
        let _ = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), None)
            .await;
        self.count
            .increment(after)
            .expect("restored dispatch rebinds the CRDT change scope");
        self.count.value()
    }

    #[msg]
    async fn increment_child_around_peer(
        &mut self,
        before: u64,
        after: u64,
        parent_after: u64,
        ctx: &mut Context<Self>,
    ) -> i64 {
        if let Ok(mut child) = ctx.child::<CrdtCounterV2Ref>("child").await {
            let _ = child.increment_around_peer(before, after).await;
        }
        self.count
            .increment(parent_after)
            .expect("restored parent dispatch rebinds the CRDT change scope");
        self.count.value()
    }
}
