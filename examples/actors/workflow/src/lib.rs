//! Root/child workflow with an exact durable cross-root await.
//!
//! Install this canonical program as `root` and its owned `child`, and bind a
//! separate root tree under the signed external name `peer`. The outer method
//! mutates before the child call; the child mutates before awaiting the peer.
//! Both mutations are part of the durable checkpoint and execute exactly once
//! after restart.

use vos::prelude::*;

#[actor]
pub struct Workflow {
    value: u64,
}

#[messages]
impl Workflow {
    fn new() -> Self {
        Self { value: 0 }
    }

    /// Entry point installed on the root actor.
    #[msg]
    async fn run(&mut self, ctx: &mut Context<Self>) -> u64 {
        self.value += 10;
        let Ok(mut child) = ctx.child::<WorkflowRef>("child").await else {
            return self.value;
        };
        if let Ok(child_value) = child.await_peer().await {
            self.value += child_value;
        }
        self.value
    }

    /// Entry point installed on the owned child. A cross-root call always
    /// enters the durable outbox/inbox path and checkpoints this exact VM.
    #[msg]
    async fn await_peer(&mut self, ctx: &mut Context<Self>) -> u64 {
        self.value += 1;
        let Ok(mut peer) = ctx.actor::<WorkflowRef>("peer").await else {
            return self.value;
        };
        if let Ok(peer_value) = peer.peer_value().await {
            self.value += peer_value;
        }
        self.value
    }

    /// Entry point installed on the separate peer root. Its result is not
    /// observable by the child until the peer's Accumulate commit succeeds.
    #[msg]
    fn peer_value(&self) -> u64 {
        7
    }
}
