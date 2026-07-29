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
        if let Ok(Value::U32(value)) = ctx
            .ask_actor(
                ActorId([36; 32]),
                &Msg::new("increment").with("amount", 1u32),
                None,
            )
            .await
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
        if let Ok(Value::U32(value)) = ctx
            .ask_actor(ActorId([36; 32]), &Msg::new("child_await_peer"), None)
            .await
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
        if let Ok(Value::U32(value)) = ctx
            .ask_actor(ActorId([36; 32]), &Msg::new("child_two_awaits"), None)
            .await
        {
            self.value += value;
        }
        self.value
    }

    #[msg]
    async fn root_child_then_peer(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.value += 10;
        if let Ok(Value::U32(value)) = ctx
            .ask_actor(ActorId([36; 32]), &Msg::new("child_await_peer"), None)
            .await
        {
            self.value += value;
        }
        if let Ok(Value::U32(value)) = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), Some(100))
            .await
        {
            self.value += value;
        }
        self.value
    }

    #[msg]
    async fn root_child_then_sibling(&mut self, ctx: &mut Context<Self>) -> u32 {
        let _ = ctx
            .ask_actor(ActorId([36; 32]), &Msg::new("child_await_peer"), None)
            .await;
        match ctx
            .ask_actor(
                ActorId([37; 32]),
                &Msg::new("increment").with("amount", 1u32),
                None,
            )
            .await
        {
            Ok(Value::U32(_)) => 1,
            _ => 0,
        }
    }

    #[msg]
    async fn call_child_repeatedly(&mut self, ctx: &mut Context<Self>) -> u32 {
        let mut last = 0;
        for _ in 0..64 {
            if let Ok(Value::U32(value)) = ctx
                .ask_actor(
                    ActorId([36; 32]),
                    &Msg::new("increment").with("amount", 1u32),
                    None,
                )
                .await
            {
                last = value;
            }
        }
        last
    }

    #[msg]
    fn wide_reply(&self) -> Vec<u8> {
        vec![0xa5; 2048]
    }

    #[msg]
    fn ipc_tail(&self) -> u8 {
        let address = vos::v2::ACTOR_IPC_BASE_PAGE as usize * 4096 + 1024;
        // SAFETY: the generic VOS service maps the invocation IPC capability
        // over this deterministic window before entering every nested actor.
        unsafe { core::ptr::read_volatile(address as *const u8) }
    }

    #[msg]
    async fn sibling_ipc_tail(&mut self, ctx: &mut Context<Self>) -> u8 {
        let _ = ctx
            .ask_actor(ActorId([36; 32]), &Msg::new("wide_reply"), None)
            .await;
        match ctx
            .ask_actor(ActorId([37; 32]), &Msg::new("ipc_tail"), None)
            .await
        {
            Ok(Value::U8(value)) => value,
            _ => u8::MAX,
        }
    }
}
