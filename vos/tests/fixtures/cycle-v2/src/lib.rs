use vos::InvokeError;
use vos::prelude::*;
use vos::value::Value;

#[actor]
pub struct CycleV2;

#[messages]
impl CycleV2 {
    fn new() -> Self {
        Self
    }

    #[msg]
    async fn child_cycle(&mut self, ctx: &mut Context<Self>) -> u32 {
        match ctx
            .ask_actor(ActorId([5; 32]), &Msg::new("unused_root_method"), None)
            .await
        {
            Err(InvokeError::Cycle) => 1,
            _ => 0,
        }
    }

    #[msg]
    async fn root_cycle(&mut self, ctx: &mut Context<Self>) -> u32 {
        match ctx
            .ask_actor(ActorId([36; 32]), &Msg::new("child_cycle"), None)
            .await
        {
            Ok(Value::U32(value)) => value,
            _ => 0,
        }
    }
}
