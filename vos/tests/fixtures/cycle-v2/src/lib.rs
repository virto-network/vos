use vos::prelude::*;

#[actor]
pub struct CycleV2;

#[messages]
impl CycleV2 {
    fn new() -> Self {
        Self
    }

    #[msg]
    async fn child_cycle(&mut self, ctx: &mut Context<Self>) -> u32 {
        let Ok(mut root) = ctx.actor::<CycleV2Ref>("root").await else {
            return 0;
        };
        match root.unused_root_method().await {
            Err(vos::ClientError::Call(CallError::Cycle)) => 1,
            _ => 0,
        }
    }

    #[msg]
    fn unused_root_method(&self) -> u32 {
        0
    }

    #[msg(space_role = SpaceRole::Member)]
    fn member_only(&self) -> u32 {
        99
    }

    #[msg]
    async fn root_forbidden(&mut self, ctx: &mut Context<Self>) -> u32 {
        let Ok(mut child) = ctx.child::<CycleV2Ref>("child").await else {
            return 0;
        };
        match child.member_only().await {
            Err(vos::ClientError::Forbidden) => 1,
            Err(vos::ClientError::Call(CallError::Panicked)) => 2,
            _ => 0,
        }
    }

    #[msg]
    async fn root_cycle(&mut self, ctx: &mut Context<Self>) -> u32 {
        let Ok(mut child) = ctx.child::<CycleV2Ref>("child").await else {
            return 0;
        };
        child.child_cycle().await.unwrap_or(0)
    }
}
