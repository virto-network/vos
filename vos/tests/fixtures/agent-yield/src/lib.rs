//! Native lifecycle test fixture: two cooperative yields around Local state
//! changes, protected by a deployment-scoped actor role. Not a system actor.

use vos::prelude::*;

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum ProbeRole {
    Run = 0,
}

impl vos::RoleByte for ProbeRole {
    fn from_byte(byte: u8) -> Option<Self> {
        (byte == 0).then_some(Self::Run)
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

const PROBE_ROLES: vos::SpaceRoleMap<ProbeRole> = vos::SpaceRoleMap {
    admin: Some(ProbeRole::Run),
    developer: Some(ProbeRole::Run),
    member: Some(ProbeRole::Run),
    guest: None,
};

#[actor(agent, role = ProbeRole, default_role = ProbeRole::Run, space_role_map = PROBE_ROLES)]
pub struct AgentYieldProbe {
    #[state(local)]
    value: u64,
}

#[messages(agent)]
impl AgentYieldProbe {
    fn new() -> Self {
        Self { value: 0 }
    }

    #[msg(
        local,
        role = ProbeRole::Run,
        actor_role_id = "5151515151515151515151515151515151515151515151515151515151515151"
    )]
    async fn run(&mut self, ctx: &mut Context<Self>) -> u64 {
        self.value = self.value.saturating_add(1);
        ctx.yield_now().await;
        self.value = self.value.saturating_add(10);
        ctx.yield_now().await;
        self.value = self.value.saturating_add(100);
        self.value
    }

    #[msg(local_query)]
    fn value(&self) -> u64 {
        self.value
    }
}
