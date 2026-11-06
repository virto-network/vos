//! A home's stand-in for the node's tests: an actor, in an agent of its
//! own granted a personal agent's role `homes`, that passes its client's
//! assignment, policy and re-proof on to the personal agent by message, as
//! `Homes` does.

#![no_std]

extern crate alloc;

use vos_personal::Personal;
use vos_personal::personal::{Assign, Configure, Renew};
use vos_sdk::prelude::*;
use vos_wire::personal::{Kit, NewDevice, Policy};

#[actor]
pub struct Home {}

#[messages]
impl Home {
    pub fn new() -> Self {
        Self {}
    }

    /// Assign the personal agent `agent`'s actor at `instance` to
    /// `device`, with `kit`.
    #[msg]
    pub async fn assign(
        &mut self,
        ctx: &mut Command<Self>,
        agent: u32,
        instance: u32,
        device: NewDevice,
        kit: Kit,
    ) {
        ctx.send(
            AgentId(agent),
            Ref::<Personal>::new(InstanceId(instance)),
            Assign { device, kit },
        );
    }

    /// Set the personal agent's policy.
    #[msg]
    pub async fn configure(
        &mut self,
        ctx: &mut Command<Self>,
        agent: u32,
        instance: u32,
        policy: Policy,
    ) {
        ctx.send(
            AgentId(agent),
            Ref::<Personal>::new(InstanceId(instance)),
            Configure { policy },
        );
    }

    /// Renew the personal agent's lease.
    #[msg]
    pub async fn renew(&mut self, ctx: &mut Command<Self>, agent: u32, instance: u32) {
        ctx.send(
            AgentId(agent),
            Ref::<Personal>::new(InstanceId(instance)),
            Renew {},
        );
    }
}
