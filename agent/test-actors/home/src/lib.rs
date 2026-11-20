//! A home's stand-in for the node's tests and the scale harness: an actor,
//! in an agent of its own granted a personal agent's role `homes`, that
//! sends its client's claim and re-proof on to the personal agent by the
//! messages `Homes` sends (`claim`, `renew`), without the member's proof
//! `Homes` asks first, and takes `Personal`'s answers as `Homes` does.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use vos_personal::Personal;
use vos_personal::personal::{Claim, Renew};
use vos_sdk::prelude::*;
use vos_wire::personal::{Kit, NewDevice, PersonalError, Policy};

#[actor]
pub struct Home {}

#[messages]
impl Home {
    /// Claim the personal agent `agent`'s actor at `instance` for
    /// `device`, with `kit`, under `policy`: its answer comes here.
    #[msg]
    pub async fn claim(
        &mut self,
        ctx: &mut Command<Self>,
        agent: u32,
        instance: u32,
        device: NewDevice,
        kit: Kit,
        policy: Policy,
    ) {
        let (_, me) = ctx.me();
        ctx.send(
            AgentId(agent),
            Ref::<Personal>::new(InstanceId(instance)),
            Claim {
                device,
                kit,
                policy,
                homes: me.0,
            },
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

    /// `Personal`'s answers and reports, as `Homes` takes them: kept by no
    /// test.
    #[msg]
    pub async fn assigned(&mut self) {}

    #[msg]
    pub async fn refused(&mut self, _error: PersonalError) {}

    #[msg]
    pub async fn record(&mut self, _nullifier: [u8; 32]) {}

    #[msg]
    pub async fn forget(&mut self, _nullifier: [u8; 32]) {}

    #[msg]
    pub async fn rekey(&mut self, _keys: Vec<[u8; 32]>) {}
}
