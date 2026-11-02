//! An actor whose agent admits a session only from a key it holds and a
//! request only through the onion (`#[actor(known_keys, onion_only)]`),
//! and a door, in an agent of its own that asks nothing, through which
//! another agent's message admits a key to it.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

#[actor(known_keys, onion_only)]
pub struct Gated {
    count: u64,
    /// The keys ingress admits to create a session.
    admitted: Table<[u8; 32], ()>,
}

#[messages]
impl Gated {
    pub fn new() -> Self {
        Self {
            count: 0,
            admitted: Table::default(),
        }
    }

    /// Admit `key` to create a session.
    #[msg]
    pub async fn admit(&mut self, key: [u8; 32]) {
        self.admitted.insert(&key, &());
    }

    /// Admit `key` no more: a session it holds goes on.
    #[msg]
    pub async fn revoke(&mut self, key: [u8; 32]) {
        self.admitted.remove(&key);
    }

    #[msg]
    pub async fn bump(&mut self) -> u64 {
        self.count += 1;
        self.count
    }

    #[msg]
    pub async fn count(&self) -> u64 {
        self.count
    }
}

#[actor]
pub struct Door {}

#[messages]
impl Door {
    pub fn new() -> Self {
        Self {}
    }

    /// Admit `key` to the gated actor at `instance` of agent `agent`, by
    /// message.
    #[msg]
    pub async fn admit(
        &mut self,
        ctx: &mut Command<Self>,
        agent: u32,
        instance: u32,
        key: [u8; 32],
    ) {
        ctx.send(
            AgentId(agent),
            Ref::<Gated>::new(InstanceId(instance)),
            gated::Admit { key },
        );
    }
}
