//! `CredentialBook`, a local actor (`light-node.md` §3.1): what the user
//! confirmed of each space it is a member of, synced among its devices.
//!
//! - **Memberships:** each space by its id, its name, its credential actor
//!   and the agents of it the user's devices call, with the identity each
//!   one's queries are signed over.
//! - **Handles:** each device's handle in a space, which its secret source
//!   is asked for, and the member digest its leaf is and its owner digest,
//!   as the registrar's person record holds them: public, so a device keeps
//!   its path from a session's start without asking the source, and
//!   another device enrolls or revokes it by its owner proof. A
//!   device's secret, its source's output and its member tree stay on the
//!   device, outside any synced scope.
//! - **Pins:** each method a device may prove for in a space, and the
//!   guard it proves under.
//!
//! Each field is a last-writer-wins map, a removal a write of none, so
//! leaving a space drops its membership and its handles and pins are
//! dropped one by one. A merge handler refuses what is out of bounds, so
//! its operation is never recorded, and a device applying a peer's that
//! its handler refuses quarantines it.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_wire::books::{
    AGENTS, BookError, DeviceHandle, Enrolled, Guard, Location, Pinned, Space, named,
};

#[actor]
pub struct CredentialBook {
    /// Each membership, by its space.
    spaces: crdt::Map<Space, Enrolled>,
    /// Each device's handle, by the space and the device's id in the
    /// device set.
    handles: crdt::Map<(Space, u32), DeviceHandle>,
    /// Each pinned method's guard, by the space, the agent, the instance
    /// and the method's name.
    pins: crdt::Map<(Space, (u32, (u32, String))), Guard>,
}

#[messages]
impl CredentialBook {
    pub fn new() -> Self {
        Self {
            spaces: Default::default(),
            handles: Default::default(),
            pins: Default::default(),
        }
    }

    /// Record the membership of `space`, or replace it.
    #[msg(merge)]
    pub async fn join(&mut self, space: Space, enrolled: Enrolled) -> Result<(), BookError> {
        if !named(&enrolled.name) || enrolled.agents.len() > AGENTS {
            return Err(BookError::Bounds);
        }
        self.spaces.insert(&space, &enrolled);
        Ok(())
    }

    /// Drop the membership of `space`.
    #[msg(merge)]
    pub async fn leave(&mut self, space: Space) {
        self.spaces.remove(&space);
    }

    /// Record `device`'s handle in `space`.
    #[msg(merge)]
    pub async fn handle(&mut self, space: Space, device: u32, handle: DeviceHandle) {
        self.handles.insert(&(space, device), &handle);
    }

    /// Drop `device`'s handle in `space`.
    #[msg(merge)]
    pub async fn unhandle(&mut self, space: Space, device: u32) {
        self.handles.remove(&(space, device));
    }

    /// Pin `pin` in `space`.
    #[msg(merge)]
    pub async fn pin(&mut self, space: Space, pin: Pinned) -> Result<(), BookError> {
        let scoped = match &pin.guard {
            Guard::Auth { scope, .. } => named(scope),
            Guard::Owner => true,
        };
        if !named(&pin.method) || !scoped {
            return Err(BookError::Bounds);
        }
        let key = (space, (pin.at.agent, (pin.at.instance, pin.method)));
        self.pins.insert(&key, &pin.guard);
        Ok(())
    }

    /// Unpin `method` at `at` in `space`.
    #[msg(merge)]
    pub async fn unpin(&mut self, space: Space, at: Location, method: String) {
        self.pins
            .remove(&(space, (at.agent, (at.instance, method))));
    }

    /// The membership of `space`, if the user is a member.
    #[msg]
    pub async fn member_of(&self, space: Space) -> Option<Enrolled> {
        self.spaces.get(&space)
    }

    /// Every membership, by space.
    #[msg(gas = 50_000_000)]
    pub async fn spaces(&self) -> Vec<(Space, Enrolled)> {
        self.spaces.iter(None).collect()
    }

    /// The devices' handles in `space`, by device.
    #[msg(gas = 50_000_000)]
    pub async fn handles(&self, space: Space) -> Vec<(u32, DeviceHandle)> {
        self.handles
            .iter(None)
            .filter(|((at, _), _)| *at == space)
            .map(|((_, device), handle)| (device, handle))
            .collect()
    }

    /// The methods pinned in `space`.
    #[msg(gas = 50_000_000)]
    pub async fn pins(&self, space: Space) -> Vec<Pinned> {
        self.pins
            .iter(None)
            .filter(|((at, _), _)| *at == space)
            .map(|((_, (agent, (instance, method))), guard)| Pinned {
                at: Location { agent, instance },
                method,
                guard,
            })
            .collect()
    }
}
