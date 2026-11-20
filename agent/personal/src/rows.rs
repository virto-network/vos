//! The rows `Personal` keeps for itself, beside the wire's: each encoding
//! fixed for good, as every row's (the layout is append-only).

use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_wire::personal::{DeviceId, KitEntry, NewKit, Pending};

/// The control log's next index and its chain so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Head {
    pub next: u64,
    pub chain: [u8; 32],
}

/// The device group as the agent orders it: the confirmed epoch, the
/// pending candidate, and the devices added so far.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Group {
    pub confirmed: u64,
    pub candidate: Option<Candidate>,
    pub devices: DeviceId,
}

/// The pending candidate: its epoch, its log entry, its committer, its
/// effect and its confirming set.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Candidate {
    pub epoch: u64,
    pub index: u64,
    pub by: DeviceId,
    pub created: u64,
    pub added: Option<DeviceId>,
    /// The matured add operation whose device it adds.
    pub carries: Option<u64>,
    pub removes: Vec<DeviceId>,
    pub set: Vec<DeviceId>,
    /// The kit re-sealed under a new `R`, its `R2` deposited by the
    /// commit's evidence: the kit's from the commit's confirmation.
    pub rekey: Option<NewKit>,
}

impl Candidate {
    pub fn pending(self) -> Pending {
        Pending {
            epoch: self.epoch,
            index: self.index,
            set: self.set,
        }
    }
}

/// The lease: until when it runs, when the claim took the agent, and
/// whether a re-proof lifted the quota: one five sixths of a lease after
/// the claim at least, in the lease's last sixth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Lease {
    pub until: u64,
    pub reproved: bool,
    pub claimed: u64,
}

/// What the agent holds and took today, against its quotas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Usage {
    /// Envelopes' and inbox items' bytes held.
    pub bytes: u64,
    /// The day, in batch time, the counts below are of.
    pub day: u64,
    pub envelopes: u32,
    pub commits: u32,
    /// Inbox items held, expired ones until a write deletes them.
    pub items: u32,
    /// The kit's operations today.
    pub kit_operations: u32,
}

impl Usage {
    /// The usage as of `day`: today's counts started afresh on a later day.
    pub fn on(self, day: u64) -> Self {
        if self.day == day {
            return self;
        }
        Self {
            day,
            envelopes: 0,
            commits: 0,
            kit_operations: 0,
            ..self
        }
    }
}

/// A device's share: its bytes held and its counted calls today.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Share {
    pub bytes: u64,
    pub day: u64,
    pub calls: u32,
}

/// What a quota counts a call as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    Envelope,
    Commit,
    Item,
}

/// A stored envelope's row: its id, its author and its length, its bytes
/// in a row of their own, which a read fetches only when they fit its
/// answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Stored {
    pub id: [u8; 32],
    pub author: DeviceId,
    pub len: u32,
}

/// The recovery kit's state beside its entries: the recovery scope's
/// position its envelopes start after, and the previous `R2` a matured
/// restore released, with the device it added and the entries it
/// replaced.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Recovery {
    pub from: u64,
    pub released: Option<(DeviceId, [u8; 32])>,
    pub previous: Vec<KitEntry>,
}

/// An open pairing slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Slot {
    pub opener: DeviceId,
    pub key: [u8; 32],
    pub expires: u64,
    /// The items its holder wrote.
    pub items: u32,
}
