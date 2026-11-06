//! The rows `Personal` keeps for itself, beside the wire's: each encoding
//! fixed for good, as every row's (the layout is append-only).

use vos_sdk::prelude::*;
use vos_wire::personal::{DeviceId, Pending};

/// The key of a table holding one row.
pub const ONE: u8 = 0;

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
    pub removes: Vec<DeviceId>,
    pub set: Vec<DeviceId>,
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

/// The lease: until when it runs, and whether a re-proof renewed it once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Lease {
    pub until: u64,
    pub reproved: bool,
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

/// An open pairing slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Slot {
    pub opener: DeviceId,
    pub key: [u8; 32],
    pub expires: u64,
    /// The items its holder wrote.
    pub items: u32,
}
