//! The rows `Personal` keeps for itself, beside the wire's: each encoding
//! fixed for good, as every row's (the layout is append-only).

use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_sdk::table::{FixedKey, TableKey};
use vos_wire::personal::{DeviceId, KitEntry, NewKit, Pending, Signer};

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

/// What the due index holds at a time: an operation's maturity, a removed
/// device's silencing (its operations cancelled and its vetoes lifted, a
/// row a step), or a replaced kit's retirement (its operations cancelled).
/// At one time they settle in that order: operations by their index, then
/// silencings by the device, then the retirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Due {
    Op(u64),
    Silence(DeviceId),
    Retire,
}

impl Due {
    const OP: u8 = 0;
    const SILENCE: u8 = 1;
    const RETIRE: u8 = 2;
}

/// Its tag, then its operation's index or its device, big-endian: keys
/// compare as the values do.
impl TableKey for Due {
    fn encode_key(&self, out: &mut Vec<u8>) {
        match self {
            Due::Op(index) => {
                out.push(Due::OP);
                index.encode_key(out);
            }
            Due::Silence(device) => {
                out.push(Due::SILENCE);
                device.encode_key(out);
            }
            Due::Retire => out.push(Due::RETIRE),
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (tag, rest) = bytes.split_first()?;
        match *tag {
            Due::OP => u64::decode_key(rest).map(Due::Op),
            Due::SILENCE => DeviceId::decode_key(rest).map(Due::Silence),
            Due::RETIRE if rest.is_empty() => Some(Due::Retire),
            _ => None,
        }
    }
}

/// An operation's signer as the first part of a key: a device's id, or a
/// kit entry's, each after its tag and big-endian in four bytes, so the
/// devices' keys sort before the kit's and each signer's rows are a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct By(pub Signer);

impl By {
    const DEVICE: u8 = 0;
    const KIT: u8 = 1;
}

impl TableKey for By {
    fn encode_key(&self, out: &mut Vec<u8>) {
        let (tag, id) = match self.0 {
            Signer::Device(device) => (By::DEVICE, device),
            Signer::Kit(entry) => (By::KIT, u32::from(entry)),
        };
        out.push(tag);
        id.encode_key(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (tag, rest) = bytes.split_first()?;
        let id = u32::decode_key(rest)?;
        match *tag {
            By::DEVICE => Some(By(Signer::Device(id))),
            By::KIT => u8::try_from(id).ok().map(|entry| By(Signer::Kit(entry))),
            _ => None,
        }
    }
}

impl FixedKey for By {
    const WIDTH: usize = 5;
}

/// The kinds of operation of which one is open at a time, for a target or
/// for the agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Remove = 0,
    Replace = 1,
    /// A kit rotation or a restore.
    Kit = 2,
    Regroup = 3,
}

/// Its one byte.
impl TableKey for Kind {
    fn encode_key(&self, out: &mut Vec<u8>) {
        (*self as u8).encode_key(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(match u8::decode_key(bytes)? {
            0 => Kind::Remove,
            1 => Kind::Replace,
            2 => Kind::Kit,
            3 => Kind::Regroup,
            _ => return None,
        })
    }
}

impl FixedKey for Kind {
    const WIDTH: usize = 1;
}

/// The key just before every key that starts with a value: so the rows of
/// an ordered table keyed `(A, B)` whose first part is `a` start after
/// `(a.before(), B::MAX)`.
pub trait Before: Sized {
    fn before(&self) -> Option<Self>;
}

impl Before for u32 {
    fn before(&self) -> Option<Self> {
        self.checked_sub(1)
    }
}

impl Before for u64 {
    fn before(&self) -> Option<Self> {
        self.checked_sub(1)
    }
}

impl Before for By {
    fn before(&self) -> Option<Self> {
        Some(By(match self.0 {
            Signer::Device(device) => Signer::Device(device.checked_sub(1)?),
            Signer::Kit(0) => Signer::Device(DeviceId::MAX),
            Signer::Kit(entry) => Signer::Kit(entry - 1),
        }))
    }
}
