//! The merge lane's rows (`core-model.md` §9.4): a merge field keeps one
//! entry an element or key and author, and a read takes the latest entry
//! among the authors not filtered out.
//!
//! - **An operation** is a merge handler's run on a device, named by its
//!   [`Origin`]: its author, the author's sequence number, the Lamport
//!   clock of the DAG node that carries it and its index there. Every
//!   device that applies the node runs the handler again on the same
//!   operation, and writes the same entries.
//! - **An entry** ([`Entry`]) is the operation's stamp and the value it
//!   wrote, or its removal. Its bytes compare as the entries order, so an
//!   author's row keeps the later entry ([`Keep::Latest`]: a map's value,
//!   a set's add or remove) or the earlier ([`Keep::Earliest`]: a grow-only
//!   set's add) by comparing bytes, and two devices that apply the same
//!   operations in any order keep the same row.
//! - **A read** ([`latest`]) takes, among an element's entries, those whose
//!   author's [`Cutoff`] admits them, and the latest of these by Lamport
//!   clock, then author. An author is cut off where it equivocated, and
//!   where the device set removed it, past its frontier; its entries
//!   applied before that was known are filtered, never unapplied.

use alloc::vec::Vec;

use scale::{Decode, Encode};

pub use crate::abi::Keep;

/// The operation a merge handler's run is: its author's key, the author's
/// sequence number, the Lamport clock of the node that carries it, and its
/// index among the node's operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Origin {
    pub author: [u8; 32],
    pub seq: u64,
    pub lamport: u64,
    pub index: u32,
}

/// The bytes an entry's stamp takes: its Lamport clock, sequence number,
/// operation index and write index, big-endian.
const STAMP: usize = 8 + 8 + 4 + 4;

/// One author's entry for an element or key: the stamp of the write that
/// made it, and its value, `None` for a removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub lamport: u64,
    pub seq: u64,
    /// The operation's index in its node.
    pub index: u32,
    /// The write's index in the operation's run: a later write of one
    /// element replaces an earlier.
    pub write: u32,
    pub value: Option<&'a [u8]>,
}

impl<'a> Entry<'a> {
    /// The entry the `write`th write of the operation `origin` makes.
    pub fn new(origin: &Origin, write: u32, value: Option<&'a [u8]>) -> Self {
        Self {
            lamport: origin.lamport,
            seq: origin.seq,
            index: origin.index,
            write,
            value,
        }
    }

    /// Its bytes: the stamp's fields big-endian, then 0 for a removal or 1
    /// and the value. They compare as the entries order: by stamp, then a
    /// removal before a value, then by value.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STAMP + 1 + self.value.map_or(0, <[u8]>::len));
        bytes.extend_from_slice(&self.lamport.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.index.to_be_bytes());
        bytes.extend_from_slice(&self.write.to_be_bytes());
        match self.value {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(value);
            }
        }
        bytes
    }

    /// The entry `bytes` hold; `None` when they are not an entry's.
    pub fn read(bytes: &'a [u8]) -> Option<Self> {
        let (stamp, rest) = bytes.split_at_checked(STAMP)?;
        let (&present, value) = rest.split_first()?;
        let value = match present {
            0 if value.is_empty() => None,
            1 => Some(value),
            _ => return None,
        };
        let word = |at: usize| u64::from_be_bytes(stamp[at..at + 8].try_into().expect("8 bytes"));
        let half = |at: usize| u32::from_be_bytes(stamp[at..at + 4].try_into().expect("4 bytes"));
        Some(Self {
            lamport: word(0),
            seq: word(8),
            index: half(16),
            write: half(20),
            value,
        })
    }
}

/// Whether the entry `new` replaces the author's stored entry `old` (both
/// as [`Entry::encode`] writes them) under `keep`: none stored, or `new`
/// later (earlier) than it.
pub fn replaces(new: &[u8], old: Option<&[u8]>, keep: Keep) -> bool {
    match (old, keep) {
        (None, _) => true,
        (Some(old), Keep::Latest) => new > old,
        (Some(old), Keep::Earliest) => new < old,
    }
}

/// An author's cutoff in a scope: its operations at sequence number `0.0`
/// and later are filtered when read. Where it equivocated, at the
/// equivocation's number; where the device set removed it, one past its
/// frontier. The lower of two stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Cutoff(pub u64);

impl Cutoff {
    /// Whether it admits an operation at `seq`.
    pub const fn admits(self, seq: u64) -> bool {
        seq < self.0
    }
}

/// A stored entry that is not an entry's bytes: state no merge handler
/// wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// The latest of `entries`, each an author and its entry's bytes, whose
/// author's cutoff (`cutoff`, `None` for an author not cut off) admits it:
/// by Lamport clock, then author. `None` when none is admitted.
pub fn latest<'a>(
    entries: impl IntoIterator<Item = ([u8; 32], &'a [u8])>,
    mut cutoff: impl FnMut(&[u8; 32]) -> Option<Cutoff>,
) -> Result<Option<Entry<'a>>, Malformed> {
    let mut best: Option<(u64, [u8; 32], Entry<'a>)> = None;
    for (author, bytes) in entries {
        let entry = Entry::read(bytes).ok_or(Malformed)?;
        if cutoff(&author).is_some_and(|cutoff| !cutoff.admits(entry.seq)) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(lamport, best, _)| (entry.lamport, author) > (*lamport, *best))
        {
            best = Some((entry.lamport, author, entry));
        }
    }
    Ok(best.map(|(_, _, entry)| entry))
}
