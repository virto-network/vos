//! A log entry: what it holds, and its payload's codec.

use super::NodeNumber;

/// A work result of this many bytes or more is stored as a blob, which its
/// log entry names: inline, entries this large hold up every agent's small
/// ones behind their writes.
pub const LARGE_RESULT: usize = 64 << 10;

// An append carries entries up to vos-raft's 1 MiB cap, or one larger entry
// alone, and a work result is inline only under `LARGE_RESULT`.
const _: () = assert!(
    vos_net::Limits::DEFAULT.consensus >= (1 << 20) + LARGE_RESULT + (64 << 10),
    "a consensus frame must hold an append"
);

/// What a log entry holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    /// A new leader's first entry in its term.
    NoOp = 0,
    /// A work result.
    Result = 1,
    /// A change to the agent's replica set.
    Configuration = 2,
    /// A work result of [`LARGE_RESULT`] bytes or more: the entry's first
    /// blob, its body empty.
    LargeResult = 3,
}

/// The bit of a payload's kind byte saying origins follow its blobs.
const WITH_ORIGINS: u8 = 0x80;

impl EntryKind {
    fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::NoOp,
            1 => Self::Result,
            2 => Self::Configuration,
            3 => Self::LargeResult,
            _ => return None,
        })
    }
}

/// A blob an entry depends on: a large work result, or a program it
/// installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobRef {
    pub hash: [u8; 32],
    pub len: u64,
}

/// Who proposed one of a work result's credentialed inputs at the leader:
/// the replica that took it at its ingress, and the token its forward
/// waits under. Beside the result, never in it: replicas read it to answer
/// their own clients, and no proof covers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The input's position among the batch's.
    pub input: u16,
    pub node: NodeNumber,
    pub token: u64,
}

/// One log entry: what it holds, the term it was proposed in, the blobs it
/// depends on, which the store reads without decoding the body, and its
/// credentialed inputs' origins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub kind: EntryKind,
    pub blobs: Vec<BlobRef>,
    pub origins: Vec<Origin>,
    pub body: Vec<u8>,
}

impl LogEntry {
    /// A work result held inline.
    pub fn result(term: u64, body: Vec<u8>) -> Self {
        Self {
            term,
            kind: EntryKind::Result,
            blobs: Vec::new(),
            origins: Vec::new(),
            body,
        }
    }

    /// The blob holding a large work result, if the entry is one.
    pub fn result_blob(&self) -> Option<&BlobRef> {
        match self.kind {
            EntryKind::LargeResult => self.blobs.first(),
            _ => None,
        }
    }

    /// The entry without its term: its kind, its blobs, its origins if any
    /// (the kind byte's top bit set) and its body, as a Raft
    /// data entry carries it.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            5 + self.blobs.len() * 40 + self.origins.len() * 11 + self.body.len(),
        );
        let flag = if self.origins.is_empty() {
            0
        } else {
            WITH_ORIGINS
        };
        out.push(self.kind as u8 | flag);
        let count = u16::try_from(self.blobs.len()).expect("at most 65,535 blobs per entry");
        out.extend_from_slice(&count.to_be_bytes());
        for blob in &self.blobs {
            out.extend_from_slice(&blob.hash);
            out.extend_from_slice(&blob.len.to_be_bytes());
        }
        if !self.origins.is_empty() {
            let count =
                u16::try_from(self.origins.len()).expect("at most 65,535 origins per entry");
            out.extend_from_slice(&count.to_be_bytes());
            for origin in &self.origins {
                out.extend_from_slice(&origin.input.to_be_bytes());
                out.push(origin.node);
                out.extend_from_slice(&origin.token.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// The length of the large work result `payload` names, if its entry
    /// is one, read without copying the body.
    pub fn result_len(payload: &[u8]) -> Option<u64> {
        let (&kind, rest) = payload.split_first()?;
        let (count, rest) = rest.split_first_chunk::<2>()?;
        if kind & !WITH_ORIGINS != EntryKind::LargeResult as u8 || *count == [0; 2] {
            return None;
        }
        let len = rest.get(32..40)?;
        Some(u64::from_be_bytes(len.try_into().expect("8 bytes")))
    }

    /// The entry at `term` whose payload is `payload`.
    pub fn from_payload(term: u64, payload: &[u8]) -> Option<Self> {
        let (kind, blobs, origins, body) = split(payload)?;
        Some(Self {
            term,
            kind,
            blobs,
            origins,
            body: body.to_vec(),
        })
    }

    /// The blobs the entry whose payload is `payload` names, read without
    /// copying its body.
    pub(super) fn blob_refs(payload: &[u8]) -> Option<Vec<BlobRef>> {
        Some(split(payload)?.1)
    }
}

/// A payload's kind, blobs, origins, and the body after them.
type Parts<'a> = (EntryKind, Vec<BlobRef>, Vec<Origin>, &'a [u8]);

/// What `payload` holds.
fn split(payload: &[u8]) -> Option<Parts<'_>> {
    let (&byte, rest) = payload.split_first()?;
    let kind = EntryKind::from_u8(byte & !WITH_ORIGINS)?;
    let (count, mut rest) = rest.split_first_chunk::<2>()?;
    let mut blobs = Vec::with_capacity(usize::from(u16::from_be_bytes(*count)));
    for _ in 0..u16::from_be_bytes(*count) {
        let (hash, after) = rest.split_first_chunk::<32>()?;
        let (len, after) = after.split_first_chunk::<8>()?;
        blobs.push(BlobRef {
            hash: *hash,
            len: u64::from_be_bytes(*len),
        });
        rest = after;
    }
    let mut origins = Vec::new();
    if byte & WITH_ORIGINS != 0 {
        let (count, after) = rest.split_first_chunk::<2>()?;
        rest = after;
        for _ in 0..u16::from_be_bytes(*count) {
            let (input, after) = rest.split_first_chunk::<2>()?;
            let (&node, after) = after.split_first()?;
            let (token, after) = after.split_first_chunk::<8>()?;
            origins.push(Origin {
                input: u16::from_be_bytes(*input),
                node,
                token: u64::from_be_bytes(*token),
            });
            rest = after;
        }
    }
    Some((kind, blobs, origins, rest))
}
