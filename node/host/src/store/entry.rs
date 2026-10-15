//! A log entry: what it holds, and its payload's codec.

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

/// One log entry: what it holds, the term it was proposed in, and the
/// blobs it depends on, which the store reads without decoding the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub kind: EntryKind,
    pub blobs: Vec<BlobRef>,
    pub body: Vec<u8>,
}

impl LogEntry {
    /// A work result held inline.
    pub fn result(term: u64, body: Vec<u8>) -> Self {
        Self {
            term,
            kind: EntryKind::Result,
            blobs: Vec::new(),
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

    /// The entry without its term: its kind, its blobs and its body, as a
    /// Raft data entry carries it.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.blobs.len() * 40 + self.body.len());
        out.push(self.kind as u8);
        let count = u16::try_from(self.blobs.len()).expect("at most 65,535 blobs per entry");
        out.extend_from_slice(&count.to_be_bytes());
        for blob in &self.blobs {
            out.extend_from_slice(&blob.hash);
            out.extend_from_slice(&blob.len.to_be_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// The length of the large work result `payload` names, if its entry
    /// is one, read without copying the body.
    pub fn result_len(payload: &[u8]) -> Option<u64> {
        let (&kind, rest) = payload.split_first()?;
        let (count, rest) = rest.split_first_chunk::<2>()?;
        if kind != EntryKind::LargeResult as u8 || *count == [0; 2] {
            return None;
        }
        let len = rest.get(32..40)?;
        Some(u64::from_be_bytes(len.try_into().expect("8 bytes")))
    }

    /// The entry at `term` whose payload is `payload`.
    pub fn from_payload(term: u64, payload: &[u8]) -> Option<Self> {
        let (kind, blobs, body) = split(payload)?;
        Some(Self {
            term,
            kind,
            blobs,
            body: body.to_vec(),
        })
    }

    /// The blobs the entry whose payload is `payload` names, read without
    /// copying its body.
    pub(super) fn blob_refs(payload: &[u8]) -> Option<Vec<BlobRef>> {
        Some(split(payload)?.1)
    }
}

/// What `payload` holds: its kind, its blobs, and the body after them.
fn split(payload: &[u8]) -> Option<(EntryKind, Vec<BlobRef>, &[u8])> {
    let (&kind, rest) = payload.split_first()?;
    let kind = EntryKind::from_u8(kind)?;
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
    Some((kind, blobs, rest))
}
