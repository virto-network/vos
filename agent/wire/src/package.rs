//! JAM mode: a batch with the witness of the state it touches, and what
//! refine returns for it.
//!
//! On JAM the agent's whole keyspace is one tree ([`vos_tree`]), whose keys
//! are the row keys themselves, prefix-free ([`crate::keys`]), and whose
//! values are the rows as stored. Refine serves its state reads from the
//! package's witness, verified once against the root before, runs the batch
//! as a VOS node's refine does, applies its work result as a VOS node's
//! accumulate does ([`crate::apply`]), and computes the root after from the
//! witness. Accumulate only swaps roots ([`JamOutput`]).
//!
//! **Exports:** each page a step stores is a segment, the page then eight
//! zero bytes, in the order the result's runs list them; then the work
//! result's encoding, a segment at a time, the last zero-padded. The
//! builder keeps them, and where each page went: refine cannot know its
//! exports' segment root, which the guarantor computes, so accumulate
//! keeps the last package's ([`EXPORTS`]) beside the root. A package that
//! resumes a workflow imports its pages by that root, and refine checks
//! each against its row, which holds the page's hash.
//!
//! **Programs** an agent runs on JAM are preimages of its service, which
//! its accumulate solicits when a package names them ([`Package::solicit`]),
//! before any package installs or runs them.

use alloc::vec::Vec;
use scale::{Decode, Encode};
use vos_tree::{BatchProof, Hash, RangeProof, Salt};

use crate::batch::Batch;
use crate::defaults::SESSION_SKEW_MS;
use crate::ids::{ProgramHash, WorkflowId};

/// A segment's length: a page then eight zero bytes.
pub const SEGMENT: usize = 4104;
/// The most segments a package imports, and the most it exports.
pub const MAX_SEGMENTS: usize = 3072;

/// The key under which accumulate keeps the agent's root, in its service's
/// storage. Absent, the root is the empty tree's.
pub const ROOT: &[u8] = b"root";
/// The key under which accumulate keeps the last package it took's
/// [`Exports`]: where its pages and work result lie. The service's storage
/// holds nothing else.
pub const EXPORTS: &[u8] = b"exports";

/// A package's exports, as accumulate keeps the last one's: the work
/// package's hash, its exports' segment root, the pages first, then the
/// work result, `segments` in all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Exports {
    pub package: Hash,
    pub root: Hash,
    pub pages: u32,
    pub segments: u32,
}

/// The start of JAM's common era, 1200 UTC on 1 January 2025, in
/// milliseconds since the Unix epoch: slot 0's start.
pub const EPOCH_MS: u64 = 1_735_732_800_000;
/// A slot's length.
pub const SLOT_MS: u64 = 6_000;

/// A JAM work item's payload: a batch, the agent's root before it, the
/// witness of every row refine reads or writes against that root, the
/// page each of the item's imports holds, in import order, and the
/// programs, by hash and length, for accumulate to solicit as preimages.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Package {
    pub batch: Batch,
    pub root: Hash,
    pub witness: StateWitness,
    pub imports: Vec<(WorkflowId, u32)>,
    pub solicit: Vec<(ProgramHash, u32)>,
}

/// The rows a package's refine touches, against its root.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct StateWitness {
    /// Every key refine reads or writes, outside what it only scans, in
    /// strictly increasing order, each opened as refine needs it.
    pub keys: Vec<(Vec<u8>, Opened)>,
    /// Their paths: refine computes the root after from it.
    pub proof: BatchProof,
    /// The ranges refine scans, each shown complete, in key order and
    /// disjoint.
    pub ranges: Vec<Range>,
}

/// A key of the witness as refine needs it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Opened {
    #[codec(index = 0)]
    Absent,
    /// Present and read: its leaf's salt and its value as stored.
    #[codec(index = 1)]
    Value { salt: Salt, value: Vec<u8> },
    /// Present and written without being read: its value's commitment
    /// alone. Reading it traps.
    #[codec(index = 2)]
    Written(Hash),
}

/// A range of keys refine scans, `[from, to)`, `to` `None` for the tree's
/// right edge: every row in it, and the proof that they are all.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Range {
    pub from: Vec<u8>,
    pub to: Option<Vec<u8>>,
    pub rows: Vec<Row>,
    pub proof: RangeProof,
}

/// A row of a scanned range: its key, its leaf's salt and its value as
/// stored.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Row {
    pub key: Vec<u8>,
    pub salt: Salt,
    pub value: Vec<u8>,
}

/// Refine's output for a package, small, as JAM caps it: the roots before
/// and after, the batch's time and seed, the work result's hash, what it
/// exported: `pages` pages, then the work result, `exports` segments in
/// all; and the programs accumulate solicits, the package's.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct JamOutput {
    pub root_before: Hash,
    pub root_after: Hash,
    pub time: u64,
    pub seed: [u8; 32],
    /// The work result's encoding's [`crate::result::digest`].
    pub work_result_hash: Hash,
    pub pages: u32,
    pub exports: u32,
    pub solicit: Vec<(ProgramHash, u32)>,
}

/// The identity a client signs its calls to the agent of JAM service
/// `service` for ([`crate::ingress::call_message`]), as it signs for a
/// VOS node's agent by the agent's.
pub fn identity(service: u64) -> Hash {
    crate::result::digest(&[b"vos/jam/service".as_slice(), &service.to_le_bytes()].concat())
}

/// The segments a work result of `len` bytes takes.
pub const fn result_segments(len: usize) -> usize {
    len.div_ceil(SEGMENT)
}

/// Whether a batch at `time`, in milliseconds since the Unix epoch, may be
/// accumulated at `slot`: within the session skew of the slot, from its
/// start back to past its end. The builder chooses the time; the slot is
/// the chain's. Time never goes back in the agent's state, which refine's
/// apply checks.
pub fn timely(time: u64, slot: u64) -> bool {
    let start = EPOCH_MS.saturating_add(slot.saturating_mul(SLOT_MS));
    let end = start.saturating_add(SLOT_MS);
    time.saturating_add(SESSION_SKEW_MS) >= start && time <= end.saturating_add(SESSION_SKEW_MS)
}
