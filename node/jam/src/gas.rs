//! A package's own work on JAM, beyond its batch's budget, estimated: the
//! builder gives the batch what the work package's refine gas leaves past
//! it.
//!
//! The work is mostly BLAKE2b, computed in software on a JAM node: each
//! compression about 19,000 gas, after the precompile's call, which
//! PolkaJam answers `WHAT` for 1,000.

use vos_tree::Entry;
use vos_wire::abi::cap::{self, Limits};
use vos_wire::abi::price;
use vos_wire::defaults;
use vos_wire::package::{Package, SEGMENT, result_segments};

use crate::simulate::Simulation;

/// A software BLAKE2b compression on JAM, its failed precompile call
/// included, with room to spare.
pub(crate) const COMPRESSION: u64 = 24_000;
/// An export: the call and its copy.
pub(crate) const EXPORT: u64 = 6_000;
/// The agent's own work on one row the apply writes, beyond hashing it.
pub(crate) const WRITE: u64 = 40_000;
/// The agent's own work on one row its witness opens, a key or a scanned
/// range's row, beyond hashing it: decoding and serving it.
pub(crate) const ROW: u64 = 20_000;
/// The agent's start and finish on JAM: entering, verifying, exporting.
pub(crate) const FIXED: u64 = 3_000_000;

/// The compressions hashing `len` bytes takes.
const fn compressions(len: usize) -> u64 {
    if len == 0 {
        return 1;
    }
    len.div_ceil(128) as u64
}

/// The compressions of a value's commitment: its tag, salt and value.
const fn commitment(value: usize) -> u64 {
    compressions(30 + value)
}

/// The compressions of a leaf: its tag, its key's length and the key, and
/// its value's commitment.
const fn leaf(key: usize) -> u64 {
    compressions(15 + key + 32)
}

/// The compressions a row the apply writes takes beyond its value's
/// commitment: its salt, its leaf, and the branch over it.
const fn rewrite(key: usize) -> u64 {
    compressions(13 + 32 + key) + leaf(key) + 1
}

/// What `len` bytes of a package's work result take: decoded, hashed with
/// the rest, and exported.
const fn result_bytes(len: usize) -> u64 {
    defaults::DECODE_BYTE * len as u64
        + COMPRESSION * compressions(len)
        + (EXPORT + SEGMENT as u64) * result_segments(len) as u64
}

/// A branch a witness opens: hashed to verify the witness, and again once
/// the apply has written the rows under it.
const BRANCH: u64 = 2 * COMPRESSION;

/// A row a witness opens with a value of `value` bytes under a key of
/// `key` bytes, beside the branches over it: served, its value's
/// commitment and its leaf hashed.
const fn opened(key: usize, value: usize) -> u64 {
    ROW + COMPRESSION * (commitment(value) + leaf(key))
}

/// A row the apply writes under a key of `key` bytes, its value of `value`
/// bytes, or (`None`) its deletion, beside the branches over it.
const fn written(key: usize, value: Option<usize>) -> u64 {
    let committed = match value {
        Some(value) => commitment(value),
        None => 0,
    };
    WRITE + COMPRESSION * (rewrite(key) + committed)
}

/// A page row's key: its row's two bytes, its workflow and its index.
const PAGE_KEY: usize = 2 + 8 + 4;
/// A page row's value on JAM: the page's hash, stored.
const PAGE_VALUE: usize = 1 + 32;
/// A held page in its workflow's record: its index and its hash.
const RECORD_PAGE: usize = 4 + 32;

/// What each page a workflow holds adds to the own work of a package whose
/// step restores it: its row opened, the branch over it (a workflow's page
/// rows lie together in key order, under as many branches as rows but
/// one), and its index and hash in the workflow's record, whose commitment
/// they lengthen.
pub const PAGE_READ: u64 =
    opened(PAGE_KEY, PAGE_VALUE) + BRANCH + (COMPRESSION * RECORD_PAGE as u64).div_ceil(128);
/// What each page a workflow holds adds to the own work of a package whose
/// step drops it, ending the workflow: its row deleted, and its entry in
/// the work result, a page's workflow, index and absent hash.
pub const PAGE_DROP: u64 =
    written(PAGE_KEY, None) + defaults::DECODE_BYTE * 13 + (COMPRESSION * 13).div_ceil(128);
/// What each page a workflow holds adds to the payload of a package whose
/// step restores it: its key and its opened row in the witness, its leaf
/// and the branch over it in the proof, its import, and its index and hash
/// in the workflow's record.
pub(crate) const PAGE_PAYLOAD: usize =
    (1 + PAGE_KEY) + (1 + 16 + 1 + PAGE_VALUE) + (2 + PAGE_KEY + 32) + 3 + 12 + RECORD_PAGE;

/// The branches above each row a package's bounds allow: the depth of a
/// tree of 2^64 rows balanced. The estimate counts a witness's branches as
/// they are, so a deeper path lowers the budget past the bound.
const PATH: u64 = 64;
/// The most a workflow's record holds beside its pages: its fields, and its
/// arguments, last input or result at their cap.
const RECORD: usize = 1024 + cap::REQUEST;
/// A workflow's record's key.
const RECORD_KEY: usize = 2 + 8;
/// The reply a workflow's end sends an agent that waits for it, in its
/// outbox: the result at its cap, framed.
const REPLY: usize = cap::REPLY + 40;
/// An outbox row's key.
const OUTBOX_KEY: usize = 2 + 4 + 8;
/// The other rows an ending step reads and writes: its rows of the due
/// index, from and to, the counts of live workflows and of its program's
/// pins, the sequence of the pair it replies on, and the version. Keys of
/// at most `SMALL_KEY` bytes, values of at most `SMALL_VALUE`.
const SMALL_ROWS: u64 = 6;
const SMALL_KEY: usize = 40;
const SMALL_VALUE: usize = 16;

/// What the step that ends a workflow adds to its package's own work
/// beyond its pages' ([`PAGE_READ`], [`PAGE_DROP`]): the agent's start and
/// finish; the workflow's record, opened at the most it holds and written
/// ended with its result at its cap; the reply to an agent waiting for it;
/// the other rows it moves; `PATH`, 64, branches over each of these rows and
/// over the pages; and the work result, which holds the record and the
/// reply.
pub const ENDING: u64 = FIXED
    + opened(RECORD_KEY, RECORD)
    + written(RECORD_KEY, Some(RECORD))
    + written(OUTBOX_KEY, Some(REPLY))
    + SMALL_ROWS * (opened(SMALL_KEY, SMALL_VALUE) + written(SMALL_KEY, Some(SMALL_VALUE)))
    + (SMALL_ROWS + 3) * PATH * BRANCH
    + result_bytes(1024 + RECORD + REPLY);
/// What each page a step stores adds to its package's own work: its row
/// written, holding its hash, and its export.
pub const PAGE_STORE: u64 =
    written(PAGE_KEY, Some(PAGE_VALUE)) + EXPORT + SEGMENT as u64 + defaults::DECODE_BYTE * 45;

/// A row a step writes beside its key and value: the work result's framing
/// of a write, and an agent's key prefix.
const ROW_FRAMING: usize = 18;
/// An outbox row's value beside its message's arguments: its body's
/// framing.
const MESSAGE_FRAMING: usize = 40;

/// What a step's effects at `limits` add to its package's own work, at
/// most: its writes in the work result and applied, each row salted,
/// committed and put; each message in the result and in its outbox row; and
/// each attest, its arguments and output, in the result. The rows a step
/// writes are as many as its limit, or as its gas pays for at the most a
/// workflow's step may use, twice a handler's largest limit, whichever is
/// fewer.
pub const fn effects(limits: &Limits) -> u64 {
    let by_gas = (2 * defaults::MAX_HANDLER_GAS / price::PUT) as usize;
    let rows = if limits.step_rows < by_gas {
        limits.step_rows
    } else {
        by_gas
    };
    let writes = result_bytes(limits.step_writes + rows * ROW_FRAMING)
        + rows as u64 * (WRITE + COMPRESSION * 4)
        + COMPRESSION * compressions(limits.step_writes);
    let message = limits.message + MESSAGE_FRAMING;
    let messages =
        limits.messages as u64 * (result_bytes(message) + written(OUTBOX_KEY, Some(message)));
    let attests = limits.attests as u64 * result_bytes(2 * limits.attest + MESSAGE_FRAMING);
    writes + messages + attests
}

/// The same for its package's payload: the package's batch and framing, the
/// record and the other rows opened, and the paths' entries, each branch
/// and its closed sibling.
pub(crate) const ENDING_PAYLOAD: usize = 1024
    + (1 + RECORD_KEY + 1 + 16 + 4 + RECORD)
    + SMALL_ROWS as usize * (2 * SMALL_KEY + SMALL_VALUE + 56)
    + (SMALL_ROWS as usize + 3) * PATH as usize * (3 + 33);

/// What hashing a pruned tree's entries takes: each opened leaf and each
/// branch.
fn proof(entries: &[Entry]) -> u64 {
    entries
        .iter()
        .map(|entry| match entry {
            Entry::Branch(_) => 1,
            Entry::Leaf { key, .. } => leaf(key.len()),
            Entry::Hash(_) | Entry::Empty => 0,
        })
        .sum()
}

/// The gas `package`'s refine takes beyond its batch's budget and the
/// decoding of its arguments, from what `simulation` found:
/// - verifying its witness: each value's commitment, and each opened leaf
///   and branch of its proofs, and decoding and serving each row;
/// - applying its work result: decoding it, then each row it writes
///   salted, committed and put, every branch its witness opens rehashed;
/// - exporting its pages and its work result, and hashing the result.
pub(crate) fn own(package: &Package, simulation: &Simulation) -> u64 {
    let witness = &package.witness;
    let mut hashes = proof(&witness.proof.entries);
    for (_, opened) in &witness.keys {
        if let vos_wire::package::Opened::Value { value, .. } = opened {
            hashes += commitment(value.len());
        }
    }
    let mut rows = witness.keys.len() as u64;
    for range in &witness.ranges {
        rows += range.rows.len() as u64;
        hashes += proof(&range.proof.entries);
        hashes += range
            .rows
            .iter()
            .map(|row| commitment(row.value.len()))
            .sum::<u64>();
    }
    let branches = witness
        .proof
        .entries
        .iter()
        .filter(|entry| matches!(entry, Entry::Branch(_)))
        .count() as u64;
    for (key, value) in &simulation.writes {
        hashes += rewrite(key.len());
        if let Some(value) = value {
            hashes += commitment(value.len());
        }
    }
    let writes = simulation.writes.len() as u64;
    hashes += branches;
    let exported = (simulation.pages * SEGMENT) as u64 + EXPORT * simulation.pages as u64;
    FIXED
        + result_bytes(simulation.encoded.len())
        + exported
        + COMPRESSION * hashes
        + ROW * rows
        + WRITE * writes
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use vos_tree::{Blake2b, Hash, Hasher, leaf_hash};
    use vos_wire::abi::Rows;
    use vos_wire::ids::InstanceId;
    use vos_wire::keys::{self, Transform};

    use super::{compressions, leaf};
    use crate::gas::cap;

    /// BLAKE2b, counting the compressions its hashes make: one per 128-byte
    /// block of input.
    struct Counting(Cell<u64>);

    impl Hasher for Counting {
        fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash {
            let len = tag.len() + parts.iter().map(|part| part.len()).sum::<usize>();
            self.0.set(self.0.get() + compressions(len));
            Blake2b.hash(tag, parts)
        }
    }

    /// The compressions of the leaf of `raw`'s committed row, as hashed
    /// and as estimated, which agree.
    fn leaf_compressions(raw: &[u8], transform: Transform) -> u64 {
        let rows = Rows::Committed { tag: 2, transform };
        let row = keys::row(InstanceId(1), rows, raw).unwrap();
        let counting = Counting(Cell::new(0));
        leaf_hash(&counting, &row, &[0; 32]);
        assert_eq!(counting.0.get(), leaf(row.len()), "{} bytes", row.len());
        counting.0.get()
    }

    /// A committed row's leaf at an ordered key of 64 bytes, its zero bytes
    /// escaped, outgrows one block: two compressions, counted as two. At
    /// 64 bytes with none, and at a hashed key of 32, it takes one.
    #[test]
    fn a_long_ordered_keys_leaf_counts_two_compressions() {
        let zeros = [0; cap::ORDERED_KEY];
        assert_eq!(leaf_compressions(&zeros, Transform::Ordered), 2);
        assert_eq!(
            leaf_compressions(&[1; cap::ORDERED_KEY], Transform::Ordered),
            1
        );
        assert_eq!(leaf_compressions(&[7; 32], Transform::Hashed), 1);
    }
}
