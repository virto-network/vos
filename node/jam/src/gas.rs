//! A package's own work on JAM, beyond its batch's budget, estimated: the
//! builder gives the batch what the work package's refine gas leaves past
//! it.
//!
//! The work is mostly BLAKE2b, computed in software on a JAM node: each
//! compression about 19,000 gas, after the precompile's call, which
//! PolkaJam answers `WHAT` for 1,000.

use vos_tree::Entry;
use vos_wire::defaults;
use vos_wire::package::{Package, SEGMENT, result_segments};

use crate::simulate::Simulation;

/// A software BLAKE2b compression on JAM, its failed precompile call
/// included, with room to spare.
pub const COMPRESSION: u64 = 24_000;
/// An export: the call and its copy.
pub const EXPORT: u64 = 6_000;
/// The agent's own work on one row the apply writes, beyond hashing it.
pub const WRITE: u64 = 40_000;
/// The agent's own work on one row its witness opens, a key or a scanned
/// range's row, beyond hashing it: decoding and serving it.
pub const ROW: u64 = 20_000;
/// The agent's start and finish on JAM: entering, verifying, exporting.
pub const FIXED: u64 = 3_000_000;

/// The compressions hashing `len` bytes takes.
fn compressions(len: usize) -> u64 {
    len.max(1).div_ceil(128) as u64
}

/// What hashing a pruned tree's entries takes: each opened leaf and each
/// branch.
fn proof(entries: &[Entry]) -> u64 {
    entries
        .iter()
        .map(|entry| match entry {
            Entry::Branch(_) => 1,
            Entry::Leaf { key, .. } => compressions(15 + key.len() + 32),
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
pub fn own(package: &Package, simulation: &Simulation) -> u64 {
    let witness = &package.witness;
    let mut hashes = proof(&witness.proof.entries);
    for (_, opened) in &witness.keys {
        if let vos_wire::package::Opened::Value { value, .. } = opened {
            hashes += compressions(30 + value.len());
        }
    }
    let mut rows = witness.keys.len() as u64;
    for range in &witness.ranges {
        rows += range.rows.len() as u64;
        hashes += proof(&range.proof.entries);
        hashes += range
            .rows
            .iter()
            .map(|row| compressions(30 + row.value.len()))
            .sum::<u64>();
    }
    let branches = witness
        .proof
        .entries
        .iter()
        .filter(|entry| matches!(entry, Entry::Branch(_)))
        .count() as u64;
    let mut writes = 0;
    for (key, value) in &simulation.writes {
        hashes += compressions(13 + 32 + key.len()) + compressions(15 + key.len() + 32) + 1;
        if let Some(value) = value {
            hashes += compressions(30 + value.len());
        }
        writes += 1;
    }
    hashes += branches + compressions(simulation.encoded.len());
    let exports = (simulation.pages + result_segments(simulation.encoded.len())) as u64;
    let copied = exports * SEGMENT as u64;
    FIXED
        + defaults::DECODE_BYTE * simulation.encoded.len() as u64
        + COMPRESSION * hashes
        + ROW * rows
        + WRITE * writes
        + EXPORT * exports
        + copied
}
