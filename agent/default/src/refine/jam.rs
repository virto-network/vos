//! A batch on JAM: a package with the witness of the state it touches.
//!
//! The witness is verified once against the package's root. Refine serves
//! its state reads from it, and its scans from its ranges, each shown
//! complete; a key or a range it does not cover traps, so no result is
//! computed on state the package does not show. The batch runs as on a VOS
//! node, then refine applies its work result as a VOS node's accumulate
//! does, and computes the root after from the witness, every row it
//! writes a leaf salted by the batch's seed, a committed row's leaf over
//! its bare value as a VOS node's root has it. It exports the pages the
//! result stores, then the result, and returns the roots
//! ([`vos_wire::package`]).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vos_tree::{Blake2b, Hash, PartialTree, salt, value_hash};
use vos_wire::apply::{Host, State, apply};
use vos_wire::ids::{AgentId, WorkflowId};
use vos_wire::package::{JamOutput, Opened, Package, SEGMENT, ScannedRange, StateWitness};
use vos_wire::records::leaf_value;
use vos_wire::result::{PAGE, WorkResult, digest};
use vos_wire::{Decode, Encode};

use super::base::{Base, Source};
use super::batch::run_batch;
use crate::host::{StateRows, export, fetch_import};

/// A package's witness, verified against its root.
pub(crate) struct Witnessed {
    /// The keys it opens, in strictly increasing order.
    keys: Vec<(Vec<u8>, Opened)>,
    /// The ranges it shows complete, in key order and disjoint.
    ranges: Vec<ScannedRange>,
    /// The tree its keys' paths open, for the root after.
    tree: PartialTree,
    /// The import that holds each page, by its workflow and index.
    imports: BTreeMap<(WorkflowId, u32), u64>,
}

impl Witnessed {
    /// Verify `witness` against `root`, or trap.
    fn verify(witness: StateWitness, root: &Hash, imports: Vec<(WorkflowId, u32)>) -> Self {
        let StateWitness {
            keys,
            proof,
            ranges,
        } = witness;
        assert!(
            keys.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "the witness's keys in order"
        );
        let claims: Vec<(&[u8], Option<Hash>)> = keys
            .iter()
            .map(|(key, opened)| (key.as_slice(), commitment(key, opened)))
            .collect();
        let tree = proof
            .verify(&Blake2b, root, &claims)
            .expect("the witness's keys against the root");
        for (index, range) in ranges.iter().enumerate() {
            if let Some(next) = ranges.get(index + 1) {
                assert!(
                    range.to.as_ref().is_some_and(|to| *to <= next.from),
                    "the witness's ranges in order"
                );
            }
            let rows: Vec<(&[u8], Hash)> = range
                .rows
                .iter()
                .map(|row| {
                    (
                        row.key.as_slice(),
                        value_hash(&Blake2b, &row.salt, committed(&row.key, &row.value)),
                    )
                })
                .collect();
            range
                .proof
                .verify(&Blake2b, root, &range.from, range.to.as_deref(), &rows)
                .expect("a witnessed range against the root");
        }
        let imports = imports
            .into_iter()
            .enumerate()
            .map(|(index, page)| (page, index as u64))
            .collect();
        Self {
            keys,
            ranges,
            tree,
            imports,
        }
    }

    /// A row as stored; `None` when absent. Traps when the witness does
    /// not open it to be read.
    pub(crate) fn read(&self, key: &[u8]) -> Option<&[u8]> {
        let at = self
            .keys
            .binary_search_by(|(opened, _)| opened.as_slice().cmp(key))
            .unwrap_or_else(|_| panic!("a read the witness does not cover"));
        match &self.keys[at].1 {
            Opened::Absent => None,
            Opened::Value { value, .. } => Some(value),
            Opened::Written(_) => panic!("a read the witness does not cover"),
        }
    }

    /// Rows under `prefix` after `after`, from the prefix when `after` is
    /// empty, as a node's `state_scan` packs them into `capacity`: each
    /// whole, until the next does not fit; `None` when the first alone
    /// does not. Traps past what the witness's ranges cover.
    pub(crate) fn scan(&self, prefix: &[u8], after: &[u8], capacity: usize) -> Option<StateRows> {
        let mut lower = prefix.to_vec();
        if !after.is_empty() {
            let past = vos_tree::keys::after(after);
            lower = lower.max(past);
        }
        let end = vos_tree::keys::prefix_end(prefix);
        if end.as_ref().is_some_and(|end| lower >= *end) {
            return Some(Vec::new());
        }
        // The ranges are disjoint, so only the last starting at or below
        // the scan can hold its rows. Were it the wrong one, it would end
        // short of the prefix's end, and the check below traps.
        let range = self
            .ranges
            .iter()
            .rev()
            .find(|range| range.from <= lower)
            .unwrap_or_else(|| panic!("a scan the witness does not cover"));
        let mut rows = Vec::new();
        let mut used = 0;
        for row in range.rows.iter().skip_while(|row| row.key < lower) {
            if end.as_ref().is_some_and(|end| row.key >= *end) {
                return Some(rows);
            }
            let len = 8 + row.key.len() + row.value.len();
            if used + len > capacity {
                return (!rows.is_empty()).then_some(rows);
            }
            used += len;
            rows.push((row.key.clone(), row.value.clone()));
        }
        // The range ends: the rows under the prefix end with it only if it
        // runs past them.
        let covered = match (&range.to, &end) {
            (None, _) => true,
            (Some(to), Some(end)) => to >= end,
            (Some(_), None) => false,
        };
        assert!(covered, "a scan the witness does not cover");
        Some(rows)
    }

    /// Workflow `id`'s page `index` from its import into `page`: false
    /// when the package does not import it, or the import is no segment.
    /// The page's hash, which restoring it checks, covers what matters of
    /// the segment; its padding is not checked.
    pub(crate) fn import(&self, id: WorkflowId, index: u32, page: &mut [u8; PAGE]) -> bool {
        self.imports
            .get(&(id, index))
            .is_some_and(|&import| fetch_import(import, page) == Some(SEGMENT))
    }
}

/// What the witness claims of a key: its value's commitment, or absence.
fn commitment(key: &[u8], opened: &Opened) -> Option<Hash> {
    match opened {
        Opened::Absent => None,
        Opened::Value { salt, value } => Some(value_hash(&Blake2b, salt, committed(key, value))),
        Opened::Written(value_hash) => Some(*value_hash),
    }
}

/// The bytes the leaf of the row `key` commits, from the row as stored,
/// which the witness carries and apply reads: a committed row's bare
/// value, as a VOS node's root commits it ([`leaf_value`]). Traps on a
/// committed row stored as no value row.
fn committed<'a>(key: &[u8], stored: &'a [u8]) -> &'a [u8] {
    leaf_value(key, stored).expect("a committed row stored as a value row")
}

/// The rows the work result's apply writes, over the witness.
struct Applying<'a> {
    witnessed: &'a Witnessed,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl State for Applying<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        match self.writes.get(key) {
            Some(value) => value.clone(),
            None => self.witnessed.read(key).map(<[u8]>::to_vec),
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.writes.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}

/// Refine a package: its batch's work result, applied to the witness, the
/// root after, the pages and the result exported.
pub(crate) fn run(agent: AgentId, package: Package) -> Vec<u8> {
    let Package {
        batch,
        root,
        witness,
        imports,
        solicit,
    } = package;
    let witnessed = Witnessed::verify(witness, &root, imports);
    let (time, seed) = (batch.time, batch.seed);
    let mut base = Base::new(agent, Source::Witness(witnessed), time, seed, batch.budget);
    let result = run_batch(&mut base, batch).result();
    let section = base.section.into_inner();
    let Source::Witness(witnessed) = base.source else {
        unreachable!("a package's refine reads its witness")
    };
    let (decoded, _) = WorkResult::decode(&result).expect("the work result");
    let mut applying = Applying {
        witnessed: &witnessed,
        writes: BTreeMap::new(),
    };
    assert!(
        apply(&mut applying, &decoded, Host::Jam),
        "the work result applies to the package's state"
    );
    let writes: Vec<(Vec<u8>, Option<Hash>)> = applying
        .writes
        .into_iter()
        .map(|(key, value)| {
            let commitment = value.map(|value| {
                let salt = salt(&Blake2b, &seed, &key);
                value_hash(&Blake2b, &salt, committed(&key, &value))
            });
            (key, commitment)
        })
        .collect();
    let mut tree = witnessed.tree;
    let root_after = tree
        .update(&Blake2b, &writes)
        .expect("the witness covers every write");
    let mut pages = 0;
    for page in section.taken() {
        export(page).expect("room for the pages");
        pages += 1;
    }
    let mut exports = pages;
    for segment in result.chunks(SEGMENT) {
        export(segment).expect("room for the work result");
        exports += 1;
    }
    JamOutput {
        root_before: root,
        root_after,
        time,
        seed,
        work_result_hash: digest(&result),
        pages,
        exports,
        solicit,
    }
    .encode()
}
