//! A package's witness, from the store and a batch's simulation: every row
//! it reads or writes, opened as refine needs it, under one multiproof, and
//! each range it scans shown complete.

use std::collections::BTreeMap;

use vos_tree::{BatchProof, RangeProof};
use vos_wire::package::{Opened, Range, Row, StateWitness};

use crate::simulate::Simulation;
use crate::store::Store;

/// The witness of `simulation` against `store`'s root.
pub fn witness(store: &Store, simulation: &Simulation) -> StateWitness {
    let mut keys: BTreeMap<&[u8], Opened> = BTreeMap::new();
    for key in &simulation.reads {
        let opened = match (store.get(key), store.leaf(key)) {
            (Some(value), Some(leaf)) => Opened::Value {
                salt: leaf.salt,
                value: value.to_vec(),
            },
            _ => Opened::Absent,
        };
        keys.insert(key, opened);
    }
    for key in simulation.writes.keys() {
        keys.entry(key).or_insert_with(|| match store.leaf(key) {
            Some(leaf) => Opened::Written(leaf.value_hash),
            None => Opened::Absent,
        });
    }
    let proof = BatchProof::generate(store.tree(), &keys.keys().collect::<Vec<_>>())
        .expect("a tree in memory");
    let ranges = merged(&simulation.ranges)
        .into_iter()
        .map(|(from, to)| range(store, from, to))
        .collect();
    StateWitness {
        keys: keys
            .into_iter()
            .map(|(key, opened)| (key.to_vec(), opened))
            .collect(),
        proof,
        ranges,
    }
}

/// The range `[from, to)` of `store`: its rows and their proof.
fn range(store: &Store, from: Vec<u8>, to: Option<Vec<u8>>) -> Range {
    let rows = store
        .rows()
        .range(from.clone()..)
        .take_while(|(key, _)| to.as_ref().is_none_or(|to| *key < to))
        .map(|(key, value)| Row {
            key: key.clone(),
            salt: store.leaf(key).expect("a row's leaf").salt,
            value: value.clone(),
        })
        .collect();
    let proof = RangeProof::generate(store.tree(), &from, to.as_deref()).expect("a tree in memory");
    Range {
        from,
        to,
        rows,
        proof,
    }
}

/// `ranges` in key order, those that meet or overlap joined, so none
/// overlaps another.
fn merged(ranges: &[(Vec<u8>, Option<Vec<u8>>)]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut sorted = ranges.to_vec();
    sorted.sort();
    let mut merged: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    for (from, to) in sorted {
        match merged.last_mut() {
            Some((_, end)) if end.as_ref().is_none_or(|end| from <= *end) => {
                if end.is_some() && to.as_ref().is_none_or(|to| Some(to) > end.as_ref()) {
                    *end = to;
                }
            }
            _ => merged.push((from, to)),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::merged;

    #[test]
    fn ranges_that_meet_or_overlap_join() {
        let key = |byte: u8| vec![byte];
        let ranges = [
            (key(5), Some(key(7))),
            (key(1), Some(key(3))),
            (key(3), Some(key(4))),
            (key(6), Some(key(9))),
            (key(10), None),
            (key(12), Some(key(13))),
        ];
        assert_eq!(
            merged(&ranges),
            [
                (key(1), Some(key(4))),
                (key(5), Some(key(9))),
                (key(10), None)
            ]
        );
    }
}
