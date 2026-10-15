//! A package's witness, from the store and a batch's simulation: every row
//! it reads or writes, opened as refine needs it, under one multiproof, and
//! each range it scans shown complete.

use std::collections::BTreeMap;

use vos_tree::{BatchProof, RangeProof};
use vos_wire::package::{Opened, Row, ScannedRange, StateWitness};

use crate::Error;
use crate::simulate::Simulation;
use crate::store::View;

/// The witness of `simulation` against `view`'s root.
pub fn witness(view: &View, simulation: &Simulation) -> Result<StateWitness, Error> {
    let mut keys: BTreeMap<&[u8], Opened> = BTreeMap::new();
    for key in &simulation.reads {
        let opened = match (view.get(key)?, view.leaf(key)?) {
            (Some(value), Some(leaf)) => Opened::Value {
                salt: leaf.salt,
                value,
            },
            _ => Opened::Absent,
        };
        keys.insert(key, opened);
    }
    for key in simulation.writes.keys() {
        if keys.contains_key(key.as_slice()) {
            continue;
        }
        let opened = match view.leaf(key)? {
            Some(leaf) => Opened::Written(leaf.value_hash),
            None => Opened::Absent,
        };
        keys.insert(key, opened);
    }
    let proof = BatchProof::generate(&view.tree(), &keys.keys().collect::<Vec<_>>())?;
    let ranges = merged(&simulation.ranges)
        .into_iter()
        .map(|(from, to)| range(view, from, to))
        .collect::<Result<_, _>>()?;
    Ok(StateWitness {
        keys: keys
            .into_iter()
            .map(|(key, opened)| (key.to_vec(), opened))
            .collect(),
        proof,
        ranges,
    })
}

/// The range `[from, to)` of `view`: its rows and their proof.
fn range(view: &View, from: Vec<u8>, to: Option<Vec<u8>>) -> Result<ScannedRange, Error> {
    let mut rows = Vec::new();
    for row in view.rows_from(&from) {
        let (key, value) = row?;
        if to.as_ref().is_some_and(|to| key >= *to) {
            break;
        }
        let salt = view.leaf(&key)?.ok_or(Error::Corrupt("a row's leaf"))?.salt;
        rows.push(Row { key, salt, value });
    }
    let proof = RangeProof::generate(&view.tree(), &from, to.as_deref())?;
    Ok(ScannedRange {
        from,
        to,
        rows,
        proof,
    })
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
