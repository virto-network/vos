//! Shared, read-only CRDT ancestry validation and frontier selection.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::{ActorGenesisV2, BlobRefV2, CrdtChangeV2, Hash, V2Wire};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CausalFrontierError<E> {
    Storage(E),
    Missing(Hash),
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CausalSelectionError {
    Corrupt,
}

pub(crate) struct CausalFrontierV2 {
    heads: Vec<Hash>,
    nodes: BTreeMap<Hash, CrdtChangeV2>,
    pub max_head_height: u64,
}

impl CausalFrontierV2 {
    /// Canonical frontier after removing advertised heads which are ancestors
    /// of another advertised head. Concurrent branches are always preserved.
    pub fn canonical_heads(&self) -> Vec<Hash> {
        let dependencies = self
            .nodes
            .values()
            .flat_map(|change| change.causal_dependencies.iter().copied())
            .collect::<BTreeSet<_>>();
        self.heads
            .iter()
            .copied()
            .filter(|head| !dependencies.contains(head))
            .collect()
    }

    /// Complete ancestry in deterministic parent-before-child order.
    pub fn nodes_in_causal_order(&self) -> Vec<(Hash, &CrdtChangeV2)> {
        let mut nodes = self
            .nodes
            .iter()
            .map(|(cid, node)| (*cid, node))
            .collect::<Vec<_>>();
        nodes.sort_by_key(|(cid, node)| (node.causal_height, *cid));
        nodes
    }

    /// Restrict this already-validated DAG to the complete ancestry of a
    /// causal snapshot. No storage is consulted and every requested head must
    /// belong to the original frontier.
    pub fn at_heads(&self, heads: &[Hash]) -> Option<Self> {
        let mut nodes = BTreeMap::new();
        let mut pending = heads.to_vec();
        while let Some(cid) = pending.pop() {
            if nodes.contains_key(&cid) {
                continue;
            }
            let change = self.nodes.get(&cid)?.clone();
            pending.extend(change.causal_dependencies.iter().copied());
            nodes.insert(cid, change);
        }
        let max_head_height = heads
            .iter()
            .filter_map(|head| nodes.get(head))
            .map(|change| change.causal_height)
            .max()
            .unwrap_or(0);
        Some(Self {
            heads: heads.to_vec(),
            nodes,
            max_head_height,
        })
    }

    /// Extend one already-validated local DAG with an accepted change and
    /// select the canonical union of the current heads and that change.
    ///
    /// This keeps Apply on one ancestry walk: validation loads the union of
    /// the committed and observed frontiers, then staging adds the new node
    /// in memory before materialization.
    pub fn with_change(mut self, current_heads: &[Hash], change: CrdtChangeV2) -> Option<Self> {
        let expected_height = change
            .causal_dependencies
            .iter()
            .map(|dependency| self.nodes.get(dependency).map(|node| node.causal_height))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0)
            .checked_add(1)?;
        if change.causal_height != expected_height {
            return None;
        }
        let cid = change.cid();
        if let Some(existing) = self.nodes.get(&cid)
            && existing != &change
        {
            return None;
        }
        self.nodes.insert(cid, change);
        self.heads = current_heads.to_vec();
        self.heads.push(cid);
        self.heads.sort();
        self.heads.dedup();
        self.heads = self.canonical_heads();
        self.max_head_height = self
            .heads
            .iter()
            .filter_map(|head| self.nodes.get(head))
            .map(|node| node.causal_height)
            .max()
            .unwrap_or(0);
        Some(self)
    }

    pub fn contains_ancestor(&self, descendant: Hash, ancestor: Hash) -> bool {
        if descendant == ancestor {
            return true;
        }
        let mut pending = alloc::vec![descendant];
        let mut visited = BTreeSet::new();
        while let Some(cid) = pending.pop() {
            if !visited.insert(cid) {
                continue;
            }
            let Some(change) = self.nodes.get(&cid) else {
                return false;
            };
            if change.causal_dependencies.contains(&ancestor) {
                return true;
            }
            pending.extend(change.causal_dependencies.iter().copied());
        }
        false
    }

    /// Select the nearest actor materialization on every concurrent branch.
    /// Each selected state already incorporates the ancestry below it; Refine
    /// folds all returned alternatives inside the canonical actor PVM.
    pub fn actor_materializations(
        &self,
        descriptor: &ActorGenesisV2,
    ) -> Result<Vec<BlobRefV2>, CausalSelectionError> {
        if self.heads.is_empty() {
            return Ok(alloc::vec![descriptor.initial_state.clone()]);
        }

        let mut frontier = BTreeMap::<Hash, BlobRefV2>::new();
        let mut visited = BTreeSet::new();
        let mut pending = self.heads.clone();
        while let Some(cid) = pending.pop() {
            if !visited.insert(cid) {
                continue;
            }
            let change = self.nodes.get(&cid).ok_or(CausalSelectionError::Corrupt)?;
            if let Some(materialization) = change
                .materializations
                .iter()
                .find(|materialization| materialization.actor == descriptor.actor)
            {
                if let Some(existing) = frontier.get(&materialization.state.hash)
                    && existing != &materialization.state
                {
                    return Err(CausalSelectionError::Corrupt);
                }
                frontier.insert(materialization.state.hash, materialization.state.clone());
            } else if change.causal_dependencies.is_empty() {
                frontier.insert(
                    descriptor.initial_state.hash,
                    descriptor.initial_state.clone(),
                );
            } else {
                pending.extend(change.causal_dependencies.iter().copied());
            }
        }
        if frontier.is_empty() {
            return Err(CausalSelectionError::Corrupt);
        }
        Ok(frontier.into_values().collect())
    }
}

/// Fetch and CID-validate the complete ancestry of `heads`.
///
/// Visiting stops only after every transitive dependency is present. A valid
/// materialization at a head never hides a missing or malicious ancestor.
pub(crate) fn load_causal_frontier<E>(
    heads: &[Hash],
    mut read_node: impl FnMut(Hash) -> Result<Option<Vec<u8>>, E>,
) -> Result<CausalFrontierV2, CausalFrontierError<E>> {
    let mut nodes = BTreeMap::<Hash, CrdtChangeV2>::new();
    let mut pending = heads.to_vec();
    while let Some(cid) = pending.pop() {
        if nodes.contains_key(&cid) {
            continue;
        }
        let bytes = read_node(cid)
            .map_err(CausalFrontierError::Storage)?
            .ok_or(CausalFrontierError::Missing(cid))?;
        let change = CrdtChangeV2::decode(&bytes).map_err(|_| CausalFrontierError::Corrupt)?;
        if change.cid() != cid {
            return Err(CausalFrontierError::Corrupt);
        }
        pending.extend(change.causal_dependencies.iter().copied());
        nodes.insert(cid, change);
    }

    // Height is part of the canonical node and is used to derive the next
    // slice identity. Recompute it across the complete ancestry instead of
    // trusting a durable or synchronized node's self-declared value. This
    // also rejects causal cycles: no finite height assignment can satisfy a
    // parent edge around a cycle.
    for change in nodes.values() {
        let expected_height = change
            .causal_dependencies
            .iter()
            .filter_map(|dependency| nodes.get(dependency))
            .map(|dependency| dependency.causal_height)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(CausalFrontierError::Corrupt)?;
        if change.causal_height != expected_height {
            return Err(CausalFrontierError::Corrupt);
        }
    }
    let max_head_height = heads
        .iter()
        .filter_map(|head| nodes.get(head))
        .map(|change| change.causal_height)
        .max()
        .unwrap_or(0);
    Ok(CausalFrontierV2 {
        heads: heads.to_vec(),
        nodes,
        max_head_height,
    })
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::v2::{ActorId, ChangeId, CrdtMaterializationV2};

    fn change(id: u8, parents: Vec<Hash>, height: u64, state: Option<u8>) -> CrdtChangeV2 {
        CrdtChangeV2 {
            id: ChangeId([id; 32]),
            work_hash: Hash([id.wrapping_add(100); 32]),
            causal_dependencies: parents,
            causal_height: height,
            operations: vec![],
            workflow: vec![],
            materializations: state
                .map(|state| CrdtMaterializationV2 {
                    actor: ActorId([7; 32]),
                    state: BlobRefV2::of_bytes(&[state]),
                })
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn validates_complete_ancestry_and_preserves_concurrent_frontier() {
        let root = change(1, vec![], 1, Some(1));
        let root_cid = root.cid();
        let left = change(2, vec![root_cid], 2, Some(2));
        let left_cid = left.cid();
        let right = change(3, vec![root_cid], 2, Some(3));
        let right_cid = right.cid();
        let nodes = BTreeMap::from([
            (root_cid, root.encode()),
            (left_cid, left.encode()),
            (right_cid, right.encode()),
        ]);
        let mut heads = vec![left_cid, right_cid];
        heads.sort();
        let frontier =
            load_causal_frontier(&heads, |cid| Ok::<_, Infallible>(nodes.get(&cid).cloned()))
                .unwrap();
        assert_eq!(frontier.max_head_height, 2);
        let left_only = frontier.at_heads(&[left_cid]).unwrap();
        assert_eq!(left_only.canonical_heads(), vec![left_cid]);
        assert_eq!(left_only.nodes_in_causal_order().len(), 2);

        let descriptor = ActorGenesisV2 {
            actor: ActorId([7; 32]),
            name: "root".into(),
            parent: None,
            producer: super::super::ProducerId([6; 32]),
            program: super::super::ProgramId([8; 32]),
            initial_state: BlobRefV2::of_bytes(b"initial"),
            crdt: true,
            role_policies: super::super::PackageRolePoliciesV2 { methods: vec![] }.encode(),
        };
        let states = frontier.actor_materializations(&descriptor).unwrap();
        assert_eq!(states.len(), 2);
        assert!(states.contains(&BlobRefV2::of_bytes(&[2])));
        assert!(states.contains(&BlobRefV2::of_bytes(&[3])));

        let merged = change(4, heads.clone(), 3, Some(4));
        let merged_cid = merged.cid();
        let extended = frontier.with_change(&heads, merged).unwrap();
        assert_eq!(extended.canonical_heads(), vec![merged_cid]);
        assert_eq!(extended.max_head_height, 3);

        let missing = load_causal_frontier(&heads, |cid| {
            Ok::<_, Infallible>((cid != root_cid).then(|| nodes[&cid].clone()))
        });
        assert!(matches!(
            missing,
            Err(CausalFrontierError::Missing(cid)) if cid == root_cid
        ));

        let wrong_height = change(4, vec![root_cid], 9, Some(4));
        let wrong_height_cid = wrong_height.cid();
        let corrupt = BTreeMap::from([
            (root_cid, root.encode()),
            (wrong_height_cid, wrong_height.encode()),
        ]);
        assert!(matches!(
            load_causal_frontier(&[wrong_height_cid], |cid| {
                Ok::<_, Infallible>(corrupt.get(&cid).cloned())
            }),
            Err(CausalFrontierError::Corrupt)
        ));
    }
}
