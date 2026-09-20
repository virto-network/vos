//! Certificate rows for the Authority table cutover. The compact index belongs
//! in the integrity-checked Linear header; certificates belong in a declared
//! storage namespace. These primitives do not replace enrollment verification.

use super::{Hash, NodeOwnerRow};
use alloc::{boxed::Box, vec, vec::Vec};
use vos::Encode;
use vos::storage::StorageMap;

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub(super) struct NodeIndexRow {
    pub node: [u8; 32],
    pub owner: [u8; 32],
    certificate: [u8; 32],
}

impl NodeIndexRow {
    pub fn of_verified(row: &NodeOwnerRow) -> Self {
        Self {
            node: row.node,
            owner: row.owner,
            certificate: Hash::digest(b"vos/authority/node-row/v1", &[&row.encode()]).0,
        }
    }
}

pub(super) type NodeRows = StorageMap<[u8; 32], NodeOwnerRow>;

/// Portable Linear header. A new incarnation carries exactly one verified
/// bootstrap certificate until its first successful mutation materializes it.
/// Restore never invents a seed when this option is absent.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub(super) struct NodeTable {
    entries: Vec<CompactNodeIndexRow>,
    owners: Vec<[u8; 32]>,
    // Keep the one-time seed out of every cloned Authority stack frame. The
    // archive still carries it until materialization; absent means no fallback.
    bootstrap: Option<Box<NodeOwnerRow>>,
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct CompactNodeIndexRow {
    node: [u8; 32],
    certificate: [u8; 32],
    owner: u8,
}

impl NodeTable {
    #[cfg(test)]
    pub fn inject_index_for_test(&mut self, row: &NodeOwnerRow) {
        let owner = self
            .owners
            .iter()
            .position(|owner| *owner == row.owner)
            .unwrap();
        let index = NodeIndexRow::of_verified(row);
        self.entries.push(CompactNodeIndexRow {
            node: index.node,
            certificate: index.certificate,
            owner: owner as u8,
        });
        self.entries.sort_by_key(|entry| entry.node);
    }

    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            owners: Vec::new(),
            bootstrap: None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn indices(&self) -> impl Iterator<Item = NodeIndexRow> + '_ {
        (0..self.entries.len()).filter_map(|index| self.expanded(index))
    }

    /// Full certificate audit retained during the table cutover. Callers must
    /// reject missing rows; do not silently filter corrupt entries out.
    pub fn all_certificates(&self, rows: &NodeRows, valid: impl Fn(&NodeOwnerRow) -> bool) -> bool {
        self.entries
            .iter()
            .all(|entry| self.get(rows, entry.node).is_some_and(|row| valid(&row)))
    }

    pub fn certificate_matches(&self, row: &NodeOwnerRow) -> bool {
        self.entries
            .binary_search_by_key(&row.node, |entry| entry.node)
            .ok()
            .and_then(|index| self.expanded(index))
            == Some(NodeIndexRow::of_verified(row))
    }

    /// No storage access: safe before generated handle initialization.
    pub fn pending_bootstrap(verified: NodeOwnerRow) -> Self {
        let index = NodeIndexRow::of_verified(&verified);
        Self {
            entries: vec![CompactNodeIndexRow {
                node: index.node,
                certificate: index.certificate,
                owner: 0,
            }],
            owners: vec![index.owner],
            bootstrap: Some(Box::new(verified)),
        }
    }

    /// Header integrity is checked by the enclosing Authority commitment;
    /// admission still verifies enrollment signatures and role membership.
    pub fn index_is_valid(&self) -> bool {
        self.entries.len() <= super::MAX_AUTHORITY_NODES
            && self.owners.len() <= super::MAX_AUTHORITY_PRINCIPALS
            && self.owners.iter().enumerate().all(|(slot, owner)| {
                *owner != [0; 32]
                    && !self.owners[..slot].contains(owner)
                    && self
                        .entries
                        .iter()
                        .any(|entry| entry.owner as usize == slot)
            })
            && self
                .entries
                .windows(2)
                .all(|pair| pair[0].node < pair[1].node)
            && self.entries.iter().all(|entry| {
                entry.node != [0; 32]
                    && (entry.owner as usize) < self.owners.len()
                    && entry.certificate != [0; 32]
            })
            && self.bootstrap.as_ref().is_none_or(|seed| {
                self.entries.len() == 1 && self.expanded(0) == Some(NodeIndexRow::of_verified(seed))
            })
    }

    fn expanded(&self, index: usize) -> Option<NodeIndexRow> {
        let entry = self.entries.get(index)?;
        Some(NodeIndexRow {
            node: entry.node,
            certificate: entry.certificate,
            owner: *self.owners.get(entry.owner as usize)?,
        })
    }

    pub fn owner(&self, node: [u8; 32]) -> Option<[u8; 32]> {
        let index = self
            .entries
            .binary_search_by_key(&node, |entry| entry.node)
            .ok()?;
        self.owners.get(self.entries[index].owner as usize).copied()
    }

    pub fn get(&self, rows: &NodeRows, node: [u8; 32]) -> Option<NodeOwnerRow> {
        let index = self.expanded(
            self.entries
                .binary_search_by_key(&node, |entry| entry.node)
                .ok()?,
        )?;
        match &self.bootstrap {
            Some(seed) => (self.index_is_valid() && NodeIndexRow::of_verified(seed) == index)
                .then(|| (**seed).clone()),
            None => read(rows, &index),
        }
    }

    fn materialize(&mut self, rows: &mut NodeRows) -> Option<()> {
        if !self.index_is_valid() {
            return None;
        }
        if let Some(seed) = &self.bootstrap {
            let index = bootstrap(rows, seed)?;
            if self.entries.len() != 1 || self.expanded(0) != Some(index) {
                return None;
            }
            self.bootstrap = None;
        }
        Some(())
    }

    /// Mutate a cloned inline header and the row overlay together. Callers must
    /// still use an enclosing Authority candidate for later policy refusals.
    fn change(
        &mut self,
        rows: &mut NodeRows,
        operation: impl FnOnce(&mut Self, &mut NodeRows) -> Option<()>,
    ) -> bool {
        let mut candidate = self.clone();
        let result = vos::storage::with_transaction(|| {
            candidate.materialize(rows).ok_or(())?;
            operation(&mut candidate, rows).ok_or(())?;
            if !candidate.index_is_valid() {
                return Err(());
            }
            Ok(())
        });
        if result.is_err() {
            return false;
        }
        *self = candidate;
        true
    }

    pub fn insert_verified(&mut self, rows: &mut NodeRows, row: &NodeOwnerRow) -> bool {
        if self.entries.len() >= super::MAX_AUTHORITY_NODES {
            return false;
        }
        let Err(index) = self
            .entries
            .binary_search_by_key(&row.node, |entry| entry.node)
        else {
            return false;
        };
        self.change(rows, |candidate, rows| {
            let owner = match candidate
                .owners
                .iter()
                .position(|owner| *owner == row.owner)
            {
                Some(slot) => slot,
                None => {
                    if candidate.owners.len() >= super::MAX_AUTHORITY_PRINCIPALS {
                        return None;
                    }
                    candidate.owners.push(row.owner);
                    candidate.owners.len() - 1
                }
            };
            let entry = insert_verified(rows, row)?;
            candidate.entries.insert(
                index,
                CompactNodeIndexRow {
                    node: entry.node,
                    certificate: entry.certificate,
                    owner: u8::try_from(owner).ok()?,
                },
            );
            Some(())
        })
    }

    pub fn remove(&mut self, rows: &mut NodeRows, node: [u8; 32], owner: [u8; 32]) -> bool {
        let Ok(index) = self.entries.binary_search_by_key(&node, |entry| entry.node) else {
            return false;
        };
        if self.owner(node) != Some(owner) {
            return false;
        }
        self.change(rows, |candidate, rows| {
            if !remove(rows, &candidate.expanded(index)?) {
                return None;
            }
            let owner = candidate.entries.remove(index).owner;
            if !candidate.entries.iter().any(|entry| entry.owner == owner) {
                candidate.owners.remove(owner as usize);
                for entry in &mut candidate.entries {
                    if entry.owner > owner {
                        entry.owner -= 1;
                    }
                }
            }
            Some(())
        })
    }
}

/// The declared actor field and this borrowed-operation handle address the
/// same signed namespace. Construction initializes a handle, never its rows.
pub(super) fn rows() -> NodeRows {
    let mut rows = NodeRows::default();
    rows.__init(b"s/authority-nodes/");
    rows
}

/// One certificate read, bound to the exact index entry. Missing or substituted
/// data fails closed; never synthesize a bootstrap certificate during lookup.
pub(super) fn read(rows: &NodeRows, index: &NodeIndexRow) -> Option<NodeOwnerRow> {
    let row = rows.get(&index.node)?;
    (NodeIndexRow::of_verified(&row) == *index).then_some(row)
}

/// Called after enrollment verification and capacity admission, inside the
/// enclosing Authority row transaction. Existing storage is never overwritten,
/// even if an inconsistent header claims that the key is absent.
pub(super) fn insert_verified(rows: &mut NodeRows, row: &NodeOwnerRow) -> Option<NodeIndexRow> {
    if rows.get(&row.node).is_some() {
        return None;
    }
    let index = NodeIndexRow::of_verified(row);
    rows.insert(&row.node, row);
    Some(index)
}

/// Explicit bootstrap may run only after the runtime initializes the declared
/// handle and establishes an empty incarnation. A nonempty table is an error,
/// not an idempotent restore path: restoring must read the persisted index.
pub(super) fn bootstrap(rows: &mut NodeRows, row: &NodeOwnerRow) -> Option<NodeIndexRow> {
    if !rows.is_empty() {
        return None;
    }
    insert_verified(rows, row)
}

pub(super) fn remove(rows: &mut NodeRows, index: &NodeIndexRow) -> bool {
    if read(rows, index).is_none() {
        return false;
    }
    rows.remove(&index.node)
}
