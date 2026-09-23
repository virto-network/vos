//! Bounded opaque runtime metadata stored alongside accounted actor rows.
//!
//! The runtime owns this representation; hosts see ordinary tree blocks only.
//! This retains whole-metadata work, independently of the retained row count.
//! Root authority, metadata decoding, aggregate signed runtime-state limits and
//! result/continuation semantics remain the enclosing runtime's responsibility.

use crate::{
    Hash,
    state_blocks::ReadBudget,
    state_tree::{BlockReader, StateTree, TreeBatch, TreeError, TreeKey, WriteBudget},
};
use alloc::vec::Vec;

const PART_BYTES: usize = 512 * 1024;
const HEADER: &[u8; 4] = b"VRM1";
const PART: &[u8; 4] = b"VRP1";

fn key(slot: u8) -> TreeKey {
    Hash::digest(b"vos/experimental/runtime-metadata/v1", &[&[slot]]).0
}
fn parts(len: usize) -> usize {
    len.div_ceil(PART_BYTES)
}
fn part_len(len: usize, index: usize) -> usize {
    (len - index * PART_BYTES).min(PART_BYTES)
}

fn decode_header(bytes: &[u8], limit: usize) -> Result<usize, TreeError> {
    if bytes.len() != 8 || &bytes[..4] != HEADER {
        return Err(TreeError::InvalidValue);
    }
    let len =
        u32::from_le_bytes(bytes[4..].try_into().map_err(|_| TreeError::InvalidValue)?) as usize;
    if len > limit || len > crate::MAX_RUNTIME_STATE_BYTES {
        return Err(TreeError::InvalidValue);
    }
    Ok(len)
}

fn decode_part(bytes: &[u8], len: usize, index: usize) -> Result<&[u8], TreeError> {
    if bytes.len() != 5 + part_len(len, index) || &bytes[..4] != PART || bytes[4] as usize != index
    {
        return Err(TreeError::InvalidValue);
    }
    Ok(&bytes[5..])
}

/// Validated candidate bytes. `limit` must be selected from admitted runtime
/// policy. It is a per-component bound, not proof of the aggregate state limit.
#[derive(Clone, Copy)]
pub struct RuntimeMetadataUpdate<'a> {
    bytes: &'a [u8],
    limit: usize,
}

impl<'a> RuntimeMetadataUpdate<'a> {
    pub fn new(bytes: &'a [u8], limit: usize) -> Result<Self, TreeError> {
        if limit == 0 || limit > crate::MAX_RUNTIME_STATE_BYTES || bytes.len() > limit {
            return Err(TreeError::InvalidValue);
        }
        Ok(Self { bytes, limit })
    }
}

/// Only a canonical empty tree has uninitialized metadata. Missing metadata
/// on an existing tree is not an implicit empty runtime or a migration path.
pub fn read_runtime_metadata(
    tree: StateTree,
    limit: usize,
    reader: &mut impl BlockReader,
    reads: &mut ReadBudget,
) -> Result<Option<Vec<u8>>, TreeError> {
    if limit == 0 || limit > crate::MAX_RUNTIME_STATE_BYTES {
        return Err(TreeError::InvalidValue);
    }
    if tree.root().is_none() {
        return Ok(None);
    }
    let header = tree
        .get(&key(0), reader, reads)?
        .ok_or(TreeError::PreconditionFailed)?;
    let len = decode_header(&header, limit)?;
    let mut bytes = Vec::with_capacity(len);
    for index in 0..parts(len) {
        let part = tree
            .get(&key((index + 1) as u8), reader, reads)?
            .ok_or(TreeError::PreconditionFailed)?;
        bytes.extend_from_slice(decode_part(&part, len, index)?);
    }
    Ok(Some(bytes))
}

pub(crate) fn stage_runtime_metadata<R: BlockReader>(
    batch: &mut TreeBatch<'_, R>,
    empty_base: bool,
    update: RuntimeMetadataUpdate<'_>,
    reads: &mut ReadBudget,
    writes: &mut WriteBudget,
) -> Result<(), TreeError> {
    let old_header = batch.get(&key(0), reads)?;
    let old_len = match old_header.as_deref() {
        Some(bytes) => Some(decode_header(bytes, update.limit)?),
        None if empty_base => None,
        None => return Err(TreeError::PreconditionFailed),
    };
    let new_len = update.bytes.len();
    for index in 0..parts(old_len.unwrap_or(0)).max(parts(new_len)) {
        let value = if index < parts(new_len) {
            let start = index * PART_BYTES;
            let mut value = Vec::with_capacity(5 + part_len(new_len, index));
            value.extend_from_slice(PART);
            value.push(index as u8);
            value.extend_from_slice(&update.bytes[start..start + part_len(new_len, index)]);
            Some(value)
        } else {
            None
        };
        batch.update_checked(
            key((index + 1) as u8),
            value.as_deref(),
            reads,
            writes,
            |old| {
                match (old_len, old) {
                    (Some(len), Some(bytes)) if index < parts(len) => {
                        decode_part(bytes, len, index)?;
                    }
                    (Some(len), None) if index >= parts(len) => {}
                    (None, None) => {}
                    _ => return Err(TreeError::PreconditionFailed),
                }
                Ok(())
            },
        )?;
    }
    let mut header = [0; 8];
    header[..4].copy_from_slice(HEADER);
    header[4..].copy_from_slice(&(new_len as u32).to_le_bytes());
    batch.update_checked(key(0), Some(&header), reads, writes, |old| {
        if old != old_header.as_deref() {
            return Err(TreeError::PreconditionFailed);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorId, AgentId, SpaceId, StateLane,
        state_blocks::{BlockRef, BlockScope},
        state_rows::{ActorRows, RowUsage, lane_row_usage},
        state_tree::TreeUpdate,
    };
    use alloc::{collections::BTreeMap, vec};

    #[derive(Default)]
    struct Store(BTreeMap<[u8; 32], Vec<u8>>);
    impl BlockReader for Store {
        fn read(&mut self, reference: BlockRef, bytes: &mut [u8]) -> Result<bool, TreeError> {
            let Some(value) = self.0.get(&reference.hash().0) else {
                return Ok(false);
            };
            if value.len() != bytes.len() {
                return Err(TreeError::Storage);
            }
            bytes.copy_from_slice(value);
            Ok(true)
        }
    }
    impl Store {
        fn install(&mut self, update: TreeUpdate) -> StateTree {
            for (reference, bytes) in update.blocks {
                self.0.insert(reference.hash().0, bytes);
            }
            update.tree
        }
    }
    fn empty() -> StateTree {
        StateTree::empty(
            BlockScope::new(
                SpaceId([1; 32]),
                AgentId([2; 32]),
                Hash([3; 32]),
                StateLane::Linear,
            )
            .unwrap(),
        )
    }
    fn reads() -> ReadBudget {
        ReadBudget::new(10000, 64 * 1024 * 1024)
    }
    fn writes() -> WriteBudget {
        WriteBudget::new(10000, 64 * 1024 * 1024)
    }
    fn rows(tree: StateTree) -> ActorRows {
        ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32])).unwrap()
    }
    fn limits() -> crate::contract::ExternalStateResourceLimits {
        crate::contract::ExternalStateResourceLimits {
            max_rows_per_lane: 10,
            max_row_bytes_per_lane: 100,
        }
    }
    fn metadata(bytes: &[u8]) -> RuntimeMetadataUpdate<'_> {
        RuntimeMetadataUpdate::new(bytes, crate::MAX_RUNTIME_STATE_BYTES).unwrap()
    }

    #[test]
    fn metadata_retirement_preserves_rows_and_rejects_unaccounted_roots() {
        use crate::state_rows::update_accounted_metadata;
        let mut store = Store::default();
        let seed = rows(empty())
            .update_accounted_with_metadata(
                &[(b"row".to_vec(), Some(vec![9]))],
                limits(),
                metadata(b"retained"),
                &mut store,
                (&mut reads(), &mut writes()),
            )
            .unwrap();
        let base = store.install(seed.update);
        let snapshot = store.0.clone();
        let candidate = update_accounted_metadata(
            base,
            metadata(b"retired"),
            limits(),
            &mut store,
            &mut reads(),
            &mut writes(),
        )
        .unwrap();
        assert_eq!(store.0, snapshot);
        assert_eq!(candidate.usage, RowUsage { rows: 1, bytes: 4 });
        let next = store.install(candidate.update);
        for tree in [base, next] {
            assert_eq!(
                rows(tree).get(b"row", &mut store, &mut reads()).unwrap(),
                Some(vec![9])
            );
            assert_eq!(
                lane_row_usage(tree, &mut store, &mut reads()).unwrap(),
                RowUsage { rows: 1, bytes: 4 }
            );
        }
        assert_eq!(
            read_runtime_metadata(base, 100, &mut store, &mut reads()).unwrap(),
            Some(b"retained".to_vec())
        );
        assert_eq!(
            read_runtime_metadata(next, 100, &mut store, &mut reads()).unwrap(),
            Some(b"retired".to_vec())
        );
        let noop = update_accounted_metadata(
            next,
            metadata(b"retired"),
            limits(),
            &mut store,
            &mut reads(),
            &mut WriteBudget::new(0, 0),
        )
        .unwrap();
        assert_eq!(noop.update.tree, next);
        assert!(noop.update.blocks.is_empty());
        let snapshot = store.0.clone();
        assert!(
            update_accounted_metadata(
                next,
                metadata(b"new"),
                limits(),
                &mut store,
                &mut reads(),
                &mut WriteBudget::new(0, 0),
            )
            .is_err()
        );
        let mut cap = limits();
        cap.max_row_bytes_per_lane = 3;
        assert!(
            update_accounted_metadata(
                next,
                metadata(b"new"),
                cap,
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .is_err()
        );
        assert!(
            update_accounted_metadata(
                empty(),
                metadata(b"new"),
                limits(),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .is_err()
        );
        assert_eq!(store.0, snapshot);
        let raw = empty()
            .update(
                [0x55; 32],
                Some(b"raw"),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let raw = store.install(raw);
        assert!(
            update_accounted_metadata(
                raw,
                metadata(b"new"),
                limits(),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_rows_and_counters_share_one_verified_candidate() {
        use crate::{
            state_change::StateChange,
            state_root::{RootContext, StateRootDescriptor},
        };
        let mut store = Store::default();
        let initial = rows(empty())
            .update_accounted_with_metadata(
                &[(b"row".to_vec(), Some(vec![1]))],
                limits(),
                metadata(b"inline and retained result"),
                &mut store,
                (&mut reads(), &mut writes()),
            )
            .unwrap();
        assert!(store.0.is_empty());
        let context = RootContext::new(empty().scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let base = StateRootDescriptor::new(context, None);
        let tree = initial.update.tree;
        let change = StateChange::from_update(base.commitment(), context, initial.update).unwrap();
        change
            .verify_reuse(base, context, &mut store, &mut reads())
            .unwrap();
        for (reference, bytes) in change.blocks() {
            store.0.insert(reference.hash().0, bytes.clone());
        }
        assert_eq!(
            read_runtime_metadata(tree, 100, &mut store, &mut reads()).unwrap(),
            Some(b"inline and retained result".to_vec())
        );
        assert_eq!(
            lane_row_usage(tree, &mut store, &mut reads()).unwrap(),
            RowUsage { rows: 1, bytes: 4 }
        );
        let snapshot = store.0.clone();
        let mut budget = WriteBudget::new(100, 1000);
        assert!(
            rows(tree)
                .update_accounted_with_metadata(
                    &[(b"row".to_vec(), Some(vec![2]))],
                    limits(),
                    metadata(&vec![3; PART_BYTES + 1]),
                    &mut store,
                    (&mut reads(), &mut budget),
                )
                .is_err()
        );
        assert!(budget.remaining().0 < 100);
        assert_eq!(store.0, snapshot);
        assert_eq!(
            rows(tree).get(b"row", &mut store, &mut reads()).unwrap(),
            Some(vec![1])
        );
        let noop = rows(tree)
            .update_accounted_with_metadata(
                &[],
                limits(),
                metadata(b"inline and retained result"),
                &mut store,
                (&mut reads(), &mut WriteBudget::new(0, 0)),
            )
            .unwrap();
        assert_eq!(noop.update.tree, tree);
        assert!(noop.update.blocks.is_empty());
    }

    #[test]
    fn metadata_boundaries_shrink_without_retaining_tail_parts() {
        let mut store = Store::default();
        let mut tree = empty();
        assert_eq!(
            read_runtime_metadata(tree, 100, &mut store, &mut reads()).unwrap(),
            None
        );
        for length in [
            0,
            1,
            PART_BYTES,
            PART_BYTES + 1,
            crate::MAX_RUNTIME_STATE_BYTES,
            1,
            0,
        ] {
            let bytes = vec![7; length];
            let prior = tree;
            let batch = rows(tree)
                .update_accounted_with_metadata(
                    &[],
                    limits(),
                    metadata(&bytes),
                    &mut store,
                    (&mut reads(), &mut writes()),
                )
                .unwrap();
            tree = store.install(batch.update);
            assert_eq!(
                read_runtime_metadata(
                    tree,
                    crate::MAX_RUNTIME_STATE_BYTES,
                    &mut store,
                    &mut reads()
                )
                .unwrap(),
                Some(bytes)
            );
            assert_eq!(
                lane_row_usage(tree, &mut store, &mut reads()).unwrap(),
                RowUsage::default()
            );
            for index in parts(length)..parts(crate::MAX_RUNTIME_STATE_BYTES) {
                assert!(
                    tree.get(&key((index + 1) as u8), &mut store, &mut reads())
                        .unwrap()
                        .is_none()
                );
            }
            if prior.root().is_some() {
                assert!(
                    read_runtime_metadata(
                        prior,
                        crate::MAX_RUNTIME_STATE_BYTES,
                        &mut store,
                        &mut reads()
                    )
                    .unwrap()
                    .is_some()
                );
            }
        }
    }

    fn published_metadata_at(
        store: &mut Store,
        length: usize,
    ) -> (StateTree, Vec<u8>, crate::state_root::RootContext) {
        use crate::{
            state_change::{MAX_STATE_CHANGE_BYTES, StateChange},
            state_root::{RootContext, StateRootDescriptor},
        };
        let mut tree = empty();
        let context = RootContext::new(tree.scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let bytes = (0..length)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        // Reach the limit through individually bounded publications.
        for end in (PART_BYTES..=bytes.len()).step_by(PART_BYTES) {
            let update = rows(tree)
                .update_accounted_with_metadata(
                    &[],
                    limits(),
                    metadata(&bytes[..end]),
                    store,
                    (
                        &mut reads(),
                        &mut WriteBudget::new(4096, MAX_STATE_CHANGE_BYTES as u64),
                    ),
                )
                .unwrap()
                .update;
            let next = update.tree;
            let base = StateRootDescriptor::new(context, tree.root());
            let change = StateChange::from_update(base.commitment(), context, update).unwrap();
            for (reference, block) in change.blocks() {
                store.0.insert(reference.hash().0, block.clone());
            }
            tree = next;
        }
        (tree, bytes, context)
    }

    #[test]
    fn full_runtime_metadata_can_outgrow_one_publication_change() {
        use crate::{
            protocol::wire::DecodeError, state_change::StateChange, state_root::StateRootDescriptor,
        };

        let mut store = Store::default();
        let (tree, bytes, context) =
            published_metadata_at(&mut store, crate::MAX_RUNTIME_STATE_BYTES);
        assert_eq!(
            read_runtime_metadata(tree, bytes.len(), &mut store, &mut reads()).unwrap(),
            Some(bytes.clone())
        );

        // Removing a leading retained item may shift all later metadata bytes.
        // A full-size runtime image is admitted, but its valid successor needs
        // more than the 4-MiB candidate envelope once block overhead is added.
        let update = rows(tree)
            .update_accounted_with_metadata(
                &[],
                limits(),
                metadata(&bytes[1..]),
                &mut store,
                (&mut reads(), &mut writes()),
            )
            .unwrap()
            .update;
        let base = StateRootDescriptor::new(context, tree.root());
        assert!(matches!(
            StateChange::from_update(base.commitment(), context, update),
            Err(DecodeError::LimitExceeded)
        ));
        assert_eq!(
            read_runtime_metadata(tree, bytes.len(), &mut store, &mut reads()).unwrap(),
            Some(bytes),
            "refused publication must preserve the selected predecessor"
        );
    }

    #[test]
    fn three_mib_shift_fits_the_provisional_publication_budget() {
        use crate::{
            state_change::{MAX_STATE_CHANGE_BYTES, StateChange},
            state_root::StateRootDescriptor,
        };

        let mut store = Store::default();
        let (tree, bytes, context) = published_metadata_at(&mut store, 3 * 1024 * 1024);
        let update = rows(tree)
            .update_accounted_with_metadata(
                &[],
                limits(),
                metadata(&bytes[1..]),
                &mut store,
                (
                    &mut reads(),
                    &mut WriteBudget::new(4096, MAX_STATE_CHANGE_BYTES as u64),
                ),
            )
            .unwrap()
            .update;
        let base = StateRootDescriptor::new(context, tree.root());
        StateChange::from_update(base.commitment(), context, update).unwrap();
        assert_eq!(
            read_runtime_metadata(tree, bytes.len(), &mut store, &mut reads()).unwrap(),
            Some(bytes)
        );
    }

    #[test]
    fn metadata_absence_corruption_and_limits_fail_closed() {
        assert!(RuntimeMetadataUpdate::new(&[1], 0).is_err());
        assert!(RuntimeMetadataUpdate::new(&[1, 2], 1).is_err());
        let mut store = Store::default();
        let batch = rows(empty())
            .update_accounted_batch(&[], limits(), &mut store, &mut reads(), &mut writes())
            .unwrap();
        let tree = store.install(batch.update);
        assert_eq!(
            read_runtime_metadata(tree, 100, &mut store, &mut reads()),
            Err(TreeError::PreconditionFailed)
        );
        assert!(
            rows(tree)
                .update_accounted_with_metadata(
                    &[],
                    limits(),
                    metadata(b"not a migration"),
                    &mut store,
                    (&mut reads(), &mut writes())
                )
                .is_err()
        );
        for header in [vec![0; 8], b"VRM1\x01\0\0\0".to_vec()] {
            let update = empty()
                .update(
                    key(0),
                    Some(&header),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap();
            let invalid = store.install(update);
            assert!(read_runtime_metadata(invalid, 100, &mut store, &mut reads()).is_err());
        }
        let batch = rows(empty())
            .update_accounted_with_metadata(
                &[],
                limits(),
                metadata(b"ok"),
                &mut store,
                (&mut reads(), &mut writes()),
            )
            .unwrap();
        let tree = store.install(batch.update);
        assert!(read_runtime_metadata(tree, 1, &mut store, &mut reads()).is_err());
        assert!(read_runtime_metadata(tree, 100, &mut store, &mut ReadBudget::new(0, 0)).is_err());
        assert!(read_runtime_metadata(tree, 100, &mut Store::default(), &mut reads()).is_err());
    }
}
