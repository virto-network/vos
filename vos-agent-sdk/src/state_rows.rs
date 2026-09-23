//! Experimental actor-row adapter for the authenticated state tree.
//!
//! Full row identities remain in authenticated values. Hashing the lookup key
//! is not permission to alias another actor/incarnation/key on collision.
//! Runtime method/lane/namespace admission is still required BEFORE using this
//! adapter; constructing it does not grant access or authenticate a root.

use crate::{
    ActorId, Hash,
    state_blocks::{BlockError, ReadBudget},
    state_tree::{BlockReader, StateTree, TreeBatch, TreeError, TreeKey, TreeUpdate, WriteBudget},
};
use alloc::vec::Vec;

pub const MAX_ROW_KEY_BYTES: usize = 64 * 1024;
pub const MAX_ROW_VALUE_BYTES: usize = 64 * 1024;
const MAGIC: &[u8; 4] = b"VSR1";
const HEADER: usize = 4 + 32 + 32 + 4;

/// Logical actor-row usage, excluding tree nodes, immutable history and inline
/// state. A runtime must authenticate the prior counters and atomically retain
/// the successor with the row root and result; this type grants no such authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowUsage {
    pub rows: u64,
    pub bytes: u64,
}

impl RowUsage {
    fn encode(self) -> [u8; 20] {
        let mut bytes = [0; 20];
        bytes[..4].copy_from_slice(b"VRU1");
        bytes[4..12].copy_from_slice(&self.rows.to_le_bytes());
        bytes[12..].copy_from_slice(&self.bytes.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if bytes.len() != 20 || &bytes[..4] != b"VRU1" {
            return Err(TreeError::InvalidValue);
        }
        let value = Self {
            rows: u64::from_le_bytes(
                bytes[4..12]
                    .try_into()
                    .map_err(|_| TreeError::InvalidValue)?,
            ),
            bytes: u64::from_le_bytes(
                bytes[12..]
                    .try_into()
                    .map_err(|_| TreeError::InvalidValue)?,
            ),
        };
        if (value.rows == 0) != (value.bytes == 0)
            || value.bytes < value.rows
            || value.bytes
                > value
                    .rows
                    .saturating_mul((MAX_ROW_KEY_BYTES + MAX_ROW_VALUE_BYTES) as u64)
        {
            return Err(TreeError::InvalidValue);
        }
        Ok(value)
    }
}

fn usage_key() -> TreeKey {
    Hash::digest(b"vos/experimental/lane-row-usage/v1", &[]).0
}

/// Read accounting from the selected lane root, not caller-provided totals.
/// Only the canonical empty tree has implicit zero usage. Existing unaccounted
/// trees cannot be upgraded by assuming their missing counter means zero.
/// Root selection and execution by a counter-preserving runtime remain required;
/// this does not audit/import arbitrary trees or authenticate a package policy.
pub fn lane_row_usage(
    tree: StateTree,
    reader: &mut impl BlockReader,
    reads: &mut ReadBudget,
) -> Result<RowUsage, TreeError> {
    if tree.root().is_none() {
        return Ok(RowUsage::default());
    }
    let bytes = tree
        .get(&usage_key(), reader, reads)?
        .ok_or(TreeError::PreconditionFailed)?;
    RowUsage::decode(&bytes)
}

#[derive(Debug)]
#[must_use]
pub struct AccountedRowBatch {
    pub update: TreeUpdate,
    pub usage: RowUsage,
}

/// Initialize an empty lane's metadata and zero accounting without inventing
/// an actor identity. Existing roots are refused; this is not an import path.
pub fn initialize_accounted_metadata(
    tree: StateTree,
    metadata: crate::state_metadata::RuntimeMetadataUpdate<'_>,
    reader: &mut impl BlockReader,
    reads: &mut ReadBudget,
    writes: &mut WriteBudget,
) -> Result<AccountedRowBatch, TreeError> {
    if tree.root().is_some() {
        return Err(TreeError::PreconditionFailed);
    }
    let usage = RowUsage::default();
    let mut batch = TreeBatch::new(tree, reader);
    batch.update_checked(usage_key(), Some(&usage.encode()), reads, writes, |old| {
        if old.is_some() {
            return Err(TreeError::PreconditionFailed);
        }
        Ok(())
    })?;
    crate::state_metadata::stage_runtime_metadata(&mut batch, true, metadata, reads, writes)?;
    Ok(AccountedRowBatch {
        update: batch.finish()?,
        usage,
    })
}

/// Replace metadata in an existing accounted lane without changing actor rows
/// or counters. In particular, retirement needs no artificial actor-row write.
/// This refuses unaccounted roots; it is not initialization or migration.
pub fn update_accounted_metadata(
    tree: StateTree,
    metadata: crate::state_metadata::RuntimeMetadataUpdate<'_>,
    limits: crate::contract::ExternalStateResourceLimits,
    reader: &mut impl BlockReader,
    reads: &mut ReadBudget,
    writes: &mut WriteBudget,
) -> Result<AccountedRowBatch, TreeError> {
    if tree.root().is_none() || !limits.is_valid() {
        return Err(TreeError::PreconditionFailed);
    }
    let usage = lane_row_usage(tree, reader, reads)?;
    if usage.rows > limits.max_rows_per_lane || usage.bytes > limits.max_row_bytes_per_lane {
        return Err(TreeError::WriteBudgetExceeded);
    }
    let mut batch = TreeBatch::new(tree, reader);
    crate::state_metadata::stage_runtime_metadata(&mut batch, false, metadata, reads, writes)?;
    Ok(AccountedRowBatch {
        update: batch.finish()?,
        usage,
    })
}

/// Deltas count full logical key/value bytes. Replacements and exchanges are
/// checked against final usage, not transient order within a canonical batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowUsageDelta {
    removed: RowUsage,
    added: RowUsage,
}

impl RowUsageDelta {
    pub fn apply(self, prior: RowUsage, limit: RowUsage) -> Result<RowUsage, TreeError> {
        let next = RowUsage {
            rows: prior
                .rows
                .checked_sub(self.removed.rows)
                .and_then(|n| n.checked_add(self.added.rows))
                .ok_or(TreeError::PreconditionFailed)?,
            bytes: prior
                .bytes
                .checked_sub(self.removed.bytes)
                .and_then(|n| n.checked_add(self.added.bytes))
                .ok_or(TreeError::PreconditionFailed)?,
        };
        if next.rows > limit.rows || next.bytes > limit.bytes {
            return Err(TreeError::WriteBudgetExceeded);
        }
        Ok(next)
    }
}

#[derive(Debug)]
#[must_use]
pub struct ActorRowBatch {
    pub update: TreeUpdate,
    pub usage: RowUsageDelta,
}

#[derive(Clone, Copy, Debug)]
pub struct ActorRows {
    tree: StateTree,
    actor: ActorId,
    incarnation: Hash,
}

impl ActorRows {
    /// Selected immutable base; obtaining it does not authenticate its authority.
    pub const fn tree(&self) -> StateTree {
        self.tree
    }

    /// Build an all-or-nothing candidate from strictly sorted, unique logical
    /// keys. Permissions must be admitted by the runtime before entry. Only
    /// touched paths are loaded; every intermediate block consumes the shared
    /// write budget. Errors leave the source and base root unchanged.
    /// Counters cover row keys/values only, not runtime metadata or physical GC.
    /// This low-level helper does not maintain the lane counter. Do not mix it
    /// with `update_accounted_batch` on the same lane.
    pub fn update_batch(
        &self,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
        reader: &mut impl BlockReader,
        reads: &mut ReadBudget,
        writes: &mut WriteBudget,
    ) -> Result<ActorRowBatch, TreeError> {
        self.validate_batch(changes)?;
        let mut batch = TreeBatch::new(self.tree, reader);
        let usage = self.stage_batch(changes, &mut batch, reads, writes)?;
        Ok(ActorRowBatch {
            update: batch.finish()?,
            usage,
        })
    }

    /// Atomically prepare row changes and the lane-wide counter under one root.
    /// `limits` must be selected from the admitted signed runtime package, with
    /// any stricter authenticated policy already applied. This never stages
    /// provider writes. The runtime must also bind inline state and outcomes to
    /// the same enclosing publication and must not mix unaccounted writes into
    /// an accounted lane. Missing blocks/counters are never empty accounting.
    pub fn update_accounted_batch(
        &self,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
        limits: crate::contract::ExternalStateResourceLimits,
        reader: &mut impl BlockReader,
        reads: &mut ReadBudget,
        writes: &mut WriteBudget,
    ) -> Result<AccountedRowBatch, TreeError> {
        self.update_accounted_inner(changes, limits, None, reader, (reads, writes))
    }

    /// Prepare rows, lane counters and opaque runtime metadata under one root.
    /// Metadata must encode the complete successor for this lane, including
    /// inline state and retained outcomes where applicable. The enclosing
    /// runtime must validate its aggregate signed state limit before entry.
    /// Failure exposes no intermediate root and never writes the provider.
    pub fn update_accounted_with_metadata(
        &self,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
        limits: crate::contract::ExternalStateResourceLimits,
        metadata: crate::state_metadata::RuntimeMetadataUpdate<'_>,
        reader: &mut impl BlockReader,
        budgets: (&mut ReadBudget, &mut WriteBudget),
    ) -> Result<AccountedRowBatch, TreeError> {
        self.update_accounted_inner(changes, limits, Some(metadata), reader, budgets)
    }

    fn update_accounted_inner(
        &self,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
        limits: crate::contract::ExternalStateResourceLimits,
        metadata: Option<crate::state_metadata::RuntimeMetadataUpdate<'_>>,
        reader: &mut impl BlockReader,
        (reads, writes): (&mut ReadBudget, &mut WriteBudget),
    ) -> Result<AccountedRowBatch, TreeError> {
        self.validate_batch(changes)?;
        if !limits.is_valid() {
            return Err(TreeError::PreconditionFailed);
        }
        let limit = RowUsage {
            rows: limits.max_rows_per_lane,
            bytes: limits.max_row_bytes_per_lane,
        };
        let prior = lane_row_usage(self.tree, reader, reads)?;
        if prior.rows > limit.rows || prior.bytes > limit.bytes {
            return Err(TreeError::PreconditionFailed);
        }
        let mut batch = TreeBatch::new(self.tree, reader);
        let delta = self.stage_batch(changes, &mut batch, reads, writes)?;
        let usage = delta.apply(prior, limit)?;
        let expected = self.tree.root().map(|_| prior);
        batch.update_checked(usage_key(), Some(&usage.encode()), reads, writes, |old| {
            if old.map(RowUsage::decode).transpose()? != expected {
                return Err(TreeError::PreconditionFailed);
            }
            Ok(())
        })?;
        if let Some(metadata) = metadata {
            crate::state_metadata::stage_runtime_metadata(
                &mut batch,
                self.tree.root().is_none(),
                metadata,
                reads,
                writes,
            )?;
        }
        Ok(AccountedRowBatch {
            update: batch.finish()?,
            usage,
        })
    }

    fn validate_batch(&self, changes: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<(), TreeError> {
        // Match the existing bounded actor delta envelope, not retained rows.
        if changes.len() > 16_384 {
            return Err(TreeError::InvalidValue);
        }
        let mut previous: Option<&[u8]> = None;
        let mut bytes = 40usize;
        for (key, value) in changes {
            self.index(key)?;
            if previous.is_some_and(|previous| previous >= key.as_slice()) {
                return Err(TreeError::InvalidKey);
            }
            previous = Some(key);
            if value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_ROW_VALUE_BYTES)
            {
                return Err(TreeError::InvalidValue);
            }
            bytes = bytes
                .checked_add(5 + key.len())
                .and_then(|bytes| {
                    bytes.checked_add(value.as_ref().map_or(0, |value| 4 + value.len()))
                })
                .filter(|bytes| *bytes <= crate::state_change::MAX_STATE_CHANGE_BYTES)
                .ok_or(TreeError::InvalidValue)?;
        }
        Ok(())
    }

    fn stage_batch<R: BlockReader>(
        &self,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
        batch: &mut TreeBatch<'_, R>,
        reads: &mut ReadBudget,
        writes: &mut WriteBudget,
    ) -> Result<RowUsageDelta, TreeError> {
        let mut usage = RowUsageDelta::default();
        for (key, value) in changes {
            let encoded = value.as_ref().map(|value| self.encode(key, value));
            batch.update_checked(self.index(key)?, encoded.as_deref(), reads, writes, |old| {
                if let Some(old) = old {
                    let old = self.decode(key, old)?;
                    usage.removed.rows += 1;
                    usage.removed.bytes += (key.len() + old.len()) as u64;
                }
                if let Some(value) = value {
                    usage.added.rows += 1;
                    usage.added.bytes += (key.len() + value.len()) as u64;
                }
                Ok(())
            })?;
        }
        Ok(usage)
    }

    pub fn new(tree: StateTree, actor: ActorId, incarnation: Hash) -> Result<Self, TreeError> {
        if actor == ActorId::ZERO || incarnation == Hash::ZERO {
            return Err(TreeError::Block(BlockError::InvalidScope));
        }
        Ok(Self {
            tree,
            actor,
            incarnation,
        })
    }

    fn index(&self, key: &[u8]) -> Result<TreeKey, TreeError> {
        if key.is_empty() || key.len() > MAX_ROW_KEY_BYTES {
            return Err(TreeError::InvalidKey);
        }
        Ok(Hash::digest(
            b"vos/experimental/actor-row-key/v1",
            &[
                self.actor.as_bytes(),
                self.incarnation.as_bytes(),
                &(key.len() as u32).to_le_bytes(),
                key,
            ],
        )
        .0)
    }

    fn encode(&self, key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER + key.len() + value.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.actor.as_bytes());
        bytes.extend_from_slice(self.incarnation.as_bytes());
        bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(value);
        bytes
    }

    fn decode<'a>(&self, expected_key: &[u8], bytes: &'a [u8]) -> Result<&'a [u8], TreeError> {
        if bytes.len() < HEADER || &bytes[..4] != MAGIC {
            return Err(TreeError::InvalidValue);
        }
        let key_len = u32::from_le_bytes(
            bytes[68..72]
                .try_into()
                .map_err(|_| TreeError::InvalidValue)?,
        ) as usize;
        if key_len == 0
            || key_len > MAX_ROW_KEY_BYTES
            || bytes.len() < HEADER + key_len
            || bytes.len() - HEADER - key_len > MAX_ROW_VALUE_BYTES
        {
            return Err(TreeError::InvalidValue);
        }
        if &bytes[4..36] != self.actor.as_bytes()
            || &bytes[36..68] != self.incarnation.as_bytes()
            || &bytes[HEADER..HEADER + key_len] != expected_key
        {
            return Err(TreeError::PreconditionFailed);
        }
        Ok(&bytes[HEADER + key_len..])
    }

    pub fn get(
        &self,
        key: &[u8],
        reader: &mut impl BlockReader,
        reads: &mut ReadBudget,
    ) -> Result<Option<Vec<u8>>, TreeError> {
        let index = self.index(key)?;
        self.tree
            .get(&index, reader, reads)?
            .map(|bytes| self.decode(key, &bytes).map(<[u8]>::to_vec))
            .transpose()
    }

    /// Validate the old full identity before either replacing or deleting it.
    /// A collision/corrupt record is not absence and cannot be overwritten.
    /// This low-level operation does not maintain lane accounting; use
    /// `update_accounted_batch` for every mutation of an accounted lane.
    pub fn update(
        &self,
        key: &[u8],
        value: Option<&[u8]>,
        reader: &mut impl BlockReader,
        reads: &mut ReadBudget,
        writes: &mut WriteBudget,
    ) -> Result<TreeUpdate, TreeError> {
        let index = self.index(key)?;
        if value.is_some_and(|value| value.len() > MAX_ROW_VALUE_BYTES) {
            return Err(TreeError::InvalidValue);
        }
        let encoded = value.map(|value| self.encode(key, value));
        self.tree
            .update_checked(index, encoded.as_deref(), reader, (reads, writes), |old| {
                if let Some(bytes) = old {
                    self.decode(key, bytes)?;
                }
                Ok(())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentId, SpaceId, StateLane,
        state_blocks::{BlockRef, BlockScope},
    };
    use alloc::{collections::BTreeMap, vec};
    #[derive(Default)]
    struct Store {
        blocks: BTreeMap<[u8; 32], Vec<u8>>,
        reads: u32,
    }
    impl BlockReader for Store {
        fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
            self.reads += 1;
            let Some(bytes) = self.blocks.get(&reference.hash().0) else {
                return Ok(false);
            };
            if bytes.len() != output.len() {
                return Err(TreeError::Storage);
            }
            output.copy_from_slice(bytes);
            Ok(true)
        }
    }
    impl Store {
        fn install(&mut self, update: TreeUpdate) -> StateTree {
            for (reference, bytes) in update.blocks {
                self.blocks.insert(reference.hash().0, bytes);
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
    fn rows(tree: StateTree, actor: u8, incarnation: u8) -> ActorRows {
        ActorRows::new(tree, ActorId([actor; 32]), Hash([incarnation; 32])).unwrap()
    }
    fn reads() -> ReadBudget {
        ReadBudget::new(300, 4 * 1024 * 1024)
    }
    fn writes() -> WriteBudget {
        WriteBudget::new(300, 4 * 1024 * 1024)
    }

    fn limits() -> crate::contract::ExternalStateResourceLimits {
        crate::contract::ExternalStateResourceLimits {
            max_rows_per_lane: 2,
            max_row_bytes_per_lane: 4,
        }
    }

    #[test]
    fn accounted_batches_share_lane_quota_and_preserve_old_roots() {
        let mut store = Store::default();
        let mut tree = empty();
        for actor in [1, 2] {
            let batch = rows(tree, actor, 1)
                .update_accounted_batch(
                    &[(b"a".to_vec(), Some(vec![1]))],
                    limits(),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap();
            assert_eq!(
                batch.usage,
                RowUsage {
                    rows: actor as u64,
                    bytes: 2 * actor as u64
                }
            );
            tree = store.install(batch.update);
        }
        let snapshot = store.blocks.clone();
        assert_eq!(
            rows(tree, 3, 2)
                .update_accounted_batch(
                    &[(b"a".to_vec(), Some(vec![1]))],
                    limits(),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap_err(),
            TreeError::WriteBudgetExceeded
        );
        assert_eq!(store.blocks, snapshot);
        let noop = rows(tree, 1, 1)
            .update_accounted_batch(
                &[(b"a".to_vec(), Some(vec![1]))],
                limits(),
                &mut store,
                &mut reads(),
                &mut WriteBudget::new(0, 0),
            )
            .unwrap();
        assert_eq!(noop.update.tree.root(), tree.root());
        assert!(noop.update.blocks.is_empty());
        let batch = rows(tree, 1, 1)
            .update_accounted_batch(
                &[(b"a".to_vec(), None), (b"b".to_vec(), Some(vec![2]))],
                limits(),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let mut successor = store.install(batch.update);
        assert_eq!(
            lane_row_usage(successor, &mut store, &mut reads()).unwrap(),
            RowUsage { rows: 2, bytes: 4 }
        );
        assert_eq!(
            rows(tree, 1, 1)
                .get(b"a", &mut store, &mut reads())
                .unwrap(),
            Some(vec![1])
        );
        for (actor, key) in [(1, b"b"), (2, b"a")] {
            let batch = rows(successor, actor, 1)
                .update_accounted_batch(
                    &[(key.to_vec(), None)],
                    limits(),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap();
            successor = store.install(batch.update);
        }
        assert!(successor.root().is_some()); // The authenticated zero counter remains.
        assert_eq!(
            lane_row_usage(successor, &mut store, &mut reads()).unwrap(),
            RowUsage::default()
        );
    }

    #[test]
    fn accounted_batches_fail_closed_without_mutating_provider() {
        let mut store = Store::default();
        let changes = [(b"a".to_vec(), Some(vec![1]))];
        let mut budget = WriteBudget::new(1, 10000);
        assert_eq!(
            rows(empty(), 1, 1)
                .update_accounted_batch(&changes, limits(), &mut store, &mut reads(), &mut budget,)
                .unwrap_err(),
            TreeError::WriteBudgetExceeded
        );
        assert_eq!(budget.remaining().0, 0);
        assert!(store.blocks.is_empty());
        let update = rows(empty(), 1, 1)
            .update(b"a", Some(&[1]), &mut store, &mut reads(), &mut writes())
            .unwrap();
        let unaccounted = store.install(update);
        let snapshot = store.blocks.clone();
        let mut budget = writes();
        let before = budget.remaining();
        assert_eq!(
            rows(unaccounted, 1, 1)
                .update_accounted_batch(&changes, limits(), &mut store, &mut reads(), &mut budget,)
                .unwrap_err(),
            TreeError::PreconditionFailed
        );
        assert_eq!(budget.remaining(), before);
        assert_eq!(store.blocks, snapshot);
        let reads_before = store.reads;
        let invalid = crate::contract::ExternalStateResourceLimits {
            max_rows_per_lane: 0,
            ..limits()
        };
        assert_eq!(
            rows(unaccounted, 1, 1)
                .update_accounted_batch(&changes, invalid, &mut store, &mut reads(), &mut writes(),)
                .unwrap_err(),
            TreeError::PreconditionFailed
        );
        assert_eq!(store.reads, reads_before);
    }

    #[test]
    fn accounting_refuses_malformed_unavailable_and_over_limit_state() {
        let mut store = Store::default();
        for bytes in [
            vec![],
            vec![0; 20],
            RowUsage { rows: 0, bytes: 1 }.encode().to_vec(),
            RowUsage { rows: 2, bytes: 1 }.encode().to_vec(),
            RowUsage {
                rows: 1,
                bytes: 131073,
            }
            .encode()
            .to_vec(),
        ] {
            let update = empty()
                .update(
                    usage_key(),
                    Some(&bytes),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap();
            let tree = store.install(update);
            assert_eq!(
                lane_row_usage(tree, &mut store, &mut reads()),
                Err(TreeError::InvalidValue)
            );
        }
        let batch = rows(empty(), 1, 1)
            .update_accounted_batch(
                &[(b"a".to_vec(), Some(vec![1]))],
                limits(),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let tree = store.install(batch.update);
        assert!(lane_row_usage(tree, &mut store, &mut ReadBudget::new(0, 0)).is_err());
        assert!(lane_row_usage(tree, &mut Store::default(), &mut reads()).is_err());
        let small = crate::contract::ExternalStateResourceLimits {
            max_row_bytes_per_lane: 1,
            ..limits()
        };
        assert_eq!(
            rows(tree, 1, 1)
                .update_accounted_batch(&[], small, &mut store, &mut reads(), &mut writes(),)
                .unwrap_err(),
            TreeError::PreconditionFailed
        );
    }

    #[test]
    fn batch_exchanges_at_capacity_without_publishing_intermediate_roots() {
        use crate::{
            state_change::StateChange,
            state_root::{RootContext, StateRootDescriptor},
        };
        let mut store = Store::default();
        let update = rows(empty(), 1, 1)
            .update(b"z", Some(b"old"), &mut store, &mut reads(), &mut writes())
            .unwrap();
        let original = store.install(update);
        let snapshot = store.blocks.clone();
        let changes = vec![
            (b"a".to_vec(), Some(b"new".to_vec())),
            (b"z".to_vec(), None),
        ];
        let batch = rows(original, 1, 1)
            .update_batch(&changes, &mut store, &mut reads(), &mut writes())
            .unwrap();
        let usage = RowUsage { rows: 1, bytes: 4 };
        assert_eq!(batch.usage.apply(usage, usage).unwrap(), usage);
        assert!(batch.usage.apply(RowUsage::default(), usage).is_err());
        assert!(
            batch
                .usage
                .apply(usage, RowUsage { rows: 1, bytes: 3 })
                .is_err()
        );
        assert_eq!(store.blocks, snapshot);
        assert_eq!(
            rows(original, 1, 1)
                .get(b"z", &mut store, &mut reads())
                .unwrap(),
            Some(b"old".to_vec())
        );
        let base_context =
            RootContext::new(original.scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let next_context =
            RootContext::new(original.scope(), Hash([4; 32]), Hash([6; 32])).unwrap();
        let base = StateRootDescriptor::new(base_context, original.root());
        let change =
            StateChange::from_update(base.commitment(), next_context, batch.update).unwrap();
        // Exact reachability refuses extraneous intermediate branches/leaves.
        change
            .verify_reuse(base, next_context, &mut store, &mut reads())
            .unwrap();
        assert_eq!(change.blocks().len(), 1);
        for (reference, bytes) in change.blocks() {
            store.blocks.insert(reference.hash().0, bytes.clone());
        }
        let successor = change
            .next()
            .bind(next_context, change.next().commitment())
            .unwrap();
        assert_eq!(
            rows(successor, 1, 1)
                .get(b"a", &mut store, &mut reads())
                .unwrap(),
            Some(b"new".to_vec())
        );
        assert!(
            rows(successor, 1, 1)
                .get(b"z", &mut store, &mut reads())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            rows(original, 1, 1)
                .get(b"z", &mut store, &mut reads())
                .unwrap(),
            Some(b"old".to_vec())
        );
    }

    #[test]
    fn batch_is_atomic_on_late_failure_and_charges_discarded_work() {
        let mut store = Store::default();
        let changes = vec![
            (b"a".to_vec(), Some(vec![1])),
            (b"b".to_vec(), Some(vec![2])),
        ];
        let mut budget = WriteBudget::new(1, 1000);
        assert!(
            rows(empty(), 1, 1)
                .update_batch(&changes, &mut store, &mut reads(), &mut budget)
                .is_err()
        );
        assert_eq!(budget.remaining().0, 0);
        assert!(store.blocks.is_empty());
        assert_eq!(store.reads, 0); // The second operation read only candidate memory.
        let mut invalid = changes.clone();
        invalid[1].0 = invalid[0].0.clone();
        let mut budget = writes();
        let initial = budget.remaining();
        assert!(
            rows(empty(), 1, 1)
                .update_batch(&invalid, &mut store, &mut reads(), &mut budget)
                .is_err()
        );
        assert_eq!(budget.remaining(), initial);
        assert!(store.blocks.is_empty());
        let mut no_reads = ReadBudget::new(0, 0);
        assert!(
            rows(empty(), 1, 1)
                .update_batch(&changes, &mut store, &mut no_reads, &mut writes())
                .is_err()
        );
        assert!(store.blocks.is_empty());
    }

    #[test]
    fn batch_chunked_candidates_verify_and_noop_emits_nothing() {
        use crate::{
            state_change::StateChange,
            state_root::{RootContext, StateRootDescriptor},
        };
        let mut store = Store::default();
        let keys = [vec![1; MAX_ROW_KEY_BYTES], vec![2; MAX_ROW_KEY_BYTES]];
        let changes = keys
            .iter()
            .map(|key| (key.clone(), Some(vec![7; MAX_ROW_VALUE_BYTES])))
            .collect::<Vec<_>>();
        let original = empty();
        let batch = rows(original, 1, 1)
            .update_batch(&changes, &mut store, &mut reads(), &mut writes())
            .unwrap();
        let usage = batch
            .usage
            .apply(
                RowUsage::default(),
                RowUsage {
                    rows: 2,
                    bytes: 4 * 65536,
                },
            )
            .unwrap();
        assert_eq!(
            usage,
            RowUsage {
                rows: 2,
                bytes: 4 * 65536
            }
        );
        let context = RootContext::new(original.scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let base = StateRootDescriptor::new(context, None);
        let change = StateChange::from_update(base.commitment(), context, batch.update).unwrap();
        change
            .verify_reuse(base, context, &mut store, &mut reads())
            .unwrap();
        for (reference, bytes) in change.blocks() {
            store.blocks.insert(reference.hash().0, bytes.clone());
        }
        let tree = change
            .next()
            .bind(context, change.next().commitment())
            .unwrap();
        let snapshot = store.blocks.clone();
        let no_change = rows(tree, 1, 1)
            .update_batch(
                &changes,
                &mut store,
                &mut reads(),
                &mut WriteBudget::new(0, 0),
            )
            .unwrap();
        assert_eq!(no_change.update.tree, tree);
        assert!(no_change.update.blocks.is_empty());
        assert_eq!(no_change.usage.apply(usage, usage).unwrap(), usage);
        assert_eq!(store.blocks, snapshot);
        assert_eq!(
            rows(tree, 1, 1)
                .get(&keys[0], &mut store, &mut reads())
                .unwrap(),
            Some(vec![7; MAX_ROW_VALUE_BYTES])
        );
    }

    #[test]
    fn full_keys_actor_and_incarnation_are_independent() {
        let mut store = Store::default();
        let mut tree = empty();
        let identities = [
            (1, 1, &b"s/1/short"[..]),
            (2, 1, &b"s/1/short"[..]),
            (1, 2, &b"s/1/short"[..]),
            (1, 1, &b"s/1/short\0tail"[..]),
        ];
        for (i, (actor, incarnation, key)) in identities.iter().enumerate() {
            let update = rows(tree, *actor, *incarnation)
                .update(
                    key,
                    Some(&[i as u8]),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap();
            tree = store.install(update);
        }
        for (i, (actor, incarnation, key)) in identities.iter().enumerate() {
            assert_eq!(
                rows(tree, *actor, *incarnation)
                    .get(key, &mut store, &mut reads())
                    .unwrap(),
                Some(vec![i as u8])
            );
        }
        assert_eq!(
            rows(tree, 3, 1)
                .get(b"s/1/short", &mut store, &mut reads())
                .unwrap(),
            None
        );
    }

    #[test]
    fn maximum_key_and_value_use_chunks_without_truncation() {
        let mut store = Store::default();
        let key = vec![7; MAX_ROW_KEY_BYTES];
        let value = vec![8; MAX_ROW_VALUE_BYTES];
        let original = empty();
        let update = rows(original, 1, 1)
            .update(&key, Some(&value), &mut store, &mut reads(), &mut writes())
            .unwrap();
        let tree = store.install(update);
        assert_eq!(
            rows(tree, 1, 1)
                .get(&key, &mut store, &mut reads())
                .unwrap(),
            Some(value)
        );
        let mut different = key.clone();
        *different.last_mut().unwrap() ^= 1;
        assert_eq!(
            rows(tree, 1, 1)
                .get(&different, &mut store, &mut reads())
                .unwrap(),
            None
        );
        let update = rows(tree, 1, 1)
            .update(&key, None, &mut store, &mut reads(), &mut writes())
            .unwrap();
        assert_eq!(store.install(update), original);
    }

    #[test]
    fn identity_substitution_is_not_read_overwritten_or_deleted() {
        for (actor, incarnation, key) in [
            (2, 1, &b"wanted"[..]),
            (1, 2, &b"wanted"[..]),
            (1, 1, &b"different"[..]),
        ] {
            let mut store = Store::default();
            let initial = empty();
            let wanted = rows(initial, 1, 1);
            // Deliberately inject a valid foreign row at the expected digest.
            // This exercises collision rejection without breaking the hash.
            let foreign = rows(initial, actor, incarnation).encode(key, b"foreign");
            let update = initial
                .update(
                    wanted.index(b"wanted").unwrap(),
                    Some(&foreign),
                    &mut store,
                    &mut reads(),
                    &mut writes(),
                )
                .unwrap();
            let tree = store.install(update);
            let bound = rows(tree, 1, 1);
            assert_eq!(
                bound.get(b"wanted", &mut store, &mut reads()),
                Err(TreeError::PreconditionFailed)
            );
            for value in [None, Some(&b"replacement"[..])] {
                let mut write_budget = writes();
                let before = write_budget.remaining();
                assert!(matches!(
                    bound.update(
                        b"wanted",
                        value,
                        &mut store,
                        &mut reads(),
                        &mut write_budget
                    ),
                    Err(TreeError::PreconditionFailed)
                ));
                assert_eq!(write_budget.remaining(), before);
            }
        }
    }

    #[test]
    fn replacement_validates_in_one_traversal_and_preserves_empty_values() {
        let mut store = Store::default();
        let update = rows(empty(), 1, 1)
            .update(b"key", Some(b""), &mut store, &mut reads(), &mut writes())
            .unwrap();
        let tree = store.install(update);
        assert_eq!(
            rows(tree, 1, 1)
                .get(b"key", &mut store, &mut reads())
                .unwrap(),
            Some(vec![])
        );
        let before = store.reads;
        let update = rows(tree, 1, 1)
            .update(
                b"key",
                Some(b"new"),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        assert_eq!(store.reads - before, 1);
        let tree = store.install(update);
        assert_eq!(
            rows(tree, 1, 1)
                .get(b"key", &mut store, &mut reads())
                .unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn malformed_records_and_input_limits_fail_closed() {
        let mut store = Store::default();
        let bound = rows(empty(), 1, 1);
        for key in [vec![], vec![0; MAX_ROW_KEY_BYTES + 1]] {
            assert_eq!(
                bound.get(&key, &mut store, &mut reads()),
                Err(TreeError::InvalidKey)
            );
        }
        assert!(matches!(
            bound.update(
                b"key",
                Some(&vec![0; MAX_ROW_VALUE_BYTES + 1]),
                &mut store,
                &mut reads(),
                &mut writes()
            ),
            Err(TreeError::InvalidValue)
        ));
        assert_eq!(store.reads, 0);
        let encoded = bound.encode(b"key", b"value");
        for end in 0..HEADER + 3 {
            assert!(bound.decode(b"key", &encoded[..end]).is_err());
        }
        for length in [0, (MAX_ROW_KEY_BYTES + 1) as u32, u32::MAX] {
            let mut bad = encoded.clone();
            bad[68..72].copy_from_slice(&length.to_le_bytes());
            assert_eq!(bound.decode(b"key", &bad), Err(TreeError::InvalidValue));
        }
        assert!(ActorRows::new(empty(), ActorId::ZERO, Hash([1; 32])).is_err());
        assert!(ActorRows::new(empty(), ActorId([1; 32]), Hash::ZERO).is_err());
    }
}
