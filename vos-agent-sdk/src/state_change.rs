//! Bounded experimental candidate-change wire, NOT a commit certificate.
//!
//! A candidate binds its base descriptor commitment and next snapshot context.
//! Blocks are hash-sorted/deduplicated and individually authenticated. Decoding
//! does NOT establish reachability, complete availability, authorization or
//! durability. Only an admitted execution plus the publication coordinator may
//! advance a head; failed/truncated executions must never publish a candidate.

use crate::{
    Hash,
    protocol::wire::{DecodeError, Decoder, Encoder},
    state_blocks::{BlockRef, MAX_STATE_BLOCK_BYTES, ReadBudget},
    state_root::{MAX_STATE_ROOT_BYTES, RootContext, StateRootDescriptor},
    state_tree::{BlockReader, ChangeReachability, TreeError, TreeUpdate},
};
use alloc::{collections::BTreeMap, vec::Vec};

pub const MAX_STATE_CHANGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STATE_CHANGE_BLOCKS: usize = 4096;
const MAGIC: &[u8; 4] = b"VSC1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    base: Hash,
    next: StateRootDescriptor,
    blocks: Vec<(BlockRef, Vec<u8>)>,
}

impl StateChange {
    pub fn from_update(
        base: Hash,
        context: RootContext,
        update: TreeUpdate,
    ) -> Result<Self, DecodeError> {
        if base == Hash::ZERO || context.scope() != update.tree.scope() {
            return Err(DecodeError::InvalidPlatform);
        }
        if update.blocks.len() > MAX_STATE_CHANGE_BLOCKS {
            return Err(DecodeError::LimitExceeded);
        }
        let next = StateRootDescriptor::new(context, update.tree.root());
        let mut unique = BTreeMap::new();
        let mut size = 44 + next.encode().len();
        for (reference, bytes) in update.blocks {
            if context.scope().reference(&bytes).ok() != Some(reference) {
                return Err(DecodeError::NonCanonical);
            }
            if let Some((prior, data)) = unique.get(&reference.hash().0) {
                if *prior != reference || *data != bytes {
                    return Err(DecodeError::NonCanonical);
                }
                continue;
            }
            size = size
                .checked_add(36 + bytes.len())
                .filter(|size| *size <= MAX_STATE_CHANGE_BYTES)
                .ok_or(DecodeError::LimitExceeded)?;
            unique.insert(reference.hash().0, (reference, bytes));
        }
        Ok(Self {
            base,
            next,
            blocks: unique.into_values().collect(),
        })
    }

    pub const fn base(&self) -> Hash {
        self.base
    }
    pub const fn next(&self) -> StateRootDescriptor {
        self.next
    }
    pub fn blocks(&self) -> &[(BlockRef, Vec<u8>)] {
        &self.blocks
    }

    /// Check candidate links and prove every reused subtree under an
    /// independently selected, completely available base. This is conditional
    /// reachability, NOT a durability/finality certificate. The owner must pin
    /// base availability against GC until candidate persistence/publication.
    /// Recovery/import must audit the base first; this never scans descendants
    /// of reused subtrees. New chunked leaves must supply all of their chunks.
    pub fn verify_reuse(
        &self,
        base: StateRootDescriptor,
        expected_next: RootContext,
        reader: &mut impl BlockReader,
        budget: &mut ReadBudget,
    ) -> Result<ChangeReachability, TreeError> {
        self.validate_context(base.commitment(), expected_next)
            .map_err(|_| TreeError::PreconditionFailed)?;
        if base.context().scope() != expected_next.scope() {
            return Err(TreeError::PreconditionFailed);
        }
        let old = base
            .bind(base.context(), self.base)
            .map_err(|_| TreeError::PreconditionFailed)?;
        let next = self
            .next
            .bind(expected_next, self.next.commitment())
            .map_err(|_| TreeError::PreconditionFailed)?;
        old.verify_candidate(next.root(), &self.blocks, reader, budget)
    }

    /// Check independently selected operation bindings. This is not an
    /// authorization/finality decision and does not publish anything.
    pub fn validate_context(
        &self,
        expected_base: Hash,
        expected_next: RootContext,
    ) -> Result<(), DecodeError> {
        if expected_base == Hash::ZERO
            || self.base != expected_base
            || self.next.context() != expected_next
        {
            return Err(DecodeError::InvalidPlatform);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        // Private fields can be created only by the bounded constructors.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(self.base.as_bytes());
        encoder.bytes(&self.next.encode());
        encoder.list(&self.blocks, |encoder, (reference, bytes)| {
            encoder.fixed(reference.hash().as_bytes());
            encoder.bytes(bytes);
        });
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_STATE_CHANGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        let base = Hash(decoder.fixed()?);
        if base == Hash::ZERO {
            return Err(DecodeError::InvalidPlatform);
        }
        let next = StateRootDescriptor::decode(decoder.bytes_ref_bounded(MAX_STATE_ROOT_BYTES)?)
            .map_err(|_| DecodeError::NonCanonical)?;
        let count = decoder.u32()? as usize;
        if count > MAX_STATE_CHANGE_BLOCKS || count > decoder.remaining() / 37 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut blocks: Vec<(BlockRef, Vec<u8>)> = Vec::new();
        for _ in 0..count {
            let hash = Hash(decoder.fixed()?);
            if blocks
                .last()
                .is_some_and(|(previous, _)| previous.hash().0 >= hash.0)
            {
                return Err(DecodeError::NonCanonical);
            }
            let value = decoder.bytes_ref_bounded(MAX_STATE_BLOCK_BYTES)?;
            let reference =
                BlockRef::new(hash, value.len() as u32).map_err(|_| DecodeError::NonCanonical)?;
            if next.context().scope().reference(value).ok() != Some(reference) {
                return Err(DecodeError::NonCanonical);
            }
            blocks.push((reference, value.to_vec()));
        }
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self { base, next, blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentId, SpaceId, StateLane, state_blocks::BlockScope, state_tree::StateTree};
    use alloc::vec;
    fn context(revision: u8) -> RootContext {
        RootContext::new(
            BlockScope::new(
                SpaceId([1; 32]),
                AgentId([2; 32]),
                Hash([3; 32]),
                StateLane::Linear,
            )
            .unwrap(),
            Hash([4; 32]),
            Hash([revision; 32]),
        )
        .unwrap()
    }
    fn candidate() -> StateChange {
        let scope = context(6).scope();
        let blocks: Vec<_> = [
            b"first".as_slice(),
            b"second".as_slice(),
            b"first".as_slice(),
        ]
        .into_iter()
        .map(|bytes| (scope.reference(bytes).unwrap(), bytes.to_vec()))
        .collect();
        let tree = StateTree::from_root(scope, Some(blocks[0].0));
        // Arbitrary block payloads here deliberately show that the transport
        // validates bytes, not tree reachability or a publication decision.
        StateChange::from_update(Hash([5; 32]), context(6), TreeUpdate { tree, blocks }).unwrap()
    }
    #[test]
    fn change_roundtrip_deduplicates_and_binds_base_and_next_context() {
        let change = candidate();
        assert_eq!(change.blocks().len(), 2);
        assert!(change.blocks()[0].0.hash().0 < change.blocks()[1].0.hash().0);
        assert_eq!(StateChange::decode(&change.encode()), Ok(change.clone()));
        assert_eq!(change.validate_context(Hash([5; 32]), context(6)), Ok(()));
        assert!(change.validate_context(Hash([9; 32]), context(6)).is_err());
        assert!(change.validate_context(Hash([5; 32]), context(7)).is_err());
    }
    #[test]
    fn truncated_corrupt_duplicate_and_reordered_candidates_fail_closed() {
        let change = candidate();
        let bytes = change.encode();
        for end in 0..bytes.len() {
            assert!(StateChange::decode(&bytes[..end]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(StateChange::decode(&bad).is_err());
        let mut bad = bytes;
        *bad.last_mut().unwrap() ^= 1;
        assert!(StateChange::decode(&bad).is_err());
        let mut duplicate = change.clone();
        duplicate.blocks.push(duplicate.blocks[1].clone());
        assert!(StateChange::decode(&duplicate.encode()).is_err());
        let mut reversed = change;
        reversed.blocks.reverse();
        assert!(StateChange::decode(&reversed.encode()).is_err());
    }
    #[test]
    fn invalid_scope_and_oversized_declared_lists_are_rejected() {
        let change = candidate();
        let mut bytes = change.encode();
        let count_offset = 40 + change.next().encode().len();
        bytes[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(StateChange::decode(&bytes), Err(DecodeError::LimitExceeded));
        assert_eq!(
            StateChange::decode(&vec![0; MAX_STATE_CHANGE_BYTES + 1]),
            Err(DecodeError::LimitExceeded)
        );
        let other = BlockScope::new(
            SpaceId([9; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap();
        assert!(
            StateChange::from_update(
                Hash([5; 32]),
                context(6),
                TreeUpdate {
                    tree: StateTree::empty(other),
                    blocks: Vec::new()
                }
            )
            .is_err()
        );
        assert!(
            StateChange::from_update(
                Hash::ZERO,
                context(6),
                TreeUpdate {
                    tree: StateTree::empty(context(6).scope()),
                    blocks: Vec::new()
                }
            )
            .is_err()
        );
    }
}
