//! Experimental revision-bound root descriptor. This is NOT a finality proof.
//!
//! The execution owner must obtain the expected context and descriptor
//! commitment from an authenticated journal/checkpoint, never from the same
//! untrusted descriptor it is checking. Binding here detects substitutions; it
//! does not establish freshness, availability, namespace ownership or quorum.
//! No current r19 runtime admits this experimental wire.

use crate::{
    AgentId, Hash, SpaceId, StateLane,
    state_blocks::{BlockRef, BlockScope},
    state_tree::StateTree,
};
use alloc::vec::Vec;

const MAGIC: &[u8; 4] = b"VSRD";
const EMPTY_BYTES: usize = 4 + 97 + 32 + 32 + 1;
pub const MAX_STATE_ROOT_BYTES: usize = EMPTY_BYTES + 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootError {
    InvalidEncoding,
    InvalidContext,
    ContextMismatch,
    CommitmentMismatch,
}

/// Exact root-producing operation snapshot. A later journal projection may
/// retain this context unchanged; its cursor is not necessarily this revision.
/// Storage generation survives ordinary revisions
/// and runtime upgrades; the runtime binding and revision commitment do not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootContext {
    scope: BlockScope,
    runtime_binding: Hash,
    revision: Hash,
}

impl RootContext {
    pub const fn scope(self) -> BlockScope {
        self.scope
    }
    /// `runtime_binding` must commit the admitted program, deployment, package
    /// and ABI. `revision` must commit the exact root-producing lane cursor/head,
    /// including genesis identity (also for empty post-genesis state).
    pub fn new(
        scope: BlockScope,
        runtime_binding: Hash,
        revision: Hash,
    ) -> Result<Self, RootError> {
        if runtime_binding == Hash::ZERO || revision == Hash::ZERO {
            return Err(RootError::InvalidContext);
        }
        Ok(Self {
            scope,
            runtime_binding,
            revision,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRootDescriptor {
    context: RootContext,
    root: Option<BlockRef>,
}

impl StateRootDescriptor {
    pub const fn context(self) -> RootContext {
        self.context
    }
    /// Construct a candidate to commit. This is not admission of stored data.
    pub const fn new(context: RootContext, root: Option<BlockRef>) -> Self {
        Self { context, root }
    }

    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_STATE_ROOT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.context.scope.space().as_bytes());
        bytes.extend_from_slice(self.context.scope.agent().as_bytes());
        bytes.extend_from_slice(self.context.scope.generation().as_bytes());
        bytes.push(self.context.scope.lane() as u8);
        bytes.extend_from_slice(self.context.runtime_binding.as_bytes());
        bytes.extend_from_slice(self.context.revision.as_bytes());
        bytes.push(u8::from(self.root.is_some()));
        if let Some(root) = self.root {
            bytes.extend_from_slice(root.hash().as_bytes());
            bytes.extend_from_slice(&root.byte_len().to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RootError> {
        if ![EMPTY_BYTES, MAX_STATE_ROOT_BYTES].contains(&bytes.len()) || &bytes[..4] != MAGIC {
            return Err(RootError::InvalidEncoding);
        }
        let fixed = |start: usize| -> Result<[u8; 32], RootError> {
            bytes[start..start + 32]
                .try_into()
                .map_err(|_| RootError::InvalidEncoding)
        };
        let lane = match bytes[100] {
            0 => StateLane::Linear,
            1 => StateLane::Merge,
            2 => StateLane::Local,
            _ => return Err(RootError::InvalidEncoding),
        };
        let scope = BlockScope::new(
            SpaceId(fixed(4)?),
            AgentId(fixed(36)?),
            Hash(fixed(68)?),
            lane,
        )
        .map_err(|_| RootError::InvalidContext)?;
        let context = RootContext::new(scope, Hash(fixed(101)?), Hash(fixed(133)?))?;
        let root = match (bytes[165], bytes.len()) {
            (0, EMPTY_BYTES) => None,
            (1, MAX_STATE_ROOT_BYTES) => {
                let len = u32::from_le_bytes(
                    bytes[198..202]
                        .try_into()
                        .map_err(|_| RootError::InvalidEncoding)?,
                );
                Some(
                    BlockRef::new(Hash(fixed(166)?), len)
                        .map_err(|_| RootError::InvalidEncoding)?,
                )
            }
            _ => return Err(RootError::InvalidEncoding),
        };
        Ok(Self { context, root })
    }

    pub fn commitment(self) -> Hash {
        Hash::digest(b"vos/experimental/state-root/v1", &[&self.encode()])
    }

    /// Verify both expected snapshot and its independently authenticated root
    /// commitment. Old snapshots can still be read when explicitly admitted;
    /// they cannot substitute for a different expected revision.
    pub fn bind(
        self,
        expected: RootContext,
        expected_commitment: Hash,
    ) -> Result<StateTree, RootError> {
        if self.context != expected {
            return Err(RootError::ContextMismatch);
        }
        if expected_commitment == Hash::ZERO || self.commitment() != expected_commitment {
            return Err(RootError::CommitmentMismatch);
        }
        Ok(StateTree::from_root(expected.scope, self.root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> RootContext {
        RootContext::new(
            BlockScope::new(
                SpaceId([1; 32]),
                AgentId([2; 32]),
                Hash([3; 32]),
                StateLane::Linear,
            )
            .unwrap(),
            Hash([4; 32]),
            Hash([5; 32]),
        )
        .unwrap()
    }
    fn descriptor() -> StateRootDescriptor {
        StateRootDescriptor::new(context(), Some(BlockRef::new(Hash([6; 32]), 99).unwrap()))
    }

    #[test]
    fn empty_and_populated_descriptors_roundtrip_and_bind_exactly() {
        for root in [None, descriptor().root] {
            let value = StateRootDescriptor::new(context(), root);
            assert_eq!(StateRootDescriptor::decode(&value.encode()), Ok(value));
            assert_eq!(
                value.bind(context(), value.commitment()).unwrap().root(),
                root
            );
            assert_eq!(
                value.encode().len(),
                if root.is_none() {
                    EMPTY_BYTES
                } else {
                    MAX_STATE_ROOT_BYTES
                }
            );
        }
    }

    #[test]
    fn every_snapshot_binding_rejects_substitution() {
        let original = descriptor();
        let scope = original.context.scope;
        let scopes = [
            BlockScope::new(
                SpaceId([9; 32]),
                scope.agent(),
                scope.generation(),
                scope.lane(),
            )
            .unwrap(),
            BlockScope::new(
                scope.space(),
                AgentId([9; 32]),
                scope.generation(),
                scope.lane(),
            )
            .unwrap(),
            BlockScope::new(scope.space(), scope.agent(), Hash([9; 32]), scope.lane()).unwrap(),
            BlockScope::new(
                scope.space(),
                scope.agent(),
                scope.generation(),
                StateLane::Local,
            )
            .unwrap(),
        ];
        let mut contexts: Vec<_> = scopes
            .into_iter()
            .map(|scope| RootContext {
                scope,
                ..original.context
            })
            .collect();
        contexts.push(RootContext {
            runtime_binding: Hash([9; 32]),
            ..original.context
        });
        contexts.push(RootContext {
            revision: Hash([9; 32]),
            ..original.context
        });
        for substituted in contexts {
            let replacement = StateRootDescriptor::new(substituted, original.root);
            assert_ne!(replacement.commitment(), original.commitment());
            assert_eq!(
                replacement.bind(original.context, replacement.commitment()),
                Err(RootError::ContextMismatch)
            );
        }
    }

    #[test]
    fn root_hash_length_and_empty_state_are_bound_to_expected_commitment() {
        let original = descriptor();
        for root in [
            None,
            Some(BlockRef::new(Hash([7; 32]), 99).unwrap()),
            Some(BlockRef::new(Hash([6; 32]), 98).unwrap()),
        ] {
            let replacement = StateRootDescriptor::new(original.context, root);
            assert_eq!(
                replacement.bind(original.context, original.commitment()),
                Err(RootError::CommitmentMismatch)
            );
        }
        assert_eq!(
            original.bind(original.context, Hash::ZERO),
            Err(RootError::CommitmentMismatch)
        );
    }

    #[test]
    fn malformed_descriptors_fail_before_exposing_a_tree() {
        let original = descriptor().encode();
        for len in 0..original.len() {
            assert!(StateRootDescriptor::decode(&original[..len]).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(StateRootDescriptor::decode(&trailing).is_err());
        for index in [0, 100, 165] {
            let mut bad = original.clone();
            bad[index] = 255;
            assert!(StateRootDescriptor::decode(&bad).is_err());
        }
        for start in [4, 36, 68, 101, 133, 166] {
            let mut bad = original.clone();
            bad[start..start + 32].fill(0);
            assert!(StateRootDescriptor::decode(&bad).is_err());
        }
        for len in [0, u32::MAX] {
            let mut bad = original.clone();
            bad[198..202].copy_from_slice(&len.to_le_bytes());
            assert!(StateRootDescriptor::decode(&bad).is_err());
        }
    }
}
