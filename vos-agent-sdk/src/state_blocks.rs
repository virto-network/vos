//! Experimental authenticated state-block fetch contract, not an r19 wire ABI.
//!
//! A verified block is NOT evidence that it belongs to an authoritative root.
//! The runtime must traverse authenticated child references from its pinned
//! root and enforce actor namespace access. Missing blocks are unavailable,
//! never authenticated absence. The experimental `state_tree` module supplies
//! traversal and staged copy-on-write updates; durable publication remains an
//! unimplemented integration boundary; journal-backed block staging alone does
//! not publish or pin a root.

use crate::{AgentId, BlobRef, Hash, SpaceId, StateLane};
use alloc::vec::Vec;

/// Candidate physical block ceiling, not a limit on retained state. Values
/// larger than a block use authenticated chunk references in the tree format.
pub const MAX_STATE_BLOCK_BYTES: usize = 64 * 1024;
/// Public storage envelope: magic, scope, and exact payload length. References
/// name the ordinary VOS blob of this envelope, so persistence needs no second
/// hash index or exception to its existing content verification.
pub const STATE_BLOCK_ENVELOPE_HEADER: usize = 4 + 32 + 32 + 32 + 1 + 4;
pub const MAX_STATE_BLOCK_ENVELOPE_BYTES: usize =
    STATE_BLOCK_ENVELOPE_HEADER + MAX_STATE_BLOCK_BYTES;
/// Experimental outer-PVM fetch: r7=hash pointer, r8=byte length,
/// r9=output pointer, r10=exact capacity, r11=declared StateLane selector.
/// Success sets r7=0, r8=length. Selectors are explicit in experimental ABI 002;
/// ABI 001 guests/packages are incompatible and must not be silently reinterpreted.
/// Unavailability is an execution failure, not a key-absence response.
/// Not admitted by the released r19 runner.
// Keep the prototype ID within a signed 12-bit immediate: the current RISC-V
// translator recognizes an explicit `li t0, N` for static host-call IDs.
pub const STATE_BLOCK_FETCH_CALL: u32 = 0x180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    InvalidScope,
    InvalidReference,
    InvalidLength,
    BudgetExceeded,
    Unavailable,
    HashMismatch,
}

/// Storage scope, distinct from a mutable head or runtime deployment. The
/// generation is a durable storage identity; a new revision does not change it.
/// Authority for selecting this scope remains the enclosing execution contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockScope {
    space: SpaceId,
    agent: AgentId,
    generation: Hash,
    lane: StateLane,
}

impl BlockScope {
    pub const fn space(self) -> SpaceId {
        self.space
    }
    pub const fn agent(self) -> AgentId {
        self.agent
    }
    pub const fn generation(self) -> Hash {
        self.generation
    }
    pub const fn lane(self) -> StateLane {
        self.lane
    }

    pub fn new(
        space: SpaceId,
        agent: AgentId,
        generation: Hash,
        lane: StateLane,
    ) -> Result<Self, BlockError> {
        if space == SpaceId::ZERO || agent == AgentId::ZERO || generation == Hash::ZERO {
            return Err(BlockError::InvalidScope);
        }
        Ok(Self {
            space,
            agent,
            generation,
            lane,
        })
    }

    /// Commit exact bounded bytes with fixed-width scope and length framing.
    /// This accepts opaque blocks: their canonical tree shape is checked by
    /// the runtime, not by the generic byte provider.
    pub fn reference(self, bytes: &[u8]) -> Result<BlockRef, BlockError> {
        let len = u32::try_from(bytes.len()).map_err(|_| BlockError::InvalidLength)?;
        if len == 0 || bytes.len() > MAX_STATE_BLOCK_BYTES {
            return Err(BlockError::InvalidLength);
        }
        let hash = Hash::digest(b"vos/blob", &[&self.envelope_header(len), bytes]);
        BlockRef::new(hash, len)
    }

    fn envelope_header(self, len: u32) -> [u8; STATE_BLOCK_ENVELOPE_HEADER] {
        let mut header = [0; STATE_BLOCK_ENVELOPE_HEADER];
        header[..4].copy_from_slice(b"VSB2");
        header[4..36].copy_from_slice(self.space.as_bytes());
        header[36..68].copy_from_slice(self.agent.as_bytes());
        header[68..100].copy_from_slice(self.generation.as_bytes());
        header[100] = self.lane as u8;
        header[101..105].copy_from_slice(&len.to_le_bytes());
        header
    }

    /// Encode a scoped payload for the journal's immutable blob store. This
    /// stages bytes only; it says nothing about root authority or availability.
    pub fn encode_block(self, bytes: &[u8]) -> Result<(BlockRef, Vec<u8>), BlockError> {
        let reference = self.reference(bytes)?;
        let mut envelope = Vec::with_capacity(STATE_BLOCK_ENVELOPE_HEADER + bytes.len());
        envelope.extend_from_slice(&self.envelope_header(reference.byte_len()));
        envelope.extend_from_slice(bytes);
        Ok((reference, envelope))
    }

    /// Verify exact scope/length/content and borrow the payload without a copy.
    /// The caller supplies the admitted scope; the envelope cannot select it.
    pub fn decode_block(self, reference: BlockRef, envelope: &[u8]) -> Result<&[u8], BlockError> {
        if envelope.len() != STATE_BLOCK_ENVELOPE_HEADER + reference.byte_len() as usize {
            return Err(BlockError::InvalidLength);
        }
        if envelope[..STATE_BLOCK_ENVELOPE_HEADER] != self.envelope_header(reference.byte_len()) {
            return Err(BlockError::InvalidScope);
        }
        let payload = &envelope[STATE_BLOCK_ENVELOPE_HEADER..];
        if self.reference(payload)? != reference {
            return Err(BlockError::HashMismatch);
        }
        Ok(payload)
    }
}

/// Untrusted references must be validated before allocating a read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    hash: Hash,
    len: u32,
}

impl BlockRef {
    pub fn new(hash: Hash, len: u32) -> Result<Self, BlockError> {
        if hash == Hash::ZERO || len == 0 || len as usize > MAX_STATE_BLOCK_BYTES {
            return Err(BlockError::InvalidReference);
        }
        Ok(Self { hash, len })
    }

    pub const fn hash(self) -> Hash {
        self.hash
    }
    pub const fn byte_len(self) -> u32 {
        self.len
    }

    /// Exact journal blob identity, including the public scope envelope.
    pub fn storage_reference(self) -> BlobRef {
        BlobRef {
            hash: self.hash,
            len: u64::from(self.len) + STATE_BLOCK_ENVELOPE_HEADER as u64,
        }
    }
}

/// Per-operation read budget. All attempted fetches, including cache hits,
/// unavailable blocks and invalid responses, consume their declared allowance.
/// This is not the complete execution budget: gas, writes and resident memory
/// must be independently bounded by the eventual execution adapter.
#[derive(Debug)]
pub struct ReadBudget {
    remaining_fetches: u32,
    remaining_bytes: u64,
}

impl ReadBudget {
    pub const fn new(fetches: u32, bytes: u64) -> Self {
        Self {
            remaining_fetches: fetches,
            remaining_bytes: bytes,
        }
    }

    pub const fn remaining(&self) -> (u32, u64) {
        (self.remaining_fetches, self.remaining_bytes)
    }

    /// Call BEFORE fetching/allocating. The provider must cap its read to
    /// `reference.byte_len()`; an oversized response is rejected before hashing.
    pub fn begin_fetch(
        &mut self,
        scope: BlockScope,
        reference: BlockRef,
    ) -> Result<FetchPermit, BlockError> {
        if self.remaining_fetches == 0 || self.remaining_bytes < u64::from(reference.len) {
            return Err(BlockError::BudgetExceeded);
        }
        self.remaining_fetches -= 1;
        self.remaining_bytes -= u64::from(reference.len);
        Ok(FetchPermit { scope, reference })
    }
}

/// A single charged verification attempt. Deliberately not Clone or Copy.
#[derive(Debug)]
#[must_use]
pub struct FetchPermit {
    scope: BlockScope,
    reference: BlockRef,
}

impl FetchPermit {
    pub fn verify(self, bytes: Option<&[u8]>) -> Result<&[u8], BlockError> {
        let bytes = bytes.ok_or(BlockError::Unavailable)?;
        if bytes.len() != self.reference.len as usize {
            return Err(BlockError::InvalidLength);
        }
        if self.scope.reference(bytes)? != self.reference {
            return Err(BlockError::HashMismatch);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> BlockScope {
        BlockScope::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap()
    }

    #[test]
    fn exact_bytes_verify_but_corruption_and_substitution_do_not() {
        let scope = scope();
        let reference = scope.reference(b"first").unwrap();
        let mut budget = ReadBudget::new(3, 15);
        assert_eq!(
            budget
                .begin_fetch(scope, reference)
                .unwrap()
                .verify(Some(b"first")),
            Ok(&b"first"[..])
        );
        assert_eq!(
            budget
                .begin_fetch(scope, reference)
                .unwrap()
                .verify(Some(b"other")),
            Err(BlockError::HashMismatch)
        );
        assert_eq!(
            budget
                .begin_fetch(scope, reference)
                .unwrap()
                .verify(Some(b"longer")),
            Err(BlockError::InvalidLength)
        );
        assert_eq!(budget.remaining(), (0, 0));
    }

    #[test]
    fn storage_envelope_uses_exact_journal_blob_hash_and_borrows_payload() {
        for len in [1, MAX_STATE_BLOCK_BYTES] {
            let bytes = alloc::vec![7; len];
            let (reference, envelope) = scope().encode_block(&bytes).unwrap();
            assert_eq!(reference.storage_reference(), BlobRef::of_bytes(&envelope));
            let payload = scope().decode_block(reference, &envelope).unwrap();
            assert_eq!(payload, bytes);
            assert_eq!(
                payload.as_ptr(),
                envelope[STATE_BLOCK_ENVELOPE_HEADER..].as_ptr()
            );
            for offset in [0, 4, 36, 68, 100, 101, STATE_BLOCK_ENVELOPE_HEADER] {
                let mut corrupt = envelope.clone();
                corrupt[offset] ^= 1;
                assert!(scope().decode_block(reference, &corrupt).is_err());
            }
            assert!(
                scope()
                    .decode_block(reference, &envelope[..envelope.len() - 1])
                    .is_err()
            );
            let mut trailing = envelope;
            trailing.push(0);
            assert!(scope().decode_block(reference, &trailing).is_err());
        }
    }

    #[test]
    fn scope_binds_space_agent_generation_and_lane() {
        let original = scope();
        let reference = original.reference(b"data").unwrap();
        let substitutions = [
            BlockScope {
                space: SpaceId([4; 32]),
                ..original
            },
            BlockScope {
                agent: AgentId([4; 32]),
                ..original
            },
            BlockScope {
                generation: Hash([4; 32]),
                ..original
            },
            BlockScope {
                lane: StateLane::Merge,
                ..original
            },
            BlockScope {
                lane: StateLane::Local,
                ..original
            },
        ];
        let mut budget = ReadBudget::new(5, 20);
        for substituted in substitutions {
            assert_eq!(
                budget
                    .begin_fetch(substituted, reference)
                    .unwrap()
                    .verify(Some(b"data")),
                Err(BlockError::HashMismatch)
            );
        }
    }

    #[test]
    fn unavailable_is_not_absence_and_failed_reads_are_charged() {
        let scope = scope();
        let reference = scope.reference(b"data").unwrap();
        let mut budget = ReadBudget::new(1, 4);
        assert_eq!(
            budget.begin_fetch(scope, reference).unwrap().verify(None),
            Err(BlockError::Unavailable)
        );
        assert_eq!(budget.remaining(), (0, 0));
        assert!(matches!(
            budget.begin_fetch(scope, reference),
            Err(BlockError::BudgetExceeded)
        ));
    }

    #[test]
    fn exhausted_byte_or_fetch_budget_refuses_without_partial_charge() {
        let scope = scope();
        let reference = scope.reference(b"data").unwrap();
        for (fetches, bytes) in [(0, 4), (1, 3), (u32::MAX, 0)] {
            let mut budget = ReadBudget::new(fetches, bytes);
            assert!(matches!(
                budget.begin_fetch(scope, reference),
                Err(BlockError::BudgetExceeded)
            ));
            assert_eq!(budget.remaining(), (fetches, bytes));
        }
    }

    #[test]
    fn references_and_scopes_reject_invalid_bounds() {
        let scope = scope();
        assert_eq!(scope.reference(&[]), Err(BlockError::InvalidLength));
        assert_eq!(
            scope.reference(&alloc::vec![0; MAX_STATE_BLOCK_BYTES + 1]),
            Err(BlockError::InvalidLength)
        );
        let maximum = alloc::vec![0; MAX_STATE_BLOCK_BYTES];
        let reference = scope.reference(&maximum).unwrap();
        assert_eq!(reference.byte_len() as usize, MAX_STATE_BLOCK_BYTES);
        assert_ne!(reference.hash(), Hash::ZERO);
        let mut budget = ReadBudget::new(1, MAX_STATE_BLOCK_BYTES as u64);
        assert_eq!(
            budget
                .begin_fetch(scope, reference)
                .unwrap()
                .verify(Some(&maximum))
                .unwrap(),
            maximum
        );
        for (hash, len) in [
            (Hash::ZERO, 1),
            (Hash([1; 32]), 0),
            (Hash([1; 32]), u32::MAX),
        ] {
            assert_eq!(BlockRef::new(hash, len), Err(BlockError::InvalidReference));
        }
        assert_eq!(
            BlockScope::new(
                SpaceId::ZERO,
                AgentId([2; 32]),
                Hash([3; 32]),
                StateLane::Linear
            ),
            Err(BlockError::InvalidScope)
        );
        assert_eq!(
            BlockScope::new(
                SpaceId([1; 32]),
                AgentId::ZERO,
                Hash([3; 32]),
                StateLane::Linear
            ),
            Err(BlockError::InvalidScope)
        );
        assert_eq!(
            BlockScope::new(
                SpaceId([1; 32]),
                AgentId([2; 32]),
                Hash::ZERO,
                StateLane::Linear
            ),
            Err(BlockError::InvalidScope)
        );
    }
}
