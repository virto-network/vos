//! Canonical Task dependency-set artifacts for AgentActor packages.
//!
//! Every row binds the exact standard-PVM artifact, its canonical ProgramId,
//! the witness-memory window, and an optional proof-system requirement. The
//! TaskId is derived from that complete descriptor rather than chosen by a
//! producer.

use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::wire::{CanonicalWire, WireError};
use crate::{
    BlobRef, Hash, MAX_CATALOG_ARTIFACT_BYTES, ProgramId, ProofSystemSet, ProofSystemSetError,
    RUNTIME_ABI_ID,
};

pub const TASK_DEPENDENCY_SET_MAGIC: [u8; 4] = *b"ATD1";
pub const TASK_ID_DOMAIN: &[u8] = b"vos/agent/task-dependency/v1";
pub const MAX_TASK_DEPENDENCIES: usize = 16;
pub const MAX_TASK_DEPENDENCY_SET_BYTES: usize =
    4 + 32 + 4 + MAX_TASK_DEPENDENCIES * (32 + 40 + 32 + 4 + 4 + 1 + 32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub [u8; 32]);

impl TaskId {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskProofRequirement {
    None,
    Required { proof_system: Hash },
}

impl TaskProofRequirement {
    fn validate(self) -> bool {
        match self {
            Self::None => true,
            Self::Required { proof_system } => proof_system != Hash::ZERO,
        }
    }

    pub const fn proof_system(self) -> Option<Hash> {
        match self {
            Self::None => None,
            Self::Required { proof_system } => Some(proof_system),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskDependency {
    /// Must equal [`Self::derived_task_id`].
    pub task: TaskId,
    /// Exact canonical standard-PVM bytes for this Task.
    pub artifact: BlobRef,
    pub program: ProgramId,
    pub witness_address: u32,
    pub witness_capacity: u32,
    pub proof: TaskProofRequirement,
}

impl TaskDependency {
    pub fn new(
        artifact: BlobRef,
        program: ProgramId,
        witness_address: u32,
        witness_capacity: u32,
        proof: TaskProofRequirement,
    ) -> Result<Self, TaskDependencyError> {
        let mut value = Self {
            task: TaskId::ZERO,
            artifact,
            program,
            witness_address,
            witness_capacity,
            proof,
        };
        value.task = value.derived_task_id()?;
        value.validate()?;
        Ok(value)
    }

    /// Derive identity from the full canonical descriptor, excluding only the
    /// derived TaskId itself.
    pub fn derived_task_id(&self) -> Result<TaskId, TaskDependencyError> {
        self.validate_descriptor()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(40 + 32 + 4 + 4 + 1 + 32)
            .map_err(|_| TaskDependencyError::LimitExceeded)?;
        encode_descriptor(&mut Encoder(&mut bytes), self);
        let identity = TaskId(
            Hash::digest(
                TASK_ID_DOMAIN,
                &[RUNTIME_ABI_ID.as_bytes(), bytes.as_slice()],
            )
            .0,
        );
        if identity == TaskId::ZERO {
            Err(TaskDependencyError::InvalidTask)
        } else {
            Ok(identity)
        }
    }

    pub fn validate(&self) -> Result<(), TaskDependencyError> {
        self.validate_descriptor()?;
        if self.task == TaskId::ZERO || self.task != self.derived_task_id()? {
            return Err(TaskDependencyError::InvalidTask);
        }
        Ok(())
    }

    fn validate_descriptor(&self) -> Result<(), TaskDependencyError> {
        if self.artifact.hash == Hash::ZERO
            || self.artifact.len == 0
            || self.artifact.len > MAX_CATALOG_ARTIFACT_BYTES
            || self.program == ProgramId::ZERO
            || self.witness_address == 0
            || self.witness_capacity == 0
            || self
                .witness_address
                .checked_add(self.witness_capacity)
                .is_none()
            || !self.proof.validate()
        {
            return Err(TaskDependencyError::InvalidDescriptor);
        }
        Ok(())
    }

    /// Verify the exact dependency bytes and canonical ProgramId derivation.
    pub fn validate_pvm_bytes(&self, bytes: &[u8]) -> Result<(), TaskDependencyError> {
        self.validate()?;
        if !self.artifact.matches(bytes) || ProgramId::of_pvm(bytes) != self.program {
            return Err(TaskDependencyError::ArtifactMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskDependencySetArtifact {
    /// Strict TaskId order with no duplicate identities.
    pub dependencies: Vec<TaskDependency>,
}

impl TaskDependencySetArtifact {
    pub fn validate(&self) -> Result<(), TaskDependencyError> {
        if self.dependencies.len() > MAX_TASK_DEPENDENCIES {
            return Err(TaskDependencyError::LimitExceeded);
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        if self
            .dependencies
            .windows(2)
            .any(|pair| pair[0].task >= pair[1].task)
        {
            return Err(TaskDependencyError::NonCanonicalOrder);
        }
        Ok(())
    }

    pub fn dependency(&self, task: TaskId) -> Option<&TaskDependency> {
        self.dependencies
            .binary_search_by_key(&task, |dependency| dependency.task)
            .ok()
            .and_then(|position| self.dependencies.get(position))
    }

    pub fn proof_systems(&self) -> Result<ProofSystemSet, TaskDependencyError> {
        self.validate()?;
        let mut systems = ProofSystemSet::EMPTY;
        for dependency in &self.dependencies {
            if let Some(system) = dependency.proof.proof_system() {
                systems.insert(system)?;
            }
        }
        Ok(systems)
    }

    pub fn artifact_ref(&self) -> Result<BlobRef, WireError> {
        Ok(BlobRef::of_bytes(&self.encode()?))
    }
}

impl CanonicalWire for TaskDependencySetArtifact {
    const MAGIC: [u8; 4] = TASK_DEPENDENCY_SET_MAGIC;
    const MAX_ENCODED_BYTES: usize = MAX_TASK_DEPENDENCY_SET_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.list(&self.dependencies, encode_dependency);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            dependencies: decoder.list_bounded(MAX_TASK_DEPENDENCIES, decode_dependency)?,
        };
        value.validate().map_err(|error| match error {
            TaskDependencyError::LimitExceeded => DecodeError::LimitExceeded,
            _ => DecodeError::NonCanonical,
        })?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskDependencyError {
    InvalidTask,
    InvalidDescriptor,
    NonCanonicalOrder,
    ArtifactMismatch,
    LimitExceeded,
}

impl fmt::Display for TaskDependencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTask => formatter.write_str("invalid derived Task identity"),
            Self::InvalidDescriptor => formatter.write_str("invalid Task dependency descriptor"),
            Self::NonCanonicalOrder => formatter.write_str("noncanonical Task dependency order"),
            Self::ArtifactMismatch => formatter.write_str("Task PVM content mismatch"),
            Self::LimitExceeded => formatter.write_str("Task dependency limit exceeded"),
        }
    }
}

impl core::error::Error for TaskDependencyError {}

impl From<ProofSystemSetError> for TaskDependencyError {
    fn from(_: ProofSystemSetError) -> Self {
        Self::LimitExceeded
    }
}

fn encode_descriptor(encoder: &mut Encoder<'_>, value: &TaskDependency) {
    encoder.fixed(value.artifact.hash.as_bytes());
    encoder.u64(value.artifact.len);
    encoder.fixed(value.program.as_bytes());
    encoder.u32(value.witness_address);
    encoder.u32(value.witness_capacity);
    match value.proof {
        TaskProofRequirement::None => encoder.u8(0),
        TaskProofRequirement::Required { proof_system } => {
            encoder.u8(1);
            encoder.fixed(proof_system.as_bytes());
        }
    }
}

fn encode_dependency(encoder: &mut Encoder<'_>, value: &TaskDependency) {
    encoder.0.extend_from_slice(value.task.as_bytes());
    encode_descriptor(encoder, value);
}

fn decode_dependency(decoder: &mut Decoder<'_>) -> Result<TaskDependency, DecodeError> {
    let task = TaskId(
        decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    );
    let artifact = BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    };
    let program = ProgramId(decoder.fixed()?);
    let witness_address = decoder.u32()?;
    let witness_capacity = decoder.u32()?;
    let proof = match decoder.u8()? {
        0 => TaskProofRequirement::None,
        1 => TaskProofRequirement::Required {
            proof_system: Hash(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    let value = TaskDependency {
        task,
        artifact,
        program,
        witness_address,
        witness_capacity,
        proof,
    };
    value.validate().map_err(|_| DecodeError::NonCanonical)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn dependency(bytes: &[u8], address: u32, proof: TaskProofRequirement) -> TaskDependency {
        TaskDependency::new(
            BlobRef::of_bytes(bytes),
            ProgramId::of_pvm(bytes),
            address,
            64,
            proof,
        )
        .unwrap()
    }

    fn set(mut dependencies: Vec<TaskDependency>) -> TaskDependencySetArtifact {
        dependencies.sort_unstable_by_key(|dependency| dependency.task);
        TaskDependencySetArtifact { dependencies }
    }

    #[test]
    fn canonical_round_trip_and_pvm_binding() {
        let artifact = set(vec![
            dependency(b"task-a", 64, TaskProofRequirement::None),
            dependency(
                b"task-b",
                128,
                TaskProofRequirement::Required {
                    proof_system: Hash([7; 32]),
                },
            ),
        ]);
        artifact.validate().unwrap();
        let encoded = artifact.encode().unwrap();
        assert_eq!(
            TaskDependencySetArtifact::decode(&encoded).unwrap(),
            artifact
        );
        assert_eq!(
            artifact.artifact_ref().unwrap(),
            BlobRef::of_bytes(&encoded)
        );
        artifact.dependencies[0]
            .validate_pvm_bytes(if artifact.dependencies[0].artifact.matches(b"task-a") {
                b"task-a"
            } else {
                b"task-b"
            })
            .unwrap();
        assert_eq!(
            artifact.dependencies[0].validate_pvm_bytes(b"tampered"),
            Err(TaskDependencyError::ArtifactMismatch)
        );
    }

    #[test]
    fn task_identity_is_sensitive_to_every_descriptor_field() {
        let original = dependency(
            b"task",
            32,
            TaskProofRequirement::Required {
                proof_system: Hash([1; 32]),
            },
        );
        let mut variants = vec![original.clone(); 5];
        variants[0].artifact = BlobRef::of_bytes(b"other-task");
        variants[0].program = ProgramId::of_pvm(b"other-task");
        variants[1].program = ProgramId([2; 32]);
        variants[2].witness_address += 1;
        variants[3].witness_capacity += 1;
        variants[4].proof = TaskProofRequirement::Required {
            proof_system: Hash([3; 32]),
        };
        for variant in variants {
            assert_ne!(variant.derived_task_id().unwrap(), original.task);
            assert_eq!(variant.validate(), Err(TaskDependencyError::InvalidTask));
        }
    }

    #[test]
    fn descriptor_rejects_overflow_zero_and_wrong_program_or_ref() {
        let mut overflow = dependency(b"task", 1, TaskProofRequirement::None);
        overflow.witness_address = u32::MAX;
        overflow.witness_capacity = 2;
        assert_eq!(
            overflow.derived_task_id(),
            Err(TaskDependencyError::InvalidDescriptor)
        );

        let mut zero_capacity = dependency(b"task", 1, TaskProofRequirement::None);
        zero_capacity.witness_capacity = 0;
        assert_eq!(
            zero_capacity.derived_task_id(),
            Err(TaskDependencyError::InvalidDescriptor)
        );

        let mut zero_address = dependency(b"task", 1, TaskProofRequirement::None);
        zero_address.witness_address = 0;
        assert_eq!(
            zero_address.derived_task_id(),
            Err(TaskDependencyError::InvalidDescriptor)
        );

        let mut zero_proof = dependency(b"task", 1, TaskProofRequirement::None);
        zero_proof.proof = TaskProofRequirement::Required {
            proof_system: Hash::ZERO,
        };
        assert_eq!(
            zero_proof.derived_task_id(),
            Err(TaskDependencyError::InvalidDescriptor)
        );

        let mut wrong_program = dependency(b"task", 1, TaskProofRequirement::None);
        wrong_program.program = ProgramId([9; 32]);
        wrong_program.task = wrong_program.derived_task_id().unwrap();
        assert_eq!(
            wrong_program.validate_pvm_bytes(b"task"),
            Err(TaskDependencyError::ArtifactMismatch)
        );

        let mut wrong_ref = dependency(b"task", 1, TaskProofRequirement::None);
        wrong_ref.artifact.len += 1;
        wrong_ref.task = wrong_ref.derived_task_id().unwrap();
        assert_eq!(
            wrong_ref.validate_pvm_bytes(b"task"),
            Err(TaskDependencyError::ArtifactMismatch)
        );
    }

    #[test]
    fn rejects_duplicates_order_count_unknown_tag_and_trailing_bytes() {
        let first = dependency(b"first", 1, TaskProofRequirement::None);
        let second = dependency(b"second", 2, TaskProofRequirement::None);
        let canonical = set(vec![first.clone(), second.clone()]);

        let mut reversed = canonical.clone();
        reversed.dependencies.reverse();
        assert_eq!(
            reversed.validate(),
            Err(TaskDependencyError::NonCanonicalOrder)
        );
        let duplicate = TaskDependencySetArtifact {
            dependencies: vec![first.clone(), first],
        };
        assert_eq!(
            duplicate.validate(),
            Err(TaskDependencyError::NonCanonicalOrder)
        );

        let empty = TaskDependencySetArtifact {
            dependencies: Vec::new(),
        }
        .encode()
        .unwrap();
        let count = 4 + 32;
        let mut oversized = empty.clone();
        oversized[count..count + 4]
            .copy_from_slice(&((MAX_TASK_DEPENDENCIES + 1) as u32).to_le_bytes());
        assert_eq!(
            TaskDependencySetArtifact::decode(&oversized),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        );

        let mut unknown = canonical.encode().unwrap();
        let first_proof_tag = 4 + 32 + 4 + 32 + 40 + 32 + 4 + 4;
        unknown[first_proof_tag] = 9;
        assert_eq!(
            TaskDependencySetArtifact::decode(&unknown),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );

        let mut trailing = canonical.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            TaskDependencySetArtifact::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );

        let mut previous_generation = canonical.encode().unwrap();
        previous_generation[..4].copy_from_slice(b"ATD0");
        assert_eq!(
            TaskDependencySetArtifact::decode(&previous_generation),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );

        let mut wrong_abi = canonical.encode().unwrap();
        wrong_abi[4] ^= 1;
        assert_eq!(
            TaskDependencySetArtifact::decode(&wrong_abi),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );

        let too_many = TaskDependencySetArtifact {
            dependencies: vec![second; MAX_TASK_DEPENDENCIES + 1],
        };
        assert_eq!(too_many.validate(), Err(TaskDependencyError::LimitExceeded));
    }
}
