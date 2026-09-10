use alloc::string::String;
use alloc::vec::Vec;

use crate::authority::AgentAuthorityBinding;
use crate::contract::{ActorPackageContract, RuntimePackageContract};
use crate::proof_system::ProofSystemSet;
use crate::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, InstallationId, NodeId, PrincipalId, ProducerId,
    ProgramId, STANDARD_MAX_ACTORS, SpaceId,
};

pub const MAX_AGENT_REPLICAS: usize = 256;
pub const MAX_ACTOR_NAME_BYTES: usize = 128;
pub const MAX_DIRECTORY_PAGE_ENTRIES: usize = 256;
pub const MAX_STORAGE_PREFIX_BYTES: usize = 128;

/// Exact immutable bytes supplied to an actor constructor on every fresh
/// machine load. `None` and `Some` with an empty byte string are distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationData {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

impl InstallationData {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.reference.hash == Hash::ZERO
            || self.bytes.len() > crate::MAX_INSTALLATION_DATA_BYTES
            || !self.reference.matches(&self.bytes)
        {
            return Err(ModelError::InvalidArtifact);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentProfile {
    Local = 0,
    Shared = 1,
    Private = 2,
}

impl AgentProfile {
    pub const fn supports(self, lane: StateLane) -> bool {
        match self {
            Self::Local | Self::Shared => true,
            Self::Private => matches!(lane, StateLane::Merge | StateLane::Local),
        }
    }

    pub const fn is_published(self) -> bool {
        matches!(self, Self::Shared)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StateLane {
    Linear = 0,
    Merge = 1,
    Local = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
#[repr(u8)]
pub enum InvocationScope {
    Ordered = 0,
    Merge = 1,
    Local = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationResultStorage {
    Control,
    Lane(StateLane),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldPersistence {
    State(StateLane),
    Constant,
    Skipped,
}

/// Physical semantics of one typed actor storage field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StorageKind {
    Value = 0,
    Map = 1,
    Set = 2,
    Vec = 3,
}

/// Canonical storage metadata emitted by actor macros. `prefix` is an
/// immutable namespace, `lane` selects the only replication component which
/// may mutate it, and all key/value commitment semantics are explicit rather
/// than hidden in a codec name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageFieldDescriptor {
    pub field: Hash,
    pub kind: StorageKind,
    pub prefix: Vec<u8>,
    pub lane: StateLane,
    pub committed: bool,
    pub key_schema: Hash,
    pub value_schema: Hash,
    pub commitment_domain: Hash,
}

impl StorageFieldDescriptor {
    /// Derive every commitment-bearing identifier from the actor schema and
    /// declared Rust field/type descriptors. `(Map, committed = true)` is the
    /// canonical representation of `CommittedMap`; replication stays an
    /// independent lane property.
    pub fn derive(
        actor_schema: Hash,
        field_name: &str,
        kind: StorageKind,
        lane: StateLane,
        committed: bool,
        key_type: &[u8],
        value_type: &[u8],
    ) -> Self {
        let field = Hash::digest(
            b"vos/actor/storage-field",
            &[actor_schema.as_bytes(), field_name.as_bytes()],
        );
        Self {
            field,
            kind,
            prefix: Hash::digest(
                b"vos/actor/storage-prefix",
                &[actor_schema.as_bytes(), field.as_bytes()],
            )
            .0
            .to_vec(),
            lane,
            committed,
            key_schema: Hash::digest(b"vos/schema/type", &[key_type]),
            value_schema: Hash::digest(b"vos/schema/type", &[value_type]),
            commitment_domain: Hash::digest(
                b"vos/actor/storage-commitment",
                &[actor_schema.as_bytes(), field.as_bytes()],
            ),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.field == Hash::ZERO
            || self.prefix.is_empty()
            || self.prefix.len() > MAX_STORAGE_PREFIX_BYTES
            || self.key_schema == Hash::ZERO
            || self.value_schema == Hash::ZERO
            || self.commitment_domain == Hash::ZERO
        {
            return Err(ModelError::InvalidActor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MethodMode {
    Query = 0,
    LinearizableQuery = 1,
    LocalQuery = 2,
    Linear = 3,
    Merge = 4,
    Local = 5,
}

impl MethodMode {
    pub const fn write_lane(self) -> Option<StateLane> {
        match self {
            Self::Linear => Some(StateLane::Linear),
            Self::Merge => Some(StateLane::Merge),
            Self::Local => Some(StateLane::Local),
            Self::Query | Self::LinearizableQuery | Self::LocalQuery => None,
        }
    }

    pub const fn result_storage(self) -> InvocationResultStorage {
        match self {
            Self::Query => InvocationResultStorage::Control,
            Self::LinearizableQuery | Self::Linear => {
                InvocationResultStorage::Lane(StateLane::Linear)
            }
            Self::Merge => InvocationResultStorage::Lane(StateLane::Merge),
            Self::LocalQuery | Self::Local => InvocationResultStorage::Lane(StateLane::Local),
        }
    }

    pub const fn invocation_scope(self) -> InvocationScope {
        match self {
            Self::Query | Self::LinearizableQuery | Self::Linear => InvocationScope::Ordered,
            Self::Merge => InvocationScope::Merge,
            Self::LocalQuery | Self::Local => InvocationScope::Local,
        }
    }

    pub const fn can_read(self, lane: StateLane) -> bool {
        match self {
            Self::Query | Self::LinearizableQuery | Self::Linear => {
                matches!(lane, StateLane::Linear | StateLane::Merge)
            }
            Self::LocalQuery | Self::Local => true,
            Self::Merge => matches!(lane, StateLane::Merge),
        }
    }

    pub const fn can_write(self, lane: StateLane) -> bool {
        matches!(
            (self, lane),
            (Self::Linear, StateLane::Linear)
                | (Self::Merge, StateLane::Merge)
                | (Self::Local, StateLane::Local)
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneSet(u8);

impl LaneSet {
    const LINEAR: u8 = 1 << 0;
    const MERGE: u8 = 1 << 1;
    const LOCAL: u8 = 1 << 2;
    const VALID: u8 = Self::LINEAR | Self::MERGE | Self::LOCAL;

    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(Self::VALID);

    pub const fn of(lane: StateLane) -> Self {
        Self(match lane {
            StateLane::Linear => Self::LINEAR,
            StateLane::Merge => Self::MERGE,
            StateLane::Local => Self::LOCAL,
        })
    }

    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::VALID == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, lane: StateLane) -> bool {
        self.0 & Self::of(lane).0 != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn supported_by(self, profile: AgentProfile) -> bool {
        (!self.contains(StateLane::Linear) || profile.supports(StateLane::Linear))
            && (!self.contains(StateLane::Merge) || profile.supports(StateLane::Merge))
            && (!self.contains(StateLane::Local) || profile.supports(StateLane::Local))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplicaRole {
    Voter = 0,
    Observer = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentReplica {
    pub node: NodeId,
    pub principal: PrincipalId,
    pub role: ReplicaRole,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeRequirements {
    pub lanes: LaneSet,
    pub scheduling: bool,
    pub proof_systems: ProofSystemSet,
}

impl RuntimeRequirements {
    pub const fn supported_by(self, profile: AgentProfile) -> bool {
        self.lanes.supported_by(profile)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    pub lanes: LaneSet,
    pub scheduling: bool,
    pub proof_systems: ProofSystemSet,
    pub max_actors: u32,
}

impl RuntimeCapabilities {
    pub const STANDARD_MAX_ACTORS: u32 = STANDARD_MAX_ACTORS;

    pub const fn standard() -> Self {
        Self {
            lanes: LaneSet::ALL,
            scheduling: false,
            proof_systems: ProofSystemSet::EMPTY,
            max_actors: Self::STANDARD_MAX_ACTORS,
        }
    }

    pub fn validate(self) -> Result<(), ModelError> {
        if self.max_actors == 0 || self.max_actors > Self::STANDARD_MAX_ACTORS {
            Err(ModelError::InvalidRuntime)
        } else {
            Ok(())
        }
    }

    pub fn satisfies(self, requirements: RuntimeRequirements) -> bool {
        (requirements.lanes.bits() & !self.lanes.bits()) == 0
            && (!requirements.scheduling || self.scheduling)
            && requirements.proof_systems.is_subset_of(&self.proof_systems)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    Actor {
        contract: ActorPackageContract,
        requirements: RuntimeRequirements,
    },
    AgentRuntime {
        contract: RuntimePackageContract,
        capabilities: RuntimeCapabilities,
    },
}

impl PackageKind {
    pub fn is_compatible_with(
        self,
        runtime_contract: RuntimePackageContract,
        runtime: RuntimeCapabilities,
    ) -> bool {
        match self {
            Self::Actor {
                contract,
                requirements,
            } => runtime_contract.supports(contract) && runtime.satisfies(requirements),
            Self::AgentRuntime { contract, .. } => contract.is_valid(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    pub space: SpaceId,
    pub agent: AgentId,
    pub owner: PrincipalId,
    pub profile: AgentProfile,
    pub runtime_deployment: DeploymentId,
    pub runtime_program: ProgramId,
    pub runtime_producer: ProducerId,
    /// Stable producer identity authorized to sign this Agent's transition
    /// proofs. Unlike `runtime_producer`, runtime upgrades never replace it.
    pub transition_producer: ProducerId,
}

/// Immutable offline-recovery identity selected when a Private agent is
/// created. The signing half is commitment-only; possession is proven only by
/// a domain-separated recovery signature. The independent X25519 public key
/// remains available for sealing epoch data into offline backups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateRecoveryBinding {
    pub signing_key_commitment: Hash,
    pub encryption_public_key: [u8; 32],
}

impl PrivateRecoveryBinding {
    pub fn is_valid(self) -> bool {
        self.signing_key_commitment != Hash::ZERO
            && crate::private::valid_x25519_public_key(&self.encryption_public_key)
    }
}

/// Host-independent immutable creation descriptor. Authority evidence is
/// carried by the enclosing [`crate::RuntimeWork`], never embedded as ambient
/// process policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentDescriptor {
    pub identity: AgentIdentity,
    pub creation_nonce: Hash,
    /// Independently selected system-authority trust anchor. The signed
    /// creation receipt must match this binding; it cannot select its own
    /// policy, issuer, or verification key.
    pub authority: AgentAuthorityBinding,
    /// Present exactly for Private agents and immutable for their lifetime.
    pub private_recovery: Option<PrivateRecoveryBinding>,
    pub runtime_package: BlobRef,
    pub runtime_contract: RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
    pub replicas: Vec<AgentReplica>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    InvalidIdentity,
    InvalidProfile,
    InvalidReplicaSet,
    InvalidRuntime,
    InvalidActor,
    InvalidArtifact,
    InvalidPage,
    LimitExceeded,
}

impl AgentDescriptor {
    /// Initial mutable RRP1 policy fixed by this descriptor's signed ceilings.
    pub const fn initial_resource_policy(&self) -> crate::contract::RuntimeResourcePolicy {
        crate::contract::RuntimeResourcePolicy::initial(
            self.capabilities,
            self.runtime_contract.resources,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.identity.space == SpaceId::ZERO
            || self.identity.agent == AgentId::ZERO
            || self.identity.owner == PrincipalId::ZERO
            || self.creation_nonce == Hash::ZERO
            || AgentId::derive(
                self.identity.space,
                self.identity.owner,
                self.creation_nonce.as_bytes(),
            ) != self.identity.agent
        {
            return Err(ModelError::InvalidIdentity);
        }
        if self.identity.runtime_deployment == DeploymentId::ZERO
            || self.identity.runtime_program == ProgramId::ZERO
            || self.identity.runtime_producer == ProducerId::ZERO
            || self.identity.transition_producer == ProducerId::ZERO
            || self.identity.transition_producer == self.identity.runtime_producer
            || !valid_blob(&self.runtime_package)
            || !self.runtime_contract.is_valid()
            || self.capabilities.max_actors == 0
            || self.capabilities.max_actors > STANDARD_MAX_ACTORS
            || !self.authority.is_valid()
        {
            return Err(ModelError::InvalidRuntime);
        }
        match (self.identity.profile, self.private_recovery) {
            (AgentProfile::Private, Some(binding)) if binding.is_valid() => {}
            (AgentProfile::Private, _) | (_, Some(_)) => return Err(ModelError::InvalidProfile),
            _ => {}
        }
        // Runtime capabilities are a superset declaration. A Private agent
        // may use the standard ALL-lane runtime; admission rejects installed
        // actor requirements that select Linear, not an unused runtime lane.
        if self.replicas.is_empty() || self.replicas.len() > MAX_AGENT_REPLICAS {
            return Err(ModelError::InvalidReplicaSet);
        }
        for replica in &self.replicas {
            if replica.node == NodeId::ZERO || replica.principal == PrincipalId::ZERO {
                return Err(ModelError::InvalidReplicaSet);
            }
        }
        for pair in self.replicas.windows(2) {
            if pair[0].node >= pair[1].node {
                return Err(ModelError::InvalidReplicaSet);
            }
        }
        match self.identity.profile {
            AgentProfile::Local if self.replicas.len() != 1 => {
                return Err(ModelError::InvalidReplicaSet);
            }
            AgentProfile::Shared
                if !self
                    .replicas
                    .iter()
                    .any(|replica| replica.role == ReplicaRole::Voter) =>
            {
                return Err(ModelError::InvalidReplicaSet);
            }
            AgentProfile::Private
                if self.replicas.iter().any(|replica| {
                    replica.role != ReplicaRole::Observer
                        || replica.principal != self.identity.owner
                }) =>
            {
                return Err(ModelError::InvalidReplicaSet);
            }
            _ => {}
        }
        Ok(())
    }

    /// Generation of the complete replica set selected by this descriptor.
    ///
    /// Replica-set changes use this value as their compare-and-replace
    /// predecessor.  It is deliberately scoped by the Agent identity so an
    /// otherwise identical roster cannot be replayed across Agents.
    pub fn replica_generation(&self) -> Hash {
        replica_set_generation(&self.identity, self.creation_nonce, &self.replicas)
    }

    /// Commitment of the complete canonical descriptor, including every
    /// replica principal. Compact authority plans carry this value while the
    /// authority reconstructs the omitted principals from exact enrollments.
    pub fn commitment(&self) -> Hash {
        crate::wire::agent_descriptor_commitment(self)
    }
}

/// Domain-separated commitment of one complete ordered replica roster.
///
/// Compact replica-change plans carry nodes and roles directly; the authority
/// reconstructs each principal from its exact enrollment and compares this
/// commitment before authorizing the full target.
pub fn replica_roster_commitment(replicas: &[AgentReplica]) -> Hash {
    let mut bytes = Vec::with_capacity(4 + replicas.len() * 65);
    bytes.extend_from_slice(&(replicas.len() as u32).to_le_bytes());
    for replica in replicas {
        bytes.extend_from_slice(replica.node.as_bytes());
        bytes.extend_from_slice(replica.principal.as_bytes());
        bytes.push(replica.role as u8);
    }
    Hash::digest(
        b"vos/agent/replica-roster/v1",
        &[crate::RUNTIME_ABI_ID.as_bytes(), &bytes],
    )
}

/// Domain-separated commitment of one canonical replica roster.
///
/// Callers must validate the surrounding descriptor (or the replacement
/// roster) before treating this commitment as an admitted generation.
pub fn replica_set_generation(
    identity: &AgentIdentity,
    creation_nonce: Hash,
    replicas: &[AgentReplica],
) -> Hash {
    let mut bytes = Vec::with_capacity(5 * 32 + 1 + 4 + replicas.len() * 65);
    bytes.extend_from_slice(identity.space.as_bytes());
    bytes.extend_from_slice(identity.agent.as_bytes());
    bytes.extend_from_slice(identity.owner.as_bytes());
    bytes.push(identity.profile as u8);
    bytes.extend_from_slice(identity.transition_producer.as_bytes());
    bytes.extend_from_slice(creation_nonce.as_bytes());
    bytes.extend_from_slice(&(replicas.len() as u32).to_le_bytes());
    for replica in replicas {
        bytes.extend_from_slice(replica.node.as_bytes());
        bytes.extend_from_slice(replica.principal.as_bytes());
        bytes.push(replica.role as u8);
    }
    let mut generation = Hash::digest(b"vos/agent/replica-set-generation/v1", &[&bytes]);
    generation.0[0] |= 0x80;
    generation
}

/// Durable actor descriptor. Top-level actors have `parent = None`; no actor
/// is privileged as an agent root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorEntry {
    pub actor: ActorId,
    pub name: String,
    pub parent: Option<ActorId>,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub method_policy: BlobRef,
    /// Nonzero commitment of the exact signed constructor ABI. This binds
    /// zero-argument, raw-byte, and named typed constructors distinctly.
    pub constructor_abi: Hash,
    /// Exact canonical constructor-argument bytes. The runtime replays this
    /// content-addressed object on every fresh inner-machine load; const fields
    /// are reconstructed by the constructor and are never serialized here.
    pub installation_data: Option<BlobRef>,
    pub state_layout: Hash,
    pub lanes: LaneSet,
    pub suspended: bool,
}

/// Preferred SDK name for an actor-directory entry.
pub type ActorDescriptor = ActorEntry;

impl ActorEntry {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.actor == ActorId::ZERO
            || self.name.is_empty()
            || self.name.len() > MAX_ACTOR_NAME_BYTES
            || self.parent == Some(self.actor)
            || self.deployment == DeploymentId::ZERO
            || self.program == ProgramId::ZERO
            || self.state_layout == Hash::ZERO
            || self.constructor_abi == Hash::ZERO
        {
            return Err(ModelError::InvalidActor);
        }
        if !valid_blob(&self.package)
            || !valid_blob(&self.agent_schema)
            || !valid_blob(&self.method_policy)
            || self
                .installation_data
                .as_ref()
                .is_some_and(|value| !valid_installation_data_blob(value))
        {
            return Err(ModelError::InvalidArtifact);
        }
        Ok(())
    }

    pub fn validate_for_profile(&self, profile: AgentProfile) -> Result<(), ModelError> {
        self.validate()?;
        if !self.lanes.supported_by(profile) {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorDirectoryRecord {
    pub entry: ActorEntry,
    pub incarnation: Hash,
    pub installation_id: InstallationId,
    pub registry_reservation: Hash,
}

impl ActorDirectoryRecord {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.entry.validate()?;
        if self.incarnation == Hash::ZERO
            || self.installation_id == InstallationId::ZERO
            || self.registry_reservation == Hash::ZERO
        {
            return Err(ModelError::InvalidActor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorDirectoryPage {
    pub entries: Vec<ActorDirectoryRecord>,
    /// Cursor to pass as `after` for the next page. Canonically equal to this
    /// page's last ActorId when another page exists.
    pub next: Option<ActorId>,
}

impl ActorDirectoryPage {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.entries.len() > MAX_DIRECTORY_PAGE_ENTRIES {
            return Err(ModelError::LimitExceeded);
        }
        for record in &self.entries {
            record.validate()?;
        }
        for pair in self.entries.windows(2) {
            if pair[0].entry.actor >= pair[1].entry.actor {
                return Err(ModelError::InvalidPage);
            }
        }
        if let Some(next) = self.next {
            if self.entries.last().map(|record| record.entry.actor) != Some(next) {
                return Err(ModelError::InvalidPage);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallActor {
    pub installation_id: InstallationId,
    pub registry_reservation: Hash,
    pub entry: ActorEntry,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub method_policy: BlobRef,
    pub constructor_abi: Hash,
    pub installation_data: Option<InstallationData>,
    pub state_layout: Hash,
    pub contract: ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

impl InstallActor {
    pub fn validate_for_profile(&self, profile: AgentProfile) -> Result<(), ModelError> {
        self.entry.validate_for_profile(profile)?;
        if !self.requirements.supported_by(profile) {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeActor {
    pub actor: ActorId,
    pub from_deployment: DeploymentId,
    pub to_deployment: DeploymentId,
    pub to_program: ProgramId,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub method_policy: BlobRef,
    /// Exact signed target constructor ABI. An in-place upgrade must preserve
    /// this commitment so existing immutable argument bytes retain meaning.
    pub constructor_abi: Hash,
    pub state_layout: Hash,
    pub contract: ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRecord {
    pub entry: ActorEntry,
    pub state_generation: Hash,
    pub installation_id: InstallationId,
    pub registry_reservation: Hash,
    pub install_request_commitment: Hash,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub method_policy: BlobRef,
    pub constructor_abi: Hash,
    pub installation_data: Option<BlobRef>,
    pub state_layout: Hash,
    pub contract: ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActorLifecycleDebt {
    pub children: u32,
    pub continuations: u32,
    pub inbox: u32,
    pub outbox: u32,
    pub schedules: u32,
    pub proof_artifacts: u32,
    pub lifecycle_operations: u32,
}

impl ActorLifecycleDebt {
    pub const fn is_clear(self) -> bool {
        self.children == 0
            && self.continuations == 0
            && self.inbox == 0
            && self.outbox == 0
            && self.schedules == 0
            && self.proof_artifacts == 0
            && self.lifecycle_operations == 0
    }
}

pub(crate) fn valid_blob(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO
        && reference.len != 0
        && reference.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
}

pub(crate) fn valid_installation_data_blob(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO && reference.len <= crate::MAX_INSTALLATION_DATA_BYTES as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_profile_rejects_linear_state() {
        assert!(!AgentProfile::Private.supports(StateLane::Linear));
        assert!(AgentProfile::Private.supports(StateLane::Merge));
        assert!(AgentProfile::Private.supports(StateLane::Local));
    }

    #[test]
    fn method_access_matrix_is_explicit() {
        assert!(MethodMode::Linear.can_read(StateLane::Merge));
        assert!(MethodMode::Linear.can_write(StateLane::Linear));
        assert!(!MethodMode::Linear.can_write(StateLane::Merge));
        assert!(!MethodMode::Merge.can_read(StateLane::Linear));
        assert!(MethodMode::Local.can_read(StateLane::Linear));
        assert!(MethodMode::Local.can_write(StateLane::Local));
        assert!(!MethodMode::Query.can_read(StateLane::Local));
    }

    #[test]
    fn runtime_requirements_are_checked_without_actor_count_coupling() {
        let runtime = RuntimeCapabilities::standard();
        assert!(runtime.satisfies(RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear),
            scheduling: false,
            proof_systems: ProofSystemSet::EMPTY,
        }));
        assert!(!runtime.satisfies(RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: true,
            proof_systems: ProofSystemSet::EMPTY,
        }));

        let proof = Hash([9; 32]);
        let proof_runtime = RuntimeCapabilities {
            proof_systems: ProofSystemSet::from_sorted(&[proof]).unwrap(),
            ..runtime
        };
        assert!(proof_runtime.satisfies(RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: false,
            proof_systems: ProofSystemSet::from_sorted(&[proof]).unwrap(),
        }));
        assert!(!runtime.satisfies(RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: false,
            proof_systems: ProofSystemSet::from_sorted(&[proof]).unwrap(),
        }));
        assert_eq!(runtime.validate(), Ok(()));
        assert_eq!(
            RuntimeCapabilities {
                max_actors: 0,
                ..runtime
            }
            .validate(),
            Err(ModelError::InvalidRuntime)
        );
    }

    #[test]
    fn standard_runtime_can_host_private_but_linear_actor_cannot() {
        let space = SpaceId([1; 32]);
        let owner = PrincipalId([2; 32]);
        let creation_nonce = Hash([3; 32]);
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, creation_nonce.as_bytes()),
                owner,
                profile: AgentProfile::Private,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
                transition_producer: ProducerId([0x26; 32]),
            },
            creation_nonce,
            authority: crate::authority::AgentAuthorityBinding {
                policy: Hash([9; 32]),
                issuer: crate::authority::AuthorityIssuer {
                    principal: PrincipalId([10; 32]),
                    actor: ActorId([11; 32]),
                    deployment: DeploymentId([12; 32]),
                    program: ProgramId([13; 32]),
                    producer: ProducerId::of_public_key(&[14; 32]),
                },
                public_key: [14; 32],
                initial_epoch: 1,
            },
            private_recovery: Some(PrivateRecoveryBinding {
                signing_key_commitment: Hash([15; 32]),
                encryption_public_key: [16; 32],
            }),
            runtime_package: BlobRef {
                hash: Hash([7; 32]),
                len: 1,
            },
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: alloc::vec![AgentReplica {
                node: NodeId([8; 32]),
                principal: owner,
                role: ReplicaRole::Observer,
            }],
        };

        assert!(descriptor.capabilities.lanes.contains(StateLane::Linear));
        assert_eq!(descriptor.validate(), Ok(()));
        let mut missing_recovery = descriptor.clone();
        missing_recovery.private_recovery = None;
        assert_eq!(missing_recovery.validate(), Err(ModelError::InvalidProfile));
        let mut invalid_recovery = descriptor.clone();
        invalid_recovery
            .private_recovery
            .as_mut()
            .unwrap()
            .encryption_public_key = [0; 32];
        assert_eq!(invalid_recovery.validate(), Err(ModelError::InvalidProfile));
        let generation = descriptor.replica_generation();
        let commitment = descriptor.commitment();
        let mut changed = descriptor.clone();
        changed.identity.transition_producer = ProducerId([0x27; 32]);
        assert_ne!(changed.commitment(), commitment);
        assert_ne!(changed.replica_generation(), generation);
        let mut missing_transition_producer = descriptor.clone();
        missing_transition_producer.identity.transition_producer = ProducerId::ZERO;
        assert_eq!(
            missing_transition_producer.validate(),
            Err(ModelError::InvalidRuntime)
        );
        let mut reused_runtime_producer = descriptor.clone();
        reused_runtime_producer.identity.transition_producer =
            reused_runtime_producer.identity.runtime_producer;
        assert_eq!(
            reused_runtime_producer.validate(),
            Err(ModelError::InvalidRuntime)
        );
        let mut changed = descriptor.clone();
        changed.replicas[0].node = NodeId([15; 32]);
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.replicas[0].principal = PrincipalId([16; 32]);
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.replicas[0].role = ReplicaRole::Voter;
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.identity.space = SpaceId([17; 32]);
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.identity.agent = AgentId([18; 32]);
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.identity.owner = PrincipalId([19; 32]);
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.identity.profile = AgentProfile::Shared;
        assert_ne!(changed.replica_generation(), generation);
        let mut changed = descriptor.clone();
        changed.creation_nonce = Hash([20; 32]);
        assert_ne!(changed.replica_generation(), generation);
        let mut runtime_changed = descriptor.clone();
        runtime_changed.identity.runtime_deployment = DeploymentId([21; 32]);
        runtime_changed.identity.runtime_program = ProgramId([22; 32]);
        runtime_changed.identity.runtime_producer = ProducerId([23; 32]);
        assert_eq!(
            runtime_changed.replica_generation(),
            generation,
            "runtime upgrades must not silently advance the replica generation"
        );
        let mut unanchored = descriptor.clone();
        unanchored.authority.policy = Hash::ZERO;
        assert_eq!(unanchored.validate(), Err(ModelError::InvalidRuntime));
        assert!(
            !RuntimeRequirements {
                lanes: LaneSet::of(StateLane::Linear),
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
            }
            .supported_by(AgentProfile::Private)
        );
    }
}
