//! Agent programming model.
//!
//! An agent is a durable runtime instance inside a space. It owns zero or
//! more actors and has one immutable storage/replication profile. Actor fields
//! select state lanes; methods select the lane they may mutate.

use alloc::string::String;
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

pub use crate::actors::tasks::{Child, TaskId, TaskRecord, TaskStatus, Tasks};
#[cfg(feature = "std")]
pub mod driver;
#[cfg(feature = "pvm")]
pub mod machine;
pub mod package;
pub mod standard;
pub mod wire;
use crate::service::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, NodeId, PrincipalId, ProducerId, ProgramId,
    SpaceId,
};

/// Stable lifecycle contract implemented by every agent runtime.
pub const RUNTIME_ABI_ID: Hash = Hash(*b"vos-agent-runtime-abi-20260829!!");

/// Program identity of the bundled standard runtime artifact.
pub const STANDARD_RUNTIME_PROGRAM_ID: ProgramId = ProgramId([
    0x85, 0x39, 0x98, 0x96, 0xb8, 0x89, 0xb3, 0x1c, 0xbc, 0xaf, 0x0d, 0x5e, 0x92, 0x06, 0x10, 0x6e,
    0x1a, 0xbf, 0xde, 0x8e, 0xfa, 0xcd, 0x98, 0xaa, 0x30, 0x18, 0x0f, 0x87, 0x05, 0x85, 0x84, 0xcd,
]);

/// Immutable storage and publication profile of an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentProfile {
    /// One node. Linear and node-local state are available; no network
    /// replication is configured.
    Local = 0,
    /// Published to the space. Linear state uses consensus, merge state uses
    /// causal replication, and local state remains per replica.
    Shared = 1,
    /// Unpublished, owner-node-only causal replication. Linear state is not
    /// available in the initial private profile.
    Private = 2,
}

impl AgentProfile {
    pub const fn supports(self, lane: StateLane) -> bool {
        match self {
            Self::Local => true,
            Self::Shared => true,
            Self::Private => matches!(lane, StateLane::Merge | StateLane::Local),
        }
    }

    pub const fn is_published(self) -> bool {
        matches!(self, Self::Shared)
    }
}

/// A durable state lane selected by an actor field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StateLane {
    /// Totally ordered state. Plain persisted fields use this lane.
    Linear = 0,
    /// Causally replicated, convergent state. `crdt::*` fields use this lane.
    Merge = 1,
    /// Per-replica state which is never synchronized.
    Local = 2,
}

/// Complete persistence classification of an actor field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldPersistence {
    State(StateLane),
    /// Immutable configuration committed at actor installation.
    Constant,
    /// Derived or transient data omitted from durable actor state.
    Skipped,
}

/// Execution mode of a generated actor method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodMode {
    /// Replica-coherent snapshot query; writes are forbidden.
    Query,
    /// Query after a linear read barrier.
    LinearizableQuery,
    /// Mutate linear state and read a pinned merge frontier.
    Linear,
    /// Mutate merge state. Linear and local state are inaccessible.
    Merge,
    /// Mutate only this replica's local state while reading immutable lane
    /// snapshots.
    Local,
}

impl MethodMode {
    pub const fn can_read(self, lane: StateLane) -> bool {
        match self {
            Self::Query | Self::LinearizableQuery | Self::Local => true,
            Self::Linear => matches!(lane, StateLane::Linear | StateLane::Merge),
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

/// Compact set of state lanes required or implemented by a package.
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

/// Consensus participation of one authorized agent replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplicaRole {
    Voter = 0,
    Observer = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentReplica {
    pub node: NodeId,
    /// Principal bound to this node's signed replica identity.
    pub principal: PrincipalId,
    pub role: ReplicaRole,
}

/// Runtime features actor packages may require.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeRequirements {
    pub lanes: LaneSet,
    pub scheduling: bool,
    pub proofs: bool,
}

/// Immutable capability declaration signed into an agent-runtime package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    pub lanes: LaneSet,
    pub scheduling: bool,
    pub proofs: bool,
    /// Durable directory capacity. This is independent of the maximum 63
    /// simultaneously active standard inner machines.
    pub max_actors: u32,
}

/// Typed payload of one signed `.vos` package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    Actor {
        requirements: RuntimeRequirements,
    },
    AgentRuntime {
        abi: Hash,
        capabilities: RuntimeCapabilities,
    },
}

impl PackageKind {
    pub fn is_compatible_with(self, runtime: RuntimeCapabilities) -> bool {
        match self {
            Self::Actor { requirements } => runtime.satisfies(requirements),
            Self::AgentRuntime { abi, .. } => abi.0 == RUNTIME_ABI_ID.0,
        }
    }
}

impl RuntimeCapabilities {
    pub const STANDARD_MAX_ACTORS: u32 = 4096;

    pub const fn standard() -> Self {
        Self {
            lanes: LaneSet::ALL,
            scheduling: false,
            proofs: true,
            max_actors: Self::STANDARD_MAX_ACTORS,
        }
    }

    pub const fn satisfies(self, requirements: RuntimeRequirements) -> bool {
        (requirements.lanes.bits() & !self.lanes.bits()) == 0
            && (!requirements.scheduling || self.scheduling)
            && (!requirements.proofs || self.proofs)
    }
}

/// Stable identity of one runtime instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    pub space: SpaceId,
    pub agent: AgentId,
    pub owner: PrincipalId,
    pub profile: AgentProfile,
    pub runtime_deployment: DeploymentId,
    pub runtime_program: ProgramId,
    pub runtime_producer: ProducerId,
}

/// Durable actor-directory entry. `parent = None` denotes a top-level actor;
/// no actor is privileged as an agent root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorEntry {
    pub actor: ActorId,
    pub name: String,
    pub parent: Option<ActorId>,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub lanes: LaneSet,
    pub suspended: bool,
}

/// One deterministic page of the potentially large actor forest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorDirectoryPage {
    pub entries: Vec<ActorEntry>,
    pub next: Option<ActorId>,
}

/// Initial lane roots carried by an actor installation. Local bytes are
/// supplied independently on each replica and therefore have no shared root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInitialState {
    pub linear: Option<BlobRef>,
    pub merge: Option<BlobRef>,
    pub local: Option<BlobRef>,
}

/// Canonical install request consumed by an agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallActor {
    pub entry: ActorEntry,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub initial_state: ActorInitialState,
    pub requirements: RuntimeRequirements,
}

/// Canonical actor upgrade request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeActor {
    pub actor: ActorId,
    pub from_deployment: DeploymentId,
    pub to_deployment: DeploymentId,
    pub to_program: ProgramId,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub requirements: RuntimeRequirements,
}

/// Complete durable provenance and lane roots of one installed actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRecord {
    pub entry: ActorEntry,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub initial_state: ActorInitialState,
    pub requirements: RuntimeRequirements,
}

/// Durable work that prevents safe leaf removal.
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

/// Lifecycle operation sent to the runtime's management entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleRequest {
    Create(AgentConfig),
    Inspect {
        after: Option<ActorId>,
        limit: u16,
    },
    Install(InstallActor),
    UpgradeActor(UpgradeActor),
    Suspend(ActorId),
    Resume(ActorId),
    RemoveLeaf {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    UpgradeRuntime {
        from_deployment: DeploymentId,
        to_deployment: DeploymentId,
        to_program: ProgramId,
        producer: ProducerId,
        package: BlobRef,
        abi: Hash,
        capabilities: RuntimeCapabilities,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    NotCreated,
    AlreadyCreated,
    NotFound,
    AlreadyExists,
    StaleDeployment,
    UnsupportedRuntime,
    UnsupportedLane,
    Busy(ActorLifecycleDebt),
    DirectoryFull,
    InvalidRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleReply {
    Created(AgentIdentity),
    Directory(ActorDirectoryPage),
    Installed(ActorEntry),
    Upgraded(ActorEntry),
    Suspended(ActorEntry),
    Resumed(ActorEntry),
    Removed(ActorId),
    RuntimeUpgraded(AgentIdentity),
}

/// Public Rust contract custom agent runtimes implement. The PVM entry glue
/// is deliberately separate from policy: alternate runtimes may choose
/// scheduling or actor-priority behavior while preserving this lifecycle.
pub trait AgentRuntime {
    fn capabilities(&self) -> RuntimeCapabilities;
    fn apply(&mut self, request: LifecycleRequest) -> Result<LifecycleReply, LifecycleError>;
    fn lifecycle_debt(&self, actor: ActorId) -> Result<ActorLifecycleDebt, LifecycleError>;
}

/// Structural validation of immutable agent configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentConfigError {
    NoReplicas,
    DuplicateReplica,
    ReplicaOrder,
    UnsupportedLane,
    InvalidLocalReplicaSet,
    InvalidPrivateReplicaRole,
    InvalidPrivateReplicaOwner,
    InvalidRuntimeCapacity,
    InvalidRuntimePackage,
}

/// Immutable creation descriptor consumed by an agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub identity: AgentIdentity,
    pub runtime_package: BlobRef,
    pub capabilities: RuntimeCapabilities,
    pub replicas: Vec<AgentReplica>,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), AgentConfigError> {
        if self.capabilities.max_actors == 0 {
            return Err(AgentConfigError::InvalidRuntimeCapacity);
        }
        if self.identity.runtime_deployment == DeploymentId::ZERO
            || self.identity.runtime_program == ProgramId::ZERO
            || self.identity.runtime_producer == ProducerId::ZERO
            || self.runtime_package.hash == Hash::ZERO
            || self.runtime_package.len == 0
        {
            return Err(AgentConfigError::InvalidRuntimePackage);
        }
        if !self.capabilities.lanes.supported_by(self.identity.profile) {
            return Err(AgentConfigError::UnsupportedLane);
        }
        if self.replicas.is_empty() {
            return Err(AgentConfigError::NoReplicas);
        }
        if self.identity.profile == AgentProfile::Local && self.replicas.len() != 1 {
            return Err(AgentConfigError::InvalidLocalReplicaSet);
        }
        for pair in self.replicas.windows(2) {
            if pair[0].node == pair[1].node {
                return Err(AgentConfigError::DuplicateReplica);
            }
            if pair[0].node > pair[1].node {
                return Err(AgentConfigError::ReplicaOrder);
            }
        }
        if self.identity.profile == AgentProfile::Private
            && self
                .replicas
                .iter()
                .any(|replica| replica.role != ReplicaRole::Observer)
        {
            return Err(AgentConfigError::InvalidPrivateReplicaRole);
        }
        if self.identity.profile == AgentProfile::Private
            && self
                .replicas
                .iter()
                .any(|replica| replica.principal != self.identity.owner)
        {
            return Err(AgentConfigError::InvalidPrivateReplicaOwner);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_profile_rejects_linear_state() {
        assert!(!AgentProfile::Private.supports(StateLane::Linear));
        assert!(AgentProfile::Private.supports(StateLane::Merge));
        assert!(AgentProfile::Private.supports(StateLane::Local));
        assert!(!LaneSet::of(StateLane::Linear).supported_by(AgentProfile::Private));
    }

    #[test]
    fn method_access_matrix_is_explicit() {
        assert!(MethodMode::Linear.can_read(StateLane::Merge));
        assert!(MethodMode::Linear.can_write(StateLane::Linear));
        assert!(!MethodMode::Linear.can_write(StateLane::Merge));
        assert!(!MethodMode::Merge.can_read(StateLane::Linear));
        assert!(MethodMode::Merge.can_write(StateLane::Merge));
        assert!(MethodMode::Local.can_read(StateLane::Linear));
        assert!(MethodMode::Local.can_write(StateLane::Local));
        assert!(!MethodMode::Query.can_write(StateLane::Linear));
    }

    #[test]
    fn runtime_requirements_are_checked_without_actor_count_coupling() {
        let standard = RuntimeCapabilities::standard();
        assert_eq!(standard.max_actors, 4096);
        assert!(standard.satisfies(RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge)),
            scheduling: false,
            proofs: true,
        }));
        assert!(!standard.satisfies(RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: true,
            proofs: false,
        }));
        assert!(
            PackageKind::Actor {
                requirements: RuntimeRequirements {
                    lanes: LaneSet::of(StateLane::Merge),
                    scheduling: false,
                    proofs: false,
                },
            }
            .is_compatible_with(standard)
        );
        assert!(
            PackageKind::AgentRuntime {
                abi: RUNTIME_ABI_ID,
                capabilities: standard,
            }
            .is_compatible_with(standard)
        );
    }

    #[test]
    fn identities_do_not_collapse_principals_nodes_and_credentials() {
        let key = b"same source bytes";
        let principal = PrincipalId::of_public_key(key);
        let node = NodeId::of_authenticated_peer(key);
        let credential = crate::service::CredentialId::of_public_key(key);
        assert_ne!(principal.as_bytes(), node.as_bytes());
        assert_ne!(principal.as_bytes(), credential.as_bytes());
        assert_ne!(node.as_bytes(), credential.as_bytes());
    }

    #[test]
    fn private_agents_accept_only_owner_nodes() {
        let owner = PrincipalId([1; 32]);
        let mut config = AgentConfig {
            identity: AgentIdentity {
                space: SpaceId([2; 32]),
                agent: AgentId([3; 32]),
                owner,
                profile: AgentProfile::Private,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([8; 32]),
            },
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local)),
                scheduling: false,
                proofs: false,
                max_actors: 4096,
            },
            runtime_package: BlobRef {
                hash: Hash([9; 32]),
                len: 100,
            },
            replicas: vec![AgentReplica {
                node: NodeId([6; 32]),
                principal: owner,
                role: ReplicaRole::Observer,
            }],
        };
        assert_eq!(config.validate(), Ok(()));
        config.replicas[0].principal = PrincipalId([7; 32]);
        assert_eq!(
            config.validate(),
            Err(AgentConfigError::InvalidPrivateReplicaOwner)
        );
    }

    #[test]
    fn every_lifecycle_debt_blocks_leaf_removal() {
        let clear = ActorLifecycleDebt::default();
        assert!(clear.is_clear());
        for debt in [
            ActorLifecycleDebt {
                children: 1,
                ..clear
            },
            ActorLifecycleDebt {
                continuations: 1,
                ..clear
            },
            ActorLifecycleDebt { inbox: 1, ..clear },
            ActorLifecycleDebt { outbox: 1, ..clear },
            ActorLifecycleDebt {
                schedules: 1,
                ..clear
            },
            ActorLifecycleDebt {
                proof_artifacts: 1,
                ..clear
            },
            ActorLifecycleDebt {
                lifecycle_operations: 1,
                ..clear
            },
        ] {
            assert!(!debt.is_clear());
        }
    }
}
