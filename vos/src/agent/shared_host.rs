//! Bounded production host boundary for ordinary Shared Agents.
//!
//! Every hosted Agent owns one full-identity journal directory, one
//! generation-bound Raft database, and one generation-bound artifact staging
//! directory.  Opening the host rechecks system-Agent finality, package trust,
//! every durable namespace, and the journal/Raft cross-store binding before an
//! Agent becomes discoverable.
//!
//! This module deliberately does not attach the existing service-oriented
//! Raft worker or the singleton service CRDT router.  Those adapters carry a
//! service snapshot format which is not an authenticated Agent journal
//! snapshot.  The status surface reports that transport is unattached and
//! snapshot/compaction is unsupported; callers can drive only already
//! committed physical slots and committee-authenticated Merge events.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use redb::Database;

use super::driver::AgentTrustProvider;
use super::execution::RuntimeBlob;
use super::genesis::{
    AgentGenesisFinalityError, AgentGenesisFinalityVerifier, AgentGenesisProvision,
    AgentGenesisProvisionVerificationError, VerifiedAgentGenesisProvision,
    validate_agent_genesis_catalog,
};
use super::host::{AgentHostError, AgentHostRootLease, AgentHostScope, LocalMergeAuthenticator};
use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, MAX_JOURNAL_RECORD_BYTES, MergeEvent,
    MergeEventId, MergeFrontierId, OrderedEntryId, RuntimeBinding,
};
use super::journal_store::{AgentJournalStore, FileAgentJournalStore, FileLocalAgentJournalSlot};
use super::local_journal_driver::LocalJournalAgentDriver;
use super::shared_journal_driver::{
    FileSharedArtifactStager, SharedArtifactStagerError, SharedJournalAgentDriver,
    SharedJournalDriverError, SharedPhysicalApplyOutcome, install_immutable_file,
    read_regular_bounded,
};
use super::shared_raft::{
    AgentGenerationRouteKey, AgentRaftApplicationErrorV2, AgentRaftApplicationLedgerV2,
    AgentRouteKey, CommitteeChangeAuthorityBinding,
};
use super::{AgentIdentity, AgentProfile, ReplicaRole, StateLane};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId};

const JOURNAL_SUFFIX: &str = ".agent";
const JOURNAL_LOCK_SUFFIX: &str = ".agent-lock";
const INTENT_SUFFIX: &str = ".shared-genesis.intent";
const INTENT_STAGE_SUFFIX: &str = ".shared-genesis.intent.next";
const EXPOSURE_SUFFIX: &str = ".shared-genesis.exposed";
const EXPOSURE_STAGE_SUFFIX: &str = ".shared-genesis.exposed.next";
const RAFT_SUFFIX: &str = ".shared-raft.redb";
const ARTIFACT_SUFFIX: &str = ".shared-artifacts";
const SHARED_GENESIS_INTENT_DOMAIN: &[u8] = b"vos/agent-host/shared-genesis-intent/v1";

/// Hard discovery bound for one Shared host root.
pub const MAX_SHARED_HOST_AGENTS: usize = 4096;
/// The intent retains one complete finalized provision and its exact genesis
/// catalog preimages. Ordinary genesis currently has exactly one catalog
/// reference, but the aggregate bound remains explicit.
pub const MAX_SHARED_GENESIS_INTENT_BYTES: usize = super::genesis::MAX_AGENT_GENESIS_PROVISION_BYTES
    + super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES as usize
    + 4096;

type FileSharedDriver = SharedJournalAgentDriver<FileAgentJournalStore, FileSharedArtifactStager>;

/// Stable public projection of the bounded Shared-host failure boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentHostError {
    Unavailable,
    DirectoryInUse,
    InvalidScope,
    ScopeMismatch,
    InvalidProvision,
    Finality(AgentGenesisFinalityError),
    InvalidCatalog,
    Conflict,
    CorruptResidue,
    AgentNotFound,
    CapacityExhausted,
    TransportNotAttached,
    SnapshotUnsupported,
}

impl core::fmt::Display for SharedAgentHostError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Shared Agent host: {self:?}")
    }
}

impl core::error::Error for SharedAgentHostError {}

/// Transport remains an explicit attachment state rather than an inferred
/// consequence of a durable Raft file existing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentTransportState {
    NotAttached,
}

/// No generic service snapshot may be installed into an Agent generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentSnapshotState {
    Unsupported,
}

/// Engines required by the currently admitted actor directory. Control is
/// always ordered for a Shared Agent; the actor-selected data lanes are
/// reported independently so a future transport coordinator creates no
/// unused Merge engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentEnginePlan {
    pub control_raft: bool,
    pub linear_raft: bool,
    pub merge: bool,
    pub local: bool,
}

/// Exact authority-certified transport identity of one active replica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedReplicaRoute {
    pub node: NodeId,
    pub role: ReplicaRole,
    pub peer_id: Vec<u8>,
    pub ed25519_public_key: [u8; 32],
    pub raft_slot: Option<u16>,
}

/// Public status for one physical generation. `remaining_slots` is a hard
/// bound, not an uptime estimate: reaching zero rejects the next application
/// before artifact, journal, reservation, or Raft-apply mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentStatus {
    pub identity: AgentIdentity,
    pub generation: AgentGenerationRouteKey,
    pub route: AgentRouteKey,
    pub replication_id: [u8; 32],
    pub local_role: Option<ReplicaRole>,
    pub replicas: Vec<SharedReplicaRoute>,
    pub engines: SharedAgentEnginePlan,
    pub applied_slots: u64,
    pub remaining_slots: u64,
    pub reservation_pending: bool,
    pub transport: SharedAgentTransportState,
    pub snapshots: SharedAgentSnapshotState,
}

/// Exact journal position needed to construct the next candidate outside the
/// physical apply boundary. It is observational and grants no commit power.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentJournalPosition {
    pub genesis: AgentJournalGenesisId,
    pub admission: super::genesis::AgentGenesisAdmissionId,
    pub ordered_index: u64,
    pub ordered_head: Option<OrderedEntryId>,
    pub merge_frontier: MergeFrontierId,
    pub runtime: RuntimeBinding,
}

/// Filesystem route handed to an Agent-specific consensus coordinator. The
/// path alone is not evidence that a transport is attached or a slot is
/// committed; application still reads the database's durable commit cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentPhysicalRoute {
    pub generation: AgentGenerationRouteKey,
    pub replication_id: [u8; 32],
    pub raft_database: PathBuf,
}

/// Result of applying one already committed physical slot or importing one
/// authenticated Merge event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedAgentApplyOutcome {
    Applied { index: u64 },
    Duplicate { index: u64 },
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedGenesisIntent {
    provision: AgentGenesisProvision,
    catalog: Vec<RuntimeBlob>,
    committee_authority: CommitteeChangeAuthorityBinding,
}

impl SharedGenesisIntent {
    fn new(
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<Self, SharedAgentHostError> {
        let intent = Self {
            provision,
            catalog,
            committee_authority,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), SharedAgentHostError> {
        self.provision
            .validate()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        validate_agent_genesis_catalog(self.provision.proposal(), &self.catalog)
            .map_err(|_| SharedAgentHostError::InvalidCatalog)?;
        let config = self
            .provision
            .proposal()
            .config()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        if config.identity.profile != AgentProfile::Shared
            || config.system_authority_genesis.is_some()
            || CommitteeChangeAuthorityBinding::decode(&self.committee_authority.encode())
                .ok()
                .as_ref()
                != Some(&self.committee_authority)
            || self.catalog.iter().any(|blob| {
                blob.bytes.len() > super::MAX_CATALOG_ARTIFACT_BYTES as usize
                    || !blob.reference.matches(&blob.bytes)
            })
        {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        let encoded = self.encode();
        if encoded.len() > MAX_SHARED_GENESIS_INTENT_BYTES {
            return Err(SharedAgentHostError::InvalidCatalog);
        }
        Ok(())
    }

    fn agent(&self) -> Result<AgentId, SharedAgentHostError> {
        Ok(self
            .provision
            .proposal()
            .config()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?
            .identity
            .agent)
    }

    fn id(&self) -> Hash {
        Hash::digest(SHARED_GENESIS_INTENT_DOMAIN, &[&self.encode()])
    }
}

impl ServiceWire for SharedGenesisIntent {
    const MAGIC: [u8; 4] = *b"AGSI";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.provision.encode());
        encoder.u32(self.catalog.len() as u32);
        for blob in &self.catalog {
            encoder.fixed(&blob.reference.hash.0);
            encoder.u64(blob.reference.len);
            encoder.bytes(&blob.bytes);
        }
        encoder.bytes(&self.committee_authority.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_SHARED_GENESIS_INTENT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let provision = AgentGenesisProvision::decode(&decoder.bytes()?)?;
        let count = decoder.u32()? as usize;
        if count > super::MAX_CATALOG_ARTIFACT_REFERENCES as usize {
            return Err(DecodeError::LimitExceeded);
        }
        let mut catalog = Vec::new();
        catalog
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            let reference = BlobRef {
                hash: Hash(decoder.fixed()?),
                len: decoder.u64()?,
            };
            let bytes = decoder.bytes()?;
            catalog.push(RuntimeBlob { reference, bytes });
        }
        let committee_authority = CommitteeChangeAuthorityBinding::decode(&decoder.bytes()?)?;
        let intent = Self {
            provision,
            catalog,
            committee_authority,
        };
        intent.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(intent)
    }
}

struct HostedSharedAgent {
    intent: SharedGenesisIntent,
    raft_path: PathBuf,
    driver: FileSharedDriver,
}

/// Serialized owner of a directory containing independently durable Shared
/// Agent replicas. Callers may place this behind their own command queue; the
/// type itself intentionally requires `&mut self` for every mutation.
pub struct SharedAgentHost {
    lease: AgentHostRootLease,
    agents: BTreeMap<AgentId, HostedSharedAgent>,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    finality: Arc<dyn AgentGenesisFinalityVerifier>,
}

impl SharedAgentHost {
    /// Acquire a stable outer lease and reopen every discoverable Shared
    /// generation. No generation is returned until live finality and complete
    /// physical recovery succeed.
    pub fn open(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<Self, SharedAgentHostError> {
        let lease = AgentHostRootLease::acquire(root, stable_lock_path, scope)
            .map_err(map_outer_lease_error)?;
        Self::open_with_lease(lease, trust, merge, finality)
    }

    /// Reopen is intentionally an alias with no weaker recovery mode.
    pub fn reopen(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::open(root, stable_lock_path, scope, trust, merge, finality)
    }

    pub fn open_with_lease(
        mut lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<Self, SharedAgentHostError> {
        if lease.scope().validate().is_err() || merge.node() != lease.scope().node {
            return Err(SharedAgentHostError::InvalidScope);
        }
        lease.validate_live().map_err(map_outer_lease_error)?;
        let files = scan_generation_namespaces(&lease)?;
        let mut host = Self {
            lease,
            agents: BTreeMap::new(),
            trust,
            merge,
            finality,
        };
        for (agent, files) in files {
            let (intent, encoded) = host.read_intent(agent, files)?;
            let sealed = host.verify_and_prepare(&intent)?;
            install_host_record(&host.intent_path(agent), &encoded)?;
            let exposed = host.read_exposure(agent, intent.id(), files)?;
            let hosted = host.open_generation(intent, &sealed, exposed, files)?;
            if host.agents.insert(agent, hosted).is_some() {
                return Err(SharedAgentHostError::CorruptResidue);
            }
        }
        host.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(host)
    }

    pub fn scope(&self) -> AgentHostScope {
        self.lease.scope()
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Provision an exact finalized generation, or return its current status
    /// for an exact retry. Finality, catalog shape, package trust, and Create
    /// replay all complete before the first intent byte is written.
    pub fn provision(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let intent = SharedGenesisIntent::new(provision, catalog, committee_authority)?;
        let agent = intent.agent()?;
        if intent.provision.proposal().locator().space != self.scope().space
            || intent
                .provision
                .replicas()
                .member_by_node(self.scope().node)
                .is_none()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let sealed = self.verify_and_prepare(&intent)?;
        if let Some(existing) = self.agents.get(&agent) {
            if existing.intent != intent {
                return Err(SharedAgentHostError::Conflict);
            }
            return status_for(existing);
        }
        if self.agents.len() == MAX_SHARED_HOST_AGENTS {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let current = scan_generation_namespaces(&self.lease)?;
        if current.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        install_host_record(&self.intent_path(agent), &intent.encode())?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self.open_generation(
            intent,
            &sealed,
            false,
            GenerationFiles {
                intent: true,
                ..GenerationFiles::default()
            },
        )?;
        let status = status_for(&hosted)?;
        self.agents.insert(agent, hosted);
        Ok(status)
    }

    pub fn list(&self) -> Result<Vec<SharedAgentStatus>, SharedAgentHostError> {
        self.agents.values().map(status_for).collect()
    }

    pub fn show(&self, agent: AgentId) -> Result<Option<SharedAgentStatus>, SharedAgentHostError> {
        self.agents.get(&agent).map(status_for).transpose()
    }

    pub fn role(&self, agent: AgentId) -> Result<Option<ReplicaRole>, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted.driver.local_role().map_err(map_driver_error)
    }

    pub fn route(&self, agent: AgentId) -> Result<AgentRouteKey, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted.driver.active_route().map_err(map_driver_error)
    }

    pub fn physical_route(
        &self,
        agent: AgentId,
    ) -> Result<SharedAgentPhysicalRoute, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let generation = hosted.driver.ledger().generation();
        Ok(SharedAgentPhysicalRoute {
            generation,
            replication_id: generation.replication_id(),
            raft_database: hosted.raft_path.clone(),
        })
    }

    pub fn journal_position(
        &self,
        agent: AgentId,
    ) -> Result<SharedAgentJournalPosition, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let (genesis, admission, ordered_index, ordered_head, merge_frontier, runtime) =
            hosted.driver.journal_position();
        Ok(SharedAgentJournalPosition {
            genesis,
            admission,
            ordered_index,
            ordered_head,
            merge_frontier,
            runtime,
        })
    }

    /// Apply exactly one slot which the generation's durable Raft metadata
    /// already marks committed. The host never manufactures commit evidence.
    pub fn apply_next(
        &mut self,
        agent: AgentId,
    ) -> Result<SharedAgentApplyOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted
            .driver
            .apply_next()
            .map(map_apply_outcome)
            .map_err(map_driver_error)
    }

    /// Import one canonical event. Committee ID, complete author identity,
    /// Ed25519 signature, causal closure, and ordered base are all rechecked
    /// before publication.
    pub fn import_merge(
        &mut self,
        agent: AgentId,
        event: &MergeEvent,
    ) -> Result<SharedAgentApplyOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted
            .driver
            .import_merge(event)
            .map(map_apply_outcome)
            .map_err(map_driver_error)
    }

    pub fn import_merge_bytes(
        &mut self,
        agent: AgentId,
        bytes: &[u8],
    ) -> Result<SharedAgentApplyOutcome, SharedAgentHostError> {
        if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        let event =
            MergeEvent::decode(bytes).map_err(|_| SharedAgentHostError::InvalidProvision)?;
        if event.encode() != bytes {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        self.import_merge(agent, &event)
    }

    /// Composite-network hook for serving an authenticated Merge frontier.
    /// The caller remains responsible for committee-gating the Noise peer.
    pub fn merge_roots(&self, agent: AgentId) -> Result<Vec<[u8; 32]>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .merge_roots()
            .map_err(map_driver_error)
    }

    /// Composite-network hook for point-fetching a canonical Merge event.
    pub fn merge_node(
        &self,
        agent: AgentId,
        event: MergeEventId,
    ) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .merge_event_bytes(event)
            .map_err(map_driver_error)
    }

    /// Explicit fail-closed gate until an Agent-specific transport adapter is
    /// installed by a later slice.
    pub fn require_transport(&self, agent: AgentId) -> Result<(), SharedAgentHostError> {
        if !self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        Err(SharedAgentHostError::TransportNotAttached)
    }

    /// Explicit fail-closed gate for the missing authenticated Agent snapshot
    /// and audit-retirement protocol.
    pub fn request_snapshot_compaction(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        if !self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        Err(SharedAgentHostError::SnapshotUnsupported)
    }

    fn verify_and_prepare(
        &self,
        intent: &SharedGenesisIntent,
    ) -> Result<super::replay::ReplaySealedSharedGenesis, SharedAgentHostError> {
        intent.validate()?;
        let verified =
            VerifiedAgentGenesisProvision::verify(intent.provision.clone(), self.finality.as_ref())
                .map_err(map_provision_verification_error)?;
        let member = verified
            .provision()
            .replicas()
            .member_by_node(self.scope().node)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_shared_genesis(
            &verified,
            member.replica(),
            &intent.catalog,
            Arc::clone(&self.trust),
            Arc::clone(&self.merge),
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)
    }

    fn open_generation(
        &mut self,
        intent: SharedGenesisIntent,
        sealed: &super::replay::ReplaySealedSharedGenesis,
        externally_exposed: bool,
        files: GenerationFiles,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        let agent = intent.agent()?;
        let scope = self.scope();
        if externally_exposed && !(files.journal && files.lock && files.raft && files.artifacts) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            scope.node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let store = slot
            .open(sealed, externally_exposed)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let state = (store.genesis(), store.heads());
        let state = match state {
            (Ok(genesis), Ok(heads)) => (genesis, heads),
            _ => return Err(SharedAgentHostError::CorruptResidue),
        };

        let generation = AgentGenerationRouteKey::new(
            scope.space,
            agent,
            sealed.genesis().id(),
            sealed.admission_record().id(),
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let raft_path = self.raft_path(agent);
        validate_database_path(&raft_path, externally_exposed)?;
        let database =
            Arc::new(Database::create(&raft_path).map_err(|_| SharedAgentHostError::Unavailable)?);
        let ledger = AgentRaftApplicationLedgerV2::open(
            database,
            generation,
            store.instance_id(),
            scope.node,
            sealed.committee().clone(),
            intent.committee_authority,
        )
        .map_err(map_ledger_error)?;

        let artifact_path = self.artifact_path(agent);
        validate_artifact_path(&artifact_path, externally_exposed)?;
        let artifacts = FileSharedArtifactStager::open(&artifact_path, generation)
            .map_err(map_artifact_error)?;
        let mut driver = match state {
            (None, None) | (Some(_), None) => FileSharedDriver::create_shared_unexposed(
                store,
                artifacts,
                ledger,
                sealed,
                &intent.catalog,
                Arc::clone(&self.trust),
                Arc::clone(&self.merge),
            ),
            (Some(_), Some(_)) => FileSharedDriver::open_shared_unexposed(
                store,
                artifacts,
                ledger,
                Arc::clone(&self.trust),
                Arc::clone(&self.merge),
            ),
            (None, Some(_)) => return Err(SharedAgentHostError::CorruptResidue),
        }
        .map_err(map_driver_error)?;

        self.lease
            .arm_after_agent_open()
            .map_err(map_outer_lease_error)?;
        driver
            .commit_exposure(sealed, intent.id())
            .map_err(map_driver_error)?;
        install_host_record(&self.exposure_path(agent), intent.id().as_bytes())?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(HostedSharedAgent {
            intent,
            raft_path,
            driver,
        })
    }

    fn read_intent(
        &self,
        agent: AgentId,
        files: GenerationFiles,
    ) -> Result<(SharedGenesisIntent, Vec<u8>), SharedAgentHostError> {
        if !files.intent && !files.intent_stage {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let bytes =
            read_host_record_pair(&self.intent_path(agent), MAX_SHARED_GENESIS_INTENT_BYTES)?
                .ok_or(SharedAgentHostError::CorruptResidue)?;
        let intent = SharedGenesisIntent::decode(&bytes)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if intent.encode() != bytes || intent.agent()? != agent {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok((intent, bytes))
    }

    fn read_exposure(
        &self,
        agent: AgentId,
        intent: Hash,
        files: GenerationFiles,
    ) -> Result<bool, SharedAgentHostError> {
        if !files.exposed && !files.exposed_stage {
            return Ok(false);
        }
        let bytes = read_host_record_pair(&self.exposure_path(agent), 32)?
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if bytes.as_slice() != intent.as_bytes() {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(true)
    }

    fn journal_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .root()
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX))
    }

    fn journal_lock_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX))
    }

    fn intent_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), INTENT_SUFFIX))
    }

    fn exposure_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), EXPOSURE_SUFFIX))
    }

    fn raft_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), RAFT_SUFFIX))
    }

    fn artifact_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), ARTIFACT_SUFFIX))
    }
}

fn status_for(hosted: &HostedSharedAgent) -> Result<SharedAgentStatus, SharedAgentHostError> {
    let identity = hosted.driver.identity().map_err(map_driver_error)?;
    let generation = hosted.driver.ledger().generation();
    let route = hosted.driver.active_route().map_err(map_driver_error)?;
    let committee = hosted.driver.active_committee().map_err(map_driver_error)?;
    let local_role = hosted.driver.local_role().map_err(map_driver_error)?;
    let lanes = hosted.driver.engine_lanes().map_err(map_driver_error)?;
    let (applied_slots, remaining_slots, reservation_pending) =
        hosted.driver.capacity().map_err(map_driver_error)?;
    let replicas = committee
        .members()
        .iter()
        .map(|member| SharedReplicaRoute {
            node: member.replica().node,
            role: member.replica().role,
            peer_id: member.peer_id().to_vec(),
            ed25519_public_key: *member.ed25519_public_key(),
            raft_slot: member.raft_slot(),
        })
        .collect();
    Ok(SharedAgentStatus {
        identity,
        generation,
        route,
        replication_id: generation.replication_id(),
        local_role,
        replicas,
        engines: SharedAgentEnginePlan {
            control_raft: true,
            linear_raft: lanes.contains(StateLane::Linear),
            merge: lanes.contains(StateLane::Merge),
            local: lanes.contains(StateLane::Local),
        },
        applied_slots,
        remaining_slots,
        reservation_pending,
        transport: SharedAgentTransportState::NotAttached,
        snapshots: SharedAgentSnapshotState::Unsupported,
    })
}

fn map_apply_outcome(outcome: SharedPhysicalApplyOutcome) -> SharedAgentApplyOutcome {
    match outcome {
        SharedPhysicalApplyOutcome::Applied { index } => SharedAgentApplyOutcome::Applied { index },
        SharedPhysicalApplyOutcome::Duplicate { index } => {
            SharedAgentApplyOutcome::Duplicate { index }
        }
        SharedPhysicalApplyOutcome::Idle => SharedAgentApplyOutcome::Idle,
    }
}

fn map_outer_lease_error(error: AgentHostError) -> SharedAgentHostError {
    match error {
        AgentHostError::DirectoryInUse => SharedAgentHostError::DirectoryInUse,
        AgentHostError::InvalidScope => SharedAgentHostError::InvalidScope,
        AgentHostError::ScopeMismatch => SharedAgentHostError::ScopeMismatch,
        AgentHostError::Conflict => SharedAgentHostError::Conflict,
        AgentHostError::Unavailable => SharedAgentHostError::Unavailable,
        _ => SharedAgentHostError::CorruptResidue,
    }
}

fn map_provision_verification_error(
    error: AgentGenesisProvisionVerificationError,
) -> SharedAgentHostError {
    match error {
        AgentGenesisProvisionVerificationError::InvalidProvision(_) => {
            SharedAgentHostError::InvalidProvision
        }
        AgentGenesisProvisionVerificationError::Finality(error) => {
            SharedAgentHostError::Finality(error)
        }
    }
}

fn map_driver_error(error: SharedJournalDriverError) -> SharedAgentHostError {
    match error {
        SharedJournalDriverError::Ledger(error) => map_ledger_error(error),
        SharedJournalDriverError::Artifact(error) => map_artifact_error(error),
        SharedJournalDriverError::Store(super::journal_store::JournalStoreError::LimitExceeded)
        | SharedJournalDriverError::Store(super::journal_store::JournalStoreError::Backpressure) => {
            SharedAgentHostError::CapacityExhausted
        }
        SharedJournalDriverError::Store(super::journal_store::JournalStoreError::Conflict) => {
            SharedAgentHostError::Conflict
        }
        SharedJournalDriverError::Store(super::journal_store::JournalStoreError::Unavailable) => {
            SharedAgentHostError::Unavailable
        }
        SharedJournalDriverError::WrongReplica | SharedJournalDriverError::InvalidProfile => {
            SharedAgentHostError::ScopeMismatch
        }
        SharedJournalDriverError::InvalidArtifactBatch
        | SharedJournalDriverError::CrossStoreMismatch
        | SharedJournalDriverError::Replay(_)
        | SharedJournalDriverError::Store(_) => SharedAgentHostError::CorruptResidue,
    }
}

fn map_ledger_error(error: AgentRaftApplicationErrorV2) -> SharedAgentHostError {
    match error {
        AgentRaftApplicationErrorV2::BacklogLimit => SharedAgentHostError::CapacityExhausted,
        AgentRaftApplicationErrorV2::SnapshotUnsupported => {
            SharedAgentHostError::SnapshotUnsupported
        }
        AgentRaftApplicationErrorV2::ConfigurationMismatch
        | AgentRaftApplicationErrorV2::WrongGeneration
        | AgentRaftApplicationErrorV2::WrongLocalReplica
        | AgentRaftApplicationErrorV2::StaleCommittee => SharedAgentHostError::ScopeMismatch,
        AgentRaftApplicationErrorV2::Backend(_) => SharedAgentHostError::Unavailable,
        _ => SharedAgentHostError::CorruptResidue,
    }
}

fn map_artifact_error(error: SharedArtifactStagerError) -> SharedAgentHostError {
    match error {
        SharedArtifactStagerError::Unavailable => SharedAgentHostError::Unavailable,
        SharedArtifactStagerError::Conflict => SharedAgentHostError::Conflict,
        SharedArtifactStagerError::LimitExceeded => SharedAgentHostError::CapacityExhausted,
        SharedArtifactStagerError::Corrupt => SharedAgentHostError::CorruptResidue,
    }
}

fn install_host_record(path: &Path, bytes: &[u8]) -> Result<(), SharedAgentHostError> {
    install_immutable_file(path, bytes).map_err(map_artifact_error)
}

fn read_host_record_pair(
    canonical: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
    use std::os::unix::fs::MetadataExt as _;

    let name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SharedAgentHostError::CorruptResidue)?;
    let staged = canonical.with_file_name(format!("{name}.next"));
    let canonical_bytes = read_optional_record(canonical, maximum)?;
    let staged_bytes = read_optional_record(&staged, maximum)?;
    match (canonical_bytes, staged_bytes) {
        (None, None) => Ok(None),
        (Some(bytes), None) | (None, Some(bytes)) => Ok(Some(bytes)),
        (Some(canonical_bytes), Some(staged_bytes)) => {
            let canonical_meta =
                fs::metadata(canonical).map_err(|_| SharedAgentHostError::Unavailable)?;
            let staged_meta =
                fs::metadata(&staged).map_err(|_| SharedAgentHostError::Unavailable)?;
            if canonical_bytes != staged_bytes
                || canonical_meta.dev() != staged_meta.dev()
                || canonical_meta.ino() != staged_meta.ino()
            {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            Ok(Some(canonical_bytes))
        }
    }
}

fn read_optional_record(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            read_regular_bounded(path, maximum)
                .map(Some)
                .map_err(map_artifact_error)
        }
        Ok(_) => Err(SharedAgentHostError::CorruptResidue),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SharedAgentHostError::Unavailable),
    }
}

fn validate_database_path(path: &Path, must_exist: bool) -> Result<(), SharedAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(SharedAgentHostError::CorruptResidue),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SharedAgentHostError::CorruptResidue)
        }
        Err(_) => Err(SharedAgentHostError::Unavailable),
    }
}

fn validate_artifact_path(path: &Path, must_exist: bool) -> Result<(), SharedAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(SharedAgentHostError::CorruptResidue),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SharedAgentHostError::CorruptResidue)
        }
        Err(_) => Err(SharedAgentHostError::Unavailable),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GenerationFiles {
    journal: bool,
    lock: bool,
    intent: bool,
    intent_stage: bool,
    exposed: bool,
    exposed_stage: bool,
    raft: bool,
    artifacts: bool,
}

fn scan_generation_namespaces(
    lease: &AgentHostRootLease,
) -> Result<BTreeMap<AgentId, GenerationFiles>, SharedAgentHostError> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(lease.root()).map_err(|_| SharedAgentHostError::Unavailable)? {
        let entry = entry.map_err(|_| SharedAgentHostError::Unavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let agent = decode_suffixed_agent(&name, JOURNAL_SUFFIX)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let metadata = entry
            .metadata()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !metadata.is_dir()
            || entry
                .file_type()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_symlink()
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let row = generation_row(&mut files, agent)?;
        if core::mem::replace(&mut row.journal, true) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
    }
    let authority_root = lease.authority_root().map_err(map_outer_lease_error)?;
    for entry in fs::read_dir(authority_root).map_err(|_| SharedAgentHostError::Unavailable)? {
        let entry = entry.map_err(|_| SharedAgentHostError::Unavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let (agent, kind) =
            decode_authority_name(&name).ok_or(SharedAgentHostError::CorruptResidue)?;
        let file_type = entry
            .file_type()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if file_type.is_symlink()
            || (kind == AuthorityFileKind::Artifacts && !file_type.is_dir())
            || (kind != AuthorityFileKind::Artifacts && !file_type.is_file())
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let row = generation_row(&mut files, agent)?;
        let present = match kind {
            AuthorityFileKind::Lock => &mut row.lock,
            AuthorityFileKind::Intent => &mut row.intent,
            AuthorityFileKind::IntentStage => &mut row.intent_stage,
            AuthorityFileKind::Exposure => &mut row.exposed,
            AuthorityFileKind::ExposureStage => &mut row.exposed_stage,
            AuthorityFileKind::Raft => &mut row.raft,
            AuthorityFileKind::Artifacts => &mut row.artifacts,
        };
        if core::mem::replace(present, true) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
    }
    for row in files.values() {
        if !row.intent && !row.intent_stage {
            return Err(SharedAgentHostError::CorruptResidue);
        }
    }
    Ok(files)
}

fn generation_row(
    files: &mut BTreeMap<AgentId, GenerationFiles>,
    agent: AgentId,
) -> Result<&mut GenerationFiles, SharedAgentHostError> {
    if !files.contains_key(&agent) && files.len() == MAX_SHARED_HOST_AGENTS {
        return Err(SharedAgentHostError::CapacityExhausted);
    }
    Ok(files.entry(agent).or_default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorityFileKind {
    Lock,
    Intent,
    IntentStage,
    Exposure,
    ExposureStage,
    Raft,
    Artifacts,
}

fn decode_authority_name(name: &str) -> Option<(AgentId, AuthorityFileKind)> {
    [
        (INTENT_STAGE_SUFFIX, AuthorityFileKind::IntentStage),
        (EXPOSURE_STAGE_SUFFIX, AuthorityFileKind::ExposureStage),
        (INTENT_SUFFIX, AuthorityFileKind::Intent),
        (EXPOSURE_SUFFIX, AuthorityFileKind::Exposure),
        (JOURNAL_LOCK_SUFFIX, AuthorityFileKind::Lock),
        (RAFT_SUFFIX, AuthorityFileKind::Raft),
        (ARTIFACT_SUFFIX, AuthorityFileKind::Artifacts),
    ]
    .into_iter()
    .find_map(|(suffix, kind)| decode_suffixed_agent(name, suffix).map(|agent| (agent, kind)))
}

fn encode_agent_id(agent: AgentId) -> String {
    let mut output = String::with_capacity(64);
    for byte in agent.0 {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_suffixed_agent(name: &str, suffix: &str) -> Option<AgentId> {
    let encoded = name.strip_suffix(suffix)?;
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex(pair[0])? << 4) | decode_hex(pair[1])?;
    }
    let agent = AgentId(bytes);
    (agent != AgentId::ZERO && encode_agent_id(agent) == encoded).then_some(agent)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_raft::EntryKind;

    use super::super::authority::{
        AgentAuthorityBinding, AgentAuthorityClaim, AgentAuthorityReceipt, ED25519_SIGNATURE_BYTES,
        ed25519_public_key_wire,
    };
    use super::super::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature,
    };
    use super::super::contract::RuntimePackageContract;
    use super::super::genesis::{
        AgentGenesisAdmissionId, AgentGenesisClaim, AgentGenesisDecision, AgentGenesisEvidence,
        AgentGenesisExpectations, AgentGenesisLocator, AgentGenesisProposal, AgentReplicaCommittee,
        AgentReplicaMember, derive_replica_raft_slot,
    };
    use super::super::journal::{
        ReplayInput, ReplayOperation, system_genesis_artifact_closure_commitment,
        system_genesis_post_create_state_commitment,
    };
    use super::super::package::{Package, PackageManifest};
    use super::super::standard::StandardAgentRuntime;
    use super::super::wire::encode_standard_runtime_state;
    use super::super::{
        AgentConfig, AgentReplica, AgentRuntime, LifecycleAuthorityAdmission, LifecycleRequest,
        PackageKind, RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, PrincipalId,
        ProducerId, ProgramId, SpaceId, artifact_hash, task_dependencies_hash,
    };

    const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vos_shared_host_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            self.0.join("agents")
        }

        fn lock(&self) -> PathBuf {
            self.0.join("shared-host.lock")
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct StaticTrust(AgentAuthorityBinding);

    impl AgentTrustProvider for StaticTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(20)
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            Some(self.0.clone())
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }

        fn use_native_standard_runtime_for_test(&self) -> bool {
            true
        }
    }

    struct AcceptFinality;

    impl AgentGenesisFinalityVerifier for AcceptFinality {
        fn verify_finalized(
            &self,
            _provision: &AgentGenesisProvision,
        ) -> Result<(), AgentGenesisFinalityError> {
            Ok(())
        }
    }

    struct SigningMerge(SigningKey);

    impl LocalMergeAuthenticator for SigningMerge {
        fn node(&self) -> NodeId {
            NodeId::of_authenticated_peer(&peer_id(&self.0))
        }

        fn sign_event(&self, event: &mut MergeEvent) -> bool {
            if event.author != self.node() || !event.signature.is_empty() {
                return false;
            }
            event.signature = self.0.sign(&event.signing_message().0).to_bytes().to_vec();
            true
        }

        fn verify_event(&self, event: &MergeEvent) -> bool {
            event.author == self.node() && event.signature.len() == ED25519_SIGNATURE_BYTES
        }
    }

    struct Fixture {
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        authority: AgentAuthorityBinding,
        committee_authority: CommitteeChangeAuthorityBinding,
        replica_keys: Vec<SigningKey>,
        agent: AgentId,
        space: SpaceId,
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn peer_id(key: &SigningKey) -> Vec<u8> {
        let mut peer = PEER_ID_PREFIX.to_vec();
        peer.extend_from_slice(&key.verifying_key().to_bytes());
        peer
    }

    fn replica_member(key: &SigningKey, role: ReplicaRole) -> AgentReplicaMember {
        let peer = peer_id(key);
        let public_key = key.verifying_key().to_bytes();
        AgentReplicaMember::new(
            AgentReplica {
                node: NodeId::of_authenticated_peer(&peer),
                principal: PrincipalId::of_public_key(&public_key),
                role,
            },
            peer.clone(),
            public_key,
            (role == ReplicaRole::Voter).then(|| derive_replica_raft_slot(&peer)),
        )
        .unwrap()
    }

    fn deployment_signature(byte: u8) -> DeploymentSignature {
        let public_key = vec![byte; 32];
        DeploymentSignature {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: vec![byte; ED25519_SIGNATURE_BYTES],
        }
    }

    fn runtime_package() -> Package {
        let pvm = include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec();
        let generated_interfaces = b"shared-host-runtime-interface".to_vec();
        let schemas = b"shared-host-runtime-schema".to_vec();
        let package = Package {
            manifest: PackageManifest {
                name: "shared-host-runtime".into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: RuntimePackageContract::canonical(),
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &[]),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: deployment_signature(0x71),
        };
        package.validate().unwrap();
        package
    }

    fn authority_binding(key: &SigningKey) -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire(key.verifying_key().to_bytes());
        AgentAuthorityBinding {
            agent: AgentId([0xa1; 32]),
            actor: ActorId([0xa2; 32]),
            deployment: DeploymentId([0xa3; 32]),
            program: ProgramId([0xa4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn committee_authority_binding(key: &SigningKey) -> CommitteeChangeAuthorityBinding {
        let public_key = key.verifying_key().to_bytes();
        CommitteeChangeAuthorityBinding::new(
            crate::agent_sdk::Hash([0xe2; 32]),
            crate::agent_sdk::authority::AuthorityIssuer {
                principal: crate::agent_sdk::PrincipalId([0xe3; 32]),
                actor: crate::agent_sdk::ActorId([0xe4; 32]),
                deployment: crate::agent_sdk::DeploymentId([0xe5; 32]),
                program: crate::agent_sdk::ProgramId([0xe6; 32]),
                producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
            },
            crate::agent_sdk::DeploymentId([0xe7; 32]),
            public_key,
            41,
        )
        .unwrap()
    }

    fn fixture(nonce_byte: u8) -> Fixture {
        let space = SpaceId([0x11; 32]);
        let owner = PrincipalId([0x12; 32]);
        let nonce = Hash([nonce_byte; 32]);
        let agent = AgentId::derive(space, owner, nonce.as_bytes());
        let authority_key = key(0x41);
        let authority = authority_binding(&authority_key);
        let package = runtime_package();
        let replica_keys = vec![key(0x31), key(0x32), key(0x33)];
        let mut members = vec![
            replica_member(&replica_keys[0], ReplicaRole::Voter),
            replica_member(&replica_keys[1], ReplicaRole::Voter),
            replica_member(&replica_keys[2], ReplicaRole::Observer),
        ];
        members.sort_by_key(|member| member.replica().node);
        let config = AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: package.deployment_id(),
                runtime_program: package.manifest.program,
                runtime_producer: package.deployment_signature.producer,
            },
            creation_nonce: nonce,
            authority: authority.clone(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(&package.encode()),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: members.iter().map(AgentReplicaMember::replica).collect(),
        };
        config.validate().unwrap();
        let inner = LifecycleRequest::Create(config.clone());
        let claim = AgentAuthorityClaim {
            authority: authority.clone(),
            space,
            agent,
            principal: owner,
            credential: CredentialId([0x24; 32]),
            capability: CapabilityId::named("agent.create.shared"),
            operation: inner.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 30,
        };
        let receipt = AgentAuthorityReceipt {
            signature: authority_key
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        };
        let authorized = LifecycleRequest::Authorized {
            admission: LifecycleAuthorityAdmission {
                receipt,
                observed_slot: 20,
            },
            request: Box::new(inner.clone()),
        };
        let runtime = RuntimeBinding {
            space,
            agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime: runtime.clone(),
            operation: ReplayOperation::Management {
                request: authorized.clone(),
            },
        };
        create.validate().unwrap();
        let mut standard = StandardAgentRuntime::new();
        standard.apply(authorized).unwrap();
        let post_create = encode_standard_runtime_state(&standard.snapshot());
        let catalog_reference = config.runtime_package.clone();
        let expectations = AgentGenesisExpectations::new(
            runtime.commitment(),
            inner.commitment(),
            system_genesis_post_create_state_commitment(&post_create).unwrap(),
            system_genesis_artifact_closure_commitment(core::slice::from_ref(&catalog_reference))
                .unwrap(),
            1,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator { space, agent },
            create,
            expectations,
            vec![catalog_reference.clone()],
        )
        .unwrap();
        let replicas =
            AgentReplicaCommittee::new(space, agent, AgentProfile::Shared, members).unwrap();
        let system_key = key(0x51);
        let system_member = AuthorityCommitteeMember::new(
            NodeId([0x52; 32]),
            system_key.verifying_key().to_bytes(),
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = system_member.signer();
        let system_committee =
            AuthorityCommittee::new(space, authority.commitment(), 1, None, vec![system_member])
                .unwrap();
        let genesis_claim = AgentGenesisClaim::new(
            authority.agent,
            AgentJournalGenesisId::new([0x92; 32]),
            AgentGenesisAdmissionId::from_bytes([0x93; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            system_committee.authority_binding(),
            system_committee.epoch(),
            system_committee.commitment(),
            genesis_claim.authority_claim(),
        );
        let signature =
            AuthoritySignature::new(signer, system_key.sign(&message.0).to_bytes()).unwrap();
        let certificate = AuthorityQuorumCertificate::new(
            &system_committee,
            genesis_claim.authority_claim(),
            vec![signature],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(genesis_claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(proposal, replicas, evidence, decision).unwrap();
        let catalog = vec![RuntimeBlob {
            reference: catalog_reference,
            bytes: package.encode(),
        }];
        Fixture {
            provision,
            catalog,
            authority,
            committee_authority: committee_authority_binding(&key(0xe1)),
            replica_keys,
            agent,
            space,
        }
    }

    fn open_host(directory: &TempDirectory, fixture: &Fixture) -> SharedAgentHost {
        let merge_key = fixture
            .replica_keys
            .iter()
            .find(|key| {
                NodeId::of_authenticated_peer(&peer_id(key))
                    == fixture.provision.replicas().members()[0].replica().node
            })
            .unwrap()
            .clone();
        SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node: NodeId::of_authenticated_peer(&peer_id(&merge_key)),
            },
            Arc::new(StaticTrust(fixture.authority.clone())),
            Arc::new(SigningMerge(merge_key)),
            Arc::new(AcceptFinality),
        )
        .unwrap()
    }

    #[test]
    fn filesystem_host_provisions_applies_committed_slot_and_reopens_exact_generation() {
        let directory = TempDirectory::new("provision_reopen_apply");
        let fixture = fixture(0x13);
        let mut host = open_host(&directory, &fixture);
        assert!(host.is_empty());
        let status = host
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        assert_eq!(status.identity.agent, fixture.agent);
        assert_eq!(status.replicas.len(), 3);
        assert_eq!(status.applied_slots, 0);
        assert_eq!(
            host.require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        assert_eq!(
            host.request_snapshot_compaction(fixture.agent),
            Err(SharedAgentHostError::SnapshotUnsupported)
        );
        let index = host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );
        let route = host.physical_route(fixture.agent).unwrap();
        let generation = status.generation;
        drop(host);

        let mut reopened = open_host(&directory, &fixture);
        let recovered = reopened.show(fixture.agent).unwrap().unwrap();
        assert_eq!(recovered.generation, generation);
        assert_eq!(recovered.replication_id, route.replication_id);
        assert_eq!(recovered.applied_slots, 1);
        assert_eq!(reopened.list().unwrap(), vec![recovered]);
        assert_eq!(
            reopened.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Idle
        );
    }

    #[test]
    fn discovery_rejects_unknown_authority_namespace_residue() {
        let directory = TempDirectory::new("unknown_namespace");
        let fixture = fixture(0x14);
        let mut host = open_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let authority_root = host.lease.authority_root().unwrap().to_path_buf();
        drop(host);
        fs::write(authority_root.join("unknown-residue"), b"ambiguous").unwrap();
        let error = match SharedAgentHost::reopen(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node: NodeId::of_authenticated_peer(&peer_id(
                    fixture
                        .replica_keys
                        .iter()
                        .find(|key| {
                            NodeId::of_authenticated_peer(&peer_id(key))
                                == fixture.provision.replicas().members()[0].replica().node
                        })
                        .unwrap(),
                )),
            },
            Arc::new(StaticTrust(fixture.authority.clone())),
            Arc::new(SigningMerge(
                fixture
                    .replica_keys
                    .iter()
                    .find(|key| {
                        NodeId::of_authenticated_peer(&peer_id(key))
                            == fixture.provision.replicas().members()[0].replica().node
                    })
                    .unwrap()
                    .clone(),
            )),
            Arc::new(AcceptFinality),
        ) {
            Ok(_) => panic!("ambiguous namespace was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, SharedAgentHostError::CorruptResidue);
    }
}
