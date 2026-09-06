//! Bounded production host boundary for ordinary Shared Agents.
//!
//! Every hosted Agent owns one full-identity journal directory, one
//! generation-bound Raft database, and one generation-bound artifact staging
//! directory.  Opening the host rechecks system-Agent finality, package trust,
//! every durable namespace, and the journal/Raft cross-store binding before an
//! Agent becomes discoverable.
//!
//! This module deliberately does not attach the service-oriented Raft worker
//! or singleton service CRDT router. The clean network owner attaches the
//! Agent-specific full-identity worker explicitly and reconstructs that
//! process-only state after restart. Agent checkpoint candidates,
//! authenticated installation, and bounded journal retirement remain driven
//! through this host boundary.

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
use super::shared_commit::{SharedAgentSnapshotCertificate, SharedAgentSnapshotClaim};
use super::shared_journal_driver::{
    FileSharedArtifactStager, SharedArtifactStagerError, SharedJournalAgentDriver,
    SharedJournalDriverError, SharedMergeObject, SharedPhysicalApplyOutcome,
    install_immutable_file, read_regular_bounded,
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
    SnapshotBoundaryRequired,
    SnapshotCertificateInvalid,
    SnapshotStale,
    SnapshotReplay,
    SnapshotEvidenceLimit,
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
    /// The exact active generation/committee is owned by the clean
    /// `/vos/agent/1.0.0` route directory. This is process state only and is
    /// intentionally reconstructed after every restart.
    Attached,
}

/// Durable Agent-specific snapshot state. This never describes the generic
/// service snapshot format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentSnapshotState {
    None,
    Installed {
        raft_index: u64,
        raft_term: u64,
        certificate: Hash,
    },
}

/// Successful exact snapshot installation. Journal cleanup is intentionally
/// reported separately by the bounded compaction API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentSnapshotInstall {
    pub raft_index: u64,
    pub raft_term: u64,
    pub certificate: Hash,
    pub journal_heads: super::journal::JournalHeadsId,
}

/// Opaque result of exact physical snapshot-candidate reconstruction.
///
/// Only [`SharedAgentHost::request_snapshot_compaction`] can construct this
/// token. It proves that this host compared the complete claim with its bound
/// journal and Raft generation. A remote voter must still reconstruct and
/// validate the authenticated evidence independently before signing; the
/// composite-network evidence exchange is not attached by this host.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentSnapshotCandidate {
    claim: SharedAgentSnapshotClaim,
    message: Hash,
}

impl VerifiedSharedAgentSnapshotCandidate {
    fn from_reconstructed(claim: SharedAgentSnapshotClaim) -> Self {
        let message = SharedAgentSnapshotCertificate::signing_message(
            claim.active_committee().id(),
            claim.commitment(),
        );
        Self { claim, message }
    }

    pub const fn claim(&self) -> &SharedAgentSnapshotClaim {
        &self.claim
    }

    /// Domain-separated bytes an independently validating voter may sign.
    pub const fn signing_message(&self) -> Hash {
        self.message
    }
}

/// Explicit bounds for one resumable post-snapshot journal cleanup pass.
/// Shared-binding validation additionally scans at most the fixed,
/// fail-closed Shared-binding namespace capacity; `max_binding_unlinks` caps
/// mutations, while the remaining fields cap generic journal traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentCompactionLimits {
    /// Maximum authenticated Shared-binding files physically removed.
    pub max_binding_unlinks: usize,
    pub max_index_nodes: usize,
    pub max_marked_objects: usize,
    pub max_marked_blobs: usize,
    pub max_scanned_files: usize,
    pub max_scanned_bytes: u64,
    pub max_unlinks: usize,
}

/// Exact physical work completed in one bounded pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentCompaction {
    pub bindings_removed: usize,
    pub bindings_remaining: usize,
    pub objects_removed: usize,
    pub blobs_removed: usize,
    pub aliases_removed: usize,
    pub resumed: bool,
    pub complete: bool,
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

/// Authenticated next-committee route visible while the durable committee
/// transition is prepared or joint. These replicas may be transport/Merge
/// members before the stable leg makes them the active journal authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedCommitteeTransitionRoute {
    pub next_committee: super::genesis::AgentReplicaCommitteeId,
    pub next_replicas: Vec<SharedReplicaRoute>,
    pub joint: bool,
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
    pub committee_transition: Option<SharedCommitteeTransitionRoute>,
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

/// Process-only ownership of the live network/storage boundary. Every
/// non-detached state blocks snapshot database replacement and journal GC:
/// both operations would invalidate a worker cache or anti-entropy walk even
/// while route setup or ordered shutdown is still in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportLeaseState {
    Attaching,
    Attached,
    Stopping,
}

/// Serialized owner of a directory containing independently durable Shared
/// Agent replicas. Callers may place this behind their own command queue; the
/// type itself intentionally requires `&mut self` for every mutation.
pub struct SharedAgentHost {
    lease: AgentHostRootLease,
    agents: BTreeMap<AgentId, HostedSharedAgent>,
    transport_leases: BTreeMap<AgentId, TransportLeaseState>,
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
            transport_leases: BTreeMap::new(),
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
            return status_for(existing, self.transport_is_attached(agent));
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
        let status = status_for(&hosted, false)?;
        self.agents.insert(agent, hosted);
        Ok(status)
    }

    pub fn list(&self) -> Result<Vec<SharedAgentStatus>, SharedAgentHostError> {
        self.agents
            .iter()
            .map(|(agent, hosted)| status_for(hosted, self.transport_is_attached(*agent)))
            .collect()
    }

    pub fn show(&self, agent: AgentId) -> Result<Option<SharedAgentStatus>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .map(|hosted| status_for(hosted, self.transport_is_attached(agent)))
            .transpose()
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

    pub(crate) fn prepare_clean_ordered(
        &self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_clean_ordered(work, authority)
            .map_err(map_driver_error)
    }

    pub(crate) fn apply_clean_local(
        &mut self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .apply_clean_local(work, authority)
            .map_err(map_driver_error)
    }

    pub(crate) fn apply_clean_merge(
        &mut self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .apply_clean_merge(work, authority)
            .map_err(map_driver_error)
    }

    pub(crate) fn take_clean_ordered_result(
        &mut self,
        agent: AgentId,
        input: super::journal::ReplayInputId,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .take_clean_ordered_result(input)
            .map_err(map_driver_error)
    }

    pub(crate) fn try_take_clean_ordered_result(
        &mut self,
        agent: AgentId,
        input: super::journal::ReplayInputId,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedAgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .try_take_clean_ordered_result(input)
            .map_err(map_driver_error)
    }

    pub(crate) fn raft_database(
        &self,
        agent: AgentId,
    ) -> Result<Arc<Database>, SharedAgentHostError> {
        Ok(self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .ledger()
            .database())
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

    /// Persist one independently authenticated Merge object without moving
    /// the journal head. Anti-entropy can therefore resume a parent walk after
    /// timeout or process restart without treating mere storage as commit.
    pub(crate) fn stage_merge(
        &mut self,
        agent: AgentId,
        event: &MergeEvent,
    ) -> Result<bool, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .stage_merge(event)
            .map_err(map_driver_error)
    }

    pub(crate) fn merge_object(
        &self,
        agent: AgentId,
        event: MergeEventId,
    ) -> Result<SharedMergeObject, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .merge_object(event)
            .map_err(map_driver_error)
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

    /// Require a live exact-generation clean network attachment. A durable
    /// Raft file alone is never attachment evidence, and reopen begins
    /// detached until the route owner is installed again.
    pub fn require_transport(&self, agent: AgentId) -> Result<(), SharedAgentHostError> {
        if !self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        if self.transport_is_attached(agent) {
            Ok(())
        } else {
            Err(SharedAgentHostError::TransportNotAttached)
        }
    }

    fn transport_is_attached(&self, agent: AgentId) -> bool {
        self.transport_leases.get(&agent) == Some(&TransportLeaseState::Attached)
    }

    pub(crate) fn reserve_transport_attachment(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        if !self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        match self.transport_leases.entry(agent) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(TransportLeaseState::Attaching);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => Err(SharedAgentHostError::Conflict),
        }
    }

    pub(crate) fn mark_transport_attached(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        match self.transport_leases.get_mut(&agent) {
            Some(state @ TransportLeaseState::Attaching) => {
                *state = TransportLeaseState::Attached;
                Ok(())
            }
            _ => Err(SharedAgentHostError::Conflict),
        }
    }

    pub(crate) fn mark_transport_stopping(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        match self.transport_leases.get_mut(&agent) {
            Some(state @ TransportLeaseState::Attached) => {
                *state = TransportLeaseState::Stopping;
                Ok(())
            }
            _ => Err(SharedAgentHostError::Conflict),
        }
    }

    /// Release a failed setup or a completely stopped attachment. An active
    /// attachment cannot be cleared directly: its owner must first enter
    /// `Stopping` and drain the worker and handler leases.
    pub(crate) fn release_transport_attachment(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        match self.transport_leases.get(&agent) {
            Some(TransportLeaseState::Attaching | TransportLeaseState::Stopping) => {
                self.transport_leases.remove(&agent);
                Ok(())
            }
            _ => Err(SharedAgentHostError::Conflict),
        }
    }

    /// Derive and locally verify an exact Agent checkpoint candidate without
    /// mutation. Only the opaque result exposes the signing message; decoding
    /// an unsigned claim is never signing authority. Remote voters must also
    /// validate authenticated candidate evidence before signing. That
    /// composite-network evidence exchange is not attached by this host.
    pub fn request_snapshot_compaction(
        &mut self,
        agent: AgentId,
    ) -> Result<VerifiedSharedAgentSnapshotCandidate, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let claim = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .snapshot_candidate()
            .map_err(map_driver_error)?;
        Ok(VerifiedSharedAgentSnapshotCandidate::from_reconstructed(
            claim,
        ))
    }

    /// Verify, publish, and atomically install one exact Agent snapshot.
    pub fn install_snapshot(
        &mut self,
        agent: AgentId,
        certificate: &SharedAgentSnapshotCertificate,
    ) -> Result<SharedAgentSnapshotInstall, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        // The current full-NodeId worker intentionally has no generic byte
        // snapshot bridge for an authenticated Agent journal certificate.
        // Mutating its shared database underneath a live storage cache would
        // desynchronize the worker and make its next reopen fail closed.
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let installed = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .install_snapshot(certificate)
            .map_err(map_driver_error)?;
        Ok(SharedAgentSnapshotInstall {
            raft_index: installed.claim.raft_index(),
            raft_term: installed.claim.raft_term(),
            certificate: installed.certificate_commitment,
            journal_heads: installed.claim.journal_heads(),
        })
    }

    pub fn install_snapshot_bytes(
        &mut self,
        agent: AgentId,
        bytes: &[u8],
    ) -> Result<SharedAgentSnapshotInstall, SharedAgentHostError> {
        if bytes.len() > super::shared_commit::MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let certificate = SharedAgentSnapshotCertificate::decode(bytes)
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        if certificate.encode() != bytes {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        self.install_snapshot(agent, &certificate)
    }

    /// Resume fail-closed retirement of Shared commit bindings and bounded
    /// retirement of unreachable journal objects/blobs after a snapshot is
    /// durably installed. Binding validation is limited by the fixed
    /// namespace capacity, while `max_binding_unlinks` bounds mutations. A
    /// false `complete` is backpressure, never a claim that cleanup finished.
    pub fn compact_snapshot(
        &mut self,
        agent: AgentId,
        limits: SharedAgentCompactionLimits,
    ) -> Result<SharedAgentCompaction, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        // Live anti-entropy may have authenticated parent objects durably
        // staged but not yet reachable from Heads. Generic journal GC quite
        // correctly treats those as garbage, so compaction requires the exact
        // generation transport to be retired first. Reattachment resumes from
        // every staged object which survived a crash; an operator-triggered
        // detached GC deliberately chooses to discard that cache and refetch.
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        if limits.max_binding_unlinks == 0 {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let outcome = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .compact_snapshot(
                limits.max_binding_unlinks,
                super::journal_store::GcLimits {
                    max_index_nodes: limits.max_index_nodes,
                    max_marked_objects: limits.max_marked_objects,
                    max_marked_blobs: limits.max_marked_blobs,
                    max_scanned_files: limits.max_scanned_files,
                    max_scanned_bytes: limits.max_scanned_bytes,
                    max_unlinks_per_run: limits.max_unlinks,
                },
            )
            .map_err(map_driver_error)?;
        let journal = outcome.journal;
        Ok(SharedAgentCompaction {
            bindings_removed: outcome.bindings_removed,
            bindings_remaining: outcome.bindings_remaining,
            objects_removed: journal.map_or(0, |gc| gc.objects_removed),
            blobs_removed: journal.map_or(0, |gc| gc.blobs_removed),
            aliases_removed: journal.map_or(0, |gc| gc.aliases_removed),
            resumed: journal.is_some_and(|gc| gc.resumed),
            complete: outcome.bindings_remaining == 0 && journal.is_some_and(|gc| gc.complete),
        })
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

fn status_for(
    hosted: &HostedSharedAgent,
    transport_attached: bool,
) -> Result<SharedAgentStatus, SharedAgentHostError> {
    let identity = hosted.driver.identity().map_err(map_driver_error)?;
    let generation = hosted.driver.ledger().generation();
    let route = hosted.driver.active_route().map_err(map_driver_error)?;
    let committee_state = hosted
        .driver
        .network_committee_state()
        .map_err(map_driver_error)?;
    let committee = &committee_state.active;
    let local_role = hosted.driver.local_role().map_err(map_driver_error)?;
    let lanes = hosted.driver.engine_lanes().map_err(map_driver_error)?;
    let (applied_slots, remaining_slots, reservation_pending) =
        hosted.driver.capacity().map_err(map_driver_error)?;
    let snapshots = match hosted.driver.current_snapshot().map_err(map_driver_error)? {
        Some(snapshot) => SharedAgentSnapshotState::Installed {
            raft_index: snapshot.claim.raft_index(),
            raft_term: snapshot.claim.raft_term(),
            certificate: snapshot.certificate_commitment,
        },
        None => SharedAgentSnapshotState::None,
    };
    let replica_route = |member: &super::genesis::AgentReplicaMember| SharedReplicaRoute {
        node: member.replica().node,
        role: member.replica().role,
        peer_id: member.peer_id().to_vec(),
        ed25519_public_key: *member.ed25519_public_key(),
        raft_slot: member.raft_slot(),
    };
    let replicas = committee.members().iter().map(replica_route).collect();
    let committee_transition = committee_state
        .next
        .map(|next| SharedCommitteeTransitionRoute {
            next_committee: next.id(),
            next_replicas: next.members().iter().map(replica_route).collect(),
            joint: committee_state.joint,
        });
    Ok(SharedAgentStatus {
        identity,
        generation,
        route,
        replication_id: generation.replication_id(),
        local_role,
        replicas,
        committee_transition,
        engines: SharedAgentEnginePlan {
            control_raft: true,
            linear_raft: lanes.contains(StateLane::Linear),
            merge: lanes.contains(StateLane::Merge),
            local: lanes.contains(StateLane::Local),
        },
        applied_slots,
        remaining_slots,
        reservation_pending,
        transport: if transport_attached {
            SharedAgentTransportState::Attached
        } else {
            SharedAgentTransportState::NotAttached
        },
        snapshots,
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
        SharedJournalDriverError::Executor(
            super::local_journal_driver::LocalReplayExecutorError::TrustUnavailable,
        ) => SharedAgentHostError::Unavailable,
        SharedJournalDriverError::Executor(
            super::local_journal_driver::LocalReplayExecutorError::InvalidAuthority
            | super::local_journal_driver::LocalReplayExecutorError::InvalidRequest,
        ) => SharedAgentHostError::InvalidProvision,
        SharedJournalDriverError::Snapshot(
            super::shared_commit::SharedCommitError::WrongSnapshotClaim,
        ) => SharedAgentHostError::SnapshotReplay,
        SharedJournalDriverError::Snapshot(_) => SharedAgentHostError::SnapshotCertificateInvalid,
        SharedJournalDriverError::InvalidArtifactBatch
        | SharedJournalDriverError::CrossStoreMismatch
        | SharedJournalDriverError::Executor(_)
        | SharedJournalDriverError::Replay(_)
        | SharedJournalDriverError::Store(_) => SharedAgentHostError::CorruptResidue,
    }
}

fn map_ledger_error(error: AgentRaftApplicationErrorV2) -> SharedAgentHostError {
    match error {
        AgentRaftApplicationErrorV2::BacklogLimit => SharedAgentHostError::CapacityExhausted,
        AgentRaftApplicationErrorV2::SnapshotBoundaryRequired => {
            SharedAgentHostError::SnapshotBoundaryRequired
        }
        AgentRaftApplicationErrorV2::SnapshotCertificateInvalid => {
            SharedAgentHostError::SnapshotCertificateInvalid
        }
        AgentRaftApplicationErrorV2::SnapshotStale => SharedAgentHostError::SnapshotStale,
        AgentRaftApplicationErrorV2::SnapshotReplay => SharedAgentHostError::SnapshotReplay,
        AgentRaftApplicationErrorV2::SnapshotEvidenceLimit => {
            SharedAgentHostError::SnapshotEvidenceLimit
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
        ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityClaim,
        AgentAuthorityReceipt, ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use super::super::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature,
    };
    use super::super::contract::RuntimePackageContract;
    use super::super::execution::{ActorInvocation, ActorInvocationAuth};
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
    use super::super::shared_commit::ReplicaCommitSignature;
    use super::super::standard::StandardAgentRuntime;
    use super::super::wire::encode_standard_runtime_state;
    use super::super::{
        AgentConfig, AgentReplica, AgentRuntime, LifecycleAuthorityAdmission, LifecycleRequest,
        MethodMode, PackageKind, RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, InvocationId,
        PrincipalId, ProducerId, ProgramId, SpaceId, artifact_hash, task_dependencies_hash,
    };

    const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    #[test]
    fn merge_store_capacity_errors_have_one_stable_host_projection() {
        for error in [
            super::super::journal_store::JournalStoreError::Backpressure,
            super::super::journal_store::JournalStoreError::LimitExceeded,
        ] {
            let driver_error: SharedJournalDriverError = error.into();
            assert_eq!(
                map_driver_error(driver_error),
                SharedAgentHostError::CapacityExhausted
            );
        }
    }

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
        authority_key: SigningKey,
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
            authority_key,
            committee_authority: committee_authority_binding(&key(0xe1)),
            replica_keys,
            agent,
            space,
        }
    }

    fn open_host(directory: &TempDirectory, fixture: &Fixture) -> SharedAgentHost {
        open_host_on_node(
            directory,
            fixture,
            fixture.provision.replicas().members()[0].replica().node,
        )
    }

    fn open_host_on_node(
        directory: &TempDirectory,
        fixture: &Fixture,
        node: NodeId,
    ) -> SharedAgentHost {
        let merge_key = fixture
            .replica_keys
            .iter()
            .find(|key| NodeId::of_authenticated_peer(&peer_id(key)) == node)
            .unwrap()
            .clone();
        SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node,
            },
            Arc::new(StaticTrust(fixture.authority.clone())),
            Arc::new(SigningMerge(merge_key)),
            Arc::new(AcceptFinality),
        )
        .unwrap()
    }

    #[cfg(feature = "network")]
    fn live_network(seed: u8, listen: Vec<libp2p::Multiaddr>) -> Arc<crate::network::Network> {
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        let peer = keypair.public().to_peer_id();
        Arc::new(crate::network::Network::start(
            crate::network::NetworkConfig {
                keypair,
                local_prefix: crate::network::derive_node_prefix(&peer),
                listen,
                bootstrap: Vec::new(),
                auto_dial_mdns: false,
            },
        ))
    }

    #[cfg(feature = "network")]
    fn wait_until(timeout: std::time::Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if predicate() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[cfg(feature = "network")]
    fn join_live_network(network: Arc<crate::network::Network>) {
        network.shutdown();
        assert!(wait_until(std::time::Duration::from_secs(5), || {
            Arc::strong_count(&network) == 1
        }));
        Arc::try_unwrap(network).ok().unwrap().join();
    }

    fn physical_bytes(directory: &TempDirectory) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, at: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(at)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    visit(root, &path, output);
                } else if kind.is_file() {
                    output.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                } else {
                    panic!("unexpected test namespace entry: {path:?}");
                }
            }
        }

        let mut output = BTreeMap::new();
        visit(&directory.0, &directory.0, &mut output);
        output
    }

    fn provision_apply_candidate(
        host: &mut SharedAgentHost,
        fixture: &Fixture,
        term: u64,
    ) -> VerifiedSharedAgentSnapshotCandidate {
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(term, authorized_management(fixture, 2, 0xc1))
            .unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );
        host.request_snapshot_compaction(fixture.agent).unwrap()
    }

    fn append_local_invocation_and_acknowledgement(
        host: &mut SharedAgentHost,
        fixture: &Fixture,
        discriminator: u8,
    ) {
        let invocation = ActorInvocation {
            invocation: InvocationId([discriminator; 32]),
            actor: ActorId([discriminator.wrapping_add(1); 32]),
            incarnation: Hash([discriminator.wrapping_add(2); 32]),
            deployment: DeploymentId([discriminator.wrapping_add(3); 32]),
            program: ProgramId([discriminator.wrapping_add(4); 32]),
            mode: MethodMode::Local,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![discriminator],
            availability: Vec::new(),
            gas: 1_000,
        };
        let claim = ActorInvocationClaim {
            authority: fixture.authority.clone(),
            space: fixture.space,
            agent: fixture.agent,
            principal: None,
            credential: None,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from: 10,
            valid_until: 30,
        };
        let receipt = ActorInvocationReceipt {
            signature: fixture
                .authority_key
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        };
        host.agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_acknowledged_local_for_test(
                ReplayOperation::Invoke {
                    invocation: invocation.clone(),
                    authority: receipt.clone(),
                    observed_slot: 20,
                },
                ReplayOperation::Acknowledge {
                    invocation,
                    authority: receipt,
                },
            )
            .unwrap();
    }

    #[cfg(feature = "network")]
    fn publish_merge_invocation(
        host: &mut SharedAgentHost,
        fixture: &Fixture,
        discriminator: u8,
    ) -> MergeEventId {
        let invocation = ActorInvocation {
            invocation: InvocationId([discriminator; 32]),
            actor: ActorId([discriminator.wrapping_add(1); 32]),
            incarnation: Hash([discriminator.wrapping_add(2); 32]),
            deployment: DeploymentId([discriminator.wrapping_add(3); 32]),
            program: ProgramId([discriminator.wrapping_add(4); 32]),
            mode: MethodMode::Merge,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![discriminator],
            availability: Vec::new(),
            gas: 1_000,
        };
        let claim = ActorInvocationClaim {
            authority: fixture.authority.clone(),
            space: fixture.space,
            agent: fixture.agent,
            principal: None,
            credential: None,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from: 10,
            valid_until: 30,
        };
        let receipt = ActorInvocationReceipt {
            signature: fixture
                .authority_key
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        };
        host.agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .publish_merge_for_test(ReplayOperation::Invoke {
                invocation,
                authority: receipt,
                observed_slot: 20,
            })
            .unwrap()
    }

    fn snapshot_certificate(
        candidate: &VerifiedSharedAgentSnapshotCandidate,
        fixture: &Fixture,
    ) -> SharedAgentSnapshotCertificate {
        snapshot_certificate_with_message(candidate, fixture, candidate.signing_message())
    }

    fn authorized_management(
        fixture: &Fixture,
        sequence: u64,
        discriminator: u8,
    ) -> ReplayOperation {
        let request = LifecycleRequest::Suspend {
            actor: ActorId([discriminator; 32]),
            expected_deployment: DeploymentId([discriminator.wrapping_add(1); 32]),
        };
        let claim = AgentAuthorityClaim {
            authority: fixture.authority.clone(),
            space: fixture.space,
            agent: fixture.agent,
            principal: PrincipalId([0x12; 32]),
            credential: CredentialId([0x24; 32]),
            capability: CapabilityId::named(request.required_capability().unwrap()),
            operation: request.commitment(),
            sequence,
            valid_from: 10,
            valid_until: 30,
        };
        let receipt = AgentAuthorityReceipt {
            signature: fixture
                .authority_key
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        };
        ReplayOperation::Management {
            request: LifecycleRequest::Authorized {
                admission: LifecycleAuthorityAdmission {
                    receipt,
                    observed_slot: 20,
                },
                request: Box::new(request),
            },
        }
    }

    fn snapshot_certificate_with_message(
        candidate: &VerifiedSharedAgentSnapshotCandidate,
        fixture: &Fixture,
        message: Hash,
    ) -> SharedAgentSnapshotCertificate {
        let committee = candidate.claim().active_committee();
        let mut signatures = fixture
            .replica_keys
            .iter()
            .filter_map(|key| {
                let node = NodeId::of_authenticated_peer(&peer_id(key));
                committee
                    .member_by_node(node)
                    .filter(|member| member.replica().role == ReplicaRole::Voter)
                    .map(|_| {
                        ReplicaCommitSignature::new(node, key.sign(&message.0).to_bytes()).unwrap()
                    })
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        SharedAgentSnapshotCertificate::new(candidate.claim().clone(), signatures).unwrap()
    }

    fn compaction_limits(max_unlinks: usize) -> SharedAgentCompactionLimits {
        SharedAgentCompactionLimits {
            max_binding_unlinks: 1,
            max_index_nodes: 10_000,
            max_marked_objects: 10_000,
            max_marked_blobs: 10_000,
            max_scanned_files: 10_000,
            max_scanned_bytes: 64 * 1024 * 1024,
            max_unlinks,
        }
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
        host.reserve_transport_attachment(fixture.agent).unwrap();
        host.mark_transport_attached(fixture.agent).unwrap();
        assert_eq!(host.require_transport(fixture.agent), Ok(()));
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap().transport,
            SharedAgentTransportState::Attached
        );
        host.mark_transport_stopping(fixture.agent).unwrap();
        host.release_transport_attachment(fixture.agent).unwrap();
        assert_eq!(
            host.require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        assert!(matches!(
            host.request_snapshot_compaction(fixture.agent),
            Err(SharedAgentHostError::SnapshotBoundaryRequired)
        ));
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
    fn filesystem_snapshot_is_authenticated_compacted_repeated_and_reopened_with_suffix() {
        let directory = TempDirectory::new("snapshot_compact_restart");
        let fixture = fixture(0x15);
        let mut host = open_host(&directory, &fixture);
        let provisioned = host
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();

        let first_index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(7, authorized_management(&fixture, 2, 0xb1))
            .unwrap();
        assert_eq!(first_index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );

        // The signed checkpoint predecessor must remain distinct from the
        // Ordered publication successor when Local work advanced the head.
        // The rejected invocation plus acknowledgement leaves no live result
        // which could independently block checkpoint creation.
        append_local_invocation_and_acknowledgement(&mut host, &fixture, 0xb3);

        let first_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(first_candidate.claim().ordered().agent(), fixture.agent);
        assert_eq!(first_candidate.claim().raft_index(), 1);
        assert_eq!(first_candidate.claim().local_node(), host.scope().node);
        assert_ne!(
            first_candidate.claim().checkpoint_predecessor(),
            first_candidate.claim().ordered_successor()
        );
        let forged = snapshot_certificate_with_message(
            &first_candidate,
            &fixture,
            Hash::digest(b"vos/test/forged-snapshot-message", &[]),
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &forged),
            Err(SharedAgentHostError::SnapshotCertificateInvalid)
        );
        let after_forgery = host.show(fixture.agent).unwrap().unwrap();
        assert_eq!(after_forgery.applied_slots, 1);
        assert_eq!(after_forgery.snapshots, SharedAgentSnapshotState::None);
        let unchanged = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(unchanged.claim(), first_candidate.claim());

        let first_certificate = snapshot_certificate(&first_candidate, &fixture);
        let first_install = host
            .install_snapshot(fixture.agent, &first_certificate)
            .unwrap();
        assert_eq!(first_install.raft_index, 1);
        assert_eq!(
            host.install_snapshot(fixture.agent, &first_certificate)
                .unwrap(),
            first_install
        );
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap().snapshots,
            SharedAgentSnapshotState::Installed {
                raft_index: 1,
                raft_term: 7,
                certificate: first_certificate.commitment(),
            }
        );

        // All budgets are rejected before either the authenticated binding
        // namespace or the object/blob namespace is touched.
        let status_before_exhaustion = host.show(fixture.agent).unwrap().unwrap();
        let bytes_before_exhaustion = physical_bytes(&directory);
        let mut exhausted = compaction_limits(1);
        exhausted.max_marked_objects = 0;
        assert_eq!(
            host.compact_snapshot(fixture.agent, exhausted),
            Err(SharedAgentHostError::CapacityExhausted)
        );
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap(),
            status_before_exhaustion
        );
        assert_eq!(physical_bytes(&directory), bytes_before_exhaustion);

        let mut complete = false;
        let mut removed = 0;
        for _ in 0..256 {
            let pass = host
                .compact_snapshot(fixture.agent, compaction_limits(1))
                .unwrap();
            removed += pass.bindings_removed
                + pass.objects_removed
                + pass.blobs_removed
                + pass.aliases_removed;
            if pass.complete {
                complete = true;
                break;
            }
        }
        assert!(complete, "bounded checkpoint cleanup did not converge");
        assert!(removed > 0, "checkpoint cleanup retired no physical data");

        // A committed suffix after the retained checkpoint must replay on
        // reopen without the retired Ordered prefix or Raft audit/log rows.
        let second_index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(8, authorized_management(&fixture, 3, 0xb2))
            .unwrap();
        assert_eq!(second_index, 2);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 2 }
        );
        let second_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(
            second_candidate.claim().previous_snapshot(),
            Some(first_certificate.commitment())
        );
        let second_certificate = snapshot_certificate(&second_candidate, &fixture);
        let second_install = host
            .install_snapshot(fixture.agent, &second_certificate)
            .unwrap();
        assert_eq!(second_install.raft_index, 2);
        assert_eq!(
            host.install_snapshot(fixture.agent, &first_certificate),
            Err(SharedAgentHostError::SnapshotStale)
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &second_certificate)
                .unwrap(),
            second_install
        );
        let route = host.physical_route(fixture.agent).unwrap();
        drop(host);

        let reopened = open_host(&directory, &fixture);
        let status = reopened.show(fixture.agent).unwrap().unwrap();
        assert_eq!(status.generation, provisioned.generation);
        assert_eq!(status.replication_id, route.replication_id);
        assert_eq!(status.applied_slots, 2);
        assert_eq!(
            status.snapshots,
            SharedAgentSnapshotState::Installed {
                raft_index: 2,
                raft_term: 8,
                certificate: second_certificate.commitment(),
            }
        );
    }

    #[test]
    fn snapshot_certificate_replay_isolated_by_agent_store_node_and_generation() {
        let fixture = fixture(0x16);
        let directory_a = TempDirectory::new("snapshot_isolation_a");
        let directory_b = TempDirectory::new("snapshot_isolation_b");
        let mut host_a = open_host(&directory_a, &fixture);
        let mut host_b = open_host(&directory_b, &fixture);
        let candidate_a = provision_apply_candidate(&mut host_a, &fixture, 9);
        let candidate_b = provision_apply_candidate(&mut host_b, &fixture, 9);
        assert_eq!(
            candidate_a.claim().raft_index(),
            candidate_b.claim().raft_index()
        );
        assert_eq!(candidate_a.claim().ordered(), candidate_b.claim().ordered());
        assert_ne!(
            candidate_a.claim().journal_store(),
            candidate_b.claim().journal_store()
        );
        let certificate_a = snapshot_certificate(&candidate_a, &fixture);
        let certificate_b = snapshot_certificate(&candidate_b, &fixture);
        assert!(
            certificate_b
                .verify(candidate_b.claim().active_committee(), candidate_b.claim(),)
                .is_ok()
        );

        // A valid quorum certificate for the byte-identical generation in a
        // different physical store cannot publish even a checkpoint blob.
        let status_b = host_b.show(fixture.agent).unwrap().unwrap();
        let bytes_b = physical_bytes(&directory_b);
        assert_eq!(
            host_b.install_snapshot(fixture.agent, &certificate_a),
            Err(SharedAgentHostError::SnapshotReplay)
        );
        assert_eq!(host_b.show(fixture.agent).unwrap().unwrap(), status_b);
        assert_eq!(physical_bytes(&directory_b), bytes_b);

        // Install A, then present B's independently valid quorum certificate
        // at the same Raft index. It is divergent, not a forged signature,
        // and must be rejected before any journal or Raft mutation.
        host_a
            .install_snapshot(fixture.agent, &certificate_a)
            .unwrap();
        let status_a = host_a.show(fixture.agent).unwrap().unwrap();
        let bytes_a = physical_bytes(&directory_a);
        assert_eq!(
            host_a.install_snapshot(fixture.agent, &certificate_b),
            Err(SharedAgentHostError::SnapshotStale)
        );
        assert_eq!(host_a.show(fixture.agent).unwrap().unwrap(), status_a);
        assert_eq!(physical_bytes(&directory_a), bytes_a);

        // The complete local replica identity is signed too. A certificate
        // from A cannot enter another admitted replica's independent store.
        let directory_node = TempDirectory::new("snapshot_isolation_node");
        let alternate_node = fixture.provision.replicas().members()[1].replica().node;
        assert_ne!(alternate_node, candidate_a.claim().local_node());
        let mut host_node = open_host_on_node(&directory_node, &fixture, alternate_node);
        let candidate_node = provision_apply_candidate(&mut host_node, &fixture, 9);
        assert_eq!(candidate_node.claim().local_node(), alternate_node);
        let status_node = host_node.show(fixture.agent).unwrap().unwrap();
        let bytes_node = physical_bytes(&directory_node);
        assert_eq!(
            host_node.install_snapshot(fixture.agent, &certificate_a),
            Err(SharedAgentHostError::SnapshotReplay)
        );
        assert_eq!(host_node.show(fixture.agent).unwrap().unwrap(), status_node);
        assert_eq!(physical_bytes(&directory_node), bytes_node);

        // A distinct Agent necessarily has a distinct full generation route,
        // even under the same space, node keys, and logical slot.
        let other = self::fixture(0x17);
        let directory_other = TempDirectory::new("snapshot_isolation_agent");
        let mut host_other = open_host(&directory_other, &other);
        let candidate_other = provision_apply_candidate(&mut host_other, &other, 9);
        assert_ne!(candidate_other.claim().ordered().agent(), fixture.agent);
        let status_other = host_other.show(other.agent).unwrap().unwrap();
        let bytes_other = physical_bytes(&directory_other);
        assert_eq!(
            host_other.install_snapshot(other.agent, &certificate_a),
            Err(SharedAgentHostError::SnapshotReplay)
        );
        assert_eq!(host_other.show(other.agent).unwrap().unwrap(), status_other);
        assert_eq!(physical_bytes(&directory_other), bytes_other);
    }

    #[test]
    fn live_transport_blocks_snapshot_database_replacement() {
        let fixture = fixture(0x26);
        let directory = TempDirectory::new("snapshot_live_transport");
        let mut host = open_host(&directory, &fixture);
        let candidate = provision_apply_candidate(&mut host, &fixture, 9);
        let certificate = snapshot_certificate(&candidate, &fixture);
        let before = physical_bytes(&directory);

        host.reserve_transport_attachment(fixture.agent).unwrap();
        assert_eq!(
            host.install_snapshot(fixture.agent, &certificate),
            Err(SharedAgentHostError::Conflict),
            "setup must reserve the database before a worker can open it"
        );
        assert_eq!(
            host.compact_snapshot(fixture.agent, compaction_limits(1)),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(
            host.reserve_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict)
        );
        host.mark_transport_attached(fixture.agent).unwrap();
        assert_eq!(
            host.reserve_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(host.require_transport(fixture.agent), Ok(()));
        assert_eq!(
            host.release_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict),
            "an active worker cannot drop its storage lease directly"
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &certificate),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(physical_bytes(&directory), before);

        host.mark_transport_stopping(fixture.agent).unwrap();
        assert_eq!(
            host.reserve_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &certificate),
            Err(SharedAgentHostError::Conflict),
            "ordered shutdown retains the lease until every cache is gone"
        );
        assert_eq!(
            host.compact_snapshot(fixture.agent, compaction_limits(1)),
            Err(SharedAgentHostError::Conflict)
        );
        host.release_transport_attachment(fixture.agent).unwrap();
        assert!(host.install_snapshot(fixture.agent, &certificate).is_ok());
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

    #[cfg(feature = "network")]
    #[test]
    fn authenticated_merge_staging_survives_restart_without_moving_heads() {
        let directory_source = TempDirectory::new("merge_stage_source");
        let directory_target = TempDirectory::new("merge_stage_target");
        let fixture = fixture(0x27);
        let source_node = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[0]));
        let target_node = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[1]));
        let mut source = open_host_on_node(&directory_source, &fixture, source_node);
        let mut target = open_host_on_node(&directory_target, &fixture, target_node);
        for host in [&mut source, &mut target] {
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        }
        let event_id = publish_merge_invocation(&mut source, &fixture, 0xd0);
        let bytes = source.merge_node(fixture.agent, event_id).unwrap().unwrap();
        let event = MergeEvent::decode(&bytes).unwrap();
        let empty_roots = target.merge_roots(fixture.agent).unwrap();

        assert!(target.stage_merge(fixture.agent, &event).unwrap());
        assert_eq!(target.merge_roots(fixture.agent).unwrap(), empty_roots);
        assert!(matches!(
            target.merge_object(fixture.agent, event_id).unwrap(),
            crate::agent::shared_journal_driver::SharedMergeObject::Staged(found) if found == bytes
        ));

        drop(target);
        let mut reopened = open_host_on_node(&directory_target, &fixture, target_node);
        assert_eq!(reopened.merge_roots(fixture.agent).unwrap(), empty_roots);
        assert!(matches!(
            reopened.merge_object(fixture.agent, event_id).unwrap(),
            crate::agent::shared_journal_driver::SharedMergeObject::Staged(found) if found == bytes
        ));
        assert!(matches!(
            reopened.import_merge(fixture.agent, &event).unwrap(),
            SharedAgentApplyOutcome::Applied { .. }
        ));
        assert!(matches!(
            reopened.merge_object(fixture.agent, event_id).unwrap(),
            crate::agent::shared_journal_driver::SharedMergeObject::Published(found) if found == bytes
        ));
    }

    #[cfg(feature = "network")]
    #[test]
    fn observer_attaches_as_authenticated_merge_member_without_a_raft_worker() {
        let directory = TempDirectory::new("clean_network_observer");
        let fixture = fixture(0x2a);
        let observer = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[2]));
        let mut opened = open_host_on_node(&directory, &fixture, observer);
        let status = opened
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        let route = crate::network::agent_protocol::AgentGenerationRoute {
            space: crate::agent_sdk::SpaceId(status.generation.space().0),
            agent: crate::agent_sdk::AgentId(status.generation.agent().0),
            generation: crate::agent_sdk::Hash(status.replication_id),
        };
        let host = Arc::new(std::sync::Mutex::new(opened));
        let network = live_network(0x33, Vec::new());
        let attachment =
            crate::network::SharedAgentNetworkHost::attach(Arc::clone(&host), Arc::clone(&network))
                .unwrap();
        let (handler, owns_worker) = attachment.attachment_for_test(fixture.agent).unwrap();
        assert!(!owns_worker);
        assert_eq!(
            host.lock().unwrap().require_transport(fixture.agent),
            Ok(())
        );

        let request = crate::network::agent_protocol::authenticate_sender(
            &network.peer_id(),
            crate::network::agent_protocol::AgentFrame {
                route,
                sender: network.agent_node_id(),
                message: crate::network::agent_protocol::AgentMessage::Merge(
                    crate::network::agent_protocol::MergeMessage::FetchHeads,
                ),
            },
        )
        .unwrap();
        assert!(matches!(
            handler.handle(request),
            Ok(crate::network::agent_protocol::AgentMessage::Merge(
                crate::network::agent_protocol::MergeMessage::Heads(_)
            ))
        ));
        let raft = crate::network::agent_protocol::authenticate_sender(
            &network.peer_id(),
            crate::network::agent_protocol::AgentFrame {
                route,
                sender: network.agent_node_id(),
                message: crate::network::agent_protocol::AgentMessage::Raft(
                    crate::network::agent_protocol::RaftMessage::StatusRequest,
                ),
            },
        )
        .unwrap();
        assert!(handler.handle(raft).is_err());

        drop(attachment);
        drop(host);
        join_live_network(network);
    }

    #[cfg(feature = "network")]
    #[test]
    fn clean_network_attachment_retires_stale_owner_and_rebuilds_after_restart() {
        let directory = TempDirectory::new("clean_network_restart");
        let fixture = fixture(0x28);
        let mut opened = open_host(&directory, &fixture);
        let status = opened
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        opened
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(5, authorized_management(&fixture, 2, 0xd7))
            .unwrap();
        assert_eq!(
            opened.show(fixture.agent).unwrap().unwrap().applied_slots,
            0
        );
        let route = crate::network::agent_protocol::AgentGenerationRoute {
            space: crate::agent_sdk::SpaceId(status.generation.space().0),
            agent: crate::agent_sdk::AgentId(status.generation.agent().0),
            generation: crate::agent_sdk::Hash(status.replication_id),
        };
        let host = Arc::new(std::sync::Mutex::new(opened));
        let network = live_network(0x31, Vec::new());
        let mut attachment =
            crate::network::SharedAgentNetworkHost::attach(Arc::clone(&host), Arc::clone(&network))
                .unwrap();
        assert_eq!(
            host.lock()
                .unwrap()
                .show(fixture.agent)
                .unwrap()
                .unwrap()
                .applied_slots,
            1,
            "attachment must drain a recovered committed suffix before exposing its route"
        );
        assert_eq!(
            host.lock().unwrap().require_transport(fixture.agent),
            Ok(())
        );
        assert!(matches!(
            host.lock()
                .unwrap()
                .compact_snapshot(fixture.agent, compaction_limits(1)),
            Err(SharedAgentHostError::Conflict)
        ));
        let (first_owner, owns_worker) = attachment.attachment_for_test(fixture.agent).unwrap();
        assert!(owns_worker, "an active voter owns the full-NodeId worker");

        assert!(attachment.mark_stale_for_test(fixture.agent));
        attachment.refresh().unwrap();
        let (replacement_owner, owns_worker) =
            attachment.attachment_for_test(fixture.agent).unwrap();
        assert!(!Arc::ptr_eq(&first_owner, &replacement_owner));
        assert!(owns_worker);
        let stale_request = crate::network::agent_protocol::authenticate_sender(
            &network.peer_id(),
            crate::network::agent_protocol::AgentFrame {
                route,
                sender: network.agent_node_id(),
                message: crate::network::agent_protocol::AgentMessage::Merge(
                    crate::network::agent_protocol::MergeMessage::FetchHeads,
                ),
            },
        )
        .unwrap();
        assert!(
            first_owner.handle(stale_request).is_err(),
            "a cloned retired handler must not cross the generation lease"
        );

        drop(attachment);
        assert_eq!(
            host.lock().unwrap().require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        let unknown = crate::agent_sdk::NodeId([0xfe; 32]);
        assert!(matches!(
            network
                .send_agent_merge_fetch_heads(unknown, route)
                .recv()
                .unwrap(),
            Err(crate::network::agent_network::AgentNetworkError::UnknownRoute(found))
                if found == route
        ));

        drop(Arc::try_unwrap(host).ok().unwrap().into_inner().unwrap());
        let reopened = Arc::new(std::sync::Mutex::new(open_host(&directory, &fixture)));
        assert_eq!(
            reopened.lock().unwrap().require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        let restarted = crate::network::SharedAgentNetworkHost::attach(
            Arc::clone(&reopened),
            Arc::clone(&network),
        )
        .unwrap();
        assert_eq!(
            reopened.lock().unwrap().require_transport(fixture.agent),
            Ok(())
        );
        assert!(restarted.attachment_for_test(fixture.agent).unwrap().1);
        drop(restarted);
        drop(reopened);
        join_live_network(network);
    }

    #[cfg(feature = "network")]
    #[test]
    fn clean_merge_pump_converges_two_real_hosts_after_partition() {
        let directory_a = TempDirectory::new("clean_merge_source");
        let directory_b = TempDirectory::new("clean_merge_target");
        let fixture = fixture(0x29);
        let node_a = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[0]));
        let node_b = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[1]));
        let mut opened_a = open_host_on_node(&directory_a, &fixture, node_a);
        let mut opened_b = open_host_on_node(&directory_b, &fixture, node_b);
        for host in [&mut opened_a, &mut opened_b] {
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        }
        let host_a = Arc::new(std::sync::Mutex::new(opened_a));
        let host_b = Arc::new(std::sync::Mutex::new(opened_b));
        let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let network_a = live_network(0x31, vec![listen]);
        let network_b = live_network(0x32, Vec::new());
        assert_eq!(
            network_a.agent_node_id(),
            crate::agent_sdk::NodeId(node_a.0)
        );
        assert_eq!(
            network_b.agent_node_id(),
            crate::agent_sdk::NodeId(node_b.0)
        );
        let attachment_a = crate::network::SharedAgentNetworkHost::attach(
            Arc::clone(&host_a),
            Arc::clone(&network_a),
        )
        .unwrap();
        let attachment_b = crate::network::SharedAgentNetworkHost::attach(
            Arc::clone(&host_b),
            Arc::clone(&network_b),
        )
        .unwrap();

        let event = publish_merge_invocation(&mut host_a.lock().unwrap(), &fixture, 0xd1);
        let source = host_a
            .lock()
            .unwrap()
            .merge_node(fixture.agent, event)
            .unwrap()
            .unwrap();
        assert_eq!(
            host_b
                .lock()
                .unwrap()
                .merge_node(fixture.agent, event)
                .unwrap(),
            None,
            "the partitioned replica cannot observe a local publication"
        );

        assert!(wait_until(std::time::Duration::from_secs(5), || {
            !network_a.listen_addrs().is_empty()
        }));
        let address = network_a.listen_addrs()[0]
            .clone()
            .with(libp2p::multiaddr::Protocol::P2p(network_a.peer_id()));
        network_b.connect(address);
        assert!(wait_until(std::time::Duration::from_secs(10), || {
            host_b
                .lock()
                .ok()
                .and_then(|host| host.merge_node(fixture.agent, event).ok().flatten())
                .as_ref()
                == Some(&source)
        }));
        assert_eq!(
            host_a.lock().unwrap().merge_roots(fixture.agent).unwrap(),
            host_b.lock().unwrap().merge_roots(fixture.agent).unwrap()
        );

        drop(attachment_a);
        drop(attachment_b);
        drop(host_a);
        drop(host_b);
        join_live_network(network_a);
        join_live_network(network_b);
    }
}
