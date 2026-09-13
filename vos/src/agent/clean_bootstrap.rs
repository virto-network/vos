//! Crash-safe bootstrap owner for the clean one-voter Shared system Agent.
//!
//! Root/QC finality creates the journal without consulting the not-yet-live
//! system authority. The authority and catalog actors are then installed and
//! invoked through the authenticated Shared journal and Raft proposer.

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use std::{fs, io::ErrorKind, path::Path, sync::Mutex};

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use super::clean_authority_issuer::{
    AuthorizedCleanManagementDecision, CleanManagementIssuerRejection,
    MAX_AUTHORIZED_DECISION_BYTES,
};
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::clean_authority_issuer::{
    CleanManagementIssuerError, CleanManagementIssuerStore, CleanManagementReceiptSigner,
    DurableCleanManagementIssuer,
};
use super::committee::{MAX_ROOT_ANCHOR_PINS_BYTES, RootAnchorPins};
use super::genesis::{AgentReplicaCommittee, MAX_AGENT_REPLICA_COMMITTEE_BYTES};
use super::package_admission::{
    AdmittedActorPackage, AdmittedRuntimePackage, admit_actor_package, admit_runtime_package,
};
use super::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialCall,
    AuthorityCredentialVerifier, AuthorityIssuer, AuthorityOperationKind, AuthorityProjectionQuery,
    AuthorityProjectionSelector, AuthorityReceipt, ManagedAgentTarget, ManagementApplicationAck,
    ManagementApproval,
};
use super::sdk::package::MAX_PACKAGE_ENCODED_BYTES;
use super::sdk::wire::{
    CanonicalWire, MAX_AGENT_DESCRIPTOR_WIRE_BYTES, MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES,
    MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES, MAX_AUTHORITY_RECEIPT_WIRE_BYTES,
    MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES, MAX_MANAGEMENT_APPROVAL_WIRE_BYTES,
    MAX_MANAGEMENT_REQUEST_WIRE_BYTES, MAX_RUNTIME_WORK_WIRE_BYTES,
};
use super::sdk::{
    ActorId, AgentDescriptor, AgentId, AgentProfile, BlobRef, Hash, InvocationAuthorization,
    InvocationId, InvocationRoleClaims, ManagementRequest, MethodMode, NodeId,
    RuntimeExecutionContext, RuntimeState, RuntimeWork, SpaceId,
};
use crate::service::wire::ServiceWire;

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::bootstrap::{
    SystemAgentGenesisLocator, SystemAgentGenesisProposal, SystemAgentGenesisProvider,
    SystemAgentGenesisProviderError, SystemAgentGenesisProvision,
    validate_prepared_system_agent_genesis_root, validate_system_agent_genesis_catalog,
};
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::driver::{AgentTrustProvider, SdkManagementArtifacts};
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::execution::RuntimeBlob;
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::genesis::AgentGenesisFinalityVerifier;
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::host::{AgentHostScope, LocalMergeAuthenticator};
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::journal_store::FileAgentJournalStore;
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::local_journal_driver::LocalJournalAgentDriver;
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::shared_host::{SharedAgentHost, SharedAgentHostError};
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::shared_raft::CommitteeChangeAuthorityBinding;
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use crate::network::{Network, SharedAgentNetworkHost};

const CLEAN_SYSTEM_AGENT_PINS_MAGIC: [u8; 4] = *b"CSP2";
const CLEAN_SYSTEM_AGENT_PLAN_MAGIC: [u8; 4] = *b"CBP3";
const CLEAN_SYSTEM_AGENT_BOOTSTRAP_MAGIC: [u8; 4] = *b"CSB2";
const CLEAN_SYSTEM_AGENT_BOOTSTRAP_VERSION: u8 = 3;

pub const MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES: usize = MAX_AGENT_DESCRIPTOR_WIRE_BYTES
    + MAX_ROOT_ANCHOR_PINS_BYTES
    + MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + 2 * 1024;
const MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES: usize = 3 * MAX_PACKAGE_ENCODED_BYTES
    + MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES
    + 2 * MAX_AUTHORIZED_DECISION_BYTES
    + MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
    + 2 * MAX_MANAGEMENT_REQUEST_WIRE_BYTES
    + 8 * 1024;
pub const MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES: usize = MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES
    + 3 * MAX_AUTHORITY_RECEIPT_WIRE_BYTES
    + MAX_MANAGEMENT_APPROVAL_WIRE_BYTES
    + MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
    + MAX_PENDING_AUTHORITY_PROJECTION_BYTES
    + 8 * 1024;

const MAX_PENDING_AUTHORITY_PROJECTION_BYTES: usize =
    MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES + MAX_RUNTIME_WORK_WIRE_BYTES + 1024;

pub trait CleanSystemAgentBootstrapStore {
    type Error;

    /// Return the one authoritative visible image. Completion is also a
    /// reconciliation barrier: a candidate staged by an earlier failed
    /// `commit` cannot become visible after this returns unless a later
    /// `commit` publishes it.
    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Atomically replace the visible image. An error does not identify the
    /// publication point; callers must reconcile with `load` before deciding
    /// whether the prior or candidate record owns subsequent work.
    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

/// Independently persisted clean Shared identity and both finality domains.
/// `replicas` is the one-voter data-plane committee; `root` is the distinct
/// root authority committee and QC pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanSystemAgentPins {
    space: SpaceId,
    agent: AgentId,
    node: NodeId,
    authority: AgentAuthorityBinding,
    runtime_package: BlobRef,
    descriptor: AgentDescriptor,
    replicas: AgentReplicaCommittee,
    root: RootAnchorPins,
    observed_slot: u64,
}

impl CleanSystemAgentPins {
    pub fn new(
        descriptor: AgentDescriptor,
        replicas: AgentReplicaCommittee,
        root: RootAnchorPins,
        observed_slot: u64,
    ) -> Result<Self, CleanSystemAgentBootstrapRejection> {
        let member = replicas
            .members()
            .first()
            .ok_or(CleanSystemAgentBootstrapRejection::InvalidDescriptor)?;
        let value = Self {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            node: NodeId(member.replica().node.0),
            authority: descriptor.authority,
            runtime_package: descriptor.runtime_package.clone(),
            descriptor,
            replicas,
            root,
            observed_slot,
        };
        value
            .is_valid()
            .then_some(value)
            .ok_or(CleanSystemAgentBootstrapRejection::InvalidDescriptor)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }
    pub const fn agent(&self) -> AgentId {
        self.agent
    }
    pub const fn node(&self) -> NodeId {
        self.node
    }
    pub const fn authority(&self) -> AgentAuthorityBinding {
        self.authority
    }
    pub const fn runtime_package(&self) -> &BlobRef {
        &self.runtime_package
    }
    pub const fn descriptor(&self) -> &AgentDescriptor {
        &self.descriptor
    }
    pub const fn replicas(&self) -> &AgentReplicaCommittee {
        &self.replicas
    }
    pub const fn root(&self) -> &RootAnchorPins {
        &self.root
    }
    pub const fn observed_slot(&self) -> u64 {
        self.observed_slot
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/clean-system-agent-pins/v2", &[&self.encode()])
    }

    fn is_valid(&self) -> bool {
        let [descriptor_replica] = self.descriptor.replicas.as_slice() else {
            return false;
        };
        let [member] = self.replicas.members() else {
            return false;
        };
        self.observed_slot != 0
            && self.descriptor.validate().is_ok()
            && self.descriptor.identity.profile == AgentProfile::Shared
            && descriptor_replica.role == super::sdk::ReplicaRole::Voter
            && self.replicas.validate().is_ok()
            && self.replicas.profile() == super::AgentProfile::Shared
            && self.replicas.voter_count() == 1
            && self.root.validate().is_ok()
            && self.space == self.descriptor.identity.space
            && self.agent == self.descriptor.identity.agent
            && self.authority == self.descriptor.authority
            && self.runtime_package == self.descriptor.runtime_package
            && self.replicas.space().0 == self.space.0
            && self.replicas.agent().0 == self.agent.0
            && member.replica().node.0 == descriptor_replica.node.0
            && member.replica().principal.0 == descriptor_replica.principal.0
            && member.replica().role == super::ReplicaRole::Voter
            && self.node.0 == descriptor_replica.node.0
            && self.root.record().space().0 == self.space.0
            && self.root.record().system_agent().0 == self.agent.0
            && self.root.record().authority_binding().0 == self.authority.commitment().0
    }

    fn encode(&self) -> Vec<u8> {
        let descriptor = self.descriptor.encode().expect("validated descriptor");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CLEAN_SYSTEM_AGENT_PINS_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
        encoder.fixed(self.space.as_bytes());
        encoder.fixed(self.agent.as_bytes());
        encoder.fixed(self.node.as_bytes());
        encode_authority_binding(&mut encoder, self.authority);
        encode_blob_ref(&mut encoder, &self.runtime_package);
        encoder.u64(self.observed_slot);
        encoder.bytes(&descriptor);
        encoder.bytes(&self.replicas.encode());
        encoder.bytes(&self.root.encode());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != CLEAN_SYSTEM_AGENT_PINS_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != super::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            node: NodeId(decoder.fixed()?),
            authority: decode_authority_binding(&mut decoder)?,
            runtime_package: decode_blob_ref(&mut decoder)?,
            observed_slot: decoder.u64()?,
            descriptor: AgentDescriptor::decode(
                &decoder.bytes_bounded(MAX_AGENT_DESCRIPTOR_WIRE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
            replicas: AgentReplicaCommittee::decode(
                &decoder.bytes_bounded(MAX_AGENT_REPLICA_COMMITTEE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
            root: RootAnchorPins::decode(&decoder.bytes_bounded(MAX_ROOT_ANCHOR_PINS_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)?,
        };
        if !decoder.exhausted() || !value.is_valid() || value.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Exact root-authorized Create/authority-install material and the signed
/// credential call which the installed authority actor must approve before
/// catalog installation.
#[derive(Clone)]
pub struct AuthorizedCleanSystemAgentBootstrap {
    pins: CleanSystemAgentPins,
    runtime_package_bytes: Vec<u8>,
    create_decision: AuthorizedCleanManagementDecision,
    authority_package_bytes: Vec<u8>,
    authority_request: ManagementRequest,
    authority_decision: AuthorizedCleanManagementDecision,
    catalog_package_bytes: Vec<u8>,
    catalog_request: ManagementRequest,
    catalog_call: AuthorityCredentialCall,
    invocation_gas: u64,
}

/// Independently held root-certification boundary for first-system startup.
/// A successful result must bind `root_certification` in its root record and
/// certify the exact replay-derived proposal. The preparation seam verifies
/// both before it mints a reusable bootstrap plan.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub trait CleanSystemAgentRootCertifier {
    fn certify(
        &mut self,
        root_certification: Hash,
        proposal: &SystemAgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError>;
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl<F> CleanSystemAgentRootCertifier for F
where
    F: FnMut(
        Hash,
        &SystemAgentGenesisProposal,
        &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError>,
{
    fn certify(
        &mut self,
        root_certification: Hash,
        proposal: &SystemAgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        self(root_certification, proposal, catalog)
    }
}

/// Complete fresh-start result. The caller durably archives `provision` and
/// `catalog`; the owner then receives `plan` through its empty-store factory.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
#[derive(Clone)]
pub struct PreparedCleanSystemAgentBootstrap {
    plan: AuthorizedCleanSystemAgentBootstrap,
    provision: SystemAgentGenesisProvision,
    catalog: Vec<RuntimeBlob>,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl PreparedCleanSystemAgentBootstrap {
    pub const fn plan(&self) -> &AuthorizedCleanSystemAgentBootstrap {
        &self.plan
    }

    pub const fn provision(&self) -> &SystemAgentGenesisProvision {
        &self.provision
    }

    pub fn catalog(&self) -> &[RuntimeBlob] {
        &self.catalog
    }

    pub fn into_parts(
        self,
    ) -> (
        AuthorizedCleanSystemAgentBootstrap,
        SystemAgentGenesisProvision,
        Vec<RuntimeBlob>,
    ) {
        (self.plan, self.provision, self.catalog)
    }
}

impl AuthorizedCleanSystemAgentBootstrap {
    /// Prepare every replay-derived and root-certified input required by one
    /// fresh system-Agent bootstrap. The first two management decisions are
    /// minted only inside `vos`; callers receive neither their constructor nor
    /// the replay-prepared capability used to derive the proposal.
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_root_authorized<S, C>(
        descriptor: AgentDescriptor,
        runtime_package_bytes: Vec<u8>,
        replicas: AgentReplicaCommittee,
        observed_slot: u64,
        authority_package_bytes: Vec<u8>,
        authority_request: ManagementRequest,
        catalog_package_bytes: Vec<u8>,
        catalog_request: ManagementRequest,
        catalog_call: AuthorityCredentialCall,
        invocation_gas: u64,
        signer: &mut S,
        root_certifier: &mut C,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<PreparedCleanSystemAgentBootstrap, CleanSystemAgentBootstrapError>
    where
        S: CleanManagementReceiptSigner,
        C: CleanSystemAgentRootCertifier,
    {
        let runtime = admit_runtime_package(&runtime_package_bytes)
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidRuntimePackage))?;
        let authority = admit_actor_package(&authority_package_bytes)
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidActorPackage))?;
        let catalog_package = admit_actor_package(&catalog_package_bytes)
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidActorPackage))?;
        validate_root_bootstrap_materials(
            &descriptor,
            &replicas,
            observed_slot,
            invocation_gas,
            &runtime,
            &authority,
            &authority_request,
            &catalog_package,
            &catalog_request,
            &catalog_call,
        )?;
        let root_certification = root_bootstrap_certification_commitment(
            &descriptor,
            &runtime_package_bytes,
            &replicas,
            observed_slot,
            &authority_package_bytes,
            &authority_request,
            &catalog_package_bytes,
            &catalog_request,
            &catalog_call,
            invocation_gas,
        )?;
        let create_request = ManagementRequest::Create(alloc::boxed::Box::new(descriptor.clone()));
        let valid_from = catalog_call.requested_valid_from;
        let expires_at = catalog_call.requested_expires_at;
        let create_decision = AuthorizedCleanManagementDecision::from_root_bootstrap(
            core::num::NonZeroU64::new(1).expect("one is nonzero"),
            &descriptor,
            &create_request,
            root_certification,
            valid_from,
            expires_at,
        )
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
        let authority_decision = AuthorizedCleanManagementDecision::from_root_bootstrap(
            core::num::NonZeroU64::new(2).expect("two is nonzero"),
            &descriptor,
            &authority_request,
            root_certification,
            valid_from,
            expires_at,
        )
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;

        let mut planning_issuer = DurableCleanManagementIssuer::open(
            CleanSystemAgentPlanningIssuerStore::default(),
            descriptor.authority,
            descriptor.identity.space,
            descriptor.identity.agent,
        )
        .map_err(map_issuer_open_error)?;
        let create_receipt = planning_issuer
            .issue(&create_decision, signer)
            .map_err(map_issuer_issue_error)?;
        let (create, genesis_catalog) =
            LocalJournalAgentDriver::<FileAgentJournalStore>::clean_shared_system_genesis_input(
                descriptor.clone(),
                &runtime,
                create_receipt,
                observed_slot,
                &trust,
                &merge,
            )
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
        let [member] = replicas.members() else {
            return Err(rejected(
                CleanSystemAgentBootstrapRejection::InvalidDescriptor,
            ));
        };
        let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
            create,
            member.replica(),
            &genesis_catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
        let proposal = SystemAgentGenesisProposal::from_prepared(
            SystemAgentGenesisLocator {
                space: crate::service::SpaceId(descriptor.identity.space.0),
                agent: crate::service::AgentId(descriptor.identity.agent.0),
                node: member.replica().node,
            },
            &prepared,
        )
        .map_err(CleanSystemAgentBootstrapError::Bootstrap)?;
        let provision = root_certifier
            .certify(root_certification, &proposal, &genesis_catalog)
            .map_err(CleanSystemAgentBootstrapError::Genesis)?;
        provision
            .validate()
            .map_err(CleanSystemAgentBootstrapError::Bootstrap)?;
        validate_system_agent_genesis_catalog(&proposal, &genesis_catalog)
            .map_err(CleanSystemAgentBootstrapError::Bootstrap)?;
        let root = provision.root();
        if provision.proposal() != &proposal
            || root.record().root_certification().0 != root_certification.0
            || root.record().initial_committee().members().len() != 1
            || root.record().initial_committee().voter_count() != 1
        {
            return Err(rejected(CleanSystemAgentBootstrapRejection::WrongAuthority));
        }
        let plan = Self::new(
            descriptor,
            runtime_package_bytes,
            replicas,
            root.clone(),
            observed_slot,
            create_decision,
            authority_package_bytes,
            authority_request,
            authority_decision,
            catalog_package_bytes,
            catalog_request,
            catalog_call,
            invocation_gas,
        )
        .map_err(CleanSystemAgentBootstrapError::Rejected)?;
        Ok(PreparedCleanSystemAgentBootstrap {
            plan,
            provision,
            catalog: genesis_catalog,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        descriptor: AgentDescriptor,
        runtime_package_bytes: Vec<u8>,
        replicas: AgentReplicaCommittee,
        root: RootAnchorPins,
        observed_slot: u64,
        create_decision: AuthorizedCleanManagementDecision,
        authority_package_bytes: Vec<u8>,
        authority_request: ManagementRequest,
        authority_decision: AuthorizedCleanManagementDecision,
        catalog_package_bytes: Vec<u8>,
        catalog_request: ManagementRequest,
        catalog_call: AuthorityCredentialCall,
        invocation_gas: u64,
    ) -> Result<Self, CleanSystemAgentBootstrapRejection> {
        let value = Self {
            pins: CleanSystemAgentPins::new(descriptor, replicas, root, observed_slot)?,
            runtime_package_bytes,
            create_decision,
            authority_package_bytes,
            authority_request,
            authority_decision,
            catalog_package_bytes,
            catalog_request,
            catalog_call,
            invocation_gas,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }
    pub fn runtime_package_bytes(&self) -> &[u8] {
        &self.runtime_package_bytes
    }
    pub const fn create_decision(&self) -> &AuthorizedCleanManagementDecision {
        &self.create_decision
    }
    pub const fn authority_request(&self) -> &ManagementRequest {
        &self.authority_request
    }
    pub const fn authority_decision(&self) -> &AuthorizedCleanManagementDecision {
        &self.authority_decision
    }
    pub const fn catalog_request(&self) -> &ManagementRequest {
        &self.catalog_request
    }
    pub const fn catalog_call(&self) -> &AuthorityCredentialCall {
        &self.catalog_call
    }
    pub fn authority_package_bytes(&self) -> &[u8] {
        &self.authority_package_bytes
    }
    pub fn catalog_package_bytes(&self) -> &[u8] {
        &self.catalog_package_bytes
    }
    pub const fn invocation_gas(&self) -> u64 {
        self.invocation_gas
    }

    fn runtime(&self) -> Result<AdmittedRuntimePackage, CleanSystemAgentBootstrapRejection> {
        admit_runtime_package(&self.runtime_package_bytes)
            .map_err(|_| CleanSystemAgentBootstrapRejection::InvalidRuntimePackage)
    }

    fn authority_package(
        &self,
    ) -> Result<AdmittedActorPackage, CleanSystemAgentBootstrapRejection> {
        admit_actor_package(&self.authority_package_bytes)
            .map_err(|_| CleanSystemAgentBootstrapRejection::InvalidActorPackage)
    }

    fn catalog_package(&self) -> Result<AdmittedActorPackage, CleanSystemAgentBootstrapRejection> {
        admit_actor_package(&self.catalog_package_bytes)
            .map_err(|_| CleanSystemAgentBootstrapRejection::InvalidActorPackage)
    }

    fn validate(&self) -> Result<(), CleanSystemAgentBootstrapRejection> {
        if !self.pins.is_valid()
            || self.invocation_gas == 0
            || self.invocation_gas > super::execution::MAX_EXECUTION_GAS
        {
            return Err(CleanSystemAgentBootstrapRejection::InvalidDescriptor);
        }
        let runtime = self.runtime()?;
        if !runtime_matches_pins(&runtime, &self.pins)
            || !self
                .create_decision
                .matches_creation(self.pins.descriptor())
            || self.create_decision.authorization_id().get() != 1
        {
            return Err(CleanSystemAgentBootstrapRejection::InvalidDecision);
        }
        let authority = self.authority_package()?;
        let catalog = self.catalog_package()?;
        validate_actor_install(self.pins.descriptor(), &self.authority_request, &authority)?;
        validate_actor_install(self.pins.descriptor(), &self.catalog_request, &catalog)?;
        let ManagementRequest::Install(authority_install) = &self.authority_request else {
            return Err(CleanSystemAgentBootstrapRejection::InvalidDecision);
        };
        let ManagementRequest::Install(catalog_install) = &self.catalog_request else {
            return Err(CleanSystemAgentBootstrapRejection::InvalidDecision);
        };
        let issuer = self.pins.authority.issuer;
        if authority_install.entry.actor != issuer.actor
            || authority_install.entry.deployment != issuer.deployment
            || authority_install.entry.program != issuer.program
            || authority_install.producer != issuer.producer
            || authority_install.entry.actor == catalog_install.entry.actor
            || self.authority_decision.authorization_id().get() != 2
            || self.authority_decision.space() != self.pins.space
            || self.authority_decision.agent() != self.pins.agent
            || self.authority_decision.operation() != AuthorityOperationKind::InstallActor
            || self.authority_decision.request() != self.authority_request.commitment()
            || self.catalog_call.validate_shape().is_err()
            || self.catalog_call.authority != self.authority_target()
            || self.catalog_call.managed != self.managed_target()
            || self.catalog_call.authenticated_node != Some(self.pins.node)
            || self.catalog_call.request_sequence.get() != 1
            || self.catalog_call.requested_valid_from > self.pins.observed_slot
            || self.catalog_call.requested_expires_at < self.pins.observed_slot
            || !self
                .catalog_call
                .plan
                .matches_request(&self.catalog_request)
            || !RawCredentialVerifier.verify(
                &self.catalog_call.credential_public_key,
                &self.catalog_call.signing_bytes(),
                &self.catalog_call.signature,
            )
            || self.canonical_bytes().len() > MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES
        {
            return Err(CleanSystemAgentBootstrapRejection::InvalidDecision);
        }
        Ok(())
    }

    fn authority_target(&self) -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: self.pins.space,
            system_agent: self.pins.agent,
            system_runtime_deployment: self.pins.descriptor.identity.runtime_deployment,
            binding: self.pins.authority,
        }
    }

    fn managed_target(&self) -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: self.pins.space,
            agent: self.pins.agent,
            owner: self.pins.descriptor.identity.owner,
            profile: self.pins.descriptor.identity.profile,
            runtime_deployment: self.pins.descriptor.identity.runtime_deployment,
            transition_producer: self.pins.descriptor.identity.transition_producer,
        }
    }

    fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/clean-system-agent-bootstrap-plan/v3",
            &[&self.canonical_bytes()],
        )
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CLEAN_SYSTEM_AGENT_PLAN_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
        encoder.bytes(&self.pins.encode());
        encode_large_bytes(&mut encoder, &self.runtime_package_bytes);
        encoder.bytes(&self.create_decision.canonical_bytes());
        encode_large_bytes(&mut encoder, &self.authority_package_bytes);
        encoder.bytes(
            &self
                .authority_request
                .encode()
                .expect("validated authority management request"),
        );
        encoder.bytes(&self.authority_decision.canonical_bytes());
        encode_large_bytes(&mut encoder, &self.catalog_package_bytes);
        encoder.bytes(
            &self
                .catalog_request
                .encode()
                .expect("validated catalog management request"),
        );
        encoder.bytes(
            &self
                .catalog_call
                .encode()
                .expect("validated credential call"),
        );
        encoder.u64(self.invocation_gas);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != CLEAN_SYSTEM_AGENT_PLAN_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != super::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let value = Self {
            pins: CleanSystemAgentPins::decode(
                &decoder.bytes_bounded(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)?,
            )?,
            runtime_package_bytes: decode_large_bytes(&mut decoder, MAX_PACKAGE_ENCODED_BYTES)?,
            create_decision: AuthorizedCleanManagementDecision::from_canonical_bytes(
                &decoder.bytes_bounded(MAX_AUTHORIZED_DECISION_BYTES)?,
            )?,
            authority_package_bytes: decode_large_bytes(&mut decoder, MAX_PACKAGE_ENCODED_BYTES)?,
            authority_request: ManagementRequest::decode(
                &decoder.bytes_bounded(MAX_MANAGEMENT_REQUEST_WIRE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
            authority_decision: AuthorizedCleanManagementDecision::from_canonical_bytes(
                &decoder.bytes_bounded(MAX_AUTHORIZED_DECISION_BYTES)?,
            )?,
            catalog_package_bytes: decode_large_bytes(&mut decoder, MAX_PACKAGE_ENCODED_BYTES)?,
            catalog_request: ManagementRequest::decode(
                &decoder.bytes_bounded(MAX_MANAGEMENT_REQUEST_WIRE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
            catalog_call: AuthorityCredentialCall::decode(
                &decoder.bytes_bounded(MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
            invocation_gas: decoder.u64()?,
        };
        if !decoder.exhausted() || value.validate().is_err() || value.canonical_bytes() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn validate_root_bootstrap_materials(
    descriptor: &AgentDescriptor,
    replicas: &AgentReplicaCommittee,
    observed_slot: u64,
    invocation_gas: u64,
    runtime: &AdmittedRuntimePackage,
    authority: &AdmittedActorPackage,
    authority_request: &ManagementRequest,
    catalog_package: &AdmittedActorPackage,
    catalog_request: &ManagementRequest,
    catalog_call: &AuthorityCredentialCall,
) -> Result<(), CleanSystemAgentBootstrapError> {
    let [descriptor_replica] = descriptor.replicas.as_slice() else {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDescriptor,
        ));
    };
    let [member] = replicas.members() else {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDescriptor,
        ));
    };
    if observed_slot == 0
        || invocation_gas == 0
        || invocation_gas > super::execution::MAX_EXECUTION_GAS
        || descriptor.validate().is_err()
        || descriptor.identity.profile != AgentProfile::Shared
        || descriptor_replica.role != super::sdk::ReplicaRole::Voter
        || replicas.validate().is_err()
        || replicas.profile() != super::AgentProfile::Shared
        || replicas.voter_count() != 1
        || replicas.space().0 != descriptor.identity.space.0
        || replicas.agent().0 != descriptor.identity.agent.0
        || member.replica().node.0 != descriptor_replica.node.0
        || member.replica().principal.0 != descriptor_replica.principal.0
        || member.replica().role != super::ReplicaRole::Voter
        || runtime.exact_bytes().len() > MAX_PACKAGE_ENCODED_BYTES
        || runtime.package_ref() != &descriptor.runtime_package
        || runtime.deployment() != descriptor.identity.runtime_deployment
        || runtime.program() != descriptor.identity.runtime_program
        || runtime.producer() != descriptor.identity.runtime_producer
        || runtime.manifest().contract != descriptor.runtime_contract
        || runtime.capabilities() != descriptor.capabilities
    {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDescriptor,
        ));
    }
    validate_actor_install(descriptor, authority_request, authority)
        .map_err(CleanSystemAgentBootstrapError::Rejected)?;
    validate_actor_install(descriptor, catalog_request, catalog_package)
        .map_err(CleanSystemAgentBootstrapError::Rejected)?;
    let ManagementRequest::Install(authority_install) = authority_request else {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDecision,
        ));
    };
    let ManagementRequest::Install(catalog_install) = catalog_request else {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDecision,
        ));
    };
    let issuer = descriptor.authority.issuer;
    let authority_target = AuthorityActorTarget {
        space: descriptor.identity.space,
        system_agent: descriptor.identity.agent,
        system_runtime_deployment: descriptor.identity.runtime_deployment,
        binding: descriptor.authority,
    };
    let managed_target = ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    if authority_install.entry.actor != issuer.actor
        || authority_install.entry.deployment != issuer.deployment
        || authority_install.entry.program != issuer.program
        || authority_install.producer != issuer.producer
        || authority_install.entry.actor == catalog_install.entry.actor
        || catalog_call.validate_shape().is_err()
        || catalog_call.authority != authority_target
        || catalog_call.managed != managed_target
        || catalog_call.authenticated_node != Some(NodeId(member.replica().node.0))
        || catalog_call.request_sequence.get() != 1
        || catalog_call.requested_valid_from > observed_slot
        || catalog_call.requested_expires_at < observed_slot
        || !catalog_call.plan.matches_request(catalog_request)
        || !RawCredentialVerifier.verify(
            &catalog_call.credential_public_key,
            &catalog_call.signing_bytes(),
            &catalog_call.signature,
        )
    {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDecision,
        ));
    }
    Ok(())
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn root_bootstrap_certification_commitment(
    descriptor: &AgentDescriptor,
    runtime_package_bytes: &[u8],
    replicas: &AgentReplicaCommittee,
    observed_slot: u64,
    authority_package_bytes: &[u8],
    authority_request: &ManagementRequest,
    catalog_package_bytes: &[u8],
    catalog_request: &ManagementRequest,
    catalog_call: &AuthorityCredentialCall,
    invocation_gas: u64,
) -> Result<Hash, CleanSystemAgentBootstrapError> {
    let descriptor = descriptor
        .encode()
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDescriptor))?;
    let authority_request = authority_request
        .encode()
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
    let catalog_request = catalog_request
        .encode()
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
    let catalog_call = catalog_call
        .encode()
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
    let mut material = Vec::new();
    material.extend_from_slice(b"CSRC1");
    let mut encoder = Encoder(&mut material);
    encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
    encoder.bytes(&descriptor);
    encoder.bytes(&replicas.encode());
    encoder.u64(observed_slot);
    encoder.fixed(
        Hash::digest(
            b"vos/clean-system-agent-bootstrap/runtime-package/v1",
            &[runtime_package_bytes],
        )
        .as_bytes(),
    );
    encoder.fixed(
        Hash::digest(
            b"vos/clean-system-agent-bootstrap/authority-package/v1",
            &[authority_package_bytes],
        )
        .as_bytes(),
    );
    encoder.bytes(&authority_request);
    encoder.fixed(
        Hash::digest(
            b"vos/clean-system-agent-bootstrap/catalog-package/v1",
            &[catalog_package_bytes],
        )
        .as_bytes(),
    );
    encoder.bytes(&catalog_request);
    encoder.bytes(&catalog_call);
    encoder.u64(invocation_gas);
    Ok(Hash::digest(
        b"vos/clean-system-agent-root-certification/v1",
        &[&material],
    ))
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
#[derive(Default)]
struct CleanSystemAgentPlanningIssuerStore {
    image: Option<Vec<u8>>,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl CleanManagementIssuerStore for CleanSystemAgentPlanningIssuerStore {
    type Error = core::convert::Infallible;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.image = Some(image.to_vec());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CleanSystemAgentBootstrapPhase {
    Intent = 0,
    CreateReceiptIssued = 1,
    Created = 2,
    AuthorityReceiptIssued = 3,
    AuthorityInstalled = 4,
    CatalogApproved = 5,
    CatalogReceiptIssued = 6,
    CatalogInstalled = 7,
    CatalogAcknowledged = 8,
    Complete = 9,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingAuthorityProjection {
    query: AuthorityProjectionQuery,
    work: RuntimeWork,
}

impl PendingAuthorityProjection {
    fn validate(&self) -> bool {
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = &self.work
        else {
            return false;
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return false;
        };
        let target = self.query.authority;
        let method = projection_method(self.query.selector);
        let Ok(query_bytes) = self.query.encode() else {
            return false;
        };
        self.query.validate_shape().is_ok()
            && *context == RuntimeExecutionContext::Direct
            && state.is_empty()
            && *observed_slot == preflight.observed_slot
            && invocation.validate()
            && authorization.matches_work(invocation)
            && invocation.space == target.space
            && invocation.agent == target.system_agent
            && invocation.runtime_deployment == target.system_runtime_deployment
            && invocation.actor == target.binding.issuer.actor
            && invocation.deployment == target.binding.issuer.deployment
            && invocation.program == target.binding.issuer.program
            && invocation.mode == MethodMode::Query
            && invocation.invocation
                == InvocationId(
                    Hash::digest(
                        b"vos/system-authority/projection-invocation/v2",
                        &[self.query.commitment().as_bytes()],
                    )
                    .0,
                )
            && invocation.origin.principal.is_none()
            && invocation.origin.transport_node == self.query.attesting_node()
            && invocation.origin.credential.is_none()
            && invocation.origin.actor.is_none()
            && invocation.origin.capability.is_none()
            && invocation.roles == InvocationRoleClaims::none()
            && invocation.message
                == dynamic_message(
                    method,
                    "query",
                    crate::actors::value::Value::Bytes(query_bytes),
                )
            && !invocation.recovery_only
    }

    fn invocation(&self) -> Option<(&super::sdk::InvocationWork, &InvocationAuthorization)> {
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = &self.work
        else {
            return None;
        };
        Some((invocation, authorization))
    }
}

impl CanonicalWire for PendingAuthorityProjection {
    const MAGIC: [u8; 4] = *b"PAP1";
    const MAX_ENCODED_BYTES: usize = MAX_PENDING_AUTHORITY_PROJECTION_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.bytes(
            &self
                .query
                .encode()
                .expect("validated pending query is canonical"),
        );
        encoder.bytes(
            &self
                .work
                .encode()
                .expect("validated pending work is canonical"),
        );
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let query = AuthorityProjectionQuery::decode(
            &decoder.bytes_bounded(MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES)?,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        let work = RuntimeWork::decode(&decoder.bytes_bounded(MAX_RUNTIME_WORK_WIRE_BYTES)?)
            .map_err(|_| DecodeError::NonCanonical)?;
        let value = Self { query, work };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

const fn projection_method(selector: AuthorityProjectionSelector) -> &'static str {
    match selector {
        AuthorityProjectionSelector::Credential => "credential_projection",
        AuthorityProjectionSelector::Agents { .. } => "agent_projection_page",
        AuthorityProjectionSelector::AgentReplicas { .. } => "agent_replica_projection_page",
        AuthorityProjectionSelector::Actors { .. } => "actor_projection_page",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanSystemAgentBootstrapRecord {
    phase: CleanSystemAgentBootstrapPhase,
    pins_commitment: Hash,
    plan_commitment: Hash,
    plan: Vec<u8>,
    create_receipt: Option<AuthorityReceipt>,
    authority_receipt: Option<AuthorityReceipt>,
    catalog_approval: Option<ManagementApproval>,
    catalog_receipt: Option<AuthorityReceipt>,
    catalog_acknowledgement: Option<ManagementApplicationAck>,
    pending_projection: Option<PendingAuthorityProjection>,
}

impl CleanSystemAgentBootstrapRecord {
    pub const fn phase(&self) -> CleanSystemAgentBootstrapPhase {
        self.phase
    }
    pub const fn create_receipt(&self) -> Option<&AuthorityReceipt> {
        self.create_receipt.as_ref()
    }
    pub const fn authority_receipt(&self) -> Option<&AuthorityReceipt> {
        self.authority_receipt.as_ref()
    }
    pub const fn catalog_receipt(&self) -> Option<&AuthorityReceipt> {
        self.catalog_receipt.as_ref()
    }

    fn intent(plan: &AuthorizedCleanSystemAgentBootstrap) -> Self {
        Self {
            phase: CleanSystemAgentBootstrapPhase::Intent,
            pins_commitment: plan.pins.commitment(),
            plan_commitment: plan.commitment(),
            plan: plan.canonical_bytes(),
            create_receipt: None,
            authority_receipt: None,
            catalog_approval: None,
            catalog_receipt: None,
            catalog_acknowledgement: None,
            pending_projection: None,
        }
    }

    fn matches_plan(&self, plan: &AuthorizedCleanSystemAgentBootstrap) -> bool {
        self.pins_commitment == plan.pins.commitment()
            && self.plan_commitment == plan.commitment()
            && self.plan == plan.canonical_bytes()
    }

    fn advance(&mut self, phase: CleanSystemAgentBootstrapPhase) {
        debug_assert!(phase >= self.phase);
        self.phase = phase;
    }

    fn is_valid(&self) -> bool {
        if self.pins_commitment == Hash::ZERO
            || self.plan_commitment == Hash::ZERO
            || self.plan.len() > MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES
            || self.plan.get(..4) != Some(&CLEAN_SYSTEM_AGENT_PLAN_MAGIC)
            || Hash::digest(b"vos/clean-system-agent-bootstrap-plan/v3", &[&self.plan])
                != self.plan_commitment
        {
            return false;
        }
        let present = |required: CleanSystemAgentBootstrapPhase, value: bool| {
            (self.phase >= required) == value
        };
        present(
            CleanSystemAgentBootstrapPhase::CreateReceiptIssued,
            self.create_receipt.is_some(),
        ) && present(
            CleanSystemAgentBootstrapPhase::AuthorityReceiptIssued,
            self.authority_receipt.is_some(),
        ) && present(
            CleanSystemAgentBootstrapPhase::CatalogApproved,
            self.catalog_approval.is_some(),
        ) && present(
            CleanSystemAgentBootstrapPhase::CatalogReceiptIssued,
            self.catalog_receipt.is_some(),
        ) && present(
            CleanSystemAgentBootstrapPhase::CatalogAcknowledged,
            self.catalog_acknowledgement.is_some(),
        ) && self
            .create_receipt
            .as_ref()
            .is_none_or(|value| value.validate_shape().is_ok())
            && self
                .authority_receipt
                .as_ref()
                .is_none_or(|value| value.validate_shape().is_ok())
            && self
                .catalog_approval
                .as_ref()
                .is_none_or(|value| value.validate_shape().is_ok())
            && self
                .catalog_receipt
                .as_ref()
                .is_none_or(|value| value.validate_shape().is_ok())
            && self
                .catalog_acknowledgement
                .as_ref()
                .is_none_or(|value| value.validate_shape().is_ok())
            && self.pending_projection.as_ref().is_none_or(|value| {
                self.phase == CleanSystemAgentBootstrapPhase::Complete && value.validate()
            })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CLEAN_SYSTEM_AGENT_BOOTSTRAP_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
        encoder.u8(CLEAN_SYSTEM_AGENT_BOOTSTRAP_VERSION);
        encoder.u8(self.phase as u8);
        encoder.fixed(self.pins_commitment.as_bytes());
        encoder.fixed(self.plan_commitment.as_bytes());
        encode_large_bytes(&mut encoder, &self.plan);
        encode_wire_option(&mut encoder, self.create_receipt.as_ref());
        encode_wire_option(&mut encoder, self.authority_receipt.as_ref());
        encode_wire_option(&mut encoder, self.catalog_approval.as_ref());
        encode_wire_option(&mut encoder, self.catalog_receipt.as_ref());
        encode_wire_option(&mut encoder, self.catalog_acknowledgement.as_ref());
        encode_wire_option(&mut encoder, self.pending_projection.as_ref());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != CLEAN_SYSTEM_AGENT_BOOTSTRAP_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != super::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        if decoder.u8()? != CLEAN_SYSTEM_AGENT_BOOTSTRAP_VERSION {
            return Err(DecodeError::InvalidTag);
        }
        let phase = match decoder.u8()? {
            0 => CleanSystemAgentBootstrapPhase::Intent,
            1 => CleanSystemAgentBootstrapPhase::CreateReceiptIssued,
            2 => CleanSystemAgentBootstrapPhase::Created,
            3 => CleanSystemAgentBootstrapPhase::AuthorityReceiptIssued,
            4 => CleanSystemAgentBootstrapPhase::AuthorityInstalled,
            5 => CleanSystemAgentBootstrapPhase::CatalogApproved,
            6 => CleanSystemAgentBootstrapPhase::CatalogReceiptIssued,
            7 => CleanSystemAgentBootstrapPhase::CatalogInstalled,
            8 => CleanSystemAgentBootstrapPhase::CatalogAcknowledged,
            9 => CleanSystemAgentBootstrapPhase::Complete,
            _ => return Err(DecodeError::InvalidTag),
        };
        let value = Self {
            phase,
            pins_commitment: Hash(decoder.fixed()?),
            plan_commitment: Hash(decoder.fixed()?),
            plan: decode_large_bytes(&mut decoder, MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES)?,
            create_receipt: decode_wire_option(&mut decoder, MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?,
            authority_receipt: decode_wire_option(&mut decoder, MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?,
            catalog_approval: decode_wire_option(&mut decoder, MAX_MANAGEMENT_APPROVAL_WIRE_BYTES)?,
            catalog_receipt: decode_wire_option(&mut decoder, MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?,
            catalog_acknowledgement: decode_wire_option(
                &mut decoder,
                MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
            )?,
            pending_projection: decode_wire_option(
                &mut decoder,
                MAX_PENDING_AUTHORITY_PROJECTION_BYTES,
            )?,
        };
        let valid_plan =
            AuthorizedCleanSystemAgentBootstrap::decode(&value.plan).is_ok_and(|plan| {
                plan.pins.commitment() == value.pins_commitment && value.matches_plan(&plan)
            });
        if !decoder.exhausted() || !value.is_valid() || !valid_plan || value.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanSystemAgentBootstrapRejection {
    InvalidDescriptor,
    InvalidRuntimePackage,
    InvalidActorPackage,
    InvalidDecision,
    InvalidPins,
    MissingPins,
    MissingRecord,
    InvalidRecord,
    DivergentPins,
    DivergentRecord,
    WrongScope,
    WrongAuthority,
    WrongReceipt,
    WrongOutcome,
    GuestDenied,
    WrongReply,
    WrongDirectory,
    PreexistingHost,
}

#[derive(Debug)]
pub enum CleanSystemAgentBootstrapError {
    PinsStorage,
    RecordStorage,
    IssuerStorage,
    Signer,
    InvalidIssuerState,
    IssuerRejected(CleanManagementIssuerRejection),
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    Host(super::shared_host::SharedAgentHostError),
    Genesis(super::bootstrap::SystemAgentGenesisProviderError),
    Bootstrap(super::bootstrap::SystemAgentGenesisBootstrapError),
    Rejected(CleanSystemAgentBootstrapRejection),
}

impl fmt::Display for CleanSystemAgentBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "clean Shared system-Agent bootstrap failed: {self:?}"
        )
    }
}

impl core::error::Error for CleanSystemAgentBootstrapError {}

/// Exclusive owner of the clean system-Agent bootstrap journal, receipt issuer, live
/// one-voter Shared host, and its authenticated Raft attachment. The signer
/// and root archive are borrowed only while the monotonic bootstrap protocol
/// is driven to `Complete`; neither becomes a process-local authority
/// fallback.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub struct CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    _pins_store: P,
    record_store: R,
    record: CleanSystemAgentBootstrapRecord,
    issuer: DurableCleanManagementIssuer<I>,
    _network_host: SharedAgentNetworkHost,
    host: Arc<Mutex<SharedAgentHost>>,
    snapshot_signer: Arc<dyn LocalMergeAuthenticator>,
    pins: CleanSystemAgentPins,
    creation_receipt: AuthorityReceipt,
    root_lineage: super::invocation_preparation::PhysicalRootLineage,
    // The protected Authority actor predates its managed inventory. Its
    // install is authorized by the root-certified bootstrap plan, not by an
    // Authority inventory row or by whatever happens to be installed now.
    authority_install: super::sdk::InstallActor,
    invocation_gas: u64,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn bootstrap_root_lineage(
    plan: &AuthorizedCleanSystemAgentBootstrap,
) -> Option<super::invocation_preparation::PhysicalRootLineage> {
    let ManagementRequest::Install(install) = plan.catalog_request() else {
        return None;
    };
    let lineage = super::invocation_preparation::PhysicalRootLineage {
        agent: plan.pins.agent,
        actor: install.entry.actor,
        installation_id: install.installation_id,
        registry_reservation: install.registry_reservation,
        install_request: install.lineage_commitment(),
    };
    (lineage.agent != AgentId::ZERO
        && lineage.actor != crate::agent_sdk::ActorId::ZERO
        && lineage.installation_id != crate::agent_sdk::InstallationId::ZERO
        && lineage.registry_reservation != Hash::ZERO
        && lineage.install_request != Hash::ZERO)
        .then_some(lineage)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Reopen from the exact durable plan, or create a fresh plan only when
    /// both bootstrap stores and the host root are empty. Partial or malformed
    /// durable state is rejected without consulting `fresh_plan`.
    #[allow(clippy::too_many_arguments)]
    pub fn open_or_bootstrap_with_factory<S, F>(
        mut pins_store: P,
        mut record_store: R,
        issuer_store: I,
        signer: &mut S,
        fresh_plan: F,
        shared_host_root: impl AsRef<Path>,
        stable_lock_path: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_node: NodeId,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        network: Arc<Network>,
    ) -> Result<Self, CleanSystemAgentBootstrapError>
    where
        S: CleanManagementReceiptSigner,
        F: FnOnce() -> Result<AuthorizedCleanSystemAgentBootstrap, CleanSystemAgentBootstrapError>,
    {
        let shared_host_root = shared_host_root.as_ref();
        let stable_lock_path = stable_lock_path.as_ref();
        let loaded_pins = pins_store
            .load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)
            .map_err(|_| CleanSystemAgentBootstrapError::PinsStorage)?;
        let loaded_record = record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)?;
        let plan = match (loaded_pins.as_deref(), loaded_record.as_deref()) {
            (None, Some(_)) => {
                return Err(rejected(CleanSystemAgentBootstrapRejection::MissingPins));
            }
            (Some(_), None) => {
                return Err(rejected(CleanSystemAgentBootstrapRejection::MissingRecord));
            }
            (Some(pins), Some(record)) => {
                let pins = CleanSystemAgentPins::decode(pins)
                    .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidPins))?;
                let record = CleanSystemAgentBootstrapRecord::decode(record)
                    .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidRecord))?;
                let plan = AuthorizedCleanSystemAgentBootstrap::decode(&record.plan)
                    .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidRecord))?;
                if plan.pins() != &pins {
                    return Err(rejected(CleanSystemAgentBootstrapRejection::DivergentPins));
                }
                if !record.matches_plan(&plan) {
                    return Err(rejected(
                        CleanSystemAgentBootstrapRejection::DivergentRecord,
                    ));
                }
                plan
            }
            (None, None) => {
                if host_root_exists(shared_host_root)? {
                    return Err(rejected(
                        CleanSystemAgentBootstrapRejection::PreexistingHost,
                    ));
                }
                fresh_plan()?
            }
        };
        Self::open_or_bootstrap(
            pins_store,
            record_store,
            issuer_store,
            signer,
            &plan,
            shared_host_root,
            stable_lock_path,
            expected_space,
            expected_node,
            trust,
            merge,
            finality,
            genesis,
            network,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_or_bootstrap<S: CleanManagementReceiptSigner>(
        mut pins_store: P,
        mut record_store: R,
        issuer_store: I,
        signer: &mut S,
        plan: &AuthorizedCleanSystemAgentBootstrap,
        shared_host_root: impl AsRef<Path>,
        stable_lock_path: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_node: NodeId,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        network: Arc<Network>,
    ) -> Result<Self, CleanSystemAgentBootstrapError> {
        plan.validate()
            .map_err(CleanSystemAgentBootstrapError::Rejected)?;
        let current_slot = validate_plan_scope(
            plan,
            expected_space,
            expected_node,
            &trust,
            &merge,
            &network,
        )?;

        let loaded_pins = pins_store
            .load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)
            .map_err(|_| CleanSystemAgentBootstrapError::PinsStorage)?;
        let loaded_record = record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)?;
        if loaded_record.is_some() && loaded_pins.is_none() {
            return Err(rejected(CleanSystemAgentBootstrapRejection::MissingPins));
        }
        let existing_pins = loaded_pins
            .as_deref()
            .map(CleanSystemAgentPins::decode)
            .transpose()
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidPins))?;
        if existing_pins
            .as_ref()
            .is_some_and(|pins| pins != plan.pins())
        {
            return Err(rejected(CleanSystemAgentBootstrapRejection::DivergentPins));
        }
        let existing_record = loaded_record
            .as_deref()
            .map(CleanSystemAgentBootstrapRecord::decode)
            .transpose()
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidRecord))?;
        if existing_record
            .as_ref()
            .is_some_and(|record| !record.matches_plan(plan))
        {
            return Err(rejected(
                CleanSystemAgentBootstrapRejection::DivergentRecord,
            ));
        }
        if existing_pins.is_some()
            && existing_record.is_none()
            && host_root_exists(shared_host_root.as_ref())?
        {
            return Err(rejected(CleanSystemAgentBootstrapRejection::MissingRecord));
        }
        if existing_pins.is_none()
            && existing_record.is_none()
            && host_root_exists(shared_host_root.as_ref())?
        {
            return Err(rejected(
                CleanSystemAgentBootstrapRejection::PreexistingHost,
            ));
        }
        if existing_pins.is_none() {
            pins_store
                .commit(&plan.pins.encode())
                .map_err(|_| CleanSystemAgentBootstrapError::PinsStorage)?;
        }
        let mut record = match existing_record {
            Some(record) => record,
            None => {
                let value = CleanSystemAgentBootstrapRecord::intent(plan);
                commit_bootstrap_record(&mut record_store, &value)?;
                value
            }
        };
        validate_record_against_plan(&record, plan)?;
        if record.phase < CleanSystemAgentBootstrapPhase::CatalogApproved
            && (current_slot < plan.catalog_call.requested_valid_from
                || current_slot > plan.catalog_call.requested_expires_at)
        {
            return Err(rejected(CleanSystemAgentBootstrapRejection::WrongScope));
        }

        let mut issuer = DurableCleanManagementIssuer::open(
            issuer_store,
            plan.pins.authority,
            plan.pins.space,
            plan.pins.agent,
        )
        .map_err(map_issuer_open_error)?;
        if issuer.sequence_high_water() > 3 || issuer.acknowledged_through() > 3 {
            return Err(CleanSystemAgentBootstrapError::InvalidIssuerState);
        }

        let create_receipt = if record.phase < CleanSystemAgentBootstrapPhase::CreateReceiptIssued {
            let issued = issuer
                .issue(&plan.create_decision, signer)
                .map_err(map_issuer_issue_error)?;
            validate_exact_receipt(plan, &plan.create_decision, &issued, 1, 0)?;
            record.create_receipt = Some(issued.clone());
            record.advance(CleanSystemAgentBootstrapPhase::CreateReceiptIssued);
            commit_bootstrap_record(&mut record_store, &record)?;
            issued
        } else {
            record
                .create_receipt
                .clone()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongReceipt))?
        };
        validate_exact_receipt(plan, &plan.create_decision, &create_receipt, 1, 0)?;

        let runtime = plan.runtime().map_err(rejected)?;
        let (create, supplied_catalog) =
            LocalJournalAgentDriver::<FileAgentJournalStore>::clean_shared_system_genesis_input(
                plan.pins.descriptor.clone(),
                &runtime,
                create_receipt.clone(),
                plan.pins.observed_slot,
                &trust,
                &merge,
            )
            .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
        let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
            create,
            plan.pins.replicas.members()[0].replica(),
            &supplied_catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::InvalidDecision))?;
        validate_prepared_system_agent_genesis_root(&prepared, &plan.pins.root)
            .map_err(CleanSystemAgentBootstrapError::Bootstrap)?;
        let locator = SystemAgentGenesisLocator {
            space: crate::service::SpaceId(plan.pins.space.0),
            agent: crate::service::AgentId(plan.pins.agent.0),
            node: crate::service::NodeId(plan.pins.node.0),
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared)
            .map_err(CleanSystemAgentBootstrapError::Bootstrap)?;
        let provision = if record.phase < CleanSystemAgentBootstrapPhase::Created {
            let returned = genesis
                .create(&proposal, &supplied_catalog)
                .map_err(CleanSystemAgentBootstrapError::Genesis)?;
            let reproduced = genesis
                .reproduce(locator)
                .map_err(CleanSystemAgentBootstrapError::Genesis)?;
            if returned != reproduced || reproduced.proposal() != &proposal {
                return Err(rejected(
                    CleanSystemAgentBootstrapRejection::DivergentRecord,
                ));
            }
            reproduced
        } else {
            let reproduced = genesis
                .reproduce(locator)
                .map_err(CleanSystemAgentBootstrapError::Genesis)?;
            if reproduced.proposal() != &proposal {
                return Err(rejected(
                    CleanSystemAgentBootstrapRejection::DivergentRecord,
                ));
            }
            reproduced
        };
        let archived_catalog = load_archived_catalog(genesis.as_ref(), &provision)?;
        if archived_catalog != supplied_catalog {
            return Err(rejected(
                CleanSystemAgentBootstrapRejection::DivergentRecord,
            ));
        }

        let scope = AgentHostScope {
            space: crate::service::SpaceId(expected_space.0),
            node: crate::service::NodeId(expected_node.0),
        };
        let mut shared_host = SharedAgentHost::open_with_root(
            shared_host_root.as_ref(),
            stable_lock_path.as_ref(),
            scope,
            trust,
            Arc::clone(&merge),
            finality,
            plan.pins.root.clone(),
        )
        .map_err(CleanSystemAgentBootstrapError::Host)?;
        let committee_authority = committee_authority_binding(plan)?;
        shared_host
            .provision_system_bootstrap(
                provision,
                plan.pins.replicas.clone(),
                archived_catalog,
                committee_authority,
            )
            .map_err(CleanSystemAgentBootstrapError::Host)?;
        // Reopen may find Raft commit evidence ahead of the clean journal
        // application cursor.  Drain it while the route is still detached so
        // an exact terminal Ack can be proved before any startup checkpoint
        // moves that Ack to the authenticated replay boundary.
        loop {
            match shared_host
                .apply_next(crate::service::AgentId(plan.pins.agent.0))
                .map_err(CleanSystemAgentBootstrapError::Host)?
            {
                crate::agent::shared_host::SharedAgentApplyOutcome::Applied { .. }
                | crate::agent::shared_host::SharedAgentApplyOutcome::Duplicate { .. } => {}
                crate::agent::shared_host::SharedAgentApplyOutcome::Idle => break,
            }
        }
        let host = Arc::new(Mutex::new(shared_host));
        // A crash may follow the exact positive Ack but precede clearing PAP.
        // Prove that terminal boundary directly from authenticated replay and
        // clear it while no route or suffix-consuming worker is reachable.
        // This avoids burying the only Ack proof under a startup checkpoint.
        if let Some(pending) = record.pending_projection.clone() {
            let (work, authorization) = pending
                .invocation()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::DivergentRecord))?;
            if host
                .lock()
                .map_err(|_| {
                    CleanSystemAgentBootstrapError::Host(SharedAgentHostError::Unavailable)
                })?
                .retained_positive_clean_acknowledgement(
                    crate::service::AgentId(plan.pins.agent.0),
                    work,
                    authorization,
                )
                .map_err(CleanSystemAgentBootstrapError::Host)?
            {
                let mut cleared = record.clone();
                cleared.pending_projection = None;
                commit_bootstrap_record(&mut record_store, &cleared)?;
                record = cleared;
            }
        }
        let network_host = if let Some(pending) = &record.pending_projection {
            let (work, authorization) = pending
                .invocation()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::DivergentRecord))?;
            SharedAgentNetworkHost::attach_recovering_projection(
                Arc::clone(&host),
                network,
                crate::service::AgentId(plan.pins.agent.0),
                work,
                authorization,
                &plan.pins.replicas,
                merge.as_ref(),
            )
        } else {
            SharedAgentNetworkHost::attach_system(
                Arc::clone(&host),
                network,
                crate::service::AgentId(plan.pins.agent.0),
                &plan.pins.replicas,
                merge.as_ref(),
            )
        }
        .map_err(CleanSystemAgentBootstrapError::Host)?;

        if issuer.acknowledged_through() < 1 {
            issuer
                .observe_durable(&create_receipt)
                .map_err(map_issuer_observation_error)?;
        }
        if record.phase < CleanSystemAgentBootstrapPhase::Created {
            record.advance(CleanSystemAgentBootstrapPhase::Created);
            commit_bootstrap_record(&mut record_store, &record)?;
        }

        let authority_receipt =
            if record.phase < CleanSystemAgentBootstrapPhase::AuthorityReceiptIssued {
                let issued = issuer
                    .issue(&plan.authority_decision, signer)
                    .map_err(map_issuer_issue_error)?;
                validate_exact_receipt(plan, &plan.authority_decision, &issued, 2, 1)?;
                record.authority_receipt = Some(issued.clone());
                record.advance(CleanSystemAgentBootstrapPhase::AuthorityReceiptIssued);
                commit_bootstrap_record(&mut record_store, &record)?;
                issued
            } else {
                record
                    .authority_receipt
                    .clone()
                    .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongReceipt))?
            };
        validate_exact_receipt(plan, &plan.authority_decision, &authority_receipt, 2, 1)?;
        if record.phase < CleanSystemAgentBootstrapPhase::AuthorityInstalled {
            apply_actor_install(
                &host,
                &network_host,
                plan,
                &plan.authority_request,
                &authority_receipt,
                plan.authority_package().map_err(rejected)?,
            )?;
            record.advance(CleanSystemAgentBootstrapPhase::AuthorityInstalled);
            commit_bootstrap_record(&mut record_store, &record)?;
        }
        ensure_actor_installed(&host, plan, &plan.authority_request)?;
        if issuer.acknowledged_through() < 2 {
            issuer
                .observe_durable(&authority_receipt)
                .map_err(map_issuer_observation_error)?;
        }

        let approval = if record.phase < CleanSystemAgentBootstrapPhase::CatalogApproved {
            let approval = invoke_authorize(&host, &network_host, plan)?;
            record.catalog_approval = Some(approval.clone());
            record.advance(CleanSystemAgentBootstrapPhase::CatalogApproved);
            commit_bootstrap_record(&mut record_store, &record)?;
            approval
        } else {
            record
                .catalog_approval
                .clone()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongOutcome))?
        };
        validate_approval(plan, &approval)?;
        let catalog_decision = AuthorizedCleanManagementDecision::from_approval(
            plan.authority_target(),
            plan.managed_target(),
            &plan.catalog_request,
            &plan.catalog_call,
            &approval,
            &RawCredentialVerifier,
        )
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::WrongOutcome))?;

        let catalog_receipt = if record.phase < CleanSystemAgentBootstrapPhase::CatalogReceiptIssued
        {
            let issued = issuer
                .issue(&catalog_decision, signer)
                .map_err(map_issuer_issue_error)?;
            validate_exact_receipt(plan, &catalog_decision, &issued, 3, 2)?;
            record.catalog_receipt = Some(issued.clone());
            record.advance(CleanSystemAgentBootstrapPhase::CatalogReceiptIssued);
            commit_bootstrap_record(&mut record_store, &record)?;
            issued
        } else {
            record
                .catalog_receipt
                .clone()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongReceipt))?
        };
        validate_exact_receipt(plan, &catalog_decision, &catalog_receipt, 3, 2)?;

        let mut catalog_application = None;
        if record.phase < CleanSystemAgentBootstrapPhase::CatalogInstalled {
            catalog_application = Some(apply_actor_install(
                &host,
                &network_host,
                plan,
                &plan.catalog_request,
                &catalog_receipt,
                plan.catalog_package().map_err(rejected)?,
            )?);
            record.advance(CleanSystemAgentBootstrapPhase::CatalogInstalled);
            commit_bootstrap_record(&mut record_store, &record)?;
        }
        ensure_actor_installed(&host, plan, &plan.catalog_request)?;

        let acknowledgement = if record.phase < CleanSystemAgentBootstrapPhase::CatalogAcknowledged
        {
            let (application, applied_at) = match catalog_application {
                Some(value) => value,
                None => apply_actor_install(
                    &host,
                    &network_host,
                    plan,
                    &plan.catalog_request,
                    &catalog_receipt,
                    plan.catalog_package().map_err(rejected)?,
                )?,
            };
            let reopened_state = host
                .lock()
                .map_err(|_| {
                    CleanSystemAgentBootstrapError::Host(SharedAgentHostError::Unavailable)
                })?
                .clean_state_commitment(crate::service::AgentId(plan.pins.agent.0))
                .map_err(CleanSystemAgentBootstrapError::Host)?;
            let acknowledgement = issuer
                .observe_durable_application(
                    &catalog_receipt,
                    &application,
                    reopened_state,
                    applied_at,
                    signer,
                )
                .map_err(map_issuer_issue_error)?;
            record.catalog_acknowledgement = Some(acknowledgement.clone());
            record.advance(CleanSystemAgentBootstrapPhase::CatalogAcknowledged);
            commit_bootstrap_record(&mut record_store, &record)?;
            acknowledgement
        } else {
            record
                .catalog_acknowledgement
                .clone()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongOutcome))?
        };
        if !acknowledgement.matches_pending(&plan.catalog_call, &approval)
            || acknowledgement.verify_with(&RawCredentialVerifier).is_err()
        {
            return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
        }

        if record.phase < CleanSystemAgentBootstrapPhase::Complete {
            invoke_finalize(&host, &network_host, plan, &acknowledgement)?;
            issuer
                .observe_durable_actor_finalization(&acknowledgement)
                .map_err(map_issuer_observation_error)?;
            record.advance(CleanSystemAgentBootstrapPhase::Complete);
            commit_bootstrap_record(&mut record_store, &record)?;
        } else {
            issuer
                .observe_durable_actor_finalization(&acknowledgement)
                .map_err(map_issuer_observation_error)?;
        }
        if issuer.sequence_high_water() != 3 || issuer.acknowledged_through() != 3 {
            return Err(CleanSystemAgentBootstrapError::InvalidIssuerState);
        }

        let root_lineage =
            bootstrap_root_lineage(plan).ok_or(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::InvalidDecision,
            ))?;
        let mut owner = Self {
            _pins_store: pins_store,
            record_store,
            record,
            issuer,
            _network_host: network_host,
            host,
            snapshot_signer: merge,
            pins: plan.pins.clone(),
            creation_receipt: create_receipt,
            root_lineage,
            authority_install: install_request(plan.authority_request())?.clone(),
            invocation_gas: plan.invocation_gas,
        };
        // Reconstruct volatile admission from the durable exact pending work
        // before returning an owner that could authenticate a fresh query.
        // This reservation is idempotent with the first recovery drive.
        if let Some(pending) = owner.record.pending_projection.clone() {
            let (work, authorization) = pending
                .invocation()
                .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::DivergentRecord))?;
            owner
                ._network_host
                .reserve_recovering_projection_pair(
                    crate::service::AgentId(owner.pins.agent.0),
                    work,
                    authorization,
                    &owner.pins.replicas,
                    owner.snapshot_signer.as_ref(),
                )
                .map_err(CleanSystemAgentBootstrapError::Host)?;
        }
        Ok(owner)
    }

    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }
    pub const fn creation_receipt(&self) -> &AuthorityReceipt {
        &self.creation_receipt
    }
    pub const fn issuer_sequence_high_water(&self) -> u64 {
        self.issuer.sequence_high_water()
    }
    pub const fn issuer_acknowledged_through(&self) -> u64 {
        self.issuer.acknowledged_through()
    }

    pub fn list(&self) -> Result<Vec<AgentId>, SharedAgentHostError> {
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host.show(crate::service::AgentId(self.pins.agent.0))?;
        status
            .is_some()
            .then_some(vec![self.pins.agent])
            .ok_or(SharedAgentHostError::AgentNotFound)
    }

    pub fn show(&self, agent: AgentId) -> Result<Option<AgentDescriptor>, SharedAgentHostError> {
        if agent != self.pins.agent {
            return Ok(None);
        }
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        host.show(crate::service::AgentId(agent.0))?
            .map(|_| self.pins.descriptor.clone())
            .ok_or(SharedAgentHostError::AgentNotFound)
            .map(Some)
    }

    /// Exact live SDK projection for the bootstrapped system Agent. Runtime
    /// and actor upgrades are read from authenticated journal state; immutable
    /// system identity fields remain pinned independently by the bootstrap
    /// record.
    pub(crate) fn supervisor_projections(
        &mut self,
    ) -> Result<Vec<super::shared_host::SharedAgentRuntimeProjection>, SharedAgentHostError> {
        let projections = self._network_host.supervisor_projections()?;
        if projections.len() != 1 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let projection = &projections[0];
        let current = &projection.descriptor;
        if current.validate().is_err()
            || current.identity.space != self.pins.space
            || current.identity.agent != self.pins.agent
            || current.identity.owner != self.pins.descriptor.identity.owner
            || current.identity.profile != AgentProfile::Shared
            || current.creation_nonce != self.pins.descriptor.creation_nonce
            || current.authority != self.pins.descriptor.authority
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(projections)
    }

    pub(crate) fn supervisor_invoke(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        if work.space != self.pins.space || work.agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_invoke(expected, work, authorization)
    }

    fn supervisor_invoke_terminal(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        if work.space != self.pins.space || work.agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_invoke_terminal(expected, work, authorization)
    }

    fn supervisor_invoke_persisted_management(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        let target = self.authority_target();
        if work.space != target.space
            || work.agent != target.system_agent
            || work.runtime_deployment != target.system_runtime_deployment
            || work.actor != target.binding.issuer.actor
            || work.deployment != target.binding.issuer.deployment
            || work.program != target.binding.issuer.program
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_invoke_persisted_management(expected, work, authorization)
    }

    fn supervisor_invoke_terminal_reserved(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        if work.space != self.pins.space || work.agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_invoke_terminal_reserved(expected, work, authorization)
    }

    pub(crate) fn supervisor_resume(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
        yielded: super::sdk::YieldedInvocation,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        if work.space != self.pins.space || work.agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_resume(expected, work, authorization, yielded)
    }

    pub(crate) fn supervisor_acknowledge(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        if work.space != self.pins.space || work.agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_acknowledge(expected, work, authorization)
    }

    fn supervisor_acknowledge_reserved(
        &self,
        expected: super::supervisor::AgentRouteIdentity,
        work: super::sdk::InvocationWork,
        authorization: super::sdk::InvocationAuthorization,
    ) -> Result<super::sdk::RuntimeOutcome, SharedAgentHostError> {
        if work.space != self.pins.space || work.agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host
            .supervisor_acknowledge_reserved(expected, work, authorization)
    }

    pub(crate) fn supervisor_invocation_material(
        &self,
        agent: super::sdk::AgentId,
        actor: super::sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedAgentHostError>
    {
        if agent != self.pins.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let material = self
            ._network_host
            .supervisor_invocation_material(agent, actor)?;
        if material.descriptor.identity.space != self.pins.space
            || material.descriptor.identity.agent != self.pins.agent
            || material.descriptor.identity.owner != self.pins.descriptor.identity.owner
            || material.descriptor.creation_nonce != self.pins.descriptor.creation_nonce
            || material.descriptor.authority != self.pins.descriptor.authority
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(material)
    }

    /// Exact installed target used for authenticated authority inventory
    /// queries. No request-supplied route identity is trusted here.
    pub(crate) const fn authority_target(&self) -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: self.pins.space,
            system_agent: self.pins.agent,
            system_runtime_deployment: self.pins.descriptor.identity.runtime_deployment,
            binding: self.pins.authority,
        }
    }

    /// Authorize the retained management input through the installed system
    /// actor and issue only its exact durably applied approval. This leaves
    /// the invocation result retained: the enclosing lifecycle coordinator
    /// must finish application/finalization before retiring that result.
    pub(crate) fn issue_management_intent<B, J, S>(
        &mut self,
        slot: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
        managed: ManagedAgentTarget,
        issuer: &mut DurableCleanManagementIssuer<J>,
        signer: &mut S,
    ) -> Result<AuthorityReceipt, SharedAgentHostError>
    where
        B: CleanManagementIssuerStore,
        J: CleanManagementIssuerStore,
        S: CleanManagementReceiptSigner,
    {
        use crate::actors::codec::Decode as _;

        if self.record.pending_projection.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        let target = self.authority_target();
        slot.intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .verify(target, managed, &RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        self._network_host
            .ensure_reattached(crate::service::AgentId(self.pins.agent.0))?;
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, target.binding.issuer.actor)?;
        if material.actor.entry.deployment != target.binding.issuer.deployment
            || material.actor.entry.program != target.binding.issuer.program
            || material.producer != target.binding.issuer.producer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        material.root_provenance = false;
        let identity = super::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_none()
        {
            let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
            let mut availability = vec![
                material.program.clone(),
                material.schema.clone(),
                material.policies.clone(),
            ];
            availability.extend(material.installation_data.clone());
            availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
            let work = super::sdk::InvocationWork {
                space: target.space,
                agent: target.system_agent,
                runtime_deployment: target.system_runtime_deployment,
                invocation: intent.call().invocation,
                actor: target.binding.issuer.actor,
                incarnation: material.actor.incarnation,
                deployment: target.binding.issuer.deployment,
                program: target.binding.issuer.program,
                mode: MethodMode::Linear,
                origin: intent.authorization_origin(),
                roles: InvocationRoleClaims::none(),
                message: intent.authorization_message(),
                installation_data: material.actor.entry.installation_data.clone(),
                availability,
                gas: self.invocation_gas,
                recovery_only: false,
            };
            let authorization = InvocationAuthorization::PublicPreflight(
                super::sdk::PublicPreflight::for_work(&work, material.observed_slot),
            );
            if !super::supervisor_adapters::physical_material_authorizes_work(
                &material,
                identity,
                RuntimeExecutionContext::Direct,
                &work,
                &authorization,
            ) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let envelope = RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                invocation: Box::new(work),
                authorization: Box::new(authorization),
                observed_slot: material.observed_slot,
            };
            self._network_host.record_management_anchor(
                crate::service::AgentId(self.pins.agent.0),
                &envelope,
                |anchor| {
                    slot.pledge_authorization_work(envelope.clone(), anchor)
                        .map_err(|_| SharedAgentHostError::Unavailable)
                },
            )?;
        }
        let Some(RuntimeWork::Invoke {
            invocation: work,
            authorization,
            observed_slot,
            ..
        }) = slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if !super::supervisor_adapters::physical_material_authorizes_reserved_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            work,
            authorization,
            *observed_slot,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let outcome = self
            .supervisor_invoke_persisted_management(
                identity,
                (**work).clone(),
                (**authorization).clone(),
            )
            .map_err(|error| {
                crate::log::warn!("management authorization dispatch failed: {error:?}");
                error
            })?;
        let super::sdk::RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            if let super::sdk::RuntimeOutcome::Completed(Err(error)) = outcome {
                crate::log::warn!(
                    "management authorization runtime rejected invocation: {error:?}"
                );
            } else {
                crate::log::warn!("management authorization did not return a completed invocation");
            }
            return Err(SharedAgentHostError::Unavailable);
        };
        if reply.invocation != work.invocation
            || reply.actor != work.actor
            || reply.incarnation != work.incarnation
            || reply.deployment != work.deployment
            || reply.mode != work.mode
            || reply.status != super::sdk::InvocationStatus::Done
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let Some(crate::actors::value::Value::Bytes(bytes)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let approval =
            ManagementApproval::decode(&bytes).map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        slot.issue_from_authenticated_approval(
            target,
            managed,
            &approval,
            &RawCredentialVerifier,
            issuer,
            signer,
        )
        .map_err(|error| {
            use super::clean_authority_issuer::CleanManagementIssuerError;
            match error {
                CleanManagementIssuerError::Rejected(reason) => {
                    crate::log::warn!("management receipt issuance rejected: {reason:?}")
                }
                CleanManagementIssuerError::Storage(_) => {
                    crate::log::warn!("management receipt storage failed")
                }
                CleanManagementIssuerError::Signer(_) => {
                    crate::log::warn!("management receipt signer failed")
                }
                CleanManagementIssuerError::InvalidState => {
                    crate::log::warn!("management receipt issuer state invalid")
                }
            }
            SharedAgentHostError::Unavailable
        })
    }

    /// Finalize only the exact durable application acknowledgement. The work
    /// receives its own current preflight, persisted in CMI4 before dispatch.
    /// Retries reuse that envelope without refreshing its accepted clock.
    pub(crate) fn finalize_management_intent<B, J>(
        &mut self,
        slot: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
        managed: ManagedAgentTarget,
        acknowledgement: &ManagementApplicationAck,
        issuer: &mut DurableCleanManagementIssuer<J>,
    ) -> Result<bool, SharedAgentHostError>
    where
        B: CleanManagementIssuerStore,
        J: CleanManagementIssuerStore,
    {
        use crate::actors::codec::Decode as _;
        let target = self.authority_target();
        let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
        intent
            .verify(target, managed, &RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let Some(RuntimeWork::Invoke {
            invocation: original,
            observed_slot,
            ..
        }) = slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if acknowledgement.authority != target
            || acknowledgement.managed != managed
            || acknowledgement.authorization_invocation != intent.call().invocation
            || acknowledgement.acknowledgement_invocation
                != ManagementApproval::derive_acknowledgement_invocation(intent.call())
            || acknowledgement.credential_call != intent.call().commitment()
            || acknowledgement.request != intent.request().commitment()
            || acknowledgement.applied_at < *observed_slot
            || acknowledgement.verify_with(&RawCredentialVerifier).is_err()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if issuer
            .application_finalization_status(acknowledgement)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        {
            return Ok(false);
        }
        if self.record.pending_projection.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        self._network_host
            .ensure_reattached(crate::service::AgentId(self.pins.agent.0))?;
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, target.binding.issuer.actor)?;
        if material.producer != target.binding.issuer.producer {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        material.root_provenance = false;
        let identity = super::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let expected_message =
            super::clean_management_intent::CleanManagementIntent::finalization_message(
                acknowledgement,
            );
        if slot
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_none()
        {
            let mut work = (**original).clone();
            work.invocation = acknowledgement.acknowledgement_invocation;
            work.origin = super::sdk::InvocationOrigin::anonymous();
            work.message = expected_message.clone();
            let authorization = InvocationAuthorization::PublicPreflight(
                super::sdk::PublicPreflight::for_work(&work, material.observed_slot),
            );
            if !super::supervisor_adapters::physical_material_authorizes_work(
                &material,
                identity,
                RuntimeExecutionContext::Direct,
                &work,
                &authorization,
            ) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let envelope = RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                invocation: Box::new(work),
                authorization: Box::new(authorization),
                observed_slot: material.observed_slot,
            };
            self._network_host.record_management_anchor(
                crate::service::AgentId(self.pins.agent.0),
                &envelope,
                |anchor| {
                    slot.pledge_finalization_work(envelope.clone(), anchor)
                        .map_err(|_| SharedAgentHostError::Unavailable)
                },
            )?;
        }
        let Some(RuntimeWork::Invoke {
            invocation: work,
            authorization,
            observed_slot,
            ..
        }) = slot
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if work.message != expected_message {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if !super::supervisor_adapters::physical_material_authorizes_reserved_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            work,
            authorization,
            *observed_slot,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let outcome = self.supervisor_invoke_persisted_management(
            identity,
            (**work).clone(),
            (**authorization).clone(),
        )?;
        let super::sdk::RuntimeOutcome::Completed(Ok(reply)) = &outcome else {
            return Err(SharedAgentHostError::Unavailable);
        };
        if reply.invocation != work.invocation
            || reply.actor != work.actor
            || reply.incarnation != work.incarnation
            || reply.deployment != work.deployment
            || reply.mode != work.mode
            || reply.status != super::sdk::InvocationStatus::Done
            || crate::actors::value::Value::try_decode(&reply.reply)
                != Some(crate::actors::value::Value::Bool(true))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let replayed = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .replay_durable_clean_terminal(
                crate::service::AgentId(self.pins.agent.0),
                (**work).clone(),
                (**authorization).clone(),
            )?;
        if replayed != outcome {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        issuer
            .observe_durable_actor_finalization(acknowledgement)
            .map_err(|_| SharedAgentHostError::Unavailable)
    }

    /// Retire both runtime results only after the exact application has a
    /// durable issuer finalization marker. This phase preserves intent/issuer
    /// evidence; it does not yet authorize clearing or replacing the intent.
    /// The reservation remains held after success until a durable handoff
    /// commits through the network owner's completion boundary.
    pub(crate) fn retire_management_intent_results<B, J>(
        &mut self,
        slot: &super::clean_management_intent::CleanManagementIntentSlot<B>,
        managed: ManagedAgentTarget,
        acknowledgement: &ManagementApplicationAck,
        issuer: &DurableCleanManagementIssuer<J>,
    ) -> Result<bool, SharedAgentHostError>
    where
        B: CleanManagementIssuerStore,
        J: CleanManagementIssuerStore,
    {
        let target = self.authority_target();
        let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
        intent
            .verify(target, managed, &RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let (_, retained) = issuer
            .recover_finalized_application(
                target,
                managed,
                intent.request(),
                intent.call(),
                &RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if retained != *acknowledgement || self.record.pending_projection.is_some() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authorization_work = slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let RuntimeWork::Invoke { observed_slot, .. } = authorization_work else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if acknowledgement.applied_at < *observed_slot {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let finalization_work = slot
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let RuntimeWork::Invoke { invocation, .. } = finalization_work else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if invocation.message
            != super::clean_management_intent::CleanManagementIntent::finalization_message(
                acknowledgement,
            )
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if slot
            .retirement_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Ok(false);
        }
        self._network_host
            .ensure_reattached(crate::service::AgentId(self.pins.agent.0))?;
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, target.binding.issuer.actor)?;
        material.root_provenance = false;
        let identity = super::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        // Validate both immutable envelopes before retiring either result.
        for envelope in [authorization_work, finalization_work] {
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = envelope
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if invocation.mode != super::sdk::MethodMode::Linear
                || !super::supervisor_adapters::physical_material_authorizes_reserved_work(
                    &material,
                    identity,
                    RuntimeExecutionContext::Direct,
                    invocation,
                    authorization,
                    *observed_slot,
                )
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let mut changed = false;
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host
            .reserve_management_retirement(agent, [authorization_work, finalization_work])?;
        for envelope in [authorization_work, finalization_work] {
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = envelope
            else {
                unreachable!()
            };
            if self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
            {
                continue;
            }
            let outcome = self
                ._network_host
                .supervisor_acknowledge_management_retirement(
                    identity,
                    (**invocation).clone(),
                    (**authorization).clone(),
                )?;
            let super::sdk::RuntimeOutcome::Acknowledged(Ok(retired)) = outcome else {
                return Err(SharedAgentHostError::Unavailable);
            };
            if retired.invocation != invocation.invocation
                || retired.actor != invocation.actor
                || retired.incarnation != invocation.incarnation
                || retired.deployment != invocation.deployment
                || retired.mode != invocation.mode
                || retired.work != invocation.commitment()
                || retired.authorization != authorization.commitment()
                || !self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            changed = true;
        }
        Ok(changed)
    }

    /// Finish retirement under live admission exclusion and publish its durable
    /// host marker before releasing the reservation. Production startup must
    /// still restore pending reservations before exposing ingress.
    pub(crate) fn finish_management_intent_retirement<B, J>(
        &mut self,
        slot: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
        managed: ManagedAgentTarget,
        acknowledgement: &ManagementApplicationAck,
        issuer: &DurableCleanManagementIssuer<J>,
    ) -> Result<bool, SharedAgentHostError>
    where
        B: CleanManagementIssuerStore,
        J: CleanManagementIssuerStore,
    {
        // Always reverify the signed intent and finalized issuer acknowledgement,
        // even when recovering the durable marker rather than journal results.
        self.retire_management_intent_results(slot, managed, acknowledgement, issuer)?;
        let authorization = slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .clone();
        let finalization = slot
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .clone();
        let agent = crate::service::AgentId(self.pins.agent.0);
        if slot
            .retirement_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            self._network_host
                .release_completed_management_retirement(agent, [&authorization, &finalization])?;
            return Ok(false);
        }
        self._network_host.complete_management_retirement(
            agent,
            [&authorization, &finalization],
            || {
                slot.commit_retirement(acknowledgement)
                    .map(|_| ())
                    .map_err(|_| SharedAgentHostError::Unavailable)
            },
        )?;
        Ok(true)
    }

    /// Execute the Local Create/application portion of a retained lifecycle
    ///
    /// The public coordinator below is the boundary for native callers.
    /// intent. No route is published and no Authority effect is finalized here.
    /// The caller must retain exclusive lifecycle ownership through those phases.
    pub(crate) fn create_local_from_management_intent<B, J, S>(
        &mut self,
        slot: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
        managed: ManagedAgentTarget,
        local: &mut super::local_sdk_host::LocalAgentHost,
        runtime: AdmittedRuntimePackage,
        issuer: &mut DurableCleanManagementIssuer<J>,
        signer: &mut S,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError>
    where
        B: CleanManagementIssuerStore,
        J: CleanManagementIssuerStore,
        S: CleanManagementReceiptSigner,
    {
        let request = slot
            .intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .request()
            .clone();
        let ManagementRequest::Create(descriptor) = &request else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if descriptor.identity.profile != AgentProfile::Local
            || local.space() != self.pins.space
            || local.node() != self.pins.node
            || descriptor.identity.space != local.space()
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != local.node()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        super::driver::verify_clean_runtime_package_binding(descriptor, &runtime)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let receipt = self.issue_management_intent(slot, managed, issuer, signer)?;
        let agent = local
            .create_agent(runtime, (**descriptor).clone(), receipt.clone())
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        // This observation reloads the image and re-admits its runtime and
        // catalog. An in-memory Created reply is not application evidence.
        let observation = local
            .observe_management_application(agent, &request, &receipt)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let acknowledgement = issuer
            .observe_local_application(&observation, signer)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok((agent, acknowledgement))
    }

    /// Create and finalize one signed Local Agent lifecycle using independent
    /// durable intent and issuer stores. Reopen those same stores after any
    /// error; a failed write may already have reached durable storage.
    ///
    /// The caller owns the Local host exclusively until authenticated route
    /// publication. This does not publish routes, retire lifecycle evidence,
    /// or provide journal-backed ordinary-Agent genesis finality.
    #[allow(clippy::too_many_arguments)]
    pub fn create_local_agent<B, J, S>(
        &mut self,
        intent_store: B,
        issuer_store: J,
        descriptor: super::sdk::AgentDescriptor,
        call: AuthorityCredentialCall,
        local: &mut super::local_sdk_host::LocalAgentHost,
        runtime: AdmittedRuntimePackage,
        signer: &mut S,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError>
    where
        B: CleanManagementIssuerStore,
        J: CleanManagementIssuerStore,
        S: CleanManagementReceiptSigner,
    {
        let target = self.authority_target();
        let managed = call.managed;
        if descriptor.identity.profile != AgentProfile::Local
            || descriptor.identity.space != self.pins.space
            || local.space() != self.pins.space
            || local.node() != self.pins.node
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != self.pins.node
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let intent = super::clean_management_intent::CleanManagementIntent::new(
            target,
            managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call,
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let mut slot =
            super::clean_management_intent::CleanManagementIntentSlot::open(intent_store)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut issuer = DurableCleanManagementIssuer::open(
            issuer_store,
            descriptor.authority,
            descriptor.identity.space,
            descriptor.identity.agent,
        )
        .map_err(|_| SharedAgentHostError::Unavailable)?;
        slot.pledge(intent).map_err(|error| {
            use super::clean_management_intent::IntentSlotError;
            match error {
                IntentSlotError::Conflict => SharedAgentHostError::Conflict,
                IntentSlotError::Invalid => SharedAgentHostError::ScopeMismatch,
                IntentSlotError::Storage(_) | IntentSlotError::Poisoned => {
                    SharedAgentHostError::Unavailable
                }
            }
        })?;
        let retained = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
        if let Some((receipt, acknowledgement)) = issuer
            .recover_finalized_application(
                target,
                managed,
                retained.request(),
                retained.call(),
                &RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        {
            // A finalized issuer record replaces repeated authority dispatch,
            // never physical application evidence or route publication. Missing
            // lifecycle envelopes or a missing/substituted Local image fail shut.
            let Some(RuntimeWork::Invoke { observed_slot, .. }) = slot
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            let Some(RuntimeWork::Invoke { invocation, .. }) = slot
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if acknowledgement.applied_at < *observed_slot
                || invocation.message
                    != super::clean_management_intent::CleanManagementIntent::finalization_message(
                        &acknowledgement,
                    )
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let agent = descriptor.identity.agent;
            let observation = local
                .observe_management_application(agent, retained.request(), &receipt)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let recovered = issuer
                .observe_local_application(&observation, signer)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if recovered != acknowledgement {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            return Ok((agent, acknowledgement));
        }
        let (agent, acknowledgement) = self.create_local_from_management_intent(
            &mut slot,
            managed,
            local,
            runtime,
            &mut issuer,
            signer,
        )?;
        self.finalize_management_intent(&mut slot, managed, &acknowledgement, &mut issuer)?;
        Ok((agent, acknowledgement))
    }

    pub(crate) fn audit_authority_projection(
        &mut self,
        head: super::sdk::authority::AuthorityProjectionHead,
        projection: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<super::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError> {
        if projection.len() != 1
            || projection[0].descriptor().identity.agent != self.pins.agent
            || projection[0].descriptor().identity.space != self.pins.space
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authority = &self.authority_install;
        let mut actors = projection[0].actors().to_vec();
        // Authority explicitly forbids managing its own protected actor.
        // Never let an inventory response replace that independent root pin.
        let index = actors
            .binary_search_by_key(&authority.entry.actor, |actor| actor.entry.actor)
            .err()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        actors.insert(
            index,
            super::sdk::authority::AuthorityActorProjection {
                agent: self.pins.agent,
                entry: authority.entry.clone(),
                producer: authority.producer,
                contract: authority.contract,
                requirements: authority.requirements,
                root_provenance: false,
                installation_id: authority.installation_id,
                registry_reservation: authority.registry_reservation,
                install_request: authority.lineage_commitment(),
            },
        );
        let complete = super::supervisor_adapters::AgentAuthorityRouteProjection::new(
            projection[0].replica_generation(),
            projection[0].descriptor().clone(),
            actors,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        // The normal physical audit still checks the complete directory and
        // exact package/install material, including the pinned Authority row.
        self._network_host
            .audit_authority_projection(head, &[complete], Some(&self.root_lineage))
    }

    /// Drain the exact authenticated operation retained before a failed
    /// dispatch. Callers must do this before minting another query nonce.
    pub(crate) fn recover_pending_authority_projection(
        &mut self,
    ) -> Result<bool, SharedAgentHostError> {
        let Some(pending) = self.record.pending_projection.clone() else {
            return Ok(false);
        };
        let (work, authorization) = pending
            .invocation()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let work = work.clone();
        let authorization = authorization.clone();
        self._network_host.reserve_recovering_projection_pair(
            crate::service::AgentId(self.pins.agent.0),
            &work,
            &authorization,
            &self.pins.replicas,
            self.snapshot_signer.as_ref(),
        )?;
        self.execute_pending_authority_projection().map(|_| true)
    }

    /// Execute one read-only authority projection through the exact physical
    /// system route, then durably acknowledge its retained result before any
    /// bytes are returned to the inventory client.
    pub(crate) fn invoke_authority_projection(
        &mut self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, SharedAgentHostError> {
        if query.validate_shape().is_err() || query.authority != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(pending) = &self.record.pending_projection {
            return if pending.query == query {
                let pending = pending.clone();
                let (work, authorization) = pending
                    .invocation()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                self._network_host.reserve_recovering_projection_pair(
                    crate::service::AgentId(self.pins.agent.0),
                    work,
                    authorization,
                    &self.pins.replicas,
                    self.snapshot_signer.as_ref(),
                )?;
                self.execute_pending_authority_projection()?
                    .ok_or(SharedAgentHostError::Unavailable)
            } else {
                Err(SharedAgentHostError::Conflict)
            };
        }
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host.ensure_reattached(agent)?;
        let pending = self.prepare_authority_projection(query)?;
        let (work, authorization) = pending
            .invocation()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let work = work.clone();
        let authorization = authorization.clone();
        let mut reserved = false;
        for attempt in 0..3 {
            match self
                ._network_host
                .reserve_projection_pair(agent, &work, &authorization, false)
            {
                Ok(()) => {
                    reserved = true;
                    break;
                }
                Err(SharedAgentHostError::CapacityExhausted) if attempt < 2 => {
                    self._network_host
                        .certified_checkpoint_for_projection_pair(
                            agent,
                            &work,
                            &authorization,
                            &self.pins.replicas,
                            self.snapshot_signer.as_ref(),
                        )?;
                }
                Err(error) => return Err(error),
            }
        }
        if !reserved {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        if let Err(error) = self.pending_authority_projection_identity(&pending, false) {
            let _ = self
                ._network_host
                .release_projection_pair(agent, &work, &authorization);
            return Err(error);
        }
        let prior = self.record.clone();
        let mut record = prior.clone();
        record.pending_projection = Some(pending);
        match commit_new_pending_projection(&mut self.record_store, &prior, &record) {
            PendingProjectionRecordCommit::Durable => {}
            PendingProjectionRecordCommit::PriorVisible => {
                let _ = self
                    ._network_host
                    .release_projection_pair(agent, &work, &authorization);
                return Err(SharedAgentHostError::Unavailable);
            }
            PendingProjectionRecordCommit::Ambiguous => {
                // The write may have published without returning success.
                // Retain the exact volatile exclusion and fail closed; only
                // reopen/reload can safely decide which record is durable.
                return Err(SharedAgentHostError::Unavailable);
            }
        }
        self.record = record;
        self.execute_pending_authority_projection()?
            .ok_or(SharedAgentHostError::Unavailable)
    }

    fn prepare_authority_projection(
        &self,
        query: AuthorityProjectionQuery,
    ) -> Result<PendingAuthorityProjection, SharedAgentHostError> {
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, self.pins.authority.issuer.actor)?;
        if material.actor.entry.actor != self.pins.authority.issuer.actor
            || material.actor.entry.deployment != self.pins.authority.issuer.deployment
            || material.actor.entry.program != self.pins.authority.issuer.program
            || material.producer != self.pins.authority.issuer.producer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // The authority actor is bootstrapped before the authority's root
        // catalog marker and therefore is not itself root-provenance marked.
        material.root_provenance = false;
        let query_bytes = query
            .encode()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let mut availability = vec![
            material.program.clone(),
            material.schema.clone(),
            material.policies.clone(),
        ];
        availability.extend(material.installation_data.clone());
        availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        if availability
            .windows(2)
            .any(|pair| pair[0].reference >= pair[1].reference)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let work = super::sdk::InvocationWork {
            space: self.pins.space,
            agent: self.pins.agent,
            runtime_deployment: material.descriptor.identity.runtime_deployment,
            invocation: super::sdk::InvocationId(
                Hash::digest(
                    b"vos/system-authority/projection-invocation/v2",
                    &[query.commitment().as_bytes()],
                )
                .0,
            ),
            actor: material.actor.entry.actor,
            incarnation: material.actor.incarnation,
            deployment: material.actor.entry.deployment,
            program: material.actor.entry.program,
            mode: super::sdk::MethodMode::Query,
            origin: super::sdk::InvocationOrigin {
                principal: None,
                transport_node: query.attesting_node(),
                credential: None,
                actor: None,
                capability: None,
            },
            roles: super::sdk::InvocationRoleClaims::none(),
            message: dynamic_message(
                projection_method(query.selector),
                "query",
                crate::actors::value::Value::Bytes(query_bytes),
            ),
            installation_data: material.actor.entry.installation_data.clone(),
            availability,
            gas: self.invocation_gas,
            recovery_only: false,
        };
        if !work.validate() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authorization = super::sdk::InvocationAuthorization::PublicPreflight(
            super::sdk::PublicPreflight::for_work(&work, material.observed_slot),
        );
        let pending = PendingAuthorityProjection {
            query,
            work: RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                invocation: Box::new(work),
                observed_slot: match &authorization {
                    InvocationAuthorization::PublicPreflight(preflight) => preflight.observed_slot,
                    InvocationAuthorization::AuthorityReceipt(_) => unreachable!(),
                },
                authorization: Box::new(authorization),
            },
        };
        pending
            .validate()
            .then_some(pending)
            .ok_or(SharedAgentHostError::ScopeMismatch)
    }

    fn execute_pending_authority_projection(
        &mut self,
    ) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
        use crate::actors::codec::Decode as _;

        let pending = self
            .record
            .pending_projection
            .clone()
            .ok_or(SharedAgentHostError::Unavailable)?;
        if !pending.validate() || pending.query.authority != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (work, authorization) = pending
            .invocation()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .retained_positive_clean_acknowledgement(
                crate::service::AgentId(self.pins.agent.0),
                work,
                authorization,
            )?
        {
            self.complete_pending_authority_projection(work, authorization)?;
            return Ok(None);
        }
        let identity = self.pending_authority_projection_identity(&pending, true)?;
        let outcome = self.supervisor_invoke_terminal_reserved(
            identity,
            work.clone(),
            authorization.clone(),
        )?;
        let response = match &outcome {
            super::sdk::RuntimeOutcome::Completed(Ok(reply))
                if reply.invocation == work.invocation
                    && reply.actor == work.actor
                    && reply.incarnation == work.incarnation
                    && reply.deployment == work.deployment
                    && reply.mode == work.mode
                    && reply.status == super::sdk::InvocationStatus::Done =>
            {
                match crate::actors::value::Value::try_decode(&reply.reply) {
                    Some(crate::actors::value::Value::Bytes(bytes)) => Some(bytes),
                    _ => None,
                }
            }
            _ => None,
        };
        if !matches!(outcome, super::sdk::RuntimeOutcome::Completed(_)) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let acknowledgement =
            self.supervisor_acknowledge_reserved(identity, work.clone(), authorization.clone())?;
        let super::sdk::RuntimeOutcome::Acknowledged(Ok(acknowledged)) = acknowledgement else {
            return Err(SharedAgentHostError::Unavailable);
        };
        if acknowledged.invocation != work.invocation
            || acknowledged.actor != work.actor
            || acknowledged.incarnation != work.incarnation
            || acknowledged.deployment != work.deployment
            || acknowledged.mode != work.mode
            || acknowledged.work != work.commitment()
            || acknowledged.authorization != authorization.commitment()
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        self.complete_pending_authority_projection(work, authorization)?;
        Ok(response)
    }

    fn pending_authority_projection_identity(
        &self,
        pending: &PendingAuthorityProjection,
        persisted: bool,
    ) -> Result<super::supervisor::AgentRouteIdentity, SharedAgentHostError> {
        if !pending.validate() || pending.query.authority != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (work, authorization) = pending
            .invocation()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, self.pins.authority.issuer.actor)?;
        if material.actor.entry.actor != self.pins.authority.issuer.actor
            || material.actor.entry.deployment != self.pins.authority.issuer.deployment
            || material.actor.entry.program != self.pins.authority.issuer.program
            || material.producer != self.pins.authority.issuer.producer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        material.root_provenance = false;
        let identity = super::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let InvocationAuthorization::PublicPreflight(preflight) = authorization else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let authorized = if persisted {
            super::supervisor_adapters::physical_material_authorizes_reserved_work(
                &material,
                identity,
                RuntimeExecutionContext::Direct,
                work,
                authorization,
                preflight.observed_slot,
            )
        } else {
            super::supervisor_adapters::physical_material_authorizes_work(
                &material,
                identity,
                RuntimeExecutionContext::Direct,
                work,
                authorization,
            )
        };
        if !authorized {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(identity)
    }

    fn clear_pending_authority_projection(&mut self) -> Result<(), SharedAgentHostError> {
        let mut record = self.record.clone();
        record.pending_projection = None;
        commit_bootstrap_record(&mut self.record_store, &record)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.record = record;
        Ok(())
    }

    fn complete_pending_authority_projection(
        &mut self,
        work: &super::sdk::InvocationWork,
        authorization: &super::sdk::InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let mut record = self.record.clone();
        record.pending_projection = None;
        let network_host = &self._network_host;
        let record_store = &mut self.record_store;
        network_host.complete_projection_pair(
            crate::service::AgentId(self.pins.agent.0),
            work,
            authorization,
            || {
                commit_bootstrap_record(record_store, &record)
                    .map_err(|_| SharedAgentHostError::Unavailable)
            },
        )?;
        self.record = record;
        Ok(())
    }

    #[cfg(test)]
    fn ordered_index_for_test(&self) -> Result<u64, SharedAgentHostError> {
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .journal_position(crate::service::AgentId(self.pins.agent.0))
            .map(|position| position.ordered_index)
    }

    #[cfg(test)]
    fn network_host_for_test(&self) -> &SharedAgentNetworkHost {
        &self._network_host
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn rejected(value: CleanSystemAgentBootstrapRejection) -> CleanSystemAgentBootstrapError {
    CleanSystemAgentBootstrapError::Rejected(value)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn validate_plan_scope(
    plan: &AuthorizedCleanSystemAgentBootstrap,
    expected_space: SpaceId,
    expected_node: NodeId,
    trust: &Arc<dyn AgentTrustProvider>,
    merge: &Arc<dyn LocalMergeAuthenticator>,
    network: &Arc<Network>,
) -> Result<u64, CleanSystemAgentBootstrapError> {
    let Some(current_slot) = trust.current_logical_slot() else {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongScope));
    };
    if expected_space != plan.pins.space
        || expected_node != plan.pins.node
        || merge.node().0 != expected_node.0
        || network.agent_node_id() != expected_node
        || current_slot < plan.pins.observed_slot
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongScope));
    }
    Ok(current_slot)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn host_root_exists(root: &Path) -> Result<bool, CleanSystemAgentBootstrapError> {
    match fs::symlink_metadata(root) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CleanSystemAgentBootstrapError::Host(
            SharedAgentHostError::Unavailable,
        )),
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn commit_bootstrap_record<R: CleanSystemAgentBootstrapStore>(
    store: &mut R,
    record: &CleanSystemAgentBootstrapRecord,
) -> Result<(), CleanSystemAgentBootstrapError> {
    if !record.is_valid() {
        return Err(rejected(CleanSystemAgentBootstrapRejection::InvalidRecord));
    }
    store
        .commit(&record.encode())
        .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingProjectionRecordCommit {
    Durable,
    PriorVisible,
    Ambiguous,
}

/// Persist a first PAP while preserving its volatile proposal exclusion over
/// an error whose publication point is unknown. Only the exact prior record
/// proves that no durable pending key exists. An exact visible candidate is
/// retried idempotently and must receive a successful commit result before
/// its physical Invoke may execute.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn commit_new_pending_projection<R: CleanSystemAgentBootstrapStore>(
    store: &mut R,
    prior: &CleanSystemAgentBootstrapRecord,
    candidate: &CleanSystemAgentBootstrapRecord,
) -> PendingProjectionRecordCommit {
    if prior.pending_projection.is_some()
        || candidate.pending_projection.is_none()
        || commit_bootstrap_record(store, candidate).is_ok()
    {
        return if prior.pending_projection.is_none() && candidate.pending_projection.is_some() {
            PendingProjectionRecordCommit::Durable
        } else {
            PendingProjectionRecordCommit::Ambiguous
        };
    }
    let visible = match store.load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) | Err(_) => return PendingProjectionRecordCommit::Ambiguous,
    };
    let prior_bytes = prior.encode();
    if visible == prior_bytes
        && CleanSystemAgentBootstrapRecord::decode(&visible)
            .ok()
            .as_ref()
            == Some(prior)
    {
        return PendingProjectionRecordCommit::PriorVisible;
    }
    let candidate_bytes = candidate.encode();
    if visible != candidate_bytes
        || CleanSystemAgentBootstrapRecord::decode(&visible)
            .ok()
            .as_ref()
            != Some(candidate)
    {
        return PendingProjectionRecordCommit::Ambiguous;
    }
    if commit_bootstrap_record(store, candidate).is_ok() {
        PendingProjectionRecordCommit::Durable
    } else {
        PendingProjectionRecordCommit::Ambiguous
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn committee_authority_binding(
    plan: &AuthorizedCleanSystemAgentBootstrap,
) -> Result<CommitteeChangeAuthorityBinding, CleanSystemAgentBootstrapError> {
    CommitteeChangeAuthorityBinding::new(
        plan.pins.authority.policy,
        plan.pins.authority.issuer,
        plan.pins.descriptor.identity.runtime_deployment,
        plan.pins.authority.public_key,
        plan.pins.authority.initial_epoch,
    )
    .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::WrongAuthority))
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn load_archived_catalog(
    provider: &dyn SystemAgentGenesisProvider,
    provision: &super::bootstrap::SystemAgentGenesisProvision,
) -> Result<Vec<RuntimeBlob>, CleanSystemAgentBootstrapError> {
    let locator = provision.proposal().locator();
    let mut catalog = Vec::new();
    for reference in provision.proposal().catalog() {
        let bytes = provider
            .load_catalog(locator, reference)
            .map_err(CleanSystemAgentBootstrapError::Genesis)?
            .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::DivergentRecord))?;
        if !reference.matches(&bytes) {
            return Err(rejected(
                CleanSystemAgentBootstrapRejection::DivergentRecord,
            ));
        }
        catalog.push(RuntimeBlob {
            reference: reference.clone(),
            bytes,
        });
    }
    Ok(catalog)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn validate_exact_receipt(
    plan: &AuthorizedCleanSystemAgentBootstrap,
    decision: &AuthorizedCleanManagementDecision,
    receipt: &AuthorityReceipt,
    sequence: u64,
    acknowledged_through: u64,
) -> Result<(), CleanSystemAgentBootstrapError> {
    if receipt.selector.decision_sequence != sequence
        || receipt.selector.acknowledged_through != acknowledged_through
        || !decision.matches_receipt(plan.pins.authority, receipt)
        || receipt
            .verify_at(receipt.selector.valid_from, &RawCredentialVerifier)
            .is_err()
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongReceipt));
    }
    Ok(())
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn validate_approval(
    plan: &AuthorizedCleanSystemAgentBootstrap,
    approval: &ManagementApproval,
) -> Result<(), CleanSystemAgentBootstrapError> {
    if !approval.matches_call(&plan.catalog_call)
        || approval.authority != plan.authority_target()
        || approval.managed != plan.managed_target()
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    }
    Ok(())
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn validate_record_against_plan(
    record: &CleanSystemAgentBootstrapRecord,
    plan: &AuthorizedCleanSystemAgentBootstrap,
) -> Result<(), CleanSystemAgentBootstrapError> {
    if !record.matches_plan(plan) {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::DivergentRecord,
        ));
    }
    if record
        .pending_projection
        .as_ref()
        .is_some_and(|pending| pending.query.authority != plan.authority_target())
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::InvalidRecord));
    }
    if let Some(receipt) = &record.create_receipt {
        validate_exact_receipt(plan, &plan.create_decision, receipt, 1, 0)?;
    }
    if let Some(receipt) = &record.authority_receipt {
        validate_exact_receipt(plan, &plan.authority_decision, receipt, 2, 1)?;
    }
    if let Some(approval) = &record.catalog_approval {
        validate_approval(plan, approval)?;
        let decision = AuthorizedCleanManagementDecision::from_approval(
            plan.authority_target(),
            plan.managed_target(),
            &plan.catalog_request,
            &plan.catalog_call,
            approval,
            &RawCredentialVerifier,
        )
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::WrongOutcome))?;
        if let Some(receipt) = &record.catalog_receipt {
            validate_exact_receipt(plan, &decision, receipt, 3, 2)?;
        }
        if let Some(acknowledgement) = &record.catalog_acknowledgement
            && (!acknowledgement.matches_pending(&plan.catalog_call, approval)
                || acknowledgement.verify_with(&RawCredentialVerifier).is_err())
        {
            return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
        }
    } else if record.catalog_receipt.is_some() || record.catalog_acknowledgement.is_some() {
        return Err(rejected(CleanSystemAgentBootstrapRejection::InvalidRecord));
    }
    Ok(())
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn install_request(
    request: &ManagementRequest,
) -> Result<&super::sdk::InstallActor, CleanSystemAgentBootstrapError> {
    let ManagementRequest::Install(install) = request else {
        return Err(rejected(
            CleanSystemAgentBootstrapRejection::InvalidDecision,
        ));
    };
    Ok(install)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn inspect_actor(
    host: &Arc<Mutex<SharedAgentHost>>,
    plan: &AuthorizedCleanSystemAgentBootstrap,
    actor: ActorId,
) -> Result<Option<super::sdk::ActorDirectoryRecord>, CleanSystemAgentBootstrapError> {
    let outcome = host
        .lock()
        .map_err(|_| CleanSystemAgentBootstrapError::Host(SharedAgentHostError::Unavailable))?
        .inspect_clean_management(
            crate::service::AgentId(plan.pins.agent.0),
            &ManagementRequest::InspectActors {
                after: None,
                limit: super::sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
            },
        )
        .map_err(CleanSystemAgentBootstrapError::Host)?;
    let super::sdk::RuntimeOutcome::Management(Ok(super::sdk::ManagementReply::Actors(page))) =
        outcome
    else {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    };
    if page.validate().is_err() || page.next.is_some() {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    }
    Ok(page
        .entries
        .into_iter()
        .find(|record| record.entry.actor == actor))
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn ensure_actor_installed(
    host: &Arc<Mutex<SharedAgentHost>>,
    plan: &AuthorizedCleanSystemAgentBootstrap,
    request: &ManagementRequest,
) -> Result<super::sdk::ActorDirectoryRecord, CleanSystemAgentBootstrapError> {
    let install = install_request(request)?;
    let record = inspect_actor(host, plan, install.entry.actor)?
        .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongDirectory))?;
    if record.entry != install.entry
        || record.installation_id != install.installation_id
        || record.registry_reservation != install.registry_reservation
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongDirectory));
    }
    Ok(record)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn apply_actor_install(
    host: &Arc<Mutex<SharedAgentHost>>,
    network_host: &SharedAgentNetworkHost,
    plan: &AuthorizedCleanSystemAgentBootstrap,
    request: &ManagementRequest,
    receipt: &AuthorityReceipt,
    package: AdmittedActorPackage,
) -> Result<(super::sdk::ManagementReply, u64), CleanSystemAgentBootstrapError> {
    let install = install_request(request)?;
    let already_installed = inspect_actor(host, plan, install.entry.actor)?;
    if let Some(record) = &already_installed
        && (record.entry != install.entry
            || record.installation_id != install.installation_id
            || record.registry_reservation != install.registry_reservation)
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongDirectory));
    }
    let artifacts = if already_installed.is_some() {
        SdkManagementArtifacts::None
    } else {
        SdkManagementArtifacts::Actor(&package)
    };
    let submission = network_host
        .manage_clean(
            crate::service::AgentId(plan.pins.agent.0),
            request.clone(),
            receipt.clone(),
            artifacts,
        )
        .map_err(CleanSystemAgentBootstrapError::Host)?;
    let (outcome, observed_slot) = match submission {
        crate::network::shared_agent::CleanManagementSubmission::Denied { .. } => {
            return Err(rejected(CleanSystemAgentBootstrapRejection::GuestDenied));
        }
        crate::network::shared_agent::CleanManagementSubmission::Applied {
            outcome,
            observed_slot,
            ..
        } => (outcome, observed_slot),
    };
    let super::sdk::RuntimeOutcome::Management(Ok(reply)) = outcome else {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongReply));
    };
    if reply != super::sdk::ManagementReply::Installed(install.entry.clone()) {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongReply));
    }
    ensure_actor_installed(host, plan, request)?;
    Ok((reply, observed_slot))
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn invocation_availability(
    install: &super::sdk::InstallActor,
    package: &AdmittedActorPackage,
) -> Result<Vec<super::sdk::RuntimeBlob>, CleanSystemAgentBootstrapError> {
    let mut blobs = [
        package.program_bytes(),
        package.state_lane_schema_bytes(),
        package.method_policy_bytes(),
    ]
    .into_iter()
    .map(|bytes| super::sdk::RuntimeBlob {
        reference: BlobRef::of_bytes(bytes),
        bytes: bytes.to_vec(),
    })
    .collect::<Vec<_>>();
    match (&install.entry.installation_data, &install.installation_data) {
        (None, None) => {}
        (Some(expected), Some(data))
            if expected == &data.reference && expected.matches(&data.bytes) =>
        {
            blobs.push(super::sdk::RuntimeBlob {
                reference: data.reference.clone(),
                bytes: data.bytes.clone(),
            });
        }
        _ => return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome)),
    }
    blobs.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
    blobs.dedup_by(|left, right| left.reference == right.reference);
    Ok(blobs)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn invoke_actor(
    host: &Arc<Mutex<SharedAgentHost>>,
    network_host: &SharedAgentNetworkHost,
    plan: &AuthorizedCleanSystemAgentBootstrap,
    invocation: super::sdk::InvocationId,
    origin: super::sdk::InvocationOrigin,
    message: Vec<u8>,
) -> Result<crate::actors::value::Value, CleanSystemAgentBootstrapError> {
    use crate::actors::codec::Decode as _;

    let install = install_request(&plan.authority_request)?;
    let actor = ensure_actor_installed(host, plan, &plan.authority_request)?;
    let work = super::sdk::InvocationWork {
        space: plan.pins.space,
        agent: plan.pins.agent,
        runtime_deployment: plan.pins.descriptor.identity.runtime_deployment,
        invocation,
        actor: actor.entry.actor,
        incarnation: actor.incarnation,
        deployment: actor.entry.deployment,
        program: actor.entry.program,
        mode: super::sdk::MethodMode::Linear,
        origin,
        roles: super::sdk::InvocationRoleClaims::none(),
        message,
        installation_data: actor.entry.installation_data.clone(),
        availability: invocation_availability(
            install,
            &plan.authority_package().map_err(rejected)?,
        )?,
        gas: plan.invocation_gas,
        recovery_only: false,
    };
    if work.actor != plan.pins.authority.issuer.actor
        || work.deployment != plan.pins.authority.issuer.deployment
        || work.program != plan.pins.authority.issuer.program
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongAuthority));
    }
    let authorization = super::sdk::InvocationAuthorization::PublicPreflight(
        super::sdk::PublicPreflight::for_work(&work, plan.pins.observed_slot),
    );
    let submission = network_host
        .invoke_bootstrap(
            crate::service::AgentId(plan.pins.agent.0),
            work.clone(),
            authorization,
        )
        .map_err(CleanSystemAgentBootstrapError::Host)?;
    let super::sdk::RuntimeOutcome::Completed(Ok(reply)) = submission.outcome else {
        match &submission.outcome {
            super::sdk::RuntimeOutcome::Completed(Err(error)) => {
                tracing::warn!(?error, "system bootstrap invocation failed");
            }
            _ => tracing::warn!("system bootstrap invocation did not complete"),
        }
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    };
    if reply.invocation != work.invocation
        || reply.actor != work.actor
        || reply.incarnation != work.incarnation
        || reply.deployment != work.deployment
        || reply.mode != work.mode
        || reply.status != super::sdk::InvocationStatus::Done
    {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    }
    crate::actors::value::Value::try_decode(&reply.reply)
        .ok_or_else(|| rejected(CleanSystemAgentBootstrapRejection::WrongOutcome))
}

fn dynamic_message(name: &str, argument: &str, value: crate::actors::value::Value) -> Vec<u8> {
    use crate::actors::codec::Encode as _;

    let mut bytes = vec![crate::actors::value::TAG_DYNAMIC];
    bytes.extend(
        crate::actors::value::Msg::new(name)
            .with(argument, value)
            .encode(),
    );
    bytes
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn invoke_authorize(
    host: &Arc<Mutex<SharedAgentHost>>,
    network_host: &SharedAgentNetworkHost,
    plan: &AuthorizedCleanSystemAgentBootstrap,
) -> Result<ManagementApproval, CleanSystemAgentBootstrapError> {
    let call = &plan.catalog_call;
    let value = invoke_actor(
        host,
        network_host,
        plan,
        call.invocation,
        super::sdk::InvocationOrigin {
            principal: Some(call.principal),
            transport_node: call.authenticated_node,
            credential: Some(call.credential),
            actor: None,
            capability: None,
        },
        dynamic_message(
            "authorize",
            "call",
            crate::actors::value::Value::Bytes(
                call.encode().expect("validated authority credential call"),
            ),
        ),
    )?;
    let crate::actors::value::Value::Bytes(bytes) = value else {
        tracing::warn!("system bootstrap authorization returned a non-bytes reply");
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    };
    let approval = ManagementApproval::decode(&bytes).map_err(|error| {
        tracing::warn!(
            ?error,
            reply_len = bytes.len(),
            "system bootstrap authorization returned no valid approval"
        );
        rejected(CleanSystemAgentBootstrapRejection::WrongOutcome)
    })?;
    validate_approval(plan, &approval)?;
    Ok(approval)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn invoke_finalize(
    host: &Arc<Mutex<SharedAgentHost>>,
    network_host: &SharedAgentNetworkHost,
    plan: &AuthorizedCleanSystemAgentBootstrap,
    acknowledgement: &ManagementApplicationAck,
) -> Result<(), CleanSystemAgentBootstrapError> {
    let value = invoke_actor(
        host,
        network_host,
        plan,
        acknowledgement.acknowledgement_invocation,
        super::sdk::InvocationOrigin::anonymous(),
        dynamic_message(
            "finalize",
            "ack",
            crate::actors::value::Value::Bytes(
                acknowledgement
                    .encode()
                    .expect("validated management acknowledgement"),
            ),
        ),
    )?;
    if value != crate::actors::value::Value::Bool(true) {
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    }
    Ok(())
}

fn validate_actor_install(
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    package: &AdmittedActorPackage,
) -> Result<(), CleanSystemAgentBootstrapRejection> {
    if !matches!(request, ManagementRequest::Install(_)) {
        return Err(CleanSystemAgentBootstrapRejection::InvalidDecision);
    }
    super::driver::validate_sdk_management_artifacts(
        descriptor,
        request,
        super::driver::SdkManagementArtifacts::Actor(package),
    )
    .map_err(|_| CleanSystemAgentBootstrapRejection::InvalidDecision)
}

fn runtime_matches_pins(runtime: &AdmittedRuntimePackage, pins: &CleanSystemAgentPins) -> bool {
    runtime.exact_bytes().len() <= MAX_PACKAGE_ENCODED_BYTES
        && runtime.package_ref() == &pins.runtime_package
        && runtime.deployment() == pins.descriptor.identity.runtime_deployment
        && runtime.program() == pins.descriptor.identity.runtime_program
        && runtime.producer() == pins.descriptor.identity.runtime_producer
        && runtime.manifest().contract == pins.descriptor.runtime_contract
        && runtime.capabilities() == pins.descriptor.capabilities
}

pub(crate) struct RawCredentialVerifier;

impl AuthorityCredentialVerifier for RawCredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

impl super::sdk::authority::AuthorityVerifier for RawCredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(reference.hash.as_bytes());
    encoder.u64(reference.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    let value = BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    };
    if value.hash == Hash::ZERO || value.len == 0 {
        Err(DecodeError::NonCanonical)
    } else {
        Ok(value)
    }
}

fn encode_authority_binding(encoder: &mut Encoder<'_>, binding: AgentAuthorityBinding) {
    encoder.fixed(binding.policy.as_bytes());
    encode_authority_issuer(encoder, binding.issuer);
    encoder.fixed(&binding.public_key);
    encoder.u64(binding.initial_epoch);
}

fn decode_authority_binding(
    decoder: &mut Decoder<'_>,
) -> Result<AgentAuthorityBinding, DecodeError> {
    let value = AgentAuthorityBinding {
        policy: Hash(decoder.fixed()?),
        issuer: decode_authority_issuer(decoder)?,
        public_key: decoder.fixed()?,
        initial_epoch: decoder.u64()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_authority_issuer(encoder: &mut Encoder<'_>, issuer: AuthorityIssuer) {
    encoder.fixed(issuer.principal.as_bytes());
    encoder.fixed(issuer.actor.as_bytes());
    encoder.fixed(issuer.deployment.as_bytes());
    encoder.fixed(issuer.program.as_bytes());
    encoder.fixed(issuer.producer.as_bytes());
}

fn decode_authority_issuer(decoder: &mut Decoder<'_>) -> Result<AuthorityIssuer, DecodeError> {
    let value = AuthorityIssuer {
        principal: super::sdk::PrincipalId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: super::sdk::DeploymentId(decoder.fixed()?),
        program: super::sdk::ProgramId(decoder.fixed()?),
        producer: super::sdk::ProducerId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_large_bytes(encoder: &mut Encoder<'_>, bytes: &[u8]) {
    encoder.u64(bytes.len() as u64);
    encoder.0.extend_from_slice(bytes);
}

fn decode_large_bytes(decoder: &mut Decoder<'_>, maximum: usize) -> Result<Vec<u8>, DecodeError> {
    let length = usize::try_from(decoder.u64()?).map_err(|_| DecodeError::LimitExceeded)?;
    if length > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(decoder.take(length)?.to_vec())
}

fn encode_wire_option<T: CanonicalWire>(encoder: &mut Encoder<'_>, value: Option<&T>) {
    encoder.option(&value, |encoder, value| {
        encoder.bytes(&value.encode().expect("validated canonical value"));
    });
}

fn decode_wire_option<T: CanonicalWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Option<T>, DecodeError> {
    decoder.option(|decoder| {
        T::decode(&decoder.bytes_bounded(maximum)?).map_err(|_| DecodeError::NonCanonical)
    })
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn map_issuer_open_error<StorageError>(
    error: CleanManagementIssuerError<StorageError>,
) -> CleanSystemAgentBootstrapError {
    match error {
        CleanManagementIssuerError::Storage(_) => CleanSystemAgentBootstrapError::IssuerStorage,
        CleanManagementIssuerError::Signer(never) => match never {},
        CleanManagementIssuerError::InvalidState => {
            CleanSystemAgentBootstrapError::InvalidIssuerState
        }
        CleanManagementIssuerError::Rejected(value) => {
            CleanSystemAgentBootstrapError::IssuerRejected(value)
        }
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn map_issuer_issue_error<StorageError, SignerError>(
    error: CleanManagementIssuerError<StorageError, SignerError>,
) -> CleanSystemAgentBootstrapError {
    match error {
        CleanManagementIssuerError::Storage(_) => CleanSystemAgentBootstrapError::IssuerStorage,
        CleanManagementIssuerError::Signer(_) => CleanSystemAgentBootstrapError::Signer,
        CleanManagementIssuerError::InvalidState => {
            CleanSystemAgentBootstrapError::InvalidIssuerState
        }
        CleanManagementIssuerError::Rejected(value) => {
            CleanSystemAgentBootstrapError::IssuerRejected(value)
        }
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn map_issuer_observation_error<StorageError>(
    error: CleanManagementIssuerError<StorageError>,
) -> CleanSystemAgentBootstrapError {
    map_issuer_open_error(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previous_generation_and_truncated_wires_fail_closed() {
        assert!(CleanSystemAgentPins::decode(b"CSP1").is_err());
        assert!(CleanSystemAgentBootstrapRecord::decode(b"CSB1").is_err());
        assert!(CleanSystemAgentBootstrapRecord::decode(b"CSB2").is_err());
    }

    #[cfg(all(
        feature = "pvm",
        feature = "storage",
        feature = "network",
        target_os = "linux"
    ))]
    mod physical {
        use alloc::boxed::Box;
        use core::num::NonZeroU64;
        use std::cell::Cell;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        use ed25519_dalek::{Signer as _, SigningKey};

        use super::*;
        use crate::actors::codec::{Decode as _, Encode as _};
        use crate::agent::authority::{ED25519_SIGNATURE_BYTES, ed25519_public_key_wire};
        use crate::agent::clean_authority_issuer::CleanManagementDecisionContext;
        use crate::agent::committee::{
            AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
            AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId, RootAnchorRecord,
            SystemAgentGenesisClaim, SystemAgentGenesisEvidence,
        };
        use crate::agent::genesis::{AgentGenesisFinalityError, AgentReplicaMember};
        use crate::agent::journal::MergeEvent;
        use crate::agent::package_admission::{
            ScriptedRuntimeCase, ScriptedRuntimeCopy, admitted_scripted_runtime_for_test,
            admitted_standard_actor_for_test,
        };
        use crate::agent::sdk::authority::{
            AuthorityActorProjectionPage, AuthorityAgentProjection, AuthorityAgentProjectionPage,
            AuthorityAgentReplicaProjectionPage, AuthorityBuiltinRole, AuthorityCredentialKind,
            AuthorityCredentialProjection, AuthorityCredentialStatus, AuthorityEvidence,
            AuthorityIngressAuthentication, AuthorityLaneRoots, AuthorityProjectionHead,
            AuthorityReceiptSelector, MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES,
            MAX_AUTHORITY_REPLICA_PAGE_ENTRIES,
        };
        use crate::agent::sdk::contract::{ActorPackageContract, RuntimePackageContract};
        use crate::agent::sdk::introspection::{
            ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
        };
        use crate::agent::sdk::method_policy::{
            ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
            AuthorizationPolicySelector, IdempotencyRequirement,
        };
        use crate::agent::sdk::package::{
            ActorPackageManifest, PackageArtifact, PackageEnvelope, PackageManifest, PackageSigning,
        };
        use crate::agent::sdk::schema::{
            ConstructorArgument, ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod,
            ParsedSchema, RAW_CONSTRUCTOR_TYPE_IDENTITY,
        };
        use crate::agent::sdk::task::TaskDependencySetArtifact;
        use crate::agent::sdk::{
            ActorDirectoryPage, ActorDirectoryRecord, ActorEntry, AgentIdentity, AgentReplica,
            CredentialId, DeploymentId, FieldPersistence, InstallationData, InstallationId,
            InvocationId, InvocationObservation, InvocationOrigin, InvocationReply,
            InvocationRoleClaims, InvocationStatus, InvocationWork, LaneSet, ManagementReply,
            MethodMode, PrincipalId, ProducerId, ProgramId, ProofSystemSet, ReplicaRole,
            RuntimeCapabilities, RuntimeOutcome, RuntimeRequirements, RuntimeTransition, StateLane,
        };
        use crate::agent::sdk::{RuntimeState, RuntimeWork};
        use crate::agent::{
            AgentConfig, AgentProfile as HostAgentProfile, AgentReplica as HostAgentReplica,
            ReplicaRole as HostReplicaRole,
        };
        use crate::network::NetworkConfig;
        use crate::service::{
            AgentId as HostAgentId, Hash as HostHash, NodeId as HostNodeId,
            PrincipalId as HostPrincipalId, SpaceId as HostSpaceId,
        };
        use vos_pvm_compiler::assembler::{Assembler, Reg};

        const NODE_SEED: u8 = 0x31;
        const RECEIPT_SEED: u8 = 0x41;
        const CREDENTIAL_SEED: u8 = 0x42;
        const ROOT_SEED: u8 = 0x43;
        const LOGICAL_SLOT: u64 = 20;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct MemoryError;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum RecordFailure {
            None,
            BeforeEveryPhase,
            AfterEveryPhase,
        }

        impl Default for RecordFailure {
            fn default() -> Self {
                Self::None
            }
        }

        #[derive(Default)]
        struct BootstrapMemoryState {
            image: Option<Vec<u8>>,
            commits: usize,
            failure: RecordFailure,
            fail_next_before_publish: bool,
        }

        #[derive(Clone, Default)]
        struct BootstrapMemoryStore {
            inner: Arc<Mutex<BootstrapMemoryState>>,
        }

        impl BootstrapMemoryStore {
            fn with_failure(failure: RecordFailure) -> Self {
                Self {
                    inner: Arc::new(Mutex::new(BootstrapMemoryState {
                        failure,
                        ..BootstrapMemoryState::default()
                    })),
                }
            }

            fn image(&self) -> Option<Vec<u8>> {
                self.inner.lock().unwrap().image.clone()
            }

            fn commits(&self) -> usize {
                self.inner.lock().unwrap().commits
            }

            fn fail_next_before_publish(&self) {
                self.inner.lock().unwrap().fail_next_before_publish = true;
            }
        }

        impl CleanSystemAgentBootstrapStore for BootstrapMemoryStore {
            type Error = MemoryError;

            fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
                let image = self.image();
                if image
                    .as_ref()
                    .is_some_and(|bytes| bytes.len() > maximum_bytes)
                {
                    return Err(MemoryError);
                }
                Ok(image)
            }

            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                let mut state = self.inner.lock().unwrap();
                state.commits += 1;
                let commit = state.commits;
                if core::mem::take(&mut state.fail_next_before_publish) {
                    return Err(MemoryError);
                }
                if state.failure == RecordFailure::BeforeEveryPhase
                    && commit <= 19
                    && commit % 2 == 1
                {
                    return Err(MemoryError);
                }
                state.image = Some(image.to_vec());
                if state.failure == RecordFailure::AfterEveryPhase && commit <= 10 {
                    return Err(MemoryError);
                }
                Ok(())
            }
        }

        #[derive(Clone, Copy)]
        enum ProjectionCommitFailure {
            BeforePublish,
            AfterPublishOnce,
            AfterPublishAlways,
            MissingAfterError,
        }

        struct ProjectionCommitStore {
            image: Option<Vec<u8>>,
            failure: ProjectionCommitFailure,
            commits: usize,
        }

        impl ProjectionCommitStore {
            fn new(
                prior: &CleanSystemAgentBootstrapRecord,
                failure: ProjectionCommitFailure,
            ) -> Self {
                Self {
                    image: Some(prior.encode()),
                    failure,
                    commits: 0,
                }
            }
        }

        impl CleanSystemAgentBootstrapStore for ProjectionCommitStore {
            type Error = MemoryError;

            fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
                if matches!(self.failure, ProjectionCommitFailure::MissingAfterError)
                    && self.commits != 0
                {
                    return Ok(None);
                }
                if self
                    .image
                    .as_ref()
                    .is_some_and(|bytes| bytes.len() > maximum_bytes)
                {
                    return Err(MemoryError);
                }
                Ok(self.image.clone())
            }

            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                self.commits += 1;
                match self.failure {
                    ProjectionCommitFailure::BeforePublish
                    | ProjectionCommitFailure::MissingAfterError
                        if self.commits == 1 =>
                    {
                        Err(MemoryError)
                    }
                    ProjectionCommitFailure::AfterPublishOnce if self.commits == 1 => {
                        self.image = Some(image.to_vec());
                        Err(MemoryError)
                    }
                    ProjectionCommitFailure::AfterPublishAlways => {
                        self.image = Some(image.to_vec());
                        Err(MemoryError)
                    }
                    _ => {
                        self.image = Some(image.to_vec());
                        Ok(())
                    }
                }
            }
        }

        #[derive(Clone, Default)]
        struct IssuerMemoryStore {
            image: Arc<Mutex<Option<Vec<u8>>>>,
            advance_clock_after_commits: Option<(Arc<AtomicU64>, usize)>,
        }

        impl CleanManagementIssuerStore for IssuerMemoryStore {
            type Error = MemoryError;

            fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.image.lock().unwrap().clone())
            }

            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                *self.image.lock().unwrap() = Some(image.to_vec());
                if let Some((clock, remaining)) = &mut self.advance_clock_after_commits {
                    if *remaining > 0 {
                        *remaining -= 1;
                        if *remaining == 0 {
                            clock.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                }
                Ok(())
            }
        }

        struct CountingSigner {
            key: SigningKey,
            calls: usize,
        }

        impl CountingSigner {
            fn new() -> Self {
                Self {
                    key: SigningKey::from_bytes(&[RECEIPT_SEED; 32]),
                    calls: 0,
                }
            }
        }

        impl CleanManagementReceiptSigner for CountingSigner {
            type Error = MemoryError;

            fn public_key(&self) -> [u8; 32] {
                self.key.verifying_key().to_bytes()
            }

            fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
                self.calls += 1;
                Ok(self.key.sign(message).to_bytes())
            }

            fn sign_management_application_ack(
                &mut self,
                message: &[u8],
            ) -> Result<[u8; 64], Self::Error> {
                self.calls += 1;
                Ok(self.key.sign(message).to_bytes())
            }
        }

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                static NEXT: AtomicUsize = AtomicUsize::new(1);
                let path = std::env::temp_dir().join(format!(
                    "vos-clean-system-bootstrap-{label}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }

            fn host(&self) -> PathBuf {
                self.0.join("agents")
            }

            fn lock(&self) -> PathBuf {
                self.0.join("shared-host.lock")
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        struct AcceptFinality;

        impl AgentGenesisFinalityVerifier for AcceptFinality {
            fn verify_finalized(
                &self,
                _provision: &super::super::super::genesis::AgentGenesisProvision,
            ) -> Result<(), AgentGenesisFinalityError> {
                Ok(())
            }
        }

        struct PhysicalTrust {
            authority: super::super::super::authority::AgentAuthorityBinding,
            logical_slot: Option<Arc<AtomicU64>>,
        }

        impl AgentTrustProvider for PhysicalTrust {
            fn current_logical_slot(&self) -> Option<u64> {
                Some(
                    self.logical_slot
                        .as_ref()
                        .map_or(LOGICAL_SLOT, |slot| slot.load(Ordering::Acquire)),
                )
            }

            fn authority_for_space(
                &self,
                _space: HostSpaceId,
            ) -> Option<super::super::super::authority::AgentAuthorityBinding> {
                Some(self.authority.clone())
            }

            fn verify_package(
                &self,
                _agent: &AgentConfig,
                _package: &super::super::super::package::Package,
            ) -> bool {
                true
            }
        }

        struct NativePhysicalTrust {
            authority: super::super::super::authority::AgentAuthorityBinding,
            logical_slot: Arc<AtomicU64>,
        }

        impl AgentTrustProvider for NativePhysicalTrust {
            fn current_logical_slot(&self) -> Option<u64> {
                Some(self.logical_slot.load(Ordering::Acquire))
            }

            fn authority_for_space(
                &self,
                _space: HostSpaceId,
            ) -> Option<super::super::super::authority::AgentAuthorityBinding> {
                Some(self.authority.clone())
            }

            fn verify_package(
                &self,
                _agent: &AgentConfig,
                _package: &super::super::super::package::Package,
            ) -> bool {
                true
            }

            fn use_native_standard_runtime_for_test(&self) -> bool {
                true
            }

            fn use_native_clean_runtime_for_test(&self) -> bool {
                true
            }
        }

        struct SigningMerge {
            key: SigningKey,
            node: HostNodeId,
        }

        impl LocalMergeAuthenticator for SigningMerge {
            fn node(&self) -> HostNodeId {
                self.node
            }

            fn sign_event(&self, event: &mut MergeEvent) -> bool {
                if event.author != self.node || !event.signature.is_empty() {
                    return false;
                }
                event.signature = self
                    .key
                    .sign(&event.signing_message().0)
                    .to_bytes()
                    .to_vec();
                true
            }

            fn verify_event(&self, event: &MergeEvent) -> bool {
                event.author == self.node && event.signature.len() == ED25519_SIGNATURE_BYTES
            }

            fn sign_snapshot_candidate(
                &self,
                candidate: &crate::agent::shared_host::VerifiedSharedAgentSnapshotCandidate,
            ) -> Option<crate::agent::shared_commit::ReplicaCommitSignature> {
                let member = candidate
                    .claim()
                    .active_committee()
                    .member_by_node(self.node)?;
                let keypair =
                    libp2p::identity::Keypair::ed25519_from_bytes(self.key.to_bytes()).ok()?;
                let peer = keypair.public().to_peer_id().to_bytes();
                if member.replica().role != HostReplicaRole::Voter
                    || member.ed25519_public_key() != &self.key.verifying_key().to_bytes()
                    || member.peer_id() != peer
                {
                    return None;
                }
                crate::agent::shared_commit::ReplicaCommitSignature::new(
                    self.node,
                    self.key.sign(&candidate.signing_message().0).to_bytes(),
                )
                .ok()
            }
        }

        struct RefusingSnapshotSigner(HostNodeId);

        impl LocalMergeAuthenticator for RefusingSnapshotSigner {
            fn node(&self) -> HostNodeId {
                self.0
            }

            fn sign_event(&self, _event: &mut MergeEvent) -> bool {
                false
            }

            fn verify_event(&self, _event: &MergeEvent) -> bool {
                false
            }
        }

        struct InvalidSnapshotSigner(HostNodeId);

        impl LocalMergeAuthenticator for InvalidSnapshotSigner {
            fn node(&self) -> HostNodeId {
                self.0
            }

            fn sign_event(&self, _event: &mut MergeEvent) -> bool {
                false
            }

            fn verify_event(&self, _event: &MergeEvent) -> bool {
                false
            }

            fn sign_snapshot_candidate(
                &self,
                _candidate: &crate::agent::shared_host::VerifiedSharedAgentSnapshotCandidate,
            ) -> Option<crate::agent::shared_commit::ReplicaCommitSignature> {
                crate::agent::shared_commit::ReplicaCommitSignature::new(self.0, [0; 64]).ok()
            }
        }

        struct MemoryProvider {
            configured: super::super::super::bootstrap::SystemAgentGenesisProvision,
            archive: Mutex<
                Option<(
                    super::super::super::bootstrap::SystemAgentGenesisProvision,
                    Vec<RuntimeBlob>,
                )>,
            >,
        }

        impl MemoryProvider {
            fn new(
                configured: super::super::super::bootstrap::SystemAgentGenesisProvision,
            ) -> Self {
                Self {
                    configured,
                    archive: Mutex::new(None),
                }
            }
        }

        impl SystemAgentGenesisProvider for MemoryProvider {
            fn create(
                &self,
                proposal: &SystemAgentGenesisProposal,
                catalog: &[RuntimeBlob],
            ) -> Result<
                super::super::super::bootstrap::SystemAgentGenesisProvision,
                super::super::super::bootstrap::SystemAgentGenesisProviderError,
            > {
                super::super::super::bootstrap::validate_system_agent_genesis_catalog(
                    proposal, catalog,
                )
                .map_err(|_| {
                    super::super::super::bootstrap::SystemAgentGenesisProviderError::Corrupt
                })?;
                let mut archive = self.archive.lock().unwrap();
                if let Some((existing, existing_catalog)) = archive.as_ref() {
                    return if existing.proposal() == proposal && existing_catalog == catalog {
                        Ok(existing.clone())
                    } else {
                        Err(super::super::super::bootstrap::SystemAgentGenesisProviderError::Conflict)
                    };
                }
                if self.configured.proposal() != proposal {
                    return Err(
                        super::super::super::bootstrap::SystemAgentGenesisProviderError::Refused,
                    );
                }
                *archive = Some((self.configured.clone(), catalog.to_vec()));
                Ok(self.configured.clone())
            }

            fn reproduce(
                &self,
                locator: SystemAgentGenesisLocator,
            ) -> Result<
                super::super::super::bootstrap::SystemAgentGenesisProvision,
                super::super::super::bootstrap::SystemAgentGenesisProviderError,
            > {
                self.archive
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|(provision, _)| provision.proposal().locator() == locator)
                    .map(|(provision, _)| provision.clone())
                    .ok_or(super::super::super::bootstrap::SystemAgentGenesisProviderError::NotConfigured)
            }

            fn load_catalog(
                &self,
                locator: SystemAgentGenesisLocator,
                reference: &crate::service::BlobRef,
            ) -> Result<
                Option<Vec<u8>>,
                super::super::super::bootstrap::SystemAgentGenesisProviderError,
            > {
                Ok(self
                    .archive
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|(provision, _)| provision.proposal().locator() == locator)
                    .and_then(|(_, catalog)| {
                        catalog
                            .iter()
                            .find(|blob| &blob.reference == reference)
                            .map(|blob| blob.bytes.clone())
                    }))
            }
        }

        fn raw_constructor_actor(name: &str, seed: u8) -> AdmittedActorPackage {
            let mut assembler = Assembler::new();
            let program = assembler.load_imm_64(Reg::A0, 1).trap().build_standard();
            let schema = ParsedSchema {
                constructor: ConstructorContract::RequiredRaw(ConstructorArgument {
                    name: "bootstrap".into(),
                    type_identity: RAW_CONSTRUCTOR_TYPE_IDENTITY.into(),
                }),
                fields: vec![ParsedField::Inline(ParsedInlineField {
                    source_index: 0,
                    name: "state".into(),
                    type_identity: "core::primitive::u64".into(),
                    persistence: FieldPersistence::State(StateLane::Linear),
                })],
                methods: Vec::new(),
            }
            .encode()
            .unwrap();
            let policies = ActorMethodPolicyArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                methods: Vec::new(),
            }
            .encode()
            .unwrap();
            let introspection = ActorIntrospectionArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policies),
                actor_doc: "physical clean system bootstrap fixture".into(),
                methods: Vec::new(),
            }
            .encode()
            .unwrap();
            let tasks = TaskDependencySetArtifact {
                dependencies: Vec::new(),
            }
            .encode()
            .unwrap();
            let artifact = |bytes: &[u8]| PackageArtifact {
                identity: BlobRef::of_bytes(bytes),
                bytes: bytes.to_vec(),
            };
            let signing = SigningKey::from_bytes(&[seed; 32]);
            let public_key = signing.verifying_key().to_bytes();
            let mut artifacts = vec![
                artifact(&program),
                artifact(&schema),
                artifact(&policies),
                artifact(&introspection),
                artifact(&tasks),
            ];
            artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
            let mut package = PackageEnvelope {
                manifest: PackageManifest::Actor(ActorPackageManifest {
                    name: name.into(),
                    program: BlobRef::of_bytes(&program),
                    contract: ActorPackageContract::canonical(),
                    state_lane_schema: BlobRef::of_bytes(&schema),
                    method_policy: BlobRef::of_bytes(&policies),
                    introspection: BlobRef::of_bytes(&introspection),
                    task_dependencies: BlobRef::of_bytes(&tasks),
                    scheduling: false,
                    requirements: RuntimeRequirements {
                        lanes: LaneSet::of(StateLane::Linear),
                        scheduling: false,
                        proof_systems: ProofSystemSet::EMPTY,
                    },
                    signing: PackageSigning {
                        producer: ProducerId::of_public_key(&public_key),
                        public_key,
                        signature: [0; 64],
                    },
                }),
                artifacts,
            };
            let signing_bytes = package.signing_bytes().unwrap();
            package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
            admit_actor_package(&package.encode().unwrap()).unwrap()
        }

        /// Purpose-built system-authority projection actor for the native
        /// Standard bootstrap fixture below. The PVM consumes the same five
        /// FETCH items as a generated actor, copies the exact query bytes from
        /// the authenticated message into a canonical response template, and
        /// returns through the ordinary actor ABI.
        fn credential_projection_actor(
            name: &str,
            seed: u8,
            placeholder: &crate::agent::sdk::authority::AuthorityCredentialProjection,
        ) -> AdmittedActorPackage {
            let query = placeholder.query.encode().unwrap();
            let query_body = &query[4 + 32..];
            let message = dynamic_message(
                "credential_projection",
                "query",
                crate::actors::value::Value::Bytes(query.clone()),
            );
            let reply = crate::actors::value::Value::Bytes(placeholder.encode().unwrap()).encode();
            let input_offsets = offsets(&message, query_body);
            let output_offsets = offsets(&reply, query_body);
            assert_eq!(input_offsets.len(), 1);
            assert_eq!(output_offsets.len(), 1);

            let mut output = vec![crate::actors::STATUS_DONE];
            output.extend_from_slice(&[0; 12]);
            output.extend_from_slice(&reply);
            const SCRATCH_BYTES: usize = 16 * 1024;
            let scratch_offset = output.len().next_multiple_of(8);
            let rw_base = 2 * usize::try_from(vos_pvm::PVM_ZONE_SIZE).unwrap();
            let scratch_address = rw_base + scratch_offset;
            let response_query_address = rw_base + 13 + output_offsets[0];
            let mut rw = output.clone();
            rw.resize(scratch_offset + SCRATCH_BYTES, 0);
            assert!(message.len() <= SCRATCH_BYTES);

            let mut assembler = Assembler::new();
            assembler.set_rw_data(rw);
            for _ in 0..5 {
                assembler
                    .load_imm_64(Reg::A0, scratch_address as u64)
                    .load_imm_64(Reg::A1, SCRATCH_BYTES as u64)
                    .ecalli(crate::abi::hostcall::FETCH);
            }
            for offset in 0..query_body.len() {
                assembler
                    .load_u8(
                        Reg::T0,
                        u32::try_from(scratch_address + input_offsets[0] + offset).unwrap(),
                    )
                    .store_u8(
                        Reg::T0,
                        u32::try_from(response_query_address + offset).unwrap(),
                    );
            }
            let program = assembler
                .load_imm_64(Reg::A0, rw_base as u64)
                .load_imm_64(Reg::A1, output.len() as u64)
                .jump_ind(Reg::RA, 0)
                .build_standard();

            let schema = ParsedSchema {
                constructor: ConstructorContract::Forbidden,
                fields: vec![ParsedField::Inline(ParsedInlineField {
                    source_index: 0,
                    name: "state".into(),
                    type_identity: "core::primitive::u64".into(),
                    persistence: FieldPersistence::State(StateLane::Linear),
                })],
                methods: vec![
                    ParsedMethod {
                        source_index: 0,
                        name: "credential_projection".into(),
                        mode: MethodMode::Query,
                        explicit: false,
                    },
                    ParsedMethod {
                        source_index: 1,
                        name: "projection_merge_probe".into(),
                        mode: MethodMode::Merge,
                        explicit: false,
                    },
                    ParsedMethod {
                        source_index: 2,
                        name: "projection_local_probe".into(),
                        mode: MethodMode::Local,
                        explicit: false,
                    },
                ],
            }
            .encode()
            .unwrap();
            let policies = ActorMethodPolicyArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                methods: [
                    ("credential_projection", MethodMode::Query),
                    ("projection_local_probe", MethodMode::Local),
                    ("projection_merge_probe", MethodMode::Merge),
                ]
                .into_iter()
                .map(|(name, mode)| ActorMethodPolicy {
                    name: name.into(),
                    mode,
                    arguments: Vec::new(),
                    return_type_identity: "alloc::vec::Vec<u8>".into(),
                    authorization_policy: AuthorizationPolicySelector::Public,
                    idempotency: IdempotencyRequirement::for_mode(mode),
                    attestation: AttestationRequirement::None,
                })
                .collect(),
            }
            .encode()
            .unwrap();
            let introspection = ActorIntrospectionArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policies),
                actor_doc: "physical projection lifecycle fixture".into(),
                methods: [
                    "credential_projection",
                    "projection_local_probe",
                    "projection_merge_probe",
                ]
                .into_iter()
                .map(|name| ActorMethodIntrospection {
                    name: name.into(),
                    doc: String::new(),
                    cli_exposure: CliExposure::Exposed,
                    timeout_ms: 0,
                    dispatch: MethodDispatch::Sync,
                })
                .collect(),
            }
            .encode()
            .unwrap();
            let tasks = TaskDependencySetArtifact {
                dependencies: Vec::new(),
            }
            .encode()
            .unwrap();
            let artifact = |bytes: &[u8]| PackageArtifact {
                identity: BlobRef::of_bytes(bytes),
                bytes: bytes.to_vec(),
            };
            let signing = SigningKey::from_bytes(&[seed; 32]);
            let public_key = signing.verifying_key().to_bytes();
            let mut artifacts = vec![
                artifact(&program),
                artifact(&schema),
                artifact(&policies),
                artifact(&introspection),
                artifact(&tasks),
            ];
            artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
            let mut package = PackageEnvelope {
                manifest: PackageManifest::Actor(ActorPackageManifest {
                    name: name.into(),
                    program: BlobRef::of_bytes(&program),
                    contract: ActorPackageContract::canonical(),
                    state_lane_schema: BlobRef::of_bytes(&schema),
                    method_policy: BlobRef::of_bytes(&policies),
                    introspection: BlobRef::of_bytes(&introspection),
                    task_dependencies: BlobRef::of_bytes(&tasks),
                    scheduling: false,
                    requirements: RuntimeRequirements {
                        lanes: LaneSet::of(StateLane::Linear)
                            .union(LaneSet::of(StateLane::Merge))
                            .union(LaneSet::of(StateLane::Local)),
                        scheduling: false,
                        proof_systems: ProofSystemSet::EMPTY,
                    },
                    signing: PackageSigning {
                        producer: ProducerId::of_public_key(&public_key),
                        public_key,
                        signature: [0; 64],
                    },
                }),
                artifacts,
            };
            let signing_bytes = package.signing_bytes().unwrap();
            package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
            admit_actor_package(&package.encode().unwrap()).unwrap()
        }

        struct ProjectionActorCase {
            input: Vec<u8>,
            output: Vec<u8>,
            copies: Vec<ScriptedRuntimeCopy>,
            discriminators: [(usize, u8); 2],
        }

        struct ProjectionTableCopy {
            source_offset: usize,
            output_offsets: Vec<usize>,
            len: usize,
        }

        struct ProjectionActorRoutine {
            case: ProjectionActorCase,
            /// Accepted nonce ordinals and their offsets in the shared compact
            /// descriptor table. Empty means every ordinal for this selector
            /// shares one response shape and no table-backed fields.
            table_sources: Vec<(u8, usize)>,
            table_copies: Vec<ProjectionTableCopy>,
        }

        fn inventory_nonce(group: u8, ordinal: u8) -> Hash {
            let mut bytes = [group; 32];
            bytes[0] = ordinal;
            bytes[1] = ordinal.rotate_left(1);
            bytes[30] = ordinal ^ 0x5a;
            bytes[31] = group ^ 0xa5;
            Hash(bytes)
        }

        fn inventory_template_query(
            target: AuthorityActorTarget,
            selector: AuthorityProjectionSelector,
            group: u8,
            ordinal: u8,
        ) -> AuthorityProjectionQuery {
            let key = SigningKey::from_bytes(&[0xa4; 32]);
            let public_key = key.verifying_key().to_bytes();
            let mut query = AuthorityProjectionQuery {
                authority: target,
                credential: CredentialId::of_public_key(&public_key),
                nonce: inventory_nonce(group, ordinal),
                selector,
                authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: public_key,
                    signature: [1; 64],
                },
            };
            let signature = key.sign(&query.signing_bytes()).to_bytes();
            let AuthorityIngressAuthentication::ApiCredentialSignature {
                signature: query_signature,
                ..
            } = &mut query.authentication
            else {
                unreachable!()
            };
            *query_signature = signature;
            query.validate_shape().unwrap();
            query
        }

        fn inventory_descriptor(target: AuthorityActorTarget, index: u64) -> AgentDescriptor {
            let owner = PrincipalId([0x71; 32]);
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&index.saturating_add(2).to_be_bytes());
            nonce[31] = 2;
            let creation_nonce = Hash(nonce);
            let agent = AgentId::derive(target.space, owner, creation_nonce.as_bytes());
            let descriptor = AgentDescriptor {
                identity: AgentIdentity {
                    space: target.space,
                    agent,
                    owner,
                    profile: AgentProfile::Shared,
                    runtime_deployment: DeploymentId([0x72; 32]),
                    runtime_program: ProgramId([0x73; 32]),
                    runtime_producer: ProducerId([0x74; 32]),
                    transition_producer: ProducerId([0x75; 32]),
                },
                creation_nonce,
                authority: target.binding,
                private_recovery: None,
                runtime_package: BlobRef::of_bytes(b"remote-runtime"),
                runtime_contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                replicas: vec![AgentReplica {
                    node: NodeId([0xf1; 32]),
                    principal: owner,
                    role: ReplicaRole::Voter,
                }],
            };
            descriptor.validate().unwrap();
            descriptor
        }

        fn inventory_agent_row(descriptor: &AgentDescriptor) -> AuthorityAgentProjection {
            AuthorityAgentProjection {
                identity: descriptor.identity.clone(),
                creation_nonce: descriptor.creation_nonce,
                authority: descriptor.authority,
                private_recovery: descriptor.private_recovery,
                runtime_package: descriptor.runtime_package.clone(),
                runtime_contract: descriptor.runtime_contract,
                capabilities: descriptor.capabilities,
                replica_count: descriptor.replicas.len() as u16,
                replica_generation: descriptor.replica_generation(),
            }
        }

        fn projection_actor_case<T: CanonicalWire>(
            query: AuthorityProjectionQuery,
            response: &T,
            placeholder_binding: AgentAuthorityBinding,
        ) -> ProjectionActorCase {
            let query_wire = query.encode().unwrap();
            let query_body = query_wire[4 + 32..].to_vec();
            let input = dynamic_message(
                projection_method(query.selector),
                "query",
                crate::actors::value::Value::Bytes(query_wire),
            );
            let reply = crate::actors::value::Value::Bytes(response.encode().unwrap()).encode();
            let mut output = vec![crate::actors::STATUS_DONE];
            output.extend_from_slice(&[0; 12]);
            output.extend_from_slice(&reply);
            let input_query = offsets(&input, &query_body);
            let output_query = offsets(&output, &query_body);
            assert_eq!(input_query.len(), 1);
            assert_eq!(output_query.len(), 1);
            let mut copies = vec![ScriptedRuntimeCopy {
                input_offset: input_query[0],
                output_offset: output_query[0],
                len: query_body.len(),
            }];
            for field in [
                placeholder_binding.issuer.deployment.0,
                placeholder_binding.issuer.program.0,
            ] {
                let input_offsets = offsets(&input, &field);
                assert_eq!(input_offsets.len(), 1);
                for output_offset in offsets(&output, &field) {
                    copies.push(ScriptedRuntimeCopy {
                        input_offset: input_offsets[0],
                        output_offset,
                        len: field.len(),
                    });
                }
            }
            let nonce = query.nonce.0;
            let nonce_offsets = offsets(&input, &nonce);
            assert_eq!(nonce_offsets.len(), 1);
            ProjectionActorCase {
                input,
                output,
                copies,
                discriminators: [
                    (nonce_offsets[0], nonce[0]),
                    (nonce_offsets[0] + nonce.len() - 1, nonce[nonce.len() - 1]),
                ],
            }
        }

        fn copy_instruction_bytes(len: usize) -> usize {
            (len / 8 + len % 8).checked_mul(12).unwrap()
        }

        fn emit_projection_copy(
            assembler: &mut Assembler,
            source: usize,
            destination: usize,
            len: usize,
            indirect_source: bool,
        ) {
            let mut copied = 0;
            while len - copied >= 8 {
                if indirect_source {
                    assembler.load_ind_u64(
                        Reg::T0,
                        Reg::S0,
                        i32::try_from(source + copied).unwrap(),
                    );
                } else {
                    assembler.load_u64(Reg::T0, u32::try_from(source + copied).unwrap());
                }
                assembler.store_u64(Reg::T0, u32::try_from(destination + copied).unwrap());
                copied += 8;
            }
            while copied < len {
                if indirect_source {
                    assembler.load_ind_u8(
                        Reg::T0,
                        Reg::S0,
                        i32::try_from(source + copied).unwrap(),
                    );
                } else {
                    assembler.load_u8(Reg::T0, u32::try_from(source + copied).unwrap());
                }
                assembler.store_u8(Reg::T0, u32::try_from(destination + copied).unwrap());
                copied += 1;
            }
        }

        /// Compact purpose PVM for the real 514-query inventory regression.
        /// It retains one response template per wire shape and one 96-byte row
        /// (Agent ID, creation nonce, replica generation) per advertised Agent.
        /// Query authentication and response validation still traverse the real
        /// actor ABI; only repetitive fixture bytes are factored out so replay's
        /// entry bound, rather than its byte bound, is exercised.
        fn scripted_projection_actor_program(
            routines: Vec<ProjectionActorRoutine>,
            descriptor_table: Vec<u8>,
        ) -> Vec<u8> {
            assert!(!routines.is_empty());
            let mut data = Vec::new();
            let mut output_offsets = Vec::with_capacity(routines.len());
            for routine in &routines {
                output_offsets.push(data.len());
                data.extend_from_slice(&routine.case.output);
            }
            let table_offset = data.len().next_multiple_of(8);
            data.resize(table_offset, 0);
            data.extend_from_slice(&descriptor_table);
            const SCRATCH_BYTES: usize = 4 * 1024;
            assert!(
                routines
                    .iter()
                    .all(|routine| routine.case.input.len() <= SCRATCH_BYTES)
            );
            let scratch_offset = data.len().next_multiple_of(8);
            data.resize(scratch_offset + SCRATCH_BYTES, 0);
            let rw_base = 2 * usize::try_from(vos_pvm::PVM_ZONE_SIZE).unwrap();
            let scratch_address = rw_base + scratch_offset;
            let mut assembler = Assembler::new();
            assembler.set_rw_data(data);
            for _ in 0..5 {
                assembler
                    .load_imm_64(Reg::A0, scratch_address as u64)
                    .load_imm_64(Reg::A1, SCRATCH_BYTES as u64)
                    .ecalli(crate::abi::hostcall::FETCH);
            }
            for (routine, data_offset) in routines.iter().zip(output_offsets) {
                let direct_copy_bytes = routine
                    .case
                    .copies
                    .iter()
                    .map(|copy| copy_instruction_bytes(copy.len))
                    .sum::<usize>();
                let table_copy_bytes = routine
                    .table_copies
                    .iter()
                    .map(|copy| {
                        copy.output_offsets
                            .len()
                            .checked_mul(copy_instruction_bytes(copy.len))
                            .unwrap()
                    })
                    .sum::<usize>();
                let common_bytes = direct_copy_bytes + table_copy_bytes + 26;
                let dispatch_bytes = if routine.table_sources.is_empty() {
                    0
                } else {
                    6 + routine.table_sources.len() * 20 + 5
                };
                let block_bytes = 10 + 16 + dispatch_bytes + common_bytes;
                assembler.branch_ne_imm(
                    Reg::A0,
                    i32::try_from(routine.case.input.len()).unwrap(),
                    u32::try_from(block_bytes).unwrap(),
                );
                let group = routine.case.discriminators[1];
                assembler
                    .load_u8(Reg::T1, u32::try_from(scratch_address + group.0).unwrap())
                    .branch_ne_imm(
                        Reg::T1,
                        i32::from(group.1),
                        u32::try_from(block_bytes - 16).unwrap(),
                    );
                if !routine.table_sources.is_empty() {
                    let ordinal = routine.case.discriminators[0];
                    assembler.load_u8(Reg::T1, u32::try_from(scratch_address + ordinal.0).unwrap());
                    for (index, (value, source_offset)) in routine.table_sources.iter().enumerate()
                    {
                        assembler.branch_ne_imm(Reg::T1, i32::from(*value), 20);
                        let remaining = routine.table_sources.len() - index;
                        assembler.load_imm_jump(
                            Reg::S0,
                            i32::try_from(rw_base + table_offset + *source_offset).unwrap(),
                            u32::try_from(remaining * 20 - 5).unwrap(),
                        );
                    }
                    assembler.jump(u32::try_from(5 + common_bytes).unwrap());
                }
                for copy in &routine.case.copies {
                    emit_projection_copy(
                        &mut assembler,
                        scratch_address + copy.input_offset,
                        rw_base + data_offset + copy.output_offset,
                        copy.len,
                        false,
                    );
                }
                for copy in &routine.table_copies {
                    for output_offset in &copy.output_offsets {
                        emit_projection_copy(
                            &mut assembler,
                            copy.source_offset,
                            rw_base + data_offset + *output_offset,
                            copy.len,
                            true,
                        );
                    }
                }
                assembler
                    .load_imm_64(Reg::A0, (rw_base + data_offset) as u64)
                    .load_imm_64(Reg::A1, routine.case.output.len() as u64)
                    .jump_ind(Reg::RA, 0);
            }
            assembler.trap();
            let program = assembler.build_standard();
            assert!(
                program.len() < 64 * 1024,
                "compact inventory purpose PVM is {} bytes",
                program.len()
            );
            program
        }

        const INVENTORY_DESCRIPTOR_ROW_BYTES: usize = 3 * 32;

        fn projection_table_copy(
            output: &[u8],
            field: &[u8; 32],
            source_offset: usize,
            expected_occurrences: usize,
        ) -> ProjectionTableCopy {
            let output_offsets = offsets(output, field);
            assert_eq!(output_offsets.len(), expected_occurrences);
            ProjectionTableCopy {
                source_offset,
                output_offsets,
                len: field.len(),
            }
        }

        fn agent_page_table_copies(
            case: &ProjectionActorCase,
            page: &AuthorityAgentProjectionPage,
        ) -> Vec<ProjectionTableCopy> {
            let mut copies = Vec::with_capacity(page.entries.len() * 3);
            for (index, entry) in page.entries.iter().enumerate() {
                let source = index * INVENTORY_DESCRIPTOR_ROW_BYTES;
                copies.push(projection_table_copy(
                    &case.output,
                    &entry.identity.agent.0,
                    source,
                    1 + usize::from(page.next == Some(entry.identity.agent)),
                ));
                copies.push(projection_table_copy(
                    &case.output,
                    &entry.creation_nonce.0,
                    source + 32,
                    1,
                ));
                copies.push(projection_table_copy(
                    &case.output,
                    &entry.replica_generation.0,
                    source + 64,
                    1,
                ));
            }
            copies
        }

        fn normalized_projection_routine(routine: &ProjectionActorRoutine) -> Vec<u8> {
            let mut output = routine.case.output.clone();
            for copy in &routine.case.copies {
                output[copy.output_offset..copy.output_offset + copy.len].fill(0);
            }
            for copy in &routine.table_copies {
                for offset in &copy.output_offsets {
                    output[*offset..*offset + copy.len].fill(0);
                }
            }
            output
        }

        fn inventory_projection_actor(
            name: &str,
            seed: u8,
            target: AuthorityActorTarget,
            descriptors: &[AgentDescriptor],
            head: AuthorityProjectionHead,
        ) -> AdmittedActorPackage {
            let credential_query =
                inventory_template_query(target, AuthorityProjectionSelector::Credential, 1, 1);
            let credential = AuthorityCredentialProjection {
                query: credential_query.clone(),
                head,
                principal: PrincipalId([0xb1; 32]),
                status: AuthorityCredentialStatus::Active,
                kind: AuthorityCredentialKind::Api,
                builtin_role: AuthorityBuiltinRole::Admin,
                management_request_high_water: 0,
                operation_request_high_water: 0,
                admin_request_high_water: 0,
                space_roles: Vec::new(),
                actor_roles: Vec::new(),
                capabilities: Vec::new(),
            };
            credential.validate_shape().unwrap();
            let credential_routine = ProjectionActorRoutine {
                case: projection_actor_case(credential_query, &credential, target.binding),
                table_sources: Vec::new(),
                table_copies: Vec::new(),
            };

            let rows = descriptors
                .iter()
                .map(inventory_agent_row)
                .collect::<Vec<_>>();
            let mut descriptor_table =
                Vec::with_capacity(descriptors.len() * INVENTORY_DESCRIPTOR_ROW_BYTES);
            for descriptor in descriptors {
                descriptor_table.extend_from_slice(&descriptor.identity.agent.0);
                descriptor_table.extend_from_slice(&descriptor.creation_nonce.0);
                descriptor_table.extend_from_slice(&descriptor.replica_generation().0);
            }
            let mut agent_page_routines = Vec::new();
            let mut after = None;
            for (page_index, chunk) in rows
                .chunks(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES)
                .enumerate()
            {
                let more = (page_index + 1) * MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES < rows.len();
                let next = more.then(|| chunk.last().unwrap().identity.agent);
                let query = inventory_template_query(
                    target,
                    AuthorityProjectionSelector::Agents {
                        after,
                        limit: MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES as u16,
                    },
                    2,
                    u8::try_from(page_index + 1).unwrap(),
                );
                let page = AuthorityAgentProjectionPage {
                    query: query.clone(),
                    head,
                    entries: chunk.to_vec(),
                    next,
                };
                page.validate_shape().unwrap();
                let case = projection_actor_case(query, &page, target.binding);
                let table_copies = agent_page_table_copies(&case, &page);
                agent_page_routines.push(ProjectionActorRoutine {
                    case,
                    table_sources: vec![(
                        u8::try_from(page_index + 1).unwrap(),
                        page_index
                            * MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
                            * INVENTORY_DESCRIPTOR_ROW_BYTES,
                    )],
                    table_copies,
                });
                after = next;
            }

            assert_eq!(agent_page_routines.len(), 31);
            let first_agent_page = agent_page_routines.remove(0);
            let last_agent_page = agent_page_routines.pop().unwrap();
            let mut middle_agent_pages = agent_page_routines.remove(0);
            let middle_shape = normalized_projection_routine(&middle_agent_pages);
            for routine in agent_page_routines {
                assert_eq!(normalized_projection_routine(&routine), middle_shape);
                middle_agent_pages
                    .table_sources
                    .extend(routine.table_sources);
            }

            let first_descriptor = descriptors.first().unwrap();
            let replica_query = inventory_template_query(
                target,
                AuthorityProjectionSelector::AgentReplicas {
                    agent: first_descriptor.identity.agent,
                    after: None,
                    limit: MAX_AUTHORITY_REPLICA_PAGE_ENTRIES as u16,
                },
                3,
                1,
            );
            let replica_page = AuthorityAgentReplicaProjectionPage {
                query: replica_query.clone(),
                head,
                replica_count: 1,
                replica_generation: first_descriptor.replica_generation(),
                entries: first_descriptor.replicas.clone(),
                next: None,
            };
            replica_page.validate_shape().unwrap();
            let replica_case = projection_actor_case(replica_query, &replica_page, target.binding);
            let replica_generation_offsets =
                offsets(&replica_case.output, &replica_page.replica_generation.0);
            assert_eq!(replica_generation_offsets.len(), 1);
            let replica_routine = ProjectionActorRoutine {
                case: replica_case,
                table_sources: descriptors
                    .iter()
                    .enumerate()
                    .map(|(index, _)| {
                        (
                            u8::try_from(index + 1).unwrap(),
                            index * INVENTORY_DESCRIPTOR_ROW_BYTES,
                        )
                    })
                    .collect(),
                table_copies: vec![ProjectionTableCopy {
                    source_offset: 64,
                    output_offsets: replica_generation_offsets,
                    len: 32,
                }],
            };

            let actor_query = inventory_template_query(
                target,
                AuthorityProjectionSelector::Actors {
                    agent: first_descriptor.identity.agent,
                    after: None,
                    limit: MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES as u16,
                },
                4,
                1,
            );
            let actor_page = AuthorityActorProjectionPage {
                query: actor_query.clone(),
                head,
                entries: Vec::new(),
                next: None,
            };
            actor_page.validate_shape().unwrap();
            let actor_routine = ProjectionActorRoutine {
                case: projection_actor_case(actor_query, &actor_page, target.binding),
                table_sources: Vec::new(),
                table_copies: Vec::new(),
            };

            // The one-row terminal page shares the same query length/group as
            // the full middle pages, so test it first and fall through on every
            // other ordinal. All other selector shapes are disjoint by length
            // and the authenticated nonce group byte.
            let program = scripted_projection_actor_program(
                vec![
                    credential_routine,
                    first_agent_page,
                    last_agent_page,
                    middle_agent_pages,
                    replica_routine,
                    actor_routine,
                ],
                descriptor_table,
            );

            let method_names = [
                "actor_projection_page",
                "agent_projection_page",
                "agent_replica_projection_page",
                "credential_projection",
            ];
            let schema = ParsedSchema {
                constructor: ConstructorContract::Forbidden,
                fields: vec![ParsedField::Inline(ParsedInlineField {
                    source_index: 0,
                    name: "state".into(),
                    type_identity: "core::primitive::u64".into(),
                    persistence: FieldPersistence::State(StateLane::Linear),
                })],
                methods: method_names
                    .iter()
                    .enumerate()
                    .map(|(index, method)| ParsedMethod {
                        source_index: index as u16,
                        name: (*method).into(),
                        mode: MethodMode::Query,
                        explicit: false,
                    })
                    .collect(),
            }
            .encode()
            .unwrap();
            let policies = ActorMethodPolicyArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                methods: method_names
                    .iter()
                    .map(|method| ActorMethodPolicy {
                        name: (*method).into(),
                        mode: MethodMode::Query,
                        arguments: Vec::new(),
                        return_type_identity: "alloc::vec::Vec<u8>".into(),
                        authorization_policy: AuthorizationPolicySelector::Public,
                        idempotency: IdempotencyRequirement::NotRequired,
                        attestation: AttestationRequirement::None,
                    })
                    .collect(),
            }
            .encode()
            .unwrap();
            let introspection = ActorIntrospectionArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policies),
                actor_doc: "bounded production inventory rotation fixture".into(),
                methods: method_names
                    .iter()
                    .map(|method| ActorMethodIntrospection {
                        name: (*method).into(),
                        doc: String::new(),
                        cli_exposure: CliExposure::Exposed,
                        timeout_ms: 0,
                        dispatch: MethodDispatch::Sync,
                    })
                    .collect(),
            }
            .encode()
            .unwrap();
            let tasks = TaskDependencySetArtifact {
                dependencies: Vec::new(),
            }
            .encode()
            .unwrap();
            let artifact = |bytes: &[u8]| PackageArtifact {
                identity: BlobRef::of_bytes(bytes),
                bytes: bytes.to_vec(),
            };
            let signing = SigningKey::from_bytes(&[seed; 32]);
            let public_key = signing.verifying_key().to_bytes();
            let mut artifacts = vec![
                artifact(&program),
                artifact(&schema),
                artifact(&policies),
                artifact(&introspection),
                artifact(&tasks),
            ];
            artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
            let mut package = PackageEnvelope {
                manifest: PackageManifest::Actor(ActorPackageManifest {
                    name: name.into(),
                    program: BlobRef::of_bytes(&program),
                    contract: ActorPackageContract::canonical(),
                    state_lane_schema: BlobRef::of_bytes(&schema),
                    method_policy: BlobRef::of_bytes(&policies),
                    introspection: BlobRef::of_bytes(&introspection),
                    task_dependencies: BlobRef::of_bytes(&tasks),
                    scheduling: false,
                    requirements: RuntimeRequirements {
                        lanes: LaneSet::of(StateLane::Linear),
                        scheduling: false,
                        proof_systems: ProofSystemSet::EMPTY,
                    },
                    signing: PackageSigning {
                        producer: ProducerId::of_public_key(&public_key),
                        public_key,
                        signature: [0; 64],
                    },
                }),
                artifacts,
            };
            let signing_bytes = package.signing_bytes().unwrap();
            package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
            admit_actor_package(&package.encode().unwrap()).unwrap()
        }

        fn network(seed: u8) -> Arc<Network> {
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            let peer = keypair.public().to_peer_id();
            Arc::new(Network::start(NetworkConfig {
                keypair,
                local_prefix: crate::network::derive_node_prefix(&peer),
                listen: Vec::new(),
                bootstrap: Vec::new(),
                auto_dial_mdns: false,
            }))
        }

        fn wait_until(timeout: std::time::Duration, mut predicate: impl FnMut() -> bool) -> bool {
            let deadline = std::time::Instant::now() + timeout;
            loop {
                if predicate() {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        fn stop_network(network: Arc<Network>) {
            network.shutdown();
            assert!(wait_until(std::time::Duration::from_secs(5), || {
                Arc::strong_count(&network) == 1
            }));
            Arc::try_unwrap(network).ok().unwrap().join();
        }

        fn node_material() -> (SigningKey, Vec<u8>, [u8; 32], HostNodeId) {
            let key = SigningKey::from_bytes(&[NODE_SEED; 32]);
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes([NODE_SEED; 32]).unwrap();
            let peer = keypair.public().to_peer_id().to_bytes();
            let public_key = key.verifying_key().to_bytes();
            assert_eq!(peer.get(peer.len() - 32..), Some(public_key.as_slice()));
            let node = HostNodeId::of_authenticated_peer(&peer);
            (key, peer, public_key, node)
        }

        fn replica_member(
            space: SpaceId,
            agent: AgentId,
        ) -> (AgentReplicaCommittee, AgentReplicaMember) {
            let (_, peer, public_key, node) = node_material();
            let member = AgentReplicaMember::new(
                HostAgentReplica {
                    node,
                    principal: HostPrincipalId::of_public_key(&public_key),
                    role: HostReplicaRole::Voter,
                },
                peer.clone(),
                public_key,
                Some(super::super::super::genesis::derive_replica_raft_slot(
                    &peer,
                )),
            )
            .unwrap();
            let committee = AgentReplicaCommittee::new(
                HostSpaceId(space.0),
                HostAgentId(agent.0),
                HostAgentProfile::Shared,
                vec![member.clone()],
            )
            .unwrap();
            (committee, member)
        }

        fn authority_binding(
            agent: AgentId,
            package: &AdmittedActorPackage,
            receipt_key: &SigningKey,
        ) -> AgentAuthorityBinding {
            AgentAuthorityBinding {
                policy: Hash([0x51; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x52; 32]),
                    actor: ActorId::top_level(agent, &package.manifest().name),
                    deployment: package.deployment(),
                    program: package.program(),
                    producer: package.producer(),
                },
                public_key: receipt_key.verifying_key().to_bytes(),
                initial_epoch: 1,
            }
        }

        fn descriptor(
            runtime: &AdmittedRuntimePackage,
            space: SpaceId,
            agent: AgentId,
            owner: PrincipalId,
            nonce: Hash,
            member: &AgentReplicaMember,
            authority: AgentAuthorityBinding,
        ) -> AgentDescriptor {
            let descriptor = AgentDescriptor {
                identity: AgentIdentity {
                    space,
                    agent,
                    owner,
                    profile: AgentProfile::Shared,
                    runtime_deployment: runtime.deployment(),
                    runtime_program: runtime.program(),
                    runtime_producer: runtime.producer(),
                    transition_producer: ProducerId([0xb1; 32]),
                },
                creation_nonce: nonce,
                authority,
                private_recovery: None,
                runtime_package: runtime.package_ref().clone(),
                runtime_contract: runtime.manifest().contract,
                capabilities: runtime.capabilities(),
                replicas: vec![AgentReplica {
                    node: NodeId(member.replica().node.0),
                    principal: PrincipalId(member.replica().principal.0),
                    role: ReplicaRole::Voter,
                }],
            };
            descriptor.validate().unwrap();
            descriptor
        }

        fn host_authority_binding(
            descriptor: &AgentDescriptor,
        ) -> super::super::super::authority::AgentAuthorityBinding {
            let public_key = ed25519_public_key_wire(descriptor.authority.public_key);
            super::super::super::authority::AgentAuthorityBinding {
                agent: HostAgentId(descriptor.identity.agent.0),
                actor: crate::service::ActorId(descriptor.authority.issuer.actor.0),
                deployment: crate::service::DeploymentId(descriptor.authority.issuer.deployment.0),
                program: crate::service::ProgramId(descriptor.authority.issuer.program.0),
                producer: crate::service::ProducerId::of_public_key(&public_key),
                public_key,
            }
        }

        fn install_request(
            agent: AgentId,
            package: &AdmittedActorPackage,
            marker: u8,
            installation_data: Option<Vec<u8>>,
        ) -> ManagementRequest {
            let schema =
                crate::agent::sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
            let data = installation_data.map(|bytes| InstallationData {
                reference: BlobRef::of_bytes(&bytes),
                bytes,
            });
            let name = package.manifest().name.clone();
            let entry = ActorEntry {
                actor: ActorId::top_level(agent, &name),
                name,
                parent: None,
                deployment: package.deployment(),
                program: package.program(),
                package: package.package_ref().clone(),
                agent_schema: package.manifest().state_lane_schema.clone(),
                method_policy: package.manifest().method_policy.clone(),
                constructor_abi: schema.constructor_abi().unwrap(),
                installation_data: data.as_ref().map(|data| data.reference.clone()),
                state_layout: schema.state_layout_hash().unwrap(),
                lanes: package.requirements().lanes,
                suspended: false,
            };
            let request = ManagementRequest::Install(Box::new(crate::agent::sdk::InstallActor {
                installation_id: InstallationId([marker; 32]),
                registry_reservation: Hash([marker.wrapping_add(1); 32]),
                entry,
                producer: package.producer(),
                package: package.package_ref().clone(),
                agent_schema: package.manifest().state_lane_schema.clone(),
                method_policy: package.manifest().method_policy.clone(),
                constructor_abi: schema.constructor_abi().unwrap(),
                installation_data: data,
                state_layout: schema.state_layout_hash().unwrap(),
                contract: package.manifest().contract,
                requirements: package.requirements(),
            }));
            assert!(request.is_valid());
            request
        }

        fn record(request: &ManagementRequest, incarnation: u8) -> ActorDirectoryRecord {
            let ManagementRequest::Install(install) = request else {
                panic!("fixture request is Install")
            };
            ActorDirectoryRecord {
                entry: install.entry.clone(),
                incarnation: Hash([incarnation; 32]),
                installation_id: install.installation_id,
                registry_reservation: install.registry_reservation,
                install_request: install.lineage_commitment(),
            }
        }

        fn page(mut entries: Vec<ActorDirectoryRecord>) -> ActorDirectoryPage {
            entries.sort_unstable_by_key(|record| record.entry.actor);
            let page = ActorDirectoryPage {
                entries,
                next: None,
            };
            page.validate().unwrap();
            page
        }

        fn state(marker: u8, page: &ActorDirectoryPage, linear: u8) -> RuntimeState {
            let mut control = vec![marker];
            control.extend(page.encode().unwrap());
            RuntimeState {
                control,
                linear: vec![linear],
                merge: Vec::new(),
                local: Vec::new(),
            }
        }

        fn decision(
            descriptor: &AgentDescriptor,
            request: &ManagementRequest,
            authorization: u64,
            evidence: u8,
        ) -> AuthorizedCleanManagementDecision {
            AuthorizedCleanManagementDecision::new(
                NonZeroU64::new(authorization).unwrap(),
                CleanManagementDecisionContext {
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: Hash([evidence; 32]),
                    },
                    lane_roots: AuthorityLaneRoots::default(),
                    epoch: 1,
                    valid_from: 10,
                    expires_at: 30,
                },
                request,
            )
            .unwrap()
        }

        fn signed_receipt(
            descriptor: &AgentDescriptor,
            request: &ManagementRequest,
            sequence: u64,
            acknowledged_through: u64,
            evidence: u8,
            key: &SigningKey,
        ) -> AuthorityReceipt {
            let (actor, actor_deployment) = request
                .authority_actor()
                .map_or((None, None), |(actor, deployment)| {
                    (Some(actor), Some(deployment))
                });
            let mut receipt = AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: descriptor.authority.policy,
                    issuer: descriptor.authority.issuer,
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    operation: request.authority_operation().unwrap(),
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    actor,
                    actor_deployment,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: Hash([evidence; 32]),
                    },
                    lane_roots: AuthorityLaneRoots::default(),
                    epoch: 1,
                    decision_sequence: sequence,
                    acknowledged_through,
                    valid_from: 10,
                    expires_at: 30,
                    request: request.commitment(),
                },
                public_key: descriptor.authority.public_key,
                signature: [0; 64],
            };
            receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
            receipt.validate_shape().unwrap();
            receipt
        }

        fn targets(descriptor: &AgentDescriptor) -> (AuthorityActorTarget, ManagedAgentTarget) {
            (
                AuthorityActorTarget {
                    space: descriptor.identity.space,
                    system_agent: descriptor.identity.agent,
                    system_runtime_deployment: descriptor.identity.runtime_deployment,
                    binding: descriptor.authority,
                },
                ManagedAgentTarget {
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    owner: descriptor.identity.owner,
                    profile: descriptor.identity.profile,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    transition_producer: descriptor.identity.transition_producer,
                },
            )
        }

        fn credential_call_and_approval(
            descriptor: &AgentDescriptor,
            request: &ManagementRequest,
            credential_key: &SigningKey,
        ) -> (AuthorityCredentialCall, ManagementApproval) {
            let (authority, managed) = targets(descriptor);
            let public_key = credential_key.verifying_key().to_bytes();
            let mut call = AuthorityCredentialCall {
                invocation: InvocationId::ZERO,
                authority,
                managed,
                principal: descriptor.identity.owner,
                credential: CredentialId::of_public_key(&public_key),
                request_sequence: NonZeroU64::new(1).unwrap(),
                credential_public_key: public_key,
                authenticated_node: Some(descriptor.replicas[0].node),
                requested_valid_from: 10,
                requested_expires_at: 30,
                plan: request.authorization_plan().unwrap(),
                signature: [0; 64],
            };
            call.invocation = call.expected_invocation();
            call.signature = credential_key.sign(&call.signing_bytes()).to_bytes();
            call.verify_with(&RawCredentialVerifier).unwrap();
            let approval = ManagementApproval::from_call(
                &call,
                NonZeroU64::new(3).unwrap(),
                AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x73; 32]),
                },
                AuthorityLaneRoots::default(),
                1,
                10,
                30,
            )
            .unwrap();
            (call, approval)
        }

        fn offsets(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
            assert!(!needle.is_empty());
            haystack
                .windows(needle.len())
                .enumerate()
                .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
                .collect()
        }

        fn copy_from_first_input_to_all_outputs(case: &mut ScriptedRuntimeCase, needle: &[u8]) {
            let input = offsets(&case.input, needle);
            let output = offsets(&case.output, needle);
            assert!(!input.is_empty(), "script input is missing copied bytes");
            assert!(!output.is_empty(), "script output is missing copied bytes");
            for output_offset in output {
                case.copies.push(ScriptedRuntimeCopy {
                    input_offset: input[0],
                    output_offset,
                    len: needle.len(),
                });
            }
        }

        fn identity_bytes(identity: &AgentIdentity) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(225);
            bytes.extend_from_slice(identity.space.as_bytes());
            bytes.extend_from_slice(identity.agent.as_bytes());
            bytes.extend_from_slice(identity.owner.as_bytes());
            bytes.push(identity.profile as u8);
            bytes.extend_from_slice(identity.runtime_deployment.as_bytes());
            bytes.extend_from_slice(identity.runtime_program.as_bytes());
            bytes.extend_from_slice(identity.runtime_producer.as_bytes());
            bytes.extend_from_slice(identity.transition_producer.as_bytes());
            bytes
        }

        fn manage_case(
            descriptor: &AgentDescriptor,
            state: RuntimeState,
            request: ManagementRequest,
            receipt: Option<AuthorityReceipt>,
            next_state: RuntimeState,
            outcome: RuntimeOutcome,
        ) -> ScriptedRuntimeCase {
            let input = RuntimeWork::Manage {
                context: crate::agent::sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: receipt
                    .as_ref()
                    .map_or(descriptor.identity.runtime_deployment, |receipt| {
                        receipt.selector.runtime_deployment
                    }),
                state,
                request: Box::new(request),
                authority: receipt.map(Box::new),
                observed_slot: LOGICAL_SLOT,
            }
            .encode()
            .unwrap();
            let output = RuntimeTransition {
                state: next_state,
                outcome,
            }
            .encode()
            .unwrap();
            ScriptedRuntimeCase {
                input,
                output,
                copies: Vec::new(),
            }
        }

        fn invocation_work(
            descriptor: &AgentDescriptor,
            record: &ActorDirectoryRecord,
            invocation: InvocationId,
            origin: InvocationOrigin,
            message: Vec<u8>,
            installation_data: &InstallationData,
            package: &AdmittedActorPackage,
        ) -> InvocationWork {
            let mut availability = vec![crate::agent::sdk::RuntimeBlob {
                reference: installation_data.reference.clone(),
                bytes: installation_data.bytes.clone(),
            }];
            availability.extend(
                [
                    package.program_bytes(),
                    package.state_lane_schema_bytes(),
                    package.method_policy_bytes(),
                ]
                .into_iter()
                .map(|bytes| crate::agent::sdk::RuntimeBlob {
                    reference: BlobRef::of_bytes(bytes),
                    bytes: bytes.to_vec(),
                }),
            );
            availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
            availability.dedup_by(|left, right| left.reference == right.reference);
            InvocationWork {
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                invocation,
                actor: record.entry.actor,
                incarnation: record.incarnation,
                deployment: record.entry.deployment,
                program: record.entry.program,
                mode: MethodMode::Linear,
                origin,
                roles: InvocationRoleClaims::none(),
                message,
                installation_data: record.entry.installation_data.clone(),
                availability,
                gas: 1_000_000,
                recovery_only: false,
            }
        }

        fn invoke_case(
            state: RuntimeState,
            work: InvocationWork,
            next_state: RuntimeState,
            reply: Vec<u8>,
        ) -> ScriptedRuntimeCase {
            let authorization = crate::agent::sdk::InvocationAuthorization::PublicPreflight(
                crate::agent::sdk::PublicPreflight::for_work(&work, LOGICAL_SLOT),
            );
            let input = RuntimeWork::Invoke {
                context: crate::agent::sdk::RuntimeExecutionContext::Direct,
                state,
                invocation: Box::new(work.clone()),
                authorization: Box::new(authorization),
                observed_slot: LOGICAL_SLOT,
            }
            .encode()
            .unwrap();
            let output = RuntimeTransition {
                state: next_state,
                outcome: RuntimeOutcome::Completed(Ok(InvocationReply {
                    invocation: work.invocation,
                    actor: work.actor,
                    incarnation: work.incarnation,
                    deployment: work.deployment,
                    mode: work.mode,
                    lane: Some(StateLane::Linear),
                    status: InvocationStatus::Done,
                    reply,
                    gas_remaining: 1,
                    observation: InvocationObservation::default(),
                })),
            }
            .encode()
            .unwrap();
            ScriptedRuntimeCase {
                input,
                output,
                copies: Vec::new(),
            }
        }

        fn approval_value(approval: &ManagementApproval) -> Vec<u8> {
            crate::actors::value::Value::Bytes(approval.encode().unwrap()).encode()
        }

        fn placeholder_acknowledgement(
            call: &AuthorityCredentialCall,
            approval: &ManagementApproval,
            descriptor: &AgentDescriptor,
            catalog_request: &ManagementRequest,
            catalog_entry: ActorEntry,
            key: &SigningKey,
        ) -> ManagementApplicationAck {
            let receipt = signed_receipt(descriptor, catalog_request, 3, 2, 0x73, key);
            let mut acknowledgement = ManagementApplicationAck {
                authorization_invocation: call.invocation,
                acknowledgement_invocation: approval.acknowledgement_invocation,
                authority: call.authority,
                managed: call.managed,
                credential_call: call.commitment(),
                approval: approval.commitment(),
                authorization_sequence: approval.authorization_sequence,
                request: catalog_request.commitment(),
                receipt,
                application: ManagementReply::Installed(catalog_entry),
                reopened_state: Hash([0x7a; 32]),
                applied_at: LOGICAL_SLOT,
                signature: [1; 64],
            };
            acknowledgement.signature = key.sign(&acknowledgement.signing_bytes()).to_bytes();
            acknowledgement.validate_shape().unwrap();
            acknowledgement
        }

        struct RuntimeFixture {
            runtime: AdmittedRuntimePackage,
            descriptor: AgentDescriptor,
            replicas: AgentReplicaCommittee,
            authority_package: AdmittedActorPackage,
            authority_request: ManagementRequest,
            catalog_package: AdmittedActorPackage,
            catalog_request: ManagementRequest,
            catalog_call: AuthorityCredentialCall,
            catalog_approval: ManagementApproval,
        }

        fn shape_only_runtime() -> AdmittedRuntimePackage {
            let mut assembler = Assembler::new();
            let program = assembler.load_imm_64(Reg::A0, 0x63).trap().build_standard();
            let signing = SigningKey::from_bytes(&[0x63; 32]);
            let public_key = signing.verifying_key().to_bytes();
            let mut package = PackageEnvelope {
                manifest: PackageManifest::AgentRuntime(
                    crate::agent::sdk::package::AgentRuntimePackageManifest {
                        name: "shape-only-r7".into(),
                        outer_program: crate::agent::sdk::BlobRef::of_bytes(&program),
                        contract: crate::agent::sdk::contract::RuntimePackageContract::canonical(),
                        capabilities: crate::agent::sdk::RuntimeCapabilities::standard(),
                        signing: PackageSigning {
                            producer: ProducerId::of_public_key(&public_key),
                            public_key,
                            signature: [0; 64],
                        },
                    },
                ),
                artifacts: vec![PackageArtifact {
                    identity: crate::agent::sdk::BlobRef::of_bytes(&program),
                    bytes: program,
                }],
            };
            let signing_bytes = package.signing_bytes().unwrap();
            package.manifest.signing_mut().signature = signing.sign(&signing_bytes).to_bytes();
            admit_runtime_package(&package.encode().unwrap()).unwrap()
        }

        fn runtime_fixture() -> RuntimeFixture {
            let receipt_key = SigningKey::from_bytes(&[RECEIPT_SEED; 32]);
            let credential_key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
            let space = SpaceId([0x21; 32]);
            let owner = PrincipalId([0x22; 32]);
            let nonce = Hash([0x23; 32]);
            let agent = AgentId::derive(space, owner, nonce.as_bytes());
            let (replicas, member) = replica_member(space, agent);
            // The authority binding pins the receipt-signing producer, so its
            // installed package is signed by that same independently retained
            // key in this physical fixture.
            let authority_package = raw_constructor_actor("system-authority", RECEIPT_SEED);
            let catalog_package =
                admitted_standard_actor_for_test("merge-catalog", StateLane::Linear, 0x62);
            let authority = authority_binding(agent, &authority_package, &receipt_key);

            // The committed runtime blob is used only to establish a fixed-width
            // descriptor template. It is never executed. Every transition below
            // is served by the newly assembled current-ABI VOS3 custom PVM.
            let placeholder = shape_only_runtime();
            let placeholder_descriptor =
                descriptor(&placeholder, space, agent, owner, nonce, &member, authority);
            let catalog_request = install_request(agent, &catalog_package, 0x82, None);
            let (placeholder_call, placeholder_approval) = credential_call_and_approval(
                &placeholder_descriptor,
                &catalog_request,
                &credential_key,
            );
            let placeholder_approval_value = approval_value(&placeholder_approval);
            let placeholder_authority_request = install_request(
                agent,
                &authority_package,
                0x80,
                Some(placeholder_approval_value.clone()),
            );
            let authority_record = record(&placeholder_authority_request, 0x84);
            let catalog_record = record(&catalog_request, 0x85);
            let empty_page = page(Vec::new());
            let authority_page = page(vec![authority_record.clone()]);
            let catalog_page = page(vec![authority_record.clone(), catalog_record.clone()]);
            let mut empty_state = state(0x90, &empty_page, 0xa0);
            // Create owns only Control. The authority installation below is
            // the first transition permitted to initialize its declared
            // Linear lane.
            empty_state.linear.clear();
            let authority_state = state(0x91, &authority_page, 0xa0);
            let approved_state = state(0x91, &authority_page, 0xa1);
            let catalog_state = state(0x92, &catalog_page, 0xa1);
            let finalized_state = state(0x92, &catalog_page, 0xa2);

            let create_request =
                ManagementRequest::Create(Box::new(placeholder_descriptor.clone()));
            let mut create = manage_case(
                &placeholder_descriptor,
                RuntimeState::default(),
                create_request.clone(),
                Some(signed_receipt(
                    &placeholder_descriptor,
                    &create_request,
                    1,
                    0,
                    0x71,
                    &receipt_key,
                )),
                empty_state.clone(),
                RuntimeOutcome::Management(Ok(ManagementReply::Created(
                    placeholder_descriptor.identity.clone(),
                ))),
            );
            copy_from_first_input_to_all_outputs(
                &mut create,
                &identity_bytes(&placeholder_descriptor.identity),
            );

            let inspect = ManagementRequest::InspectActors {
                after: None,
                limit: crate::agent::sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
            };
            let inspect_case = |current: &RuntimeState, actors: &ActorDirectoryPage| {
                let mut case = manage_case(
                    &placeholder_descriptor,
                    current.clone(),
                    inspect.clone(),
                    None,
                    current.clone(),
                    RuntimeOutcome::Management(Ok(ManagementReply::Actors(actors.clone()))),
                );
                if !actors.entries.is_empty() {
                    copy_from_first_input_to_all_outputs(&mut case, &actors.encode().unwrap());
                    for reference in actors
                        .entries
                        .iter()
                        .filter_map(|record| record.entry.installation_data.as_ref())
                    {
                        // RuntimeOutcome embeds the page body rather than its
                        // standalone wire envelope, so copy every dynamic
                        // content identity separately as well as the opaque
                        // Control-state page above.
                        copy_from_first_input_to_all_outputs(&mut case, reference.hash.as_bytes());
                    }
                }
                case
            };

            let mut install_authority = manage_case(
                &placeholder_descriptor,
                empty_state.clone(),
                placeholder_authority_request.clone(),
                Some(signed_receipt(
                    &placeholder_descriptor,
                    &placeholder_authority_request,
                    2,
                    1,
                    0x72,
                    &receipt_key,
                )),
                authority_state.clone(),
                RuntimeOutcome::Management(Ok(ManagementReply::Installed(
                    authority_record.entry.clone(),
                ))),
            );
            let placeholder_data = match &placeholder_authority_request {
                ManagementRequest::Install(install) => install.installation_data.as_ref().unwrap(),
                _ => unreachable!(),
            };
            copy_from_first_input_to_all_outputs(
                &mut install_authority,
                placeholder_data.reference.hash.as_bytes(),
            );
            let authority_install_copies = install_authority
                .copies
                .iter()
                .map(|copy| (copy.input_offset, copy.output_offset, copy.len))
                .collect::<Vec<_>>();
            let authorize_work = invocation_work(
                &placeholder_descriptor,
                &authority_record,
                placeholder_call.invocation,
                InvocationOrigin {
                    principal: Some(placeholder_call.principal),
                    transport_node: placeholder_call.authenticated_node,
                    credential: Some(placeholder_call.credential),
                    actor: None,
                    capability: None,
                },
                dynamic_message(
                    "authorize",
                    "call",
                    crate::actors::value::Value::Bytes(placeholder_call.encode().unwrap()),
                ),
                placeholder_data,
                &authority_package,
            );
            let mut authorize = invoke_case(
                authority_state.clone(),
                authorize_work,
                approved_state.clone(),
                placeholder_approval_value.clone(),
            );
            copy_from_first_input_to_all_outputs(&mut authorize, &placeholder_call.invocation.0);
            copy_from_first_input_to_all_outputs(&mut authorize, &authority_page.encode().unwrap());
            copy_from_first_input_to_all_outputs(&mut authorize, &placeholder_approval_value);

            let mut install_catalog = manage_case(
                &placeholder_descriptor,
                approved_state.clone(),
                catalog_request.clone(),
                Some(signed_receipt(
                    &placeholder_descriptor,
                    &catalog_request,
                    3,
                    2,
                    0x73,
                    &receipt_key,
                )),
                catalog_state.clone(),
                RuntimeOutcome::Management(Ok(ManagementReply::Installed(
                    catalog_record.entry.clone(),
                ))),
            );
            copy_from_first_input_to_all_outputs(
                &mut install_catalog,
                placeholder_data.reference.hash.as_bytes(),
            );

            let acknowledgement = placeholder_acknowledgement(
                &placeholder_call,
                &placeholder_approval,
                &placeholder_descriptor,
                &catalog_request,
                catalog_record.entry.clone(),
                &receipt_key,
            );
            let finalize_work = invocation_work(
                &placeholder_descriptor,
                &authority_record,
                acknowledgement.acknowledgement_invocation,
                InvocationOrigin::anonymous(),
                dynamic_message(
                    "finalize",
                    "ack",
                    crate::actors::value::Value::Bytes(acknowledgement.encode().unwrap()),
                ),
                placeholder_data,
                &authority_package,
            );
            let mut finalize = invoke_case(
                catalog_state.clone(),
                finalize_work,
                finalized_state.clone(),
                crate::actors::value::Value::Bool(true).encode(),
            );
            copy_from_first_input_to_all_outputs(
                &mut finalize,
                &acknowledgement.acknowledgement_invocation.0,
            );
            copy_from_first_input_to_all_outputs(&mut finalize, &catalog_page.encode().unwrap());

            let cases = vec![
                create,
                inspect_case(&empty_state, &empty_page),
                install_authority,
                inspect_case(&authority_state, &authority_page),
                authorize,
                inspect_case(&approved_state, &authority_page),
                install_catalog,
                inspect_case(&catalog_state, &catalog_page),
                finalize,
                inspect_case(&finalized_state, &catalog_page),
            ];
            // The scripted guest copies installation bytes at a fixed offset.
            // Keep their position in sorted availability stable when replacing
            // the placeholder runtime identity with the signed fixture identity.
            let data_rank = |reference: &BlobRef| {
                [
                    authority_package.program_bytes(),
                    authority_package.state_lane_schema_bytes(),
                    authority_package.method_policy_bytes(),
                ]
                .into_iter()
                .filter(|bytes| BlobRef::of_bytes(bytes) < *reference)
                .count()
            };
            let placeholder_rank = data_rank(&placeholder_data.reference);
            let runtime = (1..=u8::MAX)
                .find_map(|seed| {
                    let copied_cases = cases
                        .iter()
                        .map(|case| ScriptedRuntimeCase {
                            input: case.input.clone(),
                            output: case.output.clone(),
                            copies: case
                                .copies
                                .iter()
                                .map(|copy| ScriptedRuntimeCopy {
                                    input_offset: copy.input_offset,
                                    output_offset: copy.output_offset,
                                    len: copy.len,
                                })
                                .collect(),
                        })
                        .collect();
                    let candidate = admitted_scripted_runtime_for_test(
                        "system-bootstrap-current-abi",
                        seed,
                        copied_cases,
                    );
                    let candidate_descriptor =
                        descriptor(&candidate, space, agent, owner, nonce, &member, authority);
                    let (_, approval) = credential_call_and_approval(
                        &candidate_descriptor,
                        &catalog_request,
                        &credential_key,
                    );
                    (data_rank(&BlobRef::of_bytes(&approval_value(&approval))) == placeholder_rank)
                        .then_some(candidate)
                })
                .expect("fixture signer preserving sorted installation-data position");
            let descriptor = descriptor(&runtime, space, agent, owner, nonce, &member, authority);
            let (catalog_call, catalog_approval) =
                credential_call_and_approval(&descriptor, &catalog_request, &credential_key);
            let authority_request = install_request(
                agent,
                &authority_package,
                0x80,
                Some(approval_value(&catalog_approval)),
            );
            let authority_input = RuntimeWork::Manage {
                context: crate::agent::sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                state: empty_state,
                request: Box::new(authority_request.clone()),
                authority: Some(Box::new(signed_receipt(
                    &descriptor,
                    &authority_request,
                    2,
                    1,
                    0x72,
                    &receipt_key,
                ))),
                observed_slot: LOGICAL_SLOT,
            }
            .encode()
            .unwrap();
            let expected_data = match &authority_request {
                ManagementRequest::Install(install) => install.installation_data.as_ref().unwrap(),
                _ => unreachable!(),
            };
            for (input_offset, _, len) in &authority_install_copies {
                assert_eq!(*len, 32);
                assert_eq!(
                    authority_input.get(*input_offset..*input_offset + *len),
                    Some(expected_data.reference.hash.as_bytes().as_slice())
                );
            }
            let authority_entry = match &authority_request {
                ManagementRequest::Install(install) => &install.entry,
                _ => unreachable!(),
            };
            let placeholder_authority_entry = match &placeholder_authority_request {
                ManagementRequest::Install(install) => &install.entry,
                _ => unreachable!(),
            };
            assert_eq!(
                authority_entry.encode().unwrap().len(),
                placeholder_authority_entry.encode().unwrap().len()
            );
            assert_eq!(
                catalog_call.encode().unwrap().len(),
                placeholder_call.encode().unwrap().len()
            );
            assert_eq!(
                catalog_approval.encode().unwrap().len(),
                placeholder_approval.encode().unwrap().len()
            );
            RuntimeFixture {
                runtime,
                descriptor,
                replicas,
                authority_package,
                authority_request,
                catalog_package,
                catalog_request,
                catalog_call,
                catalog_approval,
            }
        }

        fn root_provision(
            proposal: SystemAgentGenesisProposal,
            descriptor: &AgentDescriptor,
            root_certification: HostHash,
        ) -> (
            RootAnchorPins,
            super::super::super::bootstrap::SystemAgentGenesisProvision,
        ) {
            let key = SigningKey::from_bytes(&[ROOT_SEED; 32]);
            let member = AuthorityCommitteeMember::new(
                HostNodeId([0xb1; 32]),
                key.verifying_key().to_bytes(),
                AuthorityMemberRole::Voter,
            )
            .unwrap();
            let committee = AuthorityCommittee::new(
                HostSpaceId(descriptor.identity.space.0),
                HostHash(descriptor.authority.commitment().0),
                1,
                None,
                vec![member],
            )
            .unwrap();
            let record = RootAnchorRecord::new(
                1,
                HostSpaceId(descriptor.identity.space.0),
                HostAgentId(descriptor.identity.agent.0),
                HostHash(descriptor.authority.commitment().0),
                root_certification,
                committee.clone(),
            )
            .unwrap();
            let claim = SystemAgentGenesisClaim::new(&record, proposal.expectations()).unwrap();
            let message = AuthorityQuorumCertificate::signing_message(
                committee.authority_binding(),
                committee.epoch(),
                committee.commitment(),
                claim.authority_claim(),
            );
            let signature = AuthoritySignature::new(
                AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                key.sign(&message.0).to_bytes(),
            )
            .unwrap();
            let certificate = AuthorityQuorumCertificate::new(
                &committee,
                claim.authority_claim(),
                vec![signature],
            )
            .unwrap();
            let evidence = SystemAgentGenesisEvidence::new(claim.clone(), certificate).unwrap();
            let pins = RootAnchorPins::new(
                record.clone(),
                record.config_version(),
                record.id(),
                record.config_commitment(),
                claim.authority_claim(),
            )
            .unwrap();
            let provision = super::super::super::bootstrap::SystemAgentGenesisProvision::new(
                proposal,
                pins.clone(),
                evidence,
            )
            .unwrap();
            (pins, provision)
        }

        struct PhysicalFixture {
            plan: AuthorizedCleanSystemAgentBootstrap,
            provision: super::super::super::bootstrap::SystemAgentGenesisProvision,
            catalog: Vec<RuntimeBlob>,
            trust: Arc<dyn AgentTrustProvider>,
            merge: Arc<dyn LocalMergeAuthenticator>,
            finality: Arc<dyn AgentGenesisFinalityVerifier>,
            logical_slot: Option<Arc<AtomicU64>>,
        }

        fn physical_fixture() -> PhysicalFixture {
            let runtime = runtime_fixture();
            assert!(
                runtime
                    .catalog_approval
                    .plan
                    .matches_request(&runtime.catalog_request)
            );
            assert_eq!(
                runtime.catalog_approval.plan_commitment,
                runtime.catalog_request.commitment()
            );
            let host_authority = host_authority_binding(&runtime.descriptor);
            let trust: Arc<dyn AgentTrustProvider> = Arc::new(PhysicalTrust {
                authority: host_authority,
                logical_slot: None,
            });
            let (node_key, _, _, node) = node_material();
            let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(SigningMerge {
                key: node_key,
                node,
            });
            let certifier_descriptor = runtime.descriptor.clone();
            let mut root_certifier =
                |root_certification: Hash,
                 proposal: &SystemAgentGenesisProposal,
                 _catalog: &[RuntimeBlob]| {
                    Ok(root_provision(
                        proposal.clone(),
                        &certifier_descriptor,
                        HostHash(root_certification.0),
                    )
                    .1)
                };
            let mut receipt_signer = CountingSigner::new();
            let prepared = AuthorizedCleanSystemAgentBootstrap::prepare_root_authorized(
                runtime.descriptor,
                runtime.runtime.exact_bytes().to_vec(),
                runtime.replicas,
                LOGICAL_SLOT,
                runtime.authority_package.exact_bytes().to_vec(),
                runtime.authority_request,
                runtime.catalog_package.exact_bytes().to_vec(),
                runtime.catalog_request,
                runtime.catalog_call,
                1_000_000,
                &mut receipt_signer,
                &mut root_certifier,
                Arc::clone(&trust),
                Arc::clone(&merge),
            )
            .unwrap();
            let (plan, provision, catalog) = prepared.into_parts();
            PhysicalFixture {
                plan,
                provision,
                catalog,
                trust,
                merge,
                finality: Arc::new(AcceptFinality),
                logical_slot: None,
            }
        }

        fn placeholder_credential_projection()
        -> crate::agent::sdk::authority::AuthorityCredentialProjection {
            use crate::agent::sdk::authority::{
                AuthorityBuiltinRole, AuthorityCredentialKind, AuthorityCredentialProjection,
                AuthorityCredentialStatus, AuthorityIngressAuthentication, AuthorityProjectionHead,
            };

            let credential_key = SigningKey::from_bytes(&[0xa4; 32]);
            let credential_public_key = credential_key.verifying_key().to_bytes();
            let authority_public_key = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
                .verifying_key()
                .to_bytes();
            let authority = AuthorityActorTarget {
                space: SpaceId([0x91; 32]),
                system_agent: AgentId([0x92; 32]),
                system_runtime_deployment: crate::agent::sdk::DeploymentId([0x93; 32]),
                binding: AgentAuthorityBinding {
                    policy: Hash([0x94; 32]),
                    issuer: AuthorityIssuer {
                        principal: PrincipalId([0x95; 32]),
                        actor: ActorId([0x96; 32]),
                        deployment: crate::agent::sdk::DeploymentId([0x97; 32]),
                        program: crate::agent::sdk::ProgramId([0x98; 32]),
                        producer: ProducerId::of_public_key(&authority_public_key),
                    },
                    public_key: authority_public_key,
                    initial_epoch: 1,
                },
            };
            let query = AuthorityProjectionQuery {
                authority,
                credential: CredentialId::of_public_key(&credential_public_key),
                nonce: Hash([0x9a; 32]),
                selector: AuthorityProjectionSelector::Credential,
                authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key,
                    signature: [0x9b; 64],
                },
            };
            query.validate_shape().unwrap();
            let projection = AuthorityCredentialProjection {
                query,
                head: AuthorityProjectionHead {
                    state_revision: NonZeroU64::new(1).unwrap(),
                    epoch: NonZeroU64::new(1).unwrap(),
                    authorization_sequence: NonZeroU64::new(1).unwrap(),
                    administration_generation: NonZeroU64::new(1).unwrap(),
                    state_commitment: Hash([0x9c; 32]),
                },
                principal: PrincipalId([0x9d; 32]),
                status: AuthorityCredentialStatus::Active,
                kind: AuthorityCredentialKind::Api,
                builtin_role: AuthorityBuiltinRole::Admin,
                management_request_high_water: 0,
                operation_request_high_water: 0,
                admin_request_high_water: 0,
                space_roles: Vec::new(),
                actor_roles: Vec::new(),
                capabilities: Vec::new(),
            };
            projection.validate_shape().unwrap();
            projection
        }

        fn native_projection_physical_fixture() -> PhysicalFixture {
            native_projection_physical_fixture_with_authority(credential_projection_actor(
                "system-authority",
                RECEIPT_SEED,
                &placeholder_credential_projection(),
            ))
        }

        fn native_projection_physical_fixture_with_authority(
            authority_package: AdmittedActorPackage,
        ) -> PhysicalFixture {
            native_physical_fixture_with_authority_configuration(authority_package, None)
        }

        fn native_physical_fixture_with_authority_configuration(
            authority_package: AdmittedActorPackage,
            configuration: Option<fn(&AgentDescriptor) -> Vec<u8>>,
        ) -> PhysicalFixture {
            let receipt_key = SigningKey::from_bytes(&[RECEIPT_SEED; 32]);
            let credential_key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
            let runtime = shape_only_runtime();
            let space = SpaceId([0x31; 32]);
            let owner = PrincipalId([0x32; 32]);
            let nonce = Hash([0x33; 32]);
            let agent = AgentId::derive(space, owner, nonce.as_bytes());
            let (replicas, member) = replica_member(space, agent);
            let catalog_package =
                admitted_standard_actor_for_test("root-catalog", StateLane::Linear, 0xa5);
            let authority = authority_binding(agent, &authority_package, &receipt_key);
            let descriptor = descriptor(&runtime, space, agent, owner, nonce, &member, authority);
            let authority_request = install_request(
                agent,
                &authority_package,
                0xa6,
                configuration.map(|encode| encode(&descriptor)),
            );
            let catalog_request = install_request(agent, &catalog_package, 0xa8, None);
            let (catalog_call, _) =
                credential_call_and_approval(&descriptor, &catalog_request, &credential_key);
            let host_authority = host_authority_binding(&descriptor);
            let logical_slot = Arc::new(AtomicU64::new(LOGICAL_SLOT));
            let trust: Arc<dyn AgentTrustProvider> = Arc::new(NativePhysicalTrust {
                authority: host_authority,
                logical_slot: Arc::clone(&logical_slot),
            });
            let (node_key, _, _, node) = node_material();
            let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(SigningMerge {
                key: node_key,
                node,
            });
            let certifier_descriptor = descriptor.clone();
            let mut root_certifier =
                |root_certification: Hash,
                 proposal: &SystemAgentGenesisProposal,
                 _catalog: &[RuntimeBlob]| {
                    Ok(root_provision(
                        proposal.clone(),
                        &certifier_descriptor,
                        HostHash(root_certification.0),
                    )
                    .1)
                };
            let mut receipt_signer = CountingSigner::new();
            let prepared = AuthorizedCleanSystemAgentBootstrap::prepare_root_authorized(
                descriptor,
                runtime.exact_bytes().to_vec(),
                replicas,
                LOGICAL_SLOT,
                authority_package.exact_bytes().to_vec(),
                authority_request,
                catalog_package.exact_bytes().to_vec(),
                catalog_request,
                catalog_call,
                if configuration.is_some() {
                    crate::agent::execution::MAX_EXECUTION_GAS
                } else {
                    10_000_000
                },
                &mut receipt_signer,
                &mut root_certifier,
                Arc::clone(&trust),
                Arc::clone(&merge),
            )
            .unwrap();
            let (plan, provision, catalog) = prepared.into_parts();
            PhysicalFixture {
                plan,
                provision,
                catalog,
                trust,
                merge,
                finality: Arc::new(AcceptFinality),
                logical_slot: Some(logical_slot),
            }
        }

        fn native_inventory_projection_fixture() -> (
            PhysicalFixture,
            Vec<AgentDescriptor>,
            AuthorityProjectionHead,
        ) {
            let mut target = placeholder_credential_projection().query.authority;
            target.space = SpaceId([0x31; 32]);
            target.system_agent = AgentId::derive(
                target.space,
                PrincipalId([0x32; 32]),
                Hash([0x33; 32]).as_bytes(),
            );
            target.binding.policy = Hash([0x51; 32]);
            target.binding.issuer.principal = PrincipalId([0x52; 32]);
            target.binding.issuer.actor =
                ActorId::top_level(target.system_agent, "system-authority");
            let mut descriptors = (0..241)
                .map(|index| inventory_descriptor(target, index))
                .collect::<Vec<_>>();
            descriptors.sort_unstable_by_key(|descriptor| descriptor.identity.agent);
            let head = placeholder_credential_projection().head;
            let package = inventory_projection_actor(
                "system-authority",
                RECEIPT_SEED,
                target,
                &descriptors,
                head,
            );
            let fixture = native_projection_physical_fixture_with_authority(package);
            for descriptor in &mut descriptors {
                descriptor.authority = fixture.plan.pins.authority;
                descriptor.validate().unwrap();
            }
            (fixture, descriptors, head)
        }

        /// Seed only the already-complete predecessor needed by projection
        /// recovery tests. Create and both actor installations traverse the
        /// real native Standard journal and live Raft worker. The authority
        /// approval/finalization records are constructed and retained through
        /// the issuer API so this helper is not evidence for the separate
        /// bootstrap actor-finalization lifecycle.
        #[allow(clippy::too_many_arguments)]
        fn seed_complete_native_projection_owner(
            fixture: &PhysicalFixture,
            directory: &TestDirectory,
            pins: BootstrapMemoryStore,
            record: BootstrapMemoryStore,
            issuer_store: IssuerMemoryStore,
            signer: &mut CountingSigner,
            provider: Arc<MemoryProvider>,
            network: Arc<Network>,
        ) -> CleanSystemAgentBootstrapOwner<
            BootstrapMemoryStore,
            BootstrapMemoryStore,
            IssuerMemoryStore,
        > {
            assert_eq!(
                provider
                    .create(fixture.provision.proposal(), &fixture.catalog)
                    .unwrap(),
                fixture.provision,
            );
            let plan = &fixture.plan;
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer_store.clone(),
                plan.pins.authority,
                plan.pins.space,
                plan.pins.agent,
            )
            .unwrap();
            let create_receipt = issuer.issue(&plan.create_decision, signer).unwrap();

            let scope = AgentHostScope {
                space: HostSpaceId(plan.pins.space.0),
                node: HostNodeId(plan.pins.node.0),
            };
            let mut shared_host = SharedAgentHost::open_with_root(
                directory.host(),
                directory.lock(),
                scope,
                Arc::clone(&fixture.trust),
                Arc::clone(&fixture.merge),
                Arc::clone(&fixture.finality),
                plan.pins.root.clone(),
            )
            .unwrap();
            shared_host
                .provision_system_bootstrap(
                    fixture.provision.clone(),
                    plan.pins.replicas.clone(),
                    fixture.catalog.clone(),
                    committee_authority_binding(plan).unwrap(),
                )
                .unwrap();
            issuer.observe_durable(&create_receipt).unwrap();

            let host = Arc::new(Mutex::new(shared_host));
            let network_host = SharedAgentNetworkHost::attach_system(
                Arc::clone(&host),
                Arc::clone(&network),
                HostAgentId(plan.pins.agent.0),
                &plan.pins.replicas,
                fixture.merge.as_ref(),
            )
            .unwrap();
            fixture
                .logical_slot
                .as_ref()
                .expect("native projection fixture clock")
                .store(LOGICAL_SLOT + 1, Ordering::Release);
            let authority_receipt = issuer.issue(&plan.authority_decision, signer).unwrap();
            apply_actor_install(
                &host,
                &network_host,
                plan,
                &plan.authority_request,
                &authority_receipt,
                plan.authority_package().unwrap(),
            )
            .unwrap();
            issuer.observe_durable(&authority_receipt).unwrap();

            let credential_key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
            let (catalog_call, catalog_approval) = credential_call_and_approval(
                &plan.pins.descriptor,
                &plan.catalog_request,
                &credential_key,
            );
            assert_eq!(catalog_call, plan.catalog_call);
            let catalog_decision = AuthorizedCleanManagementDecision::from_approval(
                plan.authority_target(),
                plan.managed_target(),
                &plan.catalog_request,
                &catalog_call,
                &catalog_approval,
                &RawCredentialVerifier,
            )
            .unwrap();
            let catalog_receipt = issuer.issue(&catalog_decision, signer).unwrap();
            fixture
                .logical_slot
                .as_ref()
                .expect("native projection fixture clock")
                .store(LOGICAL_SLOT + 2, Ordering::Release);
            let (catalog_application, applied_at) = apply_actor_install(
                &host,
                &network_host,
                plan,
                &plan.catalog_request,
                &catalog_receipt,
                plan.catalog_package().unwrap(),
            )
            .unwrap();
            let reopened_state = host
                .lock()
                .unwrap()
                .clean_state_commitment(HostAgentId(plan.pins.agent.0))
                .unwrap();
            let catalog_acknowledgement = issuer
                .observe_durable_application(
                    &catalog_receipt,
                    &catalog_application,
                    reopened_state,
                    applied_at,
                    signer,
                )
                .unwrap();
            assert!(
                issuer
                    .observe_durable_actor_finalization(&catalog_acknowledgement)
                    .unwrap()
            );
            assert_eq!(issuer.sequence_high_water(), 3);
            assert_eq!(issuer.acknowledged_through(), 3);

            let mut complete = CleanSystemAgentBootstrapRecord::intent(plan);
            complete.create_receipt = Some(create_receipt);
            complete.authority_receipt = Some(authority_receipt);
            complete.catalog_approval = Some(catalog_approval);
            complete.catalog_receipt = Some(catalog_receipt);
            complete.catalog_acknowledgement = Some(catalog_acknowledgement);
            complete.advance(CleanSystemAgentBootstrapPhase::Complete);
            assert!(complete.is_valid());
            pins.clone().commit(&plan.pins.encode()).unwrap();
            record.clone().commit(&complete.encode()).unwrap();

            drop(network_host);
            drop(host);
            open_owner(
                fixture,
                directory,
                pins,
                record,
                issuer_store,
                signer,
                provider,
                network,
            )
            .unwrap()
        }

        fn signed_credential_projection_query(
            owner: &CleanSystemAgentBootstrapOwner<
                BootstrapMemoryStore,
                BootstrapMemoryStore,
                IssuerMemoryStore,
            >,
            nonce: u8,
        ) -> AuthorityProjectionQuery {
            use crate::agent::sdk::authority::AuthorityIngressAuthentication;

            let key = SigningKey::from_bytes(&[0xa4; 32]);
            let public_key = key.verifying_key().to_bytes();
            let mut query = AuthorityProjectionQuery {
                authority: owner.authority_target(),
                credential: CredentialId::of_public_key(&public_key),
                nonce: Hash([nonce; 32]),
                selector: AuthorityProjectionSelector::Credential,
                authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: public_key,
                    signature: [1; 64],
                },
            };
            let signature = key.sign(&query.signing_bytes()).to_bytes();
            let AuthorityIngressAuthentication::ApiCredentialSignature {
                signature: query_signature,
                ..
            } = &mut query.authentication
            else {
                unreachable!()
            };
            *query_signature = signature;
            query.verify_api_with(&RawCredentialVerifier).unwrap();
            query
        }

        fn open_owner(
            fixture: &PhysicalFixture,
            directory: &TestDirectory,
            pins: BootstrapMemoryStore,
            record: BootstrapMemoryStore,
            issuer: IssuerMemoryStore,
            signer: &mut CountingSigner,
            provider: Arc<MemoryProvider>,
            network: Arc<Network>,
        ) -> Result<
            CleanSystemAgentBootstrapOwner<
                BootstrapMemoryStore,
                BootstrapMemoryStore,
                IssuerMemoryStore,
            >,
            CleanSystemAgentBootstrapError,
        > {
            CleanSystemAgentBootstrapOwner::open_or_bootstrap(
                pins,
                record,
                issuer,
                signer,
                &fixture.plan,
                directory.host(),
                directory.lock(),
                fixture.plan.pins.space,
                fixture.plan.pins.node,
                Arc::clone(&fixture.trust),
                Arc::clone(&fixture.merge),
                Arc::clone(&fixture.finality),
                provider,
                network,
            )
        }

        fn open_owner_with_factory<F>(
            fixture: &PhysicalFixture,
            directory: &TestDirectory,
            pins: BootstrapMemoryStore,
            record: BootstrapMemoryStore,
            issuer: IssuerMemoryStore,
            signer: &mut CountingSigner,
            fresh_plan: F,
            provider: Arc<MemoryProvider>,
            network: Arc<Network>,
        ) -> Result<
            CleanSystemAgentBootstrapOwner<
                BootstrapMemoryStore,
                BootstrapMemoryStore,
                IssuerMemoryStore,
            >,
            CleanSystemAgentBootstrapError,
        >
        where
            F: FnOnce() -> Result<
                AuthorizedCleanSystemAgentBootstrap,
                CleanSystemAgentBootstrapError,
            >,
        {
            CleanSystemAgentBootstrapOwner::open_or_bootstrap_with_factory(
                pins,
                record,
                issuer,
                signer,
                fresh_plan,
                directory.host(),
                directory.lock(),
                fixture.plan.pins.space,
                fixture.plan.pins.node,
                Arc::clone(&fixture.trust),
                Arc::clone(&fixture.merge),
                Arc::clone(&fixture.finality),
                provider,
                network,
            )
        }

        type MemoryBootstrapOwner = CleanSystemAgentBootstrapOwner<
            BootstrapMemoryStore,
            BootstrapMemoryStore,
            IssuerMemoryStore,
        >;

        struct NativeProjectionOwnerHarness {
            owner: Option<MemoryBootstrapOwner>,
            fixture: PhysicalFixture,
            record: BootstrapMemoryStore,
            _directory: TestDirectory,
            network: Arc<Network>,
        }

        impl NativeProjectionOwnerHarness {
            fn new(label: &str) -> Self {
                Self::with_fixture(label, native_projection_physical_fixture())
            }

            fn with_fixture(label: &str, fixture: PhysicalFixture) -> Self {
                let directory = TestDirectory::new(label);
                let network = network(NODE_SEED);
                let mut signer = CountingSigner::new();
                let record = BootstrapMemoryStore::default();
                let owner = seed_complete_native_projection_owner(
                    &fixture,
                    &directory,
                    BootstrapMemoryStore::default(),
                    record.clone(),
                    IssuerMemoryStore::default(),
                    &mut signer,
                    Arc::new(MemoryProvider::new(fixture.provision.clone())),
                    Arc::clone(&network),
                );
                Self {
                    owner: Some(owner),
                    fixture,
                    record,
                    _directory: directory,
                    network,
                }
            }

            fn stop(mut self) {
                drop(self.owner.take());
                stop_network(self.network);
            }
        }

        fn fresh_projection_pair(
            owner: &MemoryBootstrapOwner,
            nonce: u8,
        ) -> (InvocationWork, InvocationAuthorization) {
            let pending = owner
                .prepare_authority_projection(signed_credential_projection_query(owner, nonce))
                .unwrap();
            let (work, authorization) = pending.invocation().unwrap();
            (work.clone(), authorization.clone())
        }

        fn native_owner_physical_state(
            owner: &MemoryBootstrapOwner,
        ) -> (
            crate::agent::shared_host::SharedAgentJournalPosition,
            Hash,
            crate::agent::shared_host::SharedAgentStatus,
        ) {
            let agent = HostAgentId(owner.pins.agent.0);
            let host = owner.host.lock().unwrap();
            (
                host.journal_position(agent).unwrap(),
                host.clean_state_commitment(agent).unwrap(),
                host.show(agent).unwrap().unwrap(),
            )
        }

        fn assert_projection_gate_released(owner: &mut MemoryBootstrapOwner, nonce: u8) {
            let agent = HostAgentId(owner.pins.agent.0);
            let (work, authorization) = fresh_projection_pair(owner, nonce);
            owner
                ._network_host
                .reserve_projection_pair(agent, &work, &authorization, false)
                .unwrap();
            owner
                ._network_host
                .release_projection_pair(agent, &work, &authorization)
                .unwrap();
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        struct InventoryProjectionObservation {
            query: AuthorityProjectionQuery,
            ordered_index: u64,
            snapshot: Option<crate::agent::shared_host::SharedAgentSnapshotState>,
        }

        struct InventoryProjectionAuthenticator {
            counters: [u8; 4],
            host: Arc<Mutex<SharedAgentHost>>,
            agent: HostAgentId,
            observations: Arc<Mutex<Vec<InventoryProjectionObservation>>>,
        }

        impl crate::agent::production_owner::AuthorityProjectionQueryAuthenticator
            for InventoryProjectionAuthenticator
        {
            fn expected_kind(&self) -> AuthorityCredentialKind {
                AuthorityCredentialKind::Api
            }

            fn authenticate(
                &mut self,
                authority: AuthorityActorTarget,
                selector: AuthorityProjectionSelector,
            ) -> Result<
                AuthorityProjectionQuery,
                crate::agent::production_owner::AgentProductionOwnerError,
            > {
                let group = match selector {
                    AuthorityProjectionSelector::Credential => 1,
                    AuthorityProjectionSelector::Agents { .. } => 2,
                    AuthorityProjectionSelector::AgentReplicas { .. } => 3,
                    AuthorityProjectionSelector::Actors { .. } => 4,
                };
                let counter = &mut self.counters[usize::from(group - 1)];
                *counter = counter.checked_add(1).ok_or(
                    crate::agent::production_owner::AgentProductionOwnerError::InventoryLimit,
                )?;
                let query = inventory_template_query(authority, selector, group, *counter);
                let call = self
                    .counters
                    .iter()
                    .map(|counter| usize::from(*counter))
                    .sum::<usize>();
                let (ordered_index, snapshot) = {
                    let host = self.host.lock().unwrap();
                    (
                        host.journal_position(self.agent).unwrap().ordered_index,
                        matches!(call, 513 | 514)
                            .then(|| host.snapshot_state_for_test(self.agent).unwrap()),
                    )
                };
                self.observations
                    .lock()
                    .unwrap()
                    .push(InventoryProjectionObservation {
                        query: query.clone(),
                        ordered_index,
                        snapshot,
                    });
                Ok(query)
            }
        }

        fn exercise_restart_mode(failure: RecordFailure, label: &str) {
            let mut fixture = physical_fixture();
            let clock = Arc::new(AtomicU64::new(LOGICAL_SLOT));
            fixture.trust = Arc::new(PhysicalTrust {
                authority: host_authority_binding(&fixture.plan.pins.descriptor),
                logical_slot: Some(Arc::clone(&clock)),
            });
            let directory = TestDirectory::new(label);
            let pins = BootstrapMemoryStore::default();
            let record = BootstrapMemoryStore::with_failure(failure);
            let issuer = IssuerMemoryStore::default();
            let provider = Arc::new(MemoryProvider::new(fixture.provision.clone()));
            let network = network(NODE_SEED);
            let mut signer = CountingSigner::new();
            let mut attempts = 0_usize;
            let owner = loop {
                attempts += 1;
                match open_owner(
                    &fixture,
                    &directory,
                    pins.clone(),
                    record.clone(),
                    issuer.clone(),
                    &mut signer,
                    Arc::clone(&provider),
                    Arc::clone(&network),
                ) {
                    Ok(owner) => break owner,
                    Err(CleanSystemAgentBootstrapError::RecordStorage) => {
                        clock.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(error) => {
                        let phase = record
                            .image()
                            .as_deref()
                            .and_then(|bytes| CleanSystemAgentBootstrapRecord::decode(bytes).ok())
                            .map(|record| record.phase());
                        panic!(
                            "unexpected restart failure after {attempts} attempts/{} commits at {phase:?}: {error:?}",
                            record.commits()
                        );
                    }
                }
            };
            assert_eq!(owner.ordered_index_for_test().unwrap(), 4);
            // Inspect a fresh proposal without applying it: preflight and
            // journal observation must use one current slot, not genesis time.
            let actor =
                ensure_actor_installed(&owner.host, &fixture.plan, &fixture.plan.authority_request)
                    .unwrap();
            let install = super::super::install_request(&fixture.plan.authority_request).unwrap();
            let package = fixture.plan.authority_package().unwrap();
            let probe = invocation_work(
                &fixture.plan.pins.descriptor,
                &actor,
                InvocationId([0xfd; 32]),
                InvocationOrigin::anonymous(),
                vec![1],
                install.installation_data.as_ref().unwrap(),
                &package,
            );
            let prepared = owner
                .host
                .lock()
                .unwrap()
                .prepare_bootstrap_invocation(
                    crate::service::AgentId(fixture.plan.pins.agent.0),
                    crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                        context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                        authorization: InvocationAuthorization::PublicPreflight(
                            crate::agent_sdk::PublicPreflight::for_work(&probe, LOGICAL_SLOT),
                        ),
                        work: probe.clone(),
                    },
                )
                .unwrap();
            let crate::agent::shared_journal_driver::PreparedCleanOrdered::Proposal {
                payload, ..
            } = prepared
            else {
                panic!("fresh probe must propose")
            };
            let crate::agent::shared_raft::AgentRaftCommand::Ordered { entry, .. } =
                crate::agent::shared_raft::AgentRaftCommand::decode(&payload).unwrap()
            else {
                panic!("expected ordered probe")
            };
            let crate::agent::journal::ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            } = entry.input.operation
            else {
                panic!("expected invocation")
            };
            assert_eq!(work, probe);
            assert_eq!(observed_slot, clock.load(Ordering::Acquire));
            assert!(observed_slot > LOGICAL_SLOT);
            assert_eq!(
                authorization,
                InvocationAuthorization::PublicPreflight(
                    crate::agent_sdk::PublicPreflight::for_work(&probe, observed_slot)
                )
            );
            assert_eq!(owner.issuer_sequence_high_water(), 3);
            assert_eq!(owner.issuer_acknowledged_through(), 3);
            assert_eq!(signer.calls, 4);
            assert_eq!(owner.list().unwrap(), vec![fixture.plan.pins.agent]);
            assert_eq!(
                owner.show(fixture.plan.pins.agent).unwrap(),
                Some(fixture.plan.pins.descriptor.clone())
            );
            assert!(
                owner
                    .network_host_for_test()
                    .attachment_for_test(HostAgentId(fixture.plan.pins.agent.0))
                    .unwrap()
                    .1
            );
            drop(owner);

            let reopened = open_owner(
                &fixture,
                &directory,
                pins.clone(),
                record.clone(),
                issuer.clone(),
                &mut signer,
                Arc::clone(&provider),
                Arc::clone(&network),
            )
            .unwrap();
            assert_eq!(reopened.ordered_index_for_test().unwrap(), 4);
            assert_eq!(signer.calls, 4, "exact reopen must not sign again");

            let record_bytes = record.image().unwrap();
            let decoded = CleanSystemAgentBootstrapRecord::decode(&record_bytes).unwrap();
            assert_eq!(decoded.phase(), CleanSystemAgentBootstrapPhase::Complete);
            let mut trailing = record_bytes.clone();
            trailing.push(0);
            assert!(CleanSystemAgentBootstrapRecord::decode(&trailing).is_err());
            let mut previous_record_version = record_bytes.clone();
            previous_record_version[4 + 32] = 2;
            assert!(CleanSystemAgentBootstrapRecord::decode(&previous_record_version).is_err());
            let mut old = record_bytes.clone();
            old[..4].copy_from_slice(b"CSB1");
            assert!(CleanSystemAgentBootstrapRecord::decode(&old).is_err());
            let mut altered = record_bytes;
            let offset = 4 + 32 + 1 + 1 + 32 + 32 + 8;
            altered[offset] ^= 1;
            assert!(CleanSystemAgentBootstrapRecord::decode(&altered).is_err());

            let mut divergent = fixture.plan.clone();
            divergent.invocation_gas += 1;
            assert!(divergent.validate().is_ok());
            drop(reopened);
            assert!(matches!(
                CleanSystemAgentBootstrapOwner::open_or_bootstrap(
                    pins,
                    record.clone(),
                    issuer,
                    &mut signer,
                    &divergent,
                    directory.host(),
                    directory.lock(),
                    divergent.pins.space,
                    divergent.pins.node,
                    Arc::clone(&fixture.trust),
                    Arc::clone(&fixture.merge),
                    Arc::clone(&fixture.finality),
                    Arc::clone(&provider) as Arc<dyn SystemAgentGenesisProvider>,
                    Arc::clone(&network),
                ),
                Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::DivergentRecord
                ))
            ));
            match failure {
                RecordFailure::BeforeEveryPhase => assert_eq!(record.commits(), 20),
                RecordFailure::AfterEveryPhase => assert_eq!(record.commits(), 10),
                RecordFailure::None => unreachable!(),
            }
            stop_network(network);
        }

        #[test]
        fn physical_current_abi_shared_bootstrap_restarts_before_every_phase_without_duplicate_slots()
         {
            exercise_restart_mode(RecordFailure::BeforeEveryPhase, "before-every-phase");
        }

        #[test]
        fn physical_current_abi_shared_bootstrap_restarts_after_every_phase_without_duplicate_slots()
         {
            exercise_restart_mode(RecordFailure::AfterEveryPhase, "after-every-phase");
        }

        #[test]
        fn native_management_intent_executes_bundled_authority_and_recovers_receipt() {
            native_local_management_lifecycle(0);
        }

        #[test]
        fn native_local_creation_coordinator_finalizes_and_reopens_exactly() {
            native_local_management_lifecycle(1);
        }

        #[test]
        fn native_local_lifecycle_controller_uses_scoped_stores_with_attached_workers() {
            native_local_management_lifecycle(2);
        }

        #[test]
        fn native_node_rejects_lifecycle_start_after_shutdown_without_leaking_hosts() {
            native_local_management_lifecycle(3);
        }

        #[test]
        fn native_local_lifecycle_queue_is_bounded_and_closes_pending_replies() {
            native_local_management_lifecycle(4);
        }

        #[test]
        fn native_local_create_submission_is_canonical_signed_and_runtime_bound() {
            native_local_management_lifecycle(5);
        }

        #[test]
        fn native_local_authorization_clock_advance_preserves_receipt_and_intent() {
            native_local_management_lifecycle(6);
        }

        #[test]
        fn native_management_finalization_clock_advance_preserves_exact_replay() {
            native_local_management_lifecycle(7);
        }

        #[inline(never)]
        fn check_management_clock_advance(
            owner: &mut MemoryBootstrapOwner,
            intent: crate::agent::clean_management_intent::CleanManagementIntent,
            descriptor: &AgentDescriptor,
            clock: Arc<AtomicU64>,
        ) {
            use crate::agent::clean_management_intent::CleanManagementIntentSlot;
            let managed = intent.call().managed;
            let store = IssuerMemoryStore {
                // First commit pledges the intent; second saves its preflight.
                advance_clock_after_commits: Some((clock.clone(), 2)),
                ..Default::default()
            };
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            slot.pledge(intent).unwrap();
            let issuer_store = IssuerMemoryStore::default();
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer_store.clone(),
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            let mut signer = CountingSigner::new();
            let receipt = owner
                .issue_management_intent(&mut slot, managed, &mut issuer, &mut signer)
                .unwrap();
            let applied = owner.ordered_index_for_test().unwrap();
            let envelope = slot.authorization_work().unwrap().unwrap().clone();
            let image = store.image.lock().unwrap().clone();
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = &envelope
            else {
                panic!("expected persisted authorization work");
            };
            let mut material = owner
                .supervisor_invocation_material(owner.pins.agent, invocation.actor)
                .unwrap();
            material.root_provenance = false;
            let identity =
                crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
            let outcome = owner
                .supervisor_invoke_persisted_management(
                    identity,
                    (**invocation).clone(),
                    (**authorization).clone(),
                )
                .unwrap();
            assert!(matches!(outcome, RuntimeOutcome::Completed(Ok(_))));
            check_persisted_management_admission_guards(
                owner,
                identity,
                invocation,
                clock.load(Ordering::Acquire),
            );
            drop(slot);
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer.into_store(),
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            clock.fetch_add(20, Ordering::AcqRel);
            assert_eq!(
                owner
                    .issue_management_intent(&mut slot, managed, &mut issuer, &mut signer)
                    .unwrap(),
                receipt
            );
            assert_eq!(slot.authorization_work().unwrap(), Some(&envelope));
            assert_eq!(*store.image.lock().unwrap(), image);
            assert_eq!(signer.calls, 1);
            assert!(issuer_store.image.lock().unwrap().is_some());
            assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
        }

        #[inline(never)]
        fn check_persisted_management_admission_guards(
            owner: &MemoryBootstrapOwner,
            identity: crate::agent::supervisor::AgentRouteIdentity,
            work: &InvocationWork,
            observed_slot: u64,
        ) {
            let before = owner.ordered_index_for_test().unwrap();
            let authorization = InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(work, observed_slot + 1),
            );
            assert!(
                owner
                    .supervisor_invoke_persisted_management(identity, work.clone(), authorization)
                    .is_err()
            );
            let mut query = work.clone();
            query.mode = MethodMode::Query;
            let authorization = InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(&query, observed_slot),
            );
            assert!(matches!(
                owner.supervisor_invoke_persisted_management(identity, query, authorization),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            let mut other_actor = work.clone();
            other_actor.actor = ActorId::ZERO;
            let authorization = InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(&other_actor, observed_slot),
            );
            assert!(matches!(
                owner.supervisor_invoke_persisted_management(identity, other_actor, authorization),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        }

        #[inline(never)]
        fn check_local_create_submission(
            descriptor: &AgentDescriptor,
            call: &AuthorityCredentialCall,
            runtime: &AdmittedRuntimePackage,
        ) {
            use crate::agent::local_lifecycle::LocalCreateSubmission;
            let submission =
                LocalCreateSubmission::new(descriptor.clone(), call.clone(), runtime.clone())
                    .unwrap();
            let bytes = submission.encode();
            assert!(
                bytes.len() <= 1024 * 1024,
                "bundled runtime submission fits HTTP body cap"
            );
            let decoded = LocalCreateSubmission::decode(&bytes).unwrap();
            assert_eq!(decoded.encode(), bytes);
            let (restored_descriptor, restored_call, restored_runtime) = decoded.into_parts();
            assert_eq!(&restored_descriptor, descriptor);
            assert_eq!(&restored_call, call);
            assert_eq!(restored_runtime.exact_bytes(), runtime.exact_bytes());
            assert!(LocalCreateSubmission::decode(&bytes[..bytes.len() - 1]).is_err());
            let mut altered = bytes.clone();
            altered.push(0);
            assert!(LocalCreateSubmission::decode(&altered).is_err());
            altered = bytes;
            altered[0] ^= 1;
            assert!(LocalCreateSubmission::decode(&altered).is_err());
            let mut forged = call.clone();
            forged.signature[0] ^= 1;
            assert!(
                LocalCreateSubmission::new(descriptor.clone(), forged, runtime.clone()).is_err()
            );
            assert!(
                LocalCreateSubmission::new(descriptor.clone(), call.clone(), shape_only_runtime())
                    .is_err()
            );
        }

        #[test]
        fn native_system_attachment_repeated_promotions_preserve_journal() {
            let mut harness = NativeProjectionOwnerHarness::new("repeated-system-promotion");
            let owner = harness.owner.as_mut().unwrap();
            let agent = HostAgentId(owner.pins.agent.0);
            let before = owner.ordered_index_for_test().unwrap();
            for attempt in 0..16 {
                assert!(owner._network_host.mark_stale_for_test(agent));
                owner
                    ._network_host
                    .refresh()
                    .unwrap_or_else(|error| panic!("promotion {attempt}: {error:?}"));
                assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            }
            harness.stop();
        }

        #[test]
        fn native_shared_system_owner_survives_route_retirement_and_fails_closed_on_poison() {
            let mut harness = NativeProjectionOwnerHarness::new("shared-system-owner");
            let owner = Arc::new(Mutex::new(harness.owner.take().unwrap()));
            let expected = owner.lock().unwrap().authority_target();
            let attachment =
                crate::agent::supervisor_adapters::system_agent_supervisor_attachment_shared(
                    owner.clone(),
                    4,
                )
                .unwrap();
            assert_eq!(attachment.handle().authority_target().unwrap(), expected);
            let guard = owner.lock().unwrap();
            let handle = attachment.handle();
            let (sent, received) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || sent.send(handle.authority_target()).unwrap());
            assert!(matches!(
                received.recv_timeout(std::time::Duration::from_millis(20)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            drop(guard);
            assert_eq!(
                received
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap()
                    .unwrap(),
                expected
            );
            thread.join().unwrap();
            attachment.retire().unwrap();
            assert_eq!(owner.lock().unwrap().authority_target(), expected);
            let attachment =
                crate::agent::supervisor_adapters::system_agent_supervisor_attachment_shared(
                    owner.clone(),
                    4,
                )
                .unwrap();
            let poisoned = owner.clone();
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = poisoned.lock().unwrap();
                    panic!("injected system lifecycle failure");
                }))
                .is_err()
            );
            assert_eq!(
                attachment.handle().authority_target(),
                Err(crate::agent::supervisor::AgentRouteError::Unavailable)
            );
            attachment.retire().unwrap();
            drop(poisoned);
            drop(owner);
            harness.stop();
        }

        fn native_local_management_lifecycle(coordinated: u8) {
            use crate::agent::clean_management_intent::CleanManagementIntent;
            fn configuration(descriptor: &AgentDescriptor) -> Vec<u8> {
                use system_authority::{
                    AuthorityBindingState, AuthorityBlobRow, AuthorityIssuerState,
                    ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER, SystemAuthorityConfiguration,
                };
                let (key, _, public, _) = node_material();
                let principal = PrincipalId::of_public_key(&public);
                let mut enrollment = crate::agent_sdk::private::NodeEncryptionEnrollment::from_keys(
                    descriptor.identity.space,
                    descriptor.identity.owner,
                    public,
                    [0x41; 32],
                    [1; 64],
                );
                enrollment.transport_signature = key.sign(&enrollment.signing_bytes()).to_bytes();
                let authority = descriptor.authority;
                let config = SystemAuthorityConfiguration {
                    space: descriptor.identity.space.0,
                    system_agent: descriptor.identity.agent.0,
                    system_runtime_deployment: descriptor.identity.runtime_deployment.0,
                    system_runtime_program: descriptor.identity.runtime_program.0,
                    system_runtime_producer: descriptor.identity.runtime_producer.0,
                    system_transition_producer: descriptor.identity.transition_producer.0,
                    system_runtime_package: AuthorityBlobRow {
                        hash: descriptor.runtime_package.hash.0,
                        len: descriptor.runtime_package.len,
                    },
                    binding: AuthorityBindingState {
                        policy: authority.policy.0,
                        issuer: AuthorityIssuerState {
                            principal: authority.issuer.principal.0,
                            actor: authority.issuer.actor.0,
                            deployment: authority.issuer.deployment.0,
                            program: authority.issuer.program.0,
                            producer: authority.issuer.producer.0,
                        },
                        public_key: authority.public_key,
                        initial_epoch: authority.initial_epoch,
                    },
                    bootstrap_authorization_high_water: ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER,
                    bootstrap_system_agent_creation_nonce: descriptor.creation_nonce.0,
                    bootstrap_principal: descriptor.identity.owner.0,
                    bootstrap_replica_principal: principal.0,
                    bootstrap_credential_public_key: SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
                        .verifying_key()
                        .to_bytes(),
                    bootstrap_credential_kind: 0,
                    bootstrap_node: enrollment.node.0,
                    bootstrap_node_transport_public_key: enrollment.transport_public_key,
                    bootstrap_node_transport_peer_id: enrollment.transport_peer_id,
                    bootstrap_node_encryption_public_key: enrollment.encryption_public_key,
                    bootstrap_node_transport_signature: enrollment.transport_signature,
                };
                assert!(config.is_valid());
                config.encode()
            }
            // Re-sign the bundled artifact with this fixture's pinned issuer;
            // the executable PVM, schema and policies are unchanged.
            let mut package =
                PackageEnvelope::decode(include_bytes!("../../../vosx/blobs/system_authority.vos"))
                    .unwrap();
            let key = SigningKey::from_bytes(&[RECEIPT_SEED; 32]);
            let public = key.verifying_key().to_bytes();
            *package.manifest.signing_mut() = PackageSigning {
                producer: ProducerId::of_public_key(&public),
                public_key: public,
                signature: [0; 64],
            };
            package.manifest.signing_mut().signature =
                key.sign(&package.signing_bytes().unwrap()).to_bytes();
            let package = admit_actor_package(&package.encode().unwrap()).unwrap();
            let fixture =
                native_physical_fixture_with_authority_configuration(package, Some(configuration));
            let mut harness =
                NativeProjectionOwnerHarness::with_fixture("bundled-authority-management", fixture);
            let owner = harness.owner.as_mut().unwrap();
            let mut descriptor = owner.pins.descriptor.clone();
            // The ordinary Local host executes the real bundled runtime PVM,
            // not the outer system fixture's native Standard test shortcut.
            let mut runtime = PackageEnvelope::decode(shape_only_runtime().exact_bytes()).unwrap();
            let program = include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec();
            let program_ref = BlobRef::of_bytes(&program);
            let crate::agent_sdk::package::PackageManifest::AgentRuntime(manifest) =
                &mut runtime.manifest
            else {
                unreachable!()
            };
            manifest.outer_program = program_ref.clone();
            runtime.artifacts = vec![PackageArtifact {
                identity: program_ref,
                bytes: program,
            }];
            runtime.manifest.signing_mut().signature = SigningKey::from_bytes(&[0x63; 32])
                .sign(&runtime.signing_bytes().unwrap())
                .to_bytes();
            let runtime = admit_runtime_package(&runtime.encode().unwrap()).unwrap();
            descriptor.identity.runtime_deployment = runtime.deployment();
            descriptor.identity.runtime_program = runtime.program();
            descriptor.identity.runtime_producer = runtime.producer();
            descriptor.runtime_package = runtime.package_ref().clone();
            descriptor.runtime_contract = runtime.manifest().contract;
            descriptor.capabilities = runtime.capabilities();
            descriptor.creation_nonce = Hash([0xdc; 32]);
            descriptor.identity.agent = AgentId::derive(
                descriptor.identity.space,
                descriptor.identity.owner,
                descriptor.creation_nonce.as_bytes(),
            );
            descriptor.identity.profile = AgentProfile::Local;
            // Ordinary replica rosters name the enrolled node owner. The
            // bootstrap system roster separately pins its transport principal.
            descriptor.replicas[0].principal = descriptor.identity.owner;
            descriptor.validate().unwrap();
            let request = ManagementRequest::Create(Box::new(descriptor.clone()));
            let credential_key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
            let (mut call, _) =
                credential_call_and_approval(&descriptor, &request, &credential_key);
            call.authority = owner.authority_target();
            call.invocation = call.expected_invocation();
            call.signature = credential_key.sign(&call.signing_bytes()).to_bytes();
            if coordinated == 5 {
                check_local_create_submission(&descriptor, &call, &runtime);
                harness.stop();
                return;
            }
            if coordinated == 4 {
                use crate::agent::local_lifecycle::{
                    LOCAL_LIFECYCLE_QUEUE_CAPACITY, LocalLifecycleIngressError, LocalLifecycleQueue,
                };
                let queue = LocalLifecycleQueue::default();
                assert!(matches!(
                    queue.submit(descriptor.clone(), call.clone(), runtime.clone()),
                    Err(LocalLifecycleIngressError::Unavailable)
                ));
                queue.open().unwrap();
                let mut replies = Vec::new();
                for _ in 0..LOCAL_LIFECYCLE_QUEUE_CAPACITY {
                    replies.push(
                        queue
                            .submit(descriptor.clone(), call.clone(), runtime.clone())
                            .unwrap(),
                    );
                }
                assert!(matches!(
                    queue.submit(descriptor.clone(), call.clone(), runtime.clone()),
                    Err(LocalLifecycleIngressError::Busy)
                ));
                let pending = queue.pop().unwrap().unwrap();
                assert_eq!(pending.descriptor, descriptor);
                assert_eq!(pending.call, call);
                pending
                    .reply
                    .try_send(Err(
                        crate::agent::production_owner::AgentProductionOwnerError::Authentication,
                    ))
                    .unwrap();
                assert_eq!(
                    replies.remove(0).recv().unwrap(),
                    Err(crate::agent::production_owner::AgentProductionOwnerError::Authentication)
                );
                replies.push(
                    queue
                        .submit(descriptor.clone(), call.clone(), runtime.clone())
                        .unwrap(),
                );
                queue.close();
                for reply in replies {
                    assert_eq!(reply.recv().unwrap(), Err(crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration));
                }
                assert!(queue.pop().unwrap().is_none());
                assert!(matches!(
                    queue.submit(descriptor, call, runtime),
                    Err(LocalLifecycleIngressError::Unavailable)
                ));
                harness.stop();
                return;
            }
            if coordinated >= 2 {
                struct Stores {
                    scope: (SpaceId, AgentId),
                    intent: IssuerMemoryStore,
                    issuer: IssuerMemoryStore,
                    opens: Arc<AtomicUsize>,
                }
                impl crate::agent::local_lifecycle::LocalLifecycleStoreFactory for Stores {
                    type Intent = IssuerMemoryStore;
                    type Issuer = IssuerMemoryStore;
                    type Error = ();
                    fn discover(
                        &mut self,
                        space: SpaceId,
                        maximum: usize,
                    ) -> Result<Vec<AgentId>, ()> {
                        if space != self.scope.0 || maximum == 0 {
                            return Err(());
                        }
                        Ok(vec![self.scope.1])
                    }
                    fn open(
                        &mut self,
                        space: SpaceId,
                        agent: AgentId,
                    ) -> Result<(Self::Intent, Self::Issuer), ()> {
                        assert_eq!((space, agent), self.scope);
                        self.opens.fetch_add(1, Ordering::SeqCst);
                        Ok((self.intent.clone(), self.issuer.clone()))
                    }
                    fn open_existing(
                        &mut self,
                        space: SpaceId,
                        agent: AgentId,
                    ) -> Result<(Self::Intent, Self::Issuer), ()> {
                        self.open(space, agent)
                    }
                }
                let root = harness._directory.0.join("controller-local");
                let local = crate::agent::local_sdk_host::LocalAgentHost::create(
                    &root,
                    descriptor.identity.space,
                    owner.pins.node,
                    harness.fixture.trust.clone(),
                )
                .unwrap();
                let issuer_store = IssuerMemoryStore::default();
                let opens = Arc::new(AtomicUsize::new(0));
                let stores = Stores {
                    scope: (descriptor.identity.space, descriptor.identity.agent),
                    intent: IssuerMemoryStore::default(),
                    issuer: issuer_store.clone(),
                    opens: opens.clone(),
                };
                let mut controller = crate::agent::local_lifecycle::LocalLifecycleController::new(
                    harness.owner.take().unwrap(),
                    local,
                    stores,
                    CountingSigner::new(),
                )
                .unwrap();
                if coordinated == 3 {
                    let authentications = Arc::new(AtomicUsize::new(0));
                    let mut node = crate::node::VosNode::new();
                    node.shutdown();
                    assert_eq!(node.start_clean_local_agent_production(
                        harness.fixture.plan.pins.node,
                        controller,
                        Box::new(NeverProjectionAuthenticator(authentications.clone())),
                        crate::agent::supervisor::AgentSupervisorLimits::default(),
                        4,
                        std::time::Duration::from_secs(60),
                    ), Err(crate::agent::production_owner::AgentProductionOwnerError::DuplicateHost));
                    assert_eq!(authentications.load(Ordering::SeqCst), 0);
                    assert_eq!(opens.load(Ordering::SeqCst), 0);
                    assert!(node.clean_agent_supervisor().is_none());
                    node.collect_checked().unwrap();
                    let local = crate::agent::local_sdk_host::LocalAgentHost::open(
                        &root,
                        descriptor.identity.space,
                        harness.fixture.plan.pins.node,
                        harness.fixture.trust.clone(),
                    )
                    .unwrap();
                    assert!(local.list().unwrap().is_empty());
                    drop(local);
                    harness.stop();
                    return;
                }
                let system = controller.system_attachment(4).unwrap();
                let routes = controller.local_attachment(4).unwrap();
                let mut forged = call.clone();
                forged.signature[0] ^= 1;
                assert!(matches!(
                    controller.create(descriptor.clone(), forged, runtime.clone()),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
                assert_eq!(opens.load(Ordering::SeqCst), 0);
                let result = controller
                    .create(descriptor.clone(), call.clone(), runtime.clone())
                    .unwrap();
                assert_eq!(result.0, descriptor.identity.agent);
                let issuer = DurableCleanManagementIssuer::open(
                    issuer_store,
                    descriptor.authority,
                    descriptor.identity.space,
                    descriptor.identity.agent,
                )
                .unwrap();
                assert!(issuer.application_finalization_status(&result.1).unwrap());
                drop(issuer);
                routes.retire().unwrap();
                let routes = controller.local_attachment(4).unwrap();
                harness
                    .fixture
                    .logical_slot
                    .as_ref()
                    .unwrap()
                    .store(LOGICAL_SLOT + 20, Ordering::Release);
                assert_eq!(
                    controller.create(descriptor, call, runtime).unwrap(),
                    result
                );
                assert_eq!(opens.load(Ordering::SeqCst), 2);
                routes.retire().unwrap();
                system.retire().unwrap();
                drop(controller);
                harness.stop();
                return;
            }
            if coordinated == 1 {
                let shared_owner = Arc::new(Mutex::new(harness.owner.take().unwrap()));
                let attachment =
                    crate::agent::supervisor_adapters::system_agent_supervisor_attachment_shared(
                        shared_owner.clone(),
                        4,
                    )
                    .unwrap();
                let mut owner = shared_owner.lock().unwrap();
                let store = IssuerMemoryStore::default();
                let issuer_store = IssuerMemoryStore::default();
                let root = harness._directory.0.join("coordinated-local");
                let mut local = crate::agent::local_sdk_host::LocalAgentHost::create(
                    &root,
                    descriptor.identity.space,
                    owner.pins.node,
                    harness.fixture.trust.clone(),
                )
                .unwrap();
                let mut signer = CountingSigner::new();
                let before = owner.ordered_index_for_test().unwrap();
                let mut forged = call.clone();
                forged.signature[0] ^= 1;
                assert!(matches!(
                    owner.create_local_agent(
                        store.clone(),
                        issuer_store.clone(),
                        descriptor.clone(),
                        forged,
                        &mut local,
                        runtime.clone(),
                        &mut signer,
                    ),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
                assert!(store.image.lock().unwrap().is_none());
                assert!(issuer_store.image.lock().unwrap().is_none());
                assert_eq!(owner.ordered_index_for_test().unwrap(), before);
                assert_eq!(signer.calls, 0);
                let result = owner
                    .create_local_agent(
                        store.clone(),
                        issuer_store.clone(),
                        descriptor.clone(),
                        call.clone(),
                        &mut local,
                        runtime.clone(),
                        &mut signer,
                    )
                    .unwrap();
                assert_eq!(result.0, descriptor.identity.agent);
                let issuer = DurableCleanManagementIssuer::open(
                    issuer_store.clone(),
                    descriptor.authority,
                    descriptor.identity.space,
                    descriptor.identity.agent,
                )
                .unwrap();
                assert!(issuer.application_finalization_status(&result.1).unwrap());
                drop(issuer);
                assert_eq!(signer.calls, 2);
                let finalized = owner.ordered_index_for_test().unwrap();
                assert!(finalized > before);
                let mut missing_local = crate::agent::local_sdk_host::LocalAgentHost::create(
                    &harness._directory.0.join("missing-finalized-local"),
                    descriptor.identity.space,
                    owner.pins.node,
                    harness.fixture.trust.clone(),
                )
                .unwrap();
                let saved_intent = store.image.lock().unwrap().clone();
                let saved_issuer = issuer_store.image.lock().unwrap().clone();
                assert!(matches!(
                    owner.create_local_agent(
                        store.clone(),
                        issuer_store.clone(),
                        descriptor.clone(),
                        call.clone(),
                        &mut missing_local,
                        runtime.clone(),
                        &mut signer,
                    ),
                    Err(SharedAgentHostError::Unavailable)
                ));
                assert!(missing_local.show(descriptor.identity.agent).is_err());
                assert_eq!(*store.image.lock().unwrap(), saved_intent);
                assert_eq!(*issuer_store.image.lock().unwrap(), saved_issuer);
                assert_eq!(owner.ordered_index_for_test().unwrap(), finalized);
                assert_eq!(signer.calls, 2);
                drop(missing_local);
                drop(local);
                harness
                    .fixture
                    .logical_slot
                    .as_ref()
                    .unwrap()
                    .store(LOGICAL_SLOT + 20, Ordering::Release);
                let mut local = crate::agent::local_sdk_host::LocalAgentHost::open(
                    &root,
                    descriptor.identity.space,
                    owner.pins.node,
                    harness.fixture.trust.clone(),
                )
                .unwrap();
                assert_eq!(
                    owner
                        .create_local_agent(
                            store,
                            issuer_store,
                            descriptor,
                            call,
                            &mut local,
                            runtime,
                            &mut signer,
                        )
                        .unwrap(),
                    result
                );
                assert_eq!(signer.calls, 2);
                assert_eq!(owner.ordered_index_for_test().unwrap(), finalized);
                drop(local);
                drop(owner);
                attachment.retire().unwrap();
                drop(shared_owner);
                harness.stop();
                return;
            }
            let intent = CleanManagementIntent::new(
                owner.authority_target(),
                call.managed,
                request.clone(),
                call.clone(),
                &RawCredentialVerifier,
            )
            .unwrap();
            if coordinated == 6 {
                check_management_clock_advance(
                    owner,
                    intent,
                    &descriptor,
                    harness.fixture.logical_slot.as_ref().unwrap().clone(),
                );
                harness.stop();
                return;
            }
            let finalization_clock =
                (coordinated == 7).then(|| harness.fixture.logical_slot.as_ref().unwrap().clone());
            check_local_management_phases(
                harness,
                descriptor,
                call,
                request,
                runtime,
                intent,
                finalization_clock,
            );
        }

        #[inline(never)]
        fn check_management_retirement_reattachment(
            owner: &mut MemoryBootstrapOwner,
            envelopes: [&RuntimeWork; 2],
            recreate: bool,
            network: Arc<Network>,
        ) {
            let agent = HostAgentId(owner.pins.agent.0);
            let before = owner.ordered_index_for_test().unwrap();
            let (old, _) = owner
                .network_host_for_test()
                .attachment_for_test(agent)
                .unwrap();
            if recreate {
                owner
                    ._network_host
                    .retire_attachment_for_test(agent)
                    .unwrap();
                // Supply the exact envelopes retained in the durable intent,
                // not a freshly prepared invocation or current-clock preflight.
                owner._network_host = crate::network::shared_agent::SharedAgentNetworkHost::attach_recovering_management_retirement(
                    Arc::clone(&owner.host), network, agent,
                    [envelopes[0].clone(), envelopes[1].clone()],
                ).unwrap();
            } else {
                assert!(owner._network_host.mark_stale_for_test(agent));
                owner._network_host.refresh().unwrap();
            }
            let (new, _) = owner
                .network_host_for_test()
                .attachment_for_test(agent)
                .unwrap();
            assert!(!Arc::ptr_eq(&old, &new));
            let (query, authorization) = fresh_projection_pair(owner, 0xeb);
            assert!(matches!(
                owner
                    ._network_host
                    .reserve_projection_pair(agent, &query, &authorization, false),
                Err(SharedAgentHostError::Conflict)
            ));
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        }

        #[inline(never)]
        fn check_management_retirement_gate(
            owner: &mut MemoryBootstrapOwner,
            envelopes: [&RuntimeWork; 2],
            completed: bool,
        ) {
            let agent = HostAgentId(owner.pins.agent.0);
            let (query, query_auth) = fresh_projection_pair(owner, 0xe9);
            if !completed {
                owner
                    ._network_host
                    .reserve_projection_pair(agent, &query, &query_auth, false)
                    .unwrap();
                assert!(matches!(
                    owner
                        ._network_host
                        .reserve_management_retirement(agent, envelopes),
                    Err(SharedAgentHostError::Conflict)
                ));
                owner
                    ._network_host
                    .release_projection_pair(agent, &query, &query_auth)
                    .unwrap();
            }
            owner
                ._network_host
                .reserve_management_retirement(agent, envelopes)
                .unwrap();
            owner
                ._network_host
                .reserve_management_retirement(agent, envelopes)
                .unwrap();
            assert!(matches!(
                owner
                    ._network_host
                    .reserve_management_retirement(agent, [envelopes[1], envelopes[0]],),
                Err(SharedAgentHostError::Conflict)
            ));
            assert!(matches!(
                owner
                    ._network_host
                    .reserve_projection_pair(agent, &query, &query_auth, false,),
                Err(SharedAgentHostError::Conflict)
            ));
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = envelopes[0]
            else {
                unreachable!()
            };
            let material = owner
                .supervisor_invocation_material(owner.pins.agent, invocation.actor)
                .unwrap();
            let identity =
                crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
            assert!(matches!(
                owner
                    ._network_host
                    .supervisor_acknowledge_management_retirement(identity, query, query_auth,),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            let mut unrelated = (**invocation).clone();
            unrelated.invocation = crate::agent_sdk::InvocationId([0xef; 32]);
            let unrelated_authorization =
                crate::agent_sdk::InvocationAuthorization::PublicPreflight(
                    crate::agent_sdk::PublicPreflight::for_work(&unrelated, *observed_slot),
                );
            assert!(matches!(
                owner
                    ._network_host
                    .supervisor_acknowledge_management_retirement(
                        identity,
                        unrelated,
                        unrelated_authorization,
                    ),
                Err(SharedAgentHostError::CapacityExhausted)
            ));
            assert!(matches!(
                owner.supervisor_acknowledge(
                    identity,
                    (**invocation).clone(),
                    (**authorization).clone(),
                ),
                Err(SharedAgentHostError::CapacityExhausted)
            ));
            let calls = Cell::new(0);
            let result =
                owner
                    ._network_host
                    .complete_management_retirement(agent, envelopes, || {
                        calls.set(calls.get() + 1);
                        Err(SharedAgentHostError::Unavailable)
                    });
            assert_eq!(calls.get(), usize::from(completed));
            assert!(matches!(result, Err(SharedAgentHostError::Unavailable)) == completed);
            if !completed {
                assert!(matches!(result, Err(SharedAgentHostError::Conflict)));
            }
            // A failed durable handoff must not release even a fully retired pair.
            assert!(matches!(
                owner.supervisor_acknowledge(
                    identity,
                    (**invocation).clone(),
                    (**authorization).clone(),
                ),
                Err(SharedAgentHostError::CapacityExhausted)
            ));
        }

        #[inline(never)]
        fn check_lifecycle_recovery_scan(
            authority: AuthorityActorTarget,
            intent: IssuerMemoryStore,
            issuer: IssuerMemoryStore,
            retired: bool,
            finalized: bool,
        ) {
            use crate::agent::local_lifecycle::{
                LocalLifecycleStoreFactory, discover_local_lifecycle_recovery,
            };
            struct Stores {
                agents: Vec<AgentId>,
                intent: IssuerMemoryStore,
                issuer: IssuerMemoryStore,
                opens: usize,
            }
            impl LocalLifecycleStoreFactory for Stores {
                type Intent = IssuerMemoryStore;
                type Issuer = IssuerMemoryStore;
                type Error = ();
                fn discover(&mut self, _: SpaceId, _: usize) -> Result<Vec<AgentId>, ()> {
                    Ok(self.agents.clone())
                }
                fn open(
                    &mut self,
                    _: SpaceId,
                    _: AgentId,
                ) -> Result<(Self::Intent, Self::Issuer), ()> {
                    panic!("recovery must never create stores")
                }
                fn open_existing(
                    &mut self,
                    _: SpaceId,
                    _: AgentId,
                ) -> Result<(Self::Intent, Self::Issuer), ()> {
                    self.opens += 1;
                    Ok((self.intent.clone(), self.issuer.clone()))
                }
            }
            let expected = crate::agent::clean_management_intent::CleanManagementIntentSlot::open(
                intent.clone(),
            )
            .unwrap();
            let agent = expected.intent().unwrap().call().managed.agent;
            let intent_before = intent.image.lock().unwrap().clone();
            let issuer_before = issuer.image.lock().unwrap().clone();
            let mut stores = Stores {
                agents: vec![agent],
                intent: intent.clone(),
                issuer: issuer.clone(),
                opens: 0,
            };
            let recovery = discover_local_lifecycle_recovery(&mut stores, authority, 1).unwrap();
            assert_eq!(recovery.len(), 1);
            assert!(!recovery.is_empty());
            let entry = &recovery.entries[0];
            assert_eq!(entry.agent, agent);
            assert_eq!(entry.intent.intent(), expected.intent());
            assert_eq!(entry.intent.retirement_complete().unwrap(), retired);
            assert_eq!(entry.finalized.is_some(), finalized);
            assert!(entry.issuer.sequence_high_water() > 0);
            drop(recovery);
            assert_eq!(stores.opens, 1);
            stores.agents = vec![agent, agent];
            assert!(matches!(
                discover_local_lifecycle_recovery(&mut stores, authority, 2),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert!(matches!(
                discover_local_lifecycle_recovery(&mut stores, authority, 1),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(stores.opens, 1);
            stores.agents = vec![AgentId::ZERO];
            assert!(matches!(
                discover_local_lifecycle_recovery(&mut stores, authority, 1),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(stores.opens, 1);
            stores.agents = vec![AgentId([0xee; 32])];
            assert!(matches!(
                discover_local_lifecycle_recovery(&mut stores, authority, 1),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            stores.agents = vec![agent];
            let mut wrong = authority;
            wrong.system_agent = AgentId([0xee; 32]);
            assert!(matches!(
                discover_local_lifecycle_recovery(&mut stores, wrong, 1),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            if finalized {
                stores.issuer = IssuerMemoryStore::default();
                assert!(matches!(
                    discover_local_lifecycle_recovery(&mut stores, authority, 1),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
                stores.issuer = issuer.clone();
            }
            stores.intent = IssuerMemoryStore::default();
            assert!(matches!(
                discover_local_lifecycle_recovery(&mut stores, authority, 1),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            stores.issuer = IssuerMemoryStore::default();
            let empty = discover_local_lifecycle_recovery(&mut stores, authority, 1).unwrap();
            assert!(empty.entries[0].intent.intent().is_none());
            assert!(empty.entries[0].finalized.is_none());
            stores.agents.clear();
            assert!(
                discover_local_lifecycle_recovery(&mut stores, authority, 0)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(*intent.image.lock().unwrap(), intent_before);
            assert_eq!(*issuer.image.lock().unwrap(), issuer_before);
        }

        #[inline(never)]
        fn check_durable_management_retirement(
            owner: &mut MemoryBootstrapOwner,
            store: IssuerMemoryStore,
            managed: ManagedAgentTarget,
            acknowledgement: &ManagementApplicationAck,
            issuer: &DurableCleanManagementIssuer<IssuerMemoryStore>,
            issuer_store: IssuerMemoryStore,
            failures: bool,
        ) {
            use crate::agent::clean_management_intent::{
                CleanManagementIntentSlot, IntentSlotError,
            };
            struct FailingStore {
                inner: IssuerMemoryStore,
                after: bool,
                magic: &'static [u8; 4],
            }
            impl CleanManagementIssuerStore for FailingStore {
                type Error = MemoryError;
                fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                    self.inner.load()
                }
                fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                    assert!(image.starts_with(self.magic));
                    if self.after {
                        self.inner.commit(image)?;
                    }
                    Err(MemoryError)
                }
            }
            let before = owner.ordered_index_for_test().unwrap();
            let original = store.image.lock().unwrap().clone();
            if failures {
                for after in [false, true] {
                    let mut slot = CleanManagementIntentSlot::open(FailingStore {
                        inner: store.clone(),
                        after,
                        magic: b"CMR2",
                    })
                    .unwrap();
                    assert!(matches!(
                        owner.finish_management_intent_retirement(
                            &mut slot,
                            managed,
                            acknowledgement,
                            issuer,
                        ),
                        Err(SharedAgentHostError::Unavailable)
                    ));
                    assert_eq!(slot.retirement_complete(), Err(IntentSlotError::Poisoned));
                    assert_eq!(owner.ordered_index_for_test().unwrap(), before);
                    if !after {
                        assert_eq!(*store.image.lock().unwrap(), original);
                    }
                }
            }
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            assert_eq!(slot.retirement_complete().unwrap(), failures);
            assert_eq!(
                owner
                    .finish_management_intent_retirement(
                        &mut slot,
                        managed,
                        acknowledgement,
                        issuer,
                    )
                    .unwrap(),
                !failures
            );
            assert!(slot.retirement_complete().unwrap());
            let retired = store.image.lock().unwrap().clone().unwrap();
            assert!(retired.starts_with(b"CMR2"));
            assert_eq!(retired.len(), original.as_ref().unwrap().len());
            assert_eq!(&retired[4..], &original.as_ref().unwrap()[4..]);
            drop(slot);
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            assert!(
                !owner
                    .finish_management_intent_retirement(
                        &mut slot,
                        managed,
                        acknowledgement,
                        issuer,
                    )
                    .unwrap()
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            assert_eq!(store.image.lock().unwrap().as_ref(), Some(&retired));
            assert_projection_gate_released(owner, 0xea);
            check_lifecycle_recovery_scan(
                owner.authority_target(),
                store.clone(),
                issuer_store.clone(),
                true,
                true,
            );
            let agent = HostAgentId(owner.pins.agent.0);
            assert!(owner._network_host.mark_stale_for_test(agent));
            owner._network_host.refresh().unwrap();
            // Completion must remove the retained recovery envelope as well
            // as the current route's gate; it must not reappear on refresh.
            assert_projection_gate_released(owner, 0xec);
            let expected = slot.intent().unwrap().clone();
            let mut next_call = expected.call().clone();
            next_call.request_sequence =
                core::num::NonZeroU64::new(next_call.request_sequence.get() + 1).unwrap();
            next_call.invocation = next_call.expected_invocation();
            next_call.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
                .sign(&next_call.signing_bytes())
                .to_bytes();
            let next = crate::agent::clean_management_intent::CleanManagementIntent::new(
                next_call.authority,
                next_call.managed,
                expected.request().clone(),
                next_call,
                &RawCredentialVerifier,
            )
            .unwrap();
            assert!(matches!(
                slot.pledge(next.clone()),
                Err(IntentSlotError::Conflict)
            ));
            let active_store = IssuerMemoryStore {
                image: Arc::new(Mutex::new(original.clone())),
                ..Default::default()
            };
            let mut active = CleanManagementIntentSlot::open(active_store.clone()).unwrap();
            assert!(matches!(
                active.handoff_retired(&expected, next.clone(), &RawCredentialVerifier),
                Err(IntentSlotError::Conflict)
            ));
            assert_eq!(*active_store.image.lock().unwrap(), original);
            drop(slot);
            if failures {
                for after in [false, true] {
                    let mut slot = CleanManagementIntentSlot::open(FailingStore {
                        inner: store.clone(),
                        after,
                        magic: b"CMI4",
                    })
                    .unwrap();
                    assert!(matches!(
                        slot.handoff_retired(&expected, next.clone(), &RawCredentialVerifier),
                        Err(IntentSlotError::Storage(_))
                    ));
                    assert_eq!(slot.retirement_complete(), Err(IntentSlotError::Poisoned));
                    if !after {
                        assert_eq!(store.image.lock().unwrap().as_ref(), Some(&retired));
                    }
                }
            }
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            assert_eq!(
                slot.handoff_retired(&expected, next.clone(), &RawCredentialVerifier)
                    .unwrap(),
                !failures
            );
            assert!(!slot.retirement_complete().unwrap());
            assert_eq!(slot.intent(), Some(&next));
            drop(slot);
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            assert!(
                !slot
                    .handoff_retired(&expected, next.clone(), &RawCredentialVerifier)
                    .unwrap()
            );
            assert_eq!(slot.intent(), Some(&next));
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            assert!(
                store
                    .image
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .starts_with(b"CMI4")
            );
            check_lifecycle_recovery_scan(
                owner.authority_target(),
                store,
                issuer_store,
                false,
                false,
            );
        }

        #[inline(never)]
        fn check_management_retirement_admission(
            owner: &MemoryBootstrapOwner,
            authorization: &RuntimeWork,
            finalization: &RuntimeWork,
        ) {
            use crate::agent_sdk::{InvocationAuthorization, MethodMode, PublicPreflight};
            let host = owner.host.lock().unwrap();
            let agent = HostAgentId(owner.pins.agent.0);
            for (set, expected) in [
                (vec![], 0),
                (vec![authorization], 1),
                (vec![finalization], 1),
                (vec![authorization, finalization], 2),
                (vec![finalization, authorization], 2),
            ] {
                assert_eq!(
                    host.management_retirement_set_admission_requirement(agent, &set)
                        .unwrap(),
                    Some(expected)
                );
            }
            // Reject duplicate identities across pair boundaries as well as
            // within one pair; never double-budget or silently deduplicate.
            assert!(
                host.management_retirement_set_admission_requirement(
                    agent,
                    &[authorization, finalization, authorization],
                )
                .is_err()
            );
            assert!(
                host.management_retirement_set_admission_requirement(
                    agent,
                    &vec![authorization; crate::agent::replay::MAX_REPLAY_SUFFIX_ENTRIES + 1],
                )
                .is_err()
            );
            assert_eq!(
                host.management_retirement_admission_requirement(
                    agent,
                    [authorization, finalization],
                )
                .unwrap(),
                Some(2)
            );
            assert!(
                host.management_retirement_admission_requirement(
                    agent,
                    [authorization, authorization],
                )
                .is_err()
            );
            let mut substituted = finalization.clone();
            let RuntimeWork::Invoke {
                invocation,
                authorization: preflight,
                observed_slot,
                ..
            } = &mut substituted
            else {
                unreachable!()
            };
            invocation.mode = MethodMode::Query;
            **preflight = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
                invocation,
                *observed_slot,
            ));
            assert!(
                host.management_retirement_admission_requirement(
                    agent,
                    [authorization, &substituted],
                )
                .is_err()
            );
            let RuntimeWork::Invoke {
                invocation,
                authorization: preflight,
                observed_slot,
                ..
            } = &mut substituted
            else {
                unreachable!()
            };
            invocation.mode = MethodMode::Linear;
            *observed_slot += 1;
            **preflight = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
                invocation,
                *observed_slot,
            ));
            // A valid fresh preflight is not evidence of this exact invocation
            // having completed in the authenticated journal.
            assert!(
                host.management_retirement_admission_requirement(
                    agent,
                    [authorization, &substituted],
                )
                .is_err()
            );
        }

        #[inline(never)]
        fn check_multiple_management_retirement_admission(
            owner: &mut MemoryBootstrapOwner,
            original: [&RuntimeWork; 2],
            intent: &crate::agent::clean_management_intent::CleanManagementIntent,
            network: Arc<Network>,
        ) {
            // Both original results have already been positively acknowledged.
            // Execute four fresh signed calls through the bundled Authority so
            // the joint check covers four distinct, unretired journal results.
            // This tests suffix accounting, not fresh credential authorization.
            let agent = HostAgentId(owner.pins.agent.0);
            let first_anchor = owner.host.lock().unwrap().journal_position(agent).unwrap();
            let mut extra = Vec::new();
            for index in 0..4 {
                extra.push(execute_extra_management_call(
                    owner,
                    original[0],
                    intent,
                    index,
                ));
            }
            let host = owner.host.lock().unwrap();
            let agent = HostAgentId(owner.pins.agent.0);
            // Unrelated later calls cannot hide an accepted earlier call.
            assert!(
                host.management_invocation_after(agent, &first_anchor, &extra[0])
                    .unwrap()
                    .is_some()
            );
            let set: Vec<_> = extra.iter().collect();
            let before = host
                .management_retirement_set_admission_requirement(agent, &set)
                .unwrap();
            assert_eq!(before, Some(4));
            let mut mixed = original.to_vec();
            mixed.extend(set);
            assert_eq!(
                host.management_retirement_set_admission_requirement(agent, &mixed)
                    .unwrap(),
                Some(4)
            );
            mixed.push(original[0]);
            assert!(
                host.management_retirement_set_admission_requirement(agent, &mixed)
                    .is_err()
            );
            drop(host);
            check_multiple_management_retirement_gate(owner, &extra, network);
            // A later acknowledgement is not evidence of non-acceptance.
            assert!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .management_invocation_after(agent, &first_anchor, &extra[0])
                    .is_err()
            );
            let anchor = owner.host.lock().unwrap().journal_position(agent).unwrap();
            let boundary = execute_extra_management_call(owner, original[0], intent, 4);
            check_linear_checkpoint_boundary_refuses_projection_fallback(owner, &boundary, &anchor);
        }

        #[inline(never)]
        fn execute_extra_management_call(
            owner: &MemoryBootstrapOwner,
            original: &RuntimeWork,
            intent: &crate::agent::clean_management_intent::CleanManagementIntent,
            index: u64,
        ) -> RuntimeWork {
            let mut call = intent.call().clone();
            call.request_sequence =
                core::num::NonZeroU64::new(call.request_sequence.get() + index + 1).unwrap();
            call.invocation = call.expected_invocation();
            call.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
                .sign(&call.signing_bytes())
                .to_bytes();
            let next = crate::agent::clean_management_intent::CleanManagementIntent::new(
                call.authority,
                call.managed,
                intent.request().clone(),
                call,
                &RawCredentialVerifier,
            )
            .unwrap();
            let mut envelope = original.clone();
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = &mut envelope
            else {
                unreachable!()
            };
            invocation.invocation = next.call().invocation;
            invocation.message = next.authorization_message();
            let material = owner
                .supervisor_invocation_material(owner.pins.agent, invocation.actor)
                .unwrap();
            // Fresh calls use current admission; persisted retries retain it.
            *observed_slot = material.observed_slot;
            **authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
            );
            let identity =
                crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
            let agent = HostAgentId(owner.pins.agent.0);
            let anchor = owner.host.lock().unwrap().journal_position(agent).unwrap();
            let prepared = RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: crate::agent_sdk::RuntimeState::default(),
                invocation: invocation.clone(),
                authorization: authorization.clone(),
                observed_slot: *observed_slot,
            };
            assert_eq!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .management_invocation_after(agent, &anchor, &prepared)
                    .unwrap(),
                None
            );
            let result = owner
                .supervisor_invoke_persisted_management(
                    identity,
                    (**invocation).clone(),
                    (**authorization).clone(),
                )
                .unwrap();
            assert!(
                matches!(result, RuntimeOutcome::Completed(Ok(_))),
                "{result:?}"
            );
            let host = owner.host.lock().unwrap();
            assert!(
                host.management_invocation_after(agent, &anchor, &prepared)
                    .unwrap()
                    .is_some()
            );
            let mut wrong = anchor.clone();
            wrong.ordered_head = Some(crate::agent::journal::OrderedEntryId([0xdd; 32]));
            assert!(
                host.management_invocation_after(agent, &wrong, &prepared)
                    .is_err()
            );
            wrong = anchor.clone();
            wrong.genesis = crate::agent::journal::AgentJournalGenesisId([0xdd; 32]);
            assert!(matches!(
                host.management_invocation_after(agent, &wrong, &prepared),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            let current = host.journal_position(agent).unwrap();
            wrong = current.clone();
            wrong.ordered_index += 1;
            assert!(
                host.management_invocation_after(agent, &wrong, &prepared)
                    .is_err()
            );
            // A late anchor cannot prove that this call never existed before it.
            assert_eq!(
                host.management_invocation_after(agent, &current, &prepared)
                    .unwrap(),
                None
            );
            let mut altered = prepared.clone();
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = &mut altered
            else {
                unreachable!()
            };
            *observed_slot += 1;
            **authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
            );
            assert!(
                host.management_invocation_after(agent, &anchor, &altered)
                    .is_err()
            );
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } = &mut altered
            else {
                unreachable!()
            };
            invocation.agent = crate::agent_sdk::AgentId([0xdc; 32]);
            **authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
            );
            assert!(
                host.management_invocation_after(agent, &current, &altered)
                    .is_err()
            );
            envelope
        }

        #[inline(never)]
        fn check_linear_checkpoint_boundary_refuses_projection_fallback(
            owner: &mut MemoryBootstrapOwner,
            envelope: &RuntimeWork,
            anchor: &crate::agent::shared_host::SharedAgentJournalPosition,
        ) {
            let RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = envelope
            else {
                unreachable!()
            };
            let agent = HostAgentId(owner.pins.agent.0);
            let before = owner.ordered_index_for_test().unwrap();
            let (query, query_auth) = fresh_projection_pair(owner, 0xef);
            let material = owner
                .supervisor_invocation_material(owner.pins.agent, invocation.actor)
                .unwrap();
            let identity =
                crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
            assert!(matches!(
                owner
                    .supervisor_invoke_persisted_management(
                        identity,
                        (**invocation).clone(),
                        (**authorization).clone(),
                    )
                    .unwrap(),
                RuntimeOutcome::Completed(Ok(_))
            ));
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            owner._network_host.force_checkpoint_once_for_test();
            assert!(
                owner
                    ._network_host
                    .certified_checkpoint_for_projection_pair(
                        agent,
                        &query,
                        &query_auth,
                        &owner.pins.replicas,
                        owner.snapshot_signer.as_ref(),
                    )
                    .unwrap()
            );
            assert!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .management_invocation_after(agent, anchor, envelope)
                    .is_err()
            );
            let material = owner
                .supervisor_invocation_material(owner.pins.agent, invocation.actor)
                .unwrap();
            let identity =
                crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
            let result = owner.supervisor_invoke_persisted_management(
                identity,
                (**invocation).clone(),
                (**authorization).clone(),
            );
            assert!(
                result.is_err(),
                "Linear checkpoint boundary used projection fallback: {result:?}"
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        }

        #[inline(never)]
        fn check_multiple_management_retirement_gate(
            owner: &mut MemoryBootstrapOwner,
            extra: &[RuntimeWork],
            network: Arc<Network>,
        ) {
            let agent = HostAgentId(owner.pins.agent.0);
            let pairs = [[&extra[0], &extra[1]], [&extra[2], &extra[3]]];
            let before = owner.ordered_index_for_test().unwrap();
            for invalid in [
                vec![],
                vec![pairs[0], pairs[0]],
                vec![pairs[0]; crate::agent::replay::MAX_REPLAY_SUFFIX_ENTRIES / 2 + 1],
            ] {
                assert!(matches!(
                    owner
                        ._network_host
                        .reserve_management_retirement_set(agent, &invalid),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
            }
            owner
                ._network_host
                .reserve_management_retirement_set(agent, &pairs)
                .unwrap();
            assert!(matches!(
                owner._network_host.record_management_anchor(
                    agent,
                    &extra[0],
                    |_| -> Result<(), SharedAgentHostError> {
                        panic!("retirement exclusion must reject anchor publication")
                    }
                ),
                Err(SharedAgentHostError::Conflict)
            ));
            // Reserving a member is idempotent and must not replace the set.
            owner
                ._network_host
                .reserve_management_retirement(agent, pairs[0])
                .unwrap();
            assert!(matches!(
                owner._network_host.reserve_management_retirement_set(
                    agent,
                    &[[&extra[0], &extra[2]], [&extra[1], &extra[3]]],
                ),
                Err(SharedAgentHostError::Conflict)
            ));
            owner
                ._network_host
                .retire_attachment_for_test(agent)
                .unwrap();
            owner._network_host = crate::network::shared_agent::SharedAgentNetworkHost::attach_recovering_management_retirement_set(
                Arc::clone(&owner.host), network, agent,
                vec![[extra[0].clone(), extra[1].clone()], [extra[2].clone(), extra[3].clone()]],
            ).unwrap();
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            let (query, query_auth) = fresh_projection_pair(owner, 0xed);
            for (pair_index, pair) in pairs.into_iter().enumerate() {
                assert!(matches!(
                    owner
                        ._network_host
                        .reserve_projection_pair(agent, &query, &query_auth, false),
                    Err(SharedAgentHostError::Conflict)
                ));
                assert!(matches!(
                    owner
                        ._network_host
                        .complete_management_retirement(agent, pair, || {
                            panic!("unacknowledged pair must not reach durable completion")
                        }),
                    Err(SharedAgentHostError::Conflict)
                ));
                for envelope in pair {
                    let RuntimeWork::Invoke {
                        invocation,
                        authorization,
                        ..
                    } = envelope
                    else {
                        unreachable!()
                    };
                    let material = owner
                        .supervisor_invocation_material(owner.pins.agent, invocation.actor)
                        .unwrap();
                    let identity =
                        crate::agent::supervisor_adapters::physical_material_identity(&material)
                            .unwrap();
                    assert!(matches!(
                        owner.supervisor_acknowledge(
                            identity,
                            (**invocation).clone(),
                            (**authorization).clone()
                        ),
                        Err(SharedAgentHostError::CapacityExhausted)
                    ));
                    assert!(matches!(
                        owner
                            ._network_host
                            .supervisor_acknowledge_management_retirement(
                                identity,
                                (**invocation).clone(),
                                (**authorization).clone(),
                            )
                            .unwrap(),
                        RuntimeOutcome::Acknowledged(Ok(_))
                    ));
                }
                assert!(matches!(
                    owner
                        ._network_host
                        .complete_management_retirement(agent, pair, || Err(
                            SharedAgentHostError::Unavailable
                        )),
                    Err(SharedAgentHostError::Unavailable)
                ));
                assert!(owner._network_host.mark_stale_for_test(agent));
                owner._network_host.refresh().unwrap();
                assert!(matches!(
                    owner
                        ._network_host
                        .reserve_projection_pair(agent, &query, &query_auth, false),
                    Err(SharedAgentHostError::Conflict)
                ));
                // This callback tests the network boundary only. Production
                // must commit its independently verified durable intent marker.
                owner
                    ._network_host
                    .complete_management_retirement(agent, pair, || Ok(()))
                    .unwrap();
                if pair_index == 0 {
                    // An old completion cannot clear a different pending pair.
                    assert!(matches!(
                        owner
                            ._network_host
                            .release_completed_management_retirement(agent, pair),
                        Err(SharedAgentHostError::Conflict)
                    ));
                }
                // Reattachment after the first completion must keep the
                // remaining pair, not resurrect the completed one or open a gap.
                assert!(owner._network_host.mark_stale_for_test(agent));
                owner._network_host.refresh().unwrap();
            }
            assert_eq!(owner.ordered_index_for_test().unwrap(), before + 4);
            assert_projection_gate_released(owner, 0xee);
            let host = Arc::clone(&owner.host);
            assert!(matches!(
                owner._network_host.record_management_anchor(
                    agent,
                    &extra[0],
                    |anchor| -> Result<(), SharedAgentHostError> {
                        assert!(
                            host.try_lock().is_err(),
                            "journal lock must span durable anchor publication"
                        );
                        assert_eq!(anchor.ordered.index, before + 4);
                        Err(SharedAgentHostError::Unavailable)
                    }
                ),
                Err(SharedAgentHostError::Unavailable)
            ));
            assert_projection_gate_released(owner, 0xf1);
        }

        #[inline(never)]
        fn check_local_management_phases(
            mut harness: NativeProjectionOwnerHarness,
            descriptor: AgentDescriptor,
            call: AuthorityCredentialCall,
            request: ManagementRequest,
            runtime: AdmittedRuntimePackage,
            intent: crate::agent::clean_management_intent::CleanManagementIntent,
            finalization_clock: Option<Arc<AtomicU64>>,
        ) {
            use crate::agent::clean_management_intent::CleanManagementIntentSlot;
            let owner = harness.owner.as_mut().unwrap();
            let interrupted_retirement = finalization_clock.is_some();
            let store = IssuerMemoryStore {
                // Intent, authorization, then finalization envelope.
                advance_clock_after_commits: finalization_clock.map(|clock| (clock, 3)),
                ..Default::default()
            };
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            slot.pledge(intent).unwrap();
            let issuer_store = IssuerMemoryStore::default();
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer_store.clone(),
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            let mut signer = CountingSigner::new();
            let before = owner.ordered_index_for_test().unwrap();
            let receipt = owner
                .issue_management_intent(&mut slot, call.managed, &mut issuer, &mut signer)
                .unwrap();
            assert_eq!(receipt.selector.request, request.commitment());
            assert_eq!(receipt.selector.agent, descriptor.identity.agent);
            assert_eq!(signer.calls, 1);
            let applied = owner.ordered_index_for_test().unwrap();
            assert!(applied > before);
            let envelope = slot.authorization_work().unwrap().unwrap().clone();
            let authorization_anchor = slot.authorization_anchor().unwrap().unwrap().clone();
            assert_eq!(authorization_anchor.ordered.index, before);
            assert_eq!(
                authorization_anchor.runtime,
                owner
                    .host
                    .lock()
                    .unwrap()
                    .journal_position(HostAgentId(owner.pins.agent.0))
                    .unwrap()
                    .runtime
                    .commitment()
            );
            let local_root = harness._directory.0.join("ordinary-local");
            let mut local = crate::agent::local_sdk_host::LocalAgentHost::create(
                &local_root,
                descriptor.identity.space,
                owner.pins.node,
                harness.fixture.trust.clone(),
            )
            .unwrap();
            assert!(matches!(
                owner.create_local_from_management_intent(
                    &mut slot,
                    call.managed,
                    &mut local,
                    shape_only_runtime(),
                    &mut issuer,
                    &mut signer,
                ),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert!(local.list().unwrap().is_empty());
            assert_eq!(signer.calls, 1);
            assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
            let (agent, initial_acknowledgement) = owner
                .create_local_from_management_intent(
                    &mut slot,
                    call.managed,
                    &mut local,
                    runtime.clone(),
                    &mut issuer,
                    &mut signer,
                )
                .unwrap();
            assert_eq!(agent, descriptor.identity.agent);
            drop(local);
            let local = crate::agent::local_sdk_host::LocalAgentHost::open(
                &local_root,
                descriptor.identity.space,
                owner.pins.node,
                harness.fixture.trust.clone(),
            )
            .unwrap();
            let observation = local
                .observe_management_application(agent, &request, &receipt)
                .unwrap();
            assert_eq!(
                observation.result(),
                &Ok(ManagementReply::Created(descriptor.identity.clone()))
            );
            let acknowledgement = issuer
                .observe_local_application(&observation, &mut signer)
                .unwrap();
            assert_eq!(acknowledgement, initial_acknowledgement);
            assert_eq!(acknowledgement.reopened_state, observation.reopened_state());
            assert_eq!(acknowledgement.applied_at, observation.applied_at());
            assert!(acknowledgement.verify_with(&RawCredentialVerifier).is_ok());
            assert_eq!(signer.calls, 2);
            drop(local);
            drop(slot);
            drop(issuer);
            harness
                .fixture
                .logical_slot
                .as_ref()
                .unwrap()
                .store(LOGICAL_SLOT + 20, Ordering::Release);
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer_store.clone(),
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            assert_eq!(
                owner
                    .issue_management_intent(&mut slot, call.managed, &mut issuer, &mut signer)
                    .unwrap(),
                receipt
            );
            assert_eq!(slot.authorization_work().unwrap(), Some(&envelope));
            assert_eq!(signer.calls, 2);
            assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
            let mut local = crate::agent::local_sdk_host::LocalAgentHost::open(
                &local_root,
                descriptor.identity.space,
                owner.pins.node,
                harness.fixture.trust.clone(),
            )
            .unwrap();
            assert_eq!(
                owner
                    .create_local_from_management_intent(
                        &mut slot,
                        call.managed,
                        &mut local,
                        runtime,
                        &mut issuer,
                        &mut signer,
                    )
                    .unwrap(),
                (agent, acknowledgement.clone())
            );
            let recovered = local
                .observe_management_application(agent, &request, &receipt)
                .unwrap();
            assert_eq!(recovered.reopened_state(), observation.reopened_state());
            assert_eq!(
                issuer
                    .observe_local_application(&recovered, &mut signer)
                    .unwrap(),
                acknowledgement
            );
            assert_eq!(signer.calls, 2);
            drop(local);
            assert!(matches!(
                owner.retire_management_intent_results(
                    &slot,
                    call.managed,
                    &acknowledgement,
                    &issuer
                ),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
            assert!(
                !issuer
                    .application_finalization_status(&acknowledgement)
                    .unwrap()
            );
            let mut substituted = acknowledgement.clone();
            substituted.reopened_state = Hash([0xed; 32]);
            substituted.signature = signer.key.sign(&substituted.signing_bytes()).to_bytes();
            assert!(matches!(
                owner.finalize_management_intent(
                    &mut slot,
                    call.managed,
                    &substituted,
                    &mut issuer
                ),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
            let before_finalization = issuer.into_store();
            let interrupted_image = before_finalization.image.lock().unwrap().clone();
            let mut issuer = DurableCleanManagementIssuer::open(
                before_finalization,
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            assert!(
                owner
                    .finalize_management_intent(
                        &mut slot,
                        call.managed,
                        &acknowledgement,
                        &mut issuer
                    )
                    .unwrap()
            );
            assert!(
                issuer
                    .application_finalization_status(&acknowledgement)
                    .unwrap()
            );
            let finalized = owner.ordered_index_for_test().unwrap();
            assert!(finalized > applied);
            let finalization_envelope = slot.finalization_work().unwrap().unwrap().clone();
            let finalization_anchor = slot.finalization_anchor().unwrap().unwrap().clone();
            assert_eq!(finalization_anchor.ordered.index, applied);
            assert_eq!(finalization_anchor.genesis, authorization_anchor.genesis);
            assert_eq!(
                finalization_anchor.admission,
                authorization_anchor.admission
            );
            assert_eq!(finalization_anchor.runtime, authorization_anchor.runtime);
            let reopened_slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            assert_eq!(
                reopened_slot.authorization_anchor().unwrap(),
                Some(&authorization_anchor)
            );
            assert_eq!(
                reopened_slot.finalization_anchor().unwrap(),
                Some(&finalization_anchor)
            );
            drop(reopened_slot);
            drop(slot);
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            assert_eq!(
                slot.finalization_work().unwrap(),
                Some(&finalization_envelope)
            );
            // Model a crash after the actor commit but before the issuer marker.
            // A fresh issuer must recover via exact replay, not dispatch new work.
            let interrupted_store = IssuerMemoryStore {
                image: Arc::new(Mutex::new(interrupted_image)),
                ..Default::default()
            };
            let mut interrupted = DurableCleanManagementIssuer::open(
                interrupted_store,
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            harness
                .fixture
                .logical_slot
                .as_ref()
                .unwrap()
                .store(LOGICAL_SLOT + 30, Ordering::Release);
            assert!(
                owner
                    .finalize_management_intent(
                        &mut slot,
                        call.managed,
                        &acknowledgement,
                        &mut interrupted,
                    )
                    .unwrap()
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), finalized);
            assert_eq!(
                slot.finalization_work().unwrap(),
                Some(&finalization_envelope)
            );
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer.into_store(),
                descriptor.authority,
                descriptor.identity.space,
                descriptor.identity.agent,
            )
            .unwrap();
            assert!(
                !owner
                    .finalize_management_intent(
                        &mut slot,
                        call.managed,
                        &acknowledgement,
                        &mut issuer
                    )
                    .unwrap()
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), finalized);
            assert_eq!(signer.calls, 2);
            let intent_image = slot.intent().unwrap().clone();
            let issuer_image = issuer_store.image.lock().unwrap().clone();
            check_lifecycle_recovery_scan(
                owner.authority_target(),
                store.clone(),
                issuer_store.clone(),
                false,
                true,
            );
            check_management_retirement_admission(owner, &envelope, &finalization_envelope);
            assert!(matches!(
                owner.retire_management_intent_results(&slot, call.managed, &substituted, &issuer),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(owner.ordered_index_for_test().unwrap(), finalized);
            check_management_retirement_gate(owner, [&envelope, &finalization_envelope], false);
            if !interrupted_retirement {
                check_management_retirement_reattachment(
                    owner,
                    [&envelope, &finalization_envelope],
                    true,
                    Arc::clone(&harness.network),
                );
            }
            if interrupted_retirement {
                // Model interruption after the first positive acknowledgement.
                // Recovery must consume only the remaining finalization result.
                let material = owner
                    .supervisor_invocation_material(
                        owner.pins.agent,
                        owner.authority_target().binding.issuer.actor,
                    )
                    .unwrap();
                let identity =
                    crate::agent::supervisor_adapters::physical_material_identity(&material)
                        .unwrap();
                let RuntimeWork::Invoke {
                    invocation,
                    authorization,
                    ..
                } = &envelope
                else {
                    unreachable!()
                };
                assert!(matches!(
                    owner
                        ._network_host
                        .supervisor_acknowledge_management_retirement(
                            identity,
                            (**invocation).clone(),
                            (**authorization).clone()
                        )
                        .unwrap(),
                    RuntimeOutcome::Acknowledged(Ok(_))
                ));
                assert_eq!(owner.ordered_index_for_test().unwrap(), finalized + 1);
                check_management_retirement_reattachment(
                    owner,
                    [&envelope, &finalization_envelope],
                    false,
                    Arc::clone(&harness.network),
                );
                assert_eq!(
                    owner
                        .host
                        .lock()
                        .unwrap()
                        .management_retirement_admission_requirement(
                            HostAgentId(owner.pins.agent.0),
                            [&envelope, &finalization_envelope],
                        )
                        .unwrap(),
                    Some(1)
                );
            }
            assert!(
                owner
                    .retire_management_intent_results(
                        &slot,
                        call.managed,
                        &acknowledgement,
                        &issuer,
                    )
                    .unwrap()
            );
            let retired = owner.ordered_index_for_test().unwrap();
            assert_eq!(retired, finalized + 2);
            assert_eq!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .management_retirement_admission_requirement(
                        HostAgentId(owner.pins.agent.0),
                        [&envelope, &finalization_envelope],
                    )
                    .unwrap(),
                Some(0)
            );
            assert!(
                !owner
                    .retire_management_intent_results(
                        &slot,
                        call.managed,
                        &acknowledgement,
                        &issuer,
                    )
                    .unwrap()
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), retired);
            assert_eq!(slot.intent(), Some(&intent_image));
            assert_eq!(slot.authorization_work().unwrap(), Some(&envelope));
            assert_eq!(
                slot.finalization_work().unwrap(),
                Some(&finalization_envelope)
            );
            assert_eq!(*issuer_store.image.lock().unwrap(), issuer_image);
            assert_eq!(signer.calls, 2);
            check_management_retirement_gate(owner, [&envelope, &finalization_envelope], true);
            drop(slot);
            check_durable_management_retirement(
                owner,
                store,
                call.managed,
                &acknowledgement,
                &issuer,
                issuer_store,
                interrupted_retirement,
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), retired);
            check_multiple_management_retirement_admission(
                owner,
                [&envelope, &finalization_envelope],
                &intent_image,
                Arc::clone(&harness.network),
            );
            harness.stop();
        }

        #[test]
        fn native_management_intent_requires_the_installed_authorize_policy() {
            use crate::agent::clean_management_intent::{
                CleanManagementIntent, CleanManagementIntentSlot,
            };
            let mut harness = NativeProjectionOwnerHarness::new("management-policy-boundary");
            let owner = harness.owner.as_mut().unwrap();
            let call = harness.fixture.plan.catalog_call.clone();
            let intent = CleanManagementIntent::new(
                owner.authority_target(),
                call.managed,
                harness.fixture.plan.catalog_request().clone(),
                call.clone(),
                &RawCredentialVerifier,
            )
            .unwrap();
            let store = IssuerMemoryStore::default();
            let mut slot = CleanManagementIntentSlot::open(store.clone()).unwrap();
            slot.pledge(intent).unwrap();
            let before = store.image.lock().unwrap().clone();
            let issuer_store = IssuerMemoryStore::default();
            let mut issuer = DurableCleanManagementIssuer::open(
                issuer_store.clone(),
                owner.pins.authority,
                call.managed.space,
                call.managed.agent,
            )
            .unwrap();
            let mut signer = CountingSigner::new();
            let before_index = owner.ordered_index_for_test().unwrap();
            // This physically installed fixture has public projection methods,
            // but no authorize method. A signed call must not bypass that policy.
            assert!(matches!(
                owner.issue_management_intent(&mut slot, call.managed, &mut issuer, &mut signer),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
            assert_eq!(slot.authorization_work().unwrap(), None);
            assert_eq!(*store.image.lock().unwrap(), before);
            assert_eq!(*issuer_store.image.lock().unwrap(), None);
            assert_eq!(signer.calls, 0);
            assert_eq!(owner.ordered_index_for_test().unwrap(), before_index);
            harness.stop();
        }

        #[test]
        fn system_projection_audits_protected_authority_against_root_pinned_install() {
            use crate::agent::sdk::authority::AuthorityActorProjection;
            use crate::agent::supervisor_adapters::AgentAuthorityRouteProjection;

            let mut harness = NativeProjectionOwnerHarness::new("root-authority-projection");
            let owner = harness.owner.as_mut().unwrap();
            let catalog =
                super::super::install_request(harness.fixture.plan.catalog_request()).unwrap();
            let row = AuthorityActorProjection {
                agent: owner.pins.agent,
                entry: catalog.entry.clone(),
                producer: catalog.producer,
                contract: catalog.contract,
                requirements: catalog.requirements,
                root_provenance: true,
                installation_id: catalog.installation_id,
                registry_reservation: catalog.registry_reservation,
                install_request: catalog.lineage_commitment(),
            };
            let projection = AgentAuthorityRouteProjection::new(
                owner.pins.descriptor.replica_generation(),
                owner.pins.descriptor.clone(),
                vec![row.clone()],
            )
            .unwrap();
            let head = placeholder_credential_projection().head;
            let before = owner.ordered_index_for_test().unwrap();
            let audit = owner
                .audit_authority_projection(head, &[projection.clone()])
                .unwrap();
            let crate::agent::shared_host::SharedAuthorityProjectionAudit::Ready(identities) =
                audit
            else {
                panic!("the Catalog inventory plus root-pinned Authority must be ready");
            };
            assert_eq!(identities.len(), 2);
            assert!(
                identities
                    .iter()
                    .any(|identity| identity.key().actor() == owner.pins.authority.issuer.actor)
            );

            // A response cannot claim the protected root actor, even with
            // otherwise valid fields. It must come from the retained plan.
            let mut injected = row;
            injected.entry = owner.authority_install.entry.clone();
            injected.producer = owner.authority_install.producer;
            injected.contract = owner.authority_install.contract;
            injected.requirements = owner.authority_install.requirements;
            injected.root_provenance = false;
            injected.installation_id = owner.authority_install.installation_id;
            injected.registry_reservation = owner.authority_install.registry_reservation;
            injected.install_request = owner.authority_install.lineage_commitment();
            let forged = AgentAuthorityRouteProjection::new(
                projection.replica_generation(),
                projection.descriptor().clone(),
                vec![injected],
            )
            .unwrap();
            assert!(matches!(
                owner.audit_authority_projection(head, &[forged]),
                Err(SharedAgentHostError::ScopeMismatch)
            ));

            // Root trust is not an exemption from comparing physical bytes.
            owner.authority_install.entry.program = ProgramId([0xab; 32]);
            assert!(
                owner
                    .audit_authority_projection(head, &[projection])
                    .is_err()
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            harness.stop();
        }

        #[test]
        fn bootstrap_invocations_carry_the_executable_authority_closure() {
            let fixture = runtime_fixture();
            let install = super::super::install_request(&fixture.authority_request).unwrap();
            let blobs = invocation_availability(install, &fixture.authority_package).unwrap();
            for bytes in [
                fixture.authority_package.program_bytes(),
                fixture.authority_package.state_lane_schema_bytes(),
                fixture.authority_package.method_policy_bytes(),
                install.installation_data.as_ref().unwrap().bytes.as_slice(),
            ] {
                assert_eq!(
                    blobs
                        .iter()
                        .filter(|blob| blob.reference.matches(bytes))
                        .count(),
                    1
                );
            }
            assert!(
                blobs
                    .windows(2)
                    .all(|pair| pair[0].reference < pair[1].reference)
            );
            let mut invalid = install.clone();
            invalid.installation_data.as_mut().unwrap().bytes.push(0);
            assert!(invocation_availability(&invalid, &fixture.authority_package).is_err());
        }

        #[test]
        fn clean_break_plan_roundtrips_full_requests_and_rejects_recommitted_tampering() {
            let fixture = physical_fixture();
            let mut excessive_gas = fixture.plan.clone();
            excessive_gas.invocation_gas = crate::agent::execution::MAX_EXECUTION_GAS + 1;
            assert!(excessive_gas.validate().is_err());
            assert!(
                AuthorizedCleanSystemAgentBootstrap::decode(&excessive_gas.canonical_bytes())
                    .is_err()
            );
            let bytes = fixture.plan.canonical_bytes();
            assert_eq!(bytes.get(..4), Some(b"CBP3".as_slice()));

            let decoded = AuthorizedCleanSystemAgentBootstrap::decode(&bytes).unwrap();
            assert_eq!(
                decoded.authority_request(),
                fixture.plan.authority_request()
            );
            assert_eq!(decoded.catalog_request(), fixture.plan.catalog_request());
            assert_eq!(decoded.canonical_bytes(), bytes);

            let mut previous_generation = bytes;
            previous_generation[..4].copy_from_slice(b"CBP2");
            assert!(AuthorizedCleanSystemAgentBootstrap::decode(&previous_generation).is_err());

            let authority_wire = fixture.plan.authority_request().encode().unwrap();
            assert_eq!(
                ManagementRequest::decode(&authority_wire).unwrap(),
                fixture.plan.authority_request().clone()
            );
            let mut record = CleanSystemAgentBootstrapRecord::intent(&fixture.plan);
            let request_offset = record
                .plan
                .windows(authority_wire.len())
                .position(|window| window == authority_wire)
                .unwrap();
            // Keep a canonical, nonzero Install identifier but break its exact
            // link to the already-authorized decision.
            record.plan[request_offset + 4 + 32 + 1] ^= 1;
            record.plan_commitment =
                Hash::digest(b"vos/clean-system-agent-bootstrap-plan/v3", &[&record.plan]);
            assert!(CleanSystemAgentBootstrapRecord::decode(&record.encode()).is_err());
        }

        #[test]
        fn factory_is_called_once_for_fresh_bootstrap_and_never_on_exact_restart() {
            let fixture = physical_fixture();
            let directory = TestDirectory::new("factory-exact-restart");
            let pins = BootstrapMemoryStore::default();
            let record = BootstrapMemoryStore::default();
            let issuer = IssuerMemoryStore::default();
            let provider = Arc::new(MemoryProvider::new(fixture.provision.clone()));
            let network = network(NODE_SEED);
            let mut signer = CountingSigner::new();
            let factory_calls = Cell::new(0_usize);

            let owner = open_owner_with_factory(
                &fixture,
                &directory,
                pins.clone(),
                record.clone(),
                issuer.clone(),
                &mut signer,
                || {
                    factory_calls.set(factory_calls.get() + 1);
                    Ok(fixture.plan.clone())
                },
                Arc::clone(&provider),
                Arc::clone(&network),
            )
            .unwrap();
            assert_eq!(factory_calls.get(), 1);
            assert_eq!(signer.calls, 4);
            drop(owner);

            let reopened = open_owner_with_factory(
                &fixture,
                &directory,
                pins,
                record,
                issuer,
                &mut signer,
                || {
                    factory_calls.set(factory_calls.get() + 1);
                    Err(rejected(
                        CleanSystemAgentBootstrapRejection::InvalidDecision,
                    ))
                },
                provider,
                Arc::clone(&network),
            )
            .unwrap();
            assert_eq!(factory_calls.get(), 1);
            assert_eq!(signer.calls, 4, "exact restart must not sign again");
            assert_eq!(reopened.ordered_index_for_test().unwrap(), 4);
            drop(reopened);
            stop_network(network);
        }

        #[test]
        fn factory_rejects_partial_preexisting_and_tampered_state_without_fresh_material() {
            let fixture = physical_fixture();
            let provider = Arc::new(MemoryProvider::new(fixture.provision.clone()));
            let network = network(NODE_SEED);
            let mut signer = CountingSigner::new();
            let factory_calls = Cell::new(0_usize);

            let only_pins = BootstrapMemoryStore::default();
            only_pins
                .clone()
                .commit(&fixture.plan.pins.encode())
                .unwrap();
            let directory = TestDirectory::new("factory-partial-pins");
            assert!(matches!(
                open_owner_with_factory(
                    &fixture,
                    &directory,
                    only_pins,
                    BootstrapMemoryStore::default(),
                    IssuerMemoryStore::default(),
                    &mut signer,
                    || {
                        factory_calls.set(factory_calls.get() + 1);
                        Ok(fixture.plan.clone())
                    },
                    Arc::clone(&provider),
                    Arc::clone(&network),
                ),
                Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::MissingRecord
                ))
            ));

            let only_record = BootstrapMemoryStore::default();
            only_record
                .clone()
                .commit(&CleanSystemAgentBootstrapRecord::intent(&fixture.plan).encode())
                .unwrap();
            let directory = TestDirectory::new("factory-partial-record");
            assert!(matches!(
                open_owner_with_factory(
                    &fixture,
                    &directory,
                    BootstrapMemoryStore::default(),
                    only_record,
                    IssuerMemoryStore::default(),
                    &mut signer,
                    || {
                        factory_calls.set(factory_calls.get() + 1);
                        Ok(fixture.plan.clone())
                    },
                    Arc::clone(&provider),
                    Arc::clone(&network),
                ),
                Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::MissingPins
                ))
            ));

            let pins = BootstrapMemoryStore::default();
            pins.clone().commit(&fixture.plan.pins.encode()).unwrap();
            let record = BootstrapMemoryStore::default();
            let mut tampered = CleanSystemAgentBootstrapRecord::intent(&fixture.plan);
            let authority_wire = fixture.plan.authority_request().encode().unwrap();
            let request_offset = tampered
                .plan
                .windows(authority_wire.len())
                .position(|window| window == authority_wire)
                .unwrap();
            tampered.plan[request_offset + 4 + 32 + 1] ^= 1;
            tampered.plan_commitment = Hash::digest(
                b"vos/clean-system-agent-bootstrap-plan/v3",
                &[&tampered.plan],
            );
            record.clone().commit(&tampered.encode()).unwrap();
            let directory = TestDirectory::new("factory-tampered-record");
            assert!(matches!(
                open_owner_with_factory(
                    &fixture,
                    &directory,
                    pins,
                    record,
                    IssuerMemoryStore::default(),
                    &mut signer,
                    || {
                        factory_calls.set(factory_calls.get() + 1);
                        Ok(fixture.plan.clone())
                    },
                    Arc::clone(&provider),
                    Arc::clone(&network),
                ),
                Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::InvalidRecord
                ))
            ));

            let directory = TestDirectory::new("factory-preexisting-host");
            std::fs::create_dir(directory.host()).unwrap();
            assert!(matches!(
                open_owner_with_factory(
                    &fixture,
                    &directory,
                    BootstrapMemoryStore::default(),
                    BootstrapMemoryStore::default(),
                    IssuerMemoryStore::default(),
                    &mut signer,
                    || {
                        factory_calls.set(factory_calls.get() + 1);
                        Ok(fixture.plan.clone())
                    },
                    provider,
                    Arc::clone(&network),
                ),
                Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::PreexistingHost
                ))
            ));
            assert_eq!(factory_calls.get(), 0);
            stop_network(network);
        }

        #[test]
        fn pending_projection_commit_error_classifies_the_exact_visible_record() {
            let fixture = physical_fixture();
            let directory = TestDirectory::new("pending-projection-commit");
            let pins = BootstrapMemoryStore::default();
            let record = BootstrapMemoryStore::default();
            let issuer = IssuerMemoryStore::default();
            let provider = Arc::new(MemoryProvider::new(fixture.provision.clone()));
            let network = network(NODE_SEED);
            let mut signer = CountingSigner::new();
            let owner = open_owner(
                &fixture,
                &directory,
                pins,
                record,
                issuer,
                &mut signer,
                provider,
                Arc::clone(&network),
            )
            .unwrap();
            let public_key = [0xb7; 32];
            let query = AuthorityProjectionQuery {
                authority: owner.authority_target(),
                credential: CredentialId::of_public_key(&public_key),
                nonce: Hash([0xb8; 32]),
                selector: AuthorityProjectionSelector::Credential,
                authentication:
                    crate::agent::sdk::authority::AuthorityIngressAuthentication::ApiCredentialSignature {
                        credential_public_key: public_key,
                        signature: [0xb9; 64],
                    },
            };
            assert!(query.validate_shape().is_ok());
            let target = owner.authority_target();
            let query_bytes = query.encode().unwrap();
            let invocation = InvocationWork {
                space: target.space,
                agent: target.system_agent,
                runtime_deployment: target.system_runtime_deployment,
                invocation: InvocationId(
                    Hash::digest(
                        b"vos/system-authority/projection-invocation/v2",
                        &[query.commitment().as_bytes()],
                    )
                    .0,
                ),
                actor: target.binding.issuer.actor,
                incarnation: Hash([0xba; 32]),
                deployment: target.binding.issuer.deployment,
                program: target.binding.issuer.program,
                mode: MethodMode::Query,
                origin: InvocationOrigin::anonymous(),
                roles: InvocationRoleClaims::none(),
                message: dynamic_message(
                    projection_method(query.selector),
                    "query",
                    crate::actors::value::Value::Bytes(query_bytes),
                ),
                installation_data: None,
                availability: Vec::new(),
                gas: 1_000_000,
                recovery_only: false,
            };
            assert!(invocation.validate());
            let authorization = InvocationAuthorization::PublicPreflight(
                crate::agent::sdk::PublicPreflight::for_work(&invocation, LOGICAL_SLOT),
            );
            let pending = PendingAuthorityProjection {
                query,
                work: RuntimeWork::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    state: RuntimeState::default(),
                    invocation: Box::new(invocation),
                    authorization: Box::new(authorization),
                    observed_slot: LOGICAL_SLOT,
                },
            };
            assert!(pending.validate());
            let prior = owner.record.clone();
            let mut candidate = prior.clone();
            candidate.pending_projection = Some(pending);
            assert!(prior.is_valid());
            assert!(candidate.is_valid());
            drop(owner);

            let mut before =
                ProjectionCommitStore::new(&prior, ProjectionCommitFailure::BeforePublish);
            assert_eq!(
                commit_new_pending_projection(&mut before, &prior, &candidate),
                PendingProjectionRecordCommit::PriorVisible,
            );
            assert_eq!(before.image, Some(prior.encode()));
            assert_eq!(before.commits, 1);

            let mut after_once =
                ProjectionCommitStore::new(&prior, ProjectionCommitFailure::AfterPublishOnce);
            assert_eq!(
                commit_new_pending_projection(&mut after_once, &prior, &candidate),
                PendingProjectionRecordCommit::Durable,
            );
            assert_eq!(after_once.image, Some(candidate.encode()));
            assert_eq!(after_once.commits, 2);

            let mut after_always =
                ProjectionCommitStore::new(&prior, ProjectionCommitFailure::AfterPublishAlways);
            assert_eq!(
                commit_new_pending_projection(&mut after_always, &prior, &candidate),
                PendingProjectionRecordCommit::Ambiguous,
            );
            assert_eq!(after_always.image, Some(candidate.encode()));
            assert_eq!(after_always.commits, 2);

            let mut missing =
                ProjectionCommitStore::new(&prior, ProjectionCommitFailure::MissingAfterError);
            assert_eq!(
                commit_new_pending_projection(&mut missing, &prior, &candidate),
                PendingProjectionRecordCommit::Ambiguous,
            );
            assert_eq!(missing.commits, 1);

            stop_network(network);
        }

        #[test]
        fn pending_projection_recovers_exact_invoke_and_ack_before_record_clear() {
            use crate::agent::sdk::authority::AuthorityCredentialProjection;
            use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;

            let fixture = native_projection_physical_fixture();
            let directory = TestDirectory::new("pending-projection-exact-recovery");
            let pins = BootstrapMemoryStore::default();
            let record = BootstrapMemoryStore::default();
            let issuer = IssuerMemoryStore::default();
            let provider = Arc::new(MemoryProvider::new(fixture.provision.clone()));
            let network = network(NODE_SEED);
            let mut signer = CountingSigner::new();
            let mut owner = seed_complete_native_projection_owner(
                &fixture,
                &directory,
                pins.clone(),
                record.clone(),
                issuer.clone(),
                &mut signer,
                Arc::clone(&provider),
                Arc::clone(&network),
            );
            let query = signed_credential_projection_query(&owner, 0xc1);
            assert_eq!(
                query.encode().unwrap().len(),
                placeholder_credential_projection()
                    .query
                    .encode()
                    .unwrap()
                    .len()
            );
            let pending = owner.prepare_authority_projection(query.clone()).unwrap();
            let (work, authorization) = pending.invocation().unwrap();
            let work = work.clone();
            let authorization = authorization.clone();
            let agent = HostAgentId(owner.pins.agent.0);
            owner
                ._network_host
                .reserve_projection_pair(agent, &work, &authorization, false)
                .unwrap();
            owner
                .pending_authority_projection_identity(&pending, false)
                .unwrap();
            let prior = owner.record.clone();
            let mut candidate = prior.clone();
            candidate.pending_projection = Some(pending.clone());
            assert_eq!(
                commit_new_pending_projection(&mut owner.record_store, &prior, &candidate),
                PendingProjectionRecordCommit::Durable
            );
            owner.record = candidate.clone();
            let durable_pending = candidate.encode();
            assert_eq!(record.image(), Some(durable_pending.clone()));

            let identity = owner
                .pending_authority_projection_identity(&pending, true)
                .unwrap();
            let before_invoke = owner.ordered_index_for_test().unwrap();
            let prepared_input = owner
                .host
                .lock()
                .unwrap()
                .prepare_reserved_projection_operation(
                    agent,
                    CleanInvocationReplayRequest::Invoke {
                        context: RuntimeExecutionContext::Direct,
                        work: work.clone(),
                        authorization: authorization.clone(),
                    },
                    true,
                )
                .unwrap()
                .input();
            let invoked = owner
                .supervisor_invoke_terminal_reserved(identity, work.clone(), authorization.clone())
                .unwrap();
            let RuntimeOutcome::Completed(Ok(reply)) = &invoked else {
                panic!("projection invoke did not complete successfully: {invoked:?}");
            };
            assert_eq!(reply.status, InvocationStatus::Done);
            let crate::actors::value::Value::Bytes(response) =
                crate::actors::value::Value::try_decode(&reply.reply).unwrap()
            else {
                panic!("projection reply was not bytes");
            };
            let projection = AuthorityCredentialProjection::decode(&response).unwrap();
            assert_eq!(projection.query, query);
            assert_eq!(owner.ordered_index_for_test().unwrap(), before_invoke + 1);
            {
                let host = owner.host.lock().unwrap();
                assert!(
                    host.retained_terminal_projection_invoke(agent, &work, &authorization)
                        .unwrap()
                );
                assert!(
                    !host
                        .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                        .unwrap()
                );
                assert_eq!(
                    host.projection_admission_requirement(agent, &work, &authorization, true)
                        .unwrap(),
                    Some(1)
                );
            }
            let rival = owner
                .prepare_authority_projection(signed_credential_projection_query(&owner, 0xc2))
                .unwrap();
            let (rival_work, rival_authorization) = rival.invocation().unwrap();
            let earlier_authorization = InvocationAuthorization::PublicPreflight(
                crate::agent::sdk::PublicPreflight::for_work(&work, LOGICAL_SLOT - 1),
            );
            assert_ne!(authorization, earlier_authorization);
            assert_eq!(
                owner._network_host.reserve_projection_pair(
                    agent,
                    &work,
                    &earlier_authorization,
                    false,
                ),
                Err(SharedAgentHostError::Conflict)
            );
            assert!(
                matches!(
                    owner._network_host.reserve_projection_pair(
                        agent,
                        rival_work,
                        rival_authorization,
                        false,
                    ),
                    Err(SharedAgentHostError::Conflict)
                ),
                "a durable PAP must exclude every rival projection pair"
            );
            let pre_crash_snapshot = owner
                .host
                .lock()
                .unwrap()
                .show(agent)
                .unwrap()
                .unwrap()
                .snapshots;
            drop(owner);

            let mut owner = open_owner(
                &fixture,
                &directory,
                pins.clone(),
                record.clone(),
                issuer.clone(),
                &mut signer,
                Arc::clone(&provider),
                Arc::clone(&network),
            )
            .unwrap();
            assert_eq!(owner.ordered_index_for_test().unwrap(), before_invoke + 1);
            assert_eq!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .show(agent)
                    .unwrap()
                    .unwrap()
                    .snapshots,
                pre_crash_snapshot
            );
            let retained = owner
                .host
                .lock()
                .unwrap()
                .prepare_reserved_projection_operation(
                    agent,
                    CleanInvocationReplayRequest::Invoke {
                        context: RuntimeExecutionContext::Direct,
                        work: work.clone(),
                        authorization: authorization.clone(),
                    },
                    true,
                )
                .unwrap();
            assert_eq!(retained.input(), prepared_input);
            assert_eq!(retained.retained(), Some(&invoked));
            assert_eq!(owner.ordered_index_for_test().unwrap(), before_invoke + 1);

            record.fail_next_before_publish();
            assert_eq!(
                owner.recover_pending_authority_projection(),
                Err(SharedAgentHostError::Unavailable)
            );
            let after_ack = before_invoke + 2;
            assert_eq!(owner.ordered_index_for_test().unwrap(), after_ack);
            assert_eq!(record.image(), Some(durable_pending.clone()));
            assert_eq!(owner.record.pending_projection, Some(pending.clone()));
            {
                let host = owner.host.lock().unwrap();
                assert!(
                    host.retained_positive_clean_acknowledgement(agent, &work, &authorization)
                        .unwrap()
                );
                assert_eq!(
                    host.projection_admission_requirement(agent, &work, &authorization, true)
                        .unwrap(),
                    Some(0)
                );
            }
            let before_blocked_competitors = {
                let host = owner.host.lock().unwrap();
                (
                    host.journal_position(agent).unwrap(),
                    host.clean_state_commitment(agent).unwrap(),
                    host.show(agent).unwrap().unwrap(),
                )
            };
            assert_eq!(
                owner._network_host.reserve_projection_pair(
                    agent,
                    &work,
                    &earlier_authorization,
                    false,
                ),
                Err(SharedAgentHostError::Conflict)
            );
            assert_eq!(
                owner.supervisor_invoke_terminal(identity, work.clone(), authorization.clone()),
                Err(SharedAgentHostError::CapacityExhausted)
            );
            assert_eq!(
                owner._network_host.reserve_projection_pair(
                    agent,
                    rival_work,
                    rival_authorization,
                    false,
                ),
                Err(SharedAgentHostError::Conflict)
            );
            for (mode, method, nonce) in [
                (MethodMode::Merge, "projection_merge_probe", 0xd1),
                (MethodMode::Local, "projection_local_probe", 0xd2),
            ] {
                let mut probe = work.clone();
                probe.invocation = InvocationId([nonce; 32]);
                probe.mode = mode;
                probe.message = dynamic_message(method, "probe", crate::actors::value::Value::Unit);
                assert!(probe.validate());
                let probe_authorization = InvocationAuthorization::PublicPreflight(
                    crate::agent::sdk::PublicPreflight::for_work(&probe, LOGICAL_SLOT - 1),
                );
                assert_eq!(
                    owner.supervisor_invoke(identity, probe, probe_authorization),
                    Err(SharedAgentHostError::CapacityExhausted)
                );
            }
            let after_blocked_competitors = {
                let host = owner.host.lock().unwrap();
                (
                    host.journal_position(agent).unwrap(),
                    host.clean_state_commitment(agent).unwrap(),
                    host.show(agent).unwrap().unwrap(),
                )
            };
            assert_eq!(after_blocked_competitors, before_blocked_competitors);
            assert_eq!(owner.ordered_index_for_test().unwrap(), after_ack);
            let snapshots = owner
                .host
                .lock()
                .unwrap()
                .show(agent)
                .unwrap()
                .unwrap()
                .snapshots;
            drop(owner);

            let mut owner = open_owner(
                &fixture,
                &directory,
                pins,
                record.clone(),
                issuer,
                &mut signer,
                provider,
                Arc::clone(&network),
            )
            .unwrap();
            assert_eq!(owner.record.pending_projection, None);
            assert!(
                CleanSystemAgentBootstrapRecord::decode(&record.image().unwrap())
                    .unwrap()
                    .pending_projection
                    .is_none()
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), after_ack);
            assert_eq!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .show(agent)
                    .unwrap()
                    .unwrap()
                    .snapshots,
                snapshots
            );
            assert!(
                owner
                    .network_host_for_test()
                    .attachment_for_test(agent)
                    .is_some()
            );
            assert!(
                owner
                    .host
                    .lock()
                    .unwrap()
                    .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                    .unwrap()
            );
            let fresh = signed_credential_projection_query(&owner, 0xc3);
            assert!(owner.invoke_authority_projection(fresh).is_ok());
            assert_eq!(owner.ordered_index_for_test().unwrap(), after_ack + 2);
            assert_eq!(owner.record.pending_projection, None);
            drop(owner);
            stop_network(network);
        }

        #[test]
        fn projection_checkpoint_failures_restore_exact_attachment_and_gate() {
            // Candidate/committee mismatch and signer refusal occur before
            // retirement, so the exact live handler and all physical state
            // must remain unchanged.
            for (label, refusal) in [
                ("checkpoint-candidate-mismatch", false),
                ("checkpoint-signer-refusal", true),
            ] {
                let mut harness = NativeProjectionOwnerHarness::new(label);
                let expected_committee = harness.fixture.plan.pins.replicas.clone();
                let valid_signer = Arc::clone(&harness.fixture.merge);
                let wrong_agent = AgentId([0xe1; 32]);
                let (wrong_committee, _) =
                    replica_member(harness.fixture.plan.pins.space, wrong_agent);
                let refusing = RefusingSnapshotSigner(HostNodeId(harness.fixture.plan.pins.node.0));
                let owner = harness.owner.as_mut().unwrap();
                let agent = HostAgentId(owner.pins.agent.0);
                let (work, authorization) = fresh_projection_pair(owner, 0xe2);
                owner
                    ._network_host
                    .reserve_projection_pair(agent, &work, &authorization, false)
                    .unwrap();
                owner
                    ._network_host
                    .release_projection_pair(agent, &work, &authorization)
                    .unwrap();
                let before = native_owner_physical_state(owner);
                let (before_handler, before_worker) = owner
                    .network_host_for_test()
                    .attachment_for_test(agent)
                    .unwrap();
                assert!(before_worker);
                owner._network_host.force_checkpoint_once_for_test();
                let (committee, signer): (&AgentReplicaCommittee, &dyn LocalMergeAuthenticator) =
                    if refusal {
                        (&expected_committee, &refusing)
                    } else {
                        (&wrong_committee, valid_signer.as_ref())
                    };
                assert_eq!(
                    owner
                        ._network_host
                        .certified_checkpoint_for_projection_pair(
                            agent,
                            &work,
                            &authorization,
                            committee,
                            signer,
                        ),
                    Err(SharedAgentHostError::SnapshotCertificateInvalid)
                );
                let (after_handler, after_worker) = owner
                    .network_host_for_test()
                    .attachment_for_test(agent)
                    .unwrap();
                assert!(after_worker);
                assert!(Arc::ptr_eq(&before_handler, &after_handler));
                assert_eq!(native_owner_physical_state(owner), before);
                assert_projection_gate_released(owner, 0xe3);
                assert_eq!(native_owner_physical_state(owner), before);
                drop(before_handler);
                drop(after_handler);
                harness.stop();
            }

            // A shape-valid but cryptographically invalid certificate reaches
            // the real install boundary. Installation fails, then a fresh
            // worker/handler is attached to the unchanged snapshot and
            // journal before the error is returned.
            {
                let mut harness = NativeProjectionOwnerHarness::new("checkpoint-install-failure");
                let expected_committee = harness.fixture.plan.pins.replicas.clone();
                let invalid = InvalidSnapshotSigner(HostNodeId(harness.fixture.plan.pins.node.0));
                let owner = harness.owner.as_mut().unwrap();
                let agent = HostAgentId(owner.pins.agent.0);
                let (work, authorization) = fresh_projection_pair(owner, 0xe4);
                owner
                    ._network_host
                    .reserve_projection_pair(agent, &work, &authorization, false)
                    .unwrap();
                owner
                    ._network_host
                    .release_projection_pair(agent, &work, &authorization)
                    .unwrap();
                let before = native_owner_physical_state(owner);
                let (before_handler, _) = owner
                    .network_host_for_test()
                    .attachment_for_test(agent)
                    .unwrap();
                owner._network_host.force_checkpoint_once_for_test();
                assert_eq!(
                    owner
                        ._network_host
                        .certified_checkpoint_for_projection_pair(
                            agent,
                            &work,
                            &authorization,
                            &expected_committee,
                            &invalid,
                        ),
                    Err(SharedAgentHostError::SnapshotCertificateInvalid)
                );
                let after = native_owner_physical_state(owner);
                let (after_handler, after_worker) = owner
                    .network_host_for_test()
                    .attachment_for_test(agent)
                    .unwrap();
                assert!(after_worker);
                assert!(!Arc::ptr_eq(&before_handler, &after_handler));
                assert_eq!(after.0, before.0);
                assert_eq!(after.1, before.1);
                assert_eq!(after.2.snapshots, before.2.snapshots);
                assert_eq!(
                    after.2.transport,
                    crate::agent::shared_host::SharedAgentTransportState::Attached
                );
                assert_projection_gate_released(owner, 0xe5);
                drop(before_handler);
                drop(after_handler);
                harness.stop();
            }

            // Once a valid snapshot is installed, an injected first
            // reattachment failure is observable as no live generation. The
            // next ordinary ensure call repairs that exact durable snapshot
            // without installing a second checkpoint.
            {
                let mut harness = NativeProjectionOwnerHarness::new("checkpoint-reattach-repair");
                let expected_committee = harness.fixture.plan.pins.replicas.clone();
                let valid_signer = Arc::clone(&harness.fixture.merge);
                let owner = harness.owner.as_mut().unwrap();
                let agent = HostAgentId(owner.pins.agent.0);
                let (work, authorization) = fresh_projection_pair(owner, 0xe6);
                owner
                    ._network_host
                    .reserve_projection_pair(agent, &work, &authorization, false)
                    .unwrap();
                owner
                    ._network_host
                    .release_projection_pair(agent, &work, &authorization)
                    .unwrap();
                let before = native_owner_physical_state(owner);
                owner._network_host.force_checkpoint_once_for_test();
                owner._network_host.fail_reattach_once_for_test();
                assert_eq!(
                    owner
                        ._network_host
                        .certified_checkpoint_for_projection_pair(
                            agent,
                            &work,
                            &authorization,
                            &expected_committee,
                            valid_signer.as_ref(),
                        ),
                    Err(SharedAgentHostError::Unavailable)
                );
                assert!(
                    owner
                        .network_host_for_test()
                        .attachment_for_test(agent)
                        .is_none()
                );
                let installed = native_owner_physical_state(owner);
                assert_eq!(installed.0, before.0);
                assert_eq!(installed.1, before.1);
                assert_ne!(installed.2.snapshots, before.2.snapshots);
                owner._network_host.ensure_reattached(agent).unwrap();
                let repaired = native_owner_physical_state(owner);
                assert_eq!(repaired.0, before.0);
                assert_eq!(repaired.1, before.1);
                assert_eq!(repaired.2.snapshots, installed.2.snapshots);
                let (handler, worker) = owner
                    .network_host_for_test()
                    .attachment_for_test(agent)
                    .unwrap();
                assert!(worker);
                assert_projection_gate_released(owner, 0xe7);
                drop(handler);
                harness.stop();
            }
        }

        #[test]
        fn same_head_inventory_rotates_authenticated_suffix_past_1024_entries() {
            let (fixture, expected_descriptors, expected_head) =
                native_inventory_projection_fixture();
            let mut harness = NativeProjectionOwnerHarness::with_fixture(
                "production-inventory-suffix-rotation",
                fixture,
            );
            let owner = harness.owner.as_mut().unwrap();
            let agent = HostAgentId(owner.pins.agent.0);
            let (checkpoint_work, checkpoint_authorization) = fresh_projection_pair(owner, 0xf0);
            owner
                ._network_host
                .reserve_projection_pair(agent, &checkpoint_work, &checkpoint_authorization, false)
                .unwrap();
            owner
                ._network_host
                .release_projection_pair(agent, &checkpoint_work, &checkpoint_authorization)
                .unwrap();
            owner._network_host.force_checkpoint_once_for_test();
            assert_eq!(
                owner
                    ._network_host
                    .certified_checkpoint_for_projection_pair(
                        agent,
                        &checkpoint_work,
                        &checkpoint_authorization,
                        &harness.fixture.plan.pins.replicas,
                        harness.fixture.merge.as_ref(),
                    ),
                Ok(true)
            );
            let initial = native_owner_physical_state(owner);
            assert!(matches!(
                initial.2.snapshots,
                crate::agent::shared_host::SharedAgentSnapshotState::Installed { .. }
            ));
            let host = Arc::clone(&owner.host);
            let record = harness.record.clone();
            let owner = harness.owner.take().unwrap();
            let attachment =
                crate::agent::supervisor_adapters::system_agent_supervisor_attachment(owner, 8)
                    .unwrap();
            let observations = Arc::new(Mutex::new(Vec::new()));
            let inventory = crate::agent::production_owner::load_system_inventory_for_test(
                &attachment,
                Box::new(InventoryProjectionAuthenticator {
                    counters: [0; 4],
                    host: Arc::clone(&host),
                    agent,
                    observations: Arc::clone(&observations),
                }),
            );
            let (head, principal, projections) = inventory.unwrap_or_else(|error| {
                let observed = observations.lock().unwrap();
                let last = observed.last().cloned();
                let physical = {
                    let host = host.lock().unwrap();
                    (
                        host.journal_position(agent),
                        host.snapshot_state_for_test(agent),
                        host.show(agent),
                    )
                };
                panic!(
                    "inventory failed after {} authenticated queries: {error:?}; last={last:?}; physical={physical:?}",
                    observed.len()
                )
            });
            assert_eq!(head, expected_head);
            assert_eq!(principal, PrincipalId([0xb1; 32]));
            assert_eq!(projections.len(), expected_descriptors.len());
            for (projection, expected) in projections.iter().zip(&expected_descriptors) {
                assert_eq!(projection.descriptor(), expected);
                assert!(projection.actors().is_empty());
                assert_eq!(
                    projection.replica_generation(),
                    expected.replica_generation()
                );
            }

            let observations = observations.lock().unwrap();
            assert_eq!(observations.len(), 514);
            let mut expected_selectors = vec![AuthorityProjectionSelector::Credential];
            for page in 0..31 {
                let after = (page != 0).then(|| {
                    expected_descriptors[page * MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES - 1]
                        .identity
                        .agent
                });
                expected_selectors.push(AuthorityProjectionSelector::Agents {
                    after,
                    limit: MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES as u16,
                });
            }
            for descriptor in &expected_descriptors {
                expected_selectors.push(AuthorityProjectionSelector::AgentReplicas {
                    agent: descriptor.identity.agent,
                    after: None,
                    limit: MAX_AUTHORITY_REPLICA_PAGE_ENTRIES as u16,
                });
                expected_selectors.push(AuthorityProjectionSelector::Actors {
                    agent: descriptor.identity.agent,
                    after: None,
                    limit: MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES as u16,
                });
            }
            assert_eq!(
                observations
                    .iter()
                    .map(|observation| observation.query.selector)
                    .collect::<Vec<_>>(),
                expected_selectors
            );
            let unique_nonces = observations
                .iter()
                .map(|observation| observation.query.nonce.0)
                .collect::<std::collections::BTreeSet<_>>();
            let unique_queries = observations
                .iter()
                .map(|observation| observation.query.commitment().0)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(unique_nonces.len(), 514);
            assert_eq!(unique_queries.len(), 514);
            for (index, observation) in observations.iter().enumerate() {
                assert_eq!(
                    observation.ordered_index,
                    initial.0.ordered_index + 2 * index as u64
                );
                if index <= 512 {
                    if index == 512 {
                        assert_eq!(observation.snapshot, Some(initial.2.snapshots));
                    } else {
                        assert_eq!(observation.snapshot, None);
                    }
                }
            }
            let rotated_snapshot = observations[513].snapshot.unwrap();
            assert_ne!(rotated_snapshot, initial.2.snapshots);
            assert!(matches!(
                rotated_snapshot,
                crate::agent::shared_host::SharedAgentSnapshotState::Installed { raft_index, .. }
                    if raft_index == initial.2.applied_slots + 1_024
            ));
            drop(observations);

            let final_state = {
                let host = host.lock().unwrap();
                (
                    host.journal_position(agent).unwrap(),
                    host.show(agent).unwrap().unwrap(),
                )
            };
            assert_eq!(final_state.0.ordered_index, initial.0.ordered_index + 1_028);
            assert_eq!(final_state.1.snapshots, rotated_snapshot);
            assert!(!final_state.1.reservation_pending);
            assert!(
                CleanSystemAgentBootstrapRecord::decode(&record.image().unwrap())
                    .unwrap()
                    .pending_projection
                    .is_none()
            );
            assert!(attachment.handle().is_running());
            assert!(!attachment.handle().recover_authority_projection().unwrap());
            attachment.retire().unwrap();
            drop(host);
            harness.stop();
        }

        struct NeverProjectionAuthenticator(Arc<AtomicUsize>);

        impl crate::agent::production_owner::AuthorityProjectionQueryAuthenticator
            for NeverProjectionAuthenticator
        {
            fn expected_kind(&self) -> crate::agent::sdk::authority::AuthorityCredentialKind {
                crate::agent::sdk::authority::AuthorityCredentialKind::Api
            }

            fn authenticate(
                &mut self,
                _authority: AuthorityActorTarget,
                _selector: AuthorityProjectionSelector,
            ) -> Result<
                AuthorityProjectionQuery,
                crate::agent::production_owner::AgentProductionOwnerError,
            > {
                self.0.fetch_add(1, Ordering::AcqRel);
                Err(crate::agent::production_owner::AgentProductionOwnerError::Authentication)
            }
        }

        #[test]
        fn real_bootstrap_refused_before_projection_is_retired_joined_and_reopenable() {
            let fixture = physical_fixture();
            let directory = TestDirectory::new("node-production-preflight");
            let pins = BootstrapMemoryStore::default();
            let record = BootstrapMemoryStore::default();
            let issuer = IssuerMemoryStore::default();
            let provider = Arc::new(MemoryProvider::new(fixture.provision.clone()));
            let network = network(NODE_SEED);
            let mut signer = CountingSigner::new();
            let incoming = open_owner(
                &fixture,
                &directory,
                pins.clone(),
                record.clone(),
                issuer.clone(),
                &mut signer,
                Arc::clone(&provider),
                Arc::clone(&network),
            )
            .unwrap();
            let authentications = Arc::new(AtomicUsize::new(0));
            let mut node = crate::node::VosNode::new();
            node.shutdown();
            assert_eq!(
                node.start_clean_agent_production(
                    fixture.plan.pins.node,
                    incoming,
                    Box::new(NeverProjectionAuthenticator(Arc::clone(&authentications))),
                    crate::agent::supervisor::AgentSupervisorLimits::new(8, 4, 4, 1 << 20),
                    8,
                    std::time::Duration::from_secs(60),
                ),
                Err(crate::agent::production_owner::AgentProductionOwnerError::DuplicateHost)
            );
            assert_eq!(authentications.load(Ordering::Acquire), 0);
            assert!(node.clean_agent_supervisor().is_none());
            assert!(node.ingress_handle().clean_agent_supervisor().is_none());
            node.collect_checked().unwrap();

            let reopened = open_owner(
                &fixture,
                &directory,
                pins,
                record,
                issuer,
                &mut signer,
                provider,
                Arc::clone(&network),
            )
            .unwrap();
            assert_eq!(reopened.ordered_index_for_test().unwrap(), 4);
            drop(reopened);
            stop_network(network);
        }

        #[test]
        fn singleton_system_agent_portable_backup_is_authenticated_fresh_and_restartable() {
            let mut harness = NativeProjectionOwnerHarness::new("portable-shared-system");
            let agent = HostAgentId(harness.fixture.plan.pins.agent.0);
            let source_host = Arc::clone(&harness.owner.as_ref().unwrap().host);
            drop(harness.owner.take());

            let limits = crate::agent::shared_host::SharedAgentPortableBackupLimits {
                max_objects: 4096,
                max_blobs: 4096,
                max_index_nodes: 4096,
                max_bytes: 64 * 1024 * 1024,
            };
            let signing_key = SigningKey::from_bytes(&[NODE_SEED; 32]);
            let (backup, source_store, source_position, source_snapshot, management_evidence) = {
                let mut source = source_host.lock().unwrap();
                let candidate = source.request_snapshot_compaction(agent).unwrap();
                let signature = crate::agent::shared_commit::ReplicaCommitSignature::new(
                    candidate.claim().local_node(),
                    signing_key.sign(&candidate.signing_message().0).to_bytes(),
                )
                .unwrap();
                let certificate = crate::agent::shared_commit::SharedAgentSnapshotCertificate::new(
                    candidate.claim().clone(),
                    vec![signature],
                )
                .unwrap();
                source.install_snapshot(agent, &certificate).unwrap();

                let candidate = source.request_portable_backup(agent, limits).unwrap();
                let signature = crate::agent::shared_commit::ReplicaCommitSignature::new(
                    candidate.claim().local_node(),
                    signing_key.sign(&candidate.signing_message().0).to_bytes(),
                )
                .unwrap();
                let certificate =
                    crate::agent::shared_commit::SharedAgentPortableSnapshotCertificate::new(
                        candidate.claim().clone(),
                        vec![signature],
                    )
                    .unwrap();
                let backup = source
                    .export_portable_backup(agent, &certificate, limits)
                    .unwrap();
                (
                    backup,
                    source.journal_store_instance_for_test(agent).unwrap(),
                    source.journal_position(agent).unwrap(),
                    source.snapshot_state_for_test(agent).unwrap(),
                    source.management_evidence_for_test(agent).unwrap().unwrap(),
                )
            };
            assert!(
                !backup
                    .windows(source_store.as_bytes().len())
                    .any(|window| window == source_store.as_bytes())
            );

            let destination = TestDirectory::new("portable-shared-system-destination");
            let scope = AgentHostScope {
                space: HostSpaceId(harness.fixture.plan.pins.space.0),
                node: HostNodeId(harness.fixture.plan.pins.node.0),
            };
            let open_destination = || {
                SharedAgentHost::open_with_root(
                    destination.host(),
                    destination.lock(),
                    scope,
                    Arc::clone(&harness.fixture.trust),
                    Arc::clone(&harness.fixture.merge),
                    Arc::clone(&harness.fixture.finality),
                    harness.fixture.plan.pins.root.clone(),
                )
                .unwrap()
            };
            let mut restored = open_destination();
            let mut tampered = backup.clone();
            let offset = tampered.len() / 2;
            tampered[offset] ^= 0x80;
            assert_eq!(
                restored.restore_portable_backup(&tampered, limits),
                Err(crate::agent::shared_host::SharedAgentHostError::PortableBackupInvalid)
            );
            assert!(restored.is_empty());

            let restored_status = restored.restore_portable_backup(&backup, limits).unwrap();
            let destination_store = restored.journal_store_instance_for_test(agent).unwrap();
            assert_ne!(source_store, destination_store);
            assert_eq!(
                restored.management_evidence_for_test(agent).unwrap(),
                Some(management_evidence.clone())
            );
            assert_eq!(restored.journal_position(agent).unwrap(), source_position);
            let (
                crate::agent::shared_host::SharedAgentSnapshotState::Installed {
                    raft_index: restored_index,
                    raft_term: restored_term,
                    ..
                },
                crate::agent::shared_host::SharedAgentSnapshotState::Installed {
                    raft_index: source_index,
                    raft_term: source_term,
                    ..
                },
            ) = (restored_status.snapshots, source_snapshot)
            else {
                panic!("source and restored checkpoints must both be installed")
            };
            assert_eq!((restored_index, restored_term), (source_index, source_term));
            let stable_status = restored.show(agent).unwrap().unwrap();
            assert_eq!(
                restored.restore_portable_backup(&backup, limits),
                Err(crate::agent::shared_host::SharedAgentHostError::Conflict)
            );
            assert_eq!(restored.show(agent).unwrap().unwrap(), stable_status);
            assert_eq!(
                restored.journal_store_instance_for_test(agent).unwrap(),
                destination_store
            );

            drop(restored);
            let reopened = open_destination();
            assert_eq!(reopened.show(agent).unwrap().unwrap(), stable_status);
            assert_eq!(reopened.journal_position(agent).unwrap(), source_position);
            assert_eq!(
                reopened.management_evidence_for_test(agent).unwrap(),
                Some(management_evidence.clone())
            );
            assert_eq!(
                reopened.journal_store_instance_for_test(agent).unwrap(),
                destination_store
            );
            drop(reopened);

            // The complete authenticated bundle is retained before any
            // generation byte. A process loss at that first durable boundary
            // resumes into the same logical state with another fresh physical
            // store identity, then retires the recovery authority.
            for crash_boundary in 0..4 {
                let interrupted_destination =
                    TestDirectory::new("portable-shared-system-marker-crash");
                let open_interrupted_destination = || {
                    SharedAgentHost::open_with_root(
                        interrupted_destination.host(),
                        interrupted_destination.lock(),
                        scope,
                        Arc::clone(&harness.fixture.trust),
                        Arc::clone(&harness.fixture.merge),
                        Arc::clone(&harness.fixture.finality),
                        harness.fixture.plan.pins.root.clone(),
                    )
                    .unwrap()
                };
                {
                    let mut interrupted = open_interrupted_destination();
                    if crash_boundary >= 2 {
                        assert_eq!(
                            interrupted.restore_portable_backup_through_heads_stage_for_test(
                                &backup, limits
                            ),
                            Err(crate::agent::shared_host::SharedAgentHostError::Unavailable)
                        );
                    } else {
                        assert_eq!(
                            interrupted
                                .retain_portable_restore_marker_for_test(&backup, limits)
                                .unwrap(),
                            agent
                        );
                    }
                    assert!(interrupted.is_empty());
                }
                let marker = interrupted_destination.host().join(format!(
                    "{}.shared-portable-restore",
                    agent
                        .0
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ));
                let staged_marker = marker.with_extension("shared-portable-restore.next");
                let journal = marker.with_extension("agent");
                let staged_heads = if crash_boundary >= 2 {
                    let bytes = std::fs::read(journal.join("heads.next")).unwrap();
                    assert_ne!(bytes, std::fs::read(journal.join("heads")).unwrap());
                    if crash_boundary == 3 {
                        // Journal promotion committed, but the independently
                        // locked Raft ledger still has its genesis state.
                        std::fs::rename(journal.join("heads.next"), journal.join("heads")).unwrap();
                    }
                    Some(bytes)
                } else {
                    None
                };
                if crash_boundary == 1 {
                    std::fs::rename(&marker, &staged_marker).unwrap();
                }
                let recovered = open_interrupted_destination();
                assert!(!marker.exists());
                assert!(!staged_marker.exists());
                if let Some(expected) = staged_heads {
                    assert_eq!(std::fs::read(journal.join("heads")).unwrap(), expected);
                    assert!(!journal.join("heads.next").exists());
                }
                let recovered_store = recovered.journal_store_instance_for_test(agent).unwrap();
                assert_ne!(recovered_store, source_store);
                assert_ne!(recovered_store, destination_store);
                assert_eq!(recovered.journal_position(agent).unwrap(), source_position);
                assert_eq!(
                    recovered.management_evidence_for_test(agent).unwrap(),
                    Some(management_evidence.clone())
                );
                assert!(matches!(
                    recovered.snapshot_state_for_test(agent).unwrap(),
                    crate::agent::shared_host::SharedAgentSnapshotState::Installed {
                        raft_index,
                        raft_term,
                        ..
                    } if (raft_index, raft_term) == (source_index, source_term)
                ));
                drop(recovered);
                let recovered_again = open_interrupted_destination();
                assert_eq!(
                    recovered_again
                        .journal_store_instance_for_test(agent)
                        .unwrap(),
                    recovered_store
                );
                assert_eq!(
                    recovered_again.journal_position(agent).unwrap(),
                    source_position
                );
                drop(recovered_again);
            }
            drop(source_host);
            harness.stop();
        }

        #[test]
        fn credential_sequence_and_derived_invocation_are_part_of_the_plan_boundary() {
            let fixture = physical_fixture();
            assert_eq!(fixture.plan.catalog_call.request_sequence.get(), 1);
            assert_eq!(
                fixture.plan.catalog_call.invocation,
                fixture.plan.catalog_call.expected_invocation()
            );
            let mut stale = fixture.plan.clone();
            stale.catalog_call.request_sequence = NonZeroU64::new(2).unwrap();
            stale.catalog_call.invocation = stale.catalog_call.expected_invocation();
            stale.catalog_call.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
                .sign(&stale.catalog_call.signing_bytes())
                .to_bytes();
            assert_eq!(
                stale.validate(),
                Err(CleanSystemAgentBootstrapRejection::InvalidDecision)
            );

            let mut not_yet_valid = fixture.plan.clone();
            not_yet_valid.catalog_call.requested_valid_from = LOGICAL_SLOT + 1;
            not_yet_valid.catalog_call.requested_expires_at = LOGICAL_SLOT + 2;
            not_yet_valid.catalog_call.invocation =
                not_yet_valid.catalog_call.expected_invocation();
            not_yet_valid.catalog_call.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
                .sign(&not_yet_valid.catalog_call.signing_bytes())
                .to_bytes();
            assert_eq!(
                not_yet_valid.validate(),
                Err(CleanSystemAgentBootstrapRejection::InvalidDecision)
            );

            let mut expired = fixture.plan.clone();
            expired.catalog_call.requested_expires_at = LOGICAL_SLOT - 1;
            expired.catalog_call.invocation = expired.catalog_call.expected_invocation();
            expired.catalog_call.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
                .sign(&expired.catalog_call.signing_bytes())
                .to_bytes();
            assert_eq!(
                expired.validate(),
                Err(CleanSystemAgentBootstrapRejection::InvalidDecision)
            );
        }
    }
}
