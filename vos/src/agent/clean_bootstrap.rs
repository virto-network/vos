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
    AuthorityCredentialVerifier, AuthorityIssuer, AuthorityOperationKind, AuthorityReceipt,
    ManagedAgentTarget, ManagementApplicationAck, ManagementApproval,
};
use super::sdk::package::MAX_PACKAGE_ENCODED_BYTES;
use super::sdk::wire::{
    CanonicalWire, MAX_AGENT_DESCRIPTOR_WIRE_BYTES, MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES,
    MAX_AUTHORITY_RECEIPT_WIRE_BYTES, MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
    MAX_MANAGEMENT_APPROVAL_WIRE_BYTES, MAX_RUNTIME_WORK_WIRE_BYTES,
};
use super::sdk::{
    ActorId, AgentDescriptor, AgentId, AgentProfile, BlobRef, Hash, ManagementRequest, NodeId,
    SpaceId,
};
use crate::service::wire::ServiceWire;

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::bootstrap::{
    SystemAgentGenesisLocator, SystemAgentGenesisProposal, SystemAgentGenesisProvider,
    validate_prepared_system_agent_genesis_root,
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
const CLEAN_SYSTEM_AGENT_PLAN_MAGIC: [u8; 4] = *b"CBP2";
const CLEAN_SYSTEM_AGENT_BOOTSTRAP_MAGIC: [u8; 4] = *b"CSB2";
const CLEAN_SYSTEM_AGENT_BOOTSTRAP_VERSION: u8 = 2;

pub const MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES: usize = MAX_AGENT_DESCRIPTOR_WIRE_BYTES
    + MAX_ROOT_ANCHOR_PINS_BYTES
    + MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + 2 * 1024;
const MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES: usize = 3 * MAX_PACKAGE_ENCODED_BYTES
    + MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES
    + 2 * MAX_AUTHORIZED_DECISION_BYTES
    + MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
    + 2 * MAX_RUNTIME_WORK_WIRE_BYTES
    + 8 * 1024;
pub const MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES: usize = MAX_CLEAN_SYSTEM_AGENT_PLAN_BYTES
    + 3 * MAX_AUTHORITY_RECEIPT_WIRE_BYTES
    + MAX_MANAGEMENT_APPROVAL_WIRE_BYTES
    + MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
    + 8 * 1024;

pub trait CleanSystemAgentBootstrapStore {
    type Error;

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error>;
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

impl AuthorizedCleanSystemAgentBootstrap {
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
        if !self.pins.is_valid() || self.invocation_gas == 0 {
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
            || self.catalog_call.request != self.catalog_request
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
            runtime_deployment: self.pins.descriptor.identity.runtime_deployment,
        }
    }

    fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/clean-system-agent-bootstrap-plan/v2",
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
        encoder.fixed(self.authority_request.commitment().as_bytes());
        encoder.bytes(&self.authority_decision.canonical_bytes());
        encode_large_bytes(&mut encoder, &self.catalog_package_bytes);
        encoder.fixed(self.catalog_request.commitment().as_bytes());
        encoder.bytes(
            &self
                .catalog_call
                .encode()
                .expect("validated credential call"),
        );
        encoder.u64(self.invocation_gas);
        bytes
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
            || Hash::digest(b"vos/clean-system-agent-bootstrap-plan/v2", &[&self.plan])
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
        };
        if !decoder.exhausted() || !value.is_valid() || value.encode() != bytes {
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
    _record_store: R,
    issuer: DurableCleanManagementIssuer<I>,
    _network_host: SharedAgentNetworkHost,
    host: Arc<Mutex<SharedAgentHost>>,
    pins: CleanSystemAgentPins,
    creation_receipt: AuthorityReceipt,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
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
            merge,
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
        let host = Arc::new(Mutex::new(shared_host));
        let network_host = SharedAgentNetworkHost::attach(Arc::clone(&host), network)
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

        Ok(Self {
            _pins_store: pins_store,
            _record_store: record_store,
            issuer,
            _network_host: network_host,
            host,
            pins: plan.pins.clone(),
            creation_receipt: create_receipt,
        })
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
) -> Result<Vec<super::sdk::RuntimeBlob>, CleanSystemAgentBootstrapError> {
    match (&install.entry.installation_data, &install.installation_data) {
        (None, None) => Ok(Vec::new()),
        (Some(expected), Some(data))
            if expected == &data.reference && expected.matches(&data.bytes) =>
        {
            Ok(vec![super::sdk::RuntimeBlob {
                reference: data.reference.clone(),
                bytes: data.bytes.clone(),
            }])
        }
        _ => Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome)),
    }
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
        availability: invocation_availability(install)?,
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
        .invoke_clean(
            crate::service::AgentId(plan.pins.agent.0),
            work.clone(),
            authorization,
        )
        .map_err(CleanSystemAgentBootstrapError::Host)?;
    let super::sdk::RuntimeOutcome::Completed(Ok(reply)) = submission.outcome else {
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

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
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
        return Err(rejected(CleanSystemAgentBootstrapRejection::WrongOutcome));
    };
    let approval = ManagementApproval::decode(&bytes)
        .map_err(|_| rejected(CleanSystemAgentBootstrapRejection::WrongOutcome))?;
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

struct RawCredentialVerifier;

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
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use ed25519_dalek::{Signer as _, SigningKey};

        use super::*;
        use crate::actors::codec::Encode as _;
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
            admitted_standard_actor_for_test, admitted_standard_runtime_for_test,
        };
        use crate::agent::sdk::authority::{
            AuthorityEvidence, AuthorityLaneRoots, AuthorityReceiptSelector,
        };
        use crate::agent::sdk::contract::ActorPackageContract;
        use crate::agent::sdk::introspection::ActorIntrospectionArtifact;
        use crate::agent::sdk::method_policy::ActorMethodPolicyArtifact;
        use crate::agent::sdk::package::{
            ActorPackageManifest, PackageArtifact, PackageEnvelope, PackageManifest, PackageSigning,
        };
        use crate::agent::sdk::schema::{
            ConstructorArgument, ConstructorContract, ParsedField, ParsedInlineField, ParsedSchema,
            RAW_CONSTRUCTOR_TYPE_IDENTITY,
        };
        use crate::agent::sdk::task::TaskDependencySetArtifact;
        use crate::agent::sdk::{
            ActorDirectoryPage, ActorDirectoryRecord, ActorEntry, AgentIdentity, AgentReplica,
            CredentialId, FieldPersistence, InstallationData, InstallationId, InvocationId,
            InvocationObservation, InvocationOrigin, InvocationReply, InvocationRoleClaims,
            InvocationStatus, InvocationWork, LaneSet, ManagementReply, MethodMode, PrincipalId,
            ProducerId, ProofSystemSet, ReplicaRole, RuntimeOutcome, RuntimeRequirements,
            RuntimeTransition, StateLane,
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

        #[derive(Clone, Default)]
        struct IssuerMemoryStore {
            image: Arc<Mutex<Option<Vec<u8>>>>,
        }

        impl CleanManagementIssuerStore for IssuerMemoryStore {
            type Error = MemoryError;

            fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.image.lock().unwrap().clone())
            }

            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                *self.image.lock().unwrap() = Some(image.to_vec());
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
        }

        impl AgentTrustProvider for PhysicalTrust {
            fn current_logical_slot(&self) -> Option<u64> {
                Some(LOGICAL_SLOT)
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
                },
                creation_nonce: nonce,
                authority,
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
                    runtime_deployment: descriptor.identity.runtime_deployment,
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
                request: request.clone(),
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
            let mut bytes = Vec::with_capacity(193);
            bytes.extend_from_slice(identity.space.as_bytes());
            bytes.extend_from_slice(identity.agent.as_bytes());
            bytes.extend_from_slice(identity.owner.as_bytes());
            bytes.push(identity.profile as u8);
            bytes.extend_from_slice(identity.runtime_deployment.as_bytes());
            bytes.extend_from_slice(identity.runtime_program.as_bytes());
            bytes.extend_from_slice(identity.runtime_producer.as_bytes());
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
        ) -> InvocationWork {
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
                availability: vec![crate::agent::sdk::RuntimeBlob {
                    reference: installation_data.reference.clone(),
                    bytes: installation_data.bytes.clone(),
                }],
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
            let placeholder = admitted_standard_runtime_for_test("shape-only-r7", 0x63);
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
            let runtime =
                admitted_scripted_runtime_for_test("system-bootstrap-current-abi", 0x64, cases);
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
                HostHash([0xb2; 32]),
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
            trust: Arc<dyn AgentTrustProvider>,
            merge: Arc<dyn LocalMergeAuthenticator>,
            finality: Arc<dyn AgentGenesisFinalityVerifier>,
        }

        fn physical_fixture() -> PhysicalFixture {
            let runtime = runtime_fixture();
            assert_eq!(runtime.catalog_approval.request, runtime.catalog_request);
            let create_request = ManagementRequest::Create(Box::new(runtime.descriptor.clone()));
            let create_decision = decision(&runtime.descriptor, &create_request, 1, 0x71);
            let authority_decision =
                decision(&runtime.descriptor, &runtime.authority_request, 2, 0x72);

            let mut receipt_signer = CountingSigner::new();
            let mut temporary_issuer = DurableCleanManagementIssuer::open(
                IssuerMemoryStore::default(),
                runtime.descriptor.authority,
                runtime.descriptor.identity.space,
                runtime.descriptor.identity.agent,
            )
            .unwrap();
            let create_receipt = temporary_issuer
                .issue(&create_decision, &mut receipt_signer)
                .unwrap();
            let host_authority = host_authority_binding(&runtime.descriptor);
            let trust: Arc<dyn AgentTrustProvider> = Arc::new(PhysicalTrust {
                authority: host_authority,
            });
            let (node_key, _, _, node) = node_material();
            let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(SigningMerge {
                key: node_key,
                node,
            });
            let (create, catalog) =
                LocalJournalAgentDriver::<FileAgentJournalStore>::clean_shared_system_genesis_input(
                    runtime.descriptor.clone(),
                    &runtime.runtime,
                    create_receipt,
                    LOGICAL_SLOT,
                    &trust,
                    &merge,
                )
                .unwrap();
            let replica = runtime.replicas.members()[0].replica();
            let prepared =
                LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
                    create,
                    replica,
                    &catalog,
                    Arc::clone(&trust),
                    Arc::clone(&merge),
                )
                .unwrap();
            let locator = SystemAgentGenesisLocator {
                space: HostSpaceId(runtime.descriptor.identity.space.0),
                agent: HostAgentId(runtime.descriptor.identity.agent.0),
                node,
            };
            let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
            let (root, provision) = root_provision(proposal, &runtime.descriptor);
            let plan = AuthorizedCleanSystemAgentBootstrap::new(
                runtime.descriptor,
                runtime.runtime.exact_bytes().to_vec(),
                runtime.replicas,
                root,
                LOGICAL_SLOT,
                create_decision,
                runtime.authority_package.exact_bytes().to_vec(),
                runtime.authority_request,
                authority_decision,
                runtime.catalog_package.exact_bytes().to_vec(),
                runtime.catalog_request,
                runtime.catalog_call,
                1_000_000,
            )
            .unwrap();
            PhysicalFixture {
                plan,
                provision,
                trust,
                merge,
                finality: Arc::new(AcceptFinality),
            }
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

        fn exercise_restart_mode(failure: RecordFailure, label: &str) {
            let fixture = physical_fixture();
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
                    Err(CleanSystemAgentBootstrapError::RecordStorage) => {}
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
