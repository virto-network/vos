//! Crash-safe bootstrap owner for one clean Local system Agent.
//!
//! This module owns only mechanics. It neither selects authority policy nor
//! holds a signing key or manufactures an artifact. A caller supplies one
//! exact VOS3 runtime package, an immutable SDK descriptor, an explicit
//! already-authorized Create decision, a logical observation slot, and an
//! external signer. The owner persists independent pins and a replay intent
//! before asking the durable issuer to pledge or sign anything.

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use std::{fs, io::ErrorKind, path::Path};

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use super::clean_authority_issuer::{
    AuthorizedCleanManagementDecision, CleanManagementIssuerError, CleanManagementIssuerRejection,
    CleanManagementIssuerStore, CleanManagementReceiptSigner, DurableCleanManagementIssuer,
    MAX_AUTHORIZED_DECISION_BYTES,
};
use super::local_sdk_host::{CleanAgentLogicalClock, LocalAgentHost, LocalAgentHostError};
use super::package_admission::{AdmittedRuntimePackage, admit_runtime_package};
use super::sdk::authority::{
    AgentAuthorityBinding, AuthorityIssuer, AuthorityOperationKind, AuthorityReceipt,
};
use super::sdk::package::MAX_PACKAGE_ENCODED_BYTES;
use super::sdk::wire::{
    CanonicalWire, MAX_AGENT_DESCRIPTOR_WIRE_BYTES, MAX_AUTHORITY_RECEIPT_WIRE_BYTES,
};
use super::sdk::{
    AgentDescriptor, AgentId, AgentProfile, BlobRef, Hash, ManagementRequest, NodeId, SpaceId,
};

const CLEAN_SYSTEM_AGENT_PINS_MAGIC: [u8; 4] = *b"CSP1";
const CLEAN_SYSTEM_AGENT_BOOTSTRAP_MAGIC: [u8; 4] = *b"CSB1";
const CLEAN_SYSTEM_AGENT_BOOTSTRAP_VERSION: u8 = 1;

/// Complete maximum for independently provisioned immutable system-Agent
/// pins. The nested descriptor remains subject to its SDK bound.
pub const MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES: usize = MAX_AGENT_DESCRIPTOR_WIRE_BYTES + 512;
/// Complete maximum for one bootstrap image. It includes the exact admitted
/// VOS3 runtime envelope rather than a path or a process-local artifact.
pub const MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES: usize = MAX_PACKAGE_ENCODED_BYTES
    + MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES
    + MAX_AUTHORIZED_DECISION_BYTES
    + MAX_AUTHORITY_RECEIPT_WIRE_BYTES
    + 4 * 1024;

/// Minimal whole-image persistence seam for clean bootstrap metadata.
///
/// Pins and the bootstrap journal use distinct instances of this trait.
/// `commit` returns success only once every byte is recoverable following a
/// restart. An error may mean that no bytes or all bytes became durable, so
/// callers must drop the owner and reopen. Implementations are single-writer
/// and must atomically replace the complete image; they must not normalize it.
pub trait CleanSystemAgentBootstrapStore {
    type Error;

    /// Load at most `maximum_bytes`; an oversized durable object must be
    /// rejected before allocating or returning its body.
    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

/// Independently persisted immutable identity of the clean system Agent.
/// Redundant route fields are deliberate: neither an archive nor a signed
/// receipt may select the Space, Agent, node, authority, or runtime package
/// that the owner intended to create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanSystemAgentPins {
    space: SpaceId,
    agent: AgentId,
    node: NodeId,
    authority: AgentAuthorityBinding,
    runtime_package: BlobRef,
    descriptor: AgentDescriptor,
}

impl CleanSystemAgentPins {
    pub fn from_descriptor(
        descriptor: AgentDescriptor,
    ) -> Result<Self, CleanSystemAgentBootstrapRejection> {
        let node = descriptor
            .replicas
            .first()
            .map(|replica| replica.node)
            .ok_or(CleanSystemAgentBootstrapRejection::InvalidDescriptor)?;
        let value = Self {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            node,
            authority: descriptor.authority,
            runtime_package: descriptor.runtime_package.clone(),
            descriptor,
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

    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/clean-system-agent-pins/v1", &[&self.encode()])
    }

    fn is_valid(&self) -> bool {
        self.descriptor.validate().is_ok()
            && self.descriptor.identity.profile == AgentProfile::Local
            && self.descriptor.replicas.len() == 1
            && self.space == self.descriptor.identity.space
            && self.agent == self.descriptor.identity.agent
            && self.node == self.descriptor.replicas[0].node
            && self.authority == self.descriptor.authority
            && self.runtime_package == self.descriptor.runtime_package
    }

    fn encode(&self) -> Vec<u8> {
        let descriptor = self
            .descriptor
            .encode()
            .expect("validated clean system-Agent descriptor encodes");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CLEAN_SYSTEM_AGENT_PINS_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
        encoder.fixed(self.space.as_bytes());
        encoder.fixed(self.agent.as_bytes());
        encoder.fixed(self.node.as_bytes());
        encode_authority_binding(&mut encoder, self.authority);
        encode_blob_ref(&mut encoder, &self.runtime_package);
        encoder.bytes(&descriptor);
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
            descriptor: AgentDescriptor::decode(
                &decoder.bytes_bounded(MAX_AGENT_DESCRIPTOR_WIRE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
        };
        if !decoder.exhausted() || !value.is_valid() || value.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Explicit policy-approved material for one fresh clean system Agent.
/// Construction admits the exact VOS3 bytes immediately and proves that the
/// descriptor and Create decision select that complete package and authority.
#[derive(Clone)]
pub struct AuthorizedCleanSystemAgentBootstrap {
    pins: CleanSystemAgentPins,
    runtime_package_bytes: Vec<u8>,
    decision: AuthorizedCleanManagementDecision,
}

impl AuthorizedCleanSystemAgentBootstrap {
    pub fn new(
        descriptor: AgentDescriptor,
        runtime_package_bytes: Vec<u8>,
        decision: AuthorizedCleanManagementDecision,
    ) -> Result<Self, CleanSystemAgentBootstrapRejection> {
        let pins = CleanSystemAgentPins::from_descriptor(descriptor)?;
        let runtime = admit_runtime_package(&runtime_package_bytes)
            .map_err(|_| CleanSystemAgentBootstrapRejection::InvalidRuntimePackage)?;
        if !runtime_matches_pins(&runtime, &pins) || !decision.matches_creation(pins.descriptor()) {
            return Err(CleanSystemAgentBootstrapRejection::InvalidDecision);
        }
        Ok(Self {
            pins,
            runtime_package_bytes,
            decision,
        })
    }

    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }

    pub fn runtime_package_bytes(&self) -> &[u8] {
        &self.runtime_package_bytes
    }

    pub const fn decision(&self) -> &AuthorizedCleanManagementDecision {
        &self.decision
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CleanSystemAgentBootstrapPhase {
    Intent = 0,
    ReceiptIssued = 1,
    Complete = 2,
}

/// Canonical recovery journal. The intent contains the exact approved
/// decision before issuance; later phases additionally contain the exact
/// signed receipt. `Complete` is written only after issuer observation of an
/// exact durably reopened Agent image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanSystemAgentBootstrapRecord {
    phase: CleanSystemAgentBootstrapPhase,
    pins: CleanSystemAgentPins,
    pins_commitment: Hash,
    runtime_package_bytes: Vec<u8>,
    decision: AuthorizedCleanManagementDecision,
    receipt: Option<AuthorityReceipt>,
}

impl CleanSystemAgentBootstrapRecord {
    pub const fn phase(&self) -> CleanSystemAgentBootstrapPhase {
        self.phase
    }

    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }

    pub fn runtime_package_bytes(&self) -> &[u8] {
        &self.runtime_package_bytes
    }

    pub const fn decision(&self) -> &AuthorizedCleanManagementDecision {
        &self.decision
    }

    pub const fn receipt(&self) -> Option<&AuthorityReceipt> {
        self.receipt.as_ref()
    }

    fn intent(plan: &AuthorizedCleanSystemAgentBootstrap) -> Self {
        Self {
            phase: CleanSystemAgentBootstrapPhase::Intent,
            pins: plan.pins.clone(),
            pins_commitment: plan.pins.commitment(),
            runtime_package_bytes: plan.runtime_package_bytes.clone(),
            decision: plan.decision.clone(),
            receipt: None,
        }
    }

    fn with_receipt(&self, receipt: AuthorityReceipt) -> Self {
        let mut next = self.clone();
        next.phase = CleanSystemAgentBootstrapPhase::ReceiptIssued;
        next.receipt = Some(receipt);
        next
    }

    fn completed(&self) -> Self {
        let mut next = self.clone();
        next.phase = CleanSystemAgentBootstrapPhase::Complete;
        next
    }

    fn matches_plan(&self, plan: &AuthorizedCleanSystemAgentBootstrap) -> bool {
        self.pins == plan.pins
            && self.pins_commitment == plan.pins.commitment()
            && self.runtime_package_bytes == plan.runtime_package_bytes
            && self.decision == plan.decision
    }

    fn is_valid(&self) -> bool {
        if !self.pins.is_valid()
            || self.pins_commitment != self.pins.commitment()
            || !self.decision.matches_creation(self.pins.descriptor())
            || BlobRef::of_bytes(&self.runtime_package_bytes) != self.pins.runtime_package
        {
            return false;
        }
        let Ok(runtime) = admit_runtime_package(&self.runtime_package_bytes) else {
            return false;
        };
        if !runtime_matches_pins(&runtime, &self.pins) {
            return false;
        }
        match (self.phase, self.receipt.as_ref()) {
            (CleanSystemAgentBootstrapPhase::Intent, None) => true,
            (
                CleanSystemAgentBootstrapPhase::ReceiptIssued
                | CleanSystemAgentBootstrapPhase::Complete,
                Some(receipt),
            ) => exact_creation_receipt(&self.pins, &self.decision, receipt),
            _ => false,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let pins = self.pins.encode();
        let decision = self.decision.canonical_bytes();
        let receipt = self.receipt.as_ref().map(|receipt| {
            receipt
                .encode()
                .expect("validated clean bootstrap receipt encodes")
        });
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CLEAN_SYSTEM_AGENT_BOOTSTRAP_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
        encoder.u8(CLEAN_SYSTEM_AGENT_BOOTSTRAP_VERSION);
        encoder.u8(self.phase as u8);
        encoder.fixed(self.pins_commitment.as_bytes());
        encoder.bytes(&pins);
        encode_large_bytes(&mut encoder, &self.runtime_package_bytes);
        encoder.bytes(&decision);
        encoder.option(&receipt, |encoder, receipt| encoder.bytes(receipt));
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
            1 => CleanSystemAgentBootstrapPhase::ReceiptIssued,
            2 => CleanSystemAgentBootstrapPhase::Complete,
            _ => return Err(DecodeError::InvalidTag),
        };
        let pins_commitment = Hash(decoder.fixed()?);
        let pins = CleanSystemAgentPins::decode(
            &decoder.bytes_bounded(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)?,
        )?;
        let runtime_package_bytes = decode_large_bytes(&mut decoder, MAX_PACKAGE_ENCODED_BYTES)?;
        let decision = AuthorizedCleanManagementDecision::from_bootstrap_canonical_bytes(
            &decoder.bytes_bounded(MAX_AUTHORIZED_DECISION_BYTES)?,
            pins.descriptor(),
        )?;
        let receipt = decoder.option(|decoder| {
            AuthorityReceipt::decode(&decoder.bytes_bounded(MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)
        })?;
        let value = Self {
            phase,
            pins,
            pins_commitment,
            runtime_package_bytes,
            decision,
            receipt,
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
    InvalidDecision,
    InvalidPins,
    MissingPins,
    InvalidRecord,
    MissingRecord,
    DivergentPins,
    DivergentRecord,
    WrongScope,
    WrongAuthority,
    WrongReceipt,
    MissingIssuerState,
    DivergentIssuerState,
    LegacyOrDivergentHost,
}

#[derive(Debug)]
pub enum CleanSystemAgentBootstrapError {
    PinsStorage,
    RecordStorage,
    IssuerStorage,
    Signer,
    InvalidIssuerState,
    IssuerRejected(CleanManagementIssuerRejection),
    Host(LocalAgentHostError),
    Rejected(CleanSystemAgentBootstrapRejection),
}

impl fmt::Display for CleanSystemAgentBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "clean system-Agent bootstrap failed: {self:?}")
    }
}

impl core::error::Error for CleanSystemAgentBootstrapError {}

/// Exclusive owner of the bootstrap metadata, issuer journal, and clean
/// Local host root. The signer is borrowed only during `open_or_bootstrap` and
/// is never retained. Mutable host/issuer access is intentionally not exposed:
/// future lifecycle coordinators must preserve the same commit-before-observe
/// proof boundary rather than acknowledging an in-memory result.
pub struct CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    _pins_store: P,
    _record_store: R,
    issuer: DurableCleanManagementIssuer<I>,
    host: LocalAgentHost,
    pins: CleanSystemAgentPins,
    receipt: AuthorityReceipt,
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    #[allow(clippy::too_many_arguments)]
    pub fn open_or_bootstrap<S: CleanManagementReceiptSigner>(
        pins_store: P,
        record_store: R,
        issuer_store: I,
        signer: &mut S,
        plan: &AuthorizedCleanSystemAgentBootstrap,
        clean_host_root: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_node: NodeId,
        observed_slot: u64,
    ) -> Result<Self, CleanSystemAgentBootstrapError> {
        validate_plan_scope(plan, expected_space, expected_node)?;
        let root = clean_host_root.as_ref();
        let root_exists = host_root_exists(root)?;
        let coordinated = coordinate_bootstrap(
            pins_store,
            record_store,
            issuer_store,
            signer,
            plan,
            root_exists,
            |record, allow_create| {
                open_exact_host(
                    root,
                    record,
                    expected_space,
                    expected_node,
                    observed_slot,
                    allow_create,
                )
            },
        )?;
        Ok(Self {
            _pins_store: coordinated.pins_store,
            _record_store: coordinated.record_store,
            issuer: coordinated.issuer,
            host: coordinated.host,
            pins: coordinated.pins,
            receipt: coordinated.receipt,
        })
    }

    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }

    pub const fn creation_receipt(&self) -> &AuthorityReceipt {
        &self.receipt
    }

    pub const fn host(&self) -> &LocalAgentHost {
        &self.host
    }

    pub const fn issuer_sequence_high_water(&self) -> u64 {
        self.issuer.sequence_high_water()
    }

    pub const fn issuer_acknowledged_through(&self) -> u64 {
        self.issuer.acknowledged_through()
    }
}

struct CoordinatedBootstrap<P, R, I, H>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    pins_store: P,
    record_store: R,
    issuer: DurableCleanManagementIssuer<I>,
    host: H,
    pins: CleanSystemAgentPins,
    receipt: AuthorityReceipt,
}

#[allow(clippy::too_many_arguments)]
fn coordinate_bootstrap<P, R, I, S, H>(
    mut pins_store: P,
    mut record_store: R,
    issuer_store: I,
    signer: &mut S,
    plan: &AuthorizedCleanSystemAgentBootstrap,
    host_root_exists: bool,
    mut open_host: impl FnMut(
        &CleanSystemAgentBootstrapRecord,
        bool,
    ) -> Result<H, CleanSystemAgentBootstrapError>,
) -> Result<CoordinatedBootstrap<P, R, I, H>, CleanSystemAgentBootstrapError>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    S: CleanManagementReceiptSigner,
{
    let loaded_pins = pins_store
        .load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)
        .map_err(|_| CleanSystemAgentBootstrapError::PinsStorage)?;
    let loaded_record = record_store
        .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
        .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)?;
    if loaded_record.is_some() && loaded_pins.is_none() {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::MissingPins,
        ));
    }

    let existing_pins = loaded_pins
        .as_deref()
        .map(CleanSystemAgentPins::decode)
        .transpose()
        .map_err(|_| {
            CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::InvalidPins,
            )
        })?;
    if existing_pins
        .as_ref()
        .is_some_and(|pins| pins != plan.pins())
    {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::DivergentPins,
        ));
    }

    let existing_record = loaded_record
        .as_deref()
        .map(CleanSystemAgentBootstrapRecord::decode)
        .transpose()
        .map_err(|_| {
            CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::InvalidRecord,
            )
        })?;
    if existing_record
        .as_ref()
        .is_some_and(|record| !record.matches_plan(plan))
    {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::DivergentRecord,
        ));
    }

    let mut issuer = DurableCleanManagementIssuer::open(
        issuer_store,
        plan.pins.authority,
        plan.pins.space,
        plan.pins.agent,
    )
    .map_err(map_issuer_open_error)?;
    if existing_record.is_none()
        && host_root_exists
        && existing_pins.is_none()
        && issuer.sequence_high_water() == 0
        && issuer.acknowledged_through() == 0
        && !issuer.has_pending_decision()
    {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
        ));
    }
    if existing_record.is_none()
        && (host_root_exists
            || issuer.sequence_high_water() != 0
            || issuer.acknowledged_through() != 0
            || issuer.has_pending_decision())
    {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::MissingRecord,
        ));
    }
    if issuer.sequence_high_water() > 1 || issuer.acknowledged_through() > 1 {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::DivergentIssuerState,
        ));
    }
    if existing_record.as_ref().is_some_and(|record| {
        (record.receipt.is_some() && issuer.sequence_high_water() == 0)
            || (record.phase == CleanSystemAgentBootstrapPhase::Intent
                && issuer.acknowledged_through() != 0)
    }) {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::MissingIssuerState,
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
            let record = CleanSystemAgentBootstrapRecord::intent(plan);
            record_store
                .commit(&record.encode())
                .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)?;
            record
        }
    };

    if record.phase == CleanSystemAgentBootstrapPhase::Complete {
        if issuer.sequence_high_water() == 0 || issuer.acknowledged_through() == 0 {
            return Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::MissingIssuerState,
            ));
        }
        let receipt = record
            .receipt
            .clone()
            .ok_or(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::WrongReceipt,
            ))?;
        let replayed = issuer
            .issue(&record.decision, signer)
            .map_err(map_issuer_issue_error)?;
        if replayed != receipt {
            return Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::WrongReceipt,
            ));
        }
        let host = open_host(&record, false)?;
        return Ok(CoordinatedBootstrap {
            pins_store,
            record_store,
            issuer,
            host,
            pins: record.pins,
            receipt,
        });
    }

    let issued = issuer
        .issue(&record.decision, signer)
        .map_err(map_issuer_issue_error)?;
    if !exact_creation_receipt(&record.pins, &record.decision, &issued) {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::WrongReceipt,
        ));
    }
    match record.receipt.as_ref() {
        Some(existing) if existing != &issued => {
            return Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::WrongReceipt,
            ));
        }
        Some(_) => {}
        None => {
            record = record.with_receipt(issued.clone());
            record_store
                .commit(&record.encode())
                .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)?;
        }
    }

    // This closure is the only proof-producing boundary in the protocol. Its
    // success means the exact descriptor, package, request disposition, and
    // resulting Agent image can be reopened after a crash. Only then may the
    // issuer watermark advance.
    let host = open_host(&record, true)?;
    issuer
        .observe_durable(&issued)
        .map_err(map_issuer_observation_error)?;
    if issuer.acknowledged_through() < issued.selector.decision_sequence {
        return Err(CleanSystemAgentBootstrapError::InvalidIssuerState);
    }
    record = record.completed();
    record_store
        .commit(&record.encode())
        .map_err(|_| CleanSystemAgentBootstrapError::RecordStorage)?;

    Ok(CoordinatedBootstrap {
        pins_store,
        record_store,
        issuer,
        host,
        pins: record.pins,
        receipt: issued,
    })
}

fn host_root_exists(root: &Path) -> Result<bool, CleanSystemAgentBootstrapError> {
    match fs::symlink_metadata(root) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CleanSystemAgentBootstrapError::Host(
            LocalAgentHostError::Io,
        )),
    }
}

fn validate_plan_scope(
    plan: &AuthorizedCleanSystemAgentBootstrap,
    expected_space: SpaceId,
    expected_node: NodeId,
) -> Result<(), CleanSystemAgentBootstrapError> {
    if expected_space == SpaceId::ZERO
        || expected_node == NodeId::ZERO
        || plan.pins.space != expected_space
        || plan.pins.node != expected_node
    {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::WrongScope,
        ));
    }
    if plan.pins.authority != plan.pins.descriptor.authority {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::WrongAuthority,
        ));
    }
    Ok(())
}

fn open_exact_host(
    root: &Path,
    record: &CleanSystemAgentBootstrapRecord,
    expected_space: SpaceId,
    expected_node: NodeId,
    observed_slot: u64,
    allow_create: bool,
) -> Result<LocalAgentHost, CleanSystemAgentBootstrapError> {
    let clock: Arc<dyn CleanAgentLogicalClock> = Arc::new(FixedLogicalClock(observed_slot));
    let root_exists = match fs::symlink_metadata(root) {
        Ok(_) => true,
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(_) => {
            return Err(CleanSystemAgentBootstrapError::Host(
                LocalAgentHostError::Io,
            ));
        }
    };
    let mut host = if root_exists {
        LocalAgentHost::open_with_clean_clock(root, expected_space, expected_node, clock)
    } else if allow_create {
        LocalAgentHost::create_with_clean_clock(root, expected_space, expected_node, clock)
    } else {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
        ));
    }
    .map_err(|error| match error {
        LocalAgentHostError::InvalidRoot
        | LocalAgentHostError::InvalidScope
        | LocalAgentHostError::InvalidDescriptor
        | LocalAgentHostError::Corrupt
        | LocalAgentHostError::Alias
        | LocalAgentHostError::AlreadyExists => CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
        ),
        other => CleanSystemAgentBootstrapError::Host(other),
    })?;

    let admitted = admit_runtime_package(&record.runtime_package_bytes).map_err(|_| {
        CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::InvalidRuntimePackage,
        )
    })?;
    match host.show(record.pins.agent) {
        Ok(descriptor) if descriptor != &record.pins.descriptor => {
            return Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
            ));
        }
        Ok(_) => {
            host.create_agent(
                admitted,
                record.pins.descriptor.clone(),
                record
                    .receipt
                    .clone()
                    .ok_or(CleanSystemAgentBootstrapError::Rejected(
                        CleanSystemAgentBootstrapRejection::WrongReceipt,
                    ))?,
            )
            .map_err(CleanSystemAgentBootstrapError::Host)?;
        }
        Err(LocalAgentHostError::NotFound) if allow_create => {
            let receipt =
                record
                    .receipt
                    .clone()
                    .ok_or(CleanSystemAgentBootstrapError::Rejected(
                        CleanSystemAgentBootstrapRejection::WrongReceipt,
                    ))?;
            if !receipt.selector.is_live_at(observed_slot) {
                return Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::WrongReceipt,
                ));
            }
            host.create_agent(admitted, record.pins.descriptor.clone(), receipt)
                .map_err(CleanSystemAgentBootstrapError::Host)?;
        }
        Err(LocalAgentHostError::NotFound) => {
            return Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
            ));
        }
        Err(error) => return Err(CleanSystemAgentBootstrapError::Host(error)),
    }
    if host.show(record.pins.agent).ok() != Some(&record.pins.descriptor) {
        return Err(CleanSystemAgentBootstrapError::Rejected(
            CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
        ));
    }
    Ok(host)
}

fn exact_creation_receipt(
    pins: &CleanSystemAgentPins,
    decision: &AuthorizedCleanManagementDecision,
    receipt: &AuthorityReceipt,
) -> bool {
    receipt.validate_shape().is_ok()
        && pins.authority.accepts(receipt)
        && receipt.selector.space == pins.space
        && receipt.selector.agent == pins.agent
        && receipt.selector.operation == AuthorityOperationKind::CreateAgent
        && receipt.selector.runtime_deployment == pins.descriptor.identity.runtime_deployment
        && receipt.selector.actor.is_none()
        && receipt.selector.actor_deployment.is_none()
        && receipt.selector.decision_sequence == 1
        && receipt.selector.acknowledged_through == 0
        && receipt.selector.request
            == ManagementRequest::Create(Box::new(pins.descriptor.clone())).commitment()
        && decision.matches_receipt(pins.authority, receipt)
        && super::authority::verify_raw_ed25519(
            &receipt.public_key,
            &receipt.signing_bytes(),
            &receipt.signature,
        )
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

fn map_issuer_open_error<StorageError>(
    error: CleanManagementIssuerError<StorageError>,
) -> CleanSystemAgentBootstrapError {
    match error {
        CleanManagementIssuerError::Storage(_) => CleanSystemAgentBootstrapError::IssuerStorage,
        CleanManagementIssuerError::Signer(never) => match never {},
        CleanManagementIssuerError::InvalidState => {
            CleanSystemAgentBootstrapError::InvalidIssuerState
        }
        CleanManagementIssuerError::Rejected(rejection) => {
            CleanSystemAgentBootstrapError::IssuerRejected(rejection)
        }
    }
}

fn map_issuer_issue_error<StorageError, SignerError>(
    error: CleanManagementIssuerError<StorageError, SignerError>,
) -> CleanSystemAgentBootstrapError {
    match error {
        CleanManagementIssuerError::Storage(_) => CleanSystemAgentBootstrapError::IssuerStorage,
        CleanManagementIssuerError::Signer(_) => CleanSystemAgentBootstrapError::Signer,
        CleanManagementIssuerError::InvalidState => {
            CleanSystemAgentBootstrapError::InvalidIssuerState
        }
        CleanManagementIssuerError::Rejected(rejection) => {
            CleanSystemAgentBootstrapError::IssuerRejected(rejection)
        }
    }
}

fn map_issuer_observation_error<StorageError>(
    error: CleanManagementIssuerError<StorageError>,
) -> CleanSystemAgentBootstrapError {
    map_issuer_open_error(error)
}

#[derive(Clone, Copy)]
struct FixedLogicalClock(u64);

impl CleanAgentLogicalClock for FixedLogicalClock {
    fn current_logical_slot(&self) -> Option<u64> {
        Some(self.0)
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
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
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
        actor: super::sdk::ActorId(decoder.fixed()?),
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
    let source = decoder.take(length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| DecodeError::LimitExceeded)?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::clean_authority_issuer::CleanManagementDecisionContext;
    use crate::agent::sdk::authority::{AuthorityEvidence, AuthorityLaneRoots};
    use crate::agent::sdk::contract::RuntimePackageContract;
    use crate::agent::sdk::package::{
        AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope, PackageManifest,
        PackageSigning,
    };
    use crate::agent::sdk::{
        ActorId, AgentIdentity, AgentReplica, DeploymentId, PrincipalId, ProducerId, ProgramId,
        ReplicaRole, RuntimeCapabilities,
    };

    const PACKAGE_SEED: [u8; 32] = [0x61; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x62; 32];
    const RUNTIME_PVM: &[u8] = include_bytes!("../../../vosx/blobs/agent_runtime.pvm");
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-clean-bootstrap-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn child(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MemoryStoreError;

    impl fmt::Display for MemoryStoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected memory-store failure")
        }
    }

    impl std::error::Error for MemoryStoreError {}

    #[derive(Clone, Copy, Debug)]
    enum FailureMode {
        Before,
        After,
    }

    #[derive(Default)]
    struct MemoryStoreState {
        image: Option<Vec<u8>>,
        commits: usize,
        failure: Option<(usize, FailureMode)>,
    }

    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<MemoryStoreState>>);

    impl MemoryStore {
        fn fail_on(&self, commit: usize, mode: FailureMode) {
            self.0.lock().unwrap().failure = Some((commit, mode));
        }

        fn image(&self) -> Option<Vec<u8>> {
            self.0.lock().unwrap().image.clone()
        }

        fn clear(&self) {
            self.0.lock().unwrap().image = None;
        }

        fn replace(&self, image: Vec<u8>) {
            self.0.lock().unwrap().image = Some(image);
        }

        fn commit_image(&self, image: &[u8]) -> Result<(), MemoryStoreError> {
            let mut state = self.0.lock().unwrap();
            let commit = state.commits;
            state.commits += 1;
            if matches!(state.failure, Some((target, FailureMode::Before)) if target == commit) {
                state.failure = None;
                return Err(MemoryStoreError);
            }
            state.image = Some(image.to_vec());
            if matches!(state.failure, Some((target, FailureMode::After)) if target == commit) {
                state.failure = None;
                return Err(MemoryStoreError);
            }
            Ok(())
        }
    }

    impl CleanSystemAgentBootstrapStore for MemoryStore {
        type Error = MemoryStoreError;

        fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
            let image = self.image();
            if image
                .as_ref()
                .is_some_and(|image| image.len() > maximum_bytes)
            {
                return Err(MemoryStoreError);
            }
            Ok(image)
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.commit_image(image)
        }
    }

    impl CleanManagementIssuerStore for MemoryStore {
        type Error = MemoryStoreError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.image())
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.commit_image(image)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SignerError;

    impl fmt::Display for SignerError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected signer failure")
        }
    }

    impl std::error::Error for SignerError {}

    struct CountingSigner {
        key: SigningKey,
        calls: usize,
    }

    impl CountingSigner {
        fn new(seed: [u8; 32]) -> Self {
            Self {
                key: SigningKey::from_bytes(&seed),
                calls: 0,
            }
        }
    }

    impl CleanManagementReceiptSigner for CountingSigner {
        type Error = SignerError;

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

    #[derive(Clone)]
    struct Fixture {
        space: SpaceId,
        node: NodeId,
        descriptor: AgentDescriptor,
        plan: AuthorizedCleanSystemAgentBootstrap,
    }

    fn signed_runtime_package(package_seed: [u8; 32]) -> Vec<u8> {
        let key = SigningKey::from_bytes(&package_seed);
        let public_key = key.verifying_key().to_bytes();
        let mut package = PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "clean-system-runtime".into(),
                outer_program: BlobRef::of_bytes(RUNTIME_PVM),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                signing: PackageSigning {
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                    signature: [0; 64],
                },
            }),
            artifacts: vec![PackageArtifact {
                identity: BlobRef::of_bytes(RUNTIME_PVM),
                bytes: RUNTIME_PVM.to_vec(),
            }],
        };
        let signing_bytes = package.signing_bytes().unwrap();
        package.manifest.signing_mut().signature = key.sign(&signing_bytes).to_bytes();
        package.encode().unwrap()
    }

    fn make_fixture(authority_seed: [u8; 32], discriminator: u8) -> Fixture {
        let space = SpaceId([0x11; 32]);
        let node = NodeId([0x12; 32]);
        let runtime_bytes = signed_runtime_package(PACKAGE_SEED);
        let runtime = admit_runtime_package(&runtime_bytes).unwrap();
        let authority_key = SigningKey::from_bytes(&authority_seed);
        let authority_public_key = authority_key.verifying_key().to_bytes();
        let owner = PrincipalId([discriminator; 32]);
        let creation_nonce = Hash([discriminator.wrapping_add(0x20); 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: Hash([0x31; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x32; 32]),
                    actor: ActorId([0x33; 32]),
                    deployment: DeploymentId([0x34; 32]),
                    program: ProgramId([0x35; 32]),
                    producer: ProducerId::of_public_key(&authority_public_key),
                },
                public_key: authority_public_key,
                initial_epoch: 1,
            },
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![AgentReplica {
                node,
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();
        let request = ManagementRequest::Create(Box::new(descriptor.clone()));
        let decision = AuthorizedCleanManagementDecision::new(
            NonZeroU64::new(1).unwrap(),
            CleanManagementDecisionContext {
                space,
                agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x36; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                valid_from: 10,
                expires_at: 20,
            },
            &request,
        )
        .unwrap();
        let plan =
            AuthorizedCleanSystemAgentBootstrap::new(descriptor.clone(), runtime_bytes, decision)
                .unwrap();
        Fixture {
            space,
            node,
            descriptor,
            plan,
        }
    }

    fn signed_followup_receipt(
        fixture: &Fixture,
        request: &ManagementRequest,
        decision_sequence: u64,
        acknowledged_through: u64,
    ) -> AuthorityReceipt {
        let key = SigningKey::from_bytes(&AUTHORITY_SEED);
        let mut selector = fixture_creation_selector(fixture);
        selector.operation = request.authority_operation().unwrap();
        let actor = request.authority_actor();
        selector.actor = actor.map(|(actor, _)| actor);
        selector.actor_deployment = actor.map(|(_, deployment)| deployment);
        selector.decision_sequence = decision_sequence;
        selector.acknowledged_through = acknowledged_through;
        selector.request = request.commitment();
        let mut receipt = AuthorityReceipt {
            selector,
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn fixture_creation_selector(
        fixture: &Fixture,
    ) -> super::super::sdk::authority::AuthorityReceiptSelector {
        let binding = fixture.descriptor.authority;
        super::super::sdk::authority::AuthorityReceiptSelector {
            policy: binding.policy,
            issuer: binding.issuer,
            space: fixture.space,
            agent: fixture.descriptor.identity.agent,
            operation: AuthorityOperationKind::CreateAgent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            actor: None,
            actor_deployment: None,
            evidence: AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([0x36; 32]),
            },
            lane_roots: AuthorityLaneRoots::default(),
            epoch: 1,
            decision_sequence: 1,
            acknowledged_through: 0,
            valid_from: 10,
            expires_at: 20,
            request: ManagementRequest::Create(Box::new(fixture.descriptor.clone())).commitment(),
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DurableAgentImage {
        pins: CleanSystemAgentPins,
        runtime_package_bytes: Vec<u8>,
        receipt: AuthorityReceipt,
    }

    #[derive(Default)]
    struct MemoryHostState {
        image: Option<DurableAgentImage>,
        corrupt_residue: bool,
        commits: usize,
        failure: Option<(usize, FailureMode)>,
    }

    #[derive(Clone, Default)]
    struct MemoryHost(Arc<Mutex<MemoryHostState>>);

    impl MemoryHost {
        fn exists(&self) -> bool {
            let state = self.0.lock().unwrap();
            state.corrupt_residue || state.image.is_some()
        }

        fn fail_on(&self, commit: usize, mode: FailureMode) {
            self.0.lock().unwrap().failure = Some((commit, mode));
        }

        fn set_corrupt_residue(&self) {
            self.0.lock().unwrap().corrupt_residue = true;
        }

        fn ensure(
            &self,
            record: &CleanSystemAgentBootstrapRecord,
            allow_create: bool,
            observed_slot: u64,
        ) -> Result<(), CleanSystemAgentBootstrapError> {
            let mut state = self.0.lock().unwrap();
            if state.corrupt_residue {
                return Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
                ));
            }
            if let Some(image) = &state.image {
                if image.pins != record.pins
                    || image.runtime_package_bytes != record.runtime_package_bytes
                    || record.receipt.as_ref() != Some(&image.receipt)
                {
                    return Err(CleanSystemAgentBootstrapError::Rejected(
                        CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
                    ));
                }
                return Ok(());
            }
            if !allow_create {
                return Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost,
                ));
            }
            let receipt =
                record
                    .receipt
                    .clone()
                    .ok_or(CleanSystemAgentBootstrapError::Rejected(
                        CleanSystemAgentBootstrapRejection::WrongReceipt,
                    ))?;
            if !receipt.selector.is_live_at(observed_slot) {
                return Err(CleanSystemAgentBootstrapError::Rejected(
                    CleanSystemAgentBootstrapRejection::WrongReceipt,
                ));
            }
            let commit = state.commits;
            state.commits += 1;
            if matches!(state.failure, Some((target, FailureMode::Before)) if target == commit) {
                state.failure = None;
                return Err(CleanSystemAgentBootstrapError::Host(
                    LocalAgentHostError::Io,
                ));
            }
            state.image = Some(DurableAgentImage {
                pins: record.pins.clone(),
                runtime_package_bytes: record.runtime_package_bytes.clone(),
                receipt,
            });
            if matches!(state.failure, Some((target, FailureMode::After)) if target == commit) {
                state.failure = None;
                return Err(CleanSystemAgentBootstrapError::Host(
                    LocalAgentHostError::Io,
                ));
            }
            Ok(())
        }
    }

    type TestCoordinated = CoordinatedBootstrap<MemoryStore, MemoryStore, MemoryStore, ()>;

    fn bootstrap(
        stores: &(MemoryStore, MemoryStore, MemoryStore),
        host: &MemoryHost,
        signer: &mut CountingSigner,
        fixture: &Fixture,
        observed_slot: u64,
    ) -> Result<TestCoordinated, CleanSystemAgentBootstrapError> {
        validate_plan_scope(&fixture.plan, fixture.space, fixture.node)?;
        coordinate_bootstrap(
            stores.0.clone(),
            stores.1.clone(),
            stores.2.clone(),
            signer,
            &fixture.plan,
            host.exists(),
            |record, allow_create| host.ensure(record, allow_create, observed_slot),
        )
    }

    #[test]
    fn exact_completed_recovery_is_byte_identical_and_never_remints() {
        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        let fixture = make_fixture(AUTHORITY_SEED, 0x41);
        let mut signer = CountingSigner::new(AUTHORITY_SEED);
        let owner = bootstrap(&stores, &host, &mut signer, &fixture, 10).unwrap();
        let exact = owner.receipt.encode().unwrap();
        assert_eq!(signer.calls, 1);
        assert_eq!(owner.pins.descriptor(), &fixture.descriptor);
        assert_eq!(owner.issuer.sequence_high_water(), 1);
        assert_eq!(owner.issuer.acknowledged_through(), 1);
        drop(owner);

        for slot in [21, 1_000, u64::MAX] {
            let mut unavailable_wrong_signer = CountingSigner::new([0x7f; 32]);
            let recovered = bootstrap(
                &stores,
                &host,
                &mut unavailable_wrong_signer,
                &fixture,
                slot,
            )
            .unwrap();
            assert_eq!(recovered.receipt.encode().unwrap(), exact);
            assert_eq!(unavailable_wrong_signer.calls, 0);
        }

        for image in [stores.0.image(), stores.1.image(), stores.2.image()] {
            assert!(
                !image
                    .unwrap()
                    .windows(AUTHORITY_SEED.len())
                    .any(|window| window == AUTHORITY_SEED)
            );
        }
    }

    #[test]
    fn complete_archive_rejects_same_route_divergent_issuer_image() {
        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        let fixture = make_fixture(AUTHORITY_SEED, 0x48);
        let mut signer = CountingSigner::new(AUTHORITY_SEED);
        bootstrap(&stores, &host, &mut signer, &fixture, 10).unwrap();
        let metadata_before = (stores.0.image(), stores.1.image());

        let divergent_store = MemoryStore::default();
        let mut divergent_issuer = DurableCleanManagementIssuer::open(
            divergent_store.clone(),
            fixture.descriptor.authority,
            fixture.space,
            fixture.descriptor.identity.agent,
        )
        .unwrap();
        let divergent_request = ManagementRequest::ChangeReplicas {
            expected_generation: fixture.descriptor.replica_generation(),
            replicas: fixture.descriptor.replicas.clone(),
        };
        let divergent_decision = AuthorizedCleanManagementDecision::new(
            NonZeroU64::new(1).unwrap(),
            CleanManagementDecisionContext {
                space: fixture.space,
                agent: fixture.descriptor.identity.agent,
                runtime_deployment: fixture.descriptor.identity.runtime_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x36; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                valid_from: 10,
                expires_at: 20,
            },
            &divergent_request,
        )
        .unwrap();
        let mut divergent_signer = CountingSigner::new(AUTHORITY_SEED);
        let divergent_receipt = divergent_issuer
            .issue(&divergent_decision, &mut divergent_signer)
            .unwrap();
        assert!(
            divergent_issuer
                .observe_durable(&divergent_receipt)
                .unwrap()
        );
        drop(divergent_issuer);
        stores.2.replace(divergent_store.image().unwrap());

        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &fixture, 21),
            Err(CleanSystemAgentBootstrapError::IssuerRejected(
                CleanManagementIssuerRejection::DivergentRetry
            ))
        ));
        assert_eq!(signer.calls, 1);
        assert_eq!((stores.0.image(), stores.1.image()), metadata_before);
    }

    #[test]
    fn physical_host_reopens_exact_create_after_expiry_and_detects_state_mismatch() {
        let directory = TestDirectory::new("physical-reopen");
        let root = directory.child("agents");
        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let fixture = make_fixture(AUTHORITY_SEED, 0x47);
        let mut signer = CountingSigner::new(AUTHORITY_SEED);
        let owner = CleanSystemAgentBootstrapOwner::open_or_bootstrap(
            stores.0.clone(),
            stores.1.clone(),
            stores.2.clone(),
            &mut signer,
            &fixture.plan,
            &root,
            fixture.space,
            fixture.node,
            10,
        )
        .unwrap();
        let exact_receipt = owner.creation_receipt().encode().unwrap();
        assert_eq!(signer.calls, 1);
        drop(owner);

        let mut unavailable_wrong_signer = CountingSigner::new([0x7f; 32]);
        let reopened = CleanSystemAgentBootstrapOwner::open_or_bootstrap(
            stores.0.clone(),
            stores.1.clone(),
            stores.2.clone(),
            &mut unavailable_wrong_signer,
            &fixture.plan,
            &root,
            fixture.space,
            fixture.node,
            21,
        )
        .unwrap();
        assert_eq!(reopened.creation_receipt().encode().unwrap(), exact_receipt);
        assert_eq!(unavailable_wrong_signer.calls, 0);
        drop(reopened);

        // Advance only the durable Agent journal past the archived Create.
        // The descriptor stays byte-identical, so a descriptor-only reopen
        // would accept this mismatch. Exact Create replay must detect it.
        let mut host = LocalAgentHost::open_with_clean_clock(
            &root,
            fixture.space,
            fixture.node,
            Arc::new(FixedLogicalClock(11)),
        )
        .unwrap();
        let change_replicas = ManagementRequest::ChangeReplicas {
            expected_generation: fixture.descriptor.replica_generation(),
            replicas: fixture.descriptor.replicas.clone(),
        };
        let followup = signed_followup_receipt(&fixture, &change_replicas, 2, 1);
        host.manage(
            fixture.descriptor.identity.agent,
            change_replicas,
            Some(followup),
            super::super::driver::SdkManagementArtifacts::None,
        )
        .unwrap();
        assert_eq!(
            host.show(fixture.descriptor.identity.agent).unwrap(),
            &fixture.descriptor
        );
        drop(host);

        let metadata_before = (stores.0.image(), stores.1.image(), stores.2.image());
        let mut never_called = CountingSigner::new([0x7e; 32]);
        assert!(matches!(
            CleanSystemAgentBootstrapOwner::open_or_bootstrap(
                stores.0.clone(),
                stores.1.clone(),
                stores.2.clone(),
                &mut never_called,
                &fixture.plan,
                &root,
                fixture.space,
                fixture.node,
                21,
            ),
            Err(CleanSystemAgentBootstrapError::Host(
                LocalAgentHostError::Corrupt
            ))
        ));
        assert_eq!(never_called.calls, 0);
        assert_eq!(
            (stores.0.image(), stores.1.image(), stores.2.image()),
            metadata_before
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum Boundary {
        Pins,
        Intent,
        IssuerPledge,
        IssuerReceipt,
        ArchiveReceipt,
        AgentImage,
        IssuerObservation,
        Complete,
    }

    #[test]
    fn every_boundary_recovers_before_and_after_ambiguous_commit() {
        for boundary in [
            Boundary::Pins,
            Boundary::Intent,
            Boundary::IssuerPledge,
            Boundary::IssuerReceipt,
            Boundary::ArchiveReceipt,
            Boundary::AgentImage,
            Boundary::IssuerObservation,
            Boundary::Complete,
        ] {
            for mode in [FailureMode::Before, FailureMode::After] {
                let stores = (
                    MemoryStore::default(),
                    MemoryStore::default(),
                    MemoryStore::default(),
                );
                let host = MemoryHost::default();
                match boundary {
                    Boundary::Pins => stores.0.fail_on(0, mode),
                    Boundary::Intent => stores.1.fail_on(0, mode),
                    Boundary::IssuerPledge => stores.2.fail_on(0, mode),
                    Boundary::IssuerReceipt => stores.2.fail_on(1, mode),
                    Boundary::ArchiveReceipt => stores.1.fail_on(1, mode),
                    Boundary::AgentImage => host.fail_on(0, mode),
                    Boundary::IssuerObservation => stores.2.fail_on(2, mode),
                    Boundary::Complete => stores.1.fail_on(2, mode),
                }
                let fixture = make_fixture(AUTHORITY_SEED, 0x42);
                let mut signer = CountingSigner::new(AUTHORITY_SEED);
                assert!(bootstrap(&stores, &host, &mut signer, &fixture, 10).is_err());

                let retry_after_expiry = matches!(
                    (boundary, mode),
                    (Boundary::AgentImage, FailureMode::After)
                        | (Boundary::IssuerObservation, _)
                        | (Boundary::Complete, _)
                );
                let recovered = bootstrap(
                    &stores,
                    &host,
                    &mut signer,
                    &fixture,
                    if retry_after_expiry { 21 } else { 10 },
                )
                .unwrap_or_else(|error| panic!("{boundary:?}/{mode:?} did not recover: {error:?}"));
                assert_eq!(recovered.receipt.selector.decision_sequence, 1);
                assert_eq!(recovered.issuer.acknowledged_through(), 1);
                let expected_signatures = match (boundary, mode) {
                    (Boundary::IssuerReceipt, FailureMode::Before) => 2,
                    _ => 1,
                };
                assert_eq!(
                    signer.calls, expected_signatures,
                    "unexpected signing count at {boundary:?}/{mode:?}"
                );
            }
        }
    }

    #[test]
    fn missing_divergent_cross_route_and_legacy_state_fail_closed() {
        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        let fixture = make_fixture(AUTHORITY_SEED, 0x43);
        let mut signer = CountingSigner::new(AUTHORITY_SEED);
        bootstrap(&stores, &host, &mut signer, &fixture, 10).unwrap();

        stores.0.clear();
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &fixture, 10),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::MissingPins
            ))
        ));

        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        bootstrap(&stores, &host, &mut signer, &fixture, 10).unwrap();
        stores.1.clear();
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &fixture, 10),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::MissingRecord
            ))
        ));

        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        bootstrap(&stores, &host, &mut signer, &fixture, 10).unwrap();
        let other_agent = make_fixture(AUTHORITY_SEED, 0x44);
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &other_agent, 10),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::DivergentPins
            ))
        ));
        let other_key = make_fixture([0x63; 32], 0x43);
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &other_key, 10),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::DivergentPins
            ))
        ));
        assert!(matches!(
            validate_plan_scope(&fixture.plan, SpaceId([0x55; 32]), fixture.node),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::WrongScope
            ))
        ));

        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        host.set_corrupt_residue();
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &fixture, 10),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::LegacyOrDivergentHost
            ))
        ));
        assert!(stores.0.image().is_none());
        assert!(stores.1.image().is_none());
        assert!(stores.2.image().is_none());
    }

    #[test]
    fn archived_receipt_without_issuer_state_and_corruption_never_remint() {
        let stores = (
            MemoryStore::default(),
            MemoryStore::default(),
            MemoryStore::default(),
        );
        let host = MemoryHost::default();
        let fixture = make_fixture(AUTHORITY_SEED, 0x45);
        let mut signer = CountingSigner::new(AUTHORITY_SEED);
        stores.1.fail_on(2, FailureMode::Before);
        assert!(bootstrap(&stores, &host, &mut signer, &fixture, 10).is_err());
        assert_eq!(signer.calls, 1);
        stores.2.clear();
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &fixture, 21),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::MissingIssuerState
            ))
        ));
        assert_eq!(signer.calls, 1, "missing issuer state must not remint");

        let mut corrupt = stores.1.image().unwrap();
        let middle = corrupt.len() / 2;
        corrupt[middle] ^= 0x80;
        stores.1.replace(corrupt);
        assert!(matches!(
            bootstrap(&stores, &host, &mut signer, &fixture, 21),
            Err(CleanSystemAgentBootstrapError::Rejected(
                CleanSystemAgentBootstrapRejection::InvalidRecord
            ))
        ));
        assert_eq!(signer.calls, 1);
    }

    #[test]
    fn canonical_bounds_and_runtime_bytes_are_exact() {
        let fixture = make_fixture(AUTHORITY_SEED, 0x46);
        let pins = fixture.plan.pins.encode();
        assert_eq!(
            CleanSystemAgentPins::decode(&pins).unwrap(),
            fixture.plan.pins
        );
        assert!(pins.len() <= MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES);

        let record = CleanSystemAgentBootstrapRecord::intent(&fixture.plan);
        let encoded = record.encode();
        assert_eq!(
            CleanSystemAgentBootstrapRecord::decode(&encoded).unwrap(),
            record
        );
        assert!(encoded.len() <= MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(CleanSystemAgentBootstrapRecord::decode(&trailing).is_err());

        let mut changed_runtime = fixture.plan.runtime_package_bytes.clone();
        let last = changed_runtime.len() - 1;
        changed_runtime[last] ^= 1;
        assert!(matches!(
            AuthorizedCleanSystemAgentBootstrap::new(
                fixture.descriptor,
                changed_runtime,
                fixture.plan.decision,
            ),
            Err(CleanSystemAgentBootstrapRejection::InvalidRuntimePackage)
        ));
    }
}
