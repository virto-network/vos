//! Authenticated, bounded anti-entropy for ciphertext-only Private stores.
//!
//! Network transports remain outside this module. A caller supplies a verifier
//! for the live transport session, and the exact full [`PrivateNodeIdentity`]
//! must also match the current verified membership before any artifact read or
//! response allocation occurs. There is no NodeId-, Principal-, SSH-, or
//! credential-only entry point.
//!
//! Genesis is the absence of a PCTL and therefore has no fabricated authority
//! evidence. Every post-genesis control item must instead carry its exact
//! canonical AOI1+PCA1 envelope; a locally applied control whose attachment is
//! still crash-pending may reopen, but it cannot be served to another node.

use alloc::vec::Vec;
use core::fmt;

use vos_agent_sdk::authority::{AuthorityActorTarget, AuthorityVerifier, ManagedAgentTarget};
use vos_agent_sdk::authority_operation::{
    AuthorityOperationIntent, AuthorityOperationIssuanceAck,
    MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES,
    MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES, PrivateControlApplicationAck,
    PrivateRecoveryAuthorityProof, PrivateRecoveryAuthorityProofVerifier,
};
use vos_agent_sdk::private::{
    EncryptedPrivateObject, PrivateControlOperation, PrivateControlRecord, PrivateNodeIdentity,
};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_OBJECT_WIRE_BYTES,
};
use vos_agent_sdk::{
    ActorDescriptor, AgentId, AgentProfile, Hash, ManagementRequest, MethodMode, ModelError,
    RuntimeWork, SpaceId, StateLane, StorageFieldDescriptor,
};

use super::authority_operation_issuer::private_intent_matches_application;
use super::private_crypto::{PrivateCryptoError, PrivateNodeAuthorityVerifier};
use super::private_store::{
    MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES, PrivateObjectKey, PrivateStore,
    PrivateStoreError, PutDisposition, StoredControlIndex,
};

pub const MAX_PRIVATE_SYNC_ITEMS: usize = 64;
pub const MAX_PRIVATE_SYNC_PAGE_BYTES: usize = MAX_PRIVATE_OBJECT_WIRE_BYTES + 16 * 1024;
pub const MAX_PRIVATE_SYNC_FRAME_BYTES: usize = MAX_PRIVATE_SYNC_PAGE_BYTES + 32 * 1024;
// v2 makes authority evidence mandatory on every control item. A clean break
// prevents a v1 raw-control frame from being interpreted under the new layout.
const FORMAT_VERSION: u16 = 2;
const REQUEST_MAGIC: &[u8; 4] = b"PSRQ";
const PAGE_MAGIC: &[u8; 4] = b"PSPG";
const EVIDENCE_MAGIC: &[u8; 4] = b"PSE2";
const SYNC_WIRE_DOMAIN: &[u8] = b"vos/private/stored-wire/v1";
const EVIDENCE_WIRE_DOMAIN: &[u8] = b"vos/private/control-authority-evidence/v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateSyncError {
    Unauthorized,
    InvalidRequest,
    InvalidFrame,
    InvalidScope,
    StaleTarget,
    Diverged,
    LimitExceeded,
    LimitTooSmall,
    Duplicate,
    OutOfOrder,
    Alias,
    Tampered,
    MissingEvidence,
    LinearUnsupported,
    /// The evidence selects a control for which this receiver has no durable
    /// application/reopen implementation yet.
    UnsupportedOperation,
    Store(PrivateStoreError),
    Crypto(PrivateCryptoError),
}

impl fmt::Display for PrivateSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Private-agent synchronization failed: {self:?}")
    }
}

impl core::error::Error for PrivateSyncError {}

impl From<PrivateStoreError> for PrivateSyncError {
    fn from(error: PrivateStoreError) -> Self {
        match error {
            PrivateStoreError::Alias => Self::Alias,
            other => Self::Store(other),
        }
    }
}

impl From<PrivateCryptoError> for PrivateSyncError {
    fn from(error: PrivateCryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// Canonical authority evidence for one exact signed Private control.
///
/// The envelope adds no ambient authority of its own. Verification always
/// uses the independently configured descriptor authority and runtime route;
/// neither acknowledgement may select its own trust anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlAuthorityEvidence {
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) application_ack: Vec<u8>,
    /// Exact PRA1 retained only for Recover. This compact signed proof makes
    /// a live retry and another replacement Node independent of the retired
    /// host-local PVRP3 staging plan.
    pub(crate) recovery_proof: Option<Vec<u8>>,
}

impl PrivateControlAuthorityEvidence {
    pub(crate) fn from_acknowledgements(
        issuance: &AuthorityOperationIssuanceAck,
        application: &PrivateControlApplicationAck,
        recovery_proof: Option<&PrivateRecoveryAuthorityProof>,
    ) -> Result<Self, PrivateSyncError> {
        let evidence = Self {
            issuance_ack: issuance
                .encode()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
            application_ack: application
                .encode()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
            recovery_proof: recovery_proof
                .map(|proof| proof.encode().map_err(|_| PrivateSyncError::InvalidFrame))
                .transpose()?,
        };
        // Encoding supplies the common bound and catches an unexpectedly
        // enlarged SDK acknowledgement before it reaches persistent storage.
        evidence.encode()?;
        Ok(evidence)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, PrivateSyncError> {
        let issuance = AuthorityOperationIssuanceAck::decode(&self.issuance_ack)
            .map_err(|_| PrivateSyncError::InvalidFrame)?;
        let application = PrivateControlApplicationAck::decode(&self.application_ack)
            .map_err(|_| PrivateSyncError::InvalidFrame)?;
        let recovery_proof = self
            .recovery_proof
            .as_deref()
            .map(PrivateRecoveryAuthorityProof::decode)
            .transpose()
            .map_err(|_| PrivateSyncError::InvalidFrame)?;
        if issuance.encode().ok().as_deref() != Some(self.issuance_ack.as_slice())
            || application.encode().ok().as_deref() != Some(self.application_ack.as_slice())
            || recovery_proof
                .as_ref()
                .and_then(|proof| proof.encode().ok())
                .as_deref()
                != self.recovery_proof.as_deref()
            || (issuance.receipt.selector.operation
                == vos_agent_sdk::authority::AuthorityOperationKind::RecoverPrivateAgent)
                != recovery_proof.is_some()
        {
            return Err(PrivateSyncError::InvalidFrame);
        }
        let mut encoder = Encoder::new(EVIDENCE_MAGIC);
        encoder.bytes(&self.issuance_ack)?;
        encoder.bytes(&self.application_ack)?;
        match &self.recovery_proof {
            Some(proof) => {
                encoder.u8(1);
                encoder.bytes(proof)?;
            }
            None => encoder.u8(0),
        }
        encoder.finish(MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PrivateSyncError> {
        let mut decoder = Decoder::new(
            bytes,
            EVIDENCE_MAGIC,
            MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES,
        )?;
        let evidence = Self {
            issuance_ack: decoder.bytes(
                vos_agent_sdk::authority_operation::MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
            )?,
            application_ack: decoder.bytes(MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES)?,
            recovery_proof: match decoder.u8()? {
                0 => None,
                1 => Some(decoder.bytes(MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES)?),
                _ => return Err(PrivateSyncError::InvalidFrame),
            },
        };
        decoder.finish()?;
        if evidence.encode()?.as_slice() != bytes {
            return Err(PrivateSyncError::InvalidFrame);
        }
        Ok(evidence)
    }

    pub(crate) fn commitment(&self) -> Result<Hash, PrivateSyncError> {
        Ok(Hash::digest(EVIDENCE_WIRE_DOMAIN, &[&self.encode()?]))
    }

    pub(crate) fn verify_for(
        &self,
        control: &PrivateControlRecord,
        resulting_epoch: u64,
        route: ManagedAgentTarget,
        authority: AuthorityActorTarget,
    ) -> Result<(), PrivateSyncError> {
        if !route.is_valid()
            || !authority.is_valid()
            || route.space != authority.space
            || control.space != route.space
            || control.agent != route.agent
        {
            return Err(PrivateSyncError::InvalidScope);
        }
        let issuance = AuthorityOperationIssuanceAck::decode(&self.issuance_ack)
            .map_err(|_| PrivateSyncError::Tampered)?;
        let application = PrivateControlApplicationAck::decode(&self.application_ack)
            .map_err(|_| PrivateSyncError::Tampered)?;
        if issuance.encode().ok().as_deref() != Some(self.issuance_ack.as_slice())
            || application.encode().ok().as_deref() != Some(self.application_ack.as_slice())
        {
            return Err(PrivateSyncError::Tampered);
        }
        let intent = match (&control.operation, self.recovery_proof.as_deref()) {
            (PrivateControlOperation::Recover { .. }, Some(bytes)) => {
                let proof = PrivateRecoveryAuthorityProof::decode(bytes)
                    .map_err(|_| PrivateSyncError::Tampered)?;
                if proof.encode().ok().as_deref() != Some(bytes)
                    || proof.managed != route
                    || !proof.matches_control(control)
                    || proof.verify_with(&RawRecoveryProofVerifier).is_err()
                {
                    return Err(PrivateSyncError::Tampered);
                }
                AuthorityOperationIntent::RecoverPrivateAgent { proof }
            }
            (PrivateControlOperation::Recover { .. }, None) | (_, Some(_)) => {
                return Err(PrivateSyncError::Tampered);
            }
            (_, None) => {
                AuthorityOperationIntent::private_control(route.runtime_deployment, control)
                    .map_err(|_| PrivateSyncError::Tampered)?
            }
        };
        let expected_actor = match &intent {
            AuthorityOperationIntent::PrivateActorLifecycle { actor, .. } => Some(*actor),
            _ => None,
        };
        let verifier = RawAuthorityVerifier;
        if issuance.authority != authority
            || application.authority != authority
            || issuance.verify_with(authority.binding, &verifier).is_err()
            || application
                .verify_issuance_tombstone_with(
                    authority,
                    issuance.authorization_invocation,
                    issuance.acknowledgement_invocation,
                    issuance.authorization_sequence,
                    issuance.commitment(),
                    &verifier,
                )
                .is_err()
            || application.operation_call != issuance.operation_call
            || application.approval != issuance.approval
            || application.receipt != issuance.receipt
            || application.issued_at != issuance.issued_at
            || !private_intent_matches_application(&intent, &application.application)
            || application.application.epoch != resulting_epoch
            || intent.request_commitment(issuance.authorization_sequence, issuance.operation_call)
                != Some(issuance.receipt.selector.request)
            || issuance.receipt.selector.operation != intent.operation()
            || issuance.receipt.selector.actor != expected_actor
            || issuance.receipt.selector.actor_deployment.is_some()
            || issuance.receipt.selector.space != route.space
            || issuance.receipt.selector.agent != route.agent
            || issuance.receipt.selector.runtime_deployment != route.runtime_deployment
        {
            return Err(PrivateSyncError::Tampered);
        }
        Ok(())
    }
}

struct RawAuthorityVerifier;

impl AuthorityVerifier for RawAuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crate::agent::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

struct RawRecoveryProofVerifier;

impl PrivateRecoveryAuthorityProofVerifier for RawRecoveryProofVerifier {
    fn verify_private_recovery_authority_proof(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        crate::agent::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSyncHead {
    pub epoch: u64,
    pub control_head: Option<Hash>,
}

impl PrivateSyncHead {
    fn validate(self) -> bool {
        match self.control_head {
            None => self.epoch == 0,
            Some(head) => head != Hash::ZERO,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSyncCursor {
    pub space: SpaceId,
    pub agent: AgentId,
    /// State already authenticated and applied by the requester.
    pub local: PrivateSyncHead,
    /// Server head fixed by the first response in a pagination session.
    pub target: Option<PrivateSyncHead>,
    /// Last object applied. Control synchronization never carries this field.
    pub after_object: Option<PrivateObjectKey>,
}

impl PrivateSyncCursor {
    pub fn start(
        space: SpaceId,
        agent: AgentId,
        epoch: u64,
        control_head: Option<Hash>,
    ) -> Result<Self, PrivateSyncError> {
        let cursor = Self {
            space,
            agent,
            local: PrivateSyncHead {
                epoch,
                control_head,
            },
            target: None,
            after_object: None,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn validate(&self) -> Result<(), PrivateSyncError> {
        if self.space == SpaceId::ZERO || self.agent == AgentId::ZERO || !self.local.validate() {
            return Err(PrivateSyncError::InvalidRequest);
        }
        if let Some(target) = self.target {
            if !target.validate() || target.epoch < self.local.epoch {
                return Err(PrivateSyncError::InvalidRequest);
            }
        }
        if (self.after_object.is_some() && self.target != Some(self.local))
            || self
                .after_object
                .is_some_and(|key| !key_is_valid(key) || key.epoch > self.local.epoch)
        {
            return Err(PrivateSyncError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSyncRequest {
    pub cursor: PrivateSyncCursor,
    pub max_items: u16,
    pub max_bytes: u32,
}

impl PrivateSyncRequest {
    pub fn validate(&self) -> Result<(), PrivateSyncError> {
        self.cursor.validate()?;
        if self.max_items == 0
            || usize::from(self.max_items) > MAX_PRIVATE_SYNC_ITEMS
            || self.max_bytes == 0
            || self.max_bytes as usize > MAX_PRIVATE_SYNC_PAGE_BYTES
        {
            return Err(PrivateSyncError::LimitExceeded);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PrivateSyncError> {
        self.validate()?;
        let mut encoder = Encoder::new(REQUEST_MAGIC);
        encode_request_body(&mut encoder, self)?;
        encoder.finish(MAX_PRIVATE_SYNC_FRAME_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateSyncError> {
        let mut decoder = Decoder::new(bytes, REQUEST_MAGIC, MAX_PRIVATE_SYNC_FRAME_BYTES)?;
        let request = decode_request_body(&mut decoder)?;
        decoder.finish()?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateSyncPhase {
    Controls = 0,
    Objects = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateSyncItem {
    Control {
        sequence: u64,
        commitment: Hash,
        resulting_epoch: u64,
        wire: Vec<u8>,
        /// Exact canonical PSE2 envelope for this PCTL. A control item without
        /// AOI1+PCA1 evidence is never a valid synchronization item.
        evidence: Vec<u8>,
    },
    Object {
        key: PrivateObjectKey,
        wire_hash: Hash,
        wire: Vec<u8>,
    },
}

impl PrivateSyncItem {
    fn encoded_payload_len(&self) -> Result<usize, PrivateSyncError> {
        let wire_len = match self {
            Self::Control { wire, evidence, .. } => {
                if wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES
                    || evidence.len() > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
                {
                    return Err(PrivateSyncError::LimitExceeded);
                }
                wire.len()
                    .checked_add(evidence.len())
                    .ok_or(PrivateSyncError::LimitExceeded)?
            }
            Self::Object { wire, .. } => {
                if wire.len() > MAX_PRIVATE_OBJECT_WIRE_BYTES {
                    return Err(PrivateSyncError::LimitExceeded);
                }
                wire.len()
            }
        };
        wire_len
            .checked_add(96)
            .ok_or(PrivateSyncError::LimitExceeded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSyncPage {
    pub request: PrivateSyncRequest,
    pub target: PrivateSyncHead,
    pub phase: PrivateSyncPhase,
    pub items: Vec<PrivateSyncItem>,
    pub next: Option<PrivateSyncCursor>,
}

impl PrivateSyncPage {
    pub fn validate_shape(&self) -> Result<(), PrivateSyncError> {
        self.request.validate()?;
        if !self.target.validate()
            || self
                .request
                .cursor
                .target
                .is_some_and(|target| target != self.target)
            || self.items.len() > usize::from(self.request.max_items)
            || self.items.len() > MAX_PRIVATE_SYNC_ITEMS
        {
            return Err(PrivateSyncError::InvalidFrame);
        }
        let payload_bytes = self.items.iter().try_fold(0usize, |total, item| {
            total
                .checked_add(item.encoded_payload_len()?)
                .ok_or(PrivateSyncError::LimitExceeded)
        })?;
        if payload_bytes > self.request.max_bytes as usize
            || payload_bytes > MAX_PRIVATE_SYNC_PAGE_BYTES
        {
            return Err(PrivateSyncError::LimitExceeded);
        }
        match self.phase {
            PrivateSyncPhase::Controls => {
                if self.request.cursor.local == self.target
                    || self.request.cursor.after_object.is_some()
                {
                    return Err(PrivateSyncError::InvalidFrame);
                }
                validate_control_item_order(&self.items)?;
            }
            PrivateSyncPhase::Objects => {
                if self.request.cursor.local != self.target {
                    return Err(PrivateSyncError::InvalidFrame);
                }
                validate_object_item_order(&self.items)?;
            }
        }
        if let Some(next) = &self.next {
            next.validate()?;
            if next.space != self.request.cursor.space
                || next.agent != self.request.cursor.agent
                || next.target != Some(self.target)
            {
                return Err(PrivateSyncError::InvalidFrame);
            }
            match (self.phase, self.items.last()) {
                (
                    PrivateSyncPhase::Controls,
                    Some(PrivateSyncItem::Control {
                        commitment,
                        resulting_epoch,
                        ..
                    }),
                ) if next.local.control_head == Some(*commitment)
                    && next.local.epoch == *resulting_epoch
                    && next.after_object.is_none() => {}
                (PrivateSyncPhase::Objects, Some(PrivateSyncItem::Object { key, .. }))
                    if next.local == self.target && next.after_object == Some(*key) => {}
                _ => return Err(PrivateSyncError::InvalidFrame),
            }
        }
        if self.phase == PrivateSyncPhase::Controls {
            let Some(PrivateSyncItem::Control {
                commitment,
                resulting_epoch,
                ..
            }) = self.items.last()
            else {
                return Err(PrivateSyncError::InvalidFrame);
            };
            if self.next.is_none()
                && (self.target.control_head != Some(*commitment)
                    || self.target.epoch != *resulting_epoch)
            {
                return Err(PrivateSyncError::InvalidFrame);
            }
        }
        if self.items.is_empty() && self.next.is_some() {
            return Err(PrivateSyncError::InvalidFrame);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PrivateSyncError> {
        self.validate_shape()?;
        let mut encoder = Encoder::new(PAGE_MAGIC);
        encode_request_body(&mut encoder, &self.request)?;
        encode_head(&mut encoder, self.target);
        encoder.u8(self.phase as u8);
        encoder.u16(u16::try_from(self.items.len()).map_err(|_| PrivateSyncError::LimitExceeded)?);
        for item in &self.items {
            match item {
                PrivateSyncItem::Control {
                    sequence,
                    commitment,
                    resulting_epoch,
                    wire,
                    evidence,
                } => {
                    encoder.u8(0);
                    encoder.u64(*sequence);
                    encoder.fixed(commitment.as_bytes());
                    encoder.u64(*resulting_epoch);
                    encoder.bytes(wire)?;
                    encoder.bytes(evidence)?;
                }
                PrivateSyncItem::Object {
                    key,
                    wire_hash,
                    wire,
                } => {
                    encoder.u8(1);
                    encode_key(&mut encoder, *key);
                    encoder.fixed(wire_hash.as_bytes());
                    encoder.bytes(wire)?;
                }
            }
        }
        encode_optional_cursor(&mut encoder, self.next.as_ref())?;
        encoder.finish(MAX_PRIVATE_SYNC_FRAME_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateSyncError> {
        let mut decoder = Decoder::new(bytes, PAGE_MAGIC, MAX_PRIVATE_SYNC_FRAME_BYTES)?;
        let request = decode_request_body(&mut decoder)?;
        let target = decode_head(&mut decoder)?;
        let phase = match decoder.u8()? {
            0 => PrivateSyncPhase::Controls,
            1 => PrivateSyncPhase::Objects,
            _ => return Err(PrivateSyncError::InvalidFrame),
        };
        let item_count = usize::from(decoder.u16()?);
        if item_count > MAX_PRIVATE_SYNC_ITEMS {
            return Err(PrivateSyncError::LimitExceeded);
        }
        let mut items = Vec::new();
        items
            .try_reserve(item_count)
            .map_err(|_| PrivateSyncError::LimitExceeded)?;
        for _ in 0..item_count {
            let item = match decoder.u8()? {
                0 => PrivateSyncItem::Control {
                    sequence: decoder.u64()?,
                    commitment: Hash(decoder.fixed()?),
                    resulting_epoch: decoder.u64()?,
                    wire: decoder.bytes(MAX_PRIVATE_CONTROL_WIRE_BYTES)?,
                    evidence: decoder.bytes(MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES)?,
                },
                1 => PrivateSyncItem::Object {
                    key: decode_key(&mut decoder)?,
                    wire_hash: Hash(decoder.fixed()?),
                    wire: decoder.bytes(MAX_PRIVATE_OBJECT_WIRE_BYTES)?,
                },
                _ => return Err(PrivateSyncError::InvalidFrame),
            };
            items.push(item);
        }
        let next = decode_optional_cursor(&mut decoder)?;
        decoder.finish()?;
        let page = Self {
            request,
            target,
            phase,
            items,
            next,
        };
        page.validate_shape()?;
        Ok(page)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateSyncApplyDisposition {
    Applied,
    AlreadyApplied,
}

/// Live transport authentication seam. Implementations validate the current
/// connection's cryptographic identity, not a bearer credential supplied in
/// the request body.
pub trait PrivateTransportAuthVerifier {
    fn verify_authenticated_private_node(
        &self,
        space: SpaceId,
        agent: AgentId,
        owner: vos_agent_sdk::PrincipalId,
        node: &PrivateNodeIdentity,
    ) -> bool;
}

struct Encoder(Vec<u8>);

impl Encoder {
    fn new(magic: &[u8; 4]) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        Self(bytes)
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn fixed(&mut self, value: &[u8; 32]) {
        self.0.extend_from_slice(value);
    }

    fn optional_hash(&mut self, value: Option<Hash>) {
        match value {
            None => self.u8(0),
            Some(hash) => {
                self.u8(1);
                self.fixed(hash.as_bytes());
            }
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), PrivateSyncError> {
        self.u32(u32::try_from(bytes.len()).map_err(|_| PrivateSyncError::LimitExceeded)?);
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self, max: usize) -> Result<Vec<u8>, PrivateSyncError> {
        if self.0.len() > max {
            return Err(PrivateSyncError::LimitExceeded);
        }
        Ok(self.0)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 4], max: usize) -> Result<Self, PrivateSyncError> {
        if bytes.len() > max || bytes.len() < 6 || bytes.get(..4) != Some(magic) {
            return Err(PrivateSyncError::InvalidFrame);
        }
        let version = u16::from_le_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
        );
        if version != FORMAT_VERSION {
            return Err(PrivateSyncError::InvalidFrame);
        }
        Ok(Self { bytes, offset: 6 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PrivateSyncError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PrivateSyncError::LimitExceeded)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrivateSyncError::InvalidFrame)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PrivateSyncError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(PrivateSyncError::InvalidFrame)?)
    }

    fn u16(&mut self) -> Result<u16, PrivateSyncError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, PrivateSyncError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, PrivateSyncError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
        ))
    }

    fn fixed(&mut self) -> Result<[u8; 32], PrivateSyncError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PrivateSyncError::InvalidFrame)
    }

    fn optional_hash(&mut self) -> Result<Option<Hash>, PrivateSyncError> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let hash = Hash(self.fixed()?);
                if hash == Hash::ZERO {
                    return Err(PrivateSyncError::InvalidFrame);
                }
                Ok(Some(hash))
            }
            _ => Err(PrivateSyncError::InvalidFrame),
        }
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, PrivateSyncError> {
        let length = usize::try_from(self.u32()?).map_err(|_| PrivateSyncError::LimitExceeded)?;
        if length > max {
            return Err(PrivateSyncError::LimitExceeded);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<(), PrivateSyncError> {
        if self.offset != self.bytes.len() {
            return Err(PrivateSyncError::InvalidFrame);
        }
        Ok(())
    }
}

fn encode_head(encoder: &mut Encoder, head: PrivateSyncHead) {
    encoder.u64(head.epoch);
    encoder.optional_hash(head.control_head);
}

fn decode_head(decoder: &mut Decoder<'_>) -> Result<PrivateSyncHead, PrivateSyncError> {
    let head = PrivateSyncHead {
        epoch: decoder.u64()?,
        control_head: decoder.optional_hash()?,
    };
    head.validate()
        .then_some(head)
        .ok_or(PrivateSyncError::InvalidFrame)
}

fn encode_key(encoder: &mut Encoder, key: PrivateObjectKey) {
    encoder.u64(key.epoch);
    encoder.u8(key.kind);
    encoder.fixed(key.content.as_bytes());
}

fn decode_key(decoder: &mut Decoder<'_>) -> Result<PrivateObjectKey, PrivateSyncError> {
    let key = PrivateObjectKey {
        epoch: decoder.u64()?,
        kind: decoder.u8()?,
        content: Hash(decoder.fixed()?),
    };
    key_is_valid(key)
        .then_some(key)
        .ok_or(PrivateSyncError::InvalidFrame)
}

fn key_is_valid(key: PrivateObjectKey) -> bool {
    key.content != Hash::ZERO && key.encrypted_kind().is_ok()
}

fn encode_cursor(encoder: &mut Encoder, cursor: &PrivateSyncCursor) {
    encoder.fixed(cursor.space.as_bytes());
    encoder.fixed(cursor.agent.as_bytes());
    encode_head(encoder, cursor.local);
    match cursor.target {
        None => encoder.u8(0),
        Some(target) => {
            encoder.u8(1);
            encode_head(encoder, target);
        }
    }
    match cursor.after_object {
        None => encoder.u8(0),
        Some(key) => {
            encoder.u8(1);
            encode_key(encoder, key);
        }
    }
}

fn decode_cursor(decoder: &mut Decoder<'_>) -> Result<PrivateSyncCursor, PrivateSyncError> {
    let cursor = PrivateSyncCursor {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        local: decode_head(decoder)?,
        target: match decoder.u8()? {
            0 => None,
            1 => Some(decode_head(decoder)?),
            _ => return Err(PrivateSyncError::InvalidFrame),
        },
        after_object: match decoder.u8()? {
            0 => None,
            1 => Some(decode_key(decoder)?),
            _ => return Err(PrivateSyncError::InvalidFrame),
        },
    };
    cursor.validate()?;
    Ok(cursor)
}

fn encode_optional_cursor(
    encoder: &mut Encoder,
    cursor: Option<&PrivateSyncCursor>,
) -> Result<(), PrivateSyncError> {
    match cursor {
        None => encoder.u8(0),
        Some(cursor) => {
            cursor.validate()?;
            encoder.u8(1);
            encode_cursor(encoder, cursor);
        }
    }
    Ok(())
}

fn decode_optional_cursor(
    decoder: &mut Decoder<'_>,
) -> Result<Option<PrivateSyncCursor>, PrivateSyncError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_cursor(decoder)?)),
        _ => Err(PrivateSyncError::InvalidFrame),
    }
}

fn encode_request_body(
    encoder: &mut Encoder,
    request: &PrivateSyncRequest,
) -> Result<(), PrivateSyncError> {
    request.validate()?;
    encode_cursor(encoder, &request.cursor);
    encoder.u16(request.max_items);
    encoder.u32(request.max_bytes);
    Ok(())
}

fn decode_request_body(decoder: &mut Decoder<'_>) -> Result<PrivateSyncRequest, PrivateSyncError> {
    let request = PrivateSyncRequest {
        cursor: decode_cursor(decoder)?,
        max_items: decoder.u16()?,
        max_bytes: decoder.u32()?,
    };
    request.validate()?;
    Ok(request)
}

fn validate_control_item_order(items: &[PrivateSyncItem]) -> Result<(), PrivateSyncError> {
    let mut previous_sequence = None;
    let mut previous_epoch = None;
    let mut commitments = Vec::new();
    commitments
        .try_reserve(items.len())
        .map_err(|_| PrivateSyncError::LimitExceeded)?;
    for item in items {
        let PrivateSyncItem::Control {
            sequence,
            commitment,
            resulting_epoch,
            wire,
            ..
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        if *commitment == Hash::ZERO
            || wire.is_empty()
            || wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES
        {
            return Err(PrivateSyncError::InvalidFrame);
        }
        if previous_sequence.is_some_and(|previous| previous >= *sequence)
            || previous_epoch.is_some_and(|previous| previous > *resulting_epoch)
        {
            return Err(PrivateSyncError::OutOfOrder);
        }
        if commitments.contains(commitment) {
            return Err(PrivateSyncError::Duplicate);
        }
        commitments.push(*commitment);
        previous_sequence = Some(*sequence);
        previous_epoch = Some(*resulting_epoch);
    }
    Ok(())
}

fn validate_object_item_order(items: &[PrivateSyncItem]) -> Result<(), PrivateSyncError> {
    let mut previous = None;
    for item in items {
        let PrivateSyncItem::Object {
            key,
            wire_hash,
            wire,
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        if !key_is_valid(*key)
            || *wire_hash == Hash::ZERO
            || wire.is_empty()
            || wire.len() > MAX_PRIVATE_OBJECT_WIRE_BYTES
        {
            return Err(PrivateSyncError::InvalidFrame);
        }
        if previous.is_some_and(|previous| previous >= *key) {
            return Err(if previous == Some(*key) {
                PrivateSyncError::Duplicate
            } else {
                PrivateSyncError::OutOfOrder
            });
        }
        previous = Some(*key);
    }
    Ok(())
}

fn sync_wire_hash(bytes: &[u8]) -> Hash {
    Hash::digest(SYNC_WIRE_DOMAIN, &[bytes])
}

fn authenticate_peer<V: PrivateTransportAuthVerifier>(
    store: &PrivateStore,
    peer: &PrivateNodeIdentity,
    transport: &V,
) -> Result<(), PrivateSyncError> {
    let binding = store.binding();
    if !peer.validate() || peer.principal != binding.owner {
        return Err(PrivateSyncError::Unauthorized);
    }
    let position = store
        .authorized_nodes()
        .binary_search_by_key(&peer.node, |node| node.node)
        .map_err(|_| PrivateSyncError::Unauthorized)?;
    let expected = store
        .authorized_nodes()
        .get(position)
        .ok_or(PrivateSyncError::Unauthorized)?;
    if expected != peer
        || !transport.verify_authenticated_private_node(
            binding.space,
            binding.agent,
            binding.owner,
            peer,
        )
    {
        return Err(PrivateSyncError::Unauthorized);
    }
    Ok(())
}

/// Serve one authenticated page. Membership and live transport identity are
/// checked entirely from the in-memory verified control view before any
/// ciphertext/control file is opened.
pub(crate) fn serve_private_sync_page<V: PrivateTransportAuthVerifier>(
    store: &PrivateStore,
    peer: &PrivateNodeIdentity,
    request: &PrivateSyncRequest,
    transport: &V,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<PrivateSyncPage, PrivateSyncError> {
    authenticate_peer(store, peer, transport)?;
    request.validate()?;
    let binding = store.binding();
    if request.cursor.space != binding.space
        || request.cursor.agent != binding.agent
        || route.space != binding.space
        || route.agent != binding.agent
        || authority.space != binding.space
        || !route.is_valid()
        || !authority.is_valid()
    {
        return Err(PrivateSyncError::InvalidScope);
    }
    let target = PrivateSyncHead {
        epoch: binding.epoch,
        control_head: binding.control_head,
    };
    if request
        .cursor
        .target
        .is_some_and(|expected| expected != target)
    {
        return Err(PrivateSyncError::StaleTarget);
    }
    if request.cursor.local == target {
        return serve_object_page(store, request, target);
    }
    if request.cursor.after_object.is_some() {
        return Err(PrivateSyncError::InvalidRequest);
    }
    serve_control_page(store, request, target, route, authority)
}

fn control_base_position(
    controls: &[StoredControlIndex],
    local: PrivateSyncHead,
) -> Result<Option<usize>, PrivateSyncError> {
    match local.control_head {
        None if local.epoch == 0 => Ok(None),
        None => Err(PrivateSyncError::Diverged),
        Some(head) => {
            if let Some((position, entry)) = controls
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.commitment == head)
            {
                if entry.resulting_epoch != local.epoch {
                    return Err(PrivateSyncError::Diverged);
                }
                return Ok(Some(position));
            }
            // A divergent head is meaningful only when an authenticated
            // recovery record explicitly supersedes it.
            let recoverable = controls.iter().any(|entry| {
                entry.resulting_epoch > local.epoch
                    && entry.superseded_heads.binary_search(&head).is_ok()
            });
            recoverable
                .then_some(None)
                .ok_or(PrivateSyncError::Diverged)
        }
    }
}

fn next_control_position(
    controls: &[StoredControlIndex],
    after_position: Option<usize>,
    current_head: Option<Hash>,
) -> Option<usize> {
    let start = after_position.map_or(0, |position| position.saturating_add(1));
    controls
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, entry)| {
            entry.previous == current_head
                || current_head
                    .is_some_and(|head| entry.superseded_heads.binary_search(&head).is_ok())
        })
        .map(|(position, _)| position)
}

fn serve_control_page(
    store: &PrivateStore,
    request: &PrivateSyncRequest,
    target: PrivateSyncHead,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<PrivateSyncPage, PrivateSyncError> {
    let controls = store.indexed_controls();
    let mut position = control_base_position(controls, request.cursor.local)?;
    let mut current = request.cursor.local;
    let mut items = Vec::new();
    let mut bytes = 0usize;
    while current.control_head != target.control_head {
        let next_position = next_control_position(controls, position, current.control_head)
            .ok_or(PrivateSyncError::Diverged)?;
        let entry = controls
            .get(next_position)
            .ok_or(PrivateSyncError::Diverged)?;
        if entry.resulting_epoch < current.epoch || entry.resulting_epoch > target.epoch {
            return Err(PrivateSyncError::Diverged);
        }
        let wire = store.read_control_wire(entry)?;
        let evidence = store
            .read_control_authority_evidence(entry)?
            .ok_or(PrivateSyncError::MissingEvidence)?;
        let record = PrivateControlRecord::decode(&wire).map_err(|_| PrivateSyncError::Tampered)?;
        let envelope = PrivateControlAuthorityEvidence::decode(&evidence)?;
        envelope.verify_for(&record, entry.resulting_epoch, route, authority)?;
        let item_len = wire
            .len()
            .checked_add(evidence.len())
            .and_then(|length| length.checked_add(96))
            .ok_or(PrivateSyncError::LimitExceeded)?;
        if items.len() >= usize::from(request.max_items)
            || bytes
                .checked_add(item_len)
                .ok_or(PrivateSyncError::LimitExceeded)?
                > request.max_bytes as usize
        {
            if items.is_empty() {
                return Err(PrivateSyncError::LimitTooSmall);
            }
            break;
        }
        items.push(PrivateSyncItem::Control {
            sequence: entry.sequence,
            commitment: entry.commitment,
            resulting_epoch: entry.resulting_epoch,
            wire,
            evidence,
        });
        bytes += item_len;
        current = PrivateSyncHead {
            epoch: entry.resulting_epoch,
            control_head: Some(entry.commitment),
        };
        position = Some(next_position);
    }
    if items.is_empty() {
        return Err(PrivateSyncError::Diverged);
    }
    let next = if current == target && store.indexed_objects().is_empty() {
        None
    } else {
        Some(PrivateSyncCursor {
            space: request.cursor.space,
            agent: request.cursor.agent,
            local: current,
            target: Some(target),
            after_object: None,
        })
    };
    let page = PrivateSyncPage {
        request: request.clone(),
        target,
        phase: PrivateSyncPhase::Controls,
        items,
        next,
    };
    page.validate_shape()?;
    Ok(page)
}

fn serve_object_page(
    store: &PrivateStore,
    request: &PrivateSyncRequest,
    target: PrivateSyncHead,
) -> Result<PrivateSyncPage, PrivateSyncError> {
    let objects = store.indexed_objects();
    let start = match request.cursor.after_object {
        None => 0,
        Some(after) => {
            let position = objects
                .binary_search_by_key(&after, |entry| entry.key)
                .map_err(|_| PrivateSyncError::Alias)?;
            position
                .checked_add(1)
                .ok_or(PrivateSyncError::LimitExceeded)?
        }
    };
    let mut items = Vec::new();
    let mut bytes = 0usize;
    let mut next_index = start;
    while let Some(entry) = objects.get(next_index) {
        if entry.key.epoch > target.epoch {
            return Err(PrivateSyncError::Tampered);
        }
        let item_len = (entry.wire_len as usize)
            .checked_add(96)
            .ok_or(PrivateSyncError::LimitExceeded)?;
        if items.len() >= usize::from(request.max_items)
            || bytes
                .checked_add(item_len)
                .ok_or(PrivateSyncError::LimitExceeded)?
                > request.max_bytes as usize
        {
            if items.is_empty() {
                return Err(PrivateSyncError::LimitTooSmall);
            }
            break;
        }
        let wire = store.read_object_wire(entry)?;
        items.push(PrivateSyncItem::Object {
            key: entry.key,
            wire_hash: entry.wire_hash,
            wire,
        });
        bytes += item_len;
        next_index += 1;
    }
    let next = if next_index < objects.len() {
        let last_key = match items.last() {
            Some(PrivateSyncItem::Object { key, .. }) => *key,
            _ => return Err(PrivateSyncError::InvalidFrame),
        };
        Some(PrivateSyncCursor {
            space: request.cursor.space,
            agent: request.cursor.agent,
            local: target,
            target: Some(target),
            after_object: Some(last_key),
        })
    } else {
        None
    };
    let page = PrivateSyncPage {
        request: request.clone(),
        target,
        phase: PrivateSyncPhase::Objects,
        items,
        next,
    };
    page.validate_shape()?;
    Ok(page)
}

/// Apply one page received over an authenticated transport. The sender must
/// be an exact member of the receiver's current verified control view before
/// any persisted artifact is opened or changed.
/// Low-level page application for already-authorized host wiring.
///
/// This remains crate-private until the production sync envelope binds every
/// carried control to its exact authority issuance and PCA acknowledgement;
/// transport authentication and a valid PCTL signature alone are not policy
/// authorization.
pub(crate) fn apply_private_sync_page<
    A: PrivateNodeAuthorityVerifier,
    T: PrivateTransportAuthVerifier,
>(
    store: &mut PrivateStore,
    peer: &PrivateNodeIdentity,
    page: &PrivateSyncPage,
    node_authority: &A,
    transport: &T,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<PrivateSyncApplyDisposition, PrivateSyncError> {
    authenticate_peer(store, peer, transport)?;
    page.validate_shape()?;
    let binding = store.binding();
    if page.request.cursor.space != binding.space
        || page.request.cursor.agent != binding.agent
        || route.space != binding.space
        || route.agent != binding.agent
        || authority.space != binding.space
        || !route.is_valid()
        || !authority.is_valid()
    {
        return Err(PrivateSyncError::InvalidScope);
    }
    match page.phase {
        PrivateSyncPhase::Controls => {
            apply_control_page(store, page, node_authority, route, authority)
        }
        PrivateSyncPhase::Objects => apply_object_page(store, page),
    }
}

fn apply_control_page<V: PrivateNodeAuthorityVerifier>(
    store: &mut PrivateStore,
    page: &PrivateSyncPage,
    node_authority: &V,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<PrivateSyncApplyDisposition, PrivateSyncError> {
    let records = verify_private_control_page_authority_evidence(page, route, authority)?;
    let start = store.binding();
    let expected_start = page.request.cursor.local;
    let mut skip = 0usize;
    if start.epoch != expected_start.epoch || start.control_head != expected_start.control_head {
        let Some(position) = page.items.iter().position(|item| {
            matches!(
                item,
                PrivateSyncItem::Control {
                    commitment,
                    resulting_epoch,
                    ..
                } if start.control_head == Some(*commitment) && start.epoch == *resulting_epoch
            )
        }) else {
            return Err(PrivateSyncError::Diverged);
        };
        skip = position
            .checked_add(1)
            .ok_or(PrivateSyncError::LimitExceeded)?;
        for item in &page.items[..skip] {
            let PrivateSyncItem::Control {
                commitment, wire, ..
            } = item
            else {
                return Err(PrivateSyncError::InvalidFrame);
            };
            if !store.control_is_exact(*commitment, wire)? {
                return Err(PrivateSyncError::Diverged);
            }
        }
    }
    let expected_epochs = store.prevalidate_controls(&records[skip..], node_authority)?;
    for (expected, item) in expected_epochs.iter().zip(&page.items[skip..]) {
        let PrivateSyncItem::Control {
            resulting_epoch, ..
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        if expected != resulting_epoch {
            return Err(PrivateSyncError::Tampered);
        }
    }
    let mut inserted = false;
    for (record, item) in records[..skip].iter().zip(&page.items[..skip]) {
        let PrivateSyncItem::Control { evidence, .. } = item else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        inserted |= store.persist_control_authority_evidence(record.commitment(), evidence)?
            == PutDisposition::Inserted;
    }
    for (record, item) in records[skip..].iter().zip(&page.items[skip..]) {
        let PrivateSyncItem::Control { evidence, .. } = item else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        inserted |= store.append_control(record, node_authority)? == PutDisposition::Inserted;
        inserted |= store.persist_control_authority_evidence(record.commitment(), evidence)?
            == PutDisposition::Inserted;
    }
    let result = store.binding();
    let expected_result = match page.items.last() {
        Some(PrivateSyncItem::Control {
            commitment,
            resulting_epoch,
            ..
        }) => PrivateSyncHead {
            epoch: *resulting_epoch,
            control_head: Some(*commitment),
        },
        _ => return Err(PrivateSyncError::InvalidFrame),
    };
    if result.epoch != expected_result.epoch || result.control_head != expected_result.control_head
    {
        return Err(PrivateSyncError::Tampered);
    }
    Ok(if inserted {
        PrivateSyncApplyDisposition::Applied
    } else {
        PrivateSyncApplyDisposition::AlreadyApplied
    })
}

/// Verify the complete authority-evidence correspondence for a controls page
/// without reading or mutating local artifacts. The host calls this before it
/// stages any decrypted epoch sidecar; `apply_control_page` calls it again
/// immediately before cumulative chain prevalidation and persistence.
pub(crate) fn verify_private_control_page_authority_evidence(
    page: &PrivateSyncPage,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<Vec<PrivateControlRecord>, PrivateSyncError> {
    if page.phase != PrivateSyncPhase::Controls {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    records
        .try_reserve(page.items.len())
        .map_err(|_| PrivateSyncError::LimitExceeded)?;
    for item in &page.items {
        let PrivateSyncItem::Control {
            sequence,
            commitment,
            resulting_epoch,
            wire,
            evidence,
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        let record = PrivateControlRecord::decode(wire).map_err(|_| PrivateSyncError::Tampered)?;
        if matches!(
            &record.operation,
            PrivateControlOperation::SetResourcePolicy { .. }
                | PrivateControlOperation::ActorLifecycle { .. }
        ) {
            // Completed authority evidence proves what the sender applied; it
            // cannot substitute for applying and reopening that transition on
            // this receiving runtime. Refuse before prevalidation or writes.
            return Err(PrivateSyncError::UnsupportedOperation);
        }
        let actual_epoch = match &record.operation {
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch }
            | PrivateControlOperation::Recover { next_epoch, .. } => Some(next_epoch.epoch),
            PrivateControlOperation::Invite { epoch, .. } => Some(*epoch),
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => None,
        };
        if record.space != page.request.cursor.space
            || record.agent != page.request.cursor.agent
            || record.sequence != *sequence
            || record.commitment() != *commitment
            || actual_epoch.is_some_and(|epoch| epoch != *resulting_epoch)
        {
            return Err(PrivateSyncError::Tampered);
        }
        if evidence.is_empty() {
            return Err(PrivateSyncError::MissingEvidence);
        }
        let envelope = PrivateControlAuthorityEvidence::decode(evidence)?;
        envelope.verify_for(&record, *resulting_epoch, route, authority)?;
        records.push(record);
    }
    Ok(records)
}

fn apply_object_page(
    store: &mut PrivateStore,
    page: &PrivateSyncPage,
) -> Result<PrivateSyncApplyDisposition, PrivateSyncError> {
    let binding = store.binding();
    let current = PrivateSyncHead {
        epoch: binding.epoch,
        control_head: binding.control_head,
    };
    if current != page.target || page.request.cursor.local != page.target {
        return Err(PrivateSyncError::Diverged);
    }
    let mut objects = Vec::new();
    objects
        .try_reserve(page.items.len())
        .map_err(|_| PrivateSyncError::LimitExceeded)?;
    for item in &page.items {
        let PrivateSyncItem::Object {
            key,
            wire_hash,
            wire,
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        if sync_wire_hash(wire) != *wire_hash {
            return Err(PrivateSyncError::Tampered);
        }
        let object =
            EncryptedPrivateObject::decode(wire).map_err(|_| PrivateSyncError::Tampered)?;
        if object.space != binding.space
            || object.agent != binding.agent
            || object.epoch > page.target.epoch
            || PrivateObjectKey::from_object(&object) != *key
        {
            return Err(PrivateSyncError::Tampered);
        }
        store.object_is_exact(*key, wire)?;
        objects.push(object);
    }
    let mut inserted = false;
    for object in &objects {
        inserted |= store.put_object(object)? == PutDisposition::Inserted;
    }
    Ok(if inserted {
        PrivateSyncApplyDisposition::Applied
    } else {
        PrivateSyncApplyDisposition::AlreadyApplied
    })
}

/// Reject any actor/storage descriptor which selects Linear state for a
/// Private agent. Runtime capability supersets remain valid; only installed
/// requirements and actual work are restricted.
pub fn validate_private_actor_schema(
    actor: &ActorDescriptor,
    storage: &[StorageFieldDescriptor],
) -> Result<(), PrivateSyncError> {
    actor
        .validate_for_profile(AgentProfile::Private)
        .map_err(map_private_model_error)?;
    if storage.iter().any(|field| field.validate().is_err()) {
        return Err(PrivateSyncError::InvalidRequest);
    }
    if storage.iter().any(|field| field.lane == StateLane::Linear) {
        return Err(PrivateSyncError::LinearUnsupported);
    }
    Ok(())
}

pub fn validate_private_runtime_work(work: &RuntimeWork) -> Result<(), PrivateSyncError> {
    if !work.execution_context().is_direct() {
        return Err(PrivateSyncError::InvalidRequest);
    }
    let state = match work {
        RuntimeWork::Manage { state, request, .. } => {
            match request.as_ref() {
                ManagementRequest::Create(descriptor) => {
                    descriptor.validate().map_err(map_private_model_error)?;
                    if descriptor.identity.profile != AgentProfile::Private {
                        return Err(PrivateSyncError::InvalidRequest);
                    }
                }
                ManagementRequest::Install(install) => install
                    .validate_for_profile(AgentProfile::Private)
                    .map_err(map_private_model_error)?,
                ManagementRequest::UpgradeActor(upgrade)
                    if !upgrade.requirements.supported_by(AgentProfile::Private) =>
                {
                    return Err(PrivateSyncError::LinearUnsupported);
                }
                _ => {}
            }
            state
        }
        RuntimeWork::Invoke {
            state, invocation, ..
        } => {
            if matches!(
                invocation.mode,
                MethodMode::Linear | MethodMode::LinearizableQuery
            ) {
                return Err(PrivateSyncError::LinearUnsupported);
            }
            state
        }
        RuntimeWork::Acknowledge {
            state, invocation, ..
        } => {
            if matches!(
                invocation.mode,
                MethodMode::Linear | MethodMode::LinearizableQuery
            ) {
                return Err(PrivateSyncError::LinearUnsupported);
            }
            state
        }
        RuntimeWork::Resume { state, resume, .. } => {
            if matches!(
                resume.mode,
                MethodMode::Linear | MethodMode::LinearizableQuery
            ) {
                return Err(PrivateSyncError::LinearUnsupported);
            }
            state
        }
    };
    if !state.linear.is_empty() {
        return Err(PrivateSyncError::LinearUnsupported);
    }
    Ok(())
}

fn map_private_model_error(error: ModelError) -> PrivateSyncError {
    if error == ModelError::InvalidProfile {
        PrivateSyncError::LinearUnsupported
    } else {
        PrivateSyncError::InvalidRequest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::agent::private_crypto::{
        GeneratedPrivateEpoch, OfflineRecoveryDecryptionKey, OwnerSigningKey,
        PrivateNodeDecryptionKey, RecoverySigningKey, build_recovery_keyring_grant,
        encrypt_private_object, generate_fresh_private_epoch, seal_data_key_for_node,
        seal_owner_key_for_node, sign_owner_control_record, sign_recovery_control_record,
        unwrap_data_key, unwrap_owner_key,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::authority::{
        AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
        AuthorityReceipt, AuthorityReceiptSelector,
    };
    use vos_agent_sdk::authority_operation::{
        PrivateControlApplicationFact, private_member_set_commitment,
    };
    use vos_agent_sdk::private::{
        EncryptedObjectKind, PrivateActorLifecycleKind, PrivateControlSigner,
    };
    use vos_agent_sdk::{
        ActorId, BlobRef, DeploymentId, InvocationId, LaneSet, PrincipalId, ProducerId, ProgramId,
        ResumeWork, RuntimeState,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const TEST_AUTHORITY_DOMAIN: &[u8] = b"vos/test/private-sync-authority/v1";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-private-sync-{label}-{}-{sequence}",
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

    struct TestAuthority;

    impl TestAuthority {
        fn binding(
            space: SpaceId,
            agent: AgentId,
            owner: PrincipalId,
            node: &PrivateNodeIdentity,
        ) -> Hash {
            Hash::digest(
                TEST_AUTHORITY_DOMAIN,
                &[
                    space.as_bytes(),
                    agent.as_bytes(),
                    owner.as_bytes(),
                    node.node.as_bytes(),
                    &node.transport_identity,
                    &node.encryption_public_key,
                    &node.transport_signature,
                ],
            )
        }
    }

    impl PrivateNodeAuthorityVerifier for TestAuthority {
        fn verify_private_node_binding(
            &self,
            space: SpaceId,
            agent: AgentId,
            expected_principal: PrincipalId,
            node: &PrivateNodeIdentity,
        ) -> bool {
            node.principal == expected_principal
                && node.authority_binding == Self::binding(space, agent, expected_principal, node)
        }
    }

    struct TestTransport;

    impl PrivateTransportAuthVerifier for TestTransport {
        fn verify_authenticated_private_node(
            &self,
            space: SpaceId,
            agent: AgentId,
            owner: PrincipalId,
            node: &PrivateNodeIdentity,
        ) -> bool {
            TestAuthority.verify_private_node_binding(space, agent, owner, node)
        }
    }

    struct RejectTransport;

    impl PrivateTransportAuthVerifier for RejectTransport {
        fn verify_authenticated_private_node(
            &self,
            _space: SpaceId,
            _agent: AgentId,
            _owner: PrincipalId,
            _node: &PrivateNodeIdentity,
        ) -> bool {
            false
        }
    }

    struct Recipient {
        identity: PrivateNodeIdentity,
        key: PrivateNodeDecryptionKey,
    }

    struct Fixture {
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        recovery: RecoverySigningKey,
        recovery_encryption: OfflineRecoveryDecryptionKey,
        recipients: Vec<Recipient>,
        nodes: Vec<PrivateNodeIdentity>,
        epoch: GeneratedPrivateEpoch,
        owner_key: OwnerSigningKey,
    }

    fn recipient(space: SpaceId, agent: AgentId, owner: PrincipalId, label: u8) -> Recipient {
        let key = PrivateNodeDecryptionKey::from_bytes([label; 32]).unwrap();
        let transport_identity = vec![label.wrapping_add(20); 48];
        let mut identity = PrivateNodeIdentity {
            node: vos_agent_sdk::NodeId::of_authenticated_peer(&transport_identity),
            principal: owner,
            transport_identity,
            encryption_public_key: key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [label.wrapping_add(40); 64],
        };
        identity.authority_binding = TestAuthority::binding(space, agent, owner, &identity);
        Recipient { identity, key }
    }

    fn fixture() -> Fixture {
        let space = SpaceId([11; 32]);
        let agent = AgentId([12; 32]);
        let owner = PrincipalId([13; 32]);
        let recovery = RecoverySigningKey::from_seed([14; 32]).unwrap();
        let recovery_encryption = OfflineRecoveryDecryptionKey::from_bytes([19; 32]).unwrap();
        let mut recipients = vec![
            recipient(space, agent, owner, 15),
            recipient(space, agent, owner, 16),
        ];
        recipients.sort_by_key(|recipient| recipient.identity.node);
        let nodes: Vec<_> = recipients
            .iter()
            .map(|recipient| recipient.identity.clone())
            .collect();
        let epoch = generate_fresh_private_epoch(
            space,
            agent,
            0,
            owner,
            &nodes,
            recovery.verifying_key(),
            recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let owner_key = unwrap_owner_key(&epoch.record, &nodes[0], &recipients[0].key).unwrap();
        Fixture {
            space,
            agent,
            owner,
            recovery,
            recovery_encryption,
            recipients,
            nodes,
            epoch,
            owner_key,
        }
    }

    fn create_store(path: &Path, fixture: &Fixture) -> PrivateStore {
        PrivateStore::create(
            path,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            fixture.epoch.record.clone(),
            fixture.nodes.clone(),
            &TestAuthority,
        )
        .unwrap()
    }

    fn test_authority_target(store: &PrivateStore) -> AuthorityActorTarget {
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let binding = store.binding();
        AuthorityActorTarget {
            space: binding.space,
            system_agent: AgentId([0x72; 32]),
            system_runtime_deployment: DeploymentId([0x73; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x74; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x75; 32]),
                    actor: ActorId([0x76; 32]),
                    deployment: DeploymentId([0x77; 32]),
                    program: ProgramId([0x78; 32]),
                    producer: ProducerId::of_public_key(&key.verifying_key().to_bytes()),
                },
                public_key: key.verifying_key().to_bytes(),
                initial_epoch: 1,
            },
        }
    }

    fn test_route(store: &PrivateStore) -> ManagedAgentTarget {
        let binding = store.binding();
        ManagedAgentTarget {
            space: binding.space,
            agent: binding.agent,
            runtime_deployment: DeploymentId([0x79; 32]),
        }
    }

    fn signed_evidence(
        store: &PrivateStore,
        control: &PrivateControlRecord,
    ) -> PrivateControlAuthorityEvidence {
        let route = test_route(store);
        let intent =
            AuthorityOperationIntent::private_control(route.runtime_deployment, control).unwrap();
        signed_evidence_for_intent(store, control, intent, None)
    }

    fn signed_recovery_evidence(
        store: &PrivateStore,
        control: &PrivateControlRecord,
        recovery: &RecoverySigningKey,
        superseded_authority_head: Option<Hash>,
    ) -> PrivateControlAuthorityEvidence {
        let route = test_route(store);
        let proof = PrivateRecoveryAuthorityProof::from_control(
            route.runtime_deployment,
            control,
            superseded_authority_head,
            recovery,
        )
        .unwrap();
        signed_evidence_for_intent(
            store,
            control,
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: proof.clone(),
            },
            Some(&proof),
        )
    }

    fn signed_evidence_for_intent(
        store: &PrivateStore,
        control: &PrivateControlRecord,
        intent: AuthorityOperationIntent,
        recovery_proof: Option<&PrivateRecoveryAuthorityProof>,
    ) -> PrivateControlAuthorityEvidence {
        let authority = test_authority_target(store);
        let route = test_route(store);
        assert_eq!(intent.managed(), route);
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let selector_actor = match &intent {
            AuthorityOperationIntent::PrivateActorLifecycle { actor, .. } => Some(*actor),
            _ => None,
        };
        let issued_at = control.sequence.saturating_add(20);
        let applied_at = issued_at.saturating_add(1);
        let authorization_sequence = NonZeroU64::new(control.sequence + 1).unwrap();
        let operation_call = Hash::digest(
            b"vos/test/private-sync-operation-call/v1",
            &[control.commitment().as_bytes()],
        );
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: authority.binding.policy,
                issuer: authority.binding.issuer,
                space: route.space,
                agent: route.agent,
                operation: intent.operation(),
                runtime_deployment: route.runtime_deployment,
                actor: selector_actor,
                actor_deployment: None,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x7a; 32]),
                },
                lane_roots: AuthorityLaneRoots {
                    control: None,
                    linear: Some(Hash([0x7b; 32])),
                    merge: None,
                    local: None,
                },
                epoch: authority.binding.initial_epoch,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: issued_at,
                expires_at: applied_at + 100,
                request: intent
                    .request_commitment(authorization_sequence, operation_call)
                    .unwrap(),
            },
            public_key: authority.binding.public_key,
            signature: [0; 64],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        let mut authorization = [0x7c; 32];
        authorization[31] = control.sequence as u8;
        let mut issuance_invocation = [0x7d; 32];
        issuance_invocation[31] = control.sequence as u8;
        let mut issuance = AuthorityOperationIssuanceAck {
            authorization_invocation: InvocationId(authorization),
            acknowledgement_invocation: InvocationId(issuance_invocation),
            authority,
            operation_call,
            approval: Hash::digest(
                b"vos/test/private-sync-operation-approval/v1",
                &[control.commitment().as_bytes()],
            ),
            authorization_sequence,
            receipt: receipt.clone(),
            issued_at,
            signature: [0; 64],
        };
        issuance.signature = key.sign(&issuance.signing_bytes()).to_bytes();
        let post_member_set =
            private_member_set_commitment(store.authorized_nodes().iter().map(|node| node.node))
                .unwrap();
        let application_fact = PrivateControlApplicationFact {
            managed: route,
            operation: intent.operation(),
            control: control.commitment(),
            control_sequence: control.sequence,
            control_previous: control.previous,
            epoch: store.binding().epoch,
            post_member_set,
            reopened_control_state: Hash([0x81; 32]),
            reopened_control_head: control.commitment(),
            applied_at,
        };
        let mut application = PrivateControlApplicationAck {
            authorization_invocation: issuance.authorization_invocation,
            issuance_invocation: issuance.acknowledgement_invocation,
            application_invocation: PrivateControlApplicationAck::derive_application_invocation(
                &issuance,
            ),
            authority,
            operation_call: issuance.operation_call,
            approval: issuance.approval,
            issuance_ack: issuance.commitment(),
            authorization_sequence: issuance.authorization_sequence,
            receipt,
            issued_at,
            application: application_fact,
            signature: [0; 64],
        };
        application.signature = key.sign(&application.signing_bytes()).to_bytes();
        let evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
            &issuance,
            &application,
            recovery_proof,
        )
        .unwrap();
        evidence
            .verify_for(control, store.binding().epoch, route, authority)
            .unwrap();
        evidence
    }

    fn attach_signed_evidence(store: &mut PrivateStore, control: &PrivateControlRecord) {
        let evidence = signed_evidence(store, control).encode().unwrap();
        store
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
    }

    fn attach_signed_recovery_evidence(
        store: &mut PrivateStore,
        control: &PrivateControlRecord,
        recovery: &RecoverySigningKey,
        superseded_authority_head: Option<Hash>,
    ) {
        let evidence =
            signed_recovery_evidence(store, control, recovery, superseded_authority_head)
                .encode()
                .unwrap();
        store
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
    }

    fn invite_record(store: &PrivateStore, fixture: &Fixture, label: u8) -> PrivateControlRecord {
        let node = recipient(fixture.space, fixture.agent, fixture.owner, label).identity;
        let binding = store.binding();
        let mut record = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: binding.next_sequence,
            previous: binding.control_head,
            operation: PrivateControlOperation::Invite {
                sealed_owner_key: seal_owner_key_for_node(
                    fixture.space,
                    fixture.agent,
                    binding.epoch,
                    &fixture.owner_key,
                    &node,
                )
                .unwrap(),
                sealed_data_key: seal_data_key_for_node(
                    fixture.space,
                    fixture.agent,
                    binding.epoch,
                    &fixture.epoch.data_key,
                    &node,
                )
                .unwrap(),
                node,
                epoch: binding.epoch,
                historical_grants: Vec::new(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut record, &fixture.owner_key).unwrap();
        record
    }

    fn directory_image(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        fn visit(root: &Path, path: &Path, image: &mut Vec<(String, Option<Vec<u8>>)>) {
            let mut entries: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    image.push((relative, None));
                    visit(root, &path, image);
                } else {
                    image.push((relative, Some(fs::read(path).unwrap())));
                }
            }
        }

        let mut image = Vec::new();
        visit(root, root, &mut image);
        image
    }

    fn serve_private_sync_page<V: PrivateTransportAuthVerifier>(
        store: &PrivateStore,
        peer: &PrivateNodeIdentity,
        request: &PrivateSyncRequest,
        transport: &V,
    ) -> Result<PrivateSyncPage, PrivateSyncError> {
        super::serve_private_sync_page(
            store,
            peer,
            request,
            transport,
            test_route(store),
            test_authority_target(store),
        )
    }

    fn apply_private_sync_page<A: PrivateNodeAuthorityVerifier, T: PrivateTransportAuthVerifier>(
        store: &mut PrivateStore,
        peer: &PrivateNodeIdentity,
        page: &PrivateSyncPage,
        authority: &A,
        transport: &T,
    ) -> Result<PrivateSyncApplyDisposition, PrivateSyncError> {
        let route = test_route(store);
        let target = test_authority_target(store);
        super::apply_private_sync_page(store, peer, page, authority, transport, route, target)
    }

    fn policy_record(
        fixture: &Fixture,
        sequence: u64,
        previous: Option<Hash>,
        label: u8,
    ) -> PrivateControlRecord {
        let mut record = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence,
            previous,
            operation: PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef {
                    hash: Hash([label; 32]),
                    len: 1,
                },
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut record, &fixture.owner_key).unwrap();
        record
    }

    fn request_for(store: &PrivateStore, max_items: u16, max_bytes: u32) -> PrivateSyncRequest {
        let binding = store.binding();
        PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(
                binding.space,
                binding.agent,
                binding.epoch,
                binding.control_head,
            )
            .unwrap(),
            max_items,
            max_bytes,
        }
    }

    fn converge(
        server: &PrivateStore,
        client: &mut PrivateStore,
        requester: &PrivateNodeIdentity,
        sender: &PrivateNodeIdentity,
        sentinel: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut request = request_for(client, 2, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        let mut frames = Vec::new();
        loop {
            let page =
                serve_private_sync_page(server, requester, &request, &TestTransport).unwrap();
            let frame = page.encode().unwrap();
            assert!(
                !frame
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
            );
            let decoded = PrivateSyncPage::decode(&frame).unwrap();
            apply_private_sync_page(client, sender, &decoded, &TestAuthority, &TestTransport)
                .unwrap();
            frames.push(frame);
            let Some(next) = decoded.next else {
                break;
            };
            request = PrivateSyncRequest {
                cursor: next,
                max_items: 2,
                max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
            };
        }
        frames
    }

    #[test]
    fn two_nodes_converge_in_bounded_pages_and_restart_from_canonical_state() {
        let directory = TestDirectory::new("converge");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let mut client = create_store(&directory.child("client"), &fixture);
        let successor = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            core::slice::from_ref(&fixture.recipients[0].identity),
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut record = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Revoke {
                node: fixture.recipients[1].identity.node,
                next_epoch: successor.record,
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut record, &fixture.owner_key).unwrap();
        server.append_control(&record, &TestAuthority).unwrap();
        attach_signed_evidence(&mut server, &record);
        let sentinel = b"PRIVATE-FRAME-SENTINEL-8d21";
        for kind in [
            EncryptedObjectKind::Package,
            EncryptedObjectKind::Blob,
            EncryptedObjectKind::CrdtNode,
            EncryptedObjectKind::Index,
            EncryptedObjectKind::Snapshot,
        ] {
            let mut plaintext = sentinel.to_vec();
            plaintext.push(kind as u8);
            let object = encrypt_private_object(
                &fixture.epoch.data_key,
                fixture.space,
                fixture.agent,
                0,
                kind,
                &plaintext,
            )
            .unwrap();
            server.put_object(&object).unwrap();
        }
        let frames = converge(
            &server,
            &mut client,
            &fixture.recipients[0].identity,
            &fixture.recipients[0].identity,
            sentinel,
        );
        assert!(frames.len() >= 4);
        assert_eq!(client.binding(), server.binding());
        assert_eq!(client.object_count(), 5);
        assert_eq!(client.control_count(), 1);
        let client_path = directory.child("client");
        drop(client);
        let reopened =
            PrivateStore::open(&client_path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(reopened.binding(), server.binding());
        assert_eq!(reopened.object_count(), server.object_count());
    }

    #[test]
    fn revoked_unknown_and_non_identity_peers_trigger_zero_artifact_reads() {
        let directory = TestDirectory::new("revoked");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let survivor = fixture.recipients[0].identity.clone();
        let revoked = fixture.recipients[1].identity.clone();
        let successor = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            core::slice::from_ref(&survivor),
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut revoke = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Revoke {
                node: revoked.node,
                next_epoch: successor.record.clone(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut revoke, &fixture.owner_key).unwrap();
        server.append_control(&revoke, &TestAuthority).unwrap();
        attach_signed_evidence(&mut server, &revoke);
        let future = encrypt_private_object(
            &successor.data_key,
            fixture.space,
            fixture.agent,
            1,
            EncryptedObjectKind::Blob,
            b"future-revoked-node-must-not-see",
        )
        .unwrap();
        server.put_object(&future).unwrap();
        let request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, fixture.agent, 0, None).unwrap(),
            max_items: 4,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        server.reset_artifact_read_spy();
        assert_eq!(
            serve_private_sync_page(&server, &revoked, &request, &TestTransport).err(),
            Some(PrivateSyncError::Unauthorized)
        );
        assert_eq!(server.artifact_read_spy(), 0);

        let unknown = recipient(fixture.space, fixture.agent, fixture.owner, 17).identity;
        assert_eq!(
            serve_private_sync_page(&server, &unknown, &request, &TestTransport).err(),
            Some(PrivateSyncError::Unauthorized)
        );
        let mut credential_only = unknown;
        credential_only.transport_identity.clear();
        assert_eq!(
            serve_private_sync_page(&server, &credential_only, &request, &TestTransport).err(),
            Some(PrivateSyncError::Unauthorized)
        );
        let mut wrong_principal = survivor.clone();
        wrong_principal.principal = PrincipalId([99; 32]);
        assert_eq!(
            serve_private_sync_page(&server, &wrong_principal, &request, &TestTransport).err(),
            Some(PrivateSyncError::Unauthorized)
        );
        let mut aliased_identity = survivor.clone();
        aliased_identity.encryption_public_key[0] ^= 1;
        assert_eq!(
            serve_private_sync_page(&server, &aliased_identity, &request, &TestTransport).err(),
            Some(PrivateSyncError::Unauthorized)
        );
        assert_eq!(server.artifact_read_spy(), 0);

        let survivor_request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, fixture.agent, 0, None).unwrap(),
            max_items: 4,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        serve_private_sync_page(&server, &survivor, &survivor_request, &TestTransport).unwrap();
        assert!(server.artifact_read_spy() > 0);
    }

    #[test]
    fn hostile_inbound_apply_is_rejected_before_reads_or_mutation() {
        let directory = TestDirectory::new("hostile-apply");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let mut client = create_store(&directory.child("client"), &fixture);
        let object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Index,
            b"authenticated-apply-only",
        )
        .unwrap();
        server.put_object(&object).unwrap();
        let request = request_for(&client, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        let page = serve_private_sync_page(
            &server,
            &fixture.recipients[1].identity,
            &request,
            &TestTransport,
        )
        .unwrap();
        let before = client.binding();
        let before_objects = client.object_count();
        client.reset_artifact_read_spy();

        let unknown = recipient(fixture.space, fixture.agent, fixture.owner, 18).identity;
        assert_eq!(
            apply_private_sync_page(&mut client, &unknown, &page, &TestAuthority, &TestTransport,),
            Err(PrivateSyncError::Unauthorized)
        );
        assert_eq!(client.artifact_read_spy(), 0);
        assert_eq!(client.binding(), before);
        assert_eq!(client.object_count(), before_objects);

        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &page,
                &TestAuthority,
                &RejectTransport,
            ),
            Err(PrivateSyncError::Unauthorized)
        );
        assert_eq!(client.artifact_read_spy(), 0);
        assert_eq!(client.binding(), before);
        assert_eq!(client.object_count(), before_objects);
    }

    #[test]
    fn controls_without_exact_evidence_are_neither_served_nor_applied() {
        let directory = TestDirectory::new("missing-evidence");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let mut client = create_store(&directory.child("client"), &fixture);
        let control = invite_record(&server, &fixture, 50);
        server.append_control(&control, &TestAuthority).unwrap();
        let request = request_for(&client, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &request,
                &TestTransport,
            ),
            Err(PrivateSyncError::MissingEvidence)
        );

        attach_signed_evidence(&mut server, &control);
        let page = serve_private_sync_page(
            &server,
            &fixture.recipients[0].identity,
            &request,
            &TestTransport,
        )
        .unwrap();
        let item_bytes = page.items[0].encoded_payload_len().unwrap();
        let too_small = PrivateSyncRequest {
            cursor: request.cursor.clone(),
            max_items: 1,
            max_bytes: u32::try_from(item_bytes - 1).unwrap(),
        };
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &too_small,
                &TestTransport,
            ),
            Err(PrivateSyncError::LimitTooSmall)
        );
        let exact = PrivateSyncRequest {
            cursor: request.cursor,
            max_items: 1,
            max_bytes: u32::try_from(item_bytes).unwrap(),
        };
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &exact,
                &TestTransport,
            )
            .unwrap()
            .items
            .len(),
            1
        );

        let mut oversized = page.clone();
        let oversized_evidence = vec![0; MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES + 1];
        let PrivateSyncItem::Control { evidence, .. } = &mut oversized.items[0] else {
            unreachable!()
        };
        *evidence = oversized_evidence.clone();
        assert_eq!(oversized.encode(), Err(PrivateSyncError::LimitExceeded));
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&oversized_evidence),
            Err(PrivateSyncError::InvalidFrame)
        );

        let mut missing = page;
        let PrivateSyncItem::Control { evidence, .. } = &mut missing.items[0] else {
            unreachable!()
        };
        evidence.clear();
        let before = directory_image(&directory.child("client"));
        client.reset_artifact_read_spy();
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &missing,
                &TestAuthority,
                &TestTransport,
            ),
            Err(PrivateSyncError::MissingEvidence)
        );
        assert_eq!(client.artifact_read_spy(), 0);
        assert_eq!(directory_image(&directory.child("client")), before);
    }

    #[test]
    fn retained_exact_page_attaches_evidence_to_a_crash_visible_control_prefix() {
        let directory = TestDirectory::new("retry-evidence-prefix");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let client_path = directory.child("client");
        let mut client = create_store(&client_path, &fixture);
        let control = invite_record(&server, &fixture, 50);
        server.append_control(&control, &TestAuthority).unwrap();
        attach_signed_evidence(&mut server, &control);
        let request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, fixture.agent, 0, None).unwrap(),
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        let page = serve_private_sync_page(
            &server,
            &fixture.recipients[0].identity,
            &request,
            &TestTransport,
        )
        .unwrap();

        // Model process loss after the PCTL index became visible but before
        // its PSE2 transaction began. Reopen must preserve this state, and an
        // exact retained page retry attaches evidence without appending the
        // control a second time.
        client.append_control(&control, &TestAuthority).unwrap();
        drop(client);
        let mut client =
            PrivateStore::open(&client_path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(
            client
                .read_control_authority_evidence(&client.indexed_controls()[0])
                .unwrap(),
            None
        );
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &page,
                &TestAuthority,
                &TestTransport,
            ),
            Ok(PrivateSyncApplyDisposition::Applied)
        );
        assert_eq!(client.control_count(), 1);
        let expected = match &page.items[0] {
            PrivateSyncItem::Control { evidence, .. } => evidence.as_slice(),
            PrivateSyncItem::Object { .. } => unreachable!(),
        };
        assert_eq!(
            client
                .read_control_authority_evidence(&client.indexed_controls()[0])
                .unwrap()
                .as_deref(),
            Some(expected)
        );
        drop(client);
        let reopened =
            PrivateStore::open(&client_path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(
            reopened
                .read_control_authority_evidence(&reopened.indexed_controls()[0])
                .unwrap()
                .as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn signed_evidence_substitutions_are_rejected_by_independent_exact_verification() {
        let directory = TestDirectory::new("evidence-substitutions");
        let fixture = fixture();
        let mut store = create_store(&directory.child("store"), &fixture);
        let control = invite_record(&store, &fixture, 50);
        store.append_control(&control, &TestAuthority).unwrap();
        let route = test_route(&store);
        let authority = test_authority_target(&store);
        let evidence = signed_evidence(&store, &control);
        evidence
            .verify_for(&control, store.binding().epoch, route, authority)
            .unwrap();
        let key = SigningKey::from_bytes(&[0x71; 32]);

        let reject = |candidate: PrivateControlAuthorityEvidence| {
            assert_eq!(
                candidate.verify_for(&control, store.binding().epoch, route, authority),
                Err(PrivateSyncError::Tampered)
            );
        };

        let mut issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack).unwrap();
        issuance.signature[0] ^= 1;
        reject(PrivateControlAuthorityEvidence {
            issuance_ack: issuance.encode().unwrap(),
            application_ack: evidence.application_ack.clone(),
            recovery_proof: None,
        });

        let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack).unwrap();
        let mut application =
            PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
        application.signature[0] ^= 1;
        reject(PrivateControlAuthorityEvidence {
            issuance_ack: evidence.issuance_ack.clone(),
            application_ack: application.encode().unwrap(),
            recovery_proof: None,
        });

        let mut substituted_issuance = issuance.clone();
        let mut substituted_application =
            PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
        substituted_issuance.authority.system_agent = AgentId([0x91; 32]);
        substituted_application.authority = substituted_issuance.authority;
        substituted_issuance.signature = key.sign(&substituted_issuance.signing_bytes()).to_bytes();
        substituted_application.issuance_ack = substituted_issuance.commitment();
        substituted_application.application_invocation =
            PrivateControlApplicationAck::derive_application_invocation(&substituted_issuance);
        substituted_application.signature = key
            .sign(&substituted_application.signing_bytes())
            .to_bytes();
        reject(
            PrivateControlAuthorityEvidence::from_acknowledgements(
                &substituted_issuance,
                &substituted_application,
                None,
            )
            .unwrap(),
        );

        let mut substituted_issuance = issuance.clone();
        let mut substituted_application =
            PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
        substituted_issuance.receipt.selector.runtime_deployment = DeploymentId([0x92; 32]);
        substituted_issuance.receipt.signature = key
            .sign(&substituted_issuance.receipt.signing_bytes())
            .to_bytes();
        substituted_application.receipt = substituted_issuance.receipt.clone();
        substituted_application
            .application
            .managed
            .runtime_deployment = DeploymentId([0x92; 32]);
        substituted_issuance.signature = key.sign(&substituted_issuance.signing_bytes()).to_bytes();
        substituted_application.issuance_ack = substituted_issuance.commitment();
        substituted_application.application_invocation =
            PrivateControlApplicationAck::derive_application_invocation(&substituted_issuance);
        substituted_application.signature = key
            .sign(&substituted_application.signing_bytes())
            .to_bytes();
        reject(
            PrivateControlAuthorityEvidence::from_acknowledgements(
                &substituted_issuance,
                &substituted_application,
                None,
            )
            .unwrap(),
        );

        for mutation in 0..5 {
            let mut application =
                PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
            match mutation {
                0 => application.application.control = Hash([0x93; 32]),
                1 => application.application.control_sequence += 1,
                2 => application.application.control_previous = Some(Hash([0x94; 32])),
                3 => application.application.epoch += 1,
                4 => application.issued_at += 1,
                _ => unreachable!(),
            }
            application.signature = key.sign(&application.signing_bytes()).to_bytes();
            match PrivateControlAuthorityEvidence::from_acknowledgements(
                &issuance,
                &application,
                None,
            ) {
                Ok(candidate) => reject(candidate),
                Err(error) => assert_eq!(error, PrivateSyncError::InvalidFrame),
            }
        }

        let alternate = invite_record(&store, &fixture, 51);
        reject(signed_evidence(&store, &alternate));
        let mut noncanonical = evidence.encode().unwrap();
        noncanonical.push(0);
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&noncanonical),
            Err(PrivateSyncError::InvalidFrame)
        );
    }

    #[test]
    fn pse2_binds_exact_recovery_proof_and_rejects_old_mixed_or_missing_proof_frames() {
        let directory = TestDirectory::new("recovery-evidence-proof-binding");
        let fixture = fixture();
        let mut store = create_store(&directory.child("recovery"), &fixture);
        let first_head = policy_record(&fixture, 0, None, 41);
        let second_head = policy_record(&fixture, 0, None, 42);
        store.append_control(&first_head, &TestAuthority).unwrap();
        let successor = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            &fixture.nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let historical_keys = BTreeMap::from([(
            fixture.epoch.record.epoch,
            unwrap_data_key(
                &fixture.epoch.record,
                &fixture.recipients[0].identity,
                &fixture.recipients[0].key,
            )
            .unwrap(),
        )]);
        let historical_keyring = build_recovery_keyring_grant(
            core::slice::from_ref(&fixture.epoch.record),
            &historical_keys,
            &successor.record,
            &fixture.nodes,
        )
        .unwrap();
        let mut superseded_heads = vec![first_head.commitment(), second_head.commitment()];
        superseded_heads.sort();
        let mut recovery = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 1,
            previous: Some(first_head.commitment()),
            operation: PrivateControlOperation::Recover {
                superseded_heads,
                next_epoch: successor.record,
                replacement_nodes: fixture.nodes.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();
        store.append_control(&recovery, &TestAuthority).unwrap();

        let first = signed_recovery_evidence(
            &store,
            &recovery,
            &fixture.recovery,
            Some(first_head.commitment()),
        );
        let second = signed_recovery_evidence(
            &store,
            &recovery,
            &fixture.recovery,
            Some(second_head.commitment()),
        );
        let first_wire = first.encode().unwrap();
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&first_wire),
            Ok(first.clone())
        );
        first
            .verify_for(
                &recovery,
                store.binding().epoch,
                test_route(&store),
                test_authority_target(&store),
            )
            .unwrap();
        assert_ne!(first.recovery_proof, second.recovery_proof);

        // AOI1 and PCA1 were signed for the first PRA1 selector. A second,
        // independently valid PRA1 for the same PCTL but another authority
        // projection head cannot be substituted into the retained envelope.
        let mixed = PrivateControlAuthorityEvidence {
            issuance_ack: first.issuance_ack.clone(),
            application_ack: first.application_ack.clone(),
            recovery_proof: second.recovery_proof.clone(),
        };
        assert_eq!(
            mixed.verify_for(
                &recovery,
                store.binding().epoch,
                test_route(&store),
                test_authority_target(&store),
            ),
            Err(PrivateSyncError::Tampered)
        );

        let mut missing = first.clone();
        missing.recovery_proof = None;
        assert_eq!(missing.encode(), Err(PrivateSyncError::InvalidFrame));

        let mut normal_store = create_store(&directory.child("normal"), &fixture);
        let normal_control = invite_record(&normal_store, &fixture, 50);
        normal_store
            .append_control(&normal_control, &TestAuthority)
            .unwrap();
        let mut unexpected = signed_evidence(&normal_store, &normal_control);
        unexpected.recovery_proof = first.recovery_proof.clone();
        assert_eq!(unexpected.encode(), Err(PrivateSyncError::InvalidFrame));

        let mut old = first_wire.clone();
        old[..4].copy_from_slice(b"PSE1");
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&old),
            Err(PrivateSyncError::InvalidFrame)
        );
        let proof_tag = 4 + 2 + 4 + first.issuance_ack.len() + 4 + first.application_ack.len();
        let mut mixed_frame = first_wire.clone();
        mixed_frame[proof_tag] = 0;
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&mixed_frame),
            Err(PrivateSyncError::InvalidFrame)
        );
        let mut trailing = first_wire;
        trailing.push(0);
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&trailing),
            Err(PrivateSyncError::InvalidFrame)
        );
        assert_eq!(
            MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES,
            4 + 2
                + 4
                + vos_agent_sdk::authority_operation::MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
                + 4
                + MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES
                + 1
                + 4
                + MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES
        );
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&vec![
                0;
                MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
                    + 1
            ]),
            Err(PrivateSyncError::InvalidFrame)
        );
    }

    #[test]
    fn lifecycle_evidence_binds_the_exact_actor_selector() {
        let directory = TestDirectory::new("lifecycle-evidence-selector");
        let fixture = fixture();
        let mut store = create_store(&directory.child("store"), &fixture);
        let actor = ActorId([0x95; 32]);
        let mut control = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::ActorLifecycle {
                actor,
                operation: PrivateActorLifecycleKind::Install,
                request: Hash([0x96; 32]),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut control, &fixture.owner_key).unwrap();
        store.append_control(&control, &TestAuthority).unwrap();
        let route = test_route(&store);
        let authority = test_authority_target(&store);
        let evidence = signed_evidence(&store, &control);
        let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack).unwrap();
        assert_eq!(issuance.receipt.selector.actor, Some(actor));
        assert_eq!(issuance.receipt.selector.actor_deployment, None);

        let key = SigningKey::from_bytes(&[0x71; 32]);
        let mut substituted_issuance = issuance;
        substituted_issuance.receipt.selector.actor = Some(ActorId([0x97; 32]));
        substituted_issuance.receipt.signature = [0; 64];
        substituted_issuance.receipt.signature = key
            .sign(&substituted_issuance.receipt.signing_bytes())
            .to_bytes();
        substituted_issuance.signature = [0; 64];
        substituted_issuance.signature = key.sign(&substituted_issuance.signing_bytes()).to_bytes();
        let mut substituted_application =
            PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
        substituted_application.receipt = substituted_issuance.receipt.clone();
        substituted_application.issuance_ack = substituted_issuance.commitment();
        substituted_application.application_invocation =
            PrivateControlApplicationAck::derive_application_invocation(&substituted_issuance);
        substituted_application.signature = [0; 64];
        substituted_application.signature = key
            .sign(&substituted_application.signing_bytes())
            .to_bytes();
        let substituted = PrivateControlAuthorityEvidence::from_acknowledgements(
            &substituted_issuance,
            &substituted_application,
            None,
        )
        .unwrap();
        assert_eq!(
            substituted.verify_for(&control, store.binding().epoch, route, authority),
            Err(PrivateSyncError::Tampered)
        );
    }

    #[test]
    fn completed_unimplemented_controls_do_not_advance_sync_receiver() {
        let directory = TestDirectory::new("unsupported-completed-controls");
        let fixture = fixture();
        let operations = [
            PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(b"private-resource-policy"),
            },
            PrivateControlOperation::ActorLifecycle {
                actor: ActorId([0x98; 32]),
                operation: PrivateActorLifecycleKind::Install,
                request: Hash([0x99; 32]),
            },
        ];

        for (index, operation) in operations.into_iter().enumerate() {
            let server_path = directory.child(&format!("server-{index}"));
            let client_path = directory.child(&format!("client-{index}"));
            let mut server = create_store(&server_path, &fixture);
            let mut client = create_store(&client_path, &fixture);
            let mut control = PrivateControlRecord {
                space: fixture.space,
                agent: fixture.agent,
                sequence: 0,
                previous: None,
                operation,
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0; 32],
                signature: [0; 64],
            };
            sign_owner_control_record(&mut control, &fixture.owner_key).unwrap();
            server.append_control(&control, &TestAuthority).unwrap();
            attach_signed_evidence(&mut server, &control);

            let request = request_for(&client, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
            let page = serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &request,
                &TestTransport,
            )
            .unwrap();
            assert_eq!(page.items.len(), 1);

            let before_binding = client.binding();
            let before_counts = (client.control_count(), client.object_count());
            let before_image = directory_image(&client_path);
            assert_eq!(
                apply_private_sync_page(
                    &mut client,
                    &fixture.recipients[0].identity,
                    &page,
                    &TestAuthority,
                    &TestTransport,
                ),
                Err(PrivateSyncError::UnsupportedOperation)
            );
            assert_eq!(client.binding(), before_binding);
            assert_eq!(
                (client.control_count(), client.object_count()),
                before_counts
            );
            assert_eq!(directory_image(&client_path), before_image);

            drop(client);
            let mut reopened =
                PrivateStore::open(&client_path, fixture.space, fixture.agent, &TestAuthority)
                    .unwrap();
            assert_eq!(reopened.binding(), before_binding);
            assert_eq!(
                (reopened.control_count(), reopened.object_count()),
                before_counts
            );
            assert_eq!(directory_image(&client_path), before_image);
            assert_eq!(
                apply_private_sync_page(
                    &mut reopened,
                    &fixture.recipients[0].identity,
                    &page,
                    &TestAuthority,
                    &TestTransport,
                ),
                Err(PrivateSyncError::UnsupportedOperation)
            );
            assert_eq!(reopened.binding(), before_binding);
            assert_eq!(
                (reopened.control_count(), reopened.object_count()),
                before_counts
            );
            assert_eq!(directory_image(&client_path), before_image);
        }
    }

    #[test]
    fn complete_control_page_is_prevalidated_before_any_local_mutation() {
        let directory = TestDirectory::new("whole-page-prevalidation");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let first = invite_record(&server, &fixture, 50);
        server.append_control(&first, &TestAuthority).unwrap();
        attach_signed_evidence(&mut server, &first);
        let second = invite_record(&server, &fixture, 51);
        server.append_control(&second, &TestAuthority).unwrap();
        attach_signed_evidence(&mut server, &second);

        let make_page = |client: &PrivateStore| {
            let request = request_for(client, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &request,
                &TestTransport,
            )
            .unwrap()
        };

        let first_client_path = directory.child("invalid-pse-client");
        let mut first_client = create_store(&first_client_path, &fixture);
        let mut invalid_pse = make_page(&first_client);
        assert_eq!(invalid_pse.items.len(), 2);
        let PrivateSyncItem::Control { evidence, .. } = &mut invalid_pse.items[1] else {
            unreachable!()
        };
        let mut decoded = PrivateControlAuthorityEvidence::decode(evidence).unwrap();
        let mut application =
            PrivateControlApplicationAck::decode(&decoded.application_ack).unwrap();
        application.signature[0] ^= 1;
        decoded.application_ack = application.encode().unwrap();
        *evidence = decoded.encode().unwrap();
        let before = directory_image(&first_client_path);
        first_client.reset_artifact_read_spy();
        assert_eq!(
            apply_private_sync_page(
                &mut first_client,
                &fixture.recipients[0].identity,
                &invalid_pse,
                &TestAuthority,
                &TestTransport,
            ),
            Err(PrivateSyncError::Tampered)
        );
        assert_eq!(first_client.artifact_read_spy(), 0);
        assert_eq!(directory_image(&first_client_path), before);
        assert_eq!(
            (first_client.control_count(), first_client.object_count()),
            (0, 0)
        );

        let second_client_path = directory.child("invalid-chain-client");
        let mut second_client = create_store(&second_client_path, &fixture);
        let mut invalid_chain = make_page(&second_client);
        let mut alternate = second.clone();
        alternate.previous = Some(Hash([0x95; 32]));
        sign_owner_control_record(&mut alternate, &fixture.owner_key).unwrap();
        let alternate_evidence = signed_evidence(&server, &alternate).encode().unwrap();
        let alternate_commitment = alternate.commitment();
        let PrivateSyncItem::Control {
            commitment,
            wire,
            evidence,
            ..
        } = &mut invalid_chain.items[1]
        else {
            unreachable!()
        };
        *commitment = alternate_commitment;
        *wire = alternate.encode().unwrap();
        *evidence = alternate_evidence;
        invalid_chain.target.control_head = Some(alternate_commitment);
        if let Some(next) = &mut invalid_chain.next {
            next.local.control_head = Some(alternate_commitment);
            next.target = Some(invalid_chain.target);
        }
        invalid_chain.validate_shape().unwrap();
        let before = directory_image(&second_client_path);
        second_client.reset_artifact_read_spy();
        assert!(
            apply_private_sync_page(
                &mut second_client,
                &fixture.recipients[0].identity,
                &invalid_chain,
                &TestAuthority,
                &TestTransport,
            )
            .is_err()
        );
        assert_eq!(second_client.artifact_read_spy(), 0);
        assert_eq!(directory_image(&second_client_path), before);
        assert_eq!(
            (second_client.control_count(), second_client.object_count()),
            (0, 0)
        );
    }

    #[test]
    fn offline_recovery_converges_an_explicitly_superseded_control_fork() {
        let directory = TestDirectory::new("recovery-fork");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let mut client = create_store(&directory.child("client"), &fixture);
        let fork_a = policy_record(&fixture, 0, None, 41);
        let fork_b = policy_record(&fixture, 0, None, 42);
        server.append_control(&fork_a, &TestAuthority).unwrap();
        client.append_control(&fork_b, &TestAuthority).unwrap();
        let successor = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            &fixture.nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut heads = vec![fork_a.commitment(), fork_b.commitment()];
        heads.sort();
        let historical_keys = BTreeMap::from([(
            fixture.epoch.record.epoch,
            unwrap_data_key(
                &fixture.epoch.record,
                &fixture.recipients[0].identity,
                &fixture.recipients[0].key,
            )
            .unwrap(),
        )]);
        let historical_keyring = build_recovery_keyring_grant(
            core::slice::from_ref(&fixture.epoch.record),
            &historical_keys,
            &successor.record,
            &fixture.nodes,
        )
        .unwrap();
        let mut recovery = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 1,
            previous: Some(fork_a.commitment()),
            operation: PrivateControlOperation::Recover {
                superseded_heads: heads,
                next_epoch: successor.record,
                replacement_nodes: fixture.nodes.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();
        server.append_control(&recovery, &TestAuthority).unwrap();
        attach_signed_recovery_evidence(&mut server, &recovery, &fixture.recovery, None);

        let request = request_for(&client, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        let page = serve_private_sync_page(
            &server,
            &fixture.recipients[0].identity,
            &request,
            &TestTransport,
        )
        .unwrap();
        assert_eq!(page.phase, PrivateSyncPhase::Controls);
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &page,
                &TestAuthority,
                &TestTransport,
            ),
            Ok(PrivateSyncApplyDisposition::Applied)
        );
        assert_eq!(client.binding(), server.binding());
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &page,
                &TestAuthority,
                &TestTransport,
            ),
            Ok(PrivateSyncApplyDisposition::AlreadyApplied)
        );
        let path = directory.child("client");
        drop(client);
        let reopened =
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(reopened.binding(), server.binding());
    }

    #[test]
    fn canonical_pages_reject_cursor_alias_duplicates_order_tamper_and_bounds() {
        let directory = TestDirectory::new("canonical");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let mut client = create_store(&directory.child("client"), &fixture);
        for label in 0..3u8 {
            let object = encrypt_private_object(
                &fixture.epoch.data_key,
                fixture.space,
                fixture.agent,
                0,
                EncryptedObjectKind::Blob,
                &[label; 32],
            )
            .unwrap();
            server.put_object(&object).unwrap();
        }
        let request = request_for(&client, 1, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        let page = serve_private_sync_page(
            &server,
            &fixture.recipients[0].identity,
            &request,
            &TestTransport,
        )
        .unwrap();
        // Genesis is represented by the empty control chain. Object sync at
        // that exact head needs no synthetic or fabricated PSE2.
        assert_eq!(page.phase, PrivateSyncPhase::Objects);
        assert_eq!(page.items.len(), 1);
        assert!(page.next.is_some());
        let request_wire = request.encode().unwrap();
        assert_eq!(PrivateSyncRequest::decode(&request_wire), Ok(request));
        let page_wire = page.encode().unwrap();
        assert_eq!(PrivateSyncPage::decode(&page_wire), Ok(page.clone()));
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &page,
                &TestAuthority,
                &TestTransport,
            ),
            Ok(PrivateSyncApplyDisposition::Applied)
        );
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &page,
                &TestAuthority,
                &TestTransport,
            ),
            Ok(PrivateSyncApplyDisposition::AlreadyApplied)
        );

        let mut alias_request = PrivateSyncRequest {
            cursor: page.next.clone().unwrap(),
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        alias_request.cursor.after_object = Some(PrivateObjectKey {
            epoch: 0,
            kind: EncryptedObjectKind::Blob as u8,
            content: Hash([99; 32]),
        });
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &alias_request,
                &TestTransport
            )
            .err(),
            Some(PrivateSyncError::Alias)
        );

        let mut duplicate = page.clone();
        duplicate.items.push(duplicate.items[0].clone());
        duplicate.request.max_items = 2;
        assert_eq!(duplicate.validate_shape(), Err(PrivateSyncError::Duplicate));

        let mut ordered_request = request_for(&client, 3, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        ordered_request.cursor.after_object = None;
        let mut ordered = serve_private_sync_page(
            &server,
            &fixture.recipients[0].identity,
            &ordered_request,
            &TestTransport,
        )
        .unwrap();
        ordered.items.swap(0, 1);
        assert_eq!(ordered.validate_shape(), Err(PrivateSyncError::OutOfOrder));

        let mut tampered = page.clone();
        let PrivateSyncItem::Object { wire, .. } = &mut tampered.items[0] else {
            unreachable!()
        };
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &tampered,
                &TestAuthority,
                &TestTransport,
            ),
            Err(PrivateSyncError::Tampered)
        );

        let mut truncated = page_wire;
        truncated.pop();
        assert!(PrivateSyncPage::decode(&truncated).is_err());
        let too_many = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, fixture.agent, 0, None).unwrap(),
            max_items: MAX_PRIVATE_SYNC_ITEMS as u16 + 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        assert_eq!(too_many.validate(), Err(PrivateSyncError::LimitExceeded));
        let too_small = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, fixture.agent, 0, None).unwrap(),
            max_items: 1,
            max_bytes: 1,
        };
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &too_small,
                &TestTransport
            )
            .err(),
            Some(PrivateSyncError::LimitTooSmall)
        );
    }

    #[test]
    fn private_profile_rejects_linear_actor_schema_and_runtime_work() {
        let blob = || BlobRef::of_bytes(b"private-profile-artifact");
        let mut actor = ActorDescriptor {
            actor: ActorId([1; 32]),
            name: "private-actor".into(),
            parent: None,
            deployment: DeploymentId([2; 32]),
            program: ProgramId([3; 32]),
            package: blob(),
            agent_schema: blob(),
            method_policy: blob(),
            constructor_abi: Hash([0x0b; 32]),
            installation_data: None,
            state_layout: Hash([4; 32]),
            lanes: LaneSet::of(StateLane::Merge),
            suspended: false,
        };
        let mut storage = StorageFieldDescriptor::derive(
            Hash([5; 32]),
            "values",
            vos_agent_sdk::StorageKind::Map,
            StateLane::Merge,
            true,
            b"key",
            b"value",
        );
        assert_eq!(
            validate_private_actor_schema(&actor, &[storage.clone()]),
            Ok(())
        );
        actor.lanes = LaneSet::of(StateLane::Linear);
        assert_eq!(
            validate_private_actor_schema(&actor, &[storage.clone()]),
            Err(PrivateSyncError::LinearUnsupported)
        );
        actor.lanes = LaneSet::of(StateLane::Merge);
        storage.lane = StateLane::Linear;
        assert_eq!(
            validate_private_actor_schema(&actor, &[storage]),
            Err(PrivateSyncError::LinearUnsupported)
        );

        let resume = || ResumeWork {
            invocation: InvocationId([6; 32]),
            actor: ActorId([7; 32]),
            incarnation: Hash([8; 32]),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            mode: MethodMode::Merge,
            continuation: BlobRef::of_bytes(b"continuation"),
            ready_sequence: 1,
            installation_data: None,
            availability: Vec::new(),
            input: None,
        };
        let mut work = RuntimeWork::Resume {
            context: vos_agent_sdk::RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            resume: Box::new(resume()),
        };
        assert_eq!(validate_private_runtime_work(&work), Ok(()));
        let RuntimeWork::Resume { context, .. } = &mut work else {
            unreachable!()
        };
        *context = vos_agent_sdk::RuntimeExecutionContext::Attested {
            proof_system: Hash([0x0c; 32]),
        };
        assert_eq!(
            validate_private_runtime_work(&work),
            Err(PrivateSyncError::InvalidRequest),
            "the current Private executor must fail closed on attested work"
        );
        let RuntimeWork::Resume { context, .. } = &mut work else {
            unreachable!()
        };
        *context = vos_agent_sdk::RuntimeExecutionContext::Direct;
        let RuntimeWork::Resume {
            resume: resume_work,
            ..
        } = &mut work
        else {
            unreachable!()
        };
        resume_work.mode = MethodMode::Linear;
        assert_eq!(
            validate_private_runtime_work(&work),
            Err(PrivateSyncError::LinearUnsupported)
        );
        let mut linear_state = RuntimeState::default();
        linear_state.linear.push(1);
        let work = RuntimeWork::Resume {
            context: vos_agent_sdk::RuntimeExecutionContext::Direct,
            state: linear_state,
            resume: Box::new(resume()),
        };
        assert_eq!(
            validate_private_runtime_work(&work),
            Err(PrivateSyncError::LinearUnsupported)
        );
    }

    #[test]
    fn owner_bound_nodes_revoke_rotate_and_recover_onto_replacement_roots() {
        let directory = TestDirectory::new("physical-offline-recovery");
        let fixture = fixture();
        let mut primary = create_store(&directory.child("primary"), &fixture);
        let mut peer = create_store(&directory.child("peer"), &fixture);
        let initial = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::CrdtNode,
            b"before-revocation",
        )
        .unwrap();
        primary.put_object(&initial).unwrap();
        converge(
            &primary,
            &mut peer,
            &fixture.recipients[1].identity,
            &fixture.recipients[0].identity,
            b"plaintext-never-in-sync",
        );
        assert_eq!(primary.object_count(), peer.object_count());

        let survivor = fixture.recipients[0].identity.clone();
        let revoked = fixture.recipients[1].identity.clone();
        let epoch_one = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            core::slice::from_ref(&survivor),
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut revoke = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Revoke {
                node: revoked.node,
                next_epoch: epoch_one.record.clone(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut revoke, &fixture.owner_key).unwrap();
        primary.append_control(&revoke, &TestAuthority).unwrap();

        let epoch_two = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            2,
            fixture.owner,
            core::slice::from_ref(&survivor),
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut rotate = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 1,
            previous: Some(revoke.commitment()),
            operation: PrivateControlOperation::RotateKeys {
                next_epoch: epoch_two.record.clone(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut rotate, &epoch_one.owner_key).unwrap();
        primary.append_control(&rotate, &TestAuthority).unwrap();

        let stale_change = policy_record(&fixture, 2, Some(rotate.commitment()), 73);
        assert!(matches!(
            primary.append_control(&stale_change, &TestAuthority),
            Err(PrivateStoreError::Crypto(PrivateCryptoError::WrongSigner))
        ));
        let before = primary.binding();
        primary.reset_artifact_read_spy();
        let stale_request = request_for(&peer, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        assert_eq!(
            serve_private_sync_page(&primary, &revoked, &stale_request, &TestTransport),
            Err(PrivateSyncError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(), 0);
        assert_eq!(primary.binding(), before);

        let later = encrypt_private_object(
            &epoch_two.data_key,
            fixture.space,
            fixture.agent,
            2,
            EncryptedObjectKind::Snapshot,
            b"after-revoke-and-rotation",
        )
        .unwrap();
        primary.put_object(&later).unwrap();
        let backup = primary
            .export_encrypted_backup(crate::agent::private_store::MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let prior_head = rotate.commitment();
        drop(primary);
        drop(peer);

        let mut replacements = vec![
            recipient(fixture.space, fixture.agent, fixture.owner, 81),
            recipient(fixture.space, fixture.agent, fixture.owner, 82),
        ];
        replacements.sort_by_key(|recipient| recipient.identity.node);
        let replacement_nodes: Vec<_> = replacements
            .iter()
            .map(|recipient| recipient.identity.clone())
            .collect();
        let epoch_three = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            3,
            fixture.owner,
            &replacement_nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let historical_epochs = vec![
            fixture.epoch.record.clone(),
            epoch_one.record.clone(),
            epoch_two.record.clone(),
        ];
        let mut historical_keys = BTreeMap::new();
        for epoch in &historical_epochs {
            historical_keys.insert(
                epoch.epoch,
                unwrap_data_key(epoch, &survivor, &fixture.recipients[0].key).unwrap(),
            );
        }
        let historical_keyring = build_recovery_keyring_grant(
            &historical_epochs,
            &historical_keys,
            &epoch_three.record,
            &replacement_nodes,
        )
        .unwrap();
        let mut recovery = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 2,
            previous: Some(prior_head),
            operation: PrivateControlOperation::Recover {
                superseded_heads: vec![prior_head],
                next_epoch: epoch_three.record.clone(),
                replacement_nodes: replacement_nodes.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();

        let restore = |path: &Path| {
            PrivateStore::restore_encrypted_backup(
                path,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &backup,
                &TestAuthority,
            )
            .unwrap()
            .0
        };
        let mut recovered_primary = restore(&directory.child("replacement-primary"));
        let mut recovered_peer = restore(&directory.child("replacement-peer"));
        assert_eq!(recovered_primary.binding().owner, fixture.owner);
        let recovery_count = recovered_primary.control_count();
        assert_eq!(
            recovered_primary.apply_offline_recovery(
                Some(Hash([99; 32])),
                &recovery,
                &TestAuthority
            ),
            Err(PrivateStoreError::InvalidRecord)
        );
        assert_eq!(recovered_primary.control_count(), recovery_count);
        let mut tampered_recovery = recovery.clone();
        tampered_recovery.signature[0] ^= 1;
        assert!(
            recovered_primary
                .apply_offline_recovery(Some(prior_head), &tampered_recovery, &TestAuthority)
                .is_err()
        );
        assert_eq!(recovered_primary.control_count(), recovery_count);
        recovered_primary
            .apply_offline_recovery(Some(prior_head), &recovery, &TestAuthority)
            .unwrap();
        recovered_peer
            .apply_offline_recovery(Some(prior_head), &recovery, &TestAuthority)
            .unwrap();
        assert_eq!(recovered_primary.authorized_nodes(), replacement_nodes);
        assert_eq!(recovered_peer.binding(), recovered_primary.binding());

        for old in &fixture.recipients {
            assert!(unwrap_data_key(&epoch_three.record, &old.identity, &old.key).is_err());
        }
        let request = request_for(&recovered_peer, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        recovered_primary.reset_artifact_read_spy();
        for old in [&survivor, &revoked] {
            assert_eq!(
                serve_private_sync_page(&recovered_primary, old, &request, &TestTransport),
                Err(PrivateSyncError::Unauthorized)
            );
        }
        assert_eq!(recovered_primary.artifact_read_spy(), 0);

        let replacement_change = encrypt_private_object(
            &epoch_three.data_key,
            fixture.space,
            fixture.agent,
            3,
            EncryptedObjectKind::Index,
            b"replacement-nodes-converge",
        )
        .unwrap();
        recovered_primary.put_object(&replacement_change).unwrap();
        converge(
            &recovered_primary,
            &mut recovered_peer,
            &replacements[1].identity,
            &replacements[0].identity,
            b"replacement-nodes-converge",
        );
        assert_eq!(
            recovered_peer.object_count(),
            recovered_primary.object_count()
        );
        assert_eq!(recovered_peer.binding(), recovered_primary.binding());
    }
}
