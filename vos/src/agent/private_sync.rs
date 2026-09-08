//! Authenticated, bounded anti-entropy for ciphertext-only Private stores.
//!
//! Network transports remain outside this module. A caller supplies a verifier
//! for the live transport session, and the exact full [`PrivateNodeIdentity`]
//! must also match the current verified membership before any artifact read or
//! response allocation occurs. There is no NodeId-, Principal-, SSH-, or
//! credential-only entry point.
//!
//! Genesis is the absence of a PCTL and therefore has no fabricated authority
//! evidence. Every post-genesis control item instead carries its exact PCTL,
//! optional PRM1, canonical AOI1+PCA2 envelope, and replica-stable successor
//! projection commitment. The receiving physical host must execute each
//! verified control through its own PVM; this module never installs a received
//! control through the low-level Store transition path.

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
use vos_agent_sdk::wire::MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES;
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_OBJECT_WIRE_BYTES,
};
use vos_agent_sdk::{
    ActorDescriptor, AgentId, AgentProfile, Hash, ManagementRequest, MethodMode, ModelError,
    PrivateRuntimeMutation, RuntimeWork, SpaceId, StateLane, StorageFieldDescriptor,
};

use super::authority_operation_issuer::private_intent_matches_application;
use super::private_crypto::{PrivateCryptoError, PrivateNodeAuthorityVerifier};
use super::private_store::{
    MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES, MAX_PRIVATE_STORE_OBJECTS, PrivateObjectKey,
    PrivateStore, PrivateStoreError, PutDisposition, StoredControlIndex,
};

pub const MAX_PRIVATE_SYNC_ITEMS: usize = 64;
pub const MAX_PRIVATE_SYNC_PAGE_BYTES: usize = MAX_PRIVATE_OBJECT_WIRE_BYTES + 16 * 1024;
pub const MAX_PRIVATE_SYNC_FRAME_BYTES: usize = MAX_PRIVATE_SYNC_PAGE_BYTES + 32 * 1024;
// v3 adds the exact optional PRM1 and successor PSP commitment to every
// control item and pins the source object-index target across paginated
// requests. A clean break prevents v2's PCTL+PSE-only layout from being
// interpreted as runtime-complete synchronization evidence.
const SYNC_FORMAT_VERSION: u16 = 3;
// PSE2 is an independently persisted envelope, not part of the sync-frame
// layout. Keep its established wire version while its nested canonical PCA2
// decoder rejects the incompatible PCA1 payload.
const EVIDENCE_FORMAT_VERSION: u16 = 2;
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
    /// A received controls page requires physical-host PVM execution and may
    /// not be installed through the low-level ciphertext Store path.
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedPrivateControlAuthorityEvidence {
    issuance: AuthorityOperationIssuanceAck,
    application: PrivateControlApplicationAck,
    recovery_proof: Option<PrivateRecoveryAuthorityProof>,
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
        let mut encoder = Encoder::new(EVIDENCE_MAGIC, EVIDENCE_FORMAT_VERSION);
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
            EVIDENCE_FORMAT_VERSION,
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
        let application = PrivateControlApplicationAck::decode(&self.application_ack)
            .map_err(|_| PrivateSyncError::Tampered)?;
        self.verify_material_for(
            control,
            resulting_epoch,
            application.application.stable_projection,
            route,
            authority,
        )
        .map(|_| ())
    }

    pub(crate) fn verify_for_stable_projection(
        &self,
        control: &PrivateControlRecord,
        resulting_epoch: u64,
        stable_projection: Hash,
        route: ManagedAgentTarget,
        authority: AuthorityActorTarget,
    ) -> Result<(), PrivateSyncError> {
        self.verify_material_for(
            control,
            resulting_epoch,
            stable_projection,
            route,
            authority,
        )
        .map(|_| ())
    }

    fn verify_material_for(
        &self,
        control: &PrivateControlRecord,
        resulting_epoch: u64,
        stable_projection: Hash,
        route: ManagedAgentTarget,
        authority: AuthorityActorTarget,
    ) -> Result<VerifiedPrivateControlAuthorityEvidence, PrivateSyncError> {
        if !route.is_valid()
            || !authority.is_valid()
            || route.space != authority.space
            || control.space != route.space
            || control.agent != route.agent
        {
            return Err(PrivateSyncError::InvalidScope);
        }
        if stable_projection == Hash::ZERO {
            return Err(PrivateSyncError::Tampered);
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
        let (intent, recovery_proof) = match (&control.operation, self.recovery_proof.as_deref()) {
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
                (
                    AuthorityOperationIntent::RecoverPrivateAgent {
                        proof: proof.clone(),
                    },
                    Some(proof),
                )
            }
            (PrivateControlOperation::Recover { .. }, None) | (_, Some(_)) => {
                return Err(PrivateSyncError::Tampered);
            }
            (_, None) => (
                AuthorityOperationIntent::private_control(route.runtime_deployment, control)
                    .map_err(|_| PrivateSyncError::Tampered)?,
                None,
            ),
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
            || application.application.stable_projection != stable_projection
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
        Ok(VerifiedPrivateControlAuthorityEvidence {
            issuance,
            application,
            recovery_proof,
        })
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

/// Immutable source snapshot selected by the first page of a sync session.
///
/// Controls are addressed by [`Self::head`]. The object index is pinned
/// separately because same-epoch object writes do not advance that control
/// head; without this pair, an insertion which sorts before `after_object`
/// could be silently skipped by a later page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSyncTarget {
    pub head: PrivateSyncHead,
    pub object_count: u32,
    pub object_root: Option<Hash>,
}

impl PrivateSyncTarget {
    fn validate(self) -> bool {
        self.head.validate()
            && usize::try_from(self.object_count)
                .is_ok_and(|count| count <= MAX_PRIVATE_STORE_OBJECTS)
            && match (self.object_count, self.object_root) {
                (0, None) => true,
                (0, Some(_)) | (_, None) => false,
                (_, Some(root)) => root != Hash::ZERO,
            }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSyncCursor {
    pub space: SpaceId,
    pub agent: AgentId,
    /// State already authenticated and applied by the requester.
    pub local: PrivateSyncHead,
    /// Complete source target fixed by the first response in a pagination
    /// session. A source-side control or object-index change makes it stale.
    pub target: Option<PrivateSyncTarget>,
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
            if !target.validate() || target.head.epoch < self.local.epoch {
                return Err(PrivateSyncError::InvalidRequest);
            }
        }
        if (self.after_object.is_some()
            && self.target.map(|target| target.head) != Some(self.local))
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
        let mut encoder = Encoder::new(REQUEST_MAGIC, SYNC_FORMAT_VERSION);
        encode_request_body(&mut encoder, self)?;
        encoder.finish(MAX_PRIVATE_SYNC_FRAME_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateSyncError> {
        let mut decoder = Decoder::new(
            bytes,
            REQUEST_MAGIC,
            SYNC_FORMAT_VERSION,
            MAX_PRIVATE_SYNC_FRAME_BYTES,
        )?;
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
        /// Exact canonical PCTL wire selected by the signed evidence.
        wire: Vec<u8>,
        /// Exact canonical PRM1 wire for policy/lifecycle controls. Membership,
        /// key, and recovery controls must carry `None`.
        mutation: Option<Vec<u8>>,
        /// Exact canonical source PSE2 envelope for this PCTL. A control item
        /// without AOI1+PCA2 evidence is never a valid synchronization item.
        evidence: Vec<u8>,
        /// Commitment of the source PAPL's successor replica-stable PSP.
        /// The signed PCA2 repeats this exact value.
        stable_projection: Hash,
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
            Self::Control {
                wire,
                mutation,
                evidence,
                ..
            } => {
                if wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES
                    || mutation
                        .as_ref()
                        .is_some_and(|wire| wire.len() > MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES)
                    || evidence.len() > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
                {
                    return Err(PrivateSyncError::LimitExceeded);
                }
                wire.len()
                    .checked_add(mutation.as_ref().map_or(0, Vec::len))
                    .ok_or(PrivateSyncError::LimitExceeded)?
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

/// Fully authenticated control material returned to the physical receiver.
///
/// Construction is private to [`verify_private_sync_control_page`]:
/// callers cannot obtain this value without exact canonical PCTL/PRM1/PSE2
/// correspondence, an independently verified PCA2 signature, and equality
/// between the page's PSP commitment and the signed application fact. The
/// receiver still must execute the control through its own PVM and compare its
/// locally produced successor PSP to [`Self::source_stable_projection`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedPrivateSyncControl {
    control: PrivateControlRecord,
    mutation: Option<PrivateRuntimeMutation>,
    evidence_wire: Vec<u8>,
    issuance: AuthorityOperationIssuanceAck,
    source_application: PrivateControlApplicationAck,
    recovery_proof: Option<PrivateRecoveryAuthorityProof>,
    source_stable_projection: Hash,
}

impl VerifiedPrivateSyncControl {
    pub(crate) const fn control(&self) -> &PrivateControlRecord {
        &self.control
    }

    pub(crate) const fn mutation(&self) -> Option<&PrivateRuntimeMutation> {
        self.mutation.as_ref()
    }

    pub(crate) fn evidence_wire(&self) -> &[u8] {
        &self.evidence_wire
    }

    pub(crate) const fn issuance(&self) -> &AuthorityOperationIssuanceAck {
        &self.issuance
    }

    /// Source-node PCA2 retained for envelope audit. Its
    /// `reopened_runtime_state` selects the source's node-local PCRS3 and may
    /// never be adopted as the receiver's PCRS3; only the separately exposed
    /// stable projection is a cross-node convergence target.
    pub(crate) const fn source_application(&self) -> &PrivateControlApplicationAck {
        &self.source_application
    }

    pub(crate) const fn recovery_proof(&self) -> Option<&PrivateRecoveryAuthorityProof> {
        self.recovery_proof.as_ref()
    }

    pub(crate) const fn source_stable_projection(&self) -> Hash {
        self.source_stable_projection
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSyncPage {
    pub request: PrivateSyncRequest,
    pub target: PrivateSyncTarget,
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
                if self.request.cursor.local == self.target.head
                    || self.request.cursor.after_object.is_some()
                {
                    return Err(PrivateSyncError::InvalidFrame);
                }
                validate_control_item_order(
                    &self.items,
                    self.request.cursor.space,
                    self.request.cursor.agent,
                    self.request.cursor.local,
                )?;
            }
            PrivateSyncPhase::Objects => {
                if self.request.cursor.local != self.target.head {
                    return Err(PrivateSyncError::InvalidFrame);
                }
                validate_object_item_order(&self.items, self.request.cursor.after_object)?;
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
                    if next.local == self.target.head && next.after_object == Some(*key) => {}
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
                && (self.target.head.control_head != Some(*commitment)
                    || self.target.head.epoch != *resulting_epoch)
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
        let mut encoder = Encoder::new(PAGE_MAGIC, SYNC_FORMAT_VERSION);
        encode_request_body(&mut encoder, &self.request)?;
        encode_target(&mut encoder, self.target);
        encoder.u8(self.phase as u8);
        encoder.u16(u16::try_from(self.items.len()).map_err(|_| PrivateSyncError::LimitExceeded)?);
        for item in &self.items {
            match item {
                PrivateSyncItem::Control {
                    sequence,
                    commitment,
                    resulting_epoch,
                    wire,
                    mutation,
                    evidence,
                    stable_projection,
                } => {
                    encoder.u8(0);
                    encoder.u64(*sequence);
                    encoder.fixed(commitment.as_bytes());
                    encoder.u64(*resulting_epoch);
                    encoder.bytes(wire)?;
                    match mutation {
                        Some(wire) => {
                            encoder.u8(1);
                            encoder.bytes(wire)?;
                        }
                        None => encoder.u8(0),
                    }
                    encoder.bytes(evidence)?;
                    encoder.fixed(stable_projection.as_bytes());
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
        let mut decoder = Decoder::new(
            bytes,
            PAGE_MAGIC,
            SYNC_FORMAT_VERSION,
            MAX_PRIVATE_SYNC_FRAME_BYTES,
        )?;
        let request = decode_request_body(&mut decoder)?;
        let target = decode_target(&mut decoder)?;
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
                    mutation: match decoder.u8()? {
                        0 => None,
                        1 => Some(decoder.bytes(MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES)?),
                        _ => return Err(PrivateSyncError::InvalidFrame),
                    },
                    evidence: decoder.bytes(MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES)?,
                    stable_projection: Hash(decoder.fixed()?),
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
    fn new(magic: &[u8; 4], version: u16) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&version.to_le_bytes());
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
    fn new(
        bytes: &'a [u8],
        magic: &[u8; 4],
        expected_version: u16,
        max: usize,
    ) -> Result<Self, PrivateSyncError> {
        if bytes.len() > max || bytes.len() < 6 || bytes.get(..4) != Some(magic) {
            return Err(PrivateSyncError::InvalidFrame);
        }
        let version = u16::from_le_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| PrivateSyncError::InvalidFrame)?,
        );
        if version != expected_version {
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

fn encode_target(encoder: &mut Encoder, target: PrivateSyncTarget) {
    encode_head(encoder, target.head);
    encoder.u32(target.object_count);
    encoder.optional_hash(target.object_root);
}

fn decode_target(decoder: &mut Decoder<'_>) -> Result<PrivateSyncTarget, PrivateSyncError> {
    let target = PrivateSyncTarget {
        head: decode_head(decoder)?,
        object_count: decoder.u32()?,
        object_root: decoder.optional_hash()?,
    };
    target
        .validate()
        .then_some(target)
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
            encode_target(encoder, target);
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
            1 => Some(decode_target(decoder)?),
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

fn validate_control_item_order(
    items: &[PrivateSyncItem],
    space: SpaceId,
    agent: AgentId,
    local: PrivateSyncHead,
) -> Result<(), PrivateSyncError> {
    let mut previous_sequence = None;
    let mut current = local;
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
            mutation,
            evidence,
            stable_projection,
            ..
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        if *commitment == Hash::ZERO
            || *stable_projection == Hash::ZERO
            || wire.is_empty()
            || wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES
        {
            return Err(PrivateSyncError::InvalidFrame);
        }
        if evidence.is_empty() {
            return Err(PrivateSyncError::MissingEvidence);
        }
        let (record, _) = decode_exact_private_control_material(wire, mutation.as_deref())?;
        if record.space != space
            || record.agent != agent
            || record.sequence != *sequence
            || record.commitment() != *commitment
        {
            return Err(PrivateSyncError::InvalidFrame);
        }
        let links_current = record.previous == current.control_head
            || matches!(
                &record.operation,
                PrivateControlOperation::Recover {
                    superseded_heads,
                    ..
                } if current.control_head.is_some_and(|head| {
                    superseded_heads.binary_search(&head).is_ok()
                })
            );
        if !links_current {
            return Err(PrivateSyncError::OutOfOrder);
        }
        let expected_epoch = match &record.operation {
            PrivateControlOperation::Invite { epoch, .. } if *epoch == current.epoch => *epoch,
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch }
                if current.epoch.checked_add(1) == Some(next_epoch.epoch) =>
            {
                next_epoch.epoch
            }
            PrivateControlOperation::Recover { next_epoch, .. }
                if next_epoch.epoch > current.epoch =>
            {
                next_epoch.epoch
            }
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => current.epoch,
            _ => return Err(PrivateSyncError::InvalidFrame),
        };
        if expected_epoch != *resulting_epoch {
            return Err(PrivateSyncError::InvalidFrame);
        }
        let envelope = PrivateControlAuthorityEvidence::decode(evidence)?;
        let application = PrivateControlApplicationAck::decode(&envelope.application_ack)
            .map_err(|_| PrivateSyncError::InvalidFrame)?;
        if application.application.stable_projection != *stable_projection {
            return Err(PrivateSyncError::InvalidFrame);
        }
        if previous_sequence.is_some_and(|previous| previous >= *sequence) {
            return Err(PrivateSyncError::OutOfOrder);
        }
        if commitments.contains(commitment) {
            return Err(PrivateSyncError::Duplicate);
        }
        commitments.push(*commitment);
        previous_sequence = Some(*sequence);
        current = PrivateSyncHead {
            epoch: *resulting_epoch,
            control_head: Some(*commitment),
        };
    }
    Ok(())
}

fn decode_exact_private_control_material(
    control_wire: &[u8],
    mutation_wire: Option<&[u8]>,
) -> Result<(PrivateControlRecord, Option<PrivateRuntimeMutation>), PrivateSyncError> {
    let control =
        PrivateControlRecord::decode(control_wire).map_err(|_| PrivateSyncError::InvalidFrame)?;
    if control.encode().ok().as_deref() != Some(control_wire) {
        return Err(PrivateSyncError::InvalidFrame);
    }
    let mutation = mutation_wire
        .map(|wire| {
            let mutation =
                PrivateRuntimeMutation::decode(wire).map_err(|_| PrivateSyncError::InvalidFrame)?;
            if mutation.encode().ok().as_deref() != Some(wire) {
                return Err(PrivateSyncError::InvalidFrame);
            }
            Ok(mutation)
        })
        .transpose()?;
    match (&control.operation, &mutation) {
        (
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. },
            Some(mutation),
        ) => {
            let request = ManagementRequest::PrivateControl {
                control: alloc::boxed::Box::new(control.clone()),
                mutation: alloc::boxed::Box::new(mutation.clone()),
            };
            if !request.is_valid() {
                return Err(PrivateSyncError::InvalidFrame);
            }
        }
        (
            PrivateControlOperation::Invite { .. }
            | PrivateControlOperation::Revoke { .. }
            | PrivateControlOperation::RotateKeys { .. }
            | PrivateControlOperation::Recover { .. },
            None,
        ) => {}
        _ => return Err(PrivateSyncError::InvalidFrame),
    }
    Ok((control, mutation))
}

fn validate_object_item_order(
    items: &[PrivateSyncItem],
    after_object: Option<PrivateObjectKey>,
) -> Result<(), PrivateSyncError> {
    let mut previous = after_object;
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

fn sync_target(store: &PrivateStore) -> Result<PrivateSyncTarget, PrivateSyncError> {
    let position = store.cached_core_position()?;
    let target = PrivateSyncTarget {
        head: PrivateSyncHead {
            epoch: position.epoch(),
            control_head: position.control_head(),
        },
        object_count: position.object_count(),
        object_root: position.object_root(),
    };
    target
        .validate()
        .then_some(target)
        .ok_or(PrivateSyncError::Store(PrivateStoreError::Corrupt))
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
    let target = sync_target(store)?;
    if request
        .cursor
        .target
        .is_some_and(|expected| expected != target)
    {
        return Err(PrivateSyncError::StaleTarget);
    }
    if request.cursor.local == target.head {
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
    target: PrivateSyncTarget,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<PrivateSyncPage, PrivateSyncError> {
    let controls = store.indexed_controls();
    let mut position = control_base_position(controls, request.cursor.local)?;
    let mut current = request.cursor.local;
    let mut items = Vec::new();
    let mut bytes = 0usize;
    while current.control_head != target.head.control_head {
        let next_position = next_control_position(controls, position, current.control_head)
            .ok_or(PrivateSyncError::Diverged)?;
        let entry = controls
            .get(next_position)
            .ok_or(PrivateSyncError::Diverged)?;
        if entry.resulting_epoch < current.epoch || entry.resulting_epoch > target.head.epoch {
            return Err(PrivateSyncError::Diverged);
        }
        let wire = store.read_control_wire(entry)?;
        let runtime_application = store
            .read_runtime_application(entry.commitment)?
            .ok_or(PrivateSyncError::MissingEvidence)?;
        let evidence = store
            .read_control_authority_evidence(entry)?
            .ok_or(PrivateSyncError::MissingEvidence)?;
        let record = PrivateControlRecord::decode(&wire).map_err(|_| PrivateSyncError::Tampered)?;
        let envelope = PrivateControlAuthorityEvidence::decode(&evidence)?;
        let stable_projection = runtime_application
            .successor_stable_projection()
            .ok_or(PrivateSyncError::Tampered)?
            .commitment();
        if stable_projection == Hash::ZERO
            || runtime_application.managed() != route
            || runtime_application.control() != &record
        {
            return Err(PrivateSyncError::Tampered);
        }
        let verified = envelope.verify_material_for(
            &record,
            entry.resulting_epoch,
            stable_projection,
            route,
            authority,
        )?;
        if runtime_application.issuance() != &verified.issuance
            || runtime_application.receipt() != &verified.issuance.receipt
            || runtime_application.applied_at() != verified.application.application.applied_at
            || runtime_application.recovery_authority_proof() != verified.recovery_proof.as_ref()
        {
            return Err(PrivateSyncError::Tampered);
        }
        let mutation = runtime_application
            .mutation()
            .map(CanonicalWire::encode)
            .transpose()
            .map_err(|_| PrivateSyncError::Tampered)?;
        let item = PrivateSyncItem::Control {
            sequence: entry.sequence,
            commitment: entry.commitment,
            resulting_epoch: entry.resulting_epoch,
            wire,
            mutation,
            evidence,
            stable_projection,
        };
        // Account from the exact item representation so PRM1 bytes can never
        // evade either the request quota or the encoded-page bound.
        let item_len = item.encoded_payload_len()?;
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
        items.push(item);
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
    let next = if current == target.head && store.indexed_objects().is_empty() {
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
    target: PrivateSyncTarget,
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
        if entry.key.epoch > target.head.epoch {
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
            local: target.head,
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

/// Apply one object page received over an authenticated transport. Control
/// pages must first pass receiver-local PVM execution and the physical host's
/// durable application path, so this low-level entry fails closed for them.
/// The sender must be an exact member of the receiver's current verified
/// control view before any persisted artifact is opened or changed.
pub(crate) fn apply_private_sync_page<
    A: PrivateNodeAuthorityVerifier,
    T: PrivateTransportAuthVerifier,
>(
    store: &mut PrivateStore,
    peer: &PrivateNodeIdentity,
    page: &PrivateSyncPage,
    _node_authority: &A,
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
            // Authentication and complete page verification are useful to the
            // physical coordinator, but this low-level Store API must never
            // bypass the receiver's own PVM/PVRI/PCRS/PAPL transaction.
            verify_private_sync_control_page(page, route, authority)?;
            Err(PrivateSyncError::UnsupportedOperation)
        }
        PrivateSyncPhase::Objects => apply_object_page(store, page),
    }
}

/// Verify the complete control/evidence/projection correspondence without
/// reading or mutating local artifacts.
///
/// The returned values are the only control-page input intended for the
/// physical host. It must apply them in order through its own PVM, construct a
/// node-local PVRI/PCRS, and require the resulting PSP commitment to equal
/// [`VerifiedPrivateSyncControl::source_stable_projection`] before committing.
pub(crate) fn verify_private_sync_control_page(
    page: &PrivateSyncPage,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<Vec<VerifiedPrivateSyncControl>, PrivateSyncError> {
    page.validate_shape()?;
    if page.phase != PrivateSyncPhase::Controls {
        return Ok(Vec::new());
    }
    let mut controls = Vec::new();
    controls
        .try_reserve(page.items.len())
        .map_err(|_| PrivateSyncError::LimitExceeded)?;
    for item in &page.items {
        let PrivateSyncItem::Control {
            sequence,
            commitment,
            resulting_epoch,
            wire,
            mutation,
            evidence,
            stable_projection,
        } = item
        else {
            return Err(PrivateSyncError::InvalidFrame);
        };
        let (record, mutation) = decode_exact_private_control_material(wire, mutation.as_deref())
            .map_err(|_| PrivateSyncError::Tampered)?;
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
        let verified = envelope.verify_material_for(
            &record,
            *resulting_epoch,
            *stable_projection,
            route,
            authority,
        )?;
        controls.push(VerifiedPrivateSyncControl {
            control: record,
            mutation,
            evidence_wire: evidence.clone(),
            issuance: verified.issuance,
            source_application: verified.application,
            recovery_proof: verified.recovery_proof,
            source_stable_projection: *stable_projection,
        });
    }
    Ok(controls)
}

/// Fail-closed compatibility entry point for the legacy physical-host path.
///
/// That path stages epoch metadata before reaching the low-level Store apply
/// call, so returning verified controls to it would still create pre-PVM
/// artifacts. The physical-host v3 path must instead call
/// [`verify_private_sync_control_page`] and consume its values as PVM input.
pub(crate) fn verify_private_control_page_authority_evidence(
    page: &PrivateSyncPage,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<Vec<VerifiedPrivateSyncControl>, PrivateSyncError> {
    let controls = verify_private_sync_control_page(page, route, authority)?;
    if page.phase == PrivateSyncPhase::Controls {
        return Err(PrivateSyncError::UnsupportedOperation);
    }
    Ok(controls)
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
    if current != page.target.head || page.request.cursor.local != page.target.head {
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
            || object.epoch > page.target.head.epoch
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
    use crate::agent::private_runtime::{
        PrivateControlReopenedState, PrivateKeyEpochCommitment, PrivateRuntimeApplication,
        PrivateRuntimeImage, PrivateRuntimeSuccess,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::authority::{
        AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
        AuthorityReceipt, AuthorityReceiptSelector,
    };
    use vos_agent_sdk::authority_operation::{
        PrivateControlApplicationFact, private_member_set_commitment,
    };
    use vos_agent_sdk::contract::{RuntimePackageContract, RuntimeResourcePolicy};
    use vos_agent_sdk::private::{
        EncryptedObjectKind, PrivateActorLifecycleKind, PrivateControlSigner,
        recovery_signing_public_key_commitment,
    };
    use vos_agent_sdk::{
        ActorId, AgentDescriptor, AgentIdentity, AgentReplica, BlobRef, DeploymentId, InvocationId,
        LaneSet, PrincipalId, PrivateRecoveryBinding, ProducerId, ProgramId, ReplicaRole,
        ResumeWork, RuntimeCapabilities, RuntimeState,
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
        descriptor: AgentDescriptor,
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
        let creation_nonce = Hash([12; 32]);
        let owner = PrincipalId([13; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
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
        let authority_key = SigningKey::from_bytes(&[0x71; 32]);
        let authority = AgentAuthorityBinding {
            policy: Hash([0x74; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([0x75; 32]),
                actor: ActorId([0x76; 32]),
                deployment: DeploymentId([0x77; 32]),
                program: ProgramId([0x78; 32]),
                producer: ProducerId::of_public_key(&authority_key.verifying_key().to_bytes()),
            },
            public_key: authority_key.verifying_key().to_bytes(),
            initial_epoch: 1,
        };
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Private,
                runtime_deployment: DeploymentId([0x79; 32]),
                runtime_program: ProgramId([0x7a; 32]),
                runtime_producer: ProducerId([0x7b; 32]),
            },
            creation_nonce,
            authority,
            private_recovery: Some(PrivateRecoveryBinding {
                signing_key_commitment: recovery_signing_public_key_commitment(
                    &recovery.verifying_key(),
                ),
                encryption_public_key: recovery_encryption.public_key(),
            }),
            runtime_package: BlobRef::of_bytes(b"private-sync-runtime-package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: nodes
                .iter()
                .map(|node| AgentReplica {
                    node: node.node,
                    principal: owner,
                    role: ReplicaRole::Observer,
                })
                .collect(),
        };
        descriptor.validate().unwrap();
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
            descriptor,
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

    fn creation_receipt(fixture: &Fixture) -> AuthorityReceipt {
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let request = ManagementRequest::Create(Box::new(fixture.descriptor.clone()));
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: fixture.descriptor.authority.policy,
                issuer: fixture.descriptor.authority.issuer,
                space: fixture.space,
                agent: fixture.agent,
                operation: vos_agent_sdk::authority::AuthorityOperationKind::CreateAgent,
                runtime_deployment: fixture.descriptor.identity.runtime_deployment,
                actor: None,
                actor_deployment: None,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x7e; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: fixture.descriptor.authority.initial_epoch,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: 1,
                expires_at: 100,
                request: request.commitment(),
            },
            public_key: fixture.descriptor.authority.public_key,
            signature: [0; 64],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn genesis_runtime_image(store: &PrivateStore, fixture: &Fixture) -> PrivateRuntimeImage {
        PrivateRuntimeImage::genesis(
            &fixture.descriptor,
            fixture.recipients[0].identity.node,
            RuntimeState {
                control: vec![0x21],
                linear: Vec::new(),
                merge: vec![0x22],
                local: vec![0x23],
            },
            store.core_position().unwrap(),
            vec![PrivateKeyEpochCommitment::from_epoch(&fixture.epoch.record).unwrap()],
            creation_receipt(fixture),
            3,
            &RawAuthorityVerifier,
        )
        .unwrap()
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
        signed_evidence_for_intent_with_projection(
            store,
            control,
            intent,
            recovery_proof,
            Hash([0x81; 32]),
            Hash([0x82; 32]),
        )
    }

    fn signed_evidence_for_intent_with_projection(
        store: &PrivateStore,
        control: &PrivateControlRecord,
        intent: AuthorityOperationIntent,
        recovery_proof: Option<&PrivateRecoveryAuthorityProof>,
        reopened_runtime_state: Hash,
        stable_projection: Hash,
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
        let resulting_epoch = match &control.operation {
            PrivateControlOperation::Invite { epoch, .. } => *epoch,
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch }
            | PrivateControlOperation::Recover { next_epoch, .. } => next_epoch.epoch,
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => store.binding().epoch,
        };
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
            epoch: resulting_epoch,
            post_member_set,
            reopened_runtime_state,
            stable_projection,
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
            .verify_for_stable_projection(
                control,
                resulting_epoch,
                application.application.stable_projection,
                route,
                authority,
            )
            .unwrap();
        evidence
    }

    fn attach_signed_evidence(store: &mut PrivateStore, control: &PrivateControlRecord) {
        let evidence = signed_evidence(store, control).encode().unwrap();
        store
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
    }

    fn append_completed_runtime_application(
        store: &mut PrivateStore,
        fixture: &Fixture,
        predecessor: &PrivateRuntimeImage,
        control: &PrivateControlRecord,
        mutation: Option<&PrivateRuntimeMutation>,
        recovery_proof: Option<&PrivateRecoveryAuthorityProof>,
        success: PrivateRuntimeSuccess,
    ) -> (
        PrivateRuntimeImage,
        PrivateRuntimeApplication,
        PrivateControlReopenedState,
        PrivateControlAuthorityEvidence,
    ) {
        let provisional = match recovery_proof {
            Some(proof) => signed_evidence_for_intent(
                store,
                control,
                AuthorityOperationIntent::RecoverPrivateAgent {
                    proof: proof.clone(),
                },
                Some(proof),
            ),
            None => signed_evidence(store, control),
        };
        let issuance = AuthorityOperationIssuanceAck::decode(&provisional.issuance_ack).unwrap();
        let application =
            PrivateControlApplicationAck::decode(&provisional.application_ack).unwrap();
        let preview = store
            .preview_control_position(control, &TestAuthority)
            .unwrap();
        assert_eq!(preview.disposition(), PutDisposition::Inserted);
        let pending = PrivateRuntimeApplication::pending(
            &fixture.descriptor,
            predecessor,
            control.clone(),
            mutation.cloned(),
            recovery_proof.cloned(),
            issuance.receipt.clone(),
            issuance.clone(),
            application.application.applied_at,
            preview.position(),
            &RawAuthorityVerifier,
            &RawRecoveryProofVerifier,
        )
        .unwrap();
        let mut successor_key_epochs = predecessor.key_epochs().to_vec();
        match &control.operation {
            PrivateControlOperation::Invite {
                node,
                epoch,
                sealed_owner_key,
                sealed_data_key,
                ..
            } => {
                let mut next_epoch = store.key_epoch().clone();
                assert_eq!(next_epoch.epoch, *epoch);
                let position = next_epoch
                    .sealed_owner_keys
                    .binary_search_by_key(&node.node, |sealed| sealed.node)
                    .unwrap_err();
                next_epoch
                    .sealed_owner_keys
                    .insert(position, sealed_owner_key.clone());
                next_epoch
                    .sealed_data_keys
                    .insert(position, sealed_data_key.clone());
                *successor_key_epochs.last_mut().unwrap() =
                    PrivateKeyEpochCommitment::from_epoch(&next_epoch).unwrap();
            }
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch }
            | PrivateControlOperation::Recover { next_epoch, .. } => successor_key_epochs
                .push(PrivateKeyEpochCommitment::from_epoch(next_epoch).unwrap()),
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => {}
        }
        let successor = PrivateRuntimeImage::successor(
            &fixture.descriptor,
            predecessor,
            &pending,
            &success,
            predecessor.state().clone(),
            successor_key_epochs,
            &RawAuthorityVerifier,
            &RawRecoveryProofVerifier,
        )
        .unwrap();
        let completed = pending
            .complete(
                &fixture.descriptor,
                predecessor,
                &successor,
                success.clone(),
                &RawAuthorityVerifier,
                &RawRecoveryProofVerifier,
            )
            .unwrap();
        let stable_projection = completed
            .successor_stable_projection()
            .unwrap()
            .commitment();
        let reopened = PrivateControlReopenedState::new(
            completed.clone(),
            preview.position(),
            successor.clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .append_control_with_runtime_application(control, &completed, &TestAuthority)
                .unwrap(),
            PutDisposition::Inserted
        );
        let intent = match recovery_proof {
            Some(proof) => AuthorityOperationIntent::RecoverPrivateAgent {
                proof: proof.clone(),
            },
            None => AuthorityOperationIntent::private_control(
                test_route(store).runtime_deployment,
                control,
            )
            .unwrap(),
        };
        let evidence = signed_evidence_for_intent_with_projection(
            store,
            control,
            intent,
            recovery_proof,
            reopened.commitment(),
            stable_projection,
        );
        assert_eq!(
            AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack).unwrap(),
            issuance
        );
        assert_eq!(
            store
                .read_runtime_application(control.commitment())
                .unwrap()
                .as_ref(),
            Some(&completed)
        );
        (successor, completed, reopened, evidence)
    }

    fn persist_exact_evidence(
        store: &mut PrivateStore,
        control: &PrivateControlRecord,
        evidence: &PrivateControlAuthorityEvidence,
    ) {
        assert_eq!(
            store
                .persist_control_authority_evidence(
                    control.commitment(),
                    &evidence.encode().unwrap(),
                )
                .unwrap(),
            PutDisposition::Inserted
        );
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

    fn verified_control_page(
        receiver: &PrivateStore,
        source: &PrivateStore,
        control: &PrivateControlRecord,
        mutation: Option<&PrivateRuntimeMutation>,
        evidence: &PrivateControlAuthorityEvidence,
    ) -> PrivateSyncPage {
        let source_binding = source.binding();
        let application = PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
        let page = PrivateSyncPage {
            request: request_for(receiver, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32),
            target: sync_target(source).unwrap(),
            phase: PrivateSyncPhase::Controls,
            items: vec![PrivateSyncItem::Control {
                sequence: control.sequence,
                commitment: control.commitment(),
                resulting_epoch: source_binding.epoch,
                wire: control.encode().unwrap(),
                mutation: mutation.map(|value| value.encode().unwrap()),
                evidence: evidence.encode().unwrap(),
                stable_projection: application.application.stable_projection,
            }],
            next: None,
        };
        page.validate_shape().unwrap();
        page
    }

    fn control_item(
        control: &PrivateControlRecord,
        resulting_epoch: u64,
        mutation: Option<&PrivateRuntimeMutation>,
        evidence: &PrivateControlAuthorityEvidence,
    ) -> PrivateSyncItem {
        let application = PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
        PrivateSyncItem::Control {
            sequence: control.sequence,
            commitment: control.commitment(),
            resulting_epoch,
            wire: control.encode().unwrap(),
            mutation: mutation.map(|value| value.encode().unwrap()),
            evidence: evidence.encode().unwrap(),
            stable_projection: application.application.stable_projection,
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
        // Control reception is owned by the physical PVM coordinator. Once
        // that coordinator has advanced the target head, ciphertext objects
        // remain safe to apply through this low-level sync path.
        client.append_control(&record, &TestAuthority).unwrap();
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
        assert!(frames.len() >= 3);
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
        assert_eq!(
            serve_private_sync_page(&server, &survivor, &survivor_request, &TestTransport),
            Err(PrivateSyncError::MissingEvidence)
        );
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
        // A loose PSE2 beside a legacy PCTL is not exportable in v3. Serving
        // requires the Store's exact completed PAPL attachment.
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &request,
                &TestTransport,
            ),
            Err(PrivateSyncError::MissingEvidence)
        );

        let evidence = signed_evidence(&server, &control);
        let page = verified_control_page(&client, &server, &control, None, &evidence);

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
    fn serving_uses_only_completed_papl_and_exports_exact_v3_control_material() {
        let directory = TestDirectory::new("completed-papl-sync");
        let fixture = fixture();
        let mut source = create_store(&directory.child("source"), &fixture);
        let receiver = create_store(&directory.child("receiver"), &fixture);
        let genesis = genesis_runtime_image(&source, &fixture);

        let mut policy = RuntimeResourcePolicy::standard();
        policy.max_actors -= 1;
        let policy_mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let mut policy_control = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(&policy.encode().unwrap()),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut policy_control, &fixture.owner_key).unwrap();
        let (policy_successor, policy_application, policy_reopened, policy_evidence) =
            append_completed_runtime_application(
                &mut source,
                &fixture,
                &genesis,
                &policy_control,
                Some(&policy_mutation),
                None,
                PrivateRuntimeSuccess::ResourcePolicySet(policy),
            );
        persist_exact_evidence(&mut source, &policy_control, &policy_evidence);

        let invite = invite_record(&source, &fixture, 0xa8);
        let (invite_successor, invite_application, invite_reopened, invite_evidence) =
            append_completed_runtime_application(
                &mut source,
                &fixture,
                &policy_successor,
                &invite,
                None,
                None,
                PrivateRuntimeSuccess::ControlOnly,
            );
        persist_exact_evidence(&mut source, &invite, &invite_evidence);

        let request = request_for(&receiver, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        let page = serve_private_sync_page(
            &source,
            &fixture.recipients[0].identity,
            &request,
            &TestTransport,
        )
        .unwrap();
        assert_eq!(page.phase, PrivateSyncPhase::Controls);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next, None);

        let policy_wire = policy_control.encode().unwrap();
        let mutation_wire = policy_mutation.encode().unwrap();
        let policy_evidence_wire = policy_evidence.encode().unwrap();
        let invite_wire = invite.encode().unwrap();
        let invite_evidence_wire = invite_evidence.encode().unwrap();
        let PrivateSyncItem::Control {
            wire,
            mutation,
            evidence,
            stable_projection,
            ..
        } = &page.items[0]
        else {
            unreachable!()
        };
        assert_eq!(wire, &policy_wire);
        assert_eq!(mutation.as_deref(), Some(mutation_wire.as_slice()));
        assert_eq!(evidence, &policy_evidence_wire);
        assert_eq!(
            *stable_projection,
            policy_application
                .successor_stable_projection()
                .unwrap()
                .commitment()
        );
        let PrivateSyncItem::Control {
            wire,
            mutation,
            evidence,
            stable_projection,
            ..
        } = &page.items[1]
        else {
            unreachable!()
        };
        assert_eq!(wire, &invite_wire);
        assert_eq!(mutation, &None);
        assert_eq!(evidence, &invite_evidence_wire);
        assert_eq!(
            *stable_projection,
            invite_application
                .successor_stable_projection()
                .unwrap()
                .commitment()
        );

        let verified = verify_private_sync_control_page(
            &page,
            test_route(&receiver),
            test_authority_target(&receiver),
        )
        .unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].control(), &policy_control);
        assert_eq!(verified[0].mutation(), Some(&policy_mutation));
        assert_eq!(verified[1].control(), &invite);
        assert_eq!(verified[1].mutation(), None);

        let frame = page.encode().unwrap();
        for required_magic in [b"PCTL", b"PRM1", b"PSE2", b"PCA2"] {
            assert!(
                frame
                    .windows(required_magic.len())
                    .any(|window| window == required_magic)
            );
        }
        for forbidden_magic in [b"PAP1", b"PVI1", b"PCR3", b"PSP1"] {
            assert!(
                !frame
                    .windows(forbidden_magic.len())
                    .any(|window| window == forbidden_magic)
            );
        }
        let hidden_wires = [
            policy_application.encode().unwrap(),
            invite_application.encode().unwrap(),
            genesis.encode().unwrap(),
            policy_successor.encode().unwrap(),
            invite_successor.encode().unwrap(),
            policy_reopened.encode().unwrap(),
            invite_reopened.encode().unwrap(),
            policy_application
                .successor_stable_projection()
                .unwrap()
                .encode()
                .unwrap(),
            invite_application
                .successor_stable_projection()
                .unwrap()
                .encode()
                .unwrap(),
        ];
        for hidden in hidden_wires {
            assert!(!frame.windows(hidden.len()).any(|window| window == hidden));
        }

        let first_item_len = page.items[0].encoded_payload_len().unwrap();
        assert!(first_item_len > mutation_wire.len());
        let constrained = PrivateSyncRequest {
            cursor: request.cursor,
            max_items: 1,
            max_bytes: u32::try_from(first_item_len - 1).unwrap(),
        };
        assert_eq!(
            serve_private_sync_page(
                &source,
                &fixture.recipients[0].identity,
                &constrained,
                &TestTransport,
            ),
            Err(PrivateSyncError::LimitTooSmall)
        );
    }

    #[test]
    fn serving_rejects_signed_papl_pse_receipt_applied_and_psp_substitution() {
        let directory = TestDirectory::new("papl-pse-substitution");
        let fixture = fixture();
        let authority_key = SigningKey::from_bytes(&[0x71; 32]);

        for case in 0..3u8 {
            let source_path = directory.child(&format!("source-{case}"));
            let receiver_path = directory.child(&format!("receiver-{case}"));
            let mut source = create_store(&source_path, &fixture);
            let receiver = create_store(&receiver_path, &fixture);
            let predecessor = genesis_runtime_image(&source, &fixture);
            let mut policy = RuntimeResourcePolicy::standard();
            policy.max_actors -= u32::from(case) + 1;
            let mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
            let mut control = PrivateControlRecord {
                space: fixture.space,
                agent: fixture.agent,
                sequence: 0,
                previous: None,
                operation: PrivateControlOperation::SetResourcePolicy {
                    policy: BlobRef::of_bytes(&policy.encode().unwrap()),
                },
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0; 32],
                signature: [0; 64],
            };
            sign_owner_control_record(&mut control, &fixture.owner_key).unwrap();
            let (_, application, _, mut evidence) = append_completed_runtime_application(
                &mut source,
                &fixture,
                &predecessor,
                &control,
                Some(&mutation),
                None,
                PrivateRuntimeSuccess::ResourcePolicySet(policy),
            );

            let mut issuance =
                AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack).unwrap();
            let mut acknowledgement =
                PrivateControlApplicationAck::decode(&evidence.application_ack).unwrap();
            match case {
                0 => {
                    // Keep the envelope independently well signed while
                    // substituting the receipt retained in the public PAPL.
                    issuance.receipt.selector.evidence.commitment = Hash([0xd1; 32]);
                    issuance.receipt.signature = [0; 64];
                    issuance.receipt.signature = authority_key
                        .sign(&issuance.receipt.signing_bytes())
                        .to_bytes();
                    issuance.signature = [0; 64];
                    issuance.signature = authority_key.sign(&issuance.signing_bytes()).to_bytes();
                    acknowledgement.receipt = issuance.receipt.clone();
                    acknowledgement.issuance_ack = issuance.commitment();
                    acknowledgement.application_invocation =
                        PrivateControlApplicationAck::derive_application_invocation(&issuance);
                }
                1 => {
                    acknowledgement.application.applied_at += 1;
                }
                2 => {
                    acknowledgement.application.stable_projection = Hash([0xd2; 32]);
                }
                _ => unreachable!(),
            }
            acknowledgement.signature = [0; 64];
            acknowledgement.signature = authority_key
                .sign(&acknowledgement.signing_bytes())
                .to_bytes();
            evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
                &issuance,
                &acknowledgement,
                None,
            )
            .unwrap();
            evidence
                .verify_for_stable_projection(
                    &control,
                    source.binding().epoch,
                    acknowledgement.application.stable_projection,
                    test_route(&source),
                    test_authority_target(&source),
                )
                .unwrap();
            if case == 0 {
                assert_ne!(application.issuance(), &issuance);
                assert_ne!(application.receipt(), &issuance.receipt);
            } else {
                assert_eq!(application.issuance(), &issuance);
            }
            persist_exact_evidence(&mut source, &control, &evidence);

            let source_before = directory_image(&source_path);
            let receiver_before = directory_image(&receiver_path);
            assert_eq!(
                serve_private_sync_page(
                    &source,
                    &fixture.recipients[0].identity,
                    &request_for(&receiver, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32),
                    &TestTransport,
                ),
                Err(PrivateSyncError::Tampered)
            );
            assert_eq!(directory_image(&source_path), source_before);
            assert_eq!(directory_image(&receiver_path), receiver_before);
        }
    }

    #[test]
    fn serving_rejects_signed_papl_pse_recovery_proof_substitution() {
        let directory = TestDirectory::new("papl-pse-recovery-substitution");
        let fixture = fixture();
        let source_path = directory.child("source");
        let receiver_path = directory.child("receiver");
        let mut source = create_store(&source_path, &fixture);
        let receiver = create_store(&receiver_path, &fixture);
        let genesis = genesis_runtime_image(&source, &fixture);

        let mut policy = RuntimeResourcePolicy::standard();
        policy.max_actors -= 1;
        let mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let mut policy_control = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(&policy.encode().unwrap()),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut policy_control, &fixture.owner_key).unwrap();
        let (policy_successor, _, _, policy_evidence) = append_completed_runtime_application(
            &mut source,
            &fixture,
            &genesis,
            &policy_control,
            Some(&mutation),
            None,
            PrivateRuntimeSuccess::ResourcePolicySet(policy),
        );
        persist_exact_evidence(&mut source, &policy_control, &policy_evidence);

        let successor_epoch = generate_fresh_private_epoch(
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
            &successor_epoch.record,
            &fixture.nodes,
        )
        .unwrap();
        let selected_head = policy_control.commitment();
        let alternate_head = Hash([0xe9; 32]);
        let mut superseded_heads = vec![selected_head, alternate_head];
        superseded_heads.sort();
        let mut recovery = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 1,
            previous: Some(selected_head),
            operation: PrivateControlOperation::Recover {
                superseded_heads,
                next_epoch: successor_epoch.record,
                replacement_nodes: fixture.nodes.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();

        let route = test_route(&source);
        let retained_proof = PrivateRecoveryAuthorityProof::from_control(
            route.runtime_deployment,
            &recovery,
            Some(selected_head),
            &fixture.recovery,
        )
        .unwrap();
        let (_, application, reopened, _) = append_completed_runtime_application(
            &mut source,
            &fixture,
            &policy_successor,
            &recovery,
            None,
            Some(&retained_proof),
            PrivateRuntimeSuccess::ControlOnly,
        );
        assert_eq!(
            application.recovery_authority_proof(),
            Some(&retained_proof)
        );

        let substituted_proof = PrivateRecoveryAuthorityProof::from_control(
            route.runtime_deployment,
            &recovery,
            Some(alternate_head),
            &fixture.recovery,
        )
        .unwrap();
        assert_ne!(retained_proof, substituted_proof);
        let stable_projection = application
            .successor_stable_projection()
            .unwrap()
            .commitment();
        let substituted_evidence = signed_evidence_for_intent_with_projection(
            &source,
            &recovery,
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: substituted_proof.clone(),
            },
            Some(&substituted_proof),
            reopened.commitment(),
            stable_projection,
        );
        substituted_evidence
            .verify_for_stable_projection(
                &recovery,
                source.binding().epoch,
                stable_projection,
                route,
                test_authority_target(&source),
            )
            .unwrap();
        persist_exact_evidence(&mut source, &recovery, &substituted_evidence);

        let source_before = directory_image(&source_path);
        let receiver_before = directory_image(&receiver_path);
        assert_eq!(
            serve_private_sync_page(
                &source,
                &fixture.recipients[0].identity,
                &request_for(&receiver, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32),
                &TestTransport,
            ),
            Err(PrivateSyncError::Tampered)
        );
        assert_eq!(directory_image(&source_path), source_before);
        assert_eq!(directory_image(&receiver_path), receiver_before);
    }

    #[test]
    fn retained_page_cannot_attach_evidence_to_a_low_level_control_prefix() {
        let directory = TestDirectory::new("retry-evidence-prefix");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let client_path = directory.child("client");
        let mut client = create_store(&client_path, &fixture);
        let control = invite_record(&server, &fixture, 50);
        server.append_control(&control, &TestAuthority).unwrap();
        let evidence = signed_evidence(&server, &control);
        let page = verified_control_page(&client, &server, &control, None, &evidence);

        // Model a legacy process loss after a naked PCTL became visible. Even
        // an exact retained v3 page may not bless that prefix or attach source
        // evidence without the receiver's own PVM/PAPL transaction.
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
            Err(PrivateSyncError::UnsupportedOperation)
        );
        assert_eq!(client.control_count(), 1);
        assert_eq!(
            client
                .read_control_authority_evidence(&client.indexed_controls()[0])
                .unwrap()
                .as_deref(),
            None
        );
        drop(client);
        let reopened =
            PrivateStore::open(&client_path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(
            reopened
                .read_control_authority_evidence(&reopened.indexed_controls()[0])
                .unwrap()
                .as_deref(),
            None
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
            .verify_for_stable_projection(
                &control,
                store.binding().epoch,
                Hash([0x82; 32]),
                route,
                authority,
            )
            .unwrap();
        assert_eq!(
            evidence.verify_for_stable_projection(
                &control,
                store.binding().epoch,
                Hash([0x83; 32]),
                route,
                authority,
            ),
            Err(PrivateSyncError::Tampered)
        );
        let key = SigningKey::from_bytes(&[0x71; 32]);

        let reject = |candidate: PrivateControlAuthorityEvidence| {
            assert_eq!(
                candidate.verify_for_stable_projection(
                    &control,
                    store.binding().epoch,
                    Hash([0x82; 32]),
                    route,
                    authority,
                ),
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
            first_wire.get(4..6),
            Some(EVIDENCE_FORMAT_VERSION.to_le_bytes().as_slice())
        );
        assert_eq!(
            PrivateControlAuthorityEvidence::decode(&first_wire),
            Ok(first.clone())
        );
        first
            .verify_for_stable_projection(
                &recovery,
                store.binding().epoch,
                Hash([0x82; 32]),
                test_route(&store),
                test_authority_target(&store),
            )
            .unwrap();
        assert_ne!(first.recovery_proof, second.recovery_proof);

        // AOI1 and PCA2 were signed for the first PRA1 selector. A second,
        // independently valid PRA1 for the same PCTL but another authority
        // projection head cannot be substituted into the retained envelope.
        let mixed = PrivateControlAuthorityEvidence {
            issuance_ack: first.issuance_ack.clone(),
            application_ack: first.application_ack.clone(),
            recovery_proof: second.recovery_proof.clone(),
        };
        assert_eq!(
            mixed.verify_for_stable_projection(
                &recovery,
                store.binding().epoch,
                Hash([0x82; 32]),
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
            substituted.verify_for_stable_projection(
                &control,
                store.binding().epoch,
                Hash([0x82; 32]),
                route,
                authority,
            ),
            Err(PrivateSyncError::Tampered)
        );
    }

    #[test]
    fn runtime_controls_return_verified_pvm_input_and_low_level_apply_is_no_write() {
        let directory = TestDirectory::new("verified-runtime-controls");
        let fixture = fixture();
        let policy = RuntimeResourcePolicy::standard();
        let actor = ActorId([0x98; 32]);
        let deployment = DeploymentId([0x99; 32]);
        let mutations = [
            PrivateRuntimeMutation::SetResourcePolicy(policy),
            PrivateRuntimeMutation::Suspend {
                actor,
                expected_deployment: deployment,
            },
        ];

        for (index, mutation) in mutations.into_iter().enumerate() {
            let operation = match &mutation {
                PrivateRuntimeMutation::SetResourcePolicy(policy) => {
                    PrivateControlOperation::SetResourcePolicy {
                        policy: BlobRef::of_bytes(&policy.encode().unwrap()),
                    }
                }
                PrivateRuntimeMutation::Suspend { actor, .. } => {
                    PrivateControlOperation::ActorLifecycle {
                        actor: *actor,
                        operation: PrivateActorLifecycleKind::Suspend,
                        request: mutation.commitment(),
                    }
                }
                _ => unreachable!(),
            };
            let mut source = create_store(&directory.child(&format!("source-{index}")), &fixture);
            let client_path = directory.child(&format!("client-{index}"));
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
            source.append_control(&control, &TestAuthority).unwrap();
            let evidence = signed_evidence(&source, &control);
            let page =
                verified_control_page(&client, &source, &control, Some(&mutation), &evidence);
            assert_eq!(
                PrivateSyncPage::decode(&page.encode().unwrap()),
                Ok(page.clone())
            );

            let verified = verify_private_sync_control_page(
                &page,
                test_route(&client),
                test_authority_target(&client),
            )
            .unwrap();
            assert_eq!(verified.len(), 1);
            assert_eq!(verified[0].control(), &control);
            assert_eq!(verified[0].mutation(), Some(&mutation));
            assert_eq!(verified[0].evidence_wire(), evidence.encode().unwrap());
            assert_eq!(verified[0].recovery_proof(), None);
            assert_eq!(
                verified[0].source_stable_projection(),
                verified[0]
                    .source_application()
                    .application
                    .stable_projection
            );
            assert_eq!(
                verified[0].issuance(),
                &AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack).unwrap()
            );

            let before_binding = client.binding();
            let before_counts = (client.control_count(), client.object_count());
            let before_image = directory_image(&client_path);
            client.reset_artifact_read_spy();
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
            assert_eq!(client.artifact_read_spy(), 0);
            assert_eq!(client.binding(), before_binding);
            assert_eq!(
                (client.control_count(), client.object_count()),
                before_counts
            );
            assert_eq!(directory_image(&client_path), before_image);
        }
    }

    #[test]
    fn v3_rejects_v2_prm_psp_and_pca_substitution_without_store_writes() {
        let directory = TestDirectory::new("v3-hostile-substitution");
        let fixture = fixture();
        let mut source = create_store(&directory.child("source"), &fixture);
        let client_path = directory.child("client");
        let mut client = create_store(&client_path, &fixture);
        let policy = RuntimeResourcePolicy::standard();
        let mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let mut control = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(&policy.encode().unwrap()),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut control, &fixture.owner_key).unwrap();
        source.append_control(&control, &TestAuthority).unwrap();
        let evidence = signed_evidence(&source, &control);
        let page = verified_control_page(&client, &source, &control, Some(&mutation), &evidence);

        let mut v2_request = page.request.encode().unwrap();
        assert_eq!(
            v2_request.get(4..6),
            Some(SYNC_FORMAT_VERSION.to_le_bytes().as_slice())
        );
        v2_request[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            PrivateSyncRequest::decode(&v2_request),
            Err(PrivateSyncError::InvalidFrame)
        );
        let mut v2_page = page.encode().unwrap();
        v2_page[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            PrivateSyncPage::decode(&v2_page),
            Err(PrivateSyncError::InvalidFrame)
        );

        let assert_no_write = |candidate: &PrivateSyncPage, client: &mut PrivateStore, expected| {
            let before_binding = client.binding();
            let before_counts = (client.control_count(), client.object_count());
            let before_image = directory_image(&client_path);
            client.reset_artifact_read_spy();
            assert_eq!(
                apply_private_sync_page(
                    client,
                    &fixture.recipients[0].identity,
                    candidate,
                    &TestAuthority,
                    &TestTransport,
                ),
                Err(expected)
            );
            assert_eq!(client.artifact_read_spy(), 0);
            assert_eq!(client.binding(), before_binding);
            assert_eq!(
                (client.control_count(), client.object_count()),
                before_counts
            );
            assert_eq!(directory_image(&client_path), before_image);
        };

        let mut missing_prm = page.clone();
        let PrivateSyncItem::Control { mutation, .. } = &mut missing_prm.items[0] else {
            unreachable!()
        };
        *mutation = None;
        assert_no_write(&missing_prm, &mut client, PrivateSyncError::InvalidFrame);

        let mut alternate_policy = RuntimeResourcePolicy::standard();
        alternate_policy.max_actors -= 1;
        let mut substituted_prm = page.clone();
        let PrivateSyncItem::Control { mutation, .. } = &mut substituted_prm.items[0] else {
            unreachable!()
        };
        *mutation = Some(
            PrivateRuntimeMutation::SetResourcePolicy(alternate_policy)
                .encode()
                .unwrap(),
        );
        assert_no_write(
            &substituted_prm,
            &mut client,
            PrivateSyncError::InvalidFrame,
        );

        let mut substituted_psp = page.clone();
        let PrivateSyncItem::Control {
            stable_projection, ..
        } = &mut substituted_psp.items[0]
        else {
            unreachable!()
        };
        *stable_projection = Hash([0x83; 32]);
        assert_no_write(
            &substituted_psp,
            &mut client,
            PrivateSyncError::InvalidFrame,
        );

        let mut bad_signature = page.clone();
        let PrivateSyncItem::Control { evidence, .. } = &mut bad_signature.items[0] else {
            unreachable!()
        };
        let mut envelope = PrivateControlAuthorityEvidence::decode(evidence).unwrap();
        let mut application =
            PrivateControlApplicationAck::decode(&envelope.application_ack).unwrap();
        application.signature[0] ^= 1;
        envelope.application_ack = application.encode().unwrap();
        *evidence = envelope.encode().unwrap();
        bad_signature.validate_shape().unwrap();
        assert_no_write(&bad_signature, &mut client, PrivateSyncError::Tampered);

        let mut alternate_source = create_store(&directory.child("alternate-source"), &fixture);
        let alternate_control = invite_record(&alternate_source, &fixture, 0xa4);
        alternate_source
            .append_control(&alternate_control, &TestAuthority)
            .unwrap();
        let alternate_evidence = signed_evidence(&alternate_source, &alternate_control);
        let mut substituted_pca = page.clone();
        let PrivateSyncItem::Control { evidence, .. } = &mut substituted_pca.items[0] else {
            unreachable!()
        };
        *evidence = alternate_evidence.encode().unwrap();
        substituted_pca.validate_shape().unwrap();
        assert_no_write(&substituted_pca, &mut client, PrivateSyncError::Tampered);

        let control_only_page = verified_control_page(
            &client,
            &alternate_source,
            &alternate_control,
            None,
            &alternate_evidence,
        );
        let verified = verify_private_sync_control_page(
            &control_only_page,
            test_route(&client),
            test_authority_target(&client),
        )
        .unwrap();
        assert_eq!(verified[0].mutation(), None);
        let mut smuggled_prm = control_only_page;
        let PrivateSyncItem::Control { mutation, .. } = &mut smuggled_prm.items[0] else {
            unreachable!()
        };
        *mutation = Some(
            PrivateRuntimeMutation::SetResourcePolicy(policy)
                .encode()
                .unwrap(),
        );
        assert_no_write(&smuggled_prm, &mut client, PrivateSyncError::InvalidFrame);
    }

    #[test]
    fn complete_control_page_is_prevalidated_before_any_local_mutation() {
        let directory = TestDirectory::new("whole-page-prevalidation");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let first = invite_record(&server, &fixture, 50);
        server.append_control(&first, &TestAuthority).unwrap();
        let first_evidence = signed_evidence(&server, &first);
        let second = invite_record(&server, &fixture, 51);
        server.append_control(&second, &TestAuthority).unwrap();
        let second_evidence = signed_evidence(&server, &second);

        let make_page = |client: &PrivateStore| {
            let page = PrivateSyncPage {
                request: request_for(client, 4, MAX_PRIVATE_SYNC_PAGE_BYTES as u32),
                target: sync_target(&server).unwrap(),
                phase: PrivateSyncPhase::Controls,
                items: vec![
                    control_item(&first, 0, None, &first_evidence),
                    control_item(&second, 0, None, &second_evidence),
                ],
                next: None,
            };
            page.validate_shape().unwrap();
            page
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
        invalid_chain.target.head.control_head = Some(alternate_commitment);
        if let Some(next) = &mut invalid_chain.next {
            next.local.control_head = Some(alternate_commitment);
            next.target = Some(invalid_chain.target);
        }
        assert_eq!(
            invalid_chain.validate_shape(),
            Err(PrivateSyncError::OutOfOrder)
        );
        let before = directory_image(&second_client_path);
        second_client.reset_artifact_read_spy();
        assert_eq!(
            apply_private_sync_page(
                &mut second_client,
                &fixture.recipients[0].identity,
                &invalid_chain,
                &TestAuthority,
                &TestTransport,
            ),
            Err(PrivateSyncError::OutOfOrder)
        );
        assert_eq!(second_client.artifact_read_spy(), 0);
        assert_eq!(directory_image(&second_client_path), before);
        assert_eq!(
            (second_client.control_count(), second_client.object_count()),
            (0, 0)
        );
    }

    #[test]
    fn offline_recovery_page_verifies_superseded_fork_without_low_level_apply() {
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
        let evidence = signed_recovery_evidence(&server, &recovery, &fixture.recovery, None);
        let page = verified_control_page(&client, &server, &recovery, None, &evidence);
        assert_eq!(page.phase, PrivateSyncPhase::Controls);
        assert_eq!(page.items.len(), 1);
        let verified = verify_private_sync_control_page(
            &page,
            test_route(&client),
            test_authority_target(&client),
        )
        .unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].control(), &recovery);
        assert!(
            verified[0]
                .recovery_proof()
                .is_some_and(|proof| proof.matches_control(&recovery))
        );
        let before = client.binding();
        let before_image = directory_image(&directory.child("client"));
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
        assert_eq!(client.binding(), before);
        assert_eq!(directory_image(&directory.child("client")), before_image);
    }

    #[test]
    fn object_pagination_pins_source_index_and_rejects_backward_pages() {
        let directory = TestDirectory::new("object-snapshot");
        let fixture = fixture();
        let mut server = create_store(&directory.child("server"), &fixture);
        let mut client = create_store(&directory.child("client"), &fixture);
        let mut objects: Vec<_> = (1..=4u8)
            .map(|label| {
                encrypt_private_object(
                    &fixture.epoch.data_key,
                    fixture.space,
                    fixture.agent,
                    0,
                    EncryptedObjectKind::Blob,
                    &[label; 32],
                )
                .unwrap()
            })
            .collect();
        objects.sort_by_key(PrivateObjectKey::from_object);

        // Publish B and C first so the first one-item page advances its cursor
        // past the still-held A key.
        server.put_object(&objects[1]).unwrap();
        server.put_object(&objects[2]).unwrap();
        let request = request_for(&client, 1, MAX_PRIVATE_SYNC_PAGE_BYTES as u32);
        let first = serve_private_sync_page(
            &server,
            &fixture.recipients[0].identity,
            &request,
            &TestTransport,
        )
        .unwrap();
        assert_eq!(first.target.object_count, 2);
        assert!(first.target.object_root.is_some());
        let next = first.next.clone().unwrap();

        // A receiver may already contain a valid extra object. The source
        // snapshot pins serving; it is not an equality claim about the
        // receiver's mergeable object set.
        client.put_object(&objects[3]).unwrap();
        assert_eq!(
            apply_private_sync_page(
                &mut client,
                &fixture.recipients[0].identity,
                &first,
                &TestAuthority,
                &TestTransport,
            ),
            Ok(PrivateSyncApplyDisposition::Applied)
        );

        // A page may never repeat the request's advertised last-applied
        // object, even if all of its object bytes are valid.
        let mut repeated = first.clone();
        repeated.request = PrivateSyncRequest {
            cursor: next.clone(),
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        repeated.next = None;
        assert_eq!(repeated.validate_shape(), Err(PrivateSyncError::Duplicate));

        // A valid object which sorts strictly below the advertised cursor is
        // out of order rather than a duplicate.
        let mut below = repeated;
        let wire = objects[0].encode().unwrap();
        below.items = vec![PrivateSyncItem::Object {
            key: PrivateObjectKey::from_object(&objects[0]),
            wire_hash: sync_wire_hash(&wire),
            wire,
        }];
        assert_eq!(below.validate_shape(), Err(PrivateSyncError::OutOfOrder));

        let mut invalid_target = first.clone();
        invalid_target.target.object_count = 0;
        assert_eq!(
            invalid_target.validate_shape(),
            Err(PrivateSyncError::InvalidFrame)
        );

        let mut substituted = PrivateSyncRequest {
            cursor: next.clone(),
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        substituted.cursor.target.as_mut().unwrap().object_root = Some(Hash([0xa5; 32]));
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &substituted,
                &TestTransport,
            ),
            Err(PrivateSyncError::StaleTarget)
        );

        // Publishing A after the first page changes the pinned object-index
        // snapshot even though epoch/control_head are unchanged. The old
        // cursor is stale instead of silently resuming at C and missing A.
        server.put_object(&objects[0]).unwrap();
        let continuation = PrivateSyncRequest {
            cursor: next,
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        assert_eq!(
            serve_private_sync_page(
                &server,
                &fixture.recipients[0].identity,
                &continuation,
                &TestTransport,
            ),
            Err(PrivateSyncError::StaleTarget)
        );
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
