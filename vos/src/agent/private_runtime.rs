//! Canonical node-local evidence for Private Agent runtime state.
//!
//! This module owns three clean-generation formats:
//!
//! - `PVRI3` is the exact node-local runtime image paired with one immutable
//!   Private Store core position.
//! - `PAPL1` is the pending/completed application of one exact PCTL. It keeps
//!   the receipt and AOI1 preimages but can represent only a positive result.
//! - `PCRS3` reopens the exact completed application, Store position, and
//!   successor runtime image before downstream PCAF2/PCA2/PSE2 evidence exists.
//!
//! The Store position deliberately excludes PVRI/PAPL/PCRS and every
//! authority acknowledgement derived from them. This preserves the acyclic
//! commitment order `AOI1 -> PAPL1 -> (PVRI3, Store) -> PCRS3/PCAF2 -> PCA2 ->
//! PSE2`. Runtime images and applications include the local NodeId and are
//! never suitable as cross-replica equality claims; only
//! [`PrivateRuntimeStableProjection`] is replica-stable.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use vos_agent_sdk::authority::{
    AuthorityOperationKind, AuthorityReceipt, AuthorityVerifier, ManagedAgentTarget,
};
use vos_agent_sdk::authority_operation::{
    AuthorityOperationIssuanceAck, MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
    MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES, PrivateRecoveryAuthorityProof,
    PrivateRecoveryAuthorityProofVerifier, private_node_identity_set_commitment,
};
use vos_agent_sdk::contract::RuntimeResourcePolicy;
use vos_agent_sdk::private::{
    MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS, PrivateControlOperation, PrivateControlRecord,
    PrivateKeyEpoch, PrivateNodeIdentity, recovery_signing_public_key_commitment,
};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_ACTOR_ENTRY_WIRE_BYTES, MAX_AUTHORITY_RECEIPT_WIRE_BYTES,
    MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES,
    authority_private_node_identity_commitment,
};
use vos_agent_sdk::{
    ActorEntry, ActorId, AgentDescriptor, AgentId, AgentProfile, BlobRef, DeploymentId, Hash,
    MAX_CATALOG_ARTIFACT_BYTES, MAX_RUNTIME_STATE_BYTES, ManagementError, ManagementReply,
    ManagementRequest, NodeId, PrincipalId, PrivateRuntimeMutation, ProducerId, ProgramId,
    RUNTIME_ABI_ID, RuntimeOutcome, RuntimeState, RuntimeTransition, SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use super::private_store::{MAX_PRIVATE_STORE_CONTROLS, MAX_PRIVATE_STORE_OBJECTS};

const HEADER_BYTES: usize = 4 + 32;
const PRIVATE_CONTROL_ONLY_REPLAY_DOMAIN: &[u8] = b"vos/agent/private-control-only-replay/v1";
const PRIVATE_KEY_EPOCH_WIRE_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/private-key-epoch-wire/v1";
const PRIVATE_KEY_EPOCH_ROOT_DOMAIN: &[u8] = b"vos/agent/private-key-epoch-root/v1";
const PRIVATE_STORE_CORE_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/private-store-core/v1";
const PRIVATE_RUNTIME_POLICY_COMMITMENT_DOMAIN: &[u8] =
    b"vos/agent/private-runtime-resource-policy/v1";
const PRIVATE_RUNTIME_SUCCESS_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/private-runtime-success/v1";
const PRIVATE_RUNTIME_STABLE_PROJECTION_COMMITMENT_DOMAIN: &[u8] =
    b"vos/agent/private-runtime-stable-projection/v1";
const PRIVATE_RUNTIME_CONTROL_STATE_COMMITMENT_DOMAIN: &[u8] =
    b"vos/agent/private-runtime-control-state/v1";
const PRIVATE_RUNTIME_IMAGE_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/private-runtime-image/v3";
const PRIVATE_RUNTIME_ESTABLISHMENT_SEAL_DOMAIN: &[u8] =
    b"vos/agent/private-runtime-establishment-seal/v1";
const PRIVATE_RUNTIME_APPLICATION_COMMITMENT_DOMAIN: &[u8] =
    b"vos/agent/private-runtime-application/v1";
const PRIVATE_CONTROL_REOPENED_STATE_COMMITMENT_DOMAIN: &[u8] =
    b"vos/agent/private-control-reopened-state/v3";

/// One genesis epoch plus one successor for every admitted PCTL.
pub const MAX_PRIVATE_RUNTIME_KEY_EPOCHS: usize = MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS + 1;
/// A success is either `ControlOnly` or one bounded Private management reply.
pub const MAX_PRIVATE_RUNTIME_SUCCESS_WIRE_BYTES: usize =
    HEADER_BYTES + 1 + 4 + HEADER_BYTES + 32 + MAX_ACTOR_ENTRY_WIRE_BYTES;
/// Fixed-size exact commitment to one canonical PKEY preimage.
pub const PRIVATE_KEY_EPOCH_COMMITMENT_WIRE_BYTES: usize = HEADER_BYTES + 8 + 32;
/// Maximum exact node-local PVRI3 image.
pub const MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES: usize = MAX_RUNTIME_STATE_BYTES
    + MAX_PRIVATE_RUNTIME_KEY_EPOCHS * (4 + PRIVATE_KEY_EPOCH_COMMITMENT_WIRE_BYTES)
    + 16 * 1024;
/// Maximum pending/completed PAPL1 application.
pub const MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES: usize = MAX_PRIVATE_CONTROL_WIRE_BYTES
    + MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES
    + MAX_AUTHORITY_RECEIPT_WIRE_BYTES
    + MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
    + MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES
    + MAX_PRIVATE_RUNTIME_SUCCESS_WIRE_BYTES
    + 32 * 1024;
/// Maximum reopened PCRS3 aggregate.
pub const MAX_PRIVATE_CONTROL_REOPENED_STATE_WIRE_BYTES: usize =
    MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES + MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES + 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateRuntimeEvidenceError {
    InvalidDescriptor,
    InvalidState,
    InvalidStorePosition,
    InvalidKeyEpochs,
    InvalidControl,
    InvalidAuthority,
    InvalidApplication,
    InvalidSuccess,
    InvalidProjection,
    LimitExceeded,
}

/// Minimal non-secret route projection extracted inside the authenticated
/// Private runtime boundary. Names, package references, lane state, messages,
/// object bytes, and key material never cross this seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PrivateRuntimeActorRoute {
    pub(super) actor: ActorId,
    pub(super) incarnation: Hash,
    pub(super) deployment: DeploymentId,
    pub(super) program: ProgramId,
    pub(super) suspended: bool,
}

impl fmt::Display for PrivateRuntimeEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Private runtime evidence: {self:?}")
    }
}

impl core::error::Error for PrivateRuntimeEvidenceError {}

fn nonzero_option(value: Option<Hash>) -> bool {
    value.is_none_or(|value| value != Hash::ZERO)
}

fn encode_optional_hash(encoder: &mut Encoder<'_>, value: Option<Hash>) {
    encoder.option(&value, |encoder, value| encoder.fixed(value.as_bytes()));
}

fn decode_optional_hash(decoder: &mut Decoder<'_>) -> Result<Option<Hash>, DecodeError> {
    decoder.option(|decoder| {
        let value = Hash(decoder.fixed()?);
        (value != Hash::ZERO)
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    })
}

fn encode_optional_u64(encoder: &mut Encoder<'_>, value: Option<u64>) {
    encoder.option(&value, |encoder, value| encoder.u64(*value));
}

fn decode_optional_u64(decoder: &mut Decoder<'_>) -> Result<Option<u64>, DecodeError> {
    decoder.option(Decoder::u64)
}

fn encode_managed(encoder: &mut Encoder<'_>, managed: ManagedAgentTarget) {
    encoder.fixed(managed.space.as_bytes());
    encoder.fixed(managed.agent.as_bytes());
    encoder.fixed(managed.owner.as_bytes());
    encoder.u8(managed.profile as u8);
    encoder.fixed(managed.runtime_deployment.as_bytes());
    encoder.fixed(managed.transition_producer.as_bytes());
}

fn managed_target_for_descriptor(descriptor: &AgentDescriptor) -> ManagedAgentTarget {
    ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    }
}

fn decode_managed(decoder: &mut Decoder<'_>) -> Result<ManagedAgentTarget, DecodeError> {
    let managed = ManagedAgentTarget {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        profile: match decoder.u8()? {
            0 => AgentProfile::Local,
            1 => AgentProfile::Shared,
            2 => AgentProfile::Private,
            _ => return Err(DecodeError::InvalidTag),
        },
        runtime_deployment: DeploymentId(decoder.fixed()?),
        transition_producer: ProducerId(decoder.fixed()?),
    };
    managed
        .is_valid()
        .then_some(managed)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_blob(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    let value = BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    };
    valid_runtime_package(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn valid_runtime_package(value: &BlobRef) -> bool {
    value.hash != Hash::ZERO && value.len != 0 && value.len <= MAX_CATALOG_ARTIFACT_BYTES
}

fn creation_receipt_matches_image(
    managed: ManagedAgentTarget,
    receipt: &AuthorityReceipt,
    genesis_at: u64,
) -> bool {
    let selector = &receipt.selector;
    receipt.validate_shape().is_ok()
        && selector.operation == AuthorityOperationKind::CreateAgent
        && selector.space == managed.space
        && selector.agent == managed.agent
        && selector.runtime_deployment == managed.runtime_deployment
        && selector.actor.is_none()
        && selector.actor_deployment.is_none()
        && genesis_at == selector.valid_from
        && selector.is_live_at(genesis_at)
}

fn verify_creation_receipt<V: AuthorityVerifier>(
    descriptor: &AgentDescriptor,
    receipt: &AuthorityReceipt,
    genesis_at: u64,
    verifier: &V,
) -> Result<(), PrivateRuntimeEvidenceError> {
    let managed = managed_target_for_descriptor(descriptor);
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    if descriptor.validate().is_err()
        || descriptor.identity.profile != AgentProfile::Private
        || !request.is_valid()
        || !creation_receipt_matches_image(managed, receipt, genesis_at)
        || !descriptor.authority.accepts(receipt)
        || receipt.selector.request != request.commitment()
        || receipt.verify_at(genesis_at, verifier).is_err()
    {
        return Err(PrivateRuntimeEvidenceError::InvalidAuthority);
    }
    Ok(())
}

fn encode_nested<T: CanonicalWire>(encoder: &mut Encoder<'_>, value: &T) {
    encoder.bytes(
        &value
            .encode()
            .expect("validated Private runtime evidence nested wire"),
    );
}

fn decode_nested<T: CanonicalWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref_bounded(maximum)?;
    let value = T::decode(bytes).map_err(|_| DecodeError::NonCanonical)?;
    if value
        .encode()
        .map_or(true, |canonical| canonical.as_slice() != bytes)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_runtime_state(encoder: &mut Encoder<'_>, state: &RuntimeState) {
    encoder.bytes(&state.control);
    encoder.bytes(&state.linear);
    encoder.bytes(&state.merge);
    encoder.bytes(&state.local);
}

fn decode_runtime_state(decoder: &mut Decoder<'_>) -> Result<RuntimeState, DecodeError> {
    let control = decoder.bytes_bounded(MAX_RUNTIME_STATE_BYTES)?;
    let mut remaining = MAX_RUNTIME_STATE_BYTES.saturating_sub(control.len());
    let linear = decoder.bytes_bounded(remaining)?;
    remaining = remaining.saturating_sub(linear.len());
    let merge = decoder.bytes_bounded(remaining)?;
    remaining = remaining.saturating_sub(merge.len());
    let local = decoder.bytes_bounded(remaining)?;
    let state = RuntimeState {
        control,
        linear,
        merge,
        local,
    };
    (state.validate() && state.linear.is_empty())
        .then_some(state)
        .ok_or(DecodeError::NonCanonical)
}

fn resource_policy_commitment(
    policy: RuntimeResourcePolicy,
) -> Result<Hash, PrivateRuntimeEvidenceError> {
    let bytes = policy
        .encode()
        .map_err(|_| PrivateRuntimeEvidenceError::InvalidProjection)?;
    Ok(Hash::digest(
        PRIVATE_RUNTIME_POLICY_COMMITMENT_DOMAIN,
        &[RUNTIME_ABI_ID.as_bytes(), &bytes],
    ))
}

fn control_state_commitment(control: &[u8]) -> Hash {
    Hash::digest(
        PRIVATE_RUNTIME_CONTROL_STATE_COMMITMENT_DOMAIN,
        &[RUNTIME_ABI_ID.as_bytes(), control],
    )
}

/// Exact identity of one canonical PKEY preimage without retaining its sealed
/// envelopes in every runtime image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateKeyEpochCommitment {
    epoch: u64,
    exact_wire: Hash,
}

impl PrivateKeyEpochCommitment {
    pub fn from_epoch(epoch: &PrivateKeyEpoch) -> Result<Self, PrivateRuntimeEvidenceError> {
        let wire = epoch
            .encode()
            .map_err(|_| PrivateRuntimeEvidenceError::InvalidKeyEpochs)?;
        let value = Self {
            epoch: epoch.epoch,
            exact_wire: Hash::digest(
                PRIVATE_KEY_EPOCH_WIRE_COMMITMENT_DOMAIN,
                &[RUNTIME_ABI_ID.as_bytes(), &wire],
            ),
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn exact_wire(&self) -> Hash {
        self.exact_wire
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        if self.exact_wire == Hash::ZERO {
            return Err(PrivateRuntimeEvidenceError::InvalidKeyEpochs);
        }
        Ok(())
    }
}

impl CanonicalWire for PrivateKeyEpochCommitment {
    const MAGIC: [u8; 4] = *b"PKE1";
    const MAX_ENCODED_BYTES: usize = PRIVATE_KEY_EPOCH_COMMITMENT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.u64(self.epoch);
        encoder.fixed(self.exact_wire.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            epoch: decoder.u64()?,
            exact_wire: Hash(decoder.fixed()?),
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

fn validate_key_epochs(
    values: &[PrivateKeyEpochCommitment],
) -> Result<(), PrivateRuntimeEvidenceError> {
    if values.is_empty()
        || values.len() > MAX_PRIVATE_RUNTIME_KEY_EPOCHS
        || values[0].epoch != 0
        || values.iter().any(|value| value.validate().is_err())
        || !values.windows(2).all(|pair| pair[0].epoch < pair[1].epoch)
    {
        return Err(PrivateRuntimeEvidenceError::InvalidKeyEpochs);
    }
    Ok(())
}

pub fn private_key_epoch_root(
    values: &[PrivateKeyEpochCommitment],
) -> Result<Hash, PrivateRuntimeEvidenceError> {
    validate_key_epochs(values)?;
    let mut bytes = Vec::with_capacity(4 + values.len() * 40);
    let mut encoder = Encoder(&mut bytes);
    encoder.u32(values.len() as u32);
    for value in values {
        encoder.u64(value.epoch);
        encoder.fixed(value.exact_wire.as_bytes());
    }
    Ok(Hash::digest(
        PRIVATE_KEY_EPOCH_ROOT_DOMAIN,
        &[RUNTIME_ABI_ID.as_bytes(), &bytes],
    ))
}

/// Cycle-free position in the ciphertext/control Store.
///
/// `object_root`, `control_root`, and `key_epoch_root` commit only Store core
/// indices. In particular they must never include PVRI, PAPL, PCRS, PCAF2,
/// PCA2, or PSE2 bytes. A later Store row may attach those values alongside
/// this immutable core position without changing its commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateStoreCorePosition {
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    epoch: u64,
    control_head: Option<Hash>,
    next_sequence: u64,
    object_count: u32,
    object_root: Option<Hash>,
    control_count: u32,
    control_root: Option<Hash>,
    key_epoch_root: Hash,
}

impl PrivateStoreCorePosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        epoch: u64,
        control_head: Option<Hash>,
        next_sequence: u64,
        object_count: u32,
        object_root: Option<Hash>,
        control_count: u32,
        control_root: Option<Hash>,
        key_epoch_root: Hash,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        let value = Self {
            space,
            agent,
            owner,
            epoch,
            control_head,
            next_sequence,
            object_count,
            object_root,
            control_count,
            control_root,
            key_epoch_root,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }
    pub const fn agent(&self) -> AgentId {
        self.agent
    }
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn control_head(&self) -> Option<Hash> {
        self.control_head
    }
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }
    pub const fn object_root(&self) -> Option<Hash> {
        self.object_root
    }
    pub const fn control_count(&self) -> u32 {
        self.control_count
    }
    pub const fn control_root(&self) -> Option<Hash> {
        self.control_root
    }
    pub const fn key_epoch_root(&self) -> Hash {
        self.key_epoch_root
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            PRIVATE_STORE_CORE_COMMITMENT_DOMAIN,
            &[&self.encode().expect("valid PSC1")],
        )
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        let object_shape = match (self.object_count, self.object_root) {
            (0, None) => true,
            (count, Some(root)) => count > 0 && root != Hash::ZERO,
            _ => false,
        };
        let control_shape = match (
            self.control_count,
            self.control_head,
            self.control_root,
            self.next_sequence,
        ) {
            (0, None, None, 0) => true,
            (count, Some(head), Some(root), next) => {
                count > 0 && head != Hash::ZERO && root != Hash::ZERO && next > 0
            }
            _ => false,
        };
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.owner == PrincipalId::ZERO
            || self.object_count as usize > MAX_PRIVATE_STORE_OBJECTS
            || self.control_count as usize > MAX_PRIVATE_STORE_CONTROLS
            || self.key_epoch_root == Hash::ZERO
            || !object_shape
            || !control_shape
        {
            return Err(PrivateRuntimeEvidenceError::InvalidStorePosition);
        }
        Ok(())
    }
}

impl CanonicalWire for PrivateStoreCorePosition {
    const MAGIC: [u8; 4] = *b"PSC1";
    const MAX_ENCODED_BYTES: usize = HEADER_BYTES + 32 * 8 + 64;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.space.as_bytes());
        encoder.fixed(self.agent.as_bytes());
        encoder.fixed(self.owner.as_bytes());
        encoder.u64(self.epoch);
        encode_optional_hash(encoder, self.control_head);
        encoder.u64(self.next_sequence);
        encoder.u32(self.object_count);
        encode_optional_hash(encoder, self.object_root);
        encoder.u32(self.control_count);
        encode_optional_hash(encoder, self.control_root);
        encoder.fixed(self.key_epoch_root.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            owner: PrincipalId(decoder.fixed()?),
            epoch: decoder.u64()?,
            control_head: decode_optional_hash(decoder)?,
            next_sequence: decoder.u64()?,
            object_count: decoder.u32()?,
            object_root: decode_optional_hash(decoder)?,
            control_count: decoder.u32()?,
            control_root: decode_optional_hash(decoder)?,
            key_epoch_root: Hash(decoder.fixed()?),
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

/// Exact positive disposition of one PCTL application.
///
/// This type has no error or denial variant. A guest rejection is local and
/// must not enter PAPL/PCRS or any downstream authority evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateRuntimeSuccess {
    /// Invite, Revoke, RotateKeys, and Recover change Store policy only and
    /// never enter the guest runtime ABI.
    ControlOnly,
    ResourcePolicySet(RuntimeResourcePolicy),
    Installed(ActorEntry),
    Upgraded(ActorEntry),
    Suspended(ActorEntry),
    Resumed(ActorEntry),
    Removed(ActorId),
}

impl PrivateRuntimeSuccess {
    fn tag(&self) -> u8 {
        match self {
            Self::ControlOnly => 0,
            Self::ResourcePolicySet(_) => 1,
            Self::Installed(_) => 2,
            Self::Upgraded(_) => 3,
            Self::Suspended(_) => 4,
            Self::Resumed(_) => 5,
            Self::Removed(_) => 6,
        }
    }

    pub fn management_reply(&self) -> Option<ManagementReply> {
        match self {
            Self::ControlOnly => None,
            Self::ResourcePolicySet(value) => Some(ManagementReply::ResourcePolicySet(*value)),
            Self::Installed(value) => Some(ManagementReply::Installed(value.clone())),
            Self::Upgraded(value) => Some(ManagementReply::Upgraded(value.clone())),
            Self::Suspended(value) => Some(ManagementReply::Suspended(value.clone())),
            Self::Resumed(value) => Some(ManagementReply::Resumed(value.clone())),
            Self::Removed(value) => Some(ManagementReply::Removed(*value)),
        }
    }

    fn transition_wire(&self) -> Result<Option<Vec<u8>>, PrivateRuntimeEvidenceError> {
        let Some(reply) = self.management_reply() else {
            return Ok(None);
        };
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Management(Ok(reply)),
        };
        let bytes = transition
            .encode()
            .map_err(|_| PrivateRuntimeEvidenceError::InvalidSuccess)?;
        if bytes.len() > MAX_PRIVATE_RUNTIME_SUCCESS_WIRE_BYTES {
            return Err(PrivateRuntimeEvidenceError::LimitExceeded);
        }
        Ok(Some(bytes))
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            PRIVATE_RUNTIME_SUCCESS_COMMITMENT_DOMAIN,
            &[&self.encode().expect("valid PSD1")],
        )
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        if matches!(self, Self::ControlOnly) {
            return Ok(());
        }
        self.transition_wire().map(|_| ())
    }
}

impl CanonicalWire for PrivateRuntimeSuccess {
    const MAGIC: [u8; 4] = *b"PSD1";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_RUNTIME_SUCCESS_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.u8(self.tag());
        if let Some(bytes) = self
            .transition_wire()
            .expect("validated Private runtime success")
        {
            encoder.bytes(&bytes);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let tag = decoder.u8()?;
        if tag == 0 {
            return Ok(Self::ControlOnly);
        }
        let bytes = decoder.bytes_ref_bounded(MAX_PRIVATE_RUNTIME_SUCCESS_WIRE_BYTES)?;
        let transition = RuntimeTransition::decode(bytes).map_err(|_| DecodeError::NonCanonical)?;
        if transition
            .encode()
            .map_or(true, |canonical| canonical.as_slice() != bytes)
            || !transition.state.is_empty()
        {
            return Err(DecodeError::NonCanonical);
        }
        let RuntimeOutcome::Management(Ok(reply)) = transition.outcome else {
            return Err(DecodeError::NonCanonical);
        };
        let value = match (tag, reply) {
            (1, ManagementReply::ResourcePolicySet(value)) => Self::ResourcePolicySet(value),
            (2, ManagementReply::Installed(value)) => Self::Installed(value),
            (3, ManagementReply::Upgraded(value)) => Self::Upgraded(value),
            (4, ManagementReply::Suspended(value)) => Self::Suspended(value),
            (5, ManagementReply::Resumed(value)) => Self::Resumed(value),
            (6, ManagementReply::Removed(value)) => Self::Removed(value),
            _ => return Err(DecodeError::NonCanonical),
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

/// Trusted interpretation of one successfully decoded Private-control runtime
/// transition.
///
/// A guest denial is terminal only when it returns the exact full predecessor
/// state. It deliberately has no PAPL/PVRI representation because downstream
/// Private application evidence records positive dispositions only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateRuntimeControlDisposition {
    Applied {
        state: RuntimeState,
        success: PrivateRuntimeSuccess,
    },
    RetiredUnapplied {
        error: ManagementError,
    },
}

/// Validate the exact post-Create transition before constructing the genesis
/// PVRI image.
///
/// This is intentionally independent of receipt verification. The physical
/// host must first execute the exact receipt-authorized `Create` work, then
/// pass the transition here, and finally construct [`PrivateRuntimeImage`]
/// at the receipt's signed `valid_from` slot.
pub fn validate_private_runtime_genesis_transition(
    descriptor: &AgentDescriptor,
    transition: RuntimeTransition,
) -> Result<RuntimeState, PrivateRuntimeEvidenceError> {
    if descriptor.validate().is_err() || descriptor.identity.profile != AgentProfile::Private {
        return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
    }
    let RuntimeTransition { state, outcome } = transition;
    if !state.validate()
        || state.is_empty()
        || !state.linear.is_empty()
        || state.encoded_len().is_none_or(|length| {
            length > descriptor.initial_resource_policy().max_runtime_state_bytes as usize
        })
    {
        return Err(PrivateRuntimeEvidenceError::InvalidState);
    }
    match outcome {
        RuntimeOutcome::Management(Ok(ManagementReply::Created(identity)))
            if identity == descriptor.identity =>
        {
            Ok(state)
        }
        _ => Err(PrivateRuntimeEvidenceError::InvalidSuccess),
    }
}

/// Classify one Private-control guest transition after the caller has
/// authenticated its pending PAPL inputs.
///
/// Only a matching positive management reply can produce successor runtime
/// evidence. A management error is a durable terminal denial only when the
/// guest returned the byte-for-byte-equivalent full predecessor state. Every
/// other outcome is fail-closed and must leave the Store and PVRI unchanged.
pub fn classify_private_runtime_control_transition(
    predecessor: &PrivateRuntimeImage,
    request: &ManagementRequest,
    transition: RuntimeTransition,
) -> Result<PrivateRuntimeControlDisposition, PrivateRuntimeEvidenceError> {
    predecessor.validate()?;
    classify_private_runtime_control_transition_for_replay(
        predecessor.managed(),
        predecessor.state(),
        predecessor.active_resource_policy(),
        request,
        transition,
    )
}

/// Pure transition classifier used while authenticating an unpublished
/// replica replay. It applies the same state/reply/resource-policy rules as
/// the live PVRI path without requiring a destination Store or node-local
/// image to exist yet.
pub(crate) fn classify_private_runtime_control_transition_for_replay(
    managed: ManagedAgentTarget,
    predecessor_state: &RuntimeState,
    predecessor_active_policy: RuntimeResourcePolicy,
    request: &ManagementRequest,
    transition: RuntimeTransition,
) -> Result<PrivateRuntimeControlDisposition, PrivateRuntimeEvidenceError> {
    let ManagementRequest::PrivateControl { control, .. } = request else {
        return Err(PrivateRuntimeEvidenceError::InvalidApplication);
    };
    if !request.is_valid()
        || !managed.is_valid()
        || managed.profile != AgentProfile::Private
        || !predecessor_state.validate()
        || !predecessor_active_policy.is_valid()
        || control.space != managed.space
        || control.agent != managed.agent
    {
        return Err(PrivateRuntimeEvidenceError::InvalidApplication);
    }

    let RuntimeTransition { state, outcome } = transition;
    if !state.validate() {
        return Err(PrivateRuntimeEvidenceError::InvalidState);
    }
    match outcome {
        RuntimeOutcome::Management(Ok(reply)) => {
            if !request.private_runtime_reply_matches(&reply) {
                return Err(PrivateRuntimeEvidenceError::InvalidSuccess);
            }
            if !private_state_transition_matches(predecessor_state, &state, true)
                || state.is_empty()
            {
                return Err(PrivateRuntimeEvidenceError::InvalidState);
            }
            let success = match reply {
                ManagementReply::ResourcePolicySet(value) => {
                    PrivateRuntimeSuccess::ResourcePolicySet(value)
                }
                ManagementReply::Installed(value) => PrivateRuntimeSuccess::Installed(value),
                ManagementReply::Upgraded(value) => PrivateRuntimeSuccess::Upgraded(value),
                ManagementReply::Suspended(value) => PrivateRuntimeSuccess::Suspended(value),
                ManagementReply::Resumed(value) => PrivateRuntimeSuccess::Resumed(value),
                ManagementReply::Removed(value) => PrivateRuntimeSuccess::Removed(value),
                _ => return Err(PrivateRuntimeEvidenceError::InvalidSuccess),
            };
            if !success_is_private(&success) || success.validate().is_err() {
                return Err(PrivateRuntimeEvidenceError::InvalidSuccess);
            }
            let active_policy = match &success {
                PrivateRuntimeSuccess::ResourcePolicySet(policy) => *policy,
                _ => predecessor_active_policy,
            };
            if state
                .encoded_len()
                .is_none_or(|length| length > active_policy.max_runtime_state_bytes as usize)
            {
                return Err(PrivateRuntimeEvidenceError::InvalidState);
            }
            Ok(PrivateRuntimeControlDisposition::Applied { state, success })
        }
        RuntimeOutcome::Management(Err(error)) => {
            if state != *predecessor_state {
                return Err(PrivateRuntimeEvidenceError::InvalidState);
            }
            Ok(PrivateRuntimeControlDisposition::RetiredUnapplied { error })
        }
        _ => Err(PrivateRuntimeEvidenceError::InvalidSuccess),
    }
}

/// Replica-stable projection of the Private control application chain.
///
/// It deliberately excludes NodeId, applied slot, Store roots, raw runtime
/// state, and Merge/Local bytes. The shared creation-receipt commitment anchors
/// the initial runtime transition without importing each replica's observation
/// slot. Every successor commits the exact previous projection, full
/// application replay, positive disposition, and active RRP1 value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRuntimeStableProjection {
    managed: ManagedAgentTarget,
    descriptor: Hash,
    runtime_package: BlobRef,
    creation_receipt: Hash,
    generation: u64,
    previous: Option<Hash>,
    control_head: Option<Hash>,
    control_sequence: Option<u64>,
    full_replay: Option<Hash>,
    disposition: Option<Hash>,
    control_state: Hash,
    active_resource_policy: RuntimeResourcePolicy,
    active_resource_policy_commitment: Hash,
}

impl PrivateRuntimeStableProjection {
    pub fn genesis(
        managed: ManagedAgentTarget,
        descriptor: Hash,
        runtime_package: BlobRef,
        creation_receipt: Hash,
        active_resource_policy: RuntimeResourcePolicy,
        control_state: &[u8],
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        let value = Self {
            managed,
            descriptor,
            runtime_package,
            creation_receipt,
            generation: 0,
            previous: None,
            control_head: None,
            control_sequence: None,
            full_replay: None,
            disposition: None,
            control_state: control_state_commitment(control_state),
            active_resource_policy,
            active_resource_policy_commitment: resource_policy_commitment(active_resource_policy)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn successor(
        previous: &Self,
        control: &PrivateControlRecord,
        full_replay: Hash,
        success: &PrivateRuntimeSuccess,
        active_resource_policy: RuntimeResourcePolicy,
        control_state: &[u8],
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        Self::successor_with_control_commitment(
            previous,
            control,
            full_replay,
            success,
            active_resource_policy,
            control_state_commitment(control_state),
        )
    }

    fn successor_with_control_commitment(
        previous: &Self,
        control: &PrivateControlRecord,
        full_replay: Hash,
        success: &PrivateRuntimeSuccess,
        active_resource_policy: RuntimeResourcePolicy,
        control_state: Hash,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        previous.validate()?;
        if full_replay == Hash::ZERO || control_state == Hash::ZERO || !control.validate_shape() {
            return Err(PrivateRuntimeEvidenceError::InvalidProjection);
        }
        let value = Self {
            managed: previous.managed,
            descriptor: previous.descriptor,
            runtime_package: previous.runtime_package.clone(),
            creation_receipt: previous.creation_receipt,
            generation: previous
                .generation
                .checked_add(1)
                .ok_or(PrivateRuntimeEvidenceError::LimitExceeded)?,
            previous: Some(previous.commitment()),
            control_head: Some(control.commitment()),
            control_sequence: Some(control.sequence),
            full_replay: Some(full_replay),
            disposition: Some(success.commitment()),
            control_state,
            active_resource_policy,
            active_resource_policy_commitment: resource_policy_commitment(active_resource_policy)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn managed(&self) -> ManagedAgentTarget {
        self.managed
    }
    pub const fn descriptor(&self) -> Hash {
        self.descriptor
    }
    pub fn runtime_package(&self) -> &BlobRef {
        &self.runtime_package
    }
    pub const fn creation_receipt(&self) -> Hash {
        self.creation_receipt
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn previous(&self) -> Option<Hash> {
        self.previous
    }
    pub const fn control_head(&self) -> Option<Hash> {
        self.control_head
    }
    pub const fn control_sequence(&self) -> Option<u64> {
        self.control_sequence
    }
    pub const fn full_replay(&self) -> Option<Hash> {
        self.full_replay
    }
    pub const fn disposition(&self) -> Option<Hash> {
        self.disposition
    }
    pub const fn control_state(&self) -> Hash {
        self.control_state
    }
    pub const fn active_resource_policy(&self) -> RuntimeResourcePolicy {
        self.active_resource_policy
    }
    pub const fn active_resource_policy_commitment(&self) -> Hash {
        self.active_resource_policy_commitment
    }

    /// Check the exact stable projection produced by a locally replayed
    /// control result. This exposes no constructor and therefore cannot mint
    /// portable authority; it only closes preflight against a signed PSP.
    pub(crate) fn matches_replayed_successor(
        &self,
        predecessor: &Self,
        control: &PrivateControlRecord,
        full_replay: Hash,
        success: &PrivateRuntimeSuccess,
        state: &RuntimeState,
    ) -> bool {
        let active_resource_policy = match success {
            PrivateRuntimeSuccess::ResourcePolicySet(policy) => *policy,
            _ => predecessor.active_resource_policy,
        };
        Self::successor(
            predecessor,
            control,
            full_replay,
            success,
            active_resource_policy,
            &state.control,
        )
        .is_ok_and(|candidate| candidate == *self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            PRIVATE_RUNTIME_STABLE_PROJECTION_COMMITMENT_DOMAIN,
            &[&self.encode().expect("valid PSP1")],
        )
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        if !self.managed.is_valid()
            || self.managed.profile != AgentProfile::Private
            || self.descriptor == Hash::ZERO
            || !valid_runtime_package(&self.runtime_package)
            || self.creation_receipt == Hash::ZERO
            || self.control_state == Hash::ZERO
            || !self.active_resource_policy.is_valid()
            || resource_policy_commitment(self.active_resource_policy)?
                != self.active_resource_policy_commitment
            || self.active_resource_policy_commitment == Hash::ZERO
        {
            return Err(PrivateRuntimeEvidenceError::InvalidProjection);
        }
        let genesis = self.generation == 0
            && self.previous.is_none()
            && self.control_head.is_none()
            && self.control_sequence.is_none()
            && self.full_replay.is_none()
            && self.disposition.is_none();
        let successor = self.generation > 0
            && nonzero_option(self.previous)
            && self.previous.is_some()
            && nonzero_option(self.control_head)
            && self.control_head.is_some()
            && self.control_sequence.is_some()
            && nonzero_option(self.full_replay)
            && self.full_replay.is_some()
            && nonzero_option(self.disposition)
            && self.disposition.is_some();
        if !genesis && !successor {
            return Err(PrivateRuntimeEvidenceError::InvalidProjection);
        }
        Ok(())
    }
}

impl CanonicalWire for PrivateRuntimeStableProjection {
    const MAGIC: [u8; 4] = *b"PSP1";
    const MAX_ENCODED_BYTES: usize = 1024;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_managed(encoder, self.managed);
        encoder.fixed(self.descriptor.as_bytes());
        encode_blob(encoder, &self.runtime_package);
        encoder.fixed(self.creation_receipt.as_bytes());
        encoder.u64(self.generation);
        encode_optional_hash(encoder, self.previous);
        encode_optional_hash(encoder, self.control_head);
        encode_optional_u64(encoder, self.control_sequence);
        encode_optional_hash(encoder, self.full_replay);
        encode_optional_hash(encoder, self.disposition);
        encoder.fixed(self.control_state.as_bytes());
        encode_nested(encoder, &self.active_resource_policy);
        encoder.fixed(self.active_resource_policy_commitment.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            managed: decode_managed(decoder)?,
            descriptor: Hash(decoder.fixed()?),
            runtime_package: decode_blob(decoder)?,
            creation_receipt: Hash(decoder.fixed()?),
            generation: decoder.u64()?,
            previous: decode_optional_hash(decoder)?,
            control_head: decode_optional_hash(decoder)?,
            control_sequence: decode_optional_u64(decoder)?,
            full_replay: decode_optional_hash(decoder)?,
            disposition: decode_optional_hash(decoder)?,
            control_state: Hash(decoder.fixed()?),
            active_resource_policy: decode_nested(
                decoder,
                vos_agent_sdk::wire::MAX_RUNTIME_RESOURCE_POLICY_WIRE_BYTES,
            )?,
            active_resource_policy_commitment: Hash(decoder.fixed()?),
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateRuntimeControlPosition {
    pub control: Hash,
    pub sequence: u64,
}

impl PrivateRuntimeControlPosition {
    fn validate(self) -> bool {
        self.control != Hash::ZERO
    }
}

/// Exact node-local Private runtime image (`PVRI3`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRuntimeImage {
    managed: ManagedAgentTarget,
    node: NodeId,
    owner: PrincipalId,
    descriptor: Hash,
    runtime_package: BlobRef,
    creation_receipt: AuthorityReceipt,
    created_at: u64,
    establishment_origin: Option<Hash>,
    establishment_completion: Option<Hash>,
    runtime_deployment: DeploymentId,
    state: RuntimeState,
    active_resource_policy: RuntimeResourcePolicy,
    active_resource_policy_commitment: Hash,
    store: PrivateStoreCorePosition,
    key_epochs: Vec<PrivateKeyEpochCommitment>,
    runtime_control: Option<PrivateRuntimeControlPosition>,
    last_full_replay: Option<Hash>,
    stable_projection: PrivateRuntimeStableProjection,
    applied_at: u64,
}

/// Opaque one-shot authority to construct a replica-establishment genesis
/// PVRI for either a descriptor-listed or later-admitted Node.
///
/// The physical import path may mint this value only after authenticating one
/// complete source history. It binds the exact full destination identity,
/// genesis Store/PKEY inputs, final authenticated membership, and the exact
/// establishment identity. That identity commitment becomes an immutable
/// node-local PVRI3 origin, preventing a valid establishment receipt from being
/// spliced beside another same-node runtime lineage. Normal creation never needs this
/// capability and continues to require membership in `AgentDescriptor::replicas`.
///
/// This type deliberately implements neither `Clone` nor `CanonicalWire`: it
/// is an in-memory trust handoff, not portable evidence or durable authority.
pub(super) struct PrivateRuntimeReplicaEstablishment {
    descriptor: Hash,
    node: NodeId,
    local_identity: Hash,
    genesis_store: PrivateStoreCorePosition,
    genesis_key_epochs: Vec<PrivateKeyEpochCommitment>,
    final_membership: Hash,
    establishment_identity: Hash,
}

impl PrivateRuntimeReplicaEstablishment {
    /// Bind inputs selected from an already authenticated complete source.
    ///
    /// This runtime layer validates canonical shape and exact correspondence;
    /// the caller remains responsible for authenticating `final_members` and
    /// deriving `establishment_identity` from the exact source, route, owner,
    /// destination, authority, and execution budget before invoking this seam.
    pub(super) fn bind_verified_source(
        descriptor: &AgentDescriptor,
        local_node: &PrivateNodeIdentity,
        genesis_store: PrivateStoreCorePosition,
        genesis_key_epochs: &[PrivateKeyEpochCommitment],
        final_members: &[PrivateNodeIdentity],
        establishment_identity: Hash,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        if descriptor.validate().is_err()
            || descriptor.identity.profile != AgentProfile::Private
            || !local_node.validate()
            || local_node.principal != descriptor.identity.owner
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        validate_genesis_store_binding(descriptor, genesis_store, genesis_key_epochs)?;
        let final_membership = private_node_identity_set_commitment(final_members.iter())
            .ok_or(PrivateRuntimeEvidenceError::InvalidDescriptor)?;
        if establishment_identity == Hash::ZERO
            || final_members
                .iter()
                .any(|member| member.principal != descriptor.identity.owner)
            || final_members
                .binary_search_by_key(&local_node.node, |member| member.node)
                .ok()
                .and_then(|position| final_members.get(position))
                != Some(local_node)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        Ok(Self {
            descriptor: descriptor.commitment(),
            node: local_node.node,
            local_identity: authority_private_node_identity_commitment(local_node),
            genesis_store,
            genesis_key_epochs: genesis_key_epochs.to_vec(),
            final_membership,
            establishment_identity,
        })
    }

    fn consume_for(
        self,
        descriptor: &AgentDescriptor,
        store: PrivateStoreCorePosition,
        key_epochs: &[PrivateKeyEpochCommitment],
    ) -> Result<(NodeId, Hash), PrivateRuntimeEvidenceError> {
        if self.descriptor != descriptor.commitment()
            || self.local_identity == Hash::ZERO
            || self.final_membership == Hash::ZERO
            || self.establishment_identity == Hash::ZERO
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        if self.genesis_store != store {
            return Err(PrivateRuntimeEvidenceError::InvalidStorePosition);
        }
        if self.genesis_key_epochs != key_epochs {
            return Err(PrivateRuntimeEvidenceError::InvalidKeyEpochs);
        }
        Ok((self.node, self.establishment_identity))
    }
}

fn validate_genesis_store_binding(
    descriptor: &AgentDescriptor,
    store: PrivateStoreCorePosition,
    key_epochs: &[PrivateKeyEpochCommitment],
) -> Result<(), PrivateRuntimeEvidenceError> {
    store.validate()?;
    validate_key_epochs(key_epochs)?;
    if store.space != descriptor.identity.space
        || store.agent != descriptor.identity.agent
        || store.owner != descriptor.identity.owner
        || store.control_count != 0
        || store.control_head.is_some()
        || store.next_sequence != 0
    {
        return Err(PrivateRuntimeEvidenceError::InvalidStorePosition);
    }
    if private_key_epoch_root(key_epochs)? != store.key_epoch_root
        || key_epochs.last().map(|value| value.epoch) != Some(store.epoch)
    {
        return Err(PrivateRuntimeEvidenceError::InvalidKeyEpochs);
    }
    Ok(())
}

impl PrivateRuntimeImage {
    /// Construct the first image only from a valid immutable Private
    /// descriptor and the exact post-Create runtime state. `genesis_at` must
    /// equal the receipt's signed `valid_from`; the host separately checks
    /// receipt liveness at its trusted observation slot before execution.
    pub fn genesis<V: AuthorityVerifier>(
        descriptor: &AgentDescriptor,
        node: NodeId,
        state: RuntimeState,
        store: PrivateStoreCorePosition,
        key_epochs: Vec<PrivateKeyEpochCommitment>,
        creation_receipt: AuthorityReceipt,
        genesis_at: u64,
        authority_verifier: &V,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        Self::genesis_inner(
            descriptor,
            node,
            true,
            None,
            state,
            store,
            key_epochs,
            creation_receipt,
            genesis_at,
            authority_verifier,
        )
    }

    /// Construct a genesis PVRI from one fully authenticated replica source.
    ///
    /// Consuming the opaque capability admits either an immutable descriptor
    /// member or a later PKEY member and binds the verified source commitment
    /// into PVRI3. Descriptor, receipt, post-Create state, Store/PKEY,
    /// resource-policy, and stable-projection checks are shared with
    /// [`Self::genesis`].
    #[allow(clippy::too_many_arguments)]
    pub(super) fn genesis_for_established_replica<V: AuthorityVerifier>(
        descriptor: &AgentDescriptor,
        bootstrap: PrivateRuntimeReplicaEstablishment,
        state: RuntimeState,
        store: PrivateStoreCorePosition,
        key_epochs: Vec<PrivateKeyEpochCommitment>,
        creation_receipt: AuthorityReceipt,
        genesis_at: u64,
        authority_verifier: &V,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        let (node, establishment_origin) = bootstrap.consume_for(descriptor, store, &key_epochs)?;
        Self::genesis_inner(
            descriptor,
            node,
            false,
            Some(establishment_origin),
            state,
            store,
            key_epochs,
            creation_receipt,
            genesis_at,
            authority_verifier,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn genesis_inner<V: AuthorityVerifier>(
        descriptor: &AgentDescriptor,
        node: NodeId,
        require_descriptor_member: bool,
        establishment_origin: Option<Hash>,
        state: RuntimeState,
        store: PrivateStoreCorePosition,
        key_epochs: Vec<PrivateKeyEpochCommitment>,
        creation_receipt: AuthorityReceipt,
        genesis_at: u64,
        authority_verifier: &V,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        if descriptor.validate().is_err()
            || descriptor.identity.profile != AgentProfile::Private
            || (require_descriptor_member
                && !descriptor
                    .replicas
                    .iter()
                    .any(|replica| replica.node == node))
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        let managed = managed_target_for_descriptor(descriptor);
        verify_creation_receipt(
            descriptor,
            &creation_receipt,
            genesis_at,
            authority_verifier,
        )?;
        validate_genesis_store_binding(descriptor, store, &key_epochs)?;
        let active_resource_policy = descriptor.initial_resource_policy();
        let stable_projection = PrivateRuntimeStableProjection::genesis(
            managed,
            descriptor.commitment(),
            descriptor.runtime_package.clone(),
            creation_receipt.commitment(),
            active_resource_policy,
            &state.control,
        )?;
        let value = Self {
            managed,
            node,
            owner: descriptor.identity.owner,
            descriptor: descriptor.commitment(),
            runtime_package: descriptor.runtime_package.clone(),
            creation_receipt,
            created_at: genesis_at,
            establishment_origin,
            establishment_completion: None,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state,
            active_resource_policy,
            active_resource_policy_commitment: resource_policy_commitment(active_resource_policy)?,
            store,
            key_epochs,
            runtime_control: None,
            last_full_replay: None,
            stable_projection,
            applied_at: genesis_at,
        };
        value.validate()?;
        if value.state.is_empty()
            || value.state.encoded_len().is_none_or(|length| {
                length > active_resource_policy.max_runtime_state_bytes as usize
            })
        {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        Ok(value)
    }

    /// Rebind an unchanged runtime image to an exact Store position after a
    /// ciphertext-object insertion. Control, PKEY, and runtime projections
    /// must remain byte-for-byte identical; this cannot advance PCTL state.
    pub(crate) fn rebind_store_objects(
        &self,
        store: PrivateStoreCorePosition,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        self.validate()?;
        store.validate()?;
        if store.space != self.store.space
            || store.agent != self.store.agent
            || store.owner != self.store.owner
            || store.epoch != self.store.epoch
            || store.control_head != self.store.control_head
            || store.next_sequence != self.store.next_sequence
            || store.control_count != self.store.control_count
            || store.control_root != self.store.control_root
            || store.key_epoch_root != self.store.key_epoch_root
            || store.object_count < self.store.object_count
            || (store.object_count == self.store.object_count
                && store.object_root != self.store.object_root)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidStorePosition);
        }
        let mut value = self.clone();
        value.store = store;
        value.validate()?;
        Ok(value)
    }

    /// Match a completed PAPL successor after later ciphertext-only Store
    /// inserts. Reconstructing the exact pre-insert PVRI before comparing its
    /// commitment ensures object growth cannot hide a changed runtime state,
    /// projection, control position, or PKEY lineage.
    pub(crate) fn matches_application_successor_after_object_growth(
        &self,
        application: &PrivateRuntimeApplication,
    ) -> bool {
        if application.matches_successor(self) {
            return true;
        }
        let expected = application.expected_successor_store;
        if self.validate().is_err()
            || expected.validate().is_err()
            || self.store.space != expected.space
            || self.store.agent != expected.agent
            || self.store.owner != expected.owner
            || self.store.epoch != expected.epoch
            || self.store.control_head != expected.control_head
            || self.store.next_sequence != expected.next_sequence
            || self.store.control_count != expected.control_count
            || self.store.control_root != expected.control_root
            || self.store.key_epoch_root != expected.key_epoch_root
            || self.store.object_count <= expected.object_count
        {
            return false;
        }
        let mut exact_successor = self.clone();
        exact_successor.store = expected;
        exact_successor.validate().is_ok() && application.matches_successor(&exact_successor)
    }

    /// Test-only bridge for legacy host helpers which historically appended
    /// control-only PCTLs without an authority-operation/PAPL envelope.
    /// Production callers cannot construct runtime evidence through this
    /// seam; physical application must use [`PrivateRuntimeApplication`].
    #[cfg(test)]
    pub(crate) fn synthetic_control_only_successor_for_host_test(
        predecessor: &Self,
        control: &PrivateControlRecord,
        store: PrivateStoreCorePosition,
        key_epochs: Vec<PrivateKeyEpochCommitment>,
        applied_at: u64,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        predecessor.validate()?;
        if !store_transition_matches(predecessor.store, store, control) {
            return Err(PrivateRuntimeEvidenceError::InvalidStorePosition);
        }
        validate_key_epoch_transition(&predecessor.key_epochs, &key_epochs, control)?;
        let full_replay = Hash::digest(
            b"vos/test/private-host-synthetic-control-replay/v1",
            &[
                predecessor.commitment().as_bytes(),
                control.commitment().as_bytes(),
            ],
        );
        let stable_projection = PrivateRuntimeStableProjection::successor(
            &predecessor.stable_projection,
            control,
            full_replay,
            &PrivateRuntimeSuccess::ControlOnly,
            predecessor.active_resource_policy,
            &predecessor.state.control,
        )?;
        let value = Self {
            managed: predecessor.managed,
            node: predecessor.node,
            owner: predecessor.owner,
            descriptor: predecessor.descriptor,
            runtime_package: predecessor.runtime_package.clone(),
            creation_receipt: predecessor.creation_receipt.clone(),
            created_at: predecessor.created_at,
            establishment_origin: predecessor.establishment_origin,
            establishment_completion: predecessor.establishment_completion,
            runtime_deployment: predecessor.runtime_deployment,
            state: predecessor.state.clone(),
            active_resource_policy: predecessor.active_resource_policy,
            active_resource_policy_commitment: predecessor.active_resource_policy_commitment,
            store,
            key_epochs,
            runtime_control: predecessor.runtime_control,
            last_full_replay: Some(full_replay),
            stable_projection,
            applied_at,
        };
        value.validate()?;
        Ok(value)
    }

    /// Hostile-test constructor for an independently authenticated PVRI whose
    /// embedded PSC is structurally valid but not the source Store's exact
    /// authenticated position.
    #[cfg(test)]
    pub(crate) fn synthetic_store_substitution_for_host_test(
        &self,
        store: PrivateStoreCorePosition,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        self.validate()?;
        store.validate()?;
        let mut value = self.clone();
        value.store = store;
        value.validate()?;
        Ok(value)
    }

    /// Hostile-test bridge for proving that node-local establishment metadata
    /// cannot be dropped or substituted across durable reconciliation.
    #[cfg(test)]
    pub(crate) fn synthetic_establishment_completion_for_host_test(
        &self,
        completion: Option<Hash>,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        let mut value = self.clone();
        value.establishment_completion = completion;
        value.validate()?;
        Ok(value)
    }

    /// Build the successor image selected by a pending PAPL1 and positive
    /// disposition. Completion is a separate step because PAPL1 records the
    /// resulting image commitment while PVRI3 never points back to PAPL1.
    #[allow(clippy::too_many_arguments)]
    pub fn successor<V: AuthorityVerifier, R: PrivateRecoveryAuthorityProofVerifier>(
        descriptor: &AgentDescriptor,
        predecessor: &Self,
        application: &PrivateRuntimeApplication,
        success: &PrivateRuntimeSuccess,
        state: RuntimeState,
        key_epochs: Vec<PrivateKeyEpochCommitment>,
        authority_verifier: &V,
        recovery_verifier: &R,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        predecessor.validate()?;
        predecessor.reopen_with(descriptor, authority_verifier)?;
        application.verify_with(descriptor, authority_verifier, recovery_verifier)?;
        if application.completion.is_some()
            || !application.matches_predecessor(predecessor)
            || !application.success_matches(success)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidApplication);
        }
        let active_resource_policy = application.expected_active_policy(success)?;
        validate_key_epoch_transition(&predecessor.key_epochs, &key_epochs, &application.control)?;
        if !private_state_transition_matches(
            &predecessor.state,
            &state,
            application.mutation.is_some(),
        ) {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        let stable_projection = PrivateRuntimeStableProjection::successor(
            &predecessor.stable_projection,
            &application.control,
            application.full_replay,
            success,
            active_resource_policy,
            &state.control,
        )?;
        let runtime_control = if application.mutation.is_some() {
            Some(PrivateRuntimeControlPosition {
                control: application.control.commitment(),
                sequence: application.control.sequence,
            })
        } else {
            predecessor.runtime_control
        };
        let value = Self {
            managed: predecessor.managed,
            node: predecessor.node,
            owner: predecessor.owner,
            descriptor: predecessor.descriptor,
            runtime_package: predecessor.runtime_package.clone(),
            creation_receipt: predecessor.creation_receipt.clone(),
            created_at: predecessor.created_at,
            establishment_origin: predecessor.establishment_origin,
            establishment_completion: predecessor.establishment_completion,
            runtime_deployment: predecessor.runtime_deployment,
            state,
            active_resource_policy,
            active_resource_policy_commitment: resource_policy_commitment(active_resource_policy)?,
            store: application.expected_successor_store,
            key_epochs,
            runtime_control,
            last_full_replay: Some(application.full_replay),
            stable_projection,
            applied_at: application.applied_at,
        };
        value.validate()?;
        if value
            .state
            .encoded_len()
            .is_none_or(|length| length > active_resource_policy.max_runtime_state_bytes as usize)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        Ok(value)
    }

    pub const fn managed(&self) -> ManagedAgentTarget {
        self.managed
    }
    pub const fn node(&self) -> NodeId {
        self.node
    }
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    pub const fn descriptor(&self) -> Hash {
        self.descriptor
    }
    pub fn runtime_package(&self) -> &BlobRef {
        &self.runtime_package
    }
    pub const fn creation_receipt(&self) -> &AuthorityReceipt {
        &self.creation_receipt
    }
    /// Canonical creation slot, exactly the retained receipt's `valid_from`.
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
    /// Immutable destination-local commitment to the authenticated source
    /// capsule used for replica establishment. Ordinary local Create is None.
    pub const fn establishment_origin(&self) -> Option<Hash> {
        self.establishment_origin
    }

    /// Destination-local completion seal set only after the exact source
    /// Store target has been reconstructed. Ordinary local Create and an
    /// unpublished establishment prefix are None.
    pub const fn establishment_completion(&self) -> Option<Hash> {
        self.establishment_completion
    }

    /// Seal an in-progress replica image only at the exact authenticated
    /// source target. The node-local tag is excluded from PAPL lineage but is
    /// included in the full canonical-wire/storage commitment and preserved
    /// by every ordinary successor and object rebind.
    pub(super) fn seal_replica_establishment(
        &self,
        establishment_identity: Hash,
        final_store: PrivateStoreCorePosition,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        self.validate()?;
        final_store.validate()?;
        if self.store != final_store || self.establishment_origin != Some(establishment_identity) {
            return Err(PrivateRuntimeEvidenceError::InvalidStorePosition);
        }
        let sealed = Self::replica_establishment_seal(
            establishment_identity,
            final_store.commitment(),
            self.lineage_commitment(),
        )?;
        match self.establishment_completion {
            Some(current) if current == sealed => Ok(self.clone()),
            None => {
                let mut value = self.clone();
                value.establishment_completion = Some(sealed);
                value.validate()?;
                Ok(value)
            }
            _ => Err(PrivateRuntimeEvidenceError::InvalidState),
        }
    }

    pub(super) fn replica_establishment_seal(
        establishment_identity: Hash,
        final_store: Hash,
        final_lineage: Hash,
    ) -> Result<Hash, PrivateRuntimeEvidenceError> {
        if establishment_identity == Hash::ZERO
            || final_store == Hash::ZERO
            || final_lineage == Hash::ZERO
        {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        let sealed = Hash::digest(
            PRIVATE_RUNTIME_ESTABLISHMENT_SEAL_DOMAIN,
            &[
                establishment_identity.as_bytes(),
                final_store.as_bytes(),
                final_lineage.as_bytes(),
            ],
        );
        if sealed == Hash::ZERO || sealed == establishment_identity {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        Ok(sealed)
    }
    pub const fn runtime_deployment(&self) -> DeploymentId {
        self.runtime_deployment
    }
    pub fn state(&self) -> &RuntimeState {
        &self.state
    }

    /// Extract only full dispatch identities from the already-authenticated
    /// PVRI state. This does not expose plaintext actor metadata or provide an
    /// invocation path; the supervisor's Private adapter remains not-ready
    /// until a ciphertext execution backend exists.
    pub(super) fn supervisor_actor_routes(
        &self,
        descriptor: &AgentDescriptor,
    ) -> Result<Vec<PrivateRuntimeActorRoute>, PrivateRuntimeEvidenceError> {
        self.validate()?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != AgentProfile::Private
            || descriptor.commitment() != self.descriptor
            || descriptor.identity.runtime_deployment != self.runtime_deployment
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        let state = super::wire::decode_clean_standard_runtime_state(&self.state)
            .map_err(|_| PrivateRuntimeEvidenceError::InvalidState)?;
        if state.clean_descriptor.as_ref() != Some(descriptor)
            || state.actors.len() > descriptor.capabilities.max_actors as usize
            || state
                .actors
                .windows(2)
                .any(|pair| pair[0].record.entry.actor >= pair[1].record.entry.actor)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        let mut routes = Vec::with_capacity(state.actors.len());
        for actor in state.actors {
            let entry = actor.record.entry;
            let route = PrivateRuntimeActorRoute {
                actor: ActorId(entry.actor.0),
                incarnation: Hash(actor.record.state_generation.0),
                deployment: DeploymentId(entry.deployment.0),
                program: ProgramId(entry.program.0),
                suspended: entry.suspended,
            };
            if route.actor == ActorId::ZERO
                || route.incarnation == Hash::ZERO
                || route.deployment == DeploymentId::ZERO
                || route.program == ProgramId::ZERO
            {
                return Err(PrivateRuntimeEvidenceError::InvalidState);
            }
            routes.push(route);
        }
        Ok(routes)
    }
    pub const fn active_resource_policy(&self) -> RuntimeResourcePolicy {
        self.active_resource_policy
    }
    pub const fn active_resource_policy_commitment(&self) -> Hash {
        self.active_resource_policy_commitment
    }
    pub const fn store(&self) -> PrivateStoreCorePosition {
        self.store
    }
    pub fn key_epochs(&self) -> &[PrivateKeyEpochCommitment] {
        &self.key_epochs
    }
    pub const fn runtime_control(&self) -> Option<PrivateRuntimeControlPosition> {
        self.runtime_control
    }
    pub const fn last_full_replay(&self) -> Option<Hash> {
        self.last_full_replay
    }
    pub const fn stable_projection(&self) -> &PrivateRuntimeStableProjection {
        &self.stable_projection
    }
    pub const fn applied_at(&self) -> u64 {
        self.applied_at
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            PRIVATE_RUNTIME_IMAGE_COMMITMENT_DOMAIN,
            &[&self.encode().expect("valid PVR3")],
        )
    }

    /// PAPL-facing PVRI identity. The establishment completion tag is
    /// deliberately normalized away: it is node-local publication metadata,
    /// not a runtime state transition. Every other canonical PVRI field,
    /// including the immutable establishment origin, remains bound.
    pub fn lineage_commitment(&self) -> Hash {
        let mut lineage = self.clone();
        lineage.establishment_completion = None;
        Hash::digest(
            PRIVATE_RUNTIME_IMAGE_COMMITMENT_DOMAIN,
            &[&lineage.encode().expect("valid PVR3")],
        )
    }

    /// Reauthenticate the encrypted node-local image against the independently
    /// selected immutable descriptor. Shape validation alone never treats the
    /// receipt embedded in PVRI as its own trust root.
    pub fn reopen_with<V: AuthorityVerifier>(
        &self,
        descriptor: &AgentDescriptor,
        authority_verifier: &V,
    ) -> Result<(), PrivateRuntimeEvidenceError> {
        self.validate()?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != AgentProfile::Private
            || descriptor.commitment() != self.descriptor
            || managed_target_for_descriptor(descriptor) != self.managed
            || descriptor.identity.owner != self.owner
            || descriptor.identity.runtime_deployment != self.runtime_deployment
            || descriptor.runtime_package != self.runtime_package
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        verify_creation_receipt(
            descriptor,
            &self.creation_receipt,
            self.created_at,
            authority_verifier,
        )
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        self.store.validate()?;
        validate_key_epochs(&self.key_epochs)?;
        self.stable_projection.validate()?;
        if !self.managed.is_valid()
            || self.managed.profile != AgentProfile::Private
            || self.node == NodeId::ZERO
            || self.owner == PrincipalId::ZERO
            || self.descriptor == Hash::ZERO
            || !valid_runtime_package(&self.runtime_package)
            || !creation_receipt_matches_image(
                self.managed,
                &self.creation_receipt,
                self.created_at,
            )
            || !nonzero_option(self.establishment_origin)
            || !nonzero_option(self.establishment_completion)
            || (self.establishment_completion.is_some() && self.establishment_origin.is_none())
            || self.runtime_deployment == DeploymentId::ZERO
            || self.managed.runtime_deployment != self.runtime_deployment
            || self.managed.owner != self.owner
            || self.store.space != self.managed.space
            || self.store.agent != self.managed.agent
            || self.store.owner != self.owner
            || !self.state.validate()
            || self.state.is_empty()
            || !self.state.linear.is_empty()
            || !self.active_resource_policy.is_valid()
            || resource_policy_commitment(self.active_resource_policy)?
                != self.active_resource_policy_commitment
            || self.stable_projection.active_resource_policy != self.active_resource_policy
            || self.stable_projection.active_resource_policy_commitment
                != self.active_resource_policy_commitment
            || self.stable_projection.managed != self.managed
            || self.stable_projection.descriptor != self.descriptor
            || self.stable_projection.runtime_package != self.runtime_package
            || self.stable_projection.creation_receipt != self.creation_receipt.commitment()
            || self.stable_projection.control_state != control_state_commitment(&self.state.control)
            || private_key_epoch_root(&self.key_epochs)? != self.store.key_epoch_root
            || self.key_epochs.last().map(|value| value.epoch) != Some(self.store.epoch)
            || !nonzero_option(self.last_full_replay)
            || self.stable_projection.full_replay != self.last_full_replay
            || self.stable_projection.generation != u64::from(self.store.control_count)
            || self.stable_projection.control_head != self.store.control_head
            || self.stable_projection.control_sequence
                != self
                    .store
                    .control_head
                    .map(|_| self.store.next_sequence - 1)
            || self
                .runtime_control
                .is_some_and(|position| !position.validate())
            || self.runtime_control.is_some_and(|position| {
                self.stable_projection
                    .control_sequence
                    .is_none_or(|sequence| position.sequence > sequence)
            })
            || self.state.encoded_len().is_none_or(|length| {
                length > self.active_resource_policy.max_runtime_state_bytes as usize
            })
            || self.created_at > self.applied_at
        {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        Ok(())
    }
}

impl CanonicalWire for PrivateRuntimeImage {
    const MAGIC: [u8; 4] = *b"PVR3";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_managed(encoder, self.managed);
        encoder.fixed(self.node.as_bytes());
        encoder.fixed(self.owner.as_bytes());
        encoder.fixed(self.descriptor.as_bytes());
        encode_blob(encoder, &self.runtime_package);
        encode_nested(encoder, &self.creation_receipt);
        encoder.u64(self.created_at);
        encode_optional_hash(encoder, self.establishment_origin);
        encode_optional_hash(encoder, self.establishment_completion);
        encoder.fixed(self.runtime_deployment.as_bytes());
        encode_runtime_state(encoder, &self.state);
        encode_nested(encoder, &self.active_resource_policy);
        encoder.fixed(self.active_resource_policy_commitment.as_bytes());
        encode_nested(encoder, &self.store);
        encoder.list(&self.key_epochs, encode_nested);
        encoder.option(&self.runtime_control, |encoder, value| {
            encoder.fixed(value.control.as_bytes());
            encoder.u64(value.sequence);
        });
        encode_optional_hash(encoder, self.last_full_replay);
        encode_nested(encoder, &self.stable_projection);
        encoder.u64(self.applied_at);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            managed: decode_managed(decoder)?,
            node: NodeId(decoder.fixed()?),
            owner: PrincipalId(decoder.fixed()?),
            descriptor: Hash(decoder.fixed()?),
            runtime_package: decode_blob(decoder)?,
            creation_receipt: decode_nested(decoder, MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?,
            created_at: decoder.u64()?,
            establishment_origin: decode_optional_hash(decoder)?,
            establishment_completion: decode_optional_hash(decoder)?,
            runtime_deployment: DeploymentId(decoder.fixed()?),
            state: decode_runtime_state(decoder)?,
            active_resource_policy: decode_nested(
                decoder,
                vos_agent_sdk::wire::MAX_RUNTIME_RESOURCE_POLICY_WIRE_BYTES,
            )?,
            active_resource_policy_commitment: Hash(decoder.fixed()?),
            store: decode_nested(decoder, PrivateStoreCorePosition::MAX_ENCODED_BYTES)?,
            key_epochs: decoder.list_bounded(MAX_PRIVATE_RUNTIME_KEY_EPOCHS, |decoder| {
                decode_nested(decoder, PrivateKeyEpochCommitment::MAX_ENCODED_BYTES)
            })?,
            runtime_control: decoder.option(|decoder| {
                let value = PrivateRuntimeControlPosition {
                    control: Hash(decoder.fixed()?),
                    sequence: decoder.u64()?,
                };
                value
                    .validate()
                    .then_some(value)
                    .ok_or(DecodeError::NonCanonical)
            })?,
            last_full_replay: decode_optional_hash(decoder)?,
            stable_projection: decode_nested(
                decoder,
                PrivateRuntimeStableProjection::MAX_ENCODED_BYTES,
            )?,
            applied_at: decoder.u64()?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

fn control_operation_kind(control: &PrivateControlRecord) -> AuthorityOperationKind {
    match control.operation {
        PrivateControlOperation::Invite { .. } => AuthorityOperationKind::InvitePrivateNode,
        PrivateControlOperation::Revoke { .. } => AuthorityOperationKind::RevokePrivateNode,
        PrivateControlOperation::RotateKeys { .. } => AuthorityOperationKind::RotatePrivateKeys,
        PrivateControlOperation::SetResourcePolicy { .. } => {
            AuthorityOperationKind::SetPrivateResourcePolicy
        }
        PrivateControlOperation::ActorLifecycle { .. } => {
            AuthorityOperationKind::PrivateActorLifecycle
        }
        PrivateControlOperation::Recover { .. } => AuthorityOperationKind::RecoverPrivateAgent,
    }
}

fn full_application_replay(
    control: &PrivateControlRecord,
    mutation: Option<&PrivateRuntimeMutation>,
    recovery_authority_proof: Option<&PrivateRecoveryAuthorityProof>,
) -> Result<Hash, PrivateRuntimeEvidenceError> {
    if !control.validate_shape() {
        return Err(PrivateRuntimeEvidenceError::InvalidControl);
    }
    match (&control.operation, mutation) {
        (
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. },
            Some(mutation),
        ) if recovery_authority_proof.is_none() => {
            let request = ManagementRequest::PrivateControl {
                control: Box::new(control.clone()),
                mutation: Box::new(mutation.clone()),
            };
            if !request.is_valid() {
                return Err(PrivateRuntimeEvidenceError::InvalidControl);
            }
            let commitment = request.replay_commitment();
            if commitment == Hash::ZERO {
                return Err(PrivateRuntimeEvidenceError::InvalidControl);
            }
            Ok(commitment)
        }
        (
            PrivateControlOperation::Invite { .. }
            | PrivateControlOperation::Revoke { .. }
            | PrivateControlOperation::RotateKeys { .. },
            None,
        ) if recovery_authority_proof.is_none() => {
            let wire = control
                .encode()
                .map_err(|_| PrivateRuntimeEvidenceError::InvalidControl)?;
            Ok(Hash::digest(
                PRIVATE_CONTROL_ONLY_REPLAY_DOMAIN,
                &[RUNTIME_ABI_ID.as_bytes(), &wire],
            ))
        }
        (PrivateControlOperation::Recover { .. }, None) => {
            let proof =
                recovery_authority_proof.ok_or(PrivateRuntimeEvidenceError::InvalidControl)?;
            if proof.validate_shape().is_err() || !proof.matches_control(control) {
                return Err(PrivateRuntimeEvidenceError::InvalidControl);
            }
            let control_wire = control
                .encode()
                .map_err(|_| PrivateRuntimeEvidenceError::InvalidControl)?;
            let proof_wire = proof
                .encode()
                .map_err(|_| PrivateRuntimeEvidenceError::InvalidControl)?;
            Ok(Hash::digest(
                PRIVATE_CONTROL_ONLY_REPLAY_DOMAIN,
                &[RUNTIME_ABI_ID.as_bytes(), &control_wire, &proof_wire],
            ))
        }
        _ => Err(PrivateRuntimeEvidenceError::InvalidControl),
    }
}

fn authority_matches_application(
    managed: ManagedAgentTarget,
    control: &PrivateControlRecord,
    recovery_authority_proof: Option<&PrivateRecoveryAuthorityProof>,
    receipt: &AuthorityReceipt,
    issuance: &AuthorityOperationIssuanceAck,
    applied_at: u64,
) -> bool {
    let selector = &receipt.selector;
    let expected_actor = match control.operation {
        PrivateControlOperation::ActorLifecycle { actor, .. } => Some(actor),
        _ => None,
    };
    let request_matches = match (&control.operation, recovery_authority_proof) {
        (PrivateControlOperation::Recover { .. }, Some(proof)) => {
            proof.validate_shape().is_ok()
                && proof.managed == managed
                && proof.matches_control(control)
                && selector.request == proof.commitment()
        }
        (PrivateControlOperation::Recover { .. }, None) => false,
        (_, None) => selector.request == control.commitment(),
        (_, Some(_)) => false,
    };
    receipt.validate_shape().is_ok()
        && issuance.validate_shape().is_ok()
        && issuance.receipt == *receipt
        && issuance.authority.space == managed.space
        && selector.space == managed.space
        && selector.agent == managed.agent
        && selector.runtime_deployment == managed.runtime_deployment
        && selector.operation == control_operation_kind(control)
        && selector.actor == expected_actor
        && selector.actor_deployment.is_none()
        && !selector.operation.uses_management_decision_journal()
        && selector.decision_sequence == 0
        && selector.acknowledged_through == 0
        && request_matches
        && issuance.issued_at <= applied_at
        && selector.is_live_at(applied_at)
}

fn store_matches_projection(
    store: PrivateStoreCorePosition,
    projection: &PrivateRuntimeStableProjection,
) -> bool {
    projection.generation == u64::from(store.control_count)
        && projection.control_head == store.control_head
        && projection.control_sequence == store.control_head.map(|_| store.next_sequence - 1)
}

fn store_transition_matches(
    predecessor: PrivateStoreCorePosition,
    successor: PrivateStoreCorePosition,
    control: &PrivateControlRecord,
) -> bool {
    if predecessor.validate().is_err()
        || successor.validate().is_err()
        || predecessor.space != successor.space
        || predecessor.agent != successor.agent
        || predecessor.owner != successor.owner
        || control.space != predecessor.space
        || control.agent != predecessor.agent
        || successor.object_count != predecessor.object_count
        || successor.object_root != predecessor.object_root
        || successor.control_count != predecessor.control_count.checked_add(1).unwrap_or(u32::MAX)
        || successor.control_head != Some(control.commitment())
        || successor.next_sequence != control.sequence.checked_add(1).unwrap_or(0)
        || successor.control_root == predecessor.control_root
    {
        return false;
    }
    let position_matches = match &control.operation {
        PrivateControlOperation::Recover {
            superseded_heads, ..
        } => {
            control.sequence >= predecessor.next_sequence
                && match (predecessor.control_head, control.previous) {
                    (Some(local), Some(selected)) => {
                        superseded_heads.binary_search(&local).is_ok()
                            && superseded_heads.binary_search(&selected).is_ok()
                    }
                    (None, None) => superseded_heads.is_empty(),
                    _ => false,
                }
        }
        _ => {
            control.sequence == predecessor.next_sequence
                && control.previous == predecessor.control_head
        }
    };
    let expected_epoch = match &control.operation {
        PrivateControlOperation::Invite { epoch, .. } if *epoch == predecessor.epoch => *epoch,
        PrivateControlOperation::Revoke { next_epoch, .. }
        | PrivateControlOperation::RotateKeys { next_epoch }
            if predecessor.epoch.checked_add(1) == Some(next_epoch.epoch) =>
        {
            next_epoch.epoch
        }
        PrivateControlOperation::Recover { next_epoch, .. }
            if next_epoch.epoch > predecessor.epoch =>
        {
            next_epoch.epoch
        }
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => predecessor.epoch,
        _ => return false,
    };
    let key_root_changes = matches!(
        control.operation,
        PrivateControlOperation::Invite { .. }
            | PrivateControlOperation::Revoke { .. }
            | PrivateControlOperation::RotateKeys { .. }
            | PrivateControlOperation::Recover { .. }
    );
    position_matches
        && successor.epoch == expected_epoch
        && ((key_root_changes && successor.key_epoch_root != predecessor.key_epoch_root)
            || (!key_root_changes && successor.key_epoch_root == predecessor.key_epoch_root))
}

fn validate_key_epoch_transition(
    predecessor: &[PrivateKeyEpochCommitment],
    successor: &[PrivateKeyEpochCommitment],
    control: &PrivateControlRecord,
) -> Result<(), PrivateRuntimeEvidenceError> {
    validate_key_epochs(predecessor)?;
    validate_key_epochs(successor)?;
    let valid = match &control.operation {
        PrivateControlOperation::Invite { epoch, .. } => {
            predecessor.len() == successor.len()
                && predecessor[..predecessor.len() - 1] == successor[..successor.len() - 1]
                && predecessor
                    .last()
                    .is_some_and(|value| value.epoch == *epoch)
                && successor.last().is_some_and(|value| {
                    value.epoch == *epoch
                        && Some(value.exact_wire)
                            != predecessor.last().map(|prior| prior.exact_wire)
                })
        }
        PrivateControlOperation::Revoke { next_epoch, .. }
        | PrivateControlOperation::RotateKeys { next_epoch }
        | PrivateControlOperation::Recover { next_epoch, .. } => {
            successor.len() == predecessor.len() + 1
                && successor[..predecessor.len()] == *predecessor
                && PrivateKeyEpochCommitment::from_epoch(next_epoch)
                    .is_ok_and(|expected| successor.last() == Some(&expected))
        }
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => predecessor == successor,
    };
    if !valid {
        return Err(PrivateRuntimeEvidenceError::InvalidKeyEpochs);
    }
    Ok(())
}

fn private_state_transition_matches(
    predecessor: &RuntimeState,
    successor: &RuntimeState,
    runtime_control: bool,
) -> bool {
    successor.linear.is_empty()
        && if runtime_control {
            successor.merge == predecessor.merge && successor.local == predecessor.local
        } else {
            successor == predecessor
        }
}

fn success_is_private(success: &PrivateRuntimeSuccess) -> bool {
    match success {
        PrivateRuntimeSuccess::Installed(entry)
        | PrivateRuntimeSuccess::Upgraded(entry)
        | PrivateRuntimeSuccess::Suspended(entry)
        | PrivateRuntimeSuccess::Resumed(entry) => {
            entry.validate_for_profile(AgentProfile::Private).is_ok()
        }
        PrivateRuntimeSuccess::ControlOnly
        | PrivateRuntimeSuccess::ResourcePolicySet(_)
        | PrivateRuntimeSuccess::Removed(_) => true,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateRuntimeApplicationCompletion {
    success: PrivateRuntimeSuccess,
    stable_projection: PrivateRuntimeStableProjection,
    successor_runtime_image: Hash,
}

/// Exact pending or completed application of one PCTL (`PAPL1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRuntimeApplication {
    managed: ManagedAgentTarget,
    node: NodeId,
    descriptor: Hash,
    runtime_package: BlobRef,
    control: PrivateControlRecord,
    mutation: Option<PrivateRuntimeMutation>,
    recovery_authority_proof: Option<PrivateRecoveryAuthorityProof>,
    full_replay: Hash,
    receipt: AuthorityReceipt,
    issuance: AuthorityOperationIssuanceAck,
    applied_at: u64,
    predecessor_store: PrivateStoreCorePosition,
    predecessor_runtime_image: Hash,
    predecessor_stable_projection: PrivateRuntimeStableProjection,
    predecessor_runtime_control: Option<PrivateRuntimeControlPosition>,
    expected_successor_store: PrivateStoreCorePosition,
    completion: Option<PrivateRuntimeApplicationCompletion>,
}

impl PrivateRuntimeApplication {
    /// Construct persistence-ready pending evidence only after authenticating
    /// its descriptor authority and (for Recover) immutable recovery key.
    /// The predecessor must already have been opened from a Store/PKEY set
    /// which authorizes its local Node; see [`Self::verify_with`].
    #[allow(clippy::too_many_arguments)]
    pub fn pending<V: AuthorityVerifier, R: PrivateRecoveryAuthorityProofVerifier>(
        descriptor: &AgentDescriptor,
        predecessor: &PrivateRuntimeImage,
        control: PrivateControlRecord,
        mutation: Option<PrivateRuntimeMutation>,
        recovery_authority_proof: Option<PrivateRecoveryAuthorityProof>,
        receipt: AuthorityReceipt,
        issuance: AuthorityOperationIssuanceAck,
        applied_at: u64,
        expected_successor_store: PrivateStoreCorePosition,
        authority_verifier: &V,
        recovery_verifier: &R,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        predecessor.reopen_with(descriptor, authority_verifier)?;
        let value = Self::pending_unverified(
            predecessor,
            control,
            mutation,
            recovery_authority_proof,
            receipt,
            issuance,
            applied_at,
            expected_successor_store,
        )?;
        value.verify_with(descriptor, authority_verifier, recovery_verifier)?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn pending_unverified(
        predecessor: &PrivateRuntimeImage,
        control: PrivateControlRecord,
        mutation: Option<PrivateRuntimeMutation>,
        recovery_authority_proof: Option<PrivateRecoveryAuthorityProof>,
        receipt: AuthorityReceipt,
        issuance: AuthorityOperationIssuanceAck,
        applied_at: u64,
        expected_successor_store: PrivateStoreCorePosition,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        predecessor.validate()?;
        let full_replay = full_application_replay(
            &control,
            mutation.as_ref(),
            recovery_authority_proof.as_ref(),
        )?;
        let value = Self {
            managed: predecessor.managed,
            node: predecessor.node,
            descriptor: predecessor.descriptor,
            runtime_package: predecessor.runtime_package.clone(),
            control,
            mutation,
            recovery_authority_proof,
            full_replay,
            receipt,
            issuance,
            applied_at,
            predecessor_store: predecessor.store,
            predecessor_runtime_image: predecessor.lineage_commitment(),
            predecessor_stable_projection: predecessor.stable_projection.clone(),
            predecessor_runtime_control: predecessor.runtime_control,
            expected_successor_store,
            completion: None,
        };
        value.validate()?;
        if !value.matches_predecessor(predecessor) {
            return Err(PrivateRuntimeEvidenceError::InvalidApplication);
        }
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete<V: AuthorityVerifier, R: PrivateRecoveryAuthorityProofVerifier>(
        mut self,
        descriptor: &AgentDescriptor,
        predecessor: &PrivateRuntimeImage,
        successor: &PrivateRuntimeImage,
        success: PrivateRuntimeSuccess,
        authority_verifier: &V,
        recovery_verifier: &R,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        predecessor.reopen_with(descriptor, authority_verifier)?;
        self.verify_with(descriptor, authority_verifier, recovery_verifier)?;
        if self.completion.is_some()
            || !self.matches_predecessor(predecessor)
            || !self.success_matches(&success)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidApplication);
        }
        successor.reopen_with(descriptor, authority_verifier)?;
        validate_key_epoch_transition(
            &predecessor.key_epochs,
            &successor.key_epochs,
            &self.control,
        )?;
        if !private_state_transition_matches(
            &predecessor.state,
            &successor.state,
            self.mutation.is_some(),
        ) {
            return Err(PrivateRuntimeEvidenceError::InvalidState);
        }
        let active_policy = self.expected_active_policy(&success)?;
        if successor.active_resource_policy != active_policy {
            return Err(PrivateRuntimeEvidenceError::InvalidProjection);
        }
        let stable_projection = PrivateRuntimeStableProjection::successor(
            &self.predecessor_stable_projection,
            &self.control,
            self.full_replay,
            &success,
            active_policy,
            &successor.state.control,
        )?;
        self.completion = Some(PrivateRuntimeApplicationCompletion {
            success,
            stable_projection,
            successor_runtime_image: successor.lineage_commitment(),
        });
        self.validate()?;
        if !self.matches_successor(successor) {
            return Err(PrivateRuntimeEvidenceError::InvalidApplication);
        }
        Ok(self)
    }

    pub const fn managed(&self) -> ManagedAgentTarget {
        self.managed
    }
    pub const fn node(&self) -> NodeId {
        self.node
    }
    pub const fn descriptor(&self) -> Hash {
        self.descriptor
    }
    pub fn runtime_package(&self) -> &BlobRef {
        &self.runtime_package
    }
    pub const fn control(&self) -> &PrivateControlRecord {
        &self.control
    }
    pub const fn mutation(&self) -> Option<&PrivateRuntimeMutation> {
        self.mutation.as_ref()
    }
    pub const fn recovery_authority_proof(&self) -> Option<&PrivateRecoveryAuthorityProof> {
        self.recovery_authority_proof.as_ref()
    }
    pub const fn full_replay(&self) -> Hash {
        self.full_replay
    }
    pub const fn receipt(&self) -> &AuthorityReceipt {
        &self.receipt
    }
    pub const fn issuance(&self) -> &AuthorityOperationIssuanceAck {
        &self.issuance
    }
    pub const fn applied_at(&self) -> u64 {
        self.applied_at
    }
    pub const fn predecessor_store(&self) -> PrivateStoreCorePosition {
        self.predecessor_store
    }
    pub const fn predecessor_runtime_image(&self) -> Hash {
        self.predecessor_runtime_image
    }
    pub const fn predecessor_stable_projection(&self) -> &PrivateRuntimeStableProjection {
        &self.predecessor_stable_projection
    }
    pub const fn predecessor_runtime_control(&self) -> Option<PrivateRuntimeControlPosition> {
        self.predecessor_runtime_control
    }
    pub const fn expected_successor_store(&self) -> PrivateStoreCorePosition {
        self.expected_successor_store
    }
    pub const fn is_complete(&self) -> bool {
        self.completion.is_some()
    }
    pub fn success(&self) -> Option<&PrivateRuntimeSuccess> {
        self.completion.as_ref().map(|value| &value.success)
    }
    pub const fn successor_stable_projection(&self) -> Option<&PrivateRuntimeStableProjection> {
        match &self.completion {
            Some(value) => Some(&value.stable_projection),
            None => None,
        }
    }
    pub const fn successor_runtime_image(&self) -> Option<Hash> {
        match &self.completion {
            Some(value) => Some(value.successor_runtime_image),
            None => None,
        }
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            PRIVATE_RUNTIME_APPLICATION_COMMITMENT_DOMAIN,
            &[&self.encode().expect("valid PAP1")],
        )
    }

    pub fn matches_predecessor(&self, predecessor: &PrivateRuntimeImage) -> bool {
        predecessor.validate().is_ok()
            && self.applied_at >= predecessor.applied_at
            && self.managed == predecessor.managed
            && self.node == predecessor.node
            && self.descriptor == predecessor.descriptor
            && self.runtime_package == predecessor.runtime_package
            && self.predecessor_store == predecessor.store
            && self.predecessor_runtime_image == predecessor.lineage_commitment()
            && self.predecessor_stable_projection == predecessor.stable_projection
            && self.predecessor_runtime_control == predecessor.runtime_control
    }

    /// Verify decoded PAPL evidence against the immutable authority selected
    /// by the exact Private descriptor. Shape validation alone deliberately
    /// does not trust the public key carried by the receipt/AOI1.
    ///
    /// `descriptor.replicas` is the genesis roster and is checked only by
    /// [`PrivateRuntimeImage::genesis`]. Invite/Recover can replace that
    /// roster. Before calling this method for a later image, the physical
    /// Store opener must authenticate the local Node against the exact PKEY
    /// preimage committed by the predecessor image. This method then binds
    /// that already-authenticated predecessor by its node-local PVRI identity.
    pub fn verify_with<V: AuthorityVerifier, R: PrivateRecoveryAuthorityProofVerifier>(
        &self,
        descriptor: &AgentDescriptor,
        authority_verifier: &V,
        recovery_verifier: &R,
    ) -> Result<(), PrivateRuntimeEvidenceError> {
        self.validate()?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != AgentProfile::Private
            || descriptor.commitment() != self.descriptor
            || managed_target_for_descriptor(descriptor) != self.managed
            || descriptor.identity.owner != self.predecessor_store.owner
            || descriptor.runtime_package != self.runtime_package
            || !descriptor.authority.accepts(&self.receipt)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        self.validate_descriptor_scope(descriptor)?;
        self.issuance
            .verify_with(descriptor.authority, authority_verifier)
            .map_err(|_| PrivateRuntimeEvidenceError::InvalidAuthority)?;
        self.receipt
            .verify_at(self.applied_at, authority_verifier)
            .map_err(|_| PrivateRuntimeEvidenceError::InvalidAuthority)?;
        match (&self.control.operation, &self.recovery_authority_proof) {
            (PrivateControlOperation::Recover { .. }, Some(proof)) => {
                let Some(recovery) = descriptor.private_recovery else {
                    return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
                };
                if recovery_signing_public_key_commitment(&proof.recovery_public_key)
                    != recovery.signing_key_commitment
                {
                    return Err(PrivateRuntimeEvidenceError::InvalidAuthority);
                }
                proof
                    .verify_with(recovery_verifier)
                    .map_err(|_| PrivateRuntimeEvidenceError::InvalidAuthority)
            }
            (PrivateControlOperation::Recover { .. }, None) | (_, Some(_)) => {
                Err(PrivateRuntimeEvidenceError::InvalidAuthority)
            }
            (_, None) => Ok(()),
        }
    }

    fn validate_descriptor_scope(
        &self,
        descriptor: &AgentDescriptor,
    ) -> Result<(), PrivateRuntimeEvidenceError> {
        let within_descriptor = |policy: RuntimeResourcePolicy| {
            policy.is_within(
                descriptor.capabilities,
                descriptor.runtime_contract.resources,
            )
        };
        if !within_descriptor(self.predecessor_stable_projection.active_resource_policy)
            || (self.predecessor_stable_projection.generation == 0
                && self.predecessor_stable_projection.active_resource_policy
                    != descriptor.initial_resource_policy())
            || self.completion.as_ref().is_some_and(|completion| {
                !within_descriptor(completion.stable_projection.active_resource_policy)
                    || !success_is_private(&completion.success)
            })
        {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        let mutation_is_supported = match &self.mutation {
            Some(PrivateRuntimeMutation::SetResourcePolicy(policy)) => within_descriptor(*policy),
            Some(PrivateRuntimeMutation::Install(install)) => {
                install.validate_for_profile(AgentProfile::Private).is_ok()
                    && descriptor.runtime_contract.supports(install.contract)
                    && descriptor.capabilities.satisfies(install.requirements)
            }
            Some(PrivateRuntimeMutation::UpgradeActor(upgrade)) => {
                upgrade.requirements.supported_by(AgentProfile::Private)
                    && descriptor.runtime_contract.supports(upgrade.contract)
                    && descriptor.capabilities.satisfies(upgrade.requirements)
            }
            Some(
                PrivateRuntimeMutation::Suspend { .. }
                | PrivateRuntimeMutation::Resume { .. }
                | PrivateRuntimeMutation::RemoveLeaf { .. },
            )
            | None => true,
        };
        if !mutation_is_supported {
            return Err(PrivateRuntimeEvidenceError::InvalidDescriptor);
        }
        Ok(())
    }

    pub fn matches_successor(&self, successor: &PrivateRuntimeImage) -> bool {
        let Some(completion) = &self.completion else {
            return false;
        };
        successor.validate().is_ok()
            && successor.managed == self.managed
            && successor.node == self.node
            && successor.owner == self.predecessor_store.owner
            && successor.descriptor == self.descriptor
            && successor.runtime_package == self.runtime_package
            && successor.runtime_deployment == self.managed.runtime_deployment
            && successor.store == self.expected_successor_store
            && successor.applied_at == self.applied_at
            && successor.last_full_replay == Some(self.full_replay)
            && successor.stable_projection == completion.stable_projection
            && successor.lineage_commitment() == completion.successor_runtime_image
            && successor.runtime_control
                == if self.mutation.is_some() {
                    Some(PrivateRuntimeControlPosition {
                        control: self.control.commitment(),
                        sequence: self.control.sequence,
                    })
                } else {
                    self.predecessor_runtime_control
                }
    }

    fn success_matches(&self, success: &PrivateRuntimeSuccess) -> bool {
        match (&self.mutation, success.management_reply()) {
            (None, None) => matches!(success, PrivateRuntimeSuccess::ControlOnly),
            (Some(mutation), Some(reply)) => {
                let request = ManagementRequest::PrivateControl {
                    control: Box::new(self.control.clone()),
                    mutation: Box::new(mutation.clone()),
                };
                request.is_valid() && request.private_runtime_reply_matches(&reply)
            }
            _ => false,
        }
    }

    fn expected_active_policy(
        &self,
        success: &PrivateRuntimeSuccess,
    ) -> Result<RuntimeResourcePolicy, PrivateRuntimeEvidenceError> {
        if !self.success_matches(success) {
            return Err(PrivateRuntimeEvidenceError::InvalidSuccess);
        }
        match success {
            PrivateRuntimeSuccess::ResourcePolicySet(policy) => Ok(*policy),
            _ => Ok(self.predecessor_stable_projection.active_resource_policy),
        }
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        self.predecessor_store.validate()?;
        self.expected_successor_store.validate()?;
        self.predecessor_stable_projection.validate()?;
        if !self.managed.is_valid()
            || self.managed.profile != AgentProfile::Private
            || self.node == NodeId::ZERO
            || self.control.space != self.managed.space
            || self.control.agent != self.managed.agent
            || self.descriptor == Hash::ZERO
            || !valid_runtime_package(&self.runtime_package)
            || full_application_replay(
                &self.control,
                self.mutation.as_ref(),
                self.recovery_authority_proof.as_ref(),
            )
            .map_or(true, |value| value != self.full_replay)
            || self.full_replay == Hash::ZERO
            || self.predecessor_runtime_image == Hash::ZERO
            || self.predecessor_store.space != self.managed.space
            || self.predecessor_store.agent != self.managed.agent
            || self.expected_successor_store.space != self.managed.space
            || self.expected_successor_store.agent != self.managed.agent
            || self.predecessor_store.owner != self.expected_successor_store.owner
            || self.managed.owner != self.predecessor_store.owner
            || self.predecessor_stable_projection.managed != self.managed
            || self.predecessor_stable_projection.descriptor != self.descriptor
            || self.predecessor_stable_projection.runtime_package != self.runtime_package
            || !store_matches_projection(
                self.predecessor_store,
                &self.predecessor_stable_projection,
            )
            || !store_transition_matches(
                self.predecessor_store,
                self.expected_successor_store,
                &self.control,
            )
        {
            return Err(PrivateRuntimeEvidenceError::InvalidApplication);
        }
        if !authority_matches_application(
            self.managed,
            &self.control,
            self.recovery_authority_proof.as_ref(),
            &self.receipt,
            &self.issuance,
            self.applied_at,
        ) {
            return Err(PrivateRuntimeEvidenceError::InvalidAuthority);
        }
        if let Some(completion) = &self.completion {
            completion.success.validate()?;
            completion.stable_projection.validate()?;
            let active_policy = self.expected_active_policy(&completion.success)?;
            let expected = PrivateRuntimeStableProjection::successor_with_control_commitment(
                &self.predecessor_stable_projection,
                &self.control,
                self.full_replay,
                &completion.success,
                active_policy,
                completion.stable_projection.control_state,
            )?;
            if completion.successor_runtime_image == Hash::ZERO
                || completion.stable_projection != expected
            {
                return Err(PrivateRuntimeEvidenceError::InvalidApplication);
            }
        }
        Ok(())
    }
}

impl CanonicalWire for PrivateRuntimeApplication {
    const MAGIC: [u8; 4] = *b"PAP1";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_managed(encoder, self.managed);
        encoder.fixed(self.node.as_bytes());
        encoder.fixed(self.descriptor.as_bytes());
        encode_blob(encoder, &self.runtime_package);
        encode_nested(encoder, &self.control);
        encoder.option(&self.mutation, encode_nested);
        encoder.option(&self.recovery_authority_proof, encode_nested);
        encoder.fixed(self.full_replay.as_bytes());
        encode_nested(encoder, &self.receipt);
        encode_nested(encoder, &self.issuance);
        encoder.u64(self.applied_at);
        encode_nested(encoder, &self.predecessor_store);
        encoder.fixed(self.predecessor_runtime_image.as_bytes());
        encode_nested(encoder, &self.predecessor_stable_projection);
        encoder.option(&self.predecessor_runtime_control, |encoder, value| {
            encoder.fixed(value.control.as_bytes());
            encoder.u64(value.sequence);
        });
        encode_nested(encoder, &self.expected_successor_store);
        encoder.option(&self.completion, |encoder, value| {
            encode_nested(encoder, &value.success);
            encode_nested(encoder, &value.stable_projection);
            encoder.fixed(value.successor_runtime_image.as_bytes());
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            managed: decode_managed(decoder)?,
            node: NodeId(decoder.fixed()?),
            descriptor: Hash(decoder.fixed()?),
            runtime_package: decode_blob(decoder)?,
            control: decode_nested(decoder, MAX_PRIVATE_CONTROL_WIRE_BYTES)?,
            mutation: decoder.option(|decoder| {
                decode_nested(decoder, MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES)
            })?,
            recovery_authority_proof: decoder.option(|decoder| {
                decode_nested(decoder, MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES)
            })?,
            full_replay: Hash(decoder.fixed()?),
            receipt: decode_nested(decoder, MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?,
            issuance: decode_nested(decoder, MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES)?,
            applied_at: decoder.u64()?,
            predecessor_store: decode_nested(decoder, PrivateStoreCorePosition::MAX_ENCODED_BYTES)?,
            predecessor_runtime_image: Hash(decoder.fixed()?),
            predecessor_stable_projection: decode_nested(
                decoder,
                PrivateRuntimeStableProjection::MAX_ENCODED_BYTES,
            )?,
            predecessor_runtime_control: decoder.option(|decoder| {
                let value = PrivateRuntimeControlPosition {
                    control: Hash(decoder.fixed()?),
                    sequence: decoder.u64()?,
                };
                value
                    .validate()
                    .then_some(value)
                    .ok_or(DecodeError::NonCanonical)
            })?,
            expected_successor_store: decode_nested(
                decoder,
                PrivateStoreCorePosition::MAX_ENCODED_BYTES,
            )?,
            completion: decoder.option(|decoder| {
                Ok(PrivateRuntimeApplicationCompletion {
                    success: decode_nested(decoder, PrivateRuntimeSuccess::MAX_ENCODED_BYTES)?,
                    stable_projection: decode_nested(
                        decoder,
                        PrivateRuntimeStableProjection::MAX_ENCODED_BYTES,
                    )?,
                    successor_runtime_image: {
                        let value = Hash(decoder.fixed()?);
                        if value == Hash::ZERO {
                            return Err(DecodeError::NonCanonical);
                        }
                        value
                    },
                })
            })?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

/// Exact reopened Store/runtime/application aggregate (`PCRS3`).
///
/// A PCRS3 is intentionally unsigned. Its Merkle-style commitment is later
/// bound by PCAF2/PCA2/PSE2 and remains recomputable after the full historical
/// PVRI preimage is retired; callers must still verify those downstream
/// authority signatures independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateControlReopenedState {
    application: PrivateRuntimeApplication,
    store: PrivateStoreCorePosition,
    runtime_image: PrivateRuntimeImage,
}

impl PrivateControlReopenedState {
    pub fn new(
        application: PrivateRuntimeApplication,
        store: PrivateStoreCorePosition,
        runtime_image: PrivateRuntimeImage,
    ) -> Result<Self, PrivateRuntimeEvidenceError> {
        let value = Self {
            application,
            store,
            runtime_image,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn application(&self) -> &PrivateRuntimeApplication {
        &self.application
    }
    pub const fn store(&self) -> PrivateStoreCorePosition {
        self.store
    }
    pub const fn runtime_image(&self) -> &PrivateRuntimeImage {
        &self.runtime_image
    }

    pub fn commitment(&self) -> Hash {
        Self::commitment_from_application(&self.application).expect("valid PCRS3")
    }

    /// Recompute the PCRS3 endpoint retained by PCAF2 using only a completed
    /// PAPL. PAPL already carries the exact successor PSC and PVRI lineage
    /// commitment,
    /// so no historical plaintext runtime image has to remain on disk.
    pub fn commitment_from_application(
        application: &PrivateRuntimeApplication,
    ) -> Result<Hash, PrivateRuntimeEvidenceError> {
        application.validate()?;
        let successor_runtime_image = application
            .successor_runtime_image()
            .ok_or(PrivateRuntimeEvidenceError::InvalidApplication)?;
        let application_commitment = application.commitment();
        let store_commitment = application.expected_successor_store().commitment();
        Ok(Hash::digest(
            PRIVATE_CONTROL_REOPENED_STATE_COMMITMENT_DOMAIN,
            &[
                application_commitment.as_bytes(),
                store_commitment.as_bytes(),
                successor_runtime_image.as_bytes(),
            ],
        ))
    }

    pub fn validate(&self) -> Result<(), PrivateRuntimeEvidenceError> {
        self.application.validate()?;
        self.store.validate()?;
        self.runtime_image.validate()?;
        if !self.application.is_complete()
            || self.store != self.application.expected_successor_store
            || self.store != self.runtime_image.store
            || !self.application.matches_successor(&self.runtime_image)
        {
            return Err(PrivateRuntimeEvidenceError::InvalidApplication);
        }
        Ok(())
    }

    /// Reopen and authenticate the exact transitive evidence against an
    /// independently selected descriptor authority.
    pub fn reopen_with<V: AuthorityVerifier, R: PrivateRecoveryAuthorityProofVerifier>(
        &self,
        descriptor: &AgentDescriptor,
        authority_verifier: &V,
        recovery_verifier: &R,
    ) -> Result<(), PrivateRuntimeEvidenceError> {
        self.validate()?;
        self.application
            .verify_with(descriptor, authority_verifier, recovery_verifier)?;
        self.runtime_image
            .reopen_with(descriptor, authority_verifier)
    }
}

impl CanonicalWire for PrivateControlReopenedState {
    const MAGIC: [u8; 4] = *b"PCR3";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_CONTROL_REOPENED_STATE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_nested(encoder, &self.application);
        encode_nested(encoder, &self.store);
        encode_nested(encoder, &self.runtime_image);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            application: decode_nested(decoder, MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES)?,
            store: decode_nested(decoder, PrivateStoreCorePosition::MAX_ENCODED_BYTES)?,
            runtime_image: decode_nested(decoder, MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES)?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::num::NonZeroU64;

    use vos_agent_sdk::authority::{
        AgentAuthorityBinding, AuthorityActorTarget, AuthorityEvidence, AuthorityIssuer,
        AuthorityLaneRoots, AuthorityReceiptSelector,
    };
    use vos_agent_sdk::authority_operation::PrivateRecoveryAuthorityProofSigner;
    use vos_agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos_agent_sdk::private::{
        EncryptedObjectKind, EncryptedPrivateObject, PrivateControlSigner, PrivateNodeIdentity,
        PrivateRecoveryKeyringGrant, SealedPrivateKey, SealedRecoveryKey,
    };
    use vos_agent_sdk::{
        AgentIdentity, AgentReplica, InstallActor, InstallationId, LaneSet, PrivateRecoveryBinding,
        ProducerId, ProgramId, ReplicaRole, RuntimeCapabilities, RuntimeRequirements, StateLane,
    };

    const RECOVERY_PUBLIC_KEY: [u8; 32] = [0x81; 32];
    const GENESIS_AT: u64 = 1;

    fn hash(marker: u8) -> Hash {
        Hash([marker; 32])
    }

    struct AllowVerifier;

    impl AuthorityVerifier for AllowVerifier {
        fn verify(&self, _public_key: &[u8; 32], _message: &[u8], _signature: &[u8; 64]) -> bool {
            true
        }
    }

    impl PrivateRecoveryAuthorityProofVerifier for AllowVerifier {
        fn verify_private_recovery_authority_proof(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> bool {
            true
        }
    }

    struct DenyVerifier;

    impl AuthorityVerifier for DenyVerifier {
        fn verify(&self, _public_key: &[u8; 32], _message: &[u8], _signature: &[u8; 64]) -> bool {
            false
        }
    }

    impl PrivateRecoveryAuthorityProofVerifier for DenyVerifier {
        fn verify_private_recovery_authority_proof(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> bool {
            false
        }
    }

    struct RecoverySigner([u8; 32]);

    impl PrivateRecoveryAuthorityProofSigner for RecoverySigner {
        fn recovery_public_key(&self) -> [u8; 32] {
            self.0
        }

        fn sign_private_recovery_authority_proof(&self, _message: &[u8]) -> [u8; 64] {
            [0x91; 64]
        }
    }

    #[derive(Clone)]
    struct Fixture {
        descriptor: AgentDescriptor,
        node_a: NodeId,
        node_b: NodeId,
        predecessor: PrivateRuntimeImage,
    }

    impl Fixture {
        fn new() -> Self {
            let space = SpaceId([1; 32]);
            let owner = PrincipalId([2; 32]);
            let creation_nonce = hash(3);
            let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
            let node_a = NodeId([4; 32]);
            let node_b = NodeId([5; 32]);
            let authority_public_key = [6; 32];
            let authority_issuer = AuthorityIssuer {
                principal: PrincipalId([7; 32]),
                actor: ActorId([8; 32]),
                deployment: DeploymentId([9; 32]),
                program: ProgramId([10; 32]),
                producer: ProducerId::of_public_key(&authority_public_key),
            };
            let authority = AgentAuthorityBinding {
                policy: hash(11),
                issuer: authority_issuer,
                public_key: authority_public_key,
                initial_epoch: 1,
            };
            let runtime_package = BlobRef::of_bytes(b"private-runtime-package");
            let descriptor = AgentDescriptor {
                identity: AgentIdentity {
                    space,
                    agent,
                    owner,
                    profile: AgentProfile::Private,
                    runtime_deployment: DeploymentId([12; 32]),
                    runtime_program: ProgramId([13; 32]),
                    runtime_producer: ProducerId([14; 32]),
                    transition_producer: ProducerId([15; 32]),
                },
                creation_nonce,
                authority,
                private_recovery: Some(PrivateRecoveryBinding {
                    signing_key_commitment: recovery_signing_public_key_commitment(
                        &RECOVERY_PUBLIC_KEY,
                    ),
                    encryption_public_key: [16; 32],
                }),
                runtime_package,
                runtime_contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                replicas: vec![
                    AgentReplica {
                        node: node_a,
                        principal: owner,
                        role: ReplicaRole::Observer,
                    },
                    AgentReplica {
                        node: node_b,
                        principal: owner,
                        role: ReplicaRole::Observer,
                    },
                ],
            };
            descriptor.validate().unwrap();
            let creation_receipt = Self::creation_receipt_for(&descriptor);
            let genesis_epoch = key_epoch(space, agent, 0, node_a, 20);
            let epoch_commitment = PrivateKeyEpochCommitment::from_epoch(&genesis_epoch).unwrap();
            let key_epochs = vec![epoch_commitment];
            let store = initial_store(&descriptor, private_key_epoch_root(&key_epochs).unwrap());
            let predecessor = PrivateRuntimeImage::genesis(
                &descriptor,
                node_a,
                RuntimeState {
                    control: vec![0x21],
                    linear: Vec::new(),
                    merge: vec![0x22],
                    local: vec![0x23],
                },
                store,
                key_epochs,
                creation_receipt,
                GENESIS_AT,
                &AllowVerifier,
            )
            .unwrap();
            Self {
                descriptor,
                node_a,
                node_b,
                predecessor,
            }
        }

        fn creation_receipt_for(descriptor: &AgentDescriptor) -> AuthorityReceipt {
            let request = ManagementRequest::Create(Box::new(descriptor.clone()));
            AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: descriptor.authority.policy,
                    issuer: descriptor.authority.issuer,
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    operation: AuthorityOperationKind::CreateAgent,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    actor: None,
                    actor_deployment: None,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: hash(0x17),
                    },
                    lane_roots: AuthorityLaneRoots::default(),
                    epoch: descriptor.authority.initial_epoch,
                    decision_sequence: 1,
                    acknowledged_through: 0,
                    valid_from: GENESIS_AT,
                    expires_at: 40,
                    request: request.commitment(),
                },
                public_key: descriptor.authority.public_key,
                signature: [0x18; 64],
            }
        }

        fn authority_target(&self) -> AuthorityActorTarget {
            AuthorityActorTarget {
                space: self.descriptor.identity.space,
                system_agent: AgentId([0x31; 32]),
                system_runtime_deployment: DeploymentId([0x32; 32]),
                binding: self.descriptor.authority,
            }
        }

        fn receipt(
            &self,
            operation: AuthorityOperationKind,
            request: Hash,
            actor: Option<ActorId>,
        ) -> AuthorityReceipt {
            AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: self.descriptor.authority.policy,
                    issuer: self.descriptor.authority.issuer,
                    space: self.descriptor.identity.space,
                    agent: self.descriptor.identity.agent,
                    operation,
                    runtime_deployment: self.descriptor.identity.runtime_deployment,
                    actor,
                    actor_deployment: None,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: hash(0x33),
                    },
                    lane_roots: AuthorityLaneRoots::default(),
                    epoch: self.descriptor.authority.initial_epoch,
                    decision_sequence: 0,
                    acknowledged_through: 0,
                    valid_from: 4,
                    expires_at: 40,
                    request,
                },
                public_key: self.descriptor.authority.public_key,
                signature: [0x34; 64],
            }
        }

        fn issuance(&self, receipt: AuthorityReceipt) -> AuthorityOperationIssuanceAck {
            AuthorityOperationIssuanceAck {
                authorization_invocation: vos_agent_sdk::InvocationId([0x35; 32]),
                acknowledgement_invocation: vos_agent_sdk::InvocationId([0x36; 32]),
                authority: self.authority_target(),
                operation_call: hash(0x37),
                approval: hash(0x38),
                authorization_sequence: NonZeroU64::new(1).unwrap(),
                receipt,
                issued_at: 4,
                signature: [0x39; 64],
            }
        }
    }

    fn key_epoch(
        space: SpaceId,
        agent: AgentId,
        epoch: u64,
        node: NodeId,
        marker: u8,
    ) -> PrivateKeyEpoch {
        let recipient_key = [marker.wrapping_add(1); 32];
        let recovery_recipient = [marker.wrapping_add(2); 32];
        PrivateKeyEpoch {
            space,
            agent,
            epoch,
            owner_key_commitment: hash(marker.wrapping_add(3)),
            data_key_commitment: hash(marker.wrapping_add(4)),
            recovery_key_commitment: hash(marker.wrapping_add(5)),
            recovery_encryption_public_key: recovery_recipient,
            sealed_recovery_data_key: SealedRecoveryKey {
                recipient_key: recovery_recipient,
                sealed: vec![marker.wrapping_add(6)],
            },
            sealed_owner_keys: vec![SealedPrivateKey {
                node,
                recipient_key,
                sealed: vec![marker.wrapping_add(7)],
            }],
            sealed_data_keys: vec![SealedPrivateKey {
                node,
                recipient_key,
                sealed: vec![marker.wrapping_add(8)],
            }],
        }
    }

    fn initial_store(
        descriptor: &AgentDescriptor,
        key_epoch_root: Hash,
    ) -> PrivateStoreCorePosition {
        PrivateStoreCorePosition::new(
            descriptor.identity.space,
            descriptor.identity.agent,
            descriptor.identity.owner,
            0,
            None,
            0,
            0,
            None,
            0,
            None,
            key_epoch_root,
        )
        .unwrap()
    }

    fn successor_store(
        predecessor: PrivateStoreCorePosition,
        control: &PrivateControlRecord,
        key_epoch_root: Hash,
        marker: u8,
    ) -> PrivateStoreCorePosition {
        let epoch = match &control.operation {
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch }
            | PrivateControlOperation::Recover { next_epoch, .. } => next_epoch.epoch,
            _ => predecessor.epoch,
        };
        PrivateStoreCorePosition::new(
            predecessor.space,
            predecessor.agent,
            predecessor.owner,
            epoch,
            Some(control.commitment()),
            control.sequence + 1,
            predecessor.object_count,
            predecessor.object_root,
            predecessor.control_count + 1,
            Some(hash(marker)),
            key_epoch_root,
        )
        .unwrap()
    }

    fn narrowed_policy() -> RuntimeResourcePolicy {
        RuntimeResourcePolicy {
            max_actors: RuntimeCapabilities::STANDARD_MAX_ACTORS - 1,
            ..RuntimeResourcePolicy::standard()
        }
    }

    fn policy_control(fixture: &Fixture) -> (PrivateControlRecord, PrivateRuntimeMutation) {
        policy_control_for(fixture, narrowed_policy())
    }

    fn policy_control_for(
        fixture: &Fixture,
        policy: RuntimeResourcePolicy,
    ) -> (PrivateControlRecord, PrivateRuntimeMutation) {
        let policy_wire = policy.encode().unwrap();
        (
            PrivateControlRecord {
                space: fixture.descriptor.identity.space,
                agent: fixture.descriptor.identity.agent,
                sequence: 0,
                previous: None,
                operation: PrivateControlOperation::SetResourcePolicy {
                    policy: BlobRef::of_bytes(&policy_wire),
                },
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0x41; 32],
                signature: [0x42; 64],
            },
            PrivateRuntimeMutation::SetResourcePolicy(policy),
        )
    }

    fn actor(marker: u8, requirements: RuntimeRequirements) -> ActorEntry {
        let blob = |offset| BlobRef::of_bytes(&[marker.wrapping_add(offset)]);
        ActorEntry {
            actor: ActorId([marker; 32]),
            name: alloc::format!("private-{marker}"),
            parent: None,
            deployment: DeploymentId([marker.wrapping_add(1); 32]),
            program: ProgramId([marker.wrapping_add(2); 32]),
            package: blob(3),
            agent_schema: blob(4),
            method_policy: blob(5),
            constructor_abi: hash(marker.wrapping_add(6)),
            installation_data: None,
            state_layout: hash(marker.wrapping_add(7)),
            lanes: requirements.lanes,
            suspended: false,
        }
    }

    fn install_mutation(
        marker: u8,
        contract: ActorPackageContract,
        requirements: RuntimeRequirements,
    ) -> PrivateRuntimeMutation {
        let entry = actor(marker, requirements);
        PrivateRuntimeMutation::Install(InstallActor {
            installation_id: InstallationId([marker.wrapping_add(8); 32]),
            registry_reservation: hash(marker.wrapping_add(9)),
            producer: ProducerId([marker.wrapping_add(10); 32]),
            package: entry.package.clone(),
            agent_schema: entry.agent_schema.clone(),
            method_policy: entry.method_policy.clone(),
            constructor_abi: entry.constructor_abi,
            installation_data: None,
            state_layout: entry.state_layout,
            entry,
            contract,
            requirements,
        })
    }

    fn lifecycle_pending(
        fixture: &Fixture,
        descriptor: &AgentDescriptor,
        predecessor: &PrivateRuntimeImage,
        mutation: PrivateRuntimeMutation,
    ) -> Result<PrivateRuntimeApplication, PrivateRuntimeEvidenceError> {
        let actor = mutation.actor().unwrap();
        let control = PrivateControlRecord {
            space: predecessor.managed.space,
            agent: predecessor.managed.agent,
            sequence: predecessor.store.next_sequence,
            previous: predecessor.store.control_head,
            operation: PrivateControlOperation::ActorLifecycle {
                actor,
                operation: mutation.lifecycle_kind().unwrap(),
                request: mutation.commitment(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x45; 32],
            signature: [0x46; 64],
        };
        let receipt = fixture.receipt(
            AuthorityOperationKind::PrivateActorLifecycle,
            control.commitment(),
            Some(actor),
        );
        let expected_store = successor_store(
            predecessor.store,
            &control,
            predecessor.store.key_epoch_root,
            0x47,
        );
        PrivateRuntimeApplication::pending(
            descriptor,
            predecessor,
            control,
            Some(mutation),
            None,
            receipt.clone(),
            fixture.issuance(receipt),
            5,
            expected_store,
            &AllowVerifier,
            &AllowVerifier,
        )
    }

    fn policy_application(
        fixture: &Fixture,
        predecessor: &PrivateRuntimeImage,
        applied_at: u64,
    ) -> (
        PrivateRuntimeApplication,
        PrivateRuntimeImage,
        PrivateRuntimeApplication,
        PrivateControlReopenedState,
    ) {
        let (mut control, mutation) = policy_control(fixture);
        control.sequence = predecessor.store.next_sequence;
        control.previous = predecessor.store.control_head;
        let receipt = fixture.receipt(
            AuthorityOperationKind::SetPrivateResourcePolicy,
            control.commitment(),
            None,
        );
        let issuance = fixture.issuance(receipt.clone());
        let expected_store = successor_store(
            predecessor.store,
            &control,
            predecessor.store.key_epoch_root,
            0x43,
        );
        let pending = PrivateRuntimeApplication::pending(
            &fixture.descriptor,
            predecessor,
            control,
            Some(mutation),
            None,
            receipt,
            issuance,
            applied_at,
            expected_store,
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        let success = PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy());
        let successor = PrivateRuntimeImage::successor(
            &fixture.descriptor,
            predecessor,
            &pending,
            &success,
            RuntimeState {
                control: vec![0x44],
                linear: Vec::new(),
                merge: predecessor.state.merge.clone(),
                local: predecessor.state.local.clone(),
            },
            predecessor.key_epochs.clone(),
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        let completed = pending
            .clone()
            .complete(
                &fixture.descriptor,
                predecessor,
                &successor,
                success,
                &AllowVerifier,
                &AllowVerifier,
            )
            .unwrap();
        let reopened =
            PrivateControlReopenedState::new(completed.clone(), expected_store, successor.clone())
                .unwrap();
        (pending, successor, completed, reopened)
    }

    fn recovery_application(
        fixture: &Fixture,
        predecessor: &PrivateRuntimeImage,
        applied_at: u64,
    ) -> (
        PrivateRuntimeApplication,
        PrivateRuntimeImage,
        PrivateRuntimeApplication,
        PrivateControlReopenedState,
        PrivateRecoveryAuthorityProof,
    ) {
        let transport_identity = vec![0x71, 0x72, 0x73];
        let replacement_node = NodeId::of_authenticated_peer(&transport_identity);
        let replacement_key = [0x74; 32];
        let replacement = PrivateNodeIdentity {
            node: replacement_node,
            principal: predecessor.owner,
            transport_identity,
            encryption_public_key: replacement_key,
            authority_binding: hash(0x75),
            transport_signature: [0x76; 64],
        };
        assert!(replacement.validate());

        let mut next_epoch = key_epoch(
            predecessor.managed.space,
            predecessor.managed.agent,
            predecessor.store.epoch + 1,
            replacement_node,
            0x77,
        );
        next_epoch.sealed_owner_keys[0].recipient_key = replacement_key;
        next_epoch.sealed_data_keys[0].recipient_key = replacement_key;
        let historical_keyring = PrivateRecoveryKeyringGrant {
            key_commitment: hash(0x78),
            sealed_keys: vec![SealedPrivateKey {
                node: replacement_node,
                recipient_key: replacement_key,
                sealed: vec![0x79],
            }],
            ciphertext: EncryptedPrivateObject {
                space: predecessor.managed.space,
                agent: predecessor.managed.agent,
                epoch: next_epoch.epoch,
                kind: EncryptedObjectKind::Control,
                content: hash(0x7a),
                nonce: [0x7b; 24],
                ciphertext: vec![0x7c],
            },
        };
        let control = PrivateControlRecord {
            space: predecessor.managed.space,
            agent: predecessor.managed.agent,
            sequence: predecessor.store.next_sequence,
            previous: predecessor.store.control_head,
            operation: PrivateControlOperation::Recover {
                superseded_heads: predecessor.store.control_head.into_iter().collect(),
                next_epoch: next_epoch.clone(),
                replacement_nodes: vec![replacement],
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: RECOVERY_PUBLIC_KEY,
            signature: [0x7d; 64],
        };
        assert!(control.validate_shape());
        let proof = PrivateRecoveryAuthorityProof::from_control(
            predecessor.managed,
            &control,
            None,
            &RecoverySigner(RECOVERY_PUBLIC_KEY),
        )
        .unwrap();
        let receipt = fixture.receipt(
            AuthorityOperationKind::RecoverPrivateAgent,
            proof.commitment(),
            None,
        );
        let issuance = fixture.issuance(receipt.clone());
        let mut key_epochs = predecessor.key_epochs.clone();
        key_epochs.push(PrivateKeyEpochCommitment::from_epoch(&next_epoch).unwrap());
        let expected_store = successor_store(
            predecessor.store,
            &control,
            private_key_epoch_root(&key_epochs).unwrap(),
            0x7e,
        );
        let pending = PrivateRuntimeApplication::pending(
            &fixture.descriptor,
            predecessor,
            control,
            None,
            Some(proof.clone()),
            receipt,
            issuance,
            applied_at,
            expected_store,
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        let success = PrivateRuntimeSuccess::ControlOnly;
        let successor = PrivateRuntimeImage::successor(
            &fixture.descriptor,
            predecessor,
            &pending,
            &success,
            predecessor.state.clone(),
            key_epochs,
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        let completed = pending
            .clone()
            .complete(
                &fixture.descriptor,
                predecessor,
                &successor,
                success,
                &AllowVerifier,
                &AllowVerifier,
            )
            .unwrap();
        let reopened =
            PrivateControlReopenedState::new(completed.clone(), expected_store, successor.clone())
                .unwrap();
        (pending, successor, completed, reopened, proof)
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: CanonicalWire + fmt::Debug + PartialEq,
    {
        let wire = value.encode().unwrap();
        let decoded = T::decode(&wire).unwrap();
        assert_eq!(&decoded, value);
        assert_eq!(decoded.encode().unwrap(), wire);
    }

    fn assert_clean_break<T: CanonicalWire>(value: &T) {
        let wire = value.encode().unwrap();

        let mut old_magic = wire.clone();
        old_magic[3] ^= 1;
        assert!(T::decode(&old_magic).is_err());

        let mut wrong_generation = wire.clone();
        wrong_generation[4] ^= 1;
        assert!(T::decode(&wrong_generation).is_err());

        let mut trailing = wire;
        trailing.push(0);
        assert!(T::decode(&trailing).is_err());
    }

    fn legacy_stable_projection_wire(value: &PrivateRuntimeStableProjection) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"PSP1");
        wire.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut wire);
        encode_managed(&mut encoder, value.managed);
        encoder.fixed(value.descriptor.as_bytes());
        encode_blob(&mut encoder, &value.runtime_package);
        encoder.u64(value.generation);
        encode_optional_hash(&mut encoder, value.previous);
        encode_optional_hash(&mut encoder, value.control_head);
        encode_optional_u64(&mut encoder, value.control_sequence);
        encode_optional_hash(&mut encoder, value.full_replay);
        encode_optional_hash(&mut encoder, value.disposition);
        encoder.fixed(value.control_state.as_bytes());
        encode_nested(&mut encoder, &value.active_resource_policy);
        encoder.fixed(value.active_resource_policy_commitment.as_bytes());
        wire
    }

    fn legacy_runtime_image_wire(value: &PrivateRuntimeImage) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"PVI1");
        wire.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut wire);
        encode_managed(&mut encoder, value.managed);
        encoder.fixed(value.node.as_bytes());
        encoder.fixed(value.owner.as_bytes());
        encoder.fixed(value.descriptor.as_bytes());
        encode_blob(&mut encoder, &value.runtime_package);
        encoder.fixed(value.runtime_deployment.as_bytes());
        encode_runtime_state(&mut encoder, &value.state);
        encode_nested(&mut encoder, &value.active_resource_policy);
        encoder.fixed(value.active_resource_policy_commitment.as_bytes());
        encode_nested(&mut encoder, &value.store);
        encoder.list(&value.key_epochs, encode_nested);
        encoder.option(&value.runtime_control, |encoder, position| {
            encoder.fixed(position.control.as_bytes());
            encoder.u64(position.sequence);
        });
        encode_optional_hash(&mut encoder, value.last_full_replay);
        encoder.bytes(&legacy_stable_projection_wire(&value.stable_projection));
        encoder.u64(value.applied_at);
        wire
    }

    #[test]
    fn canonical_formats_round_trip_and_reopen_only_with_anchored_authority() {
        let fixture = Fixture::new();
        let (pending, successor, completed, reopened) =
            policy_application(&fixture, &fixture.predecessor, 5);

        assert_round_trip(&fixture.predecessor.key_epochs[0]);
        assert_round_trip(&fixture.predecessor.store);
        assert_round_trip(&PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy()));
        assert_round_trip(&fixture.predecessor.stable_projection);
        assert_round_trip(&fixture.predecessor);
        assert_round_trip(&pending);
        assert_round_trip(&completed);
        assert_round_trip(&successor);
        assert_round_trip(&reopened);

        let pvr3_wire = fixture.predecessor.encode().unwrap();
        assert_eq!(&pvr3_wire[..4], b"PVR3");
        assert_eq!(
            fixture.predecessor.commitment(),
            Hash::digest(b"vos/agent/private-runtime-image/v3", &[&pvr3_wire])
        );
        assert_ne!(
            fixture.predecessor.commitment(),
            Hash::digest(b"vos/agent/private-runtime-image/v2", &[&pvr3_wire])
        );
        let mut retired_pvi2 = pvr3_wire.clone();
        retired_pvi2[..4].copy_from_slice(b"PVI2");
        assert!(PrivateRuntimeImage::decode(&retired_pvi2).is_err());
        let mut retired_pvi3 = pvr3_wire.clone();
        retired_pvi3[..4].copy_from_slice(b"PVI3");
        assert!(PrivateRuntimeImage::decode(&retired_pvi3).is_err());
        let mut retired_pvi1 = pvr3_wire;
        retired_pvi1[..4].copy_from_slice(b"PVI1");
        assert!(PrivateRuntimeImage::decode(&retired_pvi1).is_err());
        assert_eq!(
            fixture.predecessor.stable_projection.creation_receipt(),
            fixture.predecessor.creation_receipt().commitment()
        );
        fixture
            .predecessor
            .reopen_with(&fixture.descriptor, &AllowVerifier)
            .unwrap();
        assert!(
            fixture
                .predecessor
                .reopen_with(&fixture.descriptor, &DenyVerifier)
                .is_err()
        );
        assert_eq!(&pending.encode().unwrap()[..4], b"PAP1");
        let reopened_wire = reopened.encode().unwrap();
        assert_eq!(&reopened_wire[..4], b"PCR3");
        assert_eq!(
            reopened.commitment(),
            PrivateControlReopenedState::commitment_from_application(&completed).unwrap()
        );
        let mut retired_pcr2 = reopened_wire;
        retired_pcr2[..4].copy_from_slice(b"PCR2");
        assert!(PrivateControlReopenedState::decode(&retired_pcr2).is_err());
        reopened
            .reopen_with(&fixture.descriptor, &AllowVerifier, &AllowVerifier)
            .unwrap();
        assert!(
            reopened
                .reopen_with(&fixture.descriptor, &DenyVerifier, &AllowVerifier)
                .is_err()
        );
    }

    #[test]
    fn pcrs3_commitment_binds_completed_papl_successor_store_and_pvri() {
        let fixture = Fixture::new();
        let (pending, _, completed, reopened) =
            policy_application(&fixture, &fixture.predecessor, 5);
        assert!(PrivateControlReopenedState::commitment_from_application(&pending).is_err());
        let commitment = reopened.commitment();

        let mut alternate_pvri = completed.clone();
        alternate_pvri
            .completion
            .as_mut()
            .unwrap()
            .successor_runtime_image = hash(0xd8);
        assert!(alternate_pvri.validate().is_ok());
        assert_ne!(
            PrivateControlReopenedState::commitment_from_application(&alternate_pvri).unwrap(),
            commitment
        );

        // A control applied after authenticated object growth has a distinct
        // predecessor/successor PSC endpoint even when every control field is
        // unchanged. PCRS3 binds that exact Store endpoint as well.
        let predecessor = completed.predecessor_store();
        let successor = completed.expected_successor_store();
        let object_root = Some(hash(0xd9));
        let mut alternate_store = completed.clone();
        alternate_store.predecessor_store = PrivateStoreCorePosition::new(
            predecessor.space(),
            predecessor.agent(),
            predecessor.owner(),
            predecessor.epoch(),
            predecessor.control_head(),
            predecessor.next_sequence(),
            predecessor.object_count() + 1,
            object_root,
            predecessor.control_count(),
            predecessor.control_root(),
            predecessor.key_epoch_root(),
        )
        .unwrap();
        alternate_store.expected_successor_store = PrivateStoreCorePosition::new(
            successor.space(),
            successor.agent(),
            successor.owner(),
            successor.epoch(),
            successor.control_head(),
            successor.next_sequence(),
            successor.object_count() + 1,
            object_root,
            successor.control_count(),
            successor.control_root(),
            successor.key_epoch_root(),
        )
        .unwrap();
        assert!(alternate_store.validate().is_ok());
        assert_ne!(
            PrivateControlReopenedState::commitment_from_application(&alternate_store).unwrap(),
            commitment
        );
    }

    #[test]
    fn clean_break_rejects_old_magic_abi_and_trailing_bytes() {
        let fixture = Fixture::new();
        let (pending, successor, completed, reopened) =
            policy_application(&fixture, &fixture.predecessor, 5);

        assert_clean_break(&fixture.predecessor.key_epochs[0]);
        assert_clean_break(&fixture.predecessor.store);
        assert_clean_break(&PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy()));
        assert_clean_break(&fixture.predecessor.stable_projection);
        assert_clean_break(&fixture.predecessor);
        assert_clean_break(&pending);
        assert_clean_break(&completed);
        assert_clean_break(&successor);
        assert_clean_break(&reopened);

        assert!(
            PrivateRuntimeStableProjection::decode(&legacy_stable_projection_wire(
                &fixture.predecessor.stable_projection,
            ))
            .is_err()
        );
        assert!(
            PrivateRuntimeImage::decode(&legacy_runtime_image_wire(&fixture.predecessor)).is_err()
        );

        let oversized = vec![0; MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES + 1];
        assert!(PrivateRuntimeApplication::decode(&oversized).is_err());
    }

    #[test]
    fn genesis_requires_exact_verified_creation_receipt_and_nonempty_state() {
        struct DynamicVerifier<'a>(&'a dyn AuthorityVerifier);
        impl AuthorityVerifier for DynamicVerifier<'_> {
            fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
                self.0.verify(public_key, message, signature)
            }
        }

        let fixture = Fixture::new();
        let construct = |state: RuntimeState,
                         receipt: AuthorityReceipt,
                         genesis_at: u64,
                         verifier: &dyn AuthorityVerifier| {
            PrivateRuntimeImage::genesis(
                &fixture.descriptor,
                fixture.node_a,
                state,
                fixture.predecessor.store,
                fixture.predecessor.key_epochs.clone(),
                receipt,
                genesis_at,
                &DynamicVerifier(verifier),
            )
        };
        let state = fixture.predecessor.state.clone();
        let receipt = Fixture::creation_receipt_for(&fixture.descriptor);
        assert!(construct(state.clone(), receipt.clone(), GENESIS_AT, &AllowVerifier).is_ok());
        assert!(
            construct(
                RuntimeState::default(),
                receipt.clone(),
                GENESIS_AT,
                &AllowVerifier
            )
            .is_err()
        );
        assert!(construct(state.clone(), receipt.clone(), 3, &AllowVerifier).is_err());
        assert!(construct(state.clone(), receipt.clone(), GENESIS_AT, &DenyVerifier).is_err());

        let mut wrong_request = receipt.clone();
        wrong_request.selector.request = hash(0xa1);
        assert!(construct(state.clone(), wrong_request, GENESIS_AT, &AllowVerifier).is_err());

        let mut wrong_route = receipt;
        wrong_route.selector.agent = AgentId([0xa2; 32]);
        assert!(construct(state, wrong_route, GENESIS_AT, &AllowVerifier).is_err());
    }

    #[test]
    fn embedded_creation_receipt_never_selects_its_own_trust_root() {
        let fixture = Fixture::new();
        let mut substituted = fixture.predecessor.clone();
        substituted.creation_receipt.selector.request = hash(0xa3);
        substituted.stable_projection.creation_receipt = substituted.creation_receipt.commitment();
        assert!(substituted.validate().is_ok());
        assert!(
            substituted
                .reopen_with(&fixture.descriptor, &AllowVerifier)
                .is_err()
        );

        let mut unbound = fixture.predecessor.clone();
        unbound.creation_receipt.signature[0] ^= 1;
        assert!(unbound.validate().is_err());
    }

    #[test]
    fn completion_retains_only_an_exact_positive_disposition() {
        let fixture = Fixture::new();
        let (_, _, completed, _) = policy_application(&fixture, &fixture.predecessor, 5);

        assert_eq!(
            completed.success(),
            Some(&PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy()))
        );
        let mut substituted = completed;
        substituted.completion.as_mut().unwrap().success =
            PrivateRuntimeSuccess::ResourcePolicySet(RuntimeResourcePolicy::standard());
        assert!(substituted.validate().is_err());
        assert!(substituted.encode().is_err());

        let denial = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Management(Err(
                vos_agent_sdk::ManagementError::InvalidRequest,
            )),
        }
        .encode()
        .unwrap();
        let mut denial_wire = Vec::new();
        denial_wire.extend_from_slice(b"PSD1");
        denial_wire.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut denial_wire);
        encoder.u8(1);
        encoder.bytes(&denial);
        assert!(PrivateRuntimeSuccess::decode(&denial_wire).is_err());
    }

    #[test]
    fn genesis_transition_requires_exact_created_identity_and_private_state() {
        let fixture = Fixture::new();
        let state = fixture.predecessor.state().clone();
        let accepted = RuntimeTransition {
            state: state.clone(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                fixture.descriptor.identity.clone(),
            ))),
        };
        assert_eq!(
            validate_private_runtime_genesis_transition(&fixture.descriptor, accepted),
            Ok(state.clone())
        );

        let mut wrong_identity = fixture.descriptor.identity.clone();
        wrong_identity.agent = AgentId([0xa4; 32]);
        assert_eq!(
            validate_private_runtime_genesis_transition(
                &fixture.descriptor,
                RuntimeTransition {
                    state: state.clone(),
                    outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                        wrong_identity,
                    ))),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidSuccess)
        );
        assert_eq!(
            validate_private_runtime_genesis_transition(
                &fixture.descriptor,
                RuntimeTransition {
                    state: RuntimeState::default(),
                    outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                        fixture.descriptor.identity.clone(),
                    ))),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidState)
        );
        assert_eq!(
            validate_private_runtime_genesis_transition(
                &fixture.descriptor,
                RuntimeTransition {
                    state,
                    outcome: RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidSuccess)
        );
    }

    #[test]
    fn control_transition_classifier_separates_application_from_exact_denial() {
        let fixture = Fixture::new();
        let (control, mutation) = policy_control(&fixture);
        let request = ManagementRequest::PrivateControl {
            control: Box::new(control),
            mutation: Box::new(mutation),
        };
        let mut applied_state = fixture.predecessor.state().clone();
        applied_state.control = vec![0xa5];
        assert_eq!(
            classify_private_runtime_control_transition(
                &fixture.predecessor,
                &request,
                RuntimeTransition {
                    state: applied_state.clone(),
                    outcome: RuntimeOutcome::Management(Ok(ManagementReply::ResourcePolicySet(
                        narrowed_policy(),
                    ))),
                },
            ),
            Ok(PrivateRuntimeControlDisposition::Applied {
                state: applied_state.clone(),
                success: PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy()),
            })
        );

        assert_eq!(
            classify_private_runtime_control_transition(
                &fixture.predecessor,
                &request,
                RuntimeTransition {
                    state: fixture.predecessor.state().clone(),
                    outcome: RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
                },
            ),
            Ok(PrivateRuntimeControlDisposition::RetiredUnapplied {
                error: ManagementError::InvalidRequest,
            })
        );

        let mut changed_denial = fixture.predecessor.state().clone();
        changed_denial.local.push(0xa6);
        assert_eq!(
            classify_private_runtime_control_transition(
                &fixture.predecessor,
                &request,
                RuntimeTransition {
                    state: changed_denial,
                    outcome: RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidState)
        );

        assert_eq!(
            classify_private_runtime_control_transition(
                &fixture.predecessor,
                &request,
                RuntimeTransition {
                    state: applied_state.clone(),
                    outcome: RuntimeOutcome::Management(Ok(ManagementReply::ResourcePolicySet(
                        RuntimeResourcePolicy::standard(),
                    ))),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidSuccess)
        );

        let mut changed_merge = applied_state;
        changed_merge.merge.push(0xa7);
        assert_eq!(
            classify_private_runtime_control_transition(
                &fixture.predecessor,
                &request,
                RuntimeTransition {
                    state: changed_merge,
                    outcome: RuntimeOutcome::Management(Ok(ManagementReply::ResourcePolicySet(
                        narrowed_policy(),
                    ))),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidState)
        );

        assert_eq!(
            classify_private_runtime_control_transition(
                &fixture.predecessor,
                &request,
                RuntimeTransition {
                    state: fixture.predecessor.state().clone(),
                    outcome: RuntimeOutcome::Completed(Err(
                        vos_agent_sdk::InvocationError::InvalidInput,
                    )),
                },
            ),
            Err(PrivateRuntimeEvidenceError::InvalidSuccess)
        );
    }

    #[test]
    fn papl_successor_match_allows_only_authenticated_object_growth() {
        let mut fixture = Fixture::new();
        let genesis = fixture.predecessor.store();
        let genesis_with_object = PrivateStoreCorePosition::new(
            genesis.space(),
            genesis.agent(),
            genesis.owner(),
            genesis.epoch(),
            genesis.control_head(),
            genesis.next_sequence(),
            1,
            Some(hash(0xd0)),
            genesis.control_count(),
            genesis.control_root(),
            genesis.key_epoch_root(),
        )
        .unwrap();
        fixture.predecessor = fixture
            .predecessor
            .rebind_store_objects(genesis_with_object)
            .unwrap();
        let (_, successor, completed, _) = policy_application(&fixture, &fixture.predecessor, 5);
        assert!(successor.matches_application_successor_after_object_growth(&completed));

        let applied = successor.store();
        let grown_store = PrivateStoreCorePosition::new(
            applied.space(),
            applied.agent(),
            applied.owner(),
            applied.epoch(),
            applied.control_head(),
            applied.next_sequence(),
            2,
            Some(hash(0xd1)),
            applied.control_count(),
            applied.control_root(),
            applied.key_epoch_root(),
        )
        .unwrap();
        let grown = successor.rebind_store_objects(grown_store).unwrap();
        assert!(grown.matches_application_successor_after_object_growth(&completed));

        let mut state_tamper = grown.clone();
        state_tamper.state.local.push(0xd2);
        assert!(state_tamper.validate().is_ok());
        assert!(!state_tamper.matches_application_successor_after_object_growth(&completed));

        let mut projection_tamper = grown.clone();
        projection_tamper.state.control.push(0xd3);
        projection_tamper.stable_projection.control_state =
            control_state_commitment(&projection_tamper.state.control);
        assert!(projection_tamper.validate().is_ok());
        assert!(!projection_tamper.matches_application_successor_after_object_growth(&completed));

        let mut runtime_control_tamper = grown.clone();
        runtime_control_tamper.runtime_control = None;
        assert!(runtime_control_tamper.validate().is_ok());
        assert!(
            !runtime_control_tamper.matches_application_successor_after_object_growth(&completed)
        );

        let mut control_root_tamper = grown.clone();
        control_root_tamper.store.control_root = Some(hash(0xd4));
        assert!(control_root_tamper.validate().is_ok());
        assert!(!control_root_tamper.matches_application_successor_after_object_growth(&completed));

        let mut key_root_tamper = grown.clone();
        key_root_tamper.key_epochs.last_mut().unwrap().exact_wire = hash(0xd5);
        key_root_tamper.store.key_epoch_root =
            private_key_epoch_root(&key_root_tamper.key_epochs).unwrap();
        assert!(key_root_tamper.validate().is_ok());
        assert!(!key_root_tamper.matches_application_successor_after_object_growth(&completed));

        let mut same_count_root_tamper = successor.clone();
        same_count_root_tamper.store.object_root = Some(hash(0xd6));
        assert!(same_count_root_tamper.validate().is_ok());
        assert!(
            !same_count_root_tamper.matches_application_successor_after_object_growth(&completed)
        );
    }

    #[test]
    fn runtime_mutation_and_recovery_proof_presence_are_exact() {
        let fixture = Fixture::new();
        let (policy_control, mutation) = policy_control(&fixture);
        let receipt = fixture.receipt(
            AuthorityOperationKind::SetPrivateResourcePolicy,
            policy_control.commitment(),
            None,
        );
        let expected_store = successor_store(
            fixture.predecessor.store,
            &policy_control,
            fixture.predecessor.store.key_epoch_root,
            0x82,
        );
        assert!(
            PrivateRuntimeApplication::pending(
                &fixture.descriptor,
                &fixture.predecessor,
                policy_control.clone(),
                None,
                None,
                receipt.clone(),
                fixture.issuance(receipt.clone()),
                5,
                expected_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );

        let (recover_pending, _, _, _, proof) =
            recovery_application(&fixture, &fixture.predecessor, 5);
        assert!(
            PrivateRuntimeApplication::pending(
                &fixture.descriptor,
                &fixture.predecessor,
                policy_control,
                Some(mutation.clone()),
                Some(proof),
                receipt.clone(),
                fixture.issuance(receipt),
                5,
                expected_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );
        assert!(
            PrivateRuntimeApplication::pending(
                &fixture.descriptor,
                &fixture.predecessor,
                recover_pending.control.clone(),
                Some(mutation),
                recover_pending.recovery_authority_proof.clone(),
                recover_pending.receipt.clone(),
                recover_pending.issuance.clone(),
                recover_pending.applied_at,
                recover_pending.expected_successor_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );
    }

    #[test]
    fn descriptor_scoped_policy_contract_and_capability_limits_fail_closed() {
        let fixture = Fixture::new();
        let mut narrow_descriptor = fixture.descriptor.clone();
        narrow_descriptor.capabilities.max_actors = 1;
        narrow_descriptor.validate().unwrap();
        let key_epochs = fixture.predecessor.key_epochs.clone();
        let narrow_store = initial_store(
            &narrow_descriptor,
            private_key_epoch_root(&key_epochs).unwrap(),
        );
        let narrow_predecessor = PrivateRuntimeImage::genesis(
            &narrow_descriptor,
            fixture.node_a,
            fixture.predecessor.state.clone(),
            narrow_store,
            key_epochs,
            Fixture::creation_receipt_for(&narrow_descriptor),
            GENESIS_AT,
            &AllowVerifier,
        )
        .unwrap();
        let over_ceiling = RuntimeResourcePolicy {
            max_actors: 2,
            ..narrow_descriptor.initial_resource_policy()
        };
        let (control, mutation) = policy_control_for(&fixture, over_ceiling);
        let receipt = fixture.receipt(
            AuthorityOperationKind::SetPrivateResourcePolicy,
            control.commitment(),
            None,
        );
        let expected_store = successor_store(
            narrow_predecessor.store,
            &control,
            narrow_predecessor.store.key_epoch_root,
            0x93,
        );
        assert!(
            PrivateRuntimeApplication::pending(
                &narrow_descriptor,
                &narrow_predecessor,
                control,
                Some(mutation),
                None,
                receipt.clone(),
                fixture.issuance(receipt),
                5,
                expected_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );

        let mut hostile_predecessor = narrow_predecessor.clone();
        hostile_predecessor.active_resource_policy = over_ceiling;
        hostile_predecessor.active_resource_policy_commitment =
            resource_policy_commitment(over_ceiling).unwrap();
        hostile_predecessor.stable_projection.active_resource_policy = over_ceiling;
        hostile_predecessor
            .stable_projection
            .active_resource_policy_commitment = resource_policy_commitment(over_ceiling).unwrap();
        assert!(hostile_predecessor.validate().is_ok());
        let (control, mutation) =
            policy_control_for(&fixture, narrow_descriptor.initial_resource_policy());
        let receipt = fixture.receipt(
            AuthorityOperationKind::SetPrivateResourcePolicy,
            control.commitment(),
            None,
        );
        let expected_store = successor_store(
            hostile_predecessor.store,
            &control,
            hostile_predecessor.store.key_epoch_root,
            0x95,
        );
        assert!(
            PrivateRuntimeApplication::pending(
                &narrow_descriptor,
                &hostile_predecessor,
                control,
                Some(mutation),
                None,
                receipt.clone(),
                fixture.issuance(receipt),
                5,
                expected_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );

        let private_requirements = RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Merge),
            ..RuntimeRequirements::default()
        };
        let unsupported_contract = ActorPackageContract {
            actor_abi: vos_agent_sdk::contract::ACTOR_ABI + 1,
        };
        assert!(
            lifecycle_pending(
                &fixture,
                &fixture.descriptor,
                &fixture.predecessor,
                install_mutation(0x94, unsupported_contract, private_requirements),
            )
            .is_err()
        );

        let unsupported_capability = RuntimeRequirements {
            scheduling: true,
            ..private_requirements
        };
        assert!(
            lifecycle_pending(
                &fixture,
                &fixture.descriptor,
                &fixture.predecessor,
                install_mutation(
                    0xa0,
                    ActorPackageContract::canonical(),
                    unsupported_capability,
                ),
            )
            .is_err()
        );

        let supported = lifecycle_pending(
            &fixture,
            &fixture.descriptor,
            &fixture.predecessor,
            install_mutation(
                0xb0,
                ActorPackageContract::canonical(),
                private_requirements,
            ),
        );
        assert!(supported.is_ok());
    }

    #[test]
    fn recover_binds_exact_proof_preimage_signer_and_receipt_request() {
        let fixture = Fixture::new();
        let (pending, _, completed, reopened, _) =
            recovery_application(&fixture, &fixture.predecessor, 5);
        assert!(pending.recovery_authority_proof().is_some());
        reopened
            .reopen_with(&fixture.descriptor, &AllowVerifier, &AllowVerifier)
            .unwrap();
        assert!(
            reopened
                .reopen_with(&fixture.descriptor, &AllowVerifier, &DenyVerifier)
                .is_err()
        );

        let mut proof_substitution = pending.clone();
        proof_substitution
            .recovery_authority_proof
            .as_mut()
            .unwrap()
            .signature[0] ^= 1;
        proof_substitution.full_replay = full_application_replay(
            &proof_substitution.control,
            None,
            proof_substitution.recovery_authority_proof.as_ref(),
        )
        .unwrap();
        assert!(proof_substitution.validate().is_err());

        let mut wrong_recovery_anchor = fixture.descriptor.clone();
        wrong_recovery_anchor
            .private_recovery
            .as_mut()
            .unwrap()
            .signing_key_commitment = hash(0x83);
        assert!(wrong_recovery_anchor.validate().is_ok());
        assert!(
            completed
                .verify_with(&wrong_recovery_anchor, &AllowVerifier, &AllowVerifier)
                .is_err()
        );
    }

    #[test]
    fn encoded_authority_cannot_be_its_own_trust_root() {
        let fixture = Fixture::new();
        let (pending, successor, mut completed, _) =
            policy_application(&fixture, &fixture.predecessor, 5);
        let success = PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy());
        assert!(
            PrivateRuntimeImage::successor(
                &fixture.descriptor,
                &fixture.predecessor,
                &pending,
                &success,
                successor.state.clone(),
                fixture.predecessor.key_epochs.clone(),
                &DenyVerifier,
                &AllowVerifier,
            )
            .is_err()
        );
        assert!(
            pending
                .clone()
                .complete(
                    &fixture.descriptor,
                    &fixture.predecessor,
                    &successor,
                    success,
                    &DenyVerifier,
                    &AllowVerifier,
                )
                .is_err()
        );
        let forged_public_key = [0x84; 32];
        let forged_producer = ProducerId::of_public_key(&forged_public_key);
        completed.receipt.public_key = forged_public_key;
        completed.receipt.selector.issuer.producer = forged_producer;
        completed.issuance.receipt = completed.receipt.clone();
        completed.issuance.authority.binding.public_key = forged_public_key;
        completed.issuance.authority.binding.issuer.producer = forged_producer;
        assert!(completed.validate().is_ok());
        assert!(
            completed
                .verify_with(&fixture.descriptor, &AllowVerifier, &AllowVerifier)
                .is_err()
        );
        let decoded = PrivateRuntimeApplication::decode(&completed.encode().unwrap()).unwrap();
        let reopened =
            PrivateControlReopenedState::new(decoded, successor.store, successor).unwrap();
        assert!(reopened.validate().is_ok());
        assert!(
            reopened
                .reopen_with(&fixture.descriptor, &AllowVerifier, &AllowVerifier)
                .is_err()
        );
    }

    #[test]
    fn private_images_and_applications_are_replica_local() {
        let fixture = Fixture::new();
        let replica_b = PrivateRuntimeImage::genesis(
            &fixture.descriptor,
            fixture.node_b,
            RuntimeState {
                control: fixture.predecessor.state.control.clone(),
                linear: Vec::new(),
                merge: vec![0x85],
                local: vec![0x86],
            },
            fixture.predecessor.store,
            fixture.predecessor.key_epochs.clone(),
            fixture.predecessor.creation_receipt.clone(),
            GENESIS_AT,
            &AllowVerifier,
        )
        .unwrap();
        assert_eq!(
            fixture.predecessor.stable_projection,
            replica_b.stable_projection
        );
        assert_ne!(fixture.predecessor.commitment(), replica_b.commitment());

        let (_, successor_a, completed_a, _) =
            policy_application(&fixture, &fixture.predecessor, 5);
        let (_, successor_b, completed_b, _) = policy_application(&fixture, &replica_b, 10);
        assert_eq!(successor_a.stable_projection, successor_b.stable_projection);
        assert_ne!(successor_a.commitment(), successor_b.commitment());
        assert_ne!(completed_a.commitment(), completed_b.commitment());
    }

    #[test]
    fn descriptor_roster_is_genesis_only_and_store_pkey_authorizes_invited_nodes() {
        let fixture = Fixture::new();
        let transport_identity = vec![0xc0, 0xc1, 0xc2];
        let invited_node = NodeId::of_authenticated_peer(&transport_identity);
        assert!(
            !fixture
                .descriptor
                .replicas
                .iter()
                .any(|replica| replica.node == invited_node)
        );
        assert!(
            PrivateRuntimeImage::genesis(
                &fixture.descriptor,
                invited_node,
                fixture.predecessor.state.clone(),
                fixture.predecessor.store,
                fixture.predecessor.key_epochs.clone(),
                fixture.predecessor.creation_receipt.clone(),
                GENESIS_AT,
                &AllowVerifier,
            )
            .is_err()
        );

        let encryption_public_key = [0x43; 32];
        let invited_identity = PrivateNodeIdentity {
            node: invited_node,
            principal: fixture.predecessor.owner,
            transport_identity,
            encryption_public_key,
            authority_binding: hash(0xc4),
            transport_signature: [0xc5; 64],
        };
        let bootstrap = PrivateRuntimeReplicaEstablishment::bind_verified_source(
            &fixture.descriptor,
            &invited_identity,
            fixture.predecessor.store,
            &fixture.predecessor.key_epochs,
            core::slice::from_ref(&invited_identity),
            hash(0xc6),
        )
        .unwrap();
        let imported = PrivateRuntimeImage::genesis_for_established_replica(
            &fixture.descriptor,
            bootstrap,
            fixture.predecessor.state.clone(),
            fixture.predecessor.store,
            fixture.predecessor.key_epochs.clone(),
            fixture.predecessor.creation_receipt.clone(),
            GENESIS_AT,
            &AllowVerifier,
        )
        .unwrap();
        assert_eq!(imported.node(), invited_node);
        assert_eq!(
            imported.stable_projection(),
            fixture.predecessor.stable_projection()
        );
        assert_ne!(imported.commitment(), fixture.predecessor.commitment());

        let sealed_owner_key = SealedPrivateKey {
            node: invited_node,
            recipient_key: encryption_public_key,
            sealed: vec![0xc7],
        };
        let sealed_data_key = SealedPrivateKey {
            node: invited_node,
            recipient_key: encryption_public_key,
            sealed: vec![0xc8],
        };
        let mut invited_epoch = key_epoch(
            fixture.predecessor.managed.space,
            fixture.predecessor.managed.agent,
            0,
            fixture.node_a,
            20,
        );
        invited_epoch
            .sealed_owner_keys
            .push(sealed_owner_key.clone());
        invited_epoch.sealed_data_keys.push(sealed_data_key.clone());
        invited_epoch
            .sealed_owner_keys
            .sort_by_key(|sealed| sealed.node);
        invited_epoch
            .sealed_data_keys
            .sort_by_key(|sealed| sealed.node);
        assert!(invited_epoch.validate());
        let invited_epochs = vec![PrivateKeyEpochCommitment::from_epoch(&invited_epoch).unwrap()];
        let invite = PrivateControlRecord {
            space: fixture.predecessor.managed.space,
            agent: fixture.predecessor.managed.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Invite {
                node: invited_identity,
                epoch: 0,
                sealed_owner_key,
                sealed_data_key,
                historical_grants: Vec::new(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0xc9; 32],
            signature: [0xca; 64],
        };
        let receipt = fixture.receipt(
            AuthorityOperationKind::InvitePrivateNode,
            invite.commitment(),
            None,
        );
        let invited_store = successor_store(
            fixture.predecessor.store,
            &invite,
            private_key_epoch_root(&invited_epochs).unwrap(),
            0xcb,
        );
        let pending = PrivateRuntimeApplication::pending(
            &fixture.descriptor,
            &imported,
            invite,
            None,
            None,
            receipt.clone(),
            fixture.issuance(receipt),
            5,
            invited_store,
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        let local_source = PrivateRuntimeImage::successor(
            &fixture.descriptor,
            &imported,
            &pending,
            &PrivateRuntimeSuccess::ControlOnly,
            imported.state.clone(),
            invited_epochs,
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        let (later, _, _, _) = policy_application(&fixture, &local_source, 7);
        assert_eq!(later.node(), invited_node);
        later
            .verify_with(&fixture.descriptor, &AllowVerifier, &AllowVerifier)
            .unwrap();
    }

    #[test]
    fn late_member_bootstrap_binds_source_identity_membership_store_and_pkey() {
        let fixture = Fixture::new();
        let transport_identity = vec![0xd0, 0xd1, 0xd2];
        let late_node = NodeId::of_authenticated_peer(&transport_identity);
        let local = PrivateNodeIdentity {
            node: late_node,
            principal: fixture.predecessor.owner,
            transport_identity,
            encryption_public_key: [0x43; 32],
            authority_binding: hash(0xd4),
            transport_signature: [0xd5; 64],
        };
        assert!(local.validate());
        let final_members = vec![local.clone()];
        let source_material = hash(0xd6);
        let bootstrap = || {
            PrivateRuntimeReplicaEstablishment::bind_verified_source(
                &fixture.descriptor,
                &local,
                fixture.predecessor.store,
                &fixture.predecessor.key_epochs,
                &final_members,
                source_material,
            )
            .unwrap()
        };

        let image = PrivateRuntimeImage::genesis_for_established_replica(
            &fixture.descriptor,
            bootstrap(),
            fixture.predecessor.state.clone(),
            fixture.predecessor.store,
            fixture.predecessor.key_epochs.clone(),
            fixture.predecessor.creation_receipt.clone(),
            GENESIS_AT,
            &AllowVerifier,
        )
        .unwrap();
        assert_eq!(image.node(), late_node);
        assert_eq!(image.establishment_origin(), Some(source_material));
        assert_eq!(image.establishment_completion(), None);
        assert_eq!(image.commitment(), image.lineage_commitment());
        assert_eq!(
            image.stable_projection(),
            fixture.predecessor.stable_projection()
        );

        let mut future_store = image.store();
        future_store.object_count = 1;
        future_store.object_root = Some(hash(0xd7));
        assert!(future_store.validate().is_ok());
        assert!(matches!(
            image.seal_replica_establishment(source_material, future_store),
            Err(PrivateRuntimeEvidenceError::InvalidStorePosition)
        ));
        let unsealed_commitment = image.commitment();
        let unsealed_lineage = image.lineage_commitment();
        let expected_completion = PrivateRuntimeImage::replica_establishment_seal(
            source_material,
            image.store().commitment(),
            unsealed_lineage,
        )
        .unwrap();
        let sealed = image
            .seal_replica_establishment(source_material, image.store())
            .unwrap();
        assert_ne!(sealed.commitment(), unsealed_commitment);
        assert_eq!(sealed.lineage_commitment(), unsealed_lineage);
        assert_eq!(sealed.establishment_completion(), Some(expected_completion));
        assert_eq!(
            sealed
                .seal_replica_establishment(source_material, image.store())
                .unwrap(),
            sealed
        );
        assert_eq!(
            PrivateRuntimeImage::decode(&sealed.encode().unwrap()).unwrap(),
            sealed
        );
        let rebound = sealed.rebind_store_objects(future_store).unwrap();
        assert_eq!(rebound.establishment_origin(), Some(source_material));
        assert_eq!(
            rebound.establishment_completion(),
            Some(expected_completion)
        );
        let (_, successor, application, _) = policy_application(&fixture, &sealed, 5);
        assert_eq!(successor.establishment_origin(), Some(source_material));
        assert_eq!(
            successor.establishment_completion(),
            Some(expected_completion)
        );
        assert!(application.matches_predecessor(&sealed));
        assert!(application.matches_successor(&successor));

        let mut substituted_identity = local.clone();
        substituted_identity.encryption_public_key = [0x44; 32];
        assert!(substituted_identity.validate());
        assert!(
            PrivateRuntimeReplicaEstablishment::bind_verified_source(
                &fixture.descriptor,
                &local,
                fixture.predecessor.store,
                &fixture.predecessor.key_epochs,
                &[substituted_identity],
                source_material,
            )
            .is_err()
        );
        assert!(
            PrivateRuntimeReplicaEstablishment::bind_verified_source(
                &fixture.descriptor,
                &local,
                fixture.predecessor.store,
                &fixture.predecessor.key_epochs,
                &final_members,
                Hash::ZERO,
            )
            .is_err()
        );

        let mut descriptor_member = fixture.descriptor.clone();
        descriptor_member.replicas = vec![AgentReplica {
            node: late_node,
            principal: fixture.predecessor.owner,
            role: ReplicaRole::Observer,
        }];
        descriptor_member.validate().unwrap();
        assert!(
            PrivateRuntimeReplicaEstablishment::bind_verified_source(
                &descriptor_member,
                &local,
                fixture.predecessor.store,
                &fixture.predecessor.key_epochs,
                &final_members,
                source_material,
            )
            .is_ok()
        );

        let mut different_store = fixture.predecessor.store;
        different_store.object_count = 1;
        different_store.object_root = Some(hash(0xd8));
        assert!(different_store.validate().is_ok());
        assert!(matches!(
            PrivateRuntimeImage::genesis_for_established_replica(
                &fixture.descriptor,
                bootstrap(),
                fixture.predecessor.state.clone(),
                different_store,
                fixture.predecessor.key_epochs.clone(),
                fixture.predecessor.creation_receipt.clone(),
                GENESIS_AT,
                &AllowVerifier,
            ),
            Err(PrivateRuntimeEvidenceError::InvalidStorePosition)
        ));

        let mut different_key_epochs = fixture.predecessor.key_epochs.clone();
        different_key_epochs[0].exact_wire = hash(0xd9);
        assert!(matches!(
            PrivateRuntimeImage::genesis_for_established_replica(
                &fixture.descriptor,
                bootstrap(),
                fixture.predecessor.state.clone(),
                fixture.predecessor.store,
                different_key_epochs,
                fixture.predecessor.creation_receipt.clone(),
                GENESIS_AT,
                &AllowVerifier,
            ),
            Err(PrivateRuntimeEvidenceError::InvalidKeyEpochs)
        ));

        assert!(matches!(
            PrivateRuntimeImage::genesis_for_established_replica(
                &fixture.descriptor,
                bootstrap(),
                fixture.predecessor.state.clone(),
                fixture.predecessor.store,
                fixture.predecessor.key_epochs.clone(),
                fixture.predecessor.creation_receipt.clone(),
                GENESIS_AT,
                &DenyVerifier,
            ),
            Err(PrivateRuntimeEvidenceError::InvalidAuthority)
        ));
        assert!(
            PrivateRuntimeImage::genesis_for_established_replica(
                &fixture.descriptor,
                bootstrap(),
                RuntimeState {
                    control: Vec::new(),
                    linear: Vec::new(),
                    merge: Vec::new(),
                    local: Vec::new(),
                },
                fixture.predecessor.store,
                fixture.predecessor.key_epochs.clone(),
                fixture.predecessor.creation_receipt.clone(),
                GENESIS_AT,
                &AllowVerifier,
            )
            .is_err()
        );
    }

    #[test]
    fn replica_establishment_completion_tag_binds_final_runtime_lineage() {
        let origin = hash(0xe1);
        let store = hash(0xe2);
        let first_lineage = hash(0xe3);
        let second_lineage = hash(0xe4);
        let first =
            PrivateRuntimeImage::replica_establishment_seal(origin, store, first_lineage).unwrap();
        let second =
            PrivateRuntimeImage::replica_establishment_seal(origin, store, second_lineage).unwrap();
        assert_ne!(first, second);
        assert!(
            PrivateRuntimeImage::replica_establishment_seal(origin, store, Hash::ZERO).is_err()
        );
    }

    #[test]
    fn only_control_lane_may_change_and_divergence_changes_projection() {
        let fixture = Fixture::new();
        let (pending, successor, _, _) = policy_application(&fixture, &fixture.predecessor, 5);
        let success = PrivateRuntimeSuccess::ResourcePolicySet(narrowed_policy());

        let divergent_control = PrivateRuntimeImage::successor(
            &fixture.descriptor,
            &fixture.predecessor,
            &pending,
            &success,
            RuntimeState {
                control: vec![0x87],
                linear: Vec::new(),
                merge: fixture.predecessor.state.merge.clone(),
                local: fixture.predecessor.state.local.clone(),
            },
            fixture.predecessor.key_epochs.clone(),
            &AllowVerifier,
            &AllowVerifier,
        )
        .unwrap();
        assert_ne!(
            successor.stable_projection,
            divergent_control.stable_projection
        );

        for (merge, local) in [(vec![0x88], vec![0x23]), (vec![0x22], vec![0x89])] {
            assert!(
                PrivateRuntimeImage::successor(
                    &fixture.descriptor,
                    &fixture.predecessor,
                    &pending,
                    &success,
                    RuntimeState {
                        control: vec![0x44],
                        linear: Vec::new(),
                        merge,
                        local,
                    },
                    fixture.predecessor.key_epochs.clone(),
                    &AllowVerifier,
                    &AllowVerifier,
                )
                .is_err()
            );
        }

        let mut merge_tamper = successor.clone();
        merge_tamper.state.merge[0] ^= 1;
        assert!(merge_tamper.validate().is_ok());
        assert!(
            pending
                .clone()
                .complete(
                    &fixture.descriptor,
                    &fixture.predecessor,
                    &merge_tamper,
                    success.clone(),
                    &AllowVerifier,
                    &AllowVerifier,
                )
                .is_err()
        );
        let mut local_tamper = successor.clone();
        local_tamper.state.local[0] ^= 1;
        assert!(local_tamper.validate().is_ok());
        assert!(
            pending
                .clone()
                .complete(
                    &fixture.descriptor,
                    &fixture.predecessor,
                    &local_tamper,
                    success,
                    &AllowVerifier,
                    &AllowVerifier,
                )
                .is_err()
        );

        let mut state_tamper = successor;
        state_tamper.state.control[0] ^= 1;
        assert!(state_tamper.validate().is_err());
        assert!(state_tamper.encode().is_err());
    }

    #[test]
    fn store_key_epoch_and_cycle_positions_fail_closed() {
        let fixture = Fixture::new();
        let (control, mutation) = policy_control(&fixture);
        let receipt = fixture.receipt(
            AuthorityOperationKind::SetPrivateResourcePolicy,
            control.commitment(),
            None,
        );
        let mut wrong_store = successor_store(
            fixture.predecessor.store,
            &control,
            fixture.predecessor.store.key_epoch_root,
            0x8a,
        );
        wrong_store.next_sequence += 1;
        assert!(wrong_store.validate().is_ok());
        assert!(
            PrivateRuntimeApplication::pending(
                &fixture.descriptor,
                &fixture.predecessor,
                control,
                Some(mutation),
                None,
                receipt.clone(),
                fixture.issuance(receipt),
                5,
                wrong_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );

        let mut later_predecessor = fixture.predecessor.clone();
        later_predecessor.applied_at = 10;
        assert!(later_predecessor.validate().is_ok());
        let (control, mutation) = policy_control(&fixture);
        let receipt = fixture.receipt(
            AuthorityOperationKind::SetPrivateResourcePolicy,
            control.commitment(),
            None,
        );
        let expected_store = successor_store(
            later_predecessor.store,
            &control,
            later_predecessor.store.key_epoch_root,
            0x8c,
        );
        assert!(
            PrivateRuntimeApplication::pending(
                &fixture.descriptor,
                &later_predecessor,
                control,
                Some(mutation),
                None,
                receipt.clone(),
                fixture.issuance(receipt),
                5,
                expected_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );

        let jumped_epoch = key_epoch(
            fixture.predecessor.managed.space,
            fixture.predecessor.managed.agent,
            2,
            fixture.node_a,
            0x8d,
        );
        let rotate = PrivateControlRecord {
            space: fixture.predecessor.managed.space,
            agent: fixture.predecessor.managed.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::RotateKeys {
                next_epoch: jumped_epoch.clone(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x8e; 32],
            signature: [0x8f; 64],
        };
        let mut jumped_commitments = fixture.predecessor.key_epochs.clone();
        jumped_commitments.push(PrivateKeyEpochCommitment::from_epoch(&jumped_epoch).unwrap());
        let jumped_store = successor_store(
            fixture.predecessor.store,
            &rotate,
            private_key_epoch_root(&jumped_commitments).unwrap(),
            0x90,
        );
        let receipt = fixture.receipt(
            AuthorityOperationKind::RotatePrivateKeys,
            rotate.commitment(),
            None,
        );
        assert!(
            PrivateRuntimeApplication::pending(
                &fixture.descriptor,
                &fixture.predecessor,
                rotate,
                None,
                None,
                receipt.clone(),
                fixture.issuance(receipt),
                5,
                jumped_store,
                &AllowVerifier,
                &AllowVerifier,
            )
            .is_err()
        );

        let (pending, mut successor, completed, _) =
            policy_application(&fixture, &fixture.predecessor, 5);
        successor.key_epochs[0].exact_wire = hash(0x8b);
        assert!(successor.validate().is_err());

        let stable_store = pending.expected_successor_store.commitment();
        let stable_image = completed.successor_runtime_image().unwrap();
        assert_ne!(pending.commitment(), completed.commitment());
        assert_eq!(
            stable_store,
            completed.expected_successor_store.commitment()
        );
        assert_eq!(stable_image, completed.successor_runtime_image().unwrap());
    }

    #[test]
    fn route_descriptor_and_store_substitution_are_detected() {
        let fixture = Fixture::new();
        let (_, successor, completed, _) = policy_application(&fixture, &fixture.predecessor, 5);

        let mut shared_projection = fixture.predecessor.stable_projection.clone();
        shared_projection.managed.profile = AgentProfile::Shared;
        assert_eq!(
            shared_projection.validate(),
            Err(PrivateRuntimeEvidenceError::InvalidProjection)
        );
        let mut shared_image = fixture.predecessor.clone();
        shared_image.managed.profile = AgentProfile::Shared;
        shared_image.stable_projection.managed.profile = AgentProfile::Shared;
        assert_eq!(
            shared_image.validate(),
            Err(PrivateRuntimeEvidenceError::InvalidProjection)
        );
        let mut shared_application = completed.clone();
        shared_application.managed.profile = AgentProfile::Shared;
        assert_eq!(
            shared_application.validate(),
            Err(PrivateRuntimeEvidenceError::InvalidApplication)
        );

        // A decoded image can be internally self-consistent while relabeling
        // its portable transition signer. Reopening must bind the complete
        // descriptor-derived target, not just space/agent/runtime deployment.
        let mut wrong_transition_producer = fixture.predecessor.clone();
        wrong_transition_producer.managed.transition_producer.0[0] ^= 1;
        wrong_transition_producer
            .stable_projection
            .managed
            .transition_producer = wrong_transition_producer.managed.transition_producer;
        assert_eq!(wrong_transition_producer.validate(), Ok(()));
        assert_eq!(
            wrong_transition_producer.reopen_with(&fixture.descriptor, &AllowVerifier),
            Err(PrivateRuntimeEvidenceError::InvalidDescriptor)
        );

        let mut wrong_descriptor = fixture.descriptor.clone();
        wrong_descriptor.runtime_package = BlobRef::of_bytes(b"different-private-runtime");
        wrong_descriptor.validate().unwrap();
        let descriptor_image = PrivateRuntimeImage::genesis(
            &wrong_descriptor,
            fixture.node_a,
            fixture.predecessor.state.clone(),
            fixture.predecessor.store,
            fixture.predecessor.key_epochs.clone(),
            Fixture::creation_receipt_for(&wrong_descriptor),
            fixture.predecessor.applied_at,
            &AllowVerifier,
        )
        .unwrap();
        assert_ne!(
            fixture.predecessor.stable_projection,
            descriptor_image.stable_projection
        );
        assert!(
            completed
                .verify_with(&wrong_descriptor, &AllowVerifier, &AllowVerifier)
                .is_err()
        );

        let mut other_route = fixture.descriptor.clone();
        other_route.identity.space = SpaceId([0x8c; 32]);
        other_route.identity.agent = AgentId::derive(
            other_route.identity.space,
            other_route.identity.owner,
            other_route.creation_nonce.as_bytes(),
        );
        other_route.validate().unwrap();
        let route_epoch = key_epoch(
            other_route.identity.space,
            other_route.identity.agent,
            0,
            fixture.node_a,
            0x8d,
        );
        let route_epochs = vec![PrivateKeyEpochCommitment::from_epoch(&route_epoch).unwrap()];
        let route_store =
            initial_store(&other_route, private_key_epoch_root(&route_epochs).unwrap());
        let route_image = PrivateRuntimeImage::genesis(
            &other_route,
            fixture.node_a,
            fixture.predecessor.state.clone(),
            route_store,
            route_epochs,
            Fixture::creation_receipt_for(&other_route),
            fixture.predecessor.applied_at,
            &AllowVerifier,
        )
        .unwrap();
        assert_ne!(
            fixture.predecessor.stable_projection,
            route_image.stable_projection
        );

        let substituted_store = PrivateStoreCorePosition::new(
            successor.store.space,
            successor.store.agent,
            successor.store.owner,
            successor.store.epoch,
            successor.store.control_head,
            successor.store.next_sequence,
            successor.store.object_count,
            successor.store.object_root,
            successor.store.control_count,
            Some(hash(0x8e)),
            successor.store.key_epoch_root,
        )
        .unwrap();
        assert!(PrivateControlReopenedState::new(completed, substituted_store, successor).is_err());
    }

    #[test]
    fn malformed_state_projection_and_key_order_are_rejected() {
        let fixture = Fixture::new();
        let mut non_private_lane = fixture.predecessor.clone();
        non_private_lane.state.linear.push(1);
        assert!(non_private_lane.validate().is_err());

        let mut wrong_projection_generation = fixture.predecessor.clone();
        wrong_projection_generation.stable_projection.generation = 1;
        wrong_projection_generation.stable_projection.previous = Some(hash(0x8f));
        wrong_projection_generation.stable_projection.control_head = Some(hash(0x90));
        wrong_projection_generation
            .stable_projection
            .control_sequence = Some(0);
        wrong_projection_generation.stable_projection.full_replay = Some(hash(0x91));
        wrong_projection_generation.stable_projection.disposition = Some(hash(0x92));
        assert!(
            wrong_projection_generation
                .stable_projection
                .validate()
                .is_ok()
        );
        assert!(wrong_projection_generation.validate().is_err());

        let mut duplicate_epoch = fixture.predecessor.clone();
        duplicate_epoch
            .key_epochs
            .push(duplicate_epoch.key_epochs[0]);
        assert!(duplicate_epoch.validate().is_err());
    }
}
