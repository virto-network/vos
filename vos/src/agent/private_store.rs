//! Durable ciphertext-only storage for Private agents.
//!
//! The store accepts canonical [`EncryptedPrivateObject`] and
//! [`PrivateControlRecord`] values only. It has no API for plaintext or
//! unwrapped owner, data, node, or recovery keys. An immutable public genesis
//! record bootstraps verification; a sorted index is advanced with each
//! artifact through a durable stage -> artifact -> index/head transaction.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use vos_agent_sdk::authority_operation::{
    MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
    MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES,
    MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES,
};
use vos_agent_sdk::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_NODES, PrivateControlOperation,
    PrivateControlRecord, PrivateControlSigner, PrivateKeyEpoch, PrivateNodeIdentity,
    PrivateRecoveryKeyringGrant,
};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES,
    MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES, MAX_PRIVATE_OBJECT_WIRE_BYTES,
};
use vos_agent_sdk::{AgentId, Hash, PrincipalId, RUNTIME_ABI_ID, SpaceId};

use super::private_crypto::{
    MAX_PRIVATE_CONTROL_RECORDS, PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES,
    PrivateControlChainVerifier, PrivateCryptoError, PrivateNodeAuthorityVerifier,
};
use super::private_runtime::{
    MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES, PrivateKeyEpochCommitment,
    PrivateRuntimeApplication, PrivateStoreCorePosition, private_key_epoch_root,
};

pub const MAX_PRIVATE_STORE_OBJECTS: usize = 16_384;
pub const MAX_PRIVATE_STORE_CONTROLS: usize = MAX_PRIVATE_CONTROL_RECORDS as usize;
pub const MAX_PRIVATE_STORE_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PRIVATE_STORE_INDEX_BYTES: usize = 48 * 1024 * 1024;
/// Exact maximum PSE2 framing: magic/version, AOI1, PCA2, recovery-proof tag,
/// and an optional canonical PRA1. Normal controls use the same frame with an
/// absent proof; Recover controls require the full third field.
pub const MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES: usize = 4
    + 2
    + 4
    + MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
    + 4
    + MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES
    + 1
    + 4
    + MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES;
pub const MAX_PRIVATE_RECOVERY_METADATA_BYTES: usize = MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES
    + MAX_PRIVATE_NODES * MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES
    + 512;
pub const MAX_PRIVATE_BACKUP_BYTES: usize = 128 * 1024 * 1024;

const FORMAT_VERSION: u16 = 1;
const RECOVERY_MAGIC: &[u8; 4] = b"PVRM";
// Generation-three Store wires add an indexed public PAPL attachment to each
// control row. Distinct magics fail closed on every older index, transaction,
// snapshot, and backup layout rather than ambiguously parsing a suffix.
const INDEX_MAGIC: &[u8; 4] = b"PVI3";
const TRANSACTION_MAGIC: &[u8; 4] = b"PVT3";
const SNAPSHOT_MAGIC: &[u8; 4] = b"PVS3";
const BACKUP_MAGIC: &[u8; 4] = b"PVB3";
const RAW_WIRE_DOMAIN: &[u8] = b"vos/private/stored-wire/v1";
const OBJECT_INDEX_ENTRY_DOMAIN: &[u8] = b"vos/agent/private-store/object-index-entry/v1";
const OBJECT_INDEX_ROOT_DOMAIN: &[u8] = b"vos/agent/private-store/object-index-root/v1";
const CONTROL_INDEX_ENTRY_DOMAIN: &[u8] = b"vos/agent/private-store/control-index-entry/v1";
const CONTROL_INDEX_ROOT_DOMAIN: &[u8] = b"vos/agent/private-store/control-index-root/v1";
const RECOVERY_FILE: &str = "recovery.meta";
const INDEX_FILE: &str = "index";
const LOCK_FILE: &str = "lock";
const OBJECTS_DIR: &str = "objects";
const CONTROLS_DIR: &str = "controls";
const RUNTIME_APPLICATIONS_DIR: &str = "runtime-applications";
const CONTROL_EVIDENCE_DIR: &str = "control-authority-evidence";
const STAGE_DIR: &str = "stage";
const STAGED_ARTIFACT: &str = "artifact.next";
const STAGED_RUNTIME_APPLICATION: &str = "runtime-application.next";
const STAGED_INDEX: &str = "index.next";
const PENDING_FILE: &str = "pending";
const STAGED_CONTROL_EVIDENCE: &str = "control-authority-evidence.next";
const STAGED_STABLE_IMPORT_CERTIFICATE: &str = "stable-import-certificate.next";
const PENDING_CONTROL_EVIDENCE: &str = "control-authority-evidence.pending";
// PVE2 binds an optional destination-authenticated PSI1 to the same durable
// terminal attachment transaction as its exact source PSE2.
const CONTROL_EVIDENCE_PENDING_MAGIC: &[u8; 4] = b"PVE2";
const MAX_PENDING_CONTROL_EVIDENCE_BYTES: usize = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateStoreError {
    Io,
    Busy,
    AlreadyExists,
    NotFound,
    Corrupt,
    InvalidScope,
    InvalidRecord,
    InvalidBinding,
    LimitExceeded,
    Alias,
    Rollback,
    Diverged,
    Interrupted,
    Crypto(PrivateCryptoError),
}

impl fmt::Display for PrivateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Private-agent store operation failed: {self:?}")
    }
}

impl core::error::Error for PrivateStoreError {}

impl From<PrivateCryptoError> for PrivateStoreError {
    fn from(error: PrivateCryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutDisposition {
    Inserted,
    AlreadyPresent,
}

/// Filesystem-independent result of planning one exact Private control.
///
/// An exact retry projects the current position with `AlreadyPresent`; a new
/// control projects the position that the durable append will publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlPositionPreview {
    disposition: PutDisposition,
    position: PrivateStoreCorePosition,
    key_epoch_commitments: Vec<PrivateKeyEpochCommitment>,
    authorized_nodes: Vec<PrivateNodeIdentity>,
}

impl PrivateControlPositionPreview {
    pub(crate) const fn disposition(&self) -> PutDisposition {
        self.disposition
    }

    pub(crate) const fn position(&self) -> PrivateStoreCorePosition {
        self.position
    }

    /// Exact projected public PKEY commitments produced by the Store's one
    /// control-transition planner; no unwrapped key material is exposed.
    pub(crate) fn key_epoch_commitments(&self) -> &[PrivateKeyEpochCommitment] {
        &self.key_epoch_commitments
    }

    /// Exact projected authorized membership produced by the Store's one
    /// control-transition planner.
    pub(crate) fn authorized_nodes(&self) -> &[PrivateNodeIdentity] {
        &self.authorized_nodes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreDisposition {
    Restored,
    AlreadyPresent,
}

/// Canonical semantic address of one encrypted object. A second ciphertext at
/// the same `(epoch, kind, epoch-keyed content identity)` is an alias and is
/// rejected rather than silently replacing the first representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateObjectKey {
    pub epoch: u64,
    pub kind: u8,
    pub content: Hash,
}

impl PrivateObjectKey {
    pub fn from_object(object: &EncryptedPrivateObject) -> Self {
        Self {
            epoch: object.epoch,
            kind: encrypted_kind_tag(object.kind),
            content: object.content,
        }
    }

    pub fn encrypted_kind(self) -> Result<EncryptedObjectKind, PrivateStoreError> {
        encrypted_kind_from_tag(self.kind).ok_or(PrivateStoreError::Corrupt)
    }

    fn validate(self) -> bool {
        encrypted_kind_from_tag(self.kind).is_some() && self.content != Hash::ZERO
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateStoreBinding {
    pub space: SpaceId,
    pub agent: AgentId,
    pub owner: PrincipalId,
    pub epoch: u64,
    pub control_head: Option<Hash>,
    pub next_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredObjectIndex {
    pub key: PrivateObjectKey,
    pub wire_hash: Hash,
    pub wire_len: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredControlIndex {
    pub sequence: u64,
    pub commitment: Hash,
    pub previous: Option<Hash>,
    pub resulting_epoch: u64,
    pub superseded_heads: Vec<Hash>,
    pub wire_hash: Hash,
    pub wire_len: u32,
    /// Public completed PAPL attached by the atomic control transaction.
    /// This binding is durable and authenticated by the index, but is
    /// intentionally excluded from the cycle-free PSC1 control root.
    pub runtime_application: Option<StoredRuntimeApplicationIndex>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredRuntimeApplicationIndex {
    pub control: Hash,
    pub application: Hash,
    pub wire_hash: Hash,
    pub wire_len: u32,
    pub successor_runtime_image: Hash,
    pub successor_stable_projection: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoveryMetadata {
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    recovery_public_key: [u8; 32],
    recovery_encryption_public_key: [u8; 32],
    genesis_epoch: PrivateKeyEpoch,
    genesis_nodes: Vec<PrivateNodeIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoreIndex {
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    control_head: Option<Hash>,
    next_sequence: u64,
    objects: Vec<StoredObjectIndex>,
    controls: Vec<StoredControlIndex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingArtifact {
    Object(PrivateObjectKey),
    Control(Hash),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingTransaction {
    artifact: PendingArtifact,
    artifact_hash: Hash,
    artifact_len: u32,
    previous_index_hash: Hash,
    previous_index_len: u32,
    next_index_hash: Hash,
    next_index_len: u32,
    runtime_application: Option<StoredRuntimeApplicationIndex>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingControlEvidence {
    control: Hash,
    evidence_hash: Hash,
    evidence_len: u32,
    stable_import_certificate: Option<PendingStableImportCertificate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStableImportCertificate {
    wire_hash: Hash,
    wire_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlEvidenceAttachmentMode {
    Ordinary,
    AuthenticatedRestore,
}

/// Control-chain-authenticated, bounded ciphertext archive held only while an
/// offline recovery ceremony prepares its exact successor. It deliberately
/// exposes sealed epoch metadata but no API for plaintext or unwrapped keys.
/// Public PAPL rows are canonical and PSC-bound at this layer; a physical host
/// must still authenticate their descriptor authority, PVRI, and node/PKEY
/// correspondence before consuming them.
pub(crate) struct VerifiedEncryptedBackup {
    metadata: RecoveryMetadata,
    index: StoreIndex,
    controls: Vec<PrivateControlRecord>,
    /// One exact PSE2 envelope per control when coordinator attachment had
    /// completed. `None` is a crash-valid intermediate state and is retained
    /// so recovery never fabricates authority evidence.
    control_evidence: Vec<Option<Vec<u8>>>,
    /// Public, canonical completed PAPL values. Encrypted PVRI bytes remain a
    /// host-archive concern and never enter this Store-owned archive.
    runtime_applications: Vec<Option<PrivateRuntimeApplication>>,
    objects: Vec<EncryptedPrivateObject>,
    key_epochs: Vec<PrivateKeyEpoch>,
    chain: PrivateControlChainVerifier,
}

/// Bounded, canonical genesis metadata decoded from an encrypted backup
/// before the backup's independently selected descriptor has been opened.
///
/// This value is deliberately named a claim: its recovery keys are suitable
/// only as inputs to [`verify_encrypted_backup`]. A physical importer must
/// subsequently authenticate the decrypted descriptor/Create receipt and
/// require their immutable recovery binding to equal these exact keys before
/// it writes any destination state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EncryptedBackupGenesisClaim {
    recovery_public_key: [u8; 32],
    recovery_encryption_public_key: [u8; 32],
}

impl EncryptedBackupGenesisClaim {
    pub(crate) const fn recovery_public_key(self) -> [u8; 32] {
        self.recovery_public_key
    }

    pub(crate) const fn recovery_encryption_public_key(self) -> [u8; 32] {
        self.recovery_encryption_public_key
    }
}

/// Complete source material for replaying one archived control locally.
///
/// Construction proves only that all three archive attachments are present
/// and retain their exact Store/index bindings. In particular, the PAPL is
/// not PVRI- or authority-authenticated here, and the PSE remains opaque
/// source bytes until a physical host verifies it.
pub(crate) struct EncryptedBackupReplayRow<'a> {
    index: &'a StoredControlIndex,
    control: &'a PrivateControlRecord,
    source_runtime_application: &'a PrivateRuntimeApplication,
    source_authority_evidence: &'a [u8],
}

impl<'a> EncryptedBackupReplayRow<'a> {
    pub(crate) const fn index(&self) -> &'a StoredControlIndex {
        self.index
    }

    pub(crate) const fn control(&self) -> &'a PrivateControlRecord {
        self.control
    }

    pub(crate) const fn source_runtime_application(&self) -> &'a PrivateRuntimeApplication {
        self.source_runtime_application
    }

    pub(crate) const fn source_authority_evidence(&self) -> &'a [u8] {
        self.source_authority_evidence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitStop {
    Never,
    #[cfg(test)]
    AfterStagedArtifact,
    #[cfg(test)]
    AfterStagedRuntimeApplication,
    #[cfg(test)]
    AfterStagedIndex,
    #[cfg(test)]
    AfterPending,
    #[cfg(test)]
    AfterStage,
    #[cfg(test)]
    AfterArtifact,
    #[cfg(test)]
    AfterRuntimeApplication,
    #[cfg(test)]
    AfterIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlEvidenceCommitStop {
    Never,
    #[cfg(test)]
    AfterEvidenceStaged,
    #[cfg(test)]
    AfterStaged,
    #[cfg(test)]
    AfterPending,
    #[cfg(test)]
    AfterCertificatePublished,
    #[cfg(test)]
    AfterPublished,
    #[cfg(test)]
    AfterRetired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlPlanMode {
    /// Append/preview semantics accept an exact already-present control before
    /// checking the capacity limit.
    Append,
    /// Preserve the legacy `validate_next_control` contract: only a genuinely
    /// new sequence is accepted, with the capacity check taking precedence.
    ValidateNew,
}

enum ControlTransitionPlan {
    AlreadyPresent { index: usize, wire: Vec<u8> },
    Insert(PlannedControlTransition),
}

struct PlannedControlTransition {
    commitment: Hash,
    wire: Vec<u8>,
    next_chain: PrivateControlChainVerifier,
    next_key_epochs: Vec<PrivateKeyEpoch>,
    next_recovery_keyring: Option<PrivateRecoveryKeyringGrant>,
    next_index: StoreIndex,
    successor: PrivateStoreCorePosition,
}

struct Encoder(Vec<u8>);

impl Encoder {
    fn new(magic: &[u8; 4]) -> Self {
        let mut bytes = Vec::with_capacity(256);
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

    fn bytes(&mut self, value: &[u8]) -> Result<(), PrivateStoreError> {
        self.u32(u32::try_from(value.len()).map_err(|_| PrivateStoreError::LimitExceeded)?);
        self.0.extend_from_slice(value);
        Ok(())
    }

    fn finish(self, max: usize) -> Result<Vec<u8>, PrivateStoreError> {
        if self.0.len() > max {
            return Err(PrivateStoreError::LimitExceeded);
        }
        Ok(self.0)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 4], max: usize) -> Result<Self, PrivateStoreError> {
        if bytes.len() > max || bytes.len() < 6 || bytes.get(..4) != Some(magic) {
            return Err(PrivateStoreError::Corrupt);
        }
        let version = u16::from_le_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| PrivateStoreError::Corrupt)?,
        );
        if version != FORMAT_VERSION {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(Self { bytes, offset: 6 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PrivateStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PrivateStoreError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrivateStoreError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PrivateStoreError> {
        Ok(*self.take(1)?.first().ok_or(PrivateStoreError::Corrupt)?)
    }

    fn u16(&mut self) -> Result<u16, PrivateStoreError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PrivateStoreError::Corrupt)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, PrivateStoreError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PrivateStoreError::Corrupt)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, PrivateStoreError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PrivateStoreError::Corrupt)?,
        ))
    }

    fn fixed(&mut self) -> Result<[u8; 32], PrivateStoreError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PrivateStoreError::Corrupt)
    }

    fn optional_hash(&mut self) -> Result<Option<Hash>, PrivateStoreError> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let hash = Hash(self.fixed()?);
                if hash == Hash::ZERO {
                    return Err(PrivateStoreError::Corrupt);
                }
                Ok(Some(hash))
            }
            _ => Err(PrivateStoreError::Corrupt),
        }
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, PrivateStoreError> {
        let length = usize::try_from(self.u32()?).map_err(|_| PrivateStoreError::Corrupt)?;
        if length > max {
            return Err(PrivateStoreError::LimitExceeded);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<(), PrivateStoreError> {
        if self.offset != self.bytes.len() {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(())
    }
}

fn encrypted_kind_tag(kind: EncryptedObjectKind) -> u8 {
    kind as u8
}

fn encrypted_kind_from_tag(tag: u8) -> Option<EncryptedObjectKind> {
    match tag {
        0 => Some(EncryptedObjectKind::CrdtNode),
        1 => Some(EncryptedObjectKind::Package),
        2 => Some(EncryptedObjectKind::Blob),
        3 => Some(EncryptedObjectKind::Index),
        4 => Some(EncryptedObjectKind::Snapshot),
        5 => Some(EncryptedObjectKind::Control),
        _ => None,
    }
}

fn encode_object_key(encoder: &mut Encoder, key: PrivateObjectKey) {
    encoder.u64(key.epoch);
    encoder.u8(key.kind);
    encoder.fixed(key.content.as_bytes());
}

fn decode_object_key(decoder: &mut Decoder<'_>) -> Result<PrivateObjectKey, PrivateStoreError> {
    let key = PrivateObjectKey {
        epoch: decoder.u64()?,
        kind: decoder.u8()?,
        content: Hash(decoder.fixed()?),
    };
    key.validate()
        .then_some(key)
        .ok_or(PrivateStoreError::Corrupt)
}

fn raw_wire_hash(bytes: &[u8]) -> Hash {
    Hash::digest(RAW_WIRE_DOMAIN, &[bytes])
}

fn framed_index_root(domain: &[u8], entries: &[Hash]) -> Result<Option<Hash>, PrivateStoreError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let count = u32::try_from(entries.len()).map_err(|_| PrivateStoreError::LimitExceeded)?;
    let capacity = entries
        .len()
        .checked_mul(4 + 32)
        .and_then(|bytes| bytes.checked_add(4))
        .ok_or(PrivateStoreError::LimitExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    let mut encoder = Encoder(bytes);
    encoder.u32(count);
    for entry in entries {
        encoder.bytes(entry.as_bytes())?;
    }
    Ok(Some(Hash::digest(
        domain,
        &[RUNTIME_ABI_ID.as_bytes(), &encoder.0],
    )))
}

fn object_index_root(entries: &[StoredObjectIndex]) -> Result<Option<Hash>, PrivateStoreError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut commitments = Vec::new();
    commitments
        .try_reserve_exact(entries.len())
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for entry in entries {
        let mut encoder = Encoder(Vec::with_capacity(8 + 1 + 32 + 32 + 4));
        encode_object_key(&mut encoder, entry.key);
        encoder.fixed(entry.wire_hash.as_bytes());
        encoder.u32(entry.wire_len);
        commitments.push(Hash::digest(
            OBJECT_INDEX_ENTRY_DOMAIN,
            &[RUNTIME_ABI_ID.as_bytes(), &encoder.0],
        ));
    }
    framed_index_root(OBJECT_INDEX_ROOT_DOMAIN, &commitments)
}

fn control_index_root(entries: &[StoredControlIndex]) -> Result<Option<Hash>, PrivateStoreError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut commitments = Vec::new();
    commitments
        .try_reserve_exact(entries.len())
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for entry in entries {
        let superseded_count = u32::try_from(entry.superseded_heads.len())
            .map_err(|_| PrivateStoreError::LimitExceeded)?;
        let capacity = entry
            .superseded_heads
            .len()
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(8 + 1 + 32 + 8 + 4 + 32 + 32 + 4))
            .ok_or(PrivateStoreError::LimitExceeded)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PrivateStoreError::LimitExceeded)?;
        let mut encoder = Encoder(bytes);
        encoder.u64(entry.sequence);
        encoder.fixed(entry.commitment.as_bytes());
        encoder.optional_hash(entry.previous);
        encoder.u64(entry.resulting_epoch);
        encoder.u32(superseded_count);
        for head in &entry.superseded_heads {
            encoder.fixed(head.as_bytes());
        }
        encoder.fixed(entry.wire_hash.as_bytes());
        encoder.u32(entry.wire_len);
        commitments.push(Hash::digest(
            CONTROL_INDEX_ENTRY_DOMAIN,
            &[RUNTIME_ABI_ID.as_bytes(), &encoder.0],
        ));
    }
    framed_index_root(CONTROL_INDEX_ROOT_DOMAIN, &commitments)
}

fn store_core_position(
    metadata: &RecoveryMetadata,
    index: &StoreIndex,
    key_epochs: &[PrivateKeyEpoch],
) -> Result<PrivateStoreCorePosition, PrivateStoreError> {
    validate_index_shape(index)?;
    if metadata.space != index.space
        || metadata.agent != index.agent
        || key_epochs.is_empty()
        || key_epochs.first().map(|epoch| epoch.epoch) != Some(0)
        || key_epochs.last().map(|epoch| epoch.epoch) != Some(index.epoch)
        || (index.controls.is_empty()
            && key_epochs != core::slice::from_ref(&metadata.genesis_epoch))
        || key_epochs.iter().any(|epoch| {
            !epoch.validate() || epoch.space != metadata.space || epoch.agent != metadata.agent
        })
        || key_epochs
            .windows(2)
            .any(|pair| pair[0].epoch >= pair[1].epoch)
    {
        return Err(PrivateStoreError::Corrupt);
    }
    let object_count =
        u32::try_from(index.objects.len()).map_err(|_| PrivateStoreError::LimitExceeded)?;
    let control_count =
        u32::try_from(index.controls.len()).map_err(|_| PrivateStoreError::LimitExceeded)?;
    let key_commitments = private_key_epoch_commitments(key_epochs)?;
    let key_epoch_root =
        private_key_epoch_root(&key_commitments).map_err(|_| PrivateStoreError::Corrupt)?;
    PrivateStoreCorePosition::new(
        index.space,
        index.agent,
        metadata.owner,
        index.epoch,
        index.control_head,
        index.next_sequence,
        object_count,
        object_index_root(&index.objects)?,
        control_count,
        control_index_root(&index.controls)?,
        key_epoch_root,
    )
    .map_err(|_| PrivateStoreError::Corrupt)
}

fn private_key_epoch_commitments(
    key_epochs: &[PrivateKeyEpoch],
) -> Result<Vec<PrivateKeyEpochCommitment>, PrivateStoreError> {
    let mut commitments = Vec::new();
    commitments
        .try_reserve_exact(key_epochs.len())
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for epoch in key_epochs {
        commitments.push(
            PrivateKeyEpochCommitment::from_epoch(epoch).map_err(|_| PrivateStoreError::Corrupt)?,
        );
    }
    Ok(commitments)
}

fn encode_recovery(metadata: &RecoveryMetadata) -> Result<Vec<u8>, PrivateStoreError> {
    let epoch = metadata
        .genesis_epoch
        .encode()
        .map_err(|_| PrivateStoreError::InvalidRecord)?;
    let mut encoder = Encoder::new(RECOVERY_MAGIC);
    encoder.fixed(metadata.space.as_bytes());
    encoder.fixed(metadata.agent.as_bytes());
    encoder.fixed(metadata.owner.as_bytes());
    encoder.0.extend_from_slice(&metadata.recovery_public_key);
    encoder
        .0
        .extend_from_slice(&metadata.recovery_encryption_public_key);
    encoder.bytes(&epoch)?;
    encoder.u16(
        u16::try_from(metadata.genesis_nodes.len())
            .map_err(|_| PrivateStoreError::LimitExceeded)?,
    );
    for node in &metadata.genesis_nodes {
        let bytes = node
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?;
        encoder.bytes(&bytes)?;
    }
    encoder.finish(MAX_PRIVATE_RECOVERY_METADATA_BYTES)
}

fn decode_recovery(bytes: &[u8]) -> Result<RecoveryMetadata, PrivateStoreError> {
    let mut decoder = Decoder::new(bytes, RECOVERY_MAGIC, MAX_PRIVATE_RECOVERY_METADATA_BYTES)?;
    let space = SpaceId(decoder.fixed()?);
    let agent = AgentId(decoder.fixed()?);
    let owner = PrincipalId(decoder.fixed()?);
    let recovery_public_key = decoder.fixed()?;
    let recovery_encryption_public_key = decoder.fixed()?;
    let epoch_bytes = decoder.bytes(MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES)?;
    let genesis_epoch =
        PrivateKeyEpoch::decode(&epoch_bytes).map_err(|_| PrivateStoreError::InvalidRecord)?;
    let node_count = usize::from(decoder.u16()?);
    if node_count == 0 || node_count > MAX_PRIVATE_NODES {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let mut genesis_nodes = Vec::new();
    genesis_nodes
        .try_reserve(node_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for _ in 0..node_count {
        let node_bytes = decoder.bytes(MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES)?;
        genesis_nodes.push(
            PrivateNodeIdentity::decode(&node_bytes)
                .map_err(|_| PrivateStoreError::InvalidRecord)?,
        );
    }
    decoder.finish()?;
    if space == SpaceId::ZERO
        || agent == AgentId::ZERO
        || owner == PrincipalId::ZERO
        || recovery_public_key == [0; 32]
        || recovery_encryption_public_key == [0; 32]
        || genesis_epoch.space != space
        || genesis_epoch.agent != agent
        || genesis_epoch.epoch != 0
        || genesis_epoch.recovery_encryption_public_key != recovery_encryption_public_key
        || genesis_nodes
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
    {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(RecoveryMetadata {
        space,
        agent,
        owner,
        recovery_public_key,
        recovery_encryption_public_key,
        genesis_epoch,
        genesis_nodes,
    })
}

fn encode_index(index: &StoreIndex) -> Result<Vec<u8>, PrivateStoreError> {
    validate_index_shape(index)?;
    let mut encoder = Encoder::new(INDEX_MAGIC);
    encoder.fixed(index.space.as_bytes());
    encoder.fixed(index.agent.as_bytes());
    encoder.u64(index.epoch);
    encoder.optional_hash(index.control_head);
    encoder.u64(index.next_sequence);
    encoder.u32(u32::try_from(index.objects.len()).map_err(|_| PrivateStoreError::LimitExceeded)?);
    for entry in &index.objects {
        encode_object_key(&mut encoder, entry.key);
        encoder.fixed(entry.wire_hash.as_bytes());
        encoder.u32(entry.wire_len);
    }
    encoder.u32(u32::try_from(index.controls.len()).map_err(|_| PrivateStoreError::LimitExceeded)?);
    for entry in &index.controls {
        encoder.u64(entry.sequence);
        encoder.fixed(entry.commitment.as_bytes());
        encoder.optional_hash(entry.previous);
        encoder.u64(entry.resulting_epoch);
        encoder.u16(
            u16::try_from(entry.superseded_heads.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
        );
        for head in &entry.superseded_heads {
            encoder.fixed(head.as_bytes());
        }
        encoder.fixed(entry.wire_hash.as_bytes());
        encoder.u32(entry.wire_len);
        match entry.runtime_application {
            None => encoder.u8(0),
            Some(application) => {
                encoder.u8(1);
                encode_runtime_application_index(&mut encoder, application);
            }
        }
    }
    encoder.finish(MAX_PRIVATE_STORE_INDEX_BYTES)
}

fn decode_index(bytes: &[u8]) -> Result<StoreIndex, PrivateStoreError> {
    let mut decoder = Decoder::new(bytes, INDEX_MAGIC, MAX_PRIVATE_STORE_INDEX_BYTES)?;
    let space = SpaceId(decoder.fixed()?);
    let agent = AgentId(decoder.fixed()?);
    let epoch = decoder.u64()?;
    let control_head = decoder.optional_hash()?;
    let next_sequence = decoder.u64()?;
    let object_count = usize::try_from(decoder.u32()?).map_err(|_| PrivateStoreError::Corrupt)?;
    if object_count > MAX_PRIVATE_STORE_OBJECTS {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let mut objects = Vec::new();
    objects
        .try_reserve(object_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for _ in 0..object_count {
        let entry = StoredObjectIndex {
            key: decode_object_key(&mut decoder)?,
            wire_hash: Hash(decoder.fixed()?),
            wire_len: decoder.u32()?,
        };
        if !stored_object_index_shape_is_valid(&entry) {
            return Err(PrivateStoreError::Corrupt);
        }
        objects.push(entry);
    }
    let control_count = usize::try_from(decoder.u32()?).map_err(|_| PrivateStoreError::Corrupt)?;
    if control_count > MAX_PRIVATE_STORE_CONTROLS {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let mut controls = Vec::new();
    controls
        .try_reserve(control_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for _ in 0..control_count {
        let sequence = decoder.u64()?;
        let commitment = Hash(decoder.fixed()?);
        let previous = decoder.optional_hash()?;
        let resulting_epoch = decoder.u64()?;
        let superseded_count = usize::from(decoder.u16()?);
        if superseded_count > MAX_PRIVATE_NODES {
            return Err(PrivateStoreError::LimitExceeded);
        }
        let mut superseded_heads = Vec::new();
        superseded_heads
            .try_reserve(superseded_count)
            .map_err(|_| PrivateStoreError::LimitExceeded)?;
        for _ in 0..superseded_count {
            let head = Hash(decoder.fixed()?);
            if head == Hash::ZERO {
                return Err(PrivateStoreError::Corrupt);
            }
            superseded_heads.push(head);
        }
        let entry = StoredControlIndex {
            sequence,
            commitment,
            previous,
            resulting_epoch,
            superseded_heads,
            wire_hash: Hash(decoder.fixed()?),
            wire_len: decoder.u32()?,
            runtime_application: match decoder.u8()? {
                0 => None,
                1 => Some(decode_runtime_application_index(&mut decoder)?),
                _ => return Err(PrivateStoreError::Corrupt),
            },
        };
        if !stored_control_index_shape_is_valid(&entry) {
            return Err(PrivateStoreError::Corrupt);
        }
        controls.push(entry);
    }
    decoder.finish()?;
    let index = StoreIndex {
        space,
        agent,
        epoch,
        control_head,
        next_sequence,
        objects,
        controls,
    };
    validate_index_shape(&index)?;
    Ok(index)
}

fn stored_object_index_shape_is_valid(entry: &StoredObjectIndex) -> bool {
    entry.key.validate()
        && entry.wire_hash != Hash::ZERO
        && entry.wire_len != 0
        && entry.wire_len as usize <= MAX_PRIVATE_OBJECT_WIRE_BYTES
}

fn stored_control_index_shape_is_valid(entry: &StoredControlIndex) -> bool {
    entry.commitment != Hash::ZERO
        && entry.previous != Some(Hash::ZERO)
        && entry.wire_hash != Hash::ZERO
        && entry.wire_len != 0
        && entry.wire_len as usize <= MAX_PRIVATE_CONTROL_WIRE_BYTES
        && entry
            .superseded_heads
            .iter()
            .all(|head| *head != Hash::ZERO)
        && !entry
            .superseded_heads
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        && entry.runtime_application.is_none_or(|application| {
            runtime_application_index_shape_is_valid(&application)
                && application.control == entry.commitment
        })
}

fn encode_runtime_application_index(
    encoder: &mut Encoder,
    application: StoredRuntimeApplicationIndex,
) {
    encoder.fixed(application.control.as_bytes());
    encoder.fixed(application.application.as_bytes());
    encoder.fixed(application.wire_hash.as_bytes());
    encoder.u32(application.wire_len);
    encoder.fixed(application.successor_runtime_image.as_bytes());
    encoder.fixed(application.successor_stable_projection.as_bytes());
}

fn decode_runtime_application_index(
    decoder: &mut Decoder<'_>,
) -> Result<StoredRuntimeApplicationIndex, PrivateStoreError> {
    let application = StoredRuntimeApplicationIndex {
        control: Hash(decoder.fixed()?),
        application: Hash(decoder.fixed()?),
        wire_hash: Hash(decoder.fixed()?),
        wire_len: decoder.u32()?,
        successor_runtime_image: Hash(decoder.fixed()?),
        successor_stable_projection: Hash(decoder.fixed()?),
    };
    runtime_application_index_shape_is_valid(&application)
        .then_some(application)
        .ok_or(PrivateStoreError::Corrupt)
}

fn runtime_application_index_shape_is_valid(application: &StoredRuntimeApplicationIndex) -> bool {
    application.control != Hash::ZERO
        && application.application != Hash::ZERO
        && application.wire_hash != Hash::ZERO
        && application.wire_len != 0
        && application.wire_len as usize <= MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES
        && application.successor_runtime_image != Hash::ZERO
        && application.successor_stable_projection != Hash::ZERO
}

fn validate_index_shape(index: &StoreIndex) -> Result<(), PrivateStoreError> {
    let artifact_bytes = index
        .objects
        .iter()
        .map(|entry| entry.wire_len as usize)
        .chain(index.controls.iter().map(|entry| entry.wire_len as usize))
        .chain(index.controls.iter().filter_map(|entry| {
            entry
                .runtime_application
                .map(|application| application.wire_len as usize)
        }))
        .try_fold(0usize, |total, length| total.checked_add(length))
        .ok_or(PrivateStoreError::LimitExceeded)?;
    if index.space == SpaceId::ZERO
        || index.agent == AgentId::ZERO
        || index.objects.len() > MAX_PRIVATE_STORE_OBJECTS
        || index.controls.len() > MAX_PRIVATE_STORE_CONTROLS
        || artifact_bytes > MAX_PRIVATE_STORE_ARTIFACT_BYTES
        || index
            .objects
            .iter()
            .any(|entry| !stored_object_index_shape_is_valid(entry))
        || index
            .controls
            .iter()
            .any(|entry| !stored_control_index_shape_is_valid(entry))
        || index
            .objects
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        || index
            .controls
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
    {
        return Err(PrivateStoreError::Corrupt);
    }
    if index.controls.is_empty() {
        if index.control_head.is_some() || index.next_sequence != 0 || index.epoch != 0 {
            return Err(PrivateStoreError::Corrupt);
        }
    } else {
        let last = index.controls.last().ok_or(PrivateStoreError::Corrupt)?;
        if index.control_head != Some(last.commitment)
            || index.next_sequence
                != last
                    .sequence
                    .checked_add(1)
                    .ok_or(PrivateStoreError::Corrupt)?
            || index.epoch != last.resulting_epoch
        {
            return Err(PrivateStoreError::Corrupt);
        }
    }
    Ok(())
}

fn encode_pending(pending: &PendingTransaction) -> Result<Vec<u8>, PrivateStoreError> {
    if pending.artifact_hash == Hash::ZERO
        || pending.previous_index_hash == Hash::ZERO
        || pending.next_index_hash == Hash::ZERO
        || pending.artifact_len == 0
        || pending.previous_index_len == 0
        || pending.next_index_len == 0
        || pending.previous_index_len as usize > MAX_PRIVATE_STORE_INDEX_BYTES
        || pending.next_index_len as usize > MAX_PRIVATE_STORE_INDEX_BYTES
        || match (pending.artifact.clone(), pending.runtime_application) {
            (PendingArtifact::Object(_), Some(_)) => true,
            (PendingArtifact::Control(control), Some(application)) => {
                application.control != control
                    || !runtime_application_index_shape_is_valid(&application)
            }
            _ => false,
        }
    {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut encoder = Encoder::new(TRANSACTION_MAGIC);
    match pending.artifact {
        PendingArtifact::Object(key) => {
            encoder.u8(0);
            encode_object_key(&mut encoder, key);
        }
        PendingArtifact::Control(commitment) => {
            encoder.u8(1);
            encoder.fixed(commitment.as_bytes());
        }
    }
    encoder.fixed(pending.artifact_hash.as_bytes());
    encoder.u32(pending.artifact_len);
    encoder.fixed(pending.previous_index_hash.as_bytes());
    encoder.u32(pending.previous_index_len);
    encoder.fixed(pending.next_index_hash.as_bytes());
    encoder.u32(pending.next_index_len);
    match pending.runtime_application {
        None => encoder.u8(0),
        Some(application) => {
            encoder.u8(1);
            encode_runtime_application_index(&mut encoder, application);
        }
    }
    encoder.finish(384)
}

fn decode_pending(bytes: &[u8]) -> Result<PendingTransaction, PrivateStoreError> {
    let mut decoder = Decoder::new(bytes, TRANSACTION_MAGIC, 384)?;
    let artifact = match decoder.u8()? {
        0 => PendingArtifact::Object(decode_object_key(&mut decoder)?),
        1 => {
            let commitment = Hash(decoder.fixed()?);
            if commitment == Hash::ZERO {
                return Err(PrivateStoreError::Corrupt);
            }
            PendingArtifact::Control(commitment)
        }
        _ => return Err(PrivateStoreError::Corrupt),
    };
    let pending = PendingTransaction {
        artifact,
        artifact_hash: Hash(decoder.fixed()?),
        artifact_len: decoder.u32()?,
        previous_index_hash: Hash(decoder.fixed()?),
        previous_index_len: decoder.u32()?,
        next_index_hash: Hash(decoder.fixed()?),
        next_index_len: decoder.u32()?,
        runtime_application: match decoder.u8()? {
            0 => None,
            1 => Some(decode_runtime_application_index(&mut decoder)?),
            _ => return Err(PrivateStoreError::Corrupt),
        },
    };
    decoder.finish()?;
    if encode_pending(&pending)?.as_slice() != bytes {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(pending)
}

fn encode_pending_control_evidence(
    pending: PendingControlEvidence,
) -> Result<Vec<u8>, PrivateStoreError> {
    if pending.control == Hash::ZERO
        || pending.evidence_hash == Hash::ZERO
        || pending.evidence_len == 0
        || pending.evidence_len as usize > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
        || pending
            .stable_import_certificate
            .is_some_and(|certificate| {
                certificate.wire_hash == Hash::ZERO
                    || certificate.wire_len as usize != PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES
            })
    {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut encoder = Encoder::new(CONTROL_EVIDENCE_PENDING_MAGIC);
    encoder.fixed(pending.control.as_bytes());
    encoder.fixed(pending.evidence_hash.as_bytes());
    encoder.u32(pending.evidence_len);
    match pending.stable_import_certificate {
        None => encoder.u8(0),
        Some(certificate) => {
            encoder.u8(1);
            encoder.fixed(certificate.wire_hash.as_bytes());
            encoder.u32(certificate.wire_len);
        }
    }
    encoder.finish(MAX_PENDING_CONTROL_EVIDENCE_BYTES)
}

fn decode_pending_control_evidence(
    bytes: &[u8],
) -> Result<PendingControlEvidence, PrivateStoreError> {
    let mut decoder = Decoder::new(
        bytes,
        CONTROL_EVIDENCE_PENDING_MAGIC,
        MAX_PENDING_CONTROL_EVIDENCE_BYTES,
    )?;
    let pending = PendingControlEvidence {
        control: Hash(decoder.fixed()?),
        evidence_hash: Hash(decoder.fixed()?),
        evidence_len: decoder.u32()?,
        stable_import_certificate: match decoder.u8()? {
            0 => None,
            1 => Some(PendingStableImportCertificate {
                wire_hash: Hash(decoder.fixed()?),
                wire_len: decoder.u32()?,
            }),
            _ => return Err(PrivateStoreError::Corrupt),
        },
    };
    decoder.finish()?;
    if encode_pending_control_evidence(pending)?.as_slice() != bytes {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(pending)
}

/// Decode only the bounded canonical recovery metadata needed to break the
/// encrypted-backup bootstrap cycle. Nothing returned by this function is an
/// authority fact until the complete backup and its independently signed
/// descriptor/Create material have both been authenticated.
pub(crate) fn encrypted_backup_genesis_claim(
    bytes: &[u8],
) -> Result<EncryptedBackupGenesisClaim, PrivateStoreError> {
    let mut decoder = Decoder::new(bytes, BACKUP_MAGIC, MAX_PRIVATE_BACKUP_BYTES)?;
    let recovery_wire = decoder.bytes(MAX_PRIVATE_RECOVERY_METADATA_BYTES)?;
    let metadata = decode_recovery(&recovery_wire)?;
    if encode_recovery(&metadata)? != recovery_wire {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(EncryptedBackupGenesisClaim {
        recovery_public_key: metadata.recovery_public_key,
        recovery_encryption_public_key: metadata.recovery_encryption_public_key,
    })
}

/// Fully decode an encrypted archive, authenticate its signed control chain,
/// and bind it to caller-selected recovery metadata without touching the
/// destination filesystem. Public PAPL rows are only canonical and
/// PSC-bound here; their authority/PVRI/PKEY proof is a physical-host gate.
/// Archive metadata is never allowed to select its own owner or recovery key.
pub(crate) fn verify_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
    bytes: &[u8],
    expected_space: SpaceId,
    expected_agent: AgentId,
    expected_owner: PrincipalId,
    expected_recovery_public_key: [u8; 32],
    expected_recovery_encryption_public_key: [u8; 32],
    authority: &V,
) -> Result<VerifiedEncryptedBackup, PrivateStoreError> {
    let mut decoder = Decoder::new(bytes, BACKUP_MAGIC, MAX_PRIVATE_BACKUP_BYTES)?;
    let recovery_wire = decoder.bytes(MAX_PRIVATE_RECOVERY_METADATA_BYTES)?;
    let metadata = decode_recovery(&recovery_wire)?;
    if encode_recovery(&metadata)? != recovery_wire {
        return Err(PrivateStoreError::Corrupt);
    }
    if metadata.space != expected_space || metadata.agent != expected_agent {
        return Err(PrivateStoreError::InvalidScope);
    }
    if metadata.owner != expected_owner
        || metadata.recovery_public_key != expected_recovery_public_key
        || metadata.recovery_encryption_public_key != expected_recovery_encryption_public_key
    {
        return Err(PrivateStoreError::InvalidBinding);
    }

    let index_wire = decoder.bytes(MAX_PRIVATE_STORE_INDEX_BYTES)?;
    let index = decode_index(&index_wire)?;
    if encode_index(&index)? != index_wire {
        return Err(PrivateStoreError::Corrupt);
    }
    if index.space != expected_space || index.agent != expected_agent {
        return Err(PrivateStoreError::InvalidScope);
    }

    let mut chain = PrivateControlChainVerifier::new_genesis(
        metadata.space,
        metadata.agent,
        metadata.owner,
        metadata.recovery_public_key,
        metadata.recovery_encryption_public_key,
        metadata.genesis_epoch.clone(),
        metadata.genesis_nodes.clone(),
        authority,
    )?;
    let mut key_epochs = vec![metadata.genesis_epoch.clone()];
    let control_count =
        usize::try_from(decoder.u32()?).map_err(|_| PrivateStoreError::LimitExceeded)?;
    if control_count != index.controls.len() || control_count > MAX_PRIVATE_STORE_CONTROLS {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut controls = Vec::new();
    controls
        .try_reserve(control_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    let mut control_evidence = Vec::new();
    control_evidence
        .try_reserve(control_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    let mut runtime_applications = Vec::new();
    runtime_applications
        .try_reserve(control_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for entry in &index.controls {
        let commitment = Hash(decoder.fixed()?);
        let wire = decoder.bytes(MAX_PRIVATE_CONTROL_WIRE_BYTES)?;
        if commitment != entry.commitment
            || wire.len() != entry.wire_len as usize
            || raw_wire_hash(&wire) != entry.wire_hash
        {
            return Err(PrivateStoreError::Corrupt);
        }
        let record =
            PrivateControlRecord::decode(&wire).map_err(|_| PrivateStoreError::InvalidRecord)?;
        if record
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?
            != wire
        {
            return Err(PrivateStoreError::Corrupt);
        }
        validate_control_index_entry(entry, &record)?;
        apply_control_transition(&mut chain, &record, authority)?;
        advance_key_epochs(&mut key_epochs, &record)?;
        if chain.epoch().epoch != entry.resulting_epoch
            || chain.head() != Some(entry.commitment)
            || chain.next_sequence()
                != entry
                    .sequence
                    .checked_add(1)
                    .ok_or(PrivateStoreError::Corrupt)?
        {
            return Err(PrivateStoreError::Corrupt);
        }
        let evidence = match decoder.u8()? {
            0 => None,
            1 => {
                let bytes = decoder.bytes(MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES)?;
                if bytes.is_empty() {
                    return Err(PrivateStoreError::Corrupt);
                }
                Some(bytes)
            }
            _ => return Err(PrivateStoreError::Corrupt),
        };
        let runtime_application = match (entry.runtime_application, decoder.u8()?) {
            (None, 0) => None,
            (Some(binding), 1) => {
                let bytes = decoder.bytes(MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES)?;
                let application = decode_bound_runtime_application(binding, &bytes)?;
                if application.control() != &record {
                    return Err(PrivateStoreError::Corrupt);
                }
                Some(application)
            }
            _ => return Err(PrivateStoreError::Corrupt),
        };
        controls.push(record);
        control_evidence.push(evidence);
        runtime_applications.push(runtime_application);
    }

    let object_count =
        usize::try_from(decoder.u32()?).map_err(|_| PrivateStoreError::LimitExceeded)?;
    if object_count != index.objects.len() || object_count > MAX_PRIVATE_STORE_OBJECTS {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut objects = Vec::new();
    objects
        .try_reserve(object_count)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    for entry in &index.objects {
        let key = decode_object_key(&mut decoder)?;
        let wire = decoder.bytes(MAX_PRIVATE_OBJECT_WIRE_BYTES)?;
        if key != entry.key
            || wire.len() != entry.wire_len as usize
            || raw_wire_hash(&wire) != entry.wire_hash
        {
            return Err(PrivateStoreError::Corrupt);
        }
        let object =
            EncryptedPrivateObject::decode(&wire).map_err(|_| PrivateStoreError::InvalidRecord)?;
        if object
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?
            != wire
            || object.epoch > index.epoch
        {
            return Err(PrivateStoreError::Corrupt);
        }
        validate_object_index_entry(entry, &object, expected_space, expected_agent)?;
        objects.push(object);
    }
    decoder.finish()?;
    if chain.epoch().epoch != index.epoch
        || chain.head() != index.control_head
        || chain.next_sequence() != index.next_sequence
        || key_epochs.last() != Some(chain.epoch())
    {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(VerifiedEncryptedBackup {
        metadata,
        index,
        controls,
        control_evidence,
        runtime_applications,
        objects,
        key_epochs,
        chain,
    })
}

/// Deterministically select one authenticated control path and union every
/// compatible ciphertext object from the contributing backups. Divergent
/// control heads are resolved only by the later recovery record; this step
/// never attempts to replay two records at the same sequence.
pub(crate) fn reconcile_encrypted_backups(
    mut backups: Vec<VerifiedEncryptedBackup>,
) -> Result<(VerifiedEncryptedBackup, Vec<Hash>, u64), PrivateStoreError> {
    if backups.is_empty() || backups.len() > MAX_PRIVATE_NODES {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let metadata = &backups[0].metadata;
    if backups
        .iter()
        .skip(1)
        .any(|backup| backup.metadata != *metadata)
    {
        return Err(PrivateStoreError::Diverged);
    }

    // A sound recovered store must be able to reconstruct every historical
    // epoch from its retained control path after restart. Authenticated
    // control state is the primary order. Equal control paths can still carry
    // distinct node-local PAPL/PVRI values, so their complete canonical
    // indexed identities are the final deterministic ordering key. This
    // orders bases only; it never requires PAPL equality or merges one
    // replica's PAPL into another.
    let selected_position = backups
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            backups
                .iter()
                .all(|source| recovery_epoch_history_covers(candidate, source))
        })
        .max_by(|(_, left), (_, right)| compare_recovery_base(left, right))
        .map(|(position, _)| position)
        .ok_or(PrivateStoreError::Diverged)?;

    let mut superseded_heads: Vec<_> = backups
        .iter()
        .filter_map(|backup| backup.chain.head())
        .collect();
    superseded_heads.sort_unstable();
    superseded_heads.dedup();
    if superseded_heads.len() > MAX_PRIVATE_NODES {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let maximum_next_sequence = backups
        .iter()
        .map(|backup| backup.chain.next_sequence())
        .max()
        .ok_or(PrivateStoreError::Corrupt)?;

    let mut selected = backups.swap_remove(selected_position);
    for source in &backups {
        selected.merge_compatible_control_evidence(source)?;
        // PAPL/PVRI identity is node-local even when two replicas apply the
        // same PCTL to the same stable PSP. Retain only the selected archive's
        // exact attachment; never copy, merge, or require equality across
        // replica backups. The base-ordering identity above is the only
        // cross-replica observation.
        selected.merge_compatible_objects(source)?;
    }
    if (selected.chain.head().is_none()) != superseded_heads.is_empty() {
        return Err(PrivateStoreError::Diverged);
    }
    Ok((selected, superseded_heads, maximum_next_sequence))
}

fn recovery_epoch_history_covers(
    candidate: &VerifiedEncryptedBackup,
    source: &VerifiedEncryptedBackup,
) -> bool {
    source.key_epochs.iter().all(|source_epoch| {
        candidate
            .key_epochs
            .binary_search_by_key(&source_epoch.epoch, |epoch| epoch.epoch)
            .ok()
            .and_then(|position| candidate.key_epochs.get(position))
            .is_some_and(|candidate_epoch| {
                recovery_epoch_material_matches(candidate_epoch, source_epoch)
            })
    })
}

fn recovery_epoch_material_matches(left: &PrivateKeyEpoch, right: &PrivateKeyEpoch) -> bool {
    left.space == right.space
        && left.agent == right.agent
        && left.epoch == right.epoch
        && left.owner_key_commitment == right.owner_key_commitment
        && left.data_key_commitment == right.data_key_commitment
        && left.recovery_key_commitment == right.recovery_key_commitment
        && left.recovery_encryption_public_key == right.recovery_encryption_public_key
        && left.sealed_recovery_data_key == right.sealed_recovery_data_key
}

fn compare_recovery_base(
    left: &VerifiedEncryptedBackup,
    right: &VerifiedEncryptedBackup,
) -> core::cmp::Ordering {
    left.chain
        .epoch()
        .epoch
        .cmp(&right.chain.epoch().epoch)
        .then_with(|| left.chain.next_sequence().cmp(&right.chain.next_sequence()))
        .then_with(|| left.index.controls.len().cmp(&right.index.controls.len()))
        .then_with(|| {
            left.index
                .controls
                .iter()
                .map(|entry| entry.commitment)
                .cmp(right.index.controls.iter().map(|entry| entry.commitment))
        })
        .then_with(|| compare_node_local_runtime_application_base(left, right))
}

fn compare_node_local_runtime_application_base(
    left: &VerifiedEncryptedBackup,
    right: &VerifiedEncryptedBackup,
) -> core::cmp::Ordering {
    let identity = |entry: &StoredControlIndex| {
        entry.runtime_application.map(|application| {
            (
                application.application,
                application.wire_hash,
                application.wire_len,
                application.successor_runtime_image,
                application.successor_stable_projection,
            )
        })
    };
    left.index
        .controls
        .iter()
        .map(identity)
        .cmp(right.index.controls.iter().map(identity))
}

impl VerifiedEncryptedBackup {
    pub(crate) fn binding(&self) -> PrivateStoreBinding {
        PrivateStoreBinding {
            space: self.metadata.space,
            agent: self.metadata.agent,
            owner: self.metadata.owner,
            epoch: self.chain.epoch().epoch,
            control_head: self.chain.head(),
            next_sequence: self.chain.next_sequence(),
        }
    }

    pub(crate) fn core_position(&self) -> Result<PrivateStoreCorePosition, PrivateStoreError> {
        if self.chain.epoch().epoch != self.index.epoch
            || self.chain.head() != self.index.control_head
            || self.chain.next_sequence() != self.index.next_sequence
            || self.key_epochs.last() != Some(self.chain.epoch())
        {
            return Err(PrivateStoreError::Corrupt);
        }
        store_core_position(&self.metadata, &self.index, &self.key_epochs)
    }

    pub(crate) fn key_epochs(&self) -> &[PrivateKeyEpoch] {
        &self.key_epochs
    }

    /// Immutable genesis membership from the recovery metadata. This is not
    /// the final membership after archived controls have been applied.
    pub(crate) fn genesis_nodes(&self) -> &[PrivateNodeIdentity] {
        &self.metadata.genesis_nodes
    }

    /// Final control-chain-authenticated membership selected by the archive.
    pub(crate) fn final_authorized_nodes(&self) -> &[PrivateNodeIdentity] {
        self.chain.nodes()
    }

    /// Final Store-core target selected by the archive's verified control
    /// chain and ciphertext index. Runtime/PVRI state is outside this target.
    pub(crate) fn final_target(&self) -> Result<PrivateStoreCorePosition, PrivateStoreError> {
        self.core_position()
    }

    /// Canonical encrypted objects authenticated by the archive index. The
    /// recovery host must additionally authenticate their AEAD tags with the
    /// exact archived epoch keys before it can publish a successor.
    pub(crate) fn objects(&self) -> &[EncryptedPrivateObject] {
        &self.objects
    }

    /// Exact authenticated control rows and their optional canonical PSE2
    /// envelopes. Recovery preflight uses this read-only view to reject a
    /// historical Recover whose authority evidence was never durably
    /// attached, before a new authority application is pledged.
    pub(crate) fn controls_with_authority_evidence(
        &self,
    ) -> impl Iterator<Item = (&StoredControlIndex, &PrivateControlRecord, Option<&[u8]>)> {
        self.index
            .controls
            .iter()
            .zip(&self.controls)
            .zip(&self.control_evidence)
            .map(|((index, control), evidence)| (index, control, evidence.as_deref()))
    }

    pub(crate) fn controls_with_runtime_applications(
        &self,
    ) -> impl Iterator<
        Item = (
            &StoredControlIndex,
            &PrivateControlRecord,
            Option<&PrivateRuntimeApplication>,
        ),
    > {
        // These values passed canonical and exact Store-position checks only.
        // Callers must not treat them as authority- or PVRI-authenticated.
        self.index
            .controls
            .iter()
            .zip(&self.controls)
            .zip(&self.runtime_applications)
            .map(|((index, control), application)| (index, control, application.as_ref()))
    }

    /// Return a bounded, read-only replay table only when every archived PCTL
    /// has both its completed source PAPL and its opaque source PSE bytes.
    ///
    /// Success establishes presence and exact Store/index correspondence, not
    /// authority signatures or PVRI provenance. Those are physical-host replay
    /// checks and the source runtime image must never be adopted as local state.
    pub(crate) fn replay_rows(
        &self,
    ) -> Result<Vec<EncryptedBackupReplayRow<'_>>, PrivateStoreError> {
        self.validate_backing_vectors()?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.index.controls.len())
            .map_err(|_| PrivateStoreError::LimitExceeded)?;
        for position in 0..self.index.controls.len() {
            let index = self
                .index
                .controls
                .get(position)
                .ok_or(PrivateStoreError::Corrupt)?;
            let control = self
                .controls
                .get(position)
                .ok_or(PrivateStoreError::Corrupt)?;
            let source_runtime_application = self
                .runtime_applications
                .get(position)
                .and_then(Option::as_ref)
                .ok_or(PrivateStoreError::Corrupt)?;
            let source_authority_evidence = self
                .control_evidence
                .get(position)
                .and_then(Option::as_deref)
                .ok_or(PrivateStoreError::Corrupt)?;
            let control_wire = control.encode().map_err(|_| PrivateStoreError::Corrupt)?;
            let application_wire = source_runtime_application
                .encode()
                .map_err(|_| PrivateStoreError::Corrupt)?;
            if source_authority_evidence.is_empty()
                || source_authority_evidence.len() > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
                || control_wire.len() != index.wire_len as usize
                || raw_wire_hash(&control_wire) != index.wire_hash
                || source_runtime_application.control() != control
                || index.runtime_application
                    != Some(
                        bind_runtime_application(source_runtime_application, &application_wire)
                            .map_err(|_| PrivateStoreError::Corrupt)?,
                    )
            {
                return Err(PrivateStoreError::Corrupt);
            }
            validate_control_index_entry(index, control)?;
            rows.push(EncryptedBackupReplayRow {
                index,
                control,
                source_runtime_application,
                source_authority_evidence,
            });
        }
        Ok(rows)
    }

    fn validate_backing_vectors(&self) -> Result<(), PrivateStoreError> {
        self.core_position()?;
        if self.controls.len() != self.index.controls.len()
            || self.control_evidence.len() != self.index.controls.len()
            || self.runtime_applications.len() != self.index.controls.len()
            || self.objects.len() != self.index.objects.len()
        {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(())
    }

    fn merge_compatible_control_evidence(
        &mut self,
        source: &VerifiedEncryptedBackup,
    ) -> Result<(), PrivateStoreError> {
        if self.control_evidence.len() != self.index.controls.len()
            || source.control_evidence.len() != source.index.controls.len()
            || self.controls.len() != self.index.controls.len()
            || source.controls.len() != source.index.controls.len()
            || self.runtime_applications.len() != self.index.controls.len()
            || source.runtime_applications.len() != source.index.controls.len()
        {
            return Err(PrivateStoreError::Corrupt);
        }
        for (source_position, (source_entry, source_evidence)) in source
            .index
            .controls
            .iter()
            .zip(&source.control_evidence)
            .enumerate()
        {
            let Some(source_evidence) = source_evidence else {
                continue;
            };
            let Some(position) = self
                .index
                .controls
                .iter()
                .position(|entry| entry.commitment == source_entry.commitment)
            else {
                continue;
            };
            // PSE authenticates a particular node-local PAPL lineage, not
            // merely the shared PCTL. Never synthesize a provenance row by
            // attaching one replica's evidence to another replica's runtime
            // application. Exact canonical control/index/application identity
            // is the minimum safe merge boundary.
            if self.index.controls.get(position) != Some(source_entry)
                || self.controls.get(position) != source.controls.get(source_position)
                || self.runtime_applications.get(position)
                    != source.runtime_applications.get(source_position)
            {
                continue;
            }
            let selected = self
                .control_evidence
                .get_mut(position)
                .ok_or(PrivateStoreError::Corrupt)?;
            match selected {
                Some(existing) if existing != source_evidence => {
                    return Err(PrivateStoreError::Alias);
                }
                Some(_) => {}
                None => *selected = Some(source_evidence.clone()),
            }
        }
        Ok(())
    }

    fn merge_compatible_objects(
        &mut self,
        source: &VerifiedEncryptedBackup,
    ) -> Result<(), PrivateStoreError> {
        if self.metadata != source.metadata
            || !recovery_epoch_history_covers(self, source)
            || self.objects.len() != self.index.objects.len()
            || source.objects.len() != source.index.objects.len()
        {
            return Err(PrivateStoreError::Diverged);
        }
        for object in &source.objects {
            let key = PrivateObjectKey::from_object(object);
            match self
                .index
                .objects
                .binary_search_by_key(&key, |entry| entry.key)
            {
                Ok(position) => {
                    if self.objects.get(position) != Some(object) {
                        return Err(PrivateStoreError::Alias);
                    }
                }
                Err(position) => {
                    if self.objects.len() >= MAX_PRIVATE_STORE_OBJECTS {
                        return Err(PrivateStoreError::LimitExceeded);
                    }
                    let wire = object
                        .encode()
                        .map_err(|_| PrivateStoreError::InvalidRecord)?;
                    self.index.objects.insert(
                        position,
                        StoredObjectIndex {
                            key,
                            wire_hash: raw_wire_hash(&wire),
                            wire_len: u32::try_from(wire.len())
                                .map_err(|_| PrivateStoreError::LimitExceeded)?,
                        },
                    );
                    self.objects.insert(position, object.clone());
                }
            }
        }
        validate_index_shape(&self.index)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_epoch_object_and_reindex_for_test(
        &mut self,
        epoch: u64,
    ) -> Result<(), PrivateStoreError> {
        let position = self
            .objects
            .iter()
            .position(|object| object.epoch == epoch)
            .ok_or(PrivateStoreError::NotFound)?;
        let object = self
            .objects
            .get_mut(position)
            .ok_or(PrivateStoreError::Corrupt)?;
        let byte = object
            .ciphertext
            .first_mut()
            .ok_or(PrivateStoreError::Corrupt)?;
        *byte ^= 1;
        let wire = object
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?;
        let entry = self
            .index
            .objects
            .get_mut(position)
            .ok_or(PrivateStoreError::Corrupt)?;
        if entry.key != PrivateObjectKey::from_object(object) {
            return Err(PrivateStoreError::Corrupt);
        }
        entry.wire_hash = raw_wire_hash(&wire);
        entry.wire_len = u32::try_from(wire.len()).map_err(|_| PrivateStoreError::LimitExceeded)?;
        Ok(())
    }

    /// Append the exact already-signed recovery successor in memory. The
    /// original backup is left untouched; the resulting bytes are still a
    /// ciphertext-only canonical backup and can be durably restored through
    /// the ordinary transactional store path.
    pub(crate) fn append_offline_recovery<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<(), PrivateStoreError> {
        if self.index.controls.len() >= MAX_PRIVATE_STORE_CONTROLS
            || record.signer != PrivateControlSigner::Recovery
            || record.sequence < self.index.next_sequence
            || !matches!(record.operation, PrivateControlOperation::Recover { .. })
        {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &record.operation
        else {
            return Err(PrivateStoreError::InvalidRecord);
        };
        match (self.index.control_head, record.previous) {
            (Some(local_head), Some(selected_head))
                if superseded_heads.binary_search(&local_head).is_ok()
                    && superseded_heads.binary_search(&selected_head).is_ok() => {}
            (None, None) if superseded_heads.is_empty() => {}
            _ => return Err(PrivateStoreError::InvalidRecord),
        }

        let wire = record
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?;
        if wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES {
            return Err(PrivateStoreError::LimitExceeded);
        }
        let commitment = record.commitment();
        if self
            .index
            .controls
            .iter()
            .any(|entry| entry.commitment == commitment || entry.sequence == record.sequence)
        {
            return Err(PrivateStoreError::Alias);
        }
        let mut next_chain = self.chain.clone();
        apply_control_transition(&mut next_chain, record, authority)?;
        let mut next_key_epochs = self.key_epochs.clone();
        advance_key_epochs(&mut next_key_epochs, record)?;
        if next_key_epochs.last() != Some(next_chain.epoch()) {
            return Err(PrivateStoreError::Corrupt);
        }
        let entry = StoredControlIndex {
            sequence: record.sequence,
            commitment,
            previous: record.previous,
            resulting_epoch: next_chain.epoch().epoch,
            superseded_heads: superseded_heads.clone(),
            wire_hash: raw_wire_hash(&wire),
            wire_len: u32::try_from(wire.len()).map_err(|_| PrivateStoreError::LimitExceeded)?,
            runtime_application: None,
        };
        self.index.controls.push(entry);
        self.index.epoch = next_chain.epoch().epoch;
        self.index.control_head = next_chain.head();
        self.index.next_sequence = next_chain.next_sequence();
        validate_index_shape(&self.index)?;
        self.controls.push(record.clone());
        self.control_evidence.push(None);
        self.runtime_applications.push(None);
        self.key_epochs = next_key_epochs;
        self.chain = next_chain;
        Ok(())
    }

    pub(crate) fn encode_backup(&self, max_bytes: usize) -> Result<Vec<u8>, PrivateStoreError> {
        let maximum = max_bytes.min(MAX_PRIVATE_BACKUP_BYTES);
        if self.controls.len() != self.index.controls.len()
            || self.control_evidence.len() != self.index.controls.len()
            || self.runtime_applications.len() != self.index.controls.len()
            || self.objects.len() != self.index.objects.len()
        {
            return Err(PrivateStoreError::Corrupt);
        }
        let recovery = encode_recovery(&self.metadata)?;
        let index = encode_index(&self.index)?;
        let mut encoder = Encoder::new(BACKUP_MAGIC);
        encoder.bytes(&recovery)?;
        encoder.bytes(&index)?;
        encoder
            .u32(u32::try_from(self.controls.len()).map_err(|_| PrivateStoreError::LimitExceeded)?);
        for (position, entry) in self.index.controls.iter().enumerate() {
            let record = self
                .controls
                .get(position)
                .ok_or(PrivateStoreError::Corrupt)?;
            let evidence = self
                .control_evidence
                .get(position)
                .ok_or(PrivateStoreError::Corrupt)?;
            let runtime_application = self
                .runtime_applications
                .get(position)
                .ok_or(PrivateStoreError::Corrupt)?;
            let wire = record
                .encode()
                .map_err(|_| PrivateStoreError::InvalidRecord)?;
            if record.commitment() != entry.commitment
                || raw_wire_hash(&wire) != entry.wire_hash
                || wire.len() != entry.wire_len as usize
            {
                return Err(PrivateStoreError::Corrupt);
            }
            encoder.fixed(entry.commitment.as_bytes());
            encoder.bytes(&wire)?;
            match evidence {
                None => encoder.u8(0),
                Some(evidence) => {
                    if evidence.is_empty()
                        || evidence.len() > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
                    {
                        return Err(PrivateStoreError::Corrupt);
                    }
                    encoder.u8(1);
                    encoder.bytes(evidence)?;
                }
            }
            match (entry.runtime_application, runtime_application) {
                (None, None) => encoder.u8(0),
                (Some(binding), Some(application)) => {
                    let application_wire = application
                        .encode()
                        .map_err(|_| PrivateStoreError::Corrupt)?;
                    if bind_runtime_application(application, &application_wire)
                        .map_err(|_| PrivateStoreError::Corrupt)?
                        != binding
                        || application.control() != record
                    {
                        return Err(PrivateStoreError::Corrupt);
                    }
                    encoder.u8(1);
                    encoder.bytes(&application_wire)?;
                }
                _ => return Err(PrivateStoreError::Corrupt),
            }
            if encoder.0.len() > maximum {
                return Err(PrivateStoreError::LimitExceeded);
            }
        }
        encoder
            .u32(u32::try_from(self.objects.len()).map_err(|_| PrivateStoreError::LimitExceeded)?);
        for (entry, object) in self.index.objects.iter().zip(&self.objects) {
            let wire = object
                .encode()
                .map_err(|_| PrivateStoreError::InvalidRecord)?;
            if PrivateObjectKey::from_object(object) != entry.key
                || raw_wire_hash(&wire) != entry.wire_hash
                || wire.len() != entry.wire_len as usize
            {
                return Err(PrivateStoreError::Corrupt);
            }
            encode_object_key(&mut encoder, entry.key);
            encoder.bytes(&wire)?;
            if encoder.0.len() > maximum {
                return Err(PrivateStoreError::LimitExceeded);
            }
        }
        encoder.finish(maximum)
    }
}

fn map_io(_: std::io::Error) -> PrivateStoreError {
    PrivateStoreError::Io
}

fn open_lock(root: &Path) -> Result<File, PrivateStoreError> {
    let path = root.join(LOCK_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(map_io)?;
    if !file.metadata().map_err(map_io)?.is_file() {
        return Err(PrivateStoreError::Corrupt);
    }
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            PrivateStoreError::Busy
        } else {
            PrivateStoreError::Io
        }
    })?;
    Ok(file)
}

fn ensure_regular_file(path: &Path) -> Result<std::fs::Metadata, PrivateStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PrivateStoreError::NotFound
        } else {
            PrivateStoreError::Io
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(metadata)
}

fn read_bounded_file(path: &Path, max: usize) -> Result<Vec<u8>, PrivateStoreError> {
    let metadata = ensure_regular_file(path)?;
    let length = usize::try_from(metadata.len()).map_err(|_| PrivateStoreError::LimitExceeded)?;
    if length > max {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(map_io)?;
    let opened = file.metadata().map_err(map_io)?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve(length)
        .map_err(|_| PrivateStoreError::LimitExceeded)?;
    file.take(u64::try_from(max).map_err(|_| PrivateStoreError::LimitExceeded)? + 1)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() != length || bytes.len() > max {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(bytes)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), PrivateStoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(map_io)?;
    file.write_all(bytes).map_err(map_io)?;
    file.sync_all().map_err(map_io)
}

fn sync_directory(path: &Path) -> Result<(), PrivateStoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    let directory = options.open(path).map_err(map_io)?;
    if !directory.metadata().map_err(map_io)?.is_dir() {
        return Err(PrivateStoreError::Corrupt);
    }
    directory.sync_all().map_err(map_io)
}

fn remove_file_if_present(path: &Path) -> Result<(), PrivateStoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrivateStoreError::Io),
    }
}

fn require_paths_absent(paths: &[&Path]) -> Result<(), PrivateStoreError> {
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(PrivateStoreError::Corrupt),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PrivateStoreError::Io),
        }
    }
    Ok(())
}

fn hash_name(hash: Hash) -> String {
    let mut name = String::with_capacity(64);
    for byte in hash.as_bytes() {
        let _ = write!(&mut name, "{byte:02x}");
    }
    name
}

fn object_file_name(key: PrivateObjectKey) -> String {
    let mut name = String::with_capacity(16 + 1 + 2 + 1 + 64 + 5);
    let _ = write!(
        &mut name,
        "{:016x}-{:02x}-{}.pobj",
        key.epoch,
        key.kind,
        hash_name(key.content)
    );
    name
}

fn control_file_name(commitment: Hash) -> String {
    let mut name = hash_name(commitment);
    name.push_str(".pctl");
    name
}

fn runtime_application_file_name(control: Hash) -> String {
    let mut name = hash_name(control);
    name.push_str(".papl");
    name
}

fn control_evidence_file_name(commitment: Hash) -> String {
    let mut name = hash_name(commitment);
    name.push_str(".pse");
    name
}

fn stable_import_certificate_file_name(commitment: Hash) -> String {
    let mut name = hash_name(commitment);
    name.push_str(".psic");
    name
}

fn decode_hash_name(name: &str) -> Option<Hash> {
    if name.len() != 64 || !name.is_ascii() {
        return None;
    }
    let mut value = [0; 32];
    for (index, pair) in name.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0])?;
        let low = decode_lower_hex(pair[1])?;
        value[index] = (high << 4) | low;
    }
    let value = Hash(value);
    (value != Hash::ZERO).then_some(value)
}

fn decode_lower_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_control_attachment_directory(
    root: &Path,
    controls: &[StoredControlIndex],
) -> Result<(), PrivateStoreError> {
    let indexed: BTreeSet<_> = controls.iter().map(|entry| entry.commitment).collect();
    let completed_applications: BTreeSet<_> = controls
        .iter()
        .filter(|entry| entry.runtime_application.is_some())
        .map(|entry| entry.commitment)
        .collect();
    let maximum = controls
        .len()
        .checked_mul(2)
        .ok_or(PrivateStoreError::LimitExceeded)?;
    let mut count = 0usize;
    let mut evidence_controls = BTreeSet::new();
    let mut certificate_controls = BTreeSet::new();
    for entry in fs::read_dir(root.join(CONTROL_EVIDENCE_DIR)).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        count = count
            .checked_add(1)
            .ok_or(PrivateStoreError::LimitExceeded)?;
        if count > maximum {
            return Err(PrivateStoreError::Corrupt);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateStoreError::Corrupt)?;
        let (encoded, certificate) = if let Some(encoded) = name.strip_suffix(".pse") {
            (encoded, false)
        } else if let Some(encoded) = name.strip_suffix(".psic") {
            (encoded, true)
        } else {
            return Err(PrivateStoreError::Corrupt);
        };
        let control = decode_hash_name(encoded).ok_or(PrivateStoreError::Corrupt)?;
        let file_type = entry.file_type().map_err(map_io)?;
        if file_type.is_symlink() || !file_type.is_file() || !indexed.contains(&control) {
            return Err(PrivateStoreError::Corrupt);
        }
        let length = entry.metadata().map_err(map_io)?.len();
        if certificate {
            if length != PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES as u64
                || !completed_applications.contains(&control)
                || !certificate_controls.insert(control)
            {
                return Err(PrivateStoreError::Corrupt);
            }
        } else if length == 0
            || length > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES as u64
            || !evidence_controls.insert(control)
        {
            return Err(PrivateStoreError::Corrupt);
        }
    }
    if !certificate_controls.is_subset(&evidence_controls) {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(())
}

fn artifact_path(root: &Path, artifact: &PendingArtifact) -> PathBuf {
    match artifact {
        PendingArtifact::Object(key) => root.join(OBJECTS_DIR).join(object_file_name(*key)),
        PendingArtifact::Control(commitment) => {
            root.join(CONTROLS_DIR).join(control_file_name(*commitment))
        }
    }
}

fn verify_file_identity(
    path: &Path,
    expected_hash: Hash,
    expected_len: u32,
    max: usize,
) -> Result<Vec<u8>, PrivateStoreError> {
    if expected_len as usize > max {
        return Err(PrivateStoreError::Corrupt);
    }
    let bytes = read_bounded_file(path, max)?;
    if bytes.len() != expected_len as usize || raw_wire_hash(&bytes) != expected_hash {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(bytes)
}

fn verify_runtime_application_file(
    path: &Path,
    binding: StoredRuntimeApplicationIndex,
) -> Result<Vec<u8>, PrivateStoreError> {
    let bytes = verify_file_identity(
        path,
        binding.wire_hash,
        binding.wire_len,
        MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES,
    )?;
    decode_bound_runtime_application(binding, &bytes)?;
    Ok(bytes)
}

fn publish_artifact(root: &Path, pending: &PendingTransaction) -> Result<(), PrivateStoreError> {
    let stage = root.join(STAGE_DIR).join(STAGED_ARTIFACT);
    let target = artifact_path(root, &pending.artifact);
    let max = match pending.artifact {
        PendingArtifact::Object(_) => MAX_PRIVATE_OBJECT_WIRE_BYTES,
        PendingArtifact::Control(_) => MAX_PRIVATE_CONTROL_WIRE_BYTES,
    };
    if target.exists() {
        verify_file_identity(&target, pending.artifact_hash, pending.artifact_len, max)?;
        remove_file_if_present(&stage)?;
    } else {
        verify_file_identity(&stage, pending.artifact_hash, pending.artifact_len, max)?;
        fs::rename(&stage, &target).map_err(map_io)?;
        let parent = target.parent().ok_or(PrivateStoreError::Corrupt)?;
        sync_directory(parent)?;
    }
    Ok(())
}

fn publish_index(root: &Path, pending: &PendingTransaction) -> Result<(), PrivateStoreError> {
    let stage = root.join(STAGE_DIR).join(STAGED_INDEX);
    let target = root.join(INDEX_FILE);
    if stage.exists() {
        verify_file_identity(
            &stage,
            pending.next_index_hash,
            pending.next_index_len,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
        fs::rename(&stage, &target).map_err(map_io)?;
        sync_directory(root)?;
    } else {
        verify_file_identity(
            &target,
            pending.next_index_hash,
            pending.next_index_len,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
    }
    Ok(())
}

fn publish_runtime_application(
    root: &Path,
    pending: &PendingTransaction,
) -> Result<(), PrivateStoreError> {
    let Some(binding) = pending.runtime_application else {
        return Ok(());
    };
    let stage = root.join(STAGE_DIR).join(STAGED_RUNTIME_APPLICATION);
    let target = root
        .join(RUNTIME_APPLICATIONS_DIR)
        .join(runtime_application_file_name(binding.control));
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            verify_runtime_application_file(&target, binding)?;
            match fs::symlink_metadata(&stage) {
                Ok(_) => {
                    // A staged suffix remains attacker-controlled until it is
                    // checked, even when the final copy is already exact.
                    verify_runtime_application_file(&stage, binding)?;
                    remove_file_if_present(&stage)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(PrivateStoreError::Io),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            verify_runtime_application_file(&stage, binding)?;
            fs::rename(&stage, &target).map_err(map_io)?;
            sync_directory(&root.join(RUNTIME_APPLICATIONS_DIR))?;
        }
        Err(_) => return Err(PrivateStoreError::Io),
    }
    Ok(())
}

fn verify_transaction_copies_if_present(
    staged: &Path,
    published: &Path,
    expected_hash: Hash,
    expected_len: u32,
    max: usize,
) -> Result<(), PrivateStoreError> {
    for path in [staged, published] {
        verify_file_identity_if_present(path, expected_hash, expected_len, max)?;
    }
    // With the old index still authoritative, every suffix copy is optional:
    // an earlier rollback attempt may already have retired it before a second
    // crash. Any copy which remains must still match the pending transaction
    // exactly, but absence is the idempotent rolled-back state.
    Ok(())
}

fn verify_file_identity_if_present(
    path: &Path,
    expected_hash: Hash,
    expected_len: u32,
    max: usize,
) -> Result<(), PrivateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_file_identity(path, expected_hash, expected_len, max).map(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrivateStoreError::Io),
    }
}

fn retire_published_copy(
    path: &Path,
    expected_hash: Hash,
    expected_len: u32,
    max: usize,
) -> Result<bool, PrivateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            verify_file_identity(path, expected_hash, expected_len, max)?;
            fs::remove_file(path).map_err(map_io)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PrivateStoreError::Io),
    }
}

fn reconcile_pending(root: &Path) -> Result<(), PrivateStoreError> {
    let stage_dir = root.join(STAGE_DIR);
    let pending_path = stage_dir.join(PENDING_FILE);
    if !pending_path.exists() {
        remove_file_if_present(&stage_dir.join(STAGED_ARTIFACT))?;
        remove_file_if_present(&stage_dir.join(STAGED_RUNTIME_APPLICATION))?;
        remove_file_if_present(&stage_dir.join(STAGED_INDEX))?;
        sync_directory(&stage_dir)?;
        return Ok(());
    }
    let pending_bytes = read_bounded_file(&pending_path, 384)?;
    let pending = decode_pending(&pending_bytes)?;
    let current_index = read_bounded_file(&root.join(INDEX_FILE), MAX_PRIVATE_STORE_INDEX_BYTES)?;
    let current_hash = raw_wire_hash(&current_index);
    let current_len =
        u32::try_from(current_index.len()).map_err(|_| PrivateStoreError::LimitExceeded)?;
    let old_index =
        current_hash == pending.previous_index_hash && current_len == pending.previous_index_len;
    let new_index =
        current_hash == pending.next_index_hash && current_len == pending.next_index_len;
    if old_index == new_index {
        return Err(PrivateStoreError::Corrupt);
    }
    if old_index {
        let staged_artifact = stage_dir.join(STAGED_ARTIFACT);
        let published_artifact = artifact_path(root, &pending.artifact);
        let artifact_max = match pending.artifact {
            PendingArtifact::Object(_) => MAX_PRIVATE_OBJECT_WIRE_BYTES,
            PendingArtifact::Control(_) => MAX_PRIVATE_CONTROL_WIRE_BYTES,
        };
        verify_transaction_copies_if_present(
            &staged_artifact,
            &published_artifact,
            pending.artifact_hash,
            pending.artifact_len,
            artifact_max,
        )?;
        verify_file_identity_if_present(
            &stage_dir.join(STAGED_INDEX),
            pending.next_index_hash,
            pending.next_index_len,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
        if let Some(application) = pending.runtime_application {
            let staged = stage_dir.join(STAGED_RUNTIME_APPLICATION);
            let published = root
                .join(RUNTIME_APPLICATIONS_DIR)
                .join(runtime_application_file_name(application.control));
            verify_transaction_copies_if_present(
                &staged,
                &published,
                application.wire_hash,
                application.wire_len,
                MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES,
            )?;
            for path in [&staged, &published] {
                if path.exists() {
                    verify_runtime_application_file(path, application)?;
                }
            }
            if retire_published_copy(
                &published,
                application.wire_hash,
                application.wire_len,
                MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES,
            )? {
                sync_directory(&root.join(RUNTIME_APPLICATIONS_DIR))?;
            }
        }
        if retire_published_copy(
            &published_artifact,
            pending.artifact_hash,
            pending.artifact_len,
            artifact_max,
        )? {
            let parent = published_artifact
                .parent()
                .ok_or(PrivateStoreError::Corrupt)?;
            sync_directory(parent)?;
        }
    } else {
        // The new index is authoritative. Its exact PCTL/object and optional
        // PAPL must be made durable from the bound staged copy, or reopening
        // fails closed when either copy is missing or divergent.
        publish_artifact(root, &pending).map_err(|error| match error {
            PrivateStoreError::NotFound => PrivateStoreError::Corrupt,
            other => other,
        })?;
        publish_runtime_application(root, &pending).map_err(|error| match error {
            PrivateStoreError::NotFound => PrivateStoreError::Corrupt,
            other => other,
        })?;
        verify_file_identity(
            &root.join(INDEX_FILE),
            pending.next_index_hash,
            pending.next_index_len,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
    }
    remove_file_if_present(&pending_path)?;
    remove_file_if_present(&stage_dir.join(STAGED_ARTIFACT))?;
    remove_file_if_present(&stage_dir.join(STAGED_RUNTIME_APPLICATION))?;
    remove_file_if_present(&stage_dir.join(STAGED_INDEX))?;
    sync_directory(&stage_dir)
}

fn publish_control_evidence(
    root: &Path,
    pending: PendingControlEvidence,
) -> Result<(), PrivateStoreError> {
    let staged = root.join(STAGE_DIR).join(STAGED_CONTROL_EVIDENCE);
    let target = root
        .join(CONTROL_EVIDENCE_DIR)
        .join(control_evidence_file_name(pending.control));
    publish_control_attachment(
        root,
        &staged,
        &target,
        pending.evidence_hash,
        pending.evidence_len,
        MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES,
    )
}

fn publish_stable_import_certificate(
    root: &Path,
    pending: PendingControlEvidence,
) -> Result<(), PrivateStoreError> {
    let staged = root.join(STAGE_DIR).join(STAGED_STABLE_IMPORT_CERTIFICATE);
    let target = root
        .join(CONTROL_EVIDENCE_DIR)
        .join(stable_import_certificate_file_name(pending.control));
    let Some(certificate) = pending.stable_import_certificate else {
        match fs::symlink_metadata(&target) {
            Ok(_) => return Err(PrivateStoreError::Corrupt),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PrivateStoreError::Io),
        }
        remove_file_if_present(&staged)?;
        return Ok(());
    };
    publish_control_attachment(
        root,
        &staged,
        &target,
        certificate.wire_hash,
        certificate.wire_len,
        PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES,
    )
}

fn publish_control_attachment(
    root: &Path,
    staged: &Path,
    target: &Path,
    expected_hash: Hash,
    expected_len: u32,
    maximum: usize,
) -> Result<(), PrivateStoreError> {
    match fs::symlink_metadata(target) {
        Ok(_) => {
            verify_file_identity(target, expected_hash, expected_len, maximum)?;
            remove_file_if_present(staged)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            verify_file_identity(staged, expected_hash, expected_len, maximum).map_err(
                |error| {
                    if error == PrivateStoreError::NotFound {
                        PrivateStoreError::Corrupt
                    } else {
                        error
                    }
                },
            )?;
            fs::rename(staged, target).map_err(map_io)?;
            sync_directory(&root.join(CONTROL_EVIDENCE_DIR))?;
        }
        Err(_) => return Err(PrivateStoreError::Io),
    }
    Ok(())
}

fn reconcile_pending_control_evidence(root: &Path) -> Result<(), PrivateStoreError> {
    let stage_dir = root.join(STAGE_DIR);
    let pending_path = stage_dir.join(PENDING_CONTROL_EVIDENCE);
    match fs::symlink_metadata(&pending_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            remove_file_if_present(&stage_dir.join(STAGED_CONTROL_EVIDENCE))?;
            remove_file_if_present(&stage_dir.join(STAGED_STABLE_IMPORT_CERTIFICATE))?;
            sync_directory(&stage_dir)?;
            return Ok(());
        }
        Err(_) => return Err(PrivateStoreError::Io),
    }
    let bytes = read_bounded_file(&pending_path, MAX_PENDING_CONTROL_EVIDENCE_BYTES)?;
    let pending = decode_pending_control_evidence(&bytes)?;
    publish_stable_import_certificate(root, pending)?;
    publish_control_evidence(root, pending)?;
    remove_file_if_present(&pending_path)?;
    remove_file_if_present(&stage_dir.join(STAGED_CONTROL_EVIDENCE))?;
    remove_file_if_present(&stage_dir.join(STAGED_STABLE_IMPORT_CERTIFICATE))?;
    sync_directory(&stage_dir)
}

fn write_initial_file(
    root: &Path,
    temporary_name: &str,
    final_name: &str,
    bytes: &[u8],
) -> Result<(), PrivateStoreError> {
    let temporary = root.join(temporary_name);
    let target = root.join(final_name);
    remove_file_if_present(&temporary)?;
    write_new_synced(&temporary, bytes)?;
    fs::rename(&temporary, &target).map_err(map_io)?;
    sync_directory(root)
}

/// Locked, single-writer store for one `(SpaceId, AgentId)` Private scope.
pub struct PrivateStore {
    root: PathBuf,
    _lock: File,
    metadata: RecoveryMetadata,
    index: StoreIndex,
    /// Exact Store-core position computed from authenticated in-memory state.
    /// Only a successful object/control transaction may advance this cache.
    cached_core_position: PrivateStoreCorePosition,
    chain: PrivateControlChainVerifier,
    /// Authenticated epoch records reconstructed from immutable genesis and
    /// the verified control chain. These contain recipient ciphertext only;
    /// unwrapped keys remain a host concern.
    key_epochs: Vec<PrivateKeyEpoch>,
    /// Latest recovery-signed ciphertext grant. Every Recover grant is a full
    /// history snapshot, so retaining older large ciphertexts is unnecessary.
    latest_recovery_keyring: Option<PrivateRecoveryKeyringGrant>,
    #[cfg(test)]
    artifact_reads: core::cell::Cell<u64>,
}

impl PrivateStore {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create<V: PrivateNodeAuthorityVerifier>(
        root: impl AsRef<Path>,
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        recovery_public_key: [u8; 32],
        recovery_encryption_public_key: [u8; 32],
        genesis_epoch: PrivateKeyEpoch,
        genesis_nodes: Vec<PrivateNodeIdentity>,
        authority: &V,
    ) -> Result<Self, PrivateStoreError> {
        // Complete every semantic and canonical-encoding check before the
        // destination path is inspected or created. In particular, a caller
        // must never be left with a poisoned partial Store merely because its
        // genesis authority verifier rejected the supplied node set.
        let chain = PrivateControlChainVerifier::new_genesis(
            space,
            agent,
            owner,
            recovery_public_key,
            recovery_encryption_public_key,
            genesis_epoch.clone(),
            genesis_nodes.clone(),
            authority,
        )?;
        let key_epochs = vec![genesis_epoch.clone()];
        let metadata = RecoveryMetadata {
            space,
            agent,
            owner,
            recovery_public_key,
            recovery_encryption_public_key,
            genesis_epoch,
            genesis_nodes,
        };
        let index = StoreIndex {
            space,
            agent,
            epoch: 0,
            control_head: None,
            next_sequence: 0,
            objects: Vec::new(),
            controls: Vec::new(),
        };
        let cached_core_position = store_core_position(&metadata, &index, &key_epochs)?;
        let recovery_wire = encode_recovery(&metadata)?;
        let index_wire = encode_index(&index)?;

        let root = root.as_ref().to_path_buf();
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(PrivateStoreError::Corrupt);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&root).map_err(map_io)?;
                let metadata = fs::symlink_metadata(&root).map_err(map_io)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(PrivateStoreError::Corrupt);
                }
            }
            Err(_) => return Err(PrivateStoreError::Io),
        }
        let lock = open_lock(&root)?;
        if root.join(RECOVERY_FILE).exists() || root.join(INDEX_FILE).exists() {
            return Err(PrivateStoreError::AlreadyExists);
        }
        fs::create_dir(root.join(OBJECTS_DIR)).map_err(map_io)?;
        fs::create_dir(root.join(CONTROLS_DIR)).map_err(map_io)?;
        fs::create_dir(root.join(RUNTIME_APPLICATIONS_DIR)).map_err(map_io)?;
        fs::create_dir(root.join(CONTROL_EVIDENCE_DIR)).map_err(map_io)?;
        fs::create_dir(root.join(STAGE_DIR)).map_err(map_io)?;
        sync_directory(&root)?;
        write_initial_file(&root, "recovery.initial", RECOVERY_FILE, &recovery_wire)?;
        write_initial_file(&root, "index.initial", INDEX_FILE, &index_wire)?;
        Ok(Self {
            root,
            _lock: lock,
            metadata,
            index,
            cached_core_position,
            chain,
            key_epochs,
            latest_recovery_keyring: None,
            #[cfg(test)]
            artifact_reads: core::cell::Cell::new(0),
        })
    }

    /// Create a new empty Store from only the verified archive's immutable
    /// genesis material.
    ///
    /// Archived controls, completed applications, authority evidence,
    /// ciphertext objects, final membership, and final epoch state are never
    /// imported by this constructor. A caller must replay and verify them
    /// through the ordinary local transition paths before publication.
    pub(crate) fn create_empty_from_verified_genesis<V: PrivateNodeAuthorityVerifier>(
        root: impl AsRef<Path>,
        backup: &VerifiedEncryptedBackup,
        authority: &V,
    ) -> Result<Self, PrivateStoreError> {
        // Validate the complete in-memory container before the ordinary
        // constructor is allowed to touch the destination path. Missing PAPL
        // or PSE attachments remain a valid crash archive here; replay_rows()
        // is the stricter completeness gate.
        backup.validate_backing_vectors()?;
        Self::create(
            root,
            backup.metadata.space,
            backup.metadata.agent,
            backup.metadata.owner,
            backup.metadata.recovery_public_key,
            backup.metadata.recovery_encryption_public_key,
            backup.metadata.genesis_epoch.clone(),
            backup.metadata.genesis_nodes.clone(),
            authority,
        )
    }

    pub fn open<V: PrivateNodeAuthorityVerifier>(
        root: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_agent: AgentId,
        authority: &V,
    ) -> Result<Self, PrivateStoreError> {
        let root = root.as_ref().to_path_buf();
        let root_metadata = fs::symlink_metadata(&root).map_err(map_io)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(PrivateStoreError::Corrupt);
        }
        for directory in [
            OBJECTS_DIR,
            CONTROLS_DIR,
            RUNTIME_APPLICATIONS_DIR,
            CONTROL_EVIDENCE_DIR,
            STAGE_DIR,
        ] {
            let metadata = fs::symlink_metadata(root.join(directory)).map_err(map_io)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(PrivateStoreError::Corrupt);
            }
        }
        let lock = open_lock(&root)?;
        reconcile_pending(&root)?;
        reconcile_pending_control_evidence(&root)?;
        let recovery_bytes = read_bounded_file(
            &root.join(RECOVERY_FILE),
            MAX_PRIVATE_RECOVERY_METADATA_BYTES,
        )?;
        let metadata = decode_recovery(&recovery_bytes)?;
        if metadata.space != expected_space || metadata.agent != expected_agent {
            return Err(PrivateStoreError::InvalidScope);
        }
        let index_bytes = read_bounded_file(&root.join(INDEX_FILE), MAX_PRIVATE_STORE_INDEX_BYTES)?;
        let index = decode_index(&index_bytes)?;
        if index.space != expected_space || index.agent != expected_agent {
            return Err(PrivateStoreError::InvalidScope);
        }
        let mut chain = PrivateControlChainVerifier::new_genesis(
            metadata.space,
            metadata.agent,
            metadata.owner,
            metadata.recovery_public_key,
            metadata.recovery_encryption_public_key,
            metadata.genesis_epoch.clone(),
            metadata.genesis_nodes.clone(),
            authority,
        )?;
        let mut key_epochs = vec![metadata.genesis_epoch.clone()];
        let mut latest_recovery_keyring = None;
        for entry in &index.controls {
            let bytes = verify_file_identity(
                &root
                    .join(CONTROLS_DIR)
                    .join(control_file_name(entry.commitment)),
                entry.wire_hash,
                entry.wire_len,
                MAX_PRIVATE_CONTROL_WIRE_BYTES,
            )?;
            let record = PrivateControlRecord::decode(&bytes)
                .map_err(|_| PrivateStoreError::InvalidRecord)?;
            validate_control_index_entry(entry, &record)?;
            if let Some(application_binding) = entry.runtime_application {
                let application_bytes = verify_runtime_application_file(
                    &root
                        .join(RUNTIME_APPLICATIONS_DIR)
                        .join(runtime_application_file_name(entry.commitment)),
                    application_binding,
                )?;
                let application =
                    decode_bound_runtime_application(application_binding, &application_bytes)?;
                if application.control() != &record {
                    return Err(PrivateStoreError::Corrupt);
                }
            }
            apply_control_transition(&mut chain, &record, authority)?;
            advance_key_epochs(&mut key_epochs, &record)?;
            if let PrivateControlOperation::Recover {
                historical_keyring, ..
            } = &record.operation
            {
                latest_recovery_keyring = Some(historical_keyring.clone());
            }
            if chain.epoch().epoch != entry.resulting_epoch
                || chain.head() != Some(entry.commitment)
                || chain.next_sequence()
                    != entry
                        .sequence
                        .checked_add(1)
                        .ok_or(PrivateStoreError::Corrupt)?
            {
                return Err(PrivateStoreError::Corrupt);
            }
        }
        if chain.epoch().epoch != index.epoch
            || chain.head() != index.control_head
            || chain.next_sequence() != index.next_sequence
            || key_epochs.last() != Some(chain.epoch())
        {
            return Err(PrivateStoreError::Corrupt);
        }
        for entry in &index.objects {
            let path = root.join(OBJECTS_DIR).join(object_file_name(entry.key));
            let bytes = verify_file_identity(
                &path,
                entry.wire_hash,
                entry.wire_len,
                MAX_PRIVATE_OBJECT_WIRE_BYTES,
            )?;
            let object = EncryptedPrivateObject::decode(&bytes)
                .map_err(|_| PrivateStoreError::InvalidRecord)?;
            if object.epoch > index.epoch {
                return Err(PrivateStoreError::Corrupt);
            }
            validate_object_index_entry(entry, &object, metadata.space, metadata.agent)?;
        }
        validate_control_attachment_directory(&root, &index.controls)?;
        let cached_core_position = store_core_position(&metadata, &index, &key_epochs)?;
        Ok(Self {
            root,
            _lock: lock,
            metadata,
            index,
            cached_core_position,
            chain,
            key_epochs,
            latest_recovery_keyring,
            #[cfg(test)]
            artifact_reads: core::cell::Cell::new(0),
        })
    }

    /// Restore a fully authenticated ciphertext archive. Archive validation
    /// and complete control-chain replay happen before the destination path is
    /// opened or created. A pre-existing destination must be an exact prefix
    /// of the archive, making retries safe while rejecting rollback. After
    /// archive authentication, opening an existing store may first reconcile
    /// one of its own previously staged transactions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
        root: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_agent: AgentId,
        expected_owner: PrincipalId,
        expected_recovery_public_key: [u8; 32],
        expected_recovery_encryption_public_key: [u8; 32],
        backup_bytes: &[u8],
        authority: &V,
    ) -> Result<(Self, RestoreDisposition), PrivateStoreError> {
        let backup = verify_encrypted_backup(
            backup_bytes,
            expected_space,
            expected_agent,
            expected_owner,
            expected_recovery_public_key,
            expected_recovery_encryption_public_key,
            authority,
        )?;
        let root = root.as_ref();
        let (mut store, created) = match fs::symlink_metadata(root) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(PrivateStoreError::Corrupt);
                }
                (
                    Self::open(root, expected_space, expected_agent, authority)?,
                    false,
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let initial_index = StoreIndex {
                    space: backup.metadata.space,
                    agent: backup.metadata.agent,
                    epoch: 0,
                    control_head: None,
                    next_sequence: 0,
                    objects: Vec::new(),
                    controls: Vec::new(),
                };
                preflight_restore_runtime_applications(
                    &backup.metadata,
                    &initial_index,
                    core::slice::from_ref(&backup.metadata.genesis_epoch),
                    &backup,
                )?;
                (
                    Self::create(
                        root,
                        expected_space,
                        expected_agent,
                        expected_owner,
                        expected_recovery_public_key,
                        expected_recovery_encryption_public_key,
                        backup.metadata.genesis_epoch.clone(),
                        backup.metadata.genesis_nodes.clone(),
                        authority,
                    )?,
                    true,
                )
            }
            Err(_) => return Err(PrivateStoreError::Io),
        };
        if store.metadata != backup.metadata {
            return Err(PrivateStoreError::Diverged);
        }
        validate_restore_prefix(&store.index, &backup.index)?;
        preflight_restore_runtime_applications(
            &store.metadata,
            &store.index,
            &store.key_epochs,
            &backup,
        )?;
        let mut changed = created || store.index != backup.index;
        // Reject a conflicting evidence attachment anywhere in the existing
        // prefix before appending even the first new control. Missing local
        // evidence remains recoverable from an exact archive attachment.
        for (entry, incoming) in store.index.controls.iter().zip(&backup.control_evidence) {
            if let (Some(existing), Some(incoming)) =
                (store.read_control_authority_evidence(entry)?, incoming)
                && existing != *incoming
            {
                return Err(PrivateStoreError::Alias);
            }
        }
        for ((entry, local_application), incoming_application) in store
            .index
            .controls
            .iter()
            .map(|entry| (entry, store.read_runtime_application(entry.commitment)))
            .zip(&backup.runtime_applications)
        {
            if local_application? != incoming_application.clone()
                || entry.runtime_application.is_some() != incoming_application.is_some()
            {
                return Err(PrivateStoreError::Alias);
            }
        }
        let existing_controls = store.index.controls.len();
        for (position, record) in backup.controls.iter().enumerate().skip(existing_controls) {
            match backup
                .runtime_applications
                .get(position)
                .ok_or(PrivateStoreError::Corrupt)?
            {
                Some(application) => {
                    store.append_control_with_runtime_application(
                        record,
                        application,
                        authority,
                    )?;
                }
                None => {
                    store.append_control(record, authority)?;
                }
            }
        }
        for (position, (record, evidence)) in backup
            .controls
            .iter()
            .zip(&backup.control_evidence)
            .enumerate()
        {
            if let Some(evidence) = evidence {
                let entry = store
                    .index
                    .controls
                    .get(position)
                    .ok_or(PrivateStoreError::Corrupt)?;
                if store
                    .read_control_authority_evidence(entry)?
                    .is_some_and(|existing| existing == *evidence)
                {
                    // In particular, retain an already-reattached node-local
                    // PSI1. Calling the ordinary evidence seam here would
                    // correctly reject that asymmetric API request.
                    continue;
                }
                changed |= store
                    .persist_control_authority_evidence(record.commitment(), evidence)?
                    == PutDisposition::Inserted;
            }
        }
        for object in &backup.objects {
            store.put_object(object)?;
        }
        if store.index != backup.index {
            return Err(PrivateStoreError::Diverged);
        }
        Ok((
            store,
            if changed {
                RestoreDisposition::Restored
            } else {
                RestoreDisposition::AlreadyPresent
            },
        ))
    }

    /// Durably apply an offline recovery transition after checking the exact
    /// authenticated local head supplied by the recovery ceremony. Only the
    /// signed SDK `Recover` operation is accepted; no secret or caller-owned
    /// authorization assertion crosses this API.
    pub(crate) fn apply_offline_recovery<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        expected_prior_head: Option<Hash>,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.apply_offline_recovery_inner(expected_prior_head, record, authority, CommitStop::Never)
    }

    #[cfg(test)]
    pub(crate) fn apply_offline_recovery_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        expected_prior_head: Option<Hash>,
        record: &PrivateControlRecord,
        authority: &V,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.apply_offline_recovery_inner(expected_prior_head, record, authority, stop)
    }

    fn apply_offline_recovery_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        expected_prior_head: Option<Hash>,
        record: &PrivateControlRecord,
        authority: &V,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        if expected_prior_head == Some(Hash::ZERO)
            || record.signer != PrivateControlSigner::Recovery
            || !matches!(record.operation, PrivateControlOperation::Recover { .. })
        {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &record.operation
        else {
            return Err(PrivateStoreError::InvalidRecord);
        };
        let supersedes_expected = match expected_prior_head {
            Some(head) => superseded_heads.binary_search(&head).is_ok(),
            None => superseded_heads.is_empty() && record.previous.is_none(),
        };
        if !supersedes_expected {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let commitment = record.commitment();
        if self.chain.head() == Some(commitment) {
            return self.append_control_inner(record, authority, stop);
        }
        if self.chain.head() != expected_prior_head {
            return Err(PrivateStoreError::Diverged);
        }
        self.append_control_inner(record, authority, stop)
    }

    pub fn binding(&self) -> PrivateStoreBinding {
        PrivateStoreBinding {
            space: self.metadata.space,
            agent: self.metadata.agent,
            owner: self.metadata.owner,
            epoch: self.chain.epoch().epoch,
            control_head: self.chain.head(),
            next_sequence: self.chain.next_sequence(),
        }
    }

    /// Deterministic cycle-free commitment to the exact authenticated Store
    /// index and full canonical PKEY history held in memory.
    ///
    /// Authority/application evidence and runtime sidecars are deliberately
    /// outside this position, so downstream acknowledgements cannot form a
    /// commitment cycle back into their Store predecessor.
    pub fn core_position(&self) -> Result<PrivateStoreCorePosition, PrivateStoreError> {
        if self.chain.epoch().epoch != self.index.epoch
            || self.chain.head() != self.index.control_head
            || self.chain.next_sequence() != self.index.next_sequence
            || self.key_epochs.last() != Some(self.chain.epoch())
        {
            return Err(PrivateStoreError::Corrupt);
        }
        store_core_position(&self.metadata, &self.index, &self.key_epochs)
    }

    /// Return the already-authenticated Store-core snapshot in O(1) time.
    ///
    /// This is intentionally crate-private and intended for repeated sync-page
    /// target derivation. It cross-checks all scalar bindings against the live
    /// Store view, but does not replace [`Self::core_position`]'s complete
    /// index/key-history drift validation.
    pub(crate) fn cached_core_position(
        &self,
    ) -> Result<PrivateStoreCorePosition, PrivateStoreError> {
        let object_count =
            u32::try_from(self.index.objects.len()).map_err(|_| PrivateStoreError::Corrupt)?;
        let control_count =
            u32::try_from(self.index.controls.len()).map_err(|_| PrivateStoreError::Corrupt)?;
        let cached = self.cached_core_position;
        if cached.validate().is_err()
            || self.metadata.space != self.index.space
            || self.metadata.agent != self.index.agent
            || self.chain.epoch().epoch != self.index.epoch
            || self.chain.head() != self.index.control_head
            || self.chain.next_sequence() != self.index.next_sequence
            || self.key_epochs.last() != Some(self.chain.epoch())
            || cached.space() != self.metadata.space
            || cached.agent() != self.metadata.agent
            || cached.owner() != self.metadata.owner
            || cached.epoch() != self.index.epoch
            || cached.control_head() != self.index.control_head
            || cached.next_sequence() != self.index.next_sequence
            || cached.object_count() != object_count
            || cached.control_count() != control_count
        {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(cached)
    }

    pub fn authorized_nodes(&self) -> &[PrivateNodeIdentity] {
        self.chain.nodes()
    }

    /// Current authenticated ciphertext-only key epoch. This exposes sealed
    /// envelopes and commitments, never an unwrapped owner/data key. A host
    /// uses it to recover its own active keys through the exact authorized
    /// [`PrivateNodeIdentity`] after restart.
    pub fn key_epoch(&self) -> &PrivateKeyEpoch {
        self.chain.epoch()
    }

    /// Authenticated, bounded history of sealed epoch records reconstructed
    /// from durable genesis/control artifacts. It exposes no unwrapped key
    /// material.
    pub(crate) fn key_epochs(&self) -> &[PrivateKeyEpoch] {
        &self.key_epochs
    }

    pub(crate) fn latest_recovery_keyring(&self) -> Option<&PrivateRecoveryKeyringGrant> {
        self.latest_recovery_keyring.as_ref()
    }

    /// Re-read the exact authenticated Invite records for one recipient. The
    /// immutable control files are hash/length checked again so late history
    /// grants cannot be swapped after the store was opened.
    pub(crate) fn invite_history_records(
        &self,
        recipient: &PrivateNodeIdentity,
    ) -> Result<Vec<PrivateControlRecord>, PrivateStoreError> {
        let mut records = Vec::new();
        records
            .try_reserve(self.index.controls.len().min(MAX_PRIVATE_STORE_CONTROLS))
            .map_err(|_| PrivateStoreError::LimitExceeded)?;
        for entry in &self.index.controls {
            let wire = self.read_control_wire(entry)?;
            let record = PrivateControlRecord::decode(&wire)
                .map_err(|_| PrivateStoreError::InvalidRecord)?;
            validate_control_index_entry(entry, &record)?;
            if matches!(
                &record.operation,
                PrivateControlOperation::Invite { node, .. } if node == recipient
            ) {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Offline recovery verification key pinned by immutable genesis
    /// metadata. The corresponding signing key is deliberately never stored
    /// by this type.
    pub fn recovery_public_key(&self) -> [u8; 32] {
        self.metadata.recovery_public_key
    }

    pub fn recovery_encryption_public_key(&self) -> [u8; 32] {
        self.metadata.recovery_encryption_public_key
    }

    pub fn object_count(&self) -> usize {
        self.index.objects.len()
    }

    pub fn control_count(&self) -> usize {
        self.index.controls.len()
    }

    pub fn put_object(
        &mut self,
        object: &EncryptedPrivateObject,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.put_object_inner(object, CommitStop::Never)
    }

    fn put_object_inner(
        &mut self,
        object: &EncryptedPrivateObject,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        if !object.validate() {
            return Err(PrivateStoreError::InvalidRecord);
        }
        if object.space != self.metadata.space || object.agent != self.metadata.agent {
            return Err(PrivateStoreError::InvalidScope);
        }
        if object.epoch > self.chain.epoch().epoch {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let wire = object
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?;
        let key = PrivateObjectKey::from_object(object);
        let wire_hash = raw_wire_hash(&wire);
        match self
            .index
            .objects
            .binary_search_by_key(&key, |entry| entry.key)
        {
            Ok(position) => {
                let existing = self
                    .index
                    .objects
                    .get(position)
                    .ok_or(PrivateStoreError::Corrupt)?;
                if existing.wire_hash != wire_hash || existing.wire_len as usize != wire.len() {
                    return Err(PrivateStoreError::Alias);
                }
                let bytes = self.read_object_wire(existing)?;
                if bytes != wire {
                    return Err(PrivateStoreError::Corrupt);
                }
                return Ok(PutDisposition::AlreadyPresent);
            }
            Err(position) => {
                if self.index.objects.len() >= MAX_PRIVATE_STORE_OBJECTS {
                    return Err(PrivateStoreError::LimitExceeded);
                }
                let mut next = self.index.clone();
                next.objects.insert(
                    position,
                    StoredObjectIndex {
                        key,
                        wire_hash,
                        wire_len: u32::try_from(wire.len())
                            .map_err(|_| PrivateStoreError::LimitExceeded)?,
                    },
                );
                let successor = store_core_position(&self.metadata, &next, &self.key_epochs)?;
                let index_bytes = encode_index(&next)?;
                self.commit_transaction(
                    PendingArtifact::Object(key),
                    &wire,
                    None,
                    &index_bytes,
                    stop,
                )?;
                self.index = next;
                self.cached_core_position = successor;
                debug_assert_eq!(self.core_position().ok(), Some(successor));
            }
        }
        Ok(PutDisposition::Inserted)
    }

    pub(crate) fn append_control<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.append_control_inner(record, authority, CommitStop::Never)
    }

    #[cfg(test)]
    pub(crate) fn append_control_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        authority: &V,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.append_control_inner(record, authority, stop)
    }

    fn append_control_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        authority: &V,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        match self.plan_control_transition(record, authority, ControlPlanMode::Append)? {
            ControlTransitionPlan::AlreadyPresent { index, wire } => {
                let existing = self
                    .index
                    .controls
                    .get(index)
                    .ok_or(PrivateStoreError::Corrupt)?;
                if self.read_control_wire(existing)? != wire {
                    return Err(PrivateStoreError::Corrupt);
                }
                Ok(PutDisposition::AlreadyPresent)
            }
            ControlTransitionPlan::Insert(plan) => {
                let index_bytes = encode_index(&plan.next_index)?;
                self.commit_transaction(
                    PendingArtifact::Control(plan.commitment),
                    &plan.wire,
                    None,
                    &index_bytes,
                    stop,
                )?;
                self.chain = plan.next_chain;
                self.key_epochs = plan.next_key_epochs;
                self.latest_recovery_keyring = plan.next_recovery_keyring;
                self.index = plan.next_index;
                self.cached_core_position = plan.successor;
                debug_assert_eq!(self.core_position().ok(), Some(plan.successor));
                Ok(PutDisposition::Inserted)
            }
        }
    }

    /// Atomically publish one PCTL and its canonical completed public PAPL.
    /// The PAPL binds the exact predecessor and planner-produced successor
    /// PSC1, while its PVRI/PSP commitments are retained in the indexed row.
    pub(crate) fn append_control_with_runtime_application<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        application: &PrivateRuntimeApplication,
        authority: &V,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.append_control_with_runtime_application_inner(
            record,
            application,
            authority,
            CommitStop::Never,
        )
    }

    pub(crate) fn append_control_with_runtime_application_with_stop_for_runtime<
        V: PrivateNodeAuthorityVerifier,
    >(
        &mut self,
        record: &PrivateControlRecord,
        application: &PrivateRuntimeApplication,
        authority: &V,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.append_control_with_runtime_application_inner(record, application, authority, stop)
    }

    fn append_control_with_runtime_application_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        application: &PrivateRuntimeApplication,
        authority: &V,
        stop: CommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        match self.plan_control_transition(record, authority, ControlPlanMode::Append)? {
            ControlTransitionPlan::AlreadyPresent { index, wire } => {
                let entry = self
                    .index
                    .controls
                    .get(index)
                    .ok_or(PrivateStoreError::Corrupt)?;
                if self.read_control_wire(entry)? != wire {
                    return Err(PrivateStoreError::Corrupt);
                }
                if application.control() != record {
                    return Err(PrivateStoreError::InvalidBinding);
                }
                let application_wire = application
                    .encode()
                    .map_err(|_| PrivateStoreError::InvalidRecord)?;
                let binding = bind_runtime_application(application, &application_wire)?;
                let stored = entry
                    .runtime_application
                    .ok_or(PrivateStoreError::Diverged)?;
                if stored != binding {
                    return Err(PrivateStoreError::Alias);
                }
                if self.read_runtime_application_wire_for_entry(entry, stored)? != application_wire
                {
                    return Err(PrivateStoreError::Corrupt);
                }
                Ok(PutDisposition::AlreadyPresent)
            }
            ControlTransitionPlan::Insert(mut plan) => {
                let predecessor = self.core_position()?;
                let (binding, application_wire) =
                    prepare_runtime_application(application, record, predecessor, plan.successor)?;
                let entry = plan
                    .next_index
                    .controls
                    .last_mut()
                    .ok_or(PrivateStoreError::Corrupt)?;
                if entry.commitment != binding.control || entry.runtime_application.is_some() {
                    return Err(PrivateStoreError::Corrupt);
                }
                entry.runtime_application = Some(binding);
                validate_index_shape(&plan.next_index)?;
                if store_core_position(&self.metadata, &plan.next_index, &plan.next_key_epochs)?
                    != plan.successor
                {
                    return Err(PrivateStoreError::Corrupt);
                }
                let index_bytes = encode_index(&plan.next_index)?;
                self.commit_transaction(
                    PendingArtifact::Control(plan.commitment),
                    &plan.wire,
                    Some((binding, &application_wire)),
                    &index_bytes,
                    stop,
                )?;
                self.chain = plan.next_chain;
                self.key_epochs = plan.next_key_epochs;
                self.latest_recovery_keyring = plan.next_recovery_keyring;
                self.index = plan.next_index;
                self.cached_core_position = plan.successor;
                debug_assert_eq!(self.core_position().ok(), Some(plan.successor));
                Ok(PutDisposition::Inserted)
            }
        }
    }

    /// Project the exact PSC1 produced by appending `record` without reading
    /// or writing any Store path. Exact retries are represented explicitly and
    /// project the current position.
    pub(crate) fn preview_control_position<V: PrivateNodeAuthorityVerifier>(
        &self,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<PrivateControlPositionPreview, PrivateStoreError> {
        match self.plan_control_transition(record, authority, ControlPlanMode::Append)? {
            ControlTransitionPlan::AlreadyPresent { .. } => Ok(PrivateControlPositionPreview {
                disposition: PutDisposition::AlreadyPresent,
                position: self.core_position()?,
                key_epoch_commitments: private_key_epoch_commitments(&self.key_epochs)?,
                authorized_nodes: self.chain.nodes().to_vec(),
            }),
            ControlTransitionPlan::Insert(plan) => {
                let key_epoch_commitments = private_key_epoch_commitments(&plan.next_key_epochs)?;
                let authorized_nodes = plan.next_chain.nodes().to_vec();
                Ok(PrivateControlPositionPreview {
                    disposition: PutDisposition::Inserted,
                    position: plan.successor,
                    key_epoch_commitments,
                    authorized_nodes,
                })
            }
        }
    }

    /// Validate the complete next signed control transition without touching
    /// the filesystem. The authoritative Private-application adapter uses
    /// this before staging epoch sidecars, so an invalid PCTL cannot leave
    /// attacker-selected ciphertext in a crash-recovery slot.
    pub(crate) fn validate_next_control<V: PrivateNodeAuthorityVerifier>(
        &self,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<(), PrivateStoreError> {
        match self.plan_control_transition(record, authority, ControlPlanMode::ValidateNew)? {
            ControlTransitionPlan::Insert(_) => Ok(()),
            ControlTransitionPlan::AlreadyPresent { .. } => Err(PrivateStoreError::Alias),
        }
    }

    fn plan_control_transition<V: PrivateNodeAuthorityVerifier>(
        &self,
        record: &PrivateControlRecord,
        authority: &V,
        mode: ControlPlanMode,
    ) -> Result<ControlTransitionPlan, PrivateStoreError> {
        let commitment = record.commitment();
        let mut append_wire = None;
        if mode == ControlPlanMode::Append {
            let wire = record
                .encode()
                .map_err(|_| PrivateStoreError::InvalidRecord)?;
            if let Some((index, existing)) = self
                .index
                .controls
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.commitment == commitment)
            {
                if existing.wire_hash != raw_wire_hash(&wire)
                    || existing.wire_len as usize != wire.len()
                {
                    return Err(PrivateStoreError::Alias);
                }
                return Ok(ControlTransitionPlan::AlreadyPresent { index, wire });
            }
            append_wire = Some(wire);
        }
        if self.index.controls.len() >= MAX_PRIVATE_STORE_CONTROLS {
            return Err(PrivateStoreError::LimitExceeded);
        }
        if self
            .index
            .controls
            .iter()
            .any(|entry| entry.sequence == record.sequence)
        {
            return Err(PrivateStoreError::Alias);
        }

        let mut next_chain = self.chain.clone();
        apply_control_transition(&mut next_chain, record, authority)?;
        let wire = match append_wire {
            Some(wire) => wire,
            None => record
                .encode()
                .map_err(|_| PrivateStoreError::InvalidRecord)?,
        };
        let mut next_key_epochs = self.key_epochs.clone();
        advance_key_epochs(&mut next_key_epochs, record)?;
        let mut next_recovery_keyring = self.latest_recovery_keyring.clone();
        if let PrivateControlOperation::Recover {
            historical_keyring, ..
        } = &record.operation
        {
            next_recovery_keyring = Some(historical_keyring.clone());
        }
        if next_key_epochs.last() != Some(next_chain.epoch())
            || next_chain.head() != Some(commitment)
            || next_chain.next_sequence()
                != record
                    .sequence
                    .checked_add(1)
                    .ok_or(PrivateStoreError::LimitExceeded)?
        {
            return Err(PrivateStoreError::Corrupt);
        }
        let superseded_heads = match &record.operation {
            PrivateControlOperation::Recover {
                superseded_heads, ..
            } => superseded_heads.clone(),
            _ => Vec::new(),
        };
        let entry = StoredControlIndex {
            sequence: record.sequence,
            commitment,
            previous: record.previous,
            resulting_epoch: next_chain.epoch().epoch,
            superseded_heads,
            wire_hash: raw_wire_hash(&wire),
            wire_len: u32::try_from(wire.len()).map_err(|_| PrivateStoreError::LimitExceeded)?,
            runtime_application: None,
        };
        let mut next_index = self.index.clone();
        next_index.controls.push(entry);
        next_index.epoch = next_chain.epoch().epoch;
        next_index.control_head = next_chain.head();
        next_index.next_sequence = next_chain.next_sequence();
        validate_index_shape(&next_index)?;
        let successor = store_core_position(&self.metadata, &next_index, &next_key_epochs)?;
        Ok(ControlTransitionPlan::Insert(PlannedControlTransition {
            commitment,
            wire,
            next_chain,
            next_key_epochs,
            next_recovery_keyring,
            next_index,
            successor,
        }))
    }

    pub fn get_object(
        &self,
        key: PrivateObjectKey,
    ) -> Result<EncryptedPrivateObject, PrivateStoreError> {
        let position = self
            .index
            .objects
            .binary_search_by_key(&key, |entry| entry.key)
            .map_err(|_| PrivateStoreError::NotFound)?;
        let entry = self
            .index
            .objects
            .get(position)
            .ok_or(PrivateStoreError::Corrupt)?;
        let bytes = self.read_object_wire(entry)?;
        let object =
            EncryptedPrivateObject::decode(&bytes).map_err(|_| PrivateStoreError::InvalidRecord)?;
        validate_object_index_entry(entry, &object, self.metadata.space, self.metadata.agent)?;
        Ok(object)
    }

    pub(crate) fn indexed_objects(&self) -> &[StoredObjectIndex] {
        &self.index.objects
    }

    pub(crate) fn indexed_controls(&self) -> &[StoredControlIndex] {
        &self.index.controls
    }

    pub(crate) fn read_object_wire(
        &self,
        entry: &StoredObjectIndex,
    ) -> Result<Vec<u8>, PrivateStoreError> {
        #[cfg(test)]
        self.artifact_reads.set(self.artifact_reads.get() + 1);
        let path = self
            .root
            .join(OBJECTS_DIR)
            .join(object_file_name(entry.key));
        let bytes = verify_file_identity(
            &path,
            entry.wire_hash,
            entry.wire_len,
            MAX_PRIVATE_OBJECT_WIRE_BYTES,
        )?;
        let object =
            EncryptedPrivateObject::decode(&bytes).map_err(|_| PrivateStoreError::InvalidRecord)?;
        validate_object_index_entry(entry, &object, self.metadata.space, self.metadata.agent)?;
        Ok(bytes)
    }

    pub(crate) fn read_control_wire(
        &self,
        entry: &StoredControlIndex,
    ) -> Result<Vec<u8>, PrivateStoreError> {
        #[cfg(test)]
        self.artifact_reads.set(self.artifact_reads.get() + 1);
        let path = self
            .root
            .join(CONTROLS_DIR)
            .join(control_file_name(entry.commitment));
        let bytes = verify_file_identity(
            &path,
            entry.wire_hash,
            entry.wire_len,
            MAX_PRIVATE_CONTROL_WIRE_BYTES,
        )?;
        let record =
            PrivateControlRecord::decode(&bytes).map_err(|_| PrivateStoreError::InvalidRecord)?;
        validate_control_index_entry(entry, &record)?;
        Ok(bytes)
    }

    /// Exact indexed attachment metadata for one control. `None` explicitly
    /// means that the transitional control-only path was used; an unknown
    /// control is `NotFound`.
    pub(crate) fn runtime_application_binding(
        &self,
        control: Hash,
    ) -> Result<Option<StoredRuntimeApplicationIndex>, PrivateStoreError> {
        self.index
            .controls
            .iter()
            .find(|entry| entry.commitment == control)
            .map(|entry| entry.runtime_application)
            .ok_or(PrivateStoreError::NotFound)
    }

    /// Re-read and canonically decode the completed PAPL attached to one
    /// exact PCTL. No runtime image or plaintext state is persisted here.
    pub(crate) fn read_runtime_application(
        &self,
        control: Hash,
    ) -> Result<Option<PrivateRuntimeApplication>, PrivateStoreError> {
        let entry = self
            .index
            .controls
            .iter()
            .find(|entry| entry.commitment == control)
            .ok_or(PrivateStoreError::NotFound)?;
        let Some(binding) = entry.runtime_application else {
            return Ok(None);
        };
        let wire = self.read_runtime_application_wire_for_entry(entry, binding)?;
        let application = decode_bound_runtime_application(binding, &wire)?;
        let control_wire = self.read_control_wire(entry)?;
        let record =
            PrivateControlRecord::decode(&control_wire).map_err(|_| PrivateStoreError::Corrupt)?;
        if application.control() != &record {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(Some(application))
    }

    /// Exact canonical completed-PAPL wire by PCTL commitment. `None` is the
    /// explicit transitional control-only state, never a fabricated value.
    pub(crate) fn read_runtime_application_wire(
        &self,
        control: Hash,
    ) -> Result<Option<Vec<u8>>, PrivateStoreError> {
        let entry = self
            .index
            .controls
            .iter()
            .find(|entry| entry.commitment == control)
            .ok_or(PrivateStoreError::NotFound)?;
        entry
            .runtime_application
            .map(|binding| self.read_runtime_application_wire_for_entry(entry, binding))
            .transpose()
    }

    fn read_runtime_application_wire_for_entry(
        &self,
        entry: &StoredControlIndex,
        binding: StoredRuntimeApplicationIndex,
    ) -> Result<Vec<u8>, PrivateStoreError> {
        if entry.commitment != binding.control
            || entry.runtime_application != Some(binding)
            || !self
                .index
                .controls
                .iter()
                .any(|candidate| candidate == entry)
        {
            return Err(PrivateStoreError::InvalidRecord);
        }
        #[cfg(test)]
        self.artifact_reads.set(self.artifact_reads.get() + 1);
        verify_runtime_application_file(
            &self
                .root
                .join(RUNTIME_APPLICATIONS_DIR)
                .join(runtime_application_file_name(binding.control)),
            binding,
        )
    }

    /// Read the immutable authority-evidence envelope for one exact indexed
    /// control. Absence is a valid crash-intermediate state; callers deciding
    /// whether to export or synchronize must fail closed on `None`.
    pub(crate) fn read_control_authority_evidence(
        &self,
        entry: &StoredControlIndex,
    ) -> Result<Option<Vec<u8>>, PrivateStoreError> {
        #[cfg(test)]
        self.artifact_reads.set(self.artifact_reads.get() + 1);
        if !self
            .index
            .controls
            .iter()
            .any(|candidate| candidate == entry)
        {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let path = self
            .root
            .join(CONTROL_EVIDENCE_DIR)
            .join(control_evidence_file_name(entry.commitment));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(PrivateStoreError::Corrupt)
            }
            Ok(_) => Ok(Some(read_bounded_file(
                &path,
                MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES,
            )?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(PrivateStoreError::Io),
        }
    }

    /// Read the opaque destination-authenticated PSI1 paired with one PSE2.
    ///
    /// Store validates only the exact fixed wire size and filesystem identity;
    /// the physical host must canonically decode and authenticate PSI1 with
    /// its independently supplied destination-node key and runtime context.
    pub(crate) fn read_stable_import_certificate(
        &self,
        entry: &StoredControlIndex,
    ) -> Result<Option<Vec<u8>>, PrivateStoreError> {
        #[cfg(test)]
        self.artifact_reads.set(self.artifact_reads.get() + 1);
        if !self
            .index
            .controls
            .iter()
            .any(|candidate| candidate == entry)
        {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let path = self
            .root
            .join(CONTROL_EVIDENCE_DIR)
            .join(stable_import_certificate_file_name(entry.commitment));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(PrivateStoreError::Corrupt)
            }
            Ok(_) => {
                if entry.runtime_application.is_none() {
                    return Err(PrivateStoreError::Corrupt);
                }
                let bytes = read_bounded_file(&path, PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES)?;
                if bytes.len() != PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES {
                    return Err(PrivateStoreError::Corrupt);
                }
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(PrivateStoreError::Io),
        }
    }

    /// Attach the exact post-coordinator PSE2 bytes to an existing PCTL.
    ///
    /// The store intentionally treats the bytes as opaque. The host adapter
    /// independently verifies their AOI1/PCA2 signatures and exact route and
    /// control bindings before calling this crate-private persistence seam.
    pub(crate) fn persist_control_authority_evidence(
        &mut self,
        control: Hash,
        evidence: &[u8],
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.persist_control_authority_evidence_inner(
            control,
            evidence,
            None,
            ControlEvidenceCommitStop::Never,
        )
    }

    /// Atomically attach one source PSE2 and its destination-authenticated
    /// PSI1 to an already completed local PAPL/PCTL row. The Store treats both
    /// byte strings as opaque; only the host may establish ImportedStable
    /// provenance before entering this persistence seam.
    pub(crate) fn persist_imported_control_authority_evidence(
        &mut self,
        control: Hash,
        evidence: &[u8],
        stable_import_certificate: &[u8],
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.persist_control_authority_evidence_inner(
            control,
            evidence,
            Some(stable_import_certificate),
            ControlEvidenceCommitStop::Never,
        )
    }

    pub(crate) fn persist_imported_control_authority_evidence_with_stop_for_runtime(
        &mut self,
        control: Hash,
        evidence: &[u8],
        stable_import_certificate: &[u8],
        stop: ControlEvidenceCommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.persist_control_authority_evidence_inner(
            control,
            evidence,
            Some(stable_import_certificate),
            stop,
        )
    }

    /// Reattach a PSI1 which was deliberately excluded from a portable PVB3
    /// and was carried instead by a same-node HostArchive. The physical host
    /// must authenticate the certificate and every exact PAPL/PSE binding
    /// before entering this narrowly scoped seam.
    ///
    /// Unlike ordinary imported persistence, restoration starts with the PSE2
    /// already present (it came from PVB3) and PSI1 absent. Keeping this case
    /// separate preserves the generic local-PSE-to-import rejection.
    pub(crate) fn reattach_authenticated_stable_import_certificate_after_restore(
        &mut self,
        control: Hash,
        evidence: &[u8],
        stable_import_certificate: &[u8],
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.persist_control_authority_evidence_inner_with_mode(
            control,
            evidence,
            Some(stable_import_certificate),
            ControlEvidenceCommitStop::Never,
            ControlEvidenceAttachmentMode::AuthenticatedRestore,
        )
    }

    pub(crate) fn persist_control_authority_evidence_with_stop_for_runtime(
        &mut self,
        control: Hash,
        evidence: &[u8],
        stop: ControlEvidenceCommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.persist_control_authority_evidence_inner(control, evidence, None, stop)
    }

    fn persist_control_authority_evidence_inner(
        &mut self,
        control: Hash,
        evidence: &[u8],
        stable_import_certificate: Option<&[u8]>,
        stop: ControlEvidenceCommitStop,
    ) -> Result<PutDisposition, PrivateStoreError> {
        self.persist_control_authority_evidence_inner_with_mode(
            control,
            evidence,
            stable_import_certificate,
            stop,
            ControlEvidenceAttachmentMode::Ordinary,
        )
    }

    fn persist_control_authority_evidence_inner_with_mode(
        &mut self,
        control: Hash,
        evidence: &[u8],
        stable_import_certificate: Option<&[u8]>,
        stop: ControlEvidenceCommitStop,
        mode: ControlEvidenceAttachmentMode,
    ) -> Result<PutDisposition, PrivateStoreError> {
        #[cfg(not(test))]
        let _ = stop;
        if control == Hash::ZERO
            || evidence.is_empty()
            || evidence.len() > MAX_PRIVATE_CONTROL_AUTHORITY_EVIDENCE_BYTES
            || stable_import_certificate.is_some_and(|certificate| {
                certificate.len() != PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES
            })
            || !self
                .index
                .controls
                .iter()
                .any(|entry| entry.commitment == control)
        {
            return Err(PrivateStoreError::InvalidRecord);
        }
        reconcile_pending_control_evidence(&self.root)?;
        let entry = self
            .index
            .controls
            .iter()
            .find(|entry| entry.commitment == control)
            .cloned()
            .ok_or(PrivateStoreError::InvalidRecord)?;
        if stable_import_certificate.is_some() && entry.runtime_application.is_none() {
            return Err(PrivateStoreError::InvalidRecord);
        }
        let existing_evidence = self.read_control_authority_evidence(&entry)?;
        let existing_certificate = self.read_stable_import_certificate(&entry)?;
        match (existing_evidence, existing_certificate) {
            (None, None) => {}
            (Some(existing), certificate)
                if existing.as_slice() == evidence
                    && certificate.as_deref() == stable_import_certificate =>
            {
                return Ok(PutDisposition::AlreadyPresent);
            }
            (Some(_), Some(_)) if stable_import_certificate.is_some() => {
                return Err(PrivateStoreError::Alias);
            }
            (Some(existing), None)
                if stable_import_certificate.is_none() && existing.as_slice() != evidence =>
            {
                return Err(PrivateStoreError::Alias);
            }
            (Some(existing), None)
                if mode == ControlEvidenceAttachmentMode::AuthenticatedRestore
                    && stable_import_certificate.is_some()
                    && existing.as_slice() == evidence => {}
            (Some(_), None)
                if mode == ControlEvidenceAttachmentMode::AuthenticatedRestore
                    && stable_import_certificate.is_some() =>
            {
                return Err(PrivateStoreError::Alias);
            }
            _ => return Err(PrivateStoreError::Corrupt),
        }

        let stage_dir = self.root.join(STAGE_DIR);
        let staged = stage_dir.join(STAGED_CONTROL_EVIDENCE);
        let staged_certificate = stage_dir.join(STAGED_STABLE_IMPORT_CERTIFICATE);
        let pending_path = stage_dir.join(PENDING_CONTROL_EVIDENCE);
        require_paths_absent(&[&staged, &staged_certificate, &pending_path])?;
        write_new_synced(&staged, evidence)?;
        #[cfg(test)]
        if stop == ControlEvidenceCommitStop::AfterEvidenceStaged {
            return Err(PrivateStoreError::Interrupted);
        }
        if let Some(certificate) = stable_import_certificate {
            write_new_synced(&staged_certificate, certificate)?;
        }
        #[cfg(test)]
        if stop == ControlEvidenceCommitStop::AfterStaged {
            return Err(PrivateStoreError::Interrupted);
        }
        let pending = PendingControlEvidence {
            control,
            evidence_hash: raw_wire_hash(evidence),
            evidence_len: u32::try_from(evidence.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
            stable_import_certificate: stable_import_certificate
                .map(|certificate| -> Result<_, PrivateStoreError> {
                    Ok(PendingStableImportCertificate {
                        wire_hash: raw_wire_hash(certificate),
                        wire_len: u32::try_from(certificate.len())
                            .map_err(|_| PrivateStoreError::LimitExceeded)?,
                    })
                })
                .transpose()?,
        };
        write_new_synced(&pending_path, &encode_pending_control_evidence(pending)?)?;
        sync_directory(&stage_dir)?;
        #[cfg(test)]
        if stop == ControlEvidenceCommitStop::AfterPending {
            return Err(PrivateStoreError::Interrupted);
        }
        publish_stable_import_certificate(&self.root, pending)?;
        #[cfg(test)]
        if stop == ControlEvidenceCommitStop::AfterCertificatePublished {
            return Err(PrivateStoreError::Interrupted);
        }
        publish_control_evidence(&self.root, pending)?;
        #[cfg(test)]
        if stop == ControlEvidenceCommitStop::AfterPublished {
            return Err(PrivateStoreError::Interrupted);
        }
        remove_file_if_present(&pending_path)?;
        remove_file_if_present(&staged_certificate)?;
        #[cfg(test)]
        if stop == ControlEvidenceCommitStop::AfterRetired {
            return Err(PrivateStoreError::Interrupted);
        }
        sync_directory(&stage_dir)?;
        Ok(PutDisposition::Inserted)
    }

    pub(crate) fn prevalidate_controls<V: PrivateNodeAuthorityVerifier>(
        &self,
        records: &[PrivateControlRecord],
        authority: &V,
    ) -> Result<Vec<u64>, PrivateStoreError> {
        let mut chain = self.chain.clone();
        let mut epochs = Vec::new();
        epochs
            .try_reserve(records.len())
            .map_err(|_| PrivateStoreError::LimitExceeded)?;
        for record in records {
            apply_control_transition(&mut chain, record, authority)?;
            epochs.push(chain.epoch().epoch);
        }
        Ok(epochs)
    }

    pub(crate) fn object_is_exact(
        &self,
        key: PrivateObjectKey,
        wire: &[u8],
    ) -> Result<bool, PrivateStoreError> {
        match self
            .index
            .objects
            .binary_search_by_key(&key, |entry| entry.key)
        {
            Ok(position) => {
                let entry = self
                    .index
                    .objects
                    .get(position)
                    .ok_or(PrivateStoreError::Corrupt)?;
                if entry.wire_hash != raw_wire_hash(wire) || entry.wire_len as usize != wire.len() {
                    return Err(PrivateStoreError::Alias);
                }
                if self.read_object_wire(entry)? != wire {
                    return Err(PrivateStoreError::Corrupt);
                }
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub(crate) fn control_is_exact(
        &self,
        commitment: Hash,
        wire: &[u8],
    ) -> Result<bool, PrivateStoreError> {
        let Some(entry) = self
            .index
            .controls
            .iter()
            .find(|entry| entry.commitment == commitment)
        else {
            return Ok(false);
        };
        if entry.wire_hash != raw_wire_hash(wire) || entry.wire_len as usize != wire.len() {
            return Err(PrivateStoreError::Alias);
        }
        if self.read_control_wire(entry)? != wire {
            return Err(PrivateStoreError::Corrupt);
        }
        Ok(true)
    }

    fn commit_transaction(
        &self,
        artifact: PendingArtifact,
        artifact_bytes: &[u8],
        runtime_application: Option<(StoredRuntimeApplicationIndex, &[u8])>,
        next_index_bytes: &[u8],
        stop: CommitStop,
    ) -> Result<(), PrivateStoreError> {
        let stage_dir = self.root.join(STAGE_DIR);
        let pending_path = stage_dir.join(PENDING_FILE);
        if pending_path.exists() {
            return Err(PrivateStoreError::Corrupt);
        }
        let staged_artifact = stage_dir.join(STAGED_ARTIFACT);
        let staged_runtime_application = stage_dir.join(STAGED_RUNTIME_APPLICATION);
        let staged_index = stage_dir.join(STAGED_INDEX);
        remove_file_if_present(&staged_artifact)?;
        remove_file_if_present(&staged_runtime_application)?;
        remove_file_if_present(&staged_index)?;
        let previous_index_bytes = encode_index(&self.index)?;
        verify_file_identity(
            &self.root.join(INDEX_FILE),
            raw_wire_hash(&previous_index_bytes),
            u32::try_from(previous_index_bytes.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
        write_new_synced(&staged_artifact, artifact_bytes)?;
        #[cfg(test)]
        if stop == CommitStop::AfterStagedArtifact {
            return Err(PrivateStoreError::Interrupted);
        }
        if let Some((binding, bytes)) = runtime_application {
            decode_bound_runtime_application(binding, bytes)
                .map_err(|_| PrivateStoreError::InvalidBinding)?;
            write_new_synced(&staged_runtime_application, bytes)?;
        }
        #[cfg(test)]
        if stop == CommitStop::AfterStagedRuntimeApplication {
            return Err(PrivateStoreError::Interrupted);
        }
        write_new_synced(&staged_index, next_index_bytes)?;
        #[cfg(test)]
        if stop == CommitStop::AfterStagedIndex {
            return Err(PrivateStoreError::Interrupted);
        }
        let pending = PendingTransaction {
            artifact,
            artifact_hash: raw_wire_hash(artifact_bytes),
            artifact_len: u32::try_from(artifact_bytes.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
            previous_index_hash: raw_wire_hash(&previous_index_bytes),
            previous_index_len: u32::try_from(previous_index_bytes.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
            next_index_hash: raw_wire_hash(next_index_bytes),
            next_index_len: u32::try_from(next_index_bytes.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
            runtime_application: runtime_application.map(|(binding, _)| binding),
        };
        write_new_synced(&pending_path, &encode_pending(&pending)?)?;
        sync_directory(&stage_dir)?;
        #[cfg(test)]
        if matches!(stop, CommitStop::AfterPending | CommitStop::AfterStage) {
            return Err(PrivateStoreError::Interrupted);
        }
        let _ = stop;
        publish_artifact(&self.root, &pending)?;
        #[cfg(test)]
        if stop == CommitStop::AfterArtifact {
            return Err(PrivateStoreError::Interrupted);
        }
        publish_runtime_application(&self.root, &pending)?;
        #[cfg(test)]
        if stop == CommitStop::AfterRuntimeApplication {
            return Err(PrivateStoreError::Interrupted);
        }
        publish_index(&self.root, &pending)?;
        #[cfg(test)]
        if stop == CommitStop::AfterIndex {
            return Err(PrivateStoreError::Interrupted);
        }
        remove_file_if_present(&pending_path)?;
        sync_directory(&stage_dir)
    }

    pub fn export_encrypted_snapshot(
        &self,
        max_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStoreError> {
        let maximum = max_bytes.min(MAX_PRIVATE_BACKUP_BYTES);
        let recovery = encode_recovery(&self.metadata)?;
        let index = encode_index(&self.index)?;
        let mut encoder = Encoder::new(SNAPSHOT_MAGIC);
        encoder.bytes(&recovery)?;
        encoder.bytes(&index)?;
        encoder.finish(maximum)
    }

    pub fn export_encrypted_backup(&self, max_bytes: usize) -> Result<Vec<u8>, PrivateStoreError> {
        let maximum = max_bytes.min(MAX_PRIVATE_BACKUP_BYTES);
        let recovery = encode_recovery(&self.metadata)?;
        let index = encode_index(&self.index)?;
        let mut encoder = Encoder::new(BACKUP_MAGIC);
        encoder.bytes(&recovery)?;
        encoder.bytes(&index)?;
        encoder.u32(
            u32::try_from(self.index.controls.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
        );
        for entry in &self.index.controls {
            encoder.fixed(entry.commitment.as_bytes());
            encoder.bytes(&self.read_control_wire(entry)?)?;
            match self.read_control_authority_evidence(entry)? {
                None => encoder.u8(0),
                Some(evidence) => {
                    encoder.u8(1);
                    encoder.bytes(&evidence)?;
                }
            }
            match entry.runtime_application {
                None => encoder.u8(0),
                Some(binding) => {
                    encoder.u8(1);
                    encoder
                        .bytes(&self.read_runtime_application_wire_for_entry(entry, binding)?)?;
                }
            }
            if encoder.0.len() > maximum {
                return Err(PrivateStoreError::LimitExceeded);
            }
        }
        encoder.u32(
            u32::try_from(self.index.objects.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
        );
        for entry in &self.index.objects {
            encode_object_key(&mut encoder, entry.key);
            encoder.bytes(&self.read_object_wire(entry)?)?;
            if encoder.0.len() > maximum {
                return Err(PrivateStoreError::LimitExceeded);
            }
        }
        encoder.finish(maximum)
    }

    #[cfg(test)]
    pub(crate) fn reset_artifact_read_spy(&self) {
        self.artifact_reads.set(0);
    }

    #[cfg(test)]
    pub(crate) fn artifact_read_spy(&self) -> u64 {
        self.artifact_reads.get()
    }
}

fn validate_restore_prefix(
    local: &StoreIndex,
    archive: &StoreIndex,
) -> Result<(), PrivateStoreError> {
    if local.space != archive.space || local.agent != archive.agent {
        return Err(PrivateStoreError::InvalidScope);
    }
    if local.controls.len() > archive.controls.len() {
        return Err(PrivateStoreError::Rollback);
    }
    for (local_entry, archive_entry) in local.controls.iter().zip(&archive.controls) {
        if local_entry.sequence != archive_entry.sequence
            || local_entry.commitment != archive_entry.commitment
        {
            return Err(PrivateStoreError::Diverged);
        }
        if local_entry != archive_entry {
            return Err(PrivateStoreError::Alias);
        }
    }
    match local.controls.last() {
        Some(last)
            if local.control_head != Some(last.commitment)
                || local.epoch != last.resulting_epoch
                || last.sequence.checked_add(1) != Some(local.next_sequence) =>
        {
            return Err(PrivateStoreError::Diverged);
        }
        None if local.control_head.is_some() || local.epoch != 0 || local.next_sequence != 0 => {
            return Err(PrivateStoreError::Diverged);
        }
        _ => {}
    }

    if local.objects.len() > archive.objects.len() {
        return Err(PrivateStoreError::Rollback);
    }
    for (local_entry, archive_entry) in local.objects.iter().zip(&archive.objects) {
        if archive_entry.key != local_entry.key {
            return Err(PrivateStoreError::Diverged);
        }
        if archive_entry != local_entry {
            return Err(PrivateStoreError::Alias);
        }
    }
    Ok(())
}

/// Generation three archives retain final ciphertext objects but not their
/// insertion chronology. Preflight the exact current restore order (existing
/// objects, then missing controls, then missing objects) so a PAPL whose
/// historical PSC1 object prefix cannot be reconstructed is rejected before
/// any new control or attachment is published. Chapter 08 can remove this
/// fail-closed limitation when it adds authenticated per-control history.
fn preflight_restore_runtime_applications(
    metadata: &RecoveryMetadata,
    local_index: &StoreIndex,
    local_key_epochs: &[PrivateKeyEpoch],
    archive: &VerifiedEncryptedBackup,
) -> Result<(), PrivateStoreError> {
    if local_index.controls.len() > archive.index.controls.len() || local_key_epochs.is_empty() {
        return Err(PrivateStoreError::Corrupt);
    }
    let mut index = local_index.clone();
    let mut key_epochs = local_key_epochs.to_vec();
    for position in local_index.controls.len()..archive.index.controls.len() {
        let record = archive
            .controls
            .get(position)
            .ok_or(PrivateStoreError::Corrupt)?;
        let archive_entry = archive
            .index
            .controls
            .get(position)
            .ok_or(PrivateStoreError::Corrupt)?;
        let application = archive
            .runtime_applications
            .get(position)
            .ok_or(PrivateStoreError::Corrupt)?;
        if archive_entry.runtime_application.is_some() != application.is_some() {
            return Err(PrivateStoreError::Corrupt);
        }
        let predecessor = store_core_position(metadata, &index, &key_epochs)?;
        advance_key_epochs(&mut key_epochs, record)?;
        index.controls.push(archive_entry.clone());
        index.epoch = archive_entry.resulting_epoch;
        index.control_head = Some(archive_entry.commitment);
        index.next_sequence = archive_entry
            .sequence
            .checked_add(1)
            .ok_or(PrivateStoreError::LimitExceeded)?;
        validate_index_shape(&index)?;
        let successor = store_core_position(metadata, &index, &key_epochs)?;
        if let Some(application) = application {
            let (binding, _) =
                prepare_runtime_application(application, record, predecessor, successor)?;
            if archive_entry.runtime_application != Some(binding) {
                return Err(PrivateStoreError::Corrupt);
            }
        }
    }
    Ok(())
}

fn validate_object_index_entry(
    entry: &StoredObjectIndex,
    object: &EncryptedPrivateObject,
    space: SpaceId,
    agent: AgentId,
) -> Result<(), PrivateStoreError> {
    if !object.validate()
        || object.space != space
        || object.agent != agent
        || PrivateObjectKey::from_object(object) != entry.key
    {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(())
}

fn validate_control_index_entry(
    entry: &StoredControlIndex,
    record: &PrivateControlRecord,
) -> Result<(), PrivateStoreError> {
    let superseded_heads = match &record.operation {
        PrivateControlOperation::Recover {
            superseded_heads, ..
        } => superseded_heads.as_slice(),
        _ => &[],
    };
    if !record.validate_shape()
        || record.sequence != entry.sequence
        || record.commitment() != entry.commitment
        || record.previous != entry.previous
        || superseded_heads != entry.superseded_heads
    {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(())
}

fn bind_runtime_application(
    application: &PrivateRuntimeApplication,
    wire: &[u8],
) -> Result<StoredRuntimeApplicationIndex, PrivateStoreError> {
    if application.validate().is_err() || !application.is_complete() {
        return Err(PrivateStoreError::InvalidRecord);
    }
    let successor_runtime_image = application
        .successor_runtime_image()
        .ok_or(PrivateStoreError::InvalidRecord)?;
    let successor_stable_projection = application
        .successor_stable_projection()
        .ok_or(PrivateStoreError::InvalidRecord)?
        .commitment();
    let binding = StoredRuntimeApplicationIndex {
        control: application.control().commitment(),
        application: application.commitment(),
        wire_hash: raw_wire_hash(wire),
        wire_len: u32::try_from(wire.len()).map_err(|_| PrivateStoreError::LimitExceeded)?,
        successor_runtime_image,
        successor_stable_projection,
    };
    if !runtime_application_index_shape_is_valid(&binding) {
        return Err(PrivateStoreError::InvalidRecord);
    }
    Ok(binding)
}

fn prepare_runtime_application(
    application: &PrivateRuntimeApplication,
    record: &PrivateControlRecord,
    predecessor: PrivateStoreCorePosition,
    successor: PrivateStoreCorePosition,
) -> Result<(StoredRuntimeApplicationIndex, Vec<u8>), PrivateStoreError> {
    if application.control() != record
        || application.predecessor_store() != predecessor
        || application.expected_successor_store() != successor
    {
        return Err(PrivateStoreError::InvalidBinding);
    }
    let wire = application
        .encode()
        .map_err(|_| PrivateStoreError::InvalidRecord)?;
    if wire.len() > MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES {
        return Err(PrivateStoreError::LimitExceeded);
    }
    let binding = bind_runtime_application(application, &wire)?;
    Ok((binding, wire))
}

fn decode_bound_runtime_application(
    binding: StoredRuntimeApplicationIndex,
    wire: &[u8],
) -> Result<PrivateRuntimeApplication, PrivateStoreError> {
    if wire.len() != binding.wire_len as usize
        || raw_wire_hash(wire) != binding.wire_hash
        || !runtime_application_index_shape_is_valid(&binding)
    {
        return Err(PrivateStoreError::Corrupt);
    }
    let application =
        PrivateRuntimeApplication::decode(wire).map_err(|_| PrivateStoreError::Corrupt)?;
    if application
        .encode()
        .map_err(|_| PrivateStoreError::Corrupt)?
        != wire
        || bind_runtime_application(&application, wire).map_err(|_| PrivateStoreError::Corrupt)?
            != binding
    {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(application)
}

/// Advance the ciphertext-only epoch history in lockstep with one control
/// record which has already passed full chain verification.
fn advance_key_epochs(
    epochs: &mut Vec<PrivateKeyEpoch>,
    record: &PrivateControlRecord,
) -> Result<(), PrivateStoreError> {
    let current = epochs.last_mut().ok_or(PrivateStoreError::Corrupt)?;
    match &record.operation {
        PrivateControlOperation::Invite {
            node,
            epoch,
            sealed_owner_key,
            sealed_data_key,
            ..
        } => {
            if current.epoch != *epoch {
                return Err(PrivateStoreError::Corrupt);
            }
            let position = current
                .sealed_owner_keys
                .binary_search_by_key(&node.node, |sealed| sealed.node)
                .err()
                .ok_or(PrivateStoreError::Corrupt)?;
            current
                .sealed_owner_keys
                .insert(position, sealed_owner_key.clone());
            current
                .sealed_data_keys
                .insert(position, sealed_data_key.clone());
            if !current.validate() {
                return Err(PrivateStoreError::Corrupt);
            }
        }
        PrivateControlOperation::Revoke { next_epoch, .. }
        | PrivateControlOperation::RotateKeys { next_epoch }
        | PrivateControlOperation::Recover { next_epoch, .. } => {
            if next_epoch.epoch <= current.epoch
                || epochs.len() >= MAX_PRIVATE_STORE_CONTROLS.saturating_add(1)
            {
                return Err(PrivateStoreError::Corrupt);
            }
            epochs.push(next_epoch.clone());
        }
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {}
    }
    Ok(())
}

fn apply_control_transition<V: PrivateNodeAuthorityVerifier>(
    chain: &mut PrivateControlChainVerifier,
    record: &PrivateControlRecord,
    authority: &V,
) -> Result<(), PrivateStoreError> {
    match chain.apply(record, authority) {
        Ok(()) => Ok(()),
        Err(PrivateCryptoError::WrongPrevious | PrivateCryptoError::WrongSequence)
            if matches!(record.operation, PrivateControlOperation::Recover { .. }) =>
        {
            chain
                .apply_recovery_from_superseded_head(record, authority)
                .map_err(PrivateStoreError::Crypto)
        }
        Err(error) => Err(PrivateStoreError::Crypto(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicU64, Ordering};

    use vos_agent_sdk::authority::{
        AgentAuthorityBinding, AuthorityActorTarget, AuthorityEvidence, AuthorityIssuer,
        AuthorityLaneRoots, AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
        AuthorityVerifier,
    };
    use vos_agent_sdk::authority_operation::{
        AuthorityOperationIssuanceAck, PrivateRecoveryAuthorityProofVerifier,
    };
    use vos_agent_sdk::contract::RuntimePackageContract;
    use vos_agent_sdk::private::{EncryptedObjectKind, recovery_signing_public_key_commitment};

    use crate::agent::private_crypto::{
        GeneratedPrivateEpoch, OfflineRecoveryDecryptionKey, OwnerSigningKey,
        PrivateNodeDecryptionKey, RecoverySigningKey, build_recovery_keyring_grant,
        encrypt_private_object, generate_fresh_private_epoch, seal_data_key_for_node,
        seal_owner_key_for_node, sign_owner_control_record, sign_recovery_control_record,
        unwrap_recovery_data_key,
    };
    use vos_agent_sdk::{
        ActorId, AgentDescriptor, AgentIdentity, AgentProfile, AgentReplica, BlobRef, DeploymentId,
        ManagementRequest, NodeId, PrivateRecoveryBinding, ProducerId, ProgramId, ReplicaRole,
        RuntimeCapabilities, RuntimeState,
    };

    use crate::agent::private_runtime::{PrivateRuntimeImage, PrivateRuntimeSuccess};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const TEST_AUTHORITY_DOMAIN: &[u8] = b"vos/test/private-store-authority/v1";
    const RUNTIME_PLAINTEXT_SENTINEL: &[u8] = b"PRIVATE-RUNTIME-STATE-SENTINEL-2d9e";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-private-store-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestAuthority;
    struct DenyAuthority;

    struct AllowRuntimeVerifier;

    impl AuthorityVerifier for AllowRuntimeVerifier {
        fn verify(&self, _public_key: &[u8; 32], _message: &[u8], _signature: &[u8; 64]) -> bool {
            true
        }
    }

    impl PrivateRecoveryAuthorityProofVerifier for AllowRuntimeVerifier {
        fn verify_private_recovery_authority_proof(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> bool {
            true
        }
    }

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

    impl PrivateNodeAuthorityVerifier for DenyAuthority {
        fn verify_private_node_binding(
            &self,
            _space: SpaceId,
            _agent: AgentId,
            _expected_principal: PrincipalId,
            _node: &PrivateNodeIdentity,
        ) -> bool {
            false
        }
    }

    struct Fixture {
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        owner_key: OwnerSigningKey,
        recovery: RecoverySigningKey,
        recovery_encryption: OfflineRecoveryDecryptionKey,
        nodes: Vec<PrivateNodeIdentity>,
        epoch: GeneratedPrivateEpoch,
    }

    fn fixture() -> Fixture {
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let owner = PrincipalId([3; 32]);
        let recovery = RecoverySigningKey::from_seed([4; 32]).unwrap();
        let recovery_encryption = OfflineRecoveryDecryptionKey::from_bytes([8; 32]).unwrap();
        let node_key = PrivateNodeDecryptionKey::from_bytes([5; 32]).unwrap();
        let transport_identity = vec![6; 48];
        let mut node = PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: owner,
            transport_identity,
            encryption_public_key: node_key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [7; 64],
        };
        node.authority_binding = TestAuthority::binding(space, agent, owner, &node);
        let nodes = vec![node];
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
        // The control key must be the one committed by the generated epoch.
        let unwrapped_owner =
            crate::agent::private_crypto::unwrap_owner_key(&epoch.record, &nodes[0], &node_key)
                .unwrap();
        Fixture {
            space,
            agent,
            owner,
            owner_key: unwrapped_owner,
            recovery,
            recovery_encryption,
            nodes,
            epoch,
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

    struct RuntimeStoreFixture {
        store_fixture: Fixture,
        descriptor: AgentDescriptor,
        predecessor: PrivateRuntimeImage,
    }

    fn test_hash(marker: u8) -> Hash {
        Hash([marker; 32])
    }

    fn runtime_genesis(
        store: &PrivateStore,
        descriptor: &AgentDescriptor,
        node: NodeId,
        genesis_at: u64,
    ) -> PrivateRuntimeImage {
        let key_epochs = store
            .key_epochs
            .iter()
            .map(|epoch| PrivateKeyEpochCommitment::from_epoch(epoch).unwrap())
            .collect();
        let creation_receipt = AuthorityReceipt {
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
                    commitment: test_hash(0xa7),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: descriptor.authority.initial_epoch,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: genesis_at,
                expires_at: 40,
                request: ManagementRequest::Create(Box::new(descriptor.clone())).commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [0xa8; 64],
        };
        PrivateRuntimeImage::genesis(
            descriptor,
            node,
            RuntimeState {
                control: RUNTIME_PLAINTEXT_SENTINEL.to_vec(),
                linear: Vec::new(),
                merge: RUNTIME_PLAINTEXT_SENTINEL.to_vec(),
                local: RUNTIME_PLAINTEXT_SENTINEL.to_vec(),
            },
            store.core_position().unwrap(),
            key_epochs,
            creation_receipt,
            genesis_at,
            &AllowRuntimeVerifier,
        )
        .unwrap()
    }

    fn runtime_store_fixture(path: &Path) -> (PrivateStore, RuntimeStoreFixture) {
        let space = SpaceId([0x91; 32]);
        let owner = PrincipalId([0x92; 32]);
        let creation_nonce = test_hash(0x93);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let recovery = RecoverySigningKey::from_seed([0x94; 32]).unwrap();
        let recovery_encryption = OfflineRecoveryDecryptionKey::from_bytes([0x95; 32]).unwrap();
        let node_key = PrivateNodeDecryptionKey::from_bytes([0x96; 32]).unwrap();
        let transport_identity = vec![0x97; 48];
        let mut node = PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: owner,
            transport_identity,
            encryption_public_key: node_key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [0x98; 64],
        };
        node.authority_binding = TestAuthority::binding(space, agent, owner, &node);
        let alternate_node_key = PrivateNodeDecryptionKey::from_bytes([0xa4; 32]).unwrap();
        let alternate_transport_identity = vec![0xa5; 48];
        let mut alternate_node = PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&alternate_transport_identity),
            principal: owner,
            transport_identity: alternate_transport_identity,
            encryption_public_key: alternate_node_key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [0xa6; 64],
        };
        alternate_node.authority_binding =
            TestAuthority::binding(space, agent, owner, &alternate_node);
        let mut nodes = vec![node.clone(), alternate_node];
        nodes.sort_unstable_by_key(|candidate| candidate.node);
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
        let owner_key =
            crate::agent::private_crypto::unwrap_owner_key(&epoch.record, &node, &node_key)
                .unwrap();
        let store_fixture = Fixture {
            space,
            agent,
            owner,
            owner_key,
            recovery,
            recovery_encryption,
            nodes,
            epoch,
        };
        let authority_public_key = [0x99; 32];
        let authority = AgentAuthorityBinding {
            policy: test_hash(0x9a),
            issuer: AuthorityIssuer {
                principal: PrincipalId([0x9b; 32]),
                actor: ActorId([0x9c; 32]),
                deployment: DeploymentId([0x9d; 32]),
                program: ProgramId([0x9e; 32]),
                producer: ProducerId::of_public_key(&authority_public_key),
            },
            public_key: authority_public_key,
            initial_epoch: 1,
        };
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Private,
                runtime_deployment: DeploymentId([0xa1; 32]),
                runtime_program: ProgramId([0xa2; 32]),
                runtime_producer: ProducerId([0xa3; 32]),
                transition_producer: ProducerId([0xa4; 32]),
            },
            creation_nonce,
            authority,
            private_recovery: Some(PrivateRecoveryBinding {
                signing_key_commitment: recovery_signing_public_key_commitment(
                    &store_fixture.recovery.verifying_key(),
                ),
                encryption_public_key: store_fixture.recovery_encryption.public_key(),
            }),
            runtime_package: BlobRef::of_bytes(b"private-store-runtime-package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: store_fixture
                .nodes
                .iter()
                .map(|node| AgentReplica {
                    node: node.node,
                    principal: owner,
                    role: ReplicaRole::Observer,
                })
                .collect(),
        };
        descriptor.validate().unwrap();
        let store = create_store(path, &store_fixture);
        let predecessor = runtime_genesis(&store, &descriptor, node.node, 3);
        (
            store,
            RuntimeStoreFixture {
                store_fixture,
                descriptor,
                predecessor,
            },
        )
    }

    fn runtime_receipt(
        fixture: &RuntimeStoreFixture,
        control: &PrivateControlRecord,
        marker: u8,
    ) -> AuthorityReceipt {
        AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: fixture.descriptor.authority.policy,
                issuer: fixture.descriptor.authority.issuer,
                space: fixture.descriptor.identity.space,
                agent: fixture.descriptor.identity.agent,
                operation: match control.operation {
                    PrivateControlOperation::Invite { .. } => {
                        AuthorityOperationKind::InvitePrivateNode
                    }
                    PrivateControlOperation::Revoke { .. } => {
                        AuthorityOperationKind::RevokePrivateNode
                    }
                    PrivateControlOperation::RotateKeys { .. } => {
                        AuthorityOperationKind::RotatePrivateKeys
                    }
                    PrivateControlOperation::Recover { .. } => {
                        AuthorityOperationKind::RecoverPrivateAgent
                    }
                    PrivateControlOperation::SetResourcePolicy { .. } => {
                        AuthorityOperationKind::SetPrivateResourcePolicy
                    }
                    PrivateControlOperation::ActorLifecycle { .. } => {
                        AuthorityOperationKind::PrivateActorLifecycle
                    }
                },
                runtime_deployment: fixture.descriptor.identity.runtime_deployment,
                actor: None,
                actor_deployment: None,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: test_hash(marker),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: fixture.descriptor.authority.initial_epoch,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 4,
                expires_at: 40,
                request: control.commitment(),
            },
            public_key: fixture.descriptor.authority.public_key,
            signature: [marker.wrapping_add(1); 64],
        }
    }

    fn completed_runtime_application(
        store: &PrivateStore,
        fixture: &RuntimeStoreFixture,
        predecessor: &PrivateRuntimeImage,
        control: &PrivateControlRecord,
        marker: u8,
    ) -> (
        PrivateRuntimeImage,
        PrivateRuntimeApplication,
        PrivateRuntimeApplication,
    ) {
        let preview = store
            .preview_control_position(control, &TestAuthority)
            .unwrap();
        assert_eq!(preview.disposition(), PutDisposition::Inserted);
        let receipt = runtime_receipt(fixture, control, marker);
        let issuance = AuthorityOperationIssuanceAck {
            authorization_invocation: vos_agent_sdk::InvocationId([marker; 32]),
            acknowledgement_invocation: vos_agent_sdk::InvocationId([marker.wrapping_add(1); 32]),
            authority: AuthorityActorTarget {
                space: fixture.descriptor.identity.space,
                system_agent: AgentId([marker.wrapping_add(2); 32]),
                system_runtime_deployment: DeploymentId([marker.wrapping_add(3); 32]),
                binding: fixture.descriptor.authority,
            },
            operation_call: test_hash(marker.wrapping_add(4)),
            approval: test_hash(marker.wrapping_add(5)),
            authorization_sequence: NonZeroU64::new(1).unwrap(),
            receipt: receipt.clone(),
            issued_at: 4,
            signature: [marker.wrapping_add(6); 64],
        };
        let pending = PrivateRuntimeApplication::pending(
            &fixture.descriptor,
            predecessor,
            control.clone(),
            None,
            None,
            receipt,
            issuance,
            5 + control.sequence,
            preview.position(),
            &AllowRuntimeVerifier,
            &AllowRuntimeVerifier,
        )
        .unwrap();
        let mut key_epochs = store.key_epochs.clone();
        advance_key_epochs(&mut key_epochs, control).unwrap();
        let key_epochs: Vec<_> = key_epochs
            .iter()
            .map(|epoch| PrivateKeyEpochCommitment::from_epoch(epoch).unwrap())
            .collect();
        let success = PrivateRuntimeSuccess::ControlOnly;
        let successor = PrivateRuntimeImage::successor(
            &fixture.descriptor,
            predecessor,
            &pending,
            &success,
            predecessor.state().clone(),
            key_epochs,
            &AllowRuntimeVerifier,
            &AllowRuntimeVerifier,
        )
        .unwrap();
        let completed = pending
            .clone()
            .complete(
                &fixture.descriptor,
                predecessor,
                &successor,
                success,
                &AllowRuntimeVerifier,
                &AllowRuntimeVerifier,
            )
            .unwrap();
        (successor, pending, completed)
    }

    fn runtime_store_with_completed_control(
        path: &Path,
        marker: u8,
    ) -> (PrivateStore, RuntimeStoreFixture, PrivateControlRecord) {
        let (mut store, fixture) = runtime_store_fixture(path);
        let invited = recipient(&fixture.store_fixture, 0xc1);
        let control = invite_control(&store, &fixture.store_fixture, invited);
        let (_, _, application) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &control, marker);
        store
            .append_control_with_runtime_application(&control, &application, &TestAuthority)
            .unwrap();
        (store, fixture, control)
    }

    fn control(fixture: &Fixture, sequence: u64, previous: Option<Hash>) -> PrivateControlRecord {
        let mut record = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence,
            previous,
            operation: PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(b"ciphertext-only-policy"),
            },
            signer: vos_agent_sdk::private::PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut record, &fixture.owner_key).unwrap();
        record
    }

    fn recipient(fixture: &Fixture, label: u8) -> PrivateNodeIdentity {
        let key = PrivateNodeDecryptionKey::from_bytes([label; 32]).unwrap();
        let transport_identity = vec![label.wrapping_add(20); 48];
        let mut node = PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: fixture.owner,
            transport_identity,
            encryption_public_key: key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [label.wrapping_add(40); 64],
        };
        node.authority_binding =
            TestAuthority::binding(fixture.space, fixture.agent, fixture.owner, &node);
        node
    }

    fn invite_control(
        store: &PrivateStore,
        fixture: &Fixture,
        node: PrivateNodeIdentity,
    ) -> PrivateControlRecord {
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

    #[derive(Debug, PartialEq, Eq)]
    struct DiskEntry {
        path: PathBuf,
        directory: bool,
        readonly: bool,
        len: u64,
        modified: Option<std::time::SystemTime>,
        bytes: Vec<u8>,
    }

    fn directory_image(root: &Path) -> Vec<DiskEntry> {
        fn visit(root: &Path, directory: &Path, image: &mut Vec<DiskEntry>) {
            let mut entries: Vec<_> = fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let directory = metadata.is_dir();
                image.push(DiskEntry {
                    path: path.strip_prefix(root).unwrap().to_path_buf(),
                    directory,
                    readonly: metadata.permissions().readonly(),
                    len: metadata.len(),
                    modified: metadata.modified().ok(),
                    bytes: if directory {
                        Vec::new()
                    } else {
                        fs::read(&path).unwrap()
                    },
                });
                if directory {
                    visit(root, &path, image);
                }
            }
        }

        let mut image = Vec::new();
        visit(root, root, &mut image);
        image
    }

    fn collect_files(path: &Path, output: &mut Vec<u8>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                collect_files(&entry.path(), output);
            } else {
                output.extend_from_slice(&fs::read(entry.path()).unwrap());
            }
        }
    }

    fn backup_with_orders(
        store: &PrivateStore,
        control_order: &[usize],
        object_order: &[usize],
    ) -> Vec<u8> {
        let mut encoder = Encoder::new(BACKUP_MAGIC);
        encoder
            .bytes(&encode_recovery(&store.metadata).unwrap())
            .unwrap();
        encoder.bytes(&encode_index(&store.index).unwrap()).unwrap();
        encoder.u32(u32::try_from(control_order.len()).unwrap());
        for position in control_order {
            let entry = &store.index.controls[*position];
            encoder.fixed(entry.commitment.as_bytes());
            encoder
                .bytes(&store.read_control_wire(entry).unwrap())
                .unwrap();
            match store.read_control_authority_evidence(entry).unwrap() {
                None => encoder.u8(0),
                Some(evidence) => {
                    encoder.u8(1);
                    encoder.bytes(&evidence).unwrap();
                }
            }
            match entry.runtime_application {
                None => encoder.u8(0),
                Some(binding) => {
                    encoder.u8(1);
                    encoder
                        .bytes(
                            &store
                                .read_runtime_application_wire_for_entry(entry, binding)
                                .unwrap(),
                        )
                        .unwrap();
                }
            }
        }
        encoder.u32(u32::try_from(object_order.len()).unwrap());
        for position in object_order {
            let entry = &store.index.objects[*position];
            encode_object_key(&mut encoder, entry.key);
            encoder
                .bytes(&store.read_object_wire(entry).unwrap())
                .unwrap();
        }
        encoder.finish(MAX_PRIVATE_BACKUP_BYTES).unwrap()
    }

    #[test]
    fn core_position_cache_advances_and_is_deterministic_after_reopen() {
        let directory = TestDirectory::new("core-position-reopen");
        let fixture = fixture();
        let path = directory.store();
        let store = create_store(&path, &fixture);
        let initial = store.core_position().unwrap();
        assert_eq!(store.cached_core_position().unwrap(), initial);
        assert_eq!(initial.object_count(), 0);
        assert_eq!(initial.object_root(), None);
        assert_eq!(initial.control_count(), 0);
        assert_eq!(initial.control_root(), None);
        drop(store);

        let mut store =
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(store.core_position().unwrap(), initial);
        assert_eq!(store.cached_core_position().unwrap(), initial);
        let record = control(&fixture, 0, None);
        store.append_control(&record, &TestAuthority).unwrap();
        let controlled = store.core_position().unwrap();
        assert_ne!(controlled, initial);
        assert_eq!(store.cached_core_position().unwrap(), controlled);
        let object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Index,
            b"core-position-reopen-object",
        )
        .unwrap();
        store.put_object(&object).unwrap();
        let populated = store.core_position().unwrap();
        assert_ne!(populated, controlled);
        assert_eq!(store.cached_core_position().unwrap(), populated);
        assert_eq!(populated.object_count(), 1);
        assert!(populated.object_root().is_some());
        assert_eq!(populated.control_count(), 1);
        assert!(populated.control_root().is_some());
        drop(store);

        let reopened =
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(reopened.core_position().unwrap(), populated);
        assert_eq!(reopened.cached_core_position().unwrap(), populated);
    }

    #[test]
    fn core_position_rejects_internal_chain_key_and_entry_drift() {
        let directory = TestDirectory::new("core-position-drift");
        let fixture = fixture();
        let mut store = create_store(&directory.store(), &fixture);

        store.index.next_sequence = 1;
        assert_eq!(store.core_position(), Err(PrivateStoreError::Corrupt));
        store.index.next_sequence = 0;

        let alternate = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            0,
            fixture.owner,
            &fixture.nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap()
        .record;
        let original_epoch = store.key_epochs[0].clone();
        store.key_epochs[0] = alternate.clone();
        assert_eq!(store.core_position(), Err(PrivateStoreError::Corrupt));
        store.key_epochs[0] = original_epoch;

        let original_genesis = store.metadata.genesis_epoch.clone();
        store.metadata.genesis_epoch = alternate;
        assert_eq!(store.core_position(), Err(PrivateStoreError::Corrupt));
        store.metadata.genesis_epoch = original_genesis;

        store.index.objects.push(StoredObjectIndex {
            key: PrivateObjectKey {
                epoch: 0,
                kind: encrypted_kind_tag(EncryptedObjectKind::Blob),
                content: Hash([0x91; 32]),
            },
            wire_hash: Hash::ZERO,
            wire_len: 1,
        });
        assert_eq!(store.core_position(), Err(PrivateStoreError::Corrupt));
        store.index.objects.clear();

        let record = control(&fixture, 0, None);
        store.append_control(&record, &TestAuthority).unwrap();
        store.index.controls[0].wire_hash = Hash::ZERO;
        assert_eq!(store.core_position(), Err(PrivateStoreError::Corrupt));
    }

    #[test]
    fn control_preview_is_no_io_exact_and_retry_aware() {
        let directory = TestDirectory::new("control-preview");
        let fixture = fixture();
        let path = directory.store();
        let mut store = create_store(&path, &fixture);
        let predecessor = store.core_position().unwrap();
        let record = control(&fixture, 0, None);
        let disk_before = directory_image(&path);
        let reads_before = store.artifact_reads.get();

        let preview = store
            .preview_control_position(&record, &TestAuthority)
            .unwrap();
        assert_eq!(preview.disposition(), PutDisposition::Inserted);
        assert_ne!(preview.position(), predecessor);
        assert_eq!(store.artifact_reads.get(), reads_before);
        assert_eq!(directory_image(&path), disk_before);
        assert_eq!(store.validate_next_control(&record, &TestAuthority), Ok(()));

        assert_eq!(
            store.append_control(&record, &TestAuthority),
            Ok(PutDisposition::Inserted)
        );
        assert_eq!(store.core_position().unwrap(), preview.position());
        let reads_after_insert = store.artifact_reads.get();
        let retry = store
            .preview_control_position(&record, &TestAuthority)
            .unwrap();
        assert_eq!(retry.disposition(), PutDisposition::AlreadyPresent);
        assert_eq!(retry.position(), preview.position());
        assert_eq!(store.artifact_reads.get(), reads_after_insert);
        assert_eq!(
            store.validate_next_control(&record, &TestAuthority),
            Err(PrivateStoreError::Alias)
        );
        assert_eq!(
            store.append_control(&record, &TestAuthority),
            Ok(PutDisposition::AlreadyPresent)
        );
        assert_eq!(store.artifact_reads.get(), reads_after_insert + 1);

        let mut alias = record.clone();
        alias.operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(b"same-sequence-different-control"),
        };
        sign_owner_control_record(&mut alias, &fixture.owner_key).unwrap();
        assert_eq!(
            store.preview_control_position(&alias, &TestAuthority),
            Err(PrivateStoreError::Alias)
        );
        assert_eq!(
            store.validate_next_control(&alias, &TestAuthority),
            Err(PrivateStoreError::Alias)
        );
        assert_eq!(
            store.append_control(&alias, &TestAuthority),
            Err(PrivateStoreError::Alias)
        );
    }

    #[test]
    fn roots_commit_every_exact_index_field_and_order() {
        assert_eq!(object_index_root(&[]), Ok(None));
        assert_eq!(control_index_root(&[]), Ok(None));

        let object = StoredObjectIndex {
            key: PrivateObjectKey {
                epoch: 3,
                kind: encrypted_kind_tag(EncryptedObjectKind::Package),
                content: Hash([1; 32]),
            },
            wire_hash: Hash([2; 32]),
            wire_len: 123,
        };
        let object_root = object_index_root(core::slice::from_ref(&object)).unwrap();
        let mut object_variants = Vec::new();
        let mut changed = object.clone();
        changed.key.epoch += 1;
        object_variants.push(changed);
        let mut changed = object.clone();
        changed.key.kind = encrypted_kind_tag(EncryptedObjectKind::Blob);
        object_variants.push(changed);
        let mut changed = object.clone();
        changed.key.content = Hash([3; 32]);
        object_variants.push(changed);
        let mut changed = object.clone();
        changed.wire_hash = Hash([4; 32]);
        object_variants.push(changed);
        let mut changed = object.clone();
        changed.wire_len += 1;
        object_variants.push(changed);
        for changed in object_variants {
            assert_ne!(
                object_index_root(core::slice::from_ref(&changed)).unwrap(),
                object_root
            );
        }

        let control = StoredControlIndex {
            sequence: 5,
            commitment: Hash([5; 32]),
            previous: Some(Hash([6; 32])),
            resulting_epoch: 7,
            superseded_heads: vec![Hash([8; 32]), Hash([9; 32])],
            wire_hash: Hash([10; 32]),
            wire_len: 456,
            runtime_application: None,
        };
        let control_root = control_index_root(core::slice::from_ref(&control)).unwrap();
        let mut control_variants = Vec::new();
        let mut changed = control.clone();
        changed.sequence += 1;
        control_variants.push(changed);
        let mut changed = control.clone();
        changed.commitment = Hash([11; 32]);
        control_variants.push(changed);
        let mut changed = control.clone();
        changed.previous = None;
        control_variants.push(changed);
        let mut changed = control.clone();
        changed.resulting_epoch += 1;
        control_variants.push(changed);
        let mut changed = control.clone();
        changed.superseded_heads[1] = Hash([12; 32]);
        control_variants.push(changed);
        let mut changed = control.clone();
        changed.wire_hash = Hash([13; 32]);
        control_variants.push(changed);
        let mut changed = control.clone();
        changed.wire_len += 1;
        control_variants.push(changed);
        for changed in control_variants {
            assert_ne!(
                control_index_root(core::slice::from_ref(&changed)).unwrap(),
                control_root
            );
        }
        let mut reordered = control;
        reordered.superseded_heads.reverse();
        assert_ne!(
            control_index_root(core::slice::from_ref(&reordered)).unwrap(),
            control_root
        );
        assert!(!stored_control_index_shape_is_valid(&reordered));
    }

    #[test]
    fn object_insert_changes_only_object_count_and_root() {
        let directory = TestDirectory::new("object-core-position");
        let fixture = fixture();
        let mut store = create_store(&directory.store(), &fixture);
        let predecessor = store.core_position().unwrap();
        let object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Snapshot,
            b"object-only-core-transition",
        )
        .unwrap();
        store.put_object(&object).unwrap();
        let successor = store.core_position().unwrap();
        assert_eq!(successor.space(), predecessor.space());
        assert_eq!(successor.agent(), predecessor.agent());
        assert_eq!(successor.owner(), predecessor.owner());
        assert_eq!(successor.epoch(), predecessor.epoch());
        assert_eq!(successor.control_head(), predecessor.control_head());
        assert_eq!(successor.next_sequence(), predecessor.next_sequence());
        assert_eq!(successor.control_count(), predecessor.control_count());
        assert_eq!(successor.control_root(), predecessor.control_root());
        assert_eq!(successor.key_epoch_root(), predecessor.key_epoch_root());
        assert_eq!(successor.object_count(), predecessor.object_count() + 1);
        assert_ne!(successor.object_root(), predecessor.object_root());
    }

    #[test]
    fn invite_changes_exact_key_root_without_advancing_epoch() {
        let directory = TestDirectory::new("invite-key-root");
        let fixture = fixture();
        let mut store = create_store(&directory.store(), &fixture);
        let predecessor = store.core_position().unwrap();
        let invited = recipient(&fixture, 31);
        let invite = invite_control(&store, &fixture, invited.clone());
        let predecessor_key_epochs = private_key_epoch_commitments(store.key_epochs()).unwrap();
        let preview = store
            .preview_control_position(&invite, &TestAuthority)
            .unwrap();
        assert_eq!(preview.disposition(), PutDisposition::Inserted);
        assert_eq!(preview.position().epoch(), predecessor.epoch());
        assert_ne!(
            preview.position().key_epoch_root(),
            predecessor.key_epoch_root()
        );
        assert_ne!(preview.key_epoch_commitments(), predecessor_key_epochs);
        assert!(
            preview
                .authorized_nodes()
                .binary_search_by_key(&invited.node, |node| node.node)
                .is_ok()
        );
        assert_eq!(store.key_epochs.len(), 1);
        store.append_control(&invite, &TestAuthority).unwrap();
        assert_eq!(store.core_position().unwrap(), preview.position());
        assert_eq!(store.key_epochs.len(), 1);
        assert_eq!(
            preview.key_epoch_commitments(),
            private_key_epoch_commitments(store.key_epochs()).unwrap()
        );
        assert_eq!(preview.authorized_nodes(), store.authorized_nodes());

        let retry = store
            .preview_control_position(&invite, &TestAuthority)
            .unwrap();
        assert_eq!(retry.disposition(), PutDisposition::AlreadyPresent);
        assert_eq!(retry.position(), preview.position());
        assert_eq!(
            retry.key_epoch_commitments(),
            preview.key_epoch_commitments()
        );
        assert_eq!(retry.authorized_nodes(), preview.authorized_nodes());
    }

    #[test]
    fn revoke_rotate_and_recovery_jump_project_exact_successors() {
        let fixture = fixture();

        let rotate_directory = TestDirectory::new("rotate-preview");
        let mut rotate_store = create_store(&rotate_directory.store(), &fixture);
        let rotate_predecessor = rotate_store.core_position().unwrap();
        let rotated_epoch = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            rotate_predecessor.epoch() + 1,
            fixture.owner,
            rotate_store.authorized_nodes(),
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut rotate = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: rotate_predecessor.next_sequence(),
            previous: rotate_predecessor.control_head(),
            operation: PrivateControlOperation::RotateKeys {
                next_epoch: rotated_epoch.record,
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut rotate, &fixture.owner_key).unwrap();
        let rotate_preview = rotate_store
            .preview_control_position(&rotate, &TestAuthority)
            .unwrap();
        assert_eq!(
            rotate_preview.position().epoch(),
            rotate_predecessor.epoch() + 1
        );
        assert_eq!(
            rotate_preview.position().next_sequence(),
            rotate_predecessor.next_sequence() + 1
        );
        rotate_store
            .append_control(&rotate, &TestAuthority)
            .unwrap();
        assert_eq!(
            rotate_store.core_position().unwrap(),
            rotate_preview.position()
        );

        let revoke_directory = TestDirectory::new("revoke-preview");
        let mut revoke_store = create_store(&revoke_directory.store(), &fixture);
        let invited = recipient(&fixture, 32);
        let invite = invite_control(&revoke_store, &fixture, invited.clone());
        revoke_store
            .append_control(&invite, &TestAuthority)
            .unwrap();
        let revoke_predecessor = revoke_store.core_position().unwrap();
        let revoked_epoch = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            revoke_predecessor.epoch() + 1,
            fixture.owner,
            &fixture.nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut revoke = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: revoke_predecessor.next_sequence(),
            previous: revoke_predecessor.control_head(),
            operation: PrivateControlOperation::Revoke {
                node: invited.node,
                next_epoch: revoked_epoch.record,
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_owner_control_record(&mut revoke, &fixture.owner_key).unwrap();
        let revoke_preview = revoke_store
            .preview_control_position(&revoke, &TestAuthority)
            .unwrap();
        assert_eq!(
            revoke_preview.position().epoch(),
            revoke_predecessor.epoch() + 1
        );
        assert_eq!(
            revoke_preview.position().next_sequence(),
            revoke_predecessor.next_sequence() + 1
        );
        revoke_store
            .append_control(&revoke, &TestAuthority)
            .unwrap();
        assert_eq!(
            revoke_store.core_position().unwrap(),
            revoke_preview.position()
        );

        let recovery_directory = TestDirectory::new("recovery-jump-preview");
        let mut recovery_store = create_store(&recovery_directory.store(), &fixture);
        let recovery_predecessor = recovery_store.core_position().unwrap();
        let recovered_epoch = generate_fresh_private_epoch(
            fixture.space,
            fixture.agent,
            4,
            fixture.owner,
            &fixture.nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let historical = alloc::collections::BTreeMap::from([(
            0,
            unwrap_recovery_data_key(&fixture.epoch.record, &fixture.recovery_encryption).unwrap(),
        )]);
        let historical_keyring = build_recovery_keyring_grant(
            core::slice::from_ref(&fixture.epoch.record),
            &historical,
            &recovered_epoch.record,
            &fixture.nodes,
        )
        .unwrap();
        let mut recovery = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 7,
            previous: None,
            operation: PrivateControlOperation::Recover {
                superseded_heads: Vec::new(),
                next_epoch: recovered_epoch.record,
                replacement_nodes: fixture.nodes.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();
        let recovery_preview = recovery_store
            .preview_control_position(&recovery, &TestAuthority)
            .unwrap();
        assert_eq!(recovery_preview.position().epoch(), 4);
        assert_eq!(recovery_preview.position().next_sequence(), 8);
        assert_eq!(recovery_preview.position().control_count(), 1);
        assert_ne!(
            recovery_preview.position().key_epoch_root(),
            recovery_predecessor.key_epoch_root()
        );
        recovery_store
            .apply_offline_recovery(None, &recovery, &TestAuthority)
            .unwrap();
        assert_eq!(
            recovery_store.core_position().unwrap(),
            recovery_preview.position()
        );
    }

    #[test]
    fn planner_preserves_capacity_retry_alias_and_validation_precedence() {
        let directory = TestDirectory::new("planner-errors");
        let fixture = fixture();
        let mut store = create_store(&directory.store(), &fixture);
        let record = control(&fixture, 0, None);
        store.append_control(&record, &TestAuthority).unwrap();

        let mut alias = record.clone();
        alias.operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(b"nonfull-alias"),
        };
        sign_owner_control_record(&mut alias, &fixture.owner_key).unwrap();
        assert_eq!(
            store.append_control(&alias, &TestAuthority),
            Err(PrivateStoreError::Alias)
        );
        assert_eq!(
            store.validate_next_control(&record, &TestAuthority),
            Err(PrivateStoreError::Alias)
        );

        let prototype = store.index.controls[0].clone();
        while store.index.controls.len() < MAX_PRIVATE_STORE_CONTROLS {
            let sequence = store.index.controls.len() as u64;
            let mut entry = prototype.clone();
            entry.sequence = sequence;
            entry.commitment = Hash::digest(
                b"vos/test/private-store-capacity-entry/v1",
                &[&sequence.to_le_bytes()],
            );
            store.index.controls.push(entry);
        }
        assert_eq!(
            store.append_control(&record, &TestAuthority),
            Ok(PutDisposition::AlreadyPresent)
        );
        assert_eq!(
            store.validate_next_control(&record, &TestAuthority),
            Err(PrivateStoreError::LimitExceeded)
        );
        assert_eq!(
            store.append_control(&alias, &TestAuthority),
            Err(PrivateStoreError::LimitExceeded)
        );
        let mut malformed = alias;
        malformed.signature = [0; 64];
        assert_eq!(
            store.append_control(&malformed, &TestAuthority),
            Err(PrivateStoreError::InvalidRecord)
        );
        assert_eq!(
            store.validate_next_control(&malformed, &TestAuthority),
            Err(PrivateStoreError::LimitExceeded)
        );
    }

    #[test]
    fn interrupted_stage_artifact_index_and_head_reconcile_without_plaintext() {
        let directory = TestDirectory::new("reconcile");
        let fixture = fixture();
        let sentinel = b"PRIVATE-DISK-SENTINEL-497c";
        let object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Package,
            sentinel,
        )
        .unwrap();
        let path = directory.store();
        let mut store = create_store(&path, &fixture);
        assert_eq!(store.key_epoch(), &fixture.epoch.record);
        assert_eq!(
            store.recovery_public_key(),
            fixture.recovery.verifying_key()
        );
        assert_eq!(
            store.put_object_inner(&object, CommitStop::AfterStage),
            Err(PrivateStoreError::Interrupted)
        );
        drop(store);

        let mut store =
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(store.object_count(), 0);
        assert_eq!(store.put_object(&object), Ok(PutDisposition::Inserted));
        assert_eq!(
            store.get_object(PrivateObjectKey::from_object(&object)),
            Ok(object.clone())
        );
        let record = control(&fixture, 0, None);
        assert_eq!(
            store.append_control_inner(&record, &TestAuthority, CommitStop::AfterArtifact),
            Err(PrivateStoreError::Interrupted)
        );
        drop(store);

        let store =
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(store.control_count(), 0);
        assert_eq!(store.binding().control_head, None);
        let next_record = control(&fixture, 1, Some(record.commitment()));
        let mut store = store;
        assert_eq!(
            store.append_control(&record, &TestAuthority),
            Ok(PutDisposition::Inserted)
        );
        assert_eq!(
            store.append_control_inner(&next_record, &TestAuthority, CommitStop::AfterIndex),
            Err(PrivateStoreError::Interrupted)
        );
        drop(store);
        let store =
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
        assert_eq!(store.control_count(), 2);
        assert_eq!(store.binding().control_head, Some(next_record.commitment()));
        let snapshot = store
            .export_encrypted_snapshot(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let mut disk = Vec::new();
        collect_files(&path, &mut disk);
        for bytes in [&disk[..], &snapshot, &backup] {
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
            );
        }
    }

    #[test]
    fn evidence_attachment_reconciles_every_write_boundary_and_rejects_aliases() {
        let fixture = fixture();
        for (index, stop) in [
            ControlEvidenceCommitStop::AfterEvidenceStaged,
            ControlEvidenceCommitStop::AfterStaged,
            ControlEvidenceCommitStop::AfterPending,
            ControlEvidenceCommitStop::AfterCertificatePublished,
            ControlEvidenceCommitStop::AfterPublished,
            ControlEvidenceCommitStop::AfterRetired,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new(&format!("evidence-stop-{index}"));
            let path = directory.store();
            let mut store = create_store(&path, &fixture);
            let record = control(&fixture, 0, None);
            store.append_control(&record, &TestAuthority).unwrap();
            let mut evidence = b"PSE2-exact-authority-evidence-".to_vec();
            evidence.push(index as u8);
            assert_eq!(
                store.persist_control_authority_evidence_inner(
                    record.commitment(),
                    &evidence,
                    None,
                    stop,
                ),
                Err(PrivateStoreError::Interrupted)
            );
            drop(store);

            let mut reopened =
                PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).unwrap();
            let entry = &reopened.indexed_controls()[0];
            let recovered = reopened.read_control_authority_evidence(entry).unwrap();
            if matches!(
                stop,
                ControlEvidenceCommitStop::AfterEvidenceStaged
                    | ControlEvidenceCommitStop::AfterStaged
            ) {
                assert_eq!(recovered, None);
            } else {
                assert_eq!(recovered.as_deref(), Some(evidence.as_slice()));
            }
            assert!(
                !path.join(STAGE_DIR).join(STAGED_CONTROL_EVIDENCE).exists()
                    && !path.join(STAGE_DIR).join(PENDING_CONTROL_EVIDENCE).exists()
            );
            assert!(matches!(
                reopened.persist_control_authority_evidence(record.commitment(), &evidence),
                Ok(PutDisposition::Inserted | PutDisposition::AlreadyPresent)
            ));
            let mut alias = evidence.clone();
            alias.push(0xff);
            assert_eq!(
                reopened.persist_control_authority_evidence(record.commitment(), &alias),
                Err(PrivateStoreError::Alias)
            );
        }
    }

    #[test]
    fn imported_evidence_pair_reconciles_every_pve2_write_boundary_exactly() {
        for (index, stop) in [
            ControlEvidenceCommitStop::AfterEvidenceStaged,
            ControlEvidenceCommitStop::AfterStaged,
            ControlEvidenceCommitStop::AfterPending,
            ControlEvidenceCommitStop::AfterCertificatePublished,
            ControlEvidenceCommitStop::AfterPublished,
            ControlEvidenceCommitStop::AfterRetired,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new(&format!("imported-evidence-stop-{index}"));
            let path = directory.store();
            let (mut store, fixture, control) =
                runtime_store_with_completed_control(&path, 0x80 + index as u8);
            let mut evidence = b"PSE2-source-authority-evidence-".to_vec();
            evidence.push(index as u8);
            let certificate =
                vec![0xa0 + index as u8; PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES];
            assert_eq!(
                store.persist_control_authority_evidence_inner(
                    control.commitment(),
                    &evidence,
                    Some(&certificate),
                    stop,
                ),
                Err(PrivateStoreError::Interrupted)
            );
            drop(store);

            let mut reopened = PrivateStore::open(
                &path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .unwrap();
            let entry = &reopened.indexed_controls()[0];
            let recovered_evidence = reopened.read_control_authority_evidence(entry).unwrap();
            let recovered_certificate = reopened.read_stable_import_certificate(entry).unwrap();
            if matches!(
                stop,
                ControlEvidenceCommitStop::AfterEvidenceStaged
                    | ControlEvidenceCommitStop::AfterStaged
            ) {
                assert_eq!(recovered_evidence, None);
                assert_eq!(recovered_certificate, None);
            } else {
                assert_eq!(recovered_evidence.as_deref(), Some(evidence.as_slice()));
                assert_eq!(
                    recovered_certificate.as_deref(),
                    Some(certificate.as_slice())
                );
            }
            for staged in [
                STAGED_CONTROL_EVIDENCE,
                STAGED_STABLE_IMPORT_CERTIFICATE,
                PENDING_CONTROL_EVIDENCE,
            ] {
                assert!(!path.join(STAGE_DIR).join(staged).exists());
            }
            assert!(matches!(
                reopened.persist_imported_control_authority_evidence(
                    control.commitment(),
                    &evidence,
                    &certificate,
                ),
                Ok(PutDisposition::Inserted | PutDisposition::AlreadyPresent)
            ));
            assert_eq!(
                reopened.persist_imported_control_authority_evidence(
                    control.commitment(),
                    &evidence,
                    &certificate,
                ),
                Ok(PutDisposition::AlreadyPresent)
            );
        }
    }

    #[test]
    fn authenticated_archive_reattachment_reconciles_every_pve2_boundary() {
        for (index, stop) in [
            ControlEvidenceCommitStop::AfterEvidenceStaged,
            ControlEvidenceCommitStop::AfterStaged,
            ControlEvidenceCommitStop::AfterPending,
            ControlEvidenceCommitStop::AfterCertificatePublished,
            ControlEvidenceCommitStop::AfterPublished,
            ControlEvidenceCommitStop::AfterRetired,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new(&format!("archive-reattach-stop-{index}"));
            let path = directory.store();
            let (mut store, fixture, control) =
                runtime_store_with_completed_control(&path, 0xb0 + index as u8);
            let mut evidence = b"PSE2-existing-exact-archive-evidence-".to_vec();
            evidence.push(index as u8);
            let certificate =
                vec![0xc0 + index as u8; PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES];
            store
                .persist_control_authority_evidence(control.commitment(), &evidence)
                .unwrap();
            assert_eq!(
                store.persist_imported_control_authority_evidence(
                    control.commitment(),
                    &evidence,
                    &certificate,
                ),
                Err(PrivateStoreError::Corrupt),
                "ordinary persistence must not reclassify local evidence"
            );
            assert_eq!(
                store.persist_control_authority_evidence_inner_with_mode(
                    control.commitment(),
                    &evidence,
                    Some(&certificate),
                    stop,
                    ControlEvidenceAttachmentMode::AuthenticatedRestore,
                ),
                Err(PrivateStoreError::Interrupted)
            );
            drop(store);

            let mut reopened = PrivateStore::open(
                &path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .unwrap();
            let entry = &reopened.indexed_controls()[0];
            assert_eq!(
                reopened.read_control_authority_evidence(entry).unwrap(),
                Some(evidence.clone())
            );
            let restored_certificate = reopened.read_stable_import_certificate(entry).unwrap();
            if matches!(
                stop,
                ControlEvidenceCommitStop::AfterEvidenceStaged
                    | ControlEvidenceCommitStop::AfterStaged
            ) {
                assert_eq!(restored_certificate, None);
            } else {
                assert_eq!(restored_certificate, Some(certificate.clone()));
            }
            assert!(matches!(
                reopened.reattach_authenticated_stable_import_certificate_after_restore(
                    control.commitment(),
                    &evidence,
                    &certificate,
                ),
                Ok(PutDisposition::Inserted | PutDisposition::AlreadyPresent)
            ));
            assert_eq!(
                reopened.read_stable_import_certificate(&reopened.indexed_controls()[0]),
                Ok(Some(certificate.clone()))
            );
            let mut alias = evidence.clone();
            alias.push(0xff);
            assert_eq!(
                reopened.reattach_authenticated_stable_import_certificate_after_restore(
                    control.commitment(),
                    &alias,
                    &certificate,
                ),
                Err(PrivateStoreError::Alias)
            );
        }
    }

    #[test]
    fn imported_evidence_rejects_aliases_asymmetry_and_missing_local_application() {
        let directory = TestDirectory::new("imported-evidence-alias");
        let path = directory.store();
        let (mut store, fixture, imported_control) =
            runtime_store_with_completed_control(&path, 0x91);
        let evidence = b"PSE2-source-evidence-for-import".to_vec();
        let certificate = vec![0x92; PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES];
        assert_eq!(
            store.persist_imported_control_authority_evidence(
                imported_control.commitment(),
                &evidence,
                &certificate,
            ),
            Ok(PutDisposition::Inserted)
        );
        let mut evidence_alias = evidence.clone();
        evidence_alias.push(0xff);
        assert_eq!(
            store.persist_imported_control_authority_evidence(
                imported_control.commitment(),
                &evidence_alias,
                &certificate,
            ),
            Err(PrivateStoreError::Alias)
        );
        let mut certificate_alias = certificate.clone();
        certificate_alias[0] ^= 1;
        assert_eq!(
            store.persist_imported_control_authority_evidence(
                imported_control.commitment(),
                &evidence,
                &certificate_alias,
            ),
            Err(PrivateStoreError::Alias)
        );
        assert_eq!(
            store.persist_control_authority_evidence(imported_control.commitment(), &evidence),
            Err(PrivateStoreError::Corrupt)
        );
        assert_eq!(
            store.persist_imported_control_authority_evidence(
                imported_control.commitment(),
                &evidence,
                &certificate[..certificate.len() - 1],
            ),
            Err(PrivateStoreError::InvalidRecord)
        );
        let mut oversized = certificate.clone();
        oversized.push(0);
        assert_eq!(
            store.persist_imported_control_authority_evidence(
                imported_control.commitment(),
                &evidence,
                &oversized,
            ),
            Err(PrivateStoreError::InvalidRecord)
        );
        assert_eq!(
            store.persist_imported_control_authority_evidence(
                Hash([0x93; 32]),
                &evidence,
                &certificate,
            ),
            Err(PrivateStoreError::InvalidRecord)
        );

        let local_directory = TestDirectory::new("imported-after-local-evidence");
        let local_path = local_directory.store();
        let (mut local, _, local_control) = runtime_store_with_completed_control(&local_path, 0x94);
        local
            .persist_control_authority_evidence(local_control.commitment(), &evidence)
            .unwrap();
        assert_eq!(
            local.persist_imported_control_authority_evidence(
                local_control.commitment(),
                &evidence,
                &certificate,
            ),
            Err(PrivateStoreError::Corrupt)
        );

        let bare_directory = TestDirectory::new("imported-without-local-application");
        let bare_path = bare_directory.store();
        let mut bare = create_store(&bare_path, &fixture.store_fixture);
        let bare_control = control(&fixture.store_fixture, 0, None);
        bare.append_control(&bare_control, &TestAuthority).unwrap();
        assert_eq!(
            bare.persist_imported_control_authority_evidence(
                bare_control.commitment(),
                &evidence,
                &certificate,
            ),
            Err(PrivateStoreError::InvalidRecord)
        );
        assert_eq!(
            bare.read_control_authority_evidence(&bare.indexed_controls()[0]),
            Ok(None)
        );
        assert_eq!(
            bare.read_stable_import_certificate(&bare.indexed_controls()[0]),
            Ok(None)
        );
        fs::write(
            bare_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(control_evidence_file_name(bare_control.commitment())),
            &evidence,
        )
        .unwrap();
        fs::write(
            bare_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(stable_import_certificate_file_name(
                    bare_control.commitment(),
                )),
            &certificate,
        )
        .unwrap();
        assert_eq!(
            bare.read_stable_import_certificate(&bare.indexed_controls()[0]),
            Err(PrivateStoreError::Corrupt)
        );
        drop(bare);
        assert_eq!(
            PrivateStore::open(
                &bare_path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn pve2_pending_codec_is_canonical_and_rejects_prior_generation() {
        let pending = PendingControlEvidence {
            control: Hash([0xb1; 32]),
            evidence_hash: Hash([0xb2; 32]),
            evidence_len: 73,
            stable_import_certificate: Some(PendingStableImportCertificate {
                wire_hash: Hash([0xb3; 32]),
                wire_len: PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES as u32,
            }),
        };
        let wire = encode_pending_control_evidence(pending).unwrap();
        assert_eq!(decode_pending_control_evidence(&wire), Ok(pending));

        let mut old_generation = wire.clone();
        old_generation[..4].copy_from_slice(b"PVEP");
        assert_eq!(
            decode_pending_control_evidence(&old_generation),
            Err(PrivateStoreError::Corrupt)
        );
        let mut invalid_option = wire.clone();
        invalid_option[4 + 2 + 32 + 32 + 4] = 2;
        assert_eq!(
            decode_pending_control_evidence(&invalid_option),
            Err(PrivateStoreError::Corrupt)
        );
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            decode_pending_control_evidence(&trailing),
            Err(PrivateStoreError::Corrupt)
        );
        assert_eq!(
            encode_pending_control_evidence(PendingControlEvidence {
                stable_import_certificate: Some(PendingStableImportCertificate {
                    wire_len: PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES as u32 - 1,
                    ..pending.stable_import_certificate.unwrap()
                }),
                ..pending
            }),
            Err(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn stable_import_certificates_are_node_local_and_excluded_from_pvb3_pvs3() {
        let directory = TestDirectory::new("imported-evidence-archive-exclusion");
        let path = directory.store();
        let (mut store, fixture, control) = runtime_store_with_completed_control(&path, 0xc1);
        let evidence = b"PSE2-portable-source-authority-evidence".to_vec();
        let certificate: Vec<_> = (0..PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES)
            .map(|index| 0x80 | (index % 0x71) as u8)
            .collect();
        store
            .persist_imported_control_authority_evidence(
                control.commitment(),
                &evidence,
                &certificate,
            )
            .unwrap();
        let backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let snapshot = store
            .export_encrypted_snapshot(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        for portable in [&backup, &snapshot] {
            assert!(
                !portable
                    .windows(certificate.len())
                    .any(|window| window == certificate)
            );
        }
        let verified = verify_encrypted_backup(
            &backup,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            fixture.store_fixture.owner,
            fixture.store_fixture.recovery.verifying_key(),
            fixture.store_fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(verified.control_evidence, vec![Some(evidence.clone())]);
        drop(store);

        let (retried, disposition) = PrivateStore::restore_encrypted_backup(
            &path,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            fixture.store_fixture.owner,
            fixture.store_fixture.recovery.verifying_key(),
            fixture.store_fixture.recovery_encryption.public_key(),
            &backup,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(disposition, RestoreDisposition::AlreadyPresent);
        assert_eq!(
            retried.read_stable_import_certificate(&retried.indexed_controls()[0]),
            Ok(Some(certificate.clone()))
        );
        drop(retried);

        let restored_path = directory.0.join("restored");
        let (restored, _) = PrivateStore::restore_encrypted_backup(
            &restored_path,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            fixture.store_fixture.owner,
            fixture.store_fixture.recovery.verifying_key(),
            fixture.store_fixture.recovery_encryption.public_key(),
            &backup,
            &TestAuthority,
        )
        .unwrap();
        let entry = &restored.indexed_controls()[0];
        assert_eq!(
            restored.read_control_authority_evidence(entry),
            Ok(Some(evidence))
        );
        assert_eq!(restored.read_stable_import_certificate(entry), Ok(None));
    }

    #[test]
    fn stable_import_certificate_scan_rejects_orphans_asymmetry_and_bad_shape() {
        let fixture = fixture();
        let certificate = vec![0xd1; PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES];

        let orphan_directory = TestDirectory::new("orphan-import-certificate");
        let orphan_path = orphan_directory.store();
        drop(create_store(&orphan_path, &fixture));
        fs::write(
            orphan_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(stable_import_certificate_file_name(Hash([0xd2; 32]))),
            &certificate,
        )
        .unwrap();
        assert_eq!(
            PrivateStore::open(&orphan_path, fixture.space, fixture.agent, &TestAuthority,).err(),
            Some(PrivateStoreError::Corrupt)
        );

        let asymmetric_directory = TestDirectory::new("asymmetric-import-certificate");
        let asymmetric_path = asymmetric_directory.store();
        let (mut asymmetric, asymmetric_fixture, asymmetric_control) =
            runtime_store_with_completed_control(&asymmetric_path, 0xd3);
        let evidence = b"PSE2-asymmetric-crash-evidence".to_vec();
        assert_eq!(
            asymmetric.persist_control_authority_evidence_inner(
                asymmetric_control.commitment(),
                &evidence,
                Some(&certificate),
                ControlEvidenceCommitStop::AfterCertificatePublished,
            ),
            Err(PrivateStoreError::Interrupted)
        );
        fs::remove_file(
            asymmetric_path
                .join(STAGE_DIR)
                .join(PENDING_CONTROL_EVIDENCE),
        )
        .unwrap();
        drop(asymmetric);
        assert_eq!(
            PrivateStore::open(
                &asymmetric_path,
                asymmetric_fixture.store_fixture.space,
                asymmetric_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );

        let missing_stage_directory = TestDirectory::new("missing-staged-import-certificate");
        let missing_stage_path = missing_stage_directory.store();
        let (mut missing_stage, missing_stage_fixture, missing_stage_control) =
            runtime_store_with_completed_control(&missing_stage_path, 0xd6);
        assert_eq!(
            missing_stage.persist_control_authority_evidence_inner(
                missing_stage_control.commitment(),
                &evidence,
                Some(&certificate),
                ControlEvidenceCommitStop::AfterPending,
            ),
            Err(PrivateStoreError::Interrupted)
        );
        fs::remove_file(
            missing_stage_path
                .join(STAGE_DIR)
                .join(STAGED_STABLE_IMPORT_CERTIFICATE),
        )
        .unwrap();
        drop(missing_stage);
        assert_eq!(
            PrivateStore::open(
                &missing_stage_path,
                missing_stage_fixture.store_fixture.space,
                missing_stage_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );

        let truncated_directory = TestDirectory::new("truncated-import-certificate");
        let truncated_path = truncated_directory.store();
        let (mut truncated, truncated_fixture, truncated_control) =
            runtime_store_with_completed_control(&truncated_path, 0xd4);
        truncated
            .persist_imported_control_authority_evidence(
                truncated_control.commitment(),
                &evidence,
                &certificate,
            )
            .unwrap();
        let truncated_certificate =
            truncated_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(stable_import_certificate_file_name(
                    truncated_control.commitment(),
                ));
        OpenOptions::new()
            .write(true)
            .open(&truncated_certificate)
            .unwrap()
            .set_len((PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES - 1) as u64)
            .unwrap();
        drop(truncated);
        assert_eq!(
            PrivateStore::open(
                &truncated_path,
                truncated_fixture.store_fixture.space,
                truncated_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );

        let uppercase_directory = TestDirectory::new("uppercase-import-certificate");
        let uppercase_path = uppercase_directory.store();
        let (mut uppercase, uppercase_fixture, uppercase_control) =
            runtime_store_with_completed_control(&uppercase_path, 0xd5);
        uppercase
            .persist_imported_control_authority_evidence(
                uppercase_control.commitment(),
                &evidence,
                &certificate,
            )
            .unwrap();
        let canonical_name = stable_import_certificate_file_name(uppercase_control.commitment());
        fs::rename(
            uppercase_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(&canonical_name),
            uppercase_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(canonical_name.to_ascii_uppercase()),
        )
        .unwrap();
        drop(uppercase);
        assert_eq!(
            PrivateStore::open(
                &uppercase_path,
                uppercase_fixture.store_fixture.space,
                uppercase_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );
    }

    #[cfg(unix)]
    #[test]
    fn stable_import_certificate_rejects_published_and_staged_symlinks() {
        use std::os::unix::fs::symlink;

        let certificate = vec![0xe1; PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES];
        let evidence = b"PSE2-symlink-hostile-evidence".to_vec();
        let published_directory = TestDirectory::new("published-import-certificate-symlink");
        let published_path = published_directory.store();
        let (mut published, published_fixture, published_control) =
            runtime_store_with_completed_control(&published_path, 0xe2);
        published
            .persist_imported_control_authority_evidence(
                published_control.commitment(),
                &evidence,
                &certificate,
            )
            .unwrap();
        let certificate_path =
            published_path
                .join(CONTROL_EVIDENCE_DIR)
                .join(stable_import_certificate_file_name(
                    published_control.commitment(),
                ));
        let external = published_directory.0.join("external-psi1");
        fs::write(&external, &certificate).unwrap();
        fs::remove_file(&certificate_path).unwrap();
        symlink(&external, &certificate_path).unwrap();
        drop(published);
        assert_eq!(
            PrivateStore::open(
                &published_path,
                published_fixture.store_fixture.space,
                published_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );

        let staged_directory = TestDirectory::new("staged-import-certificate-symlink");
        let staged_path = staged_directory.store();
        let (mut staged, staged_fixture, staged_control) =
            runtime_store_with_completed_control(&staged_path, 0xe3);
        let staged_certificate = staged_path
            .join(STAGE_DIR)
            .join(STAGED_STABLE_IMPORT_CERTIFICATE);
        assert_eq!(
            staged.persist_control_authority_evidence_inner(
                staged_control.commitment(),
                &evidence,
                Some(&certificate),
                ControlEvidenceCommitStop::AfterPending,
            ),
            Err(PrivateStoreError::Interrupted)
        );
        fs::remove_file(&staged_certificate).unwrap();
        symlink(&external, &staged_certificate).unwrap();
        drop(staged);
        assert_eq!(
            PrivateStore::open(
                &staged_path,
                staged_fixture.store_fixture.space,
                staged_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn encrypted_backup_preserves_present_and_pending_evidence_exactly() {
        let fixture = fixture();
        let directory = TestDirectory::new("backup-evidence");
        let path = directory.store();
        let mut store = create_store(&path, &fixture);
        let record = control(&fixture, 0, None);
        store.append_control(&record, &TestAuthority).unwrap();

        // A crash-valid local control may temporarily have no attached PSE2.
        let pending_backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let pending = verify_encrypted_backup(
            &pending_backup,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(pending.control_evidence, vec![None]);

        let evidence = b"PSE2-canonical-bytes-preserved-byte-for-byte".to_vec();
        store
            .persist_control_authority_evidence(record.commitment(), &evidence)
            .unwrap();
        let complete_backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let verified = verify_encrypted_backup(
            &complete_backup,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(verified.control_evidence, vec![Some(evidence.clone())]);

        let restored_path = directory.0.join("restored");
        let (restored, _) = PrivateStore::restore_encrypted_backup(
            &restored_path,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &complete_backup,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(
            restored
                .read_control_authority_evidence(&restored.indexed_controls()[0])
                .unwrap(),
            Some(evidence)
        );

        let pending_path = directory.0.join("pending-restored");
        let (pending_restored, _) = PrivateStore::restore_encrypted_backup(
            &pending_path,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &pending_backup,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(
            pending_restored
                .read_control_authority_evidence(&pending_restored.indexed_controls()[0])
                .unwrap(),
            None
        );
    }

    #[test]
    fn genesis_head_offline_recovery_is_exact_and_retryable() {
        let directory = TestDirectory::new("genesis-recovery");
        let fixture = fixture();
        let mut store = create_store(&directory.store(), &fixture);
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
        let historical = alloc::collections::BTreeMap::from([(
            0,
            unwrap_recovery_data_key(&fixture.epoch.record, &fixture.recovery_encryption).unwrap(),
        )]);
        let historical_keyring = build_recovery_keyring_grant(
            core::slice::from_ref(&fixture.epoch.record),
            &historical,
            &successor.record,
            &fixture.nodes,
        )
        .unwrap();
        let mut record = PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Recover {
                superseded_heads: Vec::new(),
                next_epoch: successor.record,
                replacement_nodes: fixture.nodes.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut record, &fixture.recovery).unwrap();
        assert_eq!(
            store
                .apply_offline_recovery(None, &record, &TestAuthority)
                .unwrap(),
            PutDisposition::Inserted
        );
        assert_eq!(
            store
                .apply_offline_recovery(None, &record, &TestAuthority)
                .unwrap(),
            PutDisposition::AlreadyPresent
        );
        assert_eq!(store.binding().epoch, 1);
    }

    #[test]
    fn semantic_object_aliases_are_rejected_and_exact_retries_are_idempotent() {
        let directory = TestDirectory::new("alias");
        let fixture = fixture();
        let mut store = create_store(&directory.store(), &fixture);
        let first = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Blob,
            b"same private content",
        )
        .unwrap();
        let alias = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Blob,
            b"same private content",
        )
        .unwrap();
        assert_eq!(store.put_object(&first), Ok(PutDisposition::Inserted));
        assert_eq!(store.put_object(&first), Ok(PutDisposition::AlreadyPresent));
        assert_eq!(store.put_object(&alias), Err(PrivateStoreError::Alias));
    }

    #[test]
    fn truncated_recovery_metadata_and_pending_transaction_fail_closed() {
        let fixture = fixture();
        let recovery_directory = TestDirectory::new("truncated-recovery");
        let recovery_path = recovery_directory.store();
        drop(create_store(&recovery_path, &fixture));
        OpenOptions::new()
            .write(true)
            .open(recovery_path.join(RECOVERY_FILE))
            .unwrap()
            .set_len(5)
            .unwrap();
        assert!(matches!(
            PrivateStore::open(&recovery_path, fixture.space, fixture.agent, &TestAuthority),
            Err(PrivateStoreError::Corrupt | PrivateStoreError::InvalidRecord)
        ));

        let pending_directory = TestDirectory::new("truncated-pending");
        let pending_path = pending_directory.store();
        drop(create_store(&pending_path, &fixture));
        fs::write(pending_path.join(STAGE_DIR).join(PENDING_FILE), b"PVTX\x01").unwrap();
        assert_eq!(
            PrivateStore::open(&pending_path, fixture.space, fixture.agent, &TestAuthority).err(),
            Some(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn reopen_fully_verifies_ciphertext_and_rejects_symlink_roots() {
        let fixture = fixture();
        let directory = TestDirectory::new("reopen-object-corruption");
        let path = directory.store();
        let mut store = create_store(&path, &fixture);
        let object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Snapshot,
            b"ciphertext-integrity-on-open",
        )
        .unwrap();
        let key = PrivateObjectKey::from_object(&object);
        store.put_object(&object).unwrap();
        drop(store);
        let object_path = path.join(OBJECTS_DIR).join(object_file_name(key));
        let mut bytes = fs::read(&object_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&object_path, bytes).unwrap();
        assert_eq!(
            PrivateStore::open(&path, fixture.space, fixture.agent, &TestAuthority).err(),
            Some(PrivateStoreError::Corrupt)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = directory.0.join("real-root");
            fs::create_dir(&real).unwrap();
            let alias = directory.0.join("symlink-root");
            symlink(&real, &alias).unwrap();
            assert_eq!(
                PrivateStore::create(
                    &alias,
                    fixture.space,
                    fixture.agent,
                    fixture.owner,
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                    fixture.epoch.record.clone(),
                    fixture.nodes.clone(),
                    &TestAuthority,
                )
                .err(),
                Some(PrivateStoreError::Corrupt)
            );
        }
    }

    #[test]
    fn backup_restore_is_side_effect_free_until_full_authentication() {
        let fixture = fixture();
        let directory = TestDirectory::new("restore-hostile");
        let source_path = directory.0.join("source");
        let mut source = create_store(&source_path, &fixture);
        let control = control(&fixture, 0, None);
        source.append_control(&control, &TestAuthority).unwrap();
        for plaintext in [b"ordered-a".as_slice(), b"ordered-b".as_slice()] {
            let object = encrypt_private_object(
                &fixture.epoch.data_key,
                fixture.space,
                fixture.agent,
                0,
                EncryptedObjectKind::Blob,
                plaintext,
            )
            .unwrap();
            source.put_object(&object).unwrap();
        }
        let backup = source
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let target = directory.0.join("target");

        let mut tampered = backup.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            PrivateStore::restore_encrypted_backup(
                &target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &tampered,
                &TestAuthority,
            )
            .is_err()
        );
        assert!(!target.exists());

        let mut truncated = backup.clone();
        truncated.pop();
        assert!(
            PrivateStore::restore_encrypted_backup(
                &target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &truncated,
                &TestAuthority,
            )
            .is_err()
        );
        assert!(!target.exists());

        for (space, agent, owner, recovery, expected) in [
            (
                SpaceId([91; 32]),
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                PrivateStoreError::InvalidScope,
            ),
            (
                fixture.space,
                AgentId([92; 32]),
                fixture.owner,
                fixture.recovery.verifying_key(),
                PrivateStoreError::InvalidScope,
            ),
            (
                fixture.space,
                fixture.agent,
                PrincipalId([93; 32]),
                fixture.recovery.verifying_key(),
                PrivateStoreError::InvalidBinding,
            ),
            (
                fixture.space,
                fixture.agent,
                fixture.owner,
                [94; 32],
                PrivateStoreError::InvalidBinding,
            ),
        ] {
            assert_eq!(
                PrivateStore::restore_encrypted_backup(
                    &target,
                    space,
                    agent,
                    owner,
                    recovery,
                    fixture.recovery_encryption.public_key(),
                    &backup,
                    &TestAuthority,
                )
                .err(),
                Some(expected)
            );
            assert!(!target.exists());
        }

        let duplicate = backup_with_orders(&source, &[0], &[0, 0]);
        assert!(
            PrivateStore::restore_encrypted_backup(
                &target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &duplicate,
                &TestAuthority,
            )
            .is_err()
        );
        assert!(!target.exists());
        let reversed = backup_with_orders(&source, &[0], &[1, 0]);
        assert!(
            PrivateStore::restore_encrypted_backup(
                &target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &reversed,
                &TestAuthority,
            )
            .is_err()
        );
        assert!(!target.exists());
    }

    #[test]
    fn restore_resumes_an_interrupted_prefix_and_rejects_rollback() {
        let fixture = fixture();
        let directory = TestDirectory::new("restore-resume-rollback");
        let mut source = create_store(&directory.0.join("source"), &fixture);
        let first_control = control(&fixture, 0, None);
        source
            .append_control(&first_control, &TestAuthority)
            .unwrap();
        let first_object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Snapshot,
            b"resumable-ciphertext-only-restore",
        )
        .unwrap();
        let second_object = encrypt_private_object(
            &fixture.epoch.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Blob,
            b"exact-object-prefix-only",
        )
        .unwrap();
        source.put_object(&first_object).unwrap();
        source.put_object(&second_object).unwrap();
        let prefix_object = source
            .get_object(source.index.objects[0].key)
            .expect("source has a first object");
        let old_backup = source
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let second_control = control(&fixture, 1, Some(first_control.commitment()));
        source
            .append_control(&second_control, &TestAuthority)
            .unwrap();
        let current_backup = source
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();

        let target = directory.0.join("target");
        let mut interrupted = create_store(&target, &fixture);
        assert_eq!(
            interrupted.put_object_inner(&prefix_object, CommitStop::AfterArtifact),
            Err(PrivateStoreError::Interrupted)
        );
        drop(interrupted);
        let (restored, disposition) = PrivateStore::restore_encrypted_backup(
            &target,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &current_backup,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(disposition, RestoreDisposition::Restored);
        assert_eq!(restored.index, source.index);
        drop(restored);

        let before = fs::read(target.join(INDEX_FILE)).unwrap();
        assert_eq!(
            PrivateStore::restore_encrypted_backup(
                &target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &old_backup,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Rollback)
        );
        assert_eq!(fs::read(target.join(INDEX_FILE)).unwrap(), before);

        let fork_target = directory.0.join("fork-target");
        let mut fork = create_store(&fork_target, &fixture);
        let mut divergent = first_control.clone();
        divergent.operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(b"authenticated-but-divergent-policy"),
        };
        sign_owner_control_record(&mut divergent, &fixture.owner_key).unwrap();
        fork.append_control(&divergent, &TestAuthority).unwrap();
        drop(fork);
        let fork_before = fs::read(fork_target.join(INDEX_FILE)).unwrap();
        assert_eq!(
            PrivateStore::restore_encrypted_backup(
                &fork_target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &current_backup,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Diverged)
        );
        assert_eq!(fs::read(fork_target.join(INDEX_FILE)).unwrap(), fork_before);

        let subsequence_target = directory.0.join("object-subsequence-target");
        let mut subsequence = create_store(&subsequence_target, &fixture);
        let second_object = source
            .get_object(source.index.objects[1].key)
            .expect("source has a second object");
        subsequence.put_object(&second_object).unwrap();
        drop(subsequence);
        let subsequence_before = fs::read(subsequence_target.join(INDEX_FILE)).unwrap();
        assert_eq!(
            PrivateStore::restore_encrypted_backup(
                &subsequence_target,
                fixture.space,
                fixture.agent,
                fixture.owner,
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &current_backup,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Diverged)
        );
        assert_eq!(
            fs::read(subsequence_target.join(INDEX_FILE)).unwrap(),
            subsequence_before
        );

        let (restored, disposition) = PrivateStore::restore_encrypted_backup(
            &target,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &current_backup,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(disposition, RestoreDisposition::AlreadyPresent);
        assert_eq!(restored.index, source.index);
    }

    #[test]
    fn runtime_application_is_exact_reopenable_backed_up_and_excluded_from_psc() {
        let directory = TestDirectory::new("runtime-application-exact");
        let path = directory.store();
        let (mut store, fixture) = runtime_store_fixture(&path);
        let control = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xb1),
        );
        let preview = store
            .preview_control_position(&control, &TestAuthority)
            .unwrap();
        let (_successor, pending, completed) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &control, 0xb2);
        let before = directory_image(&path);
        assert_eq!(
            store.append_control_with_runtime_application(&control, &pending, &TestAuthority),
            Err(PrivateStoreError::InvalidRecord)
        );
        assert_eq!(directory_image(&path), before);
        assert_eq!(
            store.append_control_with_runtime_application(&control, &completed, &TestAuthority),
            Ok(PutDisposition::Inserted)
        );
        // The preview was calculated before the attachment existed. Equality
        // proves PAPL/PVRI/PSP metadata is outside every PSC1 root.
        assert_eq!(store.core_position().unwrap(), preview.position());
        let binding = store
            .runtime_application_binding(control.commitment())
            .unwrap()
            .unwrap();
        assert_eq!(binding.control, control.commitment());
        assert_eq!(binding.application, completed.commitment());
        assert_eq!(
            binding.successor_runtime_image,
            completed.successor_runtime_image().unwrap()
        );
        assert_eq!(
            binding.successor_stable_projection,
            completed
                .successor_stable_projection()
                .unwrap()
                .commitment()
        );
        let wire = completed.encode().unwrap();
        assert_eq!(
            store
                .read_runtime_application_wire(control.commitment())
                .unwrap(),
            Some(wire.clone())
        );
        assert_eq!(
            store
                .read_runtime_application(control.commitment())
                .unwrap(),
            Some(completed.clone())
        );
        assert_eq!(
            store.append_control_with_runtime_application(&control, &completed, &TestAuthority),
            Ok(PutDisposition::AlreadyPresent)
        );
        assert_eq!(
            store.runtime_application_binding(Hash([0xee; 32])),
            Err(PrivateStoreError::NotFound)
        );

        let backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let verified = verify_encrypted_backup(
            &backup,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            fixture.store_fixture.owner,
            fixture.store_fixture.recovery.verifying_key(),
            fixture.store_fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(
            verified
                .controls_with_runtime_applications()
                .next()
                .unwrap()
                .2,
            Some(&completed)
        );
        let expected_position = store.core_position().unwrap();
        drop(store);
        let reopened = PrivateStore::open(
            &path,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.core_position().unwrap(), expected_position);
        assert_eq!(
            reopened
                .read_runtime_application(control.commitment())
                .unwrap(),
            Some(completed.clone())
        );
        drop(reopened);

        let restored_path = directory.0.join("restored");
        let (restored, disposition) = PrivateStore::restore_encrypted_backup(
            &restored_path,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            fixture.store_fixture.owner,
            fixture.store_fixture.recovery.verifying_key(),
            fixture.store_fixture.recovery_encryption.public_key(),
            &backup,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(disposition, RestoreDisposition::Restored);
        assert_eq!(restored.core_position().unwrap(), expected_position);
        assert_eq!(
            restored
                .read_runtime_application(control.commitment())
                .unwrap(),
            Some(completed)
        );
        let mut disk = Vec::new();
        collect_files(&path, &mut disk);
        collect_files(&restored_path, &mut disk);
        disk.extend_from_slice(&backup);
        assert!(
            !disk
                .windows(RUNTIME_PLAINTEXT_SENTINEL.len())
                .any(|window| window == RUNTIME_PLAINTEXT_SENTINEL)
        );
    }

    #[test]
    fn verified_backup_replay_views_bootstrap_only_exact_genesis() {
        let directory = TestDirectory::new("verified-backup-empty-genesis");
        let source_path = directory.store();
        let (mut source, fixture) = runtime_store_fixture(&source_path);
        let genesis_position = source.core_position().unwrap();
        let genesis_epoch = source.key_epoch().clone();
        let genesis_nodes = source.authorized_nodes().to_vec();
        let invited = recipient(&fixture.store_fixture, 0xc1);
        let control = invite_control(&source, &fixture.store_fixture, invited);
        let (_, _, application) =
            completed_runtime_application(&source, &fixture, &fixture.predecessor, &control, 0xc2);
        source
            .append_control_with_runtime_application(&control, &application, &TestAuthority)
            .unwrap();
        let evidence = b"PSE2-source-bytes-require-host-verification".to_vec();
        source
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
        let object = encrypt_private_object(
            &fixture.store_fixture.epoch.data_key,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            0,
            EncryptedObjectKind::Snapshot,
            b"archive-object-must-not-enter-empty-bootstrap",
        )
        .unwrap();
        source.put_object(&object).unwrap();
        let final_target = source.core_position().unwrap();
        let final_nodes = source.authorized_nodes().to_vec();
        let backup = source
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let verified = verify_encrypted_backup(
            &backup,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            fixture.store_fixture.owner,
            fixture.store_fixture.recovery.verifying_key(),
            fixture.store_fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();

        assert_ne!(final_nodes, genesis_nodes);
        assert_eq!(verified.genesis_nodes(), genesis_nodes);
        assert_eq!(verified.final_authorized_nodes(), final_nodes);
        assert_eq!(verified.final_target().unwrap(), final_target);
        assert_ne!(verified.final_target().unwrap(), genesis_position);
        // Invite modifies the live epoch-zero envelopes. The empty Store must
        // still use the immutable genesis PKEY, not this final epoch view.
        assert_ne!(verified.key_epochs()[0], genesis_epoch);
        let rows = verified.replay_rows().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.index().commitment, control.commitment());
        assert_eq!(row.control(), &control);
        assert_eq!(row.source_runtime_application(), &application);
        assert_eq!(row.source_authority_evidence(), evidence);

        let target_path = directory.0.join("empty-genesis");
        let empty = PrivateStore::create_empty_from_verified_genesis(
            &target_path,
            &verified,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(empty.core_position().unwrap(), genesis_position);
        assert_eq!(empty.key_epoch(), &genesis_epoch);
        assert_eq!(empty.key_epochs(), core::slice::from_ref(&genesis_epoch));
        assert_eq!(empty.authorized_nodes(), genesis_nodes);
        assert_eq!(empty.object_count(), 0);
        assert_eq!(empty.control_count(), 0);
        assert!(empty.indexed_objects().is_empty());
        assert!(empty.indexed_controls().is_empty());
        assert_eq!(empty.binding().control_head, None);
        assert_eq!(empty.binding().next_sequence, 0);
        assert_eq!(empty.latest_recovery_keyring(), None);
        for directory in [
            OBJECTS_DIR,
            CONTROLS_DIR,
            RUNTIME_APPLICATIONS_DIR,
            CONTROL_EVIDENCE_DIR,
        ] {
            assert_eq!(
                fs::read_dir(target_path.join(directory)).unwrap().count(),
                0
            );
        }
        drop(empty);
        let reopened = PrivateStore::open(
            &target_path,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.core_position().unwrap(), genesis_position);
        assert_eq!(reopened.key_epoch(), &genesis_epoch);
        assert_eq!(reopened.authorized_nodes(), genesis_nodes);
        assert_eq!(reopened.object_count(), 0);
        assert_eq!(reopened.control_count(), 0);
    }

    #[test]
    fn empty_genesis_bootstrap_rejects_authority_before_touching_destination() {
        let directory = TestDirectory::new("verified-backup-denied-genesis");
        let source_path = directory.store();
        let fixture = fixture();
        let source = create_store(&source_path, &fixture);
        let backup = source
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let verified = verify_encrypted_backup(
            &backup,
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        drop(source);

        let target_path = directory.0.join("denied-empty-genesis");
        assert!(!target_path.exists());
        assert_eq!(
            PrivateStore::create_empty_from_verified_genesis(
                &target_path,
                &verified,
                &DenyAuthority,
            )
            .err(),
            Some(PrivateStoreError::Crypto(
                PrivateCryptoError::UnauthorizedNode,
            ))
        );
        assert!(!target_path.exists());
    }

    #[test]
    fn verified_backup_replay_rows_reject_each_missing_required_attachment() {
        let directory = TestDirectory::new("verified-backup-incomplete-replay");
        let papl_only_path = directory.store();
        let (mut papl_only, fixture) = runtime_store_fixture(&papl_only_path);
        let control = invite_control(
            &papl_only,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xc5),
        );
        let (_, _, application) = completed_runtime_application(
            &papl_only,
            &fixture,
            &fixture.predecessor,
            &control,
            0xc6,
        );
        papl_only
            .append_control_with_runtime_application(&control, &application, &TestAuthority)
            .unwrap();
        let verify = |bytes: &[u8]| {
            verify_encrypted_backup(
                bytes,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                fixture.store_fixture.owner,
                fixture.store_fixture.recovery.verifying_key(),
                fixture.store_fixture.recovery_encryption.public_key(),
                &TestAuthority,
            )
            .unwrap()
        };
        let papl_only_backup = papl_only
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        assert_eq!(
            verify(&papl_only_backup).replay_rows().err(),
            Some(PrivateStoreError::Corrupt)
        );

        let evidence = b"PSE2-completes-source-replay-row".to_vec();
        papl_only
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
        let complete_backup = papl_only
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let complete = verify(&complete_backup);
        let complete_rows = complete.replay_rows().unwrap();
        assert_eq!(complete_rows.len(), 1);
        assert_eq!(complete_rows[0].control(), &control);

        let pse_only_path = directory.0.join("pse-only");
        let mut pse_only = create_store(&pse_only_path, &fixture.store_fixture);
        pse_only.append_control(&control, &TestAuthority).unwrap();
        pse_only
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
        let pse_only_backup = pse_only
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        assert_eq!(
            verify(&pse_only_backup).replay_rows().err(),
            Some(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn aggregate_artifact_limit_counts_papl_before_the_backup_limit() {
        let directory = TestDirectory::new("runtime-aggregate-limit");
        let path = directory.store();
        let (mut store, fixture) = runtime_store_fixture(&path);
        let control = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xb5),
        );
        let (_, _, application) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &control, 0xb6);
        store
            .append_control_with_runtime_application(&control, &application, &TestAuthority)
            .unwrap();

        // The 128 MiB archive envelope is a distinct bound from the Store's
        // 64 MiB indexed-artifact aggregate.
        let backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        assert!(backup.len() <= MAX_PRIVATE_BACKUP_BYTES);
        assert_eq!(
            store.export_encrypted_backup(backup.len() - 1),
            Err(PrivateStoreError::LimitExceeded)
        );

        let prototype = store.index.controls[0].clone();
        let control_len = prototype.wire_len as usize;
        let row_max = control_len
            .checked_add(MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES)
            .unwrap();
        let row_count = MAX_PRIVATE_STORE_ARTIFACT_BYTES / row_max + 1;
        assert!(row_count <= MAX_PRIVATE_STORE_CONTROLS);
        assert!(
            row_count
                .checked_mul(control_len + 1)
                .is_some_and(|minimum| minimum <= MAX_PRIVATE_STORE_ARTIFACT_BYTES)
        );

        let mut index = store.index.clone();
        index.controls.clear();
        for sequence in 0..row_count {
            let sequence = u64::try_from(sequence).unwrap();
            let previous = index.controls.last().map(|entry| entry.commitment);
            let commitment = Hash::digest(
                b"vos/test/private-store-papl-limit-control/v1",
                &[&sequence.to_le_bytes()],
            );
            let mut entry = prototype.clone();
            entry.sequence = sequence;
            entry.commitment = commitment;
            entry.previous = previous;
            entry.resulting_epoch = 0;
            entry.wire_hash = Hash::digest(
                b"vos/test/private-store-papl-limit-control-wire/v1",
                &[&sequence.to_le_bytes()],
            );
            let binding = entry.runtime_application.as_mut().unwrap();
            binding.control = commitment;
            binding.application = Hash::digest(
                b"vos/test/private-store-papl-limit-application/v1",
                &[&sequence.to_le_bytes()],
            );
            binding.wire_hash = Hash::digest(
                b"vos/test/private-store-papl-limit-wire/v1",
                &[&sequence.to_le_bytes()],
            );
            binding.wire_len = 1;
            binding.successor_runtime_image = Hash::digest(
                b"vos/test/private-store-papl-limit-pvri/v1",
                &[&sequence.to_le_bytes()],
            );
            binding.successor_stable_projection = Hash::digest(
                b"vos/test/private-store-papl-limit-psp/v1",
                &[&sequence.to_le_bytes()],
            );
            index.controls.push(entry);
        }
        index.control_head = index.controls.last().map(|entry| entry.commitment);
        index.next_sequence = u64::try_from(row_count).unwrap();
        index.epoch = 0;
        validate_index_shape(&index).unwrap();

        let control_bytes = row_count.checked_mul(control_len).unwrap();
        let mut remaining = MAX_PRIVATE_STORE_ARTIFACT_BYTES - control_bytes;
        for (position, entry) in index.controls.iter_mut().enumerate() {
            let rows_after = row_count - position - 1;
            let length = (remaining - rows_after).min(MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES);
            entry.runtime_application.as_mut().unwrap().wire_len = u32::try_from(length).unwrap();
            remaining -= length;
        }
        assert_eq!(remaining, 0);
        validate_index_shape(&index).unwrap();

        let binding = index
            .controls
            .iter_mut()
            .find_map(|entry| {
                entry.runtime_application.as_mut().filter(|binding| {
                    binding.wire_len as usize != MAX_PRIVATE_RUNTIME_APPLICATION_WIRE_BYTES
                })
            })
            .unwrap();
        binding.wire_len = binding.wire_len.checked_add(1).unwrap();
        assert_eq!(
            validate_index_shape(&index),
            Err(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn chronology_ambiguous_runtime_backup_is_rejected_before_publication() {
        let directory = TestDirectory::new("runtime-backup-chronology");
        let path = directory.store();
        let (mut store, fixture) = runtime_store_fixture(&path);
        let object = encrypt_private_object(
            &fixture.store_fixture.epoch.data_key,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            0,
            EncryptedObjectKind::Package,
            b"ciphertext-object-before-runtime-application",
        )
        .unwrap();
        store.put_object(&object).unwrap();
        let predecessor = runtime_genesis(
            &store,
            &fixture.descriptor,
            fixture.predecessor.node(),
            fixture.predecessor.applied_at(),
        );
        let control = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xba),
        );
        let (_, _, application) =
            completed_runtime_application(&store, &fixture, &predecessor, &control, 0xbb);
        store
            .append_control_with_runtime_application(&control, &application, &TestAuthority)
            .unwrap();
        let backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();

        // PVB3 owns the final ciphertext set, not historical object-prefix
        // chronology. Until Chapter 08 supplies that authenticated history,
        // the Store must fail closed before creating a new destination.
        let absent_target = directory.0.join("absent-target");
        assert_eq!(
            PrivateStore::restore_encrypted_backup(
                &absent_target,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                fixture.store_fixture.owner,
                fixture.store_fixture.recovery.verifying_key(),
                fixture.store_fixture.recovery_encryption.public_key(),
                &backup,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::InvalidBinding)
        );
        assert!(!absent_target.exists());

        let existing_target = directory.0.join("existing-target");
        drop(create_store(&existing_target, &fixture.store_fixture));
        let before = directory_image(&existing_target);
        assert_eq!(
            PrivateStore::restore_encrypted_backup(
                &existing_target,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                fixture.store_fixture.owner,
                fixture.store_fixture.recovery.verifying_key(),
                fixture.store_fixture.recovery_encryption.public_key(),
                &backup,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::InvalidBinding)
        );
        assert_eq!(directory_image(&existing_target), before);
    }

    #[test]
    fn runtime_application_transaction_reconciles_every_write_boundary() {
        let cases = [
            (CommitStop::AfterStagedArtifact, false),
            (CommitStop::AfterStagedRuntimeApplication, false),
            (CommitStop::AfterStagedIndex, false),
            (CommitStop::AfterPending, false),
            (CommitStop::AfterStage, false),
            (CommitStop::AfterArtifact, false),
            (CommitStop::AfterRuntimeApplication, false),
            (CommitStop::AfterIndex, true),
        ];
        for (case, (stop, committed)) in cases.into_iter().enumerate() {
            let directory = TestDirectory::new(&format!("runtime-failpoint-{case}"));
            let path = directory.store();
            let (mut store, fixture) = runtime_store_fixture(&path);
            let control = invite_control(
                &store,
                &fixture.store_fixture,
                recipient(&fixture.store_fixture, 0xc1),
            );
            let (_, _, application) = completed_runtime_application(
                &store,
                &fixture,
                &fixture.predecessor,
                &control,
                0xc2,
            );
            assert_eq!(
                store.append_control_with_runtime_application_with_stop_for_runtime(
                    &control,
                    &application,
                    &TestAuthority,
                    stop,
                ),
                Err(PrivateStoreError::Interrupted)
            );
            drop(store);
            let mut reopened = PrivateStore::open(
                &path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .unwrap();
            assert_eq!(reopened.control_count(), usize::from(committed));
            assert_eq!(
                reopened
                    .runtime_application_binding(control.commitment())
                    .ok()
                    .flatten()
                    .is_some(),
                committed
            );
            assert_eq!(fs::read_dir(path.join(STAGE_DIR)).unwrap().count(), 0);
            assert_eq!(
                fs::read_dir(path.join(RUNTIME_APPLICATIONS_DIR))
                    .unwrap()
                    .count(),
                usize::from(committed)
            );
            assert_eq!(
                reopened.append_control_with_runtime_application(
                    &control,
                    &application,
                    &TestAuthority
                ),
                Ok(if committed {
                    PutDisposition::AlreadyPresent
                } else {
                    PutDisposition::Inserted
                })
            );
        }
    }

    #[test]
    fn old_index_rollback_is_idempotent_after_suffix_retirement() {
        // AfterRuntimeApplication leaves the old index authoritative while
        // both final suffix files and the durable pending marker exist. These
        // cases model a second crash after retiring the PAPL, after retiring
        // the PCTL too, and after all three uncommitted suffixes are gone.
        for (case, (retire_control, retire_index)) in [(false, false), (true, false), (true, true)]
            .into_iter()
            .enumerate()
        {
            let directory = TestDirectory::new(&format!("runtime-rollback-retry-{case}"));
            let path = directory.store();
            let (mut store, fixture) = runtime_store_fixture(&path);
            let control = invite_control(
                &store,
                &fixture.store_fixture,
                recipient(&fixture.store_fixture, 0xc3),
            );
            let (_, _, application) = completed_runtime_application(
                &store,
                &fixture,
                &fixture.predecessor,
                &control,
                0xc4,
            );
            assert_eq!(
                store.append_control_with_runtime_application_with_stop_for_runtime(
                    &control,
                    &application,
                    &TestAuthority,
                    CommitStop::AfterRuntimeApplication,
                ),
                Err(PrivateStoreError::Interrupted)
            );
            drop(store);

            fs::remove_file(
                path.join(RUNTIME_APPLICATIONS_DIR)
                    .join(runtime_application_file_name(control.commitment())),
            )
            .unwrap();
            sync_directory(&path.join(RUNTIME_APPLICATIONS_DIR)).unwrap();
            if retire_control {
                fs::remove_file(
                    path.join(CONTROLS_DIR)
                        .join(control_file_name(control.commitment())),
                )
                .unwrap();
                sync_directory(&path.join(CONTROLS_DIR)).unwrap();
            }
            if retire_index {
                fs::remove_file(path.join(STAGE_DIR).join(STAGED_INDEX)).unwrap();
                sync_directory(&path.join(STAGE_DIR)).unwrap();
            }

            let reopened = PrivateStore::open(
                &path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .unwrap();
            assert_eq!(reopened.control_count(), 0);
            assert_eq!(
                reopened.runtime_application_binding(control.commitment()),
                Err(PrivateStoreError::NotFound)
            );
            assert_eq!(fs::read_dir(path.join(CONTROLS_DIR)).unwrap().count(), 0);
            assert_eq!(
                fs::read_dir(path.join(RUNTIME_APPLICATIONS_DIR))
                    .unwrap()
                    .count(),
                0
            );
            assert_eq!(fs::read_dir(path.join(STAGE_DIR)).unwrap().count(), 0);
            drop(reopened);

            // A completed rollback is itself exactly reopenable.
            let reopened = PrivateStore::open(
                &path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .unwrap();
            assert_eq!(reopened.control_count(), 0);
        }
    }

    #[test]
    fn published_index_requires_exact_papl_or_completes_from_exact_stage() {
        for mode in 0..4 {
            let directory = TestDirectory::new(&format!("runtime-new-index-{mode}"));
            let path = directory.store();
            let (mut store, fixture) = runtime_store_fixture(&path);
            let control = invite_control(
                &store,
                &fixture.store_fixture,
                recipient(&fixture.store_fixture, 0xd1),
            );
            let (_, _, application) = completed_runtime_application(
                &store,
                &fixture,
                &fixture.predecessor,
                &control,
                0xd2,
            );
            assert_eq!(
                store.append_control_with_runtime_application_with_stop_for_runtime(
                    &control,
                    &application,
                    &TestAuthority,
                    CommitStop::AfterIndex,
                ),
                Err(PrivateStoreError::Interrupted)
            );
            drop(store);
            let published = path
                .join(RUNTIME_APPLICATIONS_DIR)
                .join(runtime_application_file_name(control.commitment()));
            match mode {
                0 => {
                    fs::rename(
                        &published,
                        path.join(STAGE_DIR).join(STAGED_RUNTIME_APPLICATION),
                    )
                    .unwrap();
                    let reopened = PrivateStore::open(
                        &path,
                        fixture.store_fixture.space,
                        fixture.store_fixture.agent,
                        &TestAuthority,
                    )
                    .unwrap();
                    assert_eq!(
                        reopened
                            .read_runtime_application(control.commitment())
                            .unwrap(),
                        Some(application)
                    );
                }
                1 => {
                    fs::remove_file(&published).unwrap();
                    assert_eq!(
                        PrivateStore::open(
                            &path,
                            fixture.store_fixture.space,
                            fixture.store_fixture.agent,
                            &TestAuthority,
                        )
                        .err(),
                        Some(PrivateStoreError::Corrupt)
                    );
                }
                2 => {
                    let mut bytes = fs::read(&published).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(&published, bytes).unwrap();
                    assert_eq!(
                        PrivateStore::open(
                            &path,
                            fixture.store_fixture.space,
                            fixture.store_fixture.agent,
                            &TestAuthority,
                        )
                        .err(),
                        Some(PrivateStoreError::Corrupt)
                    );
                }
                _ => {
                    let mut bytes = fs::read(&published).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(path.join(STAGE_DIR).join(STAGED_RUNTIME_APPLICATION), bytes)
                        .unwrap();
                    assert_eq!(
                        PrivateStore::open(
                            &path,
                            fixture.store_fixture.space,
                            fixture.store_fixture.agent,
                            &TestAuthority,
                        )
                        .err(),
                        Some(PrivateStoreError::Corrupt)
                    );
                }
            }
        }
    }

    #[test]
    fn same_epoch_controls_bind_distinct_control_and_pvri_identities() {
        let directory = TestDirectory::new("runtime-same-epoch");
        let path = directory.store();
        let (mut store, fixture) = runtime_store_fixture(&path);
        let first = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xe1),
        );
        let (first_runtime, _, first_application) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &first, 0xe2);
        store
            .append_control_with_runtime_application(&first, &first_application, &TestAuthority)
            .unwrap();
        let second = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xe3),
        );
        let (_, _, second_application) =
            completed_runtime_application(&store, &fixture, &first_runtime, &second, 0xe4);
        store
            .append_control_with_runtime_application(&second, &second_application, &TestAuthority)
            .unwrap();
        assert_eq!(first.sequence + 1, second.sequence);
        assert_eq!(store.index.controls[0].resulting_epoch, 0);
        assert_eq!(store.index.controls[1].resulting_epoch, 0);
        let first_binding = store.index.controls[0].runtime_application.unwrap();
        let second_binding = store.index.controls[1].runtime_application.unwrap();
        assert_ne!(first_binding.control, second_binding.control);
        assert_ne!(
            first_binding.successor_runtime_image,
            second_binding.successor_runtime_image
        );
        drop(store);
        let reopened = PrivateStore::open(
            &path,
            fixture.store_fixture.space,
            fixture.store_fixture.agent,
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.control_count(), 2);
        assert_eq!(
            reopened
                .read_runtime_application(second.commitment())
                .unwrap(),
            Some(second_application)
        );
    }

    #[test]
    fn backup_reconciliation_never_pairs_node_local_papl_with_foreign_evidence() {
        let directory = TestDirectory::new("runtime-reconcile-node-local");
        let first_path = directory.store();
        let second_path = directory.0.join("replica-b");
        let (mut first_store, fixture) = runtime_store_fixture(&first_path);
        let mut second_store = create_store(&second_path, &fixture.store_fixture);
        let alternate_node = fixture
            .store_fixture
            .nodes
            .iter()
            .find(|node| node.node != fixture.predecessor.node())
            .unwrap()
            .node;
        let alternate_predecessor = runtime_genesis(
            &second_store,
            &fixture.descriptor,
            alternate_node,
            fixture.predecessor.applied_at(),
        );
        assert_eq!(
            fixture.predecessor.stable_projection(),
            alternate_predecessor.stable_projection()
        );
        assert_ne!(
            fixture.predecessor.commitment(),
            alternate_predecessor.commitment()
        );

        let control = invite_control(
            &first_store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xe7),
        );
        let (_, _, first_application) = completed_runtime_application(
            &first_store,
            &fixture,
            &fixture.predecessor,
            &control,
            0xe8,
        );
        let (_, _, second_application) = completed_runtime_application(
            &second_store,
            &fixture,
            &alternate_predecessor,
            &control,
            0xe8,
        );
        assert_eq!(
            first_application.successor_stable_projection(),
            second_application.successor_stable_projection()
        );
        assert_ne!(
            first_application.commitment(),
            second_application.commitment()
        );
        assert_ne!(
            first_application.successor_runtime_image(),
            second_application.successor_runtime_image()
        );
        first_store
            .append_control_with_runtime_application(&control, &first_application, &TestAuthority)
            .unwrap();
        second_store
            .append_control_with_runtime_application(&control, &second_application, &TestAuthority)
            .unwrap();

        let first_without_evidence = first_store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let second_without_evidence = second_store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let verify = |bytes: &[u8]| {
            verify_encrypted_backup(
                bytes,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                fixture.store_fixture.owner,
                fixture.store_fixture.recovery.verifying_key(),
                fixture.store_fixture.recovery_encryption.public_key(),
                &TestAuthority,
            )
            .unwrap()
        };
        let first_is_selected = match compare_recovery_base(
            &verify(&first_without_evidence),
            &verify(&second_without_evidence),
        ) {
            core::cmp::Ordering::Greater => true,
            core::cmp::Ordering::Less => false,
            core::cmp::Ordering::Equal => panic!("node-local PAPL identities must order exactly"),
        };
        let source_evidence = b"PSE2-evidence-for-only-the-unselected-node-local-papl".to_vec();
        if first_is_selected {
            second_store
                .persist_control_authority_evidence(control.commitment(), &source_evidence)
                .unwrap();
        } else {
            first_store
                .persist_control_authority_evidence(control.commitment(), &source_evidence)
                .unwrap();
        }
        let first_backup = first_store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let second_backup = second_store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let (selected_forward, forward_heads, forward_sequence) =
            reconcile_encrypted_backups(vec![verify(&first_backup), verify(&second_backup)])
                .unwrap();
        let (selected_reverse, reverse_heads, reverse_sequence) =
            reconcile_encrypted_backups(vec![verify(&second_backup), verify(&first_backup)])
                .unwrap();
        assert_eq!(forward_heads, reverse_heads);
        assert_eq!(forward_sequence, reverse_sequence);
        assert_eq!(
            selected_forward
                .encode_backup(MAX_PRIVATE_BACKUP_BYTES)
                .unwrap(),
            selected_reverse
                .encode_backup(MAX_PRIVATE_BACKUP_BYTES)
                .unwrap()
        );
        let selected_application = selected_forward
            .controls_with_runtime_applications()
            .next()
            .unwrap()
            .2
            .unwrap();
        assert!(
            (first_is_selected && selected_application == &first_application)
                || (!first_is_selected && selected_application == &second_application)
        );
        assert_eq!(
            selected_forward
                .controls_with_authority_evidence()
                .next()
                .unwrap()
                .2,
            None
        );
        assert_eq!(
            selected_forward.replay_rows().err(),
            Some(PrivateStoreError::Corrupt)
        );
    }

    #[test]
    fn runtime_application_rejects_substitution_alias_and_psc_mismatch_before_io() {
        let directory = TestDirectory::new("runtime-input-mismatch");
        let path = directory.store();
        let (mut store, fixture) = runtime_store_fixture(&path);
        let first = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xf1),
        );
        let (_, _, first_application) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &first, 0xf2);
        let second = invite_control(
            &store,
            &fixture.store_fixture,
            recipient(&fixture.store_fixture, 0xf3),
        );
        let (_, _, substituted_application) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &second, 0xf4);
        let before = directory_image(&path);
        assert_eq!(
            store.append_control_with_runtime_application(
                &first,
                &substituted_application,
                &TestAuthority,
            ),
            Err(PrivateStoreError::InvalidBinding)
        );
        assert_eq!(directory_image(&path), before);

        let (_, _, alias_application) =
            completed_runtime_application(&store, &fixture, &fixture.predecessor, &first, 0xf5);
        store
            .append_control_with_runtime_application(&first, &first_application, &TestAuthority)
            .unwrap();
        assert_eq!(
            store.append_control_with_runtime_application(
                &first,
                &alias_application,
                &TestAuthority,
            ),
            Err(PrivateStoreError::Alias)
        );

        let mismatch_directory = TestDirectory::new("runtime-psc-mismatch");
        let mismatch_path = mismatch_directory.store();
        let (mut mismatch_store, mismatch_fixture) = runtime_store_fixture(&mismatch_path);
        let mismatch_control = invite_control(
            &mismatch_store,
            &mismatch_fixture.store_fixture,
            recipient(&mismatch_fixture.store_fixture, 0xf6),
        );
        let (_, _, stale_application) = completed_runtime_application(
            &mismatch_store,
            &mismatch_fixture,
            &mismatch_fixture.predecessor,
            &mismatch_control,
            0xf7,
        );
        let object = encrypt_private_object(
            &mismatch_fixture.store_fixture.epoch.data_key,
            mismatch_fixture.store_fixture.space,
            mismatch_fixture.store_fixture.agent,
            0,
            EncryptedObjectKind::Package,
            b"ciphertext-object-before-control",
        )
        .unwrap();
        mismatch_store.put_object(&object).unwrap();
        let before = directory_image(&mismatch_path);
        assert_eq!(
            mismatch_store.append_control_with_runtime_application(
                &mismatch_control,
                &stale_application,
                &TestAuthority,
            ),
            Err(PrivateStoreError::InvalidBinding)
        );
        assert_eq!(directory_image(&mismatch_path), before);
    }

    #[test]
    fn reopen_rejects_every_runtime_application_binding_mismatch() {
        for field in 0..5 {
            let directory = TestDirectory::new(&format!("runtime-binding-{field}"));
            let path = directory.store();
            let (mut store, fixture) = runtime_store_fixture(&path);
            let control = invite_control(
                &store,
                &fixture.store_fixture,
                recipient(&fixture.store_fixture, 0x71),
            );
            let (_, _, application) = completed_runtime_application(
                &store,
                &fixture,
                &fixture.predecessor,
                &control,
                0x72,
            );
            store
                .append_control_with_runtime_application(&control, &application, &TestAuthority)
                .unwrap();
            let binding = store.index.controls[0]
                .runtime_application
                .as_mut()
                .unwrap();
            match field {
                0 => binding.application = test_hash(0x73),
                1 => binding.wire_hash = test_hash(0x74),
                2 => binding.wire_len = binding.wire_len.checked_add(1).unwrap(),
                3 => binding.successor_runtime_image = test_hash(0x75),
                _ => binding.successor_stable_projection = test_hash(0x76),
            }
            fs::write(path.join(INDEX_FILE), encode_index(&store.index).unwrap()).unwrap();
            drop(store);
            assert_eq!(
                PrivateStore::open(
                    &path,
                    fixture.store_fixture.space,
                    fixture.store_fixture.agent,
                    &TestAuthority,
                )
                .err(),
                Some(PrivateStoreError::Corrupt)
            );
        }
    }

    #[test]
    fn generation_three_rejects_old_index_pending_and_backup_wire() {
        let directory = TestDirectory::new("runtime-old-wire");
        let index_path = directory.0.join("index-store");
        let (store, fixture) = runtime_store_fixture(&index_path);
        let snapshot = store
            .export_encrypted_snapshot(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let backup = store
            .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let index_wire = fs::read(index_path.join(INDEX_FILE)).unwrap();
        assert_eq!(index_wire.get(..4), Some(INDEX_MAGIC.as_slice()));
        assert!(PrivateRuntimeImage::decode(&index_wire).is_err());
        assert_eq!(
            decode_index(&fixture.predecessor.encode().unwrap()).err(),
            Some(PrivateStoreError::Corrupt)
        );
        assert_eq!(snapshot.get(..4), Some(SNAPSHOT_MAGIC.as_slice()));
        assert_eq!(backup.get(..4), Some(BACKUP_MAGIC.as_slice()));
        let mut old_backup = backup;
        old_backup[..4].copy_from_slice(b"PVB2");
        assert_eq!(
            verify_encrypted_backup(
                &old_backup,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                fixture.store_fixture.owner,
                fixture.store_fixture.recovery.verifying_key(),
                fixture.store_fixture.recovery_encryption.public_key(),
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );
        drop(store);
        let mut old_index = fs::read(index_path.join(INDEX_FILE)).unwrap();
        assert_eq!(old_index.get(..4), Some(INDEX_MAGIC.as_slice()));
        old_index[..4].copy_from_slice(b"PVI2");
        fs::write(index_path.join(INDEX_FILE), old_index).unwrap();
        assert_eq!(
            PrivateStore::open(
                &index_path,
                fixture.store_fixture.space,
                fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );

        let pending_path = directory.0.join("pending-store");
        let (mut pending_store, pending_fixture) = runtime_store_fixture(&pending_path);
        let control = invite_control(
            &pending_store,
            &pending_fixture.store_fixture,
            recipient(&pending_fixture.store_fixture, 0x81),
        );
        let (_, _, application) = completed_runtime_application(
            &pending_store,
            &pending_fixture,
            &pending_fixture.predecessor,
            &control,
            0x82,
        );
        assert_eq!(
            pending_store.append_control_with_runtime_application_with_stop_for_runtime(
                &control,
                &application,
                &TestAuthority,
                CommitStop::AfterPending,
            ),
            Err(PrivateStoreError::Interrupted)
        );
        drop(pending_store);
        let pending_file = pending_path.join(STAGE_DIR).join(PENDING_FILE);
        let mut old_pending = fs::read(&pending_file).unwrap();
        assert_eq!(old_pending.get(..4), Some(TRANSACTION_MAGIC.as_slice()));
        old_pending[..4].copy_from_slice(b"PVT2");
        fs::write(pending_file, old_pending).unwrap();
        assert_eq!(
            PrivateStore::open(
                &pending_path,
                pending_fixture.store_fixture.space,
                pending_fixture.store_fixture.agent,
                &TestAuthority,
            )
            .err(),
            Some(PrivateStoreError::Corrupt)
        );
    }
}
