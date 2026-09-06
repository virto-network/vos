//! Durable ciphertext-only storage for Private agents.
//!
//! The store accepts canonical [`EncryptedPrivateObject`] and
//! [`PrivateControlRecord`] values only. It has no API for plaintext or
//! unwrapped owner, data, node, or recovery keys. An immutable public genesis
//! record bootstraps verification; a sorted index is advanced with each
//! artifact through a durable stage -> artifact -> index/head transaction.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use vos_agent_sdk::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_NODES, PrivateControlOperation,
    PrivateControlRecord, PrivateControlSigner, PrivateKeyEpoch, PrivateNodeIdentity,
    PrivateRecoveryKeyringGrant,
};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES,
    MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES, MAX_PRIVATE_OBJECT_WIRE_BYTES,
};
use vos_agent_sdk::{AgentId, Hash, PrincipalId, SpaceId};

use super::private_crypto::{
    MAX_PRIVATE_CONTROL_RECORDS, PrivateControlChainVerifier, PrivateCryptoError,
    PrivateNodeAuthorityVerifier,
};

pub const MAX_PRIVATE_STORE_OBJECTS: usize = 16_384;
pub const MAX_PRIVATE_STORE_CONTROLS: usize = MAX_PRIVATE_CONTROL_RECORDS as usize;
pub const MAX_PRIVATE_STORE_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PRIVATE_STORE_INDEX_BYTES: usize = 48 * 1024 * 1024;
pub const MAX_PRIVATE_RECOVERY_METADATA_BYTES: usize = MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES
    + MAX_PRIVATE_NODES * MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES
    + 512;
pub const MAX_PRIVATE_BACKUP_BYTES: usize = 128 * 1024 * 1024;

const FORMAT_VERSION: u16 = 1;
const RECOVERY_MAGIC: &[u8; 4] = b"PVRM";
const INDEX_MAGIC: &[u8; 4] = b"PVIX";
const TRANSACTION_MAGIC: &[u8; 4] = b"PVTX";
const SNAPSHOT_MAGIC: &[u8; 4] = b"PVSS";
const BACKUP_MAGIC: &[u8; 4] = b"PVBK";
const RAW_WIRE_DOMAIN: &[u8] = b"vos/private/stored-wire/v1";
const RECOVERY_FILE: &str = "recovery.meta";
const INDEX_FILE: &str = "index";
const LOCK_FILE: &str = "lock";
const OBJECTS_DIR: &str = "objects";
const CONTROLS_DIR: &str = "controls";
const STAGE_DIR: &str = "stage";
const STAGED_ARTIFACT: &str = "artifact.next";
const STAGED_INDEX: &str = "index.next";
const PENDING_FILE: &str = "pending";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreDisposition {
    Restored,
    AlreadyPresent,
}

/// Canonical semantic address of one encrypted object. A second ciphertext at
/// the same `(epoch, kind, plaintext-content commitment)` is an alias and is
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
    index_hash: Hash,
    index_len: u32,
}

/// Fully authenticated, bounded ciphertext archive held only while an
/// offline recovery ceremony prepares its exact successor. It deliberately
/// exposes sealed epoch metadata but no API for plaintext or unwrapped keys.
pub(crate) struct VerifiedEncryptedBackup {
    metadata: RecoveryMetadata,
    index: StoreIndex,
    controls: Vec<PrivateControlRecord>,
    objects: Vec<EncryptedPrivateObject>,
    key_epochs: Vec<PrivateKeyEpoch>,
    chain: PrivateControlChainVerifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitStop {
    Never,
    #[cfg(test)]
    AfterStage,
    #[cfg(test)]
    AfterArtifact,
    #[cfg(test)]
    AfterIndex,
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
        if entry.wire_hash == Hash::ZERO
            || entry.wire_len == 0
            || entry.wire_len as usize > MAX_PRIVATE_OBJECT_WIRE_BYTES
        {
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
        };
        if entry.commitment == Hash::ZERO
            || entry.wire_hash == Hash::ZERO
            || entry.wire_len == 0
            || entry.wire_len as usize > MAX_PRIVATE_CONTROL_WIRE_BYTES
            || entry
                .superseded_heads
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
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

fn validate_index_shape(index: &StoreIndex) -> Result<(), PrivateStoreError> {
    let artifact_bytes = index
        .objects
        .iter()
        .map(|entry| entry.wire_len as usize)
        .chain(index.controls.iter().map(|entry| entry.wire_len as usize))
        .try_fold(0usize, |total, length| total.checked_add(length))
        .ok_or(PrivateStoreError::LimitExceeded)?;
    if index.space == SpaceId::ZERO
        || index.agent == AgentId::ZERO
        || index.objects.len() > MAX_PRIVATE_STORE_OBJECTS
        || index.controls.len() > MAX_PRIVATE_STORE_CONTROLS
        || artifact_bytes > MAX_PRIVATE_STORE_ARTIFACT_BYTES
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
    encoder.fixed(pending.index_hash.as_bytes());
    encoder.u32(pending.index_len);
    encoder.finish(192)
}

fn decode_pending(bytes: &[u8]) -> Result<PendingTransaction, PrivateStoreError> {
    let mut decoder = Decoder::new(bytes, TRANSACTION_MAGIC, 192)?;
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
        index_hash: Hash(decoder.fixed()?),
        index_len: decoder.u32()?,
    };
    decoder.finish()?;
    if pending.artifact_hash == Hash::ZERO
        || pending.index_hash == Hash::ZERO
        || pending.artifact_len == 0
        || pending.index_len == 0
        || pending.index_len as usize > MAX_PRIVATE_STORE_INDEX_BYTES
    {
        return Err(PrivateStoreError::Corrupt);
    }
    Ok(pending)
}

/// Fully decode and authenticate an encrypted archive without touching the
/// destination filesystem. The caller-supplied binding is the external trust
/// anchor; archive metadata is never allowed to select its own owner or
/// recovery key.
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
        controls.push(record);
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
        objects,
        key_epochs,
        chain,
    })
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

    pub(crate) fn key_epochs(&self) -> &[PrivateKeyEpoch] {
        &self.key_epochs
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
            || record.sequence != self.index.next_sequence
            || record.previous != self.index.control_head
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
        match self.index.control_head {
            Some(head) if superseded_heads.as_slice() == [head] => {}
            None if superseded_heads.is_empty() => {}
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
        };
        self.index.controls.push(entry);
        self.index.epoch = next_chain.epoch().epoch;
        self.index.control_head = next_chain.head();
        self.index.next_sequence = next_chain.next_sequence();
        validate_index_shape(&self.index)?;
        self.controls.push(record.clone());
        self.key_epochs = next_key_epochs;
        self.chain = next_chain;
        Ok(())
    }

    pub(crate) fn encode_backup(&self, max_bytes: usize) -> Result<Vec<u8>, PrivateStoreError> {
        let maximum = max_bytes.min(MAX_PRIVATE_BACKUP_BYTES);
        if self.controls.len() != self.index.controls.len()
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
        for (entry, record) in self.index.controls.iter().zip(&self.controls) {
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
            pending.index_hash,
            pending.index_len,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
        fs::rename(&stage, &target).map_err(map_io)?;
        sync_directory(root)?;
    } else {
        verify_file_identity(
            &target,
            pending.index_hash,
            pending.index_len,
            MAX_PRIVATE_STORE_INDEX_BYTES,
        )?;
    }
    Ok(())
}

fn reconcile_pending(root: &Path) -> Result<(), PrivateStoreError> {
    let stage_dir = root.join(STAGE_DIR);
    let pending_path = stage_dir.join(PENDING_FILE);
    if !pending_path.exists() {
        remove_file_if_present(&stage_dir.join(STAGED_ARTIFACT))?;
        remove_file_if_present(&stage_dir.join(STAGED_INDEX))?;
        sync_directory(&stage_dir)?;
        return Ok(());
    }
    let pending_bytes = read_bounded_file(&pending_path, 192)?;
    let pending = decode_pending(&pending_bytes)?;
    publish_artifact(root, &pending)?;
    publish_index(root, &pending)?;
    remove_file_if_present(&pending_path)?;
    remove_file_if_present(&stage_dir.join(STAGED_ARTIFACT))?;
    remove_file_if_present(&stage_dir.join(STAGED_INDEX))?;
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
    pub fn create<V: PrivateNodeAuthorityVerifier>(
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
        fs::create_dir(root.join(STAGE_DIR)).map_err(map_io)?;
        sync_directory(&root)?;
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
        write_initial_file(
            &root,
            "recovery.initial",
            RECOVERY_FILE,
            &encode_recovery(&metadata)?,
        )?;
        write_initial_file(&root, "index.initial", INDEX_FILE, &encode_index(&index)?)?;
        Ok(Self {
            root,
            _lock: lock,
            metadata,
            index,
            chain,
            key_epochs,
            latest_recovery_keyring: None,
            #[cfg(test)]
            artifact_reads: core::cell::Cell::new(0),
        })
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
        for directory in [OBJECTS_DIR, CONTROLS_DIR, STAGE_DIR] {
            let metadata = fs::symlink_metadata(root.join(directory)).map_err(map_io)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(PrivateStoreError::Corrupt);
            }
        }
        let lock = open_lock(&root)?;
        reconcile_pending(&root)?;
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
        Ok(Self {
            root,
            _lock: lock,
            metadata,
            index,
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
    pub fn restore_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
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
            ),
            Err(_) => return Err(PrivateStoreError::Io),
        };
        if store.metadata != backup.metadata {
            return Err(PrivateStoreError::Diverged);
        }
        validate_restore_prefix(&store.index, &backup.index)?;
        let changed = created || store.index != backup.index;
        for record in backup.controls.iter().skip(store.index.controls.len()) {
            store.append_control(record, authority)?;
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
    pub fn apply_offline_recovery<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        expected_prior_head: Option<Hash>,
        record: &PrivateControlRecord,
        authority: &V,
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
            return self.append_control(record, authority);
        }
        if self.chain.head() != expected_prior_head {
            return Err(PrivateStoreError::Diverged);
        }
        self.append_control(record, authority)
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
                let index_bytes = encode_index(&next)?;
                self.commit_transaction(PendingArtifact::Object(key), &wire, &index_bytes, stop)?;
                self.index = next;
            }
        }
        Ok(PutDisposition::Inserted)
    }

    pub fn append_control<V: PrivateNodeAuthorityVerifier>(
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
        let commitment = record.commitment();
        let wire = record
            .encode()
            .map_err(|_| PrivateStoreError::InvalidRecord)?;
        if let Some(existing) = self
            .index
            .controls
            .iter()
            .find(|entry| entry.commitment == commitment)
        {
            if existing.wire_hash != raw_wire_hash(&wire)
                || existing.wire_len as usize != wire.len()
            {
                return Err(PrivateStoreError::Alias);
            }
            if self.read_control_wire(existing)? != wire {
                return Err(PrivateStoreError::Corrupt);
            }
            return Ok(PutDisposition::AlreadyPresent);
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
        let mut next_key_epochs = self.key_epochs.clone();
        advance_key_epochs(&mut next_key_epochs, record)?;
        let mut next_recovery_keyring = self.latest_recovery_keyring.clone();
        if let PrivateControlOperation::Recover {
            historical_keyring, ..
        } = &record.operation
        {
            next_recovery_keyring = Some(historical_keyring.clone());
        }
        if next_key_epochs.last() != Some(next_chain.epoch()) {
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
        };
        let mut next = self.index.clone();
        next.controls.push(entry);
        next.epoch = next_chain.epoch().epoch;
        next.control_head = next_chain.head();
        next.next_sequence = next_chain.next_sequence();
        validate_index_shape(&next)?;
        let index_bytes = encode_index(&next)?;
        self.commit_transaction(
            PendingArtifact::Control(commitment),
            &wire,
            &index_bytes,
            stop,
        )?;
        self.chain = next_chain;
        self.key_epochs = next_key_epochs;
        self.latest_recovery_keyring = next_recovery_keyring;
        self.index = next;
        Ok(PutDisposition::Inserted)
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
        index_bytes: &[u8],
        stop: CommitStop,
    ) -> Result<(), PrivateStoreError> {
        let stage_dir = self.root.join(STAGE_DIR);
        let pending_path = stage_dir.join(PENDING_FILE);
        if pending_path.exists() {
            return Err(PrivateStoreError::Corrupt);
        }
        let staged_artifact = stage_dir.join(STAGED_ARTIFACT);
        let staged_index = stage_dir.join(STAGED_INDEX);
        remove_file_if_present(&staged_artifact)?;
        remove_file_if_present(&staged_index)?;
        write_new_synced(&staged_artifact, artifact_bytes)?;
        write_new_synced(&staged_index, index_bytes)?;
        let pending = PendingTransaction {
            artifact,
            artifact_hash: raw_wire_hash(artifact_bytes),
            artifact_len: u32::try_from(artifact_bytes.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
            index_hash: raw_wire_hash(index_bytes),
            index_len: u32::try_from(index_bytes.len())
                .map_err(|_| PrivateStoreError::LimitExceeded)?,
        };
        write_new_synced(&pending_path, &encode_pending(&pending)?)?;
        sync_directory(&stage_dir)?;
        #[cfg(test)]
        if stop == CommitStop::AfterStage {
            return Err(PrivateStoreError::Interrupted);
        }
        let _ = stop;
        publish_artifact(&self.root, &pending)?;
        #[cfg(test)]
        if stop == CommitStop::AfterArtifact {
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
    use core::sync::atomic::{AtomicU64, Ordering};

    use vos_agent_sdk::private::EncryptedObjectKind;

    use crate::agent::private_crypto::{
        GeneratedPrivateEpoch, OfflineRecoveryDecryptionKey, OwnerSigningKey,
        PrivateNodeDecryptionKey, RecoverySigningKey, build_recovery_keyring_grant,
        encrypt_private_object, generate_fresh_private_epoch, sign_owner_control_record,
        sign_recovery_control_record, unwrap_recovery_data_key,
    };
    use vos_agent_sdk::{BlobRef, NodeId};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const TEST_AUTHORITY_DOMAIN: &[u8] = b"vos/test/private-store-authority/v1";

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
        assert_eq!(store.object_count(), 1);
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
        assert_eq!(store.control_count(), 1);
        assert_eq!(store.binding().control_head, Some(record.commitment()));
        let next_record = control(&fixture, 1, Some(record.commitment()));
        let mut store = store;
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
}
