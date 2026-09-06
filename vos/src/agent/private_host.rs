//! Production ownership boundary for ciphertext-only Private agents.
//!
//! One host root is immutably scoped to one Space, owner Principal, and full
//! authenticated local node identity.  Agent directories use only the exact
//! lowercase encoding of the complete clean-generation [`AgentId`].  The
//! durable [`PrivateStore`] remains ciphertext/control only; descriptor,
//! runtime-package, and bootstrap plaintexts live in zeroizing memory and in
//! separately encrypted, crash-reconciled sidecars.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use fs2::FileExt;
use vos_agent_sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
use vos_agent_sdk::contract::{
    ActorAbiRange, RuntimeMigrationPolicy, RuntimePackageContract, RuntimeResourceLimits,
};
use vos_agent_sdk::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_CIPHERTEXT_BYTES, MAX_PRIVATE_NODES,
    MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS, PrivateActorLifecycleKind, PrivateControlOperation,
    PrivateControlRecord, PrivateControlSigner, PrivateKeyEpoch, PrivateNodeIdentity,
};
use vos_agent_sdk::protocol::wire::{DecodeError, Decoder, Encoder};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES, MAX_PRIVATE_OBJECT_WIRE_BYTES,
};
use vos_agent_sdk::{
    ActorDescriptor, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, CredentialId, DeploymentId, Hash, LaneSet, NodeId, PrincipalId, ProducerId, ProgramId,
    ProofSystemSet, ReplicaRole, RuntimeCapabilities, RuntimeWork, SpaceId, StorageFieldDescriptor,
};
use zeroize::Zeroizing;

use super::package_admission::{AdmittedRuntimePackage, admit_runtime_package};
use super::private_crypto::{
    GeneratedPrivateEpoch, OfflineRecoveryKit, OwnerSigningKey, PrivateCryptoError, PrivateDataKey,
    PrivateNodeAuthorityVerifier, PrivateNodeDecryptionKey, build_recovery_keyring_grant,
    decrypt_private_object, encrypt_private_object, generate_fresh_private_epoch,
    seal_data_key_for_node, seal_owner_key_for_node, sign_owner_control_record,
    sign_recovery_control_record, unwrap_data_key, unwrap_owner_key, unwrap_recovery_data_key,
    unwrap_recovery_keyring, valid_x25519_public_key,
};
use super::private_store::{
    MAX_PRIVATE_BACKUP_BYTES, PrivateObjectKey, PrivateStore, PrivateStoreError, PutDisposition,
    RestoreDisposition, verify_encrypted_backup,
};
use super::private_sync::{
    PrivateSyncApplyDisposition, PrivateSyncError, PrivateSyncPage, PrivateSyncPhase,
    PrivateSyncRequest, PrivateTransportAuthVerifier, apply_private_sync_page,
    serve_private_sync_page, validate_private_actor_schema, validate_private_runtime_work,
};

pub const MAX_PRIVATE_HOST_AGENTS: usize = 4_096;
pub const MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_PRIVATE_HOST_ARCHIVE_BYTES: usize = MAX_PRIVATE_BACKUP_BYTES + 32 * 1024 * 1024;

const FORMAT_VERSION: u16 = 1;
const ROOT_SCOPE_MAGIC: &[u8; 4] = b"PVHR";
const DESCRIPTOR_MAGIC: &[u8; 4] = b"PVHD";
const RUNTIME_MAGIC: &[u8; 4] = b"PVHP";
const BOOTSTRAP_MAGIC: &[u8; 4] = b"PVHM";
const BACKUP_MAGIC: &[u8; 4] = b"PVHB";
const SNAPSHOT_MAGIC: &[u8; 4] = b"PVHS";
const RECOVERY_PLAN_MAGIC: &[u8; 4] = b"PVRP";
const RECOVERY_PLAN_HASH_DOMAIN: &[u8] = b"vos/private/recovery-plan-bytes/v1";
const RECOVERY_SOURCE_HASH_DOMAIN: &[u8] = b"vos/private/recovery-source-archive/v1";
const RECOVERY_REPLACEMENTS_DOMAIN: &[u8] = b"vos/private/recovery-replacements/v1";

const ROOT_SCOPE_FILE: &str = "scope";
const ROOT_LOCK_FILE: &str = "lock";
const CREATING_DIRECTORY: &str = ".creating";
const STORE_DIRECTORY: &str = "store";
const DESCRIPTOR_FILE: &str = "descriptor.enc";
const RUNTIME_FILE: &str = "runtime.enc";
const BOOTSTRAP_FILE: &str = "bootstrap.enc";
const NEXT_PREFIX: &str = ".next-";
const WRITE_SUFFIX: &str = ".write";
const RECOVERY_PLAN_FILE: &str = "recovery.plan";
const RECOVERY_PLAN_WRITE_FILE: &str = "recovery.plan.write";
const SIDECAR_FILES: [&str; 3] = [DESCRIPTOR_FILE, RUNTIME_FILE, BOOTSTRAP_FILE];
const MAX_PRIVATE_RECOVERY_PLAN_BYTES: usize = MAX_PRIVATE_HOST_ARCHIVE_BYTES + 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateAgentHostError {
    Io,
    Busy,
    AlreadyExists,
    NotFound,
    Corrupt,
    InvalidRoot,
    InvalidScope,
    InvalidDescriptor,
    InvalidMembership,
    InvalidArtifact,
    Unauthorized,
    Alias,
    LimitExceeded,
    LinearUnsupported,
    Store(PrivateStoreError),
    Crypto(PrivateCryptoError),
    Sync(PrivateSyncError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryInstallStop {
    Never,
    AfterPlan,
    AfterStore,
    AfterDescriptor,
    AfterRuntime,
    AfterBootstrap,
    AfterVerification,
    AfterPlanRetired,
    AfterPublish,
}

impl fmt::Display for PrivateAgentHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Private-agent host operation failed: {self:?}")
    }
}

impl core::error::Error for PrivateAgentHostError {}

impl From<PrivateStoreError> for PrivateAgentHostError {
    fn from(error: PrivateStoreError) -> Self {
        match error {
            PrivateStoreError::AlreadyExists => Self::AlreadyExists,
            PrivateStoreError::NotFound => Self::NotFound,
            PrivateStoreError::InvalidScope | PrivateStoreError::InvalidBinding => {
                Self::InvalidScope
            }
            PrivateStoreError::Alias => Self::Alias,
            PrivateStoreError::LimitExceeded => Self::LimitExceeded,
            PrivateStoreError::Busy => Self::Busy,
            PrivateStoreError::Corrupt => Self::Corrupt,
            other => Self::Store(other),
        }
    }
}

impl From<PrivateCryptoError> for PrivateAgentHostError {
    fn from(error: PrivateCryptoError) -> Self {
        match error {
            PrivateCryptoError::UnauthorizedNode
            | PrivateCryptoError::WrongRecipient
            | PrivateCryptoError::MissingRecipient => Self::Unauthorized,
            PrivateCryptoError::LimitExceeded => Self::LimitExceeded,
            other => Self::Crypto(other),
        }
    }
}

impl From<PrivateSyncError> for PrivateAgentHostError {
    fn from(error: PrivateSyncError) -> Self {
        match error {
            PrivateSyncError::Unauthorized => Self::Unauthorized,
            PrivateSyncError::LinearUnsupported => Self::LinearUnsupported,
            PrivateSyncError::Alias => Self::Alias,
            PrivateSyncError::LimitExceeded | PrivateSyncError::LimitTooSmall => {
                Self::LimitExceeded
            }
            other => Self::Sync(other),
        }
    }
}

/// Public recipient pair returned only after an offline recovery ceremony has
/// durably retained both independent secrets outside this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableRecoveryRecipient {
    signing_public_key: [u8; 32],
    encryption_public_key: [u8; 32],
}

impl DurableRecoveryRecipient {
    /// Bind independent Ed25519 signing and X25519 encryption public keys
    /// obtained from already-durable offline storage. The normal host never
    /// receives either corresponding secret.
    pub fn from_durable_keystore(
        signing_public_key: [u8; 32],
        encryption_public_key: [u8; 32],
    ) -> Result<Self, PrivateAgentHostError> {
        let key = VerifyingKey::from_bytes(&signing_public_key)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        if key.is_weak()
            || !valid_x25519_public_key(&encryption_public_key)
            || signing_public_key == encryption_public_key
        {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
        Ok(Self {
            signing_public_key,
            encryption_public_key,
        })
    }

    pub const fn signing_public_key(self) -> [u8; 32] {
        self.signing_public_key
    }

    pub const fn encryption_public_key(self) -> [u8; 32] {
        self.encryption_public_key
    }
}

pub struct PrivateAgentCreate<'a> {
    pub descriptor: &'a AgentDescriptor,
    pub nodes: &'a [PrivateNodeIdentity],
    pub recovery_recipient: DurableRecoveryRecipient,
    /// Package which has already crossed the canonical VOS3 signature and
    /// standard-PVM admission boundary. Older VOSK values are unrepresentable.
    pub runtime_package: &'a AdmittedRuntimePackage,
    pub bootstrap_metadata: &'a [u8],
}

/// Transport identity accepted by Private sync ingress.  Principal and SSH
/// credential identities are represented explicitly so they fail closed
/// before any persisted artifact is read.
#[derive(Clone, Copy, Debug)]
pub enum PrivatePeerIdentity<'a> {
    Node(&'a PrivateNodeIdentity),
    Principal(PrincipalId),
    Credential(CredentialId),
}

struct HostedPrivateAgent {
    store: PrivateStore,
    descriptor: AgentDescriptor,
    runtime_package: Zeroizing<Vec<u8>>,
    bootstrap_metadata: Zeroizing<Vec<u8>>,
    owner_key: OwnerSigningKey,
    /// Unwrapped only in memory, bounded by the authenticated control history,
    /// and zeroized entry-by-entry on drop. The durable representation remains
    /// node-recipient ciphertext in the store genesis/control artifacts.
    data_keys: BTreeMap<u64, PrivateDataKey>,
}

struct AgentPlaintext {
    descriptor: AgentDescriptor,
    runtime_package: Zeroizing<Vec<u8>>,
    bootstrap_metadata: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RootScope {
    space: SpaceId,
    owner: PrincipalId,
    local_node: PrivateNodeIdentity,
}

/// A single-writer host for all Private agents owned by one Principal in one
/// Space on one exact authenticated transport node.
pub struct PrivateAgentHost {
    root: PathBuf,
    canonical_root: PathBuf,
    _lock: File,
    scope: RootScope,
    node_key: PrivateNodeDecryptionKey,
    agents: BTreeMap<AgentId, HostedPrivateAgent>,
}

impl PrivateAgentHost {
    /// Create a new, empty host root.  The parent directory must already
    /// exist, which avoids silently traversing caller-controlled symlinks.
    pub fn create(
        root: impl AsRef<Path>,
        space: SpaceId,
        owner: PrincipalId,
        local_node: PrivateNodeIdentity,
        node_key: PrivateNodeDecryptionKey,
    ) -> Result<Self, PrivateAgentHostError> {
        if space == SpaceId::ZERO
            || owner == PrincipalId::ZERO
            || !local_node.validate()
            || local_node.principal != owner
            || local_node.encryption_public_key != node_key.public_key()
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let root = root.as_ref();
        let parent = root.parent().ok_or(PrivateAgentHostError::InvalidRoot)?;
        require_real_directory(parent)?;
        match fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PrivateAgentHostError::InvalidRoot);
            }
            Ok(_) => return Err(PrivateAgentHostError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PrivateAgentHostError::Io),
        }
        fs::create_dir(root).map_err(map_io)?;
        require_real_directory(root)?;
        let lock = open_root_lock(root)?;
        let scope = RootScope {
            space,
            owner,
            local_node,
        };
        write_new_synced(&root.join(ROOT_SCOPE_FILE), &encode_root_scope(&scope)?)?;
        fs::create_dir(root.join(CREATING_DIRECTORY)).map_err(map_io)?;
        sync_directory(root)?;
        let canonical_root = fs::canonicalize(root).map_err(map_io)?;
        Ok(Self {
            root: root.to_path_buf(),
            canonical_root,
            _lock: lock,
            scope,
            node_key,
            agents: BTreeMap::new(),
        })
    }

    /// Reopen every canonical agent directory, replaying each authenticated
    /// control chain before unwrapping keys for the exact local full node.
    pub fn open<V: PrivateNodeAuthorityVerifier>(
        root: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_owner: PrincipalId,
        expected_local_node: PrivateNodeIdentity,
        node_key: PrivateNodeDecryptionKey,
        authority: &V,
    ) -> Result<Self, PrivateAgentHostError> {
        let root = root.as_ref().to_path_buf();
        require_real_directory(&root)?;
        let canonical_root = fs::canonicalize(&root).map_err(map_io)?;
        let lock = open_root_lock(&root)?;
        require_regular_file(&root.join(ROOT_SCOPE_FILE))?;
        let scope_bytes = read_bounded_file(
            &root.join(ROOT_SCOPE_FILE),
            MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES + 128,
        )?;
        let scope = decode_root_scope(&scope_bytes)?;
        if scope.space != expected_space
            || scope.owner != expected_owner
            || scope.local_node != expected_local_node
            || scope.local_node.encryption_public_key != node_key.public_key()
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let creating = root.join(CREATING_DIRECTORY);
        require_real_directory(&creating)?;
        let mut host = Self {
            root,
            canonical_root,
            _lock: lock,
            scope,
            node_key,
            agents: BTreeMap::new(),
        };
        host.recover_creating(authority)?;
        let agent_ids = scan_root(&host.root)?;
        if agent_ids.len() > MAX_PRIVATE_HOST_AGENTS {
            return Err(PrivateAgentHostError::LimitExceeded);
        }
        for agent in agent_ids {
            let hosted = open_hosted_agent(
                &host.agent_path(agent),
                host.scope.space,
                host.scope.owner,
                &host.scope.local_node,
                &host.node_key,
                authority,
            )?;
            if hosted.descriptor.identity.agent != agent
                || host.agents.insert(agent, hosted).is_some()
            {
                return Err(PrivateAgentHostError::Alias);
            }
        }
        Ok(host)
    }

    pub fn space(&self) -> SpaceId {
        self.scope.space
    }

    pub fn owner(&self) -> PrincipalId {
        self.scope.owner
    }

    pub fn local_node(&self) -> &PrivateNodeIdentity {
        &self.scope.local_node
    }

    pub fn agent_ids(&self) -> impl ExactSizeIterator<Item = AgentId> + '_ {
        self.agents.keys().copied()
    }

    pub fn descriptor(&self, agent: AgentId) -> Result<&AgentDescriptor, PrivateAgentHostError> {
        self.agents
            .get(&agent)
            .map(|hosted| &hosted.descriptor)
            .ok_or(PrivateAgentHostError::NotFound)
    }

    pub fn binding(
        &self,
        agent: AgentId,
    ) -> Result<super::private_store::PrivateStoreBinding, PrivateAgentHostError> {
        Ok(self.hosted(agent)?.store.binding())
    }

    pub fn create_agent<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        request: PrivateAgentCreate<'_>,
        authority: &V,
    ) -> Result<AgentId, PrivateAgentHostError> {
        self.verify_root_scope()?;
        validate_create_request(&self.scope, &self.node_key, &request)?;
        if self.agents.len() >= MAX_PRIVATE_HOST_AGENTS {
            return Err(PrivateAgentHostError::LimitExceeded);
        }
        let descriptor = request.descriptor;
        let agent = descriptor.identity.agent;
        if self.agents.contains_key(&agent)
            || fs::symlink_metadata(self.agent_path(agent)).is_ok()
            || fs::symlink_metadata(self.creating_path(agent)).is_ok()
        {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let generated = generate_fresh_private_epoch(
            self.scope.space,
            agent,
            0,
            self.scope.owner,
            request.nodes,
            request.recovery_recipient.signing_public_key(),
            request.recovery_recipient.encryption_public_key(),
            authority,
        )?;
        let stage = self.creating_path(agent);
        fs::create_dir(&stage).map_err(map_io)?;
        let result = (|| {
            let store = PrivateStore::create(
                stage.join(STORE_DIRECTORY),
                self.scope.space,
                agent,
                self.scope.owner,
                request.recovery_recipient.signing_public_key(),
                request.recovery_recipient.encryption_public_key(),
                generated.record.clone(),
                request.nodes.to_vec(),
                authority,
            )?;
            let plaintext = AgentPlaintext {
                descriptor: descriptor.clone(),
                runtime_package: Zeroizing::new(request.runtime_package.exact_bytes().to_vec()),
                bootstrap_metadata: Zeroizing::new(request.bootstrap_metadata.to_vec()),
            };
            write_initial_sidecars(&stage, 0, &generated.data_key, &plaintext)?;
            drop(store);
            sync_directory(&stage)?;
            fs::rename(&stage, self.agent_path(agent)).map_err(map_io)?;
            sync_directory(&self.root)?;
            sync_directory(&self.root.join(CREATING_DIRECTORY))?;
            open_hosted_agent(
                &self.agent_path(agent),
                self.scope.space,
                self.scope.owner,
                &self.scope.local_node,
                &self.node_key,
                authority,
            )
        })();
        match result {
            Ok(hosted) => {
                if self.agents.insert(agent, hosted).is_some() {
                    return Err(PrivateAgentHostError::Alias);
                }
                Ok(agent)
            }
            Err(error) => {
                // Only an unpublished, exactly named creation slot is ever
                // retired here. A published canonical slot is retained for
                // restart reconciliation rather than being deleted.
                if fs::symlink_metadata(&stage)
                    .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                {
                    let _ = fs::remove_dir_all(&stage);
                    let _ = sync_directory(&self.root.join(CREATING_DIRECTORY));
                }
                Err(error)
            }
        }
    }

    /// Store caller-supplied ciphertext only at the current authenticated
    /// epoch. This prevents an old, revoked key holder from injecting stale
    /// writes through a still-running caller.
    pub fn put_encrypted_object(
        &mut self,
        agent: AgentId,
        object: &EncryptedPrivateObject,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        if object.space != hosted.store.binding().space
            || object.agent != agent
            || object.epoch != hosted.store.binding().epoch
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        Ok(hosted.store.put_object(object)?)
    }

    pub fn get_encrypted_object(
        &self,
        agent: AgentId,
        key: PrivateObjectKey,
    ) -> Result<EncryptedPrivateObject, PrivateAgentHostError> {
        Ok(self.hosted(agent)?.store.get_object(key)?)
    }

    /// Encrypt and durably store one bounded application object with the
    /// current key epoch. Plaintext is never written to a filesystem API.
    pub fn encrypt_and_put(
        &mut self,
        agent: AgentId,
        kind: EncryptedObjectKind,
        plaintext: &[u8],
    ) -> Result<PrivateObjectKey, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let hosted = self.hosted_mut(agent)?;
        let binding = hosted.store.binding();
        let data_key = hosted
            .data_keys
            .get(&binding.epoch)
            .ok_or(PrivateAgentHostError::Corrupt)?;
        let object = encrypt_private_object(
            data_key,
            binding.space,
            binding.agent,
            binding.epoch,
            kind,
            plaintext,
        )?;
        let key = PrivateObjectKey::from_object(&object);
        hosted.store.put_object(&object)?;
        Ok(key)
    }

    pub fn get_and_decrypt(
        &self,
        agent: AgentId,
        key: PrivateObjectKey,
    ) -> Result<Zeroizing<Vec<u8>>, PrivateAgentHostError> {
        let hosted = self.hosted(agent)?;
        let object = hosted.store.get_object(key)?;
        let data_key = hosted
            .data_keys
            .get(&object.epoch)
            .ok_or(PrivateAgentHostError::Unauthorized)?;
        Ok(Zeroizing::new(decrypt_private_object(data_key, &object)?))
    }

    pub fn invite_node<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        node: PrivateNodeIdentity,
        authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let hosted = self.hosted_mut(agent)?;
        let binding = hosted.store.binding();
        if !node.validate()
            || node.principal != binding.owner
            || hosted
                .store
                .authorized_nodes()
                .binary_search_by_key(&node.node, |entry| entry.node)
                .is_ok()
            || !authority.verify_private_node_binding(
                binding.space,
                binding.agent,
                binding.owner,
                &node,
            )
        {
            return Err(PrivateAgentHostError::InvalidMembership);
        }
        let sealed_owner_key = seal_owner_key_for_node(
            binding.space,
            binding.agent,
            binding.epoch,
            &hosted.owner_key,
            &node,
        )?;
        let sealed_data_key = seal_data_key_for_node(
            binding.space,
            binding.agent,
            binding.epoch,
            hosted
                .data_keys
                .get(&binding.epoch)
                .ok_or(PrivateAgentHostError::Corrupt)?,
            &node,
        )?;
        let operation = PrivateControlOperation::Invite {
            node,
            epoch: binding.epoch,
            sealed_owner_key,
            sealed_data_key,
        };
        append_owner_record(hosted, operation, authority)
    }

    /// Revoke one exact Node and commit a fresh owner/data epoch before this
    /// method returns. The serving local node cannot revoke itself and keep
    /// using the same scoped host root.
    pub fn revoke_node<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        node: NodeId,
        authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        if node == self.scope.local_node.node {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        let local_node = self.scope.local_node.clone();
        let slot = self.agent_path(agent);
        let owner = self.scope.owner;
        let node_key = &self.node_key;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let mut nodes = hosted.store.authorized_nodes().to_vec();
        let position = nodes
            .binary_search_by_key(&node, |entry| entry.node)
            .map_err(|_| PrivateAgentHostError::InvalidMembership)?;
        nodes.remove(position);
        rotate_with_operation(
            &slot,
            hosted,
            owner,
            &local_node,
            node_key,
            &nodes,
            |next_epoch| PrivateControlOperation::Revoke { node, next_epoch },
            authority,
        )
    }

    pub fn rotate_keys<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let local_node = self.scope.local_node.clone();
        let slot = self.agent_path(agent);
        let owner = self.scope.owner;
        let node_key = &self.node_key;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let nodes = hosted.store.authorized_nodes().to_vec();
        rotate_with_operation(
            &slot,
            hosted,
            owner,
            &local_node,
            node_key,
            &nodes,
            |next_epoch| PrivateControlOperation::RotateKeys { next_epoch },
            authority,
        )
    }

    pub fn record_actor_lifecycle<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        actor: ActorId,
        operation: PrivateActorLifecycleKind,
        request: Hash,
        authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        if actor == ActorId::ZERO || request == Hash::ZERO {
            return Err(PrivateAgentHostError::InvalidDescriptor);
        }
        append_owner_record(
            self.hosted_mut(agent)?,
            PrivateControlOperation::ActorLifecycle {
                actor,
                operation,
                request,
            },
            authority,
        )
    }

    /// Apply an externally signed offline recovery record. The replacement
    /// set must contain this exact local identity, otherwise this host cannot
    /// safely own the recovered Agent.
    pub fn apply_recovery_record<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        expected_prior_head: Hash,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let local_node = self.scope.local_node.clone();
        let slot = self.agent_path(agent);
        let node_key = &self.node_key;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let PrivateControlOperation::Recover {
            next_epoch,
            replacement_nodes,
            historical_keyring,
            ..
        } = &record.operation
        else {
            return Err(PrivateAgentHostError::InvalidDescriptor);
        };
        require_exact_local_member(replacement_nodes, &local_node)?;
        let next_owner = unwrap_owner_key(next_epoch, &local_node, node_key)?;
        let next_data = unwrap_data_key(next_epoch, &local_node, node_key)?;
        let prior_epoch_count = hosted
            .store
            .key_epochs()
            .partition_point(|epoch| epoch.epoch < next_epoch.epoch);
        if prior_epoch_count == 0 {
            return Err(PrivateAgentHostError::Corrupt);
        }
        let historical = unwrap_recovery_keyring(
            historical_keyring,
            &hosted.store.key_epochs()[..prior_epoch_count],
            &local_node,
            node_key,
        )?;
        stage_metadata(&slot, next_epoch.epoch, &next_data, hosted)?;
        let disposition =
            match hosted
                .store
                .apply_offline_recovery(Some(expected_prior_head), record, authority)
            {
                Ok(disposition) => disposition,
                Err(error) => {
                    discard_next_sidecars(&slot, next_epoch.epoch);
                    return Err(error.into());
                }
            };
        hosted.owner_key = next_owner;
        for (epoch, key) in historical {
            if let Some(existing) = hosted.data_keys.get(&epoch) {
                if existing.commitment() != key.commitment() {
                    return Err(PrivateAgentHostError::Corrupt);
                }
            } else {
                hosted.data_keys.insert(epoch, key);
            }
        }
        hosted.data_keys.insert(next_epoch.epoch, next_data);
        promote_next_sidecars(&slot, next_epoch.epoch)?;
        Ok(disposition)
    }

    pub fn validate_actor_schema(
        actor: &ActorDescriptor,
        storage: &[StorageFieldDescriptor],
    ) -> Result<(), PrivateAgentHostError> {
        validate_private_actor_schema(actor, storage).map_err(Into::into)
    }

    pub fn validate_runtime_work(work: &RuntimeWork) -> Result<(), PrivateAgentHostError> {
        validate_private_runtime_work(work).map_err(Into::into)
    }

    pub fn export_encrypted_snapshot(
        &self,
        agent: AgentId,
        max_bytes: usize,
    ) -> Result<Vec<u8>, PrivateAgentHostError> {
        self.export_archive(agent, max_bytes, false)
    }

    pub fn export_encrypted_backup(
        &self,
        agent: AgentId,
        max_bytes: usize,
    ) -> Result<Vec<u8>, PrivateAgentHostError> {
        self.export_archive(agent, max_bytes, true)
    }

    /// Restore a complete ciphertext archive onto another currently
    /// authorized owner node. No descriptor, runtime, bootstrap, or key
    /// plaintext crosses the archive boundary.
    pub fn restore_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_recipient: DurableRecoveryRecipient,
        bytes: &[u8],
        authority: &V,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        if self.agents.contains_key(&agent)
            || fs::symlink_metadata(self.agent_path(agent)).is_ok()
            || fs::symlink_metadata(self.creating_path(agent)).is_ok()
        {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let archive = decode_host_archive(bytes, true)?;
        if archive.space != self.scope.space || archive.agent != agent {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let stage = self.creating_path(agent);
        fs::create_dir(&stage).map_err(map_io)?;
        let result = (|| {
            let (store, disposition) = PrivateStore::restore_encrypted_backup(
                stage.join(STORE_DIRECTORY),
                self.scope.space,
                agent,
                self.scope.owner,
                recovery_recipient.signing_public_key(),
                recovery_recipient.encryption_public_key(),
                &archive.store,
                authority,
            )?;
            write_new_synced(&stage.join(DESCRIPTOR_FILE), &archive.descriptor)?;
            write_new_synced(&stage.join(RUNTIME_FILE), &archive.runtime)?;
            write_new_synced(&stage.join(BOOTSTRAP_FILE), &archive.bootstrap)?;
            drop(store);
            // The files themselves are durable, but their directory entries
            // must also reach disk before the staging directory is published.
            // Otherwise a power loss after the rename can expose a slot whose
            // authenticated sidecars were never durably linked.
            sync_directory(&stage)?;
            let hosted = open_hosted_agent(
                &stage,
                self.scope.space,
                self.scope.owner,
                &self.scope.local_node,
                &self.node_key,
                authority,
            )?;
            drop(hosted);
            fs::rename(&stage, self.agent_path(agent)).map_err(map_io)?;
            sync_directory(&self.root)?;
            sync_directory(&self.root.join(CREATING_DIRECTORY))?;
            let hosted = open_hosted_agent(
                &self.agent_path(agent),
                self.scope.space,
                self.scope.owner,
                &self.scope.local_node,
                &self.node_key,
                authority,
            )?;
            Ok::<_, PrivateAgentHostError>((hosted, disposition))
        })();
        match result {
            Ok((hosted, disposition)) => {
                self.agents.insert(agent, hosted);
                Ok(disposition)
            }
            Err(error) => {
                if fs::symlink_metadata(&stage).is_ok_and(|metadata| metadata.is_dir()) {
                    let _ = fs::remove_dir_all(&stage);
                    let _ = sync_directory(&self.root.join(CREATING_DIRECTORY));
                }
                Err(error)
            }
        }
    }

    /// Recover a complete ciphertext archive after every previously active
    /// Node has been lost. Both independent halves of the offline kit are
    /// required: the X25519 half unwraps every authenticated data epoch and
    /// the Ed25519 half signs one exact replacement control. The prepared
    /// archive persisted for crash recovery contains ciphertext and public
    /// metadata only.
    pub fn recover_from_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        bytes: &[u8],
        authority: &V,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.recover_from_encrypted_backup_inner(
            agent,
            recovery_kit,
            replacement_nodes,
            bytes,
            authority,
            RecoveryInstallStop::Never,
        )
    }

    #[cfg(test)]
    fn recover_from_encrypted_backup_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        bytes: &[u8],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.recover_from_encrypted_backup_inner(
            agent,
            recovery_kit,
            replacement_nodes,
            bytes,
            authority,
            stop,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_from_encrypted_backup_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        bytes: &[u8],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        require_exact_local_member(replacement_nodes, &self.scope.local_node)?;
        let source_hash = Hash::digest(RECOVERY_SOURCE_HASH_DOMAIN, &[bytes]);
        let replacements_hash = recovery_replacements_hash(
            self.scope.space,
            agent,
            self.scope.owner,
            replacement_nodes,
        )?;
        if self.agents.contains_key(&agent) || fs::symlink_metadata(self.agent_path(agent)).is_ok()
        {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let stage = self.creating_path(agent);
        if fs::symlink_metadata(&stage).is_ok() {
            require_real_directory(&stage)?;
            let plan = read_and_authenticate_recovery_plan(
                &stage.join(RECOVERY_PLAN_FILE),
                &self.node_key,
            )?;
            if plan.space != self.scope.space
                || plan.agent != agent
                || plan.owner != self.scope.owner
                || plan.source_hash != source_hash
                || plan.replacements_hash != replacements_hash
                || plan.recovery_signing_public_key != recovery_kit.signing_public_key()
                || plan.recovery_encryption_public_key != recovery_kit.encryption_public_key()
            {
                return Err(PrivateAgentHostError::Alias);
            }
            let disposition = self.complete_recovery_plan(agent, authority, stop)?;
            let hosted = open_hosted_agent(
                &self.agent_path(agent),
                self.scope.space,
                self.scope.owner,
                &self.scope.local_node,
                &self.node_key,
                authority,
            )?;
            if self.agents.insert(agent, hosted).is_some() {
                return Err(PrivateAgentHostError::Alias);
            }
            return Ok(disposition);
        }

        let archive = decode_host_archive(bytes, true)?;
        if archive.space != self.scope.space || archive.agent != agent {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let mut verified = verify_encrypted_backup(
            &archive.store,
            self.scope.space,
            agent,
            self.scope.owner,
            recovery_kit.signing_public_key(),
            recovery_kit.encryption_public_key(),
            authority,
        )?;
        let prior_binding = verified.binding();
        if verified.key_epochs().is_empty()
            || verified.key_epochs().len() > MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS
            || prior_binding.next_sequence >= super::private_crypto::MAX_PRIVATE_CONTROL_RECORDS
        {
            return Err(PrivateAgentHostError::LimitExceeded);
        }
        let mut historical_keys = BTreeMap::new();
        let mut historical_commitments = BTreeMap::new();
        for epoch in verified.key_epochs() {
            let key = unwrap_recovery_data_key(epoch, recovery_kit.decryption_key())?;
            if historical_keys.insert(epoch.epoch, key).is_some() {
                return Err(PrivateAgentHostError::Corrupt);
            }
            if historical_commitments
                .insert(epoch.epoch, epoch.data_key_commitment)
                .is_some()
            {
                return Err(PrivateAgentHostError::Corrupt);
            }
        }
        if historical_keys.len() != verified.key_epochs().len()
            || historical_commitments.len() != verified.key_epochs().len()
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        // The archive index authenticates the canonical ciphertext records,
        // but only the exact historical epoch keys can authenticate their
        // contents. Audit every object before creating or publishing any
        // recovery plan; successful plaintext exists only in this bounded
        // zeroizing buffer.
        for object in verified.objects() {
            if !object.validate() || object.space != self.scope.space || object.agent != agent {
                return Err(PrivateAgentHostError::Corrupt);
            }
            let key = historical_keys
                .get(&object.epoch)
                .ok_or(PrivateAgentHostError::Corrupt)?;
            let commitment = historical_commitments
                .get(&object.epoch)
                .ok_or(PrivateAgentHostError::Corrupt)?;
            if key.commitment() != *commitment {
                return Err(PrivateAgentHostError::Corrupt);
            }
            let plaintext = Zeroizing::new(decrypt_private_object(key, object)?);
            drop(plaintext);
        }
        let current_key = historical_keys
            .get(&prior_binding.epoch)
            .ok_or(PrivateAgentHostError::Corrupt)?;
        let mut plaintext = decrypt_archive_plaintext(&archive, prior_binding.epoch, current_key)?;
        validate_archive_plaintext(&plaintext, self.scope.space, agent, self.scope.owner)?;
        plaintext.descriptor.replicas = replacement_nodes
            .iter()
            .map(|node| AgentReplica {
                node: node.node,
                principal: node.principal,
                role: ReplicaRole::Observer,
            })
            .collect();
        plaintext
            .descriptor
            .validate()
            .map_err(|_| PrivateAgentHostError::InvalidDescriptor)?;

        let successor_epoch = prior_binding
            .epoch
            .checked_add(1)
            .ok_or(PrivateAgentHostError::LimitExceeded)?;
        let generated = generate_fresh_private_epoch(
            self.scope.space,
            agent,
            successor_epoch,
            self.scope.owner,
            replacement_nodes,
            recovery_kit.signing_public_key(),
            recovery_kit.encryption_public_key(),
            authority,
        )?;
        let historical_keyring = build_recovery_keyring_grant(
            verified.key_epochs(),
            &historical_keys,
            &generated.record,
            replacement_nodes,
        )?;
        let mut recovery_record = PrivateControlRecord {
            space: self.scope.space,
            agent,
            sequence: prior_binding.next_sequence,
            previous: prior_binding.control_head,
            operation: PrivateControlOperation::Recover {
                superseded_heads: prior_binding.control_head.into_iter().collect(),
                next_epoch: generated.record.clone(),
                replacement_nodes: replacement_nodes.to_vec(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery_record, recovery_kit.signing_key())?;
        verified.append_offline_recovery(&recovery_record, authority)?;
        let recovered_store = verified.encode_backup(MAX_PRIVATE_BACKUP_BYTES)?;
        let recovered_sidecars = encrypt_sidecars(
            self.scope.space,
            agent,
            successor_epoch,
            &generated.data_key,
            &plaintext,
        )?;
        let recovered_archive = encode_host_archive(
            &HostArchive {
                space: self.scope.space,
                agent,
                store: recovered_store,
                descriptor: recovered_sidecars.descriptor,
                runtime: recovered_sidecars.runtime,
                bootstrap: recovered_sidecars.bootstrap,
            },
            true,
            MAX_PRIVATE_HOST_ARCHIVE_BYTES,
        )?;
        let plan = RecoveryPlan {
            space: self.scope.space,
            agent,
            owner: self.scope.owner,
            source_hash,
            replacements_hash,
            recovery_signing_public_key: recovery_kit.signing_public_key(),
            recovery_encryption_public_key: recovery_kit.encryption_public_key(),
            recovered_archive,
        };
        let plan_bytes = encode_recovery_plan(&plan, &self.node_key)?;
        fs::create_dir(&stage).map_err(map_io)?;
        let publish_result = publish_recovery_plan(&stage, &plan_bytes);
        if let Err(error) = publish_result {
            let _ = fs::remove_dir_all(&stage);
            let _ = sync_directory(&self.root.join(CREATING_DIRECTORY));
            return Err(error);
        }
        recovery_stop(stop, RecoveryInstallStop::AfterPlan)?;
        let disposition = self.complete_recovery_plan(agent, authority, stop)?;
        let hosted = open_hosted_agent(
            &self.agent_path(agent),
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            authority,
        )?;
        if self.agents.insert(agent, hosted).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        Ok(disposition)
    }

    fn complete_recovery_plan<V: PrivateNodeAuthorityVerifier>(
        &self,
        agent: AgentId,
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        let stage = self.creating_path(agent);
        let destination = self.agent_path(agent);
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let plan =
            read_and_authenticate_recovery_plan(&stage.join(RECOVERY_PLAN_FILE), &self.node_key)?;
        if plan.space != self.scope.space || plan.agent != agent || plan.owner != self.scope.owner {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let archive = decode_host_archive(&plan.recovered_archive, true)?;
        if archive.space != self.scope.space || archive.agent != agent {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let store_root = stage.join(STORE_DIRECTORY);
        let restore_store = || {
            PrivateStore::restore_encrypted_backup(
                &store_root,
                self.scope.space,
                agent,
                self.scope.owner,
                plan.recovery_signing_public_key,
                plan.recovery_encryption_public_key,
                &archive.store,
                authority,
            )
        };
        let (store, disposition) = match restore_store() {
            Ok(restored) => restored,
            Err(PrivateStoreError::Corrupt | PrivateStoreError::NotFound)
                if fs::symlink_metadata(&store_root).is_ok() =>
            {
                // A process may stop while the unpublished store is creating
                // its immutable metadata. The authenticated plan retains the
                // exact recovery bytes, so only this exact real staging
                // directory is retired and rebuilt from those same bytes.
                require_real_directory(&store_root)?;
                fs::remove_dir_all(&store_root).map_err(map_io)?;
                sync_directory(&stage)?;
                restore_store()?
            }
            Err(error) => return Err(error.into()),
        };
        drop(store);
        recovery_stop(stop, RecoveryInstallStop::AfterStore)?;
        write_exact_or_new_synced(&stage.join(DESCRIPTOR_FILE), &archive.descriptor)?;
        recovery_stop(stop, RecoveryInstallStop::AfterDescriptor)?;
        write_exact_or_new_synced(&stage.join(RUNTIME_FILE), &archive.runtime)?;
        recovery_stop(stop, RecoveryInstallStop::AfterRuntime)?;
        write_exact_or_new_synced(&stage.join(BOOTSTRAP_FILE), &archive.bootstrap)?;
        recovery_stop(stop, RecoveryInstallStop::AfterBootstrap)?;
        sync_directory(&stage)?;
        let hosted = open_hosted_agent(
            &stage,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            authority,
        )?;
        drop(hosted);
        recovery_stop(stop, RecoveryInstallStop::AfterVerification)?;
        remove_regular_file_if_present(&stage.join(RECOVERY_PLAN_FILE))?;
        sync_directory(&stage)?;
        recovery_stop(stop, RecoveryInstallStop::AfterPlanRetired)?;
        fs::rename(&stage, &destination).map_err(map_io)?;
        sync_directory(&self.root.join(CREATING_DIRECTORY))?;
        sync_directory(&self.root)?;
        recovery_stop(stop, RecoveryInstallStop::AfterPublish)?;
        Ok(disposition)
    }

    /// Decode and serve one exact authenticated sync request. Authentication
    /// happens from the in-memory membership view before request decoding or
    /// any ciphertext/control read.
    pub fn serve_sync_page<T: PrivateTransportAuthVerifier>(
        &self,
        agent: AgentId,
        peer: PrivatePeerIdentity<'_>,
        request_bytes: &[u8],
        transport: &T,
    ) -> Result<Vec<u8>, PrivateAgentHostError> {
        let hosted = self.hosted(agent)?;
        let peer = authenticate_peer_identity(hosted, peer, transport)?;
        let request = PrivateSyncRequest::decode(request_bytes)?;
        Ok(serve_private_sync_page(&hosted.store, peer, &request, transport)?.encode()?)
    }

    /// Apply one exact authenticated sync page. If it carries a key epoch,
    /// new encrypted sidecars are durably staged before the control head is
    /// advanced, closing the restart gap between rotation and metadata.
    pub fn apply_sync_page<A, T>(
        &mut self,
        agent: AgentId,
        peer: PrivatePeerIdentity<'_>,
        page_bytes: &[u8],
        authority: &A,
        transport: &T,
    ) -> Result<PrivateSyncApplyDisposition, PrivateAgentHostError>
    where
        A: PrivateNodeAuthorityVerifier,
        T: PrivateTransportAuthVerifier,
    {
        let local_node = self.scope.local_node.clone();
        let slot = self.agent_path(agent);
        let node_key = &self.node_key;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let peer = authenticate_peer_identity(hosted, peer, transport)?;
        let page = PrivateSyncPage::decode(page_bytes)?;
        let starting_epoch = hosted.store.binding().epoch;
        // Validate the complete signed control suffix before encrypting any
        // host plaintext to a page-supplied epoch key. This prevents a valid
        // transport peer from turning an unsigned key epoch into a plaintext
        // disclosure sidecar.
        let staged_keys = validated_candidate_keys_from_page(
            &hosted.store,
            &page,
            &local_node,
            node_key,
            authority,
        )?;
        for candidate in &staged_keys {
            stage_metadata(&slot, candidate.epoch, &candidate.data, hosted)?;
        }
        let result = apply_private_sync_page(&mut hosted.store, peer, &page, authority, transport);
        match result {
            Ok(disposition) => {
                reconcile_staged_sync_keys(&slot, hosted, starting_epoch, staged_keys, false)?;
                Ok(disposition)
            }
            Err(error) => {
                // The store commits each control independently. If its live
                // binding advanced, install the exact visible prefix. If it
                // did not, an I/O failure may still have durably published an
                // index before the in-memory assignment; retain every staged
                // generation so restart recovery can select the disk truth.
                if hosted.store.binding().epoch > starting_epoch {
                    reconcile_staged_sync_keys(&slot, hosted, starting_epoch, staged_keys, true)?;
                }
                Err(error.into())
            }
        }
    }

    fn export_archive(
        &self,
        agent: AgentId,
        max_bytes: usize,
        complete: bool,
    ) -> Result<Vec<u8>, PrivateAgentHostError> {
        let hosted = self.hosted(agent)?;
        let slot = self.agent_path(agent);
        let store = if complete {
            hosted.store.export_encrypted_backup(max_bytes)?
        } else {
            hosted.store.export_encrypted_snapshot(max_bytes)?
        };
        let archive = HostArchive {
            space: self.scope.space,
            agent,
            store,
            descriptor: read_sidecar_wire(&slot, DESCRIPTOR_FILE)?,
            runtime: read_sidecar_wire(&slot, RUNTIME_FILE)?,
            bootstrap: read_sidecar_wire(&slot, BOOTSTRAP_FILE)?,
        };
        encode_host_archive(&archive, complete, max_bytes)
    }

    fn hosted(&self, agent: AgentId) -> Result<&HostedPrivateAgent, PrivateAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(PrivateAgentHostError::NotFound)
    }

    fn hosted_mut(
        &mut self,
        agent: AgentId,
    ) -> Result<&mut HostedPrivateAgent, PrivateAgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(PrivateAgentHostError::NotFound)
    }

    fn agent_path(&self, agent: AgentId) -> PathBuf {
        self.root.join(encode_agent_id(agent))
    }

    fn creating_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(CREATING_DIRECTORY)
            .join(encode_agent_id(agent))
    }

    fn verify_root_scope(&self) -> Result<(), PrivateAgentHostError> {
        require_real_directory(&self.root)?;
        if fs::canonicalize(&self.root).map_err(map_io)? != self.canonical_root {
            return Err(PrivateAgentHostError::InvalidRoot);
        }
        require_regular_file(&self.root.join(ROOT_SCOPE_FILE))?;
        let bytes = read_bounded_file(
            &self.root.join(ROOT_SCOPE_FILE),
            MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES + 128,
        )?;
        if decode_root_scope(&bytes)? != self.scope {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        Ok(())
    }

    fn recover_creating<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        authority: &V,
    ) -> Result<(), PrivateAgentHostError> {
        let creating = self.root.join(CREATING_DIRECTORY);
        let mut staged = scan_agent_directories(&creating)?;
        staged.sort_unstable();
        for agent in staged {
            let source = self.creating_path(agent);
            let destination = self.agent_path(agent);
            if fs::symlink_metadata(&destination).is_ok() {
                return Err(PrivateAgentHostError::Alias);
            }
            let plan = source.join(RECOVERY_PLAN_FILE);
            let unpublished_plan = source.join(RECOVERY_PLAN_WRITE_FILE);
            if fs::symlink_metadata(&plan).is_ok() {
                if fs::symlink_metadata(&unpublished_plan).is_ok() {
                    return Err(PrivateAgentHostError::Alias);
                }
                self.complete_recovery_plan(agent, authority, RecoveryInstallStop::Never)?;
                continue;
            }
            if fs::symlink_metadata(&unpublished_plan).is_ok() {
                // The random successor became resumable only when its single
                // authenticated plan file was atomically published. A lone
                // write file is therefore an unpublished exact staging slot,
                // safe to retire without selecting any of its contents.
                require_regular_file(&unpublished_plan)?;
                require_real_directory(&source)?;
                fs::remove_dir_all(&source).map_err(map_io)?;
                sync_directory(&creating)?;
                continue;
            }
            let hosted = open_hosted_agent(
                &source,
                self.scope.space,
                self.scope.owner,
                &self.scope.local_node,
                &self.node_key,
                authority,
            )?;
            drop(hosted);
            fs::rename(&source, &destination).map_err(map_io)?;
            sync_directory(&creating)?;
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn reset_artifact_read_spy(&self, agent: AgentId) {
        self.agents[&agent].store.reset_artifact_read_spy();
    }

    #[cfg(test)]
    fn artifact_read_spy(&self, agent: AgentId) -> u64 {
        self.agents[&agent].store.artifact_read_spy()
    }
}

fn validate_create_request(
    scope: &RootScope,
    node_key: &PrivateNodeDecryptionKey,
    request: &PrivateAgentCreate<'_>,
) -> Result<(), PrivateAgentHostError> {
    let descriptor = request.descriptor;
    descriptor
        .validate()
        .map_err(|_| PrivateAgentHostError::InvalidDescriptor)?;
    if descriptor.identity.profile != AgentProfile::Private
        || descriptor.identity.space != scope.space
        || descriptor.identity.owner != scope.owner
        || descriptor.runtime_package != *request.runtime_package.package_ref()
        || descriptor.identity.runtime_deployment != request.runtime_package.deployment()
        || descriptor.identity.runtime_program != request.runtime_package.program()
        || descriptor.identity.runtime_producer != request.runtime_package.producer()
        || descriptor.runtime_contract != request.runtime_package.manifest().contract
        || descriptor.capabilities != request.runtime_package.capabilities()
        || request.runtime_package.exact_bytes().len()
            > MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(256)
        || request.bootstrap_metadata.len() > MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES
        || scope.local_node.encryption_public_key != node_key.public_key()
        || descriptor.replicas.len() != request.nodes.len()
    {
        return Err(PrivateAgentHostError::InvalidDescriptor);
    }
    if request.nodes.is_empty()
        || request
            .nodes
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
    {
        return Err(PrivateAgentHostError::InvalidMembership);
    }
    for (replica, node) in descriptor.replicas.iter().zip(request.nodes) {
        if replica.node != node.node
            || replica.principal != node.principal
            || replica.principal != scope.owner
            || replica.role != ReplicaRole::Observer
        {
            return Err(PrivateAgentHostError::InvalidMembership);
        }
    }
    require_exact_local_member(request.nodes, &scope.local_node)
}

fn require_exact_local_member(
    nodes: &[PrivateNodeIdentity],
    local: &PrivateNodeIdentity,
) -> Result<(), PrivateAgentHostError> {
    let position = nodes
        .binary_search_by_key(&local.node, |entry| entry.node)
        .map_err(|_| PrivateAgentHostError::Unauthorized)?;
    if nodes.get(position) != Some(local) {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    Ok(())
}

fn unsigned_owner_record(
    hosted: &HostedPrivateAgent,
    operation: PrivateControlOperation,
) -> PrivateControlRecord {
    let binding = hosted.store.binding();
    PrivateControlRecord {
        space: binding.space,
        agent: binding.agent,
        sequence: binding.next_sequence,
        previous: binding.control_head,
        operation,
        signer: PrivateControlSigner::Owner,
        signer_public_key: [0; 32],
        signature: [0; 64],
    }
}

fn append_owner_record<V: PrivateNodeAuthorityVerifier>(
    hosted: &mut HostedPrivateAgent,
    operation: PrivateControlOperation,
    authority: &V,
) -> Result<PutDisposition, PrivateAgentHostError> {
    let mut record = unsigned_owner_record(hosted, operation);
    sign_owner_control_record(&mut record, &hosted.owner_key)?;
    Ok(hosted.store.append_control(&record, authority)?)
}

#[allow(clippy::too_many_arguments)]
fn rotate_with_operation<V, F>(
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
    owner: PrincipalId,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    nodes: &[PrivateNodeIdentity],
    operation: F,
    authority: &V,
) -> Result<PutDisposition, PrivateAgentHostError>
where
    V: PrivateNodeAuthorityVerifier,
    F: FnOnce(PrivateKeyEpoch) -> PrivateControlOperation,
{
    require_exact_local_member(nodes, local_node)?;
    let binding = hosted.store.binding();
    let next_epoch = binding
        .epoch
        .checked_add(1)
        .ok_or(PrivateAgentHostError::LimitExceeded)?;
    let GeneratedPrivateEpoch {
        record,
        owner_key,
        data_key,
    } = generate_fresh_private_epoch(
        binding.space,
        binding.agent,
        next_epoch,
        owner,
        nodes,
        hosted.store.recovery_public_key(),
        hosted.store.recovery_encryption_public_key(),
        authority,
    )?;
    // Independently prove the newly sealed generation can be recovered by
    // this exact host identity before it is allowed to advance durable state.
    let checked_owner = unwrap_owner_key(&record, local_node, node_key)?;
    let checked_data = unwrap_data_key(&record, local_node, node_key)?;
    if checked_owner.verifying_key() != owner_key.verifying_key()
        || checked_data.commitment() != data_key.commitment()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    stage_metadata(slot, next_epoch, &data_key, hosted)?;
    let mut control = unsigned_owner_record(hosted, operation(record));
    sign_owner_control_record(&mut control, &hosted.owner_key)?;
    let disposition = match hosted.store.append_control(&control, authority) {
        Ok(disposition) => disposition,
        Err(error) => {
            discard_next_sidecars(slot, next_epoch);
            return Err(error.into());
        }
    };
    hosted.owner_key = owner_key;
    hosted.data_keys.insert(next_epoch, data_key);
    promote_next_sidecars(slot, next_epoch)?;
    Ok(disposition)
}

fn authenticate_peer_identity<'a, T: PrivateTransportAuthVerifier>(
    hosted: &HostedPrivateAgent,
    peer: PrivatePeerIdentity<'a>,
    transport: &T,
) -> Result<&'a PrivateNodeIdentity, PrivateAgentHostError> {
    let PrivatePeerIdentity::Node(peer) = peer else {
        return Err(PrivateAgentHostError::Unauthorized);
    };
    let binding = hosted.store.binding();
    if !peer.validate() || peer.principal != binding.owner {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    let position = hosted
        .store
        .authorized_nodes()
        .binary_search_by_key(&peer.node, |entry| entry.node)
        .map_err(|_| PrivateAgentHostError::Unauthorized)?;
    if hosted.store.authorized_nodes().get(position) != Some(peer)
        || !transport.verify_authenticated_private_node(
            binding.space,
            binding.agent,
            binding.owner,
            peer,
        )
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    Ok(peer)
}

struct CandidateEpochKeys {
    epoch: u64,
    owner: OwnerSigningKey,
    data: PrivateDataKey,
    historical: Option<BTreeMap<u64, PrivateDataKey>>,
}

fn validated_candidate_keys_from_page<V: PrivateNodeAuthorityVerifier>(
    store: &PrivateStore,
    page: &PrivateSyncPage,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    authority: &V,
) -> Result<Vec<CandidateEpochKeys>, PrivateAgentHostError> {
    if page.phase != PrivateSyncPhase::Controls {
        return Ok(Vec::new());
    }
    let binding = store.binding();
    if page.request.cursor.space != binding.space || page.request.cursor.agent != binding.agent {
        return Err(PrivateAgentHostError::Sync(PrivateSyncError::InvalidScope));
    }
    let mut records = Vec::new();
    records
        .try_reserve(page.items.len())
        .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
    for item in &page.items {
        let super::private_sync::PrivateSyncItem::Control {
            sequence,
            commitment,
            resulting_epoch,
            wire,
        } = item
        else {
            return Err(PrivateAgentHostError::Sync(PrivateSyncError::InvalidFrame));
        };
        let record = PrivateControlRecord::decode(wire)
            .map_err(|_| PrivateAgentHostError::Sync(PrivateSyncError::Tampered))?;
        let transition_epoch = match &record.operation {
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch }
            | PrivateControlOperation::Recover { next_epoch, .. } => Some(next_epoch.epoch),
            _ => None,
        };
        if record.space != page.request.cursor.space
            || record.agent != page.request.cursor.agent
            || record.sequence != *sequence
            || record.commitment() != *commitment
            || transition_epoch.is_some_and(|epoch| epoch != *resulting_epoch)
        {
            return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
        }
        records.push(record);
    }

    // A retried page may contain a prefix already applied by this store. The
    // prefix must be byte-identical; only the remaining suffix is reverified
    // and considered for staging.
    let expected_start = page.request.cursor.local;
    let mut skip = 0usize;
    if binding.epoch != expected_start.epoch || binding.control_head != expected_start.control_head
    {
        let Some(position) = page.items.iter().position(|item| {
            matches!(
                item,
                super::private_sync::PrivateSyncItem::Control {
                    commitment,
                    resulting_epoch,
                    ..
                } if binding.control_head == Some(*commitment)
                    && binding.epoch == *resulting_epoch
            )
        }) else {
            return Err(PrivateAgentHostError::Sync(PrivateSyncError::Diverged));
        };
        skip = position
            .checked_add(1)
            .ok_or(PrivateAgentHostError::LimitExceeded)?;
        for item in &page.items[..skip] {
            let super::private_sync::PrivateSyncItem::Control {
                commitment, wire, ..
            } = item
            else {
                return Err(PrivateAgentHostError::Sync(PrivateSyncError::InvalidFrame));
            };
            if !store.control_is_exact(*commitment, wire)? {
                return Err(PrivateAgentHostError::Sync(PrivateSyncError::Diverged));
            }
        }
    }
    if skip == records.len() {
        return Ok(Vec::new());
    }
    let expected_epochs = store.prevalidate_controls(&records[skip..], authority)?;
    for (expected, item) in expected_epochs.iter().zip(&page.items[skip..]) {
        let super::private_sync::PrivateSyncItem::Control {
            resulting_epoch, ..
        } = item
        else {
            return Err(PrivateAgentHostError::Sync(PrivateSyncError::InvalidFrame));
        };
        if expected != resulting_epoch {
            return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
        }
    }

    let mut candidates = Vec::new();
    let mut authenticated_epochs = store.key_epochs().to_vec();
    for record in &records[skip..] {
        let (epoch, historical) = match &record.operation {
            PrivateControlOperation::Revoke { next_epoch, .. }
            | PrivateControlOperation::RotateKeys { next_epoch } => (Some(next_epoch), None),
            PrivateControlOperation::Recover {
                next_epoch,
                historical_keyring,
                ..
            } => (
                Some(next_epoch),
                Some(unwrap_recovery_keyring(
                    historical_keyring,
                    &authenticated_epochs,
                    local_node,
                    node_key,
                )?),
            ),
            _ => (None, None),
        };
        if let Some(epoch) = epoch {
            if epoch.epoch <= binding.epoch {
                return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
            }
            if candidates
                .last()
                .is_some_and(|candidate: &CandidateEpochKeys| candidate.epoch >= epoch.epoch)
            {
                return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
            }
            candidates.push(CandidateEpochKeys {
                epoch: epoch.epoch,
                owner: unwrap_owner_key(epoch, local_node, node_key)?,
                data: unwrap_data_key(epoch, local_node, node_key)?,
                historical,
            });
            authenticated_epochs.push(epoch.clone());
        }
    }
    Ok(candidates)
}

fn reconcile_staged_sync_keys(
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
    starting_epoch: u64,
    candidates: Vec<CandidateEpochKeys>,
    retain_unobserved: bool,
) -> Result<(), PrivateAgentHostError> {
    let committed_epoch = hosted.store.binding().epoch;
    if committed_epoch == starting_epoch {
        return discard_all_next_sidecars(slot);
    }
    let mut committed_owner = None;
    let mut has_committed_generation = false;
    for candidate in candidates {
        if candidate.epoch > committed_epoch {
            continue;
        }
        if candidate.epoch == committed_epoch {
            has_committed_generation = true;
            committed_owner = Some(candidate.owner);
        }
        if let Some(historical) = candidate.historical {
            for (epoch, key) in historical {
                if let Some(existing) = hosted.data_keys.get(&epoch) {
                    if existing.commitment() != key.commitment() {
                        return Err(PrivateAgentHostError::Corrupt);
                    }
                } else {
                    hosted.data_keys.insert(epoch, key);
                }
            }
        }
        if hosted.data_keys.contains_key(&candidate.epoch) {
            return Err(PrivateAgentHostError::Alias);
        }
        hosted.data_keys.insert(candidate.epoch, candidate.data);
    }
    if !has_committed_generation {
        return Err(PrivateAgentHostError::Corrupt);
    }
    hosted.owner_key = committed_owner.ok_or(PrivateAgentHostError::Corrupt)?;
    promote_next_sidecars(slot, committed_epoch)?;
    if retain_unobserved {
        // A later candidate can already be the durable disk generation even
        // when the corresponding in-memory assignment was interrupted. Keep
        // it for restart reconciliation; the exact authenticated store epoch
        // will retire every unreachable generation on open.
        Ok(())
    } else {
        discard_all_next_sidecars(slot)
    }
}

fn encode_root_scope(scope: &RootScope) -> Result<Vec<u8>, PrivateAgentHostError> {
    let node = scope
        .local_node
        .encode()
        .map_err(|_| PrivateAgentHostError::InvalidScope)?;
    let mut bytes = Vec::with_capacity(node.len() + 104);
    bytes.extend_from_slice(ROOT_SCOPE_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(scope.space.as_bytes());
    encoder.fixed(scope.owner.as_bytes());
    encoder.bytes(&node);
    Ok(bytes)
}

fn decode_root_scope(bytes: &[u8]) -> Result<RootScope, PrivateAgentHostError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4).map_err(map_decode)? != ROOT_SCOPE_MAGIC
        || decoder.u16().map_err(map_decode)? != FORMAT_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let space = SpaceId(decoder.fixed().map_err(map_decode)?);
    let owner = PrincipalId(decoder.fixed().map_err(map_decode)?);
    let node_bytes = decoder
        .bytes_ref_bounded(MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES)
        .map_err(map_decode)?;
    if !decoder.exhausted() {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let local_node =
        PrivateNodeIdentity::decode(node_bytes).map_err(|_| PrivateAgentHostError::Corrupt)?;
    let scope = RootScope {
        space,
        owner,
        local_node,
    };
    if scope.space == SpaceId::ZERO
        || scope.owner == PrincipalId::ZERO
        || scope.local_node.principal != scope.owner
        || !scope.local_node.validate()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(scope)
}

fn encode_descriptor_metadata(
    epoch: u64,
    descriptor: &AgentDescriptor,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    descriptor
        .validate()
        .map_err(|_| PrivateAgentHostError::InvalidDescriptor)?;
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(DESCRIPTOR_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.u64(epoch);
    encode_agent_descriptor(&mut encoder, descriptor);
    Ok(bytes)
}

fn decode_descriptor_metadata(
    bytes: &[u8],
    expected_epoch: u64,
) -> Result<AgentDescriptor, PrivateAgentHostError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4).map_err(map_decode)? != DESCRIPTOR_MAGIC
        || decoder.u16().map_err(map_decode)? != FORMAT_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
        || decoder.u64().map_err(map_decode)? != expected_epoch
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let descriptor = decode_agent_descriptor(&mut decoder).map_err(map_decode)?;
    if !decoder.exhausted() || descriptor.validate().is_err() {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(descriptor)
}

fn encode_agent_descriptor(encoder: &mut Encoder<'_>, value: &AgentDescriptor) {
    let identity = &value.identity;
    encoder.fixed(identity.space.as_bytes());
    encoder.fixed(identity.agent.as_bytes());
    encoder.fixed(identity.owner.as_bytes());
    encoder.u8(identity.profile as u8);
    encoder.fixed(identity.runtime_deployment.as_bytes());
    encoder.fixed(identity.runtime_program.as_bytes());
    encoder.fixed(identity.runtime_producer.as_bytes());
    encoder.fixed(value.creation_nonce.as_bytes());
    encode_authority_binding(encoder, value.authority);
    encode_blob_ref(encoder, &value.runtime_package);
    encode_runtime_contract(encoder, value.runtime_contract);
    encode_runtime_capabilities(encoder, value.capabilities);
    encoder.list(&value.replicas, |encoder, replica| {
        encoder.fixed(replica.node.as_bytes());
        encoder.fixed(replica.principal.as_bytes());
        encoder.u8(replica.role as u8);
    });
}

fn decode_agent_descriptor(decoder: &mut Decoder<'_>) -> Result<AgentDescriptor, DecodeError> {
    let identity = AgentIdentity {
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
        runtime_program: ProgramId(decoder.fixed()?),
        runtime_producer: ProducerId(decoder.fixed()?),
    };
    let creation_nonce = Hash(decoder.fixed()?);
    let authority = decode_authority_binding(decoder)?;
    let runtime_package = decode_blob_ref(decoder)?;
    let runtime_contract = decode_runtime_contract(decoder)?;
    let capabilities = decode_runtime_capabilities(decoder)?;
    let replicas = decoder.list_bounded(vos_agent_sdk::MAX_AGENT_REPLICAS, |decoder| {
        Ok(AgentReplica {
            node: NodeId(decoder.fixed()?),
            principal: PrincipalId(decoder.fixed()?),
            role: match decoder.u8()? {
                0 => ReplicaRole::Voter,
                1 => ReplicaRole::Observer,
                _ => return Err(DecodeError::InvalidTag),
            },
        })
    })?;
    let descriptor = AgentDescriptor {
        identity,
        creation_nonce,
        authority,
        runtime_package,
        runtime_contract,
        capabilities,
        replicas,
    };
    descriptor
        .validate()
        .map_err(|_| DecodeError::NonCanonical)?;
    Ok(descriptor)
}

fn encode_authority_binding(encoder: &mut Encoder<'_>, value: AgentAuthorityBinding) {
    encoder.fixed(value.policy.as_bytes());
    encoder.fixed(value.issuer.principal.as_bytes());
    encoder.fixed(value.issuer.actor.as_bytes());
    encoder.fixed(value.issuer.deployment.as_bytes());
    encoder.fixed(value.issuer.program.as_bytes());
    encoder.fixed(value.issuer.producer.as_bytes());
    encoder.fixed(&value.public_key);
    encoder.u64(value.initial_epoch);
}

fn decode_authority_binding(
    decoder: &mut Decoder<'_>,
) -> Result<AgentAuthorityBinding, DecodeError> {
    let value = AgentAuthorityBinding {
        policy: Hash(decoder.fixed()?),
        issuer: AuthorityIssuer {
            principal: PrincipalId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            deployment: DeploymentId(decoder.fixed()?),
            program: ProgramId(decoder.fixed()?),
            producer: ProducerId(decoder.fixed()?),
        },
        public_key: decoder.fixed()?,
        initial_epoch: decoder.u64()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_runtime_contract(encoder: &mut Encoder<'_>, value: RuntimePackageContract) {
    encoder.fixed(value.lifecycle_abi.as_bytes());
    encoder.u32(value.actor_abis.minimum);
    encoder.u32(value.actor_abis.maximum);
    encoder.fixed(value.control_schema.as_bytes());
    encoder.u32(value.resources.max_runtime_state_bytes);
    encoder.u32(value.resources.max_artifact_references);
    encoder.u64(value.resources.max_artifact_referenced_bytes);
    encoder.u8(value.migration as u8);
}

fn decode_runtime_contract(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimePackageContract, DecodeError> {
    let value = RuntimePackageContract {
        lifecycle_abi: Hash(decoder.fixed()?),
        actor_abis: ActorAbiRange {
            minimum: decoder.u32()?,
            maximum: decoder.u32()?,
        },
        control_schema: Hash(decoder.fixed()?),
        resources: RuntimeResourceLimits {
            max_runtime_state_bytes: decoder.u32()?,
            max_artifact_references: decoder.u32()?,
            max_artifact_referenced_bytes: decoder.u64()?,
        },
        migration: match decoder.u8()? {
            0 => RuntimeMigrationPolicy::None,
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_capabilities(encoder: &mut Encoder<'_>, value: RuntimeCapabilities) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    encoder.list(value.proof_systems.as_slice(), |encoder, system| {
        encoder.fixed(system.as_bytes())
    });
    encoder.u32(value.max_actors);
}

fn decode_runtime_capabilities(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimeCapabilities, DecodeError> {
    let lanes = LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?;
    let scheduling = decoder.bool()?;
    let systems = decoder
        .list_bounded(vos_agent_sdk::proof_system::MAX_PROOF_SYSTEMS, |decoder| {
            Ok(Hash(decoder.fixed()?))
        })?;
    let proof_systems =
        ProofSystemSet::from_sorted(&systems).map_err(|_| DecodeError::NonCanonical)?;
    let value = RuntimeCapabilities {
        lanes,
        scheduling,
        proof_systems,
        max_actors: decoder.u32()?,
    };
    value.validate().map_err(|_| DecodeError::NonCanonical)?;
    Ok(value)
}

fn encode_bytes_metadata(
    magic: &[u8; 4],
    epoch: u64,
    bytes_value: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    if bytes_value.len() > maximum {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let mut bytes = Vec::with_capacity(bytes_value.len() + 64);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.u64(epoch);
    encoder.bytes(bytes_value);
    Ok(bytes)
}

fn decode_bytes_metadata(
    bytes: &[u8],
    magic: &[u8; 4],
    expected_epoch: u64,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, PrivateAgentHostError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4).map_err(map_decode)? != magic
        || decoder.u16().map_err(map_decode)? != FORMAT_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
        || decoder.u64().map_err(map_decode)? != expected_epoch
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let value = decoder.bytes_bounded(maximum).map_err(map_decode)?;
    if !decoder.exhausted() {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(Zeroizing::new(value))
}

struct SidecarSet {
    descriptor: Vec<u8>,
    runtime: Vec<u8>,
    bootstrap: Vec<u8>,
}

fn encrypt_sidecars(
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    data_key: &PrivateDataKey,
    plaintext: &AgentPlaintext,
) -> Result<SidecarSet, PrivateAgentHostError> {
    let descriptor = Zeroizing::new(encode_descriptor_metadata(epoch, &plaintext.descriptor)?);
    let runtime = Zeroizing::new(encode_bytes_metadata(
        RUNTIME_MAGIC,
        epoch,
        &plaintext.runtime_package,
        MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(16),
    )?);
    let bootstrap = Zeroizing::new(encode_bytes_metadata(
        BOOTSTRAP_MAGIC,
        epoch,
        &plaintext.bootstrap_metadata,
        MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES,
    )?);
    let descriptor = encrypt_private_object(
        data_key,
        space,
        agent,
        epoch,
        EncryptedObjectKind::Index,
        &descriptor,
    )?
    .encode()
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let runtime = encrypt_private_object(
        data_key,
        space,
        agent,
        epoch,
        EncryptedObjectKind::Package,
        &runtime,
    )?
    .encode()
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let bootstrap = encrypt_private_object(
        data_key,
        space,
        agent,
        epoch,
        EncryptedObjectKind::Blob,
        &bootstrap,
    )?
    .encode()
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(SidecarSet {
        descriptor,
        runtime,
        bootstrap,
    })
}

fn write_initial_sidecars(
    slot: &Path,
    epoch: u64,
    data_key: &PrivateDataKey,
    plaintext: &AgentPlaintext,
) -> Result<(), PrivateAgentHostError> {
    let identity = &plaintext.descriptor.identity;
    let sidecars = encrypt_sidecars(identity.space, identity.agent, epoch, data_key, plaintext)?;
    write_new_synced(&slot.join(DESCRIPTOR_FILE), &sidecars.descriptor)?;
    write_new_synced(&slot.join(RUNTIME_FILE), &sidecars.runtime)?;
    write_new_synced(&slot.join(BOOTSTRAP_FILE), &sidecars.bootstrap)?;
    sync_directory(slot)
}

fn stage_metadata(
    slot: &Path,
    epoch: u64,
    data_key: &PrivateDataKey,
    hosted: &HostedPrivateAgent,
) -> Result<(), PrivateAgentHostError> {
    let plaintext = AgentPlaintext {
        descriptor: hosted.descriptor.clone(),
        runtime_package: Zeroizing::new(hosted.runtime_package.to_vec()),
        bootstrap_metadata: Zeroizing::new(hosted.bootstrap_metadata.to_vec()),
    };
    let identity = &plaintext.descriptor.identity;
    let sidecars = encrypt_sidecars(identity.space, identity.agent, epoch, data_key, &plaintext)?;
    replace_staged_file(slot, DESCRIPTOR_FILE, epoch, &sidecars.descriptor)?;
    replace_staged_file(slot, RUNTIME_FILE, epoch, &sidecars.runtime)?;
    replace_staged_file(slot, BOOTSTRAP_FILE, epoch, &sidecars.bootstrap)?;
    sync_directory(slot)
}

fn replace_staged_file(
    slot: &Path,
    canonical: &str,
    epoch: u64,
    bytes: &[u8],
) -> Result<(), PrivateAgentHostError> {
    let next = slot.join(staged_sidecar_name(canonical, epoch));
    remove_regular_file_if_present(&next)?;
    write_new_synced(&next, bytes)
}

fn promote_next_sidecars(slot: &Path, epoch: u64) -> Result<(), PrivateAgentHostError> {
    for canonical in SIDECAR_FILES {
        let next = slot.join(staged_sidecar_name(canonical, epoch));
        require_regular_file(&next)?;
        fs::rename(&next, slot.join(canonical)).map_err(map_io)?;
        sync_directory(slot)?;
    }
    Ok(())
}

fn discard_next_sidecars(slot: &Path, epoch: u64) {
    for canonical in SIDECAR_FILES {
        let _ = remove_regular_file_if_present(&slot.join(staged_sidecar_name(canonical, epoch)));
    }
    let _ = sync_directory(slot);
}

fn discard_all_next_sidecars(slot: &Path) -> Result<(), PrivateAgentHostError> {
    for entry in fs::read_dir(slot).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateAgentHostError::InvalidRoot)?;
        if SIDECAR_FILES
            .iter()
            .any(|canonical| staged_sidecar_epoch(&name, canonical).is_some())
        {
            remove_regular_file_if_present(&entry.path())?;
        }
    }
    sync_directory(slot)
}

fn staged_sidecar_name(canonical: &str, epoch: u64) -> String {
    format!("{canonical}{NEXT_PREFIX}{epoch:016x}")
}

fn staged_sidecar_epoch(name: &str, canonical: &str) -> Option<u64> {
    let encoded = name.strip_prefix(&format!("{canonical}{NEXT_PREFIX}"))?;
    if encoded.len() != 16
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u64::from_str_radix(encoded, 16).ok()
}

fn open_hosted_agent<V: PrivateNodeAuthorityVerifier>(
    slot: &Path,
    expected_space: SpaceId,
    expected_owner: PrincipalId,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    authority: &V,
) -> Result<HostedPrivateAgent, PrivateAgentHostError> {
    validate_slot_layout(slot)?;
    let name = slot
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(PrivateAgentHostError::InvalidRoot)?;
    let agent = decode_agent_id(name).ok_or(PrivateAgentHostError::InvalidRoot)?;
    let store = PrivateStore::open(slot.join(STORE_DIRECTORY), expected_space, agent, authority)?;
    let binding = store.binding();
    if binding.owner != expected_owner {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    require_exact_local_member(store.authorized_nodes(), local_node)?;
    let owner_key = unwrap_owner_key(store.key_epoch(), local_node, node_key)?;
    let data_keys = unwrap_local_data_keyring(&store, local_node, node_key)?;
    let data_key = data_keys
        .get(&store.binding().epoch)
        .ok_or(PrivateAgentHostError::Unauthorized)?;
    let plaintext = reconcile_and_open_sidecars(slot, &store, &data_key)?;
    if plaintext.descriptor.identity.space != expected_space
        || plaintext.descriptor.identity.agent != agent
        || plaintext.descriptor.identity.owner != expected_owner
        || plaintext.descriptor.identity.profile != AgentProfile::Private
        || !plaintext
            .descriptor
            .runtime_package
            .matches(&plaintext.runtime_package)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let admitted = admit_runtime_package(&plaintext.runtime_package)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    if plaintext.descriptor.runtime_package != *admitted.package_ref()
        || plaintext.descriptor.identity.runtime_deployment != admitted.deployment()
        || plaintext.descriptor.identity.runtime_program != admitted.program()
        || plaintext.descriptor.identity.runtime_producer != admitted.producer()
        || plaintext.descriptor.runtime_contract != admitted.manifest().contract
        || plaintext.descriptor.capabilities != admitted.capabilities()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(HostedPrivateAgent {
        store,
        descriptor: plaintext.descriptor,
        runtime_package: plaintext.runtime_package,
        bootstrap_metadata: plaintext.bootstrap_metadata,
        owner_key,
        data_keys,
    })
}

fn unwrap_local_data_keyring(
    store: &PrivateStore,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<BTreeMap<u64, PrivateDataKey>, PrivateAgentHostError> {
    // History is available only where the authenticated epoch actually
    // contains a seal for this exact node recipient. A later Invite or
    // replacement Recovery deliberately does not synthesize access to epochs
    // that predate that identity's authorization.
    let mut data_keys = BTreeMap::new();
    for epoch in store.key_epochs() {
        let Some(sealed) = epoch
            .sealed_data_keys
            .iter()
            .find(|sealed| sealed.node == local_node.node)
        else {
            continue;
        };
        // A later authority binding may legitimately reuse a NodeId with a
        // different encryption recipient. It must not make an old seal usable
        // by the new identity.
        if sealed.recipient_key != local_node.encryption_public_key {
            continue;
        }
        let data_key = unwrap_data_key(epoch, local_node, node_key)?;
        if data_keys.insert(epoch.epoch, data_key).is_some() {
            return Err(PrivateAgentHostError::Corrupt);
        }
    }
    if let Some(grant) = store.latest_recovery_keyring() {
        let successor_position = store
            .key_epochs()
            .binary_search_by_key(&grant.ciphertext.epoch, |epoch| epoch.epoch)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let has_exact_seal = grant.sealed_keys.iter().any(|sealed| {
            sealed.node == local_node.node
                && sealed.recipient_key == local_node.encryption_public_key
        });
        if has_exact_seal {
            let historical = unwrap_recovery_keyring(
                grant,
                &store.key_epochs()[..successor_position],
                local_node,
                node_key,
            )?;
            for (epoch, key) in historical {
                if let Some(existing) = data_keys.get(&epoch) {
                    if existing.commitment() != key.commitment() {
                        return Err(PrivateAgentHostError::Corrupt);
                    }
                } else {
                    data_keys.insert(epoch, key);
                }
            }
        }
    }
    if data_keys.len() > store.control_count().saturating_add(1) {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(data_keys)
}

fn reconcile_and_open_sidecars(
    slot: &Path,
    store: &PrivateStore,
    data_key: &PrivateDataKey,
) -> Result<AgentPlaintext, PrivateAgentHostError> {
    let binding = store.binding();
    let descriptor_bytes = select_sidecar_generation(
        slot,
        DESCRIPTOR_FILE,
        binding.space,
        binding.agent,
        binding.epoch,
        EncryptedObjectKind::Index,
        data_key,
    )?;
    let runtime_bytes = select_sidecar_generation(
        slot,
        RUNTIME_FILE,
        binding.space,
        binding.agent,
        binding.epoch,
        EncryptedObjectKind::Package,
        data_key,
    )?;
    let bootstrap_bytes = select_sidecar_generation(
        slot,
        BOOTSTRAP_FILE,
        binding.space,
        binding.agent,
        binding.epoch,
        EncryptedObjectKind::Blob,
        data_key,
    )?;
    let descriptor = decode_descriptor_metadata(&descriptor_bytes, binding.epoch)?;
    let runtime_package = decode_bytes_metadata(
        &runtime_bytes,
        RUNTIME_MAGIC,
        binding.epoch,
        MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(16),
    )?;
    let bootstrap_metadata = decode_bytes_metadata(
        &bootstrap_bytes,
        BOOTSTRAP_MAGIC,
        binding.epoch,
        MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES,
    )?;
    // Any other pre-staged generation belongs to an uncommitted suffix of a
    // sync page. Once all three sidecars for the authenticated store epoch are
    // selected, those generations are unreachable and may be retired.
    discard_all_next_sidecars(slot)?;
    Ok(AgentPlaintext {
        descriptor,
        runtime_package,
        bootstrap_metadata,
    })
}

#[allow(clippy::too_many_arguments)]
fn select_sidecar_generation(
    slot: &Path,
    canonical: &str,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EncryptedObjectKind,
    data_key: &PrivateDataKey,
) -> Result<Zeroizing<Vec<u8>>, PrivateAgentHostError> {
    let current_path = slot.join(canonical);
    let next_path = slot.join(staged_sidecar_name(canonical, epoch));
    let current = read_and_decrypt_sidecar(&current_path, space, agent, epoch, kind, data_key);
    let next = match fs::symlink_metadata(&next_path) {
        Ok(_) => Some(read_and_decrypt_sidecar(
            &next_path, space, agent, epoch, kind, data_key,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(PrivateAgentHostError::Io),
    };
    match (current, next) {
        (Ok(current), None) => Ok(current),
        (Ok(current), Some(Ok(next))) => {
            if current.as_slice() != next.as_slice() {
                return Err(PrivateAgentHostError::Alias);
            }
            remove_regular_file_if_present(&next_path)?;
            sync_directory(slot)?;
            Ok(current)
        }
        (Ok(current), Some(Err(_))) => {
            // A complete control transition was not committed; the staged
            // next-key ciphertext is unreachable from the authenticated head.
            remove_regular_file_if_present(&next_path)?;
            sync_directory(slot)?;
            Ok(current)
        }
        (Err(_), Some(Ok(next))) => {
            fs::rename(&next_path, &current_path).map_err(map_io)?;
            sync_directory(slot)?;
            Ok(next)
        }
        (Err(_), None) | (Err(_), Some(Err(_))) => Err(PrivateAgentHostError::Corrupt),
    }
}

fn read_and_decrypt_sidecar(
    path: &Path,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EncryptedObjectKind,
    data_key: &PrivateDataKey,
) -> Result<Zeroizing<Vec<u8>>, PrivateAgentHostError> {
    require_regular_file(path)?;
    let bytes = read_bounded_file(path, MAX_PRIVATE_OBJECT_WIRE_BYTES)?;
    let object =
        EncryptedPrivateObject::decode(&bytes).map_err(|_| PrivateAgentHostError::Corrupt)?;
    if object.space != space
        || object.agent != agent
        || object.epoch != epoch
        || object.kind != kind
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(Zeroizing::new(decrypt_private_object(data_key, &object)?))
}

fn validate_slot_layout(slot: &Path) -> Result<(), PrivateAgentHostError> {
    require_real_directory(slot)?;
    let allow_recovery_plan = slot
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        == Some(CREATING_DIRECTORY);
    // A process may stop between writing and renaming one known temporary
    // file. It was never published and is safe to retire on restart.
    for canonical in SIDECAR_FILES {
        remove_regular_file_if_present(&slot.join(format!("{canonical}{WRITE_SUFFIX}")))?;
    }
    let mut seen_store = false;
    let mut seen = BTreeMap::new();
    for entry in fs::read_dir(slot).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateAgentHostError::InvalidRoot)?;
        let file_type = entry.file_type().map_err(map_io)?;
        if name == STORE_DIRECTORY {
            if file_type.is_symlink() || !file_type.is_dir() || seen_store {
                return Err(PrivateAgentHostError::Alias);
            }
            seen_store = true;
            continue;
        }
        if name == RECOVERY_PLAN_FILE && allow_recovery_plan {
            if file_type.is_symlink() || !file_type.is_file() || seen.insert(name, ()).is_some() {
                return Err(PrivateAgentHostError::Alias);
            }
            continue;
        }
        let canonical = SIDECAR_FILES.iter().find(|canonical| {
            name == **canonical || staged_sidecar_epoch(&name, canonical).is_some()
        });
        let Some(_) = canonical else {
            return Err(PrivateAgentHostError::Corrupt);
        };
        if file_type.is_symlink() || !file_type.is_file() || seen.insert(name, ()).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
    }
    if !seen_store || SIDECAR_FILES.iter().any(|name| !seen.contains_key(*name)) {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
}

fn scan_root(root: &Path) -> Result<Vec<AgentId>, PrivateAgentHostError> {
    let mut agents = Vec::new();
    for entry in fs::read_dir(root).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateAgentHostError::InvalidRoot)?;
        let file_type = entry.file_type().map_err(map_io)?;
        match name.as_str() {
            ROOT_SCOPE_FILE | ROOT_LOCK_FILE => {
                if file_type.is_symlink() || !file_type.is_file() {
                    return Err(PrivateAgentHostError::InvalidRoot);
                }
            }
            CREATING_DIRECTORY => {
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(PrivateAgentHostError::InvalidRoot);
                }
            }
            _ => {
                let agent = decode_agent_id(&name).ok_or(PrivateAgentHostError::InvalidRoot)?;
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(PrivateAgentHostError::InvalidRoot);
                }
                agents.push(agent);
            }
        }
    }
    agents.sort_unstable();
    if agents.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PrivateAgentHostError::Alias);
    }
    Ok(agents)
}

fn scan_agent_directories(root: &Path) -> Result<Vec<AgentId>, PrivateAgentHostError> {
    let mut agents = Vec::new();
    for entry in fs::read_dir(root).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateAgentHostError::InvalidRoot)?;
        let agent = decode_agent_id(&name).ok_or(PrivateAgentHostError::InvalidRoot)?;
        let file_type = entry.file_type().map_err(map_io)?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(PrivateAgentHostError::InvalidRoot);
        }
        agents.push(agent);
    }
    Ok(agents)
}

fn encode_agent_id(agent: AgentId) -> String {
    let mut output = String::with_capacity(64);
    for byte in agent.as_bytes() {
        use core::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_agent_id(name: &str) -> Option<AgentId> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, pair) in name.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_digit(pair[0])?;
        let low = decode_hex_digit(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    let agent = AgentId(bytes);
    (agent != AgentId::ZERO && encode_agent_id(agent) == name).then_some(agent)
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn open_root_lock(root: &Path) -> Result<File, PrivateAgentHostError> {
    let path = root.join(ROOT_LOCK_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(PrivateAgentHostError::InvalidRoot);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(map_io)?;
    file.try_lock_exclusive()
        .map_err(|_| PrivateAgentHostError::Busy)?;
    Ok(file)
}

fn require_real_directory(path: &Path) -> Result<(), PrivateAgentHostError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PrivateAgentHostError::InvalidRoot);
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), PrivateAgentHostError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PrivateAgentHostError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(PrivateAgentHostError::Alias);
        }
    }
    Ok(())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), PrivateAgentHostError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(map_io)?;
    file.write_all(bytes).map_err(map_io)?;
    file.sync_all().map_err(map_io)
}

fn write_exact_or_new_synced(path: &Path, bytes: &[u8]) -> Result<(), PrivateAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(PrivateAgentHostError::Corrupt);
            }
            if read_bounded_file(path, bytes.len())? != bytes {
                return Err(PrivateAgentHostError::Alias);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => write_new_synced(path, bytes),
        Err(_) => Err(PrivateAgentHostError::Io),
    }
}

fn remove_regular_file_if_present(path: &Path) -> Result<(), PrivateAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(PrivateAgentHostError::Corrupt);
            }
            fs::remove_file(path).map_err(map_io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrivateAgentHostError::Io),
    }
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, PrivateAgentHostError> {
    require_regular_file(path)?;
    let metadata = fs::metadata(path).map_err(map_io)?;
    if metadata.len() > maximum as u64 {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let file = File::open(path).map_err(map_io)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(metadata.len() as usize)
        .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() > maximum {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), PrivateAgentHostError> {
    File::open(path).map_err(map_io)?.sync_all().map_err(map_io)
}

fn map_io(error: std::io::Error) -> PrivateAgentHostError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => PrivateAgentHostError::AlreadyExists,
        std::io::ErrorKind::NotFound => PrivateAgentHostError::NotFound,
        _ => PrivateAgentHostError::Io,
    }
}

fn map_decode(_: DecodeError) -> PrivateAgentHostError {
    PrivateAgentHostError::Corrupt
}

struct HostArchive {
    space: SpaceId,
    agent: AgentId,
    store: Vec<u8>,
    descriptor: Vec<u8>,
    runtime: Vec<u8>,
    bootstrap: Vec<u8>,
}

struct RecoveryPlan {
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    source_hash: Hash,
    replacements_hash: Hash,
    recovery_signing_public_key: [u8; 32],
    recovery_encryption_public_key: [u8; 32],
    recovered_archive: Vec<u8>,
}

fn recovery_replacements_hash(
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    nodes: &[PrivateNodeIdentity],
) -> Result<Hash, PrivateAgentHostError> {
    if space == SpaceId::ZERO
        || agent == AgentId::ZERO
        || owner == PrincipalId::ZERO
        || nodes.is_empty()
        || nodes.len() > MAX_PRIVATE_NODES
        || nodes.windows(2).any(|pair| pair[0].node >= pair[1].node)
    {
        return Err(PrivateAgentHostError::InvalidMembership);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve(
            nodes
                .len()
                .saturating_mul(MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES),
        )
        .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
    for node in nodes {
        if !node.validate() || node.principal != owner {
            return Err(PrivateAgentHostError::InvalidMembership);
        }
        let wire = node
            .encode()
            .map_err(|_| PrivateAgentHostError::InvalidMembership)?;
        bytes.extend_from_slice(
            &u32::try_from(wire.len())
                .map_err(|_| PrivateAgentHostError::LimitExceeded)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&wire);
    }
    Ok(Hash::digest(
        RECOVERY_REPLACEMENTS_DOMAIN,
        &[space.as_bytes(), agent.as_bytes(), owner.as_bytes(), &bytes],
    ))
}

fn encode_recovery_plan(
    plan: &RecoveryPlan,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    if plan.space == SpaceId::ZERO
        || plan.agent == AgentId::ZERO
        || plan.owner == PrincipalId::ZERO
        || plan.source_hash == Hash::ZERO
        || plan.replacements_hash == Hash::ZERO
        || plan.recovery_signing_public_key == [0; 32]
        || !valid_x25519_public_key(&plan.recovery_encryption_public_key)
        || plan.recovered_archive.len() > MAX_PRIVATE_HOST_ARCHIVE_BYTES
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RECOVERY_PLAN_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(plan.space.as_bytes());
    encoder.fixed(plan.agent.as_bytes());
    encoder.fixed(plan.owner.as_bytes());
    encoder.fixed(plan.source_hash.as_bytes());
    encoder.fixed(plan.replacements_hash.as_bytes());
    encoder.fixed(&plan.recovery_signing_public_key);
    encoder.fixed(&plan.recovery_encryption_public_key);
    encoder.bytes(&plan.recovered_archive);
    if bytes.len().saturating_add(32) > MAX_PRIVATE_RECOVERY_PLAN_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let plan_hash = Hash::digest(RECOVERY_PLAN_HASH_DOMAIN, &[&bytes]);
    let authenticator = node_key.recovery_plan_authenticator(plan_hash)?;
    bytes.extend_from_slice(authenticator.as_bytes());
    Ok(bytes)
}

fn decode_recovery_plan(
    bytes: &[u8],
    node_key: &PrivateNodeDecryptionKey,
) -> Result<RecoveryPlan, PrivateAgentHostError> {
    if bytes.len() > MAX_PRIVATE_RECOVERY_PLAN_BYTES || bytes.len() < 32 {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let authenticated_len = bytes
        .len()
        .checked_sub(32)
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4).map_err(map_decode)? != RECOVERY_PLAN_MAGIC
        || decoder.u16().map_err(map_decode)? != FORMAT_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let plan = RecoveryPlan {
        space: SpaceId(decoder.fixed().map_err(map_decode)?),
        agent: AgentId(decoder.fixed().map_err(map_decode)?),
        owner: PrincipalId(decoder.fixed().map_err(map_decode)?),
        source_hash: Hash(decoder.fixed().map_err(map_decode)?),
        replacements_hash: Hash(decoder.fixed().map_err(map_decode)?),
        recovery_signing_public_key: decoder.fixed().map_err(map_decode)?,
        recovery_encryption_public_key: decoder.fixed().map_err(map_decode)?,
        recovered_archive: decoder
            .bytes_bounded(MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .map_err(map_decode)?,
    };
    let authenticator = Hash(decoder.fixed().map_err(map_decode)?);
    if !decoder.exhausted()
        || plan.space == SpaceId::ZERO
        || plan.agent == AgentId::ZERO
        || plan.owner == PrincipalId::ZERO
        || plan.source_hash == Hash::ZERO
        || plan.replacements_hash == Hash::ZERO
        || plan.recovery_signing_public_key == [0; 32]
        || !valid_x25519_public_key(&plan.recovery_encryption_public_key)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let plan_hash = Hash::digest(RECOVERY_PLAN_HASH_DOMAIN, &[&bytes[..authenticated_len]]);
    if node_key.recovery_plan_authenticator(plan_hash)? != authenticator {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(plan)
}

fn read_and_authenticate_recovery_plan(
    path: &Path,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<RecoveryPlan, PrivateAgentHostError> {
    let bytes = read_bounded_file(path, MAX_PRIVATE_RECOVERY_PLAN_BYTES)?;
    decode_recovery_plan(&bytes, node_key)
}

fn publish_recovery_plan(slot: &Path, bytes: &[u8]) -> Result<(), PrivateAgentHostError> {
    let temporary = slot.join(RECOVERY_PLAN_WRITE_FILE);
    let canonical = slot.join(RECOVERY_PLAN_FILE);
    write_new_synced(&temporary, bytes)?;
    fs::rename(&temporary, &canonical).map_err(map_io)?;
    sync_directory(slot)
}

fn recovery_stop(
    actual: RecoveryInstallStop,
    boundary: RecoveryInstallStop,
) -> Result<(), PrivateAgentHostError> {
    #[cfg(test)]
    if actual == boundary {
        return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
    }
    let _ = (actual, boundary);
    Ok(())
}

fn encode_host_archive(
    archive: &HostArchive,
    complete: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    let maximum = max_bytes.min(MAX_PRIVATE_HOST_ARCHIVE_BYTES);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(if complete {
        BACKUP_MAGIC
    } else {
        SNAPSHOT_MAGIC
    });
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(archive.space.as_bytes());
    encoder.fixed(archive.agent.as_bytes());
    encoder.bytes(&archive.store);
    encoder.bytes(&archive.descriptor);
    encoder.bytes(&archive.runtime);
    encoder.bytes(&archive.bootstrap);
    if bytes.len() > maximum {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    Ok(bytes)
}

fn decode_host_archive(bytes: &[u8], complete: bool) -> Result<HostArchive, PrivateAgentHostError> {
    if bytes.len() > MAX_PRIVATE_HOST_ARCHIVE_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    let expected_magic = if complete {
        BACKUP_MAGIC
    } else {
        SNAPSHOT_MAGIC
    };
    if decoder.take(4).map_err(map_decode)? != expected_magic
        || decoder.u16().map_err(map_decode)? != FORMAT_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let archive = HostArchive {
        space: SpaceId(decoder.fixed().map_err(map_decode)?),
        agent: AgentId(decoder.fixed().map_err(map_decode)?),
        store: decoder
            .bytes_bounded(MAX_PRIVATE_BACKUP_BYTES)
            .map_err(map_decode)?,
        descriptor: decoder
            .bytes_bounded(MAX_PRIVATE_OBJECT_WIRE_BYTES)
            .map_err(map_decode)?,
        runtime: decoder
            .bytes_bounded(MAX_PRIVATE_OBJECT_WIRE_BYTES)
            .map_err(map_decode)?,
        bootstrap: decoder
            .bytes_bounded(MAX_PRIVATE_OBJECT_WIRE_BYTES)
            .map_err(map_decode)?,
    };
    if !decoder.exhausted() || archive.space == SpaceId::ZERO || archive.agent == AgentId::ZERO {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(archive)
}

fn decrypt_archive_sidecar(
    bytes: &[u8],
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EncryptedObjectKind,
    data_key: &PrivateDataKey,
) -> Result<Zeroizing<Vec<u8>>, PrivateAgentHostError> {
    let object =
        EncryptedPrivateObject::decode(bytes).map_err(|_| PrivateAgentHostError::Corrupt)?;
    if object.space != space
        || object.agent != agent
        || object.epoch != epoch
        || object.kind != kind
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(Zeroizing::new(decrypt_private_object(data_key, &object)?))
}

fn decrypt_archive_plaintext(
    archive: &HostArchive,
    epoch: u64,
    data_key: &PrivateDataKey,
) -> Result<AgentPlaintext, PrivateAgentHostError> {
    let descriptor = decrypt_archive_sidecar(
        &archive.descriptor,
        archive.space,
        archive.agent,
        epoch,
        EncryptedObjectKind::Index,
        data_key,
    )?;
    let runtime = decrypt_archive_sidecar(
        &archive.runtime,
        archive.space,
        archive.agent,
        epoch,
        EncryptedObjectKind::Package,
        data_key,
    )?;
    let bootstrap = decrypt_archive_sidecar(
        &archive.bootstrap,
        archive.space,
        archive.agent,
        epoch,
        EncryptedObjectKind::Blob,
        data_key,
    )?;
    Ok(AgentPlaintext {
        descriptor: decode_descriptor_metadata(&descriptor, epoch)?,
        runtime_package: decode_bytes_metadata(
            &runtime,
            RUNTIME_MAGIC,
            epoch,
            MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(16),
        )?,
        bootstrap_metadata: decode_bytes_metadata(
            &bootstrap,
            BOOTSTRAP_MAGIC,
            epoch,
            MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES,
        )?,
    })
}

fn validate_archive_plaintext(
    plaintext: &AgentPlaintext,
    expected_space: SpaceId,
    expected_agent: AgentId,
    expected_owner: PrincipalId,
) -> Result<(), PrivateAgentHostError> {
    if plaintext.descriptor.identity.space != expected_space
        || plaintext.descriptor.identity.agent != expected_agent
        || plaintext.descriptor.identity.owner != expected_owner
        || plaintext.descriptor.identity.profile != AgentProfile::Private
        || !plaintext
            .descriptor
            .runtime_package
            .matches(&plaintext.runtime_package)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let admitted = admit_runtime_package(&plaintext.runtime_package)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    if plaintext.descriptor.runtime_package != *admitted.package_ref()
        || plaintext.descriptor.identity.runtime_deployment != admitted.deployment()
        || plaintext.descriptor.identity.runtime_program != admitted.program()
        || plaintext.descriptor.identity.runtime_producer != admitted.producer()
        || plaintext.descriptor.runtime_contract != admitted.manifest().contract
        || plaintext.descriptor.capabilities != admitted.capabilities()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
}

fn read_sidecar_wire(slot: &Path, name: &str) -> Result<Vec<u8>, PrivateAgentHostError> {
    read_bounded_file(&slot.join(name), MAX_PRIVATE_OBJECT_WIRE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::package::{
        AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope, PackageManifest,
        PackageSigning,
    };
    use vos_agent_sdk::private::PrivateControlSigner;
    use vos_agent_sdk::{
        InvocationId, MethodMode, ResumeWork, RuntimeState, StateLane, StorageKind,
    };

    use crate::agent::private_crypto::{
        OfflineRecoveryDecryptionKey, OfflineRecoveryKit, RecoverySigningKey,
        sign_recovery_control_record,
    };
    use crate::agent::private_store::CommitStop;
    use crate::agent::private_sync::{
        MAX_PRIVATE_SYNC_ITEMS, MAX_PRIVATE_SYNC_PAGE_BYTES, PrivateSyncCursor, PrivateSyncItem,
        PrivateSyncPhase,
    };
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const TEST_AUTHORITY_DOMAIN: &[u8] = b"vos/test/private-host-authority/v1";
    const SENTINEL: &[u8] = b"PRIVATE-HOST-PLAINTEXT-SENTINEL-7fbd96";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-private-host-{label}-{}-{sequence}",
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
        fn binding(space: SpaceId, owner: PrincipalId, node: &PrivateNodeIdentity) -> Hash {
            // One system binding is reusable across this root's multiple
            // Agent scopes; the trait still receives the exact AgentId.
            Hash::digest(
                TEST_AUTHORITY_DOMAIN,
                &[
                    space.as_bytes(),
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
            _agent: AgentId,
            expected_principal: PrincipalId,
            node: &PrivateNodeIdentity,
        ) -> bool {
            node.principal == expected_principal
                && node.authority_binding == Self::binding(space, expected_principal, node)
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

    #[derive(Clone)]
    struct NodeFixture {
        seed: [u8; 32],
        identity: PrivateNodeIdentity,
    }

    impl NodeFixture {
        fn key(&self) -> PrivateNodeDecryptionKey {
            PrivateNodeDecryptionKey::from_bytes(self.seed).unwrap()
        }
    }

    fn node(space: SpaceId, owner: PrincipalId, label: u8) -> NodeFixture {
        let seed = [label; 32];
        let key = PrivateNodeDecryptionKey::from_bytes(seed).unwrap();
        let transport_identity = vec![label.wrapping_add(40); 48];
        let mut identity = PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: owner,
            transport_identity,
            encryption_public_key: key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [label.wrapping_add(80); 64],
        };
        identity.authority_binding = TestAuthority::binding(space, owner, &identity);
        assert!(identity.validate());
        NodeFixture { seed, identity }
    }

    fn descriptor(
        space: SpaceId,
        owner: PrincipalId,
        nonce_label: u8,
        nodes: &[PrivateNodeIdentity],
        runtime: &AdmittedRuntimePackage,
    ) -> AgentDescriptor {
        let creation_nonce = Hash([nonce_label; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let authority_key = SigningKey::from_bytes(&[nonce_label.wrapping_add(90); 32])
            .verifying_key()
            .to_bytes();
        let issuer = AuthorityIssuer {
            principal: PrincipalId([21; 32]),
            actor: ActorId([22; 32]),
            deployment: DeploymentId([23; 32]),
            program: ProgramId([24; 32]),
            producer: ProducerId::of_public_key(&authority_key),
        };
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Private,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: Hash([28; 32]),
                issuer,
                public_key: authority_key,
                initial_epoch: 1,
            },
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
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
        descriptor
    }

    fn runtime_package() -> Vec<u8> {
        let mut assembler = Assembler::new();
        assembler.load_imm_64(Reg::A0, 7).trap();
        let program = assembler.build_standard();
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let artifact = PackageArtifact {
            identity: BlobRef::of_bytes(&program),
            bytes: program.clone(),
        };
        let mut envelope = PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: format!(
                    "fixture-runtime-{}",
                    core::str::from_utf8(SENTINEL).unwrap()
                ),
                outer_program: BlobRef::of_bytes(&program),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                signing: PackageSigning {
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                    signature: [0; 64],
                },
            }),
            artifacts: vec![artifact],
        };
        let signing_bytes = envelope.signing_bytes().unwrap();
        envelope.manifest.signing_mut().signature = signing_key.sign(&signing_bytes).to_bytes();
        envelope.encode().unwrap()
    }

    struct Fixture {
        directory: TestDirectory,
        space: SpaceId,
        owner: PrincipalId,
        recovery: RecoverySigningKey,
        recovery_encryption: OfflineRecoveryDecryptionKey,
        nodes: Vec<NodeFixture>,
        descriptor: AgentDescriptor,
        runtime: Vec<u8>,
        bootstrap: Vec<u8>,
    }

    fn fixture(node_count: usize) -> Fixture {
        let directory = TestDirectory::new("physical");
        let space = SpaceId([11; 32]);
        let owner = PrincipalId([12; 32]);
        let recovery = RecoverySigningKey::from_seed([13; 32]).unwrap();
        let recovery_encryption = OfflineRecoveryDecryptionKey::from_bytes([77; 32]).unwrap();
        let mut nodes: Vec<_> = (0..node_count)
            .map(|index| node(space, owner, u8::try_from(index + 14).unwrap()))
            .collect();
        nodes.sort_by_key(|node| node.identity.node);
        let identities: Vec<_> = nodes.iter().map(|node| node.identity.clone()).collect();
        let runtime = runtime_package();
        let mut bootstrap = b"private-bootstrap:".to_vec();
        bootstrap.extend_from_slice(SENTINEL);
        let admitted = admit_runtime_package(&runtime).unwrap();
        let descriptor = descriptor(space, owner, 31, &identities, &admitted);
        Fixture {
            directory,
            space,
            owner,
            recovery,
            recovery_encryption,
            nodes,
            descriptor,
            runtime,
            bootstrap,
        }
    }

    fn identities(fixture: &Fixture) -> Vec<PrivateNodeIdentity> {
        fixture
            .nodes
            .iter()
            .map(|node| node.identity.clone())
            .collect()
    }

    fn recovery_kit() -> OfflineRecoveryKit {
        OfflineRecoveryKit::new(
            RecoverySigningKey::from_seed([13; 32]).unwrap(),
            OfflineRecoveryDecryptionKey::from_bytes([77; 32]).unwrap(),
        )
        .unwrap()
    }

    fn create_host(fixture: &Fixture, node_index: usize, name: &str) -> PrivateAgentHost {
        PrivateAgentHost::create(
            fixture.directory.child(name),
            fixture.space,
            fixture.owner,
            fixture.nodes[node_index].identity.clone(),
            fixture.nodes[node_index].key(),
        )
        .unwrap()
    }

    fn create_agent(host: &mut PrivateAgentHost, fixture: &Fixture) -> AgentId {
        let runtime = admit_runtime_package(&fixture.runtime).unwrap();
        host.create_agent(
            PrivateAgentCreate {
                descriptor: &fixture.descriptor,
                nodes: &identities(fixture),
                recovery_recipient: DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                runtime_package: &runtime,
                bootstrap_metadata: &fixture.bootstrap,
            },
            &TestAuthority,
        )
        .unwrap()
    }

    fn collect_files(path: &Path, output: &mut Vec<u8>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                collect_files(&entry.path(), output);
            } else if metadata.is_file() {
                output.extend_from_slice(&fs::read(entry.path()).unwrap());
            }
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn two_nodes_restore_sync_restart_and_leak_no_plaintext() {
        let fixture = fixture(2);
        let mut primary = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut primary, &fixture);
        let backup = primary
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let snapshot = primary
            .export_encrypted_snapshot(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        assert!(!contains(&backup, SENTINEL));
        assert!(!contains(&snapshot, SENTINEL));

        let mut peer = create_host(&fixture, 1, "peer");
        assert_eq!(
            peer.restore_encrypted_backup(
                agent,
                DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                &backup,
                &TestAuthority,
            )
            .unwrap(),
            RestoreDisposition::Restored
        );

        let mut object_plaintext = b"merge-object:".to_vec();
        object_plaintext.extend_from_slice(SENTINEL);
        let key = primary
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, &object_plaintext)
            .unwrap();
        let binding = peer.binding(agent).unwrap();
        let mut cursor = PrivateSyncCursor::start(
            binding.space,
            binding.agent,
            binding.epoch,
            binding.control_head,
        )
        .unwrap();
        loop {
            let request = PrivateSyncRequest {
                cursor,
                max_items: MAX_PRIVATE_SYNC_ITEMS as u16,
                max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
            };
            let request_bytes = request.encode().unwrap();
            let page_bytes = primary
                .serve_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                    &request_bytes,
                    &TestTransport,
                )
                .unwrap();
            assert!(!contains(&page_bytes, SENTINEL));
            let page = PrivateSyncPage::decode(&page_bytes).unwrap();
            peer.apply_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &page_bytes,
                &TestAuthority,
                &TestTransport,
            )
            .unwrap();
            let Some(next) = page.next else {
                break;
            };
            cursor = next;
        }
        assert_eq!(
            peer.get_and_decrypt(agent, key).unwrap().as_slice(),
            object_plaintext
        );

        let mut disk = Vec::new();
        collect_files(&fixture.directory.child("primary"), &mut disk);
        collect_files(&fixture.directory.child("peer"), &mut disk);
        assert!(!contains(&disk, SENTINEL));

        drop(primary);
        drop(peer);
        let primary = PrivateAgentHost::open(
            fixture.directory.child("primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        let peer = PrivateAgentHost::open(
            fixture.directory.child("peer"),
            fixture.space,
            fixture.owner,
            fixture.nodes[1].identity.clone(),
            fixture.nodes[1].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(primary.agent_ids().collect::<Vec<_>>(), vec![agent]);
        assert_eq!(
            peer.get_and_decrypt(agent, key).unwrap().as_slice(),
            object_plaintext
        );
        assert_eq!(primary.descriptor(agent).unwrap(), &fixture.descriptor);
    }

    #[test]
    fn revocation_rotates_before_writes_and_all_non_node_ingress_reads_nothing() {
        let fixture = fixture(2);
        let mut primary = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut primary, &fixture);
        let old_epoch = primary.binding(agent).unwrap().epoch;
        let revoked_epoch_key = unwrap_data_key(
            primary.agents[&agent].store.key_epoch(),
            &fixture.nodes[1].identity,
            &fixture.nodes[1].key(),
        )
        .unwrap();
        primary
            .revoke_node(agent, fixture.nodes[1].identity.node, &TestAuthority)
            .unwrap();
        assert_eq!(primary.binding(agent).unwrap().epoch, old_epoch + 1);
        assert!(
            unwrap_data_key(
                primary.agents[&agent].store.key_epoch(),
                &fixture.nodes[1].identity,
                &fixture.nodes[1].key(),
            )
            .is_err(),
            "the revoked node must not unwrap the successor data epoch"
        );

        let malformed = b"not-even-a-sync-request";
        primary.reset_artifact_read_spy(agent);
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                malformed,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(agent), 0);
        assert_eq!(
            primary.apply_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                malformed,
                &TestAuthority,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(agent), 0);
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Principal(fixture.owner),
                malformed,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Credential(CredentialId([77; 32])),
                malformed,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(agent), 0);

        let mut altered = fixture.nodes[1].identity.clone();
        altered.transport_signature[0] ^= 1;
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&altered),
                malformed,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(agent), 0);

        let mut wrong_principal = fixture.nodes[0].identity.clone();
        wrong_principal.principal = PrincipalId([79; 32]);
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&wrong_principal),
                malformed,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(agent), 0);

        let future = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"post-revocation-state",
            )
            .unwrap();
        assert_eq!(future.epoch, old_epoch + 1);
        let future_ciphertext = primary.get_encrypted_object(agent, future).unwrap();
        assert!(decrypt_private_object(&revoked_epoch_key, &future_ciphertext).is_err());
        let request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, agent, old_epoch, None).unwrap(),
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        primary.reset_artifact_read_spy(agent);
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                &request.encode().unwrap(),
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(primary.artifact_read_spy(agent), 0);

        drop(primary);
        let reopened = PrivateAgentHost::open(
            fixture.directory.child("primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.binding(agent).unwrap().epoch, old_epoch + 1);
        assert_eq!(
            reopened.get_and_decrypt(agent, future).unwrap().as_slice(),
            b"post-revocation-state"
        );
    }

    #[test]
    fn authorized_survivors_reopen_and_decrypt_objects_across_multiple_rotations() {
        let fixture = fixture(2);
        let mut primary = create_host(&fixture, 0, "historical-primary");
        let agent = create_agent(&mut primary, &fixture);
        let epoch_zero = primary
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, b"epoch-zero-state")
            .unwrap();
        primary.rotate_keys(agent, &TestAuthority).unwrap();
        let epoch_one = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Snapshot, b"epoch-one-state")
            .unwrap();
        primary.rotate_keys(agent, &TestAuthority).unwrap();
        let epoch_two = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Blob, b"epoch-two-state")
            .unwrap();

        assert_eq!(primary.agents[&agent].data_keys.len(), 3);
        for (key, expected) in [
            (epoch_zero, b"epoch-zero-state".as_slice()),
            (epoch_one, b"epoch-one-state".as_slice()),
            (epoch_two, b"epoch-two-state".as_slice()),
        ] {
            assert_eq!(
                primary.get_and_decrypt(agent, key).unwrap().as_slice(),
                expected
            );
        }

        let backup = primary
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        drop(primary);
        let primary = PrivateAgentHost::open(
            fixture.directory.child("historical-primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(primary.agents[&agent].data_keys.len(), 3);
        assert_eq!(
            primary
                .get_and_decrypt(agent, epoch_zero)
                .unwrap()
                .as_slice(),
            b"epoch-zero-state"
        );

        let mut survivor = create_host(&fixture, 1, "historical-survivor");
        survivor
            .restore_encrypted_backup(
                agent,
                DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                &backup,
                &TestAuthority,
            )
            .unwrap();
        assert_eq!(survivor.agents[&agent].data_keys.len(), 3);
        assert_eq!(
            survivor
                .get_and_decrypt(agent, epoch_zero)
                .unwrap()
                .as_slice(),
            b"epoch-zero-state"
        );
    }

    #[test]
    fn post_history_invite_gets_current_epoch_but_not_retroactive_history() {
        let fixture = fixture(1);
        let invited = node(fixture.space, fixture.owner, 99);
        let mut primary = create_host(&fixture, 0, "late-invite-primary");
        let agent = create_agent(&mut primary, &fixture);
        let historical = primary
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, b"before-invite")
            .unwrap();
        primary.rotate_keys(agent, &TestAuthority).unwrap();
        let current = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Snapshot, b"current-at-invite")
            .unwrap();
        primary
            .invite_node(agent, invited.identity.clone(), &TestAuthority)
            .unwrap();
        let backup = primary
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();

        let invited_root = fixture.directory.child("late-invite-peer");
        let mut invited_host = PrivateAgentHost::create(
            &invited_root,
            fixture.space,
            fixture.owner,
            invited.identity.clone(),
            invited.key(),
        )
        .unwrap();
        invited_host
            .restore_encrypted_backup(
                agent,
                DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                &backup,
                &TestAuthority,
            )
            .unwrap();
        assert_eq!(invited_host.agents[&agent].data_keys.len(), 1);
        assert_eq!(
            invited_host
                .get_and_decrypt(agent, current)
                .unwrap()
                .as_slice(),
            b"current-at-invite"
        );
        assert_eq!(
            invited_host.get_and_decrypt(agent, historical),
            Err(PrivateAgentHostError::Unauthorized)
        );

        drop(invited_host);
        let invited_host = PrivateAgentHost::open(
            &invited_root,
            fixture.space,
            fixture.owner,
            invited.identity.clone(),
            invited.key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(invited_host.agents[&agent].data_keys.len(), 1);
        assert_eq!(
            invited_host.get_and_decrypt(agent, historical),
            Err(PrivateAgentHostError::Unauthorized)
        );
    }

    #[test]
    fn multi_rotation_sync_stages_every_epoch_for_each_store_commit_boundary() {
        let fixture = fixture(2);
        let mut source = create_host(&fixture, 0, "multi-rotation-source");
        let agent = create_agent(&mut source, &fixture);
        let historical = source
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, b"survivor-history")
            .unwrap();
        let base_backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        source.rotate_keys(agent, &TestAuthority).unwrap();
        source.rotate_keys(agent, &TestAuthority).unwrap();

        let request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, agent, 0, None).unwrap(),
            max_items: MAX_PRIVATE_SYNC_ITEMS as u16,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        let page_bytes = source
            .serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                &request.encode().unwrap(),
                &TestTransport,
            )
            .unwrap();
        let page = PrivateSyncPage::decode(&page_bytes).unwrap();
        assert_eq!(page.phase, PrivateSyncPhase::Controls);
        assert_eq!(page.items.len(), 2);
        let records: Vec<_> = page
            .items
            .iter()
            .map(|item| {
                let PrivateSyncItem::Control { wire, .. } = item else {
                    panic!("control page contained an object")
                };
                PrivateControlRecord::decode(wire).unwrap()
            })
            .collect();

        for control_index in 0..records.len() {
            for (label, stop) in [
                ("stage", CommitStop::AfterStage),
                ("artifact", CommitStop::AfterArtifact),
                ("index", CommitStop::AfterIndex),
            ] {
                let root = fixture
                    .directory
                    .child(&format!("multi-rotation-{control_index}-{label}"));
                let mut peer = PrivateAgentHost::create(
                    &root,
                    fixture.space,
                    fixture.owner,
                    fixture.nodes[1].identity.clone(),
                    fixture.nodes[1].key(),
                )
                .unwrap();
                peer.restore_encrypted_backup(
                    agent,
                    DurableRecoveryRecipient::from_durable_keystore(
                        fixture.recovery.verifying_key(),
                        fixture.recovery_encryption.public_key(),
                    )
                    .unwrap(),
                    &base_backup,
                    &TestAuthority,
                )
                .unwrap();

                let slot = peer.agent_path(agent);
                let candidates = validated_candidate_keys_from_page(
                    &peer.agents[&agent].store,
                    &page,
                    &fixture.nodes[1].identity,
                    &peer.node_key,
                    &TestAuthority,
                )
                .unwrap();
                assert_eq!(candidates.len(), 2);
                {
                    let hosted = peer.agents.get_mut(&agent).unwrap();
                    for candidate in &candidates {
                        stage_metadata(&slot, candidate.epoch, &candidate.data, hosted).unwrap();
                    }
                    for record in &records[..control_index] {
                        hosted.store.append_control(record, &TestAuthority).unwrap();
                    }
                    assert_eq!(
                        hosted.store.append_control_with_stop(
                            &records[control_index],
                            &TestAuthority,
                            stop,
                        ),
                        Err(PrivateStoreError::Interrupted)
                    );
                }
                // Model the host error path when a verified prefix is already
                // visible in memory. A later durable-but-unassigned control
                // still needs its distinct staged generation after restart.
                if peer.binding(agent).unwrap().epoch > 0 {
                    reconcile_staged_sync_keys(
                        &slot,
                        peer.agents.get_mut(&agent).unwrap(),
                        0,
                        candidates,
                        true,
                    )
                    .unwrap();
                } else {
                    drop(candidates);
                }
                // Process loss discards unwrapped keys. Store recovery must
                // select exactly the epoch whose control became durable.
                drop(peer);

                let reopened = PrivateAgentHost::open(
                    &root,
                    fixture.space,
                    fixture.owner,
                    fixture.nodes[1].identity.clone(),
                    fixture.nodes[1].key(),
                    &TestAuthority,
                )
                .unwrap();
                let expected_epoch = u64::try_from(control_index + 1).unwrap();
                assert_eq!(reopened.binding(agent).unwrap().epoch, expected_epoch);
                assert_eq!(
                    reopened
                        .get_and_decrypt(agent, historical)
                        .unwrap()
                        .as_slice(),
                    b"survivor-history"
                );
                assert_eq!(reopened.agents[&agent].data_keys.len(), control_index + 2);
                for name in SIDECAR_FILES {
                    assert!(slot.join(name).is_file());
                    assert!(fs::read_dir(&slot).unwrap().all(|entry| {
                        staged_sidecar_epoch(&entry.unwrap().file_name().to_string_lossy(), name)
                            .is_none()
                    }));
                }
            }
        }
    }

    #[test]
    fn unsigned_sync_epoch_never_receives_encrypted_host_sidecars() {
        let fixture = fixture(2);
        let mut source = create_host(&fixture, 0, "unsigned-epoch-source");
        let agent = create_agent(&mut source, &fixture);
        let base_backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        source.rotate_keys(agent, &TestAuthority).unwrap();

        let request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, agent, 0, None).unwrap(),
            max_items: MAX_PRIVATE_SYNC_ITEMS as u16,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        let page_bytes = source
            .serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                &request.encode().unwrap(),
                &TestTransport,
            )
            .unwrap();
        let mut page = PrivateSyncPage::decode(&page_bytes).unwrap();
        let PrivateSyncItem::Control {
            commitment, wire, ..
        } = &mut page.items[0]
        else {
            panic!("rotation page contained an object")
        };
        let mut unsigned = PrivateControlRecord::decode(wire).unwrap();
        unsigned.signature[0] ^= 1;
        *wire = unsigned.encode().unwrap();
        *commitment = unsigned.commitment();
        page.target.control_head = Some(*commitment);
        if let Some(next) = &mut page.next {
            next.local.control_head = Some(*commitment);
            next.target = Some(page.target);
        }

        let root = fixture.directory.child("unsigned-epoch-peer");
        let mut peer = PrivateAgentHost::create(
            &root,
            fixture.space,
            fixture.owner,
            fixture.nodes[1].identity.clone(),
            fixture.nodes[1].key(),
        )
        .unwrap();
        peer.restore_encrypted_backup(
            agent,
            DurableRecoveryRecipient::from_durable_keystore(
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
            )
            .unwrap(),
            &base_backup,
            &TestAuthority,
        )
        .unwrap();
        assert!(
            peer.apply_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &page.encode().unwrap(),
                &TestAuthority,
                &TestTransport,
            )
            .is_err()
        );
        let slot = peer.agent_path(agent);
        assert!(fs::read_dir(slot).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            !name.to_string_lossy().contains(NEXT_PREFIX)
        }));
    }

    #[test]
    fn offline_recovery_replaces_a_node_and_survives_restart() {
        let fixture = fixture(2);
        let replacement = node(fixture.space, fixture.owner, 99);
        let mut primary = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut primary, &fixture);
        primary
            .record_actor_lifecycle(
                agent,
                ActorId([51; 32]),
                PrivateActorLifecycleKind::Install,
                Hash([52; 32]),
                &TestAuthority,
            )
            .unwrap();
        let binding = primary.binding(agent).unwrap();
        let prior_head = binding.control_head.unwrap();
        let mut replacements = vec![
            fixture.nodes[0].identity.clone(),
            replacement.identity.clone(),
        ];
        replacements.sort_by_key(|node| node.node);
        let generated = generate_fresh_private_epoch(
            fixture.space,
            agent,
            binding.epoch + 1,
            fixture.owner,
            &replacements,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let historical_keyring = build_recovery_keyring_grant(
            primary.agents[&agent].store.key_epochs(),
            &primary.agents[&agent].data_keys,
            &generated.record,
            &replacements,
        )
        .unwrap();
        let mut recovery = PrivateControlRecord {
            space: fixture.space,
            agent,
            sequence: binding.next_sequence,
            previous: Some(prior_head),
            operation: PrivateControlOperation::Recover {
                superseded_heads: vec![prior_head],
                next_epoch: generated.record,
                replacement_nodes: replacements.clone(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();
        primary
            .apply_recovery_record(agent, prior_head, &recovery, &TestAuthority)
            .unwrap();
        assert_eq!(primary.binding(agent).unwrap().epoch, binding.epoch + 1);
        assert_eq!(
            primary.agents[&agent].store.authorized_nodes(),
            replacements
        );
        let key = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Snapshot, b"recovered-state")
            .unwrap();

        drop(primary);
        let reopened = PrivateAgentHost::open(
            fixture.directory.child("primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(
            reopened.agents[&agent].store.authorized_nodes(),
            replacements
        );
        assert_eq!(
            reopened.get_and_decrypt(agent, key).unwrap().as_slice(),
            b"recovered-state"
        );
    }

    #[test]
    fn encrypted_backup_recovers_all_epochs_after_total_node_loss_at_every_boundary() {
        let fixture = fixture(2);
        let mut primary = create_host(&fixture, 0, "offline-source");
        let agent = create_agent(&mut primary, &fixture);
        let mut before_revocation = b"epoch-zero:".to_vec();
        before_revocation.extend_from_slice(SENTINEL);
        let epoch_zero = primary
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, &before_revocation)
            .unwrap();
        primary
            .revoke_node(agent, fixture.nodes[1].identity.node, &TestAuthority)
            .unwrap();
        let epoch_one = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Blob, b"epoch-one-survivor")
            .unwrap();
        primary.rotate_keys(agent, &TestAuthority).unwrap();
        let epoch_two = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Snapshot, b"epoch-two-survivor")
            .unwrap();
        let backup = primary
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        assert!(!contains(&backup, SENTINEL));
        drop(primary);

        let replacement = node(fixture.space, fixture.owner, 111);
        let replacements = vec![replacement.identity.clone()];

        let wrong_signing_root = fixture.directory.child("wrong-signing-kit");
        let mut wrong_signing = PrivateAgentHost::create(
            &wrong_signing_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let wrong_signing_kit = OfflineRecoveryKit::new(
            RecoverySigningKey::from_seed([88; 32]).unwrap(),
            OfflineRecoveryDecryptionKey::from_bytes([77; 32]).unwrap(),
        )
        .unwrap();
        assert!(
            wrong_signing
                .recover_from_encrypted_backup(
                    agent,
                    &wrong_signing_kit,
                    &replacements,
                    &backup,
                    &TestAuthority,
                )
                .is_err()
        );
        assert!(!wrong_signing.creating_path(agent).exists());
        drop(wrong_signing);

        let wrong_encryption_root = fixture.directory.child("wrong-encryption-kit");
        let mut wrong_encryption = PrivateAgentHost::create(
            &wrong_encryption_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let wrong_encryption_kit = OfflineRecoveryKit::new(
            RecoverySigningKey::from_seed([13; 32]).unwrap(),
            OfflineRecoveryDecryptionKey::from_bytes([89; 32]).unwrap(),
        )
        .unwrap();
        assert!(
            wrong_encryption
                .recover_from_encrypted_backup(
                    agent,
                    &wrong_encryption_kit,
                    &replacements,
                    &backup,
                    &TestAuthority,
                )
                .is_err()
        );
        assert!(!wrong_encryption.creating_path(agent).exists());
        drop(wrong_encryption);

        let forged_root = fixture.directory.child("forged-backup");
        let mut forged_host = PrivateAgentHost::create(
            &forged_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let mut forged_backup = backup.clone();
        let last = forged_backup.len() - 1;
        forged_backup[last] ^= 1;
        assert!(
            forged_host
                .recover_from_encrypted_backup(
                    agent,
                    &recovery_kit(),
                    &replacements,
                    &forged_backup,
                    &TestAuthority,
                )
                .is_err()
        );
        assert!(!forged_host.creating_path(agent).exists());
        drop(forged_host);

        // Re-indexing a corrupted historical ciphertext makes the outer
        // archive structurally canonical. Recovery must still authenticate
        // every object with its exact epoch key before it stages a plan.
        let mut forged_object_archive = decode_host_archive(&backup, true).unwrap();
        let audit_kit = recovery_kit();
        let mut forged_objects = verify_encrypted_backup(
            &forged_object_archive.store,
            fixture.space,
            agent,
            fixture.owner,
            audit_kit.signing_public_key(),
            audit_kit.encryption_public_key(),
            &TestAuthority,
        )
        .unwrap();
        forged_objects
            .corrupt_epoch_object_and_reindex_for_test(0)
            .unwrap();
        forged_object_archive.store = forged_objects
            .encode_backup(MAX_PRIVATE_BACKUP_BYTES)
            .unwrap();
        let forged_object_backup =
            encode_host_archive(&forged_object_archive, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
                .unwrap();
        let forged_object_root = fixture.directory.child("forged-object-backup");
        let mut forged_object_host = PrivateAgentHost::create(
            &forged_object_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            forged_object_host.recover_from_encrypted_backup(
                agent,
                &audit_kit,
                &replacements,
                &forged_object_backup,
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Crypto(
                PrivateCryptoError::Decryption
            ))
        );
        assert!(!forged_object_host.creating_path(agent).exists());
        assert_eq!(
            forged_object_host.binding(agent),
            Err(PrivateAgentHostError::NotFound)
        );
        drop(forged_object_host);

        let forged_plan_root = fixture.directory.child("forged-recovery-plan");
        let mut forged_plan_host = PrivateAgentHost::create(
            &forged_plan_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            forged_plan_host.recover_from_encrypted_backup_with_stop(
                agent,
                &recovery_kit(),
                &replacements,
                &backup,
                &TestAuthority,
                RecoveryInstallStop::AfterPlan,
            ),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
        );
        let plan_path = forged_plan_host
            .creating_path(agent)
            .join(RECOVERY_PLAN_FILE);
        let mut forged_plan = fs::read(&plan_path).unwrap();
        let last = forged_plan.len() - 1;
        forged_plan[last] ^= 1;
        fs::write(&plan_path, forged_plan).unwrap();
        drop(forged_plan_host);
        assert!(matches!(
            PrivateAgentHost::open(
                &forged_plan_root,
                fixture.space,
                fixture.owner,
                replacement.identity.clone(),
                replacement.key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Corrupt)
        ));

        let stops = [
            RecoveryInstallStop::AfterPlan,
            RecoveryInstallStop::AfterStore,
            RecoveryInstallStop::AfterDescriptor,
            RecoveryInstallStop::AfterRuntime,
            RecoveryInstallStop::AfterBootstrap,
            RecoveryInstallStop::AfterVerification,
            RecoveryInstallStop::AfterPlanRetired,
            RecoveryInstallStop::AfterPublish,
        ];
        for (index, stop) in stops.into_iter().enumerate() {
            let root = fixture.directory.child(&format!("recovery-stop-{index}"));
            let mut host = PrivateAgentHost::create(
                &root,
                fixture.space,
                fixture.owner,
                replacement.identity.clone(),
                replacement.key(),
            )
            .unwrap();
            assert_eq!(
                host.recover_from_encrypted_backup_with_stop(
                    agent,
                    &recovery_kit(),
                    &replacements,
                    &backup,
                    &TestAuthority,
                    stop,
                ),
                Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
            );
            let mut disk = Vec::new();
            collect_files(&root, &mut disk);
            assert!(!contains(&disk, SENTINEL));
            if stop == RecoveryInstallStop::AfterStore {
                let plan_path = host.creating_path(agent).join(RECOVERY_PLAN_FILE);
                let exact_plan = fs::read(&plan_path).unwrap();
                assert_eq!(
                    host.recover_from_encrypted_backup_with_stop(
                        agent,
                        &recovery_kit(),
                        &replacements,
                        &backup,
                        &TestAuthority,
                        RecoveryInstallStop::AfterStore,
                    ),
                    Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
                );
                assert_eq!(fs::read(plan_path).unwrap(), exact_plan);
            }
            drop(host);

            let mut reopened = PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                replacement.identity.clone(),
                replacement.key(),
                &TestAuthority,
            )
            .unwrap();
            assert_eq!(reopened.binding(agent).unwrap().epoch, 3);
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, epoch_zero)
                    .unwrap()
                    .as_slice(),
                before_revocation
            );
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, epoch_one)
                    .unwrap()
                    .as_slice(),
                b"epoch-one-survivor"
            );
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, epoch_two)
                    .unwrap()
                    .as_slice(),
                b"epoch-two-survivor"
            );
            let successor = reopened.agents[&agent].store.key_epoch().clone();
            for old_node in &fixture.nodes {
                assert!(
                    unwrap_data_key(&successor, &old_node.identity, &old_node.key()).is_err(),
                    "lost/revoked node unexpectedly received successor epoch"
                );
            }
            let new_object = reopened
                .encrypt_and_put(agent, EncryptedObjectKind::Index, b"post-recovery-write")
                .unwrap();
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, new_object)
                    .unwrap()
                    .as_slice(),
                b"post-recovery-write"
            );
            drop(reopened);
            let reopened = PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                replacement.identity.clone(),
                replacement.key(),
                &TestAuthority,
            )
            .unwrap();
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, epoch_zero)
                    .unwrap()
                    .as_slice(),
                before_revocation
            );
            let mut disk = Vec::new();
            collect_files(&root, &mut disk);
            assert!(!contains(&disk, SENTINEL));
        }
    }

    #[test]
    fn one_scoped_root_owns_multiple_agents_and_invite_then_rotate_is_durable() {
        let fixture = fixture(1);
        let invited = node(fixture.space, fixture.owner, 101);
        let mut host = create_host(&fixture, 0, "primary");
        let first = create_agent(&mut host, &fixture);

        let admitted = admit_runtime_package(&fixture.runtime).unwrap();
        let nodes = identities(&fixture);
        let second_descriptor = descriptor(fixture.space, fixture.owner, 32, &nodes, &admitted);
        let second = host
            .create_agent(
                PrivateAgentCreate {
                    descriptor: &second_descriptor,
                    nodes: &nodes,
                    recovery_recipient: DurableRecoveryRecipient::from_durable_keystore(
                        fixture.recovery.verifying_key(),
                        fixture.recovery_encryption.public_key(),
                    )
                    .unwrap(),
                    runtime_package: &admitted,
                    bootstrap_metadata: &fixture.bootstrap,
                },
                &TestAuthority,
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(host.agent_ids().collect::<Vec<_>>(), {
            let mut ids = vec![first, second];
            ids.sort_unstable();
            ids
        });

        host.invite_node(first, invited.identity.clone(), &TestAuthority)
            .unwrap();
        assert_eq!(host.agents[&first].store.authorized_nodes().len(), 2);
        let before = host.binding(first).unwrap().epoch;
        host.rotate_keys(first, &TestAuthority).unwrap();
        assert_eq!(host.binding(first).unwrap().epoch, before + 1);

        drop(host);
        let reopened = PrivateAgentHost::open(
            fixture.directory.child("primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.agent_ids().len(), 2);
        assert_eq!(reopened.agents[&first].store.authorized_nodes().len(), 2);
        assert_eq!(reopened.binding(first).unwrap().epoch, before + 1);
    }

    #[test]
    fn restart_finishes_metadata_promotion_after_committed_rotation() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut host, &fixture);
        let slot = host.agent_path(agent);
        let hosted = host.agents.get_mut(&agent).unwrap();
        let binding = hosted.store.binding();
        let generated = generate_fresh_private_epoch(
            binding.space,
            binding.agent,
            binding.epoch + 1,
            binding.owner,
            hosted.store.authorized_nodes(),
            hosted.store.recovery_public_key(),
            hosted.store.recovery_encryption_public_key(),
            &TestAuthority,
        )
        .unwrap();
        stage_metadata(&slot, binding.epoch + 1, &generated.data_key, hosted).unwrap();
        let mut record = unsigned_owner_record(
            hosted,
            PrivateControlOperation::RotateKeys {
                next_epoch: generated.record,
            },
        );
        sign_owner_control_record(&mut record, &hosted.owner_key).unwrap();
        hosted
            .store
            .append_control(&record, &TestAuthority)
            .unwrap();
        // Simulate process loss before `.next` files are promoted.
        drop(host);

        let reopened = PrivateAgentHost::open(
            fixture.directory.child("primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.binding(agent).unwrap().epoch, binding.epoch + 1);
        for name in SIDECAR_FILES {
            assert!(slot.join(name).is_file());
            assert!(
                !slot
                    .join(staged_sidecar_name(name, binding.epoch + 1))
                    .exists()
            );
        }
    }

    #[test]
    fn root_scope_and_canonical_names_reject_principal_transport_aliases_and_residue() {
        let fixture = fixture(1);
        let root = fixture.directory.child("primary");
        let mut host = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut host, &fixture);
        drop(host);

        let wrong_owner = PrincipalId([91; 32]);
        assert!(matches!(
            PrivateAgentHost::open(
                &root,
                fixture.space,
                wrong_owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidScope)
        ));
        let mut wrong_transport = fixture.nodes[0].identity.clone();
        wrong_transport.transport_signature[0] ^= 1;
        assert!(matches!(
            PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                wrong_transport,
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidScope)
        ));

        fs::create_dir(root.join(encode_agent_id(agent).to_uppercase())).unwrap();
        assert!(matches!(
            PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidRoot)
        ));
        fs::remove_dir(root.join(encode_agent_id(agent).to_uppercase())).unwrap();
        fs::write(root.join("legacy-services"), b"VOSK").unwrap();
        assert!(matches!(
            PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidRoot)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn root_and_agent_symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;

        let fixture = fixture(1);
        let outside = fixture.directory.child("outside");
        fs::create_dir(&outside).unwrap();
        let root_link = fixture.directory.child("root-link");
        symlink(&outside, &root_link).unwrap();
        assert!(matches!(
            PrivateAgentHost::create(
                &root_link,
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
            ),
            Err(PrivateAgentHostError::InvalidRoot)
        ));

        let root = fixture.directory.child("primary");
        let host = create_host(&fixture, 0, "primary");
        drop(host);
        symlink(
            &outside,
            root.join(encode_agent_id(fixture.descriptor.identity.agent)),
        )
        .unwrap();
        assert!(matches!(
            PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidRoot)
        ));
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }

    #[test]
    fn private_schema_and_runtime_work_reject_linear_state() {
        let blob = || BlobRef::of_bytes(b"private-host-schema-artifact");
        let mut actor = ActorDescriptor {
            actor: ActorId([1; 32]),
            name: "private-actor".into(),
            parent: None,
            deployment: DeploymentId([2; 32]),
            program: ProgramId([3; 32]),
            package: blob(),
            agent_schema: blob(),
            method_policy: blob(),
            constructor_abi: Hash([4; 32]),
            installation_data: None,
            state_layout: Hash([5; 32]),
            lanes: LaneSet::of(StateLane::Merge),
            suspended: false,
        };
        let mut storage = StorageFieldDescriptor::derive(
            Hash([6; 32]),
            "values",
            StorageKind::Map,
            StateLane::Merge,
            true,
            b"key",
            b"value",
        );
        assert_eq!(
            PrivateAgentHost::validate_actor_schema(&actor, &[storage.clone()]),
            Ok(())
        );
        actor.lanes = LaneSet::of(StateLane::Linear);
        assert_eq!(
            PrivateAgentHost::validate_actor_schema(&actor, &[storage.clone()]),
            Err(PrivateAgentHostError::LinearUnsupported)
        );
        actor.lanes = LaneSet::of(StateLane::Merge);
        storage.lane = StateLane::Linear;
        assert_eq!(
            PrivateAgentHost::validate_actor_schema(&actor, &[storage]),
            Err(PrivateAgentHostError::LinearUnsupported)
        );

        let resume = || ResumeWork {
            invocation: InvocationId([7; 32]),
            actor: ActorId([8; 32]),
            incarnation: Hash([9; 32]),
            deployment: DeploymentId([10; 32]),
            program: ProgramId([11; 32]),
            mode: MethodMode::Merge,
            continuation: BlobRef::of_bytes(b"continuation"),
            ready_sequence: 1,
            installation_data: None,
            availability: Vec::new(),
            input: None,
        };
        let mut work = RuntimeWork::Resume {
            state: RuntimeState::default(),
            resume: Box::new(resume()),
        };
        assert_eq!(PrivateAgentHost::validate_runtime_work(&work), Ok(()));
        let RuntimeWork::Resume { resume, .. } = &mut work else {
            unreachable!()
        };
        resume.mode = MethodMode::Linear;
        assert_eq!(
            PrivateAgentHost::validate_runtime_work(&work),
            Err(PrivateAgentHostError::LinearUnsupported)
        );
    }
}
