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
use vos_agent_sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityIssuer, AuthorityOperationKind,
    AuthorityReceipt, AuthorityVerifier, ManagedAgentTarget,
};
use vos_agent_sdk::authority_operation::{
    AuthorityOperationIntent, AuthorityOperationIssuanceAck, PrivateControlApplicationAck,
    PrivateControlApplicationFact, private_member_set_commitment,
};
use vos_agent_sdk::contract::{
    ActorAbiRange, RuntimeMigrationPolicy, RuntimePackageContract, RuntimeResourceLimits,
};
use vos_agent_sdk::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_CIPHERTEXT_BYTES, MAX_PRIVATE_NODES,
    MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS, PrivateControlOperation, PrivateControlRecord,
    PrivateControlSigner, PrivateNodeIdentity, recovery_signing_public_key_commitment,
};
#[cfg(test)]
use vos_agent_sdk::private::{PrivateActorLifecycleKind, PrivateKeyEpoch};
use vos_agent_sdk::protocol::wire::{DecodeError, Decoder, Encoder};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES, MAX_PRIVATE_OBJECT_WIRE_BYTES,
};
use vos_agent_sdk::{
    ActorDescriptor, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, CredentialId, DeploymentId, Hash, LaneSet, NodeId, PrincipalId,
    PrivateRecoveryBinding, ProducerId, ProgramId, ProofSystemSet, ReplicaRole,
    RuntimeCapabilities, RuntimeWork, SpaceId, StorageFieldDescriptor,
};
use zeroize::Zeroizing;

use super::package_admission::{AdmittedRuntimePackage, admit_runtime_package};
#[cfg(test)]
use super::private_control_application_coordinator::decode_private_application_fact;
use super::private_control_application_coordinator::{
    PrivateControlRuntimeApplicationAdapter, PrivateControlRuntimeApplicationRequest,
    PrivateControlRuntimeApplicationResult, PrivateControlRuntimeEvidenceRequest,
    PrivateControlRuntimeEvidenceResult, encode_private_application_fact,
};
#[cfg(test)]
use super::private_crypto::{
    GeneratedPrivateEpoch, build_invite_history_grants, seal_data_key_for_node,
    seal_owner_key_for_node, sign_owner_control_record,
};
use super::private_crypto::{
    OfflineRecoveryKit, OwnerSigningKey, PrivateCryptoError, PrivateDataKey,
    PrivateNodeAuthorityVerifier, PrivateNodeDecryptionKey, build_recovery_keyring_grant,
    decrypt_private_object, encrypt_private_object, generate_fresh_private_epoch,
    sign_recovery_control_record, unwrap_data_key, unwrap_invite_history_grants, unwrap_owner_key,
    unwrap_recovery_data_key, unwrap_recovery_keyring, valid_x25519_public_key,
    verify_control_record_signature,
};
use super::private_store::{
    ControlEvidenceCommitStop, MAX_PRIVATE_BACKUP_BYTES, PrivateObjectKey, PrivateStore,
    PrivateStoreError, PutDisposition, RestoreDisposition, reconcile_encrypted_backups,
    verify_encrypted_backup,
};
use super::private_sync::{
    PrivateControlAuthorityEvidence, PrivateSyncApplyDisposition, PrivateSyncError,
    PrivateSyncPage, PrivateSyncPhase, PrivateSyncRequest, PrivateTransportAuthVerifier,
    apply_private_sync_page, serve_private_sync_page, validate_private_actor_schema,
    validate_private_runtime_work, verify_private_control_page_authority_evidence,
};

pub const MAX_PRIVATE_HOST_AGENTS: usize = 4_096;
pub const MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_PRIVATE_HOST_ARCHIVE_BYTES: usize = MAX_PRIVATE_BACKUP_BYTES + 32 * 1024 * 1024;

const FORMAT_VERSION: u16 = 2;
const ROOT_SCOPE_MAGIC: &[u8; 4] = b"PVHR";
const DESCRIPTOR_MAGIC: &[u8; 4] = b"PVHD";
const RUNTIME_MAGIC: &[u8; 4] = b"PVHP";
const BOOTSTRAP_MAGIC: &[u8; 4] = b"PVHM";
const BACKUP_MAGIC: &[u8; 4] = b"PVHB";
const SNAPSHOT_MAGIC: &[u8; 4] = b"PVHS";
const RECOVERY_PLAN_MAGIC: &[u8; 4] = b"PVRP";
const RECOVERY_PLAN_VERSION: u16 = 2;
const RECOVERY_PLAN_HASH_DOMAIN: &[u8] = b"vos/private/recovery-plan-bytes/v2";
const RECOVERY_SOURCE_ARCHIVE_HASH_DOMAIN: &[u8] = b"vos/private/recovery-source-archive/v2";
const RECOVERY_SOURCE_SET_HASH_DOMAIN: &[u8] = b"vos/private/recovery-source-set/v2";
const RECOVERY_REPLACEMENTS_DOMAIN: &[u8] = b"vos/private/recovery-replacements/v1";
const PRIVATE_REOPENED_CONTROL_STATE_DOMAIN: &[u8] = b"vos/private/reopened-control-state/v1";

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
const MAX_PRIVATE_RECOVERY_SOURCE_BYTES: usize =
    MAX_PRIVATE_HOST_ARCHIVE_BYTES.saturating_mul(MAX_PRIVATE_NODES);

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
    /// The signed control names a transition for which this host has no
    /// durable application/reopen implementation yet.
    UnsupportedOperation,
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
            PrivateSyncError::UnsupportedOperation => Self::UnsupportedOperation,
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

/// Concrete ciphertext-only runtime half of the Private authority pipeline.
///
/// Construction is crate-private because the caller must pair this adapter
/// with the durable operation issuer/coordinator and an exact system-authority
/// dispatcher. It accepts only the externally signed PCTL carried by the
/// coordinator request; it has no key-generation or control-signing API.
/// Every accepted mutation is projected from the exact signed PCTL into an
/// authority intent before it can reach the physical store.
pub(crate) struct PrivateAgentRuntimeApplication<'host, V> {
    host: &'host mut PrivateAgentHost,
    authority: AuthorityActorTarget,
    node_authority: &'host V,
    stop: PrivateRuntimeApplicationStop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateRuntimeApplicationStop {
    Never,
    AfterDescriptorStaged,
    AfterRuntimeStaged,
    AfterBootstrapStaged,
    AfterStoreStagedArtifact,
    AfterStoreStagedIndex,
    AfterStorePending,
    AfterStoreArtifact,
    AfterStoreIndex,
    AfterStoreCommitted,
    AfterDescriptorPromoted,
    AfterRuntimePromoted,
    AfterBootstrapPromoted,
    AfterReopen,
    #[cfg(test)]
    AfterEvidenceStaged,
    #[cfg(test)]
    AfterEvidencePending,
    #[cfg(test)]
    AfterEvidencePublished,
    #[cfg(test)]
    AfterEvidenceRetired,
    #[cfg(test)]
    AfterEvidenceReopen,
}

struct PreparedPrivateApplication {
    control: PrivateControlRecord,
    control_wire: Vec<u8>,
    operation: AuthorityOperationKind,
    expected_epoch: u64,
    expected_members: Vec<NodeId>,
    already_applied: bool,
}

struct RawAuthorityVerifier;

impl AuthorityVerifier for RawAuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
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

    /// Borrow the concrete ciphertext-only runtime application boundary.
    ///
    /// This is deliberately not a standalone public mutation API. Trusted
    /// boot/control wiring must install it inside
    /// `DurablePrivateControlApplicationCoordinator` together with durable
    /// issuer/coordinator stores and the real exact-route authority actor
    /// dispatcher. Until that dispatcher is wired, production control
    /// application remains unavailable rather than bypassing evidence.
    pub(crate) fn runtime_application_adapter<'host, V>(
        &'host mut self,
        authority: AuthorityActorTarget,
        node_authority: &'host V,
    ) -> Result<PrivateAgentRuntimeApplication<'host, V>, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        self.verify_root_scope()?;
        if !authority.is_valid() || authority.space != self.scope.space {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        Ok(PrivateAgentRuntimeApplication {
            host: self,
            authority,
            node_authority,
            stop: PrivateRuntimeApplicationStop::Never,
        })
    }

    pub(crate) fn create_agent<V: PrivateNodeAuthorityVerifier>(
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

    #[cfg(test)]
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
        let mut record = unsigned_owner_record(
            hosted,
            PrivateControlOperation::Invite {
                node,
                epoch: binding.epoch,
                sealed_owner_key,
                sealed_data_key,
                historical_grants: Vec::new(),
            },
        );
        let grants =
            build_invite_history_grants(&record, hosted.store.key_epochs(), &hosted.data_keys)?;
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut record.operation
        else {
            return Err(PrivateAgentHostError::Corrupt);
        };
        *historical_grants = grants;
        sign_owner_control_record(&mut record, &hosted.owner_key)?;
        Ok(hosted.store.append_control(&record, authority)?)
    }

    /// Revoke one exact Node and commit a fresh owner/data epoch before this
    /// method returns. The serving local node cannot revoke itself and keep
    /// using the same scoped host root.
    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
    #[cfg(test)]
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
    /// authorized owner node. This establishment primitive stays crate-local:
    /// production attachment must additionally correlate the imported control
    /// head with the authority/PCA pipeline. No descriptor, runtime, bootstrap,
    /// or key plaintext crosses the archive boundary.
    pub(crate) fn restore_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
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
    pub(crate) fn recover_from_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        bytes: &[u8],
        authority: &V,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.recover_from_encrypted_backups_inner(
            agent,
            recovery_kit,
            replacement_nodes,
            &[bytes],
            authority,
            RecoveryInstallStop::Never,
        )
    }

    /// Recover from the deterministic union of complete independently held
    /// ciphertext archives. Every archive, control head, epoch, sidecar, and
    /// object is authenticated before a recovery plan is made durable.
    pub(crate) fn recover_from_encrypted_backups<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        backups: &[&[u8]],
        authority: &V,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.recover_from_encrypted_backups_inner(
            agent,
            recovery_kit,
            replacement_nodes,
            backups,
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
        self.recover_from_encrypted_backups_inner(
            agent,
            recovery_kit,
            replacement_nodes,
            &[bytes],
            authority,
            stop,
        )
    }

    #[cfg(test)]
    fn recover_from_encrypted_backups_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        backups: &[&[u8]],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.recover_from_encrypted_backups_inner(
            agent,
            recovery_kit,
            replacement_nodes,
            backups,
            authority,
            stop,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_from_encrypted_backups_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        backups: &[&[u8]],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<RestoreDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        require_exact_local_member(replacement_nodes, &self.scope.local_node)?;
        let source_hash = recovery_sources_hash(backups)?;
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

        let mut sources = Vec::new();
        sources
            .try_reserve_exact(backups.len())
            .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
        for bytes in backups {
            let archive = decode_host_archive(bytes, true)?;
            if archive.space != self.scope.space || archive.agent != agent {
                return Err(PrivateAgentHostError::InvalidScope);
            }
            let verified = verify_encrypted_backup(
                &archive.store,
                self.scope.space,
                agent,
                self.scope.owner,
                recovery_kit.signing_public_key(),
                recovery_kit.encryption_public_key(),
                authority,
            )?;
            if verified.key_epochs().is_empty()
                || verified.key_epochs().len() > MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS
            {
                return Err(PrivateAgentHostError::LimitExceeded);
            }
            sources.push((archive, verified));
        }

        let mut historical_keys = BTreeMap::new();
        let mut historical_commitments = BTreeMap::new();
        let mut plaintext = None;
        for (archive, verified) in &sources {
            for epoch in verified.key_epochs() {
                let key = unwrap_recovery_data_key(epoch, recovery_kit.decryption_key())?;
                match historical_commitments.get(&epoch.epoch) {
                    Some(commitment)
                        if *commitment != epoch.data_key_commitment
                            || historical_keys.get(&epoch.epoch).is_none_or(
                                |existing: &PrivateDataKey| {
                                    existing.commitment() != key.commitment()
                                },
                            ) =>
                    {
                        return Err(PrivateStoreError::Diverged.into());
                    }
                    Some(_) => {}
                    None => {
                        historical_commitments.insert(epoch.epoch, epoch.data_key_commitment);
                        historical_keys.insert(epoch.epoch, key);
                    }
                }
            }
            // The archive index authenticates the canonical ciphertext
            // records, but only the exact historical epoch keys authenticate
            // their contents. Audit every object from every contributor
            // before reconciling or publishing a recovery plan.
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
                let object_plaintext = Zeroizing::new(decrypt_private_object(key, object)?);
                drop(object_plaintext);
            }

            let binding = verified.binding();
            let current_key = historical_keys
                .get(&binding.epoch)
                .ok_or(PrivateAgentHostError::Corrupt)?;
            let candidate = decrypt_archive_plaintext(archive, binding.epoch, current_key)?;
            validate_archive_plaintext(&candidate, self.scope.space, agent, self.scope.owner)?;
            if let Some(reference) = &plaintext {
                if !recovery_plaintext_is_compatible(reference, &candidate) {
                    return Err(PrivateStoreError::Diverged.into());
                }
            } else {
                plaintext = Some(candidate);
            }
        }

        let verified_backups = sources.into_iter().map(|(_, verified)| verified).collect();
        let (mut verified, superseded_heads, recovery_sequence) =
            reconcile_encrypted_backups(verified_backups)?;
        let prior_binding = verified.binding();
        if recovery_sequence >= super::private_crypto::MAX_PRIVATE_CONTROL_RECORDS {
            return Err(PrivateAgentHostError::LimitExceeded);
        }
        if historical_keys.len() != verified.key_epochs().len()
            || historical_commitments.len() != verified.key_epochs().len()
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        let mut plaintext = plaintext.ok_or(PrivateAgentHostError::Corrupt)?;
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
            sequence: recovery_sequence,
            previous: prior_binding.control_head,
            operation: PrivateControlOperation::Recover {
                superseded_heads,
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
        authority: AuthorityActorTarget,
        transport: &T,
    ) -> Result<Vec<u8>, PrivateAgentHostError> {
        let hosted = self.hosted(agent)?;
        let peer = authenticate_peer_identity(hosted, peer, transport)?;
        let request = PrivateSyncRequest::decode(request_bytes)?;
        let route = ManagedAgentTarget {
            space: hosted.descriptor.identity.space,
            agent: hosted.descriptor.identity.agent,
            runtime_deployment: hosted.descriptor.identity.runtime_deployment,
        };
        if authority.binding != hosted.descriptor.authority {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        Ok(
            serve_private_sync_page(&hosted.store, peer, &request, transport, route, authority)?
                .encode()?,
        )
    }

    /// Apply one exact authenticated, authority-evidenced sync page. Every
    /// PCTL is bound to canonical AOI1+PCA1 under the independently configured
    /// authority before any epoch sidecar or store artifact is staged.
    pub fn apply_sync_page<A, T>(
        &mut self,
        agent: AgentId,
        peer: PrivatePeerIdentity<'_>,
        page_bytes: &[u8],
        authority: AuthorityActorTarget,
        node_authority: &A,
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
        let route = ManagedAgentTarget {
            space: hosted.descriptor.identity.space,
            agent: hosted.descriptor.identity.agent,
            runtime_deployment: hosted.descriptor.identity.runtime_deployment,
        };
        if authority.binding != hosted.descriptor.authority {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        verify_private_control_page_authority_evidence(&page, route, authority)?;
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
            node_authority,
        )?;
        for candidate in &staged_keys {
            stage_metadata(&slot, candidate.epoch, &candidate.data, hosted)?;
        }
        let result = apply_private_sync_page(
            &mut hosted.store,
            peer,
            &page,
            node_authority,
            transport,
            route,
            authority,
        );
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

    fn apply_authorized_private_control<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeApplicationRequest,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeApplicationResult, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        self.verify_root_scope()?;
        let agent = request.route.agent;
        let prepared = prepare_private_application(
            self.hosted(agent)?,
            &self.scope.local_node,
            authority,
            node_authority,
            request,
        )?;
        let slot = self.agent_path(agent);
        let expected_space = self.scope.space;
        let expected_owner = self.scope.owner;
        let local_node = self.scope.local_node.clone();
        let mut hosted = self
            .agents
            .remove(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;

        let transition = apply_prepared_private_control(
            &slot,
            &mut hosted,
            &local_node,
            &self.node_key,
            node_authority,
            &prepared,
            stop,
        );
        drop(hosted);
        if let Err(error) = transition {
            // Production I/O failures are ambiguous. Reopen the physical
            // store immediately so its pending transaction and staged
            // sidecars are reconciled before this handle can be used again.
            // Test failpoints deliberately model a process stop and therefore
            // leave reconciliation to a newly opened host.
            if stop == PrivateRuntimeApplicationStop::Never {
                let reopened = open_hosted_agent(
                    &slot,
                    expected_space,
                    expected_owner,
                    &local_node,
                    &self.node_key,
                    node_authority,
                )
                .map_err(|_| PrivateAgentHostError::Corrupt)?;
                if self.agents.insert(agent, reopened).is_some() {
                    return Err(PrivateAgentHostError::Alias);
                }
            }
            return Err(error);
        }

        // A successful runtime assertion is made only from a brand-new
        // physical reopen. This replays the signed chain, reconciles a pending
        // store transaction, selects the exact committed sidecar generation,
        // unwraps this node's keys, and authenticates the admitted runtime.
        let reopened = open_hosted_agent(
            &slot,
            expected_space,
            expected_owner,
            &local_node,
            &self.node_key,
            node_authority,
        )?;
        let fact = reopened_private_application_fact(&reopened, request, &prepared)?;
        if self.agents.insert(agent, reopened).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        #[cfg(test)]
        if stop == PrivateRuntimeApplicationStop::AfterReopen {
            return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
        }
        Ok(PrivateControlRuntimeApplicationResult {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            receipt: request.receipt.clone(),
            issuance_ack: request.issuance_ack.clone(),
            applied_at: request.applied_at,
            authenticated: true,
            durably_applied: true,
            durably_reopened: true,
            application_fact: encode_private_application_fact(&fact),
        })
    }

    fn persist_completed_private_control_evidence<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeEvidenceRequest,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeEvidenceResult, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        self.verify_root_scope()?;
        if request.authority != authority || !request.route.is_valid() {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let control = PrivateControlRecord::decode(&request.control)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        if control.encode().ok().as_deref() != Some(request.control.as_slice()) {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
        verify_control_record_signature(&control)?;
        let issuance = AuthorityOperationIssuanceAck::decode(&request.issuance_ack)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        let application = PrivateControlApplicationAck::decode(&request.application_ack)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        if issuance.encode().ok().as_deref() != Some(request.issuance_ack.as_slice())
            || application.encode().ok().as_deref() != Some(request.application_ack.as_slice())
        {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
        let evidence =
            PrivateControlAuthorityEvidence::from_acknowledgements(&issuance, &application)?;
        evidence.verify_for(
            &control,
            application.application.epoch,
            request.route,
            authority,
        )?;
        let evidence_wire = evidence.encode()?;
        let evidence_commitment = evidence.commitment()?;
        let agent = request.route.agent;
        let hosted = self.hosted(agent)?;
        let binding = hosted.store.binding();
        if request.route.space != binding.space
            || request.route.agent != binding.agent
            || request.route.runtime_deployment != hosted.descriptor.identity.runtime_deployment
            || authority.space != binding.space
            || authority.binding != hosted.descriptor.authority
            || application.application.epoch
                != hosted
                    .store
                    .indexed_controls()
                    .iter()
                    .find(|entry| entry.commitment == control.commitment())
                    .ok_or(PrivateAgentHostError::InvalidArtifact)?
                    .resulting_epoch
            || !hosted
                .store
                .control_is_exact(control.commitment(), &request.control)?
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }

        #[cfg(test)]
        let evidence_stop = match stop {
            PrivateRuntimeApplicationStop::AfterEvidenceStaged => {
                ControlEvidenceCommitStop::AfterStaged
            }
            PrivateRuntimeApplicationStop::AfterEvidencePending => {
                ControlEvidenceCommitStop::AfterPending
            }
            PrivateRuntimeApplicationStop::AfterEvidencePublished => {
                ControlEvidenceCommitStop::AfterPublished
            }
            PrivateRuntimeApplicationStop::AfterEvidenceRetired => {
                ControlEvidenceCommitStop::AfterRetired
            }
            _ => ControlEvidenceCommitStop::Never,
        };
        #[cfg(not(test))]
        let evidence_stop = ControlEvidenceCommitStop::Never;
        let persistence = self
            .hosted_mut(agent)?
            .store
            .persist_control_authority_evidence_with_stop_for_runtime(
                control.commitment(),
                &evidence_wire,
                evidence_stop,
            );
        if let Err(error) = persistence {
            if stop == PrivateRuntimeApplicationStop::Never {
                let slot = self.agent_path(agent);
                let previous = self
                    .agents
                    .remove(&agent)
                    .ok_or(PrivateAgentHostError::NotFound)?;
                drop(previous);
                let reopened = open_hosted_agent(
                    &slot,
                    self.scope.space,
                    self.scope.owner,
                    &self.scope.local_node,
                    &self.node_key,
                    node_authority,
                )
                .map_err(|_| PrivateAgentHostError::Corrupt)?;
                if self.agents.insert(agent, reopened).is_some() {
                    return Err(PrivateAgentHostError::Alias);
                }
            }
            return Err(error.into());
        }

        let slot = self.agent_path(agent);
        let previous = self
            .agents
            .remove(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        drop(previous);
        let reopened = open_hosted_agent(
            &slot,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            node_authority,
        )?;
        let entry = reopened
            .store
            .indexed_controls()
            .iter()
            .find(|entry| entry.commitment == control.commitment())
            .ok_or(PrivateAgentHostError::Corrupt)?;
        if reopened
            .store
            .read_control_authority_evidence(entry)?
            .as_deref()
            != Some(evidence_wire.as_slice())
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        if self.agents.insert(agent, reopened).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        #[cfg(test)]
        if stop == PrivateRuntimeApplicationStop::AfterEvidenceReopen {
            return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
        }
        Ok(PrivateControlRuntimeEvidenceResult {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            issuance_ack: request.issuance_ack.clone(),
            application_ack: request.application_ack.clone(),
            evidence_commitment,
            authenticated: true,
            durably_persisted: true,
            durably_reopened: true,
        })
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

impl<V> PrivateControlRuntimeApplicationAdapter for PrivateAgentRuntimeApplication<'_, V>
where
    V: PrivateNodeAuthorityVerifier,
{
    type Error = PrivateAgentHostError;

    fn apply(
        &mut self,
        request: &PrivateControlRuntimeApplicationRequest,
    ) -> Result<PrivateControlRuntimeApplicationResult, Self::Error> {
        self.host.apply_authorized_private_control(
            self.authority,
            self.node_authority,
            request,
            self.stop,
        )
    }

    fn persist_completed_evidence(
        &mut self,
        request: &PrivateControlRuntimeEvidenceRequest,
    ) -> Result<PrivateControlRuntimeEvidenceResult, Self::Error> {
        self.host.persist_completed_private_control_evidence(
            self.authority,
            self.node_authority,
            request,
            self.stop,
        )
    }
}

#[cfg(test)]
impl<V> PrivateAgentRuntimeApplication<'_, V> {
    fn stop_after(&mut self, stop: PrivateRuntimeApplicationStop) {
        self.stop = stop;
    }
}

fn prepare_private_application<V>(
    hosted: &HostedPrivateAgent,
    local_node: &PrivateNodeIdentity,
    authority: AuthorityActorTarget,
    node_authority: &V,
    request: &PrivateControlRuntimeApplicationRequest,
) -> Result<PreparedPrivateApplication, PrivateAgentHostError>
where
    V: PrivateNodeAuthorityVerifier,
{
    let binding = hosted.store.binding();
    if request.authority != authority
        || !request.route.is_valid()
        || request.route.space != authority.space
        || request.route.space != binding.space
        || request.route.agent != binding.agent
        || request.route.runtime_deployment != hosted.descriptor.identity.runtime_deployment
        || authority.binding != hosted.descriptor.authority
        || hosted.descriptor.identity.owner != binding.owner
    {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    let control = PrivateControlRecord::decode(&request.control)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    if control.encode().ok().as_deref() != Some(request.control.as_slice())
        || control.space != binding.space
        || control.agent != binding.agent
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    verify_control_record_signature(&control)?;
    if matches!(
        &control.operation,
        PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. }
    ) {
        // A control-chain append is not application of either operation. In
        // particular, this request carries only the lifecycle request hash and
        // HostedPrivateAgent has no durably reopenable runtime image. Refuse
        // before inspecting or mutating the store until a real runtime bridge
        // can commit and reopen the selected policy/actor-forest transition.
        return Err(PrivateAgentHostError::UnsupportedOperation);
    }
    let intent =
        AuthorityOperationIntent::private_control(request.route.runtime_deployment, &control)
            .map_err(|_| PrivateAgentHostError::Unauthorized)?;
    let operation = intent.operation();
    let expected_actor = match &intent {
        AuthorityOperationIntent::PrivateActorLifecycle { actor, .. } => Some(*actor),
        _ => None,
    };

    let receipt = AuthorityReceipt::decode(&request.receipt)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let issuance = AuthorityOperationIssuanceAck::decode(&request.issuance_ack)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let selector = &receipt.selector;
    if receipt.encode().ok().as_deref() != Some(request.receipt.as_slice())
        || issuance.encode().ok().as_deref() != Some(request.issuance_ack.as_slice())
        || issuance.authority != authority
        || issuance.receipt != receipt
        || issuance.issued_at > request.applied_at
        || selector.space != request.route.space
        || selector.agent != request.route.agent
        || selector.runtime_deployment != request.route.runtime_deployment
        || selector.operation != operation
        || selector.actor != expected_actor
        || selector.actor_deployment.is_some()
        || selector.request != control.commitment()
        || issuance
            .verify_with(authority.binding, &RawAuthorityVerifier)
            .is_err()
        || receipt
            .verify_at(request.applied_at, &RawAuthorityVerifier)
            .is_err()
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }

    let already_applied = hosted
        .store
        .control_is_exact(control.commitment(), &request.control)?;
    if already_applied {
        if binding.control_head != Some(control.commitment())
            || binding.next_sequence
                != control
                    .sequence
                    .checked_add(1)
                    .ok_or(PrivateAgentHostError::LimitExceeded)?
        {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
    } else {
        validate_new_private_application_position(hosted, local_node, &control)?;
        hosted
            .store
            .validate_next_control(&control, node_authority)?;
    }

    let expected_epoch = match &control.operation {
        PrivateControlOperation::Invite { epoch, .. } => *epoch,
        PrivateControlOperation::Revoke { next_epoch, .. }
        | PrivateControlOperation::RotateKeys { next_epoch }
        | PrivateControlOperation::Recover { next_epoch, .. } => next_epoch.epoch,
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => binding.epoch,
    };
    let expected_members = if already_applied {
        hosted
            .store
            .authorized_nodes()
            .iter()
            .map(|node| node.node)
            .collect()
    } else {
        expected_private_members(hosted.store.authorized_nodes(), local_node, &control)?
    };
    let member_set = private_member_set_commitment(expected_members.iter().copied())
        .ok_or(PrivateAgentHostError::InvalidMembership)?;
    match &intent {
        AuthorityOperationIntent::RevokePrivateNode {
            member_set: expected,
            ..
        }
        | AuthorityOperationIntent::RotatePrivateKeys {
            member_set: expected,
            ..
        } if *expected != member_set => {
            return Err(PrivateAgentHostError::InvalidMembership);
        }
        AuthorityOperationIntent::RecoverPrivateAgent { proof }
            if proof.replacement_member_set != member_set =>
        {
            return Err(PrivateAgentHostError::InvalidMembership);
        }
        _ => {}
    }
    if already_applied && binding.epoch != expected_epoch {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    Ok(PreparedPrivateApplication {
        control,
        control_wire: request.control.clone(),
        operation,
        expected_epoch,
        expected_members,
        already_applied,
    })
}

fn validate_new_private_application_position(
    hosted: &HostedPrivateAgent,
    local_node: &PrivateNodeIdentity,
    control: &PrivateControlRecord,
) -> Result<(), PrivateAgentHostError> {
    let binding = hosted.store.binding();
    let recovery = matches!(&control.operation, PrivateControlOperation::Recover { .. });
    if (!recovery && control.sequence != binding.next_sequence)
        || (recovery && control.sequence < binding.next_sequence)
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    match &control.operation {
        PrivateControlOperation::Invite { epoch, .. } => {
            if control.previous != binding.control_head
                || *epoch != binding.epoch
                || control.signer != PrivateControlSigner::Owner
                || control.signer_public_key != hosted.owner_key.verifying_key()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
        }
        PrivateControlOperation::Revoke { node, next_epoch } => {
            if control.previous != binding.control_head
                || *node == local_node.node
                || binding.epoch.checked_add(1) != Some(next_epoch.epoch)
                || control.signer != PrivateControlSigner::Owner
                || control.signer_public_key != hosted.owner_key.verifying_key()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
        }
        PrivateControlOperation::RotateKeys { next_epoch } => {
            if control.previous != binding.control_head
                || binding.epoch.checked_add(1) != Some(next_epoch.epoch)
                || control.signer != PrivateControlSigner::Owner
                || control.signer_public_key != hosted.owner_key.verifying_key()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
        }
        PrivateControlOperation::Recover {
            superseded_heads,
            next_epoch,
            replacement_nodes,
            ..
        } => {
            let supersedes_local = match binding.control_head {
                Some(head) => {
                    superseded_heads.binary_search(&head).is_ok()
                        && control.previous.is_some_and(|selected| {
                            superseded_heads.binary_search(&selected).is_ok()
                        })
                }
                None => superseded_heads.is_empty() && control.previous.is_none(),
            };
            if !supersedes_local
                || next_epoch.epoch <= binding.epoch
                || control.signer != PrivateControlSigner::Recovery
                || control.signer_public_key != hosted.store.recovery_public_key()
                || require_exact_local_member(replacement_nodes, local_node).is_err()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
        }
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {
            if control.previous != binding.control_head
                || control.signer != PrivateControlSigner::Owner
                || control.signer_public_key != hosted.owner_key.verifying_key()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
        }
    }
    Ok(())
}

fn expected_private_members(
    current: &[PrivateNodeIdentity],
    local_node: &PrivateNodeIdentity,
    control: &PrivateControlRecord,
) -> Result<Vec<NodeId>, PrivateAgentHostError> {
    let mut members: Vec<NodeId> = current.iter().map(|node| node.node).collect();
    match &control.operation {
        PrivateControlOperation::Invite { node, .. } => {
            let position = members
                .binary_search(&node.node)
                .err()
                .ok_or(PrivateAgentHostError::InvalidMembership)?;
            members.insert(position, node.node);
        }
        PrivateControlOperation::Revoke { node, .. } => {
            let position = members
                .binary_search(node)
                .map_err(|_| PrivateAgentHostError::InvalidMembership)?;
            members.remove(position);
            if members.binary_search(&local_node.node).is_err() {
                return Err(PrivateAgentHostError::Unauthorized);
            }
        }
        PrivateControlOperation::Recover {
            replacement_nodes, ..
        } => {
            require_exact_local_member(replacement_nodes, local_node)?;
            members = replacement_nodes.iter().map(|node| node.node).collect();
        }
        PrivateControlOperation::RotateKeys { .. }
        | PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {}
    }
    Ok(members)
}

fn apply_prepared_private_control<V>(
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    node_authority: &V,
    prepared: &PreparedPrivateApplication,
    stop: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError>
where
    V: PrivateNodeAuthorityVerifier,
{
    if prepared.already_applied {
        return Ok(());
    }
    let successor_data = match &prepared.control.operation {
        PrivateControlOperation::Invite { .. } => None,
        PrivateControlOperation::Revoke { next_epoch, .. }
        | PrivateControlOperation::RotateKeys { next_epoch } => {
            let owner = unwrap_owner_key(next_epoch, local_node, node_key)?;
            let data = unwrap_data_key(next_epoch, local_node, node_key)?;
            if owner.verifying_key() == hosted.owner_key.verifying_key()
                || data.commitment()
                    == hosted
                        .data_keys
                        .get(&hosted.store.binding().epoch)
                        .ok_or(PrivateAgentHostError::Corrupt)?
                        .commitment()
            {
                return Err(PrivateAgentHostError::InvalidArtifact);
            }
            Some(data)
        }
        PrivateControlOperation::Recover {
            next_epoch,
            historical_keyring,
            ..
        } => {
            let _owner = unwrap_owner_key(next_epoch, local_node, node_key)?;
            let data = unwrap_data_key(next_epoch, local_node, node_key)?;
            let prior_epoch_count = hosted
                .store
                .key_epochs()
                .partition_point(|epoch| epoch.epoch < next_epoch.epoch);
            if prior_epoch_count == 0 {
                return Err(PrivateAgentHostError::Corrupt);
            }
            let _historical = unwrap_recovery_keyring(
                historical_keyring,
                &hosted.store.key_epochs()[..prior_epoch_count],
                local_node,
                node_key,
            )?;
            Some(data)
        }
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => None,
    };
    if let Some(data) = successor_data.as_ref() {
        stage_metadata_for_application(slot, prepared.expected_epoch, data, hosted, stop)?;
    }

    #[cfg(test)]
    let store_stop = private_store_stop(stop);
    let store_result = match &prepared.control.operation {
        PrivateControlOperation::Recover { .. } => {
            #[cfg(test)]
            if let Some(store_stop) = store_stop {
                hosted.store.apply_offline_recovery_with_stop(
                    hosted.store.binding().control_head,
                    &prepared.control,
                    node_authority,
                    store_stop,
                )
            } else {
                hosted.store.apply_offline_recovery(
                    hosted.store.binding().control_head,
                    &prepared.control,
                    node_authority,
                )
            }
            #[cfg(not(test))]
            {
                hosted.store.apply_offline_recovery(
                    hosted.store.binding().control_head,
                    &prepared.control,
                    node_authority,
                )
            }
        }
        _ => {
            #[cfg(test)]
            if let Some(store_stop) = store_stop {
                hosted
                    .store
                    .append_control_with_stop(&prepared.control, node_authority, store_stop)
            } else {
                hosted
                    .store
                    .append_control(&prepared.control, node_authority)
            }
            #[cfg(not(test))]
            {
                hosted
                    .store
                    .append_control(&prepared.control, node_authority)
            }
        }
    };
    store_result?;
    #[cfg(test)]
    if stop == PrivateRuntimeApplicationStop::AfterStoreCommitted {
        return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
    }
    if successor_data.is_some() {
        promote_application_sidecars(slot, prepared.expected_epoch, stop)?;
    }
    Ok(())
}

fn reopened_private_application_fact(
    hosted: &HostedPrivateAgent,
    request: &PrivateControlRuntimeApplicationRequest,
    prepared: &PreparedPrivateApplication,
) -> Result<PrivateControlApplicationFact, PrivateAgentHostError> {
    let binding = hosted.store.binding();
    let members: Vec<NodeId> = hosted
        .store
        .authorized_nodes()
        .iter()
        .map(|node| node.node)
        .collect();
    if binding.space != request.route.space
        || binding.agent != request.route.agent
        || hosted.descriptor.identity.runtime_deployment != request.route.runtime_deployment
        || binding.epoch != prepared.expected_epoch
        || binding.control_head != Some(prepared.control.commitment())
        || binding.next_sequence
            != prepared
                .control
                .sequence
                .checked_add(1)
                .ok_or(PrivateAgentHostError::LimitExceeded)?
        || members != prepared.expected_members
        || !hosted
            .store
            .control_is_exact(prepared.control.commitment(), &prepared.control_wire)?
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let post_member_set = private_member_set_commitment(members.iter().copied())
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let fact = PrivateControlApplicationFact {
        managed: request.route,
        operation: prepared.operation,
        control: prepared.control.commitment(),
        control_sequence: prepared.control.sequence,
        control_previous: prepared.control.previous,
        epoch: prepared.expected_epoch,
        post_member_set,
        reopened_control_state: reopened_control_state(hosted, request.route, post_member_set)?,
        reopened_control_head: prepared.control.commitment(),
        applied_at: request.applied_at,
    };
    fact.validate_shape()
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(fact)
}

fn reopened_control_state(
    hosted: &HostedPrivateAgent,
    route: ManagedAgentTarget,
    member_set: Hash,
) -> Result<Hash, PrivateAgentHostError> {
    let binding = hosted.store.binding();
    let head = binding.control_head.ok_or(PrivateAgentHostError::Corrupt)?;
    let epoch = hosted.store.key_epoch();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PCRS");
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(route.space.as_bytes());
    encoder.fixed(route.agent.as_bytes());
    encoder.fixed(route.runtime_deployment.as_bytes());
    encoder.fixed(binding.owner.as_bytes());
    encoder.u64(binding.epoch);
    encoder.fixed(head.as_bytes());
    encoder.u64(binding.next_sequence);
    encoder.fixed(member_set.as_bytes());
    encoder.fixed(epoch.owner_key_commitment.as_bytes());
    encoder.fixed(epoch.data_key_commitment.as_bytes());
    encoder.fixed(epoch.recovery_key_commitment.as_bytes());
    Ok(Hash::digest(
        PRIVATE_REOPENED_CONTROL_STATE_DOMAIN,
        &[&bytes],
    ))
}

fn stage_metadata_for_application(
    slot: &Path,
    epoch: u64,
    data_key: &PrivateDataKey,
    hosted: &HostedPrivateAgent,
    stop: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError> {
    let plaintext = AgentPlaintext {
        descriptor: hosted.descriptor.clone(),
        runtime_package: Zeroizing::new(hosted.runtime_package.to_vec()),
        bootstrap_metadata: Zeroizing::new(hosted.bootstrap_metadata.to_vec()),
    };
    let identity = &plaintext.descriptor.identity;
    let sidecars = encrypt_sidecars(identity.space, identity.agent, epoch, data_key, &plaintext)?;
    replace_staged_file(slot, DESCRIPTOR_FILE, epoch, &sidecars.descriptor)?;
    application_stop(stop, PrivateRuntimeApplicationStop::AfterDescriptorStaged)?;
    replace_staged_file(slot, RUNTIME_FILE, epoch, &sidecars.runtime)?;
    application_stop(stop, PrivateRuntimeApplicationStop::AfterRuntimeStaged)?;
    replace_staged_file(slot, BOOTSTRAP_FILE, epoch, &sidecars.bootstrap)?;
    sync_directory(slot)?;
    application_stop(stop, PrivateRuntimeApplicationStop::AfterBootstrapStaged)
}

fn promote_application_sidecars(
    slot: &Path,
    epoch: u64,
    stop: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError> {
    let boundaries = [
        PrivateRuntimeApplicationStop::AfterDescriptorPromoted,
        PrivateRuntimeApplicationStop::AfterRuntimePromoted,
        PrivateRuntimeApplicationStop::AfterBootstrapPromoted,
    ];
    for (canonical, boundary) in SIDECAR_FILES.into_iter().zip(boundaries) {
        let next = slot.join(staged_sidecar_name(canonical, epoch));
        require_regular_file(&next)?;
        fs::rename(&next, slot.join(canonical)).map_err(map_io)?;
        sync_directory(slot)?;
        application_stop(stop, boundary)?;
    }
    Ok(())
}

fn application_stop(
    actual: PrivateRuntimeApplicationStop,
    boundary: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError> {
    #[cfg(test)]
    if actual == boundary {
        return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
    }
    let _ = (actual, boundary);
    Ok(())
}

#[cfg(test)]
fn private_store_stop(
    stop: PrivateRuntimeApplicationStop,
) -> Option<super::private_store::CommitStop> {
    use super::private_store::CommitStop;

    match stop {
        PrivateRuntimeApplicationStop::AfterStoreStagedArtifact => {
            Some(CommitStop::AfterStagedArtifact)
        }
        PrivateRuntimeApplicationStop::AfterStoreStagedIndex => Some(CommitStop::AfterStagedIndex),
        PrivateRuntimeApplicationStop::AfterStorePending => Some(CommitStop::AfterPending),
        PrivateRuntimeApplicationStop::AfterStoreArtifact => Some(CommitStop::AfterArtifact),
        PrivateRuntimeApplicationStop::AfterStoreIndex => Some(CommitStop::AfterIndex),
        _ => None,
    }
}

fn validate_create_request(
    scope: &RootScope,
    node_key: &PrivateNodeDecryptionKey,
    request: &PrivateAgentCreate<'_>,
) -> Result<(), PrivateAgentHostError> {
    let descriptor = request.descriptor;
    let expected_recovery = PrivateRecoveryBinding {
        signing_key_commitment: recovery_signing_public_key_commitment(
            &request.recovery_recipient.signing_public_key(),
        ),
        encryption_public_key: request.recovery_recipient.encryption_public_key(),
    };
    descriptor
        .validate()
        .map_err(|_| PrivateAgentHostError::InvalidDescriptor)?;
    if descriptor.identity.profile != AgentProfile::Private
        || descriptor.identity.space != scope.space
        || descriptor.identity.owner != scope.owner
        || descriptor.private_recovery != Some(expected_recovery)
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

#[cfg(test)]
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

#[cfg(test)]
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
#[cfg(test)]
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
            ..
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
    encoder.option(&value.private_recovery, |encoder, binding| {
        encoder.fixed(binding.signing_key_commitment.as_bytes());
        encoder.fixed(&binding.encryption_public_key);
    });
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
    let private_recovery = decoder.option(|decoder| {
        Ok(PrivateRecoveryBinding {
            signing_key_commitment: Hash(decoder.fixed()?),
            encryption_public_key: decoder.fixed()?,
        })
    })?;
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
        private_recovery,
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
        || plaintext.descriptor.private_recovery
            != Some(PrivateRecoveryBinding {
                signing_key_commitment: recovery_signing_public_key_commitment(
                    &store.recovery_public_key(),
                ),
                encryption_public_key: store.recovery_encryption_public_key(),
            })
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
    // Current and directly authorized epochs remain independently sealed in
    // their epoch records. Complete Invite and Recovery grants add only the
    // exact authenticated history explicitly authorized for this recipient.
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
    for invite in store.invite_history_records(local_node)? {
        let PrivateControlOperation::Invite { epoch, .. } = &invite.operation else {
            return Err(PrivateAgentHostError::Corrupt);
        };
        let current_position = store
            .key_epochs()
            .binary_search_by_key(epoch, |candidate| candidate.epoch)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let history = unwrap_invite_history_grants(
            &invite,
            &store.key_epochs()[..=current_position],
            store.binding().owner,
            local_node,
            node_key,
        )?;
        for (epoch, key) in history {
            if let Some(existing) = data_keys.get(&epoch) {
                if existing.commitment() != key.commitment() {
                    return Err(PrivateAgentHostError::Corrupt);
                }
            } else {
                data_keys.insert(epoch, key);
            }
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

fn recovery_sources_hash(backups: &[&[u8]]) -> Result<Hash, PrivateAgentHostError> {
    if backups.is_empty() || backups.len() > MAX_PRIVATE_NODES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let total_bytes = backups
        .iter()
        .try_fold(0usize, |total, backup| total.checked_add(backup.len()));
    if total_bytes.is_none_or(|total| total > MAX_PRIVATE_RECOVERY_SOURCE_BYTES) {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let mut hashes = Vec::new();
    hashes
        .try_reserve_exact(backups.len())
        .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
    for backup in backups {
        if backup.len() > MAX_PRIVATE_HOST_ARCHIVE_BYTES {
            return Err(PrivateAgentHostError::LimitExceeded);
        }
        hashes.push(Hash::digest(RECOVERY_SOURCE_ARCHIVE_HASH_DOMAIN, &[backup]));
    }
    hashes.sort_unstable();
    if hashes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PrivateAgentHostError::Alias);
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(2 + hashes.len() * 32)
        .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
    canonical.extend_from_slice(
        &u16::try_from(hashes.len())
            .map_err(|_| PrivateAgentHostError::LimitExceeded)?
            .to_le_bytes(),
    );
    for hash in hashes {
        canonical.extend_from_slice(hash.as_bytes());
    }
    Ok(Hash::digest(RECOVERY_SOURCE_SET_HASH_DOMAIN, &[&canonical]))
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
    bytes.extend_from_slice(&RECOVERY_PLAN_VERSION.to_le_bytes());
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
        || decoder.u16().map_err(map_decode)? != RECOVERY_PLAN_VERSION
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

fn recovery_plaintext_is_compatible(left: &AgentPlaintext, right: &AgentPlaintext) -> bool {
    let mut left_descriptor = left.descriptor.clone();
    let mut right_descriptor = right.descriptor.clone();
    // Replica membership belongs to each authenticated control head and is
    // replaced by the recovery ceremony. Every other descriptor field and
    // both opaque plaintext sidecars must agree across contributing backups.
    left_descriptor.replicas.clear();
    right_descriptor.replicas.clear();
    left_descriptor == right_descriptor
        && left.runtime_package.as_slice() == right.runtime_package.as_slice()
        && left.bootstrap_metadata.as_slice() == right.bootstrap_metadata.as_slice()
}

fn read_sidecar_wire(slot: &Path, name: &str) -> Result<Vec<u8>, PrivateAgentHostError> {
    read_bounded_file(&slot.join(name), MAX_PRIVATE_OBJECT_WIRE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, AuthorityReceiptSelector,
    };
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
            private_recovery: Some(PrivateRecoveryBinding {
                signing_key_commitment: recovery_signing_public_key_commitment(
                    &RecoverySigningKey::from_seed([13; 32])
                        .unwrap()
                        .verifying_key(),
                ),
                encryption_public_key: OfflineRecoveryDecryptionKey::from_bytes([77; 32])
                    .unwrap()
                    .public_key(),
            }),
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

    fn reopen_host(fixture: &Fixture, node_index: usize, name: &str) -> PrivateAgentHost {
        PrivateAgentHost::open(
            fixture.directory.child(name),
            fixture.space,
            fixture.owner,
            fixture.nodes[node_index].identity.clone(),
            fixture.nodes[node_index].key(),
            &TestAuthority,
        )
        .unwrap()
    }

    fn authority_target(fixture: &Fixture) -> (AuthorityActorTarget, SigningKey) {
        let key = SigningKey::from_bytes(&[121; 32]);
        assert_eq!(
            key.verifying_key().to_bytes(),
            fixture.descriptor.authority.public_key
        );
        (
            AuthorityActorTarget {
                space: fixture.space,
                system_agent: AgentId([0xa1; 32]),
                system_runtime_deployment: DeploymentId([0xa2; 32]),
                binding: fixture.descriptor.authority,
            },
            key,
        )
    }

    fn signed_revoke_control(
        host: &PrivateAgentHost,
        agent: AgentId,
        revoked: NodeId,
    ) -> PrivateControlRecord {
        let hosted = host.hosted(agent).unwrap();
        let binding = hosted.store.binding();
        let mut nodes = hosted.store.authorized_nodes().to_vec();
        let position = nodes
            .binary_search_by_key(&revoked, |node| node.node)
            .unwrap();
        nodes.remove(position);
        let generated = generate_fresh_private_epoch(
            binding.space,
            binding.agent,
            binding.epoch + 1,
            binding.owner,
            &nodes,
            hosted.store.recovery_public_key(),
            hosted.store.recovery_encryption_public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut control = unsigned_owner_record(
            hosted,
            PrivateControlOperation::Revoke {
                node: revoked,
                next_epoch: generated.record,
            },
        );
        sign_owner_control_record(&mut control, &hosted.owner_key).unwrap();
        control
    }

    fn signed_rotate_control_for(
        host: &PrivateAgentHost,
        agent: AgentId,
        nodes: &[PrivateNodeIdentity],
        next_epoch: u64,
    ) -> PrivateControlRecord {
        let hosted = host.hosted(agent).unwrap();
        let binding = hosted.store.binding();
        let generated = generate_fresh_private_epoch(
            binding.space,
            binding.agent,
            next_epoch,
            binding.owner,
            nodes,
            hosted.store.recovery_public_key(),
            hosted.store.recovery_encryption_public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut control = unsigned_owner_record(
            hosted,
            PrivateControlOperation::RotateKeys {
                next_epoch: generated.record,
            },
        );
        sign_owner_control_record(&mut control, &hosted.owner_key).unwrap();
        control
    }

    fn signed_rotate_control(host: &PrivateAgentHost, agent: AgentId) -> PrivateControlRecord {
        let hosted = host.hosted(agent).unwrap();
        signed_rotate_control_for(
            host,
            agent,
            hosted.store.authorized_nodes(),
            hosted.store.binding().epoch + 1,
        )
    }

    fn signed_invite_control(
        host: &PrivateAgentHost,
        agent: AgentId,
        node: PrivateNodeIdentity,
    ) -> PrivateControlRecord {
        let hosted = host.hosted(agent).unwrap();
        let binding = hosted.store.binding();
        let sealed_owner_key = seal_owner_key_for_node(
            binding.space,
            binding.agent,
            binding.epoch,
            &hosted.owner_key,
            &node,
        )
        .unwrap();
        let sealed_data_key = seal_data_key_for_node(
            binding.space,
            binding.agent,
            binding.epoch,
            hosted.data_keys.get(&binding.epoch).unwrap(),
            &node,
        )
        .unwrap();
        let mut control = unsigned_owner_record(
            hosted,
            PrivateControlOperation::Invite {
                node,
                epoch: binding.epoch,
                sealed_owner_key,
                sealed_data_key,
                historical_grants: Vec::new(),
            },
        );
        let grants =
            build_invite_history_grants(&control, hosted.store.key_epochs(), &hosted.data_keys)
                .unwrap();
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut control.operation
        else {
            unreachable!();
        };
        *historical_grants = grants;
        sign_owner_control_record(&mut control, &hosted.owner_key).unwrap();
        control
    }

    fn signed_recovery_control(
        host: &PrivateAgentHost,
        agent: AgentId,
        replacement_nodes: &[PrivateNodeIdentity],
        recovery: &RecoverySigningKey,
    ) -> PrivateControlRecord {
        let hosted = host.hosted(agent).unwrap();
        let binding = hosted.store.binding();
        let prior_head = binding.control_head;
        let generated = generate_fresh_private_epoch(
            binding.space,
            binding.agent,
            binding.epoch + 1,
            binding.owner,
            replacement_nodes,
            hosted.store.recovery_public_key(),
            hosted.store.recovery_encryption_public_key(),
            &TestAuthority,
        )
        .unwrap();
        let historical_keyring = build_recovery_keyring_grant(
            hosted.store.key_epochs(),
            &hosted.data_keys,
            &generated.record,
            replacement_nodes,
        )
        .unwrap();
        let mut control = PrivateControlRecord {
            space: binding.space,
            agent: binding.agent,
            sequence: binding.next_sequence,
            previous: prior_head,
            operation: PrivateControlOperation::Recover {
                superseded_heads: prior_head.into_iter().collect(),
                next_epoch: generated.record,
                replacement_nodes: replacement_nodes.to_vec(),
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
        sign_recovery_control_record(&mut control, recovery).unwrap();
        control
    }

    fn runtime_application_request(
        fixture: &Fixture,
        control: &PrivateControlRecord,
        issued_at: u64,
        applied_at: u64,
    ) -> (
        AuthorityActorTarget,
        PrivateControlRuntimeApplicationRequest,
    ) {
        let (authority, key) = authority_target(fixture);
        let route = ManagedAgentTarget {
            space: fixture.space,
            agent: control.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
        };
        let intent =
            AuthorityOperationIntent::private_control(route.runtime_deployment, control).unwrap();
        let operation = intent.operation();
        let actor = match intent {
            AuthorityOperationIntent::PrivateActorLifecycle { actor, .. } => Some(actor),
            _ => None,
        };
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: authority.binding.policy,
                issuer: authority.binding.issuer,
                space: route.space,
                agent: route.agent,
                operation,
                runtime_deployment: route.runtime_deployment,
                actor,
                actor_deployment: None,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0xa3; 32]),
                },
                lane_roots: AuthorityLaneRoots {
                    control: None,
                    linear: Some(Hash([0xa4; 32])),
                    merge: None,
                    local: None,
                },
                epoch: authority.binding.initial_epoch,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: issued_at,
                expires_at: applied_at.saturating_add(100),
                request: control.commitment(),
            },
            public_key: authority.binding.public_key,
            signature: [0; 64],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        let mut authorization_invocation = [0xa5; 32];
        authorization_invocation[24..].copy_from_slice(&control.sequence.to_le_bytes());
        let mut acknowledgement_invocation = [0xa6; 32];
        acknowledgement_invocation[24..].copy_from_slice(&control.sequence.to_le_bytes());
        let mut issuance = AuthorityOperationIssuanceAck {
            authorization_invocation: InvocationId(authorization_invocation),
            acknowledgement_invocation: InvocationId(acknowledgement_invocation),
            authority,
            operation_call: Hash::digest(
                b"vos/test/private-operation-call/v1",
                &[control.commitment().as_bytes()],
            ),
            approval: Hash::digest(
                b"vos/test/private-operation-approval/v1",
                &[control.commitment().as_bytes()],
            ),
            authorization_sequence: NonZeroU64::new(control.sequence + 1).unwrap(),
            receipt: receipt.clone(),
            issued_at,
            signature: [0; 64],
        };
        issuance.signature = key.sign(&issuance.signing_bytes()).to_bytes();
        assert!(
            issuance
                .verify_with(authority.binding, &RawAuthorityVerifier)
                .is_ok()
        );
        (
            authority,
            PrivateControlRuntimeApplicationRequest {
                route,
                authority,
                control: control.encode().unwrap(),
                receipt: receipt.encode().unwrap(),
                issuance_ack: issuance.encode().unwrap(),
                applied_at,
            },
        )
    }

    fn canonical_sidecars(host: &PrivateAgentHost, agent: AgentId) -> [Vec<u8>; 3] {
        let slot = host.agent_path(agent);
        SIDECAR_FILES.map(|name| fs::read(slot.join(name)).unwrap())
    }

    fn apply_runtime_request(
        host: &mut PrivateAgentHost,
        authority: AuthorityActorTarget,
        request: &PrivateControlRuntimeApplicationRequest,
    ) -> Result<PrivateControlRuntimeApplicationResult, PrivateAgentHostError> {
        host.runtime_application_adapter(authority, &TestAuthority)
            .unwrap()
            .apply(request)
    }

    fn apply_and_attach_test_authority_evidence(
        host: &mut PrivateAgentHost,
        fixture: &Fixture,
        control: &PrivateControlRecord,
        issued_at: u64,
        applied_at: u64,
    ) -> (
        PrivateControlRuntimeApplicationResult,
        PrivateControlApplicationAck,
    ) {
        let (authority, request) =
            runtime_application_request(fixture, control, issued_at, applied_at);
        let result = apply_runtime_request(host, authority, &request).unwrap();
        let application = signed_test_application_ack(fixture, &request, &result);
        let evidence_request = test_evidence_request(&request, &application);
        let evidence = host
            .runtime_application_adapter(authority, &TestAuthority)
            .unwrap()
            .persist_completed_evidence(&evidence_request)
            .unwrap();
        assert!(evidence.authenticated && evidence.durably_persisted && evidence.durably_reopened);
        (result, application)
    }

    fn signed_test_application_ack(
        fixture: &Fixture,
        request: &PrivateControlRuntimeApplicationRequest,
        result: &PrivateControlRuntimeApplicationResult,
    ) -> PrivateControlApplicationAck {
        let issuance = AuthorityOperationIssuanceAck::decode(&request.issuance_ack).unwrap();
        let application_fact = decode_private_application_fact(&result.application_fact).unwrap();
        let (authority, key) = authority_target(fixture);
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
            receipt: issuance.receipt.clone(),
            issued_at: issuance.issued_at,
            application: application_fact,
            signature: [0; 64],
        };
        application.signature = key.sign(&application.signing_bytes()).to_bytes();
        application
    }

    fn test_evidence_request(
        request: &PrivateControlRuntimeApplicationRequest,
        application: &PrivateControlApplicationAck,
    ) -> PrivateControlRuntimeEvidenceRequest {
        PrivateControlRuntimeEvidenceRequest {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            issuance_ack: request.issuance_ack.clone(),
            application_ack: application.encode().unwrap(),
        }
    }

    #[test]
    fn creation_requires_the_exact_descriptor_recovery_binding() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "recovery-binding");
        let runtime = admit_runtime_package(&fixture.runtime).unwrap();
        let nodes = identities(&fixture);
        let recipient = DurableRecoveryRecipient::from_durable_keystore(
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
        )
        .unwrap();

        let mut wrong_signing = fixture.descriptor.clone();
        wrong_signing
            .private_recovery
            .as_mut()
            .unwrap()
            .signing_key_commitment = Hash([0x91; 32]);
        assert_eq!(
            host.create_agent(
                PrivateAgentCreate {
                    descriptor: &wrong_signing,
                    nodes: &nodes,
                    recovery_recipient: recipient,
                    runtime_package: &runtime,
                    bootstrap_metadata: &fixture.bootstrap,
                },
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidDescriptor)
        );

        let mut wrong_encryption = fixture.descriptor.clone();
        wrong_encryption
            .private_recovery
            .as_mut()
            .unwrap()
            .encryption_public_key = [0x92; 32];
        assert_eq!(
            host.create_agent(
                PrivateAgentCreate {
                    descriptor: &wrong_encryption,
                    nodes: &nodes,
                    recovery_recipient: recipient,
                    runtime_package: &runtime,
                    bootstrap_metadata: &fixture.bootstrap,
                },
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidDescriptor)
        );
    }

    #[test]
    fn authorized_runtime_application_reopens_and_exact_retry_is_byte_identical() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "authorized-application");
        let agent = create_agent(&mut host, &fixture);
        let revoked = fixture.nodes[1].identity.node;
        let control = signed_revoke_control(&host, agent, revoked);
        let (authority, request) = runtime_application_request(&fixture, &control, 40, 44);

        let first = {
            let mut runtime = host
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap();
            runtime.apply(&request).unwrap()
        };
        assert!(first.authenticated && first.durably_applied && first.durably_reopened);
        assert_eq!(first.control, request.control);
        assert_eq!(first.receipt, request.receipt);
        assert_eq!(first.issuance_ack, request.issuance_ack);
        assert!(!first.application_fact.is_empty());
        let binding = host.binding(agent).unwrap();
        assert_eq!(binding.epoch, 1);
        assert_eq!(binding.control_head, Some(control.commitment()));
        assert_eq!(host.agents[&agent].store.authorized_nodes().len(), 1);
        assert_eq!(
            host.agents[&agent].store.authorized_nodes()[0],
            fixture.nodes[0].identity
        );

        let sidecars = canonical_sidecars(&host, agent);
        let retry = {
            let mut runtime = host
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap();
            runtime.apply(&request).unwrap()
        };
        assert_eq!(retry, first);
        assert_eq!(canonical_sidecars(&host, agent), sidecars);

        drop(host);
        let mut reopened = reopen_host(&fixture, 0, "authorized-application");
        let restart_retry = {
            let mut runtime = reopened
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap();
            runtime.apply(&request).unwrap()
        };
        assert_eq!(restart_retry, first);
        assert_eq!(canonical_sidecars(&reopened, agent), sidecars);
    }

    #[test]
    fn authorized_runtime_application_recovers_every_physical_write_boundary() {
        let boundaries = [
            PrivateRuntimeApplicationStop::AfterDescriptorStaged,
            PrivateRuntimeApplicationStop::AfterRuntimeStaged,
            PrivateRuntimeApplicationStop::AfterBootstrapStaged,
            PrivateRuntimeApplicationStop::AfterStoreStagedArtifact,
            PrivateRuntimeApplicationStop::AfterStoreStagedIndex,
            PrivateRuntimeApplicationStop::AfterStorePending,
            PrivateRuntimeApplicationStop::AfterStoreArtifact,
            PrivateRuntimeApplicationStop::AfterStoreIndex,
            PrivateRuntimeApplicationStop::AfterStoreCommitted,
            PrivateRuntimeApplicationStop::AfterDescriptorPromoted,
            PrivateRuntimeApplicationStop::AfterRuntimePromoted,
            PrivateRuntimeApplicationStop::AfterBootstrapPromoted,
            PrivateRuntimeApplicationStop::AfterReopen,
        ];
        let fixture = fixture(2);
        for rotate in [false, true] {
            for (index, boundary) in boundaries.into_iter().enumerate() {
                let name = format!("authorized-boundary-{rotate}-{index}");
                let mut host = create_host(&fixture, 0, &name);
                let agent = create_agent(&mut host, &fixture);
                let control = if rotate {
                    signed_rotate_control(&host, agent)
                } else {
                    signed_revoke_control(&host, agent, fixture.nodes[1].identity.node)
                };
                let (authority, request) = runtime_application_request(&fixture, &control, 50, 55);
                let interrupted = {
                    let mut runtime = host
                        .runtime_application_adapter(authority, &TestAuthority)
                        .unwrap();
                    runtime.stop_after(boundary);
                    runtime.apply(&request)
                };
                assert_eq!(
                    interrupted,
                    Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted)),
                    "rotate {rotate}, boundary {boundary:?}"
                );
                drop(host);

                let mut reopened = reopen_host(&fixture, 0, &name);
                let result = {
                    let mut runtime = reopened
                        .runtime_application_adapter(authority, &TestAuthority)
                        .unwrap();
                    runtime.apply(&request).unwrap()
                };
                assert!(result.authenticated && result.durably_applied && result.durably_reopened);
                let binding = reopened.binding(agent).unwrap();
                assert_eq!(binding.epoch, 1, "rotate {rotate}, boundary {boundary:?}");
                assert_eq!(
                    binding.control_head,
                    Some(control.commitment()),
                    "rotate {rotate}, boundary {boundary:?}"
                );
                let expected_members = if rotate {
                    identities(&fixture)
                } else {
                    vec![fixture.nodes[0].identity.clone()]
                };
                assert_eq!(
                    reopened.agents[&agent].store.authorized_nodes(),
                    expected_members,
                    "rotate {rotate}, boundary {boundary:?}"
                );
            }
        }
    }

    #[test]
    fn completed_evidence_attachment_recovers_every_physical_write_boundary() {
        let boundaries = [
            PrivateRuntimeApplicationStop::AfterEvidenceStaged,
            PrivateRuntimeApplicationStop::AfterEvidencePending,
            PrivateRuntimeApplicationStop::AfterEvidencePublished,
            PrivateRuntimeApplicationStop::AfterEvidenceRetired,
            PrivateRuntimeApplicationStop::AfterEvidenceReopen,
        ];
        let fixture = fixture(2);
        for (index, boundary) in boundaries.into_iter().enumerate() {
            let name = format!("evidence-boundary-{index}");
            let mut host = create_host(&fixture, 0, &name);
            let agent = create_agent(&mut host, &fixture);
            let control = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
            let (authority, request) = runtime_application_request(&fixture, &control, 60, 64);
            let application_result = apply_runtime_request(&mut host, authority, &request).unwrap();
            let application = signed_test_application_ack(&fixture, &request, &application_result);
            let evidence_request = test_evidence_request(&request, &application);
            let expected = PrivateControlAuthorityEvidence::from_acknowledgements(
                &AuthorityOperationIssuanceAck::decode(&request.issuance_ack).unwrap(),
                &application,
            )
            .unwrap();
            let expected_wire = expected.encode().unwrap();
            let expected_commitment = expected.commitment().unwrap();
            let interrupted = {
                let mut runtime = host
                    .runtime_application_adapter(authority, &TestAuthority)
                    .unwrap();
                runtime.stop_after(boundary);
                runtime.persist_completed_evidence(&evidence_request)
            };
            assert_eq!(
                interrupted,
                Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted)),
                "boundary {boundary:?}"
            );
            drop(host);

            // Physical reopen accepts the crash-valid missing-evidence state
            // and reconciles any transaction whose intent was durable.
            let mut reopened = reopen_host(&fixture, 0, &name);
            assert_eq!(
                reopened.binding(agent).unwrap().control_head,
                Some(control.commitment())
            );
            let result = reopened
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap()
                .persist_completed_evidence(&evidence_request)
                .unwrap();
            assert!(result.authenticated && result.durably_persisted && result.durably_reopened);
            assert_eq!(result.evidence_commitment, expected_commitment);
            let entry = reopened.agents[&agent]
                .store
                .indexed_controls()
                .iter()
                .find(|entry| entry.commitment == control.commitment())
                .unwrap();
            assert_eq!(
                reopened.agents[&agent]
                    .store
                    .read_control_authority_evidence(entry)
                    .unwrap()
                    .as_deref(),
                Some(expected_wire.as_slice()),
                "boundary {boundary:?}"
            );
            let retry = reopened
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap()
                .persist_completed_evidence(&evidence_request)
                .unwrap();
            assert_eq!(retry, result);
        }
    }

    #[test]
    fn evidence_callback_rejects_every_exact_echo_and_signed_fact_substitution() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "evidence-substitutions");
        let agent = create_agent(&mut host, &fixture);
        let control = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
        let (authority, request) = runtime_application_request(&fixture, &control, 70, 74);
        let application_result = apply_runtime_request(&mut host, authority, &request).unwrap();
        let application = signed_test_application_ack(&fixture, &request, &application_result);
        let exact = test_evidence_request(&request, &application);
        let (_, key) = authority_target(&fixture);
        let applied_binding = host.binding(agent).unwrap();
        let applied_sidecars = canonical_sidecars(&host, agent);

        let mut cases = Vec::new();
        let mut candidate = exact.clone();
        candidate.route.runtime_deployment = DeploymentId([0xc1; 32]);
        cases.push(("route", candidate));
        let mut candidate = exact.clone();
        candidate.authority.system_agent = AgentId([0xc2; 32]);
        cases.push(("authority", candidate));
        let mut candidate = exact.clone();
        candidate.control.push(0);
        cases.push(("control frame", candidate));
        let mut candidate = exact.clone();
        let mut issuance = AuthorityOperationIssuanceAck::decode(&candidate.issuance_ack).unwrap();
        issuance.signature[0] ^= 1;
        candidate.issuance_ack = issuance.encode().unwrap();
        cases.push(("issuance signature", candidate));
        let mut candidate = exact.clone();
        let mut application =
            PrivateControlApplicationAck::decode(&candidate.application_ack).unwrap();
        application.signature[0] ^= 1;
        candidate.application_ack = application.encode().unwrap();
        cases.push(("application signature", candidate));
        for (label, mutate) in [
            ("application control", 0u8),
            ("application sequence", 1),
            ("application epoch", 2),
            ("application route", 3),
            ("application member set", 4),
        ] {
            let mut candidate = exact.clone();
            let mut issuance =
                AuthorityOperationIssuanceAck::decode(&candidate.issuance_ack).unwrap();
            let mut application =
                PrivateControlApplicationAck::decode(&candidate.application_ack).unwrap();
            match mutate {
                0 => {
                    application.application.control = Hash([0xc0; 32]);
                    application.application.reopened_control_head = application.application.control;
                    issuance.receipt.selector.request = application.application.control;
                }
                1 => {
                    application.application.control_sequence += 1;
                    application.application.control_previous = Some(Hash([0xc5; 32]));
                }
                2 => application.application.epoch += 1,
                3 => {
                    application.application.managed.runtime_deployment = DeploymentId([0xc3; 32]);
                    issuance.receipt.selector.runtime_deployment =
                        application.application.managed.runtime_deployment;
                }
                4 => application.application.post_member_set = Hash([0xc4; 32]),
                _ => unreachable!(),
            }
            if matches!(mutate, 0 | 3) {
                issuance.receipt.signature = key.sign(&issuance.receipt.signing_bytes()).to_bytes();
                issuance.signature = key.sign(&issuance.signing_bytes()).to_bytes();
                candidate.issuance_ack = issuance.encode().unwrap();
                application.receipt = issuance.receipt.clone();
                application.issuance_ack = issuance.commitment();
                application.application_invocation =
                    PrivateControlApplicationAck::derive_application_invocation(&issuance);
            }
            application.signature = key.sign(&application.signing_bytes()).to_bytes();
            candidate.application_ack = application.encode().unwrap();
            cases.push((label, candidate));
        }

        for (label, candidate) in cases {
            assert!(
                host.runtime_application_adapter(authority, &TestAuthority)
                    .unwrap()
                    .persist_completed_evidence(&candidate)
                    .is_err(),
                "{label}"
            );
            let entry = &host.agents[&agent].store.indexed_controls()[0];
            assert_eq!(
                host.agents[&agent]
                    .store
                    .read_control_authority_evidence(entry)
                    .unwrap(),
                None,
                "{label}"
            );
            assert_eq!(host.binding(agent).unwrap(), applied_binding, "{label}");
            assert_eq!(
                canonical_sidecars(&host, agent),
                applied_sidecars,
                "{label}"
            );
            let stage = host.agent_path(agent).join(STORE_DIRECTORY).join("stage");
            assert!(
                fs::read_dir(stage).unwrap().all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("control-authority-evidence")),
                "{label}"
            );
        }

        host.runtime_application_adapter(authority, &TestAuthority)
            .unwrap()
            .persist_completed_evidence(&exact)
            .unwrap();
    }

    #[test]
    fn authority_evidence_survives_encrypted_backup_restore_and_sync_restart() {
        let fixture = fixture(2);
        let mut source = create_host(&fixture, 0, "evidence-backup-source");
        let agent = create_agent(&mut source, &fixture);
        let control = signed_revoke_control(&source, agent, fixture.nodes[1].identity.node);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &control, 80, 84);
        let backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        assert!(!contains(&backup, SENTINEL));

        let mut restored = create_host(&fixture, 0, "evidence-backup-restored");
        restored
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
        drop(restored);
        let restored = reopen_host(&fixture, 0, "evidence-backup-restored");
        let request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(fixture.space, agent, 0, None).unwrap(),
            max_items: MAX_PRIVATE_SYNC_ITEMS as u16,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        let page = restored
            .serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &request.encode().unwrap(),
                authority_target(&fixture).0,
                &TestTransport,
            )
            .unwrap();
        assert!(!contains(&page, SENTINEL));
        let page = PrivateSyncPage::decode(&page).unwrap();
        let PrivateSyncItem::Control { evidence, .. } = &page.items[0] else {
            unreachable!()
        };
        let decoded = PrivateControlAuthorityEvidence::decode(evidence).unwrap();
        decoded
            .verify_for(
                &control,
                1,
                ManagedAgentTarget {
                    space: fixture.space,
                    agent,
                    runtime_deployment: fixture.descriptor.identity.runtime_deployment,
                },
                authority_target(&fixture).0,
            )
            .unwrap();
    }

    #[test]
    fn authorized_runtime_application_rejects_every_evidence_and_transition_substitution() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "authorized-substitutions");
        let agent = create_agent(&mut host, &fixture);
        let original = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
        let alternate = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
        assert_ne!(original.commitment(), alternate.commitment());
        let (authority, request) = runtime_application_request(&fixture, &original, 40, 44);
        let (_, alternate_request) = runtime_application_request(&fixture, &alternate, 40, 44);
        let initial_binding = host.binding(agent).unwrap();
        let initial_sidecars = canonical_sidecars(&host, agent);

        let mut cases = Vec::new();
        let mut candidate = request.clone();
        candidate.route.space = SpaceId([0xb1; 32]);
        cases.push(("route space", candidate));
        let mut candidate = request.clone();
        candidate.route.agent = AgentId([0xb2; 32]);
        cases.push(("route agent", candidate));
        let mut candidate = request.clone();
        candidate.route.runtime_deployment = DeploymentId([0xb3; 32]);
        cases.push(("runtime", candidate));
        let mut candidate = request.clone();
        candidate.authority.system_agent = AgentId([0xb4; 32]);
        cases.push(("authority target", candidate));
        let mut candidate = request.clone();
        candidate.control.push(0);
        cases.push(("noncanonical control", candidate));
        let mut candidate = request.clone();
        candidate.control = alternate_request.control.clone();
        cases.push(("control preimage", candidate));
        let mut candidate = request.clone();
        candidate.receipt.push(0);
        cases.push(("noncanonical receipt", candidate));
        let mut candidate = request.clone();
        candidate.receipt = alternate_request.receipt.clone();
        cases.push(("receipt preimage", candidate));
        let mut candidate = request.clone();
        candidate.issuance_ack.push(0);
        cases.push(("noncanonical issuance", candidate));
        let mut candidate = request.clone();
        candidate.issuance_ack = alternate_request.issuance_ack.clone();
        cases.push(("issuance preimage", candidate));
        let mut candidate = request.clone();
        candidate.applied_at = 39;
        cases.push(("slot before issuance", candidate));
        let mut candidate = request.clone();
        candidate.applied_at = 145;
        cases.push(("slot after expiry", candidate));
        let mut candidate = request.clone();
        candidate.control = vec![0; vos_agent_sdk::wire::MAX_PRIVATE_CONTROL_WIRE_BYTES + 1];
        cases.push(("oversize control", candidate));

        let mut invalid_signature = original.clone();
        invalid_signature.signature[0] ^= 1;
        let (_, candidate) = runtime_application_request(&fixture, &invalid_signature, 40, 44);
        cases.push(("control signature", candidate));

        let mut wrong_position = original.clone();
        wrong_position.sequence = 1;
        wrong_position.previous = Some(Hash([0xb5; 32]));
        sign_owner_control_record(&mut wrong_position, &host.hosted(agent).unwrap().owner_key)
            .unwrap();
        let (_, candidate) = runtime_application_request(&fixture, &wrong_position, 40, 44);
        cases.push(("head and sequence", candidate));

        let mut wrong_epoch = original.clone();
        let PrivateControlOperation::Revoke { next_epoch, .. } = &mut wrong_epoch.operation else {
            unreachable!();
        };
        next_epoch.epoch += 1;
        sign_owner_control_record(&mut wrong_epoch, &host.hosted(agent).unwrap().owner_key)
            .unwrap();
        let (_, candidate) = runtime_application_request(&fixture, &wrong_epoch, 40, 44);
        cases.push(("epoch", candidate));

        let mut local_revoke = original.clone();
        let PrivateControlOperation::Revoke { node, .. } = &mut local_revoke.operation else {
            unreachable!();
        };
        *node = fixture.nodes[0].identity.node;
        sign_owner_control_record(&mut local_revoke, &host.hosted(agent).unwrap().owner_key)
            .unwrap();
        let (_, candidate) = runtime_application_request(&fixture, &local_revoke, 40, 44);
        cases.push(("member transition", candidate));

        let mut wrong_owner = original.clone();
        let wrong_owner_key = SigningKey::from_bytes(&[0xb6; 32]);
        wrong_owner.signer_public_key = wrong_owner_key.verifying_key().to_bytes();
        wrong_owner.signature = wrong_owner_key
            .sign(&wrong_owner.signing_bytes())
            .to_bytes();
        let (_, candidate) = runtime_application_request(&fixture, &wrong_owner, 40, 44);
        cases.push(("owner signer", candidate));

        let next_epoch = match &original.operation {
            PrivateControlOperation::Revoke { next_epoch, .. } => next_epoch.clone(),
            _ => unreachable!(),
        };
        let unsupported = [
            PrivateControlOperation::RotateKeys { next_epoch },
            PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(b"private-resource-policy"),
            },
            PrivateControlOperation::ActorLifecycle {
                actor: ActorId([0xb7; 32]),
                operation: PrivateActorLifecycleKind::Install,
                request: Hash([0xb8; 32]),
            },
        ];
        for operation in unsupported {
            let mut control = unsigned_owner_record(host.hosted(agent).unwrap(), operation);
            sign_owner_control_record(&mut control, &host.hosted(agent).unwrap().owner_key)
                .unwrap();
            let mut candidate = request.clone();
            candidate.control = control.encode().unwrap();
            cases.push(("cross-operation control", candidate));
        }

        for (label, candidate) in cases {
            assert!(
                apply_runtime_request(&mut host, authority, &candidate).is_err(),
                "accepted {label} substitution"
            );
            assert_eq!(
                host.binding(agent).unwrap(),
                initial_binding,
                "case {label}"
            );
            assert_eq!(
                canonical_sidecars(&host, agent),
                initial_sidecars,
                "case {label}"
            );
        }

        let mut wrong_configured_authority = authority;
        wrong_configured_authority.system_runtime_deployment = DeploymentId([0xb9; 32]);
        assert!(apply_runtime_request(&mut host, wrong_configured_authority, &request).is_err());
        assert_eq!(host.binding(agent).unwrap(), initial_binding);

        // A second internally consistent signer/binding in the same Space is
        // not the authority pinned by this Agent descriptor.
        let alternate_key = SigningKey::from_bytes(&[0xbb; 32]);
        let mut alternate_authority = authority;
        alternate_authority.binding.policy = Hash([0xbc; 32]);
        alternate_authority.binding.public_key = alternate_key.verifying_key().to_bytes();
        alternate_authority.binding.issuer.producer =
            ProducerId::of_public_key(&alternate_authority.binding.public_key);
        let mut alternate_receipt = AuthorityReceipt::decode(&request.receipt).unwrap();
        alternate_receipt.selector.policy = alternate_authority.binding.policy;
        alternate_receipt.selector.issuer = alternate_authority.binding.issuer;
        alternate_receipt.public_key = alternate_authority.binding.public_key;
        alternate_receipt.signature = [0; 64];
        alternate_receipt.signature = alternate_key
            .sign(&alternate_receipt.signing_bytes())
            .to_bytes();
        let mut alternate_issuance =
            AuthorityOperationIssuanceAck::decode(&request.issuance_ack).unwrap();
        alternate_issuance.authority = alternate_authority;
        alternate_issuance.receipt = alternate_receipt.clone();
        alternate_issuance.signature = [0; 64];
        alternate_issuance.signature = alternate_key
            .sign(&alternate_issuance.signing_bytes())
            .to_bytes();
        let mut alternate_request = request.clone();
        alternate_request.authority = alternate_authority;
        alternate_request.receipt = alternate_receipt.encode().unwrap();
        alternate_request.issuance_ack = alternate_issuance.encode().unwrap();
        assert!(apply_runtime_request(&mut host, alternate_authority, &alternate_request).is_err());
        assert_eq!(host.binding(agent).unwrap(), initial_binding);

        let result = apply_runtime_request(&mut host, authority, &request).unwrap();
        assert!(result.authenticated && result.durably_applied && result.durably_reopened);
    }

    #[test]
    fn authorized_rotation_is_restartable_and_unimplemented_controls_fail_closed() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "authorized-private-controls");
        let agent = create_agent(&mut host, &fixture);
        let initial_binding = host.binding(agent).unwrap();
        let initial_members = host.agents[&agent].store.authorized_nodes().to_vec();
        let initial_sidecars = canonical_sidecars(&host, agent);

        // Rotation is exactly the next epoch and may not rewrite membership.
        let skipped_epoch = signed_rotate_control_for(&host, agent, &initial_members, 2);
        let (authority, skipped_epoch_request) =
            runtime_application_request(&fixture, &skipped_epoch, 40, 44);
        assert!(apply_runtime_request(&mut host, authority, &skipped_epoch_request).is_err());
        let wrong_members = vec![fixture.nodes[0].identity.clone()];
        let changed_members = signed_rotate_control_for(&host, agent, &wrong_members, 1);
        let (_, changed_members_request) =
            runtime_application_request(&fixture, &changed_members, 40, 44);
        assert!(apply_runtime_request(&mut host, authority, &changed_members_request).is_err());
        assert_eq!(host.binding(agent).unwrap(), initial_binding);
        assert_eq!(
            host.agents[&agent].store.authorized_nodes(),
            initial_members
        );
        assert_eq!(canonical_sidecars(&host, agent), initial_sidecars);

        let rotate = signed_rotate_control(&host, agent);
        let (_, rotate_request) = runtime_application_request(&fixture, &rotate, 40, 44);
        let rotate_receipt = AuthorityReceipt::decode(&rotate_request.receipt).unwrap();
        assert_eq!(
            rotate_receipt.selector.operation,
            AuthorityOperationKind::RotatePrivateKeys
        );
        assert_eq!(rotate_receipt.selector.actor, None);
        assert_eq!(rotate_receipt.selector.actor_deployment, None);
        let rotate_result = apply_runtime_request(&mut host, authority, &rotate_request).unwrap();
        let rotate_fact = decode_private_application_fact(&rotate_result.application_fact).unwrap();
        let rotated_member_set =
            private_member_set_commitment(initial_members.iter().map(|node| node.node)).unwrap();
        assert_eq!(
            rotate_fact.operation,
            AuthorityOperationKind::RotatePrivateKeys
        );
        assert_eq!(rotate_fact.control, rotate.commitment());
        assert_eq!(rotate_fact.epoch, 1);
        assert_eq!(rotate_fact.post_member_set, rotated_member_set);
        assert_eq!(host.binding(agent).unwrap().epoch, 1);
        assert_eq!(
            host.agents[&agent].store.authorized_nodes(),
            initial_members
        );
        assert_eq!(host.agents[&agent].store.key_epochs().len(), 2);
        let rotated_sidecars = canonical_sidecars(&host, agent);
        assert_ne!(rotated_sidecars, initial_sidecars);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &rotate_request).unwrap(),
            rotate_result
        );
        assert_eq!(canonical_sidecars(&host, agent), rotated_sidecars);

        drop(host);
        let mut host = reopen_host(&fixture, 0, "authorized-private-controls");
        assert_eq!(
            apply_runtime_request(&mut host, authority, &rotate_request).unwrap(),
            rotate_result
        );

        // A resource-policy PCTL cannot be reported as applied until the host
        // has a durable policy application/reopen implementation.
        let mut resource = unsigned_owner_record(
            host.hosted(agent).unwrap(),
            PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(b"private-resource-policy-v1"),
            },
        );
        sign_owner_control_record(&mut resource, &host.hosted(agent).unwrap().owner_key).unwrap();
        let (_, resource_request) = runtime_application_request(&fixture, &resource, 50, 54);
        let before_resource = host.binding(agent).unwrap();
        let before_resource_sidecars = canonical_sidecars(&host, agent);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &resource_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(host.binding(agent).unwrap(), before_resource);
        assert_eq!(canonical_sidecars(&host, agent), before_resource_sidecars);

        // A lifecycle PCTL carries only the committed request hash. It cannot
        // mutate or reopen an actor forest without the exact request bytes and
        // a durable runtime image.
        let actor = ActorId([0xb7; 32]);
        let lifecycle_request_hash = Hash([0xb8; 32]);
        let mut lifecycle = unsigned_owner_record(
            host.hosted(agent).unwrap(),
            PrivateControlOperation::ActorLifecycle {
                actor,
                operation: PrivateActorLifecycleKind::Install,
                request: lifecycle_request_hash,
            },
        );
        sign_owner_control_record(&mut lifecycle, &host.hosted(agent).unwrap().owner_key).unwrap();
        let (_, lifecycle_request) = runtime_application_request(&fixture, &lifecycle, 60, 64);
        let lifecycle_receipt = AuthorityReceipt::decode(&lifecycle_request.receipt).unwrap();
        assert_eq!(
            lifecycle_receipt.selector.operation,
            AuthorityOperationKind::PrivateActorLifecycle
        );
        assert_eq!(lifecycle_receipt.selector.actor, Some(actor));
        assert_eq!(lifecycle_receipt.selector.actor_deployment, None);

        let before_lifecycle = host.binding(agent).unwrap();
        let before_lifecycle_sidecars = canonical_sidecars(&host, agent);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &lifecycle_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(host.binding(agent).unwrap(), before_lifecycle);
        assert_eq!(canonical_sidecars(&host, agent), before_lifecycle_sidecars);

        drop(host);
        let mut reopened = reopen_host(&fixture, 0, "authorized-private-controls");
        assert_eq!(
            apply_runtime_request(&mut reopened, authority, &resource_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            apply_runtime_request(&mut reopened, authority, &lifecycle_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(reopened.binding(agent).unwrap(), before_lifecycle);
        assert_eq!(
            reopened.agents[&agent].store.authorized_nodes(),
            initial_members
        );
        assert_eq!(
            canonical_sidecars(&reopened, agent),
            before_lifecycle_sidecars
        );
    }

    #[test]
    fn authorized_invite_requires_exact_authority_enrolled_node_binding() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "authorized-invite");
        let agent = create_agent(&mut host, &fixture);
        let valid_node = node(fixture.space, fixture.owner, 99).identity;
        let valid_control = signed_invite_control(&host, agent, valid_node.clone());
        let (authority, request) = runtime_application_request(&fixture, &valid_control, 60, 65);

        let mut unauthoritative_node = valid_node;
        unauthoritative_node.authority_binding = Hash([0xba; 32]);
        let rejected = signed_invite_control(&host, agent, unauthoritative_node);
        let (_, rejected_request) = runtime_application_request(&fixture, &rejected, 60, 65);
        assert!(apply_runtime_request(&mut host, authority, &rejected_request).is_err());
        assert_eq!(host.binding(agent).unwrap().next_sequence, 0);

        let result = apply_runtime_request(&mut host, authority, &request).unwrap();
        assert!(result.durably_reopened);
        assert_eq!(host.binding(agent).unwrap().epoch, 0);
        assert_eq!(
            host.binding(agent).unwrap().control_head,
            Some(valid_control.commitment())
        );
        assert_eq!(host.agents[&agent].store.authorized_nodes().len(), 2);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &request).unwrap(),
            result
        );
    }

    #[test]
    fn authorized_existing_host_recovery_reopens_exact_replacement_and_history() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "authorized-recovery");
        let agent = create_agent(&mut host, &fixture);
        let revoke = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
        let (authority, revoke_request) = runtime_application_request(&fixture, &revoke, 70, 75);
        apply_runtime_request(&mut host, authority, &revoke_request).unwrap();

        let replacements = identities(&fixture);
        let recovery = signed_recovery_control(&host, agent, &replacements, &fixture.recovery);
        let (_, recovery_request) = runtime_application_request(&fixture, &recovery, 80, 85);
        let result = apply_runtime_request(&mut host, authority, &recovery_request).unwrap();
        assert!(result.authenticated && result.durably_applied && result.durably_reopened);
        let binding = host.binding(agent).unwrap();
        assert_eq!(binding.epoch, 2);
        assert_eq!(binding.control_head, Some(recovery.commitment()));
        assert_eq!(host.agents[&agent].store.authorized_nodes(), replacements);
        assert_eq!(host.agents[&agent].data_keys.len(), 3);

        drop(host);
        let mut reopened = reopen_host(&fixture, 0, "authorized-recovery");
        assert_eq!(
            apply_runtime_request(&mut reopened, authority, &recovery_request).unwrap(),
            result
        );
        assert_eq!(reopened.agents[&agent].data_keys.len(), 3);
    }

    #[test]
    fn authorized_genesis_head_recovery_is_exact_and_restart_safe() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "authorized-genesis-recovery");
        let agent = create_agent(&mut host, &fixture);
        let replacements = identities(&fixture);
        let recovery = signed_recovery_control(&host, agent, &replacements, &fixture.recovery);
        assert_eq!(recovery.previous, None);
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &recovery.operation
        else {
            unreachable!();
        };
        assert!(superseded_heads.is_empty());
        let (authority, request) = runtime_application_request(&fixture, &recovery, 90, 95);
        let result = apply_runtime_request(&mut host, authority, &request).unwrap();
        assert_eq!(host.binding(agent).unwrap().epoch, 1);
        assert_eq!(
            host.binding(agent).unwrap().control_head,
            Some(recovery.commitment())
        );
        drop(host);

        let mut reopened = reopen_host(&fixture, 0, "authorized-genesis-recovery");
        assert_eq!(
            apply_runtime_request(&mut reopened, authority, &request).unwrap(),
            result
        );
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
                    authority_target(&fixture).0,
                    &TestTransport,
                )
                .unwrap();
            assert!(!contains(&page_bytes, SENTINEL));
            let page = PrivateSyncPage::decode(&page_bytes).unwrap();
            peer.apply_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &page_bytes,
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::Unauthorized)
        );
        assert_eq!(
            primary.serve_sync_page(
                agent,
                PrivatePeerIdentity::Credential(CredentialId([77; 32])),
                malformed,
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
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
    fn post_history_invite_gets_every_prior_epoch_and_reopens() {
        let fixture = fixture(1);
        let invited = node(fixture.space, fixture.owner, 99);
        let mut primary = create_host(&fixture, 0, "late-invite-primary");
        let agent = create_agent(&mut primary, &fixture);
        let epoch_zero = primary
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, b"epoch-zero")
            .unwrap();
        primary.rotate_keys(agent, &TestAuthority).unwrap();
        let epoch_one = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Blob, b"epoch-one")
            .unwrap();
        primary.rotate_keys(agent, &TestAuthority).unwrap();
        let current = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Snapshot, b"epoch-two")
            .unwrap();
        drop(primary);
        let mut primary = PrivateAgentHost::open(
            fixture.directory.child("late-invite-primary"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        primary
            .invite_node(agent, invited.identity.clone(), &TestAuthority)
            .unwrap();
        let invites = primary.agents[&agent]
            .store
            .invite_history_records(&invited.identity)
            .unwrap();
        let PrivateControlOperation::Invite {
            historical_grants,
            epoch,
            ..
        } = &invites[0].operation
        else {
            panic!("expected Invite");
        };
        assert_eq!(*epoch, 2);
        assert_eq!(
            historical_grants
                .iter()
                .map(|grant| grant.epoch)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
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
        assert_eq!(invited_host.agents[&agent].data_keys.len(), 3);
        for (key, expected) in [
            (epoch_zero, b"epoch-zero".as_slice()),
            (epoch_one, b"epoch-one".as_slice()),
            (current, b"epoch-two".as_slice()),
        ] {
            assert_eq!(
                invited_host.get_and_decrypt(agent, key).unwrap().as_slice(),
                expected
            );
        }
        let post_invite = primary
            .encrypt_and_put(agent, EncryptedObjectKind::Package, b"post-invite-sync")
            .unwrap();
        let binding = invited_host.binding(agent).unwrap();
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
            let page_bytes = primary
                .serve_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&invited.identity),
                    &request.encode().unwrap(),
                    authority_target(&fixture).0,
                    &TestTransport,
                )
                .unwrap();
            let page = PrivateSyncPage::decode(&page_bytes).unwrap();
            invited_host
                .apply_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                    &page_bytes,
                    authority_target(&fixture).0,
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
            invited_host
                .get_and_decrypt(agent, post_invite)
                .unwrap()
                .as_slice(),
            b"post-invite-sync"
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
        assert_eq!(invited_host.agents[&agent].data_keys.len(), 3);
        assert_eq!(
            invited_host
                .get_and_decrypt(agent, epoch_zero)
                .unwrap()
                .as_slice(),
            b"epoch-zero"
        );

        let invited_epoch_key = &invited_host.agents[&agent].data_keys[&2];
        primary
            .revoke_node(agent, invited.identity.node, &TestAuthority)
            .unwrap();
        let future = primary
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, b"after-revocation")
            .unwrap();
        assert_eq!(future.epoch, 3);
        assert!(
            decrypt_private_object(
                invited_epoch_key,
                &primary.get_encrypted_object(agent, future).unwrap(),
            )
            .is_err()
        );
        assert!(!invited_host.agents[&agent].data_keys.contains_key(&3));
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
        let first =
            signed_recovery_control(&source, agent, &identities(&fixture), &fixture.recovery);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &first, 40, 41);
        let second =
            signed_recovery_control(&source, agent, &identities(&fixture), &fixture.recovery);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &second, 42, 43);

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
                authority_target(&fixture).0,
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
        let recovery =
            signed_recovery_control(&source, agent, &identities(&fixture), &fixture.recovery);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &recovery, 40, 41);

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
                authority_target(&fixture).0,
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
                authority_target(&fixture).0,
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
    fn divergent_backups_union_deterministically_and_resume_across_publish_phases() {
        let fixture = fixture(2);
        let mut left = create_host(&fixture, 0, "union-left");
        let agent = create_agent(&mut left, &fixture);
        let base = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let mut right = create_host(&fixture, 1, "union-right");
        right
            .restore_encrypted_backup(
                agent,
                DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                &base,
                &TestAuthority,
            )
            .unwrap();

        left.record_actor_lifecycle(
            agent,
            ActorId([0x41; 32]),
            PrivateActorLifecycleKind::Install,
            Hash([0x42; 32]),
            &TestAuthority,
        )
        .unwrap();
        right
            .record_actor_lifecycle(
                agent,
                ActorId([0x43; 32]),
                PrivateActorLifecycleKind::Install,
                Hash([0x44; 32]),
                &TestAuthority,
            )
            .unwrap();
        let left_head = left.binding(agent).unwrap().control_head.unwrap();
        let right_head = right.binding(agent).unwrap().control_head.unwrap();
        assert_ne!(left_head, right_head);
        let selected_head = left_head.max(right_head);
        let mut expected_heads = vec![left_head, right_head];
        expected_heads.sort_unstable();

        let left_object = left
            .encrypt_and_put(agent, EncryptedObjectKind::CrdtNode, b"left-fork-object")
            .unwrap();
        let right_object = right
            .encrypt_and_put(agent, EncryptedObjectKind::Snapshot, b"right-fork-object")
            .unwrap();
        let left_backup = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let right_backup = right
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        drop(left);
        drop(right);

        let replacement = node(fixture.space, fixture.owner, 111);
        let replacements = vec![replacement.identity.clone()];
        let ordered = [left_backup.as_slice(), right_backup.as_slice()];
        let reversed = [right_backup.as_slice(), left_backup.as_slice()];

        // The canonical source-set commitment is order independent, so an
        // exact retry can resume the same random recovery plan with the input
        // archives presented in the opposite order.
        let retry_root = fixture.directory.child("union-retry");
        let mut retry_host = PrivateAgentHost::create(
            &retry_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            retry_host.recover_from_encrypted_backups_with_stop(
                agent,
                &recovery_kit(),
                &replacements,
                &ordered,
                &TestAuthority,
                RecoveryInstallStop::AfterPlan,
            ),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
        );
        let plan_path = retry_host.creating_path(agent).join(RECOVERY_PLAN_FILE);
        let exact_plan = fs::read(&plan_path).unwrap();
        assert_eq!(
            retry_host.recover_from_encrypted_backups_with_stop(
                agent,
                &recovery_kit(),
                &replacements,
                &reversed,
                &TestAuthority,
                RecoveryInstallStop::AfterStore,
            ),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
        );
        assert_eq!(fs::read(&plan_path).unwrap(), exact_plan);
        drop(retry_host);

        let mut roots = vec![retry_root];
        for (position, stop) in [
            RecoveryInstallStop::AfterDescriptor,
            RecoveryInstallStop::AfterVerification,
            RecoveryInstallStop::AfterPublish,
        ]
        .into_iter()
        .enumerate()
        {
            let root = fixture.directory.child(&format!("union-stop-{position}"));
            let mut host = PrivateAgentHost::create(
                &root,
                fixture.space,
                fixture.owner,
                replacement.identity.clone(),
                replacement.key(),
            )
            .unwrap();
            let sources = if position % 2 == 0 {
                &ordered[..]
            } else {
                &reversed[..]
            };
            assert_eq!(
                host.recover_from_encrypted_backups_with_stop(
                    agent,
                    &recovery_kit(),
                    &replacements,
                    sources,
                    &TestAuthority,
                    stop,
                ),
                Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
            );
            drop(host);
            roots.push(root);
        }

        for root in roots {
            let reopened = PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                replacement.identity.clone(),
                replacement.key(),
                &TestAuthority,
            )
            .unwrap();
            let binding = reopened.binding(agent).unwrap();
            assert_eq!(binding.epoch, 1);
            assert_eq!(binding.next_sequence, 2);
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, left_object)
                    .unwrap()
                    .as_slice(),
                b"left-fork-object"
            );
            assert_eq!(
                reopened
                    .get_and_decrypt(agent, right_object)
                    .unwrap()
                    .as_slice(),
                b"right-fork-object"
            );
            let controls = reopened.agents[&agent].store.indexed_controls();
            assert_eq!(controls.len(), 2);
            assert_eq!(controls[0].commitment, selected_head);
            let recovery = PrivateControlRecord::decode(
                &reopened.agents[&agent]
                    .store
                    .read_control_wire(controls.last().unwrap())
                    .unwrap(),
            )
            .unwrap();
            let PrivateControlOperation::Recover {
                superseded_heads, ..
            } = recovery.operation
            else {
                panic!("union did not finish with an offline recovery record")
            };
            assert_eq!(superseded_heads, expected_heads);
        }
    }

    #[test]
    fn backup_union_rejects_aliases_incompatible_epochs_cross_scope_and_bounds() {
        let fixture = fixture(2);
        let mut left = create_host(&fixture, 0, "hostile-union-left");
        let agent = create_agent(&mut left, &fixture);
        let base = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let mut right = create_host(&fixture, 1, "hostile-union-right");
        right
            .restore_encrypted_backup(
                agent,
                DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                &base,
                &TestAuthority,
            )
            .unwrap();

        // Equal semantic object identities with distinct canonical
        // ciphertexts are equivocation, not a caller-order tie break.
        let left_alias = left
            .encrypt_and_put(agent, EncryptedObjectKind::Blob, b"same-semantic-object")
            .unwrap();
        let right_alias = right
            .encrypt_and_put(agent, EncryptedObjectKind::Blob, b"same-semantic-object")
            .unwrap();
        assert_eq!(left_alias, right_alias);
        let left_alias_backup = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let right_alias_backup = right
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();

        let replacement = node(fixture.space, fixture.owner, 112);
        let replacements = vec![replacement.identity.clone()];
        let hostile_root = fixture.directory.child("hostile-union-target");
        let mut hostile = PrivateAgentHost::create(
            &hostile_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            hostile.recover_from_encrypted_backups(
                agent,
                &recovery_kit(),
                &replacements,
                &[left_alias_backup.as_slice(), right_alias_backup.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Alias)
        );
        assert!(!hostile.creating_path(agent).exists());
        assert_eq!(
            hostile.recover_from_encrypted_backups(
                agent,
                &recovery_kit(),
                &replacements,
                &[left_alias_backup.as_slice(), left_alias_backup.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Alias)
        );

        let mut cross_scope = decode_host_archive(&left_alias_backup, true).unwrap();
        cross_scope.space = SpaceId([0xE1; 32]);
        let cross_scope =
            encode_host_archive(&cross_scope, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES).unwrap();
        assert_eq!(
            hostile.recover_from_encrypted_backups(
                agent,
                &recovery_kit(),
                &replacements,
                &[left_alias_backup.as_slice(), cross_scope.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidScope)
        );
        let too_many = vec![base.as_slice(); MAX_PRIVATE_NODES + 1];
        assert_eq!(
            hostile.recover_from_encrypted_backups(
                agent,
                &recovery_kit(),
                &replacements,
                &too_many,
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::LimitExceeded)
        );
        assert!(!hostile.creating_path(agent).exists());
        drop(hostile);

        // Independent rotations from the same head assign different exact
        // key material to epoch one. No retained control path can represent
        // both histories, so the ceremony must reject the fork.
        left.rotate_keys(agent, &TestAuthority).unwrap();
        right.rotate_keys(agent, &TestAuthority).unwrap();
        assert_ne!(
            left.agents[&agent].store.key_epoch().data_key_commitment,
            right.agents[&agent].store.key_epoch().data_key_commitment
        );
        let left_rotated = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let right_rotated = right
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let incompatible_root = fixture.directory.child("incompatible-union-target");
        let mut incompatible = PrivateAgentHost::create(
            &incompatible_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            incompatible.recover_from_encrypted_backups(
                agent,
                &recovery_kit(),
                &replacements,
                &[left_rotated.as_slice(), right_rotated.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Diverged))
        );
        assert!(!incompatible.creating_path(agent).exists());
        drop(incompatible);

        // A stale prefix may contribute to the authenticated set, but it
        // cannot lower either the successor epoch or control sequence.
        let rollback_root = fixture.directory.child("rollback-union-target");
        let mut rollback = PrivateAgentHost::create(
            &rollback_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        rollback
            .recover_from_encrypted_backups(
                agent,
                &recovery_kit(),
                &replacements,
                &[base.as_slice(), left_rotated.as_slice()],
                &TestAuthority,
            )
            .unwrap();
        let binding = rollback.binding(agent).unwrap();
        assert_eq!(binding.epoch, 2);
        assert_eq!(binding.next_sequence, 2);
        assert_eq!(
            rollback
                .get_and_decrypt(agent, left_alias)
                .unwrap()
                .as_slice(),
            b"same-semantic-object"
        );
        drop(rollback);
        let reopened = PrivateAgentHost::open(
            &rollback_root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.binding(agent).unwrap().epoch, 2);
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
            forged_object_host.recover_from_encrypted_backups(
                agent,
                &audit_kit,
                &replacements,
                &[backup.as_slice(), forged_object_backup.as_slice()],
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
    fn recovery_successor_can_late_invite_complete_prior_history() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "recovery-invite-source");
        let agent = create_agent(&mut source, &fixture);
        let epoch_zero = source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"before-recovery-zero",
            )
            .unwrap();
        source.rotate_keys(agent, &TestAuthority).unwrap();
        let epoch_one = source
            .encrypt_and_put(agent, EncryptedObjectKind::Blob, b"before-recovery-one")
            .unwrap();
        let source_backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        drop(source);

        let replacement = node(fixture.space, fixture.owner, 121);
        let mut recovered = PrivateAgentHost::create(
            fixture.directory.child("recovery-invite-owner"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        recovered
            .recover_from_encrypted_backup(
                agent,
                &recovery_kit(),
                core::slice::from_ref(&replacement.identity),
                &source_backup,
                &TestAuthority,
            )
            .unwrap();
        assert_eq!(recovered.binding(agent).unwrap().epoch, 2);

        let invited = node(fixture.space, fixture.owner, 122);
        recovered
            .invite_node(agent, invited.identity.clone(), &TestAuthority)
            .unwrap();
        let backup = recovered
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let invited_root = fixture.directory.child("recovery-invite-peer");
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
        for (key, expected) in [
            (epoch_zero, b"before-recovery-zero".as_slice()),
            (epoch_one, b"before-recovery-one".as_slice()),
        ] {
            assert_eq!(
                invited_host.get_and_decrypt(agent, key).unwrap().as_slice(),
                expected
            );
        }
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
        assert_eq!(invited_host.agents[&agent].data_keys.len(), 3);
        assert_eq!(
            invited_host
                .get_and_decrypt(agent, epoch_zero)
                .unwrap()
                .as_slice(),
            b"before-recovery-zero"
        );
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
