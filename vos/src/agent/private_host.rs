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
use vos_agent_sdk::authority_operation::PrivateControlApplicationFact;
use vos_agent_sdk::authority_operation::{
    AuthorityOperationIntent, AuthorityOperationIssuanceAck,
    MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
    MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES,
    MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES, PrivateControlApplicationAck,
    PrivateRecoveryAuthorityProof, PrivateRecoveryAuthorityProofVerifier,
    private_member_set_commitment,
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
    CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES,
    MAX_PRIVATE_OBJECT_WIRE_BYTES, MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES,
};
use vos_agent_sdk::{
    ActorDescriptor, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, CredentialId, DeploymentId, Hash, LaneSet, ManagementRequest, NodeId, PrincipalId,
    PrivateRecoveryBinding, PrivateRuntimeMutation, ProducerId, ProgramId, ProofSystemSet,
    ReplicaRole, RuntimeCapabilities, RuntimeExecutionContext, RuntimeState, RuntimeTransition,
    RuntimeWork, SpaceId, StorageFieldDescriptor,
};
use zeroize::Zeroizing;

use super::authority_operation_issuer::private_intent_matches_application;
use super::driver::DEFAULT_MANAGEMENT_GAS;
use super::package_admission::{AdmittedRuntimePackage, admit_runtime_package};
#[cfg(test)]
use super::private_control_application_coordinator::decode_private_application_fact;
use super::private_control_application_coordinator::{
    PrivateControlRuntimeApplicationAdapter, PrivateControlRuntimeApplicationRequest,
    PrivateControlRuntimeApplicationResolution, PrivateControlRuntimeApplicationResult,
    PrivateControlRuntimeEvidenceRequest, PrivateControlRuntimeEvidenceResult,
    PrivateControlRuntimeRetirementResult, encode_private_application_fact,
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
use super::private_runtime::{
    MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES, PrivateControlReopenedState, PrivateKeyEpochCommitment,
    PrivateRuntimeApplication, PrivateRuntimeControlDisposition, PrivateRuntimeControlPosition,
    PrivateRuntimeImage, PrivateRuntimeSuccess, PrivateStoreCorePosition,
    classify_private_runtime_control_transition, validate_private_runtime_genesis_transition,
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
use super::runtime_pvm::execute_canonical_wire;

pub const MAX_PRIVATE_HOST_AGENTS: usize = 4_096;
pub const MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_PRIVATE_HOST_ARCHIVE_BYTES: usize = MAX_PRIVATE_BACKUP_BYTES + 32 * 1024 * 1024;

const FORMAT_VERSION: u16 = 2;
const HOST_ARCHIVE_VERSION: u16 = 3;
const ROOT_SCOPE_MAGIC: &[u8; 4] = b"PVHR";
const DESCRIPTOR_MAGIC: &[u8; 4] = b"PVHD";
const RUNTIME_MAGIC: &[u8; 4] = b"PVHP";
const BOOTSTRAP_MAGIC: &[u8; 4] = b"PVHM";
const BACKUP_MAGIC: &[u8; 4] = b"PVHB";
const SNAPSHOT_MAGIC: &[u8; 4] = b"PVHS";
const RECOVERY_PLAN_MAGIC: &[u8; 4] = b"PVRP";
const RECOVERY_PLAN_VERSION: u16 = 3;
const RECOVERY_PLAN_HASH_DOMAIN: &[u8] = b"vos/private/recovery-plan-bytes/v3";
const RECOVERY_SOURCE_ARCHIVE_HASH_DOMAIN: &[u8] = b"vos/private/recovery-source-archive/v2";
const RECOVERY_SOURCE_SET_HASH_DOMAIN: &[u8] = b"vos/private/recovery-source-set/v2";
const RECOVERY_REPLACEMENTS_DOMAIN: &[u8] = b"vos/private/recovery-replacements/v1";

const ROOT_SCOPE_FILE: &str = "scope";
const ROOT_LOCK_FILE: &str = "lock";
const CREATING_DIRECTORY: &str = ".creating";
const STORE_DIRECTORY: &str = "store";
const DESCRIPTOR_FILE: &str = "descriptor.enc";
const RUNTIME_FILE: &str = "runtime.enc";
const BOOTSTRAP_FILE: &str = "bootstrap.enc";
const RUNTIME_STATE_FILE: &str = "runtime-state.enc";
const NEXT_PREFIX: &str = ".next-";
const WRITE_SUFFIX: &str = ".write";
const RECOVERY_PLAN_FILE: &str = "recovery.plan";
const RECOVERY_PLAN_WRITE_FILE: &str = "recovery.plan.write";
const RETIRED_DUPLICATE_SUFFIX: &str = ".retired";
const SIDECAR_FILES: [&str; 3] = [DESCRIPTOR_FILE, RUNTIME_FILE, BOOTSTRAP_FILE];
const RECOVERY_PLAN_FIXED_BYTES: usize =
    4 + 2 + 32 + 8 * 32 + 5 * core::mem::size_of::<u32>() + 1 + 32 + 32;
const MAX_PRIVATE_RECOVERY_PLAN_BYTES: usize = MAX_PRIVATE_HOST_ARCHIVE_BYTES
    .saturating_add(MAX_PRIVATE_CONTROL_WIRE_BYTES)
    .saturating_add(MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES)
    .saturating_add(MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES)
    .saturating_add(MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES)
    .saturating_add(RECOVERY_PLAN_FIXED_BYTES);
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
    AfterStageDirectory,
    AfterPlanFile,
    AfterPlan,
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
    /// Exact descriptor-authority receipt authorizing the initial Create PVM
    /// invocation. It is retained verbatim in the genesis PVRI.
    pub creation_receipt: &'a AuthorityReceipt,
    /// Trusted host observation slot used to authenticate receipt liveness.
    /// The Direct Create PVM work and canonical PVRI use the receipt's signed
    /// `valid_from` slot instead.
    pub observed_at: u64,
}

/// Durable, ciphertext-only handoff from an offline recovery ceremony to the
/// normal authority-operation issuer and Private application coordinator.
/// Possession of this value is not authorization: the embedded intent still
/// has to cross AOC4/AOP4/AOI1 before the host will restore any staged files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedPrivateRecovery {
    route: ManagedAgentTarget,
    control_wire: Vec<u8>,
    proof: PrivateRecoveryAuthorityProof,
}

impl PreparedPrivateRecovery {
    pub(crate) const fn route(&self) -> ManagedAgentTarget {
        self.route
    }

    pub(crate) fn control_wire(&self) -> &[u8] {
        &self.control_wire
    }

    pub(crate) fn authorization_intent(
        &self,
    ) -> Result<AuthorityOperationIntent, PrivateAgentHostError> {
        AuthorityOperationIntent::private_recovery_control(self.proof.clone())
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)
    }
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
    runtime_image: PrivateRuntimeImage,
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
    management_gas: u64,
    agents: BTreeMap<AgentId, HostedPrivateAgent>,
}

/// Physical Private-runtime half of the authority pipeline.
///
/// Construction is crate-private because the caller must pair this adapter
/// with the durable operation issuer/coordinator and an exact system-authority
/// dispatcher. It accepts only the externally signed PCTL carried by the
/// coordinator request; it has no key-generation or control-signing API.
/// Runtime-backed controls execute only after canonical receipt, issuance,
/// control, mutation, Store-position, PKEY, and membership validation. A
/// positive transition stages its encrypted successor PVRI, atomically appends
/// PCTL plus completed PAPL, promotes the PVRI, and fully reopens. A
/// deterministic unchanged-state denial writes none of them.
pub(crate) struct PrivateAgentRuntimeApplication<'host, V> {
    host: &'host mut PrivateAgentHost,
    authority: AuthorityActorTarget,
    node_authority: &'host V,
    stop: PrivateRuntimeApplicationStop,
}

/// Test-only bridge for the pre-PCRS Store failpoint/recovery coverage.
///
/// This never exists in production and its synthetic proof bindings must not
/// be confused with evidence from a physical Private runtime lifecycle.
#[cfg(test)]
struct SyntheticLegacyPrivateRuntimeApplicationForTest<'host, V> {
    host: &'host mut PrivateAgentHost,
    authority: AuthorityActorTarget,
    node_authority: &'host V,
    stop: PrivateRuntimeApplicationStop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateRuntimeApplicationStop {
    Never,
    AfterRecoveryStore,
    AfterRecoveryDescriptor,
    AfterRecoveryRuntime,
    AfterRecoveryBootstrap,
    AfterRecoveryReopen,
    AfterRecoveryPlanWrite,
    AfterRecoveryPlanCommitted,
    AfterRecoveryPlanRetired,
    AfterRecoveryRename,
    AfterRecoveryDestinationSync,
    AfterRecoveryPublished,
    AfterDescriptorStaged,
    AfterRuntimeStaged,
    AfterBootstrapStaged,
    AfterRuntimeStateStaged,
    AfterStoreStagedArtifact,
    AfterStoreStagedRuntimeApplication,
    AfterStoreStagedIndex,
    AfterStorePending,
    AfterStoreArtifact,
    AfterStoreRuntimeApplication,
    AfterStoreIndex,
    AfterStoreCommitted,
    AfterDescriptorPromoted,
    AfterRuntimePromoted,
    AfterBootstrapPromoted,
    AfterRuntimeStatePromoted,
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
    projected_store: PrivateStoreCorePosition,
    projected_key_epochs: Vec<PrivateKeyEpochCommitment>,
    mutation: Option<PrivateRuntimeMutation>,
    receipt: Option<AuthorityReceipt>,
    issuance: Option<AuthorityOperationIssuanceAck>,
    already_applied: bool,
}

enum PreparedPrivateRuntimeDisposition {
    Applied {
        successor_image: PrivateRuntimeImage,
        runtime_application: PrivateRuntimeApplication,
    },
    RetiredUnapplied,
}

struct RawAuthorityVerifier;

impl AuthorityVerifier for RawAuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

struct RawRecoveryAuthorityProofVerifier;

impl PrivateRecoveryAuthorityProofVerifier for RawRecoveryAuthorityProofVerifier {
    fn verify_private_recovery_authority_proof(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
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
            management_gas: DEFAULT_MANAGEMENT_GAS,
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
            management_gas: DEFAULT_MANAGEMENT_GAS,
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

    /// Set the gas budget used for physical Private management execution.
    ///
    /// The budget applies to both Create and runtime-backed Private controls.
    pub fn set_management_gas(&mut self, gas: u64) {
        self.management_gas = gas;
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
    /// dispatcher.
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

    #[cfg(test)]
    fn synthetic_legacy_runtime_application_adapter_for_test<'host, V>(
        &'host mut self,
        authority: AuthorityActorTarget,
        node_authority: &'host V,
    ) -> Result<SyntheticLegacyPrivateRuntimeApplicationForTest<'host, V>, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        self.verify_root_scope()?;
        if !authority.is_valid() || authority.space != self.scope.space {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        Ok(SyntheticLegacyPrivateRuntimeApplicationForTest {
            host: self,
            authority,
            node_authority,
            stop: PrivateRuntimeApplicationStop::Never,
        })
    }

    /// Reopen one authenticated but not-yet-published offline recovery plan.
    /// This never restores its ciphertext archive or advances it to the live
    /// Agent map; callers must resume the retained authority/coordinator flow.
    pub(crate) fn prepared_recovery(
        &self,
        agent: AgentId,
    ) -> Result<Option<PreparedPrivateRecovery>, PrivateAgentHostError> {
        self.verify_root_scope()?;
        if self.agents.contains_key(&agent) || fs::symlink_metadata(self.agent_path(agent)).is_ok()
        {
            return Ok(None);
        }
        let path = self.creating_path(agent).join(RECOVERY_PLAN_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let plan = read_and_authenticate_recovery_plan(&path, &self.node_key)?;
                if plan.route.agent != agent
                    || plan.route.space != self.scope.space
                    || plan.owner != self.scope.owner
                    || plan.completion.is_some()
                {
                    return Err(PrivateAgentHostError::Corrupt);
                }
                let (control, proof) = validate_recovery_plan_material(&plan)?;
                Ok(Some(PreparedPrivateRecovery {
                    route: plan.route,
                    control_wire: control
                        .encode()
                        .map_err(|_| PrivateAgentHostError::Corrupt)?,
                    proof,
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(PrivateAgentHostError::Io),
        }
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
        // Execute after the read-only reservation checks but before creating
        // a staging directory: a duplicate cannot consume the management gas
        // budget, while traps or substituted output still leave no artifact.
        let initial_state = execute_private_runtime_genesis(&request, self.management_gas)?;
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
            let runtime_image = PrivateRuntimeImage::genesis(
                descriptor,
                self.scope.local_node.node,
                initial_state,
                store.core_position()?,
                private_runtime_key_epoch_commitments(&store)?,
                request.creation_receipt.clone(),
                request.creation_receipt.selector.valid_from,
                &RawAuthorityVerifier,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            let plaintext = AgentPlaintext {
                descriptor: descriptor.clone(),
                runtime_package: Zeroizing::new(request.runtime_package.exact_bytes().to_vec()),
                bootstrap_metadata: Zeroizing::new(request.bootstrap_metadata.to_vec()),
            };
            write_initial_sidecars(&stage, 0, &generated.data_key, &plaintext)?;
            write_initial_runtime_image(&stage, &generated.data_key, &runtime_image)?;
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
    pub fn put_encrypted_object<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        object: &EncryptedPrivateObject,
        authority: AuthorityActorTarget,
        node_authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let slot = self.agent_path(agent);
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        if !authority.is_valid()
            || authority.space != self.scope.space
            || authority.binding != hosted.descriptor.authority
            || object.space != hosted.store.binding().space
            || object.agent != agent
            || object.epoch != hosted.store.binding().epoch
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        require_resolved_runtime_application_head(&hosted.store)?;
        let mut hosted = self
            .agents
            .remove(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let result = (|| {
            let disposition = hosted.store.put_object(object)?;
            refresh_runtime_image_after_object_write(&slot, &mut hosted)?;
            Ok(disposition)
        })();
        match result {
            Ok(disposition) => {
                self.insert_hosted_exact(agent, hosted)?;
                Ok(disposition)
            }
            Err(error) => {
                drop(hosted);
                let _ = self.reopen_quarantined_agent(agent, node_authority);
                Err(error)
            }
        }
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
    pub fn encrypt_and_put<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        kind: EncryptedObjectKind,
        plaintext: &[u8],
        authority: AuthorityActorTarget,
        node_authority: &V,
    ) -> Result<PrivateObjectKey, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let slot = self.agent_path(agent);
        let hosted = self.hosted(agent)?;
        let binding = hosted.store.binding();
        if !authority.is_valid()
            || authority.space != binding.space
            || authority.binding != hosted.descriptor.authority
        {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        require_resolved_runtime_application_head(&hosted.store)?;
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
        let mut hosted = self
            .agents
            .remove(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let result = (|| {
            hosted.store.put_object(&object)?;
            refresh_runtime_image_after_object_write(&slot, &mut hosted)?;
            Ok(key)
        })();
        match result {
            Ok(key) => {
                self.insert_hosted_exact(agent, hosted)?;
                Ok(key)
            }
            Err(error) => {
                drop(hosted);
                let _ = self.reopen_quarantined_agent(agent, node_authority);
                Err(error)
            }
        }
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
        let slot = self.agent_path(agent);
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
        append_synthetic_control_only_with_runtime_image_for_test(
            &slot, hosted, &record, None, authority,
        )
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
        let slot = self.agent_path(agent);
        append_owner_record(
            &slot,
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
        expected_prior_head: Option<Hash>,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<PutDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let local_node = self.scope.local_node.clone();
        let node_key = &self.node_key;
        let slot = self.agent_path(agent);
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
        let preview = hosted.store.preview_control_position(record, authority)?;
        let successor_store = preview.position();
        let key_epochs = preview.key_epoch_commitments().to_vec();
        let successor_image = PrivateRuntimeImage::synthetic_control_only_successor_for_host_test(
            &hosted.runtime_image,
            record,
            successor_store,
            key_epochs,
            hosted.runtime_image.applied_at().saturating_add(1),
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let runtime_stage = slot.join(staged_runtime_image_name(record.commitment()));
        remove_regular_file_if_present(&runtime_stage)?;
        write_new_synced(
            &runtime_stage,
            &encrypt_runtime_image_sidecar(&next_data, &successor_image)?,
        )?;
        sync_directory(&slot)?;
        let disposition =
            match hosted
                .store
                .apply_offline_recovery(expected_prior_head, record, authority)
            {
                Ok(disposition) => disposition,
                Err(error) => {
                    discard_next_sidecars(&slot, next_epoch.epoch);
                    let _ = remove_regular_file_if_present(&runtime_stage);
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
        fs::rename(&runtime_stage, slot.join(RUNTIME_STATE_FILE)).map_err(map_io)?;
        sync_directory(&slot)?;
        hosted.runtime_image = successor_image;
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
    #[cfg(test)]
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
            write_new_synced(&stage.join(RUNTIME_STATE_FILE), &archive.runtime_state)?;
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
    pub(crate) fn prepare_recovery_from_encrypted_backup<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        superseded_authority_head: Option<Hash>,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        bytes: &[u8],
        authority: &V,
    ) -> Result<PreparedPrivateRecovery, PrivateAgentHostError> {
        self.prepare_recovery_from_encrypted_backups_inner(
            route,
            superseded_authority_head,
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
    pub(crate) fn prepare_recovery_from_encrypted_backups<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        superseded_authority_head: Option<Hash>,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        backups: &[&[u8]],
        authority: &V,
    ) -> Result<PreparedPrivateRecovery, PrivateAgentHostError> {
        self.prepare_recovery_from_encrypted_backups_inner(
            route,
            superseded_authority_head,
            recovery_kit,
            replacement_nodes,
            backups,
            authority,
            RecoveryInstallStop::Never,
        )
    }

    #[cfg(test)]
    fn prepare_recovery_from_encrypted_backup_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        superseded_authority_head: Option<Hash>,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        bytes: &[u8],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<PreparedPrivateRecovery, PrivateAgentHostError> {
        self.prepare_recovery_from_encrypted_backups_inner(
            route,
            superseded_authority_head,
            recovery_kit,
            replacement_nodes,
            &[bytes],
            authority,
            stop,
        )
    }

    #[cfg(test)]
    fn prepare_recovery_from_encrypted_backups_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        superseded_authority_head: Option<Hash>,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        backups: &[&[u8]],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<PreparedPrivateRecovery, PrivateAgentHostError> {
        self.prepare_recovery_from_encrypted_backups_inner(
            route,
            superseded_authority_head,
            recovery_kit,
            replacement_nodes,
            backups,
            authority,
            stop,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_recovery_from_encrypted_backups_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        superseded_authority_head: Option<Hash>,
        recovery_kit: &OfflineRecoveryKit,
        replacement_nodes: &[PrivateNodeIdentity],
        backups: &[&[u8]],
        authority: &V,
        stop: RecoveryInstallStop,
    ) -> Result<PreparedPrivateRecovery, PrivateAgentHostError> {
        self.verify_root_scope()?;
        if !route.is_valid() || route.space != self.scope.space {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let agent = route.agent;
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
            if plan.route != route
                || plan.owner != self.scope.owner
                || plan.source_hash != source_hash
                || plan.replacements_hash != replacements_hash
                || plan.recovery_signing_public_key != recovery_kit.signing_public_key()
                || plan.recovery_encryption_public_key != recovery_kit.encryption_public_key()
                || plan.completion.is_some()
            {
                return Err(PrivateAgentHostError::Alias);
            }
            let (control, proof) = validate_recovery_plan_material(&plan)?;
            if proof.superseded_authority_head != superseded_authority_head {
                return Err(PrivateAgentHostError::Alias);
            }
            // The first process may have committed PVRP3 but failed while
            // syncing the newly linked staging directory. Replaying both
            // durability edges is mandatory before returning an authority
            // handoff, even though the plan bytes themselves are exact.
            sync_directory(&stage)?;
            recovery_stop(stop, RecoveryInstallStop::AfterPlanFile)?;
            sync_directory(&self.root.join(CREATING_DIRECTORY))?;
            recovery_stop(stop, RecoveryInstallStop::AfterPlan)?;
            return Ok(PreparedPrivateRecovery {
                route,
                control_wire: control
                    .encode()
                    .map_err(|_| PrivateAgentHostError::Corrupt)?,
                proof,
            });
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
            authenticate_recovery_source_runtime_image(
                archive,
                verified,
                &candidate.descriptor,
                current_key,
            )?;
            if let Some(reference) = &plaintext {
                if !recovery_plaintext_is_compatible(reference, &candidate) {
                    return Err(PrivateStoreError::Diverged.into());
                }
            } else {
                plaintext = Some(candidate);
            }
        }

        // Recovery publication remains Unsupported until PAPL can authorize
        // construction of a replacement-node PVRI. Retain one source image
        // in the inert plan archive so no runtime state is silently dropped;
        // it must never be treated as a rebound successor.
        let recovered_runtime_state = sources
            .first()
            .ok_or(PrivateAgentHostError::Corrupt)?
            .0
            .runtime_state
            .clone();
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
        let plaintext = plaintext.ok_or(PrivateAgentHostError::Corrupt)?;
        // The descriptor, including its genesis roster, is immutable. A
        // recovery control may change live membership in Store but must never
        // rewrite and re-sign this creation preimage.
        plaintext
            .descriptor
            .validate()
            .map_err(|_| PrivateAgentHostError::InvalidDescriptor)?;
        if plaintext.descriptor.identity.space != route.space
            || plaintext.descriptor.identity.agent != route.agent
            || plaintext.descriptor.identity.runtime_deployment != route.runtime_deployment
            || plaintext.descriptor.private_recovery
                != Some(PrivateRecoveryBinding {
                    signing_key_commitment: recovery_signing_public_key_commitment(
                        &recovery_kit.signing_public_key(),
                    ),
                    encryption_public_key: recovery_kit.encryption_public_key(),
                })
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        validate_verified_backup_recovery_evidence(&verified, &plaintext.descriptor)?;

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
        let proof = PrivateRecoveryAuthorityProof::from_control(
            route.runtime_deployment,
            &recovery_record,
            superseded_authority_head,
            recovery_kit.signing_key(),
        )
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
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
                runtime_state: recovered_runtime_state,
            },
            true,
            MAX_PRIVATE_HOST_ARCHIVE_BYTES,
        )?;
        let plan = RecoveryPlan {
            route,
            owner: self.scope.owner,
            source_hash,
            replacements_hash,
            recovery_signing_public_key: recovery_kit.signing_public_key(),
            recovery_encryption_public_key: recovery_kit.encryption_public_key(),
            control_wire: recovery_record
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?,
            proof_wire: proof
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?,
            recovered_archive,
            completion: None,
        };
        let plan_bytes = encode_recovery_plan(&plan, &self.node_key)?;
        fs::create_dir(&stage).map_err(map_io)?;
        recovery_stop(stop, RecoveryInstallStop::AfterStageDirectory)?;
        let publish_result = publish_recovery_plan(&stage, &plan_bytes);
        if let Err(error) = publish_result {
            let _ = fs::remove_dir_all(&stage);
            let _ = sync_directory(&self.root.join(CREATING_DIRECTORY));
            return Err(error);
        }
        // `publish_recovery_plan` commits the file within the new directory;
        // the parent sync is the separate durability edge for the staging
        // directory name itself. Authority handoff cannot begin before both.
        recovery_stop(stop, RecoveryInstallStop::AfterPlanFile)?;
        sync_directory(&self.root.join(CREATING_DIRECTORY))?;
        recovery_stop(stop, RecoveryInstallStop::AfterPlan)?;
        Ok(PreparedPrivateRecovery {
            route,
            control_wire: plan.control_wire,
            proof,
        })
    }

    fn stage_recovery_plan<V: PrivateNodeAuthorityVerifier>(
        &self,
        agent: AgentId,
        authority: &V,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<(HostedPrivateAgent, RestoreDisposition), PrivateAgentHostError> {
        let stage = self.creating_path(agent);
        let destination = self.agent_path(agent);
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let plan =
            read_and_authenticate_recovery_plan(&stage.join(RECOVERY_PLAN_FILE), &self.node_key)?;
        if plan.route.space != self.scope.space
            || plan.route.agent != agent
            || plan.owner != self.scope.owner
            || plan.completion.is_some()
        {
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
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryStore)?;
        write_exact_or_new_synced(&stage.join(DESCRIPTOR_FILE), &archive.descriptor)?;
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryDescriptor)?;
        write_exact_or_new_synced(&stage.join(RUNTIME_FILE), &archive.runtime)?;
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryRuntime)?;
        write_exact_or_new_synced(&stage.join(BOOTSTRAP_FILE), &archive.bootstrap)?;
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryBootstrap)?;
        write_exact_or_new_synced(&stage.join(RUNTIME_STATE_FILE), &archive.runtime_state)?;
        sync_directory(&stage)?;
        let hosted = open_hosted_agent(
            &stage,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            authority,
        )?;
        validate_recovery_plan_host(&plan, &hosted)?;
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryReopen)?;
        Ok((hosted, disposition))
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
        // An applied PAPL without its terminal authority evidence is a
        // crash-resume state, not a sync-visible history endpoint.  Refuse
        // every outbound page until the exact PSE is durable.
        require_resolved_runtime_application_head(&hosted.store)?;
        Ok(
            serve_private_sync_page(&hosted.store, peer, &request, transport, route, authority)?
                .encode()?,
        )
    }

    /// Apply one exact authenticated, authority-evidenced sync page. Every
    /// PCTL is bound to canonical AOI1+PCA2 under the independently configured
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
        let slot = self.agent_path(agent);
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
        if page.phase == PrivateSyncPhase::Controls {
            // FOLLOW-UP(PAPL): controls require local PVM execution, a
            // completed application attachment, and a staged successor PVRI.
            // The legacy low-level Store receiver cannot supply those facts.
            return Err(PrivateAgentHostError::UnsupportedOperation);
        }
        require_resolved_runtime_application_head(&hosted.store)?;
        let starting_store = hosted.store.core_position()?;
        let mut hosted = self
            .agents
            .remove(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
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
                let refresh = (|| {
                    if hosted.store.core_position()? != starting_store {
                        refresh_runtime_image_after_object_write(&slot, &mut hosted)?;
                    }
                    Ok(())
                })();
                if let Err(error) = refresh {
                    drop(hosted);
                    let _ = self.reopen_quarantined_agent(agent, node_authority);
                    return Err(error);
                }
                self.insert_hosted_exact(agent, hosted)?;
                Ok(disposition)
            }
            Err(error) => {
                // Object pages commit each item independently. Preserve the
                // original receiver error, but advance the running PVRI over
                // every prefix which did become visible. The refresh helper
                // assigns memory before its fallible durable replacement, so
                // later calls cannot observe a stale Store predecessor.
                if hosted
                    .store
                    .core_position()
                    .is_ok_and(|current| current != starting_store)
                {
                    let _ = refresh_runtime_image_after_object_write(&slot, &mut hosted);
                }
                drop(hosted);
                let _ = self.reopen_quarantined_agent(agent, node_authority);
                Err(error.into())
            }
        }
    }

    fn apply_private_runtime_application<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeApplicationRequest,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeApplicationResolution, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        self.verify_root_scope()?;
        let control = PrivateControlRecord::decode(&request.control)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        if control.encode().ok().as_deref() != Some(request.control.as_slice()) {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
        if matches!(control.operation, PrivateControlOperation::Recover { .. }) {
            // Recover selects a replacement-host lineage and is never a
            // direct mutation of an already-live runtime image.
            return Err(PrivateAgentHostError::UnsupportedOperation);
        }

        let agent = request.route.agent;
        let prepared = prepare_private_application(
            self.hosted(agent)?,
            &self.scope.local_node,
            authority,
            node_authority,
            request,
        )?;
        if prepared.already_applied {
            return self.reopen_completed_private_application(
                authority,
                node_authority,
                request,
                &prepared,
                stop,
            );
        }

        let disposition = prepare_private_runtime_disposition(
            self.hosted(agent)?,
            request,
            &prepared,
            self.management_gas,
        )?;
        let PreparedPrivateRuntimeDisposition::Applied {
            successor_image,
            runtime_application,
        } = disposition
        else {
            return self.reopen_retired_private_application(
                authority,
                node_authority,
                request,
                &prepared,
                stop,
            );
        };

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
            successor_image,
            &runtime_application,
            stop,
        );
        drop(hosted);
        if let Err(error) = transition {
            // I/O errors after staging are ambiguous. Reopen immediately in
            // production so pending Store/sidecar transactions reconcile
            // before this handle becomes usable again. Test stop points model
            // process death and deliberately leave recovery to a new host.
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

        self.reopen_completed_private_application(
            authority,
            node_authority,
            request,
            &prepared,
            stop,
        )
    }

    fn reopen_completed_private_application<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeApplicationRequest,
        prepared: &PreparedPrivateApplication,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeApplicationResolution, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        let agent = request.route.agent;
        let slot = self.agent_path(agent);
        drop(self.agents.remove(&agent));
        let reopened = open_hosted_agent(
            &slot,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            node_authority,
        )?;
        let fact = private_application_fact(&reopened, request, prepared);
        if self.agents.insert(agent, reopened).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        let fact = fact?;
        #[cfg(test)]
        if stop == PrivateRuntimeApplicationStop::AfterReopen {
            return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
        }
        let _ = stop;
        Ok(PrivateControlRuntimeApplicationResolution::Applied(
            PrivateControlRuntimeApplicationResult {
                route: request.route,
                authority,
                control: request.control.clone(),
                mutation: request.mutation.clone(),
                receipt: request.receipt.clone(),
                issuance_ack: request.issuance_ack.clone(),
                applied_at: request.applied_at,
                authenticated: true,
                durably_applied: true,
                durably_reopened: true,
                reopened_runtime_state: fact.reopened_runtime_state,
                stable_projection: fact.stable_projection,
                application_fact: encode_private_application_fact(&fact),
            },
        ))
    }

    fn reopen_retired_private_application<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeApplicationRequest,
        prepared: &PreparedPrivateApplication,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeApplicationResolution, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        if prepared.already_applied {
            return Err(PrivateAgentHostError::Corrupt);
        }
        let agent = request.route.agent;
        let slot = self.agent_path(agent);
        let predecessor = self
            .agents
            .remove(&agent)
            .ok_or(PrivateAgentHostError::NotFound)?;
        let predecessor_image = predecessor.runtime_image.commitment();
        let predecessor_store = predecessor.store.core_position()?;
        drop(predecessor);
        let reopened = open_hosted_agent(
            &slot,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            node_authority,
        )?;
        if reopened.runtime_image.commitment() != predecessor_image
            || reopened.store.core_position()? != predecessor_store
            || reopened.store.binding().control_head == Some(prepared.control.commitment())
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        if self.agents.insert(agent, reopened).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        #[cfg(test)]
        if stop == PrivateRuntimeApplicationStop::AfterReopen {
            return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
        }
        let _ = stop;
        Ok(
            PrivateControlRuntimeApplicationResolution::RetiredUnapplied(
                PrivateControlRuntimeRetirementResult {
                    route: request.route,
                    authority,
                    control: request.control.clone(),
                    mutation: request.mutation.clone(),
                    receipt: request.receipt.clone(),
                    issuance_ack: request.issuance_ack.clone(),
                    resolved_at: request.applied_at,
                    authenticated: true,
                    predecessor_unchanged: true,
                    durably_reopened: true,
                },
            ),
        )
    }

    #[cfg(test)]
    fn apply_synthetic_legacy_private_control_for_test<V>(
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
        if !self.agents.contains_key(&agent)
            && fs::symlink_metadata(self.creating_path(agent).join(RECOVERY_PLAN_FILE)).is_ok()
        {
            return self.apply_synthetic_legacy_staged_recovery_for_test(
                authority,
                node_authority,
                request,
                stop,
            );
        }
        match self.apply_private_runtime_application(authority, node_authority, request, stop)? {
            PrivateControlRuntimeApplicationResolution::Applied(result) => Ok(result),
            PrivateControlRuntimeApplicationResolution::RetiredUnapplied(_) => {
                Err(PrivateAgentHostError::Corrupt)
            }
        }
    }

    #[cfg(test)]
    fn apply_synthetic_legacy_staged_recovery_for_test<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeApplicationRequest,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeApplicationResult, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        let agent = request.route.agent;
        if self.agents.contains_key(&agent) || fs::symlink_metadata(self.agent_path(agent)).is_ok()
        {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let plan = read_and_authenticate_recovery_plan(
            &self.creating_path(agent).join(RECOVERY_PLAN_FILE),
            &self.node_key,
        )?;
        validate_staged_recovery_application_request(&plan, authority, request)?;
        // This callback is reached only after the coordinator has durably
        // pledged the exact authorization invocation, PCTL, and apply slot.
        // Until now the post-Recover archive existed solely inside the
        // authenticated plan and selected no live filesystem state.
        let (hosted, _) = self.stage_recovery_plan(agent, node_authority, stop)?;
        let prepared = prepare_staged_recovery_application(&plan, &hosted)?;
        if !prepared.already_applied
            || prepared.operation != AuthorityOperationKind::RecoverPrivateAgent
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        let fact = synthetic_legacy_private_application_fact_for_test(&hosted, request, &prepared)?;
        drop(hosted);
        Ok(PrivateControlRuntimeApplicationResult {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            mutation: request.mutation.clone(),
            receipt: request.receipt.clone(),
            issuance_ack: request.issuance_ack.clone(),
            applied_at: request.applied_at,
            authenticated: true,
            durably_applied: true,
            durably_reopened: true,
            reopened_runtime_state: fact.reopened_runtime_state,
            stable_projection: fact.stable_projection,
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
        let agent = request.route.agent;
        if !self.agents.contains_key(&agent)
            && fs::symlink_metadata(self.creating_path(agent).join(RECOVERY_PLAN_FILE)).is_ok()
        {
            return self.persist_completed_staged_recovery_evidence(
                authority,
                node_authority,
                request,
                stop,
            );
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
        let recovery_proof = request
            .recovery_proof
            .as_deref()
            .map(PrivateRecoveryAuthorityProof::decode)
            .transpose()
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        let evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
            &issuance,
            &application,
            recovery_proof.as_ref(),
        )?;
        let evidence_wire = evidence.encode()?;
        let recovery = matches!(&control.operation, PrivateControlOperation::Recover { .. });
        if recovery && !self.agents.contains_key(&agent) {
            // The evidence callback may lose its result after PVRP3 was
            // retired or after the cross-directory rename. Reconcile only a
            // self-authenticating planless Recover slot (or its already-live
            // destination), then fall through to the byte-identical no-write
            // evidence lookup below. This does not replay the transition.
            self.reopen_recovery_result_loss_target(
                agent,
                &control,
                &evidence_wire,
                request.route,
                authority,
                node_authority,
            )?;
        }
        if recovery {
            let proof = recovery_proof
                .as_ref()
                .ok_or(PrivateAgentHostError::Unauthorized)?;
            verify_recovery_authority_evidence(
                &evidence,
                &control,
                proof,
                application.application.epoch,
                request.route,
                authority,
            )?;
        }
        let evidence_commitment = evidence.commitment()?;
        let hosted = self.hosted(agent)?;
        let binding = hosted.store.binding();
        let entry = hosted
            .store
            .indexed_controls()
            .iter()
            .find(|entry| entry.commitment == control.commitment())
            .ok_or(PrivateAgentHostError::InvalidArtifact)?;
        if request.route.space != binding.space
            || request.route.agent != binding.agent
            || request.route.runtime_deployment != hosted.descriptor.identity.runtime_deployment
            || authority.space != binding.space
            || authority.binding != hosted.descriptor.authority
            || application.application.epoch != entry.resulting_epoch
            || !hosted
                .store
                .control_is_exact(control.commitment(), &request.control)?
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        if !recovery {
            let runtime_application = hosted
                .store
                .read_runtime_application(control.commitment())?
                .ok_or(PrivateAgentHostError::Corrupt)?;
            authenticate_local_runtime_application_endpoint(
                &hosted.descriptor,
                &control,
                entry.resulting_epoch,
                &runtime_application,
                &evidence_wire,
            )?;
        }
        if recovery {
            if control.signer != PrivateControlSigner::Recovery
                || control.signer_public_key != hosted.store.recovery_public_key()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
            // PVRP3 is retired before a recovered slot becomes live. A live
            // Recover callback is therefore only a result-loss retry and may
            // never attach new evidence after the authenticated plan vanished.
            // Exact retained PSE2 bytes prove the transition crossed the sole
            // staged recovery path; missing or divergent bytes fail closed.
            if hosted
                .store
                .read_control_authority_evidence(entry)?
                .as_deref()
                != Some(evidence_wire.as_slice())
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
            return Ok(PrivateControlRuntimeEvidenceResult {
                route: request.route,
                authority: request.authority,
                control: request.control.clone(),
                issuance_ack: request.issuance_ack.clone(),
                application_ack: request.application_ack.clone(),
                recovery_proof: request.recovery_proof.clone(),
                evidence_commitment,
                authenticated: true,
                durably_persisted: true,
                durably_reopened: true,
            });
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
            recovery_proof: request.recovery_proof.clone(),
            evidence_commitment,
            authenticated: true,
            durably_persisted: true,
            durably_reopened: true,
        })
    }

    fn persist_completed_staged_recovery_evidence<V>(
        &mut self,
        authority: AuthorityActorTarget,
        node_authority: &V,
        request: &PrivateControlRuntimeEvidenceRequest,
        stop: PrivateRuntimeApplicationStop,
    ) -> Result<PrivateControlRuntimeEvidenceResult, PrivateAgentHostError>
    where
        V: PrivateNodeAuthorityVerifier,
    {
        let agent = request.route.agent;
        let stage = self.creating_path(agent);
        let destination = self.agent_path(agent);
        if self.agents.contains_key(&agent) || fs::symlink_metadata(&destination).is_ok() {
            return Err(PrivateAgentHostError::AlreadyExists);
        }
        let mut plan =
            read_and_authenticate_recovery_plan(&stage.join(RECOVERY_PLAN_FILE), &self.node_key)?;
        if request.authority != authority
            || request.route != plan.route
            || request.control != plan.control_wire
            || request.recovery_proof.as_deref() != Some(plan.proof_wire.as_slice())
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        let (control, proof) = validate_recovery_plan_material(&plan)?;
        let plan_write = stage.join(RECOVERY_PLAN_WRITE_FILE);
        if fs::symlink_metadata(&plan_write).is_ok() {
            // The canonical authenticated plan is the commit point. A lost
            // result while replacing it may leave a regular, partially or
            // fully written successor temp. Once the exact callback has been
            // matched to the canonical plan, retire that uncommitted temp so
            // slot reopening cannot be poisoned and the update can be rebuilt.
            require_regular_file(&plan_write)?;
            remove_regular_file_if_present(&plan_write)?;
            sync_directory(&stage)?;
        }
        let issuance = AuthorityOperationIssuanceAck::decode(&request.issuance_ack)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        let application = PrivateControlApplicationAck::decode(&request.application_ack)
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
        if issuance.encode().ok().as_deref() != Some(request.issuance_ack.as_slice())
            || application.encode().ok().as_deref() != Some(request.application_ack.as_slice())
        {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
        let evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
            &issuance,
            &application,
            Some(&proof),
        )?;
        verify_recovery_authority_evidence(
            &evidence,
            &control,
            &proof,
            application.application.epoch,
            request.route,
            authority,
        )?;
        let evidence_wire = evidence.encode()?;
        let evidence_commitment = evidence.commitment()?;
        let expected_completion = RecoveryPlanCompletion {
            issuance_ack: request.issuance_ack.clone(),
            application_ack: request.application_ack.clone(),
            evidence_commitment,
        };
        if plan
            .completion
            .as_ref()
            .is_some_and(|retained| retained != &expected_completion)
        {
            return Err(PrivateAgentHostError::Alias);
        }

        // Runtime.apply has already staged and reopened this exact archive.
        // A completed plan may be observed on an exact retry after the plan
        // update commit point; in that case its evidence must already be
        // physically present and is checked again below.
        let mut hosted = open_hosted_agent(
            &stage,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            node_authority,
        )?;
        if plan.completion.is_none() {
            validate_recovery_plan_host(&plan, &hosted)?;
        }
        if authority.binding != hosted.descriptor.authority {
            return Err(PrivateAgentHostError::Unauthorized);
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
        hosted
            .store
            .persist_control_authority_evidence_with_stop_for_runtime(
                control.commitment(),
                &evidence_wire,
                evidence_stop,
            )?;
        drop(hosted);

        let reopened = open_hosted_agent(
            &stage,
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
        #[cfg(test)]
        if stop == PrivateRuntimeApplicationStop::AfterEvidenceReopen {
            return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
        }

        if plan.completion.is_none() {
            plan.completion = Some(expected_completion);
            commit_completed_recovery_plan(&stage, &plan, &self.node_key, stop)?;
        }
        validate_recovery_plan_host(&plan, &reopened)?;
        drop(reopened);

        // The plan is legal only below `.creating`. Retire and sync it before
        // the directory rename so every published slot has the ordinary live
        // layout. A stop here leaves a planless, fully authenticated staged
        // slot which normal create recovery may safely publish on reopen.
        remove_regular_file_if_present(&stage.join(RECOVERY_PLAN_FILE))?;
        sync_directory(&stage)?;
        application_stop(
            stop,
            PrivateRuntimeApplicationStop::AfterRecoveryPlanRetired,
        )?;
        fs::rename(&stage, &destination).map_err(map_io)?;
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryRename)?;
        sync_directory(&self.root)?;
        application_stop(
            stop,
            PrivateRuntimeApplicationStop::AfterRecoveryDestinationSync,
        )?;
        sync_directory(&self.root.join(CREATING_DIRECTORY))?;
        application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryPublished)?;

        let reopened = open_hosted_agent(
            &destination,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            node_authority,
        )?;
        if self.agents.insert(agent, reopened).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        Ok(PrivateControlRuntimeEvidenceResult {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            issuance_ack: request.issuance_ack.clone(),
            application_ack: request.application_ack.clone(),
            recovery_proof: request.recovery_proof.clone(),
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
        // A newest PAPL without its terminal authority evidence is retained
        // solely so the exact callback can finish after a crash.  It is not
        // an authenticated history endpoint and must never escape through an
        // otherwise complete snapshot or backup.
        require_resolved_runtime_application_head(&hosted.store)?;
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
            runtime_state: read_sidecar_wire(&slot, RUNTIME_STATE_FILE)?,
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

    fn insert_hosted_exact(
        &mut self,
        agent: AgentId,
        hosted: HostedPrivateAgent,
    ) -> Result<(), PrivateAgentHostError> {
        if self.agents.insert(agent, hosted).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        Ok(())
    }

    fn reopen_quarantined_agent<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        node_authority: &V,
    ) -> Result<(), PrivateAgentHostError> {
        if self.agents.contains_key(&agent) {
            return Err(PrivateAgentHostError::Alias);
        }
        let hosted = open_hosted_agent(
            &self.agent_path(agent),
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            node_authority,
        )?;
        self.insert_hosted_exact(agent, hosted)
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
        retire_duplicate_tombstones(&creating)?;
        let mut staged = scan_agent_directories(&creating)?;
        staged.sort_unstable();
        for agent in staged {
            let source = self.creating_path(agent);
            let destination = self.agent_path(agent);
            if fs::symlink_metadata(&destination).is_ok() {
                reconcile_exact_duplicate_slot(
                    &source,
                    &destination,
                    self.scope.space,
                    self.scope.owner,
                    &self.scope.local_node,
                    &self.node_key,
                    authority,
                )?;
                retire_exact_duplicate_slot(&source, &creating, agent)?;
                sync_directory(&creating)?;
                continue;
            }
            let plan = source.join(RECOVERY_PLAN_FILE);
            let unpublished_plan = source.join(RECOVERY_PLAN_WRITE_FILE);
            if fs::symlink_metadata(&plan).is_ok() {
                if fs::symlink_metadata(&unpublished_plan).is_ok() {
                    // The canonical plan is the last committed state. A stop
                    // before rename leaves only an uncommitted replacement;
                    // retire it without interpreting its bytes.
                    require_regular_file(&unpublished_plan)?;
                    remove_regular_file_if_present(&unpublished_plan)?;
                    sync_directory(&source)?;
                }
                let plan = read_and_authenticate_recovery_plan(&plan, &self.node_key)?;
                if plan.route.space != self.scope.space
                    || plan.route.agent != agent
                    || plan.owner != self.scope.owner
                {
                    return Err(PrivateAgentHostError::InvalidScope);
                }
                // An authenticated preparation is deliberately inert. Only
                // the post-authority evidence transition marks it publishable.
                if plan.completion.is_none() {
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
                validate_recovery_plan_host(&plan, &hosted)?;
                drop(hosted);
                remove_regular_file_if_present(&source.join(RECOVERY_PLAN_FILE))?;
                sync_directory(&source)?;
                fs::rename(&source, &destination).map_err(map_io)?;
                sync_directory(&self.root)?;
                sync_directory(&creating)?;
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
            require_real_directory(&source)?;
            if fs::read_dir(&source).map_err(map_io)?.next().is_none() {
                // Preparation creates this exact staging directory before it
                // publishes PVRP3. A stop before the first file write leaves
                // no authenticated state to retain and no data to interpret.
                fs::remove_dir(&source).map_err(map_io)?;
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
            validate_planless_staged_recovery(&hosted, false)?;
            drop(hosted);
            fs::rename(&source, &destination).map_err(map_io)?;
            sync_directory(&self.root)?;
            sync_directory(&creating)?;
        }
        Ok(())
    }

    fn reopen_recovery_result_loss_target<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        agent: AgentId,
        expected_control: &PrivateControlRecord,
        expected_evidence_wire: &[u8],
        expected_route: ManagedAgentTarget,
        expected_authority: AuthorityActorTarget,
        authority: &V,
    ) -> Result<(), PrivateAgentHostError> {
        if self.agents.contains_key(&agent) {
            return Ok(());
        }
        let creating = self.root.join(CREATING_DIRECTORY);
        let source = self.creating_path(agent);
        let destination = self.agent_path(agent);
        if fs::symlink_metadata(&destination).is_ok() {
            if fs::symlink_metadata(&source).is_ok() {
                reconcile_exact_duplicate_slot(
                    &source,
                    &destination,
                    self.scope.space,
                    self.scope.owner,
                    &self.scope.local_node,
                    &self.node_key,
                    authority,
                )?;
                retire_exact_duplicate_slot(&source, &creating, agent)?;
            }
        } else {
            require_real_directory(&source)?;
            if fs::symlink_metadata(source.join(RECOVERY_PLAN_FILE)).is_ok()
                || fs::symlink_metadata(source.join(RECOVERY_PLAN_WRITE_FILE)).is_ok()
            {
                return Err(PrivateAgentHostError::Unauthorized);
            }
            let staged = open_hosted_agent(
                &source,
                self.scope.space,
                self.scope.owner,
                &self.scope.local_node,
                &self.node_key,
                authority,
            )?;
            validate_exact_recovery_result_loss_target(
                &staged,
                expected_control,
                expected_evidence_wire,
                expected_route,
                expected_authority,
            )?;
            drop(staged);
            // Repair an ambiguous failure of the preceding PVRP unlink
            // directory sync before moving this name into the live parent.
            sync_directory(&source)?;
            fs::rename(&source, &destination).map_err(map_io)?;
        }
        // Whether this call performed the rename or merely observed its
        // destination after a lost result, replay both namespace durability
        // edges in destination-first order before returning success.
        sync_directory(&self.root)?;
        sync_directory(&creating)?;
        let hosted = open_hosted_agent(
            &destination,
            self.scope.space,
            self.scope.owner,
            &self.scope.local_node,
            &self.node_key,
            authority,
        )?;
        validate_exact_recovery_result_loss_target(
            &hosted,
            expected_control,
            expected_evidence_wire,
            expected_route,
            expected_authority,
        )?;
        if hosted.descriptor.identity.agent != agent || self.agents.insert(agent, hosted).is_some()
        {
            return Err(PrivateAgentHostError::Alias);
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
    ) -> Result<PrivateControlRuntimeApplicationResolution, Self::Error> {
        self.host.apply_private_runtime_application(
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

#[cfg(test)]
impl<V> PrivateControlRuntimeApplicationAdapter
    for SyntheticLegacyPrivateRuntimeApplicationForTest<'_, V>
where
    V: PrivateNodeAuthorityVerifier,
{
    type Error = PrivateAgentHostError;

    fn apply(
        &mut self,
        request: &PrivateControlRuntimeApplicationRequest,
    ) -> Result<PrivateControlRuntimeApplicationResolution, Self::Error> {
        self.host
            .apply_synthetic_legacy_private_control_for_test(
                self.authority,
                self.node_authority,
                request,
                self.stop,
            )
            .map(PrivateControlRuntimeApplicationResolution::Applied)
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

fn validate_staged_recovery_application_request(
    plan: &RecoveryPlan,
    authority: AuthorityActorTarget,
    request: &PrivateControlRuntimeApplicationRequest,
) -> Result<(), PrivateAgentHostError> {
    if plan.completion.is_some()
        || request.authority != authority
        || request.route != plan.route
        || authority.space != plan.route.space
    {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    let (_control, proof) = validate_recovery_plan_material(plan)?;
    if request.control != plan.control_wire
        || request.mutation.is_some()
        || proof.managed != request.route
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
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
        || selector.space != plan.route.space
        || selector.agent != plan.route.agent
        || selector.runtime_deployment != plan.route.runtime_deployment
        || selector.operation != AuthorityOperationKind::RecoverPrivateAgent
        || selector.actor.is_some()
        || selector.actor_deployment.is_some()
        || selector.request != proof.commitment()
        || issuance
            .verify_with(authority.binding, &RawAuthorityVerifier)
            .is_err()
        || receipt
            .verify_at(request.applied_at, &RawAuthorityVerifier)
            .is_err()
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    Ok(())
}

fn prepare_staged_recovery_application(
    plan: &RecoveryPlan,
    hosted: &HostedPrivateAgent,
) -> Result<PreparedPrivateApplication, PrivateAgentHostError> {
    validate_recovery_plan_host(plan, hosted)?;
    let (control, proof) = validate_recovery_plan_material(plan)?;
    let expected_members: Vec<NodeId> = hosted
        .store
        .authorized_nodes()
        .iter()
        .map(|node| node.node)
        .collect();
    if private_member_set_commitment(expected_members.iter().copied())
        != Some(proof.replacement_member_set)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(PreparedPrivateApplication {
        control,
        control_wire: plan.control_wire.clone(),
        operation: AuthorityOperationKind::RecoverPrivateAgent,
        expected_epoch: proof.next_epoch,
        expected_members,
        projected_store: hosted.store.core_position()?,
        projected_key_epochs: private_runtime_key_epoch_commitments(&hosted.store)?,
        mutation: None,
        receipt: None,
        issuance: None,
        already_applied: true,
    })
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
    let mutation =
        validate_private_runtime_application_mutation(&control, request.mutation.as_deref())?;
    if matches!(control.operation, PrivateControlOperation::Recover { .. }) {
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
        let application = hosted
            .store
            .read_runtime_application(control.commitment())?
            .ok_or(PrivateAgentHostError::Corrupt)?;
        if !completed_private_application_matches_request(
            &application,
            request,
            &control,
            mutation.as_ref(),
            &receipt,
            &issuance,
        ) {
            return Err(PrivateAgentHostError::InvalidArtifact);
        }
        if !current_private_application_successor_is_exact(hosted, &application)? {
            return Err(PrivateAgentHostError::Corrupt);
        }
    } else {
        require_resolved_runtime_application_head(&hosted.store)?;
        validate_new_private_application_position(hosted, local_node, &control)?;
        hosted
            .store
            .validate_next_control(&control, node_authority)?;
    }

    let preview = hosted
        .store
        .preview_control_position(&control, node_authority)?;
    if (preview.disposition() == PutDisposition::AlreadyPresent) != already_applied {
        return Err(PrivateAgentHostError::Corrupt);
    }

    let operation_epoch = match &control.operation {
        PrivateControlOperation::Invite { epoch, .. } => *epoch,
        PrivateControlOperation::Revoke { next_epoch, .. }
        | PrivateControlOperation::RotateKeys { next_epoch }
        | PrivateControlOperation::Recover { next_epoch, .. } => next_epoch.epoch,
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => binding.epoch,
    };
    let expected_epoch = preview.position().epoch();
    if expected_epoch != operation_epoch {
        return Err(PrivateAgentHostError::Corrupt);
    }
    require_exact_local_member(preview.authorized_nodes(), local_node)?;
    let expected_members = preview
        .authorized_nodes()
        .iter()
        .map(|node| node.node)
        .collect::<Vec<_>>();
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
        projected_store: preview.position(),
        projected_key_epochs: preview.key_epoch_commitments().to_vec(),
        mutation,
        receipt: Some(receipt),
        issuance: Some(issuance),
        already_applied,
    })
}

fn completed_private_application_matches_request(
    application: &PrivateRuntimeApplication,
    request: &PrivateControlRuntimeApplicationRequest,
    control: &PrivateControlRecord,
    mutation: Option<&PrivateRuntimeMutation>,
    receipt: &AuthorityReceipt,
    issuance: &AuthorityOperationIssuanceAck,
) -> bool {
    application.managed() == request.route
        && application.control() == control
        && application.mutation() == mutation
        && application.receipt() == receipt
        && application.issuance() == issuance
        && application.applied_at() == request.applied_at
}

fn current_private_application_successor_is_exact(
    hosted: &HostedPrivateAgent,
    application: &PrivateRuntimeApplication,
) -> Result<bool, PrivateAgentHostError> {
    Ok((application.matches_successor(&hosted.runtime_image)
        || hosted
            .runtime_image
            .matches_application_successor_after_object_growth(application))
        && hosted.runtime_image.store() == hosted.store.core_position()?)
}

fn require_resolved_runtime_application_head(
    store: &PrivateStore,
) -> Result<(), PrivateAgentHostError> {
    let Some(head) = store.indexed_controls().last() else {
        return Ok(());
    };
    if store.read_runtime_application(head.commitment)?.is_none()
        || store.read_control_authority_evidence(head)?.is_none()
    {
        return Err(PrivateAgentHostError::UnsupportedOperation);
    }
    Ok(())
}

fn require_runtime_application_attachments_for_open(
    store: &PrivateStore,
) -> Result<(), PrivateAgentHostError> {
    let controls = store.indexed_controls();
    for (position, control) in controls.iter().enumerate() {
        if store
            .read_runtime_application(control.commitment)?
            .is_none()
            || (position + 1 != controls.len()
                && store.read_control_authority_evidence(control)?.is_none())
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
    }
    Ok(())
}

fn validate_private_runtime_application_mutation(
    control: &PrivateControlRecord,
    mutation_wire: Option<&[u8]>,
) -> Result<Option<PrivateRuntimeMutation>, PrivateAgentHostError> {
    match &control.operation {
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {
            let mutation_wire = mutation_wire.ok_or(PrivateAgentHostError::InvalidArtifact)?;
            if mutation_wire.len() > MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES {
                return Err(PrivateAgentHostError::LimitExceeded);
            }
            let mutation = PrivateRuntimeMutation::decode(mutation_wire)
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            let request = ManagementRequest::PrivateControl {
                control: Box::new(control.clone()),
                mutation: Box::new(mutation.clone()),
            };
            if mutation.encode().ok().as_deref() != Some(mutation_wire) || !request.is_valid() {
                return Err(PrivateAgentHostError::InvalidArtifact);
            }
            Ok(Some(mutation))
        }
        PrivateControlOperation::Invite { .. }
        | PrivateControlOperation::Revoke { .. }
        | PrivateControlOperation::RotateKeys { .. }
        | PrivateControlOperation::Recover { .. } => {
            if mutation_wire.is_some() {
                return Err(PrivateAgentHostError::InvalidArtifact);
            }
            Ok(None)
        }
    }
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

fn apply_prepared_private_control<V>(
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    node_authority: &V,
    prepared: &PreparedPrivateApplication,
    successor_image: PrivateRuntimeImage,
    runtime_application: &PrivateRuntimeApplication,
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
        PrivateControlOperation::Recover { .. } => {
            return Err(PrivateAgentHostError::UnsupportedOperation);
        }
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => None,
    };
    if let Some(data) = successor_data.as_ref() {
        stage_metadata_for_application(slot, prepared.expected_epoch, data, hosted, stop)?;
    }
    let runtime_data_key = successor_data.as_ref().unwrap_or(
        hosted
            .data_keys
            .get(&hosted.store.binding().epoch)
            .ok_or(PrivateAgentHostError::Corrupt)?,
    );
    stage_runtime_image_for_application(
        slot,
        runtime_data_key,
        &successor_image,
        prepared.control.commitment(),
        stop,
    )?;

    #[cfg(test)]
    let store_stop = private_store_stop(stop);
    #[cfg(test)]
    let store_result = if let Some(store_stop) = store_stop {
        hosted
            .store
            .append_control_with_runtime_application_with_stop_for_runtime(
                &prepared.control,
                runtime_application,
                node_authority,
                store_stop,
            )
    } else {
        hosted.store.append_control_with_runtime_application(
            &prepared.control,
            runtime_application,
            node_authority,
        )
    };
    #[cfg(not(test))]
    let store_result = hosted.store.append_control_with_runtime_application(
        &prepared.control,
        runtime_application,
        node_authority,
    );
    store_result?;
    #[cfg(test)]
    if stop == PrivateRuntimeApplicationStop::AfterStoreCommitted {
        return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
    }
    if successor_data.is_some() {
        promote_application_sidecars(slot, prepared.expected_epoch, stop)?;
    }
    promote_runtime_image_for_application(slot, prepared.control.commitment(), stop)?;
    hosted.runtime_image = successor_image;
    Ok(())
}

fn prepare_private_runtime_disposition(
    hosted: &HostedPrivateAgent,
    request: &PrivateControlRuntimeApplicationRequest,
    prepared: &PreparedPrivateApplication,
    management_gas: u64,
) -> Result<PreparedPrivateRuntimeDisposition, PrivateAgentHostError> {
    if prepared.already_applied {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let pending = PrivateRuntimeApplication::pending(
        &hosted.descriptor,
        &hosted.runtime_image,
        prepared.control.clone(),
        prepared.mutation.clone(),
        None,
        prepared
            .receipt
            .clone()
            .ok_or(PrivateAgentHostError::Corrupt)?,
        prepared
            .issuance
            .clone()
            .ok_or(PrivateAgentHostError::Corrupt)?,
        request.applied_at,
        prepared.projected_store,
        &RawAuthorityVerifier,
        &RawRecoveryAuthorityProofVerifier,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;

    let (state, success) = match &prepared.control.operation {
        PrivateControlOperation::Invite { .. }
        | PrivateControlOperation::Revoke { .. }
        | PrivateControlOperation::RotateKeys { .. } => (
            hosted.runtime_image.state().clone(),
            PrivateRuntimeSuccess::ControlOnly,
        ),
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {
            let mutation = prepared
                .mutation
                .clone()
                .ok_or(PrivateAgentHostError::Corrupt)?;
            let management = ManagementRequest::PrivateControl {
                control: Box::new(prepared.control.clone()),
                mutation: Box::new(mutation),
            };
            if !management.is_valid() {
                return Err(PrivateAgentHostError::InvalidArtifact);
            }
            let work = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: request.route.space,
                agent: request.route.agent,
                runtime_deployment: request.route.runtime_deployment,
                state: hosted.runtime_image.state().clone(),
                request: Box::new(management.clone()),
                authority: Some(Box::new(
                    prepared
                        .receipt
                        .clone()
                        .ok_or(PrivateAgentHostError::Corrupt)?,
                )),
                observed_slot: request.applied_at,
            };
            let wire = work
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            let admitted = admit_runtime_package(&hosted.runtime_package)
                .map_err(|_| PrivateAgentHostError::Corrupt)?;
            let transition = execute_canonical_wire::<RuntimeTransition>(
                admitted.program_bytes(),
                management_gas,
                &wire,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            match classify_private_runtime_control_transition(
                &hosted.runtime_image,
                &management,
                transition,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?
            {
                PrivateRuntimeControlDisposition::Applied { state, success } => (state, success),
                PrivateRuntimeControlDisposition::RetiredUnapplied { .. } => {
                    return Ok(PreparedPrivateRuntimeDisposition::RetiredUnapplied);
                }
            }
        }
        PrivateControlOperation::Recover { .. } => {
            return Err(PrivateAgentHostError::UnsupportedOperation);
        }
    };
    let successor = PrivateRuntimeImage::successor(
        &hosted.descriptor,
        &hosted.runtime_image,
        &pending,
        &success,
        state,
        prepared.projected_key_epochs.clone(),
        &RawAuthorityVerifier,
        &RawRecoveryAuthorityProofVerifier,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let completed = pending
        .complete(
            &hosted.descriptor,
            &hosted.runtime_image,
            &successor,
            success,
            &RawAuthorityVerifier,
            &RawRecoveryAuthorityProofVerifier,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(PreparedPrivateRuntimeDisposition::Applied {
        successor_image: successor,
        runtime_application: completed,
    })
}

fn stage_runtime_image_for_application(
    slot: &Path,
    data_key: &PrivateDataKey,
    image: &PrivateRuntimeImage,
    control: Hash,
    stop: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError> {
    if image.stable_projection().control_head() != Some(control) {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let path = slot.join(staged_runtime_image_name(control));
    remove_regular_file_if_present(&path)?;
    let ciphertext = encrypt_runtime_image_sidecar(data_key, image)?;
    write_new_synced(&path, &ciphertext)?;
    sync_directory(slot)?;
    application_stop(stop, PrivateRuntimeApplicationStop::AfterRuntimeStateStaged)
}

fn promote_runtime_image_for_application(
    slot: &Path,
    control: Hash,
    stop: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError> {
    let path = slot.join(staged_runtime_image_name(control));
    require_regular_file(&path)?;
    fs::rename(path, slot.join(RUNTIME_STATE_FILE)).map_err(map_io)?;
    sync_directory(slot)?;
    application_stop(
        stop,
        PrivateRuntimeApplicationStop::AfterRuntimeStatePromoted,
    )
}

fn private_application_fact(
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
    let (reopened_runtime_state, stable_projection) = match hosted
        .store
        .read_runtime_application(prepared.control.commitment())?
    {
        Some(application) => {
            if !completed_private_application_matches_request(
                &application,
                request,
                &prepared.control,
                prepared.mutation.as_ref(),
                prepared
                    .receipt
                    .as_ref()
                    .ok_or(PrivateAgentHostError::Corrupt)?,
                prepared
                    .issuance
                    .as_ref()
                    .ok_or(PrivateAgentHostError::Corrupt)?,
            ) || !current_private_application_successor_is_exact(hosted, &application)?
            {
                return Err(PrivateAgentHostError::Corrupt);
            }
            let stable_projection = application
                .successor_stable_projection()
                .ok_or(PrivateAgentHostError::Corrupt)?
                .commitment();
            let reopened_runtime_state =
                PrivateControlReopenedState::commitment_from_application(&application)
                    .map_err(|_| PrivateAgentHostError::Corrupt)?;
            (reopened_runtime_state, stable_projection)
        }
        None => return Err(PrivateAgentHostError::Corrupt),
    };
    let fact = PrivateControlApplicationFact {
        managed: request.route,
        operation: prepared.operation,
        control: prepared.control.commitment(),
        control_sequence: prepared.control.sequence,
        control_previous: prepared.control.previous,
        epoch: prepared.expected_epoch,
        post_member_set,
        reopened_runtime_state,
        stable_projection,
        reopened_control_head: prepared.control.commitment(),
        applied_at: request.applied_at,
    };
    fact.validate_shape()
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(fact)
}

#[cfg(test)]
fn synthetic_legacy_private_application_fact_for_test(
    hosted: &HostedPrivateAgent,
    request: &PrivateControlRuntimeApplicationRequest,
    prepared: &PreparedPrivateApplication,
) -> Result<PrivateControlApplicationFact, PrivateAgentHostError> {
    if hosted
        .store
        .read_runtime_application(prepared.control.commitment())?
        .is_some()
    {
        return private_application_fact(hosted, request, prepared);
    }

    // Retired pre-PAPL recovery fixtures cannot cross the production direct
    // application boundary, but still need an opaque fact while exercising
    // their isolated recovery crash machinery.
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
    let fact = PrivateControlApplicationFact {
        managed: request.route,
        operation: prepared.operation,
        control: prepared.control.commitment(),
        control_sequence: prepared.control.sequence,
        control_previous: prepared.control.previous,
        epoch: prepared.expected_epoch,
        post_member_set: private_member_set_commitment(members.iter().copied())
            .ok_or(PrivateAgentHostError::Corrupt)?,
        reopened_runtime_state: Hash([0xf1; 32]),
        stable_projection: Hash([0xf2; 32]),
        reopened_control_head: prepared.control.commitment(),
        applied_at: request.applied_at,
    };
    fact.validate_shape()
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(fact)
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
        PrivateRuntimeApplicationStop::AfterStoreStagedRuntimeApplication => {
            Some(CommitStop::AfterStagedRuntimeApplication)
        }
        PrivateRuntimeApplicationStop::AfterStoreStagedIndex => Some(CommitStop::AfterStagedIndex),
        PrivateRuntimeApplicationStop::AfterStorePending => Some(CommitStop::AfterPending),
        PrivateRuntimeApplicationStop::AfterStoreArtifact => Some(CommitStop::AfterArtifact),
        PrivateRuntimeApplicationStop::AfterStoreRuntimeApplication => {
            Some(CommitStop::AfterRuntimeApplication)
        }
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
    require_exact_local_member(request.nodes, &scope.local_node)?;
    validate_private_creation_receipt(descriptor, request.creation_receipt, request.observed_at)
}

fn validate_private_creation_receipt(
    descriptor: &AgentDescriptor,
    receipt: &AuthorityReceipt,
    observed_at: u64,
) -> Result<(), PrivateAgentHostError> {
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let selector = &receipt.selector;
    if !request.is_valid()
        || receipt.validate_shape().is_err()
        || !descriptor.authority.accepts(receipt)
        || selector.space != descriptor.identity.space
        || selector.agent != descriptor.identity.agent
        || selector.runtime_deployment != descriptor.identity.runtime_deployment
        || selector.actor.is_some()
        || selector.actor_deployment.is_some()
        || selector.operation != AuthorityOperationKind::CreateAgent
        || selector.request != request.commitment()
        || !selector.is_live_at(observed_at)
        || receipt
            .verify_at(observed_at, &RawAuthorityVerifier)
            .is_err()
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    Ok(())
}

fn execute_private_runtime_genesis(
    request: &PrivateAgentCreate<'_>,
    management_gas: u64,
) -> Result<RuntimeState, PrivateAgentHostError> {
    let descriptor = request.descriptor;
    let genesis_at = request.creation_receipt.selector.valid_from;
    let work = RuntimeWork::Manage {
        context: RuntimeExecutionContext::Direct,
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: descriptor.identity.runtime_deployment,
        state: RuntimeState::default(),
        request: Box::new(ManagementRequest::Create(Box::new(descriptor.clone()))),
        authority: Some(Box::new(request.creation_receipt.clone())),
        observed_slot: genesis_at,
    };
    let wire = work
        .encode()
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let transition = execute_canonical_wire::<RuntimeTransition>(
        request.runtime_package.program_bytes(),
        management_gas,
        &wire,
    )
    .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    validate_private_runtime_genesis_transition(descriptor, transition)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)
}

fn private_runtime_key_epoch_commitments(
    store: &PrivateStore,
) -> Result<Vec<PrivateKeyEpochCommitment>, PrivateAgentHostError> {
    store
        .key_epochs()
        .iter()
        .map(|epoch| {
            PrivateKeyEpochCommitment::from_epoch(epoch).map_err(|_| PrivateAgentHostError::Corrupt)
        })
        .collect()
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
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
    operation: PrivateControlOperation,
    authority: &V,
) -> Result<PutDisposition, PrivateAgentHostError> {
    let mut record = unsigned_owner_record(hosted, operation);
    sign_owner_control_record(&mut record, &hosted.owner_key)?;
    append_synthetic_control_only_with_runtime_image_for_test(
        slot, hosted, &record, None, authority,
    )
}

#[cfg(test)]
fn append_synthetic_control_only_with_runtime_image_for_test<V: PrivateNodeAuthorityVerifier>(
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
    record: &PrivateControlRecord,
    successor_data_key: Option<&PrivateDataKey>,
    authority: &V,
) -> Result<PutDisposition, PrivateAgentHostError> {
    let preview = hosted.store.preview_control_position(record, authority)?;
    let successor_store = preview.position();
    let key_epochs = preview.key_epoch_commitments().to_vec();
    let successor = PrivateRuntimeImage::synthetic_control_only_successor_for_host_test(
        &hosted.runtime_image,
        record,
        successor_store,
        key_epochs,
        hosted.runtime_image.applied_at().saturating_add(1),
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let ciphertext = {
        let key = match successor_data_key {
            Some(key) => key,
            None => hosted
                .data_keys
                .get(&hosted.store.binding().epoch)
                .ok_or(PrivateAgentHostError::Corrupt)?,
        };
        encrypt_runtime_image_sidecar(key, &successor)?
    };
    let staged = slot.join(staged_runtime_image_name(record.commitment()));
    remove_regular_file_if_present(&staged)?;
    write_new_synced(&staged, &ciphertext)?;
    sync_directory(slot)?;
    let disposition = match hosted.store.append_control(record, authority) {
        Ok(disposition) => disposition,
        Err(error) => {
            let _ = remove_regular_file_if_present(&staged);
            let _ = sync_directory(slot);
            return Err(error.into());
        }
    };
    fs::rename(&staged, slot.join(RUNTIME_STATE_FILE)).map_err(map_io)?;
    sync_directory(slot)?;
    hosted.runtime_image = successor;
    Ok(disposition)
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
    let disposition = match append_synthetic_control_only_with_runtime_image_for_test(
        slot,
        hosted,
        &control,
        Some(&data_key),
        authority,
    ) {
        Ok(disposition) => disposition,
        Err(error) => {
            discard_next_sidecars(slot, next_epoch);
            return Err(error);
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
    encoder.u64(value.resources.max_proof_material_bytes);
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
            max_proof_material_bytes: decoder.u64()?,
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

fn encrypt_runtime_image_sidecar(
    data_key: &PrivateDataKey,
    image: &PrivateRuntimeImage,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    let wire = Zeroizing::new(image.encode().map_err(|_| PrivateAgentHostError::Corrupt)?);
    encrypt_private_object(
        data_key,
        image.managed().space,
        image.managed().agent,
        image.store().epoch(),
        EncryptedObjectKind::Snapshot,
        &wire,
    )?
    .encode()
    .map_err(|_| PrivateAgentHostError::Corrupt)
}

fn write_initial_runtime_image(
    slot: &Path,
    data_key: &PrivateDataKey,
    image: &PrivateRuntimeImage,
) -> Result<(), PrivateAgentHostError> {
    let ciphertext = encrypt_runtime_image_sidecar(data_key, image)?;
    write_new_synced(&slot.join(RUNTIME_STATE_FILE), &ciphertext)?;
    sync_directory(slot)
}

fn refresh_runtime_image_after_object_write(
    slot: &Path,
    hosted: &mut HostedPrivateAgent,
) -> Result<(), PrivateAgentHostError> {
    let successor = hosted
        .runtime_image
        .rebind_store_objects(hosted.store.core_position()?)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let data_key = hosted
        .data_keys
        .get(&successor.store().epoch())
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let ciphertext = encrypt_runtime_image_sidecar(data_key, &successor)?;
    hosted.runtime_image = successor;
    replace_regular_file_synced(&slot.join(RUNTIME_STATE_FILE), &ciphertext)
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
    // Reject incomplete historical lineage—and especially a bare PCTL—before
    // reconciling any encrypted sidecar. Full signature/PVRI verification is
    // performed once the immutable descriptor has been authenticated below.
    require_runtime_application_attachments_for_open(&store)?;
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
    let runtime_image = reconcile_and_open_runtime_image(
        slot,
        &store,
        &plaintext.descriptor,
        local_node,
        &data_keys,
    )?;
    Ok(HostedPrivateAgent {
        store,
        descriptor: plaintext.descriptor,
        runtime_package: plaintext.runtime_package,
        bootstrap_metadata: plaintext.bootstrap_metadata,
        runtime_image,
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

fn reconcile_and_open_runtime_image(
    slot: &Path,
    store: &PrivateStore,
    descriptor: &AgentDescriptor,
    local_node: &PrivateNodeIdentity,
    data_keys: &BTreeMap<u64, PrivateDataKey>,
) -> Result<PrivateRuntimeImage, PrivateAgentHostError> {
    let current_store = store.core_position()?;
    let current_key_epochs = private_runtime_key_epoch_commitments(store)?;
    let canonical_path = slot.join(RUNTIME_STATE_FILE);
    let canonical = read_and_authenticate_runtime_image(
        &canonical_path,
        current_store.space(),
        current_store.agent(),
        descriptor,
        local_node.node,
        data_keys,
    )?;
    let staged = find_staged_runtime_image(slot)?;

    if runtime_image_matches_store(&canonical, current_store, &current_key_epochs) {
        authenticate_runtime_application_lineage(store, descriptor, &canonical)?;
        if let Some((path, _)) = staged {
            // Deliberate deletion-only exception: when Store and canonical
            // PVRI agree, any single strictly named staged ciphertext is an
            // unreachable suffix. It may use a successor epoch key which the
            // Store correctly did not retain. Never decrypt, promote, or
            // derive evidence from this file.
            remove_regular_file_if_present(&path)?;
            sync_directory(slot)?;
        }
        return Ok(canonical);
    }

    if canonical.key_epochs() == current_key_epochs
        && let Ok(rebound) = canonical.rebind_store_objects(current_store)
    {
        let key = data_keys
            .get(&current_store.epoch())
            .ok_or(PrivateAgentHostError::Corrupt)?;
        authenticate_runtime_application_lineage(store, descriptor, &rebound)?;
        replace_regular_file_synced(
            &canonical_path,
            &encrypt_runtime_image_sidecar(key, &rebound)?,
        )?;
        if let Some((path, _)) = staged {
            remove_regular_file_if_present(&path)?;
            sync_directory(slot)?;
        }
        return Ok(rebound);
    }

    let Some((staged_path, staged_control)) = staged else {
        return Err(PrivateAgentHostError::Corrupt);
    };
    let successor = read_and_authenticate_runtime_image(
        &staged_path,
        current_store.space(),
        current_store.agent(),
        descriptor,
        local_node.node,
        data_keys,
    )?;
    if successor.stable_projection().control_head() != Some(staged_control)
        || !runtime_image_matches_store(&successor, current_store, &current_key_epochs)
        || !runtime_image_is_direct_successor(&canonical, &successor)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    authenticate_runtime_application_lineage(store, descriptor, &successor)?;
    fs::rename(&staged_path, &canonical_path).map_err(map_io)?;
    sync_directory(slot)?;
    Ok(successor)
}

fn authenticate_runtime_application_lineage(
    store: &PrivateStore,
    descriptor: &AgentDescriptor,
    runtime_image: &PrivateRuntimeImage,
) -> Result<(), PrivateAgentHostError> {
    let controls = store.indexed_controls();
    if controls.is_empty() {
        if runtime_image.store().control_count() != 0
            || runtime_image.stable_projection().generation() != 0
            || runtime_image.stable_projection().control_head().is_some()
            || runtime_image.runtime_control().is_some()
            || runtime_image.last_full_replay().is_some()
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        return Ok(());
    }

    let mut previous: Option<(PrivateRuntimeApplication, bool)> = None;
    for (position, indexed) in controls.iter().enumerate() {
        let control_wire = store.read_control_wire(indexed)?;
        let control = PrivateControlRecord::decode(&control_wire)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let application = store
            .read_runtime_application(indexed.commitment)?
            .ok_or(PrivateAgentHostError::Corrupt)?;
        application
            .verify_with(
                descriptor,
                &RawAuthorityVerifier,
                &RawRecoveryAuthorityProofVerifier,
            )
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let is_last = position + 1 == controls.len();
        let endpoint_authenticated = match store.read_control_authority_evidence(indexed)? {
            Some(evidence_wire) => {
                authenticate_local_runtime_application_endpoint(
                    descriptor,
                    &control,
                    indexed.resulting_epoch,
                    &application,
                    &evidence_wire,
                )?;
                true
            }
            None if is_last
                && !matches!(&control.operation, PrivateControlOperation::Recover { .. }) =>
            {
                false
            }
            None => return Err(PrivateAgentHostError::Corrupt),
        };
        let predecessor_count =
            u32::try_from(position).map_err(|_| PrivateAgentHostError::LimitExceeded)?;
        let successor_count = predecessor_count
            .checked_add(1)
            .ok_or(PrivateAgentHostError::LimitExceeded)?;
        if !application.is_complete()
            || application.node() != runtime_image.node()
            || application.control() != &control
            || application.predecessor_store().control_count() != predecessor_count
            || application.expected_successor_store().control_count() != successor_count
            || application.expected_successor_store().control_head() != Some(indexed.commitment)
            || application.expected_successor_store().epoch() != indexed.resulting_epoch
        {
            return Err(PrivateAgentHostError::Corrupt);
        }

        if let Some((prior, prior_endpoint_authenticated)) = &previous {
            let expected_runtime_control = if prior.mutation().is_some() {
                Some(PrivateRuntimeControlPosition {
                    control: prior.control().commitment(),
                    sequence: prior.control().sequence,
                })
            } else {
                prior.predecessor_runtime_control()
            };
            let store_continuity =
                prior.expected_successor_store() == application.predecessor_store();
            let object_rebind = private_store_is_strict_object_growth(
                prior.expected_successor_store(),
                application.predecessor_store(),
            );
            if (!store_continuity && !object_rebind)
                || (object_rebind
                    && (!*prior_endpoint_authenticated || (!endpoint_authenticated && !is_last)))
                || (store_continuity
                    && prior.successor_runtime_image()
                        != Some(application.predecessor_runtime_image()))
                || prior.successor_stable_projection()
                    != Some(application.predecessor_stable_projection())
                || application.predecessor_runtime_control() != expected_runtime_control
                || application.applied_at() < prior.applied_at()
            {
                return Err(PrivateAgentHostError::Corrupt);
            }
        } else if application.predecessor_store().control_head().is_some()
            || application.predecessor_store().next_sequence() != 0
            || application.predecessor_stable_projection().generation() != 0
            || application
                .predecessor_stable_projection()
                .control_head()
                .is_some()
            || application.predecessor_runtime_control().is_some()
            || application
                .predecessor_stable_projection()
                .creation_receipt()
                != runtime_image.creation_receipt().commitment()
            || application.applied_at() < runtime_image.created_at()
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        previous = Some((application, endpoint_authenticated));
    }

    let (last, last_endpoint_authenticated) = previous.ok_or(PrivateAgentHostError::Corrupt)?;
    if last.expected_successor_store().control_count() as usize != controls.len()
        || last.expected_successor_store().control_head() != runtime_image.store().control_head()
        || if last_endpoint_authenticated {
            !runtime_image.matches_application_successor_after_object_growth(&last)
        } else {
            // The one crash-valid unresolved state is the exact newest PAPL
            // and its exact reopened PVRI before PCA/PSE attachment. It may
            // never become historical, and no object growth after that PAPL
            // is accepted until the authority evidence is durable.
            !last.matches_successor(runtime_image)
        }
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
}

/// Authenticate an authority endpoint emitted for this node's own completed
/// application. Local provenance requires exact PCRS3 equality. A future sync
/// receiver must use an explicit replica-stable provenance record instead:
/// raw-verify the source PCA/PRA/AOI, compare only its signed PSP with the
/// local completed PAPL, and never adopt the source node's PCRS/PVRI.
fn authenticate_local_runtime_application_endpoint(
    descriptor: &AgentDescriptor,
    control: &PrivateControlRecord,
    resulting_epoch: u64,
    application: &PrivateRuntimeApplication,
    evidence_wire: &[u8],
) -> Result<(), PrivateAgentHostError> {
    let evidence = PrivateControlAuthorityEvidence::decode(evidence_wire)?;
    let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let application_ack = PrivateControlApplicationAck::decode(&evidence.application_ack)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let authority = issuance.authority;
    let route = application.managed();
    let successor_projection = application
        .successor_stable_projection()
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let reopened_runtime_state =
        PrivateControlReopenedState::commitment_from_application(application)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if authority.space != route.space
        || authority.binding != descriptor.authority
        || application.issuance() != &issuance
        || application_ack.application.reopened_runtime_state != reopened_runtime_state
        || application_ack.application.stable_projection != successor_projection.commitment()
        || application_ack.application.applied_at != application.applied_at()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    evidence.verify_for_stable_projection(
        control,
        resulting_epoch,
        successor_projection.commitment(),
        route,
        authority,
    )?;
    Ok(())
}

fn private_store_is_strict_object_growth(
    predecessor: PrivateStoreCorePosition,
    successor: PrivateStoreCorePosition,
) -> bool {
    predecessor.validate().is_ok()
        && successor.validate().is_ok()
        && predecessor.space() == successor.space()
        && predecessor.agent() == successor.agent()
        && predecessor.owner() == successor.owner()
        && predecessor.epoch() == successor.epoch()
        && predecessor.control_head() == successor.control_head()
        && predecessor.next_sequence() == successor.next_sequence()
        && predecessor.control_count() == successor.control_count()
        && predecessor.control_root() == successor.control_root()
        && predecessor.key_epoch_root() == successor.key_epoch_root()
        && successor.object_count() > predecessor.object_count()
        && successor.object_root() != predecessor.object_root()
}

fn runtime_image_matches_store(
    image: &PrivateRuntimeImage,
    store: super::private_runtime::PrivateStoreCorePosition,
    key_epochs: &[PrivateKeyEpochCommitment],
) -> bool {
    image.store() == store && image.key_epochs() == key_epochs
}

fn runtime_image_is_direct_successor(
    predecessor: &PrivateRuntimeImage,
    successor: &PrivateRuntimeImage,
) -> bool {
    let key_lineage = if successor.key_epochs() == predecessor.key_epochs() {
        true
    } else if successor.key_epochs().len() == predecessor.key_epochs().len() {
        let last = predecessor.key_epochs().len().saturating_sub(1);
        !predecessor.key_epochs().is_empty()
            && successor.key_epochs()[..last] == predecessor.key_epochs()[..last]
            && successor.key_epochs()[last].epoch() == predecessor.key_epochs()[last].epoch()
            && successor.key_epochs()[last] != predecessor.key_epochs()[last]
    } else {
        successor.key_epochs().len() == predecessor.key_epochs().len().saturating_add(1)
            && successor.key_epochs().starts_with(predecessor.key_epochs())
    };
    successor.store().control_count()
        == predecessor
            .store()
            .control_count()
            .checked_add(1)
            .unwrap_or(u32::MAX)
        && successor.store().space() == predecessor.store().space()
        && successor.store().agent() == predecessor.store().agent()
        && successor.store().owner() == predecessor.store().owner()
        && successor.store().object_count() == predecessor.store().object_count()
        && successor.store().object_root() == predecessor.store().object_root()
        && successor.stable_projection().generation()
            == predecessor
                .stable_projection()
                .generation()
                .checked_add(1)
                .unwrap_or(u64::MAX)
        && successor.stable_projection().previous()
            == Some(predecessor.stable_projection().commitment())
        && successor.created_at() == predecessor.created_at()
        && successor.creation_receipt() == predecessor.creation_receipt()
        && successor.applied_at() >= predecessor.applied_at()
        && key_lineage
}

fn read_and_authenticate_runtime_image(
    path: &Path,
    space: SpaceId,
    agent: AgentId,
    descriptor: &AgentDescriptor,
    expected_node: NodeId,
    data_keys: &BTreeMap<u64, PrivateDataKey>,
) -> Result<PrivateRuntimeImage, PrivateAgentHostError> {
    require_regular_file(path)?;
    let bytes = read_bounded_file(path, MAX_PRIVATE_OBJECT_WIRE_BYTES)?;
    let object =
        EncryptedPrivateObject::decode(&bytes).map_err(|_| PrivateAgentHostError::Corrupt)?;
    if object.space != space
        || object.agent != agent
        || object.kind != EncryptedObjectKind::Snapshot
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let key = data_keys
        .get(&object.epoch)
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let plaintext = Zeroizing::new(decrypt_private_object(key, &object)?);
    if plaintext.len() > MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let image =
        PrivateRuntimeImage::decode(&plaintext).map_err(|_| PrivateAgentHostError::Corrupt)?;
    if image.node() != expected_node || image.store().epoch() != object.epoch {
        return Err(PrivateAgentHostError::Corrupt);
    }
    image
        .reopen_with(descriptor, &RawAuthorityVerifier)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(image)
}

fn staged_runtime_image_name(control: Hash) -> String {
    format!("{RUNTIME_STATE_FILE}{NEXT_PREFIX}{}", encode_hash(control))
}

fn staged_runtime_image_control(name: &str) -> Option<Hash> {
    let encoded = name.strip_prefix(&format!("{RUNTIME_STATE_FILE}{NEXT_PREFIX}"))?;
    decode_hash(encoded)
}

fn find_staged_runtime_image(
    slot: &Path,
) -> Result<Option<(PathBuf, Hash)>, PrivateAgentHostError> {
    let mut found = None;
    for entry in fs::read_dir(slot).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateAgentHostError::InvalidRoot)?;
        let Some(control) = staged_runtime_image_control(&name) else {
            continue;
        };
        if found.is_some() || entry.file_type().map_err(map_io)?.is_symlink() {
            return Err(PrivateAgentHostError::Alias);
        }
        require_regular_file(&entry.path())?;
        found = Some((entry.path(), control));
    }
    Ok(found)
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
    remove_regular_file_if_present(&slot.join(format!("{RUNTIME_STATE_FILE}{WRITE_SUFFIX}")))?;
    let mut seen_store = false;
    let mut runtime_stages = 0usize;
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
        if name == RUNTIME_STATE_FILE || staged_runtime_image_control(&name).is_some() {
            if file_type.is_symlink()
                || !file_type.is_file()
                || seen.insert(name.clone(), ()).is_some()
            {
                return Err(PrivateAgentHostError::Alias);
            }
            if name != RUNTIME_STATE_FILE {
                runtime_stages = runtime_stages.saturating_add(1);
                if runtime_stages > 1 {
                    return Err(PrivateAgentHostError::Alias);
                }
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
    if !seen_store
        || !seen.contains_key(RUNTIME_STATE_FILE)
        || SIDECAR_FILES.iter().any(|name| !seen.contains_key(*name))
    {
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
    encode_32_bytes(agent.as_bytes())
}

fn encode_hash(value: Hash) -> String {
    encode_32_bytes(value.as_bytes())
}

fn encode_32_bytes(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
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

fn decode_hash(name: &str) -> Option<Hash> {
    let bytes = decode_32_bytes(name)?;
    let value = Hash(bytes);
    (value != Hash::ZERO && encode_hash(value) == name).then_some(value)
}

fn decode_32_bytes(name: &str) -> Option<[u8; 32]> {
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
    Some(bytes)
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
    let parent = path.parent().ok_or(PrivateAgentHostError::InvalidRoot)?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(PrivateAgentHostError::InvalidRoot)?;
    let temporary = parent.join(format!("{file_name}{WRITE_SUFFIX}"));
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(PrivateAgentHostError::Corrupt);
            }
            if read_bounded_file(path, bytes.len())? != bytes {
                return Err(PrivateAgentHostError::Alias);
            }
            remove_regular_file_if_present(&temporary)?;
            sync_directory(parent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A stopped first attempt can leave only this unpublished file.
            // PVRP3 authenticates the exact canonical bytes, so discarding the
            // temporary and replaying them is deterministic and safe.
            remove_regular_file_if_present(&temporary)?;
            write_new_synced(&temporary, bytes)?;
            fs::rename(&temporary, path).map_err(map_io)?;
            sync_directory(parent)
        }
        Err(_) => Err(PrivateAgentHostError::Io),
    }
}

fn replace_regular_file_synced(path: &Path, bytes: &[u8]) -> Result<(), PrivateAgentHostError> {
    require_regular_file(path)?;
    let parent = path.parent().ok_or(PrivateAgentHostError::InvalidRoot)?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(PrivateAgentHostError::InvalidRoot)?;
    let temporary = parent.join(format!("{file_name}{WRITE_SUFFIX}"));
    remove_regular_file_if_present(&temporary)?;
    write_new_synced(&temporary, bytes)?;
    fs::rename(&temporary, path).map_err(map_io)?;
    sync_directory(parent)
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
    runtime_state: Vec<u8>,
}

struct RecoveryPlan {
    route: ManagedAgentTarget,
    owner: PrincipalId,
    source_hash: Hash,
    replacements_hash: Hash,
    recovery_signing_public_key: [u8; 32],
    recovery_encryption_public_key: [u8; 32],
    control_wire: Vec<u8>,
    proof_wire: Vec<u8>,
    recovered_archive: Vec<u8>,
    completion: Option<RecoveryPlanCompletion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoveryPlanCompletion {
    issuance_ack: Vec<u8>,
    application_ack: Vec<u8>,
    evidence_commitment: Hash,
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
    if !plan.route.is_valid()
        || plan.owner == PrincipalId::ZERO
        || plan.source_hash == Hash::ZERO
        || plan.replacements_hash == Hash::ZERO
        || plan.recovery_signing_public_key == [0; 32]
        || !valid_x25519_public_key(&plan.recovery_encryption_public_key)
        || plan.control_wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES
        || plan.proof_wire.len() > MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES
        || plan.recovered_archive.len() > MAX_PRIVATE_HOST_ARCHIVE_BYTES
        || plan.completion.as_ref().is_some_and(|completion| {
            completion.issuance_ack.len() > MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
                || completion.application_ack.len() > MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES
                || completion.evidence_commitment == Hash::ZERO
        })
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RECOVERY_PLAN_MAGIC);
    bytes.extend_from_slice(&RECOVERY_PLAN_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(plan.route.space.as_bytes());
    encoder.fixed(plan.route.agent.as_bytes());
    encoder.fixed(plan.route.runtime_deployment.as_bytes());
    encoder.fixed(plan.owner.as_bytes());
    encoder.fixed(plan.source_hash.as_bytes());
    encoder.fixed(plan.replacements_hash.as_bytes());
    encoder.fixed(&plan.recovery_signing_public_key);
    encoder.fixed(&plan.recovery_encryption_public_key);
    encoder.bytes(&plan.control_wire);
    encoder.bytes(&plan.proof_wire);
    encoder.bytes(&plan.recovered_archive);
    encoder.option(&plan.completion, |encoder, completion| {
        encoder.bytes(&completion.issuance_ack);
        encoder.bytes(&completion.application_ack);
        encoder.fixed(completion.evidence_commitment.as_bytes());
    });
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
        route: ManagedAgentTarget {
            space: SpaceId(decoder.fixed().map_err(map_decode)?),
            agent: AgentId(decoder.fixed().map_err(map_decode)?),
            runtime_deployment: DeploymentId(decoder.fixed().map_err(map_decode)?),
        },
        owner: PrincipalId(decoder.fixed().map_err(map_decode)?),
        source_hash: Hash(decoder.fixed().map_err(map_decode)?),
        replacements_hash: Hash(decoder.fixed().map_err(map_decode)?),
        recovery_signing_public_key: decoder.fixed().map_err(map_decode)?,
        recovery_encryption_public_key: decoder.fixed().map_err(map_decode)?,
        control_wire: decoder
            .bytes_bounded(MAX_PRIVATE_CONTROL_WIRE_BYTES)
            .map_err(map_decode)?,
        proof_wire: decoder
            .bytes_bounded(MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES)
            .map_err(map_decode)?,
        recovered_archive: decoder
            .bytes_bounded(MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .map_err(map_decode)?,
        completion: decoder
            .option(|decoder| {
                Ok(RecoveryPlanCompletion {
                    issuance_ack: decoder
                        .bytes_bounded(MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES)?,
                    application_ack: decoder
                        .bytes_bounded(MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES)?,
                    evidence_commitment: Hash(decoder.fixed()?),
                })
            })
            .map_err(map_decode)?,
    };
    let authenticator = Hash(decoder.fixed().map_err(map_decode)?);
    if !decoder.exhausted()
        || !plan.route.is_valid()
        || plan.owner == PrincipalId::ZERO
        || plan.source_hash == Hash::ZERO
        || plan.replacements_hash == Hash::ZERO
        || plan.recovery_signing_public_key == [0; 32]
        || !valid_x25519_public_key(&plan.recovery_encryption_public_key)
        || plan.completion.as_ref().is_some_and(|completion| {
            completion.evidence_commitment == Hash::ZERO
                || completion.issuance_ack.is_empty()
                || completion.application_ack.is_empty()
        })
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let plan_hash = Hash::digest(RECOVERY_PLAN_HASH_DOMAIN, &[&bytes[..authenticated_len]]);
    if node_key.recovery_plan_authenticator(plan_hash)? != authenticator {
        return Err(PrivateAgentHostError::Corrupt);
    }
    validate_recovery_plan_material(&plan)?;
    if encode_recovery_plan(&plan, node_key)? != bytes {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(plan)
}

fn validate_recovery_plan_material(
    plan: &RecoveryPlan,
) -> Result<(PrivateControlRecord, PrivateRecoveryAuthorityProof), PrivateAgentHostError> {
    let control = PrivateControlRecord::decode(&plan.control_wire)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let proof = PrivateRecoveryAuthorityProof::decode(&plan.proof_wire)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if control.encode().ok().as_deref() != Some(plan.control_wire.as_slice())
        || proof.encode().ok().as_deref() != Some(plan.proof_wire.as_slice())
        || !matches!(&control.operation, PrivateControlOperation::Recover { .. })
        || control.signer != PrivateControlSigner::Recovery
        || control.signer_public_key != plan.recovery_signing_public_key
        || !proof.matches_control(&control)
        || proof.managed != plan.route
        || proof.recovery_public_key != plan.recovery_signing_public_key
        || proof
            .verify_with(&RawRecoveryAuthorityProofVerifier)
            .is_err()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    verify_control_record_signature(&control).map_err(|_| PrivateAgentHostError::Corrupt)?;
    let archive = decode_host_archive(&plan.recovered_archive, true)?;
    if archive.space != plan.route.space || archive.agent != plan.route.agent {
        return Err(PrivateAgentHostError::Corrupt);
    }
    if let Some(completion) = &plan.completion {
        let issuance = AuthorityOperationIssuanceAck::decode(&completion.issuance_ack)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let application = PrivateControlApplicationAck::decode(&completion.application_ack)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
            &issuance,
            &application,
            Some(&proof),
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
        if issuance.encode().ok().as_deref() != Some(completion.issuance_ack.as_slice())
            || application.encode().ok().as_deref() != Some(completion.application_ack.as_slice())
            || evidence.commitment().ok() != Some(completion.evidence_commitment)
            || issuance.authority != application.authority
            || issuance.receipt.selector.operation != AuthorityOperationKind::RecoverPrivateAgent
            || issuance.receipt.selector.space != plan.route.space
            || issuance.receipt.selector.agent != plan.route.agent
            || issuance.receipt.selector.runtime_deployment != plan.route.runtime_deployment
            || issuance.receipt.selector.request != proof.commitment()
            || application.application.managed != plan.route
            || application.application.operation != AuthorityOperationKind::RecoverPrivateAgent
            || application.application.control != control.commitment()
            || application.application.control_sequence != control.sequence
            || application.application.control_previous != control.previous
            || application.application.epoch != proof.next_epoch
            || application.application.post_member_set != proof.replacement_member_set
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
    }
    Ok((control, proof))
}

fn validate_recovery_plan_host(
    plan: &RecoveryPlan,
    hosted: &HostedPrivateAgent,
) -> Result<(), PrivateAgentHostError> {
    let (control, proof) = validate_recovery_plan_material(plan)?;
    let binding = hosted.store.binding();
    let member_set =
        private_member_set_commitment(hosted.store.authorized_nodes().iter().map(|node| node.node))
            .ok_or(PrivateAgentHostError::Corrupt)?;
    if binding.space != plan.route.space
        || binding.agent != plan.route.agent
        || binding.owner != plan.owner
        || binding.epoch != proof.next_epoch
        || binding.control_head != Some(control.commitment())
        || binding.next_sequence
            != control
                .sequence
                .checked_add(1)
                .ok_or(PrivateAgentHostError::LimitExceeded)?
        || hosted.descriptor.identity.space != plan.route.space
        || hosted.descriptor.identity.agent != plan.route.agent
        || hosted.descriptor.identity.owner != plan.owner
        || hosted.descriptor.identity.runtime_deployment != plan.route.runtime_deployment
        || hosted.descriptor.private_recovery
            != Some(PrivateRecoveryBinding {
                signing_key_commitment: recovery_signing_public_key_commitment(
                    &plan.recovery_signing_public_key,
                ),
                encryption_public_key: plan.recovery_encryption_public_key,
            })
        || hosted.store.recovery_public_key() != plan.recovery_signing_public_key
        || hosted.store.recovery_encryption_public_key() != plan.recovery_encryption_public_key
        || member_set != proof.replacement_member_set
        || !hosted
            .store
            .control_is_exact(control.commitment(), &plan.control_wire)?
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    if let Some(completion) = &plan.completion {
        verify_completed_recovery_evidence(plan, hosted, completion)?;
        // Publication is gated on the whole imported recovery history, not
        // merely the new head. This keeps a missing, mixed-version, or forged
        // historical PSE from becoming live on the no-crash success path.
        validate_planless_staged_recovery(hosted, true)?;
    }
    Ok(())
}

/// A planless staging slot is normally an ordinary create that stopped after
/// its own authenticated files were complete. Recovery has a stronger gate:
/// PVRP3 is retired immediately before publication, so the exact Recover head
/// must already carry a self-contained PSE2 with PRA1+AOI1+PCA2. This check
/// prevents a nonempty, planless partial recovery from being mistaken for an
/// ordinary completed create.
fn validate_planless_staged_recovery(
    hosted: &HostedPrivateAgent,
    recovery_required: bool,
) -> Result<(), PrivateAgentHostError> {
    let binding = hosted.store.binding();
    let mut saw_recovery = false;
    let mut current_head_is_verified_recovery = false;
    for indexed in hosted.store.indexed_controls() {
        let indexed_wire = hosted.store.read_control_wire(indexed)?;
        let indexed_control = PrivateControlRecord::decode(&indexed_wire)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        if !matches!(
            &indexed_control.operation,
            PrivateControlOperation::Recover { .. }
        ) {
            continue;
        }
        saw_recovery = true;
        if indexed_control.signer != PrivateControlSigner::Recovery
            || indexed_control.signer_public_key != hosted.store.recovery_public_key()
        {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        let evidence_wire = hosted
            .store
            .read_control_authority_evidence(indexed)?
            .ok_or(PrivateAgentHostError::Unauthorized)?;
        let evidence = PrivateControlAuthorityEvidence::decode(&evidence_wire)?;
        let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let selector = &issuance.receipt.selector;
        let authority = issuance.authority;
        let route = ManagedAgentTarget {
            space: selector.space,
            agent: selector.agent,
            runtime_deployment: selector.runtime_deployment,
        };
        let is_current = binding.control_head == Some(indexed.commitment);
        if !route.is_valid()
            || route.space != hosted.descriptor.identity.space
            || route.agent != hosted.descriptor.identity.agent
            || (is_current
                && route.runtime_deployment != hosted.descriptor.identity.runtime_deployment)
            || authority.space != route.space
            || authority.binding != hosted.descriptor.authority
        {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        evidence.verify_for(&indexed_control, indexed.resulting_epoch, route, authority)?;
        current_head_is_verified_recovery |= is_current;
    }
    let Some(_) = binding.control_head else {
        if saw_recovery || recovery_required {
            return Err(PrivateAgentHostError::Corrupt);
        }
        return Ok(());
    };
    if !current_head_is_verified_recovery {
        // Ordinary create staging has no control head. The recovery staging
        // flow publishes immediately after attaching evidence, so its current
        // head must be the exact Recover carried by PVRP3. Historical Recover
        // entries are permitted only when their own PSE2 is valid, but a
        // later owner control cannot pass through this recovery-only path.
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
}

fn validate_verified_backup_recovery_evidence(
    backup: &super::private_store::VerifiedEncryptedBackup,
    descriptor: &AgentDescriptor,
) -> Result<(), PrivateAgentHostError> {
    for (index, control, evidence_wire) in backup.controls_with_authority_evidence() {
        if !matches!(&control.operation, PrivateControlOperation::Recover { .. }) {
            continue;
        }
        let recovery = descriptor
            .private_recovery
            .as_ref()
            .ok_or(PrivateAgentHostError::Corrupt)?;
        if control.signer != PrivateControlSigner::Recovery
            || recovery.signing_key_commitment
                != recovery_signing_public_key_commitment(&control.signer_public_key)
        {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        let evidence_wire = evidence_wire.ok_or(PrivateAgentHostError::Unauthorized)?;
        let evidence = PrivateControlAuthorityEvidence::decode(evidence_wire)?;
        let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let selector = &issuance.receipt.selector;
        let route = ManagedAgentTarget {
            space: selector.space,
            agent: selector.agent,
            runtime_deployment: selector.runtime_deployment,
        };
        if route.space != descriptor.identity.space
            || route.agent != descriptor.identity.agent
            || issuance.authority.space != route.space
            || issuance.authority.binding != descriptor.authority
        {
            return Err(PrivateAgentHostError::Unauthorized);
        }
        evidence.verify_for(control, index.resulting_epoch, route, issuance.authority)?;
    }
    Ok(())
}

fn validate_exact_recovery_result_loss_target(
    hosted: &HostedPrivateAgent,
    expected_control: &PrivateControlRecord,
    expected_evidence_wire: &[u8],
    expected_route: ManagedAgentTarget,
    expected_authority: AuthorityActorTarget,
) -> Result<(), PrivateAgentHostError> {
    validate_planless_staged_recovery(hosted, true)?;
    let binding = hosted.store.binding();
    let commitment = expected_control.commitment();
    let entry = hosted
        .store
        .indexed_controls()
        .iter()
        .find(|entry| entry.commitment == commitment)
        .ok_or(PrivateAgentHostError::Unauthorized)?;
    if binding.control_head != Some(commitment)
        || binding.space != expected_route.space
        || binding.agent != expected_route.agent
        || hosted.descriptor.identity.runtime_deployment != expected_route.runtime_deployment
        || expected_authority.space != binding.space
        || hosted.descriptor.authority != expected_authority.binding
        || !hosted.store.control_is_exact(
            commitment,
            &expected_control
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?,
        )?
        || hosted
            .store
            .read_control_authority_evidence(entry)?
            .as_deref()
            != Some(expected_evidence_wire)
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    let evidence = PrivateControlAuthorityEvidence::decode(expected_evidence_wire)?;
    evidence.verify_for(
        expected_control,
        entry.resulting_epoch,
        expected_route,
        expected_authority,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reconcile_exact_duplicate_slot<V: PrivateNodeAuthorityVerifier>(
    source: &Path,
    destination: &Path,
    space: SpaceId,
    owner: PrincipalId,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    authority: &V,
) -> Result<(), PrivateAgentHostError> {
    require_real_directory(source)?;
    require_real_directory(destination)?;
    if fs::symlink_metadata(source.join(RECOVERY_PLAN_FILE)).is_ok()
        || fs::symlink_metadata(source.join(RECOVERY_PLAN_WRITE_FILE)).is_ok()
    {
        return Err(PrivateAgentHostError::Alias);
    }
    let staged = open_hosted_agent(source, space, owner, local_node, node_key, authority)?;
    let published = open_hosted_agent(destination, space, owner, local_node, node_key, authority)?;
    // A destination-first cross-directory Create publication can leave the
    // exact zero-head genesis visible under both names. Recover heads remain
    // accepted only when their own retained authority evidence verifies.
    validate_planless_staged_recovery(&staged, false)?;
    validate_planless_staged_recovery(&published, false)?;
    let exact_archive =
        |slot: &Path, hosted: &HostedPrivateAgent| -> Result<Vec<u8>, PrivateAgentHostError> {
            let archive = HostArchive {
                space,
                agent: hosted.descriptor.identity.agent,
                store: hosted
                    .store
                    .export_encrypted_backup(MAX_PRIVATE_BACKUP_BYTES)?,
                descriptor: read_sidecar_wire(slot, DESCRIPTOR_FILE)?,
                runtime: read_sidecar_wire(slot, RUNTIME_FILE)?,
                bootstrap: read_sidecar_wire(slot, BOOTSTRAP_FILE)?,
                runtime_state: read_sidecar_wire(slot, RUNTIME_STATE_FILE)?,
            };
            encode_host_archive(&archive, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
        };
    if exact_archive(source, &staged)? != exact_archive(destination, &published)? {
        return Err(PrivateAgentHostError::Alias);
    }
    drop(staged);
    drop(published);
    Ok(())
}

fn retired_duplicate_path(creating: &Path, agent: AgentId) -> PathBuf {
    creating.join(format!(
        "{}{RETIRED_DUPLICATE_SUFFIX}",
        encode_agent_id(agent)
    ))
}

/// Retire an already-proven byte-identical staging duplicate through one
/// atomic name change. Once the parent sync publishes the reserved tombstone,
/// recursive cleanup is restartable: no partial tree is ever interpreted as
/// an Agent slot again.
fn retire_exact_duplicate_slot(
    source: &Path,
    creating: &Path,
    agent: AgentId,
) -> Result<(), PrivateAgentHostError> {
    let retired = retired_duplicate_path(creating, agent);
    match fs::symlink_metadata(&retired) {
        Ok(_) => return Err(PrivateAgentHostError::Alias),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrivateAgentHostError::Io),
    }
    fs::rename(source, &retired).map_err(map_io)?;
    sync_directory(creating)?;
    require_real_directory(&retired)?;
    fs::remove_dir_all(&retired).map_err(map_io)?;
    sync_directory(creating)
}

/// Resume only names which the exact duplicate-retirement protocol can have
/// published. The atomic tombstone is sufficient authorization to finish
/// removal; arbitrary names and symlinks remain fail-closed for the normal
/// staging-directory scanner.
fn retire_duplicate_tombstones(creating: &Path) -> Result<(), PrivateAgentHostError> {
    let mut retired = Vec::new();
    for entry in fs::read_dir(creating).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateAgentHostError::InvalidRoot)?;
        let Some(agent_name) = name.strip_suffix(RETIRED_DUPLICATE_SUFFIX) else {
            continue;
        };
        if decode_agent_id(agent_name).is_none() {
            continue;
        }
        let file_type = entry.file_type().map_err(map_io)?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(PrivateAgentHostError::Alias);
        }
        retired.push(entry.path());
    }
    retired.sort_unstable();
    for path in retired {
        require_real_directory(&path)?;
        fs::remove_dir_all(&path).map_err(map_io)?;
        sync_directory(creating)?;
    }
    Ok(())
}

fn verify_completed_recovery_evidence(
    plan: &RecoveryPlan,
    hosted: &HostedPrivateAgent,
    completion: &RecoveryPlanCompletion,
) -> Result<(), PrivateAgentHostError> {
    let (control, proof) = validate_recovery_plan_material(plan)?;
    let issuance = AuthorityOperationIssuanceAck::decode(&completion.issuance_ack)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let application = PrivateControlApplicationAck::decode(&completion.application_ack)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let authority = issuance.authority;
    let evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
        &issuance,
        &application,
        Some(&proof),
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if authority.space != plan.route.space || authority.binding != hosted.descriptor.authority {
        return Err(PrivateAgentHostError::Corrupt);
    }
    verify_recovery_authority_evidence(
        &evidence,
        &control,
        &proof,
        proof.next_epoch,
        plan.route,
        authority,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if evidence.commitment().ok() != Some(completion.evidence_commitment) {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let entry = hosted
        .store
        .indexed_controls()
        .iter()
        .find(|entry| entry.commitment == control.commitment())
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let evidence_wire = evidence.encode()?;
    if hosted
        .store
        .read_control_authority_evidence(entry)?
        .as_deref()
        != Some(evidence_wire.as_slice())
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
}

/// Verify recovery completion against the exact retained PRA1 rather than
/// attempting the normal private-control intent reconstruction (which
/// deliberately rejects Recover). Neither AOI1 nor PCA2 is accepted as a
/// substitute for possession of the independently signed recovery proof.
fn verify_recovery_authority_evidence(
    evidence: &PrivateControlAuthorityEvidence,
    control: &PrivateControlRecord,
    proof: &PrivateRecoveryAuthorityProof,
    resulting_epoch: u64,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<(), PrivateAgentHostError> {
    if !route.is_valid()
        || !authority.is_valid()
        || route.space != authority.space
        || control.space != route.space
        || control.agent != route.agent
        || proof.managed != route
        || !proof.matches_control(control)
        || proof
            .verify_with(&RawRecoveryAuthorityProofVerifier)
            .is_err()
        || evidence.recovery_proof.as_deref() != proof.encode().ok().as_deref()
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    verify_control_record_signature(control)?;
    let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let application = PrivateControlApplicationAck::decode(&evidence.application_ack)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    if issuance.encode().ok().as_deref() != Some(evidence.issuance_ack.as_slice())
        || application.encode().ok().as_deref() != Some(evidence.application_ack.as_slice())
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    let intent = AuthorityOperationIntent::RecoverPrivateAgent {
        proof: proof.clone(),
    };
    let selector = &issuance.receipt.selector;
    if issuance.authority != authority
        || application.authority != authority
        || issuance
            .verify_with(authority.binding, &RawAuthorityVerifier)
            .is_err()
        || application
            .verify_issuance_tombstone_with(
                authority,
                issuance.authorization_invocation,
                issuance.acknowledgement_invocation,
                issuance.authorization_sequence,
                issuance.commitment(),
                &RawAuthorityVerifier,
            )
            .is_err()
        || application.operation_call != issuance.operation_call
        || application.approval != issuance.approval
        || application.receipt != issuance.receipt
        || application.issued_at != issuance.issued_at
        || !private_intent_matches_application(&intent, &application.application)
        || application.application.epoch != resulting_epoch
        || selector.request != proof.commitment()
        || selector.operation != AuthorityOperationKind::RecoverPrivateAgent
        || selector.actor.is_some()
        || selector.actor_deployment.is_some()
        || selector.space != route.space
        || selector.agent != route.agent
        || selector.runtime_deployment != route.runtime_deployment
    {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    Ok(())
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

fn commit_completed_recovery_plan(
    slot: &Path,
    plan: &RecoveryPlan,
    node_key: &PrivateNodeDecryptionKey,
    stop: PrivateRuntimeApplicationStop,
) -> Result<(), PrivateAgentHostError> {
    let temporary = slot.join(RECOVERY_PLAN_WRITE_FILE);
    let canonical = slot.join(RECOVERY_PLAN_FILE);
    require_regular_file(&canonical)?;
    remove_regular_file_if_present(&temporary)?;
    let bytes = encode_recovery_plan(plan, node_key)?;
    write_new_synced(&temporary, &bytes)?;
    application_stop(stop, PrivateRuntimeApplicationStop::AfterRecoveryPlanWrite)?;
    fs::rename(&temporary, &canonical).map_err(map_io)?;
    sync_directory(slot)?;
    application_stop(
        stop,
        PrivateRuntimeApplicationStop::AfterRecoveryPlanCommitted,
    )
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
    bytes.extend_from_slice(&HOST_ARCHIVE_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(archive.space.as_bytes());
    encoder.fixed(archive.agent.as_bytes());
    encoder.bytes(&archive.store);
    encoder.bytes(&archive.descriptor);
    encoder.bytes(&archive.runtime);
    encoder.bytes(&archive.bootstrap);
    encoder.bytes(&archive.runtime_state);
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
        || decoder.u16().map_err(map_decode)? != HOST_ARCHIVE_VERSION
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
        runtime_state: decoder
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

fn authenticate_recovery_source_runtime_image(
    archive: &HostArchive,
    verified: &super::private_store::VerifiedEncryptedBackup,
    descriptor: &AgentDescriptor,
    data_key: &PrivateDataKey,
) -> Result<(), PrivateAgentHostError> {
    let binding = verified.binding();
    let object = EncryptedPrivateObject::decode(&archive.runtime_state)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if object.space != archive.space
        || object.agent != archive.agent
        || object.epoch != binding.epoch
        || object.kind != EncryptedObjectKind::Snapshot
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let plaintext = Zeroizing::new(decrypt_private_object(data_key, &object)?);
    if plaintext.len() > MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let image =
        PrivateRuntimeImage::decode(&plaintext).map_err(|_| PrivateAgentHostError::Corrupt)?;
    image
        .reopen_with(descriptor, &RawAuthorityVerifier)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let store = image.store();
    let exact_store = verified.core_position()?;
    let key_epochs = verified
        .key_epochs()
        .iter()
        .map(|epoch| {
            PrivateKeyEpochCommitment::from_epoch(epoch).map_err(|_| PrivateAgentHostError::Corrupt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_node_is_current = verified.key_epochs().last().is_some_and(|epoch| {
        epoch
            .sealed_data_keys
            .binary_search_by_key(&image.node(), |sealed| sealed.node)
            .is_ok()
    });
    if !source_node_is_current || store != exact_store || image.key_epochs() != key_epochs {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
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
    // The complete creation descriptor is immutable, including its genesis
    // replica roster. Live membership is carried only by Store controls.
    left.descriptor == right.descriptor
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
        InvocationId, ManagementError, ManagementReply, MethodMode, ResumeWork, RuntimeOutcome,
        RuntimeState, StateLane, StorageKind,
    };

    use crate::agent::package_admission::{
        ScriptedRuntimeCase, ScriptedRuntimeCopy, admitted_scripted_runtime_for_test,
        admitted_standard_runtime_for_test,
    };
    use crate::agent::private_crypto::{
        OfflineRecoveryDecryptionKey, OfflineRecoveryKit, RecoverySigningKey,
        sign_recovery_control_record,
    };
    use crate::agent::private_sync::{
        MAX_PRIVATE_SYNC_ITEMS, MAX_PRIVATE_SYNC_PAGE_BYTES, PrivateSyncCursor, PrivateSyncItem,
        PrivateSyncPhase,
    };
    use vos_pvm_compiler::assembler::Assembler;
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const TEST_AUTHORITY_DOMAIN: &[u8] = b"vos/test/private-host-authority/v1";
    const SENTINEL: &[u8] = b"PRIVATE-HOST-PLAINTEXT-SENTINEL-7fbd96";
    const RUNTIME_STATE_SENTINEL: &[u8] = b"PRIVATE-RUNTIME-STATE-SENTINEL-b189f2";
    const CREATED_AT: u64 = 20;

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

    fn creation_receipt(descriptor: &AgentDescriptor, observed_at: u64) -> AuthorityReceipt {
        let request = ManagementRequest::Create(Box::new(descriptor.clone()));
        let key =
            SigningKey::from_bytes(&[descriptor.creation_nonce.as_bytes()[0].wrapping_add(90); 32]);
        assert_eq!(
            key.verifying_key().to_bytes(),
            descriptor.authority.public_key
        );
        let mut receipt = AuthorityReceipt {
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
                    commitment: Hash([0x91; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: descriptor.authority.initial_epoch,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: observed_at.saturating_sub(1),
                expires_at: observed_at.saturating_add(100),
                request: request.commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [0; 64],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        receipt
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

    fn unique_offset(haystack: &[u8], needle: &[u8]) -> usize {
        let offsets = haystack
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(offsets.len(), 1, "fixture identity must be unique");
        offsets[0]
    }

    fn scripted_runtime_fixture(
        space: SpaceId,
        owner: PrincipalId,
        nodes: &[PrivateNodeIdentity],
    ) -> (Vec<u8>, AgentDescriptor, AuthorityReceipt) {
        scripted_runtime_fixture_with_management(space, owner, nodes, None)
    }

    fn genesis_runtime_state() -> RuntimeState {
        RuntimeState {
            control: RUNTIME_STATE_SENTINEL.to_vec(),
            linear: Vec::new(),
            merge: b"private-genesis-merge".to_vec(),
            local: b"private-genesis-local".to_vec(),
        }
    }

    fn scripted_runtime_fixture_with_management(
        space: SpaceId,
        owner: PrincipalId,
        nodes: &[PrivateNodeIdentity],
        management: Option<(PrivateControlOperation, PrivateRuntimeMutation, Vec<u8>)>,
    ) -> (Vec<u8>, AgentDescriptor, AuthorityReceipt) {
        // Program identity and the descriptor refer to each other. Construct
        // one same-width placeholder call, then have the real PVM copy the
        // exact descriptor identity from its read-only input into the fixed
        // canonical Created reply.
        let placeholder_runtime = admitted_standard_runtime_for_test("private-placeholder", 0x59);
        let placeholder = descriptor(space, owner, 31, nodes, &placeholder_runtime);
        let placeholder_receipt = creation_receipt(&placeholder, CREATED_AT);
        let genesis_at = placeholder_receipt.selector.valid_from;
        let input = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space,
            agent: placeholder.identity.agent,
            runtime_deployment: placeholder.identity.runtime_deployment,
            state: RuntimeState::default(),
            request: Box::new(ManagementRequest::Create(Box::new(placeholder.clone()))),
            authority: Some(Box::new(placeholder_receipt)),
            observed_slot: genesis_at,
        }
        .encode()
        .unwrap();
        let output = RuntimeTransition {
            state: genesis_runtime_state(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                placeholder.identity.clone(),
            ))),
        }
        .encode()
        .unwrap();
        let identity = identity_bytes(&placeholder.identity);
        let create_case = ScriptedRuntimeCase {
            copies: vec![ScriptedRuntimeCopy {
                input_offset: unique_offset(&input, &identity),
                output_offset: unique_offset(&output, &identity),
                len: identity.len(),
            }],
            input,
            output,
        };
        let mut cases = vec![create_case];
        if let Some((operation, mutation, output)) = management {
            let control = PrivateControlRecord {
                space,
                agent: placeholder.identity.agent,
                sequence: 0,
                previous: None,
                operation,
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0x71; 32],
                signature: [0x72; 64],
            };
            // The runtime dispatch case needs canonical shape and exact wire
            // length, not an owner-valid signature from the future Store.
            assert!(control.validate_shape());
            let management_request = ManagementRequest::PrivateControl {
                control: Box::new(control.clone()),
                mutation: Box::new(mutation),
            };
            assert!(management_request.is_valid());
            let operation = management_request.authority_operation().unwrap();
            let (actor, actor_deployment) = management_request.authority_actor_selector();
            let key = SigningKey::from_bytes(
                &[placeholder.creation_nonce.as_bytes()[0].wrapping_add(90); 32],
            );
            let mut authority_receipt = AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: placeholder.authority.policy,
                    issuer: placeholder.authority.issuer,
                    space,
                    agent: placeholder.identity.agent,
                    operation,
                    runtime_deployment: placeholder.identity.runtime_deployment,
                    actor,
                    actor_deployment,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: Hash([0x73; 32]),
                    },
                    lane_roots: AuthorityLaneRoots {
                        control: None,
                        linear: Some(Hash([0x74; 32])),
                        merge: None,
                        local: None,
                    },
                    epoch: placeholder.authority.initial_epoch,
                    decision_sequence: 0,
                    acknowledged_through: 0,
                    valid_from: 40,
                    expires_at: 144,
                    request: control.commitment(),
                },
                public_key: placeholder.authority.public_key,
                signature: [0; 64],
            };
            authority_receipt.signature = key.sign(&authority_receipt.signing_bytes()).to_bytes();
            let management_input = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space,
                agent: placeholder.identity.agent,
                runtime_deployment: placeholder.identity.runtime_deployment,
                state: genesis_runtime_state(),
                request: Box::new(management_request),
                authority: Some(Box::new(authority_receipt)),
                observed_slot: 44,
            }
            .encode()
            .unwrap();
            assert_ne!(management_input.len(), cases[0].input.len());
            cases.push(ScriptedRuntimeCase {
                input: management_input,
                output,
                copies: Vec::new(),
            });
        }
        let runtime = admitted_scripted_runtime_for_test(
            &format!(
                "fixture-runtime-{}",
                core::str::from_utf8(SENTINEL).unwrap()
            ),
            0x5a,
            cases,
        );
        let descriptor = descriptor(space, owner, 31, nodes, &runtime);
        let receipt = creation_receipt(&descriptor, CREATED_AT);
        (runtime.exact_bytes().to_vec(), descriptor, receipt)
    }

    fn admitted_runtime_with_program_for_test(
        name: &str,
        program: Vec<u8>,
    ) -> AdmittedRuntimePackage {
        let signing_key = SigningKey::from_bytes(&[0x5b; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut envelope = PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: name.into(),
                outer_program: BlobRef::of_bytes(&program),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                signing: PackageSigning {
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                    signature: [0; 64],
                },
            }),
            artifacts: vec![PackageArtifact {
                identity: BlobRef::of_bytes(&program),
                bytes: program,
            }],
        };
        let signing_bytes = envelope.signing_bytes().unwrap();
        envelope.manifest.signing_mut().signature = signing_key.sign(&signing_bytes).to_bytes();
        admit_runtime_package(&envelope.encode().unwrap()).unwrap()
    }

    struct Fixture {
        directory: TestDirectory,
        space: SpaceId,
        owner: PrincipalId,
        recovery: RecoverySigningKey,
        recovery_encryption: OfflineRecoveryDecryptionKey,
        nodes: Vec<NodeFixture>,
        descriptor: AgentDescriptor,
        creation_receipt: AuthorityReceipt,
        observed_at: u64,
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
        let mut bootstrap = b"private-bootstrap:".to_vec();
        bootstrap.extend_from_slice(SENTINEL);
        let (runtime, descriptor, creation_receipt) =
            scripted_runtime_fixture(space, owner, &identities);
        Fixture {
            directory,
            space,
            owner,
            recovery,
            recovery_encryption,
            nodes,
            descriptor,
            creation_receipt,
            observed_at: CREATED_AT,
            runtime,
            bootstrap,
        }
    }

    fn fixture_with_management(
        operation: PrivateControlOperation,
        mutation: PrivateRuntimeMutation,
        output: Vec<u8>,
    ) -> Fixture {
        let mut fixture = fixture(1);
        let identities = identities(&fixture);
        let (runtime, descriptor, creation_receipt) = scripted_runtime_fixture_with_management(
            fixture.space,
            fixture.owner,
            &identities,
            Some((operation, mutation, output)),
        );
        assert_eq!(descriptor.identity.agent, fixture.descriptor.identity.agent);
        fixture.runtime = runtime;
        fixture.descriptor = descriptor;
        fixture.creation_receipt = creation_receipt;
        fixture
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
                creation_receipt: &fixture.creation_receipt,
                observed_at: fixture.observed_at,
            },
            &TestAuthority,
        )
        .unwrap()
    }

    fn assert_node_local_backup_restore_fails_closed(
        host: &mut PrivateAgentHost,
        fixture: &Fixture,
        agent: AgentId,
        backup: &[u8],
    ) {
        let result = host.restore_encrypted_backup(
            agent,
            DurableRecoveryRecipient::from_durable_keystore(
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
            )
            .unwrap(),
            backup,
            &TestAuthority,
        );
        assert!(
            matches!(
                &result,
                Err(PrivateAgentHostError::Corrupt)
                    | Err(PrivateAgentHostError::InvalidScope)
                    | Err(PrivateAgentHostError::UnsupportedOperation)
            ),
            "unexpected restore result: {result:?}"
        );
        assert_eq!(host.binding(agent), Err(PrivateAgentHostError::NotFound));
        assert!(!host.agent_path(agent).exists());
        assert!(!host.creating_path(agent).exists());
    }

    fn create_with_runtime(
        host: &mut PrivateAgentHost,
        fixture: &Fixture,
        descriptor: &AgentDescriptor,
        runtime: &AdmittedRuntimePackage,
        receipt: &AuthorityReceipt,
    ) -> Result<AgentId, PrivateAgentHostError> {
        host.create_agent(
            PrivateAgentCreate {
                descriptor,
                nodes: &identities(fixture),
                recovery_recipient: DurableRecoveryRecipient::from_durable_keystore(
                    fixture.recovery.verifying_key(),
                    fixture.recovery_encryption.public_key(),
                )
                .unwrap(),
                runtime_package: runtime,
                bootstrap_metadata: &fixture.bootstrap,
                creation_receipt: receipt,
                observed_at: fixture.observed_at,
            },
            &TestAuthority,
        )
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
        let route = ManagedAgentTarget {
            space: fixture.space,
            agent: control.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
        };
        let intent =
            AuthorityOperationIntent::private_control(route.runtime_deployment, control).unwrap();
        runtime_application_request_for_intent(fixture, control, intent, issued_at, applied_at)
    }

    fn signed_runtime_mutation_request(
        host: &PrivateAgentHost,
        fixture: &Fixture,
        operation: PrivateControlOperation,
        mutation: &PrivateRuntimeMutation,
        issued_at: u64,
        applied_at: u64,
    ) -> (
        PrivateControlRecord,
        AuthorityActorTarget,
        PrivateControlRuntimeApplicationRequest,
    ) {
        let agent = fixture.descriptor.identity.agent;
        let mut control = unsigned_owner_record(host.hosted(agent).unwrap(), operation);
        sign_owner_control_record(&mut control, &host.hosted(agent).unwrap().owner_key).unwrap();
        let (authority, mut request) =
            runtime_application_request(fixture, &control, issued_at, applied_at);
        request.mutation = Some(mutation.encode().unwrap());
        (control, authority, request)
    }

    fn recovery_runtime_application_request(
        fixture: &Fixture,
        control: &PrivateControlRecord,
        superseded_authority_head: Option<Hash>,
        issued_at: u64,
        applied_at: u64,
    ) -> (
        AuthorityActorTarget,
        PrivateControlRuntimeApplicationRequest,
        PrivateRecoveryAuthorityProof,
    ) {
        let route = recovery_route(fixture, control.agent);
        let proof = PrivateRecoveryAuthorityProof::from_control(
            route.runtime_deployment,
            control,
            superseded_authority_head,
            &fixture.recovery,
        )
        .unwrap();
        let intent = AuthorityOperationIntent::RecoverPrivateAgent {
            proof: proof.clone(),
        };
        let (authority, request) =
            runtime_application_request_for_intent(fixture, control, intent, issued_at, applied_at);
        (authority, request, proof)
    }

    fn runtime_application_request_for_intent(
        fixture: &Fixture,
        control: &PrivateControlRecord,
        intent: AuthorityOperationIntent,
        issued_at: u64,
        applied_at: u64,
    ) -> (
        AuthorityActorTarget,
        PrivateControlRuntimeApplicationRequest,
    ) {
        let (authority, key) = authority_target(fixture);
        let route = intent.managed();
        assert_eq!(route.space, fixture.space);
        assert_eq!(route.agent, control.agent);
        let operation = intent.operation();
        let actor = match &intent {
            AuthorityOperationIntent::PrivateActorLifecycle { actor, .. } => Some(*actor),
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
                request: match &intent {
                    AuthorityOperationIntent::RecoverPrivateAgent { proof } => proof.commitment(),
                    _ => control.commitment(),
                },
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
                mutation: None,
                receipt: receipt.encode().unwrap(),
                issuance_ack: issuance.encode().unwrap(),
                applied_at,
            },
        )
    }

    fn recovery_route(fixture: &Fixture, agent: AgentId) -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: fixture.space,
            agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
        }
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
        let resolution = host
            .runtime_application_adapter(authority, &TestAuthority)
            .unwrap()
            .apply(request)?;
        match resolution {
            PrivateControlRuntimeApplicationResolution::Applied(result) => Ok(result),
            PrivateControlRuntimeApplicationResolution::RetiredUnapplied(_) => {
                Err(PrivateAgentHostError::Corrupt)
            }
        }
    }

    fn require_applied_runtime_result(
        resolution: PrivateControlRuntimeApplicationResolution,
    ) -> PrivateControlRuntimeApplicationResult {
        match resolution {
            PrivateControlRuntimeApplicationResolution::Applied(result) => result,
            PrivateControlRuntimeApplicationResolution::RetiredUnapplied(_) => {
                panic!("physical Private host unexpectedly retired an application")
            }
        }
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

    fn apply_and_attach_test_recovery_authority_evidence(
        host: &mut PrivateAgentHost,
        fixture: &Fixture,
        control: &PrivateControlRecord,
        superseded_authority_head: Option<Hash>,
        issued_at: u64,
        applied_at: u64,
    ) -> (
        PrivateControlRuntimeApplicationResult,
        PrivateControlApplicationAck,
    ) {
        let (_authority, request, proof) = recovery_runtime_application_request(
            fixture,
            control,
            superseded_authority_head,
            issued_at,
            applied_at,
        );
        // Sync fixtures need an authenticated historical Recover row but must
        // not reopen the production live-adapter recovery path. Apply through
        // the explicitly test-only PCTL helper, construct the exact reopened
        // fact, and attach its proof-bound PSE2 directly to the test store.
        host.apply_recovery_record(control.agent, control.previous, control, &TestAuthority)
            .unwrap();
        let expected_members: Vec<NodeId> = host.agents[&control.agent]
            .store
            .authorized_nodes()
            .iter()
            .map(|node| node.node)
            .collect();
        let prepared = PreparedPrivateApplication {
            control: control.clone(),
            control_wire: request.control.clone(),
            operation: AuthorityOperationKind::RecoverPrivateAgent,
            expected_epoch: proof.next_epoch,
            expected_members,
            projected_store: host.agents[&control.agent].store.core_position().unwrap(),
            projected_key_epochs: private_runtime_key_epoch_commitments(
                &host.agents[&control.agent].store,
            )
            .unwrap(),
            mutation: None,
            receipt: None,
            issuance: None,
            already_applied: true,
        };
        let application_fact = synthetic_legacy_private_application_fact_for_test(
            &host.agents[&control.agent],
            &request,
            &prepared,
        )
        .unwrap();
        let result = PrivateControlRuntimeApplicationResult {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            mutation: request.mutation.clone(),
            receipt: request.receipt.clone(),
            issuance_ack: request.issuance_ack.clone(),
            applied_at: request.applied_at,
            authenticated: true,
            durably_applied: true,
            durably_reopened: true,
            reopened_runtime_state: application_fact.reopened_runtime_state,
            stable_projection: application_fact.stable_projection,
            application_fact: encode_private_application_fact(&application_fact),
        };
        let application = signed_test_application_ack(fixture, &request, &result);
        let issuance = AuthorityOperationIssuanceAck::decode(&request.issuance_ack).unwrap();
        let evidence = PrivateControlAuthorityEvidence::from_acknowledgements(
            &issuance,
            &application,
            Some(&proof),
        )
        .unwrap()
        .encode()
        .unwrap();
        host.agents
            .get_mut(&control.agent)
            .unwrap()
            .store
            .persist_control_authority_evidence(control.commitment(), &evidence)
            .unwrap();
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
            recovery_proof: None,
        }
    }

    fn test_recovery_evidence_request(
        request: &PrivateControlRuntimeApplicationRequest,
        application: &PrivateControlApplicationAck,
        proof: &PrivateRecoveryAuthorityProof,
    ) -> PrivateControlRuntimeEvidenceRequest {
        PrivateControlRuntimeEvidenceRequest {
            route: request.route,
            authority: request.authority,
            control: request.control.clone(),
            issuance_ack: request.issuance_ack.clone(),
            application_ack: application.encode().unwrap(),
            recovery_proof: Some(proof.encode().unwrap()),
        }
    }

    fn complete_prepared_recovery(
        host: &mut PrivateAgentHost,
        fixture: &Fixture,
        prepared: &PreparedPrivateRecovery,
    ) -> Result<PrivateControlRuntimeEvidenceResult, PrivateAgentHostError> {
        let (authority, request) = prepared_recovery_runtime_request(fixture, prepared);
        let result = host
            .synthetic_legacy_runtime_application_adapter_for_test(authority, &TestAuthority)?
            .apply(&request)
            .map(require_applied_runtime_result)?;
        let application = signed_test_application_ack(fixture, &request, &result);
        let evidence_request =
            test_recovery_evidence_request(&request, &application, &prepared.proof);
        host.runtime_application_adapter(authority, &TestAuthority)?
            .persist_completed_evidence(&evidence_request)
    }

    fn prepared_recovery_runtime_request(
        fixture: &Fixture,
        prepared: &PreparedPrivateRecovery,
    ) -> (
        AuthorityActorTarget,
        PrivateControlRuntimeApplicationRequest,
    ) {
        let control = PrivateControlRecord::decode(prepared.control_wire()).unwrap();
        let intent = prepared.authorization_intent().unwrap();
        runtime_application_request_for_intent(fixture, &control, intent, 80, 85)
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
                    creation_receipt: &fixture.creation_receipt,
                    observed_at: fixture.observed_at,
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
                    creation_receipt: &fixture.creation_receipt,
                    observed_at: fixture.observed_at,
                },
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidDescriptor)
        );
    }

    #[test]
    fn creation_executes_pvm_at_signed_valid_from_and_reopens_exact_pvi2() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "runtime-genesis");
        let agent = create_agent(&mut host, &fixture);
        let image = &host.agents[&agent].runtime_image;
        assert_eq!(image.creation_receipt(), &fixture.creation_receipt);
        let genesis_at = fixture.creation_receipt.selector.valid_from;
        // The scripted PVM accepts only the exact Direct Create work encoded
        // with this slot, while receipt admission observed it one slot later.
        assert_ne!(fixture.observed_at, genesis_at);
        assert_eq!(image.created_at(), genesis_at);
        assert_eq!(image.applied_at(), genesis_at);
        assert_eq!(&image.encode().unwrap()[..4], b"PVI2");
        assert_eq!(image.state().control, RUNTIME_STATE_SENTINEL);
        assert!(image.state().linear.is_empty());
        assert_eq!(
            image.store(),
            host.agents[&agent].store.core_position().unwrap()
        );
        assert_eq!(
            image.key_epochs(),
            private_runtime_key_epoch_commitments(&host.agents[&agent].store)
                .unwrap()
                .as_slice()
        );
        let commitment = image.commitment();
        let runtime_state_wire = fs::read(host.agent_path(agent).join(RUNTIME_STATE_FILE)).unwrap();
        assert!(!contains(&runtime_state_wire, RUNTIME_STATE_SENTINEL));
        let mut disk = Vec::new();
        collect_files(&host.root, &mut disk);
        assert!(!contains(&disk, SENTINEL));
        assert!(!contains(&disk, RUNTIME_STATE_SENTINEL));

        drop(host);
        let reopened = reopen_host(&fixture, 0, "runtime-genesis");
        assert_eq!(
            reopened.agents[&agent].runtime_image.commitment(),
            commitment
        );
    }

    #[test]
    fn creation_uses_configured_management_gas_without_leaving_artifacts() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "runtime-genesis-gas");
        let runtime = admit_runtime_package(&fixture.runtime).unwrap();
        let agent = fixture.descriptor.identity.agent;

        host.set_management_gas(0);
        assert_eq!(
            create_with_runtime(
                &mut host,
                &fixture,
                &fixture.descriptor,
                &runtime,
                &fixture.creation_receipt,
            ),
            Err(PrivateAgentHostError::InvalidArtifact)
        );
        assert!(!host.agent_path(agent).exists());
        assert!(!host.creating_path(agent).exists());

        host.set_management_gas(DEFAULT_MANAGEMENT_GAS);
        assert_eq!(create_agent(&mut host, &fixture), agent);
    }

    #[test]
    fn host_archive_v3_rejects_v2_after_mandatory_runtime_image_field() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "archive-v3");
        let agent = create_agent(&mut host, &fixture);
        for complete in [false, true] {
            let mut archive = if complete {
                host.export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
                    .unwrap()
            } else {
                host.export_encrypted_snapshot(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
                    .unwrap()
            };
            assert_eq!(
                u16::from_le_bytes(archive[4..6].try_into().unwrap()),
                HOST_ARCHIVE_VERSION
            );
            archive[4..6].copy_from_slice(&2_u16.to_le_bytes());
            assert!(matches!(
                decode_host_archive(&archive, complete),
                Err(PrivateAgentHostError::Corrupt)
            ));
        }
    }

    #[test]
    fn duplicate_create_is_rejected_before_executing_trapping_pvm() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "duplicate-before-pvm");
        let agent = create_agent(&mut host, &fixture);
        let mut before = Vec::new();
        collect_files(&host.agent_path(agent), &mut before);

        let mut trap = Assembler::new();
        trap.trap();
        let runtime =
            admitted_runtime_with_program_for_test("private-duplicate-trap", trap.build_standard());
        let descriptor = descriptor(
            fixture.space,
            fixture.owner,
            31,
            &identities(&fixture),
            &runtime,
        );
        assert_eq!(descriptor.identity.agent, agent);
        let receipt = creation_receipt(&descriptor, fixture.observed_at);
        assert_eq!(
            create_with_runtime(&mut host, &fixture, &descriptor, &runtime, &receipt),
            Err(PrivateAgentHostError::AlreadyExists)
        );
        let mut after = Vec::new();
        collect_files(&host.agent_path(agent), &mut after);
        assert_eq!(after, before);
        assert!(!host.creating_path(agent).exists());
    }

    #[test]
    fn create_duplicate_namespace_crash_retires_only_exact_genesis() {
        let fixture = fixture(1);
        let mut exact = create_host(&fixture, 0, "create-duplicate-exact");
        let agent = create_agent(&mut exact, &fixture);
        let exact_root = fixture.directory.child("create-duplicate-exact");
        let published = exact.agent_path(agent);
        let staged = exact.creating_path(agent);
        drop(exact);
        copy_directory_tree(&published, &staged);

        let reopened = PrivateAgentHost::open(
            &exact_root,
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(reopened.agent_ids().collect::<Vec<_>>(), vec![agent]);
        assert!(!staged.exists());
        drop(reopened);

        let mut hostile = create_host(&fixture, 0, "create-duplicate-hostile");
        let hostile_agent = create_agent(&mut hostile, &fixture);
        let hostile_root = fixture.directory.child("create-duplicate-hostile");
        let published = hostile.agent_path(hostile_agent);
        let staged = hostile.creating_path(hostile_agent);
        drop(hostile);
        copy_directory_tree(&published, &staged);
        let runtime_state = staged.join(RUNTIME_STATE_FILE);
        let mut substituted = fs::read(&runtime_state).unwrap();
        let last = substituted.last_mut().unwrap();
        *last ^= 1;
        fs::write(&runtime_state, substituted).unwrap();
        assert!(
            PrivateAgentHost::open(
                &hostile_root,
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            )
            .is_err()
        );
        assert!(published.exists());
        assert!(staged.exists());
    }

    #[test]
    fn creation_rejects_receipt_route_request_time_and_signer_before_artifacts() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "creation-receipt-hostile");
        let nodes = identities(&fixture);
        let runtime = admit_runtime_package(&fixture.runtime).unwrap();
        let recipient = DurableRecoveryRecipient::from_durable_keystore(
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[121; 32]);
        let mut wrong_route = fixture.creation_receipt.clone();
        wrong_route.selector.agent = AgentId([0x81; 32]);
        wrong_route.signature = signing_key.sign(&wrong_route.signing_bytes()).to_bytes();
        let mut wrong_request = fixture.creation_receipt.clone();
        wrong_request.selector.request = Hash([0x82; 32]);
        wrong_request.signature = signing_key.sign(&wrong_request.signing_bytes()).to_bytes();
        let wrong_signing_key = SigningKey::from_bytes(&[0x83; 32]);
        let mut wrong_signer = fixture.creation_receipt.clone();
        wrong_signer.public_key = wrong_signing_key.verifying_key().to_bytes();
        wrong_signer.selector.issuer.producer = ProducerId::of_public_key(&wrong_signer.public_key);
        wrong_signer.signature = wrong_signing_key
            .sign(&wrong_signer.signing_bytes())
            .to_bytes();

        for (label, receipt, observed_at) in [
            ("route", wrong_route, fixture.observed_at),
            ("request", wrong_request, fixture.observed_at),
            (
                "before-valid",
                fixture.creation_receipt.clone(),
                fixture
                    .creation_receipt
                    .selector
                    .valid_from
                    .saturating_sub(1),
            ),
            (
                "expired",
                fixture.creation_receipt.clone(),
                fixture
                    .creation_receipt
                    .selector
                    .expires_at
                    .saturating_add(1),
            ),
            ("signer", wrong_signer, fixture.observed_at),
        ] {
            assert_eq!(
                host.create_agent(
                    PrivateAgentCreate {
                        descriptor: &fixture.descriptor,
                        nodes: &nodes,
                        recovery_recipient: recipient,
                        runtime_package: &runtime,
                        bootstrap_metadata: &fixture.bootstrap,
                        creation_receipt: &receipt,
                        observed_at,
                    },
                    &TestAuthority,
                ),
                Err(PrivateAgentHostError::Unauthorized),
                "{label}"
            );
            assert!(!host.agent_path(fixture.descriptor.identity.agent).exists());
            assert!(
                !host
                    .creating_path(fixture.descriptor.identity.agent)
                    .exists()
            );
        }
    }

    #[test]
    fn creation_trap_malformed_and_substituted_transitions_leave_no_artifacts() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "creation-pvm-hostile");

        let mut trap = Assembler::new();
        trap.trap();
        let trap_runtime =
            admitted_runtime_with_program_for_test("private-create-trap", trap.build_standard());
        let trap_descriptor = descriptor(
            fixture.space,
            fixture.owner,
            31,
            &identities(&fixture),
            &trap_runtime,
        );
        let trap_receipt = creation_receipt(&trap_descriptor, fixture.observed_at);
        assert_eq!(
            create_with_runtime(
                &mut host,
                &fixture,
                &trap_descriptor,
                &trap_runtime,
                &trap_receipt,
            ),
            Err(PrivateAgentHostError::InvalidArtifact)
        );

        let placeholder_input = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: fixture.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            state: RuntimeState::default(),
            request: Box::new(ManagementRequest::Create(Box::new(
                fixture.descriptor.clone(),
            ))),
            authority: Some(Box::new(fixture.creation_receipt.clone())),
            observed_slot: fixture.creation_receipt.selector.valid_from,
        }
        .encode()
        .unwrap();
        let malformed_runtime = admitted_scripted_runtime_for_test(
            "private-create-malformed",
            0x5c,
            vec![ScriptedRuntimeCase {
                input: placeholder_input.clone(),
                output: vec![0xff],
                copies: Vec::new(),
            }],
        );
        let malformed_descriptor = descriptor(
            fixture.space,
            fixture.owner,
            31,
            &identities(&fixture),
            &malformed_runtime,
        );
        let malformed_receipt = creation_receipt(&malformed_descriptor, fixture.observed_at);
        assert_eq!(
            create_with_runtime(
                &mut host,
                &fixture,
                &malformed_descriptor,
                &malformed_runtime,
                &malformed_receipt,
            ),
            Err(PrivateAgentHostError::InvalidArtifact)
        );

        let substituted_output = RuntimeTransition {
            state: RuntimeState {
                control: b"substituted-control".to_vec(),
                linear: Vec::new(),
                merge: Vec::new(),
                local: Vec::new(),
            },
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                fixture.descriptor.identity.clone(),
            ))),
        }
        .encode()
        .unwrap();
        let substituted_runtime = admitted_scripted_runtime_for_test(
            "private-create-substituted",
            0x5d,
            vec![ScriptedRuntimeCase {
                input: placeholder_input.clone(),
                output: substituted_output,
                copies: Vec::new(),
            }],
        );
        let substituted_descriptor = descriptor(
            fixture.space,
            fixture.owner,
            31,
            &identities(&fixture),
            &substituted_runtime,
        );
        let substituted_receipt = creation_receipt(&substituted_descriptor, fixture.observed_at);
        assert_eq!(
            create_with_runtime(
                &mut host,
                &fixture,
                &substituted_descriptor,
                &substituted_runtime,
                &substituted_receipt,
            ),
            Err(PrivateAgentHostError::InvalidArtifact)
        );

        let changed_output = RuntimeTransition {
            state: RuntimeState {
                control: b"changed-control".to_vec(),
                linear: vec![1],
                merge: Vec::new(),
                local: Vec::new(),
            },
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                fixture.descriptor.identity.clone(),
            ))),
        }
        .encode()
        .unwrap();
        let identity = identity_bytes(&fixture.descriptor.identity);
        let changed_runtime = admitted_scripted_runtime_for_test(
            "private-create-changed-state",
            0x5e,
            vec![ScriptedRuntimeCase {
                copies: vec![ScriptedRuntimeCopy {
                    input_offset: unique_offset(&placeholder_input, &identity),
                    output_offset: unique_offset(&changed_output, &identity),
                    len: identity.len(),
                }],
                input: placeholder_input,
                output: changed_output,
            }],
        );
        let changed_descriptor = descriptor(
            fixture.space,
            fixture.owner,
            31,
            &identities(&fixture),
            &changed_runtime,
        );
        let changed_receipt = creation_receipt(&changed_descriptor, fixture.observed_at);
        assert_eq!(
            create_with_runtime(
                &mut host,
                &fixture,
                &changed_descriptor,
                &changed_runtime,
                &changed_receipt,
            ),
            Err(PrivateAgentHostError::InvalidArtifact)
        );
        let agent = fixture.descriptor.identity.agent;
        assert!(!host.agent_path(agent).exists());
        assert!(!host.creating_path(agent).exists());
    }

    #[test]
    fn object_commit_with_interrupted_pvri_refresh_repairs_exact_store_on_reopen() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "object-pvri-repair");
        let agent = create_agent(&mut host, &fixture);
        let slot = host.agent_path(agent);
        let canonical_before = fs::read(slot.join(RUNTIME_STATE_FILE)).unwrap();
        let temporary = slot.join(format!("{RUNTIME_STATE_FILE}{WRITE_SUFFIX}"));
        fs::create_dir(&temporary).unwrap();
        assert_eq!(
            host.encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"committed-before-pvri-refresh",
                authority_target(&fixture).0,
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Corrupt)
        );
        assert_eq!(host.binding(agent), Err(PrivateAgentHostError::NotFound));
        assert_eq!(
            host.export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::NotFound)
        );
        assert_eq!(
            host.encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"must-not-continue-while-quarantined",
                authority_target(&fixture).0,
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::NotFound)
        );
        assert_eq!(
            fs::read(slot.join(RUNTIME_STATE_FILE)).unwrap(),
            canonical_before
        );
        fs::remove_dir(&temporary).unwrap();
        drop(host);

        let reopened = reopen_host(&fixture, 0, "object-pvri-repair");
        assert_eq!(
            reopened.agents[&agent].runtime_image.store(),
            reopened.agents[&agent].store.core_position().unwrap()
        );
        assert_ne!(
            fs::read(reopened.agent_path(agent).join(RUNTIME_STATE_FILE)).unwrap(),
            canonical_before
        );
    }

    #[test]
    fn runtime_image_ciphertext_and_stage_identity_substitution_fail_closed() {
        let fixture = fixture(1);
        let mut left = create_host(&fixture, 0, "pvri-substitution-left");
        let agent = create_agent(&mut left, &fixture);
        let left_wire = fs::read(left.agent_path(agent).join(RUNTIME_STATE_FILE)).unwrap();
        let mut right = create_host(&fixture, 0, "pvri-substitution-right");
        create_agent(&mut right, &fixture);
        let right_path = right.agent_path(agent).join(RUNTIME_STATE_FILE);
        drop(right);
        replace_regular_file_synced(&right_path, &left_wire).unwrap();
        assert!(
            PrivateAgentHost::open(
                fixture.directory.child("pvri-substitution-right"),
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            )
            .is_err()
        );

        let control = signed_rotate_control(&left, agent);
        let (authority, request) = runtime_application_request(&fixture, &control, 50, 55);
        let mut runtime = left
            .runtime_application_adapter(authority, &TestAuthority)
            .unwrap();
        runtime.stop_after(PrivateRuntimeApplicationStop::AfterStoreCommitted);
        assert_eq!(
            runtime.apply(&request),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
        );
        let slot = left.agent_path(agent);
        let correct = slot.join(staged_runtime_image_name(control.commitment()));
        let wrong = slot.join(staged_runtime_image_name(Hash([0x99; 32])));
        fs::rename(correct, wrong).unwrap();
        drop(left);
        assert!(
            PrivateAgentHost::open(
                fixture.directory.child("pvri-substitution-left"),
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            )
            .is_err()
        );
    }

    #[test]
    fn production_runtime_adapter_commits_control_and_completed_papl() {
        let fixture = fixture(64);
        let mut host = create_host(&fixture, 0, "physical-runtime-application");
        let agent = create_agent(&mut host, &fixture);
        let revoked = fixture.nodes[1].identity.node;
        let control = signed_revoke_control(&host, agent, revoked);
        let (authority, request) = runtime_application_request(&fixture, &control, 40, 44);
        let binding = host.binding(agent).unwrap();

        let result = host
            .runtime_application_adapter(authority, &TestAuthority)
            .unwrap()
            .apply(&request)
            .map(require_applied_runtime_result)
            .unwrap();
        let applied = host.binding(agent).unwrap();
        assert_eq!(applied.epoch, binding.epoch + 1);
        assert_eq!(applied.control_head, Some(control.commitment()));
        assert!(result.authenticated && result.durably_applied && result.durably_reopened);
        assert!(
            host.agents[&agent]
                .store
                .control_is_exact(control.commitment(), &request.control)
                .unwrap()
        );
        assert!(
            host.agents[&agent]
                .store
                .read_runtime_application(control.commitment())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn runtime_backed_policy_and_lifecycle_execute_commit_reopen_and_skip_retry_execution() {
        let policy = vos_agent_sdk::contract::RuntimeResourcePolicy::standard();
        let policy_mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let policy_operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(&policy.encode().unwrap()),
        };
        let mut policy_state = genesis_runtime_state();
        policy_state.control = b"runtime-policy-applied".to_vec();
        let policy_output = RuntimeTransition {
            state: policy_state.clone(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::ResourcePolicySet(policy))),
        }
        .encode()
        .unwrap();
        let fixture = fixture_with_management(
            policy_operation.clone(),
            policy_mutation.clone(),
            policy_output,
        );
        let mut host = create_host(&fixture, 0, "runtime-policy-positive");
        let agent = create_agent(&mut host, &fixture);
        let (control, authority, request) = signed_runtime_mutation_request(
            &host,
            &fixture,
            policy_operation,
            &policy_mutation,
            40,
            44,
        );
        let mut before_exhaustion = Vec::new();
        collect_files(&host.agent_path(agent), &mut before_exhaustion);
        host.set_management_gas(0);
        assert_eq!(
            host.runtime_application_adapter(authority, &TestAuthority)
                .unwrap()
                .apply(&request),
            Err(PrivateAgentHostError::InvalidArtifact)
        );
        let mut after_exhaustion = Vec::new();
        collect_files(&host.agent_path(agent), &mut after_exhaustion);
        assert_eq!(after_exhaustion, before_exhaustion);

        host.set_management_gas(DEFAULT_MANAGEMENT_GAS);
        let first = require_applied_runtime_result(
            host.runtime_application_adapter(authority, &TestAuthority)
                .unwrap()
                .apply(&request)
                .unwrap(),
        );
        let application = host.agents[&agent]
            .store
            .read_runtime_application(control.commitment())
            .unwrap()
            .unwrap();
        assert_eq!(application.mutation(), Some(&policy_mutation));
        assert_eq!(
            application.success(),
            Some(&PrivateRuntimeSuccess::ResourcePolicySet(policy))
        );
        assert_eq!(host.agents[&agent].runtime_image.state(), &policy_state);
        assert_eq!(
            host.agents[&agent].runtime_image.active_resource_policy(),
            policy
        );
        let exact_slot = {
            let mut bytes = Vec::new();
            collect_files(&host.agent_path(agent), &mut bytes);
            bytes
        };

        // Zero gas proves an exact retry never enters the PVM or rewrites the
        // already committed Store/PVRI generation.
        host.set_management_gas(0);
        let retry = require_applied_runtime_result(
            host.runtime_application_adapter(authority, &TestAuthority)
                .unwrap()
                .apply(&request)
                .unwrap(),
        );
        assert_eq!(retry, first);
        let mut retry_slot = Vec::new();
        collect_files(&host.agent_path(agent), &mut retry_slot);
        assert_eq!(retry_slot, exact_slot);

        drop(host);
        let mut reopened = reopen_host(&fixture, 0, "runtime-policy-positive");
        reopened.set_management_gas(0);
        assert_eq!(
            require_applied_runtime_result(
                reopened
                    .runtime_application_adapter(authority, &TestAuthority)
                    .unwrap()
                    .apply(&request)
                    .unwrap(),
            ),
            first
        );

        let actor = ActorId([0x81; 32]);
        let expected_deployment = DeploymentId([0x82; 32]);
        let lifecycle_mutation = PrivateRuntimeMutation::RemoveLeaf {
            actor,
            expected_deployment,
        };
        let lifecycle_operation = PrivateControlOperation::ActorLifecycle {
            actor,
            operation: PrivateActorLifecycleKind::Remove,
            request: lifecycle_mutation.commitment(),
        };
        let mut lifecycle_state = genesis_runtime_state();
        lifecycle_state.control = b"runtime-lifecycle-applied".to_vec();
        let lifecycle_output = RuntimeTransition {
            state: lifecycle_state.clone(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Removed(actor))),
        }
        .encode()
        .unwrap();
        let fixture = fixture_with_management(
            lifecycle_operation.clone(),
            lifecycle_mutation.clone(),
            lifecycle_output,
        );
        let mut host = create_host(&fixture, 0, "runtime-lifecycle-positive");
        let agent = create_agent(&mut host, &fixture);
        let (control, authority, request) = signed_runtime_mutation_request(
            &host,
            &fixture,
            lifecycle_operation,
            &lifecycle_mutation,
            50,
            54,
        );
        let result = require_applied_runtime_result(
            host.runtime_application_adapter(authority, &TestAuthority)
                .unwrap()
                .apply(&request)
                .unwrap(),
        );
        let application = host.agents[&agent]
            .store
            .read_runtime_application(control.commitment())
            .unwrap()
            .unwrap();
        assert_eq!(application.mutation(), Some(&lifecycle_mutation));
        assert_eq!(
            application.success(),
            Some(&PrivateRuntimeSuccess::Removed(actor))
        );
        assert_eq!(host.agents[&agent].runtime_image.state(), &lifecycle_state);
        let fact = decode_private_application_fact(&result.application_fact).unwrap();
        assert_eq!(
            fact.operation,
            AuthorityOperationKind::PrivateActorLifecycle
        );
        assert_eq!(fact.control, control.commitment());
    }

    #[test]
    fn exact_unchanged_management_denial_retires_without_any_physical_write() {
        let policy = vos_agent_sdk::contract::RuntimeResourcePolicy::standard();
        let mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(&policy.encode().unwrap()),
        };
        let output = RuntimeTransition {
            state: genesis_runtime_state(),
            outcome: RuntimeOutcome::Management(Err(ManagementError::ResourceLimit)),
        }
        .encode()
        .unwrap();
        let fixture = fixture_with_management(operation.clone(), mutation.clone(), output);
        let mut host = create_host(&fixture, 0, "runtime-retirement");
        let agent = create_agent(&mut host, &fixture);
        let (control, authority, request) =
            signed_runtime_mutation_request(&host, &fixture, operation, &mutation, 40, 44);
        let binding = host.binding(agent).unwrap();
        let image = host.agents[&agent].runtime_image.commitment();
        let mut before = Vec::new();
        collect_files(&host.agent_path(agent), &mut before);

        let resolution = host
            .runtime_application_adapter(authority, &TestAuthority)
            .unwrap()
            .apply(&request)
            .unwrap();
        let PrivateControlRuntimeApplicationResolution::RetiredUnapplied(retired) = resolution
        else {
            panic!("exact management denial was reported as applied")
        };
        assert_eq!(retired.route, request.route);
        assert_eq!(retired.resolved_at, request.applied_at);
        assert!(retired.authenticated && retired.predecessor_unchanged && retired.durably_reopened);
        assert_eq!(host.binding(agent).unwrap(), binding);
        assert_eq!(host.agents[&agent].runtime_image.commitment(), image);
        assert!(
            !host.agents[&agent]
                .store
                .control_is_exact(control.commitment(), &request.control)
                .unwrap()
        );
        assert_eq!(
            host.agents[&agent]
                .store
                .read_runtime_application(control.commitment()),
            Err(PrivateStoreError::NotFound)
        );
        let mut after = Vec::new();
        collect_files(&host.agent_path(agent), &mut after);
        assert_eq!(after, before);
    }

    #[test]
    fn runtime_trap_malformed_and_changed_denial_leave_no_physical_write() {
        let policy = vos_agent_sdk::contract::RuntimeResourcePolicy::standard();
        let mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(&policy.encode().unwrap()),
        };
        let mut changed_state = genesis_runtime_state();
        changed_state.control = b"changed-denial-must-not-commit".to_vec();
        let changed_denial = RuntimeTransition {
            state: changed_state,
            outcome: RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
        }
        .encode()
        .unwrap();
        let cases = [
            ("trap", fixture(1)),
            (
                "malformed",
                fixture_with_management(operation.clone(), mutation.clone(), vec![0xff]),
            ),
            (
                "changed-denial",
                fixture_with_management(operation.clone(), mutation.clone(), changed_denial),
            ),
        ];
        for (label, fixture) in cases {
            let mut host = create_host(&fixture, 0, &format!("runtime-{label}"));
            let agent = create_agent(&mut host, &fixture);
            let (control, authority, request) = signed_runtime_mutation_request(
                &host,
                &fixture,
                operation.clone(),
                &mutation,
                40,
                44,
            );
            let binding = host.binding(agent).unwrap();
            let image = host.agents[&agent].runtime_image.commitment();
            let mut before = Vec::new();
            collect_files(&host.agent_path(agent), &mut before);
            assert!(
                host.runtime_application_adapter(authority, &TestAuthority)
                    .unwrap()
                    .apply(&request)
                    .is_err(),
                "accepted {label} runtime transition"
            );
            assert_eq!(host.binding(agent).unwrap(), binding, "case {label}");
            assert_eq!(
                host.agents[&agent].runtime_image.commitment(),
                image,
                "case {label}"
            );
            assert!(
                !host.agents[&agent]
                    .store
                    .control_is_exact(control.commitment(), &request.control)
                    .unwrap()
            );
            let mut after = Vec::new();
            collect_files(&host.agent_path(agent), &mut after);
            assert_eq!(after, before, "case {label}");
        }
    }

    #[test]
    fn applied_retry_rejects_fresh_receipt_issuance_and_slot_without_new_fact() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "runtime-divergent-retry");
        let agent = create_agent(&mut host, &fixture);
        let control = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
        let (authority, request) = runtime_application_request(&fixture, &control, 40, 44);
        let first = apply_runtime_request(&mut host, authority, &request).unwrap();
        let mut before = Vec::new();
        collect_files(&host.agent_path(agent), &mut before);

        let mut changed_slot = request.clone();
        changed_slot.applied_at += 1;

        let (_, fresh_pair) = runtime_application_request(&fixture, &control, 41, 44);

        let (_, authority_key) = authority_target(&fixture);
        let mut changed_issuance = request.clone();
        let mut issuance =
            AuthorityOperationIssuanceAck::decode(&changed_issuance.issuance_ack).unwrap();
        issuance.issued_at += 1;
        issuance.signature = [0; 64];
        issuance.signature = authority_key.sign(&issuance.signing_bytes()).to_bytes();
        changed_issuance.issuance_ack = issuance.encode().unwrap();

        for (label, candidate) in [
            ("applied slot", changed_slot),
            ("fresh receipt and issuance", fresh_pair),
            ("fresh issuance", changed_issuance),
        ] {
            assert!(
                host.runtime_application_adapter(authority, &TestAuthority)
                    .unwrap()
                    .apply(&candidate)
                    .is_err(),
                "accepted divergent {label} retry"
            );
            let mut after = Vec::new();
            collect_files(&host.agent_path(agent), &mut after);
            assert_eq!(after, before, "divergent {label} retry wrote state");
        }
        assert_eq!(
            apply_runtime_request(&mut host, authority, &request).unwrap(),
            first
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
            require_applied_runtime_result(runtime.apply(&request).unwrap())
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
        let sync_request = PrivateSyncRequest {
            cursor: PrivateSyncCursor::start(
                binding.space,
                binding.agent,
                binding.epoch,
                binding.control_head,
            )
            .unwrap(),
            max_items: 1,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        assert_eq!(
            host.serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &sync_request.encode().unwrap(),
                authority,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            host.export_encrypted_snapshot(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            host.export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );

        let sidecars = canonical_sidecars(&host, agent);
        let retry = {
            let mut runtime = host
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap();
            require_applied_runtime_result(runtime.apply(&request).unwrap())
        };
        assert_eq!(retry, first);
        assert_eq!(canonical_sidecars(&host, agent), sidecars);

        drop(host);
        let mut reopened = reopen_host(&fixture, 0, "authorized-application");
        let restart_retry = {
            let mut runtime = reopened
                .runtime_application_adapter(authority, &TestAuthority)
                .unwrap();
            require_applied_runtime_result(runtime.apply(&request).unwrap())
        };
        assert_eq!(restart_retry, first);
        assert_eq!(canonical_sidecars(&reopened, agent), sidecars);
        assert_eq!(
            reopened.serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &sync_request.encode().unwrap(),
                authority,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            reopened.export_encrypted_snapshot(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            reopened.export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
    }

    #[test]
    fn authorized_runtime_application_recovers_every_physical_write_boundary() {
        let boundaries = [
            PrivateRuntimeApplicationStop::AfterDescriptorStaged,
            PrivateRuntimeApplicationStop::AfterRuntimeStaged,
            PrivateRuntimeApplicationStop::AfterBootstrapStaged,
            PrivateRuntimeApplicationStop::AfterRuntimeStateStaged,
            PrivateRuntimeApplicationStop::AfterStoreStagedArtifact,
            PrivateRuntimeApplicationStop::AfterStoreStagedRuntimeApplication,
            PrivateRuntimeApplicationStop::AfterStoreStagedIndex,
            PrivateRuntimeApplicationStop::AfterStorePending,
            PrivateRuntimeApplicationStop::AfterStoreArtifact,
            PrivateRuntimeApplicationStop::AfterStoreRuntimeApplication,
            PrivateRuntimeApplicationStop::AfterStoreIndex,
            PrivateRuntimeApplicationStop::AfterStoreCommitted,
            PrivateRuntimeApplicationStop::AfterDescriptorPromoted,
            PrivateRuntimeApplicationStop::AfterRuntimePromoted,
            PrivateRuntimeApplicationStop::AfterBootstrapPromoted,
            PrivateRuntimeApplicationStop::AfterRuntimeStatePromoted,
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
                    require_applied_runtime_result(runtime.apply(&request).unwrap())
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
                None,
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
        for (label, reopened_runtime_state, stable_projection) in [
            ("PCRS3 endpoint", Some(Hash([0xce; 32])), None),
            ("stable projection endpoint", None, Some(Hash([0xcf; 32]))),
        ] {
            let mut candidate = exact.clone();
            let mut application =
                PrivateControlApplicationAck::decode(&candidate.application_ack).unwrap();
            if let Some(commitment) = reopened_runtime_state {
                application.application.reopened_runtime_state = commitment;
            }
            if let Some(commitment) = stable_projection {
                application.application.stable_projection = commitment;
            }
            application.signature = key.sign(&application.signing_bytes()).to_bytes();
            candidate.application_ack = application.encode().unwrap();
            cases.push((label, candidate));
        }
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
    fn authorized_rotation_is_restartable_and_unresolved_head_blocks_later_controls() {
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

        // A later resource-policy PCTL cannot pass the physical boundary while
        // the preceding rotation still lacks its authority evidence endpoint.
        let policy = vos_agent_sdk::contract::RuntimeResourcePolicy::standard();
        let policy_mutation = PrivateRuntimeMutation::SetResourcePolicy(policy);
        let mut resource = unsigned_owner_record(
            host.hosted(agent).unwrap(),
            PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(&policy.encode().unwrap()),
            },
        );
        sign_owner_control_record(&mut resource, &host.hosted(agent).unwrap().owner_key).unwrap();
        let (_, mut resource_request) = runtime_application_request(&fixture, &resource, 50, 54);
        let before_resource = host.binding(agent).unwrap();
        let before_resource_sidecars = canonical_sidecars(&host, agent);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &resource_request),
            Err(PrivateAgentHostError::InvalidArtifact)
        );
        resource_request.mutation = Some(vec![1, 2, 3]);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &resource_request),
            Err(PrivateAgentHostError::InvalidArtifact)
        );
        resource_request.mutation = Some(vec![0; MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES + 1]);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &resource_request),
            Err(PrivateAgentHostError::LimitExceeded)
        );
        resource_request.mutation = Some(policy_mutation.encode().unwrap());
        assert_eq!(
            apply_runtime_request(&mut host, authority, &resource_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(host.binding(agent).unwrap(), before_resource);
        assert_eq!(canonical_sidecars(&host, agent), before_resource_sidecars);

        // The same unresolved-head rule blocks a later lifecycle PCTL even
        // when the exact mutation preimage is supplied.
        let actor = ActorId([0xb7; 32]);
        let lifecycle_mutation = PrivateRuntimeMutation::Suspend {
            actor,
            expected_deployment: DeploymentId([0xb8; 32]),
        };
        let lifecycle_request_hash = lifecycle_mutation.commitment();
        let mut lifecycle = unsigned_owner_record(
            host.hosted(agent).unwrap(),
            PrivateControlOperation::ActorLifecycle {
                actor,
                operation: PrivateActorLifecycleKind::Suspend,
                request: lifecycle_request_hash,
            },
        );
        sign_owner_control_record(&mut lifecycle, &host.hosted(agent).unwrap().owner_key).unwrap();
        let (_, mut lifecycle_request) = runtime_application_request(&fixture, &lifecycle, 60, 64);
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
            Err(PrivateAgentHostError::InvalidArtifact)
        );
        lifecycle_request.mutation = Some(lifecycle_mutation.encode().unwrap());
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
    fn direct_live_recover_is_rejected_without_an_authenticated_pvrp3_stage() {
        let fixture = fixture(2);
        let mut host = create_host(&fixture, 0, "direct-live-recovery");
        let agent = create_agent(&mut host, &fixture);
        let revoke = signed_revoke_control(&host, agent, fixture.nodes[1].identity.node);
        let (authority, revoke_request) = runtime_application_request(&fixture, &revoke, 70, 75);
        apply_runtime_request(&mut host, authority, &revoke_request).unwrap();

        let replacements = identities(&fixture);
        let recovery = signed_recovery_control(&host, agent, &replacements, &fixture.recovery);
        let (_, recovery_request, _) =
            recovery_runtime_application_request(&fixture, &recovery, None, 80, 85);
        let before_binding = host.binding(agent).unwrap();
        let mut before = Vec::new();
        collect_files(&host.agent_path(agent), &mut before);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &recovery_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(host.binding(agent).unwrap(), before_binding);
        let mut after = Vec::new();
        collect_files(&host.agent_path(agent), &mut after);
        assert_eq!(after, before);
        assert_eq!(
            apply_runtime_request(&mut host, authority, &recovery_request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
    }

    #[test]
    fn genesis_recovery_stays_unpublished_without_authenticated_pvri_rebind() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "genesis-recovery-source");
        let agent = create_agent(&mut source, &fixture);
        let backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        drop(source);

        let replacement = node(fixture.space, fixture.owner, 99);
        let replacements = vec![replacement.identity.clone()];
        let root = fixture.directory.child("genesis-recovery-target");
        let mut host = PrivateAgentHost::create(
            &root,
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let prepared = host
            .prepare_recovery_from_encrypted_backup(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &backup,
                &TestAuthority,
            )
            .unwrap();
        let recovery = PrivateControlRecord::decode(prepared.control_wire()).unwrap();
        assert_eq!(recovery.previous, None);
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &recovery.operation
        else {
            unreachable!();
        };
        assert!(superseded_heads.is_empty());
        assert_eq!(prepared.proof.superseded_authority_head, None);
        assert!(matches!(
            complete_prepared_recovery(&mut host, &fixture, &prepared),
            Err(PrivateAgentHostError::Corrupt) | Err(PrivateAgentHostError::UnsupportedOperation)
        ));
        assert_eq!(host.binding(agent), Err(PrivateAgentHostError::NotFound));
        assert!(!host.agent_path(agent).exists());
        assert!(host.creating_path(agent).exists());
        drop(host);

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
            reopened.binding(agent),
            Err(PrivateAgentHostError::NotFound)
        );
        assert!(!reopened.agent_path(agent).exists());
        assert!(reopened.creating_path(agent).exists());
        assert_eq!(
            reopened.descriptor(agent),
            Err(PrivateAgentHostError::NotFound)
        );

        let source = PrivateAgentHost::open(
            fixture.directory.child("genesis-recovery-source"),
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(source.descriptor(agent).unwrap(), &fixture.descriptor);
    }

    #[test]
    fn pvrp3_rejects_old_trailing_noncanonical_and_oversize_frames() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "pvrp3-wire-source");
        let agent = create_agent(&mut source, &fixture);
        let backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        drop(source);

        let replacement = node(fixture.space, fixture.owner, 99);
        let replacements = vec![replacement.identity.clone()];
        let mut target = PrivateAgentHost::create(
            fixture.directory.child("pvrp3-wire-target"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            target.prepare_recovery_from_encrypted_backup_with_stop(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &backup,
                &TestAuthority,
                RecoveryInstallStop::AfterPlan,
            ),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted))
        );
        let exact = fs::read(target.creating_path(agent).join(RECOVERY_PLAN_FILE)).unwrap();
        assert!(decode_recovery_plan(&exact, &target.node_key).is_ok());

        let authenticate = |body: &mut Vec<u8>| {
            let plan_hash = Hash::digest(RECOVERY_PLAN_HASH_DOMAIN, &[body]);
            let authenticator = target
                .node_key
                .recovery_plan_authenticator(plan_hash)
                .unwrap();
            body.extend_from_slice(authenticator.as_bytes());
        };

        // PVRP2-looking bytes signed by this exact node are still an
        // incompatible clean-break format, not a compatibility input.
        let mut old_version = exact[..exact.len() - 32].to_vec();
        old_version[4..6].copy_from_slice(&2_u16.to_le_bytes());
        authenticate(&mut old_version);
        assert!(matches!(
            decode_recovery_plan(&old_version, &target.node_key),
            Err(PrivateAgentHostError::Corrupt)
        ));

        // An authenticated suffix cannot be normalized away.
        let mut trailing = exact[..exact.len() - 32].to_vec();
        trailing.push(0);
        authenticate(&mut trailing);
        assert!(matches!(
            decode_recovery_plan(&trailing, &target.node_key),
            Err(PrivateAgentHostError::Corrupt)
        ));

        // Completion is a typed AOI1/PCA2/PSE2 closure. Merely placing
        // nonempty bounded payloads in its canonical frame is insufficient.
        let mut noncanonical_completion = decode_recovery_plan(&exact, &target.node_key).unwrap();
        noncanonical_completion.completion = Some(RecoveryPlanCompletion {
            issuance_ack: vec![1],
            application_ack: vec![2],
            evidence_commitment: Hash([3; 32]),
        });
        let noncanonical_completion =
            encode_recovery_plan(&noncanonical_completion, &target.node_key).unwrap();
        assert!(matches!(
            decode_recovery_plan(&noncanonical_completion, &target.node_key),
            Err(PrivateAgentHostError::Corrupt)
        ));

        assert_eq!(
            MAX_PRIVATE_RECOVERY_PLAN_BYTES,
            MAX_PRIVATE_HOST_ARCHIVE_BYTES
                + MAX_PRIVATE_CONTROL_WIRE_BYTES
                + MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES
                + MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
                + MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES
                + RECOVERY_PLAN_FIXED_BYTES
        );
        let boundary = vec![0_u8; MAX_PRIVATE_RECOVERY_PLAN_BYTES + 1];
        assert!(matches!(
            decode_recovery_plan(
                &boundary[..MAX_PRIVATE_RECOVERY_PLAN_BYTES],
                &target.node_key,
            ),
            Err(PrivateAgentHostError::Corrupt)
        ));
        assert!(matches!(
            decode_recovery_plan(&boundary, &target.node_key),
            Err(PrivateAgentHostError::LimitExceeded)
        ));
    }

    #[test]
    fn archive_export_rejects_missing_historical_pse2_before_staging() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "missing-historical-pse-source");
        let agent = create_agent(&mut source, &fixture);
        let recovery =
            signed_recovery_control(&source, agent, &identities(&fixture), &fixture.recovery);
        source
            .apply_recovery_record(agent, recovery.previous, &recovery, &TestAuthority)
            .unwrap();
        assert_eq!(
            source.export_encrypted_snapshot(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            source.export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
    }

    #[test]
    fn planless_recovery_requires_recover_at_the_current_authenticated_head() {
        let fixture = fixture(1);
        let root = fixture.directory.child("planless-non-recover-head");
        let mut host = PrivateAgentHost::create(
            &root,
            fixture.space,
            fixture.owner,
            fixture.nodes[0].identity.clone(),
            fixture.nodes[0].key(),
        )
        .unwrap();
        let agent = create_agent(&mut host, &fixture);
        let recovery =
            signed_recovery_control(&host, agent, &identities(&fixture), &fixture.recovery);
        apply_and_attach_test_recovery_authority_evidence(
            &mut host, &fixture, &recovery, None, 80, 85,
        );
        host.record_actor_lifecycle(
            agent,
            ActorId([0x51; 32]),
            PrivateActorLifecycleKind::Install,
            Hash([0x52; 32]),
            &TestAuthority,
        )
        .unwrap();
        let source = host.agent_path(agent);
        let stage = host.creating_path(agent);
        drop(host);
        fs::rename(&source, &stage).unwrap();

        assert!(matches!(
            PrivateAgentHost::open(
                &root,
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Corrupt)
        ));
        assert!(!source.exists());
        assert!(stage.exists());
    }

    #[test]
    fn recovery_runtime_result_is_not_fabricated_without_authenticated_pvri_rebind() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "result-loss-source");
        let agent = create_agent(&mut source, &fixture);
        let backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();

        let replacement = node(fixture.space, fixture.owner, 99);
        let replacements = vec![replacement.identity.clone()];
        let mut target = PrivateAgentHost::create(
            fixture.directory.child("result-loss-planless"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let prepared = target
            .prepare_recovery_from_encrypted_backup(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &backup,
                &TestAuthority,
            )
            .unwrap();
        let (authority, request) = prepared_recovery_runtime_request(&fixture, &prepared);
        assert!(matches!(
            apply_runtime_request(&mut target, authority, &request),
            Err(PrivateAgentHostError::Corrupt) | Err(PrivateAgentHostError::UnsupportedOperation)
        ));
        assert_eq!(target.binding(agent), Err(PrivateAgentHostError::NotFound));
        assert!(!target.agent_path(agent).exists());
        assert!(target.creating_path(agent).exists());
        assert_eq!(source.descriptor(agent).unwrap(), &fixture.descriptor);

        drop(target);
        let reopened = PrivateAgentHost::open(
            fixture.directory.child("result-loss-planless"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
            &TestAuthority,
        )
        .unwrap();
        assert_eq!(
            reopened.binding(agent),
            Err(PrivateAgentHostError::NotFound)
        );
        assert!(reopened.prepared_recovery(agent).unwrap().is_some());
        assert!(!reopened.agent_path(agent).exists());
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

    fn copy_directory_tree(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                copy_directory_tree(&source_path, &destination_path);
            } else {
                assert!(metadata.is_file());
                fs::copy(source_path, destination_path).unwrap();
            }
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn independent_node_genesis_sync_is_fail_closed_and_leaks_no_plaintext() {
        let fixture = fixture(2);
        let mut primary = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut primary, &fixture);
        let mut object_plaintext = b"merge-object:".to_vec();
        object_plaintext.extend_from_slice(SENTINEL);
        primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                &object_plaintext,
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let rotate = signed_rotate_control(&primary, agent);
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &rotate, 40, 41);
        let backup = primary
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let snapshot = primary
            .export_encrypted_snapshot(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        assert!(!contains(&backup, SENTINEL));
        assert!(!contains(&snapshot, SENTINEL));
        assert!(!contains(&backup, RUNTIME_STATE_SENTINEL));
        assert!(!contains(&snapshot, RUNTIME_STATE_SENTINEL));
        for magic in [b"PVI1", b"PVI2"] {
            assert!(!contains(&backup, magic));
            assert!(!contains(&snapshot, magic));
        }

        let mut peer = create_host(&fixture, 1, "peer");
        assert_eq!(create_agent(&mut peer, &fixture), agent);
        let binding = peer.binding(agent).unwrap();
        let cursor = PrivateSyncCursor::start(
            binding.space,
            binding.agent,
            binding.epoch,
            binding.control_head,
        )
        .unwrap();
        let request = PrivateSyncRequest {
            cursor,
            max_items: MAX_PRIVATE_SYNC_ITEMS as u16,
            max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
        };
        let before_binding = peer.binding(agent).unwrap();
        let mut before_slot = Vec::new();
        collect_files(&peer.agent_path(agent), &mut before_slot);
        let page = primary
            .serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[1].identity),
                &request.encode().unwrap(),
                authority_target(&fixture).0,
                &TestTransport,
            )
            .unwrap();
        assert_eq!(
            peer.apply_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &page,
                authority_target(&fixture).0,
                &TestAuthority,
                &TestTransport,
            ),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(peer.binding(agent).unwrap(), before_binding);
        let mut after_slot = Vec::new();
        collect_files(&peer.agent_path(agent), &mut after_slot);
        assert_eq!(after_slot, before_slot);
        assert!(fs::read_dir(peer.agent_path(agent)).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(NEXT_PREFIX)
        }));

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
        assert_eq!(peer.binding(agent).unwrap(), before_binding);
        assert_eq!(primary.descriptor(agent).unwrap(), &fixture.descriptor);
        assert_eq!(peer.descriptor(agent).unwrap(), &fixture.descriptor);
    }

    #[test]
    fn object_sync_refreshes_pvri_and_quarantines_ambiguous_store_errors() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "object-sync-source");
        let agent = create_agent(&mut source, &fixture);
        let base = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        let first = source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"object-sync-first",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let second = source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"object-sync-second",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();

        let request_for = |host: &PrivateAgentHost| {
            let binding = host.binding(agent).unwrap();
            PrivateSyncRequest {
                cursor: PrivateSyncCursor::start(
                    binding.space,
                    binding.agent,
                    binding.epoch,
                    binding.control_head,
                )
                .unwrap(),
                max_items: MAX_PRIVATE_SYNC_ITEMS as u16,
                max_bytes: MAX_PRIVATE_SYNC_PAGE_BYTES as u32,
            }
        };
        let restore = |host: &mut PrivateAgentHost| {
            assert_eq!(
                host.restore_encrypted_backup(
                    agent,
                    DurableRecoveryRecipient::from_durable_keystore(
                        fixture.recovery.verifying_key(),
                        fixture.recovery_encryption.public_key(),
                    )
                    .unwrap(),
                    &base,
                    &TestAuthority,
                )
                .unwrap(),
                RestoreDisposition::Restored
            );
        };

        let mut receiver = create_host(&fixture, 0, "object-sync-receiver");
        restore(&mut receiver);
        let page_bytes = source
            .serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &request_for(&receiver).encode().unwrap(),
                authority_target(&fixture).0,
                &TestTransport,
            )
            .unwrap();
        let page = PrivateSyncPage::decode(&page_bytes).unwrap();
        assert_eq!(page.phase, PrivateSyncPhase::Objects);
        assert_eq!(page.items.len(), 2);
        assert_eq!(
            receiver
                .apply_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                    &page_bytes,
                    authority_target(&fixture).0,
                    &TestAuthority,
                    &TestTransport,
                )
                .unwrap(),
            PrivateSyncApplyDisposition::Applied
        );
        assert_eq!(
            receiver.agents[&agent].runtime_image.store(),
            receiver.agents[&agent].store.core_position().unwrap()
        );
        let after_apply = receiver.agents[&agent].runtime_image.commitment();
        assert_eq!(
            receiver
                .apply_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                    &page_bytes,
                    authority_target(&fixture).0,
                    &TestAuthority,
                    &TestTransport,
                )
                .unwrap(),
            PrivateSyncApplyDisposition::AlreadyApplied
        );
        assert_eq!(
            receiver.agents[&agent].runtime_image.commitment(),
            after_apply
        );
        drop(receiver);
        let receiver = reopen_host(&fixture, 0, "object-sync-receiver");
        assert_eq!(
            receiver.get_and_decrypt(agent, first).unwrap().as_slice(),
            b"object-sync-first"
        );
        assert_eq!(
            receiver.get_and_decrypt(agent, second).unwrap().as_slice(),
            b"object-sync-second"
        );

        let mut interrupted = create_host(&fixture, 0, "object-sync-interrupted");
        restore(&mut interrupted);
        let page_bytes = source
            .serve_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &request_for(&interrupted).encode().unwrap(),
                authority_target(&fixture).0,
                &TestTransport,
            )
            .unwrap();
        let page = PrivateSyncPage::decode(&page_bytes).unwrap();
        let applied_key = match page.items.first().unwrap() {
            PrivateSyncItem::Object { key, .. } => *key,
            _ => panic!("object page contained a control"),
        };
        let blocked_key = match page.items.get(1).unwrap() {
            PrivateSyncItem::Object { key, .. } => *key,
            _ => panic!("object page contained a control"),
        };
        let blocked_name = format!(
            "{:016x}-{:02x}-{}.pobj",
            blocked_key.epoch,
            blocked_key.kind,
            encode_hash(blocked_key.content)
        );
        let blocker = interrupted
            .agent_path(agent)
            .join(STORE_DIRECTORY)
            .join("objects")
            .join(blocked_name);
        fs::create_dir(&blocker).unwrap();
        assert!(
            interrupted
                .apply_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                    &page_bytes,
                    authority_target(&fixture).0,
                    &TestAuthority,
                    &TestTransport,
                )
                .is_err()
        );
        assert_eq!(
            interrupted.binding(agent),
            Err(PrivateAgentHostError::NotFound)
        );
        assert_eq!(
            interrupted.export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES),
            Err(PrivateAgentHostError::NotFound)
        );
        fs::remove_dir(&blocker).unwrap();
        interrupted
            .reopen_quarantined_agent(agent, &TestAuthority)
            .unwrap();
        assert_eq!(
            interrupted.agents[&agent].runtime_image.store(),
            interrupted.agents[&agent].store.core_position().unwrap()
        );
        assert!(interrupted.get_encrypted_object(agent, applied_key).is_ok());
        assert_eq!(
            interrupted.get_encrypted_object(agent, blocked_key),
            Err(PrivateAgentHostError::NotFound)
        );
        assert_eq!(
            interrupted
                .apply_sync_page(
                    agent,
                    PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                    &page_bytes,
                    authority_target(&fixture).0,
                    &TestAuthority,
                    &TestTransport,
                )
                .unwrap(),
            PrivateSyncApplyDisposition::Applied
        );
        for (key, expected) in [
            (first, b"object-sync-first".as_slice()),
            (second, b"object-sync-second".as_slice()),
        ] {
            assert_eq!(
                interrupted.get_and_decrypt(agent, key).unwrap().as_slice(),
                expected
            );
        }
    }

    #[test]
    fn runtime_application_lineage_accepts_object_growth_between_controls() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "papl-object-papl");
        let agent = create_agent(&mut host, &fixture);
        let first = signed_rotate_control(&host, agent);
        apply_and_attach_test_authority_evidence(&mut host, &fixture, &first, 40, 41);
        let object = host
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"object-between-applications",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let second = signed_rotate_control(&host, agent);
        apply_and_attach_test_authority_evidence(&mut host, &fixture, &second, 42, 43);
        let expected_image = host.agents[&agent].runtime_image.commitment();
        let expected_store = host.agents[&agent].store.core_position().unwrap();
        drop(host);

        let reopened = reopen_host(&fixture, 0, "papl-object-papl");
        assert_eq!(
            reopened.agents[&agent].runtime_image.commitment(),
            expected_image
        );
        assert_eq!(
            reopened.agents[&agent].runtime_image.store(),
            expected_store
        );
        assert_eq!(
            reopened.get_and_decrypt(agent, object).unwrap().as_slice(),
            b"object-between-applications"
        );
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
        let revoke = signed_revoke_control(&primary, agent, fixture.nodes[1].identity.node);
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &revoke, 40, 41);
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
                authority_target(&fixture).0,
                &TestAuthority,
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
    fn same_node_reopens_history_but_cross_node_backup_needs_authenticated_pvri_rebind() {
        let fixture = fixture(2);
        let mut primary = create_host(&fixture, 0, "historical-primary");
        let agent = create_agent(&mut primary, &fixture);
        let epoch_zero = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"epoch-zero-state",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let first_rotate = signed_rotate_control(&primary, agent);
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &first_rotate, 40, 41);
        let epoch_one = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Snapshot,
                b"epoch-one-state",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let second_rotate = signed_rotate_control(&primary, agent);
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &second_rotate, 42, 43);
        let epoch_two = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"epoch-two-state",
                authority_target(&fixture).0,
                &TestAuthority,
            )
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
        assert_node_local_backup_restore_fails_closed(&mut survivor, &fixture, agent, &backup);
    }

    #[test]
    fn invite_retains_history_but_cross_node_pvri_requires_authenticated_rebind() {
        let fixture = fixture(1);
        let invited = node(fixture.space, fixture.owner, 99);
        let mut primary = create_host(&fixture, 0, "late-invite-primary");
        let agent = create_agent(&mut primary, &fixture);
        let epoch_zero = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"epoch-zero",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let first_rotate = signed_rotate_control(&primary, agent);
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &first_rotate, 40, 41);
        let epoch_one = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"epoch-one",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let second_rotate = signed_rotate_control(&primary, agent);
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &second_rotate, 42, 43);
        let current = primary
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Snapshot,
                b"epoch-two",
                authority_target(&fixture).0,
                &TestAuthority,
            )
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
        let invite = signed_invite_control(&primary, agent, invited.identity.clone());
        apply_and_attach_test_authority_evidence(&mut primary, &fixture, &invite, 44, 45);
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
        for (key, expected) in [
            (epoch_zero, b"epoch-zero".as_slice()),
            (epoch_one, b"epoch-one".as_slice()),
            (current, b"epoch-two".as_slice()),
        ] {
            assert_eq!(
                primary.get_and_decrypt(agent, key).unwrap().as_slice(),
                expected
            );
        }
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
        assert_node_local_backup_restore_fails_closed(&mut invited_host, &fixture, agent, &backup);
        assert_eq!(primary.agents[&agent].descriptor, fixture.descriptor);
    }

    #[test]
    fn multi_control_sync_is_fail_closed_before_any_epoch_or_pvri_stage() {
        let fixture = fixture(2);
        let mut source = create_host(&fixture, 0, "multi-rotation-source");
        let agent = create_agent(&mut source, &fixture);
        let first = signed_rotate_control(&source, agent);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &first, 40, 41);
        let second = signed_rotate_control(&source, agent);
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
        let mut peer = create_host(&fixture, 1, "multi-rotation-peer");
        assert_eq!(create_agent(&mut peer, &fixture), agent);
        let before_binding = peer.binding(agent).unwrap();
        let mut before_slot = Vec::new();
        collect_files(&peer.agent_path(agent), &mut before_slot);
        assert!(
            peer.apply_sync_page(
                agent,
                PrivatePeerIdentity::Node(&fixture.nodes[0].identity),
                &page_bytes,
                authority_target(&fixture).0,
                &TestAuthority,
                &TestTransport,
            )
            .is_err()
        );
        assert_eq!(peer.binding(agent).unwrap(), before_binding);
        let mut after_slot = Vec::new();
        collect_files(&peer.agent_path(agent), &mut after_slot);
        assert_eq!(after_slot, before_slot);
        assert!(fs::read_dir(peer.agent_path(agent)).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(NEXT_PREFIX)
        }));
    }

    #[test]
    fn unsigned_sync_epoch_never_receives_encrypted_host_sidecars() {
        let fixture = fixture(2);
        let mut source = create_host(&fixture, 0, "unsigned-epoch-source");
        let agent = create_agent(&mut source, &fixture);
        let rotate = signed_rotate_control(&source, agent);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &rotate, 40, 41);

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
        page.target.head.control_head = Some(*commitment);
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
        assert_eq!(create_agent(&mut peer, &fixture), agent);
        let before = peer.binding(agent).unwrap();
        let mut before_slot = Vec::new();
        collect_files(&peer.agent_path(agent), &mut before_slot);
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
        assert_eq!(peer.binding(agent).unwrap(), before);
        let mut after_slot = Vec::new();
        collect_files(&peer.agent_path(agent), &mut after_slot);
        assert_eq!(after_slot, before_slot);
        let slot = peer.agent_path(agent);
        assert!(fs::read_dir(slot).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            !name.to_string_lossy().contains(NEXT_PREFIX)
        }));
    }

    #[test]
    fn offline_recovery_without_authenticated_stage_is_restart_safe_and_unsupported() {
        let fixture = fixture(2);
        let replacement = node(fixture.space, fixture.owner, 99);
        let mut primary = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut primary, &fixture);
        let mut replacements = vec![
            fixture.nodes[0].identity.clone(),
            replacement.identity.clone(),
        ];
        replacements.sort_by_key(|node| node.node);
        let recovery = signed_recovery_control(&primary, agent, &replacements, &fixture.recovery);
        let (authority, request, _) =
            recovery_runtime_application_request(&fixture, &recovery, None, 80, 85);
        let before_binding = primary.binding(agent).unwrap();
        let before_descriptor = primary.descriptor(agent).unwrap().clone();
        let mut before_slot = Vec::new();
        collect_files(&primary.agent_path(agent), &mut before_slot);
        assert_eq!(
            apply_runtime_request(&mut primary, authority, &request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(
            apply_runtime_request(&mut primary, authority, &request),
            Err(PrivateAgentHostError::UnsupportedOperation)
        );
        assert_eq!(primary.binding(agent).unwrap(), before_binding);
        assert_eq!(primary.descriptor(agent).unwrap(), &before_descriptor);
        let mut after_slot = Vec::new();
        collect_files(&primary.agent_path(agent), &mut after_slot);
        assert_eq!(after_slot, before_slot);

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
        assert_eq!(reopened.binding(agent).unwrap(), before_binding);
        assert_eq!(reopened.descriptor(agent).unwrap(), &before_descriptor);
        assert_eq!(
            reopened.agents[&agent].store.authorized_nodes(),
            identities(&fixture)
        );
    }

    #[test]
    fn cross_node_backup_restore_requires_authenticated_pvri_rebind() {
        let fixture = fixture(2);
        let mut left = create_host(&fixture, 0, "union-left");
        let agent = create_agent(&mut left, &fixture);
        let object = left
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"left-fork-object",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let backup = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        assert_eq!(
            left.get_and_decrypt(agent, object).unwrap().as_slice(),
            b"left-fork-object"
        );
        let descriptor = left.descriptor(agent).unwrap().clone();
        let mut right = create_host(&fixture, 1, "union-right");
        assert_node_local_backup_restore_fails_closed(&mut right, &fixture, agent, &backup);
        assert_eq!(left.descriptor(agent).unwrap(), &descriptor);
    }

    #[test]
    fn recovery_sources_reject_alias_scope_bounds_and_independent_pvri_lineages() {
        let fixture = fixture(2);
        let mut left = create_host(&fixture, 0, "hostile-union-left");
        let agent = create_agent(&mut left, &fixture);
        left.encrypt_and_put(
            agent,
            EncryptedObjectKind::Blob,
            b"left-independent-object",
            authority_target(&fixture).0,
            &TestAuthority,
        )
        .unwrap();
        let left_backup = left
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();

        let mut right = create_host(&fixture, 1, "hostile-union-right");
        assert_eq!(create_agent(&mut right, &fixture), agent);
        right
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"right-independent-object",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let right_backup = right
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();

        let replacement = node(fixture.space, fixture.owner, 112);
        let replacements = vec![replacement.identity.clone()];
        let mut target = PrivateAgentHost::create(
            fixture.directory.child("hostile-union-target"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();

        assert_eq!(
            target.prepare_recovery_from_encrypted_backups(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &[left_backup.as_slice(), left_backup.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Alias)
        );

        let mut cross_scope = decode_host_archive(&left_backup, true).unwrap();
        cross_scope.space = SpaceId([0xe1; 32]);
        let cross_scope =
            encode_host_archive(&cross_scope, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES).unwrap();
        assert_eq!(
            target.prepare_recovery_from_encrypted_backups(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &[left_backup.as_slice(), cross_scope.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::InvalidScope)
        );

        let too_many = vec![left_backup.as_slice(); MAX_PRIVATE_NODES + 1];
        assert_eq!(
            target.prepare_recovery_from_encrypted_backups(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &too_many,
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::LimitExceeded)
        );

        assert!(matches!(
            target.prepare_recovery_from_encrypted_backups(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &[left_backup.as_slice(), right_backup.as_slice()],
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Store(PrivateStoreError::Diverged))
                | Err(PrivateAgentHostError::Corrupt)
        ));
        assert_eq!(target.binding(agent), Err(PrivateAgentHostError::NotFound));
        assert!(!target.agent_path(agent).exists());
        assert!(!target.creating_path(agent).exists());
        assert_eq!(left.descriptor(agent).unwrap(), &fixture.descriptor);
        assert_eq!(right.descriptor(agent).unwrap(), &fixture.descriptor);
    }
    #[test]
    fn encrypted_backup_authenticates_all_epochs_but_recovery_waits_for_pvri_rebind() {
        let fixture = fixture(2);
        let mut source = create_host(&fixture, 0, "offline-source");
        let agent = create_agent(&mut source, &fixture);
        let mut before_revocation = b"epoch-zero:".to_vec();
        before_revocation.extend_from_slice(SENTINEL);
        let epoch_zero = source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                &before_revocation,
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let revoke = signed_revoke_control(&source, agent, fixture.nodes[1].identity.node);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &revoke, 40, 41);
        source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Blob,
                b"epoch-one-survivor",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let rotate = signed_rotate_control(&source, agent);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &rotate, 42, 43);
        source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::Snapshot,
                b"epoch-two-survivor",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        assert_eq!(
            source
                .get_and_decrypt(agent, epoch_zero)
                .unwrap()
                .as_slice(),
            before_revocation.as_slice()
        );
        let backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();
        assert!(!contains(&backup, SENTINEL));

        let replacement = node(fixture.space, fixture.owner, 111);
        let replacements = vec![replacement.identity.clone()];

        let mut wrong_signing = PrivateAgentHost::create(
            fixture.directory.child("wrong-signing-kit"),
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
                .prepare_recovery_from_encrypted_backup(
                    recovery_route(&fixture, agent),
                    None,
                    &wrong_signing_kit,
                    &replacements,
                    &backup,
                    &TestAuthority,
                )
                .is_err()
        );
        assert!(!wrong_signing.creating_path(agent).exists());

        let mut wrong_encryption = PrivateAgentHost::create(
            fixture.directory.child("wrong-encryption-kit"),
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
                .prepare_recovery_from_encrypted_backup(
                    recovery_route(&fixture, agent),
                    None,
                    &wrong_encryption_kit,
                    &replacements,
                    &backup,
                    &TestAuthority,
                )
                .is_err()
        );
        assert!(!wrong_encryption.creating_path(agent).exists());

        // The PVRI is node-local and inert during this foundation's recovery
        // plan, but it is still AEAD-authenticated and rebound to its source
        // descriptor/Store before the plan may be staged.
        let mut forged_backup = backup.clone();
        *forged_backup.last_mut().unwrap() ^= 1;
        let mut forged = PrivateAgentHost::create(
            fixture.directory.child("forged-backup"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert!(
            forged
                .prepare_recovery_from_encrypted_backup(
                    recovery_route(&fixture, agent),
                    None,
                    &recovery_kit(),
                    &replacements,
                    &forged_backup,
                    &TestAuthority,
                )
                .is_err()
        );
        assert!(!forged.creating_path(agent).exists());
        assert!(!forged.agent_path(agent).exists());

        let audit_kit = recovery_kit();
        let mut substituted_archive = decode_host_archive(&backup, true).unwrap();
        let verified = verify_encrypted_backup(
            &substituted_archive.store,
            fixture.space,
            agent,
            fixture.owner,
            audit_kit.signing_public_key(),
            audit_kit.encryption_public_key(),
            &TestAuthority,
        )
        .unwrap();
        let data_key = unwrap_recovery_data_key(
            verified.key_epochs().last().unwrap(),
            audit_kit.decryption_key(),
        )
        .unwrap();
        let encrypted_image =
            EncryptedPrivateObject::decode(&substituted_archive.runtime_state).unwrap();
        let image = PrivateRuntimeImage::decode(
            &decrypt_private_object(&data_key, &encrypted_image).unwrap(),
        )
        .unwrap();
        let store = image.store();
        let substituted_store = PrivateStoreCorePosition::new(
            store.space(),
            store.agent(),
            store.owner(),
            store.epoch(),
            store.control_head(),
            store.next_sequence(),
            store.object_count(),
            Some(Hash([0xd2; 32])),
            store.control_count(),
            store.control_root(),
            store.key_epoch_root(),
        )
        .unwrap();
        let substituted_image = image
            .synthetic_store_substitution_for_host_test(substituted_store)
            .unwrap();
        substituted_archive.runtime_state =
            encrypt_runtime_image_sidecar(&data_key, &substituted_image).unwrap();
        let substituted_backup =
            encode_host_archive(&substituted_archive, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
                .unwrap();
        let mut substituted = PrivateAgentHost::create(
            fixture.directory.child("substituted-pvri-store-root"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        assert_eq!(
            substituted.prepare_recovery_from_encrypted_backup(
                recovery_route(&fixture, agent),
                None,
                &audit_kit,
                &replacements,
                &substituted_backup,
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Corrupt)
        );
        assert!(!substituted.creating_path(agent).exists());
        assert!(!substituted.agent_path(agent).exists());

        let mut target = PrivateAgentHost::create(
            fixture.directory.child("valid-recovery-awaiting-pvri"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let prepared = target
            .prepare_recovery_from_encrypted_backup(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                &replacements,
                &backup,
                &TestAuthority,
            )
            .unwrap();
        let result = complete_prepared_recovery(&mut target, &fixture, &prepared);
        assert!(
            matches!(
                &result,
                Err(PrivateAgentHostError::Corrupt)
                    | Err(PrivateAgentHostError::InvalidScope)
                    | Err(PrivateAgentHostError::UnsupportedOperation)
            ),
            "unexpected recovery result: {result:?}"
        );
        assert_eq!(target.binding(agent), Err(PrivateAgentHostError::NotFound));
        assert!(!target.agent_path(agent).exists());
        assert!(target.creating_path(agent).exists());
        assert_eq!(source.descriptor(agent).unwrap(), &fixture.descriptor);
    }
    #[test]
    fn recovery_successor_requires_authenticated_pvri_rebind_before_late_invite() {
        let fixture = fixture(1);
        let mut source = create_host(&fixture, 0, "recovery-invite-source");
        let agent = create_agent(&mut source, &fixture);
        let epoch_zero = source
            .encrypt_and_put(
                agent,
                EncryptedObjectKind::CrdtNode,
                b"before-recovery-zero",
                authority_target(&fixture).0,
                &TestAuthority,
            )
            .unwrap();
        let rotate = signed_rotate_control(&source, agent);
        apply_and_attach_test_authority_evidence(&mut source, &fixture, &rotate, 40, 41);
        assert_eq!(
            source
                .get_and_decrypt(agent, epoch_zero)
                .unwrap()
                .as_slice(),
            b"before-recovery-zero"
        );
        let source_backup = source
            .export_encrypted_backup(agent, MAX_PRIVATE_HOST_ARCHIVE_BYTES)
            .unwrap();

        let replacement = node(fixture.space, fixture.owner, 121);
        let mut recovered = PrivateAgentHost::create(
            fixture.directory.child("recovery-invite-owner"),
            fixture.space,
            fixture.owner,
            replacement.identity.clone(),
            replacement.key(),
        )
        .unwrap();
        let prepared = recovered
            .prepare_recovery_from_encrypted_backup(
                recovery_route(&fixture, agent),
                None,
                &recovery_kit(),
                core::slice::from_ref(&replacement.identity),
                &source_backup,
                &TestAuthority,
            )
            .unwrap();
        let result = complete_prepared_recovery(&mut recovered, &fixture, &prepared);
        assert!(
            matches!(
                &result,
                Err(PrivateAgentHostError::Corrupt)
                    | Err(PrivateAgentHostError::InvalidScope)
                    | Err(PrivateAgentHostError::UnsupportedOperation)
            ),
            "unexpected recovery result: {result:?}"
        );
        assert_eq!(
            recovered.binding(agent),
            Err(PrivateAgentHostError::NotFound)
        );
        assert!(!recovered.agent_path(agent).exists());
        assert!(recovered.creating_path(agent).exists());
        assert_eq!(source.descriptor(agent).unwrap(), &fixture.descriptor);
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
        let second_receipt = creation_receipt(&second_descriptor, fixture.observed_at);
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
                    creation_receipt: &second_receipt,
                    observed_at: fixture.observed_at,
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

        let invite = signed_invite_control(&host, first, invited.identity.clone());
        apply_and_attach_test_authority_evidence(&mut host, &fixture, &invite, 40, 41);
        assert_eq!(host.agents[&first].store.authorized_nodes().len(), 2);
        let before = host.binding(first).unwrap().epoch;
        let rotate = signed_rotate_control(&host, first);
        apply_and_attach_test_authority_evidence(&mut host, &fixture, &rotate, 42, 43);
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
    fn restart_rejects_committed_control_without_papl_before_promoting_sidecars() {
        let fixture = fixture(1);
        let mut host = create_host(&fixture, 0, "primary");
        let agent = create_agent(&mut host, &fixture);
        let slot = host.agent_path(agent);
        let canonical_before = canonical_sidecars(&host, agent);
        let runtime_before = fs::read(slot.join(RUNTIME_STATE_FILE)).unwrap();
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
        let preview = hosted
            .store
            .preview_control_position(&record, &TestAuthority)
            .unwrap();
        let successor_store = preview.position();
        let successor_key_epochs = preview.key_epoch_commitments().to_vec();
        let successor_image = PrivateRuntimeImage::synthetic_control_only_successor_for_host_test(
            &hosted.runtime_image,
            &record,
            successor_store,
            successor_key_epochs,
            hosted.runtime_image.applied_at().saturating_add(1),
        )
        .unwrap();
        let runtime_stage = slot.join(staged_runtime_image_name(record.commitment()));
        write_new_synced(
            &runtime_stage,
            &encrypt_runtime_image_sidecar(&generated.data_key, &successor_image).unwrap(),
        )
        .unwrap();
        sync_directory(&slot).unwrap();
        hosted
            .store
            .append_control(&record, &TestAuthority)
            .unwrap();
        assert!(
            host.agents[&agent]
                .store
                .read_runtime_application(record.commitment())
                .unwrap()
                .is_none()
        );
        // Simulate process loss after the PCTL commit but before `.next`
        // promotion. A bare PCTL is never a trusted runtime transition.
        drop(host);

        assert!(matches!(
            PrivateAgentHost::open(
                fixture.directory.child("primary"),
                fixture.space,
                fixture.owner,
                fixture.nodes[0].identity.clone(),
                fixture.nodes[0].key(),
                &TestAuthority,
            ),
            Err(PrivateAgentHostError::Corrupt)
        ));
        assert_eq!(
            SIDECAR_FILES.map(|name| fs::read(slot.join(name)).unwrap()),
            canonical_before
        );
        assert_eq!(
            fs::read(slot.join(RUNTIME_STATE_FILE)).unwrap(),
            runtime_before
        );
        for name in SIDECAR_FILES {
            assert!(
                slot.join(staged_sidecar_name(name, binding.epoch + 1))
                    .exists()
            );
        }
        assert!(runtime_stage.exists());
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
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
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
