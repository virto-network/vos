//! Hardened whole-image stores for clean system-Agent bootstrap state.
//!
//! The directory is a dedicated, single-writer namespace. Each logical image
//! has a fixed file name and a fixed staging name; callers cannot supply either
//! name. Files contain a role-bound integrity envelope, while the persistence
//! traits continue to return the caller's exact image bytes. The envelope also
//! binds a staged replacement to the exact canonical predecessor, allowing
//! restart to finish only an unambiguous publication.

#[cfg(unix)]
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use fs2::FileExt as _;
use vos::agent::bootstrap::MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES;
use vos::agent::clean_authority_issuer::{
    CleanManagementIssuerStore, CleanManagementRuntimeStore,
    MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES, MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES,
};
use vos::agent::clean_bootstrap::{
    CleanSystemAgentBootstrapStore, MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES,
    MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES,
};
use vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES;

#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

const LOCK_FILE: &str = "lock";
const PINS_FILE: &str = "system-agent.pins";
const PINS_STAGE_FILE: &str = "system-agent.pins.next";
const BOOTSTRAP_FILE: &str = "system-agent.bootstrap";
const BOOTSTRAP_STAGE_FILE: &str = "system-agent.bootstrap.next";
const ISSUER_FILE: &str = "system-agent.management-issuer";
const ISSUER_STAGE_FILE: &str = "system-agent.management-issuer.next";
const GENESIS_FILE: &str = "system-agent.genesis-archive";
const GENESIS_STAGE_FILE: &str = "system-agent.genesis-archive.next";
const INTENT_FILE: &str = "management.intent";
const INTENT_STAGE_FILE: &str = "management.intent.next";
const LIFECYCLE_ISSUER_FILE: &str = "management.issuer";
const LIFECYCLE_ISSUER_STAGE_FILE: &str = "management.issuer.next";
const LIFECYCLE_RUNTIME_FILE: &str = "management.runtime";
const LIFECYCLE_RUNTIME_STAGE_FILE: &str = "management.runtime.next";
const LOCAL_REQUEST_FILE: &str = "local-create.request";
const LOCAL_REQUEST_STAGE_FILE: &str = "local-create.request.next";
const LOCAL_REQUEST_ENTRIES: [&str; 3] = [LOCK_FILE, LOCAL_REQUEST_FILE, LOCAL_REQUEST_STAGE_FILE];
const LOCAL_ACK_FILE: &str = "local-create.acknowledgement";
const LOCAL_ACK_STAGE_FILE: &str = "local-create.acknowledgement.next";
const LOCAL_ACK_ENTRIES: [&str; 3] = [LOCK_FILE, LOCAL_ACK_FILE, LOCAL_ACK_STAGE_FILE];
const CREDENTIAL_QUERY_FILE: &str = "credential.query";
const RESERVATION_FILE: &str = "credential.reservation";
const RESERVATION_STAGE_FILE: &str = "credential.reservation.next";
const RESERVATION_ENTRIES: [&str; 3] = [LOCK_FILE, RESERVATION_FILE, RESERVATION_STAGE_FILE];
const CREDENTIAL_QUERY_STAGE_FILE: &str = "credential.query.next";
const CREDENTIAL_QUERY_ENTRIES: [&str; 3] = [
    LOCK_FILE,
    CREDENTIAL_QUERY_FILE,
    CREDENTIAL_QUERY_STAGE_FILE,
];
const LIFECYCLE_ENTRIES: [&str; 7] = [
    LOCK_FILE,
    INTENT_FILE,
    INTENT_STAGE_FILE,
    LIFECYCLE_ISSUER_FILE,
    LIFECYCLE_ISSUER_STAGE_FILE,
    LIFECYCLE_RUNTIME_FILE,
    LIFECYCLE_RUNTIME_STAGE_FILE,
];

pub(crate) const MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES: usize =
    MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES + MAX_PACKAGE_ENCODED_BYTES + 1024;

const STORE_MAGIC: [u8; 4] = *b"CSF1";
const STORE_VERSION: u8 = 1;
const STORE_HEADER_BYTES: usize = 80;
const NO_PREDECESSOR: [u8; 32] = [0; 32];
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"vos/clean-system-agent/file-envelope/v1";

const ALLOWED_ENTRIES: [&str; 9] = [
    LOCK_FILE,
    PINS_FILE,
    PINS_STAGE_FILE,
    BOOTSTRAP_FILE,
    BOOTSTRAP_STAGE_FILE,
    ISSUER_FILE,
    ISSUER_STAGE_FILE,
    GENESIS_FILE,
    GENESIS_STAGE_FILE,
];

/// Failure at the physical clean-system-Agent persistence boundary.
///
/// Structural failures are kept separate from I/O failures so startup can
/// distinguish an unavailable filesystem from state that must never be
/// selected automatically.
#[derive(Debug)]
pub(crate) enum CleanFileStoreError {
    InvalidPath,
    InsecureParent,
    InsecureRoot,
    InsecurePermissions,
    Busy,
    Alias,
    HardLink,
    NonRegular,
    UnexpectedResidue,
    WrongStoreRole,
    Oversized,
    Corrupt,
    AmbiguousPublication,
    StageCollision,
    RequestConflict,
    LockPoisoned,
    Io(io::Error),
}

impl fmt::Display for CleanFileStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "clean store I/O failure: {error}"),
            other => write!(formatter, "clean store rejected physical state: {other:?}"),
        }
    }
}

impl std::error::Error for CleanFileStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CleanFileStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum StoreRole {
    Pins = 1,
    Bootstrap = 2,
    ManagementIssuer = 3,
    GenesisArchive = 4,
    ManagementIntent = 5,
    LifecycleIssuer = 6,
    LocalCreateRequest = 7,
    CredentialQuery = 8,
    CredentialReservation = 9,
    LocalCreateAcknowledgement = 10,
    LifecycleRuntime = 11,
}

impl StoreRole {
    const fn file(self) -> &'static str {
        match self {
            Self::Pins => PINS_FILE,
            Self::Bootstrap => BOOTSTRAP_FILE,
            Self::ManagementIssuer => ISSUER_FILE,
            Self::GenesisArchive => GENESIS_FILE,
            Self::ManagementIntent => INTENT_FILE,
            Self::LifecycleIssuer => LIFECYCLE_ISSUER_FILE,
            Self::LocalCreateRequest => LOCAL_REQUEST_FILE,
            Self::CredentialQuery => CREDENTIAL_QUERY_FILE,
            Self::CredentialReservation => RESERVATION_FILE,
            Self::LocalCreateAcknowledgement => LOCAL_ACK_FILE,
            Self::LifecycleRuntime => LIFECYCLE_RUNTIME_FILE,
        }
    }

    const fn stage_file(self) -> &'static str {
        match self {
            Self::Pins => PINS_STAGE_FILE,
            Self::Bootstrap => BOOTSTRAP_STAGE_FILE,
            Self::ManagementIssuer => ISSUER_STAGE_FILE,
            Self::GenesisArchive => GENESIS_STAGE_FILE,
            Self::ManagementIntent => INTENT_STAGE_FILE,
            Self::LifecycleIssuer => LIFECYCLE_ISSUER_STAGE_FILE,
            Self::LocalCreateRequest => LOCAL_REQUEST_STAGE_FILE,
            Self::CredentialQuery => CREDENTIAL_QUERY_STAGE_FILE,
            Self::CredentialReservation => RESERVATION_STAGE_FILE,
            Self::LocalCreateAcknowledgement => LOCAL_ACK_STAGE_FILE,
            Self::LifecycleRuntime => LIFECYCLE_RUNTIME_STAGE_FILE,
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::Pins => MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES,
            Self::Bootstrap => MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES,
            Self::ManagementIssuer => MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES,
            Self::GenesisArchive => MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES,
            Self::ManagementIntent => MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES,
            Self::LifecycleIssuer => MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES,
            Self::LocalCreateRequest => 1024 * 1024,
            Self::LifecycleRuntime => MAX_PACKAGE_ENCODED_BYTES,
            Self::CredentialReservation => 165,
            Self::LocalCreateAcknowledgement => {
                vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
            }
            Self::CredentialQuery => {
                vos::agent::sdk::wire::MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES
            }
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Pins),
            2 => Some(Self::Bootstrap),
            3 => Some(Self::ManagementIssuer),
            4 => Some(Self::GenesisArchive),
            5 => Some(Self::ManagementIntent),
            6 => Some(Self::LifecycleIssuer),
            7 => Some(Self::LocalCreateRequest),
            8 => Some(Self::CredentialQuery),
            9 => Some(Self::CredentialReservation),
            10 => Some(Self::LocalCreateAcknowledgement),
            11 => Some(Self::LifecycleRuntime),
            _ => None,
        }
    }
}

/// The three independently addressable files under one shared writer lease.
pub(crate) struct CleanSystemAgentFileStores {
    pins: CleanSystemAgentPinsFile,
    bootstrap: CleanSystemAgentBootstrapFile,
    issuer: CleanManagementIssuerFile,
    genesis: CleanSystemAgentGenesisFile,
}

impl CleanSystemAgentFileStores {
    /// Open or create one dedicated clean store directory.
    ///
    /// The immediate parent must already be an absolute, canonical, private
    /// directory. A missing final directory is created as `0700`; existing
    /// directories and all existing entries are verified before any image is
    /// read or changed.
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_or_create(root.as_ref())?);
        Ok(Self {
            pins: CleanSystemAgentPinsFile(ExactFileStore::new(Arc::clone(&root), StoreRole::Pins)),
            bootstrap: CleanSystemAgentBootstrapFile(ExactFileStore::new(
                Arc::clone(&root),
                StoreRole::Bootstrap,
            )),
            issuer: CleanManagementIssuerFile(ExactFileStore::new(
                Arc::clone(&root),
                StoreRole::ManagementIssuer,
            )),
            genesis: CleanSystemAgentGenesisFile(ExactFileStore::new(
                root,
                StoreRole::GenesisArchive,
            )),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CleanSystemAgentPinsFile,
        CleanSystemAgentBootstrapFile,
        CleanManagementIssuerFile,
    ) {
        (self.pins, self.bootstrap, self.issuer)
    }

    pub(crate) fn into_production_parts(
        self,
    ) -> (
        CleanSystemAgentPinsFile,
        CleanSystemAgentBootstrapFile,
        CleanManagementIssuerFile,
        CleanSystemAgentGenesisFile,
    ) {
        (self.pins, self.bootstrap, self.issuer, self.genesis)
    }
}

pub(crate) struct CleanSystemAgentPinsFile(ExactFileStore);
pub(crate) struct CleanSystemAgentBootstrapFile(ExactFileStore);
pub(crate) struct CleanManagementIssuerFile(ExactFileStore);
pub(crate) struct CleanSystemAgentGenesisFile(ExactFileStore);

/// One per-agent lifecycle directory with a shared exclusive writer lease.
/// The coordinator must validate the signed intent and issuer binding against
/// its configured Space/Agent; the file envelope is integrity, not authority.
pub(crate) struct CleanManagementLifecycleFiles {
    intent: CleanManagementIntentFile,
    issuer: CleanManagementIssuerFile,
}

impl CleanManagementLifecycleFiles {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        Ok(Self::from_root(StoreRoot::open_with_entries(
            root.as_ref(),
            &LIFECYCLE_ENTRIES,
        )?))
    }

    fn open_existing(root: &Path) -> Result<Self, CleanFileStoreError> {
        Ok(Self::from_root(StoreRoot::open_with_entries_mode(
            root,
            &LIFECYCLE_ENTRIES,
            false,
        )?))
    }

    fn from_root(root: StoreRoot) -> Self {
        let root = Arc::new(root);
        Self {
            intent: CleanManagementIntentFile(
                ExactFileStore::new(Arc::clone(&root), StoreRole::ManagementIntent),
                ExactFileStore::new(Arc::clone(&root), StoreRole::LifecycleRuntime),
            ),
            issuer: CleanManagementIssuerFile(ExactFileStore::new(
                root,
                StoreRole::LifecycleIssuer,
            )),
        }
    }

    pub(crate) fn into_parts(self) -> (CleanManagementIntentFile, CleanManagementIssuerFile) {
        (self.intent, self.issuer)
    }
}

pub(crate) struct CleanManagementIntentFile(ExactFileStore, ExactFileStore);

/// One immutable signed submission in its own leased private directory.
/// Keep this lease until submission finishes; ambiguous outcomes retain the
/// same request for restart. This does not allocate a credential sequence.
#[cfg(target_os = "linux")]
pub(crate) struct CleanLocalCreateRequestFile(ExactFileStore);

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialReservationStatus {
    Pending,
    Completed,
}

/// One local operation at a time for a Space/Credential in this configured
/// private parent. Retain the lease across discovery, preparation and sending.
/// Other machines are still serialized by Authority's exact sequence policy.
#[cfg(target_os = "linux")]
pub(crate) struct CleanCredentialReservation {
    store: ExactFileStore,
    space: vos::agent::sdk::SpaceId,
    credential: vos::agent::sdk::CredentialId,
}

#[cfg(target_os = "linux")]
impl CleanCredentialReservation {
    pub(crate) fn open_or_create(
        parent: &Path,
        space: vos::agent::sdk::SpaceId,
        credential: vos::agent::sdk::CredentialId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::agent::sdk::SpaceId::ZERO
            || credential == vos::agent::sdk::CredentialId::ZERO
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let path = parent.join(format!(
            "{}-{}",
            hex::encode(space.0),
            hex::encode(credential.0)
        ));
        let root = Arc::new(StoreRoot::open_with_entries(&path, &RESERVATION_ENTRIES)?);
        Ok(Self {
            store: ExactFileStore::new(root, StoreRole::CredentialReservation),
            space,
            credential,
        })
    }

    fn image(
        &self,
        nonce: vos::agent::sdk::Hash,
        completed: Option<(vos::agent::sdk::Hash, vos::agent::sdk::Hash)>,
    ) -> Vec<u8> {
        let mut bytes = b"CRS1".to_vec();
        bytes.extend_from_slice(self.space.as_bytes());
        bytes.extend_from_slice(self.credential.as_bytes());
        bytes.extend_from_slice(nonce.as_bytes());
        bytes.push(u8::from(completed.is_some()));
        let (request, ack) =
            completed.unwrap_or((vos::agent::sdk::Hash::ZERO, vos::agent::sdk::Hash::ZERO));
        bytes.extend_from_slice(request.as_bytes());
        bytes.extend_from_slice(ack.as_bytes());
        bytes
    }

    fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::CredentialReservation.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            if bytes.len() != 165
                || &bytes[..4] != b"CRS1"
                || bytes[4..36] != self.space.0
                || bytes[36..68] != self.credential.0
                || bytes[68..100] == [0; 32]
                || !match bytes[100] {
                    0 => bytes[101..165] == [0; 64],
                    1 => bytes[101..133] != [0; 32] && bytes[133..165] != [0; 32],
                    _ => false,
                }
            {
                return Err(CleanFileStoreError::Corrupt);
            }
            self.store.commit(bytes)?;
        }
        Ok(bytes)
    }

    pub(crate) fn current(
        &mut self,
    ) -> Result<Option<(vos::agent::sdk::Hash, CredentialReservationStatus)>, CleanFileStoreError>
    {
        self.load()?
            .map(|bytes| {
                let nonce = vos::agent::sdk::Hash(
                    bytes[68..100]
                        .try_into()
                        .map_err(|_| CleanFileStoreError::Corrupt)?,
                );
                let status = if bytes[100] == 0 {
                    CredentialReservationStatus::Pending
                } else {
                    CredentialReservationStatus::Completed
                };
                Ok((nonce, status))
            })
            .transpose()
    }

    pub(crate) fn reserve(
        &mut self,
        nonce: vos::agent::sdk::Hash,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        if nonce == vos::agent::sdk::Hash::ZERO {
            return Err(CleanFileStoreError::Corrupt);
        }
        if let Some(current) = self.load()? {
            if current[68..100] == nonce.0 {
                return Ok(if current[100] == 0 {
                    CredentialReservationStatus::Pending
                } else {
                    CredentialReservationStatus::Completed
                });
            }
            if current[100] == 0 {
                return Err(CleanFileStoreError::RequestConflict);
            }
        }
        self.store.commit(&self.image(nonce, None))?;
        Ok(CredentialReservationStatus::Pending)
    }

    /// Only a cryptographically verified acknowledgement for the reserved
    /// Create can complete this reservation. Never interpret an HTTP error,
    /// cancellation or unsigned projection as completion.
    pub(crate) fn complete(
        &mut self,
        request: &[u8],
        acknowledgement: &[u8],
    ) -> Result<(), CleanFileStoreError> {
        use vos::agent::sdk::Hash;
        let ack = super::local_create::verify_acknowledgement(request, acknowledgement)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let submission = vos::agent::local_lifecycle::LocalCreateSubmission::decode(request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let (descriptor, call, _) = submission.into_parts();
        if descriptor.identity.space != self.space || call.credential != self.credential {
            return Err(CleanFileStoreError::Corrupt);
        }
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != descriptor.creation_nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let completed = self.image(
            descriptor.creation_nonce,
            Some((
                Hash::digest(b"vos/local-create/retained-request/v1", &[request]),
                ack.commitment(),
            )),
        );
        if current[100] == 1 && current != completed {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&completed)
    }
}

/// Immutable signed discovery query, scoped to an independently chosen target
/// and credential. A valid initial stage is recoverable; no nonce replacement
/// is allowed after publication or ambiguous completion.
#[cfg(target_os = "linux")]
pub(crate) struct CleanCredentialQueryFile {
    store: ExactFileStore,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    credential: vos::agent::sdk::CredentialId,
}

#[cfg(target_os = "linux")]
impl CleanCredentialQueryFile {
    pub(crate) fn open_or_create(
        root: impl AsRef<Path>,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        credential: vos::agent::sdk::CredentialId,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid() || credential == vos::agent::sdk::CredentialId::ZERO {
            return Err(CleanFileStoreError::Corrupt);
        }
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &CREDENTIAL_QUERY_ENTRIES,
        )?);
        Ok(Self {
            store: ExactFileStore::new(root, StoreRole::CredentialQuery),
            authority,
            credential,
        })
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::CredentialQuery.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate(bytes)?;
            self.store.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate(bytes)?;
        self.store.commit_with_replacement(bytes, false)
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        use vos::agent::sdk::authority::{AuthorityProjectionQuery, AuthorityProjectionSelector};
        use vos::agent::sdk::wire::CanonicalWire as _;
        let query =
            AuthorityProjectionQuery::decode(bytes).map_err(|_| CleanFileStoreError::Corrupt)?;
        if query.authority != self.authority
            || query.credential != self.credential
            || query.selector != AuthorityProjectionSelector::Credential
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        query
            .verify_api_with(&super::local_create::CredentialVerifier)
            .map_err(|_| CleanFileStoreError::Corrupt)
    }
}

#[cfg(target_os = "linux")]
/// Immutable client delivery evidence, bound to the complete retained request.
/// This is not a substitute for server publication or runtime finality.
pub(crate) struct CleanLocalCreateAcknowledgementFile {
    store: ExactFileStore,
    request: Vec<u8>,
}

impl CleanLocalCreateAcknowledgementFile {
    pub(crate) fn open_or_create(
        root: impl AsRef<Path>,
        request: &[u8],
    ) -> Result<Self, CleanFileStoreError> {
        CleanLocalCreateRequestFile::validate(request)?;
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &LOCAL_ACK_ENTRIES,
        )?);
        Ok(Self {
            store: ExactFileStore::new(root, StoreRole::LocalCreateAcknowledgement),
            request: request.to_vec(),
        })
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::LocalCreateAcknowledgement.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate(bytes)?;
            self.store.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate(bytes)?;
        self.store.commit_with_replacement(bytes, false)
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > StoreRole::LocalCreateAcknowledgement.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        super::local_create::verify_acknowledgement(&self.request, bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }
}

impl CleanLocalCreateRequestFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &LOCAL_REQUEST_ENTRIES,
        )?);
        Ok(Self(ExactFileStore::new(
            root,
            StoreRole::LocalCreateRequest,
        )))
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self.0.load(StoreRole::LocalCreateRequest.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            Self::validate(bytes)?;
            // A prior publication may have renamed successfully but failed
            // its directory sync. Re-establish durability before a retry sends.
            self.0.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        Self::validate(bytes)?;
        self.0.commit_with_replacement(bytes, false)
    }

    fn validate(bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > StoreRole::LocalCreateRequest.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let submission = vos::agent::local_lifecycle::LocalCreateSubmission::decode(bytes)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if submission.into_parts().1.authenticated_node.is_some() {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }
}

/// A configured private directory for per-agent lifecycle images. Keeping the
/// opened directory pins its physical identity across factory calls; image
/// signatures/bindings remain the controller's responsibility.
pub(crate) struct CleanManagementLifecycleStoreFactory {
    parent: PathBuf,
    directory: File,
    space: vos::agent::sdk::SpaceId,
}

impl CleanManagementLifecycleStoreFactory {
    pub(crate) fn open_or_create(
        parent: impl AsRef<Path>,
        space: vos::agent::sdk::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::agent::sdk::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let path = parent.as_ref();
        let directory = ensure_private_directory(path)?;
        Ok(Self {
            parent: path.to_path_buf(),
            directory,
            space,
        })
    }

    pub(crate) fn new(
        parent: impl AsRef<Path>,
        space: vos::agent::sdk::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::agent::sdk::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let parent = parent.as_ref().to_path_buf();
        let directory = open_private_directory(&parent, true)?;
        Ok(Self {
            parent,
            directory,
            space,
        })
    }
}

/// Create one private directory under an existing validated private parent.
pub(crate) fn ensure_private_directory(path: &Path) -> Result<File, CleanFileStoreError> {
    validate_new_path(path)?;
    let ancestor =
        open_private_directory(path.parent().ok_or(CleanFileStoreError::InvalidPath)?, true)?;
    let (directory, created) = open_or_create_child_directory(&ancestor, path)?;
    if created {
        set_private_directory_permissions(&directory)?;
        directory.sync_all()?;
        ancestor.sync_all()?;
    }
    validate_opened_directory(&directory, path, false)?;
    Ok(directory)
}

impl vos::agent::local_lifecycle::LocalLifecycleStoreFactory
    for CleanManagementLifecycleStoreFactory
{
    type Intent = CleanManagementIntentFile;
    type Issuer = CleanManagementIssuerFile;
    type Error = CleanFileStoreError;

    fn discover(
        &mut self,
        space: vos::agent::sdk::SpaceId,
        maximum: usize,
    ) -> Result<Vec<vos::agent::sdk::AgentId>, Self::Error> {
        if space != self.space {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        // Scan the pinned directory, not a pathname that can be replaced
        // between validation and read_dir. This backend already relies on
        // Linux descriptor-relative physical storage boundaries.
        #[cfg(target_os = "linux")]
        let scan = PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let scan: PathBuf = return Err(CleanFileStoreError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-pinned lifecycle discovery requires Linux",
        )));
        let mut agents = Vec::new();
        for entry in fs::read_dir(scan)? {
            let entry = entry?;
            if agents.len() == maximum {
                return Err(CleanFileStoreError::Oversized);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(CleanFileStoreError::UnexpectedResidue);
            }
            let mut bytes = [0; 32];
            hex::decode_to_slice(&name, &mut bytes)
                .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
            let agent = vos::agent::sdk::AgentId(bytes);
            if agent == vos::agent::sdk::AgentId::ZERO {
                return Err(CleanFileStoreError::UnexpectedResidue);
            }
            let path = self.parent.join(&name);
            let directory = open_child_directory(&self.directory, &path)?;
            validate_opened_directory(&directory, &path, false)?;
            agents.push(agent);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        agents.sort_unstable();
        if agents.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CleanFileStoreError::Alias);
        }
        Ok(agents)
    }

    fn open_existing(
        &mut self,
        space: vos::agent::sdk::SpaceId,
        agent: vos::agent::sdk::AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error> {
        if space != self.space || agent == vos::agent::sdk::AgentId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        let stores =
            CleanManagementLifecycleFiles::open_existing(&self.parent.join(hex::encode(agent.0)))?;
        validate_opened_directory(&self.directory, &self.parent, true)?;
        Ok(stores.into_parts())
    }

    fn open(
        &mut self,
        space: vos::agent::sdk::SpaceId,
        agent: vos::agent::sdk::AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error> {
        if space != self.space || agent == vos::agent::sdk::AgentId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        let stores =
            CleanManagementLifecycleFiles::open_or_create(self.parent.join(hex::encode(agent.0)))?;
        validate_opened_directory(&self.directory, &self.parent, true)?;
        Ok(stores.into_parts())
    }
}

impl CleanManagementIssuerStore for CleanManagementIntentFile {
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

impl CleanManagementRuntimeStore for CleanManagementIntentFile {
    fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.1.load(MAX_PACKAGE_ENCODED_BYTES)
    }
    fn commit_runtime(&mut self, package: &[u8]) -> Result<(), Self::Error> {
        match self.load_runtime()? {
            Some(bytes) if bytes == package => Ok(()),
            Some(_) => Err(CleanFileStoreError::RequestConflict),
            None => self.1.commit(package),
        }
    }
}

impl CleanSystemAgentGenesisFile {
    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        self.0.load(MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES)
    }

    pub(crate) fn commit(&mut self, image: &[u8]) -> Result<(), CleanFileStoreError> {
        self.0.commit(image)
    }
}

impl CleanSystemAgentBootstrapStore for CleanSystemAgentPinsFile {
    type Error = CleanFileStoreError;

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(maximum_bytes)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

impl CleanSystemAgentBootstrapStore for CleanSystemAgentBootstrapFile {
    type Error = CleanFileStoreError;

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(maximum_bytes)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

impl CleanManagementIssuerStore for CleanManagementIssuerFile {
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

struct StoreRoot {
    allowed_entries: &'static [&'static str],
    parent_path: PathBuf,
    parent: File,
    path: PathBuf,
    directory: File,
    lock: File,
    writes: Mutex<()>,
}

impl StoreRoot {
    fn open_or_create(path: &Path) -> Result<Self, CleanFileStoreError> {
        Self::open_with_entries(path, &ALLOWED_ENTRIES)
    }

    fn open_with_entries(
        path: &Path,
        allowed_entries: &'static [&'static str],
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_with_entries_mode(path, allowed_entries, true)
    }

    fn open_with_entries_mode(
        path: &Path,
        allowed_entries: &'static [&'static str],
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        validate_new_path(path)?;
        let parent_path = path.parent().ok_or(CleanFileStoreError::InvalidPath)?;
        let parent = open_private_directory(parent_path, true)?;
        let (directory, created) = if create {
            open_or_create_child_directory(&parent, path)?
        } else {
            (open_child_directory(&parent, path)?, false)
        };
        if created {
            set_private_directory_permissions(&directory)?;
        }
        let opened = directory.metadata()?;
        validate_private_directory_metadata(&opened, false)?;
        let named = fs::symlink_metadata(path).map_err(CleanFileStoreError::Io)?;
        validate_private_directory_metadata(&named, false)?;
        same_file_identity(&opened, &named)?;
        if created {
            directory.sync_all()?;
            parent.sync_all()?;
        }
        audit_named_entries(path, allowed_entries)?;
        let lock = open_lock(&directory, path)?;
        match lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(CleanFileStoreError::Busy);
            }
            Err(error) => return Err(error.into()),
        }
        let root = Self {
            allowed_entries,
            parent_path: parent_path.to_path_buf(),
            parent,
            path: path.to_path_buf(),
            directory,
            lock,
            writes: Mutex::new(()),
        };
        root.validate_path()?;
        root.audit_entries()?;
        Ok(root)
    }

    fn guard(&self) -> Result<MutexGuard<'_, ()>, CleanFileStoreError> {
        self.writes
            .lock()
            .map_err(|_| CleanFileStoreError::LockPoisoned)
    }

    fn validate_path(&self) -> Result<(), CleanFileStoreError> {
        self.validate_directory_path()?;
        self.validate_lock()?;
        self.validate_directory_path()
    }

    fn validate_directory_path(&self) -> Result<(), CleanFileStoreError> {
        validate_opened_directory(&self.parent, &self.parent_path, true)?;
        let named = fs::symlink_metadata(&self.path).map_err(CleanFileStoreError::Io)?;
        validate_private_directory_metadata(&named, false)?;
        let opened = self.directory.metadata()?;
        same_file_identity(&opened, &named)?;
        let entry = open_child_directory(&self.parent, &self.path)?;
        same_file_identity(&entry.metadata()?, &opened)?;
        let canonical = fs::canonicalize(&self.path).map_err(CleanFileStoreError::Io)?;
        if canonical != self.path {
            return Err(CleanFileStoreError::Alias);
        }
        Ok(())
    }

    fn validate_lock(&self) -> Result<(), CleanFileStoreError> {
        let named = named_metadata(&self.path, LOCK_FILE)?;
        validate_private_regular_metadata(&named)?;
        validate_opened_file(&self.lock, &named)?;
        if named.len() != 0 {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }

    fn audit_entries(&self) -> Result<(), CleanFileStoreError> {
        self.validate_path()?;
        audit_named_entries(&self.path, self.allowed_entries)?;
        self.validate_path()
    }

    fn sync(&self) -> Result<(), CleanFileStoreError> {
        self.validate_path()?;
        self.directory.sync_all()?;
        self.validate_path()
    }
}

struct ExactFileStore {
    root: Arc<StoreRoot>,
    role: StoreRole,
}

impl ExactFileStore {
    fn new(root: Arc<StoreRoot>, role: StoreRole) -> Self {
        Self { root, role }
    }

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let _guard = self.root.guard()?;
        let maximum_bytes = maximum_bytes.min(self.role.maximum_bytes());
        self.reconcile(maximum_bytes)
            .map(|stored| stored.map(|stored| stored.payload))
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), CleanFileStoreError> {
        self.commit_with_replacement(image, true)
    }

    fn commit_with_replacement(
        &mut self,
        image: &[u8],
        replace: bool,
    ) -> Result<(), CleanFileStoreError> {
        if image.len() > self.role.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let _guard = self.root.guard()?;
        let current = self.reconcile(self.role.maximum_bytes())?;
        if current
            .as_ref()
            .is_some_and(|current| current.payload == image)
        {
            self.sync_named(self.role.file())?;
            return self.root.sync();
        }
        if !replace && current.is_some() {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let predecessor = current.as_ref().map(StoredImage::commitment);
        let encoded = encode_envelope(self.role, predecessor, image)?;
        self.write_stage(&encoded)?;
        self.publish_stage(
            current.as_ref(),
            &decode_envelope(self.role, &encoded, image.len())?,
        )
    }

    fn reconcile(&self, maximum_bytes: usize) -> Result<Option<StoredImage>, CleanFileStoreError> {
        self.root.audit_entries()?;
        let canonical = self.read_optional(self.role.file(), maximum_bytes)?;
        let staged = self.read_optional(self.role.stage_file(), maximum_bytes)?;
        if matches!(
            self.role,
            StoreRole::LocalCreateRequest
                | StoreRole::CredentialQuery
                | StoreRole::LocalCreateAcknowledgement
        ) && canonical
            .iter()
            .chain(staged.iter())
            .any(|image| image.predecessor.is_some())
        {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let resolved = match (canonical, staged) {
            (None, None) => None,
            (Some(canonical), None) => Some(canonical),
            (None, Some(staged)) if staged.predecessor.is_none() => {
                self.publish_stage(None, &staged)?;
                Some(staged)
            }
            (Some(canonical), Some(staged)) if canonical == staged => {
                self.unlink_stage()?;
                Some(canonical)
            }
            (Some(canonical), Some(staged))
                if staged.predecessor == Some(canonical.commitment()) =>
            {
                self.publish_stage(Some(&canonical), &staged)?;
                Some(staged)
            }
            (None, Some(_)) | (Some(_), Some(_)) => {
                return Err(CleanFileStoreError::AmbiguousPublication);
            }
        };
        self.root.audit_entries()?;
        Ok(resolved)
    }

    fn read_optional(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Option<StoredImage>, CleanFileStoreError> {
        let named = match named_metadata(&self.root.path, name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_private_regular_metadata(&named)?;
        let mut file = open_read_at(&self.root.directory, &self.root.path, name)?;
        validate_opened_file(&file, &named)?;
        let physical_maximum = STORE_HEADER_BYTES
            .checked_add(maximum_bytes)
            .ok_or(CleanFileStoreError::Oversized)?;
        let length = usize::try_from(named.len()).map_err(|_| CleanFileStoreError::Oversized)?;
        if length > physical_maximum {
            return Err(CleanFileStoreError::Oversized);
        }
        if length < STORE_HEADER_BYTES {
            return Err(CleanFileStoreError::Corrupt);
        }
        let mut header = [0_u8; STORE_HEADER_BYTES];
        read_exact_or_corrupt(&mut file, &mut header)?;
        let payload_length = decode_payload_length(self.role, &header, maximum_bytes)?;
        if STORE_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(CleanFileStoreError::Oversized)?
            != length
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_length)
            .map_err(|_| CleanFileStoreError::Oversized)?;
        payload.resize(payload_length, 0);
        read_exact_or_corrupt(&mut file, &mut payload)?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(CleanFileStoreError::Io)? != 0 {
            return Err(CleanFileStoreError::Corrupt);
        }
        let after = file.metadata()?;
        validate_opened_file(&file, &named)?;
        if after.len() != named.len() {
            return Err(CleanFileStoreError::Corrupt);
        }
        decode_envelope_parts(self.role, &header, payload).map(Some)
    }

    fn write_stage(&self, encoded: &[u8]) -> Result<(), CleanFileStoreError> {
        let name = self.role.stage_file();
        let mut file = match create_new_at(&self.root.directory, &self.root.path, name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(CleanFileStoreError::StageCollision);
            }
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<(), CleanFileStoreError> {
            set_private_file_permissions(&file)?;
            file.write_all(encoded)?;
            file.sync_all()?;
            let named = named_metadata(&self.root.path, name)?;
            validate_private_regular_metadata(&named)?;
            validate_opened_file(&file, &named)?;
            if usize::try_from(named.len()).ok() != Some(encoded.len()) {
                return Err(CleanFileStoreError::Corrupt);
            }
            Ok(())
        })();
        if result.is_err() {
            self.remove_owned_failed_stage(&file, name);
        }
        result
    }

    fn remove_owned_failed_stage(&self, file: &File, name: &str) {
        let Ok(named) = named_metadata(&self.root.path, name) else {
            return;
        };
        if validate_private_regular_metadata(&named).is_err()
            || validate_opened_file(file, &named).is_err()
        {
            return;
        }
        if unlink_at(&self.root.directory, &self.root.path, name).is_ok() {
            let _ = self.root.sync();
        }
    }

    fn publish_stage(
        &self,
        expected: Option<&StoredImage>,
        staged: &StoredImage,
    ) -> Result<(), CleanFileStoreError> {
        let observed_stage = self
            .read_optional(self.role.stage_file(), self.role.maximum_bytes())?
            .ok_or(CleanFileStoreError::AmbiguousPublication)?;
        if &observed_stage != staged {
            return Err(CleanFileStoreError::AmbiguousPublication);
        }
        let observed_canonical = self.read_optional(self.role.file(), self.role.maximum_bytes())?;
        if observed_canonical.as_ref() != expected
            || staged.predecessor != expected.map(StoredImage::commitment)
        {
            return Err(CleanFileStoreError::AmbiguousPublication);
        }
        self.sync_named(self.role.stage_file())?;
        rename_at(
            &self.root.directory,
            &self.root.path,
            self.role.stage_file(),
            self.role.file(),
        )?;
        self.root.sync()?;
        let published = self
            .read_optional(self.role.file(), self.role.maximum_bytes())?
            .ok_or(CleanFileStoreError::Corrupt)?;
        if &published != staged {
            return Err(CleanFileStoreError::Corrupt);
        }
        match named_metadata(&self.root.path, self.role.stage_file()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(CleanFileStoreError::Corrupt),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn unlink_stage(&self) -> Result<(), CleanFileStoreError> {
        unlink_at(
            &self.root.directory,
            &self.root.path,
            self.role.stage_file(),
        )?;
        self.root.sync()
    }

    fn sync_named(&self, name: &str) -> Result<(), CleanFileStoreError> {
        let named = named_metadata(&self.root.path, name)?;
        validate_private_regular_metadata(&named)?;
        let file = open_read_at(&self.root.directory, &self.root.path, name)?;
        validate_opened_file(&file, &named)?;
        file.sync_all()?;
        Ok(())
    }
}

fn read_exact_or_corrupt(
    reader: &mut impl Read,
    buffer: &mut [u8],
) -> Result<(), CleanFileStoreError> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(CleanFileStoreError::Corrupt)
        }
        Err(error) => Err(CleanFileStoreError::Io(error)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredImage {
    role: StoreRole,
    predecessor: Option<[u8; 32]>,
    payload: Vec<u8>,
}

impl StoredImage {
    fn commitment(&self) -> [u8; 32] {
        envelope_digest(self.role, self.predecessor, &self.payload)
    }
}

fn encode_envelope(
    role: StoreRole,
    predecessor: Option<[u8; 32]>,
    payload: &[u8],
) -> Result<Vec<u8>, CleanFileStoreError> {
    if payload.len() > role.maximum_bytes()
        || predecessor.is_some_and(|predecessor| predecessor == NO_PREDECESSOR)
    {
        return Err(CleanFileStoreError::Corrupt);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            STORE_HEADER_BYTES
                .checked_add(payload.len())
                .ok_or(CleanFileStoreError::Oversized)?,
        )
        .map_err(|_| CleanFileStoreError::Oversized)?;
    encoded.extend_from_slice(&STORE_MAGIC);
    encoded.push(STORE_VERSION);
    encoded.push(role as u8);
    encoded.push(u8::from(predecessor.is_some()));
    encoded.push(0);
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&predecessor.unwrap_or(NO_PREDECESSOR));
    encoded.extend_from_slice(&envelope_digest(role, predecessor, payload));
    encoded.extend_from_slice(payload);
    debug_assert_eq!(encoded.len(), STORE_HEADER_BYTES + payload.len());
    Ok(encoded)
}

fn decode_payload_length(
    expected_role: StoreRole,
    header: &[u8; STORE_HEADER_BYTES],
    maximum_bytes: usize,
) -> Result<usize, CleanFileStoreError> {
    if header[..4] != STORE_MAGIC || header[4] != STORE_VERSION || header[7] != 0 {
        return Err(CleanFileStoreError::Corrupt);
    }
    let role = StoreRole::from_byte(header[5]).ok_or(CleanFileStoreError::Corrupt)?;
    if role != expected_role {
        return Err(CleanFileStoreError::WrongStoreRole);
    }
    let length = u64::from_le_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| CleanFileStoreError::Corrupt)?,
    );
    let length = usize::try_from(length).map_err(|_| CleanFileStoreError::Oversized)?;
    if length > maximum_bytes || length > expected_role.maximum_bytes() {
        return Err(CleanFileStoreError::Oversized);
    }
    Ok(length)
}

fn decode_envelope(
    role: StoreRole,
    encoded: &[u8],
    maximum_bytes: usize,
) -> Result<StoredImage, CleanFileStoreError> {
    if encoded.len() < STORE_HEADER_BYTES {
        return Err(CleanFileStoreError::Corrupt);
    }
    let header: &[u8; STORE_HEADER_BYTES] = encoded[..STORE_HEADER_BYTES]
        .try_into()
        .map_err(|_| CleanFileStoreError::Corrupt)?;
    let length = decode_payload_length(role, header, maximum_bytes)?;
    if encoded.len() != STORE_HEADER_BYTES + length {
        return Err(CleanFileStoreError::Corrupt);
    }
    decode_envelope_parts(role, header, encoded[STORE_HEADER_BYTES..].to_vec())
}

fn decode_envelope_parts(
    role: StoreRole,
    header: &[u8; STORE_HEADER_BYTES],
    payload: Vec<u8>,
) -> Result<StoredImage, CleanFileStoreError> {
    let length = decode_payload_length(role, header, role.maximum_bytes())?;
    let predecessor_bytes: [u8; 32] = header[16..48]
        .try_into()
        .map_err(|_| CleanFileStoreError::Corrupt)?;
    let predecessor = match header[6] {
        0 if predecessor_bytes == NO_PREDECESSOR => None,
        1 if predecessor_bytes != NO_PREDECESSOR => Some(predecessor_bytes),
        _ => return Err(CleanFileStoreError::Corrupt),
    };
    if payload.len() != length || header[48..80] != envelope_digest(role, predecessor, &payload) {
        return Err(CleanFileStoreError::Corrupt);
    }
    let stored = StoredImage {
        role,
        predecessor,
        payload,
    };
    if stored.commitment() == NO_PREDECESSOR {
        return Err(CleanFileStoreError::Corrupt);
    }
    Ok(stored)
}

fn envelope_digest(role: StoreRole, predecessor: Option<[u8; 32]>, payload: &[u8]) -> [u8; 32] {
    digest(ENVELOPE_DIGEST_DOMAIN, role, predecessor, payload)
}

fn digest(
    domain: &[u8],
    role: StoreRole,
    predecessor: Option<[u8; 32]>,
    payload: &[u8],
) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    state.update(domain);
    state.update(&[role as u8]);
    state.update(&[u8::from(predecessor.is_some())]);
    state.update(&predecessor.unwrap_or(NO_PREDECESSOR));
    state.update(&(payload.len() as u64).to_le_bytes());
    state.update(payload);
    let hash = state.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

fn validate_new_path(path: &Path) -> Result<(), CleanFileStoreError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(CleanFileStoreError::InvalidPath);
    }
    let parent = path.parent().ok_or(CleanFileStoreError::InvalidPath)?;
    let canonical_parent = fs::canonicalize(parent).map_err(CleanFileStoreError::Io)?;
    if canonical_parent != parent {
        return Err(CleanFileStoreError::Alias);
    }
    let metadata = fs::symlink_metadata(parent).map_err(CleanFileStoreError::Io)?;
    validate_private_directory_metadata(&metadata, true)
}

fn open_private_directory(path: &Path, parent: bool) -> Result<File, CleanFileStoreError> {
    let named = fs::symlink_metadata(path).map_err(CleanFileStoreError::Io)?;
    validate_private_directory_metadata(&named, parent)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    let file = options.open(path).map_err(CleanFileStoreError::Io)?;
    same_file_identity(&file.metadata()?, &named)?;
    Ok(file)
}

fn validate_opened_directory(
    file: &File,
    path: &Path,
    parent: bool,
) -> Result<(), CleanFileStoreError> {
    let named = fs::symlink_metadata(path).map_err(CleanFileStoreError::Io)?;
    validate_private_directory_metadata(&named, parent)?;
    let opened = file.metadata()?;
    validate_private_directory_metadata(&opened, parent)?;
    same_file_identity(&opened, &named)?;
    let canonical = fs::canonicalize(path).map_err(CleanFileStoreError::Io)?;
    if canonical != path {
        return Err(CleanFileStoreError::Alias);
    }
    Ok(())
}

#[cfg(unix)]
fn child_name(path: &Path) -> Result<CString, CleanFileStoreError> {
    let name = path.file_name().ok_or(CleanFileStoreError::InvalidPath)?;
    CString::new(name.as_bytes()).map_err(|_| CleanFileStoreError::InvalidPath)
}

#[cfg(unix)]
fn open_child_directory(parent: &File, path: &Path) -> Result<File, CleanFileStoreError> {
    let name = child_name(path)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_or_create_child_directory(
    parent: &File,
    path: &Path,
) -> Result<(File, bool), CleanFileStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_directory_metadata(&metadata, false)?;
            let directory = open_child_directory(parent, path)?;
            same_file_identity(&directory.metadata()?, &metadata)?;
            Ok((directory, false))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = child_name(path)?;
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if result != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let directory = open_child_directory(parent, path)?;
            Ok((directory, true))
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_private_directory_metadata(
    metadata: &fs::Metadata,
    parent: bool,
) -> Result<(), CleanFileStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(CleanFileStoreError::Alias);
    }
    if !metadata.is_dir() {
        return Err(if parent {
            CleanFileStoreError::InsecureParent
        } else {
            CleanFileStoreError::InsecureRoot
        });
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(if parent {
                CleanFileStoreError::InsecureParent
            } else {
                CleanFileStoreError::InsecureRoot
            });
        }
    }
    Ok(())
}

fn validate_private_regular_metadata(metadata: &fs::Metadata) -> Result<(), CleanFileStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(CleanFileStoreError::Alias);
    }
    if !metadata.is_file() {
        return Err(CleanFileStoreError::NonRegular);
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
            return Err(CleanFileStoreError::InsecurePermissions);
        }
        if metadata.nlink() == 0 {
            return Err(CleanFileStoreError::Alias);
        }
        if metadata.nlink() > 1 {
            return Err(CleanFileStoreError::HardLink);
        }
    }
    Ok(())
}

fn audit_named_entries(root: &Path, allowed_entries: &[&str]) -> Result<(), CleanFileStoreError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
        if !allowed_entries.contains(&name.as_str()) {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        validate_private_regular_metadata(&fs::symlink_metadata(entry.path())?)?;
    }
    Ok(())
}

fn same_file_identity(
    opened: &fs::Metadata,
    named: &fs::Metadata,
) -> Result<(), CleanFileStoreError> {
    #[cfg(unix)]
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(CleanFileStoreError::Alias);
    }
    Ok(())
}

fn validate_opened_file(file: &File, named: &fs::Metadata) -> Result<(), CleanFileStoreError> {
    let opened = file.metadata()?;
    validate_private_regular_metadata(&opened)?;
    same_file_identity(&opened, named)
}

fn named_metadata(root: &Path, name: &str) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(root.join(name))
}

fn open_lock(directory: &File, root: &Path) -> Result<File, CleanFileStoreError> {
    let (file, created) = match create_new_at(directory, root, LOCK_FILE) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let named = named_metadata(root, LOCK_FILE)?;
            validate_private_regular_metadata(&named)?;
            let file = open_write_at(directory, root, LOCK_FILE)?;
            validate_opened_file(&file, &named)?;
            (file, false)
        }
        Err(error) => return Err(error.into()),
    };
    if created {
        set_private_file_permissions(&file)?;
        file.sync_all()?;
        directory.sync_all()?;
    }
    let named = named_metadata(root, LOCK_FILE)?;
    validate_private_regular_metadata(&named)?;
    validate_opened_file(&file, &named)?;
    if named.len() != 0 {
        return Err(CleanFileStoreError::Corrupt);
    }
    Ok(file)
}

fn set_private_file_permissions(file: &File) -> Result<(), CleanFileStoreError> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_private_directory_permissions(directory: &File) -> Result<(), CleanFileStoreError> {
    let result = unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_read_at(directory: &File, _root: &Path, name: &str) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
}

#[cfg(unix)]
fn open_write_at(directory: &File, _root: &Path, name: &str) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
}

#[cfg(unix)]
fn create_new_at(directory: &File, _root: &Path, name: &str) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK,
        0o600,
    )
}

#[cfg(unix)]
fn rename_at(
    directory: &File,
    _root: &Path,
    from: &str,
    to: &str,
) -> Result<(), CleanFileStoreError> {
    let from = CString::new(from).map_err(|_| CleanFileStoreError::InvalidPath)?;
    let to = CString::new(to).map_err(|_| CleanFileStoreError::InvalidPath)?;
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn unlink_at(directory: &File, _root: &Path, name: &str) -> Result<(), CleanFileStoreError> {
    let name = CString::new(name).map_err(|_| CleanFileStoreError::InvalidPath)?;
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Seek as _, SeekFrom};
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    struct Fixture {
        parent: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let mut nonce = [0_u8; 8];
            getrandom::getrandom(&mut nonce).expect("test entropy");
            let parent = std::env::temp_dir().join(format!(
                "vosx-clean-store-{label}-{}-{}",
                std::process::id(),
                hex::encode(nonce)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&parent).expect("create private test parent");
            #[cfg(unix)]
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .expect("set private test parent mode");
            let root = parent.join("state");
            Self { parent, root }
        }

        fn stores(&self) -> CleanSystemAgentFileStores {
            CleanSystemAgentFileStores::open_or_create(&self.root).expect("open clean stores")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&self.parent, fs::Permissions::from_mode(0o700));
                if let Ok(metadata) = fs::symlink_metadata(&self.root)
                    && metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                {
                    let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
                }
            }
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).expect("create private test file");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private test file mode");
        file.write_all(bytes).expect("write private test file");
        file.sync_all().expect("sync private test file");
        File::open(path.parent().unwrap())
            .and_then(|directory| directory.sync_all())
            .expect("sync private test directory");
    }

    fn stage(store: &ExactFileStore, predecessor: Option<[u8; 32]>, payload: &[u8]) -> StoredImage {
        let encoded = encode_envelope(store.role, predecessor, payload).expect("encode stage");
        let staged = decode_envelope(store.role, &encoded, payload.len()).expect("decode stage");
        store.write_stage(&encoded).expect("write stage");
        staged
    }

    #[cfg(target_os = "linux")]
    fn local_request(sequence: u64) -> Vec<u8> {
        let (operator, authority, descriptor, runtime) =
            super::super::local_create::tests::fixture();
        super::super::local_create::prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            std::num::NonZeroU64::new(sequence).unwrap(),
            10,
            30,
        )
        .unwrap()
        .encode()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_reservation_keeps_pending_operation_across_restart() {
        use vos::agent::sdk::{CredentialId, Hash, SpaceId};
        let fixture = Fixture::new("credential-reservation");
        let space = SpaceId([1; 32]);
        let credential = CredentialId([2; 32]);
        let nonce = Hash([3; 32]);
        let mut store =
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).unwrap();
        assert!(matches!(
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.reserve(Hash::ZERO).is_err());
        assert_eq!(store.current().unwrap(), None);
        assert_eq!(
            store.reserve(nonce).unwrap(),
            CredentialReservationStatus::Pending
        );
        let root = store.store.root.path.clone();
        let before = fs::read(root.join(RESERVATION_FILE)).unwrap();
        assert!(matches!(
            store.reserve(Hash([4; 32])),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert!(store.complete(b"LCQ1", b"MAA2").is_err());
        assert_eq!(fs::read(root.join(RESERVATION_FILE)).unwrap(), before);
        drop(store);
        let mut store =
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).unwrap();
        assert_eq!(
            store.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        assert_eq!(
            store.reserve(nonce).unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(matches!(
            store.reserve(Hash([4; 32])),
            Err(CleanFileStoreError::RequestConflict)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_create_requires_resume_and_rejects_a_different_retained_target() {
        let fixture = Fixture::new("fresh-create-pending");
        let (operator, _, descriptor, _) = super::super::local_create::tests::fixture();
        let identity =
            super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
        let root = fixture.parent.join("agent-client");
        let _root = ensure_private_directory(&root).unwrap();
        let claims = root.join("credentials");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            descriptor.identity.space,
            identity.credential(),
        )
        .unwrap();
        reservation.reserve(descriptor.creation_nonce).unwrap();
        drop(reservation);
        let node = libp2p::identity::Keypair::ed25519_from_bytes([0x64; 32]).unwrap();
        let public = node.public().try_into_ed25519().unwrap().to_bytes();
        let create = |resume| {
            super::super::local_create::create_local(
                &fixture.parent,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                descriptor.identity.space,
                public,
                resume,
            )
        };
        assert!(create(false).unwrap_err().to_string().contains("--resume"));
        let operations = root.join("operations");
        let _operations = ensure_private_directory(&operations).unwrap();
        let operation = operations.join(format!(
            "{}-{}",
            hex::encode(identity.credential().0),
            hex::encode(descriptor.creation_nonce.0)
        ));
        let _operation = ensure_private_directory(&operation).unwrap();
        let request_root = operation.join("request");
        let bytes = local_request(2);
        CleanLocalCreateRequestFile::open_or_create(&request_root)
            .unwrap()
            .publish(&bytes)
            .unwrap();
        assert!(
            create(true)
                .unwrap_err()
                .to_string()
                .contains("retained Create differs")
        );
        assert_eq!(
            CleanLocalCreateRequestFile::open_or_create(&request_root)
                .unwrap()
                .load()
                .unwrap(),
            Some(bytes)
        );
        assert_eq!(
            CleanCredentialReservation::open_or_create(
                &claims,
                descriptor.identity.space,
                identity.credential()
            )
            .unwrap()
            .current()
            .unwrap(),
            Some((
                descriptor.creation_nonce,
                CredentialReservationStatus::Pending
            ))
        );
    }

    /// Called by the signed acknowledgement fixture; keeps its large setup out
    /// of the persistence test's stack frame.
    #[cfg(target_os = "linux")]
    pub(crate) fn check_reservation_completion(request: &[u8], acknowledgement: &[u8]) {
        use vos::agent::sdk::Hash;
        let fixture = Fixture::new("reservation-completion");
        let (descriptor, call, _) =
            vos::agent::local_lifecycle::LocalCreateSubmission::decode(request)
                .unwrap()
                .into_parts();
        let open = || {
            CleanCredentialReservation::open_or_create(
                &fixture.parent,
                descriptor.identity.space,
                call.credential,
            )
            .unwrap()
        };
        let mut store = open();
        assert!(store.complete(request, acknowledgement).is_err());
        store.reserve(descriptor.creation_nonce).unwrap();
        let mut forged = acknowledgement.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(store.complete(request, &forged).is_err());
        store.complete(request, acknowledgement).unwrap();
        store.complete(request, acknowledgement).unwrap();
        drop(store);
        let mut store = open();
        assert_eq!(
            store.reserve(descriptor.creation_nonce).unwrap(),
            CredentialReservationStatus::Completed
        );
        let next = Hash([91; 32]);
        assert_eq!(
            store.reserve(next).unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(matches!(
            store.complete(request, acknowledgement),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            store.reserve(next).unwrap(),
            CredentialReservationStatus::Pending
        );
    }

    #[cfg(target_os = "linux")]
    #[inline(never)]
    pub(crate) fn check_acknowledgement_storage(request: &[u8], acknowledgement: &[u8]) {
        let fixture = Fixture::new("local-create-acknowledgement");
        let open =
            || CleanLocalCreateAcknowledgementFile::open_or_create(&fixture.root, request).unwrap();
        let mut store = open();
        assert_eq!(store.load().unwrap(), None);
        let mut forged = acknowledgement.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(store.publish(&forged).is_err());
        assert!(!fixture.root.join(LOCAL_ACK_FILE).exists());
        store.publish(acknowledgement).unwrap();
        let original = fs::read(fixture.root.join(LOCAL_ACK_FILE)).unwrap();
        store.publish(acknowledgement).unwrap();
        assert!(store.publish(&forged).is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_ACK_FILE)).unwrap(),
            original
        );
        drop(store);
        let mut store = open();
        assert_eq!(store.load().unwrap().as_deref(), Some(acknowledgement));
        drop(store);
        let different = local_request(u64::MAX);
        assert_ne!(different, request);
        let mut wrong_scope =
            CleanLocalCreateAcknowledgementFile::open_or_create(&fixture.root, &different).unwrap();
        assert!(wrong_scope.load().is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_ACK_FILE)).unwrap(),
            original
        );
        drop(wrong_scope);

        let staged_fixture = Fixture::new("local-create-acknowledgement-stage");
        let mut staged =
            CleanLocalCreateAcknowledgementFile::open_or_create(&staged_fixture.root, request)
                .unwrap();
        stage(&staged.store, None, acknowledgement);
        drop(staged);
        staged = CleanLocalCreateAcknowledgementFile::open_or_create(&staged_fixture.root, request)
            .unwrap();
        assert_eq!(staged.load().unwrap().as_deref(), Some(acknowledgement));
        assert!(!staged_fixture.root.join(LOCAL_ACK_STAGE_FILE).exists());
        let before = fs::read(staged_fixture.root.join(LOCAL_ACK_FILE)).unwrap();
        stage(&staged.store, Some([0x31; 32]), acknowledgement);
        assert!(matches!(
            staged.load(),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            fs::read(staged_fixture.root.join(LOCAL_ACK_FILE)).unwrap(),
            before
        );
        assert!(staged_fixture.root.join(LOCAL_ACK_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    fn credential_queries() -> (
        vos::agent::sdk::authority::AuthorityActorTarget,
        vos::agent::sdk::CredentialId,
        Vec<u8>,
        Vec<u8>,
    ) {
        use vos::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;
        use vos::agent::sdk::{authority::AuthorityProjectionSelector, wire::CanonicalWire as _};
        let (operator, authority, _, _) = super::super::local_create::tests::fixture();
        let mut signer = super::super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator::new(operator).unwrap();
        let first = signer
            .authenticate(authority, AuthorityProjectionSelector::Credential)
            .unwrap();
        let second = signer
            .authenticate(authority, AuthorityProjectionSelector::Credential)
            .unwrap();
        (
            authority,
            first.credential,
            first.encode().unwrap(),
            second.encode().unwrap(),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_query_retains_exact_nonce_and_scope_under_one_lease() {
        use vos::agent::sdk::{
            authority::{AuthorityIngressAuthentication, AuthorityProjectionQuery},
            wire::CanonicalWire as _,
        };
        let fixture = Fixture::new("credential-query");
        let (authority, credential, first, second) = credential_queries();
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert!(matches!(
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential),
            Err(CleanFileStoreError::Busy)
        ));
        let mut forged = AuthorityProjectionQuery::decode(&first).unwrap();
        let AuthorityIngressAuthentication::ApiCredentialSignature { signature, .. } =
            &mut forged.authentication
        else {
            unreachable!()
        };
        signature[0] ^= 1;
        assert!(store.publish(&forged.encode().unwrap()).is_err());
        assert!(store.load().unwrap().is_none());
        store.publish(&first).unwrap();
        store.publish(&first).unwrap();
        assert!(matches!(
            store.publish(&second),
            Err(CleanFileStoreError::RequestConflict)
        ));
        drop(store);
        let mut wrong = CleanCredentialQueryFile::open_or_create(
            &fixture.root,
            authority,
            vos::agent::sdk::CredentialId([99; 32]),
        )
        .unwrap();
        assert!(wrong.load().is_err());
        drop(wrong);
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_query_recovers_initial_stage_without_accepting_replacement() {
        let fixture = Fixture::new("credential-query-stage");
        let (authority, credential, first, second) = credential_queries();
        let store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        let initial = stage(&store.store, None, &first);
        drop(store);
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
        let canonical = fs::read(fixture.root.join(CREDENTIAL_QUERY_FILE)).unwrap();
        stage(&store.store, Some(initial.commitment()), &second);
        drop(store);
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert!(matches!(
            store.load(),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            fs::read(fixture.root.join(CREDENTIAL_QUERY_FILE)).unwrap(),
            canonical
        );
        assert!(fixture.root.join(CREDENTIAL_QUERY_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_discovery_reuses_published_query_across_http_retries() {
        use vos::agent::sdk::authority::*;
        use vos::agent::sdk::{Hash, wire::CanonicalWire as _};
        let fixture = Fixture::new("credential-discovery-http");
        let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
        let principal = descriptor.identity.owner;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let root = fixture.root.clone();
        let server = std::thread::spawn(move || {
            let mut original = None;
            for _ in 0..2 {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "discovery never connected"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                assert!(header.starts_with("POST /__agents/credential HTTP/1.1\r\n"));
                let len: usize = header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .unwrap()
                    .1
                    .trim()
                    .parse()
                    .unwrap();
                assert!(len <= StoreRole::CredentialQuery.maximum_bytes());
                let mut bytes = vec![0; len];
                stream.read_exact(&mut bytes).unwrap();
                if let Some(original) = &original {
                    assert_eq!(original, &bytes);
                } else {
                    original = Some(bytes.clone());
                }
                let query = AuthorityProjectionQuery::decode(&bytes).unwrap();
                assert!(root.join(CREDENTIAL_QUERY_FILE).exists());
                assert!(matches!(
                    CleanCredentialQueryFile::open_or_create(&root, authority, query.credential),
                    Err(CleanFileStoreError::Busy)
                ));
                let one = std::num::NonZeroU64::new(1).unwrap();
                let reply = AuthorityCredentialProjection {
                    query,
                    head: AuthorityProjectionHead {
                        state_revision: one,
                        epoch: one,
                        authorization_sequence: one,
                        administration_generation: one,
                        state_commitment: Hash([42; 32]),
                    },
                    principal,
                    status: AuthorityCredentialStatus::Active,
                    kind: AuthorityCredentialKind::Api,
                    builtin_role: AuthorityBuiltinRole::Admin,
                    management_request_high_water: 1,
                    operation_request_high_water: 0,
                    admin_request_high_water: 0,
                    space_roles: vec![],
                    actor_roles: vec![],
                    capabilities: vec![],
                }
                .encode()
                .unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
                stream.write_all(&reply).unwrap();
            }
            original.unwrap()
        });
        for _ in 0..2 {
            let (_, sequence) = super::super::local_create::discover_credential(
                &fixture.root,
                address,
                &operator,
                authority,
            )
            .unwrap();
            assert_eq!(sequence.get(), 2);
        }
        let bytes = server.join().unwrap();
        let query = AuthorityProjectionQuery::decode(&bytes).unwrap();
        assert_eq!(
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, query.credential)
                .unwrap()
                .load()
                .unwrap(),
            Some(bytes)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_request_is_immutable_durable_and_exclusively_leased() {
        let fixture = Fixture::new("local-request");
        let first = local_request(2);
        let second = local_request(3);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert!(store.load().unwrap().is_none());
        assert!(matches!(
            CleanLocalCreateRequestFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.publish(b"LCQ1").is_err());
        assert!(store.load().unwrap().is_none());
        store.publish(&first).unwrap();
        let envelope = fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap();
        store.publish(&first).unwrap();
        assert!(matches!(
            store.publish(&second),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap(),
            envelope
        );
        drop(store);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
        assert!(!fixture.root.join(LOCAL_REQUEST_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_request_recovers_first_publication_but_refuses_staged_replacement() {
        let fixture = Fixture::new("local-request-stage");
        let first = local_request(2);
        let second = local_request(3);
        let store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        let original = stage(&store.0, None, &first);
        drop(store);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
        let envelope = fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap();
        stage(&store.0, Some(original.commitment()), &second);
        drop(store);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert!(matches!(
            store.load(),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert!(store.publish(&second).is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap(),
            envelope
        );
        assert!(fixture.root.join(LOCAL_REQUEST_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_request_preserves_incomplete_or_wrong_role_evidence() {
        let fixture = Fixture::new("local-request-incomplete");
        let first = local_request(2);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        write_private(&fixture.root.join(LOCAL_REQUEST_STAGE_FILE), b"CSF1");
        assert!(store.load().is_err());
        assert!(store.publish(&first).is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_REQUEST_STAGE_FILE)).unwrap(),
            b"CSF1"
        );
        assert!(!fixture.root.join(LOCAL_REQUEST_FILE).exists());

        let other = Fixture::new("local-request-wrong-role");
        let mut store = CleanLocalCreateRequestFile::open_or_create(&other.root).unwrap();
        let wrong = encode_envelope(StoreRole::ManagementIntent, None, &first).unwrap();
        write_private(&other.root.join(LOCAL_REQUEST_FILE), &wrong);
        assert!(matches!(
            store.load(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        assert!(store.publish(&first).is_err());
        assert_eq!(
            fs::read(other.root.join(LOCAL_REQUEST_FILE)).unwrap(),
            wrong
        );
    }

    #[test]
    fn lifecycle_discovery_is_sorted_bounded_and_does_not_open_images() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-discovery");
        let space = SpaceId([1; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(factory.discover(space, 0).unwrap().is_empty());
        assert!(matches!(
            factory.discover(SpaceId([9; 32]), 4),
            Err(CleanFileStoreError::InvalidPath)
        ));
        let high = AgentId([3; 32]);
        let low = AgentId([2; 32]);
        // Leases remain held: discovery must not open, reconcile, or write
        // either image, even though a later recovery open must acquire them.
        let (mut high_intent, _high_issuer) = factory.open(space, high).unwrap();
        high_intent.commit(b"unverified candidate bytes").unwrap();
        let (_low_intent, _low_issuer) = factory.open(space, low).unwrap();
        let path = fixture.root.join(hex::encode(high.0)).join(INTENT_FILE);
        let before = fs::read(&path).unwrap();
        assert_eq!(factory.discover(space, 2).unwrap(), vec![low, high]);
        assert_eq!(factory.discover(space, 2).unwrap(), vec![low, high]);
        assert!(matches!(
            factory.discover(space, 1),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            factory.discover(space, 0),
            Err(CleanFileStoreError::Oversized)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn lifecycle_discovery_rejects_residue_and_non_directories() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::SpaceId;
        for name in ["unrecognized".to_owned(), "AB".repeat(32), "00".repeat(32)] {
            let fixture = Fixture::new("lifecycle-discovery-residue");
            let space = SpaceId([1; 32]);
            let mut factory =
                CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
            fs::create_dir(fixture.root.join(name)).unwrap();
            assert!(matches!(
                factory.discover(space, 4),
                Err(CleanFileStoreError::UnexpectedResidue)
            ));
        }
        let fixture = Fixture::new("lifecycle-discovery-file");
        let space = SpaceId([1; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        fs::write(fixture.root.join("ab".repeat(32)), b"not a directory").unwrap();
        assert!(factory.discover(space, 4).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_discovery_rejects_symlinks_and_parent_replacement() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::SpaceId;
        let fixture = Fixture::new("lifecycle-discovery-symlink");
        let space = SpaceId([1; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        let alias = fixture.root.join("ab".repeat(32));
        std::os::unix::fs::symlink(&fixture.parent, &alias).unwrap();
        assert!(factory.discover(space, 4).is_err());
        fs::rename(&fixture.root, fixture.parent.join("retained-parent")).unwrap();
        let _replacement =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(matches!(
            factory.discover(space, 4),
            Err(CleanFileStoreError::Alias)
        ));
        assert!(
            fs::symlink_metadata(fixture.parent.join("retained-parent").join("ab".repeat(32)))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn lifecycle_recovery_open_never_recreates_a_missing_candidate() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-existing-only");
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(factory.open_existing(space, agent).is_err());
        assert!(fs::read_dir(&fixture.root).unwrap().next().is_none());
        let (mut intent, issuer) = factory.open(space, agent).unwrap();
        intent.commit(b"retained intent").unwrap();
        assert!(matches!(
            factory.open_existing(space, agent),
            Err(CleanFileStoreError::Busy)
        ));
        drop((intent, issuer));
        let (mut intent, issuer) = factory.open_existing(space, agent).unwrap();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(b"retained intent".as_slice())
        );
        drop((intent, issuer));
        assert_eq!(factory.discover(space, 1).unwrap(), vec![agent]);
        let path = fixture.root.join(hex::encode(agent.0));
        let retained = fixture.parent.join("retained-candidate");
        fs::rename(&path, &retained).unwrap();
        assert!(factory.open_existing(space, agent).is_err());
        assert!(!path.exists());
        assert!(retained.join(INTENT_FILE).is_file());
    }

    #[test]
    fn lifecycle_factory_creates_and_reopens_its_private_parent() {
        let fixture = Fixture::new("lifecycle-parent");
        let space = vos::agent::sdk::SpaceId([1; 32]);
        let factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&fixture.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(factory);
        let factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        validate_opened_directory(&factory.directory, &fixture.root, false).unwrap();
    }

    #[test]
    fn lifecycle_factory_derives_agent_paths_and_rejects_wrong_space() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-factory");
        let mut factory =
            CleanManagementLifecycleStoreFactory::new(&fixture.parent, SpaceId([1; 32])).unwrap();
        let agent = AgentId([2; 32]);
        assert!(matches!(
            factory.open(SpaceId([3; 32]), agent),
            Err(CleanFileStoreError::InvalidPath)
        ));
        assert!(fs::read_dir(&fixture.parent).unwrap().next().is_none());
        let (mut intent, mut issuer) = factory.open(SpaceId([1; 32]), agent).unwrap();
        intent.commit(b"intent").unwrap();
        issuer.commit(b"issuer").unwrap();
        assert!(
            fixture
                .parent
                .join(hex::encode(agent.0))
                .join(INTENT_FILE)
                .is_file()
        );
        assert!(matches!(
            factory.open(SpaceId([1; 32]), agent),
            Err(CleanFileStoreError::Busy)
        ));
        drop((intent, issuer));
        let (mut intent, mut issuer) = factory.open(SpaceId([1; 32]), agent).unwrap();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(b"intent".as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(b"issuer".as_slice())
        );
    }

    #[test]
    fn lifecycle_files_reopen_independently_and_share_the_writer_lease() {
        let fixture = Fixture::new("lifecycle-reopen");
        let stores = CleanManagementLifecycleFiles::open_or_create(&fixture.root).unwrap();
        let (mut intent, mut issuer) = stores.into_parts();
        assert_eq!(intent.load().unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);
        intent.commit(b"pending-intent").unwrap();
        issuer.commit(b"issued-receipt").unwrap();
        let predecessor = intent
            .0
            .reconcile(MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES)
            .unwrap()
            .unwrap();
        stage(
            &intent.0,
            Some(predecessor.commitment()),
            b"prepared-finalization",
        );
        drop(intent);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(b"prepared-finalization".as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(b"issued-receipt".as_slice())
        );
        assert!(!fixture.root.join(INTENT_STAGE_FILE).exists());
        assert!(matches!(
            intent.commit(&vec![0; MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            issuer.commit(&vec![0; MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
    }

    #[test]
    fn lifecycle_files_reload_staged_images_without_releasing_writer_lease() {
        fn reload<B: CleanManagementIssuerStore>(mut store: B) -> Option<Vec<u8>> {
            store.load().ok().flatten()
        }
        let fixture = Fixture::new("lifecycle-retained-lease");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        intent.commit(b"intent-before").unwrap();
        issuer.commit(b"issuer-before").unwrap();
        for (store, payload) in [
            (&intent.0, b"intent-after".as_slice()),
            (&issuer.0, b"issuer-after".as_slice()),
        ] {
            let predecessor = store
                .reconcile(store.role.maximum_bytes())
                .unwrap()
                .unwrap();
            stage(store, Some(predecessor.commitment()), payload);
        }
        assert_eq!(
            reload(&mut intent).as_deref(),
            Some(b"intent-after".as_slice())
        );
        assert_eq!(
            reload(&mut issuer).as_deref(),
            Some(b"issuer-after".as_slice())
        );
        assert!(!fixture.root.join(INTENT_STAGE_FILE).exists());
        assert!(!fixture.root.join(LIFECYCLE_ISSUER_STAGE_FILE).exists());
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(intent);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        assert!(CleanManagementLifecycleFiles::open_or_create(&fixture.root).is_ok());
    }

    #[test]
    fn lifecycle_runtime_recovers_staged_publication_and_is_immutable_under_lease() {
        let fixture = Fixture::new("lifecycle-runtime");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        intent.commit(b"intent").unwrap();
        issuer.commit(b"issuer").unwrap();
        assert_eq!(intent.load_runtime().unwrap(), None);
        stage(&intent.1, None, b"exact-runtime");
        assert_eq!(
            CleanManagementRuntimeStore::load_runtime(&mut &mut intent).unwrap(),
            Some(b"exact-runtime".to_vec())
        );
        assert!(!fixture.root.join(LIFECYCLE_RUNTIME_STAGE_FILE).exists());
        intent.commit_runtime(b"exact-runtime").unwrap();
        assert!(matches!(
            intent.commit_runtime(b"different-runtime"),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(intent.load().unwrap(), Some(b"intent".to_vec()));
        assert_eq!(issuer.load().unwrap(), Some(b"issuer".to_vec()));
        assert!(matches!(
            CleanManagementLifecycleFiles::open_existing(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_existing(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(intent);
        let (mut intent, _) = CleanManagementLifecycleFiles::open_existing(&fixture.root)
            .unwrap()
            .into_parts();
        assert_eq!(
            intent.load_runtime().unwrap(),
            Some(b"exact-runtime".to_vec())
        );
        assert_eq!(intent.1.role.maximum_bytes(), MAX_PACKAGE_ENCODED_BYTES);
    }

    #[test]
    fn lifecycle_runtime_rejects_an_issuer_envelope() {
        let fixture = Fixture::new("lifecycle-runtime-role");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        issuer.commit(b"issuer").unwrap();
        let bytes = fs::read(fixture.root.join(LIFECYCLE_ISSUER_FILE)).unwrap();
        write_private(&fixture.root.join(LIFECYCLE_RUNTIME_FILE), &bytes);
        assert!(matches!(
            intent.load_runtime(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        assert_eq!(issuer.load().unwrap(), Some(b"issuer".to_vec()));
    }

    #[test]
    fn lifecycle_files_reject_bootstrap_names_and_cross_role_envelopes() {
        let fixture = Fixture::new("lifecycle-role");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        issuer.commit(b"issuer").unwrap();
        let bytes = fs::read(fixture.root.join(LIFECYCLE_ISSUER_FILE)).unwrap();
        write_private(&fixture.root.join(INTENT_FILE), &bytes);
        assert!(matches!(
            intent.load(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        drop(intent);
        drop(issuer);
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));

        let fixture = Fixture::new("lifecycle-bootstrap-refusal");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"pins").unwrap();
        drop((pins, bootstrap, issuer));
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
    }

    #[test]
    fn exact_reads_distinguish_truncation_from_io_failure() {
        let mut truncated = &b"short"[..];
        let mut target = [0_u8; 6];
        assert!(matches!(
            read_exact_or_corrupt(&mut truncated, &mut target),
            Err(CleanFileStoreError::Corrupt)
        ));

        struct FailedReader;

        impl Read for FailedReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected read failure",
                ))
            }
        }

        let error = read_exact_or_corrupt(&mut FailedReader, &mut target)
            .expect_err("non-truncation read failures remain I/O errors");
        assert!(matches!(
            error,
            CleanFileStoreError::Io(error)
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn missing_parent_canonicalization_preserves_io_failure() {
        let fixture = Fixture::new("missing-parent");
        let root = fixture.parent.join("absent").join("state");
        match CleanSystemAgentFileStores::open_or_create(root) {
            Err(CleanFileStoreError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            Err(error) => panic!("missing parent was misclassified: {error}"),
            Ok(_) => panic!("missing parent unexpectedly opened"),
        }
    }

    fn flip_first_predecessor_byte(path: &Path) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open envelope for predecessor tamper");
        file.seek(SeekFrom::Start(16)).expect("seek to predecessor");
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("read predecessor byte");
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(16))
            .expect("rewind to predecessor");
        file.write_all(&byte).expect("tamper predecessor byte");
        file.sync_all().expect("sync predecessor tamper");
    }

    #[test]
    fn missing_files_create_and_reopen_with_exact_bytes() {
        let fixture = Fixture::new("roundtrip");
        let stores = fixture.stores();
        let (mut pins, mut bootstrap, mut issuer) = stores.into_parts();
        assert_eq!(pins.load(1024).unwrap(), None);
        assert_eq!(bootstrap.load(1024).unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);

        let pins_bytes = b"pins\0exact";
        let bootstrap_bytes = b"bootstrap\xffexact";
        let issuer_bytes = b"issuer\0\xffexact";
        pins.commit(pins_bytes).unwrap();
        bootstrap.commit(bootstrap_bytes).unwrap();
        issuer.commit(issuer_bytes).unwrap();
        assert_ne!(fs::read(fixture.root.join(PINS_FILE)).unwrap(), pins_bytes);
        drop((pins, bootstrap, issuer));

        let (mut pins, mut bootstrap, mut issuer) = fixture.stores().into_parts();
        assert_eq!(
            pins.load(1024).unwrap().as_deref(),
            Some(pins_bytes.as_slice())
        );
        assert_eq!(
            bootstrap.load(1024).unwrap().as_deref(),
            Some(bootstrap_bytes.as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(issuer_bytes.as_slice())
        );
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        assert!(!fixture.root.join(BOOTSTRAP_STAGE_FILE).exists());
        assert!(!fixture.root.join(ISSUER_STAGE_FILE).exists());
    }

    #[test]
    fn genesis_archive_shares_the_lease_and_has_an_independent_role() {
        let fixture = Fixture::new("genesis-archive");
        let (pins, bootstrap, issuer, mut genesis) = fixture.stores().into_production_parts();
        assert_eq!(genesis.load().unwrap(), None);
        genesis.commit(b"exact-root-provision-and-catalog").unwrap();
        assert_ne!(
            fs::read(fixture.root.join(GENESIS_FILE)).unwrap(),
            b"exact-root-provision-and-catalog",
        );
        drop((pins, bootstrap, issuer, genesis));

        let (pins, bootstrap, issuer, mut genesis) = fixture.stores().into_production_parts();
        assert_eq!(
            genesis.load().unwrap().as_deref(),
            Some(b"exact-root-provision-and-catalog".as_slice()),
        );
        assert!(!fixture.root.join(GENESIS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer, genesis));
    }

    #[test]
    fn exact_retry_preserves_the_exact_payload() {
        let fixture = Fixture::new("exact-retry");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"same-image").unwrap();
        let physical = fs::read(fixture.root.join(PINS_FILE)).unwrap();
        pins.commit(b"same-image").unwrap();
        assert_eq!(fs::read(fixture.root.join(PINS_FILE)).unwrap(), physical);
        assert_eq!(
            pins.load(64).unwrap().as_deref(),
            Some(b"same-image".as_slice())
        );
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn valid_initial_stage_is_the_only_safe_missing_target_recovery() {
        let fixture = Fixture::new("initial-stage");
        let (pins, bootstrap, issuer) = fixture.stores().into_parts();
        stage(&pins.0, None, b"initial");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert_eq!(
            pins.load(64).unwrap().as_deref(),
            Some(b"initial".as_slice())
        );
        assert!(fixture.root.join(PINS_FILE).is_file());
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn predecessor_bound_stage_completes_replacement_on_reopen() {
        let fixture = Fixture::new("replacement-stage");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"old").unwrap();
        let current = pins
            .0
            .reconcile(StoreRole::Pins.maximum_bytes())
            .unwrap()
            .unwrap();
        stage(&pins.0, Some(current.commitment()), b"new");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert_eq!(pins.load(64).unwrap().as_deref(), Some(b"new".as_slice()));
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn canonical_predecessor_tamper_is_detected() {
        let fixture = Fixture::new("canonical-predecessor-tamper");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"predecessor").unwrap();
        pins.commit(b"successor").unwrap();
        drop((pins, bootstrap, issuer));

        flip_first_predecessor_byte(&fixture.root.join(PINS_FILE));
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        assert!(fixture.root.join(PINS_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn staged_predecessor_tamper_is_detected() {
        let fixture = Fixture::new("staged-predecessor-tamper");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"predecessor").unwrap();
        let current = pins
            .0
            .reconcile(StoreRole::Pins.maximum_bytes())
            .unwrap()
            .unwrap();
        stage(&pins.0, Some(current.commitment()), b"successor");
        flip_first_predecessor_byte(&fixture.root.join(PINS_STAGE_FILE));
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        assert!(fixture.root.join(PINS_FILE).is_file());
        assert!(fixture.root.join(PINS_STAGE_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn exact_duplicate_stage_is_retired_without_republication() {
        let fixture = Fixture::new("duplicate-stage");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"published").unwrap();
        fs::copy(
            fixture.root.join(PINS_FILE),
            fixture.root.join(PINS_STAGE_FILE),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            fixture.root.join(PINS_STAGE_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert_eq!(
            pins.load(64).unwrap().as_deref(),
            Some(b"published".as_slice())
        );
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn unrelated_stage_and_target_fail_closed_without_cleanup() {
        let fixture = Fixture::new("ambiguous-stage");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"published").unwrap();
        stage(&pins.0, Some([0x55; 32]), b"unrelated");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::AmbiguousPublication)
        ));
        assert!(fixture.root.join(PINS_FILE).is_file());
        assert!(fixture.root.join(PINS_STAGE_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn predecessor_without_a_target_is_ambiguous() {
        let fixture = Fixture::new("missing-predecessor");
        let (pins, bootstrap, issuer) = fixture.stores().into_parts();
        stage(&pins.0, Some([0x33; 32]), b"orphan-successor");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::AmbiguousPublication)
        ));
        assert!(!fixture.root.join(PINS_FILE).exists());
        assert!(fixture.root.join(PINS_STAGE_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn corrupt_stage_fails_closed_and_is_not_removed() {
        let fixture = Fixture::new("corrupt-stage");
        let stores = fixture.stores();
        drop(stores);
        write_private(&fixture.root.join(PINS_STAGE_FILE), b"partial");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        assert_eq!(
            fs::read(fixture.root.join(PINS_STAGE_FILE)).unwrap(),
            b"partial"
        );
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn create_new_stage_never_overwrites_a_collision() {
        let fixture = Fixture::new("stage-collision");
        let (pins, bootstrap, issuer) = fixture.stores().into_parts();
        write_private(&fixture.root.join(PINS_STAGE_FILE), b"occupied");
        let encoded = encode_envelope(StoreRole::Pins, None, b"candidate").unwrap();
        assert!(matches!(
            pins.0.write_stage(&encoded),
            Err(CleanFileStoreError::StageCollision)
        ));
        assert_eq!(
            fs::read(fixture.root.join(PINS_STAGE_FILE)).unwrap(),
            b"occupied"
        );
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn one_lease_serializes_all_three_files() {
        let fixture = Fixture::new("lease");
        let stores = fixture.stores();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(stores);
        assert!(CleanSystemAgentFileStores::open_or_create(&fixture.root).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_or_unlinked_named_lock_invalidates_the_held_lease() {
        let replacement_fixture = Fixture::new("lock-replacement");
        let (mut pins, mut bootstrap, issuer) = replacement_fixture.stores().into_parts();
        let lock_path = replacement_fixture.root.join(LOCK_FILE);
        fs::remove_file(&lock_path).unwrap();
        write_private(&lock_path, b"");
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Alias)));
        assert!(matches!(
            bootstrap.load(64),
            Err(CleanFileStoreError::Alias)
        ));
        drop((pins, bootstrap, issuer));

        let unlink_fixture = Fixture::new("lock-unlink");
        let (mut pins, bootstrap, issuer) = unlink_fixture.stores().into_parts();
        fs::remove_file(unlink_fixture.root.join(LOCK_FILE)).unwrap();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::Io(error))
                if error.kind() == io::ErrorKind::NotFound
        ));
        drop((pins, bootstrap, issuer));
    }

    #[cfg(unix)]
    #[test]
    fn parent_mode_and_root_inode_are_revalidated_for_existing_handles() {
        let parent_fixture = Fixture::new("live-parent-mode");
        let (mut pins, bootstrap, issuer) = parent_fixture.stores().into_parts();
        fs::set_permissions(&parent_fixture.parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::InsecureParent)
        ));
        drop((pins, bootstrap, issuer));

        let root_fixture = Fixture::new("live-root-replacement");
        let (mut pins, bootstrap, issuer) = root_fixture.stores().into_parts();
        let displaced = root_fixture.parent.join("displaced-state");
        fs::rename(&root_fixture.root, &displaced).unwrap();
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&root_fixture.root).unwrap();
        fs::set_permissions(&root_fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Alias)));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn relative_dotdot_and_symlink_roots_are_rejected() {
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(Path::new("relative-clean-store")),
            Err(CleanFileStoreError::InvalidPath)
        ));

        let fixture = Fixture::new("root-alias");
        let stores = fixture.stores();
        drop(stores);
        let dotdot = fixture.root.join("..").join("state");
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(dotdot),
            Err(CleanFileStoreError::InvalidPath)
        ));

        #[cfg(unix)]
        {
            let alias = fixture.parent.join("alias");
            std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
            assert!(matches!(
                CleanSystemAgentFileStores::open_or_create(alias),
                Err(CleanFileStoreError::Alias)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn parent_and_root_must_be_exact_private_directories() {
        let fixture = Fixture::new("directory-modes");
        fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::InsecureParent)
        ));
        fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o700)).unwrap();
        let stores = fixture.stores();
        drop(stores);
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::InsecureRoot)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_nonregular_entries_are_rejected() {
        let symlink_fixture = Fixture::new("symlink-entry");
        drop(symlink_fixture.stores());
        let outside = symlink_fixture.parent.join("outside");
        write_private(&outside, b"outside");
        std::os::unix::fs::symlink(&outside, symlink_fixture.root.join(PINS_FILE)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&symlink_fixture.root),
            Err(CleanFileStoreError::Alias)
        ));

        let hardlink_fixture = Fixture::new("hardlink-entry");
        drop(hardlink_fixture.stores());
        let outside = hardlink_fixture.parent.join("outside");
        write_private(&outside, b"outside");
        fs::hard_link(&outside, hardlink_fixture.root.join(PINS_FILE)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&hardlink_fixture.root),
            Err(CleanFileStoreError::HardLink)
        ));

        let directory_fixture = Fixture::new("directory-entry");
        drop(directory_fixture.stores());
        fs::create_dir(directory_fixture.root.join(PINS_FILE)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&directory_fixture.root),
            Err(CleanFileStoreError::NonRegular)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn image_and_lock_permissions_are_revalidated_on_reopen() {
        let image_fixture = Fixture::new("image-mode");
        let (mut pins, bootstrap, issuer) = image_fixture.stores().into_parts();
        pins.commit(b"pins").unwrap();
        drop((pins, bootstrap, issuer));
        fs::set_permissions(
            image_fixture.root.join(PINS_FILE),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&image_fixture.root),
            Err(CleanFileStoreError::InsecurePermissions)
        ));
        assert_eq!(
            fs::symlink_metadata(image_fixture.root.join(PINS_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o640
        );

        let lock_fixture = Fixture::new("lock-mode");
        drop(lock_fixture.stores());
        fs::set_permissions(
            lock_fixture.root.join(LOCK_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&lock_fixture.root),
            Err(CleanFileStoreError::InsecurePermissions)
        ));
        assert_eq!(
            fs::symlink_metadata(lock_fixture.root.join(LOCK_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn truncated_and_digest_corrupt_images_fail_closed() {
        let truncated_fixture = Fixture::new("truncated");
        let (mut pins, bootstrap, issuer) = truncated_fixture.stores().into_parts();
        pins.commit(b"complete").unwrap();
        drop((pins, bootstrap, issuer));
        OpenOptions::new()
            .write(true)
            .open(truncated_fixture.root.join(PINS_FILE))
            .unwrap()
            .set_len((STORE_HEADER_BYTES - 1) as u64)
            .unwrap();
        let (mut pins, bootstrap, issuer) = truncated_fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        drop((pins, bootstrap, issuer));

        let corrupt_fixture = Fixture::new("digest-corrupt");
        let (mut pins, bootstrap, issuer) = corrupt_fixture.stores().into_parts();
        pins.commit(b"complete").unwrap();
        drop((pins, bootstrap, issuer));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(corrupt_fixture.root.join(PINS_FILE))
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[0x7f]).unwrap();
        file.sync_all().unwrap();
        let (mut pins, bootstrap, issuer) = corrupt_fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn oversized_state_is_rejected_before_body_allocation() {
        let fixture = Fixture::new("oversized");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"small").unwrap();
        drop((pins, bootstrap, issuer));
        OpenOptions::new()
            .write(true)
            .open(fixture.root.join(PINS_FILE))
            .unwrap()
            .set_len((STORE_HEADER_BYTES + MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES + 1) as u64)
            .unwrap();
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES),
            Err(CleanFileStoreError::Oversized)
        ));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn caller_bound_and_store_bound_are_both_enforced() {
        let fixture = Fixture::new("bounds");
        let (mut pins, bootstrap, mut issuer) = fixture.stores().into_parts();
        pins.commit(b"four").unwrap();
        assert!(matches!(pins.load(3), Err(CleanFileStoreError::Oversized)));
        assert!(matches!(
            issuer.commit(&vec![0_u8; MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn role_bound_envelopes_reject_cross_store_file_swaps() {
        let fixture = Fixture::new("role-swap");
        let (mut pins, mut bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"pins").unwrap();
        bootstrap.commit(b"bootstrap").unwrap();
        drop((pins, bootstrap, issuer));
        let temporary = fixture.parent.join("swap");
        fs::rename(fixture.root.join(PINS_FILE), &temporary).unwrap();
        fs::rename(
            fixture.root.join(BOOTSTRAP_FILE),
            fixture.root.join(PINS_FILE),
        )
        .unwrap();
        fs::rename(temporary, fixture.root.join(BOOTSTRAP_FILE)).unwrap();

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn unknown_files_are_never_treated_as_store_residue() {
        let fixture = Fixture::new("unknown-residue");
        drop(fixture.stores());
        write_private(&fixture.root.join("old-generation"), b"legacy");
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));

        let fresh_fixture = Fixture::new("fresh-unknown-residue");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&fresh_fixture.root).unwrap();
        fs::set_permissions(&fresh_fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&fresh_fixture.root.join("foreign"), b"foreign");
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fresh_fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        assert!(!fresh_fixture.root.join(LOCK_FILE).exists());
    }
}
