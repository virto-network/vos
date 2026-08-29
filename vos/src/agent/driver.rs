//! Host driver for one durable agent-runtime instance.
//!
//! The node persists a small descriptor and an opaque runtime state. It never
//! decodes actor directories or runtime-internal scheduling data. A custom
//! runtime is therefore free to change those internals while preserving the
//! stable lifecycle ABI.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::string::String;

use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, Gas};

use super::authority::{AuthorityError, VerifiedAgentAuthorityReceipt, authorize_lifecycle};
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::package::{PackageError, VerifiedPackage};
use super::wire::{RuntimeCall, RuntimeReturn, RuntimeState};
use super::{
    ActorEntry, ActorInitialState, AgentConfig, AgentConfigError, InstallActor, LifecycleError,
    LifecycleReply, LifecycleRequest, PackageKind, RUNTIME_ABI_ID, RuntimeCapabilities,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{ActorId, BlobRef, CapabilityId, DeploymentId, Hash, ProducerId, ProgramId};

pub const DEFAULT_MANAGEMENT_GAS: Gas = 1_000_000_000;
pub const MAX_RUNTIME_STATE_BYTES: usize = 16 * 1024 * 1024;

/// One atomically persisted agent revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentImage {
    pub revision: u64,
    pub runtime_program: ProgramId,
    pub config: AgentConfig,
    pub runtime_state: RuntimeState,
}

impl ServiceWire for AgentImage {
    const MAGIC: [u8; 4] = *b"AGIM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&RUNTIME_ABI_ID.0);
        encoder.u64(self.revision);
        encoder.fixed(&self.runtime_program.0);
        encoder.bytes(&self.config.encode());
        encoder.bytes(&self.runtime_state.control);
        encoder.bytes(&self.runtime_state.linear);
        encoder.bytes(&self.runtime_state.merge);
        encoder.bytes(&self.runtime_state.local);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let image = Self {
            revision: decoder.u64()?,
            runtime_program: ProgramId(decoder.fixed()?),
            config: AgentConfig::decode(&decoder.bytes()?)?,
            runtime_state: RuntimeState {
                control: decoder.bytes()?,
                linear: decoder.bytes()?,
                merge: decoder.bytes()?,
                local: decoder.bytes()?,
            },
        };
        if image.revision == 0
            || image.runtime_program == ProgramId::ZERO
            || image.runtime_state.is_empty()
            || runtime_state_size(&image.runtime_state) > MAX_RUNTIME_STATE_BYTES
            || image.config.validate().is_err()
            || image.config.identity.runtime_program != image.runtime_program
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(image)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStoreError {
    Conflict,
    Corrupt,
    Unavailable,
}

impl core::fmt::Display for AgentStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent image store: {self:?}")
    }
}

impl std::error::Error for AgentStoreError {}

/// Compare-and-replace persistence used by Local and replicated drivers.
pub trait AgentImageStore {
    fn load(&self) -> Result<Option<AgentImage>, AgentStoreError>;
    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        image: &AgentImage,
    ) -> Result<(), AgentStoreError>;

    /// Persist a canonical signed package before its lifecycle transition is
    /// made durable. Returns `true` when this call created the artifact.
    fn put_package(&mut self, reference: &BlobRef, bytes: &[u8]) -> Result<bool, AgentStoreError>;
    fn remove_package(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError>;

    /// Persist and resolve executable actor bytes by their exact ProgramId.
    fn put_program(&mut self, program: ProgramId, bytes: &[u8]) -> Result<bool, AgentStoreError>;
    fn load_program(&self, program: ProgramId) -> Result<Option<Vec<u8>>, AgentStoreError>;
    fn remove_program(&mut self, program: ProgramId) -> Result<(), AgentStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryAgentStore {
    image: Option<AgentImage>,
    packages: BTreeMap<Hash, Vec<u8>>,
    programs: BTreeMap<ProgramId, Vec<u8>>,
}

impl MemoryAgentStore {
    pub fn image(&self) -> Option<&AgentImage> {
        self.image.as_ref()
    }
}

impl AgentImageStore for MemoryAgentStore {
    fn load(&self) -> Result<Option<AgentImage>, AgentStoreError> {
        Ok(self.image.clone())
    }

    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        image: &AgentImage,
    ) -> Result<(), AgentStoreError> {
        if self.image.as_ref().map(|image| image.revision) != expected_revision {
            return Err(AgentStoreError::Conflict);
        }
        self.image = Some(image.clone());
        Ok(())
    }

    fn put_package(&mut self, reference: &BlobRef, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if !reference.matches(bytes) {
            return Err(AgentStoreError::Corrupt);
        }
        put_memory_artifact(&mut self.packages, reference.hash, bytes)
    }

    fn remove_package(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError> {
        self.packages.remove(&reference.hash);
        Ok(())
    }

    fn put_program(&mut self, program: ProgramId, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if ProgramId::of_pvm(bytes) != program {
            return Err(AgentStoreError::Corrupt);
        }
        put_memory_artifact(&mut self.programs, program, bytes)
    }

    fn load_program(&self, program: ProgramId) -> Result<Option<Vec<u8>>, AgentStoreError> {
        Ok(self.programs.get(&program).cloned())
    }

    fn remove_program(&mut self, program: ProgramId) -> Result<(), AgentStoreError> {
        self.programs.remove(&program);
        Ok(())
    }
}

fn put_memory_artifact<K: Ord + Copy>(
    artifacts: &mut BTreeMap<K, Vec<u8>>,
    key: K,
    bytes: &[u8],
) -> Result<bool, AgentStoreError> {
    if let Some(existing) = artifacts.get(&key) {
        return if existing == bytes {
            Ok(false)
        } else {
            Err(AgentStoreError::Corrupt)
        };
    }
    artifacts.insert(key, bytes.to_vec());
    Ok(true)
}

/// Crash-durable single-image store for Local agents. Daemon-level agent
/// ownership locks serialize writers; the revision comparison catches stale
/// drivers inside that ownership domain.
#[derive(Clone, Debug)]
pub struct FileAgentStore {
    path: PathBuf,
}

impl FileAgentStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_image(&self) -> Result<Option<AgentImage>, AgentStoreError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AgentStoreError::Unavailable),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| AgentStoreError::Unavailable)?;
        AgentImage::decode(&bytes)
            .map(Some)
            .map_err(|_| AgentStoreError::Corrupt)
    }

    fn sync_parent(&self) -> Result<(), AgentStoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AgentStoreError::Unavailable)
    }

    fn catalog_path(&self, kind: &str, id: &[u8; 32], suffix: &str) -> PathBuf {
        self.path
            .with_extension("agent-catalog")
            .join(kind)
            .join(format!("{}.{suffix}", encode_hex(id)))
    }

    fn put_artifact(&self, path: &Path, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        match std::fs::read(path) {
            Ok(existing) => {
                return if existing == bytes {
                    Ok(false)
                } else {
                    Err(AgentStoreError::Corrupt)
                };
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(AgentStoreError::Unavailable),
        }
        let parent = path.parent().ok_or(AgentStoreError::Unavailable)?;
        std::fs::create_dir_all(parent).map_err(|_| AgentStoreError::Unavailable)?;
        let next = path.with_extension("next");
        match std::fs::read(&next) {
            Ok(staged) if staged == bytes => {
                std::fs::rename(&next, path).map_err(|_| AgentStoreError::Unavailable)?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| AgentStoreError::Unavailable)?;
                return Ok(true);
            }
            Ok(_) => return Err(AgentStoreError::Corrupt),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(AgentStoreError::Unavailable),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&next)
            .map_err(|_| AgentStoreError::Unavailable)?;
        let result = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| std::fs::rename(&next, path))
            .and_then(|()| File::open(parent)?.sync_all());
        if result.is_err() {
            let _ = std::fs::remove_file(&next);
            return Err(AgentStoreError::Unavailable);
        }
        Ok(true)
    }

    fn remove_artifact(&self, path: &Path) -> Result<(), AgentStoreError> {
        match std::fs::remove_file(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|_| AgentStoreError::Unavailable)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AgentStoreError::Unavailable),
        }
    }
}

impl AgentImageStore for FileAgentStore {
    fn load(&self) -> Result<Option<AgentImage>, AgentStoreError> {
        self.read_image()
    }

    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        image: &AgentImage,
    ) -> Result<(), AgentStoreError> {
        if self.read_image()?.as_ref().map(|image| image.revision) != expected_revision {
            return Err(AgentStoreError::Conflict);
        }
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|_| AgentStoreError::Unavailable)?;
        }
        let next = self.path.with_extension("next");
        let bytes = image.encode();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&next)
            .map_err(|_| AgentStoreError::Unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| AgentStoreError::Unavailable)?;
        std::fs::rename(&next, &self.path).map_err(|_| AgentStoreError::Unavailable)?;
        self.sync_parent()
    }

    fn put_package(&mut self, reference: &BlobRef, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if !reference.matches(bytes) {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(
            &self.catalog_path("packages", &reference.hash.0, "vos"),
            bytes,
        )
    }

    fn remove_package(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("packages", &reference.hash.0, "vos"))
    }

    fn put_program(&mut self, program: ProgramId, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if ProgramId::of_pvm(bytes) != program {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(&self.catalog_path("programs", &program.0, "pvm"), bytes)
    }

    fn load_program(&self, program: ProgramId) -> Result<Option<Vec<u8>>, AgentStoreError> {
        let path = self.catalog_path("programs", &program.0, "pvm");
        match std::fs::read(path) {
            Ok(bytes) if ProgramId::of_pvm(&bytes) == program => Ok(Some(bytes)),
            Ok(_) => Err(AgentStoreError::Corrupt),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AgentStoreError::Unavailable),
        }
    }

    fn remove_program(&mut self, program: ProgramId) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("programs", &program.0, "pvm"))
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDriverError {
    InvalidConfig(AgentConfigError),
    RuntimeProgramMismatch,
    InvalidRuntime,
    RuntimeExit { reason: ExitReason, pc: u32 },
    RuntimeOutput,
    RuntimeStateTooLarge,
    ProgramUnavailable(ProgramId),
    Lifecycle(LifecycleError),
    Execution(ActorExecutionError),
    Package(PackageError),
    Authority(AuthorityError),
    Store(AgentStoreError),
}

impl core::fmt::Display for AgentDriverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent driver: {self:?}")
    }
}

impl std::error::Error for AgentDriverError {}

impl From<AgentStoreError> for AgentDriverError {
    fn from(error: AgentStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AuthorityError> for AgentDriverError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

/// One loaded agent. Calls are serialized by mutable access; replication
/// adapters order calls before they reach this driver.
pub struct AgentDriver<S> {
    runtime_pvm: Vec<u8>,
    image: AgentImage,
    store: S,
    management_gas: Gas,
}

impl<S: AgentImageStore> AgentDriver<S> {
    pub fn create_or_open(
        runtime_pvm: Vec<u8>,
        config: AgentConfig,
        mut store: S,
    ) -> Result<Self, AgentDriverError> {
        config.validate().map_err(AgentDriverError::InvalidConfig)?;
        let runtime_program = ProgramId::of_pvm(&runtime_pvm);
        if runtime_program != config.identity.runtime_program {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        if let Some(image) = store.load()? {
            if image.runtime_program != runtime_program || image.config != config {
                return Err(AgentDriverError::RuntimeProgramMismatch);
            }
            let driver = Self {
                runtime_pvm,
                image,
                store,
                management_gas: DEFAULT_MANAGEMENT_GAS,
            };
            driver.validate_loaded_state()?;
            return Ok(driver);
        }

        let output = execute_runtime(
            &runtime_pvm,
            DEFAULT_MANAGEMENT_GAS,
            RuntimeCall {
                state: RuntimeState::default(),
                request: LifecycleRequest::Create(config.clone()),
            },
        )?;
        if output.result != Ok(LifecycleReply::Created(config.identity.clone())) {
            return Err(AgentDriverError::InvalidRuntime);
        }
        validate_state_size(&output.state)?;
        let image = AgentImage {
            revision: 1,
            runtime_program,
            config,
            runtime_state: output.state,
        };
        store.commit(None, &image)?;
        Ok(Self {
            runtime_pvm,
            image,
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
        })
    }

    pub fn image(&self) -> &AgentImage {
        &self.image
    }

    pub fn set_management_gas(&mut self, gas: Gas) {
        self.management_gas = gas;
    }

    fn lifecycle(&mut self, request: LifecycleRequest) -> Result<LifecycleReply, AgentDriverError> {
        if matches!(request, LifecycleRequest::Create(_)) {
            return Err(AgentDriverError::Lifecycle(LifecycleError::AlreadyCreated));
        }
        if matches!(request, LifecycleRequest::UpgradeRuntime { .. }) {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        let read_only = matches!(request, LifecycleRequest::Inspect { .. });
        let output = execute_runtime(
            &self.runtime_pvm,
            self.management_gas,
            RuntimeCall {
                state: self.image.runtime_state.clone(),
                request,
            },
        )?;
        match output.result {
            Err(error) => {
                if output.state != self.image.runtime_state {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                Err(AgentDriverError::Lifecycle(error))
            }
            Ok(reply) => {
                validate_state_size(&output.state)?;
                if read_only {
                    if output.state != self.image.runtime_state {
                        return Err(AgentDriverError::InvalidRuntime);
                    }
                    return Ok(reply);
                }
                let next_revision = self
                    .image
                    .revision
                    .checked_add(1)
                    .ok_or(AgentDriverError::InvalidRuntime)?;
                let next = AgentImage {
                    revision: next_revision,
                    runtime_program: self.image.runtime_program,
                    config: self.image.config.clone(),
                    runtime_state: output.state,
                };
                self.store.commit(Some(self.image.revision), &next)?;
                self.image = next;
                Ok(reply)
            }
        }
    }

    pub fn inspect(
        &mut self,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<super::ActorDirectoryPage, AgentDriverError> {
        match self.lifecycle(LifecycleRequest::Inspect { after, limit })? {
            LifecycleReply::Directory(page) => Ok(page),
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    /// Construct the exact lifecycle operation an authority must approve for
    /// this signed package and target location.
    pub fn actor_install_request(
        &self,
        name: String,
        parent: Option<ActorId>,
        package: &VerifiedPackage,
        initial_state: ActorInitialState,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        let package = package.package();
        let PackageKind::Actor { requirements } = package.manifest.kind else {
            return Err(AgentDriverError::Package(PackageError::WrongKind));
        };
        let actor = match parent {
            Some(parent) => ActorId::owned_child(parent, &name),
            None => ActorId::top_level(self.image.config.identity.agent, &name),
        };
        Ok(LifecycleRequest::Install(InstallActor {
            entry: ActorEntry {
                actor,
                name,
                parent,
                deployment: package.deployment_id(),
                program: package.manifest.program,
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: package.deployment_signature.producer,
            package: BlobRef::of_bytes(&package.encode()),
            initial_state,
            requirements,
        }))
    }

    pub fn install_actor(
        &mut self,
        authority: &VerifiedAgentAuthorityReceipt,
        name: String,
        parent: Option<ActorId>,
        package: &VerifiedPackage,
        initial_state: ActorInitialState,
    ) -> Result<ActorEntry, AgentDriverError> {
        let request = self.actor_install_request(name, parent, package, initial_state)?;
        authorize_lifecycle(
            authority,
            &self.image.config.authority,
            self.image.config.identity.space,
            self.image.config.identity.agent,
            CapabilityId::named(super::authority::CAPABILITY_ACTOR_INSTALL),
            &request,
        )?;
        let LifecycleRequest::Install(install) = request else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        let package = package.package();
        let entry = install.entry.clone();
        let package_reference = install.package.clone();
        let package_bytes = package.encode();
        let created_package = self.store.put_package(&package_reference, &package_bytes)?;
        let created_program = match self
            .store
            .put_program(package.manifest.program, &package.pvm)
        {
            Ok(created) => created,
            Err(error) => {
                if created_package {
                    let _ = self.store.remove_package(&package_reference);
                }
                return Err(error.into());
            }
        };
        let reply = self.lifecycle(LifecycleRequest::Install(install));
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                // A typed runtime refusal happened before image persistence,
                // so newly staged artifacts are unowned and may be removed.
                // Store failures are intentionally retained: a rename may
                // have reached durable storage before a directory sync error,
                // and deleting its program would make that image unusable.
                if matches!(error, AgentDriverError::Lifecycle(_)) {
                    if created_program {
                        let _ = self.store.remove_program(package.manifest.program);
                    }
                    if created_package {
                        let _ = self.store.remove_package(&package_reference);
                    }
                }
                return Err(error);
            }
        };
        match reply {
            LifecycleReply::Installed(installed) if installed == entry => Ok(installed),
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    /// Execute one authenticated actor invocation through this agent's
    /// runtime. Actor failures are typed replies and do not commit runtime
    /// state; deterministic runtime validation failures are driver errors.
    pub fn invoke(
        &mut self,
        invocation: ActorInvocation,
    ) -> Result<ActorExecutionReply, AgentDriverError> {
        let expected_invocation = invocation.invocation;
        let expected_actor = invocation.actor;
        let expected_deployment = invocation.deployment;
        let mode = invocation.mode;
        let outer_gas = self.management_gas.saturating_add(invocation.gas);
        let actor_pvm = self
            .store
            .load_program(invocation.program)?
            .ok_or(AgentDriverError::ProgramUnavailable(invocation.program))?;
        let output: RuntimeExecutionReturn = execute_runtime_wire(
            &self.runtime_pvm,
            outer_gas,
            &RuntimeExecutionCall {
                state: self.image.runtime_state.clone(),
                invocation,
                actor_pvm,
            }
            .encode(),
        )?;
        let reply = match output.result {
            Ok(reply) => reply,
            Err(error) => {
                if output.state != self.image.runtime_state {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                return Err(AgentDriverError::Execution(error));
            }
        };
        if reply.invocation != expected_invocation
            || reply.actor != expected_actor
            || reply.deployment != expected_deployment
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        validate_state_size(&output.state)?;
        if reply.status != ActorExecutionStatus::Done {
            if output.state != self.image.runtime_state {
                return Err(AgentDriverError::InvalidRuntime);
            }
            return Ok(reply);
        }
        validate_execution_transition(&self.image.runtime_state, &output.state, mode)?;
        if output.state == self.image.runtime_state {
            // The runtime recovered an exact durable invocation result. A
            // retry is observationally successful but is not a new agent
            // revision.
            return Ok(reply);
        }

        let next = AgentImage {
            revision: self
                .image
                .revision
                .checked_add(1)
                .ok_or(AgentDriverError::InvalidRuntime)?,
            runtime_program: self.image.runtime_program,
            config: self.image.config.clone(),
            runtime_state: output.state,
        };
        self.store.commit(Some(self.image.revision), &next)?;
        self.image = next;
        Ok(reply)
    }

    /// Retire a durable exact-result record after its response has reached
    /// the caller. Until this explicit acknowledgement, retries remain
    /// recoverable across process restart.
    pub fn acknowledge_invocation(
        &mut self,
        invocation: &ActorInvocation,
    ) -> Result<(), AgentDriverError> {
        let reply = self.lifecycle(LifecycleRequest::AcknowledgeInvocation {
            invocation: invocation.invocation,
            request: invocation.commitment(),
        })?;
        if reply == LifecycleReply::InvocationAcknowledged(invocation.invocation) {
            Ok(())
        } else {
            Err(AgentDriverError::InvalidRuntime)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upgrade_runtime(
        &mut self,
        new_runtime_pvm: Vec<u8>,
        from_deployment: DeploymentId,
        to_deployment: DeploymentId,
        producer: ProducerId,
        package: BlobRef,
        capabilities: RuntimeCapabilities,
    ) -> Result<LifecycleReply, AgentDriverError> {
        let to_program = ProgramId::of_pvm(&new_runtime_pvm);
        let output = execute_runtime(
            &self.runtime_pvm,
            self.management_gas,
            RuntimeCall {
                state: self.image.runtime_state.clone(),
                request: LifecycleRequest::UpgradeRuntime {
                    from_deployment,
                    to_deployment,
                    to_program,
                    producer,
                    package: package.clone(),
                    abi: RUNTIME_ABI_ID,
                    capabilities,
                },
            },
        )?;
        let reply = output.result.map_err(AgentDriverError::Lifecycle)?;
        let LifecycleReply::RuntimeUpgraded(identity) = &reply else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        if identity.agent != self.image.config.identity.agent
            || identity.runtime_deployment != to_deployment
            || identity.runtime_program != to_program
            || identity.runtime_producer != producer
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        validate_state_size(&output.state)?;
        let probe = execute_runtime(
            &new_runtime_pvm,
            self.management_gas,
            RuntimeCall {
                state: output.state.clone(),
                request: LifecycleRequest::Inspect {
                    after: None,
                    limit: 1,
                },
            },
        )?;
        if !matches!(probe.result, Ok(LifecycleReply::Directory(_))) || probe.state != output.state
        {
            return Err(AgentDriverError::InvalidRuntime);
        }

        let mut config = self.image.config.clone();
        config.identity = identity.clone();
        config.runtime_package = package;
        config.capabilities = capabilities;
        let next = AgentImage {
            revision: self
                .image
                .revision
                .checked_add(1)
                .ok_or(AgentDriverError::InvalidRuntime)?,
            runtime_program: to_program,
            config,
            runtime_state: output.state,
        };
        self.store.commit(Some(self.image.revision), &next)?;
        self.runtime_pvm = new_runtime_pvm;
        self.image = next;
        Ok(reply)
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn validate_loaded_state(&self) -> Result<(), AgentDriverError> {
        validate_state_size(&self.image.runtime_state)?;
        let mut after = None;
        loop {
            let output = execute_runtime(
                &self.runtime_pvm,
                self.management_gas,
                RuntimeCall {
                    state: self.image.runtime_state.clone(),
                    request: LifecycleRequest::Inspect {
                        after,
                        limit: super::standard::MAX_DIRECTORY_PAGE,
                    },
                },
            )?;
            let Ok(LifecycleReply::Directory(page)) = output.result else {
                return Err(AgentDriverError::InvalidRuntime);
            };
            if output.state != self.image.runtime_state {
                return Err(AgentDriverError::InvalidRuntime);
            }
            for actor in &page.entries {
                self.store
                    .load_program(actor.program)?
                    .ok_or(AgentDriverError::ProgramUnavailable(actor.program))?;
            }
            let Some(next) = page.next else {
                break;
            };
            after = Some(next);
        }
        Ok(())
    }
}

fn runtime_state_size(state: &RuntimeState) -> usize {
    state
        .control
        .len()
        .saturating_add(state.linear.len())
        .saturating_add(state.merge.len())
        .saturating_add(state.local.len())
}

fn validate_state_size(state: &RuntimeState) -> Result<(), AgentDriverError> {
    if state.is_empty() || runtime_state_size(state) > MAX_RUNTIME_STATE_BYTES {
        Err(AgentDriverError::RuntimeStateTooLarge)
    } else {
        Ok(())
    }
}

fn validate_execution_transition(
    prior: &RuntimeState,
    next: &RuntimeState,
    mode: super::MethodMode,
) -> Result<(), AgentDriverError> {
    let Some(write_lane) = mode.write_lane() else {
        return if next == prior {
            Ok(())
        } else {
            Err(AgentDriverError::InvalidRuntime)
        };
    };
    if next.control != prior.control
        || [
            super::StateLane::Linear,
            super::StateLane::Merge,
            super::StateLane::Local,
        ]
        .into_iter()
        .any(|lane| lane != write_lane && next.component(lane) != prior.component(lane))
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    Ok(())
}

fn execute_runtime(
    runtime_pvm: &[u8],
    gas: Gas,
    call: RuntimeCall,
) -> Result<RuntimeReturn, AgentDriverError> {
    execute_runtime_wire(runtime_pvm, gas, &call.encode())
}

fn execute_runtime_wire<T: ServiceWire>(
    runtime_pvm: &[u8],
    gas: Gas,
    input: &[u8],
) -> Result<T, AgentDriverError> {
    let invocation = RefineContext::load(runtime_pvm, input, gas)
        .map_err(|_| AgentDriverError::InvalidRuntime)?
        .run();
    if invocation.exit != ExitReason::Halt {
        return Err(AgentDriverError::RuntimeExit {
            reason: invocation.exit,
            pc: invocation.pc,
        });
    }
    let output = invocation.output().ok_or(AgentDriverError::RuntimeOutput)?;
    T::decode(&output).map_err(|_| AgentDriverError::RuntimeOutput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_wire_rejects_empty_runtime_state() {
        let bytes = AgentImage {
            revision: 1,
            runtime_program: ProgramId([1; 32]),
            config: invalid_config(),
            runtime_state: RuntimeState::default(),
        }
        .encode();
        assert!(AgentImage::decode(&bytes).is_err());
    }

    fn invalid_config() -> AgentConfig {
        use crate::agent::{AgentIdentity, AgentProfile, RuntimeCapabilities};
        use crate::service::{AgentId, BlobRef, DeploymentId, PrincipalId, ProducerId, SpaceId};
        AgentConfig {
            identity: AgentIdentity {
                space: SpaceId([1; 32]),
                agent: AgentId([2; 32]),
                owner: PrincipalId([3; 32]),
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([1; 32]),
                runtime_producer: ProducerId([5; 32]),
            },
            authority: crate::agent::authority::AgentAuthorityBinding {
                agent: AgentId([7; 32]),
                actor: ActorId([8; 32]),
                deployment: DeploymentId([9; 32]),
                program: ProgramId([10; 32]),
                producer: ProducerId::of_public_key(b"authority-key"),
                public_key: b"authority-key".to_vec(),
            },
            runtime_package: BlobRef {
                hash: Hash([6; 32]),
                len: 1,
            },
            capabilities: RuntimeCapabilities::standard(),
            replicas: Vec::new(),
        }
    }
}
