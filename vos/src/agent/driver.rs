//! Host driver for one durable agent-runtime instance.
//!
//! The node persists a small descriptor and an opaque runtime state. It never
//! decodes actor directories or runtime-internal scheduling data. A custom
//! runtime is therefore free to change those internals while preserving the
//! stable lifecycle ABI.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::string::String;

use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, Gas};

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
use crate::service::{ActorId, BlobRef, DeploymentId, Hash, ProducerId, ProgramId};

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
}

#[derive(Clone, Debug, Default)]
pub struct MemoryAgentStore {
    image: Option<AgentImage>,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDriverError {
    InvalidConfig(AgentConfigError),
    RuntimeProgramMismatch,
    InvalidRuntime,
    RuntimeExit { reason: ExitReason, pc: u32 },
    RuntimeOutput,
    RuntimeStateTooLarge,
    Lifecycle(LifecycleError),
    Execution(ActorExecutionError),
    Package(PackageError),
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

    pub fn lifecycle(
        &mut self,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, AgentDriverError> {
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

    /// Install one signature-verified actor package. Package-derived identity,
    /// program, producer, and runtime requirements are never accepted as
    /// parallel caller-controlled fields.
    pub fn install_actor(
        &mut self,
        name: String,
        parent: Option<ActorId>,
        package: &VerifiedPackage,
        initial_state: ActorInitialState,
    ) -> Result<ActorEntry, AgentDriverError> {
        let package = package.package();
        let PackageKind::Actor { requirements } = package.manifest.kind else {
            return Err(AgentDriverError::Package(PackageError::WrongKind));
        };
        let actor = match parent {
            Some(parent) => ActorId::owned_child(parent, &name),
            None => ActorId::top_level(self.image.config.identity.agent, &name),
        };
        let entry = ActorEntry {
            actor,
            name,
            parent,
            deployment: package.deployment_id(),
            program: package.manifest.program,
            lanes: requirements.lanes,
            suspended: false,
        };
        let reply = self.lifecycle(LifecycleRequest::Install(InstallActor {
            entry: entry.clone(),
            producer: package.deployment_signature.producer,
            package: BlobRef::of_bytes(&package.encode()),
            initial_state,
            requirements,
        }))?;
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
        let output: RuntimeExecutionReturn = execute_runtime_wire(
            &self.runtime_pvm,
            outer_gas,
            &RuntimeExecutionCall {
                state: self.image.runtime_state.clone(),
                invocation,
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
        let output = execute_runtime(
            &self.runtime_pvm,
            self.management_gas,
            RuntimeCall {
                state: self.image.runtime_state.clone(),
                request: LifecycleRequest::Inspect {
                    after: None,
                    limit: 1,
                },
            },
        )?;
        if !matches!(output.result, Ok(LifecycleReply::Directory(_)))
            || output.state != self.image.runtime_state
        {
            return Err(AgentDriverError::InvalidRuntime);
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
            runtime_package: BlobRef {
                hash: Hash([6; 32]),
                len: 1,
            },
            capabilities: RuntimeCapabilities::standard(),
            replicas: Vec::new(),
        }
    }
}
