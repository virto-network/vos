//! Durable multi-agent host.
//!
//! An [`AgentHost`] owns one filesystem directory and any number of agent
//! runtime instances. Each image remains independently replaceable and is
//! addressed by its full [`AgentId`]. Runtime programs come from an explicit
//! content-addressed source; reopening never substitutes a default runtime.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::authority::{
    CAPABILITY_AGENT_CREATE_LOCAL, CAPABILITY_AGENT_CREATE_PRIVATE, CAPABILITY_AGENT_CREATE_SHARED,
    VerifiedAgentAuthorityReceipt, authorize_lifecycle,
};
use super::driver::{AgentDriver, AgentDriverError, AgentImageStore, FileAgentStore};
use super::execution::{ActorExecutionReply, ActorInvocation};
use super::package::VerifiedPackage;
use super::{
    ActorDirectoryPage, ActorEntry, ActorInitialState, AgentConfig, AgentIdentity, AgentProfile,
    LifecycleRequest,
};
use crate::service::{ActorId, AgentId, CapabilityId, ProgramId};

const IMAGE_SUFFIX: &str = ".agent-image";

/// Exact runtime-program lookup used while creating or reopening agents.
pub trait RuntimeSource {
    fn runtime(&self, program: ProgramId) -> Option<Vec<u8>>;
}

impl<F> RuntimeSource for F
where
    F: Fn(ProgramId) -> Option<Vec<u8>>,
{
    fn runtime(&self, program: ProgramId) -> Option<Vec<u8>> {
        self(program)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHostError {
    Unavailable,
    InvalidImageName,
    DuplicateAgent,
    AgentNotFound,
    RuntimeUnavailable(ProgramId),
    IdentityMismatch,
    Driver(AgentDriverError),
}

impl core::fmt::Display for AgentHostError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent host: {self:?}")
    }
}

impl std::error::Error for AgentHostError {}

impl From<AgentDriverError> for AgentHostError {
    fn from(error: AgentDriverError) -> Self {
        Self::Driver(error)
    }
}

/// One process-local owner of a directory of durable agents.
pub struct AgentHost<R> {
    root: PathBuf,
    runtimes: R,
    agents: BTreeMap<AgentId, AgentDriver<FileAgentStore>>,
}

impl<R: RuntimeSource> AgentHost<R> {
    /// Open every canonical image in `root`.
    ///
    /// Runtime state is validated by executing the exact runtime named in the
    /// image. A missing runtime or malformed image fails the complete open;
    /// the host never exposes a partially recovered directory.
    pub fn open(root: impl Into<PathBuf>, runtimes: R) -> Result<Self, AgentHostError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| AgentHostError::Unavailable)?;
        let mut discovered = Vec::new();
        for entry in fs::read_dir(&root).map_err(|_| AgentHostError::Unavailable)? {
            let entry = entry.map_err(|_| AgentHostError::Unavailable)?;
            let file_type = entry.file_type().map_err(|_| AgentHostError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AgentHostError::InvalidImageName)?;
            if !name.ends_with(IMAGE_SUFFIX) {
                continue;
            }
            if !file_type.is_file() {
                return Err(AgentHostError::InvalidImageName);
            }
            let encoded = &name[..name.len() - IMAGE_SUFFIX.len()];
            let agent = decode_agent_id(encoded).ok_or(AgentHostError::InvalidImageName)?;
            discovered.push((agent, entry.path()));
        }
        discovered.sort_unstable_by_key(|(agent, _)| *agent);
        if discovered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(AgentHostError::DuplicateAgent);
        }

        let mut agents = BTreeMap::new();
        for (agent, path) in discovered {
            let store = FileAgentStore::new(path);
            let image = store
                .load()
                .map_err(|error| AgentHostError::Driver(AgentDriverError::Store(error)))?
                .ok_or(AgentHostError::InvalidImageName)?;
            if image.config.identity.agent != agent {
                return Err(AgentHostError::IdentityMismatch);
            }
            let runtime = runtimes
                .runtime(image.runtime_program)
                .ok_or(AgentHostError::RuntimeUnavailable(image.runtime_program))?;
            let driver = AgentDriver::create_or_open(runtime, image.config, store)?;
            agents.insert(agent, driver);
        }
        Ok(Self {
            root,
            runtimes,
            agents,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Immutable agent identities in canonical ID order.
    pub fn identities(&self) -> impl ExactSizeIterator<Item = &AgentIdentity> {
        self.agents
            .values()
            .map(|driver| &driver.image().config.identity)
    }

    pub fn identity(&self, agent: AgentId) -> Option<&AgentIdentity> {
        self.agents
            .get(&agent)
            .map(|driver| &driver.image().config.identity)
    }

    /// Create a durable empty agent with its explicitly selected runtime.
    pub fn create(
        &mut self,
        config: AgentConfig,
        authority: &VerifiedAgentAuthorityReceipt,
    ) -> Result<&AgentIdentity, AgentHostError> {
        let capability = match config.identity.profile {
            AgentProfile::Local => CAPABILITY_AGENT_CREATE_LOCAL,
            AgentProfile::Shared => CAPABILITY_AGENT_CREATE_SHARED,
            AgentProfile::Private => CAPABILITY_AGENT_CREATE_PRIVATE,
        };
        authorize_lifecycle(
            authority,
            &config.authority,
            config.identity.space,
            config.identity.agent,
            CapabilityId::named(capability),
            &LifecycleRequest::Create(config.clone()),
        )
        .map_err(|error| AgentHostError::Driver(AgentDriverError::Authority(error)))?;
        let agent = config.identity.agent;
        if self.agents.contains_key(&agent) || self.image_path(agent).exists() {
            return Err(AgentHostError::DuplicateAgent);
        }
        let runtime = self
            .runtimes
            .runtime(config.identity.runtime_program)
            .ok_or(AgentHostError::RuntimeUnavailable(
                config.identity.runtime_program,
            ))?;
        let store = FileAgentStore::new(self.image_path(agent));
        let driver = AgentDriver::create_or_open(runtime, config, store)?;
        self.agents.insert(agent, driver);
        Ok(&self
            .agents
            .get(&agent)
            .expect("agent was inserted above")
            .image()
            .config
            .identity)
    }

    pub fn inspect(
        &mut self,
        agent: AgentId,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .inspect(after, limit)
            .map_err(Into::into)
    }

    pub fn install_actor(
        &mut self,
        agent: AgentId,
        authority: &VerifiedAgentAuthorityReceipt,
        name: String,
        parent: Option<ActorId>,
        package: &VerifiedPackage,
        initial_state: ActorInitialState,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .install_actor(authority, name, parent, package, initial_state)
            .map_err(Into::into)
    }

    pub fn invoke(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .invoke(invocation)
            .map_err(Into::into)
    }

    pub fn revision(&self, agent: AgentId) -> Option<u64> {
        self.agents
            .get(&agent)
            .map(|driver| driver.image().revision)
    }

    pub fn into_runtime_source(self) -> R {
        self.runtimes
    }

    fn image_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(format!("{}{}", encode_agent_id(agent), IMAGE_SUFFIX))
    }
}

fn encode_agent_id(agent: AgentId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in agent.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_agent_id(input: &str) -> Option<AgentId> {
    if input.len() != 64 || !input.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(AgentId(bytes))
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_image_names_are_canonical() {
        let agent = AgentId([0xab; 32]);
        let encoded = encode_agent_id(agent);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_agent_id(&encoded), Some(agent));
        assert_eq!(decode_agent_id(&encoded.to_uppercase()), None);
        assert_eq!(decode_agent_id("ab"), None);
    }
}
