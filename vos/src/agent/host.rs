//! Durable multi-agent host.
//!
//! An [`AgentHost`] owns one filesystem directory and any number of agent
//! runtime instances. Each image remains independently replaceable and is
//! addressed by its full [`AgentId`]. Runtime packages and programs live in
//! each image's mandatory content-addressed catalog closure.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::authority::{ActorInvocationReceipt, AgentAuthorityReceipt};
use super::driver::{AgentDriver, AgentDriverError, AgentTrustProvider, FileAgentStore};
use super::execution::{ActorExecutionReply, ActorInvocation};
use super::package::Package;
use super::{ActorDirectoryPage, ActorEntry, AgentConfig, AgentIdentity};
use crate::service::{ActorId, AgentId, DeploymentId};

const IMAGE_SUFFIX: &str = ".agent-image";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHostError {
    Unavailable,
    InvalidImageName,
    DuplicateAgent,
    AgentNotFound,
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
pub struct AgentHost {
    root: PathBuf,
    agents: BTreeMap<AgentId, AgentDriver<FileAgentStore>>,
    trust: Arc<dyn AgentTrustProvider>,
}

impl AgentHost {
    /// Open every canonical image in `root`.
    ///
    /// Runtime state is validated by executing the exact runtime named in the
    /// image. A missing runtime or malformed image fails the complete open;
    /// the host never exposes a partially recovered directory.
    pub fn open(
        root: impl Into<PathBuf>,
        trust: Arc<dyn AgentTrustProvider>,
    ) -> Result<Self, AgentHostError> {
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
            let driver = AgentDriver::open(store, trust.clone())?;
            if driver.image().config.identity.agent != agent {
                return Err(AgentHostError::IdentityMismatch);
            }
            agents.insert(agent, driver);
        }
        Ok(Self {
            root,
            agents,
            trust,
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
        runtime_package: Package,
        authority: &AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        let agent = config.identity.agent;
        if self.agents.contains_key(&agent) {
            self.agents
                .get_mut(&agent)
                .expect("agent presence checked above")
                .retry_create(&config, &runtime_package, authority)?;
            return Ok(self
                .agents
                .get(&agent)
                .expect("agent presence checked above")
                .image()
                .config
                .identity
                .clone());
        }
        let path = self.image_path(agent);
        if path.exists() {
            // A prior Create may have reached the atomic image rename before
            // its final directory sync (or before the caller received the
            // response). Reopen the exact durable closure and recover only
            // the same authority disposition; mismatched or corrupt images
            // still fail closed.
            let mut driver = AgentDriver::open(FileAgentStore::new(&path), self.trust.clone())?;
            if driver.image().config.identity.agent != agent {
                return Err(AgentHostError::IdentityMismatch);
            }
            let identity = driver.retry_create(&config, &runtime_package, authority)?;
            self.agents.insert(agent, driver);
            return Ok(identity);
        }
        let store = FileAgentStore::new(path);
        let driver = AgentDriver::create(
            runtime_package,
            config,
            store,
            self.trust.clone(),
            authority,
        )?;
        self.agents.insert(agent, driver);
        Ok(self
            .agents
            .get(&agent)
            .expect("agent was inserted above")
            .image()
            .config
            .identity
            .clone())
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
        authority: &AgentAuthorityReceipt,
        name: String,
        parent: Option<ActorId>,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .install_actor(authority, name, parent, package)
            .map_err(Into::into)
    }

    pub fn upgrade_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .upgrade_actor(authority, actor, from_deployment, package)
            .map_err(Into::into)
    }

    pub fn suspend_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .suspend_actor(authority, actor)
            .map_err(Into::into)
    }

    pub fn resume_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .resume_actor(authority, actor)
            .map_err(Into::into)
    }

    pub fn remove_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .remove_actor(authority, actor, expected_deployment)
            .map_err(Into::into)
    }

    pub fn upgrade_runtime(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<AgentIdentity, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .upgrade_runtime(authority, from_deployment, package)
            .map_err(Into::into)
    }

    pub fn invoke(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .invoke(invocation, authority)
            .map_err(Into::into)
    }

    pub fn acknowledge_invocation(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .acknowledge_invocation(invocation, authority)
            .map_err(Into::into)
    }

    pub fn revision(&self, agent: AgentId) -> Option<u64> {
        self.agents
            .get(&agent)
            .map(|driver| driver.image().revision)
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
