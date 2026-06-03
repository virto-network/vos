//! A snapshot of a space's installed agents and their decoded schemas, used
//! by the TUI browser and tab-completion. The engine registers commands
//! directly from the client; this cache is the read model for the UI.

use std::collections::HashMap;

use vos::metadata::ParsedMeta;

use crate::backend::{AgentInfo, BackendError, SpaceClient};

#[derive(Debug, Clone, Default)]
pub struct SchemaCache {
    pub agents: Vec<AgentInfo>,
    /// instance name → decoded schema (absent if the binary has no/old meta).
    pub schemas: HashMap<String, ParsedMeta>,
}

impl SchemaCache {
    /// Load every installed agent and its schema. Agents whose schema can't be
    /// fetched/decoded are still listed (with no entry in `schemas`).
    pub fn load(client: &dyn SpaceClient) -> Result<Self, BackendError> {
        let agents = client.list_agents()?;
        let mut schemas = HashMap::new();
        for a in &agents {
            if let Ok(Some(meta)) = client.schema(&a.instance_name) {
                schemas.insert(a.instance_name.clone(), meta);
            }
        }
        Ok(Self { agents, schemas })
    }

    /// All message names for an agent (for completion). The console exposes
    /// the full interface, so this is not filtered by `exposed_to_cli`.
    pub fn methods(&self, agent: &str) -> Vec<&str> {
        self.schemas
            .get(agent)
            .map(|m| m.messages.iter().map(|msg| msg.name.as_str()).collect())
            .unwrap_or_default()
    }
}
