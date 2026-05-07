//! Boot a saved space's registry briefly, run a closure that
//! talks to it via `SpaceRegistryRef`, and shut down.
//!
//! Used by every Phase-2 command (publish, install, programs,
//! agents, …) to avoid duplicating the load → boot → query →
//! shutdown choreography.
//!
//! NOTE: each transient run mutates / reads the same redb the
//! long-running `space up` would use. Two `vosx space *`
//! processes concurrently touching the same space is currently
//! unsafe — redb opens are exclusive. A lock-or-libp2p-control
//! channel will land alongside `space up` becoming a daemon.

use std::path::PathBuf;

use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode};

use crate::blob_store::{self, BlobHash};
use crate::commands::space::up::derive_registry_replication_id;
use crate::spaces_index::{self, SpaceEntry};

pub struct TransientRegistry {
    node: VosNode,
    /// Cached so the closure can derive related ids if needed
    /// (e.g. the agent's replication_id for its own redb path).
    /// Used by Phase 2/3 commands that work with the space at
    /// large.
    #[allow(dead_code)]
    pub space_id: [u8; 32],
    #[allow(dead_code)]
    pub entry: SpaceEntry,
}

impl TransientRegistry {
    pub fn boot(query: &str) -> anyhow::Result<Self> {
        let index = spaces_index::load()?;
        let entry = spaces_index::find(&index, query)?.clone();

        if entry.registry_hash.is_empty() {
            anyhow::bail!("space '{}' missing registry_hash", entry.name);
        }
        let hash = BlobHash::from_hex(&entry.registry_hash)
            .map_err(|_| anyhow::anyhow!("registry_hash not valid hex"))?;
        let elf = blob_store::cache_get(&hash)?
            .ok_or_else(|| anyhow::anyhow!("registry blob {hash} not in cache"))?;
        let blob = grey_transpiler::link_elf(&elf)
            .map_err(|e| anyhow::anyhow!("transpile registry elf: {e:?}"))?;

        let space_id = entry
            .id_bytes()
            .ok_or_else(|| anyhow::anyhow!("space id is not 32 bytes of hex"))?;
        let data_dir = PathBuf::from(&entry.data_dir);
        if !data_dir.exists() {
            anyhow::bail!("data dir does not exist: {}", data_dir.display());
        }

        let mut node = VosNode::new();
        let cfg = AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .with_replication_id(derive_registry_replication_id(&space_id))
            .persist(&data_dir);
        let _ = node.register_at_id(cfg, ServiceId::REGISTRY);

        Ok(Self {
            node,
            space_id,
            entry,
        })
    }

    pub fn node(&self) -> &VosNode {
        &self.node
    }

    /// Drop the runtime; collects results so any panic in the
    /// agent thread bubbles back to the caller as a non-zero
    /// exit.
    pub fn shutdown(self) -> anyhow::Result<()> {
        self.node.shutdown();
        let results = self.node.collect();
        let panics: u32 = results.iter().map(|r| r.panics).sum();
        for r in &results {
            if let Some(err) = &r.error {
                eprintln!("vosx: agent {} error: {err}", r.id);
            }
        }
        if panics > 0 {
            anyhow::bail!("{panics} pvm panic(s) inside the registry");
        }
        Ok(())
    }
}
