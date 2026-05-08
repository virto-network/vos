//! `space subscribe / unsubscribe / subscriptions` — per-node
//! opt-in filter for which installed agents this node syncs.
//!
//! By default (no `local.toml` or empty `subscriptions` list)
//! `space up` spawns every agent in the registry's catalog —
//! the node is a full replica. With subscriptions set, the
//! daemon spawns ONLY listed agents and ignores the rest, so
//! a node can be a partial replica (lower storage / bandwidth)
//! or stay private (don't pull data it doesn't need).
//!
//! Writes to `<data_dir>/local.toml`. The format is
//! `subscriptions = ["counter", "chat"]` at the top level.
//! Other per-node overrides may join the same file later.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::spaces_index::{self, SpaceEntry};

const LOCAL_FILE: &str = "local.toml";

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LocalConfig {
    /// Empty = sync all installed agents. Non-empty = sync
    /// only the listed instance names.
    #[serde(default)]
    pub subscriptions: Vec<String>,
    /// libp2p multiaddrs the daemon should bind on every
    /// `space up`. Empty (default) = bind a loopback auto-port
    /// for local-only client commands. `--listen` on
    /// `space up` overrides for one run.
    #[serde(default)]
    pub listen: Vec<String>,
}

impl LocalConfig {
    /// True when the node has explicitly opted into a subset
    /// rather than the default "sync everything".
    pub fn is_filtering(&self) -> bool {
        !self.subscriptions.is_empty()
    }

    /// True when the agent should be spawned on this node.
    /// Defaults to true (full replica) if no filter is set.
    pub fn should_spawn(&self, instance_name: &str) -> bool {
        if !self.is_filtering() {
            return true;
        }
        self.subscriptions.iter().any(|s| s == instance_name)
    }
}

pub fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(LOCAL_FILE)
}

pub fn load(data_dir: &Path) -> anyhow::Result<LocalConfig> {
    let p = path(data_dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LocalConfig::default()),
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", p.display())),
    };
    let s = String::from_utf8_lossy(&bytes);
    toml::from_str(&s).map_err(|e| anyhow::anyhow!("parse {}: {e}", p.display()))
}

pub fn save(data_dir: &Path, cfg: &LocalConfig) -> anyhow::Result<()> {
    let p = path(data_dir);
    let body = toml::to_string_pretty(cfg)
        .map_err(|e| anyhow::anyhow!("encode local.toml: {e}"))?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&p, body).map_err(|e| anyhow::anyhow!("write {}: {e}", p.display()))
}

/// Resolve a space query to its on-disk data dir, then load
/// the local config.
fn data_dir_of(space: &str) -> anyhow::Result<(SpaceEntry, std::path::PathBuf)> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, space)?.clone();
    let dir = std::path::PathBuf::from(&entry.data_dir);
    Ok((entry, dir))
}

pub fn run_subscribe(space: &str, agent: &str) -> anyhow::Result<()> {
    let (entry, dir) = data_dir_of(space)?;
    let mut cfg = load(&dir)?;
    if cfg.subscriptions.iter().any(|s| s == agent) {
        println!("space '{}' already subscribed to '{agent}'", entry.name);
        return Ok(());
    }
    cfg.subscriptions.push(agent.to_string());
    cfg.subscriptions.sort();
    save(&dir, &cfg)?;
    println!(
        "subscribed space '{}' to '{agent}' ({} total)",
        entry.name,
        cfg.subscriptions.len(),
    );
    println!("note: takes effect on next `vosx space up {}`.", entry.name);
    Ok(())
}

pub fn run_unsubscribe(space: &str, agent: &str) -> anyhow::Result<()> {
    let (entry, dir) = data_dir_of(space)?;
    let mut cfg = load(&dir)?;
    let before = cfg.subscriptions.len();
    cfg.subscriptions.retain(|s| s != agent);
    if cfg.subscriptions.len() == before {
        anyhow::bail!("space '{}' wasn't subscribed to '{agent}'", entry.name);
    }
    save(&dir, &cfg)?;
    println!(
        "unsubscribed space '{}' from '{agent}' ({} remaining)",
        entry.name,
        cfg.subscriptions.len(),
    );
    if cfg.subscriptions.is_empty() {
        println!("note: subscription list is now empty — node will sync all agents again.");
    } else {
        println!("note: takes effect on next `vosx space up {}`.", entry.name);
    }
    Ok(())
}

pub fn run_list(space: &str) -> anyhow::Result<()> {
    let (entry, dir) = data_dir_of(space)?;
    let cfg = load(&dir)?;
    if cfg.subscriptions.is_empty() {
        println!(
            "space '{}': no filter — syncing all installed agents.",
            entry.name,
        );
        println!("subscribe to a subset with `vosx space subscribe {} <agent>`.", entry.name);
    } else {
        println!("space '{}' subscriptions ({}):", entry.name, cfg.subscriptions.len());
        for s in &cfg.subscriptions {
            println!("  - {s}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_should_spawn_everything() {
        let cfg = LocalConfig::default();
        assert!(!cfg.is_filtering());
        assert!(cfg.should_spawn("anything"));
    }

    #[test]
    fn non_empty_config_filters() {
        let cfg = LocalConfig {
            subscriptions: vec!["counter".into(), "chat".into()],
            listen: vec![],
        };
        assert!(cfg.is_filtering());
        assert!(cfg.should_spawn("counter"));
        assert!(cfg.should_spawn("chat"));
        assert!(!cfg.should_spawn("voting"));
    }

    #[test]
    fn save_load_roundtrips() {
        let tmp = std::env::temp_dir().join(format!(
            "vosx-subs-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = LocalConfig {
            subscriptions: vec!["a".into(), "b".into()],
            listen: vec!["/ip4/0.0.0.0/tcp/4811".into()],
        };
        save(&tmp, &cfg).unwrap();
        let back = load(&tmp).unwrap();
        assert_eq!(back.subscriptions, cfg.subscriptions);
        assert_eq!(back.listen, cfg.listen);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_file_is_default() {
        let tmp = std::env::temp_dir().join(format!(
            "vosx-subs-missing-{}",
            std::process::id(),
        ));
        // Don't create the dir — load should still succeed
        // with default config.
        let cfg = load(&tmp).unwrap();
        assert!(cfg.subscriptions.is_empty());
    }
}
