//! `space subs [add|rm|list]` — per-node opt-in filter for
//! which installed agents this node syncs.
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

use std::collections::BTreeMap;
use std::path::Path;

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::output;
use crate::spaces_index::{self, SpaceEntry};

#[derive(Serialize)]
struct SubsView<'a> {
    space: &'a str,
    subscriptions: &'a [String],
}

#[derive(Subcommand, Debug)]
pub enum SubsCommand {
    /// List the current filter (default if no subcommand given).
    List,
    /// Add an agent to the subscription filter.
    Add { agent: String },
    /// Remove an agent from the filter.
    Rm { agent: String },
}

pub fn run(space: &str, command: Option<SubsCommand>) -> anyhow::Result<()> {
    match command.unwrap_or(SubsCommand::List) {
        SubsCommand::List => run_list(space),
        SubsCommand::Add { agent } => run_subscribe(space, &agent),
        SubsCommand::Rm { agent } => run_unsubscribe(space, &agent),
    }
}

const LOCAL_FILE: &str = "local.toml";

/// A node's local half of a space's configuration — everything the
/// registry does NOT replicate. Written by `space apply` / `space new
/// --recipe` (the node-local projection of a recipe), read at every
/// `space up`. The replicated half (which agents exist, their sync
/// floor, consistency, init) lives in the registry; this file carries
/// the per-node policy a recipe declares but that never leaves the node.
///
/// TOML ordering constraint: scalar/array fields must precede the
/// table-valued ones (`agents`, `extensions`), or `toml` refuses to
/// serialize.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
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
    /// Space-level default extension `cap_policy` (`"log"` / `"block"`
    /// / `"kill"`); per-extension overrides live on each
    /// [`ExtensionLocal`]. Node-local — a recipe declares it, `apply`
    /// projects it here, boot reads it. `None` → host default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_policy: Option<String>,
    /// Per-agent node-local policy, keyed by instance name. Only agents
    /// that declare at least one node-local field get an entry — a bare
    /// agent isn't listed. Written by `apply`, applied at every boot so
    /// a plain `space up` restart no longer drops `tick_ms`/`intra_caps`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, AgentLocal>,
    /// Native `.so` extensions to register at boot. Host-local — never
    /// replicated (they're loaded in-process via `dlopen`, so a running
    /// daemon can't register them remotely; they attach on the next
    /// `space up`).
    #[serde(default, rename = "extension", skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionLocal>,
}

/// The node-local half of an `[[agent]]` recipe entry. Everything else
/// on the entry (program, consistency, sync floor, init, on_start) is
/// replicated through the registry `install`; these three fields never
/// touch the `AgentRow`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct AgentLocal {
    /// Periodic `tick` cadence in ms (0 / omitted → no ticking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_ms: Option<u64>,
    /// `"actor:role"` intra-system caps bounding this agent's outbound
    /// relays. Empty → legacy trusted relay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intra_caps: Vec<String>,
    /// Mint + deliver a node-local device secret seed to this agent on
    /// every spawn (the messenger's MLS root). Never leaves the node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub device_secret: bool,
}

/// A native `.so` extension registration — the node-local mirror of a
/// recipe `[[extension]]`. Serializable (unlike [`crate::commands::space::reconcile::ExtensionDef`],
/// which is deserialize-only) so it can round-trip through `local.toml`.
/// `init` is last because it serializes as a table and TOML requires
/// scalar fields first.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ExtensionLocal {
    pub name: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_policy: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub relay_unauthenticated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intra_caps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub init: BTreeMap<String, toml::Value>,
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
    let body =
        toml::to_string_pretty(cfg).map_err(|e| anyhow::anyhow!("encode local.toml: {e}"))?;
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

fn run_subscribe(space: &str, agent: &str) -> anyhow::Result<()> {
    let (entry, dir) = data_dir_of(space)?;
    let mut cfg = load(&dir)?;
    if !cfg.subscriptions.iter().any(|s| s == agent) {
        cfg.subscriptions.push(agent.to_string());
        cfg.subscriptions.sort();
        save(&dir, &cfg)?;
    }
    if output::is_json() {
        output::print_json(&SubsView {
            space: &entry.name,
            subscriptions: &cfg.subscriptions,
        });
    } else {
        println!(
            "subscribed space '{}' to '{agent}' ({} total)",
            entry.name,
            cfg.subscriptions.len(),
        );
        println!("note: takes effect on next `vosx space up {}`.", entry.name);
    }
    Ok(())
}

fn run_unsubscribe(space: &str, agent: &str) -> anyhow::Result<()> {
    let (entry, dir) = data_dir_of(space)?;
    let mut cfg = load(&dir)?;
    let before = cfg.subscriptions.len();
    cfg.subscriptions.retain(|s| s != agent);
    if cfg.subscriptions.len() == before {
        anyhow::bail!("space '{}' wasn't subscribed to '{agent}'", entry.name);
    }
    save(&dir, &cfg)?;
    if output::is_json() {
        output::print_json(&SubsView {
            space: &entry.name,
            subscriptions: &cfg.subscriptions,
        });
    } else {
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
    }
    Ok(())
}

fn run_list(space: &str) -> anyhow::Result<()> {
    let (entry, dir) = data_dir_of(space)?;
    let cfg = load(&dir)?;
    if output::is_json() {
        output::print_json(&SubsView {
            space: &entry.name,
            subscriptions: &cfg.subscriptions,
        });
        return Ok(());
    }
    if cfg.subscriptions.is_empty() {
        println!(
            "space '{}': no filter — syncing all installed agents.",
            entry.name,
        );
        println!(
            "subscribe to a subset with `vosx space subs {} add <agent>`.",
            entry.name
        );
    } else {
        println!(
            "space '{}' subscriptions ({}):",
            entry.name,
            cfg.subscriptions.len()
        );
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
            ..Default::default()
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
            ..Default::default()
        };
        save(&tmp, &cfg).unwrap();
        let back = load(&tmp).unwrap();
        assert_eq!(back.subscriptions, cfg.subscriptions);
        assert_eq!(back.listen, cfg.listen);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn node_local_policy_roundtrips_through_toml() {
        // The grown schema — per-agent tables, cap_policy, extensions —
        // must survive a save/load so `apply`-written policy re-applies
        // verbatim on the next boot. Also guards the TOML value-before-
        // table ordering constraint (a bad field order panics on save).
        let tmp = std::env::temp_dir().join(format!(
            "vosx-local-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut agents = BTreeMap::new();
        agents.insert(
            "messenger".to_string(),
            AgentLocal {
                tick_ms: Some(500),
                intra_caps: vec!["space-registry:member".into()],
                device_secret: true,
            },
        );
        let mut init = BTreeMap::new();
        init.insert("port".to_string(), toml::Value::Integer(8080));
        let cfg = LocalConfig {
            subscriptions: vec!["messenger".into()],
            listen: vec![],
            cap_policy: Some("block".into()),
            agents,
            extensions: vec![ExtensionLocal {
                name: "gateway".into(),
                path: "libgateway.so".into(),
                cap_policy: Some("log".into()),
                relay_unauthenticated: true,
                intra_caps: vec![],
                tick_ms: None,
                init,
            }],
        };
        save(&tmp, &cfg).unwrap();
        let back = load(&tmp).unwrap();
        assert_eq!(back, cfg);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_file_is_default() {
        let tmp = std::env::temp_dir().join(format!("vosx-subs-missing-{}", std::process::id(),));
        // Don't create the dir — load should still succeed
        // with default config.
        let cfg = load(&tmp).unwrap();
        assert!(cfg.subscriptions.is_empty());
    }
}
