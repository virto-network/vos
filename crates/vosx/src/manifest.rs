//! `space.toml` schema, parser, and the helpers that turn TOML
//! values into actor init args / `on_start` payloads.
//!
//! One vosx instance runs one space. Space-level properties live
//! at the TOML root (no `[space]` wrapper). `[[agent]]` lists the
//! PVM services running here; each agent can host child actors
//! inline. `[[worker]]` lists native plugins (.so / .dylib) — the
//! I/O surface of the space. `[node]` is the per-instance section
//! (libp2p identity, listen addresses, data dir).
//!
//! ## Schema overview
//!
//! ```toml
//! space      = "demo"                # required
//! version    = "0.1.0"               # optional, the space's own version
//! hyperspace = "main-hub"            # optional; inherits registry + peers
//!
//! [[agent]]
//!   name = "scheduler"
//!   path | service = ...             # exactly one
//!   consistency = "ephemeral" | "local" | "crdt"
//!   provides = ["role-1", ...]
//!   init = { ... }
//!   actors = [ { name = "ledger", path = "...", init = { ... } }, ... ]
//!
//! [[worker]]
//!   name = "rate-oracle"
//!   path | service = ...
//!   provides = ["rates"]
//!   init = { ... }
//!
//! [node]
//!   identity = "auto"
//!   listen   = ["/ip4/0.0.0.0/tcp/4001"]
//!   data_dir = "./data"
//! ```
//!
//! Everything in `[node]` is also accepted in a sibling
//! `<base>.local.toml` overlay (e.g. `space.local.toml`), which
//! the parser merges over the base manifest. Per-agent
//! `on_start` overrides go in the overlay too — the canonical
//! use case is "two operators run the same manifest with
//! different kick-off messages".

use crate::die;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vos::init::{InitArgs, InitValue};

#[derive(Deserialize)]
pub struct Manifest {
    pub space: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
    /// Optional hyperspace this space joins. When set, vosx
    /// auto-spawns a registry replica at `ServiceId::REGISTRY`
    /// using `registry_blob` as the actor binary, and registers
    /// every declared agent in it on startup.
    #[serde(default)]
    pub hyperspace: Option<String>,
    /// Path to the registry actor's `.elf`. Required when
    /// `hyperspace` is set. Resolved relative to the manifest
    /// directory.
    #[serde(default)]
    pub registry_blob: Option<PathBuf>,
    /// How often vosx pings each auto-announced service via
    /// `heartbeat(name)` so the registry's `last_seen` stays
    /// current. `None` (the default) → 30s. Set to 0 to disable
    /// auto-heartbeat.
    #[serde(default)]
    pub heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    pub agent: Vec<AgentDef>,
    #[serde(default)]
    pub worker: Vec<WorkerDef>,
    #[serde(default)]
    pub node: NodeMeta,
}

#[derive(Deserialize, Default)]
pub struct NodeMeta {
    /// libp2p keypair material (path to file, or `"auto"` to
    /// derive on first run).
    #[serde(default)]
    pub identity: Option<String>,
    /// libp2p listen multiaddrs.
    #[serde(default)]
    pub listen: Vec<String>,
    /// Per-actor redb files live under `{data_dir}/agents/...` and
    /// `{data_dir}/workers/...`. CLI `--data-dir` takes precedence.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
pub struct AgentDef {
    pub name: String,
    /// Local path to an ELF or pre-compiled .pvm. Mutually exclusive
    /// with `service`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Registry lookup, e.g. `"kunekt/scheduler@1.2"`. Currently
    /// errors out — registry resolution is a future feature.
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub consistency: ConsistencyDef,
    /// Roles this agent provides. Other actors can address by role
    /// via `init` values prefixed `@role-name`.
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
    /// Replication group identifier. Only meaningful when
    /// `consistency = "crdt"`. Three forms:
    ///   - omitted / "auto" — derive from `blake2b(name || 0 || blob)`,
    ///     so two replicas of the same code+name auto-share a group
    ///   - 64-char hex string — explicit, for cross-cluster pinning
    ///   - "off" — no replication (DAG stays purely local)
    #[serde(default)]
    pub replication_id: Option<String>,
    /// Messages to send to this agent immediately after startup.
    /// Each entry is encoded as a TAG_DYNAMIC + rkyv(Msg) payload
    /// and queued via `AgentConfig::init_payloads`. Useful for
    /// kicking a CRDT actor with a per-process unique tag from
    /// the local overlay so two replicas of the same manifest
    /// produce different EffectLogs.
    #[serde(default)]
    pub on_start: Vec<OnStartMsg>,
    /// Child actors hosted by this agent. Each becomes its own
    /// registered service.
    #[serde(default)]
    pub actors: Vec<ActorDef>,
}

#[derive(Deserialize)]
pub struct ActorDef {
    pub name: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pub replication_id: Option<String>,
    #[serde(default)]
    pub on_start: Vec<OnStartMsg>,
}

#[derive(Deserialize, Clone)]
pub struct OnStartMsg {
    /// Handler name (the actor's `#[msg]` method).
    pub msg: String,
    /// Arguments to pack into the dynamic `Msg`. Keys must match
    /// the handler's parameter names.
    #[serde(default)]
    pub args: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConsistencyDef {
    #[default]
    Ephemeral,
    Local,
    Crdt,
}

impl From<ConsistencyDef> for vos::node::Consistency {
    fn from(c: ConsistencyDef) -> Self {
        match c {
            ConsistencyDef::Ephemeral => vos::node::Consistency::Ephemeral,
            ConsistencyDef::Local => vos::node::Consistency::Local,
            ConsistencyDef::Crdt => vos::node::Consistency::Crdt,
        }
    }
}

#[derive(Deserialize)]
pub struct WorkerDef {
    pub name: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub service: Option<String>,
    /// Roles this worker provides.
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
}

/// Subset of the manifest schema that's allowed in the overlay
/// file. `[node]` for libp2p identity / listen / data_dir, and
/// `[[agent]]` entries for per-host on_start overrides keyed by
/// agent name.
#[derive(Deserialize, Default)]
struct LocalOverlay {
    #[serde(default)]
    node: Option<NodeMeta>,
    #[serde(default)]
    agent: Vec<LocalOverlayAgent>,
}

#[derive(Deserialize)]
struct LocalOverlayAgent {
    name: String,
    #[serde(default)]
    on_start: Vec<OnStartMsg>,
}

// ── Loader ──────────────────────────────────────────────────────────

pub fn manifest_from(path: Option<PathBuf>) -> (Manifest, PathBuf) {
    let path = path.unwrap_or_else(|| "space.toml".into());
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())));
    let mut manifest: Manifest = toml::from_str(&content)
        .unwrap_or_else(|e| die(&format!("parsing {}: {e}", path.display())));

    let overlay_path = local_overlay_path(&path);
    if overlay_path.exists() {
        let overlay_content = std::fs::read_to_string(&overlay_path)
            .unwrap_or_else(|e| die(&format!("reading {}: {e}", overlay_path.display())));
        let overlay: LocalOverlay = toml::from_str(&overlay_content)
            .unwrap_or_else(|e| die(&format!("parsing {}: {e}", overlay_path.display())));
        if let Some(node) = overlay.node {
            manifest.node = node;
        }
        for ov in overlay.agent {
            let mut applied = false;
            for a in manifest.agent.iter_mut() {
                if a.name == ov.name {
                    a.on_start = ov.on_start;
                    applied = true;
                    break;
                }
                for child in a.actors.iter_mut() {
                    if child.name == ov.name {
                        child.on_start = ov.on_start.clone();
                        applied = true;
                        break;
                    }
                }
                if applied { break; }
            }
            if !applied {
                eprintln!(
                    "vosx: overlay agent '{}' not found in base manifest; ignoring",
                    ov.name,
                );
            }
        }
        eprintln!("vosx: merged overlay from {}", overlay_path.display());
    }

    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    (manifest, dir)
}

/// Derive the local-overlay file path: insert `.local` before the
/// extension. `space.toml` → `space.local.toml`.
fn local_overlay_path(manifest: &Path) -> PathBuf {
    let stem = manifest
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("space");
    let dir = manifest.parent().unwrap_or(Path::new("."));
    dir.join(format!("{stem}.local.toml"))
}

/// Resolve the local file path for an entry that may use `path`
/// (dev) or `service` (registry lookup). `service` errors out
/// today — registry-lookup loading is future work.
pub fn resolve_entry_path(
    name: &str,
    path: &Option<PathBuf>,
    service: &Option<String>,
    dir: &Path,
) -> PathBuf {
    match (path, service) {
        (Some(_), Some(_)) => die(&format!(
            "'{name}': 'service' and 'path' are mutually exclusive — pick one",
        )),
        (None, None) => die(&format!(
            "'{name}': either 'service' or 'path' is required",
        )),
        (None, Some(s)) => die(&format!(
            "'{name}': 'service = {s:?}' requires registry resolution which lands \
             with the networking layer; use 'path' for now",
        )),
        (Some(p), None) => dir.join(p),
    }
}

// ── Replication-id derivation ──────────────────────────────────────

/// Resolve a manifest's `replication_id` field (or `None` to mean
/// "auto"). Returns `Some(rep_id)` for an active group or `None`
/// when the actor opts out via `"off"`. Anything else is a
/// manifest error.
pub fn resolve_replication_id(name: &str, spec: Option<&str>, blob: &[u8]) -> Option<[u8; 32]> {
    match spec.map(str::trim) {
        Some("off") => None,
        None | Some("") | Some("auto") => Some(auto_replication_id(name, blob)),
        Some(hex) => match decode_hex_32(hex) {
            Some(arr) => Some(arr),
            None => die(&format!(
                "'{name}': replication_id must be \"auto\", \"off\", or 64 hex chars; got {hex:?}",
            )),
        },
    }
}

fn auto_replication_id(name: &str, blob: &[u8]) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(name.as_bytes());
    h.update(&[0u8]);
    h.update(blob);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ── Init args + on_start encoding ──────────────────────────────────

/// Encode the manifest's `on_start` entries as TAG_DYNAMIC +
/// rkyv-encoded `Msg` payloads. The agent thread receives
/// these as initial inbox messages and dispatches them before
/// reading from the inbox channel.
///
/// Argument types are looked up from the actor's `MessageMeta`
/// so a TOML integer sent to a `u32` parameter lands as
/// `Value::U32` (not the default `Value::U64`).
pub fn encode_on_start(
    agent_name: &str,
    entries: &[OnStartMsg],
    elf_data: &[u8],
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> Vec<Vec<u8>> {
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    let meta = vos::metadata::from_elf(elf_data);
    let mut out = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let mut m = Msg::new(entry.msg.clone());
        let handler_meta = meta
            .as_ref()
            .and_then(|am| am.messages.iter().find(|h| h.name.as_str() == entry.msg.as_str()));
        for (k, v) in &entry.args {
            let typed = handler_meta
                .and_then(|h| h.fields.iter().find(|f| f.name.as_str() == k.as_str()))
                .and_then(|f| typed_value(v, f.ty.as_str()));
            let value = typed.unwrap_or_else(|| toml_to_value(v, name_ids, provides_map));
            m = m.with(k.clone(), value);
        }
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        eprintln!(
            "vosx: on_start[{idx}] '{}' -> {}({})",
            agent_name,
            entry.msg,
            entry.args.iter().map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>().join(", "),
        );
        out.push(payload);
        let _ = (name_ids, provides_map);
    }
    out
}

/// Coerce a TOML scalar to a typed `Value` matching the handler's
/// declared parameter type. Returns `None` for unhandled
/// combinations so the caller can fall back to inference.
fn typed_value(val: &toml::Value, ty: &str) -> Option<vos::value::Value> {
    use vos::value::Value;
    match (val, ty.replace(' ', "").as_str()) {
        (toml::Value::Integer(n), "u32") => Some(Value::U32(*n as u32)),
        (toml::Value::Integer(n), "u64") => Some(Value::U64(*n as u64)),
        (toml::Value::Integer(n), "i64") => Some(Value::I64(*n)),
        (toml::Value::Integer(n), "i32") => Some(Value::I32(*n as i32)),
        (toml::Value::Integer(n), "u16") => Some(Value::U16(*n as u16)),
        (toml::Value::Integer(n), "u8") => Some(Value::U8(*n as u8)),
        (toml::Value::Boolean(b), "bool") => Some(Value::Bool(*b)),
        (toml::Value::String(s), "String") => Some(Value::Str(s.clone())),
        _ => None,
    }
}

pub fn apply_init(
    mut cfg: vos::node::AgentConfig,
    init: &BTreeMap<String, toml::Value>,
    elf_data: &[u8],
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> vos::node::AgentConfig {
    if init.is_empty() {
        return cfg;
    }
    let meta = vos::metadata::from_elf(elf_data);
    let mut args = InitArgs::new();
    for (key, val) in init {
        let ty = meta
            .as_ref()
            .and_then(|m| m.constructor.iter().find(|f| f.name == *key))
            .map(|f| f.ty.as_str())
            .unwrap_or("String");
        args = args.with(key, toml_to_init_value(val, ty, name_ids, provides_map));
    }
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    cfg = cfg.with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), encoded.to_vec())]);
    cfg
}

/// Resolve a string reference to a `ServiceId` u32. Two forms:
///   `name`     → look up in `name_ids` (declared actor/worker name)
///   `@role`    → look up in `provides_map` (must be unambiguous)
fn resolve_string_to_id(
    s: &str,
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> u32 {
    if let Some(role) = s.strip_prefix('@') {
        match provides_map.get(role) {
            None => die(&format!(
                "no actor or worker provides role '{role}' (referenced by '@{role}')",
            )),
            Some(ids) if ids.is_empty() => die(&format!(
                "no actor or worker provides role '{role}'",
            )),
            Some(ids) if ids.len() > 1 => die(&format!(
                "role '{role}' is provided by {} entries; cannot resolve '@{role}' unambiguously",
                ids.len(),
            )),
            Some(ids) => ids[0],
        }
    } else {
        name_ids.get(s).copied().unwrap_or_else(|| {
            die(&format!(
                "init value '{s}' is not a declared actor or worker (forward reference? use '@role' for role lookup)",
            ))
        })
    }
}

/// Convert a TOML value to a typed `InitValue`, resolving string
/// references against the running map of declared peers.
fn toml_to_init_value(
    val: &toml::Value,
    expected_ty: &str,
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> InitValue {
    let ty = expected_ty.replace(' ', "");
    match (val, ty.as_str()) {
        (toml::Value::Integer(n), "u32") => InitValue::U32(*n as u32),
        (toml::Value::Integer(n), "u64") => InitValue::U64(*n as u64),
        (toml::Value::Integer(n), "i32") => InitValue::I32(*n as i32),
        (toml::Value::Boolean(b), "bool") => InitValue::Bool(*b),
        (toml::Value::String(s), "String") => InitValue::Str(s.clone()),
        (toml::Value::String(s), "u32") => {
            InitValue::U32(resolve_string_to_id(s, name_ids, provides_map))
        }
        (toml::Value::Array(arr), "Vec<u32>") => InitValue::ListU32(
            arr.iter()
                .map(|v| match v {
                    toml::Value::Integer(n) => *n as u32,
                    toml::Value::String(s) => resolve_string_to_id(s, name_ids, provides_map),
                    other => die(&format!(
                        "Vec<u32> array element must be integer or actor/worker name, got {other:?}",
                    )),
                })
                .collect(),
        ),
        _ => die(&format!("cannot convert TOML value to {expected_ty}")),
    }
}

/// Convert a TOML value into an untyped `vos::value::Value` for
/// worker init args. Strings resolve to ServiceIds when they
/// match a declared name or `@role` reference, otherwise they
/// stay strings.
pub fn toml_to_value(
    val: &toml::Value,
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> vos::value::Value {
    use vos::value::Value;
    match val {
        toml::Value::Integer(n) => {
            if *n >= 0 {
                Value::U64(*n as u64)
            } else {
                Value::I64(*n)
            }
        }
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::String(s) => {
            if let Some(role) = s.strip_prefix('@') {
                Value::U32(resolve_string_to_id(&format!("@{role}"), name_ids, provides_map))
            } else if let Some(&id) = name_ids.get(s) {
                Value::U32(id)
            } else {
                Value::Str(s.clone())
            }
        }
        other => die(&format!("worker init value of unsupported TOML kind: {other:?}")),
    }
}

pub fn is_manifest(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "toml")
}
