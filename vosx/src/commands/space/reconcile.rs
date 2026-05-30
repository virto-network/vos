//! Manifest → registry reconciliation.
//!
//! `space up --manifest <path>` reads a TOML, walks every
//! `[[agent]]` (and nested `actors` children), and ensures
//! the registry catalog reflects what the manifest declares:
//!
//! - Each `path = "…"` ELF gets blob-cached and published as
//!   `<name>:manifest` if not already in the catalog.
//! - Each agent gets `install()`'d if no instance with that
//!   `name` is already registered.
//! - Agents already in the registry are left alone (their
//!   state takes precedence over the manifest). An explicit
//!   `space upgrade` is required to re-point at a different
//!   blob.
//!
//! Manifests are dev-time conveniences — the registry stays
//! the runtime source of truth. This module's only job is to
//! arrange the registry once on startup; after that, `space
//! up` proceeds normally and spawns whatever the registry says
//! is installed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use space_registry::{ProgramRow, STATUS_OK, STATUS_TAG_CONFLICT, SpaceRegistryRef};
use vos::abi::service::ServiceId;
use vos::init::{InitArgs, InitValue};
use vos::node::{ExtensionConfig, VosNode};
use vos::value::Args;

use crate::blob_store;
use crate::commands::space::common::{auto_replication_id, instance_service_id, parse_consistency};
use crate::commands::space::payload_codec;

/// Slim view of the manifest TOML — only the fields the
/// reconciler cares about. Extra fields are silently ignored
/// so manifests can carry whatever annotations they want.
#[derive(Deserialize, Debug, Default)]
pub struct Manifest {
    /// Top-level `space = "..."` informational name. Not used
    /// by the reconciler — the space identity is the canonical
    /// `space_id`, looked up from the running entry.
    #[allow(dead_code)]
    pub space: Option<String>,
    /// Sprint 2: default `cap_policy` for every extension in
    /// this space — `"log"` / `"block"` / `"kill"`. Per-extension
    /// `cap_policy` overrides. Omitted → host default
    /// ([`vos::extension::CapPolicy::Block`]).
    pub cap_policy: Option<String>,
    #[serde(rename = "agent", default)]
    pub agents: Vec<AgentDef>,
    /// Native `.so` extension plugins. Each `[[extension]]` entry
    /// in a manifest maps onto a single `node.register_extension`
    /// call when the daemon boots; the host loads the .so, reads
    /// its meta.kind, and dispatches to actor- or service-mode
    /// glue accordingly. Phase 5 doesn't surface extensions in the
    /// space registry — they're host-local; only PVM agents live in
    /// the registry today.
    #[serde(rename = "extension", default)]
    pub extensions: Vec<ExtensionDef>,
}

#[derive(Deserialize, Debug, Default)]
pub struct ExtensionDef {
    /// Display name. Logged at boot; not used for routing today
    /// (extensions get auto-allocated ServiceIds).
    pub name: String,
    /// Path to the `.so` — relative to the manifest file's
    /// directory.
    pub path: String,
    /// Constructor args. Encoded as a rkyv `vos::value::Args`
    /// which the extension's `fn new(args: &[u8])` parses. Strings,
    /// ints, and bools all flow through as-is; richer types
    /// (Vec<u32> name-list, etc.) come later if needed.
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
    /// Sprint 2: per-extension override of the space-level
    /// [`Manifest::cap_policy`]. Useful for relaxing one
    /// extension to `"log"` while keeping the rest at `"block"`.
    pub cap_policy: Option<String>,
    /// M9 — this extension is a relay for *external* traffic
    /// (HTTP gateway, future REST adapters). When `true`, the
    /// extension's outbound calls tag every InvokeRequest as
    /// [`Caller::Unauthenticated`] so the targeted actor's
    /// role-gated handlers refuse anonymous traffic.
    ///
    /// Defaults to `false` — most extensions compose with
    /// other actors as trusted in-process peers.
    #[serde(default)]
    pub relay_unauthenticated: bool,
}

#[derive(Deserialize, Debug, Default)]
pub struct AgentDef {
    pub name: String,
    /// Path to the actor ELF — relative to the manifest file's
    /// directory.
    pub path: String,
    /// `ephemeral` / `local` / `crdt` / `raft`. Defaults to
    /// `crdt` for replicated actors; manifests that omit this
    /// for one-off services typically want `ephemeral`.
    #[serde(default = "default_consistency")]
    pub consistency: String,
    /// Constructor args. Values are resolved against the
    /// actor's `.vos_meta` so e.g. `Vec<u32>` typed args
    /// automatically map a list of agent names to their
    /// derived ServiceIds.
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
    /// Inline child actors. Each becomes its own installed
    /// agent (separate replication group). Nested children
    /// are not currently supported.
    #[serde(default)]
    pub actors: Vec<AgentDef>,
    /// Override replication id (`auto` / `off` / 64-hex).
    /// `auto` (default) hashes `(name, blob_hash)`.
    #[serde(default)]
    pub replication_id: Option<String>,
    /// One-shot messages dispatched when the agent first
    /// cold-starts. Each entry is `{ msg = "name", … }`
    /// where extra keys become `Msg::with` arguments.
    #[serde(default)]
    pub on_start: Vec<OnStartMsg>,
}

#[derive(Deserialize, Debug, Default)]
pub struct OnStartMsg {
    /// Message handler name to invoke.
    pub msg: String,
    /// Remaining keys are typed args. `flatten` so the manifest
    /// can write `{ msg = "set", val = 42 }` without nesting.
    #[serde(flatten, default)]
    pub args: BTreeMap<String, toml::Value>,
}

fn default_consistency() -> String {
    "crdt".to_string()
}

/// Resolve an extension's `.so` path against the manifest dir,
/// build init args (rkyv `Args`), and hand off to
/// `node.register_extension`. Logs the load + each init arg so
/// operators can spot misconfigured manifests at boot.
///
/// Also pulls the `.so`'s `vos_extension_meta` blob out via a one-
/// shot `ExtensionPlugin::load` and forwards it to the registry's
/// `register_extension_meta` keyed by the manifest instance name.
/// `vosx <ext> <cmd>` (Phase 4) reads back through the same name to
/// drive its dynamic clap surface. Double-loading the .so here is
/// trivial: cdylibs are small and meta extraction doesn't run any
/// extension code.
fn register_extension(
    node: &mut VosNode,
    reg: &SpaceRegistryRef,
    ext: &ExtensionDef,
    manifest_dir: &Path,
    daemon_prefix: u16,
    space_cap_policy: vos::extension::CapPolicy,
) -> anyhow::Result<()> {
    let so_path = manifest_dir.join(&ext.path);
    if !so_path.exists() {
        anyhow::bail!(
            "extension '{}': .so not found at {}",
            ext.name,
            so_path.display()
        );
    }

    let mut args = Args::new();
    for (k, v) in &ext.init {
        let resolved = resolve_env_indirection(&ext.name, k, v)?;
        args = match &resolved {
            toml::Value::String(s) => args.with(k.clone(), s.clone()),
            toml::Value::Integer(i) => args.with(k.clone(), *i as u32),
            toml::Value::Boolean(b) => args.with(k.clone(), *b),
            other => {
                anyhow::bail!(
                    "extension '{}': init arg '{}' has unsupported type {}; \
                     supported: string, integer, bool",
                    ext.name,
                    k,
                    other.type_str()
                );
            }
        };
    }

    // Open the .so once to read meta + keep the handle alive past
    // the `node.register_extension` call below. The worker thread
    // does its own dlopen; by holding our handle until after the
    // worker is spawned, we make the common interleaving (worker
    // dlopens before our drop) keep dlopen's refcount ≥ 1, so the
    // library never round-trips through an unmap. There's still a
    // narrow race if the worker thread hasn't run yet at our drop;
    // a stronger fix would have `node.register_extension` return
    // the meta blob itself, which is the right Phase 5+ shape.
    // SAFETY: dlopen on a vos-built extension .so; the manifest's
    // path is operator-supplied. See node.rs:run_service_extension
    // for the full FFI contract docstring.
    let plugin = match unsafe { vos::extension::ExtensionPlugin::load(&so_path) } {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(
                "extension '{}': failed to read .vos_meta from {} ({e}); \
                 schema-aware CLI dispatch disabled",
                ext.name,
                so_path.display(),
            );
            None
        }
    };
    let meta_blob = plugin
        .as_ref()
        .map(|p| p.meta_bytes().to_vec())
        .unwrap_or_default();

    // Sprint 2: per-extension cap_policy override > space-level
    // default. Falls back to the host-side CapPolicy::default()
    // when neither is set.
    let cap_policy = match ext.cap_policy.as_deref() {
        Some(s) => vos::extension::CapPolicy::parse(s),
        None => space_cap_policy,
    };
    tracing::info!(
        "extension '{}' cap_policy = {}",
        ext.name,
        cap_policy.as_str(),
    );

    let cfg = if ext.init.is_empty() {
        ExtensionConfig::new(&so_path).with_cap_policy(cap_policy)
    } else {
        ExtensionConfig::with_args(&so_path, &args).with_cap_policy(cap_policy)
    };
    let cfg = if ext.relay_unauthenticated {
        cfg.relay_unauthenticated()
    } else {
        cfg
    };

    // Install at a *deterministic* ServiceId derived from the
    // extension's manifest name + daemon prefix, identical to the
    // shape `instance_service_id` gives PVM agents. Without this,
    // the host's `alloc_id` hands out an opaque incrementing id
    // that vosx-side `resolve_target` has no way to rediscover
    // — making `vosx <ext> <method>` unreachable. The blake2b-
    // derived id is stable across daemon restarts so the cache
    // and any external scripting stay valid.
    let id = node.register_extension_at_id(cfg, instance_service_id(&ext.name, daemon_prefix));
    tracing::info!(
        "extension '{}' loaded from {} as {id}",
        ext.name,
        so_path.display(),
    );

    if !meta_blob.is_empty() {
        let status =
            vos::block_on(reg.register_extension_meta(&mut &*node, ext.name.clone(), meta_blob))
                .map_err(|e| {
                    anyhow::anyhow!("registry.register_extension_meta('{}'): {e}", ext.name)
                })?;
        if status != STATUS_OK {
            tracing::warn!(
                "register_extension_meta('{}') returned status {status}; \
                 CLI dispatch surface unavailable for this extension",
                ext.name,
            );
        } else {
            tracing::debug!("registered extension meta for '{}'", ext.name);
        }
    }

    // Plugin handle drops here, *after* the worker thread has its
    // own dlopen — the library stays mapped throughout.
    drop(plugin);

    Ok(())
}

pub fn parse_manifest_file(path: &Path) -> anyhow::Result<(Manifest, PathBuf)> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let manifest: Manifest = toml::from_str(std::str::from_utf8(&bytes)?)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
    let dir = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((manifest, dir))
}

/// Walk the manifest and call `registry.publish` / `install`
/// for every entry that's missing. `node` must already have
/// the registry registered locally (so `&mut &node` can drive
/// in-process Ref calls).
pub fn reconcile(
    node: &mut VosNode,
    manifest: &Manifest,
    manifest_dir: &Path,
    daemon_prefix: u16,
) -> anyhow::Result<()> {
    validate_manifest_names(manifest)?;

    let reg = SpaceRegistryRef::at(ServiceId::new(
        daemon_prefix,
        ServiceId::REGISTRY.local_id(),
    ));

    // Extensions land first — they're host-local and don't need the
    // registry to *boot*, but each one's meta blob does ride into
    // the registry's `extension_metas` table so `meta_for_instance`
    // (and Phase 4's `vosx <ext> <cmd>`) can find the CLI surface.
    // Doing extensions up-front lets a service-mode extension
    // (gateway, etc.) be ready by the time PVM agents start sending
    // traffic at it.
    if !manifest.extensions.is_empty() {
        tracing::info!(
            "reconciling manifest ({} extension definition(s))",
            manifest.extensions.len(),
        );
        // Resolve the space-level default once; per-extension
        // overrides are applied inside register_extension.
        let space_cap_policy = match manifest.cap_policy.as_deref() {
            Some(s) => vos::extension::CapPolicy::parse(s),
            None => vos::extension::CapPolicy::default(),
        };
        for ext in &manifest.extensions {
            register_extension(
                node,
                &reg,
                ext,
                manifest_dir,
                daemon_prefix,
                space_cap_policy,
            )?;
        }
    }

    if manifest.agents.is_empty() {
        return Ok(());
    }
    tracing::info!(
        "reconciling manifest ({} agent definition(s))",
        flat_count(&manifest.agents),
    );

    // Pre-compute every agent's name → derived svc_id so
    // init-arg resolution (e.g. `children = ["greeter"]` →
    // Vec<u32>) can hand back the right ids without round-
    // tripping through the registry.
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    for a in flatten(&manifest.agents) {
        name_ids.insert(
            a.name.clone(),
            instance_service_id(&a.name, daemon_prefix).0,
        );
    }

    for agent in flatten(&manifest.agents) {
        reconcile_one(node, &reg, agent, manifest_dir, daemon_prefix, &name_ids)?;
    }

    Ok(())
}

fn reconcile_one(
    node: &VosNode,
    reg: &SpaceRegistryRef,
    agent: &AgentDef,
    manifest_dir: &Path,
    _daemon_prefix: u16,
    name_ids: &BTreeMap<String, u32>,
) -> anyhow::Result<()> {
    // 1. Resolve and cache the agent's blob.
    let elf_path = manifest_dir.join(&agent.path);
    let elf_bytes = std::fs::read(&elf_path).map_err(|e| {
        anyhow::anyhow!(
            "read {} for agent '{}': {e}",
            elf_path.display(),
            agent.name
        )
    })?;
    let hash = blob_store::cache_put(&elf_bytes)
        .map_err(|e| anyhow::anyhow!("cache blob for '{}': {e}", agent.name))?;

    // 2. Ensure published. Treat the agent's `name` as the
    //    program name; manifests don't carry per-program
    //    versions yet, so we use the literal "manifest" tag.
    let program_name = agent.name.clone();
    let program_version = "manifest".to_string();
    let existing: Option<ProgramRow> =
        vos::block_on(reg.program(&mut &*node, program_name.clone(), program_version.clone()))
            .map_err(|e| anyhow::anyhow!("registry.program('{program_name}'): {e}"))?;
    let program_hash = match existing {
        Some(p) if p.hash == hash.0 => {
            tracing::debug!("{program_name}:{program_version} already published");
            p.hash
        }
        Some(_) => {
            // Tag pinned to a different blob — manifest's blob
            // and registry's disagree. Don't silently overwrite;
            // this is what `space upgrade` is for.
            anyhow::bail!(
                "manifest's '{program_name}:{program_version}' has a different hash than \
                 the catalog. Run `vosx space upgrade {} {program_name}:<new-version>` \
                 explicitly, or remove the agent from the manifest.",
                agent.name,
            );
        }
        None => {
            let status = vos::block_on(reg.publish(
                &mut &*node,
                program_name.clone(),
                program_version.clone(),
                hash.0.to_vec(),
            ))
            .map_err(|e| anyhow::anyhow!("registry.publish('{program_name}'): {e}"))?;
            match status {
                STATUS_OK => {
                    tracing::info!("published {program_name}:{program_version}");
                }
                STATUS_TAG_CONFLICT => {
                    anyhow::bail!("publish conflict on {program_name}:{program_version}");
                }
                other => anyhow::bail!("publish status {other}"),
            }
            hash.0
        }
    };

    // 2b. Forward the program's metadata blob to the registry so
    //     downstream consumers (gateway, schema CLIs) can fetch a
    //     per-method type signature. Idempotent — re-registering
    //     the same hash overwrites. Older binaries built before
    //     `.vos_meta` lands as a section just skip this step;
    //     the registry's `meta_for_*` queries will return empty
    //     and consumers fall back to whatever heuristic they
    //     have today.
    if let Some(meta_blob) = vos::metadata::raw_section_from_elf(&elf_bytes) {
        let status =
            vos::block_on(reg.register_meta(&mut &*node, program_hash.to_vec(), meta_blob))
                .map_err(|e| anyhow::anyhow!("registry.register_meta('{program_name}'): {e}"))?;
        if status != STATUS_OK {
            // Don't fail the install — meta registration is a
            // nice-to-have. Log so a future operator can spot
            // schema drift.
            tracing::warn!(
                "register_meta('{program_name}') returned status {status}; \
                 schema-aware coercion disabled for this agent",
            );
        } else {
            tracing::debug!("registered meta for {program_name}:{program_version}");
        }
    } else {
        tracing::debug!("{program_name}:{program_version} has no .vos_meta section; skipping",);
    }

    // 3. Ensure installed.
    let already_installed = vos::block_on(reg.agent(&mut &*node, agent.name.clone()))
        .map_err(|e| anyhow::anyhow!("registry.agent('{}'): {e}", agent.name))?;
    if already_installed.is_some() {
        tracing::debug!("{} already installed", agent.name);
        return Ok(());
    }

    let consistency = parse_consistency(&agent.consistency).ok_or_else(|| {
        anyhow::anyhow!(
            "agent '{}': unknown consistency '{}', expected ephemeral|local|crdt|raft",
            agent.name,
            agent.consistency,
        )
    })?;

    let replication_id = match agent.replication_id.as_deref() {
        Some("auto") | None => auto_replication_id(&agent.name, &program_hash),
        Some("off") => [0u8; 32],
        Some(hex) => {
            let v = hex::decode(hex.trim_start_matches("0x")).map_err(|_| {
                anyhow::anyhow!("agent '{}': replication_id must be hex", agent.name)
            })?;
            if v.len() != 32 {
                anyhow::bail!("agent '{}': replication_id must be 32 bytes", agent.name);
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            out
        }
    };

    let install_args = encode_init_args(&agent.name, &elf_bytes, &agent.init, name_ids)?;
    let install_payloads = encode_on_start_payloads(&agent.on_start)?;

    let status = vos::block_on(reg.install(
        &mut &*node,
        agent.name.clone(),
        program_name.clone(),
        program_version.clone(),
        program_hash.to_vec(),
        replication_id.to_vec(),
        consistency,
        install_args,
        install_payloads,
    ))
    .map_err(|e| anyhow::anyhow!("registry.install('{}'): {e}", agent.name))?;

    if status != STATUS_OK {
        anyhow::bail!("install '{}' returned status {}", agent.name, status);
    }
    tracing::info!(
        "installed {} (consistency={})",
        agent.name,
        agent.consistency,
    );
    Ok(())
}

/// Encode init args into rkyv bytes, using the actor's
/// `.vos_meta` to type each entry. List-of-string init values
/// whose target type is `Vec<u32>` get translated through
/// `name_ids` so manifest-style `children = ["greeter", …]`
/// resolves to actual ServiceIds.
fn encode_init_args(
    agent_name: &str,
    elf_bytes: &[u8],
    init: &BTreeMap<String, toml::Value>,
    name_ids: &BTreeMap<String, u32>,
) -> anyhow::Result<Vec<u8>> {
    if init.is_empty() {
        return Ok(Vec::new());
    }
    let meta = vos::metadata::from_elf(elf_bytes);
    let mut args = InitArgs::new();
    for (key, val) in init {
        let resolved = resolve_env_indirection(agent_name, key, val)?;
        let ty = meta
            .as_ref()
            .and_then(|m| m.constructor.iter().find(|f| f.name == *key))
            .map(|f| f.ty.as_str())
            .unwrap_or("String");
        args = args.with(key, toml_to_init_value(&resolved, ty, name_ids));
    }
    Ok(vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .map_err(|e| anyhow::anyhow!("encode init args: {e}"))?
        .to_vec())
}

/// Encode each `on_start` entry as a `[TAG_DYNAMIC] + rkyv(Msg)`
/// payload, then hand the resulting `Vec<Vec<u8>>` to
/// `payload_codec::encode` so the registry can store it as a
/// single `Vec<u8>` field on `AgentRow`. `spawn_installed_agents`
/// reverses both layers on cold start.
fn encode_on_start_payloads(on_start: &[OnStartMsg]) -> anyhow::Result<Vec<u8>> {
    use vos::Encode;
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(on_start.len());
    for entry in on_start {
        let mut msg = vos::value::Msg::new(&entry.msg);
        for (k, v) in &entry.args {
            // Same heuristic as `space install --init`: numeric
            // → u64, true/false → bool, else string. Manifest
            // authors who want explicit typing can upgrade to
            // typed init args once we have schemas.
            //
            // Sprint 3: `$env:VAR` strings get resolved here too
            // so on_start payloads can pull secrets out of the
            // container's env without baking them into the
            // manifest.
            let resolved = resolve_env_indirection(&entry.msg, k, v)?;
            match &resolved {
                toml::Value::Integer(n) => msg = msg.with(k, *n as u64),
                toml::Value::Boolean(b) => msg = msg.with(k, *b),
                toml::Value::String(s) => msg = msg.with(k, s.clone()),
                other => {
                    anyhow::bail!(
                        "on_start arg '{k}' has unsupported type {other:?}; \
                         use string, integer, or boolean",
                    );
                }
            }
        }
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payloads.push(payload);
    }
    payload_codec::encode(&payloads)
}

/// Sprint 3 — resolve `$env:VAR` indirection in manifest init
/// values. String values matching `$env:NAME` are looked up in
/// the process environment; everything else passes through
/// unchanged. Used by extension `[[extension]] init = {...}` and
/// agent `[[agent]] init = {...}` paths so container deployments
/// can keep secrets (HF tokens, API keys, …) out of the manifest
/// file itself.
///
/// Error semantics:
/// - `$env:NAME` where `NAME` is unset → `Err(anyhow)` so the
///   daemon refuses to boot rather than passing an empty string
///   to a handler expecting a secret.
/// - `$env:` (no name) → treated as a literal string (operator
///   typo; surface in logs but don't bail).
///
/// String values that *contain* but don't start with `$env:`
/// (e.g. a default value with `$env:` embedded mid-string) pass
/// through verbatim — only the prefix form is special-cased.
fn resolve_env_indirection(
    ext_name: &str,
    key: &str,
    val: &toml::Value,
) -> anyhow::Result<toml::Value> {
    let toml::Value::String(s) = val else {
        return Ok(val.clone());
    };
    let Some(var_name) = s.strip_prefix("$env:") else {
        return Ok(val.clone());
    };
    if var_name.is_empty() {
        // Literal `$env:` with nothing after — treat as a typo,
        // keep as-is.
        return Ok(val.clone());
    }
    match std::env::var(var_name) {
        Ok(resolved) => Ok(toml::Value::String(resolved)),
        Err(_) => anyhow::bail!(
            "extension '{ext_name}': init arg '{key}' references \
             env var ${var_name} but it is not set in the daemon's \
             environment. Set it before `vosx space up`, or remove \
             the `$env:` indirection from the manifest.",
        ),
    }
}

fn toml_to_init_value(val: &toml::Value, ty: &str, name_ids: &BTreeMap<String, u32>) -> InitValue {
    match val {
        toml::Value::String(s) => match ty {
            "u64" | "u32" | "u16" | "u8" => s
                .parse::<u64>()
                .map(InitValue::U64)
                .unwrap_or(InitValue::Str(s.clone())),
            _ => InitValue::Str(s.clone()),
        },
        toml::Value::Integer(n) => match ty {
            "bool" => InitValue::Bool(*n != 0),
            _ => InitValue::U64(*n as u64),
        },
        toml::Value::Boolean(b) => InitValue::Bool(*b),
        toml::Value::Array(items) => {
            // Heuristic: if every entry is a string AND the
            // declared type is `Vec<u32>`, resolve names →
            // ServiceIds via `name_ids`. Otherwise emit a
            // plain ListStr (or empty if mixed types).
            if ty == "Vec<u32>" && items.iter().all(|v| matches!(v, toml::Value::String(_))) {
                let ids: Vec<u32> = items
                    .iter()
                    .filter_map(|v| {
                        let s = v.as_str()?;
                        name_ids.get(s).copied()
                    })
                    .collect();
                InitValue::ListU32(ids)
            } else if items.iter().all(|v| matches!(v, toml::Value::String(_))) {
                let strs: Vec<String> = items
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                InitValue::ListStr(strs)
            } else if items.iter().all(|v| matches!(v, toml::Value::Integer(_))) {
                let ns: Vec<u32> = items
                    .iter()
                    .filter_map(|v| v.as_integer().map(|n| n as u32))
                    .collect();
                InitValue::ListU32(ns)
            } else {
                InitValue::Unit
            }
        }
        _ => InitValue::Unit,
    }
}

/// Walk every agent in the manifest, including nested children.
/// Returned in tree-iteration order (parents before children) so
/// `reconcile` can process them sequentially while `name_ids` is
/// still being built up.
fn flatten(agents: &[AgentDef]) -> Vec<&AgentDef> {
    let mut out = Vec::new();
    for a in agents {
        out.push(a);
        for c in &a.actors {
            out.push(c);
        }
    }
    out
}

fn flat_count(agents: &[AgentDef]) -> usize {
    flatten(agents).len()
}

/// Reject manifests where the same `instance_name` appears in
/// more than one slot — agent + agent, agent + extension, or
/// extension + extension.
///
/// Both `register_at_id` (PVM agents) and `register_extension_at_id`
/// (native extensions) use `instance_service_id(name, prefix)` to
/// pick the daemon-side ServiceId. Identical name → identical id →
/// silent route shadow: the second registration overwrites the
/// first's invoke channel, leaving the first's worker thread
/// orphaned and its inbound traffic redirected to the wrong
/// handler. The registry's `install` catches duplicate agent
/// names (`STATUS_INSTANCE_EXISTS`) but it knows nothing about
/// extensions and nothing about within-extension duplicates;
/// catching the full set manifest-side gives the operator a
/// single clear error before any side-effects land.
fn validate_manifest_names(manifest: &Manifest) -> anyhow::Result<()> {
    use std::collections::BTreeMap;

    // Preserve first-seen order so duplicates list the original
    // declaration kind first. BTreeMap keys sort lexically — fine
    // for an error message; an IndexMap would preserve source
    // order but isn't worth the dep for one-shot validation.
    let mut seen: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    for agent in flatten(&manifest.agents) {
        seen.entry(agent.name.clone()).or_default().push("agent");
    }
    for ext in &manifest.extensions {
        seen.entry(ext.name.clone()).or_default().push("extension");
    }

    let conflicts: Vec<String> = seen
        .iter()
        .filter(|(_, kinds)| kinds.len() > 1)
        .map(|(name, kinds)| format!("'{name}' appears {}× ({})", kinds.len(), kinds.join(", ")))
        .collect();

    if conflicts.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "manifest has duplicate instance_names — both agents and \
         extensions install at a deterministic ServiceId derived \
         from the name, so duplicates silently shadow each other's \
         routes:\n  {}",
        conflicts.join("\n  "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_manifest() {
        let s = r#"
            space = "demo"
            [[agent]]
            name = "counter"
            path = "actors/counter/foo.elf"
            consistency = "crdt"
        "#;
        let m: Manifest = toml::from_str(s).unwrap();
        assert_eq!(m.space.as_deref(), Some("demo"));
        assert_eq!(m.agents.len(), 1);
        assert_eq!(m.agents[0].name, "counter");
        assert_eq!(m.agents[0].consistency, "crdt");
    }

    #[test]
    fn parses_nested_actors() {
        let s = r#"
            [[agent]]
            name = "scheduler"
            path = "agents/scheduler.elf"
            consistency = "ephemeral"
            actors = [
                { name = "greeter", path = "actors/greeter.elf" },
            ]
        "#;
        let m: Manifest = toml::from_str(s).unwrap();
        assert_eq!(m.agents.len(), 1);
        assert_eq!(m.agents[0].actors.len(), 1);
        assert_eq!(m.agents[0].actors[0].name, "greeter");
    }

    #[test]
    fn validate_names_accepts_distinct() {
        let m: Manifest = toml::from_str(
            r#"
                [[agent]]
                name = "counter"
                path = "a.elf"
                [[agent]]
                name = "greeter"
                path = "b.elf"
                [[extension]]
                name = "gateway"
                path = "c.so"
            "#,
        )
        .unwrap();
        validate_manifest_names(&m).expect("distinct names pass");
    }

    #[test]
    fn validate_names_rejects_agent_extension_clash() {
        // The headline case — operator names both an agent and an
        // extension `gateway`. They'd install at the same
        // `instance_service_id(name, prefix)`, second silently
        // shadows the first.
        let m: Manifest = toml::from_str(
            r#"
                [[agent]]
                name = "gateway"
                path = "a.elf"
                [[extension]]
                name = "gateway"
                path = "b.so"
            "#,
        )
        .unwrap();
        let err = validate_manifest_names(&m).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'gateway'"), "{msg}");
        assert!(msg.contains("agent") && msg.contains("extension"), "{msg}");
    }

    #[test]
    fn validate_names_rejects_duplicate_extensions() {
        let m: Manifest = toml::from_str(
            r#"
                [[extension]]
                name = "gateway"
                path = "a.so"
                [[extension]]
                name = "gateway"
                path = "b.so"
            "#,
        )
        .unwrap();
        let err = validate_manifest_names(&m).unwrap_err();
        assert!(err.to_string().contains("'gateway' appears 2×"), "{}", err);
    }

    #[test]
    fn validate_names_rejects_duplicate_agents() {
        // The registry's `install` handler returns
        // STATUS_INSTANCE_EXISTS for this case at runtime, but
        // the manifest-side check fails earlier — before any
        // .elf gets blob-cached or any partial registration
        // lands.
        let m: Manifest = toml::from_str(
            r#"
                [[agent]]
                name = "counter"
                path = "a.elf"
                [[agent]]
                name = "counter"
                path = "b.elf"
            "#,
        )
        .unwrap();
        let err = validate_manifest_names(&m).unwrap_err();
        assert!(err.to_string().contains("'counter' appears 2×"), "{}", err);
    }

    #[test]
    fn validate_names_catches_nested_child_collision() {
        // `flatten` walks parent + child agents; a child named
        // the same as a top-level agent is a collision too.
        let m: Manifest = toml::from_str(
            r#"
                [[agent]]
                name = "scheduler"
                path = "s.elf"
                actors = [
                    { name = "scheduler", path = "dup.elf" },
                ]
            "#,
        )
        .unwrap();
        let err = validate_manifest_names(&m).unwrap_err();
        assert!(err.to_string().contains("'scheduler'"), "{}", err);
    }

    #[test]
    fn flatten_yields_parents_then_children() {
        let m: Manifest = toml::from_str(
            r#"
                [[agent]]
                name = "scheduler"
                path = "x.elf"
                actors = [
                    { name = "a", path = "a.elf" },
                    { name = "b", path = "b.elf" },
                ]
                [[agent]]
                name = "outer"
                path = "y.elf"
            "#,
        )
        .unwrap();
        let flat: Vec<&str> = flatten(&m.agents).iter().map(|a| a.name.as_str()).collect();
        assert_eq!(flat, vec!["scheduler", "a", "b", "outer"]);
    }

    #[test]
    fn vec_u32_init_resolves_names_to_ids() {
        let mut name_ids = BTreeMap::new();
        name_ids.insert("alpha".to_string(), 0xC0DE_0001);
        name_ids.insert("beta".to_string(), 0xC0DE_0002);
        let val = toml::Value::Array(vec![
            toml::Value::String("alpha".into()),
            toml::Value::String("beta".into()),
        ]);
        match toml_to_init_value(&val, "Vec<u32>", &name_ids) {
            InitValue::ListU32(ids) => assert_eq!(ids, vec![0xC0DE_0001, 0xC0DE_0002]),
            other => panic!("expected ListU32, got {other:?}"),
        }
    }

    #[test]
    fn unknown_names_are_dropped_when_resolving_to_u32() {
        let name_ids = BTreeMap::new();
        let val = toml::Value::Array(vec![toml::Value::String("ghost".into())]);
        // No name_ids entry for "ghost" → empty ListU32 rather
        // than panicking. The actor will see an empty list and
        // can decide what to do.
        match toml_to_init_value(&val, "Vec<u32>", &name_ids) {
            InitValue::ListU32(ids) => assert!(ids.is_empty()),
            other => panic!("expected ListU32, got {other:?}"),
        }
    }

    // ── Sprint 3: $env:VAR indirection ──────────────────────

    /// Use a per-test process-unique env-var name so concurrent
    /// tests don't race on the same key. We unset on Drop so
    /// stale state doesn't leak across tests.
    struct EnvGuard {
        key: String,
    }
    impl EnvGuard {
        fn new(label: &str, value: &str) -> Self {
            let key = format!(
                "VOSX_RECONCILE_TEST_{}_{}_{}",
                std::process::id(),
                label,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            );
            // SAFETY: tests in this crate run single-threaded
            // per the suite layout; we restore by remove on drop.
            unsafe {
                std::env::set_var(&key, value);
            }
            Self { key }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: pair with the set above.
            unsafe {
                std::env::remove_var(&self.key);
            }
        }
    }

    #[test]
    fn env_indirection_resolves_set_var() {
        let guard = EnvGuard::new("set_var", "s3cr3t");
        let val = toml::Value::String(format!("$env:{}", guard.key));
        let resolved = resolve_env_indirection("ai", "hf_token", &val).expect("set var resolves");
        assert_eq!(resolved.as_str(), Some("s3cr3t"));
    }

    #[test]
    fn env_indirection_errors_on_unset_var() {
        // Use a fresh non-existent name (no EnvGuard set).
        let nonexistent = format!(
            "VOSX_RECONCILE_NEVER_SET_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        let val = toml::Value::String(format!("$env:{nonexistent}"));
        let err =
            resolve_env_indirection("ai", "hf_token", &val).expect_err("unset var must error");
        let msg = format!("{err}");
        // Sprint 5: error contract — the operator needs (a) the
        // unset *var name*, (b) the extension + key context so
        // they can find it in the manifest, and (c) a clear cause
        // and remediation hint. Any one of these going missing
        // means a refactor silently degraded the error.
        assert!(
            msg.contains(&nonexistent),
            "error must name the unset var ({nonexistent}); got: {msg}",
        );
        assert!(
            msg.contains("ai"),
            "error must name the extension (ai); got: {msg}",
        );
        assert!(
            msg.contains("hf_token"),
            "error must name the init key (hf_token); got: {msg}",
        );
        assert!(
            msg.contains("is not set"),
            "error must state the cause (not set); got: {msg}",
        );
        assert!(
            msg.contains("vosx space up") || msg.contains("Set it"),
            "error should include a remediation hint; got: {msg}",
        );
    }

    #[test]
    fn env_indirection_unset_var_error_propagates_through_init_loop() {
        // The unit error above is the local contract. This guards
        // the *call site* — `resolve_env_indirection` is invoked
        // from a `for (k, v) in &ext.init { ?; }` loop, and the
        // anyhow result must bubble up unchanged so the caller can
        // surface it as a refuse-to-boot. Simulates the loop body.
        let nonexistent = format!(
            "VOSX_RECONCILE_BUBBLES_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        let init: Vec<(String, toml::Value)> = vec![
            ("region".into(), toml::Value::String("us-east-1".into())),
            (
                "hf_token".into(),
                toml::Value::String(format!("$env:{nonexistent}")),
            ),
        ];
        let mut resolved_first = false;
        let result: anyhow::Result<()> = (|| {
            for (k, v) in &init {
                let r = resolve_env_indirection("ai", k, v)?;
                if k == "region" {
                    assert_eq!(r.as_str(), Some("us-east-1"));
                    resolved_first = true;
                }
            }
            Ok(())
        })();
        assert!(
            resolved_first,
            "literal init args before $env:UNSET must still resolve"
        );
        let err = result.expect_err("unset var must abort the loop");
        let msg = format!("{err}");
        assert!(msg.contains(&nonexistent) && msg.contains("hf_token"));
    }

    #[test]
    fn env_indirection_passes_through_literal_string() {
        let val = toml::Value::String("plain-literal".into());
        let out = resolve_env_indirection("ai", "k", &val).expect("literal passthrough");
        assert_eq!(out.as_str(), Some("plain-literal"));
    }

    #[test]
    fn env_indirection_passes_through_non_strings() {
        for val in [
            toml::Value::Integer(42),
            toml::Value::Boolean(true),
            toml::Value::Array(vec![]),
        ] {
            let out = resolve_env_indirection("ai", "k", &val).expect("non-string passthrough");
            assert_eq!(format!("{out:?}"), format!("{val:?}"));
        }
    }

    #[test]
    fn env_indirection_tolerates_bare_marker() {
        // `$env:` with nothing after — operator typo; keep as
        // literal so they see the bad value in the actor logs
        // instead of a fatal error during reconcile.
        let val = toml::Value::String("$env:".into());
        let out = resolve_env_indirection("ai", "k", &val).expect("bare marker passthrough");
        assert_eq!(out.as_str(), Some("$env:"));
    }

    #[test]
    fn env_indirection_only_prefix_form_special() {
        let guard = EnvGuard::new("mid", "ignored");
        // Embedded $env: in the middle of the string is NOT
        // special — only the prefix form is resolved.
        let val = toml::Value::String(format!("prefix-$env:{}-suffix", guard.key));
        let out = resolve_env_indirection("ai", "k", &val).expect("mid-string passthrough");
        let s = out.as_str().unwrap();
        assert!(
            s.contains(&format!("$env:{}", guard.key)),
            "mid-string $env: must NOT be expanded; got: {s}",
        );
    }
}
