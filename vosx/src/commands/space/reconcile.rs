//! Recipe → registry reconciliation.
//!
//! The recipe parser and in-process genesis installer. Reads a
//! recipe TOML, walks every `[[agent]]` (and nested `actors`
//! children), and ensures the registry catalog reflects what the
//! recipe declares. Consumed by `space apply` (against a running
//! space) and by the genesis apply that runs on a space's first
//! `space up`:
//!
//! - Each `path = "…"` ELF gets blob-cached and published as
//!   `<name>:recipe` if not already in the catalog.
//! - Each agent gets `install()`'d if no instance with that
//!   `name` is already registered.
//! - Agents already in the registry are left alone (their
//!   state takes precedence over the recipe). An explicit
//!   `space upgrade` is required to re-point at a different
//!   blob.
//!
//! Recipes are dev-time conveniences — the registry stays
//! the runtime source of truth. This module's only job is to
//! arrange the registry once on startup; after that, `space
//! up` proceeds normally and spawns whatever the registry says
//! is installed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use vos::registry::{ProgramRow, RegistryRef, Status};
use vos::abi::service::ServiceId;
use vos::init::{InitArgs, InitValue};
use vos::node::{ExtensionConfig, VosNode};
use vos::value::Args;

use crate::blob_store;
use crate::commands::space::common::{auto_replication_id, instance_service_id, parse_consistency};
use crate::commands::space::payload_codec;

/// Slim view of the recipe TOML — only the fields the
/// reconciler cares about. Extra fields are silently ignored
/// so recipes can carry whatever annotations they want.
#[derive(Deserialize, Debug, Default)]
pub struct Recipe {
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
    /// Hyperspace this space belongs to. When set, the daemon
    /// additionally spawns a registry replica into the
    /// hyperspace's replication group so cross-space `resolve`
    /// can fall through. See `derive_hyperspace_id` for the
    /// replication-id derivation. Wired up in Phase 1.3 of the
    /// hyperspace runtime; for now the parser just round-trips it.
    #[allow(dead_code)]
    pub hyperspace: Option<String>,
    #[serde(rename = "agent", default)]
    pub agents: Vec<AgentDef>,
    /// Native `.so` extension plugins. Each `[[extension]]` entry
    /// in a recipe maps onto a single `node.register_extension`
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
    /// Path to the `.so` — relative to the recipe file's
    /// directory.
    pub path: String,
    /// Constructor args. Encoded as a rkyv `vos::value::Args`
    /// which the extension's `fn new(args: &[u8])` parses. Strings,
    /// ints, and bools all flow through as-is; richer types
    /// (Vec<u32> name-list, etc.) come later if needed.
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
    /// Sprint 2: per-extension override of the space-level
    /// [`Recipe::cap_policy`]. Useful for relaxing one
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
    /// Declared intra-system capabilities — `"actor:role"` strings
    /// bounding what this extension may relay to other actors. Empty
    /// (the default) denies all role-gated relays: outbound calls
    /// reach their target as `Caller::Unauthenticated`. See
    /// [`vos::IntraCap`] for wildcard semantics. Malformed entries
    /// fail the boot (parsed eagerly in `register_extension`) rather
    /// than silently dropping authority bounds.
    #[serde(default)]
    pub intra_caps: Vec<String>,
    /// Periodic `tick` interval in milliseconds. When set
    /// (and > 0), the host calls the extension's `tick` handler roughly this
    /// often, between inbound work — the actor-mode way to originate periodic
    /// work (a heartbeat ping, a cache sweep). Omitted / `0` → no ticking.
    pub tick_ms: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
pub struct AgentDef {
    pub name: String,
    /// Path to the actor ELF — relative to the recipe file's
    /// directory. A hand-written recipe carries this; a `space export`
    /// output does NOT (blobs are content-addressed, with no source
    /// path on a running node) and instead carries `program_hash`, so
    /// `apply` resolves the blob by hash. Empty when absent.
    #[serde(default)]
    pub path: String,
    /// `name:version` of the already-published program (emitted by
    /// `space export`). When absent, the program name is the agent name
    /// and the version is the recipe tag.
    #[serde(default)]
    pub program: Option<String>,
    /// Hex blob hash of an already-published program (emitted by `space
    /// export`). Lets `apply` resolve the blob without a source `path` —
    /// the precondition for `export | apply --diff` being all-skips.
    #[serde(default)]
    pub program_hash: Option<String>,
    /// `ephemeral` / `local` / `crdt` / `raft`. Defaults to
    /// `crdt` for replicated actors; recipes that omit this
    /// for one-off services typically want `ephemeral`.
    #[serde(default = "default_consistency")]
    pub consistency: String,
    /// Opt a network-served but node-confined (`local`/`ephemeral`) agent OUT
    /// of the device-confinement gate so remote peers can reach it — for the
    /// cross-bank `clerk-bridge` and cross-space `space-bridge`. `false`
    /// (confined, device-private) by default; `crdt`/`raft` agents are never
    /// confined and ignore it.
    #[serde(default)]
    pub network_reachable: bool,
    /// Serving-side sync floor: `public` | `member` | `private`.
    /// Omitted → `member` (served to space members). Drives who this
    /// replica's state is served to and the default spawn set.
    #[serde(default)]
    pub sync: Option<String>,
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
    /// Provision a device-local secret seed into this agent (the
    /// messenger's MLS CSPRNG root). The daemon mints 32 bytes of OS
    /// entropy into a node-local `{svc_id}.seed` sidecar on first spawn and
    /// sends it via a `seed` message (`Caller::System`), re-sent idempotently
    /// on every restart. Node-LOCAL by design: unlike `on_start`/`init` (which
    /// ride the replicated `AgentRow`), this never touches the registry, so the
    /// secret never leaves the node. Only meaningful for `consistency = "local"`
    /// agents that expose a `seed(Vec<u8>)` handler.
    #[serde(default)]
    pub device_secret: bool,
    /// Periodic `tick` interval in milliseconds — the host dispatches a
    /// synthetic `tick` to this agent's `tick` handler about this often,
    /// between inbound work (the agent analogue of an extension's
    /// `tick_ms`). Node-local policy; only set it on agents with a `tick`
    /// handler. Omitted / 0 → no ticking.
    pub tick_ms: Option<u64>,
    /// Declared intra-system capabilities — `"actor:role"` strings bounding
    /// what this agent may relay to other actors on its OUTBOUND invokes.
    /// Node-local policy (never the replicated `AgentRow`). Empty (the
    /// default) keeps the legacy trusted relay (outbound calls are
    /// `Caller::Actor`, bypassing role gates); a non-empty list opts the
    /// agent into bounded relay (the real caller's role capped per cap),
    /// mirroring an extension's `intra_caps`.
    #[serde(default)]
    pub intra_caps: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct OnStartMsg {
    /// Message handler name to invoke.
    pub msg: String,
    /// Remaining keys are typed args. `flatten` so the recipe
    /// can write `{ msg = "set", val = 42 }` without nesting.
    #[serde(flatten, default)]
    pub args: BTreeMap<String, toml::Value>,
}

fn default_consistency() -> String {
    "crdt".to_string()
}

/// Resolve an extension's `.so` path against the recipe dir,
/// build init args (rkyv `Args`), and hand off to
/// `node.register_extension`. Logs the load + each init arg so
/// operators can spot misconfigured recipes at boot.
///
/// Also pulls the `.so`'s `vos_extension_meta` blob out via a one-
/// shot `ExtensionPlugin::load` and forwards it to the registry's
/// `register_extension_meta` keyed by the recipe instance name.
/// `vosx <ext> <cmd>` reads back through the same name to
/// drive its dynamic clap surface. Double-loading the .so here is
/// trivial: cdylibs are small and meta extraction doesn't run any
/// extension code.
pub(crate) fn register_extension(
    node: &mut VosNode,
    reg: &RegistryRef,
    ext: &ExtensionDef,
    recipe_dir: &Path,
    daemon_prefix: u16,
    space_cap_policy: vos::extension::CapPolicy,
    known_names: &std::collections::HashSet<String>,
) -> anyhow::Result<Vec<String>> {
    let so_path = recipe_dir.join(&ext.path);
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
    // SAFETY: dlopen on a vos-built extension .so; the recipe's
    // path is operator-supplied. See `vos::extension::ExtensionPlugin::load`
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

    // Parse declared intra-system caps eagerly: a malformed entry is
    // a boot failure naming the offending token, not a silent loss of
    // an authority bound.
    let mut intra_caps = Vec::with_capacity(ext.intra_caps.len());
    for tok in &ext.intra_caps {
        let cap = vos::IntraCap::parse(tok)
            .map_err(|e| anyhow::anyhow!("extension '{}': {e}", ext.name))?;
        intra_caps.push(cap);
    }
    if ext.relay_unauthenticated && !intra_caps.is_empty() {
        tracing::warn!(
            "extension '{}': relay_unauthenticated=true overrides intra_caps \
             ({} declared) — a relay has no authority of its own, so the caps \
             are ignored",
            ext.name,
            intra_caps.len(),
        );
    }

    // M4 — operator visibility. `intra_caps` are host-side daemon
    // config (not replicated registry state). Render the *effective*
    // caps (relay mode collapses to none) for the boot log, warn
    // loudly on footgun wildcards, and capture the canonical tokens to
    // return — the caller stamps them into the local endpoint
    // descriptor so `space describe` / `space caps` can surface them
    // without scraping the log.
    let effective_caps: &[vos::IntraCap] = if ext.relay_unauthenticated {
        &[]
    } else {
        &intra_caps
    };
    let effective_tokens: Vec<String> = effective_caps.iter().map(|c| c.to_string()).collect();
    tracing::info!(
        "extension '{}' intra_caps: {}",
        ext.name,
        render_intra_caps(effective_caps),
    );
    if let Some(warning) = intra_caps_wildcard_warning(&ext.name, effective_caps) {
        tracing::warn!("{warning}");
    }
    if let Some(warning) = unresolvable_cap_warning(&ext.name, effective_caps, known_names) {
        tracing::warn!("{warning}");
    }

    let cfg = if ext.init.is_empty() {
        ExtensionConfig::new(&so_path).with_cap_policy(cap_policy)
    } else {
        ExtensionConfig::with_args(&so_path, &args).with_cap_policy(cap_policy)
    };
    // Record the instance name so the host's reverse map can resolve
    // this extension's ServiceId — letting it be the *target* of a
    // named intra_cap or an actor-local grant.
    let cfg = cfg.with_name(ext.name.clone());
    let cfg = if ext.relay_unauthenticated {
        cfg.relay_unauthenticated()
    } else {
        cfg.with_intra_caps(intra_caps)
    };

    // Periodic `tick` cadence. `with_tick_ms` treats 0 as off.
    let cfg = match ext.tick_ms {
        Some(ms) if ms > 0 => {
            tracing::info!("extension '{}' tick_ms = {}", ext.name, ms);
            cfg.with_tick_ms(ms)
        }
        _ => cfg,
    };

    // A transport-mode extension (the http-gateway) has the
    // HOST own its listener + accept loop. Pull bind_addr/port (+ optional
    // TLS PEM paths) out of the init args and hand them to `serves(..)` so
    // the host binds the socket + terminates TLS for it, then drives one
    // `handle_connection` task per accepted connection. (Backpressure is
    // the host's `serves_max_conns` default of 1024.)
    let cfg = match plugin.as_ref().map(|p| p.kind()) {
        Some(vos::extension::ExtensionKind::Transport) => {
            configure_transport_serves(cfg, ext, recipe_dir)?
        }
        _ => cfg,
    };

    // Install at a *deterministic* ServiceId derived from the
    // extension's recipe name + daemon prefix, identical to the
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
        // Empty `auth`: the daemon signs on relay with the operator key
        // (see the catalog mutators). A non-admin node's metadata write
        // is refused and arrives via sync instead — non-fatal below.
        let status = vos::block_on(reg.register_extension_meta(
            &mut &*node,
            ext.name.clone(),
            meta_blob,
            Vec::new(),
        ))
        .map_err(|e| anyhow::anyhow!("registry.register_extension_meta('{}'): {e}", ext.name))?;
        if status != Status::Ok {
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

    Ok(effective_tokens)
}

/// Configure a transport-mode extension's host-owned listener from its
/// Init args. `bind_addr` (default `127.0.0.1`) + `port`
/// (default `8080`) become the `serves(..)` endpoint; `tls_cert`/`tls_key`
/// (relative to the recipe dir, or absolute) — when both are set — make
/// the host terminate TLS on each accepted connection. The extension's
/// own `new()` still receives the full init args (for `auth_token` /
/// `agent_tokens` / its `/__status` port readout).
fn configure_transport_serves(
    cfg: ExtensionConfig,
    ext: &ExtensionDef,
    recipe_dir: &Path,
) -> anyhow::Result<ExtensionConfig> {
    let init_str = |k: &str| ext.init.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    let bind_addr = {
        let b = init_str("bind_addr");
        if b.is_empty() { "127.0.0.1" } else { b }
    };
    let port = ext
        .init
        .get("port")
        .and_then(|v| v.as_integer())
        .unwrap_or(8080);
    let addr = format!("{bind_addr}:{port}");

    let tls_cert = init_str("tls_cert");
    let tls_key = init_str("tls_key");
    let tls = !tls_cert.is_empty() && !tls_key.is_empty();
    let cfg = cfg.serves(addr, tls);

    if tls {
        let cert_path = recipe_dir.join(tls_cert);
        let key_path = recipe_dir.join(tls_key);
        let cert_pem = std::fs::read(&cert_path).map_err(|e| {
            anyhow::anyhow!(
                "extension '{}': reading tls_cert {}: {e}",
                ext.name,
                cert_path.display(),
            )
        })?;
        let key_pem = std::fs::read(&key_path).map_err(|e| {
            anyhow::anyhow!(
                "extension '{}': reading tls_key {}: {e}",
                ext.name,
                key_path.display(),
            )
        })?;
        tracing::info!(
            "extension '{}': host-terminated TLS on {bind_addr}:{port}",
            ext.name,
        );
        Ok(cfg.tls_pem(cert_pem, key_pem))
    } else {
        Ok(cfg)
    }
}

/// Render an extension's declared intra_caps for the operator-facing
/// boot log. Empty renders an explicit "(none …)" so the operator
/// sees the deny-by-default posture rather than silence.
fn render_intra_caps(caps: &[vos::IntraCap]) -> String {
    if caps.is_empty() {
        return "(none — outbound calls relay as Unauthenticated)".to_string();
    }
    caps.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A loud warning when an extension's caps include an any-actor
/// wildcard — it can then relay to *every* actor, which defeats the
/// per-extension scoping the cap model exists for. Returns the
/// warning text (naming the extension), or `None` for named-only caps.
fn intra_caps_wildcard_warning(name: &str, caps: &[vos::IntraCap]) -> Option<String> {
    let full = caps.iter().any(|c| c.is_full_wildcard());
    let actor_wild = caps.iter().any(|c| c.is_actor_wildcard());
    // A prefix cap with a `*` role ("msg-*:*") is the same footgun
    // one namespace down: uncapped (Admin-ceiling) relay across
    // every actor matching the prefix, present and future.
    let prefix_uncapped = caps.iter().any(|c| c.is_actor_prefix() && c.role.is_none());
    if !actor_wild && !prefix_uncapped {
        return None;
    }
    let detail = if full {
        "'*' / '*:*' grants ANY role on ANY actor — the extension becomes a fully-trusted relay"
    } else if actor_wild {
        "a '*:<role>' cap grants that role on EVERY actor in the space"
    } else {
        "a '<prefix>*:*' cap grants ANY role (Admin ceiling) on every actor matching the \
         prefix — including ones installed later"
    };
    Some(format!(
        "extension '{name}': intra_caps wildcard is a footgun — {detail}. \
         Name each target actor explicitly instead.",
    ))
}

/// Warn when an extension declares a cap for a *named* actor the host
/// can't resolve at dispatch time. v1 maps only the well-known
/// `space-registry` target id back to a name, so a named cap for any
/// other actor is silently never matched (the relay falls back to
/// `Unauthenticated`). Surfacing it at boot keeps a typo'd or
/// premature cap from vanishing without the operator noticing. `*`
/// (wildcard-actor) caps always match, so they're exempt.
/// Warn about named `intra_cap` targets that don't correspond to any
/// actor this space installs. R3 made the host resolve *any* installed
/// agent or extension by name (via its reverse map), so the host can no
/// longer say in isolation whether a name is resolvable — the authority
/// is the recipe's own roster. `known_names` is that roster (every
/// agent + extension instance name, plus the built-in `space-registry`,
/// compared case-insensitively to match [`vos::IntraCap`]'s matching).
/// A named cap outside it is almost certainly a typo: it will silently
/// relay as `Unauthenticated`, so we flag it at boot. Wildcard-actor
/// caps (`*:<role>`) match anything and are never flagged; trailing-`*`
/// prefix caps (`msg-*:<role>`) are forward-looking grants for agents
/// installed after boot, so the recipe roster can't falsify them —
/// also exempt.
fn unresolvable_cap_warning(
    name: &str,
    caps: &[vos::IntraCap],
    known_names: &std::collections::HashSet<String>,
) -> Option<String> {
    let known_lc: std::collections::HashSet<String> =
        known_names.iter().map(|n| n.to_ascii_lowercase()).collect();
    let mut unresolved: Vec<&str> = caps
        .iter()
        .filter(|c| !c.is_actor_wildcard() && !c.is_actor_prefix())
        .filter_map(|c| c.actor_name.as_deref())
        .filter(|n| !known_lc.contains(&n.to_ascii_lowercase()))
        .collect();
    if unresolved.is_empty() {
        return None;
    }
    unresolved.sort_unstable();
    unresolved.dedup();
    Some(format!(
        "extension '{name}': intra_caps name actor(s) this space doesn't install ({}) — likely \
         a typo. These caps won't bind: calls to those actors relay as Unauthenticated. Name an \
         installed agent/extension, or use a wildcard (\"*:<role>\") to grant authority broadly.",
        unresolved.join(", "),
    ))
}

pub fn parse_recipe_file(path: &Path) -> anyhow::Result<(Recipe, PathBuf)> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let recipe: Recipe = toml::from_str(std::str::from_utf8(&bytes)?)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
    let dir = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((recipe, dir))
}

/// Install every recipe agent into the in-process registry (the
/// *replicated* half of a recipe). Extensions are node-local and are
/// handled separately from `local.toml` at boot, so this path is
/// agent-only — the genesis apply `space up` runs when it consumes a
/// pending recipe. `node` must already have the registry registered
/// locally (so `&mut &node` drives in-process Ref calls).
pub(crate) fn install_agents(
    node: &mut VosNode,
    recipe: &Recipe,
    recipe_dir: &Path,
    daemon_prefix: u16,
    space_id: &[u8; 32],
) -> anyhow::Result<()> {
    validate_recipe_names(recipe)?;

    let reg = RegistryRef::at(ServiceId::new(
        daemon_prefix,
        ServiceId::REGISTRY.local_id(),
    ));

    if recipe.agents.is_empty() {
        return Ok(());
    }
    tracing::info!(
        "genesis apply ({} agent definition(s))",
        flat_count(&recipe.agents),
    );

    // Pre-compute every agent's name → derived svc_id so
    // init-arg resolution (e.g. `children = ["greeter"]` →
    // Vec<u32>) can hand back the right ids without round-
    // tripping through the registry.
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    for a in flatten(&recipe.agents) {
        name_ids.insert(
            a.name.clone(),
            instance_service_id(&a.name, daemon_prefix).0,
        );
    }

    // Is this daemon the space's admin authoring node? True when its
    // operator is the genesis root or holds an ADMIN grant. The daemon
    // signs catalog ops on relay with the operator key; on an admin node
    // a Status::Forbidden therefore means the signer can't author (key
    // absent/unreadable/wrong) — a misconfiguration to surface loudly,
    // NOT the benign "non-admin joiner awaiting sync" case. (A node that
    // is the admin machine but loaded the wrong key reads as non-admin
    // here — unavoidable from the registry's view — so the tolerated-path
    // log points at that possibility rather than asserting non-admin.)
    let node_is_admin = match node.operator_peer().map(<[u8]>::to_vec) {
        Some(op) => {
            let root = vos::block_on(reg.root(&mut &*node)).unwrap_or_default();
            (!root.is_empty() && root == op)
                || vos::block_on(reg.peer_role(&mut &*node, op)).unwrap_or(0)
                    == vos::registry::AUTH_ROLE_ADMIN
        }
        None => false,
    };

    for agent in flatten(&recipe.agents) {
        reconcile_one(
            node,
            &reg,
            agent,
            recipe_dir,
            daemon_prefix,
            &name_ids,
            node_is_admin,
            space_id,
        )?;
    }

    Ok(())
}

fn reconcile_one(
    node: &VosNode,
    reg: &RegistryRef,
    agent: &AgentDef,
    recipe_dir: &Path,
    _daemon_prefix: u16,
    name_ids: &BTreeMap<String, u32>,
    node_is_admin: bool,
    space_id: &[u8; 32],
) -> anyhow::Result<()> {
    // 1. Resolve and cache the agent's blob. Genesis recipes carry a
    //    `path`; the path-less `program_hash` form is `apply`-only.
    if agent.path.is_empty() {
        anyhow::bail!(
            "recipe agent '{}' has no `path` — a genesis-applied recipe installs from source \
             ELFs. (The path-less `program_hash` form is only for `space apply` against an \
             already-published catalog.)",
            agent.name,
        );
    }
    let elf_path = recipe_dir.join(&agent.path);
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
    //    program name; recipes don't carry per-program
    //    versions yet, so we use the literal "recipe" tag.
    let program_name = agent.name.clone();
    let program_version = "recipe".to_string();
    let existing: Option<ProgramRow> =
        vos::block_on(reg.program(&mut &*node, program_name.clone(), program_version.clone()))
            .map_err(|e| anyhow::anyhow!("registry.program('{program_name}'): {e}"))?;
    let program_hash = match existing {
        Some(p) if p.hash == hash.0 => {
            tracing::debug!("{program_name}:{program_version} already published");
            p.hash
        }
        Some(_) => {
            // Tag pinned to a different blob — recipe's blob
            // and registry's disagree. Don't silently overwrite;
            // this is what `space upgrade` is for.
            anyhow::bail!(
                "recipe's '{program_name}:{program_version}' has a different hash than \
                 the catalog. Run `vosx space upgrade {} {program_name}:<new-version>` \
                 explicitly, or remove the agent from the recipe.",
                agent.name,
            );
        }
        None => {
            // Empty `auth`: the daemon signs catalog mutations on relay
            // with its operator key. On the admin (operator) node that
            // signature authorizes the op; on a joined non-admin node it
            // doesn't, yielding Status::Forbidden — which is expected, the
            // row arrives via registry sync instead (handled below).
            let status = vos::block_on(reg.publish(
                &mut &*node,
                program_name.clone(),
                program_version.clone(),
                hash.0.to_vec(),
                Vec::new(),
            ))
            .map_err(|e| anyhow::anyhow!("registry.publish('{program_name}'): {e}"))?;
            match status {
                Status::Ok => {
                    tracing::info!("published {program_name}:{program_version}");
                }
                Status::Forbidden if node_is_admin => {
                    // This node IS the space admin, yet the daemon's
                    // on-relay signature was refused — the operator key
                    // can't author catalog ops. Fail loud rather than
                    // silently install nothing (no peer will supply the
                    // rows for the authoring node).
                    anyhow::bail!(
                        "publish '{program_name}:{program_version}' refused (Status::Forbidden) on \
                         the space-admin node — the operator key cannot author registry ops. \
                         Check that the correct identity.key is loaded and matches the space root."
                    );
                }
                Status::Forbidden => {
                    // Not authored locally: this node isn't the space
                    // admin, so the program row is signed on the admin's
                    // node and replicates here via CRDT sync. Proceed to
                    // install (likewise tolerant) so the agent spawns
                    // once the synced rows land.
                    tracing::debug!(
                        "publish {program_name}:{program_version} not authored locally; awaiting \
                         registry sync (if this should be the admin node, check identity.key)",
                    );
                }
                Status::TagConflict => {
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
        // Meta registration is a nice-to-have (it enables schema-aware
        // coercion for the gateway / dynamic CLIs); it must never abort the
        // install. Both a non-Ok status (e.g. FORBIDDEN on a non-admin node —
        // the row arrives via sync) and a transport failure (e.g. a large
        // `.vos_meta` that overflows the registry guest's FETCH buffer) are
        // tolerated: log and move on, agent still spawns without a schema.
        // Empty `auth`: signed on relay by the daemon (operator key).
        match vos::block_on(reg.register_meta(&mut &*node, program_hash.to_vec(), meta_blob, Vec::new())) {
            Ok(Status::Ok) => {
                tracing::debug!("registered meta for {program_name}:{program_version}");
            }
            Ok(status) => tracing::warn!(
                "register_meta('{program_name}') returned status {status}; \
                 schema-aware coercion disabled for this agent",
            ),
            Err(e) => tracing::warn!(
                "register_meta('{program_name}') did not reach the registry ({e}); \
                 schema-aware coercion disabled for this agent",
            ),
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
        Some("auto") | None => auto_replication_id(space_id, &agent.name, &program_hash),
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

    let sync_role = match agent.sync.as_deref() {
        Some(s) => vos::registry::SyncFloor::parse(s).ok_or_else(|| {
            anyhow::anyhow!(
                "agent '{}': unknown sync floor '{}', expected public|member|private",
                agent.name,
                s,
            )
        })?,
        None => vos::registry::SyncFloor::Member,
    };

    let install_args = encode_init_args(&agent.name, &elf_bytes, &agent.init, name_ids)?;
    let install_payloads = encode_on_start_payloads(&agent.on_start)?;

    // Empty `auth`: the daemon signs on relay (see the publish call
    // above). Status::Forbidden here means this isn't the admin node, so
    // the agent row is authored on the operator's node and arrives via
    // sync — tolerated the same way as Status::InstanceExists below.
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
        agent.network_reachable,
        sync_role,
        Vec::new(),
    ))
    .map_err(|e| anyhow::anyhow!("registry.install('{}'): {e}", agent.name))?;

    // A joining node's registry replica may already carry this
    // agent (the creator installed it and it arrived via CRDT sync
    // before — or during — this reconcile). `install` is not
    // idempotent in the registry; it reports Status::InstanceExists.
    // That's the agent already being present, which is exactly the
    // post-condition we want, so treat it as success and proceed to
    // spawn. Only an unexpected status is fatal.
    if status == Status::InstanceExists {
        tracing::info!(
            "agent {} already installed (synced from a peer) — reusing",
            agent.name,
        );
        return Ok(());
    }
    if status == Status::Forbidden {
        if node_is_admin {
            // The admin node's own signature was refused → the operator
            // key can't author. Surface it instead of silently failing
            // to install (this node authors the rows; no peer supplies
            // them).
            anyhow::bail!(
                "install '{}' refused (Status::Forbidden) on the space-admin node — the operator \
                 key cannot author registry ops. Check that the correct identity.key is loaded \
                 and matches the space root.",
                agent.name,
            );
        }
        // Not the admin node: the agent row is installed + signed on the
        // admin's node and replicates here. The runtime reconcile pass
        // spawns the agent once the synced row + program blob land.
        tracing::info!(
            "agent {} not authored locally — awaiting registry sync (if this should be the admin \
             node, check identity.key matches the space root)",
            agent.name,
        );
        return Ok(());
    }
    if status == vos::registry::Status::ReplicationIdReused {
        // The `replication_id` is a retired anti-replay tombstone — this
        // agent (or one with the same auto-derived id) was installed and
        // uninstalled before, and an `auto`/fixed id can't be reused.
        // Don't resurrect it from a stale slot; surface it so the
        // operator either removes it from the recipe or assigns a
        // fresh `replication_id` (which is a fresh, empty state).
        tracing::warn!(
            "agent {} not (re)installed: its replication_id is a retired tombstone (was \
             uninstalled). Assign a fresh `replication_id` in the recipe to re-create it with \
             clean state, or remove it from the recipe.",
            agent.name,
        );
        return Ok(());
    }
    if status != Status::Ok {
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
/// `name_ids` so recipe-style `children = ["greeter", …]`
/// resolves to actual ServiceIds.
pub(crate) fn encode_init_args(
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
pub(crate) fn encode_on_start_payloads(on_start: &[OnStartMsg]) -> anyhow::Result<Vec<u8>> {
    use vos::Encode;
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(on_start.len());
    for entry in on_start {
        let mut msg = vos::value::Msg::new(&entry.msg);
        for (k, v) in &entry.args {
            // Same heuristic as `space install --init`: numeric
            // → u64, true/false → bool, else string. Recipe
            // authors who want explicit typing can upgrade to
            // typed init args once we have schemas.
            //
            // Sprint 3: `$env:VAR` strings get resolved here too
            // so on_start payloads can pull secrets out of the
            // container's env without baking them into the
            // recipe.
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

/// Sprint 3 — resolve `$env:VAR` indirection in recipe init
/// values. String values matching `$env:NAME` are looked up in
/// the process environment; everything else passes through
/// unchanged. Used by extension `[[extension]] init = {...}` and
/// agent `[[agent]] init = {...}` paths so container deployments
/// can keep secrets (HF tokens, API keys, …) out of the recipe
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
             the `$env:` indirection from the recipe.",
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

/// Walk every agent in the recipe, including nested children.
/// Returned in tree-iteration order (parents before children) so
/// `reconcile` can process them sequentially while `name_ids` is
/// still being built up.
pub(crate) fn flatten(agents: &[AgentDef]) -> Vec<&AgentDef> {
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

/// Reject recipes where the same `instance_name` appears in
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
/// names (`Status::InstanceExists`) but it knows nothing about
/// extensions and nothing about within-extension duplicates;
/// catching the full set recipe-side gives the operator a
/// single clear error before any side-effects land.
pub(crate) fn validate_recipe_names(recipe: &Recipe) -> anyhow::Result<()> {
    use std::collections::BTreeMap;

    // Preserve first-seen order so duplicates list the original
    // declaration kind first. BTreeMap keys sort lexically — fine
    // for an error message; an IndexMap would preserve source
    // order but isn't worth the dep for one-shot validation.
    let mut seen: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    for agent in flatten(&recipe.agents) {
        seen.entry(agent.name.clone()).or_default().push("agent");
    }
    for ext in &recipe.extensions {
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
        "recipe has duplicate instance_names — both agents and \
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
    fn export_output_parses_as_a_recipe() {
        // `space export` emits path-less agents (blobs are content-
        // addressed) carrying `program` + `program_hash`, plus
        // `[[program]]` / `space_id` / `[members]` blocks the recipe
        // parser doesn't model. All of it must parse cleanly so
        // `export | apply --diff` can round-trip.
        let s = r#"
            space    = "e2e"
            space_id = "aabb"

            [[program]]
            name    = "counter"
            version = "recipe"
            hash    = "deadbeef"

            [[agent]]
            name           = "counter"
            program        = "counter:recipe"
            program_hash   = "deadbeef"
            replication_id = "0011"
            consistency    = "crdt"
            sync           = "member"
            network_reachable = true

            [[member]]
            kind    = "node"
            prefix  = 1
            peer_id = "cc"
            role    = 3

            [[member]]
            kind    = "node"
            prefix  = 2
            peer_id = "dd"
            role    = 0
        "#;
        let m: Recipe = toml::from_str(s).expect("export output parses as a recipe");
        assert_eq!(m.space.as_deref(), Some("e2e"));
        assert_eq!(m.agents.len(), 1);
        let a = &m.agents[0];
        assert_eq!(a.name, "counter");
        assert!(a.path.is_empty(), "exported agents carry no source path");
        assert_eq!(a.program.as_deref(), Some("counter:recipe"));
        assert_eq!(a.program_hash.as_deref(), Some("deadbeef"));
        assert_eq!(a.sync.as_deref(), Some("member"));
        assert!(a.network_reachable);
    }

    #[test]
    fn parses_minimal_recipe() {
        let s = r#"
            space = "demo"
            [[agent]]
            name = "counter"
            path = "actors/counter/foo.elf"
            consistency = "crdt"
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert_eq!(m.space.as_deref(), Some("demo"));
        assert!(m.hyperspace.is_none());
        assert_eq!(m.agents.len(), 1);
        assert_eq!(m.agents[0].name, "counter");
        assert_eq!(m.agents[0].consistency, "crdt");
        assert!(
            !m.agents[0].network_reachable,
            "network_reachable is confined (false) by default"
        );
    }

    #[test]
    fn parses_network_reachable_opt_in() {
        // A network-served bridge opts out of the device-confinement gate.
        let s = r#"
            space = "bank-a"
            [[agent]]
            name = "clerk-bridge"
            path = "actors/clerk-bridge.elf"
            consistency = "ephemeral"
            network_reachable = true
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert!(m.agents[0].network_reachable);
        assert_eq!(m.agents[0].consistency, "ephemeral");
    }

    #[test]
    fn parses_hyperspace_field() {
        let s = r#"
            space = "bank-a"
            hyperspace = "bank-federation"
            [[agent]]
            name = "noop"
            path = "actors/noop.elf"
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert_eq!(m.space.as_deref(), Some("bank-a"));
        assert_eq!(m.hyperspace.as_deref(), Some("bank-federation"));
    }

    #[test]
    fn parses_extension_intra_caps() {
        let s = r#"
            [[extension]]
            name = "dev"
            path = "libdev_extension.so"
            intra_caps = ["space-registry:admin", "*:guest"]
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert_eq!(m.extensions.len(), 1);
        assert_eq!(
            m.extensions[0].intra_caps,
            vec!["space-registry:admin".to_string(), "*:guest".to_string()],
        );
        // Each token round-trips through the typed parser the
        // reconciler uses at boot.
        for tok in &m.extensions[0].intra_caps {
            vos::IntraCap::parse(tok).expect("declared caps parse");
        }
    }

    #[test]
    fn extension_intra_caps_default_empty() {
        // An extension with no intra_caps key parses to an empty Vec
        // (deny-by-default: every relayed call is Unauthenticated).
        let s = r#"
            [[extension]]
            name = "math"
            path = "libmath.so"
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert!(m.extensions[0].intra_caps.is_empty());
    }

    #[test]
    fn render_intra_caps_empty_is_explicit() {
        // Deny-by-default must be visible, not silent.
        let s = render_intra_caps(&[]);
        assert!(s.contains("none"), "{s}");
        assert!(s.contains("Unauthenticated"), "{s}");
    }

    #[test]
    fn render_intra_caps_lists_canonical_tokens() {
        let caps = vec![
            vos::IntraCap::parse("space-registry:admin").unwrap(),
            vos::IntraCap::parse("*:guest").unwrap(),
        ];
        assert_eq!(render_intra_caps(&caps), "space-registry:admin, *:guest");
    }

    #[test]
    fn wildcard_warning_fires_on_actor_wildcards() {
        // Full wildcard → loud warning naming the extension.
        let caps = vec![vos::IntraCap::parse("*").unwrap()];
        let w = intra_caps_wildcard_warning("dev", &caps).expect("full wildcard warns");
        assert!(w.contains("dev"), "{w}");
        assert!(w.contains("fully-trusted relay"), "{w}");

        // Actor wildcard with a concrete role → still fires (broad
        // authority on every actor).
        let caps = vec![vos::IntraCap::parse("*:developer").unwrap()];
        let w = intra_caps_wildcard_warning("dev", &caps).expect("actor wildcard warns");
        assert!(w.contains("EVERY actor"), "{w}");
    }

    #[test]
    fn no_wildcard_warning_for_named_caps_or_empty() {
        let caps = vec![vos::IntraCap::parse("space-registry:admin").unwrap()];
        assert!(intra_caps_wildcard_warning("dev", &caps).is_none());
        // Empty = deny-by-default, not a footgun.
        assert!(intra_caps_wildcard_warning("dev", &[]).is_none());
    }

    #[test]
    fn unresolvable_named_cap_warns() {
        // A named cap for an actor the space doesn't install is almost
        // certainly a typo — warn so it doesn't silently fail to bind.
        // `dev-project` and the registry are installed; `auth-service`
        // is not.
        let known: std::collections::HashSet<String> = ["space-registry", "dev-project"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let caps = vec![
            vos::IntraCap::parse("space-registry:admin").unwrap(),
            vos::IntraCap::parse("dev-project:developer").unwrap(),
            vos::IntraCap::parse("auth-service:member").unwrap(),
        ];
        let w = unresolvable_cap_warning("dev", &caps, &known).expect("unresolvable cap warns");
        assert!(w.contains("auth-service"), "{w}");
        assert!(w.contains("won't bind"), "{w}");
        // Installed actors must NOT be listed.
        assert!(!w.contains("space-registry:"), "{w}");
        assert!(!w.contains("dev-project"), "{w}");
    }

    #[test]
    fn named_cap_match_against_known_is_case_insensitive() {
        // IntraCap matching is case-insensitive, so the typo check must
        // be too — a correctly-named-but-differently-cased cap is fine.
        let known: std::collections::HashSet<String> =
            std::iter::once("Dev-Project".to_string()).collect();
        let caps = vec![vos::IntraCap::parse("dev-project:admin").unwrap()];
        assert!(unresolvable_cap_warning("dev", &caps, &known).is_none());
    }

    #[test]
    fn no_unresolvable_warning_for_known_or_wildcards() {
        // Installed-actor caps + wildcard-actor caps are all matchable.
        let known: std::collections::HashSet<String> = ["space-registry", "dev-project"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let caps = vec![
            vos::IntraCap::parse("space-registry:admin").unwrap(),
            vos::IntraCap::parse("dev-project:admin").unwrap(),
            vos::IntraCap::parse("*:developer").unwrap(),
            vos::IntraCap::parse("*").unwrap(),
        ];
        assert!(unresolvable_cap_warning("dev", &caps, &known).is_none());
        assert!(unresolvable_cap_warning("dev", &[], &known).is_none());
    }

    #[test]
    fn malformed_intra_cap_token_is_rejected_by_parser() {
        // The reconciler parses each token eagerly; a malformed entry
        // becomes a boot failure rather than a silently-dropped bound.
        let s = r#"
            [[extension]]
            name = "bad"
            path = "libbad.so"
            intra_caps = ["space-registry"]
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        let err = vos::IntraCap::parse(&m.extensions[0].intra_caps[0]).unwrap_err();
        assert!(err.reason.contains("actor:role"), "{}", err.reason);
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
        let m: Recipe = toml::from_str(s).unwrap();
        assert_eq!(m.agents.len(), 1);
        assert_eq!(m.agents[0].actors.len(), 1);
        assert_eq!(m.agents[0].actors[0].name, "greeter");
    }

    #[test]
    fn validate_names_accepts_distinct() {
        let m: Recipe = toml::from_str(
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
        validate_recipe_names(&m).expect("distinct names pass");
    }

    #[test]
    fn validate_names_rejects_agent_extension_clash() {
        // The headline case — operator names both an agent and an
        // extension `gateway`. They'd install at the same
        // `instance_service_id(name, prefix)`, second silently
        // shadows the first.
        let m: Recipe = toml::from_str(
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
        let err = validate_recipe_names(&m).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'gateway'"), "{msg}");
        assert!(msg.contains("agent") && msg.contains("extension"), "{msg}");
    }

    #[test]
    fn validate_names_rejects_duplicate_extensions() {
        let m: Recipe = toml::from_str(
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
        let err = validate_recipe_names(&m).unwrap_err();
        assert!(err.to_string().contains("'gateway' appears 2×"), "{}", err);
    }

    #[test]
    fn validate_names_rejects_duplicate_agents() {
        // The registry's `install` handler returns
        // Status::InstanceExists for this case at runtime, but
        // the recipe-side check fails earlier — before any
        // .elf gets blob-cached or any partial registration
        // lands.
        let m: Recipe = toml::from_str(
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
        let err = validate_recipe_names(&m).unwrap_err();
        assert!(err.to_string().contains("'counter' appears 2×"), "{}", err);
    }

    #[test]
    fn validate_names_catches_nested_child_collision() {
        // `flatten` walks parent + child agents; a child named
        // the same as a top-level agent is a collision too.
        let m: Recipe = toml::from_str(
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
        let err = validate_recipe_names(&m).unwrap_err();
        assert!(err.to_string().contains("'scheduler'"), "{}", err);
    }

    #[test]
    fn flatten_yields_parents_then_children() {
        let m: Recipe = toml::from_str(
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
        // they can find it in the recipe, and (c) a clear cause
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
