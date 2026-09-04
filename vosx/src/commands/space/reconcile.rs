//! Recipe → registry reconciliation.
//!
//! The recipe parser and in-process genesis installer. Reads a
//! recipe TOML, walks every `[[agent]]` (and nested `actors`
//! children), and ensures the registry catalog reflects what the
//! recipe declares. Consumed by `space apply` (against a running
//! space) and by the genesis apply that runs on a space's first
//! `space up`:
//!
//! - Each `path = "…"` signed service package gets blob-cached and
//!   published if not already in the catalog.
//! - Each agent gets `install()`'d if no instance with that
//!   `name` is already registered.
//! - Agents already in the registry are left alone (their state takes
//!   precedence over the recipe). Replacing one now belongs to the Agent
//!   lifecycle; the retired legacy `space upgrade` path fails closed.
//!
//! Recipes are dev-time conveniences — the registry stays
//! the runtime source of truth. This module's only job is to
//! arrange the registry once on startup; after that, `space
//! up` proceeds normally and spawns whatever the registry says
//! is installed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use vos::abi::service::ServiceId;
use vos::node::{ExtensionConfig, VosNode};
use vos::registry::{
    AgentRow, ProgramKind, ProgramRow, ProgramTag, RegistryRef, Status, SyncFloor,
};
use vos::value::Args;

use crate::blob_store;
use crate::commands::space::common::{
    auto_replication_id, instance_service_id, parse_consistency, parse_instance_name,
    parse_nonzero_replication_id, parse_program_name,
};

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
    /// Hyperspace this space belongs to. When set, the daemon
    /// additionally spawns a registry replica into the
    /// hyperspace's replication group so cross-space `resolve`
    /// can fall through. See `derive_hyperspace_id` for the
    /// replication-id derivation. Wired up by the boot path when a
    /// recipe sets the field; for now the parser just round-trips it.
    #[allow(dead_code)]
    pub hyperspace: Option<String>,
    #[serde(rename = "agent", default)]
    pub agents: Vec<AgentDef>,
    /// Native `.so` extension plugins. Each `[[extension]]` entry
    /// in a recipe maps onto a single `node.register_extension`
    /// call when the daemon boots; the host loads the .so, reads
    /// its metadata, and runs it as a request-driven actor. The registry doesn't surface extensions
    /// today — they're host-local; only PVM agents live in the
    /// registry.
    #[serde(rename = "extension", default)]
    pub extensions: Vec<ExtensionDef>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
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
    /// often, between inbound work — the extension way to originate periodic
    /// work (a heartbeat ping, a cache sweep). Omitted / `0` → no ticking.
    pub tick_ms: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentDef {
    pub name: String,
    /// Path to the signed `.vos` package, relative to the recipe file.
    /// Exported recipes use `program_hash` instead because a running
    /// node does not retain the package's original source path.
    #[serde(default)]
    pub path: String,
    /// Published program name (emitted by `space export`). When absent,
    /// the instance name is also used as the catalog name.
    #[serde(default)]
    pub program: Option<String>,
    /// Hex blob hash of an already-published program (emitted by `space
    /// export`). Lets `apply` resolve the blob without a source `path` —
    /// the precondition for `export | apply --diff` being all-skips.
    #[serde(default)]
    pub program_hash: Option<String>,
    /// `local` / `crdt` / `raft`. Defaults to `local`.
    #[serde(default = "default_consistency")]
    pub consistency: String,
    /// Opt a network-served but node-confined (`local`) agent OUT
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
    /// Override replication id (`auto` / nonzero 64-hex).
    /// `auto` (default) hashes `(name, blob_hash)`.
    #[serde(default)]
    pub replication_id: Option<String>,
    /// Configure this service with a host-private device signer. The secret is
    /// stored beside the service image and never enters replicated state.
    #[serde(default)]
    pub device_secret: bool,
    /// Node-local authority this service may exercise when invoking native
    /// extensions, expressed as `"extension:role"` capability strings.
    /// Omitted preserves existing node-local policy during recipe merge;
    /// an explicit empty list revokes all native-extension calls.
    #[serde(default)]
    pub intra_caps: Option<Vec<String>>,
}

fn default_consistency() -> String {
    "local".to_string()
}

/// Resolve an extension's `.so` path against the space data directory,
/// enable instance-scoped persistence, build init args (rkyv `Args`), and hand off to
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
    data_dir: &Path,
    daemon_prefix: u16,
    space_id: &[u8; 32],
    known_names: &std::collections::HashSet<String>,
    operator: Option<&libp2p::identity::Keypair>,
) -> anyhow::Result<Vec<String>> {
    parse_instance_name(&ext.name)
        .map_err(|error| anyhow::anyhow!("extension '{}': {error}", ext.name))?;
    // `local.toml` stores absolute extension paths, so joining with the space
    // data directory preserves that path while also giving this function the
    // durable state root for the installed instance.
    let so_path = data_dir.join(&ext.path);
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
    // the `node.try_register_extension_at_id` call below. The worker thread
    // does its own dlopen; by holding our handle until after the
    // worker is spawned, we make the common interleaving (worker
    // dlopens before our drop) keep dlopen's refcount ≥ 1, so the
    // library never round-trips through an unmap. There's still a
    // registration handshake now waits until that worker has loaded,
    // restored, and committed its initial state before returning.
    // SAFETY: dlopen on a vos-built extension .so; the recipe's
    // path is operator-supplied. See `vos::extension::ExtensionPlugin::load`
    // for the full FFI contract docstring.
    let plugin = unsafe { vos::extension::ExtensionPlugin::load(&so_path) }.map_err(|error| {
        anyhow::anyhow!(
            "extension '{}': failed to load metadata from {}: {error}",
            ext.name,
            so_path.display(),
        )
    })?;
    let meta_blob = plugin.meta_bytes().to_vec();

    // Parse declared intra-system caps eagerly: a malformed entry is
    // a boot failure naming the offending token, not a silent loss of
    // an authority bound.
    let mut intra_caps = Vec::with_capacity(ext.intra_caps.len());
    for tok in &ext.intra_caps {
        let cap = vos::IntraCap::parse(tok)
            .map_err(|e| anyhow::anyhow!("extension '{}': {e}", ext.name))?;
        intra_caps.push(cap);
    }
    // Operator visibility. `intra_caps` are host-side daemon
    // config (not replicated registry state). Render the *effective*
    // caps for the boot log, warn
    // loudly on footgun wildcards, and capture the canonical tokens to
    // return — the caller stamps them into the local endpoint
    // descriptor so `space describe` / `space caps` can surface them
    // without scraping the log.
    let effective_caps: &[vos::IntraCap] = &intra_caps;
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
        ExtensionConfig::new(&so_path)
    } else {
        ExtensionConfig::with_args(&so_path, &args)
    };
    // Record the instance name so the host's reverse map can resolve
    // this extension's ServiceId — letting it be the *target* of a
    // named intra_cap or an actor-local grant.
    let cfg = cfg.with_name(ext.name.clone());
    let cfg = cfg.with_intra_caps(intra_caps).persist(data_dir);

    // Periodic `tick` cadence. `with_tick_ms` treats 0 as off.
    let cfg = match ext.tick_ms {
        Some(ms) if ms > 0 => {
            tracing::info!("extension '{}' tick_ms = {}", ext.name, ms);
            cfg.with_tick_ms(ms)
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
    let id = node
        .try_register_extension_at_id(cfg, instance_service_id(&ext.name, daemon_prefix))
        .map_err(|error| anyhow::anyhow!("extension '{}': startup failed: {error}", ext.name))?;
    tracing::info!(
        "extension '{}' loaded from {} as {id}",
        ext.name,
        so_path.display(),
    );

    if !meta_blob.is_empty() {
        // Author the exact mutation at its source. A non-admin node's
        // signature is refused and the row arrives via sync instead; a
        // missing operator key deliberately sends no ambient authority.
        let auth = operator
            .map(|operator| {
                crate::commands::space::op_sign::op_auth(
                    operator,
                    space_id,
                    "register_extension_meta",
                    &[ext.name.as_bytes(), &meta_blob],
                )
            })
            .transpose()?
            .unwrap_or_default();
        let status = vos::block_on(reg.register_extension_meta(
            &mut &*node,
            ext.name.clone(),
            meta_blob,
            auth,
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
        "'*' / '*:*' grants ANY role on ANY actor"
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
/// can't resolve at dispatch time. The host resolves any installed
/// agent or extension by name (via its reverse map), so the authority
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
    operator: Option<&libp2p::identity::Keypair>,
) -> anyhow::Result<()> {
    validate_recipe_names(recipe)?;

    let reg = RegistryRef::at(ServiceId::new(
        daemon_prefix,
        ServiceId::REGISTRY.local_id(),
    ));

    if recipe.agents.is_empty() {
        return Ok(());
    }
    tracing::info!("genesis apply ({} service package(s))", recipe.agents.len());

    // Is this daemon the space's admin authoring node? True when its
    // operator is the genesis root or holds an ADMIN grant. This path signs
    // catalog ops directly with that operator key; on an admin node a
    // Status::Forbidden therefore means the signer can't author (key
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

    for agent in &recipe.agents {
        reconcile_one(
            node,
            &reg,
            agent,
            recipe_dir,
            node_is_admin,
            space_id,
            operator,
        )?;
    }

    Ok(())
}

fn reconcile_one(
    node: &VosNode,
    reg: &RegistryRef,
    agent: &AgentDef,
    recipe_dir: &Path,
    node_is_admin: bool,
    space_id: &[u8; 32],
    operator: Option<&libp2p::identity::Keypair>,
) -> anyhow::Result<()> {
    // Genesis recipes must carry the exact signed package bytes. A path-less
    // exported recipe can only reconcile an already-running space.
    if agent.path.is_empty() {
        anyhow::bail!(
            "recipe agent '{}' has no `path` — a genesis-applied recipe installs from source \
             packages. (The path-less `program_hash` form is only for `space apply` against an \
             already-published catalog.)",
            agent.name,
        );
    }
    let package_path = recipe_dir.join(&agent.path);
    let package_bytes = std::fs::read(&package_path).map_err(|e| {
        anyhow::anyhow!(
            "read {} for agent '{}': {e}",
            package_path.display(),
            agent.name
        )
    })?;
    let program_name =
        super::common::parse_program_name(agent.program.as_deref().unwrap_or(&agent.name))?;
    let package = super::publish::validate_package(&program_name, &package_bytes)?;
    let hash = blob_store::cache_put(&package_bytes)
        .map_err(|e| anyhow::anyhow!("cache blob for '{}': {e}", agent.name))?;
    let crdt = package.manifest.crdt;

    // Ensure the requested catalog name points at this exact package.
    let existing: Option<ProgramRow> =
        vos::block_on(reg.program(&mut &*node, program_name.clone()))
            .map_err(|e| anyhow::anyhow!("registry.program('{program_name}'): {e}"))?;
    let program = match existing {
        Some(p) if p.hash == hash.0 && p.kind == (ProgramKind::Service { crdt }) => {
            tracing::debug!("{program_name} already published");
            p.tag()
        }
        current => {
            let publication_id = super::common::mint_publication_id()?;
            let expected_current = current.as_ref().map(|row| row.tag());
            let expected_publication_id = expected_current
                .map(|tag| tag.publication_id.into_bytes().to_vec())
                .unwrap_or_default();
            let expected_hash = expected_current
                .map(|tag| tag.hash.to_vec())
                .unwrap_or_default();
            // Sign at the authoring call site. On a joined non-admin node the
            // signature is valid but lacks authority, yielding Forbidden;
            // the root-authored row then arrives through registry sync.
            let auth = operator
                .map(|operator| {
                    crate::commands::space::op_sign::op_auth(
                        operator,
                        space_id,
                        "publish_service_program",
                        &[
                            program_name.as_bytes(),
                            &hash.0,
                            &[crdt as u8],
                            publication_id.as_bytes(),
                            &expected_publication_id,
                            &expected_hash,
                        ],
                    )
                })
                .transpose()?
                .unwrap_or_default();
            let status = vos::block_on(reg.publish_service_program(
                &mut &*node,
                program_name.clone(),
                hash.0,
                crdt,
                publication_id,
                expected_current,
                auth,
            ))
            .map_err(|e| anyhow::anyhow!("registry.publish('{program_name}'): {e}"))?;
            match status {
                Status::Ok => {
                    tracing::info!("published {program_name}");
                }
                Status::Forbidden if node_is_admin => {
                    // This node IS the space admin, yet its directly authored
                    // signature was refused — the operator key
                    // can't author catalog ops. Fail loud rather than
                    // silently install nothing (no peer will supply the
                    // rows for the authoring node).
                    anyhow::bail!(
                        "publish '{program_name}' refused (Status::Forbidden) on \
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
                        "publish {program_name} not authored locally; awaiting \
                         registry sync (if this should be the admin node, check identity.key)",
                    );
                }
                other => anyhow::bail!("publish status {other}"),
            }
            ProgramTag {
                publication_id,
                hash: hash.0,
            }
        }
    };

    // Forward the signed package schema so dynamic clients can resolve
    // method arguments. The package is still installable if the best-effort
    // registry side channel is temporarily unavailable.
    if !package.schemas.is_empty() {
        // Meta registration is a nice-to-have (it enables schema-aware
        // coercion for the worker / dynamic CLIs); it must never abort the
        // install. Both a non-Ok status (e.g. FORBIDDEN on a non-admin node —
        // the row arrives via sync) and a transport failure (e.g. a large
        // `.vos_meta` that overflows the registry guest's FETCH buffer) are
        // tolerated: log and move on, agent still spawns without a schema.
        let auth = operator
            .map(|operator| {
                crate::commands::space::op_sign::op_auth(
                    operator,
                    space_id,
                    "register_meta",
                    &[&program.hash, &package.schemas],
                )
            })
            .transpose()?
            .unwrap_or_default();
        match vos::block_on(reg.register_meta(
            &mut &*node,
            program.hash.to_vec(),
            package.schemas,
            auth,
        )) {
            Ok(Status::Ok) => {
                tracing::debug!("registered meta for {program_name}");
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
    }

    // 3. Ensure installed.
    let already_installed = vos::block_on(reg.agent(&mut &*node, agent.name.clone()))
        .map_err(|e| anyhow::anyhow!("registry.agent('{}'): {e}", agent.name))?;
    let consistency = parse_consistency(&agent.consistency).ok_or_else(|| {
        anyhow::anyhow!(
            "agent '{}': unknown consistency '{}', expected local|crdt|raft",
            agent.name,
            agent.consistency,
        )
    })?;
    if consistency == vos::node::Consistency::Ephemeral as u8 {
        anyhow::bail!(
            "agent '{}': service packages cannot be ephemeral",
            agent.name
        );
    }

    let replication_id = resolve_replication_id(agent, space_id, &program.hash)?;

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

    if let Some(installed) = already_installed {
        if service_install_matches(
            &installed,
            &agent.name,
            &program_name,
            program,
            replication_id,
            consistency,
            agent.network_reachable,
            sync_role,
        ) {
            tracing::debug!("{} already installed", agent.name);
            return Ok(());
        }
        anyhow::bail!(
            "agent '{}' is already installed with a different program or service configuration",
            agent.name,
        );
    }

    // Bind the exact installation fields before dispatch. Status::Forbidden
    // means this is not an authoring admin (or no operator key was available),
    // so the root-authored row must arrive via sync.
    let installation_id = super::common::mint_installation_id()?;
    let auth = operator
        .map(|operator| {
            crate::commands::space::op_sign::op_auth(
                operator,
                space_id,
                "install_service_actor",
                &[
                    agent.name.as_bytes(),
                    program_name.as_bytes(),
                    &program.hash,
                    program.publication_id.as_bytes(),
                    installation_id.as_bytes(),
                    &replication_id,
                    &[consistency],
                    &[agent.network_reachable as u8],
                    &[sync_role as u8],
                ],
            )
        })
        .transpose()?
        .unwrap_or_default();
    let status = vos::block_on(reg.install_service_actor(
        &mut &*node,
        agent.name.clone(),
        program_name.clone(),
        program,
        installation_id,
        replication_id,
        consistency,
        agent.network_reachable,
        sync_role,
        auth,
    ))
    .map_err(|e| anyhow::anyhow!("registry.install('{}'): {e}", agent.name))?;

    // A joining node's registry replica may acquire the row during this
    // request. Treat that race as success only after checking the exact
    // semantic postcondition.
    if status == Status::InstanceExists {
        let observed = vos::block_on(reg.agent(&mut &*node, agent.name.clone()))
            .map_err(|error| anyhow::anyhow!("registry.agent('{}'): {error}", agent.name))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "install '{}' raced with a row that is no longer readable",
                    agent.name,
                )
            })?;
        if !service_install_matches(
            &observed,
            &agent.name,
            &program_name,
            program,
            replication_id,
            consistency,
            agent.network_reachable,
            sync_role,
        ) {
            anyhow::bail!(
                "install '{}' raced with a different live installation",
                agent.name,
            );
        }
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

fn service_install_matches(
    row: &AgentRow,
    instance_name: &str,
    program_name: &str,
    program: ProgramTag,
    replication_id: [u8; 32],
    consistency: u8,
    network_reachable: bool,
    sync_role: SyncFloor,
) -> bool {
    row.instance_name == instance_name
        && row.program_name == program_name
        && row.program_hash == program.hash
        && row.program_publication_id == program.publication_id
        && row.replication_id == replication_id
        && row.consistency == consistency
        && row.network_reachable == network_reachable
        && row.sync_role == sync_role
}

fn resolve_replication_id(
    agent: &AgentDef,
    space_id: &[u8; 32],
    program_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    Ok(match agent.replication_id.as_deref() {
        Some("auto") | None => auto_replication_id(space_id, &agent.name, program_hash),
        Some(value) => parse_nonzero_replication_id(value)
            .map_err(|error| anyhow::anyhow!("agent '{}': {error}", agent.name))?,
    })
}

/// Resolve `$env:VAR` indirection in recipe init values. String values
/// matching `$env:NAME` are looked up in the process environment;
/// everything else passes through unchanged. Used by extension
/// `[[extension]] init = {...}` paths so container deployments can keep
/// secrets (HF tokens,
/// API keys, …) out of the recipe file itself.
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

    // Validate the whole recipe before any package is cached, catalog row is
    // authored, or node-local route is installed. The registry guest uses the
    // same shared predicate, so the signer and verifier accept one exact set.
    for agent in &recipe.agents {
        parse_instance_name(&agent.name)
            .map_err(|error| anyhow::anyhow!("recipe agent '{}': {error}", agent.name))?;
        let requested_program = agent.program.as_deref().unwrap_or(&agent.name);
        parse_program_name(requested_program).map_err(|error| {
            anyhow::anyhow!(
                "recipe agent '{}' program '{}': {error}",
                agent.name,
                requested_program,
            )
        })?;
        if let Some(replication_id) = agent
            .replication_id
            .as_deref()
            .filter(|replication_id| *replication_id != "auto")
        {
            parse_nonzero_replication_id(replication_id)
                .map_err(|error| anyhow::anyhow!("recipe agent '{}': {error}", agent.name))?;
        }
    }
    for extension in &recipe.extensions {
        parse_instance_name(&extension.name)
            .map_err(|error| anyhow::anyhow!("recipe extension '{}': {error}", extension.name))?;
    }

    // Preserve first-seen order so duplicates list the original
    // declaration kind first. BTreeMap keys sort lexically — fine
    // for an error message; an IndexMap would preserve source
    // order but isn't worth the dep for one-shot validation.
    let mut seen: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    for agent in &recipe.agents {
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
            hash    = "deadbeef"
            crdt    = true

            [[agent]]
            name           = "counter"
            program        = "counter"
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
        assert_eq!(a.program.as_deref(), Some("counter"));
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
            path = "packages/counter.vos"
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
    fn omitted_consistency_defaults_to_local() {
        let m: Recipe = toml::from_str(
            r#"
                [[agent]]
                name = "counter"
                path = "counter.vos"
            "#,
        )
        .unwrap();
        assert_eq!(m.agents[0].consistency, "local");
    }

    #[test]
    fn parses_network_reachable_opt_in() {
        // A network-served bridge opts out of the device-confinement gate.
        let s = r#"
            space = "bank-a"
            [[agent]]
            name = "clerk-bridge"
            path = "packages/clerk-bridge.vos"
            consistency = "local"
            network_reachable = true
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert!(m.agents[0].network_reachable);
        assert_eq!(m.agents[0].consistency, "local");
    }

    #[test]
    fn parses_hyperspace_field() {
        let s = r#"
            space = "bank-a"
            hyperspace = "bank-federation"
            [[agent]]
            name = "noop"
            path = "packages/noop.vos"
        "#;
        let m: Recipe = toml::from_str(s).unwrap();
        assert_eq!(m.space.as_deref(), Some("bank-a"));
        assert_eq!(m.hyperspace.as_deref(), Some("bank-federation"));
    }

    #[test]
    fn agent_intra_caps_distinguish_omission_from_explicit_revocation() {
        let omitted: Recipe = toml::from_str(
            r#"
            [[agent]]
            name = "reader"
            path = "reader.vos"
        "#,
        )
        .unwrap();
        assert!(omitted.agents[0].intra_caps.is_none());

        let revoked: Recipe = toml::from_str(
            r#"
            [[agent]]
            name = "reader"
            path = "reader.vos"
            intra_caps = []
        "#,
        )
        .unwrap();
        assert_eq!(revoked.agents[0].intra_caps, Some(Vec::new()));
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
        assert!(w.contains("ANY role on ANY actor"), "{w}");

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
        // `workspace` and the registry are installed; `auth-service`
        // is not.
        let known: std::collections::HashSet<String> = ["space-registry", "workspace"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let caps = vec![
            vos::IntraCap::parse("space-registry:admin").unwrap(),
            vos::IntraCap::parse("workspace:developer").unwrap(),
            vos::IntraCap::parse("auth-service:member").unwrap(),
        ];
        let w = unresolvable_cap_warning("dev", &caps, &known).expect("unresolvable cap warns");
        assert!(w.contains("auth-service"), "{w}");
        assert!(w.contains("won't bind"), "{w}");
        // Installed actors must NOT be listed.
        assert!(!w.contains("space-registry:"), "{w}");
        assert!(!w.contains("workspace"), "{w}");
    }

    #[test]
    fn named_cap_match_against_known_is_case_insensitive() {
        // IntraCap matching is case-insensitive, so the typo check must
        // be too — a correctly-named-but-differently-cased cap is fine.
        let known: std::collections::HashSet<String> =
            std::iter::once("Workspace".to_string()).collect();
        let caps = vec![vos::IntraCap::parse("workspace:admin").unwrap()];
        assert!(unresolvable_cap_warning("dev", &caps, &known).is_none());
    }

    #[test]
    fn no_unresolvable_warning_for_known_or_wildcards() {
        // Installed-actor caps + wildcard-actor caps are all matchable.
        let known: std::collections::HashSet<String> = ["space-registry", "workspace"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let caps = vec![
            vos::IntraCap::parse("space-registry:admin").unwrap(),
            vos::IntraCap::parse("workspace:admin").unwrap(),
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
    fn validate_names_accepts_distinct() {
        let m: Recipe = toml::from_str(
            r#"
                [[agent]]
                name = "counter"
                path = "a.vos"
                [[agent]]
                name = "greeter"
                path = "b.vos"
                [[extension]]
                name = "worker"
                path = "c.so"
            "#,
        )
        .unwrap();
        validate_recipe_names(&m).expect("distinct names pass");
    }

    #[test]
    fn validate_names_rejects_agent_extension_clash() {
        // The headline case — operator names both an agent and an
        // extension `worker`. They'd install at the same
        // `instance_service_id(name, prefix)`, second silently
        // shadows the first.
        let m: Recipe = toml::from_str(
            r#"
                [[agent]]
                name = "worker"
                path = "a.vos"
                [[extension]]
                name = "worker"
                path = "b.so"
            "#,
        )
        .unwrap();
        let err = validate_recipe_names(&m).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'worker'"), "{msg}");
        assert!(msg.contains("agent") && msg.contains("extension"), "{msg}");
    }

    #[test]
    fn validate_names_rejects_duplicate_extensions() {
        let m: Recipe = toml::from_str(
            r#"
                [[extension]]
                name = "worker"
                path = "a.so"
                [[extension]]
                name = "worker"
                path = "b.so"
            "#,
        )
        .unwrap();
        let err = validate_recipe_names(&m).unwrap_err();
        assert!(err.to_string().contains("'worker' appears 2×"), "{}", err);
    }

    #[test]
    fn validate_names_rejects_duplicate_agents() {
        // The registry's `install` handler returns
        // Status::InstanceExists for this case at runtime, but
        // the recipe-side check fails earlier — before any
        // package gets blob-cached or any partial registration
        // lands.
        let m: Recipe = toml::from_str(
            r#"
                [[agent]]
                name = "counter"
                path = "a.vos"
                [[agent]]
                name = "counter"
                path = "b.vos"
            "#,
        )
        .unwrap();
        let err = validate_recipe_names(&m).unwrap_err();
        assert!(err.to_string().contains("'counter' appears 2×"), "{}", err);
    }

    #[test]
    fn recipe_validation_rejects_noncanonical_instance_and_program_names() {
        for recipe in [
            r#"
                [[agent]]
                name = "Bad_Agent"
                path = "a.vos"
            "#,
            r#"
                [[agent]]
                name = "worker"
                program = "bad/program"
                path = "a.vos"
            "#,
            r#"
                [[extension]]
                name = "native_worker"
                path = "a.so"
            "#,
        ] {
            let recipe: Recipe = toml::from_str(recipe).unwrap();
            let error = validate_recipe_names(&recipe).unwrap_err().to_string();
            assert!(error.contains("canonical registry slug"), "{error}");
        }
    }

    #[test]
    fn boot_replication_identity_rejects_off_and_zero() {
        let mut agent = AgentDef {
            name: "worker".into(),
            replication_id: Some("off".into()),
            ..Default::default()
        };
        let error = resolve_replication_id(&agent, &[1; 32], &[2; 32]).unwrap_err();
        assert!(error.to_string().contains("not supported"));

        agent.replication_id = Some("00".repeat(32));
        let error = resolve_replication_id(&agent, &[1; 32], &[2; 32]).unwrap_err();
        assert!(error.to_string().contains("must be nonzero"));

        for value in ["off".to_string(), "00".repeat(32)] {
            let recipe = Recipe {
                agents: vec![AgentDef {
                    name: "worker".into(),
                    replication_id: Some(value),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(
                validate_recipe_names(&recipe).is_err(),
                "whole-recipe preflight must reject invalid replication identity before writes",
            );
        }
    }

    #[test]
    fn boot_install_race_binds_the_exact_program_generation_and_configuration() {
        use vos::registry::{PublicationId, SyncFloor};
        use vos::service::InstallationId;

        let program = ProgramTag {
            publication_id: PublicationId::new([0x41; 32]),
            hash: [0x42; 32],
        };
        let replication_id = [0x43; 32];
        let mut row = AgentRow {
            instance_name: "worker".into(),
            installation_id: InstallationId::new([0x44; 32]),
            revision: 3,
            program_hash: program.hash,
            program_name: "worker-program".into(),
            program_publication_id: program.publication_id,
            replication_id,
            consistency: vos::node::Consistency::Crdt as u8,
            network_reachable: true,
            sync_role: SyncFloor::Private,
        };
        let matches = |row: &AgentRow| {
            service_install_matches(
                row,
                "worker",
                "worker-program",
                program,
                replication_id,
                vos::node::Consistency::Crdt as u8,
                true,
                SyncFloor::Private,
            )
        };
        assert!(matches(&row));

        row.instance_name = "other-worker".into();
        assert!(!matches(&row));
        row.instance_name = "worker".into();

        row.program_publication_id = PublicationId::new([0x51; 32]);
        assert!(!matches(&row));
        row.program_publication_id = program.publication_id;
        row.program_hash[0] ^= 1;
        assert!(!matches(&row));
        row.program_hash = program.hash;
        row.program_name = "other".into();
        assert!(!matches(&row));
        row.program_name = "worker-program".into();
        row.replication_id[0] ^= 1;
        assert!(!matches(&row));
        row.replication_id = replication_id;
        row.consistency = vos::node::Consistency::Local as u8;
        assert!(!matches(&row));
        row.consistency = vos::node::Consistency::Crdt as u8;
        row.network_reachable = false;
        assert!(!matches(&row));
        row.network_reachable = true;
        row.sync_role = SyncFloor::Member;
        assert!(!matches(&row));
    }

    // ── $env:VAR indirection ──────────────────────

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
        // The error contract — the operator needs (a) the unset
        // *var name*, (b) the extension + key context so they can
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
