//! `space apply <recipe> [--diff] [--upgrade]` — reconcile a recipe
//! TOML against a *running* space.
//!
//! A recipe is a dev-time convenience; the registry stays the runtime
//! source of truth. `apply` is the one-shot admin op that arranges the
//! registry to match a recipe and projects the recipe's node-local half
//! into `local.toml`:
//!
//! - **Replicated half** → the registry, over `DaemonClient`: each
//!   `[[agent]]`'s signed `.vos` v2 package is
//!   blob-cached + published under its immutable
//!   program tag (if missing) and installed (if no instance exists).
//!   The bytes reach the daemon through the shared content-addressed
//!   blob cache — `publish` only ships `(name, version, hash)`.
//! - **Node-local half** → `local.toml`: per-agent `tick_ms` /
//!   `intra_caps` / `device_secret`, the space `cap_policy`, and
//!   `[[extension]]` entries. These never touch the `AgentRow`; boot
//!   reads them back so a bare `space up` restart re-applies them.
//!   Extensions are host-local (`dlopen` in-process) — a running daemon
//!   can't register them remotely, so `apply` only records them; they
//!   attach on the next `space up`.
//!
//! Idempotent: a second `apply` of the same recipe is all-skips.
//! `--diff` prints the plan and exits without touching anything.
//! `--upgrade` re-points installed agents whose blob differs (otherwise
//! a differing blob is flagged, never silently overwritten).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use vos::registry::{SyncFloor, Status};

use crate::blob_store;
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::{auto_replication_id, instance_service_id, parse_consistency};
use crate::commands::space::reconcile::{
    self, encode_init_args, encode_on_start_payloads, flatten, AgentDef, Recipe,
};
use crate::commands::space::subscriptions::{self, AgentLocal, ExtensionLocal, LocalConfig};
use crate::output;

/// Initial tag used when a recipe omits `program`. It is safe for first
/// install and idempotent re-apply; changed content must choose a new,
/// explicit immutable version.
const RECIPE_VERSION: &str = "recipe";

pub struct Args {
    pub space: String,
    pub recipe: PathBuf,
    /// Print the plan and exit without mutating the registry or
    /// `local.toml`.
    pub diff: bool,
    /// Re-point installed agents whose recipe blob differs from the
    /// catalog. Without it, a differing blob is flagged, not applied.
    pub upgrade: bool,
}

#[derive(Serialize, Default)]
pub(crate) struct ApplyReport {
    /// `name:version` newly published to the catalog.
    published: Vec<String>,
    /// Instance names newly installed.
    installed: Vec<String>,
    /// Instances already present with the recipe's blob — no-ops.
    skipped: Vec<String>,
    /// Instances re-pointed at a new blob (only with `--upgrade`).
    upgraded: Vec<String>,
    /// Instances whose catalog blob differs from the recipe but that
    /// weren't upgraded (needs `--upgrade`).
    upgrade_pending: Vec<String>,
    /// Changed implicit `name:recipe` instances that need an explicit
    /// immutable target such as `program = "name:v2"`.
    version_required: Vec<String>,
    /// Whether `local.toml` changed (or would change, under `--diff`).
    local_changed: bool,
    /// `--diff` dry run — nothing was written.
    diff: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // Canonicalize so a relative recipe path still yields ABSOLUTE
    // extension `.so` paths in local.toml — a later bare `space up` has
    // no recipe dir to resolve a relative one against.
    let recipe = std::fs::canonicalize(&args.recipe).unwrap_or(args.recipe);
    let (recipe, recipe_dir) = reconcile::parse_recipe_file(&recipe)?;
    reconcile::validate_recipe_names(&recipe)?;

    DaemonClient::with_connect(&args.space, |client| {
        let data_dir = PathBuf::from(&client.entry.data_dir);
        let report = apply_recipe(client, &recipe, &recipe_dir, &data_dir, args.diff, args.upgrade)?;
        emit(&client.entry.name, &report);
        Ok(())
    })
}

/// Reconcile `recipe` against the daemon `client` is connected to.
/// Returns the plan (or, under `diff`, what the plan *would* be). The
/// caller owns the `DaemonClient`; genesis apply (`space new
/// --recipe` / the recipe path of `space up`) reuses this against the
/// just-booted local daemon.
pub(crate) fn apply_recipe(
    client: &DaemonClient,
    recipe: &Recipe,
    recipe_dir: &Path,
    data_dir: &Path,
    diff: bool,
    upgrade: bool,
) -> anyhow::Result<ApplyReport> {
    let space_id = client
        .entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;

    // name → derived svc id, for `Vec<u32>` init-arg resolution (e.g.
    // `children = ["greeter"]`). Same derivation the daemon uses to
    // register the agents, so the ids match.
    let prefix = client.daemon_prefix();
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    for a in flatten(&recipe.agents) {
        name_ids.insert(a.name.clone(), instance_service_id(&a.name, prefix).0);
    }

    // Node-local half → local.toml. Recipe fields overwrite the recipe-
    // owned sections (cap_policy, per-agent policy, extensions) while
    // node-owned fields (subscriptions, listen) are preserved.
    let mut cfg = subscriptions::load(data_dir)?;
    let next = project_node_local(&cfg, recipe, recipe_dir);
    let local_changed = next != cfg;

    // Validate the entire plan before the first cache, catalog, instance,
    // or local-config write.
    let mut plans = Vec::new();
    let mut planned_tags: BTreeMap<(String, String), [u8; 32]> = BTreeMap::new();
    for agent in flatten(&recipe.agents) {
        let mut plan = preflight_one(client, agent, recipe_dir, &space_id, &name_ids, upgrade)?;
        if plan.needs_publish {
            let key = (plan.program_name.clone(), plan.program_version.clone());
            match planned_tags.get(&key) {
                Some(hash) if hash == &plan.hash => plan.needs_publish = false,
                Some(_) => anyhow::bail!(
                    "recipe assigns program {}:{} to multiple blobs; version tags are immutable",
                    key.0,
                    key.1,
                ),
                None => {
                    planned_tags.insert(key, plan.hash);
                }
            }
        }
        plans.push(plan);
    }

    let mut report = ApplyReport {
        local_changed,
        diff,
        ..Default::default()
    };
    for plan in &plans {
        if plan.needs_publish {
            report
                .published
                .push(format!("{}:{}", plan.program_name, plan.program_version));
        }
        match &plan.action {
            ApplyAction::Skip => report.skipped.push(plan.instance_name.clone()),
            ApplyAction::Install { .. } => report.installed.push(plan.instance_name.clone()),
            ApplyAction::Upgrade => report.upgraded.push(plan.instance_name.clone()),
            ApplyAction::UpgradePending => report.upgrade_pending.push(plan.instance_name.clone()),
            ApplyAction::VersionRequired => {
                report.version_required.push(plan.instance_name.clone())
            }
        }
    }

    if diff {
        return Ok(report);
    }

    // A real apply heals the content-addressed cache even for skipped
    // instances. Dry runs never reach this write.
    for plan in &plans {
        if let Some(bytes) = &plan.artifact_bytes {
            let cached = blob_store::cache_put(bytes)
                .map_err(|e| anyhow::anyhow!("cache blob for '{}': {e}", plan.instance_name))?;
            debug_assert_eq!(cached.0, plan.hash);
        }
    }
    for plan in &plans {
        execute_one(client, plan, &mut report)?;
    }
    if local_changed {
        cfg = next;
        subscriptions::save(data_dir, &cfg)?;
    }

    Ok(report)
}

enum ApplyAction {
    Skip,
    Install {
        consistency: u8,
        replication_id: [u8; 32],
        install_args: Vec<u8>,
        install_payloads: Vec<u8>,
        network_reachable: bool,
        sync_role: SyncFloor,
    },
    Upgrade,
    UpgradePending,
    VersionRequired,
}

struct PreparedAgent {
    instance_name: String,
    program_name: String,
    program_version: String,
    hash: [u8; 32],
    artifact_bytes: Option<Vec<u8>>,
    metadata: Option<Vec<u8>>,
    needs_publish: bool,
    action: ApplyAction,
}

#[allow(clippy::too_many_arguments)]
fn preflight_one(
    client: &DaemonClient,
    agent: &AgentDef,
    recipe_dir: &Path,
    space_id: &[u8; 32],
    name_ids: &BTreeMap<String, u32>,
    upgrade: bool,
) -> anyhow::Result<PreparedAgent> {
    // 1. Resolve the blob hash + program identity from either a source
    //    `path` (a hand-written recipe) or `program_hash` (a `space
    //    export` output, which carries no path). Path-based also yields
    //    artifact bytes — needed to validate and publish the exact package; the
    //    hash-based form resolves against the already-published catalog,
    //    which is what makes `export | apply --diff` all-skips.
    let (program_name, program_version, explicit_program) = program_ref(agent)?;
    let (hash, artifact_bytes, metadata) = if !agent.path.is_empty() {
        let artifact_path = recipe_dir.join(&agent.path);
        let bytes = std::fs::read(&artifact_path).map_err(|e| {
            anyhow::anyhow!(
                "read {} for agent '{}': {e}",
                artifact_path.display(),
                agent.name
            )
        })?;
        let source_hash = blob_store::BlobHash::of(&bytes);
        let (hash, bytes, package_metadata) = super::publish::canonical_program(
            &program_name,
            &program_version,
            source_hash,
            bytes,
        )?;
        reconcile::validate_v2_recipe_lifecycle(agent)?;
        let metadata = package_metadata
            .or_else(|| vos::metadata::raw_section_from_elf(&bytes));
        (hash.0, Some(bytes), metadata)
    } else if let Some(ph) = &agent.program_hash {
        let h = blob_store::BlobHash::from_hex(ph)
            .map_err(|_| anyhow::anyhow!("agent '{}': program_hash must be 64 hex", agent.name))?;
        (h.0, None, None)
    } else {
        anyhow::bail!(
            "agent '{}' has neither `path` (a source recipe) nor `program_hash` (an exported \
             recipe) — nothing to resolve the blob from",
            agent.name,
        );
    };

    // Resolve the instance first. An unchanged instance is already at the
    // requested content and does not need a synthetic catalog rewrite.
    let existing = client.agent(&agent.name)?;
    if existing
        .as_ref()
        .is_some_and(|row| row.program_hash == hash)
    {
        return Ok(PreparedAgent {
            instance_name: agent.name.clone(),
            program_name,
            program_version,
            hash,
            artifact_bytes,
            metadata,
            needs_publish: false,
            action: ApplyAction::Skip,
        });
    }

    if existing.is_some() && !explicit_program {
        if upgrade {
            anyhow::bail!(
                "agent '{}': an upgrade requires an explicit new immutable target, e.g. \
                 `program = \"{}:v2\"`",
                agent.name,
                agent.name,
            );
        }
        return Ok(PreparedAgent {
            instance_name: agent.name.clone(),
            program_name,
            program_version,
            hash,
            artifact_bytes,
            metadata,
            needs_publish: false,
            action: ApplyAction::VersionRequired,
        });
    }

    let needs_publish = match client.program(&program_name, &program_version)? {
        Some(p) if p.hash == hash => false,
        Some(_) => anyhow::bail!(
            "agent '{}': program {program_name}:{program_version} is already pinned to a \
             different blob; choose a new explicit version",
            agent.name,
        ),
        None => {
            if artifact_bytes.is_none() {
                anyhow::bail!(
                    "agent '{}': program {program_name}:{program_version} (hash {}) is not in the \
                     catalog and this recipe carries no `path` to publish it from",
                    agent.name,
                    hex::encode(hash),
                );
            }
            true
        }
    };

    if existing.is_some() {
        return Ok(PreparedAgent {
            instance_name: agent.name.clone(),
            program_name,
            program_version,
            hash,
            artifact_bytes,
            metadata,
            needs_publish,
            action: if upgrade {
                ApplyAction::Upgrade
            } else {
                ApplyAction::UpgradePending
            },
        });
    }

    // Not installed — install it (replicated half only).
    let consistency = parse_consistency(&agent.consistency).ok_or_else(|| {
        anyhow::anyhow!(
            "agent '{}': unknown consistency '{}', expected ephemeral|local|crdt|raft",
            agent.name,
            agent.consistency,
        )
    })?;
    let replication_id = resolve_replication_id(agent, space_id, &hash)?;
    let sync_role = match agent.sync.as_deref() {
        Some(s) => SyncFloor::parse(s).ok_or_else(|| {
            anyhow::anyhow!(
                "agent '{}': unknown sync floor '{}', expected public|member|private",
                agent.name,
                s,
            )
        })?,
        None => SyncFloor::Member,
    };
    // Installing a new instance needs the exact signed package. V2 packages
    // admit no host-side init payload.
    // The path-less `program_hash` form only supports the already-installed
    // (skip) path — the round-trip case.
    let Some(install_artifact_bytes) = &artifact_bytes else {
        anyhow::bail!(
            "agent '{}' is not installed and this recipe carries no `path` — the path-less \
             (exported) form can only reconcile already-installed instances",
            agent.name,
        );
    };
    let install_args = encode_init_args(
        &agent.name,
        install_artifact_bytes,
        &agent.init,
        name_ids,
    )?;
    let install_payloads = encode_on_start_payloads(&agent.on_start)?;

    Ok(PreparedAgent {
        instance_name: agent.name.clone(),
        program_name,
        program_version,
        hash,
        artifact_bytes,
        metadata,
        needs_publish,
        action: ApplyAction::Install {
            consistency,
            replication_id,
            install_args,
            install_payloads,
            network_reachable: agent.network_reachable,
            sync_role,
        },
    })
}

fn execute_one(
    client: &DaemonClient,
    plan: &PreparedAgent,
    report: &mut ApplyReport,
) -> anyhow::Result<()> {
    if plan.needs_publish {
        match client.publish(
            plan.program_name.clone(),
            plan.program_version.clone(),
            plan.hash.to_vec(),
        )? {
            Status::Ok => {
                if let Some(metadata) = &plan.metadata {
                    forward_meta(client, &blob_store::BlobHash(plan.hash), metadata);
                }
            }
            Status::Forbidden => anyhow::bail!(
                "publish '{}:{}' refused (Status::Forbidden) — the operator key is not an admin \
                 of this space. `apply` is an admin op.",
                plan.program_name,
                plan.program_version,
            ),
            Status::TagConflict => anyhow::bail!(
                "publish '{}:{}' raced with a different immutable tag; re-run apply and choose a \
                 fresh version if the conflict remains",
                plan.program_name,
                plan.program_version,
            ),
            other => anyhow::bail!(
                "publish '{}:{}' returned status {other}",
                plan.program_name,
                plan.program_version,
            ),
        }
    }

    match &plan.action {
        ApplyAction::Skip | ApplyAction::UpgradePending | ApplyAction::VersionRequired => Ok(()),
        ApplyAction::Upgrade => match client.upgrade(
            plan.instance_name.clone(),
            plan.program_name.clone(),
            plan.program_version.clone(),
            plan.hash.to_vec(),
        )? {
            Status::Ok => Ok(()),
            Status::Forbidden => anyhow::bail!(
                "upgrade '{}' refused (Status::Forbidden) — the operator key is not an admin of \
                 this space",
                plan.instance_name,
            ),
            other => anyhow::bail!("upgrade '{}' returned status {other}", plan.instance_name),
        },
        ApplyAction::Install {
            consistency,
            replication_id,
            install_args,
            install_payloads,
            network_reachable,
            sync_role,
        } => {
            let status = client.install(
                plan.instance_name.clone(),
                plan.program_name.clone(),
                plan.program_version.clone(),
                plan.hash.to_vec(),
                replication_id.to_vec(),
                *consistency,
                install_args.clone(),
                install_payloads.clone(),
                *network_reachable,
                sync_role.clone(),
            )?;
            match status {
                Status::Ok => Ok(()),
                // A peer's row synced in after preflight. The instance now
                // exists; report the race as an idempotent skip.
                Status::InstanceExists => {
                    report.installed.retain(|n| n != &plan.instance_name);
                    report.skipped.push(plan.instance_name.clone());
                    Ok(())
                }
                Status::Forbidden => anyhow::bail!(
                    "install '{}' refused (Status::Forbidden) — the operator key is not an admin \
                     of this space. `apply` is an admin op.",
                    plan.instance_name,
                ),
                Status::ReplicationIdReused => anyhow::bail!(
                    "install '{}' refused: its replication_id is a retired tombstone. Assign a \
                     fresh `replication_id` in the recipe to re-create it with clean state.",
                    plan.instance_name,
                ),
                Status::CrdtOptInRequired => anyhow::bail!(
                    "install '{}' requested CRDT consistency, but the program is not declared \
                     #[actor(crdt)]",
                    plan.instance_name,
                ),
                other => anyhow::bail!("install '{}' returned status {other}", plan.instance_name,),
            }
        }
    }
}

/// The program `(name, version)` an agent installs from. Changed agents
/// must name an explicit immutable `program = "name:version"`; the
/// implicit `<instance>:recipe` tag is only for initial/idempotent apply.
pub(crate) fn program_ref(agent: &AgentDef) -> anyhow::Result<(String, String, bool)> {
    match &agent.program {
        Some(pv) => {
            let Some((name, version)) = pv.split_once(':') else {
                anyhow::bail!(
                    "agent '{}': `program` must be `name:version`, got '{pv}'",
                    agent.name,
                );
            };
            if name.is_empty() || version.is_empty() || version.contains(':') {
                anyhow::bail!(
                    "agent '{}': `program` must contain exactly one `:` with non-empty name and \
                     version",
                    agent.name,
                );
            }
            Ok((name.to_string(), version.to_string(), true))
        }
        None => Ok((agent.name.clone(), RECIPE_VERSION.to_string(), false)),
    }
}

/// Recipe replication-id → 32 bytes: `auto`/absent hashes
/// `(space_id, name, hash)`; `off` disables; an explicit 64-hex value
/// is used verbatim.
fn resolve_replication_id(
    agent: &AgentDef,
    space_id: &[u8; 32],
    program_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    Ok(match agent.replication_id.as_deref() {
        Some("auto") | None => auto_replication_id(space_id, &agent.name, program_hash),
        Some("off") => [0u8; 32],
        Some(hex) => {
            let v = hex::decode(hex.trim_start_matches("0x"))
                .map_err(|_| anyhow::anyhow!("agent '{}': replication_id must be hex", agent.name))?;
            if v.len() != 32 {
                anyhow::bail!("agent '{}': replication_id must be 32 bytes", agent.name);
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            out
        }
    })
}

/// MERGE the recipe's node-local half onto `base`. Reconcile semantics
/// (like the registry install): a recipe field that IS declared upserts;
/// anything the recipe doesn't mention is preserved, never wiped. This
/// is what keeps `export | apply` non-destructive — `space export`
/// emits none of the node-local fields (they aren't in the registry),
/// so merging an exported recipe changes nothing (all-skips), whereas a
/// replace would delete the operator's cap_policy / intra_caps /
/// extensions. Node-owned fields (subscriptions, listen) always survive.
/// Deterministic → idempotent (re-applying the same recipe re-produces
/// the same config). Extension `.so` paths are resolved absolute against
/// `recipe_dir` so a later bare `space up` still finds them.
pub(crate) fn project_node_local(
    base: &LocalConfig,
    recipe: &Recipe,
    recipe_dir: &Path,
) -> LocalConfig {
    let mut out = base.clone();
    // cap_policy: the recipe overrides only if it declares one.
    if recipe.cap_policy.is_some() {
        out.cap_policy = recipe.cap_policy.clone();
    }
    // agents: upsert each recipe agent that carries node-local policy.
    for a in flatten(&recipe.agents) {
        if a.tick_ms.is_none() && a.intra_caps.is_empty() && !a.device_secret {
            continue; // no node-local policy — leave any base entry intact
        }
        out.agents.insert(
            a.name.clone(),
            AgentLocal {
                tick_ms: a.tick_ms,
                intra_caps: a.intra_caps.clone(),
                device_secret: a.device_secret,
            },
        );
    }
    // extensions: upsert by name (recipe wins), preserving base
    // extensions the recipe doesn't mention.
    for e in &recipe.extensions {
        let projected = ExtensionLocal {
            name: e.name.clone(),
            path: absolutize(recipe_dir, &e.path),
            cap_policy: e.cap_policy.clone(),
            relay_unauthenticated: e.relay_unauthenticated,
            intra_caps: e.intra_caps.clone(),
            tick_ms: e.tick_ms,
            init: e.init.clone(),
        };
        match out.extensions.iter_mut().find(|x| x.name == e.name) {
            Some(slot) => *slot = projected,
            None => out.extensions.push(projected),
        }
    }
    out
}

/// Resolve an extension `.so` path against the recipe dir. An absolute
/// path is used as-is; a relative one is joined onto `recipe_dir` so a
/// later bare `space up` (which has no recipe dir) still resolves it.
fn absolutize(recipe_dir: &Path, path: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        recipe_dir.join(p).to_string_lossy().to_string()
    }
}

/// Best-effort: forward a program's `.vos_meta` schema so dynamic
/// dispatch resolves types. A blob without meta, or a transport hiccup,
/// is a no-op — it never blocks the apply.
fn forward_meta(client: &DaemonClient, hash: &blob_store::BlobHash, metadata: &[u8]) {
    if let Err(e) = client.register_meta(hash.0.to_vec(), metadata.to_vec()) {
        tracing::debug!("register_meta during apply skipped: {e}");
    }
}

fn emit(space: &str, report: &ApplyReport) {
    if output::is_json() {
        output::print_json(report);
        return;
    }
    let verb = if report.diff { "would " } else { "" };
    println!("apply {space}{}", if report.diff { " (--diff, dry run)" } else { "" });
    for p in &report.published {
        println!("  {verb}publish {p}");
    }
    for i in &report.installed {
        println!("  {verb}install {i}");
    }
    for u in &report.upgraded {
        println!("  {verb}upgrade {u}");
    }
    for u in &report.upgrade_pending {
        println!("  {u}: catalog blob differs — run with --upgrade to re-point");
    }
    for u in &report.version_required {
        println!("  {u}: recipe blob differs — set an explicit new `program = \"name:version\"`");
    }
    for s in &report.skipped {
        println!("  skip {s} (already installed)");
    }
    if report.local_changed {
        println!("  {verb}update local.toml (node-local policy)");
    }
    if report.published.is_empty()
        && report.installed.is_empty()
        && report.upgraded.is_empty()
        && report.upgrade_pending.is_empty()
        && report.version_required.is_empty()
        && !report.local_changed
    {
        println!("  nothing to do — registry already matches the recipe");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe_from(s: &str) -> Recipe {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn project_node_local_only_emits_agents_with_policy() {
        // A bare agent gets no [agents.<name>] table; one with node-local
        // fields does. cap_policy + extensions ride from the recipe.
        let m = recipe_from(
            r#"
            cap_policy = "block"
            [[agent]]
            name = "plain"
            path = "plain.elf"
            [[agent]]
            name = "ticker"
            path = "ticker.elf"
            tick_ms = 250
            intra_caps = ["space-registry:member"]
            device_secret = true
            [[extension]]
            name = "gateway"
            path = "libgw.so"
        "#,
        );
        let base = LocalConfig {
            subscriptions: vec!["keep-me".into()],
            listen: vec!["/ip4/0.0.0.0/tcp/1".into()],
            ..Default::default()
        };
        let out = project_node_local(&base, &m, Path::new("/recipes"));
        // node-owned fields preserved
        assert_eq!(out.subscriptions, vec!["keep-me".to_string()]);
        assert_eq!(out.listen, vec!["/ip4/0.0.0.0/tcp/1".to_string()]);
        // recipe-owned fields projected
        assert_eq!(out.cap_policy.as_deref(), Some("block"));
        assert!(!out.agents.contains_key("plain"), "bare agent has no table");
        let ticker = out.agents.get("ticker").expect("ticker has policy");
        assert_eq!(ticker.tick_ms, Some(250));
        assert_eq!(ticker.intra_caps, vec!["space-registry:member".to_string()]);
        assert!(ticker.device_secret);
        assert_eq!(out.extensions.len(), 1);
        assert_eq!(out.extensions[0].name, "gateway");
        // extension .so path resolved absolute against the recipe dir.
        assert_eq!(out.extensions[0].path, "/recipes/libgw.so");
    }

    #[test]
    fn program_ref_from_program_field_or_defaults() {
        // A hand-written recipe agent (no `program`) installs
        // `<name>:recipe`; an exported agent carries an explicit
        // `program = "name:version"`.
        let bare = AgentDef {
            name: "counter".into(),
            ..Default::default()
        };
        assert_eq!(
            program_ref(&bare).unwrap(),
            ("counter".into(), RECIPE_VERSION.into(), false),
        );

        let exported = AgentDef {
            name: "counter".into(),
            program: Some("counter:recipe".into()),
            ..Default::default()
        };
        assert_eq!(
            program_ref(&exported).unwrap(),
            ("counter".into(), "recipe".into(), true),
        );

        // Explicit references always carry a version; otherwise an
        // upgrade could accidentally target the immutable recipe tag.
        let noversion = AgentDef {
            name: "x".into(),
            program: Some("libcounter".into()),
            ..Default::default()
        };
        assert!(program_ref(&noversion).is_err());
    }

    #[test]
    fn project_node_local_merges_preserving_existing_policy() {
        // The `export | apply` non-destructiveness guarantee: an exported
        // recipe declares NO node-local fields (they aren't in the
        // registry), so merging it must leave an operator's existing
        // cap_policy / per-agent policy / extensions untouched.
        let mut existing_agents = BTreeMap::new();
        existing_agents.insert(
            "messenger".to_string(),
            AgentLocal {
                tick_ms: Some(500),
                intra_caps: vec!["space-registry:member".into()],
                device_secret: true,
            },
        );
        let base = LocalConfig {
            subscriptions: vec!["messenger".into()],
            listen: vec![],
            cap_policy: Some("block".into()),
            agents: existing_agents,
            extensions: vec![ExtensionLocal {
                name: "gateway".into(),
                path: "/abs/libgw.so".into(),
                ..Default::default()
            }],
        };
        // An export-shaped recipe: agents carry program_hash but no
        // node-local fields, and there are no extensions / cap_policy.
        let m = recipe_from(
            r#"
            space = "x"
            [[agent]]
            name = "messenger"
            program = "messenger:recipe"
            program_hash = "aa"
        "#,
        );
        let out = project_node_local(&base, &m, Path::new("/recipes"));
        assert_eq!(out, base, "an export recipe must not wipe existing node-local policy");
    }

    #[test]
    fn project_node_local_is_idempotent() {
        // Re-projecting an already-projected config is a fixed point, so
        // a second `apply` writes nothing (the all-skips guarantee).
        let m = recipe_from(
            r#"
            cap_policy = "log"
            [[agent]]
            name = "ticker"
            path = "ticker.elf"
            tick_ms = 100
        "#,
        );
        let once = project_node_local(&LocalConfig::default(), &m, Path::new("/recipes"));
        let twice = project_node_local(&once, &m, Path::new("/recipes"));
        assert_eq!(once, twice);
    }
}
