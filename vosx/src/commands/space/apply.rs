//! `space apply <recipe> [--diff] [--upgrade]` — reconcile a recipe
//! TOML against a *running* space.
//!
//! A recipe is a dev-time convenience; the registry stays the runtime
//! source of truth. `apply` is the one-shot admin op that arranges the
//! registry to match a recipe and projects the recipe's node-local half
//! into `local.toml`:
//!
//! - **Replicated half** → the registry, over `DaemonClient`: each
//!   `[[agent]]`'s ELF is blob-cached + published as `<name>:manifest`
//!   (if missing) and `install`ed (if no instance of that name exists).
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
    self, encode_init_args, encode_on_start_payloads, flatten, AgentDef, Manifest,
};
use crate::commands::space::subscriptions::{self, AgentLocal, ExtensionLocal, LocalConfig};
use crate::output;

/// The version tag manifest/recipe programs publish under. Recipes
/// don't carry per-program versions, so both `reconcile` (genesis) and
/// `apply` (runtime) use the same literal so their catalog rows agree.
const RECIPE_VERSION: &str = "manifest";

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
    /// Whether `local.toml` changed (or would change, under `--diff`).
    local_changed: bool,
    /// `--diff` dry run — nothing was written.
    diff: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (manifest, recipe_dir) = reconcile::parse_manifest_file(&args.recipe)?;
    reconcile::validate_manifest_names(&manifest)?;

    DaemonClient::with_connect(&args.space, |client| {
        let data_dir = PathBuf::from(&client.entry.data_dir);
        let report = apply_manifest(client, &manifest, &recipe_dir, &data_dir, args.diff, args.upgrade)?;
        emit(&client.entry.name, &report);
        Ok(())
    })
}

/// Reconcile `manifest` against the daemon `client` is connected to.
/// Returns the plan (or, under `diff`, what the plan *would* be). The
/// caller owns the `DaemonClient`; genesis apply (`space new
/// --manifest` / the recipe path of `space up`) reuses this against the
/// just-booted local daemon.
pub(crate) fn apply_manifest(
    client: &DaemonClient,
    manifest: &Manifest,
    recipe_dir: &Path,
    data_dir: &Path,
    diff: bool,
    upgrade: bool,
) -> anyhow::Result<ApplyReport> {
    let mut report = ApplyReport {
        diff,
        ..Default::default()
    };

    let space_id = client
        .entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;

    // name → derived svc id, for `Vec<u32>` init-arg resolution (e.g.
    // `children = ["greeter"]`). Same derivation the daemon uses to
    // register the agents, so the ids match.
    let prefix = client.daemon_prefix();
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    for a in flatten(&manifest.agents) {
        name_ids.insert(a.name.clone(), instance_service_id(&a.name, prefix).0);
    }

    for agent in flatten(&manifest.agents) {
        apply_one(
            client,
            agent,
            recipe_dir,
            &space_id,
            &name_ids,
            diff,
            upgrade,
            &mut report,
        )?;
    }

    // Node-local half → local.toml. Recipe fields overwrite the recipe-
    // owned sections (cap_policy, per-agent policy, extensions) while
    // node-owned fields (subscriptions, listen) are preserved.
    let mut cfg = subscriptions::load(data_dir)?;
    let next = project_node_local(&cfg, manifest, recipe_dir);
    if next != cfg {
        report.local_changed = true;
        if !diff {
            cfg = next;
            subscriptions::save(data_dir, &cfg)?;
        }
    }

    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn apply_one(
    client: &DaemonClient,
    agent: &AgentDef,
    recipe_dir: &Path,
    space_id: &[u8; 32],
    name_ids: &BTreeMap<String, u32>,
    diff: bool,
    upgrade: bool,
    report: &mut ApplyReport,
) -> anyhow::Result<()> {
    // 1. Resolve the blob hash + program identity from either a source
    //    `path` (a hand-written recipe) or `program_hash` (a `space
    //    export` output, which carries no path). Path-based also yields
    //    the ELF bytes — needed to publish and to encode init args; the
    //    hash-based form resolves against the already-published catalog,
    //    which is what makes `export | apply --diff` all-skips.
    let (program_name, program_version) = program_ref(agent);
    let (hash, elf_bytes) = if !agent.path.is_empty() {
        let elf_path = recipe_dir.join(&agent.path);
        let bytes = std::fs::read(&elf_path).map_err(|e| {
            anyhow::anyhow!("read {} for agent '{}': {e}", elf_path.display(), agent.name)
        })?;
        let h = blob_store::cache_put(&bytes)
            .map_err(|e| anyhow::anyhow!("cache blob for '{}': {e}", agent.name))?;
        (h.0, Some(bytes))
    } else if let Some(ph) = &agent.program_hash {
        let h = blob_store::BlobHash::from_hex(ph)
            .map_err(|_| anyhow::anyhow!("agent '{}': program_hash must be 64 hex", agent.name))?;
        (h.0, None)
    } else {
        anyhow::bail!(
            "agent '{}' has neither `path` (a source recipe) nor `program_hash` (an exported \
             recipe) — nothing to resolve the blob from",
            agent.name,
        );
    };

    // 2. Ensure the program is published at this blob.
    match client.program(&program_name, &program_version)? {
        Some(p) if p.hash == hash => {
            // Already the catalog's blob — nothing to publish.
        }
        Some(_) => {
            // The tag is pinned to a different blob. Never silently
            // overwrite (tags are immutable) — `--upgrade` re-points the
            // instance below; a fresh install would need a new version.
            report.upgrade_pending.push(agent.name.clone());
        }
        None => {
            let Some(bytes) = &elf_bytes else {
                anyhow::bail!(
                    "agent '{}': program {program_name}:{program_version} (hash {}) is not in the \
                     catalog and this recipe carries no `path` to publish it from",
                    agent.name,
                    hex::encode(hash),
                );
            };
            report.published.push(format!("{program_name}:{program_version}"));
            if !diff {
                match client.publish(program_name.clone(), program_version.clone(), hash.to_vec())? {
                    Status::Ok => forward_meta(client, &blob_store::BlobHash(hash), bytes),
                    Status::Forbidden => anyhow::bail!(
                        "publish '{program_name}' refused (Status::Forbidden) — the operator key \
                         is not an admin of this space. `apply` is an admin op; grant the operator \
                         a role or apply from the admin node."
                    ),
                    Status::TagConflict => anyhow::bail!(
                        "publish '{program_name}:{program_version}' conflicts with an existing tag \
                         at a different hash (race?). Retry."
                    ),
                    other => anyhow::bail!("publish '{program_name}' returned status {other}"),
                }
            }
        }
    }

    // 3. Ensure the instance is installed.
    let existing = client.agent(&agent.name)?;
    match existing {
        Some(row) if row.program_hash == hash => {
            report.skipped.push(agent.name.clone());
            return Ok(());
        }
        Some(_) => {
            // Installed but pointing at a different blob. Upgrade (if
            // asked) or flag it — a synced-in row must not be silently
            // clobbered.
            if upgrade && !diff {
                match client.upgrade(
                    agent.name.clone(),
                    program_name.clone(),
                    program_version.clone(),
                    hash.to_vec(),
                )? {
                    Status::Ok => report.upgraded.push(agent.name.clone()),
                    other => anyhow::bail!("upgrade '{}' returned status {other}", agent.name),
                }
            } else if !report.upgrade_pending.iter().any(|n| n == &agent.name) {
                report.upgrade_pending.push(agent.name.clone());
            }
            return Ok(());
        }
        None => {}
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
    // Installing a new instance needs the ELF (to encode init args). The
    // path-less `program_hash` form only supports the already-installed
    // (skip) path — the round-trip case.
    let Some(elf_bytes) = &elf_bytes else {
        anyhow::bail!(
            "agent '{}' is not installed and this recipe carries no `path` — the path-less \
             (exported) form can only reconcile already-installed instances",
            agent.name,
        );
    };
    let install_args = encode_init_args(&agent.name, elf_bytes, &agent.init, name_ids)?;
    let install_payloads = encode_on_start_payloads(&agent.on_start)?;

    report.installed.push(agent.name.clone());
    if diff {
        return Ok(());
    }

    let status = client.install(
        agent.name.clone(),
        program_name,
        program_version,
        hash.to_vec(),
        replication_id.to_vec(),
        consistency,
        install_args,
        install_payloads,
        agent.network_reachable,
        sync_role,
    )?;
    match status {
        Status::Ok => {}
        // A peer's row for this instance synced in between our check and
        // our install — the post-condition (installed) already holds.
        Status::InstanceExists => {
            report.installed.retain(|n| n != &agent.name);
            report.skipped.push(agent.name.clone());
        }
        Status::Forbidden => anyhow::bail!(
            "install '{}' refused (Status::Forbidden) — the operator key is not an admin of this \
             space. `apply` is an admin op.",
            agent.name,
        ),
        Status::ReplicationIdReused => anyhow::bail!(
            "install '{}' refused: its replication_id is a retired tombstone (uninstalled before). \
             Assign a fresh `replication_id` in the recipe to re-create it with clean state.",
            agent.name,
        ),
        other => anyhow::bail!("install '{}' returned status {other}", agent.name),
    }
    Ok(())
}

/// The program `(name, version)` an agent installs from: an explicit
/// `program = "name:version"` (as `space export` emits), else the agent
/// name at the recipe version tag.
fn program_ref(agent: &AgentDef) -> (String, String) {
    match &agent.program {
        Some(pv) => match pv.split_once(':') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (pv.clone(), RECIPE_VERSION.to_string()),
        },
        None => (agent.name.clone(), RECIPE_VERSION.to_string()),
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

/// Build the local.toml the recipe implies, preserving `base`'s
/// node-owned fields (subscriptions, listen). The recipe wholly owns
/// `cap_policy`, per-agent policy, and extensions — so a re-apply is
/// deterministic (equal recipe → equal output → no write). Extension
/// `.so` paths are resolved absolute against `recipe_dir` so a later
/// bare `space up` (with no recipe dir) still finds them.
pub(crate) fn project_node_local(
    base: &LocalConfig,
    manifest: &Manifest,
    recipe_dir: &Path,
) -> LocalConfig {
    let mut agents: BTreeMap<String, AgentLocal> = BTreeMap::new();
    for a in flatten(&manifest.agents) {
        if a.tick_ms.is_none() && a.intra_caps.is_empty() && !a.device_secret {
            continue; // no node-local policy — don't emit an empty table
        }
        agents.insert(
            a.name.clone(),
            AgentLocal {
                tick_ms: a.tick_ms,
                intra_caps: a.intra_caps.clone(),
                device_secret: a.device_secret,
            },
        );
    }
    let extensions = manifest
        .extensions
        .iter()
        .map(|e| ExtensionLocal {
            name: e.name.clone(),
            path: absolutize(recipe_dir, &e.path),
            cap_policy: e.cap_policy.clone(),
            relay_unauthenticated: e.relay_unauthenticated,
            intra_caps: e.intra_caps.clone(),
            tick_ms: e.tick_ms,
            init: e.init.clone(),
        })
        .collect();
    LocalConfig {
        subscriptions: base.subscriptions.clone(),
        listen: base.listen.clone(),
        cap_policy: manifest.cap_policy.clone(),
        agents,
        extensions,
    }
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
fn forward_meta(client: &DaemonClient, hash: &blob_store::BlobHash, elf_bytes: &[u8]) {
    let Some(meta_blob) = vos::metadata::raw_section_from_elf(elf_bytes) else {
        return;
    };
    if let Err(e) = client.register_meta(hash.0.to_vec(), meta_blob) {
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
        println!("  upgrade {u}");
    }
    for u in &report.upgrade_pending {
        println!("  {u}: catalog blob differs — run with --upgrade to re-point");
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
        && !report.local_changed
    {
        println!("  nothing to do — registry already matches the recipe");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_from(s: &str) -> Manifest {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn project_node_local_only_emits_agents_with_policy() {
        // A bare agent gets no [agents.<name>] table; one with node-local
        // fields does. cap_policy + extensions ride from the manifest.
        let m = manifest_from(
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
        // `<name>:manifest`; an exported agent carries an explicit
        // `program = "name:version"`.
        let bare = AgentDef {
            name: "counter".into(),
            ..Default::default()
        };
        assert_eq!(program_ref(&bare), ("counter".into(), RECIPE_VERSION.into()));

        let exported = AgentDef {
            name: "counter".into(),
            program: Some("counter:manifest".into()),
            ..Default::default()
        };
        assert_eq!(program_ref(&exported), ("counter".into(), "manifest".into()));

        // A `program` with no `:` is treated as a bare name at the
        // recipe version.
        let noversion = AgentDef {
            name: "x".into(),
            program: Some("libcounter".into()),
            ..Default::default()
        };
        assert_eq!(program_ref(&noversion), ("libcounter".into(), RECIPE_VERSION.into()));
    }

    #[test]
    fn project_node_local_is_idempotent() {
        // Re-projecting an already-projected config is a fixed point, so
        // a second `apply` writes nothing (the all-skips guarantee).
        let m = manifest_from(
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
