//! `space apply <recipe> [--diff] [--upgrade]` — reconcile a recipe
//! TOML against a *running* space.
//!
//! A recipe is a dev-time convenience; the registry stays the runtime
//! source of truth. `apply` is the one-shot admin op that arranges the
//! registry to match a recipe and projects the recipe's node-local half
//! into `local.toml`:
//!
//! - **Replicated half** → the registry, over `DaemonClient`: each
//!   `[[agent]]`'s package is blob-cached, published under a name, and
//!   installed (if no instance exists).
//!   The bytes reach the daemon through the shared content-addressed
//!   blob cache — `publish` only ships `(name, hash)`.
//! - **Node-local half** → `local.toml`: per-service device signing,
//!   node-local extension relay authority, and
//!   `[[extension]]` entries. These never touch the `AgentRow`; boot
//!   reads them back so a bare `space up` restart re-applies them.
//!   Extensions are host-local (`dlopen` in-process) — a running daemon
//!   can't register them remotely, so `apply` only records them; they
//!   attach on the next `space up`.
//!
//! Idempotent: a second `apply` of the same recipe is all-skips.
//! `--diff` prints the plan and exits without touching anything.
//! A differing installed blob is flagged, never silently overwritten. The
//! retained `--upgrade` compatibility flag fails closed before any write when
//! a legacy service upgrade would be required; the Agent lifecycle owns that
//! transition after the clean cutover.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use vos::registry::{ProgramKind, ProgramTag, Status, SyncFloor};

use crate::blob_store;
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::{
    auto_replication_id, parse_consistency, parse_nonzero_replication_id,
};
use crate::commands::space::reconcile::{self, AgentDef, Recipe};
use crate::commands::space::subscriptions::{self, ExtensionLocal, LocalConfig};
use crate::output;

pub struct Args {
    pub space: String,
    pub recipe: PathBuf,
    /// Print the plan and exit without mutating the registry or
    /// `local.toml`.
    pub diff: bool,
    /// Compatibility guard for the retired service-upgrade path. If an
    /// installed blob differs, this fails before writes and directs the
    /// operator to the Agent lifecycle.
    pub upgrade: bool,
}

#[derive(Serialize, Default)]
pub(crate) struct ApplyReport {
    /// Names newly published or moved to another package.
    published: Vec<String>,
    /// Instance names newly installed.
    installed: Vec<String>,
    /// Instances already present with the recipe's blob — no-ops.
    skipped: Vec<String>,
    /// Legacy compatibility field. The clean-cutover path never populates it.
    upgraded: Vec<String>,
    /// Instances whose catalog blob differs from the recipe and must move
    /// through the Agent lifecycle.
    upgrade_pending: Vec<String>,
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
        let report = apply_recipe(
            client,
            &recipe,
            &recipe_dir,
            &data_dir,
            args.diff,
            args.upgrade,
        )?;
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

    // Node-local half → local.toml. Recipe fields overwrite the recipe-
    // owned sections (per-agent policy and extensions) while
    // node-owned fields (subscriptions, listen) are preserved.
    let mut cfg = subscriptions::load(data_dir)?;
    let next = project_node_local(&cfg, recipe, recipe_dir);
    let local_changed = next != cfg;

    // Validate the entire plan before the first cache, catalog, instance,
    // or local-config write.
    let mut plans = Vec::new();
    let mut planned_names: BTreeMap<String, ([u8; 32], ProgramTag)> = BTreeMap::new();
    for agent in &recipe.agents {
        let mut plan = preflight_one(client, agent, recipe_dir, &space_id, upgrade)?;
        deduplicate_publication_plan(&mut planned_names, &mut plan)?;
        plans.push(plan);
    }
    reject_legacy_upgrade_plans(&plans)?;

    let mut report = ApplyReport {
        local_changed,
        diff,
        ..Default::default()
    };
    for plan in &plans {
        if plan.needs_publish {
            report.published.push(plan.program_name.clone());
        }
        match &plan.action {
            ApplyAction::Skip => report.skipped.push(plan.instance_name.clone()),
            ApplyAction::Install { .. } => report.installed.push(plan.instance_name.clone()),
            ApplyAction::Upgrade => report.upgraded.push(plan.instance_name.clone()),
            ApplyAction::UpgradePending => report.upgrade_pending.push(plan.instance_name.clone()),
        }
    }

    if diff {
        return Ok(report);
    }

    // A real apply heals the content-addressed cache even for skipped
    // instances. Dry runs never reach this write.
    for plan in &plans {
        if let Some(bytes) = &plan.package_bytes {
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
        network_reachable: bool,
        sync_role: SyncFloor,
    },
    Upgrade,
    UpgradePending,
}

struct PreparedAgent {
    instance_name: String,
    program_name: String,
    hash: [u8; 32],
    /// Signed catalog capability copied from the service package.
    crdt: bool,
    /// Exact catalog generation the install/upgrade must pin.
    program: ProgramTag,
    /// CAS base observed before a requested publication move.
    expected_program: Option<ProgramTag>,
    package_bytes: Option<Vec<u8>>,
    schemas: Option<Vec<u8>>,
    needs_publish: bool,
    action: ApplyAction,
}

fn deduplicate_publication_plan(
    planned_names: &mut BTreeMap<String, ([u8; 32], ProgramTag)>,
    plan: &mut PreparedAgent,
) -> anyhow::Result<()> {
    if !plan.needs_publish {
        return Ok(());
    }
    let name = plan.program_name.clone();
    match planned_names.get(&name) {
        Some((hash, tag)) if hash == &plan.hash => {
            // Every install sharing one newly-published package must pin the
            // single generation actually emitted by the first plan, rather
            // than its own never-published nonce.
            plan.program = *tag;
            plan.expected_program = None;
            plan.needs_publish = false;
        }
        Some(_) => anyhow::bail!("recipe assigns program {name} to more than one package"),
        None => {
            planned_names.insert(name, (plan.hash, plan.program));
        }
    }
    Ok(())
}

fn reject_legacy_upgrade_plans(plans: &[PreparedAgent]) -> anyhow::Result<()> {
    if plans
        .iter()
        .any(|plan| matches!(&plan.action, ApplyAction::Upgrade))
    {
        return Err(super::client::legacy_service_upgrade_cutover_error());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preflight_one(
    client: &DaemonClient,
    agent: &AgentDef,
    recipe_dir: &Path,
    space_id: &[u8; 32],
    upgrade: bool,
) -> anyhow::Result<PreparedAgent> {
    // Resolve the exact package from either a source `path` or the hash in
    // exported recipes. Path-less recipes can reconcile existing rows but
    // cannot publish or install bytes they do not contain.
    let program_name = program_name(agent)?;
    let (hash, package_bytes, package_kind, schemas) = if !agent.path.is_empty() {
        let package_path = recipe_dir.join(&agent.path);
        let bytes = std::fs::read(&package_path).map_err(|e| {
            anyhow::anyhow!(
                "read {} for agent '{}': {e}",
                package_path.display(),
                agent.name
            )
        })?;
        let h = blob_store::BlobHash::of(&bytes);
        match super::publish::canonical_program(&program_name, h, bytes)? {
            super::publish::AdmittedProgram::Service {
                hash,
                exact_bytes,
                metadata,
                crdt,
            } => (
                hash.0,
                Some(exact_bytes),
                Some(ProgramKind::Service { crdt }),
                Some(metadata),
            ),
            super::publish::AdmittedProgram::AgentActor { .. } => anyhow::bail!(
                "agent '{}': recipes currently describe service actors; publish AgentActor packages with `vosx space publish` and install them through the system Agent lifecycle",
                agent.name,
            ),
        }
    } else if let Some(ph) = &agent.program_hash {
        let h = blob_store::BlobHash::from_hex(ph)
            .map_err(|_| anyhow::anyhow!("agent '{}': program_hash must be 64 hex", agent.name))?;
        (h.0, None, None, None)
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
    if let Some(row) = existing.as_ref().filter(|row| row.program_hash == hash) {
        return Ok(PreparedAgent {
            instance_name: agent.name.clone(),
            program_name,
            hash,
            crdt: match package_kind {
                Some(ProgramKind::Service { crdt }) => crdt,
                Some(ProgramKind::AgentActor) => unreachable!("AgentActor recipe rejected above"),
                None => false,
            },
            program: ProgramTag {
                publication_id: row.program_publication_id,
                hash: row.program_hash,
            },
            expected_program: None,
            package_bytes,
            schemas,
            needs_publish: false,
            action: ApplyAction::Skip,
        });
    }

    let current_program = client.program(&program_name)?;
    let needs_publish = match current_program.as_ref() {
        Some(p)
            if p.hash == hash
                && package_kind
                    .as_ref()
                    .is_none_or(|expected| &p.kind == expected) =>
        {
            false
        }
        Some(_) if package_bytes.is_some() => true,
        Some(_) => anyhow::bail!(
            "agent '{}': catalog name {program_name} points at another package and this recipe \
             has no `path` with replacement bytes",
            agent.name,
        ),
        None => {
            if package_bytes.is_none() {
                anyhow::bail!(
                    "agent '{}': program {program_name} (hash {}) is not in the \
                     catalog and this recipe carries no `path` to publish it from",
                    agent.name,
                    hex::encode(hash),
                );
            }
            true
        }
    };
    let crdt = match package_kind
        .as_ref()
        .or_else(|| current_program.as_ref().map(|row| &row.kind))
    {
        Some(ProgramKind::Service { crdt }) => *crdt,
        Some(ProgramKind::AgentActor) => anyhow::bail!(
            "agent '{}': an AgentActor program cannot be installed through the legacy recipe service slot",
            agent.name,
        ),
        None => anyhow::bail!(
            "agent '{}': cannot classify its path-less unpublished program",
            agent.name,
        ),
    };
    let expected_program = needs_publish
        .then(|| current_program.as_ref().map(|row| row.tag()))
        .flatten();
    let program = if needs_publish {
        ProgramTag {
            publication_id: super::common::mint_publication_id()?,
            hash,
        }
    } else {
        current_program
            .as_ref()
            .expect("non-published program was resolved above")
            .tag()
    };

    if existing.is_some() {
        return Ok(PreparedAgent {
            instance_name: agent.name.clone(),
            program_name,
            hash,
            crdt,
            program,
            expected_program,
            package_bytes,
            schemas,
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
    let Some(_) = &package_bytes else {
        anyhow::bail!(
            "agent '{}' is not installed and this recipe carries no `path` — the path-less \
             (exported) form can only reconcile already-installed instances",
            agent.name,
        );
    };
    Ok(PreparedAgent {
        instance_name: agent.name.clone(),
        program_name,
        hash,
        crdt,
        program,
        expected_program,
        package_bytes,
        schemas,
        needs_publish,
        action: ApplyAction::Install {
            consistency,
            replication_id,
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
        match client.publish_service_program(
            plan.program_name.clone(),
            plan.hash,
            plan.crdt,
            plan.program.publication_id,
            plan.expected_program,
        )? {
            Status::Ok => {
                if let Some(schemas) = &plan.schemas {
                    forward_meta(client, &blob_store::BlobHash(plan.hash), schemas);
                }
            }
            Status::Forbidden => anyhow::bail!(
                "publish '{}' refused (Status::Forbidden) — the operator key is not an admin \
                 of this space. `apply` is an admin op.",
                plan.program_name,
            ),
            other => anyhow::bail!("publish '{}' returned status {other}", plan.program_name,),
        }
    }

    match &plan.action {
        ApplyAction::Skip | ApplyAction::UpgradePending => Ok(()),
        // Defense in depth: `apply_recipe` rejects the whole plan before its
        // first write, and the executor itself has no legacy upgrade transport
        // path if a future caller bypasses that preflight.
        ApplyAction::Upgrade => Err(super::client::legacy_service_upgrade_cutover_error()),
        ApplyAction::Install {
            consistency,
            replication_id,
            network_reachable,
            sync_role,
        } => {
            let status = client.install_service_actor(
                plan.instance_name.clone(),
                plan.program_name.clone(),
                plan.program,
                super::common::mint_installation_id()?,
                *replication_id,
                *consistency,
                *network_reachable,
                *sync_role,
            )?;
            match status {
                Status::Ok => Ok(()),
                // A peer's row synced in after preflight. The instance now
                // exists; accept the race only if it established the exact
                // semantic postcondition this plan requested.
                Status::InstanceExists => {
                    let observed = client.agent(&plan.instance_name)?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "install '{}' raced with a row that is no longer readable",
                            plan.instance_name,
                        )
                    })?;
                    if !service_install_matches(
                        &observed,
                        &plan.instance_name,
                        &plan.program_name,
                        plan.program,
                        *replication_id,
                        *consistency,
                        *network_reachable,
                        *sync_role,
                    ) {
                        anyhow::bail!(
                            "install '{}' raced with a different live installation; rerun after reconciling the conflict",
                            plan.instance_name,
                        );
                    }
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

/// Catalog name used by this actor. If omitted, the instance name is used.
fn program_name(agent: &AgentDef) -> anyhow::Result<String> {
    super::common::parse_program_name(agent.program.as_deref().unwrap_or(&agent.name))
}

/// Recipe replication-id → 32 bytes: `auto`/absent hashes
/// `(space_id, name, hash)`; an explicit nonzero 64-hex value is used
/// verbatim. The clean-break registry has no zero/off identity.
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

fn service_install_matches(
    row: &vos::registry::AgentRow,
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

/// MERGE the recipe's node-local half onto `base`. Reconcile semantics
/// (like the registry install): a recipe field that IS declared upserts;
/// anything the recipe doesn't mention is preserved, never wiped. This
/// is what keeps `export | apply` non-destructive — `space export`
/// emits none of the node-local fields (they aren't in the registry),
/// so merging an exported recipe changes nothing (all-skips), whereas a
/// replace would delete operator-owned extensions. Node-owned fields
/// (subscriptions, listen, ingress) always survive.
/// Deterministic → idempotent (re-applying the same recipe re-produces
/// the same config). Extension `.so` paths are resolved absolute against
/// `recipe_dir` so a later bare `space up` still finds them.
pub(crate) fn project_node_local(
    base: &LocalConfig,
    recipe: &Recipe,
    recipe_dir: &Path,
) -> LocalConfig {
    let mut out = base.clone();
    // agents: upsert each recipe agent that carries node-local policy.
    for a in &recipe.agents {
        if !a.device_secret && a.intra_caps.is_none() {
            continue; // no node-local policy — leave any base entry intact
        }
        let policy = out.agents.entry(a.name.clone()).or_default();
        if a.device_secret {
            policy.device_secret = true;
        }
        if let Some(intra_caps) = &a.intra_caps {
            policy.intra_caps.clone_from(intra_caps);
        }
    }
    // extensions: upsert by name (recipe wins), preserving base
    // extensions the recipe doesn't mention.
    for e in &recipe.extensions {
        let projected = ExtensionLocal {
            name: e.name.clone(),
            path: absolutize(recipe_dir, &e.path),
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

/// Best-effort: forward a package schema so dynamic
/// dispatch resolves types. A blob without meta, or a transport hiccup,
/// is a no-op — it never blocks the apply.
fn forward_meta(client: &DaemonClient, hash: &blob_store::BlobHash, schemas: &[u8]) {
    if schemas.is_empty() {
        return;
    }
    if let Err(e) = client.register_meta(hash.0.to_vec(), schemas.to_vec()) {
        tracing::debug!("register_meta during apply skipped: {e}");
    }
}

fn emit(space: &str, report: &ApplyReport) {
    if output::is_json() {
        output::print_json(report);
        return;
    }
    let verb = if report.diff { "would " } else { "" };
    println!(
        "apply {space}{}",
        if report.diff {
            " (--diff, dry run)"
        } else {
            ""
        }
    );
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
        println!(
            "  {u}: catalog blob differs — migrate it through the Agent lifecycle \
             (the legacy --upgrade path is retired)"
        );
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

    fn recipe_from(s: &str) -> Recipe {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn project_node_local_only_emits_agents_with_policy() {
        // A bare service gets no local table; either local policy does.
        let m = recipe_from(
            r#"
            [[agent]]
            name = "plain"
            path = "plain.vos"
            [[agent]]
            name = "authority"
            path = "authority.vos"
            device_secret = true
            [[agent]]
            name = "chain-reader"
            path = "reader.vos"
            intra_caps = ["substrate:member"]
            [[extension]]
            name = "worker"
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
        assert!(!out.agents.contains_key("plain"), "bare agent has no table");
        assert!(out.agents["authority"].device_secret);
        assert_eq!(
            out.agents["chain-reader"].intra_caps,
            vec!["substrate:member"]
        );
        assert_eq!(out.extensions.len(), 1);
        assert_eq!(out.extensions[0].name, "worker");
        // extension .so path resolved absolute against the recipe dir.
        assert_eq!(out.extensions[0].path, "/recipes/libgw.so");
    }

    #[test]
    fn program_name_uses_explicit_name_or_instance_name() {
        let bare = AgentDef {
            name: "counter".into(),
            ..Default::default()
        };
        assert_eq!(program_name(&bare).unwrap(), "counter");

        let exported = AgentDef {
            name: "counter".into(),
            program: Some("counter-package".into()),
            ..Default::default()
        };
        assert_eq!(program_name(&exported).unwrap(), "counter-package");

        let invalid = AgentDef {
            name: "x".into(),
            program: Some("counter:tag".into()),
            ..Default::default()
        };
        assert!(program_name(&invalid).is_err());
    }

    fn publication_plan(name: &str, hash: [u8; 32], publication: u8) -> PreparedAgent {
        PreparedAgent {
            instance_name: format!("{name}-{publication}"),
            program_name: name.into(),
            hash,
            crdt: false,
            program: ProgramTag {
                publication_id: vos::registry::PublicationId::new([publication; 32]),
                hash,
            },
            expected_program: Some(ProgramTag {
                publication_id: vos::registry::PublicationId::new([0xEE; 32]),
                hash: [0xDD; 32],
            }),
            package_bytes: Some(vec![publication]),
            schemas: None,
            needs_publish: true,
            action: ApplyAction::Install {
                consistency: vos::node::Consistency::Local as u8,
                replication_id: [publication; 32],
                network_reachable: false,
                sync_role: SyncFloor::Member,
            },
        }
    }

    #[test]
    fn shared_publication_plans_pin_one_exact_program_tag() {
        let mut names = BTreeMap::new();
        let mut first = publication_plan("worker", [0x11; 32], 0x21);
        let mut second = publication_plan("worker", [0x11; 32], 0x22);

        deduplicate_publication_plan(&mut names, &mut first).unwrap();
        deduplicate_publication_plan(&mut names, &mut second).unwrap();

        assert!(first.needs_publish);
        assert!(!second.needs_publish);
        assert_eq!(second.program, first.program);
        assert_eq!(second.expected_program, None);
        assert_eq!(names["worker"], (first.hash, first.program));
    }

    #[test]
    fn shared_catalog_name_rejects_two_different_packages() {
        let mut names = BTreeMap::new();
        let mut first = publication_plan("worker", [0x11; 32], 0x21);
        let mut second = publication_plan("worker", [0x12; 32], 0x22);
        deduplicate_publication_plan(&mut names, &mut first).unwrap();
        let error = deduplicate_publication_plan(&mut names, &mut second).unwrap_err();
        assert!(error.to_string().contains("more than one package"));
    }

    #[test]
    fn apply_upgrade_plan_is_rejected_before_execution() {
        let mut plan = publication_plan("worker", [0x11; 32], 0x21);
        plan.action = ApplyAction::Upgrade;
        let error = reject_legacy_upgrade_plans(&[plan])
            .unwrap_err()
            .to_string();
        assert!(error.contains("clean cutover"), "{error}");
        assert!(error.contains("Agent lifecycle"), "{error}");
        assert!(error.contains("no guest mutation"), "{error}");
    }

    #[test]
    fn install_race_requires_the_complete_semantic_postcondition() {
        use vos::service::InstallationId;

        let program = ProgramTag {
            publication_id: vos::registry::PublicationId::new([0x31; 32]),
            hash: [0x32; 32],
        };
        let replication_id = [0x33; 32];
        let mut row = vos::registry::AgentRow {
            instance_name: "worker".into(),
            installation_id: InstallationId::new([0x34; 32]),
            revision: 7,
            program_hash: program.hash,
            program_name: "worker-program".into(),
            program_publication_id: program.publication_id,
            replication_id,
            consistency: vos::node::Consistency::Raft as u8,
            network_reachable: true,
            sync_role: SyncFloor::Private,
        };
        let matches = |row: &vos::registry::AgentRow| {
            service_install_matches(
                row,
                "worker",
                "worker-program",
                program,
                replication_id,
                vos::node::Consistency::Raft as u8,
                true,
                SyncFloor::Private,
            )
        };
        assert!(matches(&row));

        row.instance_name = "other-worker".into();
        assert!(!matches(&row));
        row.instance_name = "worker".into();

        row.program_name = "other".into();
        assert!(!matches(&row));
        row.program_name = "worker-program".into();
        row.program_hash[0] ^= 1;
        assert!(!matches(&row));
        row.program_hash = program.hash;
        row.program_publication_id = vos::registry::PublicationId::new([0x41; 32]);
        assert!(!matches(&row));
        row.program_publication_id = program.publication_id;
        row.replication_id[0] ^= 1;
        assert!(!matches(&row));
        row.replication_id = replication_id;
        row.consistency = vos::node::Consistency::Local as u8;
        assert!(!matches(&row));
        row.consistency = vos::node::Consistency::Raft as u8;
        row.network_reachable = false;
        assert!(!matches(&row));
        row.network_reachable = true;
        row.sync_role = SyncFloor::Member;
        assert!(!matches(&row));

        // The concurrent installation owns its own identity/revision; logical
        // idempotence is defined by the requested service semantics above.
        row.sync_role = SyncFloor::Private;
        row.installation_id = InstallationId::new([0x51; 32]);
        row.revision += 1;
        assert!(matches(&row));
    }

    #[test]
    fn recipe_replication_identity_rejects_off_and_zero() {
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
    }

    #[test]
    fn project_node_local_merges_preserving_existing_policy() {
        // The `export | apply` non-destructiveness guarantee: an exported
        // recipe declares NO node-local fields (they aren't in the
        // registry), so merging it must leave an operator's existing
        // per-agent policy / extensions untouched.
        let mut existing_agents = BTreeMap::new();
        existing_agents.insert(
            "ledger".to_string(),
            subscriptions::AgentLocal {
                device_secret: true,
                intra_caps: Vec::new(),
            },
        );
        let base = LocalConfig {
            subscriptions: vec!["ledger".into()],
            listen: vec![],
            agents: existing_agents,
            ingress: Default::default(),
            extensions: vec![ExtensionLocal {
                name: "worker".into(),
                path: "/abs/libgw.so".into(),
                ..Default::default()
            }],
        };
        // An export-shaped recipe: agents carry program_hash but no
        // node-local fields, and there are no extensions.
        let m = recipe_from(
            r#"
            space = "x"
            [[agent]]
            name = "ledger"
            program = "ledger"
            program_hash = "aa"
        "#,
        );
        let out = project_node_local(&base, &m, Path::new("/recipes"));
        assert_eq!(
            out, base,
            "an export recipe must not wipe existing node-local policy"
        );
    }

    #[test]
    fn project_node_local_explicit_empty_caps_revoke_existing_grant() {
        let mut base = LocalConfig::default();
        base.agents.insert(
            "reader".into(),
            subscriptions::AgentLocal {
                device_secret: true,
                intra_caps: vec!["substrate:member".into()],
            },
        );
        let recipe = recipe_from(
            r#"
            [[agent]]
            name = "reader"
            path = "reader.vos"
            intra_caps = []
        "#,
        );
        let out = project_node_local(&base, &recipe, Path::new("/recipes"));
        assert!(out.agents["reader"].intra_caps.is_empty());
        assert!(out.agents["reader"].device_secret);
    }

    #[test]
    fn project_node_local_is_idempotent() {
        // Re-projecting an already-projected config is a fixed point, so
        // a second `apply` writes nothing (the all-skips guarantee).
        let m = recipe_from(
            r#"
            [[agent]]
            name = "authority"
            path = "authority.vos"
            device_secret = true
        "#,
        );
        let once = project_node_local(&LocalConfig::default(), &m, Path::new("/recipes"));
        let twice = project_node_local(&once, &m, Path::new("/recipes"));
        assert_eq!(once, twice);
    }
}
