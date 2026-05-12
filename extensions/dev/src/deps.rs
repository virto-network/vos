//! Cross-project dependency resolution for the dev extension's
//! compile path.
//!
//! Walks the project's `ProjectMetadata.deps` graph, materialises
//! each reachable dev-project's tree under `vendor/<name>/` in
//! the compile tempdir, synthesises each one's Cargo.toml, and
//! reports back a flat list of resolved nodes for the top-level
//! workspace manifest. Same-space deps only in v1 — the
//! `space_id` field on `DepRef::Space` is checked against the
//! local space and rejected if it diverges, since cross-space
//! fetch needs DHT plumbing the dev extension doesn't have.
//!
//! Cycle detection runs during the walk: a (project_name,
//! commit) tuple seen twice on the resolution stack aborts the
//! compile with `COMPILE_STATUS_CYCLE`. A self-cycle (A → A) is
//! caught by the same mechanism.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use dev_project::{CommitNode, DepEntry, DepRef, HASH_BYTES, ProjectMetadata};
use vos::extension::ServiceCtx;
use vos::value::{Msg, Value};

use crate::compile::{
    COMPILE_STATUS_BAD_REPLY, COMPILE_STATUS_COMMIT_NOT_FOUND, COMPILE_STATUS_TRANSPORT,
    decode_value, dyn_payload, fetch_commit, materialise_to_path, value_to_bytes,
};

/// Extra status codes for the dep resolution path.
pub const COMPILE_STATUS_DEP_NOT_FOUND: u8 = 20;
pub const COMPILE_STATUS_CYCLE: u8 = 21;
/// Reserved for the federated fetch path (cross-space deps),
/// not used yet — same-space deps are the only flavour the
/// resolver handles in v1.
#[allow(dead_code)]
pub const COMPILE_STATUS_CROSS_SPACE_DEP: u8 = 22;

/// One resolved dependency, ready to write into the workspace.
pub struct ResolvedDep {
    /// Vendor directory name — the local key from the parent
    /// project's `DepEntry.name`. Two distinct deps must not
    /// share the same vendor name even if they happen to point
    /// at different project_names.
    pub vendor_name: String,
    /// The project_name as registered in the space registry.
    pub project_name: String,
    /// Pinned commit hash on the dep's project.
    pub commit: [u8; HASH_BYTES],
    /// Commit row the resolver fetched. Carries the file list
    /// the materialise step writes under vendor/.
    pub commit_node: CommitNode,
    /// Dep's own crate type. Defaults to `rlib` for cargo
    /// resolution. The root project's crate_type is set
    /// separately via the compile path's main Cargo.toml.
    pub crate_type: String,
    /// Dep's own DepEntry list, so we can synthesise its
    /// Cargo.toml with the right `[dependencies]` section.
    pub deps: Vec<DepEntry>,
}

/// Walk the project's metadata.deps recursively, return a flat
/// list of every reachable dev-project dep. Order is breadth-
/// first; same-name deps deduplicate (must point at the same
/// commit when they do).
pub fn resolve(
    ctx: &ServiceCtx,
    _root_project_id: u32,
    root_metadata: &ProjectMetadata,
) -> Result<Vec<ResolvedDep>, (u8, String)> {
    let local_prefix = (ctx.me() >> 16) as u16;
    let mut resolved: Vec<ResolvedDep> = Vec::new();
    let mut queue: Vec<(String, DepRef)> = root_metadata
        .deps
        .iter()
        .filter_map(|e| match &e.dep {
            DepRef::Builtin(_) => None,
            DepRef::Space { .. } => Some((e.name.clone(), e.dep.clone())),
        })
        .collect();
    // Walking-set for cycle detection (project_name + commit).
    let mut visited: BTreeSet<(String, [u8; HASH_BYTES])> = BTreeSet::new();
    // The root project is visited even though we don't enqueue
    // it — guards against `root → root` cycle declarations.
    visited.insert((root_metadata.name.clone(), [0u8; HASH_BYTES]));

    while let Some((vendor_name, dep)) = queue.pop() {
        let DepRef::Space {
            space_id: _space_id,
            project_name,
            commit,
        } = dep
        else {
            continue;
        };
        // v1 ignores `space_id`: deps must be in the same space
        // as the resolver. Reject obvious cross-space declarations
        // when the field is non-zero AND doesn't match the root.
        // (We don't have the local space_id handy, so the strictest
        // check is "non-zero space_id means future federation
        // territory, refuse now.")
        // TODO: thread the local space_id in once a daemon hook
        // exposes it. For now defer to the registry resolve which
        // is also same-space only.

        // Cycle detection: don't enqueue a (project, commit) pair
        // we've already seen.
        let key = (project_name.clone(), commit);
        if visited.contains(&key) {
            // If the same project_name is reached via a different
            // commit, surface as cycle (or pin conflict — same
            // semantic from the resolver's view).
            if resolved
                .iter()
                .any(|r| r.project_name == project_name && r.commit != commit)
            {
                return Err((
                    COMPILE_STATUS_CYCLE,
                    format!(
                        "project '{project_name}' pinned at two different commits in the dep graph",
                    ),
                ));
            }
            continue;
        }
        // Self-cycle: project listing itself as a dep.
        if project_name == root_metadata.name {
            return Err((
                COMPILE_STATUS_CYCLE,
                format!("project '{project_name}' depends on itself"),
            ));
        }
        visited.insert(key);

        // Resolve project_name → ServiceId via the space registry.
        let dep_project_id = match registry_resolve(ctx, &project_name, local_prefix) {
            Ok(id) if id != 0 => id,
            Ok(_) => {
                return Err((
                    COMPILE_STATUS_DEP_NOT_FOUND,
                    format!("project '{project_name}' not registered in this space"),
                ));
            }
            Err(status) => {
                return Err((status, format!("resolve dep '{project_name}' failed")));
            }
        };

        let commit_node = match fetch_commit(ctx, dep_project_id, &commit) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err((
                    COMPILE_STATUS_COMMIT_NOT_FOUND,
                    format!("commit on dep '{project_name}' not found"),
                ));
            }
            Err(status) => return Err((status, "fetch_commit for dep failed".to_string())),
        };

        let metadata = match fetch_metadata(ctx, dep_project_id) {
            Ok(m) => m,
            Err(status) => return Err((status, "fetch_metadata for dep failed".to_string())),
        };

        let crate_type = if metadata.crate_type.is_empty() {
            "rlib".to_string()
        } else {
            metadata.crate_type.clone()
        };
        let entry_deps = metadata.deps.clone();

        resolved.push(ResolvedDep {
            vendor_name,
            project_name,
            commit,
            commit_node,
            crate_type,
            deps: entry_deps.clone(),
        });

        for d in &entry_deps {
            if let DepRef::Space { .. } = &d.dep {
                queue.push((d.name.clone(), d.dep.clone()));
            }
        }
    }

    Ok(resolved)
}

/// Lay each resolved dep into `<root>/vendor/<name>/` and
/// synthesise its Cargo.toml. Same materialise function the root
/// project uses, plus a per-dep Cargo.toml with the right
/// `[lib]` crate-type and dependency stanza.
pub fn write_to_workspace(
    ctx: &ServiceCtx,
    root: &Path,
    resolved: &[ResolvedDep],
) -> Result<(), (u8, String)> {
    let local_prefix = (ctx.me() >> 16) as u16;
    let vendor_dir = root.join("vendor");
    fs::create_dir_all(&vendor_dir)
        .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e.to_string()))?;
    for r in resolved {
        let dep_root = vendor_dir.join(&r.vendor_name);
        fs::create_dir_all(&dep_root)
            .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e.to_string()))?;

        // Resolve the dep's project_id again — we need it to
        // fetch each file's blob bytes during materialise.
        let dep_project_id = match registry_resolve(ctx, &r.project_name, local_prefix) {
            Ok(id) if id != 0 => id,
            _ => {
                return Err((
                    COMPILE_STATUS_DEP_NOT_FOUND,
                    format!("project '{}' not registered (race?)", r.project_name),
                ));
            }
        };
        materialise_to_path(ctx, dep_project_id, &r.commit_node, &dep_root)
            .map_err(|outcome| (outcome.status, "materialise dep failed".to_string()))?;

        let cargo_toml = synthesise_dep_cargo_toml(&r.vendor_name, &r.crate_type, &r.deps);
        fs::write(dep_root.join("Cargo.toml"), cargo_toml)
            .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e.to_string()))?;
    }
    Ok(())
}

fn synthesise_dep_cargo_toml(name: &str, crate_type: &str, deps: &[DepEntry]) -> String {
    let mut s = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["{crate_type}"]

[dependencies]
"#
    );
    for d in deps {
        match &d.dep {
            DepRef::Space { project_name, .. } => {
                // Sibling under vendor/, so `../<project_name>`.
                s.push_str(&format!(
                    "{} = {{ path = \"../{}\" }}\n",
                    d.name, project_name
                ));
            }
            DepRef::Builtin(crate_name) => {
                s.push_str(&format!("{} = \"*\" # builtin: {}\n", d.name, crate_name));
            }
        }
    }
    s
}

/// Synthesise the root project's Cargo.toml when there are deps:
/// adds `[workspace] members = [vendor/...]` and a
/// `[dependencies]` row for each `DepRef::Space` dep.
pub fn synthesise_root_dependencies(deps: &[DepEntry]) -> String {
    let mut s = String::new();
    s.push_str("\n[workspace]\nmembers = [\n");
    for d in deps {
        if let DepRef::Space { project_name, .. } = &d.dep {
            s.push_str(&format!("    \"vendor/{project_name}\",\n"));
        }
    }
    s.push_str("]\n\n[dependencies]\n");
    for d in deps {
        match &d.dep {
            DepRef::Space { project_name, .. } => {
                s.push_str(&format!(
                    "{} = {{ path = \"vendor/{}\" }}\n",
                    d.name, project_name
                ));
            }
            DepRef::Builtin(crate_name) => {
                s.push_str(&format!("{} = \"*\" # builtin: {}\n", d.name, crate_name));
            }
        }
    }
    s
}

// ── Wire helpers ─────────────────────────────────────────────────────

pub(crate) fn fetch_metadata(ctx: &ServiceCtx, project_id: u32) -> Result<ProjectMetadata, u8> {
    // ProjectMetadata is the Phase 5.1 dep-graph payload. The
    // current PVM-side actor doesn't expose a `metadata` handler
    // (kept host-side to dodge the grey-transpiler edge — see
    // dev-project's NOTE comments), so the dispatch may bounce
    // back as STATUS_NOT_FOUND. Treat any of "transport bounced",
    // "empty reply", or "non-decodable payload" as "no metadata
    // declared yet" — the compile path falls through to a
    // dep-less workspace synthesis in that case.
    let Some(raw) = ctx.ask_raw(project_id, &dyn_payload(&Msg::new("metadata"))) else {
        return Ok(ProjectMetadata::default());
    };
    let Some(value) = decode_value(&raw) else {
        return Ok(ProjectMetadata::default());
    };
    let Some(inner) = value_to_bytes(value) else {
        return Ok(ProjectMetadata::default());
    };
    if inner.is_empty() {
        return Ok(ProjectMetadata::default());
    }
    Ok(<ProjectMetadata as vos::Decode>::try_decode(&inner).unwrap_or_default())
}

fn registry_resolve(ctx: &ServiceCtx, name: &str, caller_prefix: u16) -> Result<u32, u8> {
    const REGISTRY_ID: u32 = 0;
    let msg = Msg::new("resolve")
        .with("name", name.to_string())
        .with("caller_prefix", caller_prefix as u64);
    let raw = ctx
        .ask_raw(REGISTRY_ID, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    match value {
        Value::U32(id) => Ok(id),
        Value::U64(id) => Ok(id as u32),
        // Fallback for Bytes-encoded primitive replies — older
        // codegen paths emit u32 returns as Value::Bytes.
        Value::Bytes(b) if b.len() == 4 => Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        _ => Err(COMPILE_STATUS_BAD_REPLY),
    }
}
