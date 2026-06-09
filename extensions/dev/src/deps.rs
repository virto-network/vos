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

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use dev_project::{CommitNode, DepEntry, DepRef, HASH_BYTES, ProjectMetadata};
use vos::actors::context::ServiceId;
use vos::value::{Msg, Value};

use crate::DevCtx;

use crate::compile::{
    COMPILE_STATUS_BAD_REPLY, COMPILE_STATUS_COMMIT_NOT_FOUND, COMPILE_STATUS_TRANSPORT,
    decode_value, dyn_payload, fetch_blob, fetch_commit, materialise_to_path,
};

/// Well-known path under a dev-project's source tree carrying the
/// project's rkyv-encoded `ProjectMetadata`. The dev extension's
/// compile path reads this file off the commit being built —
/// keeps metadata versioned with the source it describes and
/// avoids any cross-actor field that would force a PVM-side
/// `metadata` handler.
pub const METADATA_PATH: &str = ".vos-project.rkyv";

/// Extra status codes for the dep resolution path.
pub const COMPILE_STATUS_DEP_NOT_FOUND: u8 = 20;
pub const COMPILE_STATUS_CYCLE: u8 = 21;
pub const COMPILE_STATUS_PIN_CONFLICT: u8 = 22;

/// One resolved dependency, ready to write into the workspace.
pub struct ResolvedDep {
    /// Local key from the parent project's `DepEntry.name`.
    /// Currently informational only — the vendor directory is
    /// keyed by `project_name` so multiple parents reaching the
    /// same project under different local names converge on a
    /// single vendor entry. Kept for debugging and the eventual
    /// duplicate-local-name diagnostic.
    #[allow(dead_code)]
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
pub async fn resolve(
    ctx: &mut DevCtx,
    _root_project_id: u32,
    root_metadata: &ProjectMetadata,
) -> Result<Vec<ResolvedDep>, (u8, String)> {
    let local_prefix = (ctx.id().0 >> 16) as u16;
    let mut resolved: Vec<ResolvedDep> = Vec::new();
    let mut queue: Vec<(String, DepRef)> = root_metadata
        .deps
        .iter()
        .filter_map(|e| match &e.dep {
            DepRef::Builtin(_) => None,
            DepRef::Space { .. } => Some((e.name.clone(), e.dep.clone())),
        })
        .collect();
    // Per-project pin map. The first time we see a project_name we
    // record its pinned commit; the second time we either no-op
    // (same commit → already resolved) or fail with PIN_CONFLICT
    // (same name, different commit pinned by two different
    // ancestors in the dep graph). Storing one commit per name —
    // not a `(name, commit)` set — is what lets the conflict
    // check actually fire: with a set, distinct commits look like
    // distinct entries and the conflict never trips.
    let mut pinned: BTreeMap<String, [u8; HASH_BYTES]> = BTreeMap::new();
    // The root project is recorded even though we don't enqueue
    // it — guards against `root → root` cycle declarations and
    // catches deps that pin the root at a non-root commit.
    pinned.insert(root_metadata.name.clone(), [0u8; HASH_BYTES]);

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

        // Self-cycle: project listing itself as a dep. Catch
        // this before the pin-map check so the error message is
        // specific (the pin check would also catch it under the
        // root's `[0u8; 32]` placeholder, but with a less useful
        // diagnostic).
        if project_name == root_metadata.name {
            return Err((
                COMPILE_STATUS_CYCLE,
                format!("project '{project_name}' depends on itself"),
            ));
        }
        // Pin-and-cycle check: have we seen this project_name?
        // - Same commit → already enqueued/resolved, skip.
        // - Different commit → two parents pin the project at
        //   different versions; refuse to silently pick one.
        if let Some(existing) = pinned.get(&project_name) {
            if *existing == commit {
                continue;
            }
            return Err((
                COMPILE_STATUS_PIN_CONFLICT,
                format!(
                    "project '{project_name}' pinned at two different commits in the dep graph",
                ),
            ));
        }
        pinned.insert(project_name.clone(), commit);

        // Resolve project_name → ServiceId via the space registry.
        let dep_project_id = match registry_resolve(ctx, &project_name, local_prefix).await {
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

        let commit_node = match fetch_commit(ctx, dep_project_id, &commit).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err((
                    COMPILE_STATUS_COMMIT_NOT_FOUND,
                    format!("commit on dep '{project_name}' not found"),
                ));
            }
            Err(status) => return Err((status, "fetch_commit for dep failed".to_string())),
        };

        let metadata = match fetch_metadata_from_tree(ctx, dep_project_id, &commit_node).await {
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
///
/// Each dep's file tree gets shadowed into a persistent
/// source cache at `$XDG_CACHE_HOME/vos-dev/source-cache/<hex
/// commit>/`. Subsequent compiles that depend on the same commit
/// skip the fetch path entirely and copy from the cache. v1
/// never garbage-collects the cache — that's a TODO for whenever
/// disk-pressure becomes a real concern.
pub async fn write_to_workspace(
    ctx: &mut DevCtx,
    root: &Path,
    resolved: &[ResolvedDep],
) -> Result<(), (u8, String)> {
    let local_prefix = (ctx.id().0 >> 16) as u16;
    let vendor_dir = root.join("vendor");
    fs::create_dir_all(&vendor_dir)
        .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e.to_string()))?;
    for r in resolved {
        // Vendor directory is keyed by `project_name`, not the
        // local-dep `vendor_name`. Two reasons:
        //
        // - Different parents can reach the same project under
        //   different local names; we want a single canonical
        //   vendor entry per (project_name, commit).
        // - The synthesised `[workspace] members = […]` list in
        //   `synthesise_root_dependencies` and the inter-dep
        //   `path = "../<project_name>"` references in
        //   `synthesise_dep_cargo_toml` both use project_name,
        //   so the directory layout has to match.
        let dep_root = vendor_dir.join(&r.project_name);
        fs::create_dir_all(&dep_root)
            .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e.to_string()))?;

        let cache_dir = source_cache_path(&r.commit);
        if cache_dir.exists() {
            // Cache hit: shadow the cached tree into the vendor
            // dir. No actor invokes; just filesystem copy.
            vos::log::info!(
                "dev: source-cache hit for {} @ {}",
                r.project_name,
                hex_short(&r.commit)
            );
            copy_dir_contents(&cache_dir, &dep_root)
                .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e))?;
        } else {
            // Cache miss: fetch + materialise into the vendor
            // dir, then mirror to the cache so the next compile
            // hits.
            let dep_project_id = match registry_resolve(ctx, &r.project_name, local_prefix).await {
                Ok(id) if id != 0 => id,
                _ => {
                    return Err((
                        COMPILE_STATUS_DEP_NOT_FOUND,
                        format!("project '{}' not registered (race?)", r.project_name),
                    ));
                }
            };
            materialise_to_path(ctx, dep_project_id, &r.commit_node, &dep_root)
                .await
                .map_err(|outcome| (outcome.status, "materialise dep failed".to_string()))?;
            if let Err(e) = mirror_to_cache(&dep_root, &cache_dir) {
                vos::log::warn!(
                    "dev: failed to populate source cache for {} @ {}: {e}",
                    r.project_name,
                    hex_short(&r.commit),
                );
            }
        }

        let cargo_toml = synthesise_dep_cargo_toml(&r.project_name, &r.crate_type, &r.deps);
        fs::write(dep_root.join("Cargo.toml"), cargo_toml)
            .map_err(|e| (crate::compile::COMPILE_STATUS_IO, e.to_string()))?;
    }
    Ok(())
}

// ── Source cache ────────────────────────────────────────────────────

/// Root for the dev extension's persistent source cache. Sits
/// alongside vosx's blob cache so a single `XDG_CACHE_HOME`
/// override scopes both stores. v1 never garbage-collects this
/// directory; an operator can `rm -rf` it safely.
///
/// Matches vosx's `xdg_root` semantics so a test or operator
/// setting `XDG_CACHE_HOME` once gets coherent paths across
/// vosx's blob cache, the dev extension's blob mirror, and this
/// source cache.
fn source_cache_root() -> std::path::PathBuf {
    let from_home = || std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache"));
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(from_home)
        .unwrap_or_else(|| std::path::PathBuf::from(".cache"));
    base.join("vos-dev").join("source-cache")
}

/// Cache directory for one project's commit. Keyed by the commit
/// hash (content-addressed → no invalidation problem).
fn source_cache_path(commit: &[u8; HASH_BYTES]) -> std::path::PathBuf {
    source_cache_root().join(hex_full(commit))
}

/// Copy every file under `src` (recursively) into `dst`.
/// Directories are created as needed. Files are copied verbatim.
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    let mut stack: Vec<(std::path::PathBuf, std::path::PathBuf)> =
        vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        for entry in fs::read_dir(&s).map_err(|e| format!("read_dir {}: {e}", s.display()))? {
            let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
            let name = entry.file_name();
            let s_child = entry.path();
            let d_child = d.join(&name);
            let ty = entry
                .file_type()
                .map_err(|e| format!("file_type {}: {e}", s_child.display()))?;
            if ty.is_dir() {
                fs::create_dir_all(&d_child)
                    .map_err(|e| format!("mkdir {}: {e}", d_child.display()))?;
                stack.push((s_child, d_child));
            } else if ty.is_file() {
                fs::copy(&s_child, &d_child).map_err(|e| {
                    format!("copy {} → {}: {e}", s_child.display(), d_child.display())
                })?;
            }
            // Symlinks etc. ignored — the materialise step never
            // produces them, and a cached tree mirrors that.
        }
    }
    Ok(())
}

/// Snapshot a freshly-materialised dep tree into the source
/// cache. Atomic-write semantics: write into a sibling
/// `.partial-<pid>` dir, then rename into place so a parallel
/// reader doesn't see a half-populated entry. If the rename
/// fails because someone else won the race, leave the existing
/// cache entry alone.
fn mirror_to_cache(src: &Path, cache_dir: &Path) -> Result<(), String> {
    if let Some(parent) = cache_dir.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging = cache_dir.with_extension(format!("partial-{pid}-{nanos}"));
    copy_dir_contents(src, &staging)?;
    match fs::rename(&staging, cache_dir) {
        Ok(()) => Ok(()),
        Err(_) if cache_dir.exists() => {
            // Race: another compile populated the cache first.
            // Drop the staging dir and accept their version.
            let _ = fs::remove_dir_all(&staging);
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            Err(format!(
                "rename {} → {}: {e}",
                staging.display(),
                cache_dir.display()
            ))
        }
    }
}

fn hex_full(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0xF));
    }
    s
}

fn hex_short(bytes: &[u8]) -> String {
    hex_full(&bytes[..bytes.len().min(8)])
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
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
                // `package = "..."` keeps the local dep name in
                // `[dependencies]` independent of the upstream
                // crate's actual `name` (the parent might call
                // proj-b as `b` or `proj_b`).
                s.push_str(&format!(
                    "{} = {{ path = \"../{}\", package = \"{}\" }}\n",
                    d.name, project_name, project_name,
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
                // `package = "..."` so the local dep name in
                // `[dependencies]` can differ from the upstream
                // crate's actual `name`.
                s.push_str(&format!(
                    "{} = {{ path = \"vendor/{}\", package = \"{}\" }}\n",
                    d.name, project_name, project_name,
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

/// Read the project's `ProjectMetadata` off the given commit by
/// looking for a `.vos-project.rkyv` file in its `files` table.
/// Metadata lives in the tree (not as an actor field) so it
/// versions atomically with the source it describes and the
/// PVM actor stays free of the metadata-specific codegen.
///
/// Returns `Default::default()` when no metadata file is
/// committed (project is dep-less) or when its bytes fail to
/// decode (treated as "ignore the malformed metadata, fall back
/// to no deps"). Surface a status only on transport errors.
pub(crate) async fn fetch_metadata_from_tree(
    ctx: &mut DevCtx,
    project_id: u32,
    commit: &CommitNode,
) -> Result<ProjectMetadata, u8> {
    let Some(entry) = commit.files.iter().find(|f| f.path == METADATA_PATH) else {
        return Ok(ProjectMetadata::default());
    };
    let blob = match fetch_blob(ctx, project_id, &entry.blob).await {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(ProjectMetadata::default()),
        Err(status) => return Err(status),
    };
    if blob.bytes.is_empty() {
        return Ok(ProjectMetadata::default());
    }
    Ok(<ProjectMetadata as vos::Decode>::try_decode(&blob.bytes).unwrap_or_default())
}

async fn registry_resolve(ctx: &mut DevCtx, name: &str, caller_prefix: u16) -> Result<u32, u8> {
    const REGISTRY_ID: u32 = 0;
    let msg = Msg::new("resolve")
        .with("name", name.to_string())
        .with("caller_prefix", caller_prefix as u64);
    let raw = ctx
        .ask_dispatch(ServiceId(REGISTRY_ID), &dyn_payload(&msg))
        .await
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
