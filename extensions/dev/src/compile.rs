//! compile() — turn a project's commit into a PVM blob.
//!
//! Fetches a `CommitNode` from a dev-project actor, materialises
//! every referenced blob under a tempdir mirroring the project's
//! path structure, synthesises the build infra (Cargo.toml +
//! .cargo/config.toml + rust-toolchain.toml + the riscv64em-javm
//! target spec), invokes cargo, transpiles the resulting RISC-V
//! ELF through `grey_transpiler::link_elf`, stores the resulting
//! PVM blob back into the project via `put_blob`, and returns the
//! blob's hash.
//!
//! v1 keeps the synthesised crate name fixed (`actor`) so the
//! output ELF is always at `target/riscv64em-javm/release/actor.elf`
//! — saves the extension a round trip to fetch the project's
//! display name. Phase 2's AST blobs and Phase 5's cross-project
//! deps will revisit that, but for v1 every dev-project compiles
//! as `actor`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use dev_project::{
    BlobKind, BlobObject, BuildIntent, CommitNode, HASH_BYTES, HashResult, INTENT_BUILD, STATUS_OK,
};
use vos::Encode;
use vos::extension::ServiceCtx;
use vos::log;
use vos::value::{Msg, TAG_DYNAMIC, Value};

// ── Embedded build infra (synced from the workspace at build time) ───

/// The riscv64em-javm rustc target spec. Lives next to the
/// dev-project actor so the same JSON drives both the bundled
/// actor build and synthesised compiles.
const RISCV_TARGET_JSON: &str = include_str!("../../../actors/dev-project/riscv64em-javm.json");

/// Toolchain pin baked into every synthesised project. We
/// deliberately *don't* mirror the workspace's
/// `rust-toolchain.toml` here: the workspace pins
/// `nightly-2025-05-09` for zkpvm reproducibility, but that
/// nightly is too old to accept the riscv64em-javm JSON target
/// spec's current shape. Pinning the generic `nightly` channel
/// means the synthesised build picks up whatever fresh nightly
/// the operator's rustup default points at — same one the
/// `examples/actors/*/cargo actor` recipes target.
const RUST_TOOLCHAIN: &str = r#"[toolchain]
channel = "nightly"
components = ["rust-src"]
"#;

/// Path to the `vos` crate as a fully-qualified directory string.
/// Baked at build time so the synthesised Cargo.toml can declare
/// `vos = { path = "..." }`. v1 of the dev extension assumes the
/// workspace tree exists at the bake-time location — fine for
/// local dev and CI, will need a `vos` crates.io publish before
/// we can ship a real distribution.
const WORKSPACE_VOS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vos");

// ── Status codes (extra to dev_project::STATUS_*) ───────────────────
//
// dev_project's STATUS_* run 0..=6 and cover the PVM-side concerns
// (parent not found, bad hash, etc.). Compile adds host-side
// failure modes starting at 10 so the two ranges don't collide.

pub const COMPILE_STATUS_COMMIT_NOT_FOUND: u8 = 10;
pub const COMPILE_STATUS_BLOB_NOT_FOUND: u8 = 11;
pub const COMPILE_STATUS_CARGO_FAILED: u8 = 12;
pub const COMPILE_STATUS_ELF_NOT_FOUND: u8 = 13;
pub const COMPILE_STATUS_TRANSPILE_FAILED: u8 = 14;
pub const COMPILE_STATUS_TRANSPORT: u8 = 15;
pub const COMPILE_STATUS_BAD_REPLY: u8 = 16;
pub const COMPILE_STATUS_BAD_PATH: u8 = 17;
pub const COMPILE_STATUS_IO: u8 = 18;
pub const COMPILE_STATUS_RECORD_FAILED: u8 = 19;

/// Outcome of a compile attempt. Successful compile carries the
/// PVM blob's hash; failure carries stderr (or another diagnostic
/// blob) so the caller can surface the build error.
pub struct CompileOutcome {
    pub status: u8,
    pub hash: Vec<u8>,
    /// On failure: the cargo invocation's stderr (or another
    /// short host-side error message). Empty on success.
    pub stderr: Vec<u8>,
}

impl CompileOutcome {
    fn err(status: u8, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            hash: Vec::new(),
            stderr: stderr.into(),
        }
    }
    fn ok(hash: Vec<u8>) -> Self {
        Self {
            status: dev_project::STATUS_OK,
            hash,
            stderr: Vec::new(),
        }
    }
}

/// Log a compile failure's stderr verbatim. Phase 1.3 also
/// persists the stderr as a blob and links it from the build
/// commit's `intent.artifact` field so it survives across daemon
/// restarts; this trace just gets the operator's eyes on the
/// failure mode without making them open a redb.
fn log_outcome_stderr(o: &CompileOutcome) {
    if o.stderr.is_empty() {
        return;
    }
    let stderr_str = String::from_utf8_lossy(&o.stderr);
    log::warn!(
        "dev: compile failed (status={}):\n{}",
        o.status,
        stderr_str.trim_end()
    );
}

/// Top-level: compile a source commit and record the result on the
/// `builds` branch. Returns the build commit's hash on success or
/// failure (the commit itself encodes which); status only signals
/// "recording itself broke" (transport / commit handler refused).
///
/// The wire shape callers see in `Value::Bytes(HashResult)` is:
///   * `status == STATUS_OK` + 32-byte build commit hash → done;
///     decode `intent.ok` from that commit's `intent_data` to
///     check if cargo actually succeeded.
///   * `status == COMPILE_STATUS_RECORD_FAILED` + empty hash →
///     we couldn't even record the build attempt (most often a
///     transport error or a malformed `source_commit` arg).
pub fn compile_and_record(ctx: &ServiceCtx, project_id: u32, source_commit: Vec<u8>) -> HashResult {
    let outcome = compile_project(ctx, project_id, source_commit.clone());
    log_outcome_stderr(&outcome);

    // Resolve the artifact-hash slot for the build commit:
    // - success: PVM blob hash from put_blob (already in
    //   outcome.hash).
    // - failure with stderr: persist stderr as its own blob so the
    //   operator can fetch it from the commit DAG.
    // - failure with no stderr: zeroes — the status field on the
    //   commit's intent encoding already signals "no artifact".
    let artifact_bytes = if outcome.status == STATUS_OK {
        outcome.hash.clone()
    } else if !outcome.stderr.is_empty() {
        match put_blob(ctx, project_id, &outcome.stderr) {
            Ok(h) => h,
            Err(_) => {
                return HashResult {
                    status: COMPILE_STATUS_RECORD_FAILED,
                    hash: Vec::new(),
                };
            }
        }
    } else {
        vec![0u8; HASH_BYTES]
    };

    let source_arr = bytes_to_32_or_zero(&source_commit);
    let artifact_arr = bytes_to_32_or_zero(&artifact_bytes);
    let intent = BuildIntent {
        ok: if outcome.status == STATUS_OK { 1 } else { 0 },
        source_commit: source_arr,
        artifact: artifact_arr,
    };
    let intent_data = <BuildIntent as Encode>::encode(&intent);

    let builds_head = match fetch_head(ctx, project_id, "builds") {
        Ok(b) => b,
        Err(_) => {
            return HashResult {
                status: COMPILE_STATUS_RECORD_FAILED,
                hash: Vec::new(),
            };
        }
    };

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    match remote_commit(
        ctx,
        project_id,
        builds_head,
        Vec::new(),
        Vec::new(),
        "builds".to_string(),
        INTENT_BUILD,
        intent_data,
        Vec::new(),
        ts_ms,
        Vec::new(),
    ) {
        Ok(commit_hash) => HashResult {
            status: STATUS_OK,
            hash: commit_hash,
        },
        Err(_) => HashResult {
            status: COMPILE_STATUS_RECORD_FAILED,
            hash: Vec::new(),
        },
    }
}

/// Extract the toolchain channel string out of a `rust-
/// toolchain.toml` body. Returns `None` if the file shape isn't
/// the expected `[toolchain] channel = "..."`.
fn parse_toolchain_channel(s: &str) -> Option<&str> {
    let mut in_toolchain = false;
    for line in s.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_toolchain = line.starts_with("[toolchain");
            continue;
        }
        if !in_toolchain {
            continue;
        }
        let Some(rest) = line.strip_prefix("channel") else {
            continue;
        };
        let rest = rest.trim_start().strip_prefix('=')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        return rest.split('"').next();
    }
    None
}

pub(crate) fn bytes_to_32_or_zero(b: &[u8]) -> [u8; HASH_BYTES] {
    let mut out = [0u8; HASH_BYTES];
    if b.len() == HASH_BYTES {
        out.copy_from_slice(b);
    }
    out
}

/// Compile the tree at `commit_hash` from the dev-project actor at
/// `project_id`. Returns the resulting PVM blob's hash (also
/// inserted back into the project's blob store) on success.
pub fn compile_project(ctx: &ServiceCtx, project_id: u32, commit_hash: Vec<u8>) -> CompileOutcome {
    // ── 1. Fetch the commit
    let commit = match fetch_commit(ctx, project_id, &commit_hash) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return CompileOutcome::err(COMPILE_STATUS_COMMIT_NOT_FOUND, "commit not found");
        }
        Err(status) => return CompileOutcome::err(status, "fetch_commit failed"),
    };

    // ── 2. Fetch project metadata off the commit being built.
    //    Metadata is a tree file at `.vos-project.rkyv`, not an
    //    actor field — see `deps::METADATA_PATH`. Dep-less
    //    projects (no metadata file in the tree) get a default
    //    metadata back and the rest of the compile pipeline
    //    short-circuits the dep-resolution path.
    let metadata = match crate::deps::fetch_metadata_from_tree(ctx, project_id, &commit) {
        Ok(m) => m,
        Err(status) => return CompileOutcome::err(status, "fetch_metadata failed"),
    };

    // ── 3. Lay out the tree
    let tempdir = match tempfile::Builder::new().prefix("vos-dev-").tempdir() {
        Ok(d) => d,
        Err(e) => return CompileOutcome::err(COMPILE_STATUS_IO, e.to_string()),
    };
    let project_root = tempdir.path();
    if let Err(e) = materialise_tree(ctx, project_id, &commit, project_root) {
        return e;
    }

    // ── 4. Resolve + materialise cross-project deps. No-op when
    //    `metadata.deps` is empty (which the v1 happy-path test
    //    relies on).
    let resolved_deps = match crate::deps::resolve(ctx, project_id, &metadata) {
        Ok(d) => d,
        Err((status, msg)) => return CompileOutcome::err(status, msg),
    };
    if !resolved_deps.is_empty()
        && let Err((status, msg)) =
            crate::deps::write_to_workspace(ctx, project_root, &resolved_deps)
    {
        return CompileOutcome::err(status, msg);
    }

    // ── 5. Synthesise the build infra (now metadata-aware so
    //    the root Cargo.toml carries `[workspace]` + the
    //    `[dependencies]` section when there are deps).
    if let Err(e) = write_build_infra(project_root, &metadata) {
        return CompileOutcome::err(COMPILE_STATUS_IO, e);
    }

    // ── 4. Invoke cargo. Clear `RUSTUP_TOOLCHAIN` so the
    //    synthesised `rust-toolchain.toml` actually drives the
    //    channel selection — if the daemon was launched under
    //    `cargo +stable test`, the env var would otherwise pin
    //    cargo to stable and `-Zbuild-std` immediately rejects.
    // The synthesised `rust-toolchain.toml` pins the channel, but
    // rustup's rust-toolchain auto-detection runs *before* it picks
    // up the file in CWD when invoked through the proxy in non-
    // workspace contexts. Pass `+<channel>` explicitly so the right
    // cargo binary handles `-Zjson-target-spec` + `-Zbuild-std`.
    let cargo_channel = parse_toolchain_channel(RUST_TOOLCHAIN).unwrap_or("nightly");
    let toolchain_arg = format!("+{cargo_channel}");
    let output = match Command::new("cargo")
        .args([
            toolchain_arg.as_str(),
            "-Zjson-target-spec",
            "rustc",
            "--lib",
            "--crate-type",
            "bin",
            "-Zbuild-std=core,alloc,compiler_builtins",
            "-Zbuild-std-features=compiler-builtins-mem",
            "--release",
            "--target",
            "riscv64em-javm.json",
        ])
        .env_remove("RUSTUP_TOOLCHAIN")
        .current_dir(project_root)
        .output()
    {
        Ok(o) => o,
        Err(e) => return CompileOutcome::err(COMPILE_STATUS_IO, e.to_string()),
    };
    if !output.status.success() {
        log::warn!("dev: cargo invocation failed for project {project_id}");
        return CompileOutcome::err(COMPILE_STATUS_CARGO_FAILED, output.stderr);
    }

    // ── 5. Read the produced ELF (synthesised crate name = "actor")
    let elf_path = project_root
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join("actor.elf");
    let elf_bytes = match fs::read(&elf_path) {
        Ok(b) => b,
        Err(e) => {
            return CompileOutcome::err(
                COMPILE_STATUS_ELF_NOT_FOUND,
                format!("read {}: {e}", elf_path.display()),
            );
        }
    };

    // ── 6. Sanity-check the transpile works — produces the PVM
    //    blob that `space up`'s startup will compute later. We
    //    discard the result; persisting the RISC-V ELF instead
    //    keeps the cache shape symmetric with the rest of the
    //    toolchain (`space publish <source>` → ELF → cache →
    //    `space up`'s `link_elf` on load). Trying to cache the
    //    PVM blob directly would force the install path to
    //    distinguish "pre-transpiled" from "needs transpile"
    //    bytes, which is more breakage than it's worth.
    if let Err(e) = grey_transpiler::link_elf(&elf_bytes) {
        return CompileOutcome::err(COMPILE_STATUS_TRANSPILE_FAILED, format!("{e:?}"));
    }

    // ── 7. Persist the RISC-V ELF to the host-side blob cache.
    //    Neither dev-project nor space-registry can hold these
    //    bytes in their PVM-archived state — both run in the PVM
    //    with a 64KB heap, well under the typical ~150KB compiled
    //    actor. The local cache (mirror of vosx's
    //    `~/.cache/vosx/blobs/`) is the host-side store the rest
    //    of the toolchain (`vosx space install`) already reads
    //    from, so dropping the bytes there closes the loop without
    //    a new transport. Cross-node distribution will need a
    //    dedicated host-side blob agent — out of scope for v1.
    let elf_hash = match crate::publish::write_to_blob_cache(&elf_bytes) {
        Ok(h) => h,
        Err(e) => return CompileOutcome::err(COMPILE_STATUS_IO, e),
    };

    CompileOutcome::ok(elf_hash)
}

// ── Wire helpers ─────────────────────────────────────────────────────

pub(crate) fn dyn_payload(msg: &Msg) -> Vec<u8> {
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

/// Decode a `Value` from raw reply bytes. Returns `None` when the
/// bytes don't decode (transport/encoding bug) — distinct from a
/// successful decode that just happens to be `Value::Unit` or
/// `Value::Bytes(empty)`.
pub(crate) fn decode_value(bytes: &[u8]) -> Option<Value> {
    <Value as vos::Decode>::try_decode(bytes)
}

/// Extract a `Vec<u8>` from a reply Value. Both typed-handler
/// returns (`Value::Bytes`) and `Value::Unit` map here — the
/// caller is expected to know which is "missing" vs "empty".
pub(crate) fn value_to_bytes(v: Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b),
        Value::Unit => Some(Vec::new()),
        _ => None,
    }
}

pub(crate) fn fetch_commit(
    ctx: &ServiceCtx,
    project_id: u32,
    hash: &[u8],
) -> Result<Option<CommitNode>, u8> {
    let msg = Msg::new("get_commit").with("hash", hash.to_vec());
    let raw = ctx
        .ask_raw(project_id, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    let inner = value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    if inner.is_empty() {
        return Ok(None);
    }
    let commit = <CommitNode as vos::Decode>::try_decode(&inner).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    Ok(Some(commit))
}

pub(crate) fn fetch_blob(
    ctx: &ServiceCtx,
    project_id: u32,
    hash: &[u8],
) -> Result<Option<BlobObject>, u8> {
    let msg = Msg::new("get_blob").with("hash", hash.to_vec());
    let raw = ctx
        .ask_raw(project_id, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    let inner = value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    if inner.is_empty() {
        return Ok(None);
    }
    let blob = <BlobObject as vos::Decode>::try_decode(&inner).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    Ok(Some(blob))
}

pub(crate) fn put_blob(ctx: &ServiceCtx, project_id: u32, bytes: &[u8]) -> Result<Vec<u8>, u8> {
    let msg = Msg::new("put_blob").with("bytes", bytes.to_vec());
    let raw = ctx
        .ask_raw(project_id, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)
}

pub(crate) fn fetch_head(ctx: &ServiceCtx, project_id: u32, branch: &str) -> Result<Vec<u8>, u8> {
    let msg = Msg::new("head").with("branch", branch.to_string());
    let raw = ctx
        .ask_raw(project_id, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn remote_commit(
    ctx: &ServiceCtx,
    project_id: u32,
    parent: Vec<u8>,
    paths: Vec<String>,
    blob_hashes: Vec<u8>,
    branch: String,
    intent_tag: u8,
    intent_data: Vec<u8>,
    author: Vec<u8>,
    ts_ms: u64,
    change_id: Vec<u8>,
) -> Result<Vec<u8>, u8> {
    let msg = Msg::new("commit")
        .with("parent", parent)
        .with("paths", paths)
        .with("blob_hashes", blob_hashes)
        .with("branch", branch)
        .with("intent_tag", intent_tag)
        .with("intent_data", intent_data)
        .with("author", author)
        .with("ts_ms", ts_ms)
        .with("change_id", change_id);
    let raw = ctx
        .ask_raw(project_id, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    let inner = value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    let result = <HashResult as vos::Decode>::try_decode(&inner).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    if result.status != STATUS_OK {
        // Surface the actor's status as a transport-level error so the
        // caller distinguishes "recording itself failed" from
        // "compile failed but recorded".
        return Err(result.status);
    }
    Ok(result.hash)
}

// ── Filesystem layout ────────────────────────────────────────────────

fn materialise_tree(
    ctx: &ServiceCtx,
    project_id: u32,
    commit: &CommitNode,
    root: &Path,
) -> Result<(), CompileOutcome> {
    materialise_to_path(ctx, project_id, commit, root)
}

/// Inner: materialise a commit's tree under an arbitrary
/// destination path. Used by `materialise_tree` for the root
/// project (writes into the tempdir's root) and by
/// `deps::write_to_workspace` for each dep (writes into
/// `vendor/<name>/`).
pub(crate) fn materialise_to_path(
    ctx: &ServiceCtx,
    project_id: u32,
    commit: &CommitNode,
    root: &Path,
) -> Result<(), CompileOutcome> {
    for file in &commit.files {
        let blob = match fetch_blob(ctx, project_id, &file.blob) {
            Ok(Some(b)) => b,
            Ok(None) => {
                return Err(CompileOutcome::err(
                    COMPILE_STATUS_BLOB_NOT_FOUND,
                    format!("blob missing for {}", file.path),
                ));
            }
            Err(status) => {
                return Err(CompileOutcome::err(status, "fetch_blob failed"));
            }
        };
        let dest = match resolve_safe_path(root, &file.path) {
            Some(p) => p,
            None => {
                return Err(CompileOutcome::err(
                    COMPILE_STATUS_BAD_PATH,
                    format!("rejected path: {}", file.path),
                ));
            }
        };
        if let Some(parent) = dest.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            return Err(CompileOutcome::err(COMPILE_STATUS_IO, e.to_string()));
        }

        // Decode the blob according to its kind:
        // - RustAst on a .rs path: render back to text via
        //   dev_ast (canonical prettyplease output).
        // - RustAst on a non-.rs path: a Cargo.toml or build
        //   script tagged as Rust source by mistake. Reject —
        //   silently treating it as raw would defeat the AST's
        //   hash dedup invariant the next time it's stored.
        // - Raw: write verbatim.
        let bytes_to_write: Vec<u8> = match blob.kind {
            BlobKind::RustAst => {
                if !file.path.ends_with(".rs") {
                    return Err(CompileOutcome::err(
                        COMPILE_STATUS_BAD_PATH,
                        format!("RustAst blob on non-.rs path: {}", file.path),
                    ));
                }
                match dev_ast::ast_to_text(&blob.bytes) {
                    Ok(s) => s.into_bytes(),
                    Err(e) => {
                        return Err(CompileOutcome::err(
                            COMPILE_STATUS_BAD_REPLY,
                            format!("ast_to_text for {}: {e}", file.path),
                        ));
                    }
                }
            }
            BlobKind::Raw => blob.bytes,
        };
        if let Err(e) = fs::write(&dest, &bytes_to_write) {
            return Err(CompileOutcome::err(COMPILE_STATUS_IO, e.to_string()));
        }
    }
    Ok(())
}

/// Resolve `path` (a project-relative path that already passed the
/// actor's `is_valid_path` check) under `root` and refuse anything
/// that escapes via symlinks or repeated `..`. The actor rejects
/// `..` and leading `/` but symlinks come from the materialised
/// tree itself, which v1 doesn't create — kept as a belt-and-
/// braces check.
fn resolve_safe_path(root: &Path, path: &str) -> Option<PathBuf> {
    if path.is_empty() || path.starts_with('/') {
        return None;
    }
    let mut out = root.to_path_buf();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

fn write_build_infra(root: &Path, metadata: &dev_project::ProjectMetadata) -> Result<(), String> {
    let cargo_toml = synthesised_cargo_toml(metadata);
    fs::write(root.join("Cargo.toml"), cargo_toml).map_err(|e| e.to_string())?;

    let cargo_dir = root.join(".cargo");
    fs::create_dir_all(&cargo_dir).map_err(|e| e.to_string())?;
    fs::write(cargo_dir.join("config.toml"), CARGO_CONFIG_TOML).map_err(|e| e.to_string())?;

    fs::write(root.join("rust-toolchain.toml"), RUST_TOOLCHAIN).map_err(|e| e.to_string())?;
    fs::write(root.join("riscv64em-javm.json"), RISCV_TARGET_JSON).map_err(|e| e.to_string())?;
    Ok(())
}

fn synthesised_cargo_toml(metadata: &dev_project::ProjectMetadata) -> String {
    // The agent-supplied tree owns `src/`; the dev extension owns
    // everything else around it. `name = "actor"` is fixed so the
    // output ELF path stays predictable across compiles.
    let vos_path = WORKSPACE_VOS_PATH;
    let has_space_deps = metadata
        .deps
        .iter()
        .any(|d| matches!(d.dep, dev_project::DepRef::Space { .. }));
    // The default `[workspace]` empty section lets a synthesised
    // project sit outside any parent workspace. When metadata
    // declares Space deps, we replace it with an explicit
    // members list + `[dependencies]` section.
    let workspace_section = if has_space_deps {
        crate::deps::synthesise_root_dependencies(&metadata.deps)
    } else {
        "\n[workspace]\n".to_string()
    };
    format!(
        r#"[package]
name = "actor"
version = "0.1.0"
edition = "2024"
{workspace_section}
[features]
default = ["bin"]
bin = []

[lints.rust.unexpected_cfgs]
level = "allow"
check-cfg = ['cfg(feature, values("pvm", "service", "extension", "wasm"))']

[lib]
crate-type = ["rlib", "cdylib"]

[target.'cfg(target_arch = "riscv64")'.dependencies]
vos = {{ path = "{vos_path}", default-features = false, features = ["macros", "service"] }}

[target.'cfg(target_arch = "wasm32")'.dependencies]
vos = {{ path = "{vos_path}", default-features = false, features = ["macros", "wasm-bootstrap"] }}

[target.'cfg(not(any(target_arch = "riscv64", target_arch = "wasm32")))'.dependencies]
vos = {{ path = "{vos_path}", default-features = false, features = ["macros", "extension"] }}

[profile.release]
opt-level = "s"
lto = true
panic = "abort"
"#
    )
}

/// Cargo config baked into every synthesised project. Mirrors what
/// `examples/actors/*/`.cargo/config.toml looks like — the rustflags
/// inject the `no_std` / `no_main` crate attrs that PVM actors
/// expect, and `json-target-spec` lets `--target X.json` resolve.
const CARGO_CONFIG_TOML: &str = r#"[target.riscv64em-javm]
rustflags = [
    "-Zunstable-options",
    "-Zcrate-attr=no_std",
    "-Zcrate-attr=no_main",
    "-Aduplicate-macro-attributes",
    "-Aunused-attributes",
]

[unstable]
json-target-spec = true
"#;
