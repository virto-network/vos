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

use dev_project::{BlobObject, CommitNode, HASH_BYTES, HashResult};
use vos::Encode;
use vos::extension::ServiceCtx;
use vos::log;
use vos::value::{Msg, TAG_DYNAMIC, Value};

// ── Embedded build infra (synced from the workspace at build time) ───

/// The riscv64em-javm rustc target spec. Lives next to the
/// dev-project actor so the same JSON drives both the bundled
/// actor build and synthesised compiles.
const RISCV_TARGET_JSON: &str = include_str!("../../../actors/dev-project/riscv64em-javm.json");

/// Nightly channel the rest of the workspace pins. Synthesised
/// projects use the same pin so a rustup install satisfying the
/// workspace also satisfies dev-extension compiles.
const RUST_TOOLCHAIN: &str = include_str!("../../../rust-toolchain.toml");

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

impl From<&CompileOutcome> for HashResult {
    fn from(o: &CompileOutcome) -> Self {
        HashResult {
            status: o.status,
            hash: o.hash.clone(),
        }
    }
}

/// rkyv-encode an outcome's `HashResult` projection for the wire.
/// stderr stays host-side (logged + persisted to the build
/// commit's intent_data in Phase 1.3); the caller only needs to
/// see status + hash to decide what to do next.
pub fn encode_outcome(o: &CompileOutcome) -> Vec<u8> {
    if !o.stderr.is_empty() {
        // Best-effort logging so the operator sees the failure
        // even before Phase 1.3 records it on the commit DAG.
        let stderr_str = String::from_utf8_lossy(&o.stderr);
        log::warn!(
            "dev: compile failed (status={}):\n{}",
            o.status,
            stderr_str.trim_end()
        );
    }
    let result: HashResult = o.into();
    <HashResult as vos::Encode>::encode(&result)
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

    // ── 2. Lay out the tree
    let tempdir = match tempfile::Builder::new().prefix("vos-dev-").tempdir() {
        Ok(d) => d,
        Err(e) => return CompileOutcome::err(COMPILE_STATUS_IO, e.to_string()),
    };
    let project_root = tempdir.path();
    if let Err(e) = materialise_tree(ctx, project_id, &commit, project_root) {
        return e;
    }

    // ── 3. Synthesise the build infra
    if let Err(e) = write_build_infra(project_root) {
        return CompileOutcome::err(COMPILE_STATUS_IO, e);
    }

    // ── 4. Invoke cargo
    let output = match Command::new("cargo")
        .args([
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

    // ── 6. Transpile RISC-V ELF → PVM blob
    let pvm_blob = match grey_transpiler::link_elf(&elf_bytes) {
        Ok(b) => b,
        Err(e) => {
            return CompileOutcome::err(COMPILE_STATUS_TRANSPILE_FAILED, format!("{e:?}"));
        }
    };

    // ── 7. Store the PVM blob back into the project's object store
    let pvm_hash = match put_blob(ctx, project_id, &pvm_blob) {
        Ok(h) => h,
        Err(status) => return CompileOutcome::err(status, "put_blob failed"),
    };
    if pvm_hash.len() != HASH_BYTES {
        return CompileOutcome::err(
            COMPILE_STATUS_BAD_REPLY,
            "put_blob returned wrong hash length",
        );
    }

    CompileOutcome::ok(pvm_hash)
}

// ── Wire helpers ─────────────────────────────────────────────────────

fn dyn_payload(msg: &Msg) -> Vec<u8> {
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
fn decode_value(bytes: &[u8]) -> Option<Value> {
    <Value as vos::Decode>::try_decode(bytes)
}

/// Extract a `Vec<u8>` from a reply Value. Both typed-handler
/// returns (`Value::Bytes`) and `Value::Unit` map here — the
/// caller is expected to know which is "missing" vs "empty".
fn value_to_bytes(v: Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b),
        Value::Unit => Some(Vec::new()),
        _ => None,
    }
}

fn fetch_commit(ctx: &ServiceCtx, project_id: u32, hash: &[u8]) -> Result<Option<CommitNode>, u8> {
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

fn fetch_blob(ctx: &ServiceCtx, project_id: u32, hash: &[u8]) -> Result<Option<BlobObject>, u8> {
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

fn put_blob(ctx: &ServiceCtx, project_id: u32, bytes: &[u8]) -> Result<Vec<u8>, u8> {
    let msg = Msg::new("put_blob").with("bytes", bytes.to_vec());
    let raw = ctx
        .ask_raw(project_id, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)
}

// ── Filesystem layout ────────────────────────────────────────────────

fn materialise_tree(
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
        if let Err(e) = fs::write(&dest, &blob.bytes) {
            return Err(CompileOutcome::err(COMPILE_STATUS_IO, e.to_string()));
        }
    }
    Ok(())
}

/// Resolve `path` (a project-relative path that already passed the
/// actor's `is_valid_path` check) under `root` and refuse anything
/// that escapes via symlinks or repeated `..`. The actor strips
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

fn write_build_infra(root: &Path) -> Result<(), String> {
    let cargo_toml = synthesised_cargo_toml();
    fs::write(root.join("Cargo.toml"), cargo_toml).map_err(|e| e.to_string())?;

    let cargo_dir = root.join(".cargo");
    fs::create_dir_all(&cargo_dir).map_err(|e| e.to_string())?;
    fs::write(cargo_dir.join("config.toml"), CARGO_CONFIG_TOML).map_err(|e| e.to_string())?;

    fs::write(root.join("rust-toolchain.toml"), RUST_TOOLCHAIN).map_err(|e| e.to_string())?;
    fs::write(root.join("riscv64em-javm.json"), RISCV_TARGET_JSON).map_err(|e| e.to_string())?;
    Ok(())
}

fn synthesised_cargo_toml() -> String {
    // The agent-supplied tree owns `src/`; the dev extension owns
    // everything else around it. `name = "actor"` is fixed so the
    // output ELF path stays predictable across compiles.
    let vos_path = WORKSPACE_VOS_PATH;
    format!(
        r#"[package]
name = "actor"
version = "0.1.0"
edition = "2024"

[workspace]

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
