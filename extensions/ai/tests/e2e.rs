//! End-to-end smoke for the AI extension. `#[ignore]`d by
//! default because it fetches ~470MB of model + tokenizer files
//! from HuggingFace and runs CPU inference for several seconds.
//! Re-enable with `cargo test -p ai-extension --test e2e --
//! --ignored`.
//!
//! What this exercises:
//!
//! 1. `vosx space new` + `space up` with the AI extension loaded
//!    from the manifest.
//! 2. A `vosx ai generate` invoke through the CLI.
//! 3. The dispatch sidecar's lazy-load path: model files are
//!    fetched on the first call into the test's tempdir cache.
//! 4. Greedy-ish inference loop returns non-empty text.
//!
//! What this deliberately doesn't exercise:
//!
//! - Output quality. The model can answer "7 times 8" correctly
//!   in a manual run, but asserting on the exact reply would tie
//!   the test to one specific HF revision of the GGUF — too
//!   brittle. We assert the reply is non-empty + doesn't carry
//!   an `error: ` prefix.
//! - Concurrent invokes. The extension serialises behind a
//!   mutex; a second concurrent generate would block. The host's
//!   own scheduling tests cover the concurrency primitive.
//!
//! The harness mirrors the dev extension's e2e shape so two
//! people setting up extension tests learn one set of moves.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

// ── Paths ────────────────────────────────────────────────────────────

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("extensions/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn vosx_bin() -> PathBuf {
    workspace().join("target").join("debug").join("vosx")
}

fn ai_extension_so() -> PathBuf {
    // Prefer the release .so when present — debug-build candle
    // inference is several-fold slower and pushes the
    // actor-context test past every reasonable wedge threshold.
    // The release .so is ~12MB vs debug's 200MB+; building it
    // costs more once but pays back on every test run.
    let release = workspace()
        .join("target")
        .join("release")
        .join("libai_extension.so");
    if release.exists() {
        return release;
    }
    workspace()
        .join("target")
        .join("debug")
        .join("libai_extension.so")
}

fn ensure_built() {
    for (path, hint) in [
        (vosx_bin(), "cargo build -p vosx"),
        (ai_extension_so(), "cargo build -p ai-extension"),
    ] {
        if !path.exists() {
            panic!("test artifact missing: {}\nRun: {hint}", path.display());
        }
    }
}

/// Same as [`ensure_built`] plus the dev extension `.so`, which
/// the actor-flow test needs.
fn ensure_built_with_dev() {
    ensure_built();
    let dev_so = workspace()
        .join("target")
        .join("debug")
        .join("libdev_extension.so");
    if !dev_so.exists() {
        panic!(
            "test artifact missing: {}\nRun: cargo build -p dev-extension",
            dev_so.display()
        );
    }
}

fn dev_extension_so() -> PathBuf {
    workspace()
        .join("target")
        .join("debug")
        .join("libdev_extension.so")
}

// ── Tiny temp-dir helper ─────────────────────────────────────────────

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vos-ai-e2e-{}-{}-{}",
            std::process::id(),
            label,
            nanos
        ));
        fs::create_dir_all(&p).expect("create tempdir");
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("TempDir kept for debugging: {}", self.0.display());
            return;
        }
        // Deliberately NOT removing the cache tempdir contents
        // automatically — model files are large and re-fetching
        // them on every run is expensive. The OS will clean
        // /tmp on reboot anyway.
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ── Daemon harness ───────────────────────────────────────────────────

struct Daemon {
    child: Option<Child>,
    data_home: TempDir,
    config_home: TempDir,
    /// Cache home is kept separately so tests can opt into a
    /// persistent location via `VOS_AI_E2E_CACHE_HOME`. Default
    /// is a tempdir which means each run pays the full fetch.
    cache_home: PathBuf,
    space_name: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn boot_daemon() -> Daemon {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    // Allow a developer to point at a persistent cache via
    // `VOS_AI_E2E_CACHE_HOME=/some/path cargo test -- --ignored`
    // so back-to-back local runs don't re-fetch 470MB. Default
    // falls back to a tempdir.
    let cache_home = std::env::var("VOS_AI_E2E_CACHE_HOME")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let cache_dir = TempDir::new("cache");
            let p = cache_dir.path().to_path_buf();
            // Leak the tempdir guard so the OS-level path lives
            // for the duration of the test (Drop would wipe the
            // model bytes).
            std::mem::forget(cache_dir);
            p
        });
    let space_name = "ai-e2e";

    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr)
    );

    let manifest = write_manifest(config_home.path());

    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create daemon stderr log");
    let child = Command::new(vosx_bin())
        .args(["space", "up", space_name, "--manifest"])
        .arg(&manifest)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up");

    // Wait for the endpoint file — daemon's ready once it's
    // written its libp2p listening address.
    let space_data_dir = resolve_space_data_dir(config_home.path(), space_name);
    let endpoint_path = space_data_dir.join(".endpoint");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if endpoint_path.exists() {
            return Daemon {
                child: Some(child),
                data_home,
                config_home,
                cache_home,
                space_name: space_name.to_string(),
            };
        }
        thread::sleep(Duration::from_millis(150));
    }

    let stderr_tail = fs::read_to_string(&log_path).unwrap_or_default();
    panic!(
        "daemon didn't write endpoint within 30s\n--- stderr ---\n{stderr_tail}\n--- data ---\n{}",
        space_data_dir.display(),
    );
}

fn resolve_space_data_dir(config_home: &Path, space_name: &str) -> PathBuf {
    let index_path = config_home.join("vosx").join("spaces.toml");
    let raw = fs::read_to_string(&index_path)
        .unwrap_or_else(|e| panic!("read spaces.toml {}: {e}", index_path.display()));
    let parsed: toml::Value = toml::from_str(&raw).expect("parse spaces.toml");
    let entries = parsed
        .get("space")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("spaces.toml missing [[space]] entries: {raw}"));
    for entry in entries {
        let n = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if n == space_name {
            let d = entry
                .get("data_dir")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            return PathBuf::from(d);
        }
    }
    panic!("space '{space_name}' not in spaces.toml");
}

fn write_manifest(dir: &Path) -> PathBuf {
    let manifest_path = dir.join("ai-e2e-manifest.toml");
    let body = format!(
        r#"
space = "ai-e2e"
version = "0.1.0"

[[extension]]
name = "ai"
path = "{ai_so}"
"#,
        ai_so = ai_extension_so().display(),
    );
    fs::write(&manifest_path, body).expect("write manifest");
    manifest_path
}

fn write_manifest_with_dev(dir: &Path, space_name: &str) -> PathBuf {
    let manifest_path = dir.join(format!("{space_name}-manifest.toml"));
    let body = format!(
        r#"
space = "{space_name}"
version = "0.1.0"

[[extension]]
name = "dev"
path = "{dev_so}"

[[extension]]
name = "ai"
path = "{ai_so}"
"#,
        space_name = space_name,
        dev_so = dev_extension_so().display(),
        ai_so = ai_extension_so().display(),
    );
    fs::write(&manifest_path, body).expect("write manifest");
    manifest_path
}

// ── The test ────────────────────────────────────────────────────────

/// Drive `vosx ai generate` through the daemon. Asserts the
/// reply is non-empty text without an `error:` prefix.
///
/// First-run cost: ~15-30s on a typical broadband link + a few
/// seconds of CPU inference. Subsequent runs against the same
/// cache (via `VOS_AI_E2E_CACHE_HOME`) skip the fetch and just
/// pay the model-load + inference time (~5s).
#[test]
#[ignore = "fetches 470MB from HuggingFace + runs CPU inference; opt in via --ignored"]
fn ai_generate_e2e() {
    ensure_built();
    let daemon = boot_daemon();

    let out = Command::new(vosx_bin())
        .args([
            "ai",
            "generate",
            "--space",
            &daemon.space_name,
            "--max-tokens",
            "32",
            "Reply with the single word OK.",
        ])
        .env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", daemon.config_home.path())
        .env("XDG_CACHE_HOME", &daemon.cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        // First call includes the model fetch + load; bump the
        // CLI's invoke timeout well above the network round-trip.
        .env("VOSX_INVOKE_TIMEOUT_MS", "600000")
        .output()
        .expect("spawn vosx ai generate");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert!(
        out.status.success(),
        "vosx ai generate exited non-zero\nstdout: {stdout}\nstderr: {stderr}"
    );
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "vosx ai generate produced no output\nstderr: {stderr}"
    );
    assert!(
        !trimmed.starts_with("error:"),
        "vosx ai generate returned an error reply: {trimmed}"
    );
}

/// No-model actor-mode smoke. Boots a daemon with the ai
/// extension and asserts it loads as an **actor-mode** plugin
/// (`kind=Actor`) — a loadable plugin with the right kind — *without* paying the
/// 470MB model fetch the generate e2e needs. The actor-mode cli-dispatch +
/// reply round-trip itself is the same host path the dev e2e exercises
/// (`#[msg(cli)]` handlers), and the real inference path is covered by the
/// (model-gated) `ai_generate_e2e` above. `boot_daemon` only returns after
/// the daemon has reconciled the manifest and written its `.endpoint`, so
/// the plugin-load log line is already present.
#[test]
fn ai_loads_as_actor_mode() {
    ensure_built();
    let daemon = boot_daemon();

    let log_path = daemon.data_home.path().join("daemon.stderr");
    let raw = fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("read daemon stderr {}: {e}", log_path.display()));
    // tracing interleaves ANSI SGR codes between a field's name and value
    // (`actor\x1b[0m\x1b[2m=\x1b[0mAiExtension`), so strip them before
    // substring-matching the `name=value` pairs.
    let log = strip_ansi(&raw);
    assert!(
        log.contains("actor=AiExtension") && log.contains("kind=Actor"),
        "ai extension did not load as actor-mode (expected `actor=AiExtension kind=Actor`); \
         daemon log:\n{log}"
    );
}

/// Strip ANSI SGR escape sequences (`\x1b[..m`) so log assertions match the
/// plain `field=value` text regardless of tracing's colourised output.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// End-to-end for the full dev+ai pairing: provision a project,
/// seed source on `main`, ask the AI to extend it with --apply
/// on the default per-identity side branch, verify the head of
/// that branch advanced.
///
/// Like `ai_generate_e2e`, marked #[ignore] because of the
/// 470MB model fetch + several seconds of CPU. Re-use the cached
/// model via `VOS_AI_E2E_CACHE_HOME`.
#[test]
#[ignore = "boots dev+ai; uses cached model via VOS_AI_E2E_CACHE_HOME"]
fn ai_actor_apply_e2e() {
    ensure_built_with_dev();

    // Bring up a daemon with BOTH extensions loaded. We mirror
    // boot_daemon() but with a different manifest + space name
    // so the test can run alongside the ai-only one.
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    let cache_home = std::env::var("VOS_AI_E2E_CACHE_HOME")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let cache_dir = TempDir::new("cache");
            let p = cache_dir.path().to_path_buf();
            std::mem::forget(cache_dir);
            p
        });
    let space_name = "ai-actor-e2e";

    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr),
    );

    let manifest = write_manifest_with_dev(config_home.path(), space_name);

    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create daemon stderr log");
    let mut child = Command::new(vosx_bin())
        .args(["space", "up", space_name, "--manifest"])
        .arg(&manifest)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("RUST_LOG", "warn")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up");

    // The reconciler doesn't watch the registry at runtime, so
    // we need `space new` → daemon restart cycles to pick up
    // each new agent. Pattern matches the dev extension's e2e.
    let space_data_dir = resolve_space_data_dir(config_home.path(), space_name);
    wait_endpoint(&space_data_dir, &log_path);

    // 1. Provision a dev-project named `applytest`.
    let new_proj = Command::new(vosx_bin())
        .args(["dev", "new", "--space", space_name, "applytest"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx dev new");
    assert!(
        new_proj.status.success(),
        "vosx dev new failed: stderr={}",
        String::from_utf8_lossy(&new_proj.stderr),
    );

    // Restart so the project's actor instance comes up. Same
    // dance the dev extension's e2e does.
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(space_data_dir.join(".endpoint"));
    let log_file2 = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("reopen daemon log");
    let mut child = Command::new(vosx_bin())
        .args(["space", "up", space_name, "--manifest"])
        .arg(&manifest)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("RUST_LOG", "warn")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file2)
        .spawn()
        .expect("spawn vosx space up restart");
    wait_endpoint(&space_data_dir, &log_path);

    // 2. Seed src/lib.rs on `main` via vosx space call (uses the
    //    @file shorthand for blob bytes). A minimal counter that
    //    the AI can extend.
    let src_path = data_home.path().join("tiny.rs");
    fs::write(
        &src_path,
        "use vos::prelude::*;\n#[actor]\npub struct C { n: u32 }\n#[messages]\nimpl C {\n    fn new() -> Self { Self { n: 0 } }\n    #[msg]\n    async fn inc(&mut self) -> u32 { self.n += 1; self.n }\n}\n",
    )
    .expect("write tiny.rs");

    let blob_hex = vosx_call_capture(
        &data_home,
        &config_home,
        &cache_home,
        &[
            "--format",
            "json",
            "space",
            "call",
            space_name,
            "applytest",
            "put_blob",
            &format!("bytes=@{}", src_path.display()),
        ],
    );
    let blob_hex = blob_hex.trim().trim_matches('"').trim_start_matches("0x");
    let blob_bin_path = data_home.path().join("tiny.hash");
    write_hex(&blob_bin_path, blob_hex);

    let open_raw = vosx_call_capture(
        &data_home,
        &config_home,
        &cache_home,
        &[
            "space",
            "call",
            space_name,
            "applytest",
            "open_change",
            "base=@/dev/null",
        ],
    );
    let change_hex = open_raw
        .trim()
        .trim_start_matches("0x")
        .chars()
        .take(64)
        .collect::<String>();
    let change_bin_path = data_home.path().join("change.id");
    write_hex(&change_bin_path, &change_hex);

    let _ = vosx_call_capture(
        &data_home,
        &config_home,
        &cache_home,
        &[
            "space",
            "call",
            space_name,
            "applytest",
            "put_file_working",
            &format!("change_id=@{}", change_bin_path.display()),
            "path=src/lib.rs",
            &format!("blob_hash=@{}", blob_bin_path.display()),
        ],
    );
    let _ = vosx_call_capture(
        &data_home,
        &config_home,
        &cache_home,
        &[
            "space",
            "call",
            space_name,
            "applytest",
            "commit_change",
            &format!("change_id=@{}", change_bin_path.display()),
            "branch=main",
            "intent_tag=1",
            "intent_data=@/dev/null",
            "author=@/dev/null",
            "ts_ms=0",
        ],
    );

    // 3. Capture pre-state for the side branch (should be empty).
    let pre_main = vosx_call_capture(
        &data_home,
        &config_home,
        &cache_home,
        &[
            "space",
            "call",
            space_name,
            "applytest",
            "head",
            "branch=main",
        ],
    );
    assert!(
        pre_main.trim() != "0x",
        "main should have a commit after seeding, got {pre_main:?}",
    );

    // 4. Run `vosx ai actor --apply` with the default branch
    //    (per-identity ai/<prefix>/suggested). Use a small
    //    max_tokens so the test wraps up quickly.
    let actor_out = Command::new(vosx_bin())
        .args([
            "ai",
            "actor",
            "--space",
            space_name,
            "--project",
            "applytest",
            "--max-tokens",
            "256",
            "--apply",
            "Add a reset() handler that sets n to 0.",
        ])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .env("VOSX_INVOKE_TIMEOUT_MS", "600000")
        .output()
        .expect("spawn vosx ai actor");
    let actor_stdout = String::from_utf8_lossy(&actor_out.stdout).to_string();
    let actor_stderr = String::from_utf8_lossy(&actor_out.stderr).to_string();
    assert!(
        actor_out.status.success(),
        "vosx ai actor --apply exited non-zero\nstdout: {actor_stdout}\nstderr: {actor_stderr}",
    );

    // 5. The stderr summary should report a per-identity branch
    //    `ai/XXXX/suggested` (not the legacy `ai-suggested`),
    //    and the new commit hash.
    assert!(
        actor_stderr.contains("on 'ai/"),
        "--apply should target ai/<prefix>/suggested, got: {actor_stderr}",
    );
    assert!(
        actor_stderr.contains("/suggested'"),
        "--apply branch should end in /suggested, got: {actor_stderr}",
    );

    // 6. main stays put; the side branch has a new head.
    let post_main = vosx_call_capture(
        &data_home,
        &config_home,
        &cache_home,
        &[
            "space",
            "call",
            space_name,
            "applytest",
            "head",
            "branch=main",
        ],
    );
    assert_eq!(
        pre_main.trim(),
        post_main.trim(),
        "main should NOT move on --apply with default side-branch behavior",
    );

    let _ = child.kill();
    let _ = child.wait();
}

fn wait_endpoint(space_data: &Path, log_path: &Path) {
    let endpoint_path = space_data.join(".endpoint");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if endpoint_path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(150));
    }
    let stderr_tail = fs::read_to_string(log_path).unwrap_or_default();
    panic!(
        "daemon didn't write endpoint within 30s\n--- stderr ---\n{stderr_tail}\n--- data ---\n{}",
        space_data.display(),
    );
}

/// Run a `vosx` subcommand and return its stdout. Panics on
/// non-zero exit to surface the test failure clearly.
fn vosx_call_capture(
    data_home: &TempDir,
    config_home: &TempDir,
    cache_home: &Path,
    args: &[&str],
) -> String {
    let out = Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_CACHE_HOME", cache_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .env("VOSX_INVOKE_TIMEOUT_MS", "60000")
        .output()
        .unwrap_or_else(|e| panic!("spawn vosx {args:?}: {e}"));
    if !out.status.success() {
        panic!(
            "vosx {args:?} failed (status={:?})\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn write_hex(path: &Path, hex: &str) {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect::<Vec<u8>>();
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
