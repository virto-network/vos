//! End-to-end: real `vosx` daemon + bundled (PVM) space-registry + a real PVM
//! actor (`math`), driven through `vosx space console`. Proves the full local
//! console path:
//!
//!   piped stdin → vos-shell ConsoleEngine → DaemonClientBackend → libp2p →
//!   space-registry (resolve + meta_for_instance) → math actor (PVM) → reply →
//!   rendered text on stdout
//!
//! and the sandbox guarantee (filesystem/external commands rejected).
//!
//! Build prerequisites (the test panics with a hint rather than building):
//!   cargo build -p vosx
//!   cd examples && just build      # produces examples/actors/*/…/math.elf

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn vosx_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vosx"))
}

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vosx's parent is the workspace")
        .to_path_buf()
}

fn actor_elf(name: &str) -> PathBuf {
    workspace().join(format!(
        "examples/actors/{name}/target/riscv64em-javm/release/{name}.elf"
    ))
}

fn ensure_built() {
    for (path, hint) in [
        (vosx_bin(), "cargo build -p vosx"),
        (actor_elf("math"), "cd examples && just build"),
    ] {
        if !path.exists() {
            panic!("test artifact missing: {}\nRun: {}", path.display(), hint);
        }
    }
}

/// Minimal temp dir (avoids a tempfile dep; mirrors the gateway e2e helper).
struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vosx-console-e2e-{}-{}-{}",
            std::process::id(),
            label,
            nanos
        ));
        std::fs::create_dir_all(&p).expect("create tempdir");
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon {
    child: Child,
    data_home: TempDir,
    config_home: TempDir,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const SPACE: &str = "e2e";

fn write_manifest(dir: &Path) -> PathBuf {
    let path = dir.join("manifest.toml");
    let body = format!(
        r#"
space = "e2e"
version = "0.1.0"

[[agent]]
name = "math"
path = "{math}"
consistency = "ephemeral"
"#,
        math = actor_elf("math").display(),
    );
    std::fs::write(&path, body).expect("write manifest");
    path
}

/// `vosx` invocation pinned to this daemon's isolated XDG homes.
fn vosx(daemon: &Daemon, args: &[&str]) -> std::process::Output {
    Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", daemon.config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("spawn vosx")
}

/// The oracle: dynamic dispatch via the known-good `vosx <agent> <method>`
/// path. `--format json` renders the reply as `5` (the default text format
/// would Debug-print `U64(5)`). Returns trimmed stdout on success.
fn oracle_math_add(daemon: &Daemon, a: u64, b: u64) -> Option<String> {
    let out = vosx(
        daemon,
        &[
            "--format",
            "json",
            "--space",
            SPACE,
            "math",
            "add",
            &format!("a={a}"),
            &format!("b={b}"),
        ],
    );
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn boot_daemon() -> Daemon {
    let data_home = TempDir::new("data");
    let config_home = TempDir::new("config");
    let manifest_dir = TempDir::new("manifest");
    let manifest = write_manifest(manifest_dir.path());

    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", SPACE])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .output()
        .expect("spawn vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: {}",
        String::from_utf8_lossy(&new.stderr)
    );

    let log = std::fs::File::create(data_home.path().join("daemon.stderr")).expect("log file");
    let child = Command::new(vosx_bin())
        .args(["space", "up", SPACE, "--manifest"])
        .arg(&manifest)
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("RUST_LOG", "warn")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("spawn vosx space up");

    // manifest_dir must outlive `space up` reading it; the daemon reads it at
    // startup, so holding it until we confirm readiness is enough.
    let daemon = Daemon {
        child,
        data_home,
        config_home,
    };

    // Readiness = the oracle can add via the math agent. Doubles as "daemon
    // bound + client can reach it + math installed".
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if oracle_math_add(&daemon, 2, 3).as_deref() == Some("5") {
            drop(manifest_dir);
            return daemon;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "math agent never became ready within 40s; daemon log: {}",
        std::fs::read_to_string(daemon.data_home.path().join("daemon.stderr")).unwrap_or_default()
    );
}

/// Drive `vosx space console` with `input` on stdin (non-interactive). Returns
/// (stdout, stderr).
fn run_console(daemon: &Daemon, input: &str) -> (String, String) {
    let mut child = Command::new(vosx_bin())
        .args(["space", "console", SPACE])
        .env("XDG_DATA_HOME", daemon.data_home.path())
        .env("XDG_CONFIG_HOME", daemon.config_home.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vosx space console");
    child
        .stdin
        .take()
        .expect("console stdin")
        .write_all(input.as_bytes())
        .expect("write console stdin"); // drop closes stdin → EOF → REPL exits
    let out = child.wait_with_output().expect("console output");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn console_drives_pvm_actor_and_sandbox_holds() {
    ensure_built();
    let daemon = boot_daemon();

    // 1. Actor invocation through the console matches the oracle.
    let (stdout, stderr) = run_console(
        &daemon,
        "math add 2 3\nmath multiply 6 7\nmath add 5000000000 1\n",
    );
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines,
        vec!["5", "42", "5000000001"],
        "console stdout mismatch.\nstdout={stdout:?}\nstderr={stderr:?}"
    );
    // Parity with the known-good dispatch path.
    assert_eq!(oracle_math_add(&daemon, 2, 3).as_deref(), Some("5"));

    // 2. Sandbox: filesystem + external commands are rejected (stderr), and
    //    they produce no stdout. Real nu control flow still works.
    let (stdout, stderr) = run_console(
        &daemon,
        "open /etc/passwd\n^ls /\nhttp get https://example.com\nif true { math add 1 1 } else { math add 9 9 }\n",
    );
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines,
        vec!["2"],
        "only the control-flow line should produce output.\nstdout={stdout:?}\nstderr={stderr:?}"
    );
    assert!(
        stderr.contains("disabled in this sandbox")
            || stderr.to_lowercase().contains("unknown command"),
        "sandbox rejections should explain themselves on stderr, got: {stderr:?}"
    );

    // 3. Unknown actor / method → error on stderr, nothing on stdout.
    let (stdout, _stderr) = run_console(&daemon, "no_such_agent whatever\n");
    assert!(
        stdout.trim().is_empty(),
        "unknown agent should produce no stdout, got: {stdout:?}"
    );
}
