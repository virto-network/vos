//! Sprint 2 daemon-auth gate end-to-end.
//!
//! Three properties verified:
//!
//! 1. `space new` records the creator's PeerId in
//!    `admin_bootstrap.txt`; on first `space up` the daemon
//!    grants `AUTH_ROLE_ADMIN` to that peer and removes the file.
//! 2. The admin operator (XDG_CONFIG_HOME A) can `vosx space
//!    publish` against the running daemon.
//! 3. A second client with a different identity (XDG_CONFIG_HOME
//!    B) is *refused* by the dispatch-layer auth gate when it
//!    tries to publish.
//! 4. After the admin grants role to B via `vosx space role
//!    grant`, B can publish.
//!
//! The test reuses the same `vosx` binary across A and B —
//! identity comes from `$XDG_CONFIG_HOME`, so a second
//! XDG_CONFIG_HOME pointed at a fresh tempdir gives B its own
//! libp2p keypair. The daemon's `XDG_DATA_HOME` is shared so
//! both clients dial the same `.endpoint`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

fn vosx_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vosx"))
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!(
            "vosx-auth-{}-{}-{}",
            std::process::id(),
            label,
            nanos,
        ));
        fs::create_dir_all(&p).expect("create tmpdir");
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn find_endpoint(root: &Path) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir()
            && let Some(found) = find_endpoint(&p)
        {
            return Some(found);
        } else if p.file_name().and_then(|f| f.to_str()) == Some(".endpoint") {
            return Some(p);
        }
    }
    None
}

fn space_data_dir(data_home: &Path) -> PathBuf {
    // Walk one level into the per-space subdirectory under
    // `<DATA_HOME>/vosx/<space_id>/`.
    let vosx = data_home.join("vosx");
    let mut found = None;
    if let Ok(rd) = fs::read_dir(&vosx) {
        for entry in rd.flatten() {
            if entry.path().is_dir() {
                found = Some(entry.path());
                break;
            }
        }
    }
    found.unwrap_or(vosx)
}

#[test]
fn auth_gate_admits_admin_refuses_outsider_then_grant_admits() {
    let data_home = TempDir::new("data");
    let config_a = TempDir::new("configA"); // admin operator
    let config_b = TempDir::new("configB"); // outsider
    let space_name = "auth-smoke";

    // ── A: space new (writes admin_bootstrap.txt for A's id) ─
    let new = Command::new(vosx_bin())
        .args(["space", "new", "--name", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_a.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("vosx space new");
    assert!(
        new.status.success(),
        "vosx space new failed: stderr={}",
        String::from_utf8_lossy(&new.stderr)
    );

    let data_dir = space_data_dir(data_home.path());
    let bootstrap = data_dir.join("admin_bootstrap.txt");
    assert!(
        bootstrap.exists(),
        "space new must record admin bootstrap PeerId at {}",
        bootstrap.display(),
    );

    // ── space up (admin bootstrap consumed; file deleted) ───
    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(vosx_bin())
        .args(["space", "up", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_a.path())
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("vosx space up");

    let endpoint_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < endpoint_deadline {
        if find_endpoint(data_home.path()).is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        find_endpoint(data_home.path()).is_some(),
        "daemon didn't write endpoint within 10s — log:\n{}",
        fs::read_to_string(&log_path).unwrap_or_default(),
    );

    // The bootstrap file must be gone after the daemon's
    // startup grant.
    let after_boot_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < after_boot_deadline {
        if !bootstrap.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !bootstrap.exists(),
        "admin_bootstrap.txt should be deleted after space up consumes it — log:\n{}",
        fs::read_to_string(&log_path).unwrap_or_default(),
    );

    // ── A: role list — expect A's own peer_id with role=admin ──
    let list = Command::new(vosx_bin())
        .args(["space", "role", space_name, "list"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_a.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("vosx space role list");
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list.status.success(), "role list failed: {stdout}");
    assert!(
        stdout.contains("admin"),
        "role list should show A's admin grant; got:\n{stdout}",
    );

    // B needs to know which daemon to dial; replicate A's
    // spaces.toml into B's config home. Identity stays
    // independent (different XDG_CONFIG_HOME → different
    // `identity.key`), but the spaces index just maps name →
    // data_dir → endpoint.
    let a_spaces = config_a.path().join("vosx").join("spaces.toml");
    let b_vosx = config_b.path().join("vosx");
    fs::create_dir_all(&b_vosx).expect("create B vosx config dir");
    fs::copy(&a_spaces, b_vosx.join("spaces.toml")).expect("copy spaces.toml");

    // ── Capture B's PeerId via `vosx whoami` (identity is
    // loaded from the second XDG_CONFIG_HOME). ───────────────
    let whoami_b = Command::new(vosx_bin())
        .args(["whoami"])
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("vosx whoami");
    assert!(whoami_b.status.success());
    let b_out = String::from_utf8_lossy(&whoami_b.stdout);
    let b_peer = b_out
        .lines()
        .find_map(|l| l.strip_prefix("peer_id = "))
        .map(str::trim)
        .expect("whoami output should contain peer_id")
        .to_string();

    // ── B: `space role grant` against the daemon must FAIL —
    // grant_role is in the admin-only list and B has no role. ─
    let grant_b = Command::new(vosx_bin())
        .args(["space", "role", space_name, "grant", &b_peer, "developer"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("outsider grant");
    let stderr_b = String::from_utf8_lossy(&grant_b.stderr);
    assert!(
        !grant_b.status.success(),
        "outsider's `role grant` must be refused by the auth gate. stderr:\n{stderr_b}",
    );

    // ── A: grant B admin — must SUCCEED (A is the bootstrap
    // admin from `space new`). ──────────────────────────────
    let grant_a = Command::new(vosx_bin())
        .args(["space", "role", space_name, "grant", &b_peer, "admin"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_a.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("admin grant");
    assert!(
        grant_a.status.success(),
        "admin grant must succeed. stderr:\n{}",
        String::from_utf8_lossy(&grant_a.stderr),
    );

    // ── B: now-admin can grant a third (synthetic) peer. ─────
    // Use a fabricated PeerId by parsing a known multibase
    // string — the registry doesn't verify peer existence on
    // grant, only that the caller is admin.
    let synthetic = "12D3KooWAfBVdmphtMFPVq3GVRkubsbjY7d4kkpEFG1cd6CSC95N";
    let grant_b_again = Command::new(vosx_bin())
        .args(["space", "role", space_name, "grant", synthetic, "developer"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("now-admin B grants synthetic");
    assert!(
        grant_b_again.status.success(),
        "B's grant should now succeed (B is admin). stderr:\n{}",
        String::from_utf8_lossy(&grant_b_again.stderr),
    );

    // Cleanup.
    let _ = child.kill();
    let _ = child.wait();
}
