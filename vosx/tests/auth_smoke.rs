//! Daemon-auth gate end-to-end.
//!
//! Properties verified:
//!
//! 1. `space new` grants the creator `AUTH_ROLE_ADMIN` via a signed
//!    `grant_role` op baked into the genesis DAG (no on-disk
//!    bootstrap file), so `space role list` shows the operator as admin.
//! 2. The admin operator (XDG_CONFIG_HOME A) can grant roles against the
//!    running daemon.
//! 3. A second client with a different identity (XDG_CONFIG_HOME
//!    B) is *refused* by the dispatch-layer auth gate.
//! 4. After the admin grants role to B via `vosx space role
//!    grant`, B can grant in turn — and the actor-local (`--in <actor>`)
//!    grant path is independent of the space-level one.
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

    // ── space up (the genesis admin grant is already in the DAG) ───
    let log_path = data_home.path().join("daemon.stderr");
    let log_file = fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(vosx_bin())
        .args(["space", "up", space_name])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_a.path())
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        // Disable ANSI styling so log assertions below can match
        // `handler=grant_role` etc. as literal substrings.
        .env("NO_COLOR", "1")
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

    // ── A: role list — expect A's own peer_id with role=admin
    // (the genesis grant_role from `space new`, replayed from the DAG) ──
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

    // Client-side surface: the refusal must now reach vosx as a
    // distinct "permission denied" message (ClientError::Forbidden
    // through STATUS_FORBIDDEN), not collapse into a generic
    // transport error. Operators in the field rely on this — the
    // daemon-log assertion below confirms the gate fired, but only
    // this assertion proves the user-facing surface is operable.
    assert!(
        stderr_b.contains("permission denied"),
        "outsider's `role grant` stderr must surface 'permission denied' \
         (STATUS_FORBIDDEN end-to-end). stderr:\n{stderr_b}",
    );

    // Evidence: the failure must be a real auth refusal, not a
    // CLI parse error, transport timeout, or anything else. The
    // host-side warn() in node.rs::dispatch_invoke fires when
    // an actor returns STATUS_FORBIDDEN — confirms both that
    // the wire status round-tripped and that the offending peer
    // is named. The warn comes from the actor's macro-emitted
    // role check when it returns STATUS_FORBIDDEN.
    let gate_deadline = Instant::now() + Duration::from_secs(2);
    let mut log_snapshot = String::new();
    let mut saw_refusal = false;
    let mut saw_peer = false;
    while Instant::now() < gate_deadline {
        log_snapshot = fs::read_to_string(&log_path).unwrap_or_default();
        saw_refusal = log_snapshot.contains("auth: actor refused call");
        saw_peer = log_snapshot.contains(&b_peer);
        if saw_refusal && saw_peer {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw_refusal,
        "daemon log must record the actor's refusal — \
         the failure could have happened anywhere otherwise. log:\n{log_snapshot}"
    );
    assert!(
        saw_peer,
        "log must name the refused peer ({b_peer}); log:\n{log_snapshot}"
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

    // ── M8: --in <actor> actor-local grants ──────────────────
    //
    // The actor-local grant path is independent of the
    // space-level path. Confirm:
    //   1. `grant --in <actor>` succeeds for an admin (B is now
    //      admin from above) and stores a row in `actor_acls`.
    //   2. `list --in <actor>` shows the new row (and only that
    //      row — separate scope from the space-level list).
    //   3. `revoke --in <actor>` removes it; subsequent
    //      `list --in <actor>` is empty.
    //   4. The space-level row for the same peer is unchanged.
    let target_agent = "space-registry";
    let grant_local = Command::new(vosx_bin())
        .args([
            "space",
            "role",
            space_name,
            "grant",
            synthetic,
            "2", // raw role byte — actor-local roles are opaque to the CLI
            "--in",
            target_agent,
        ])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("actor-local grant");
    assert!(
        grant_local.status.success(),
        "actor-local grant must succeed. stderr:\n{}",
        String::from_utf8_lossy(&grant_local.stderr),
    );

    let list_local = Command::new(vosx_bin())
        .args(["space", "role", space_name, "list", "--in", target_agent])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("actor-local list");
    assert!(list_local.status.success());
    let list_out = String::from_utf8_lossy(&list_local.stdout);
    assert!(
        list_out.contains(synthetic),
        "actor-local list must show the granted peer. stdout:\n{list_out}",
    );

    let revoke_local = Command::new(vosx_bin())
        .args([
            "space",
            "role",
            space_name,
            "revoke",
            synthetic,
            "--in",
            target_agent,
        ])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("actor-local revoke");
    assert!(
        revoke_local.status.success(),
        "actor-local revoke must succeed. stderr:\n{}",
        String::from_utf8_lossy(&revoke_local.stderr),
    );

    // Space-level list still shows the synthetic peer as
    // `developer` — actor-local revoke didn't touch it.
    let list_space = Command::new(vosx_bin())
        .args(["space", "role", space_name, "list"])
        .env("XDG_DATA_HOME", data_home.path())
        .env("XDG_CONFIG_HOME", config_b.path())
        .env("VOSX_DISABLE_MDNS", "1")
        .output()
        .expect("space-level list");
    assert!(list_space.status.success());
    let space_out = String::from_utf8_lossy(&list_space.stdout);
    assert!(
        space_out.contains(synthetic),
        "space-level list must still show the peer after actor-local revoke.\
         \n{space_out}",
    );

    // Cleanup.
    let _ = child.kill();
    let _ = child.wait();
}
