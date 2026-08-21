//! Onboarding end-to-end: `space up <token>` join + redeem + sync.
//!
//! The point of the whole onboarding plan: getting a second node into a
//! space is one command with one argument. This test drives the real
//! two-daemon path with the bundled registry (no riscv actor build
//! needed):
//!
//!   host A: `space new` → `space up` → `space invite --role member`
//!   host B: `space up <token>`  (join-if-needed + auto-redeem)
//!
//! and asserts the two properties that make the wave work:
//!
//! 1. B's redeem loop reaches A, A's canonical authority commits the exact
//!    redemption, and only then A records the root-attested registry grant.
//!    Its `space members` output grows an `# invites` section.
//! 2. B syncs A's registry — which now serves at the MEMBER floor
//!    (decision 9). B started with an empty registry, so the genesis
//!    ADMIN grant showing up in B's `space role list` can only have
//!    arrived by a Member-gated `FetchHeads` that A served *because* the
//!    redemption granted B's node key. This is the bootstrap the flip
//!    depends on: public redeem request → authority commit → attested
//!    registry grant → sync.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, thread};

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

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
            "vosx-onb-{}-{}-{}",
            std::process::id(),
            label,
            nanos
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

/// A running daemon; SIGKILLed on drop so a failed assertion doesn't
/// leak the process.
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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

fn spawned_v2_root_id(log: &Path, name: &str) -> Option<String> {
    let marker = format!("v2 root tree '{name}' spawned as ");
    fs::read_to_string(log)
        .ok()?
        .lines()
        .find_map(|line| line.split_once(&marker).map(|(_, id)| id.trim().to_owned()))
}

fn daemon_peer_id(log: &Path) -> Option<String> {
    fs::read_to_string(log).ok()?.lines().find_map(|line| {
        line.split_once("node identity ")
            .and_then(|(_, rest)| rest.split_once(" (prefix"))
            .map(|(peer, _)| peer.to_owned())
    })
}

fn endpoint_prefix(endpoint: &Path) -> u16 {
    let body = fs::read_to_string(endpoint).expect("read daemon endpoint");
    let endpoint: toml::Value = toml::from_str(&body).expect("decode daemon endpoint");
    endpoint["prefix"]
        .as_integer()
        .and_then(|prefix| u16::try_from(prefix).ok())
        .expect("daemon endpoint carries a u16 prefix")
}

fn endpoint_connect_addr(endpoint: &Path) -> String {
    let body = fs::read_to_string(endpoint).expect("read daemon endpoint");
    let endpoint: toml::Value = toml::from_str(&body).expect("decode daemon endpoint");
    endpoint["multiaddrs"]
        .as_array()
        .and_then(|addresses| addresses.first())
        .and_then(toml::Value::as_str)
        .expect("daemon endpoint advertises a listen address")
        .to_owned()
}

#[derive(Debug)]
struct TestRaftStatus {
    present: bool,
    role: String,
    leader: Option<u16>,
    members: Vec<u16>,
    joint_old: Option<Vec<u16>>,
    active_config_index: Option<u64>,
    daemon_prefix: u16,
    commit_index: u64,
    last_applied: u64,
}

fn production_raft_status(
    data_home: &Path,
    config_home: &Path,
    space: &str,
    instance: &str,
) -> Option<TestRaftStatus> {
    let output = vosx(
        data_home,
        config_home,
        &["--format", "json", "space", "raft-status", space, instance],
    );
    if !output.status.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    Some(TestRaftStatus {
        present: value.get("present")?.as_bool()?,
        role: value.get("role")?.as_str()?.to_owned(),
        leader: value
            .get("leader")?
            .as_u64()
            .and_then(|prefix| u16::try_from(prefix).ok()),
        members: value
            .get("members")?
            .as_array()?
            .iter()
            .map(|member| member.as_u64().and_then(|value| u16::try_from(value).ok()))
            .collect::<Option<Vec<_>>>()?,
        joint_old: match value.get("joint_old")? {
            serde_json::Value::Null => None,
            serde_json::Value::Array(members) => Some(
                members
                    .iter()
                    .map(|member| member.as_u64().and_then(|value| u16::try_from(value).ok()))
                    .collect::<Option<Vec<_>>>()?,
            ),
            _ => return None,
        },
        active_config_index: match value.get("active_config_index")? {
            serde_json::Value::Null => None,
            serde_json::Value::Number(index) => index.as_u64(),
            _ => return None,
        },
        daemon_prefix: value
            .get("daemon_prefix")?
            .as_u64()
            .and_then(|prefix| u16::try_from(prefix).ok())?,
        commit_index: value.get("commit_index")?.as_u64()?,
        last_applied: value.get("last_applied")?.as_u64()?,
    })
}

/// Run a one-shot `vosx` client command against a config/data home.
fn vosx(data_home: &Path, config_home: &Path, args: &[&str]) -> Output {
    Command::new(vosx_bin())
        .args(args)
        .env("XDG_DATA_HOME", data_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("VOSX_DISABLE_MDNS", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run vosx")
}

/// Spawn a long-running `space up <arg>` daemon, logging to a file.
fn spawn_up_with_service(
    data_home: &Path,
    config_home: &Path,
    arg: &str,
    log_path: &Path,
    service_pvm: Option<&Path>,
) -> Child {
    spawn_up_with_service_and_trust(data_home, config_home, arg, log_path, service_pvm, None)
}

fn spawn_up_with_service_and_trust(
    data_home: &Path,
    config_home: &Path,
    arg: &str,
    log_path: &Path,
    service_pvm: Option<&Path>,
    production_trust_socket: Option<&Path>,
) -> Child {
    spawn_up_with_service_trust_and_connects(
        data_home,
        config_home,
        arg,
        log_path,
        service_pvm,
        production_trust_socket,
        &[],
    )
}

fn spawn_up_with_service_trust_and_connects(
    data_home: &Path,
    config_home: &Path,
    arg: &str,
    log_path: &Path,
    service_pvm: Option<&Path>,
    production_trust_socket: Option<&Path>,
    connect: &[&str],
) -> Child {
    let log_file = fs::File::create(log_path).expect("create log");
    let mut command = Command::new(vosx_bin());
    command.args(["space", "up", arg]);
    if let Some(path) = service_pvm {
        command.arg("--service-pvm").arg(path);
    }
    if let Some(path) = production_trust_socket {
        command.arg("--production-trust-socket").arg(path);
    }
    for address in connect {
        command.arg("--connect").arg(address);
    }
    command
        .env("XDG_DATA_HOME", data_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("RUST_LOG", "info")
        .env("VOSX_DISABLE_MDNS", "1")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .expect("spawn vosx space up")
}

/// Minimal independent implementation of the documented VTA1/VTR1 authority
/// protocol. Keeping this outside the daemon crate makes the acceptance test
/// exercise the public wire rather than its private codec helpers.
struct TestProductionTrustSidecar {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    observations: Arc<Mutex<TestProductionTrustObservations>>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct TestProductionTrustObservations {
    tags: Vec<u8>,
    installs: Vec<vos::v2::ServiceGenesisV2>,
    receipts: Vec<vos::v2::ReceiptVerificationRequestV2>,
}

impl TestProductionTrustSidecar {
    const REQUEST_MAGIC: [u8; 4] = *b"VTA1";
    const RESPONSE_MAGIC: [u8; 4] = *b"VTR1";
    const VERSION: u16 = 1;
    const QUERY_POLICY: u8 = 0;
    const CURRENT_TIMESLOT: u8 = 1;
    const VERIFY_TIMESLOT: u8 = 2;
    const VERIFY_PROOF: u8 = 3;
    const VERIFY_INSTALL: u8 = 4;
    const VERIFY_UPGRADE: u8 = 5;
    const VERIFY_ROLE: u8 = 6;
    const VERIFY_RECEIPT: u8 = 7;
    const AUTHORIZED: u8 = 0;
    const DENIED: u8 = 1;
    const TIMESLOT: u8 = 4;
    const POLICY: u8 = 5;
    const LOGICAL_TIMESLOT: u64 = 1_000;

    fn start(path: PathBuf, policy: vos::v2::Hash) -> Self {
        let listener = UnixListener::bind(&path).expect("bind production trust sidecar");
        listener
            .set_nonblocking(true)
            .expect("make production trust sidecar nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let observations = Arc::new(Mutex::new(TestProductionTrustObservations::default()));
        let thread_stop = stop.clone();
        let thread_observations = observations.clone();
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("production trust sidecar accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("bound production trust request read");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("bound production trust response write");
                let mut frame_len = [0; 4];
                if stream.read_exact(&mut frame_len).is_err() {
                    continue;
                }
                let frame_len = u32::from_le_bytes(frame_len) as usize;
                assert!(
                    frame_len <= 64 * 1024 * 1024,
                    "authority request is bounded"
                );
                let mut request = vec![0; frame_len];
                if stream.read_exact(&mut request).is_err() {
                    continue;
                }
                assert!(request.len() >= 11, "authority request header");
                assert_eq!(request[..4], Self::REQUEST_MAGIC);
                assert_eq!(u16::from_le_bytes([request[4], request[5]]), Self::VERSION);
                let tag = request[6];
                let payload_len = u32::from_le_bytes(request[7..11].try_into().unwrap()) as usize;
                assert_eq!(payload_len, request.len() - 11);

                let request_hash =
                    vos::v2::Hash::digest(b"vos/production-trust-socket/request/v1", &[&request]);
                let result = Self::classify(
                    tag,
                    &request[11..],
                    &mut thread_observations.lock().unwrap(),
                );
                let mut response = Vec::with_capacity(79);
                response.extend_from_slice(&Self::RESPONSE_MAGIC);
                response.extend_from_slice(&Self::VERSION.to_le_bytes());
                response.extend_from_slice(&request_hash.0);
                response.extend_from_slice(&policy.0);
                response.push(result);
                if result == Self::TIMESLOT {
                    // One JAM slot admits multiple service transitions. Keep
                    // the observation stable across the node's allocation and
                    // IC-5 verification calls; changing it between those two
                    // reads must fail closed.
                    response.extend_from_slice(&Self::LOGICAL_TIMESLOT.to_le_bytes());
                }
                if stream
                    .write_all(&(response.len() as u32).to_le_bytes())
                    .and_then(|()| stream.write_all(&response))
                    .is_err()
                {
                    continue;
                }
            }
        });
        Self {
            path,
            stop,
            observations,
            thread: Some(handle),
        }
    }

    fn classify(tag: u8, payload: &[u8], observations: &mut TestProductionTrustObservations) -> u8 {
        use vos::v2::V2Wire;

        let valid = match tag {
            Self::QUERY_POLICY if payload.is_empty() => {
                observations.tags.push(tag);
                return Self::POLICY;
            }
            Self::CURRENT_TIMESLOT if payload.is_empty() => {
                observations.tags.push(tag);
                return Self::TIMESLOT;
            }
            Self::VERIFY_TIMESLOT => payload
                .try_into()
                .map(u64::from_le_bytes)
                .is_ok_and(|slot| slot == Self::LOGICAL_TIMESLOT),
            Self::VERIFY_PROOF => Self::decode_pair(payload).is_some_and(|(request, proof)| {
                vos::v2::ProofVerificationRequestV2::decode(request)
                    .is_ok_and(|request| request.proof_blob.matches(proof))
            }),
            Self::VERIFY_INSTALL => match vos::v2::ServiceGenesisV2::decode(payload) {
                Ok(genesis) => {
                    observations.installs.push(genesis);
                    true
                }
                Err(_) => false,
            },
            Self::VERIFY_UPGRADE => vos::v2::ActorUpgradeV2::decode(payload).is_ok(),
            Self::VERIFY_ROLE => {
                vos::v2::RoleCredentialVerificationRequestV2::decode(payload).is_ok()
            }
            Self::VERIFY_RECEIPT => match vos::v2::ReceiptVerificationRequestV2::decode(payload) {
                Ok(request) => {
                    observations.receipts.push(request);
                    true
                }
                Err(_) => false,
            },
            _ => false,
        };
        if valid {
            observations.tags.push(tag);
            Self::AUTHORIZED
        } else {
            Self::DENIED
        }
    }

    fn decode_pair(payload: &[u8]) -> Option<(&[u8], &[u8])> {
        let left_len = u32::from_le_bytes(payload.get(..4)?.try_into().ok()?) as usize;
        let left_end = 4_usize.checked_add(left_len)?;
        let right_len_end = left_end.checked_add(4)?;
        let right_len =
            u32::from_le_bytes(payload.get(left_end..right_len_end)?.try_into().ok()?) as usize;
        let right_end = right_len_end.checked_add(right_len)?;
        (right_end == payload.len())
            .then(|| (&payload[4..left_end], &payload[right_len_end..right_end]))
    }

    fn saw(&self, tag: u8) -> bool {
        self.observations.lock().unwrap().tags.contains(&tag)
    }

    fn tag_count(&self, tag: u8) -> usize {
        self.observations
            .lock()
            .unwrap()
            .tags
            .iter()
            .filter(|observed| **observed == tag)
            .count()
    }

    fn saw_install_for(&self, actor_name: &str, consistency: vos::v2::ConsistencyModeV2) -> bool {
        self.observations
            .lock()
            .unwrap()
            .installs
            .iter()
            .any(|genesis| {
                genesis.consistency == consistency
                    && genesis.actors.iter().any(|actor| actor.name == actor_name)
            })
    }

    fn receipt_digests_for(
        &self,
        actor_name: &str,
        consistency: vos::v2::ConsistencyModeV2,
    ) -> Vec<vos::v2::Hash> {
        let observations = self.observations.lock().unwrap();
        let Some(service) = observations
            .installs
            .iter()
            .find(|genesis| {
                genesis.consistency == consistency
                    && genesis.actors.iter().any(|actor| actor.name == actor_name)
            })
            .map(|genesis| &genesis.service)
        else {
            return Vec::new();
        };
        let mut digests = Vec::new();
        for request in observations.receipts.iter().filter(|request| {
            request.receipt.service == *service && request.receipt.consistency == consistency
        }) {
            let digest = request.hash();
            if !digests.contains(&digest) {
                digests.push(digest);
            }
        }
        digests
    }

    fn new_receipt_digests_since(
        &self,
        actor_name: &str,
        consistency: vos::v2::ConsistencyModeV2,
        baseline: &[vos::v2::Hash],
    ) -> Vec<vos::v2::Hash> {
        self.receipt_digests_for(actor_name, consistency)
            .into_iter()
            .filter(|digest| !baseline.contains(digest))
            .collect()
    }

    fn newest_receipt_digest_since(
        &self,
        actor_name: &str,
        consistency: vos::v2::ConsistencyModeV2,
        baseline: &[vos::v2::Hash],
    ) -> Option<vos::v2::Hash> {
        let observations = self.observations.lock().unwrap();
        let service = observations
            .installs
            .iter()
            .find(|genesis| {
                genesis.consistency == consistency
                    && genesis.actors.iter().any(|actor| actor.name == actor_name)
            })?
            .service
            .clone();
        observations
            .receipts
            .iter()
            .filter(|request| {
                request.receipt.service == service && request.receipt.consistency == consistency
            })
            .filter_map(|request| {
                let digest = request.hash();
                (!baseline.contains(&digest)).then_some((request.receipt.sequence, digest))
            })
            .max_by_key(|(sequence, _)| *sequence)
            .map(|(_, digest)| digest)
    }
}

fn combined_receipt_digests_for(
    left: &TestProductionTrustSidecar,
    right: &TestProductionTrustSidecar,
    actor_name: &str,
    consistency: vos::v2::ConsistencyModeV2,
) -> Vec<vos::v2::Hash> {
    let mut digests = left.receipt_digests_for(actor_name, consistency);
    for digest in right.receipt_digests_for(actor_name, consistency) {
        if !digests.contains(&digest) {
            digests.push(digest);
        }
    }
    digests
}

impl Drop for TestProductionTrustSidecar {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            handle.join().expect("join production trust sidecar");
        }
        let _ = fs::remove_file(&self.path);
    }
}

fn counter_package_fixture(output_dir: &Path) -> PathBuf {
    let actor_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/target/riscv64em-javm/release/v2_counter.elf");
    assert!(
        actor_elf.is_file(),
        "build the public counter first: `just build-examples` ({})",
        actor_elf.display(),
    );
    let build_data = output_dir.join("build-data");
    let build_config = output_dir.join("build-config");
    let actor = actor_elf.to_string_lossy().into_owned();
    let out = output_dir.to_string_lossy().into_owned();
    vosx_ok(
        &build_data,
        &build_config,
        &[
            "build",
            &actor,
            "--name",
            "onboarding-counter",
            "--version",
            "0.1.0",
            "--out-dir",
            &out,
        ],
    );
    let package = output_dir.join("onboarding-counter.vos");
    assert!(package.is_file(), "vosx build must emit the signed package");
    package
}

fn crdt_counter_package_fixture(output_dir: &Path) -> PathBuf {
    let actor_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../tests/fixtures/v2/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter_v2.elf",
    );
    assert!(
        actor_elf.is_file(),
        "build the v2 CRDT counter first: `just build-v2-registry-fixtures` ({})",
        actor_elf.display(),
    );
    let build_data = output_dir.join("build-data");
    let build_config = output_dir.join("build-config");
    let actor = actor_elf.to_string_lossy().into_owned();
    let out = output_dir.to_string_lossy().into_owned();
    vosx_ok(
        &build_data,
        &build_config,
        &[
            "build",
            &actor,
            "--name",
            "production-crdt-counter",
            "--version",
            "0.1.0",
            "--out-dir",
            &out,
        ],
    );
    let package = output_dir.join("production-crdt-counter.vos");
    assert!(package.is_file(), "vosx build must emit the signed package");
    package
}

fn assert_bundled_space_authority_matches_fresh_build(output_dir: &Path) {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let actor_elf =
        workspace.join("actors/space-authority/target/riscv64em-javm/release/space_authority.elf");
    assert!(
        actor_elf.is_file(),
        "build the canonical authority first: `just build-actor space-authority`",
    );
    let build_data = output_dir.join("authority-build-data");
    let build_config = output_dir.join("authority-build-config");
    let actor = actor_elf.to_string_lossy().into_owned();
    let out = output_dir.to_string_lossy().into_owned();
    vosx_ok(
        &build_data,
        &build_config,
        &[
            "build",
            &actor,
            "--name",
            "space-authority",
            "--version",
            "artifact-only",
            "--out-dir",
            &out,
        ],
    );
    let fresh = fs::read(output_dir.join("space-authority.pvm"))
        .expect("fresh authority build emits its PVM");
    let bundled = fs::read(workspace.join("vosx/blobs/space_authority.pvm"))
        .expect("vosx ships the canonical authority PVM");
    assert_eq!(
        bundled, fresh,
        "the bundled space-authority PVM must match a fresh canonical actor build",
    );
}

fn wait_for_endpoint(data_home: &Path, log_path: &Path, who: &str) -> PathBuf {
    // Production restarts open and policy-check each durable root before
    // publishing the endpoint. A voter hosting both the canonical authority
    // and an application Raft root can legitimately take longer than the old
    // 15-second single-root budget on an unoptimized test build.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(p) = find_endpoint(data_home) {
            return p;
        }
        if Instant::now() >= deadline {
            panic!(
                "daemon {who} didn't write an endpoint within 30s — log:\n{}",
                fs::read_to_string(log_path).unwrap_or_default(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Poll `f` until it returns true or the deadline elapses; panic with
/// `msg` (and the daemon logs) on timeout.
fn poll_until(secs: u64, mut f: impl FnMut() -> bool, on_fail: impl FnOnce() -> String) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if f() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{}", on_fail());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn onboarding_via_token_redeems_syncs_spawns_and_reattaches() {
    let space = "onb";
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );
    let artifacts = TempDir::new("onb-artifacts");
    let counter_package = counter_package_fixture(artifacts.path());
    let data_b = TempDir::new("b-data");
    let cfg_b = TempDir::new("b-config");

    // ── host A: create + boot + install a MEMBER-floor v2 actor ────
    let (data_a, cfg_a, _daemon_a, log_a) = boot_admin_with_service(space, Some(&service_pvm));
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "publish",
            space,
            "onboarding-counter:0.1.0",
            counter_package.to_str().expect("package path is UTF-8"),
        ],
    );
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "install",
            space,
            "onboarding-counter:0.1.0",
            "--name",
            "counter",
            "--consistency",
            "local",
            "--sync",
            "member",
        ],
    );

    // ── host A: mint a member invite (default bootnodes = A's addrs) ─
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = stdout
        .lines()
        .next()
        .expect("invite prints the token first")
        .trim()
        .to_string();
    assert!(
        token.starts_with("vos1"),
        "expected a vos1… token, got: {token}"
    );

    // ── host B: literally `space up <token>` — join + redeem + sync ─
    let log_b = data_b.path().join("daemon-b.stderr");
    let daemon_b = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
    ));
    let endpoint_b = wait_for_endpoint(data_b.path(), &log_b, "B");
    let pending_invite = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join(".pending-invite.token");

    // (1) Redemption reaches A: an `# invites` section appears in A's
    //     members only once the `redeem_invite` handler records the row.
    poll_until(
        40,
        || {
            let o = vosx(data_a.path(), cfg_a.path(), &["space", "members", space]);
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("# invites")
        },
        || {
            format!(
                "A never recorded the redemption (no `# invites` in `space members`) — \
                 the redeem loop didn't reach A. B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );

    // (2) B synced A's MEMBER-gated registry: B started empty, so the
    //     genesis ADMIN grant in B's role list arrived only via a
    //     Member-gated FetchHeads A served because the redemption
    //     granted B's node key. This is the flip working.
    poll_until(
        40,
        || {
            let o = vosx(
                data_b.path(),
                cfg_b.path(),
                &["space", "role", space, "list"],
            );
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("admin")
        },
        || {
            format!(
                "B never synced A's Member-gated registry (no admin grant in B's `space role \
                 list`) — either the redeem didn't grant B's node key, or the Member floor \
                 refused B's sync. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    poll_until(
        40,
        || !pending_invite.exists(),
        || {
            format!(
                "B's registry grant landed, but canonical authority redemption did not. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (3) B starts the signed Member-floor v2 root and serves a real call.
    // Registry sync alone cannot make this pass: B must fetch the exact
    // package, validate its service pin, open the guest-owned image, and
    // register the root route.
    poll_until(
        40,
        || {
            vosx(
                data_b.path(),
                cfg_b.path(),
                &["space", "call", space, "counter", "value"],
            )
            .status
            .success()
        },
        || {
            format!(
                "a call to the signed v2 counter on B never succeeded. B log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // (5) Bare-restart re-attach: kill B and restart with `space up
    //     <name>` — no token, no manifest. The redemption already
    //     cleared the pending invite secret, so B re-boots from the index + synced
    //     registry + local.toml alone and re-spawns crdt-counter. This is
    //     the standing restart-bug fix under the onboarding flow.
    drop(daemon_b); // SIGKILL B's first daemon
    let restart_at = std::time::SystemTime::now();
    let log_b2 = data_b.path().join("daemon-b2.stderr");
    let _daemon_b2 = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        space,
        &log_b2,
        Some(&service_pvm),
    ));
    // Wait for a FRESH endpoint (newer than the kill), past the stale one.
    poll_until(
        20,
        || {
            find_endpoint(data_b.path())
                .and_then(|p| fs::metadata(&p).ok())
                .and_then(|m| m.modified().ok())
                .is_some_and(|mt| mt >= restart_at)
        },
        || {
            format!(
                "B didn't re-attach after a bare restart; log:\n{}",
                fs::read_to_string(&log_b2).unwrap_or_default()
            )
        },
    );
    // Reopen is proven by the actor being reachable again; merely retaining
    // its image on disk would not prove route registration or guest startup.
    poll_until(
        30,
        || {
            vosx(
                data_b.path(),
                cfg_b.path(),
                &["space", "call", space, "counter", "value"],
            )
            .status
            .success()
        },
        || {
            format!(
                "B didn't reopen counter after a bare `space up {space}` restart; log:\n{}",
                fs::read_to_string(&log_b2).unwrap_or_default()
            )
        },
    );
}

#[test]
fn signed_v2_package_runs_and_reopens_through_the_space_daemon() {
    let space = "v2-root";
    let data = TempDir::new("v2-root-data");
    let config = TempDir::new("v2-root-config");
    let dist = TempDir::new("v2-root-dist");
    let upgrade_dist = TempDir::new("v2-root-upgrade-dist");
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let actor_elf = workspace.join("examples/actors/target/riscv64em-javm/release/v2_counter.elf");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        actor_elf.is_file(),
        "build the v2 daemon actor first: `cd examples/actors && cargo +nightly actor -p v2-counter`",
    );
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );

    let actor = actor_elf.to_string_lossy().into_owned();
    let out = dist.path().to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "build",
            &actor,
            "--name",
            "counter",
            "--version",
            "0.1.0",
            "--out-dir",
            &out,
        ],
    );
    let package = dist.path().join("counter.vos");
    assert!(package.is_file(), "vosx build must emit the signed package");
    let upgrade_out = upgrade_dist.path().to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "build",
            &actor,
            "--name",
            "counter",
            "--version",
            "0.2.0",
            "--out-dir",
            &upgrade_out,
        ],
    );
    let upgrade_package = upgrade_dist.path().join("counter.vos");
    assert!(
        upgrade_package.is_file(),
        "vosx build must emit the upgrade package",
    );

    vosx_ok(data.path(), config.path(), &["space", "new", space]);
    let first_log = data.path().join("v2-root-first.stderr");
    let first = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &first_log,
        Some(&service_pvm),
    ));
    wait_for_endpoint(data.path(), &first_log, "v2-root-first");

    let package_source = package.to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &["space", "publish", space, "counter:0.1.0", &package_source],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "counter:0.1.0",
            "--consistency",
            "local",
        ],
    );

    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the daemon never attached the installed v2 root service; log:\n{}",
                fs::read_to_string(&first_log).unwrap_or_default(),
            )
        },
    );
    let incremented = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "counter", "increment", "by=3"],
    );
    assert_eq!(incremented.trim(), "U64(3)");

    let endpoint_path = find_endpoint(data.path()).unwrap();
    let service_data_dir = endpoint_path.parent().unwrap().to_path_buf();
    let endpoint_body = fs::read_to_string(&endpoint_path).unwrap();
    let endpoint: toml::Value = toml::from_str(&endpoint_body).unwrap();
    let prefix = endpoint["prefix"].as_integer().unwrap() as u16;
    let raw_route = format!(
        "0x{:08x}",
        vos::registry::instance_service_id("counter", prefix),
    );
    let raw_value = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, &raw_route, "value"],
    );
    assert_eq!(raw_value.trim(), "U64(3)");

    let described = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "counter", "describe"],
    );
    assert!(
        described.contains("counter"),
        "reserved host describe must bypass package method lookup: {described}",
    );

    let upgrade_source = upgrade_package.to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &["space", "publish", space, "counter:0.2.0", &upgrade_source],
    );
    let refused_upgrade = vosx(
        data.path(),
        config.path(),
        &["space", "upgrade", space, "counter", "counter:0.2.0"],
    );
    assert!(!refused_upgrade.status.success());
    assert!(
        String::from_utf8_lossy(&refused_upgrade.stderr).contains("guest-owned UpgradeActor"),
        "v2 catalog upgrade must fail before mutating the registry: {}",
        String::from_utf8_lossy(&refused_upgrade.stderr),
    );

    drop(first);
    let restart_at = std::time::SystemTime::now();
    let second_log = data.path().join("v2-root-second.stderr");
    let second = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &second_log,
        Some(&service_pvm),
    ));
    poll_until(
        20,
        || {
            find_endpoint(data.path())
                .and_then(|path| fs::metadata(path).ok())
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified >= restart_at)
        },
        || {
            format!(
                "the daemon did not reopen the v2 root service; log:\n{}",
                fs::read_to_string(&second_log).unwrap_or_default(),
            )
        },
    );
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(3)"
        },
        || {
            format!(
                "the reopened v2 service did not retain its committed state; log:\n{}",
                fs::read_to_string(&second_log).unwrap_or_default(),
            )
        },
    );

    let old_image = fs::read_dir(service_data_dir.join("v2-services"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "image")
        })
        .expect("the first installation must own a durable v2 image");

    vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "counter", "stop"],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &["space", "uninstall", space, "counter"],
    );
    let fresh_replication_id = "22".repeat(32);
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "counter:0.1.0",
            "--consistency",
            "local",
            "--replication-id",
            &fresh_replication_id,
        ],
    );

    drop(second);
    let reinstall_at = std::time::SystemTime::now();
    let third_log = data.path().join("v2-root-third.stderr");
    let _third = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &third_log,
        Some(&service_pvm),
    ));
    poll_until(
        20,
        || {
            find_endpoint(data.path())
                .and_then(|path| fs::metadata(path).ok())
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified >= reinstall_at)
        },
        || {
            format!(
                "the daemon did not open the reinstalled v2 root; log:\n{}",
                fs::read_to_string(&third_log).unwrap_or_default(),
            )
        },
    );
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the fresh installation inherited old state or failed to start; log:\n{}",
                fs::read_to_string(&third_log).unwrap_or_default(),
            )
        },
    );
    assert!(!old_image.exists(), "deleted installation remained active");
    assert!(
        service_data_dir
            .join("trash")
            .join("v2-services")
            .join(old_image.file_name().unwrap())
            .is_file(),
        "deleted installation image was not moved to recoverable trash",
    );
}

#[test]
fn signed_v2_roots_run_under_production_trust_and_recover() {
    let mut malformed_observations = TestProductionTrustObservations::default();
    assert_eq!(
        TestProductionTrustSidecar::classify(
            TestProductionTrustSidecar::QUERY_POLICY,
            b"unexpected",
            &mut malformed_observations,
        ),
        TestProductionTrustSidecar::DENIED,
    );
    assert_eq!(
        TestProductionTrustSidecar::classify(
            TestProductionTrustSidecar::VERIFY_INSTALL,
            b"not a canonical genesis",
            &mut malformed_observations,
        ),
        TestProductionTrustSidecar::DENIED,
    );
    assert_eq!(
        TestProductionTrustSidecar::classify(0xff, &[], &mut malformed_observations),
        TestProductionTrustSidecar::DENIED,
    );
    assert!(
        malformed_observations.tags.is_empty() && malformed_observations.installs.is_empty(),
        "denied authority requests must not be recorded as valid observations",
    );

    let space = "v2-production";
    let data = TempDir::new("v2-production-data");
    let config = TempDir::new("v2-production-config");
    let dist = TempDir::new("v2-production-dist");
    let crdt_dist = TempDir::new("v2-production-crdt-dist");
    let sidecar_dir = TempDir::new("v2-production-sidecar");
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );
    let package = counter_package_fixture(dist.path());
    let crdt_package = crdt_counter_package_fixture(crdt_dist.path());

    vosx_ok(data.path(), config.path(), &["space", "new", space]);

    // Selecting production mode is fail-closed before the endpoint is
    // published: the daemon cannot silently fall back to conformance when the
    // configured authority is absent.
    let trust_socket = sidecar_dir.path().join("authority.sock");
    let unavailable_log = data.path().join("v2-production-unavailable.stderr");
    let mut unavailable = spawn_up_with_service_and_trust(
        data.path(),
        config.path(),
        space,
        &unavailable_log,
        Some(&service_pvm),
        Some(&trust_socket),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let unavailable_status = loop {
        if let Some(status) = unavailable.try_wait().expect("poll rejected daemon") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = unavailable.kill();
            let _ = unavailable.wait();
            panic!(
                "daemon did not fail closed while its production authority was absent; log:\n{}",
                fs::read_to_string(&unavailable_log).unwrap_or_default(),
            );
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert!(!unavailable_status.success());
    assert!(
        find_endpoint(data.path()).is_none(),
        "an unavailable production authority must fail before route publication",
    );

    let policy = vos::v2::Hash([0x67; 32]);
    let sidecar = TestProductionTrustSidecar::start(trust_socket.clone(), policy);
    let first_log = data.path().join("v2-production-first.stderr");
    let first = Daemon(spawn_up_with_service_and_trust(
        data.path(),
        config.path(),
        space,
        &first_log,
        Some(&service_pvm),
        Some(&trust_socket),
    ));
    let endpoint = wait_for_endpoint(data.path(), &first_log, "v2-production-first");

    let package_source = package.to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "publish",
            space,
            "onboarding-counter:0.1.0",
            &package_source,
        ],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "onboarding-counter:0.1.0",
            "--name",
            "production-counter",
            "--consistency",
            "local",
        ],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "onboarding-counter:0.1.0",
            "--name",
            "production-raft-counter",
            "--consistency",
            "raft",
        ],
    );
    let crdt_package_source = crdt_package.to_string_lossy().into_owned();
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "publish",
            space,
            "production-crdt-counter:0.1.0",
            &crdt_package_source,
        ],
    );
    vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "install",
            space,
            "production-crdt-counter:0.1.0",
            "--name",
            "production-crdt-counter",
            "--consistency",
            "crdt",
        ],
    );
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "production-counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the production daemon never attached the signed root; log:\n{}",
                fs::read_to_string(&first_log).unwrap_or_default(),
            )
        },
    );
    let incremented = vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "call",
            space,
            "production-counter",
            "increment",
            "by=7",
        ],
    );
    assert_eq!(incremented.trim(), "U64(7)");
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "production-raft-counter", "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the production daemon never attached the Raft root; log:\n{}",
                fs::read_to_string(&first_log).unwrap_or_default(),
            )
        },
    );
    let raft_incremented = vosx_ok(
        data.path(),
        config.path(),
        &[
            "space",
            "call",
            space,
            "production-raft-counter",
            "increment",
            "by=11",
        ],
    );
    assert_eq!(raft_incremented.trim(), "U64(11)");
    poll_until(
        30,
        || {
            let output = vosx(
                data.path(),
                config.path(),
                &["space", "call", space, "production-crdt-counter", "get"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "the production daemon never attached the CRDT root; log:\n{}",
                fs::read_to_string(&first_log).unwrap_or_default(),
            )
        },
    );
    let crdt_incremented = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "production-crdt-counter", "inc"],
    );
    assert_eq!(crdt_incremented.trim(), "()");
    let crdt_value = vosx_ok(
        data.path(),
        config.path(),
        &["space", "call", space, "production-crdt-counter", "get"],
    );
    assert_eq!(crdt_value.trim(), "U64(1)");
    assert!(sidecar.saw(TestProductionTrustSidecar::QUERY_POLICY));
    assert!(sidecar.saw(TestProductionTrustSidecar::CURRENT_TIMESLOT));
    assert!(sidecar.saw(TestProductionTrustSidecar::VERIFY_TIMESLOT));
    assert!(
        sidecar.saw_install_for("production-counter", vos::v2::ConsistencyModeV2::Local,),
        "the independent authority did not decode and authorize the production-counter Install",
    );
    assert!(
        sidecar.saw_install_for("production-raft-counter", vos::v2::ConsistencyModeV2::Raft,),
        "the independent authority did not decode and authorize the Raft Install",
    );
    assert!(
        sidecar.saw_install_for("production-crdt-counter", vos::v2::ConsistencyModeV2::Crdt,),
        "the independent authority did not decode and authorize the CRDT Install",
    );
    let raft_service_id = spawned_v2_root_id(&first_log, "production-raft-counter")
        .expect("the production Raft counter spawn log must expose its concrete service id");

    // A production-sealed image cannot be reopened by omitting the authority.
    // The daemon itself remains available for legacy/control-plane traffic,
    // while the v2 route stays fail-closed.
    drop(first);
    let _ = fs::remove_file(&endpoint);
    let conformance_log = data.path().join("v2-production-no-authority.stderr");
    let conformance = Daemon(spawn_up_with_service(
        data.path(),
        config.path(),
        space,
        &conformance_log,
        Some(&service_pvm),
    ));
    wait_for_endpoint(data.path(), &conformance_log, "v2-production-no-authority");
    poll_until(
        40,
        || {
            let log = fs::read_to_string(&conformance_log).unwrap_or_default();
            let local_and_crdt_refused = ["production-counter", "production-crdt-counter"]
                .into_iter()
                .all(|name| {
                    log.lines().any(|line| {
                        line.contains(&format!("agent '{name}' v2 route failed to register"))
                            && line.contains("ProductionTrust(TrustRequired)")
                    })
                });
            let raft_private = log.lines().any(|line| {
                line.contains("persisted v2 Raft voter is retrying service open/replay")
                    && line.contains(&format!("id={raft_service_id}"))
            });
            local_and_crdt_refused && raft_private
        },
        || {
            format!(
                "the sealed root was not visibly refused without its authority; log:\n{}",
                fs::read_to_string(&conformance_log).unwrap_or_default(),
            )
        },
    );
    let refused = vosx(
        data.path(),
        config.path(),
        &[
            "space",
            "call",
            space,
            "production-counter",
            "increment",
            "by=100",
        ],
    );
    assert!(
        !refused.status.success(),
        "a call to the specifically refused production-counter route unexpectedly succeeded: {}",
        String::from_utf8_lossy(&refused.stdout),
    );
    for (name, method) in [
        ("production-raft-counter", "value"),
        ("production-crdt-counter", "get"),
    ] {
        let refused = vosx(
            data.path(),
            config.path(),
            &["space", "call", space, name, method],
        );
        assert!(
            !refused.status.success(),
            "a call to the specifically refused {name} route unexpectedly succeeded: {}",
            String::from_utf8_lossy(&refused.stdout),
        );
    }
    assert!(
        !fs::read_to_string(&conformance_log)
            .unwrap_or_default()
            .contains("v2 root tree 'production-counter' spawned"),
        "a production image must never attach through the conformance profile",
    );

    // Restoring the exact policy reattaches the durable route and recovers the
    // already committed state rather than reinstalling a fresh service.
    drop(conformance);
    if let Some(endpoint) = find_endpoint(data.path()) {
        let _ = fs::remove_file(endpoint);
    }
    let recovery_log = data.path().join("v2-production-recovery.stderr");
    let _recovered = Daemon(spawn_up_with_service_and_trust(
        data.path(),
        config.path(),
        space,
        &recovery_log,
        Some(&service_pvm),
        Some(&trust_socket),
    ));
    wait_for_endpoint(data.path(), &recovery_log, "v2-production-recovery");
    poll_until(
        40,
        || {
            [
                ("production-counter", "value", "U64(7)"),
                ("production-raft-counter", "value", "U64(11)"),
                ("production-crdt-counter", "get", "U64(1)"),
            ]
            .into_iter()
            .all(|(name, method, expected)| {
                let output = vosx(
                    data.path(),
                    config.path(),
                    &["space", "call", space, name, method],
                );
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim() == expected
            })
        },
        || {
            format!(
                "the original production policy did not recover the pre-refusal committed state; log:\n{}",
                fs::read_to_string(&recovery_log).unwrap_or_default(),
            )
        },
    );
}

#[test]
fn production_crdt_root_converges_across_enrolled_daemons_and_restart() {
    let space = "v2-production-crdt-network";
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );

    let data_a = TempDir::new("production-crdt-a-data");
    let config_a = TempDir::new("production-crdt-a-config");
    let data_b = TempDir::new("production-crdt-b-data");
    let config_b = TempDir::new("production-crdt-b-config");
    let dist = TempDir::new("production-crdt-network-dist");
    let sidecar_dir = TempDir::new("production-crdt-sidecars");
    assert_bundled_space_authority_matches_fresh_build(dist.path());
    let package = crdt_counter_package_fixture(dist.path());
    let policy = vos::v2::Hash([0x69; 32]);
    let trust_a_path = sidecar_dir.path().join("authority-a.sock");
    let trust_b_path = sidecar_dir.path().join("authority-b.sock");
    let trust_a = TestProductionTrustSidecar::start(trust_a_path.clone(), policy);
    let trust_b = TestProductionTrustSidecar::start(trust_b_path.clone(), policy);

    vosx_ok(data_a.path(), config_a.path(), &["space", "new", space]);
    let log_a = data_a.path().join("production-crdt-a.stderr");
    let daemon_a = Daemon(spawn_up_with_service_and_trust(
        data_a.path(),
        config_a.path(),
        space,
        &log_a,
        Some(&service_pvm),
        Some(&trust_a_path),
    ));
    wait_for_endpoint(data_a.path(), &log_a, "production CRDT A");

    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space",
            "publish",
            space,
            "production-crdt-counter:0.1.0",
            package.to_str().expect("package path is UTF-8"),
        ],
    );
    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space",
            "install",
            space,
            "production-crdt-counter:0.1.0",
            "--name",
            "production-crdt-counter",
            "--consistency",
            "crdt",
            "--sync",
            "member",
        ],
    );
    poll_until(
        40,
        || {
            let output = vosx(
                data_a.path(),
                config_a.path(),
                &["space", "call", space, "production-crdt-counter", "get"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "production CRDT root did not attach on A; log:\n{}",
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );

    let invite = vosx_ok(
        data_a.path(),
        config_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = invite
        .lines()
        .next()
        .expect("invite prints the token first")
        .trim()
        .to_owned();
    let log_b = data_b.path().join("production-crdt-b.stderr");
    let daemon_b = Daemon(spawn_up_with_service_and_trust(
        data_b.path(),
        config_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
        Some(&trust_b_path),
    ));
    let endpoint_b = wait_for_endpoint(data_b.path(), &log_b, "production CRDT B");
    let pending_invite = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join(".pending-invite.token");
    poll_until(
        60,
        || !pending_invite.exists(),
        || {
            format!(
                "B did not complete canonical production onboarding; B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );
    let peer_b = daemon_peer_id(&log_b).expect("B's startup log names its authenticated PeerId");
    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space", "members", space, "add-node", &peer_b, "--role", "observer",
        ],
    );
    poll_until(
        60,
        || {
            let output = vosx(
                data_b.path(),
                config_b.path(),
                &["space", "call", space, "production-crdt-counter", "get"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(0)"
        },
        || {
            format!(
                "B did not install and expose the production CRDT root; log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
            )
        },
    );

    // Each successful readiness call commits an ingress change and its Apply
    // change. Wait until all four exact receipts have crossed the wire before
    // taking the mutation baseline; otherwise a later echo could masquerade
    // as `inc`.
    poll_until(
        60,
        || {
            combined_receipt_digests_for(
                &trust_a,
                &trust_b,
                "production-crdt-counter",
                vos::v2::ConsistencyModeV2::Crdt,
            )
            .len()
                >= 4
        },
        || "the initial A and B readiness receipts did not fully synchronize".to_owned(),
    );
    let receipts_before_a_mutation = combined_receipt_digests_for(
        &trust_a,
        &trust_b,
        "production-crdt-counter",
        vos::v2::ConsistencyModeV2::Crdt,
    );
    assert_eq!(
        receipts_before_a_mutation.len(),
        4,
        "only the two readiness invocations precede the A mutation baseline",
    );
    assert_eq!(
        vosx_ok(
            data_a.path(),
            config_a.path(),
            &["space", "call", space, "production-crdt-counter", "inc"],
        )
        .trim(),
        "()",
    );
    poll_until(
        60,
        || {
            trust_b
                .new_receipt_digests_since(
                    "production-crdt-counter",
                    vos::v2::ConsistencyModeV2::Crdt,
                    &receipts_before_a_mutation,
                )
                .len()
                >= 2
        },
        || "B did not independently verify a new receipt for A's counter mutation".to_owned(),
    );
    let receipts_before_b_state_reads = combined_receipt_digests_for(
        &trust_a,
        &trust_b,
        "production-crdt-counter",
        vos::v2::ConsistencyModeV2::Crdt,
    );
    let mut successful_b_state_reads = 0_usize;
    poll_until(
        60,
        || {
            let output = vosx(
                data_b.path(),
                config_b.path(),
                &["space", "call", space, "production-crdt-counter", "get"],
            );
            if output.status.success() {
                successful_b_state_reads += 1;
            }
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(1)"
        },
        || {
            format!(
                "A's production CRDT mutation did not converge on B; B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );
    assert!(
        successful_b_state_reads > 0,
        "observing the converged state performs at least one B-side read",
    );
    let a_mutation_receipts = trust_b.new_receipt_digests_since(
        "production-crdt-counter",
        vos::v2::ConsistencyModeV2::Crdt,
        &receipts_before_a_mutation,
    );
    assert_eq!(
        a_mutation_receipts.len(),
        2,
        "A's inc contributes exactly its admitted-ingress and Apply receipts",
    );
    // Quiescence above rules out concurrent unaccounted branches. Within the
    // one invocation, Apply causally follows admission, so its higher sequence
    // identifies the exact mutation receipt without relying on a global CRDT
    // height tie-break.
    let a_mutation_receipt = trust_b
        .newest_receipt_digest_since(
            "production-crdt-counter",
            vos::v2::ConsistencyModeV2::Crdt,
            &receipts_before_a_mutation,
        )
        .expect("B retained A's exact newly verified mutation receipt");
    let expected_b_state_receipts = successful_b_state_reads
        .checked_mul(2)
        .expect("state-read receipt count is bounded by the poll deadline");
    poll_until(
        60,
        || {
            trust_a
                .new_receipt_digests_since(
                    "production-crdt-counter",
                    vos::v2::ConsistencyModeV2::Crdt,
                    &receipts_before_b_state_reads,
                )
                .len()
                >= expected_b_state_receipts
        },
        || "A did not account for every B-side state read before the next baseline".to_owned(),
    );
    assert_eq!(
        trust_a
            .new_receipt_digests_since(
                "production-crdt-counter",
                vos::v2::ConsistencyModeV2::Crdt,
                &receipts_before_b_state_reads,
            )
            .len(),
        expected_b_state_receipts,
        "only the counted B-side state reads occur between mutation baselines",
    );
    let receipts_before_b_mutation = combined_receipt_digests_for(
        &trust_a,
        &trust_b,
        "production-crdt-counter",
        vos::v2::ConsistencyModeV2::Crdt,
    );
    assert_eq!(
        vosx_ok(
            data_b.path(),
            config_b.path(),
            &["space", "call", space, "production-crdt-counter", "inc"],
        )
        .trim(),
        "()",
    );
    poll_until(
        60,
        || {
            trust_a
                .new_receipt_digests_since(
                    "production-crdt-counter",
                    vos::v2::ConsistencyModeV2::Crdt,
                    &receipts_before_b_mutation,
                )
                .len()
                >= 2
        },
        || "A did not independently verify a new receipt for B's counter mutation".to_owned(),
    );
    poll_until(
        60,
        || {
            let output = vosx(
                data_a.path(),
                config_a.path(),
                &["space", "call", space, "production-crdt-counter", "get"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(2)"
        },
        || {
            format!(
                "B's production CRDT mutation did not converge on A; B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );
    assert_eq!(
        trust_a
            .new_receipt_digests_since(
                "production-crdt-counter",
                vos::v2::ConsistencyModeV2::Crdt,
                &receipts_before_b_mutation,
            )
            .len(),
        2,
        "B's inc contributes exactly its admitted-ingress and Apply receipts",
    );
    let b_mutation_receipt = trust_a
        .newest_receipt_digest_since(
            "production-crdt-counter",
            vos::v2::ConsistencyModeV2::Crdt,
            &receipts_before_b_mutation,
        )
        .expect("A retained B's exact newly verified mutation receipt");
    assert_ne!(
        a_mutation_receipt, b_mutation_receipt,
        "the two independently verified mutations must have distinct receipt digests",
    );
    drop(daemon_a);
    drop(daemon_b);
    let _ = fs::remove_file(&endpoint_b);
    let restart_at = std::time::SystemTime::now();
    let restart_log_b = data_b.path().join("production-crdt-b-restart.stderr");
    let _restarted_b = Daemon(spawn_up_with_service_and_trust(
        data_b.path(),
        config_b.path(),
        space,
        &restart_log_b,
        Some(&service_pvm),
        Some(&trust_b_path),
    ));
    poll_until(
        30,
        || {
            find_endpoint(data_b.path())
                .and_then(|path| fs::metadata(path).ok())
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified >= restart_at)
        },
        || {
            format!(
                "B did not republish its endpoint after restart; log:\n{}",
                fs::read_to_string(&restart_log_b).unwrap_or_default(),
            )
        },
    );
    poll_until(
        60,
        || {
            let output = vosx(
                data_b.path(),
                config_b.path(),
                &["space", "call", space, "production-crdt-counter", "get"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(2)"
        },
        || {
            format!(
                "B did not recover the converged production CRDT state; log:\n{}",
                fs::read_to_string(&restart_log_b).unwrap_or_default(),
            )
        },
    );
}

#[test]
fn production_raft_root_survives_voter_join_leader_loss_and_catch_up() {
    let space = "v2-production-raft-network";
    let root = "production-raft-cluster-counter";
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let service_pvm = workspace.join("services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );

    let data_a = TempDir::new("production-raft-a-data");
    let config_a = TempDir::new("production-raft-a-config");
    let data_b = TempDir::new("production-raft-b-data");
    let config_b = TempDir::new("production-raft-b-config");
    let data_c = TempDir::new("production-raft-c-data");
    let config_c = TempDir::new("production-raft-c-config");
    let dist = TempDir::new("production-raft-network-dist");
    let sidecar_dir = TempDir::new("production-raft-sidecars");
    let package = counter_package_fixture(dist.path());
    let policy = vos::v2::Hash([0x70; 32]);
    let trust_a_path = sidecar_dir.path().join("authority-a.sock");
    let trust_b_path = sidecar_dir.path().join("authority-b.sock");
    let trust_c_path = sidecar_dir.path().join("authority-c.sock");
    let trust_a = TestProductionTrustSidecar::start(trust_a_path.clone(), policy);
    let trust_b = TestProductionTrustSidecar::start(trust_b_path.clone(), policy);
    let trust_c = TestProductionTrustSidecar::start(trust_c_path.clone(), policy);

    vosx_ok(data_a.path(), config_a.path(), &["space", "new", space]);
    let log_a = data_a.path().join("production-raft-a.stderr");
    let mut daemon_a = Some(Daemon(spawn_up_with_service_and_trust(
        data_a.path(),
        config_a.path(),
        space,
        &log_a,
        Some(&service_pvm),
        Some(&trust_a_path),
    )));
    let endpoint_a = wait_for_endpoint(data_a.path(), &log_a, "production Raft A");
    let prefix_a = endpoint_prefix(&endpoint_a);

    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space",
            "publish",
            space,
            "onboarding-counter:0.1.0",
            package.to_str().expect("package path is UTF-8"),
        ],
    );
    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space",
            "install",
            space,
            "onboarding-counter:0.1.0",
            "--name",
            root,
            "--consistency",
            "raft",
            "--sync",
            "member",
        ],
    );
    poll_until(
        40,
        || {
            production_raft_status(data_a.path(), config_a.path(), space, root)
                .is_some_and(|status| status.present && status.role == "leader")
        },
        || {
            format!(
                "the initial production Raft root did not elect on A; log:\n{}",
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );

    let invite_b = vosx_ok(
        data_a.path(),
        config_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token_b = invite_b
        .lines()
        .next()
        .expect("B invite prints its token first")
        .trim()
        .to_owned();
    let log_b = data_b.path().join("production-raft-b.stderr");
    let mut daemon_b = Some(Daemon(spawn_up_with_service_and_trust(
        data_b.path(),
        config_b.path(),
        &token_b,
        &log_b,
        Some(&service_pvm),
        Some(&trust_b_path),
    )));
    let endpoint_b = wait_for_endpoint(data_b.path(), &log_b, "production Raft B");
    let prefix_b = endpoint_prefix(&endpoint_b);
    let pending_b = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join(".pending-invite.token");
    poll_until(
        60,
        || !pending_b.exists(),
        || {
            format!(
                "B did not complete production onboarding; B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );
    let peer_b = daemon_peer_id(&log_b).expect("B startup names its authenticated PeerId");
    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space", "members", space, "add-node", &peer_b, "--role", "voter",
        ],
    );
    poll_until(
        90,
        || {
            production_raft_status(data_b.path(), config_b.path(), space, root).is_some_and(
                |status| {
                    status.present
                        && status.members.len() == 2
                        && status.members.contains(&prefix_a)
                        && status.members.contains(&prefix_b)
                        && status.joint_old.is_none()
                        && status
                            .active_config_index
                            .is_some_and(|index| index <= status.commit_index)
                },
            )
        },
        || {
            format!(
                "B did not join the production Raft group; B log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );

    let invite_c = vosx_ok(
        data_a.path(),
        config_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token_c = invite_c
        .lines()
        .next()
        .expect("C invite prints its token first")
        .trim()
        .to_owned();
    let log_c = data_c.path().join("production-raft-c.stderr");
    let mut daemon_c = Some(Daemon(spawn_up_with_service_and_trust(
        data_c.path(),
        config_c.path(),
        &token_c,
        &log_c,
        Some(&service_pvm),
        Some(&trust_c_path),
    )));
    let endpoint_c = wait_for_endpoint(data_c.path(), &log_c, "production Raft C");
    let prefix_c = endpoint_prefix(&endpoint_c);
    let pending_c = endpoint_c
        .parent()
        .expect("C endpoint has a space directory")
        .join(".pending-invite.token");
    poll_until(
        60,
        || !pending_c.exists(),
        || {
            format!(
                "C did not complete production onboarding; C log:\n{}\nA log:\n{}",
                fs::read_to_string(&log_c).unwrap_or_default(),
                fs::read_to_string(&log_a).unwrap_or_default(),
            )
        },
    );
    let peer_c = daemon_peer_id(&log_c).expect("C startup names its authenticated PeerId");
    // Membership carries authenticated voter identities, not dial addresses.
    // The test disables mDNS, so establish the B<->C path explicitly after
    // canonical invite redemption and before promoting C. Restarting B here
    // also proves an already-committed production voter can reopen privately
    // before its route returns.
    drop(daemon_b.take());
    let _ = fs::remove_file(&endpoint_b);
    let c_connect = endpoint_connect_addr(&endpoint_c);
    daemon_b = Some(Daemon(spawn_up_with_service_trust_and_connects(
        data_b.path(),
        config_b.path(),
        space,
        &log_b,
        Some(&service_pvm),
        Some(&trust_b_path),
        &[&c_connect],
    )));
    let restarted_endpoint_b = wait_for_endpoint(
        data_b.path(),
        &log_b,
        "production Raft B after mesh attachment",
    );
    assert_eq!(
        endpoint_prefix(&restarted_endpoint_b),
        prefix_b,
        "restarting a committed voter preserves its authenticated prefix",
    );
    vosx_ok(
        data_a.path(),
        config_a.path(),
        &[
            "space", "members", space, "add-node", &peer_c, "--role", "voter",
        ],
    );

    let expected_members = {
        let mut members = vec![prefix_a, prefix_b, prefix_c];
        members.sort_unstable();
        members
    };
    poll_until(
        120,
        || {
            [
                production_raft_status(data_a.path(), config_a.path(), space, root),
                production_raft_status(data_b.path(), config_b.path(), space, root),
                production_raft_status(data_c.path(), config_c.path(), space, root),
            ]
            .into_iter()
            .all(|status| {
                status.is_some_and(|mut status| {
                    status.members.sort_unstable();
                    status.present
                        && status.leader.is_some()
                        && status.members == expected_members
                        && status.joint_old.is_none()
                        && status
                            .active_config_index
                            .is_some_and(|index| index <= status.commit_index)
                })
            })
        },
        || {
            format!(
                "the three-voter production Raft group did not become steady; \
                 A log:\n{}\nB log:\n{}\nC log:\n{}",
                fs::read_to_string(&log_a).unwrap_or_default(),
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_c).unwrap_or_default(),
            )
        },
    );
    // A log-replaying joiner re-runs Install verification, while a snapshot
    // joiner authenticates the snapshot's sealed provenance under the exact
    // production policy. Either path must consult that voter's authority.
    assert!(
        trust_b.saw(TestProductionTrustSidecar::QUERY_POLICY),
        "B did not authenticate the production policy",
    );
    assert!(
        trust_c.saw(TestProductionTrustSidecar::QUERY_POLICY),
        "C did not authenticate the production policy",
    );

    let status_a = production_raft_status(data_a.path(), config_a.path(), space, root)
        .expect("A reports the steady Raft group");
    let status_b = production_raft_status(data_b.path(), config_b.path(), space, root)
        .expect("B reports the steady Raft group");
    let status_c = production_raft_status(data_c.path(), config_c.path(), space, root)
        .expect("C reports the steady Raft group");
    assert_eq!(status_a.daemon_prefix, prefix_a);
    assert_eq!(status_b.daemon_prefix, prefix_b);
    assert_eq!(status_c.daemon_prefix, prefix_c);
    assert_eq!(status_a.leader, status_b.leader);
    assert_eq!(status_a.leader, status_c.leader);
    let original_leader = status_a.leader.expect("the steady group has a leader");
    let first_follower = [prefix_a, prefix_b, prefix_c]
        .into_iter()
        .find(|prefix| *prefix != original_leader)
        .expect("a three-voter group has a follower");
    let slot_baselines = [
        trust_a.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT),
        trust_b.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT),
        trust_c.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT),
    ];

    let try_call_on = |prefix: u16, args: &[&str]| -> Result<String, String> {
        let output = if prefix == prefix_a {
            vosx(data_a.path(), config_a.path(), args)
        } else if prefix == prefix_b {
            vosx(data_b.path(), config_b.path(), args)
        } else if prefix == prefix_c {
            vosx(data_c.path(), config_c.path(), args)
        } else {
            return Err(format!("unknown test daemon prefix {prefix:#06x}"));
        };
        if !output.status.success() {
            return Err(format!(
                "`vosx {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    };
    let call_on = |prefix: u16, args: &[&str]| -> String {
        try_call_on(prefix, args).unwrap_or_else(|error| panic!("{error}"))
    };
    assert_eq!(
        call_on(
            first_follower,
            &["space", "call", space, root, "increment", "by=5",],
        )
        .trim(),
        "U64(5)",
        "the typed client must follow the production follower redirect",
    );
    poll_until(
        60,
        || {
            [prefix_a, prefix_b, prefix_c].into_iter().all(|prefix| {
                try_call_on(prefix, &["space", "call", space, root, "value"])
                    .is_ok_and(|value| value.trim() == "U64(5)")
            })
        },
        || "the initial follower-routed mutation did not reach every voter".to_owned(),
    );
    assert!(
        trust_a.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT) > slot_baselines[0]
            && trust_b.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT) > slot_baselines[1]
            && trust_c.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT) > slot_baselines[2],
        "the target mutation must cause fresh historical-slot verification on every voter",
    );

    if original_leader == prefix_a {
        drop(daemon_a.take());
    } else if original_leader == prefix_b {
        drop(daemon_b.take());
    } else if original_leader == prefix_c {
        drop(daemon_c.take());
    } else {
        panic!("the elected leader is not one of the enrolled voters");
    }
    let survivors: Vec<u16> = [prefix_a, prefix_b, prefix_c]
        .into_iter()
        .filter(|prefix| *prefix != original_leader)
        .collect();
    poll_until(
        90,
        || {
            let statuses: Vec<TestRaftStatus> = survivors
                .iter()
                .filter_map(|prefix| {
                    if *prefix == prefix_a {
                        production_raft_status(data_a.path(), config_a.path(), space, root)
                    } else if *prefix == prefix_b {
                        production_raft_status(data_b.path(), config_b.path(), space, root)
                    } else {
                        production_raft_status(data_c.path(), config_c.path(), space, root)
                    }
                })
                .collect();
            statuses.len() == 2
                && statuses.iter().all(|status| status.present)
                && statuses[0].leader.is_some()
                && statuses[0].leader == statuses[1].leader
                && statuses[0].leader != Some(original_leader)
        },
        || {
            format!(
                "the surviving production voters did not elect after leader loss; \
                 A log:\n{}\nB log:\n{}\nC log:\n{}",
                fs::read_to_string(&log_a).unwrap_or_default(),
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_c).unwrap_or_default(),
            )
        },
    );
    let failover_status = if survivors[0] == prefix_a {
        production_raft_status(data_a.path(), config_a.path(), space, root)
    } else if survivors[0] == prefix_b {
        production_raft_status(data_b.path(), config_b.path(), space, root)
    } else {
        production_raft_status(data_c.path(), config_c.path(), space, root)
    }
    .expect("a surviving voter reports the replacement leader");
    let replacement_leader = failover_status
        .leader
        .expect("the surviving quorum elected a replacement leader");
    let failover_follower = survivors
        .iter()
        .copied()
        .find(|prefix| *prefix != replacement_leader)
        .expect("the surviving quorum includes a follower");
    assert_eq!(
        call_on(
            failover_follower,
            &["space", "call", space, root, "increment", "by=7",],
        )
        .trim(),
        "U64(12)",
        "a follower redirect must survive production leadership transfer",
    );
    poll_until(
        60,
        || {
            survivors.iter().all(|prefix| {
                try_call_on(*prefix, &["space", "call", space, root, "value"])
                    .is_ok_and(|value| value.trim() == "U64(12)")
            })
        },
        || "the post-failover mutation did not reach the surviving quorum".to_owned(),
    );
    let committed_after_failover = survivors
        .iter()
        .filter_map(|prefix| {
            if *prefix == prefix_a {
                production_raft_status(data_a.path(), config_a.path(), space, root)
            } else if *prefix == prefix_b {
                production_raft_status(data_b.path(), config_b.path(), space, root)
            } else {
                production_raft_status(data_c.path(), config_c.path(), space, root)
            }
        })
        .map(|status| status.commit_index)
        .max()
        .expect("the surviving quorum reports a commit index");

    let (retired_data, retired_config, retired_trust, retired_log) = if original_leader == prefix_a
    {
        (data_a.path(), config_a.path(), &trust_a_path, &log_a)
    } else if original_leader == prefix_b {
        (data_b.path(), config_b.path(), &trust_b_path, &log_b)
    } else {
        (data_c.path(), config_c.path(), &trust_c_path, &log_c)
    };
    let retired_slot_baseline = if original_leader == prefix_a {
        trust_a.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT)
    } else if original_leader == prefix_b {
        trust_b.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT)
    } else {
        trust_c.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT)
    };
    if let Some(endpoint) = find_endpoint(retired_data) {
        let _ = fs::remove_file(endpoint);
    }
    // Discovery is deliberately disabled in this gate, so restore the retired
    // voter with explicit addresses for both live peers. That lets it catch up
    // from either voter and follow the current leader without smuggling an
    // automatic-discovery assumption into the Raft recovery assertion.
    let recovery_connects = survivors
        .iter()
        .map(|prefix| {
            if *prefix == prefix_a {
                endpoint_connect_addr(&endpoint_a)
            } else if *prefix == prefix_b {
                endpoint_connect_addr(&endpoint_b)
            } else {
                endpoint_connect_addr(&endpoint_c)
            }
        })
        .collect::<Vec<_>>();
    let recovery_connect_refs = recovery_connects
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let restart_log = retired_data.join("production-raft-restarted-leader.stderr");
    let restarted_old_leader = Daemon(spawn_up_with_service_trust_and_connects(
        retired_data,
        retired_config,
        space,
        &restart_log,
        Some(&service_pvm),
        Some(retired_trust),
        &recovery_connect_refs,
    ));
    wait_for_endpoint(
        retired_data,
        &restart_log,
        "restarted production Raft voter",
    );
    poll_until(
        90,
        || {
            production_raft_status(retired_data, retired_config, space, root).is_some_and(
                |status| {
                    status.present
                        && status.members.len() == 3
                        && status.commit_index >= committed_after_failover
                        && status.last_applied >= committed_after_failover
                },
            )
        },
        || {
            format!(
                "the restarted voter did not catch up through its production policy; \
                 restart log:\n{}\nold log:\n{}",
                fs::read_to_string(&restart_log).unwrap_or_default(),
                fs::read_to_string(retired_log).unwrap_or_default(),
            )
        },
    );
    poll_until(
        90,
        || {
            let output = vosx(
                retired_data,
                retired_config,
                &["space", "call", space, root, "value"],
            );
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "U64(12)"
        },
        || {
            format!(
                "the restarted voter did not attach the caught-up root; restart log:\n{}",
                fs::read_to_string(&restart_log).unwrap_or_default(),
            )
        },
    );
    let retired_slot_count = if original_leader == prefix_a {
        trust_a.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT)
    } else if original_leader == prefix_b {
        trust_b.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT)
    } else {
        trust_c.tag_count(TestProductionTrustSidecar::VERIFY_TIMESLOT)
    };
    assert!(
        retired_slot_count > retired_slot_baseline,
        "the restarted voter must verify the target's post-failover slot history",
    );

    // Keep the restarted old leader and the other survivor alive, but remove
    // the replacement leader. A second election demonstrates that the caught-
    // up voter is an active quorum participant rather than a read-only route.
    if replacement_leader == prefix_a {
        drop(daemon_a.take());
    } else if replacement_leader == prefix_b {
        drop(daemon_b.take());
    } else if replacement_leader == prefix_c {
        drop(daemon_c.take());
    }
    let final_survivor = survivors
        .iter()
        .copied()
        .find(|prefix| *prefix != replacement_leader)
        .expect("one original follower remains beside the restarted voter");
    poll_until(
        90,
        || {
            production_raft_status(retired_data, retired_config, space, root)
                .and_then(|status| status.leader)
                .is_some_and(|leader| leader != replacement_leader)
        },
        || "the quorum including the restarted voter did not elect again".to_owned(),
    );
    assert_eq!(
        call_on(
            final_survivor,
            &["space", "call", space, root, "increment", "by=3",],
        )
        .trim(),
        "U64(15)",
        "the quorum containing the restarted voter must keep accepting work",
    );
    drop(restarted_old_leader);
}

/// Run a `vosx` command and assert it succeeded, returning stdout.
fn vosx_ok(data_home: &Path, config_home: &Path, args: &[&str]) -> String {
    let o = vosx(data_home, config_home, args);
    assert!(
        o.status.success(),
        "`vosx {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&o.stderr),
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Boot host A (new + up) with the canonical service guest. Returns
/// `(data_a, cfg_a, daemon_a, log_a)`.
fn boot_admin_with_service(
    space: &str,
    service_pvm: Option<&Path>,
) -> (TempDir, TempDir, Daemon, PathBuf) {
    let data_a = TempDir::new("a-data");
    let cfg_a = TempDir::new("a-config");
    vosx_ok(data_a.path(), cfg_a.path(), &["space", "new", space]);
    let log_a = data_a.path().join("daemon-a.stderr");
    let daemon_a = Daemon(spawn_up_with_service(
        data_a.path(),
        cfg_a.path(),
        space,
        &log_a,
        service_pvm,
    ));
    wait_for_endpoint(data_a.path(), &log_a, "A");
    let counter_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/v2/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter_v2.elf");
    assert!(
        counter_elf.is_file(),
        "build the onboarding CRDT fixture first: `just build-v2-registry-fixtures`",
    );
    let counter_source = counter_elf.to_string_lossy().into_owned();
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "publish",
            space,
            "crdt-counter:0.1.0",
            &counter_source,
        ],
    );
    vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "install",
            space,
            "crdt-counter:0.1.0",
            "--consistency",
            "crdt",
        ],
    );
    (data_a, cfg_a, daemon_a, log_a)
}

/// A tampered `vos1…` token fails the checksum at parse time, so `space
/// up` errors immediately (no daemon, no partial join).
#[test]
fn tampered_token_fails_parse() {
    let data = TempDir::new("tamper-data");
    let cfg = TempDir::new("tamper-config");
    // A syntactically-`vos1` string with a corrupt body.
    let o = vosx(
        data.path(),
        cfg.path(),
        &["space", "up", "vos1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"],
    );
    assert!(!o.status.success(), "a tampered token must be rejected");
    let err = String::from_utf8_lossy(&o.stderr).to_lowercase();
    assert!(
        err.contains("token") || err.contains("checksum") || err.contains("base58"),
        "error should name the bad token; got: {err}",
    );
}

/// An expired invite is not redeemed (honored on the joiner path), so
/// the joiner stays a non-member — and the Member-gated registry then
/// refuses its sync, so it never learns the catalog. One test, both
/// properties: `--expires` is real AND the Member floor excludes
/// non-members.
#[test]
fn expired_token_not_redeemed_and_non_member_cannot_sync() {
    let space = "exp";
    let service_pvm =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm");
    assert!(service_pvm.is_file(), "run `just build-vos-service`");
    let (data_a, cfg_a, _da, _la) = boot_admin_with_service(space, Some(&service_pvm));

    // Mint with a 1-second lifetime, then let it lapse before B boots.
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &[
            "space",
            "invite",
            space,
            "--role",
            "member",
            "--expires",
            "1",
        ],
    );
    let token = stdout.lines().next().unwrap().trim().to_string();
    thread::sleep(Duration::from_secs(2));

    let data_b = TempDir::new("exp-b-data");
    let cfg_b = TempDir::new("exp-b-config");
    let log_b = data_b.path().join("daemon-b.stderr");
    let _db = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
    ));
    wait_for_endpoint(data_b.path(), &log_b, "B");

    // The daemon recognizes the token as expired and refuses to redeem.
    poll_until(
        20,
        || {
            fs::read_to_string(&log_b)
                .unwrap_or_default()
                .contains("expired")
        },
        || {
            format!(
                "B never logged the token as expired; log:\n{}",
                fs::read_to_string(&log_b).unwrap_or_default()
            )
        },
    );

    // And because it never became a member, the Member-gated registry is
    // never served to it: give sync a generous window, then assert its
    // role list still lacks A's admin grant (it started empty).
    thread::sleep(Duration::from_secs(6));
    let roles = vosx_ok(
        data_b.path(),
        cfg_b.path(),
        &["space", "role", space, "list"],
    );
    assert!(
        !roles.contains("admin"),
        "a non-member must NOT sync the Member-gated registry; got role list:\n{roles}",
    );
}

/// A minted bearer has no registry row yet. Revoking by the exact token must
/// pre-create the grow-only cancellation in both authority stores; a later
/// join cannot redeem or cross the Member sync floor.
#[test]
fn unredeemed_token_can_be_revoked_before_join() {
    let space = "rev";
    let service_pvm =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm");
    assert!(service_pvm.is_file(), "run `just build-vos-service`");
    let (data_a, cfg_a, _da, log_a) = boot_admin_with_service(space, Some(&service_pvm));
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = stdout.lines().next().unwrap().trim().to_string();

    let revoked = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "revoke", &token],
    );
    assert!(
        revoked.contains("revoked invite"),
        "the exact offline token should be accepted: {revoked}",
    );
    let prefix = revoked
        .split_whitespace()
        .nth(2)
        .expect("revoke output contains token prefix")
        .trim_end_matches('…');
    let repeated = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "revoke", prefix],
    );
    assert!(
        repeated.contains("revoked invite"),
        "recorded-prefix revocation remains idempotent: {repeated}",
    );
    let invites = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "list"],
    );
    assert!(
        invites.contains("revoked"),
        "revocation must be durable before redemption:\n{invites}",
    );

    let data_b = TempDir::new("rev-b-data");
    let cfg_b = TempDir::new("rev-b-config");
    let log_b = data_b.path().join("daemon-b.stderr");
    let _db = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
    ));
    wait_for_endpoint(data_b.path(), &log_b, "B");

    // Give redemption and anti-entropy several passes. The revoked row must
    // win regardless of delivery order, leaving B below the Member floor.
    thread::sleep(Duration::from_secs(8));
    let roles = vosx_ok(
        data_b.path(),
        cfg_b.path(),
        &["space", "role", space, "list"],
    );
    assert!(
        !roles.contains("admin"),
        "a revoked invite must not grant Member sync access; got:\n{roles}\nB log:\n{}\nA log:\n{}",
        fs::read_to_string(&log_b).unwrap_or_default(),
        fs::read_to_string(&log_a).unwrap_or_default(),
    );
}

/// Partition honesty (decision 6): the same token redeemed at two
/// distinct nodes yields two grants, and `space members` flags the
/// double-redemption rather than pretending to have prevented it.
#[test]
fn double_redemption_is_flagged() {
    let space = "dbl";
    let service_pvm =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm");
    assert!(
        service_pvm.is_file(),
        "build the canonical service first: `just build-vos-service`",
    );
    let (data_a, cfg_a, _da, _la) = boot_admin_with_service(space, Some(&service_pvm));
    let stdout = vosx_ok(
        data_a.path(),
        cfg_a.path(),
        &["space", "invite", space, "--role", "member"],
    );
    let token = stdout.lines().next().unwrap().trim().to_string();

    // Two joiners redeem the SAME token (both dial A; they never connect
    // to each other — VOSX_DISABLE_MDNS and no cross --connect).
    let data_b = TempDir::new("dbl-b-data");
    let cfg_b = TempDir::new("dbl-b-config");
    let log_b = data_b.path().join("b.stderr");
    let _db = Daemon(spawn_up_with_service(
        data_b.path(),
        cfg_b.path(),
        &token,
        &log_b,
        Some(&service_pvm),
    ));
    let endpoint_b = wait_for_endpoint(data_b.path(), &log_b, "B");
    let pending_b = endpoint_b
        .parent()
        .expect("B endpoint has a space directory")
        .join(".pending-invite.token");

    let data_c = TempDir::new("dbl-c-data");
    let cfg_c = TempDir::new("dbl-c-config");
    let log_c = data_c.path().join("c.stderr");
    let _dc = Daemon(spawn_up_with_service(
        data_c.path(),
        cfg_c.path(),
        &token,
        &log_c,
        Some(&service_pvm),
    ));
    let endpoint_c = wait_for_endpoint(data_c.path(), &log_c, "C");
    let pending_c = endpoint_c
        .parent()
        .expect("C endpoint has a space directory")
        .join(".pending-invite.token");

    // A records BOTH redemptions on the one InviteRow → members flags it.
    poll_until(
        40,
        || {
            let m = vosx_ok(data_a.path(), cfg_a.path(), &["space", "members", space]);
            m.contains("double-redeemed")
        },
        || {
            format!(
                "A never flagged the double-redemption. members:\n{}\nB log:\n{}\nC log:\n{}",
                vosx_ok(data_a.path(), cfg_a.path(), &["space", "members", space]),
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_c).unwrap_or_default(),
            )
        },
    );

    // Registry acceptance is emitted only after the canonical authority PVM
    // accepts the exact evidence through physical guest Accumulate. The
    // daemon removes the bearer secret only after that combined operation
    // replies successfully.
    poll_until(
        30,
        || !pending_b.exists() && !pending_c.exists(),
        || {
            format!(
                "one or both joiners never committed invite redemption to space-authority \
                 (pending B={}, C={}). B log:\n{}\nC log:\n{}",
                pending_b.exists(),
                pending_c.exists(),
                fs::read_to_string(&log_b).unwrap_or_default(),
                fs::read_to_string(&log_c).unwrap_or_default(),
            )
        },
    );
}
