// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's process killed (SIGKILL) during a proof and during a
//! sync, as Android kills `:vos` without notice: the enrollments it leaves
//! are the ones it had, byte for byte, the background job's runs read
//! whole (a run cut short never finished), and the next process opens
//! them, syncs and proves. The facility runs in a child (this test binary again, its role
//! in the environment), against a stand-in gateway in this process; each
//! scenario kills it at drawn delays after it says it is proving or
//! syncing, five times.
//!
//! A client that goes away during an operation costs the facility only
//! that operation: what it asks of the client's prompts then fails, and the
//! next operation is served.

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::*;
use s4_credential::node::{Device, Node, Prompts};
use s4_credential::{Enroll, SignIn};
use s4_credential_contract::KeyAnswer;

const KEY: [u8; 32] = [9; 32];
const ROLE: &str = "S4_CREDENTIAL_KILLED_ROLE";
const DIRECTORY: &str = "S4_CREDENTIAL_KILLED_DIRECTORY";
const PORT: &str = "S4_CREDENTIAL_KILLED_PORT";
/// The kills each scenario makes.
const KILLS: usize = 5;

struct Phone;

impl Device for Phone {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }
}

/// A client whose user confirms everything, its key in memory; it says
/// when a proof is about to start, its key's output handed over.
struct Client {
    gone: bool,
}

impl Prompts for Client {
    fn confirm(&self, _: Form) -> Answer {
        if self.gone {
            return Answer::Declined;
        }
        Answer::Confirmed {
            choice: 0,
            values: Vec::new(),
        }
    }

    fn create_key(&self, _: Kind) -> KeyAnswer {
        KeyAnswer::Done(b"vos.device.killed".to_vec().into())
    }

    fn sign_key(&self, _: Kind, _: &[u8], _: &[u8]) -> KeyAnswer {
        KeyAnswer::Declined
    }

    fn evaluate_key(&self, _: Kind, _: &[u8], input: &[u8; 32]) -> KeyAnswer {
        if self.gone {
            return KeyAnswer::Failed("the client is gone".into());
        }
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(input);
        println!("proving");
        KeyAnswer::Done(mac.finalize().into_bytes().to_vec().into())
    }
}

/// The facility under `directory`, through the world's gateway at its
/// loopback `port`.
fn at(directory: &Path, port: u16) -> Node {
    node_over(Arc::new(world::Loopback(port)), directory, Arc::new(Phone))
}

fn login() -> SignIn {
    SignIn::read(&object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("login")),
        ("arguments", Value::Bytes(Vec::new())),
    ]))
    .unwrap()
}

/// A sign-in, once the path is held (a sync fetches it).
fn signed_in(node: &Node, session: u64) {
    loop {
        match node.sign_in(session, login(), Arc::new(Client { gone: false })) {
            Err(refusal) if refusal.code == Code::NoPath => {
                node.sync().unwrap();
            }
            signed => {
                signed.unwrap();
                return;
            }
        }
    }
}

/// Every enrollment file of the store, and its bytes.
fn files(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

/// The child: the facility proving or syncing in a loop until it is killed.
fn child(role: &str) {
    let directory = PathBuf::from(std::env::var(DIRECTORY).unwrap());
    let port: u16 = std::env::var(PORT).unwrap().parse().unwrap();
    let node = at(&directory, port);
    let session = node.open_session(gateway());
    node.granted(session).unwrap();
    loop {
        match role {
            "proof" => signed_in(&node, session),
            _ => {
                println!("syncing");
                node.sync().unwrap();
            }
        }
    }
}

/// A drawn delay below `most`.
fn below(most: Duration) -> Duration {
    let mut bytes = [0; 8];
    getrandom::getrandom(&mut bytes).unwrap();
    Duration::from_millis(u64::from_le_bytes(bytes) % most.as_millis() as u64)
}

/// The facility enrolled here, then killed `KILLS` times in a child while
/// it does `role`, the store checked after each.
fn killed_during(role: &str, test: &str, marker: &str, most: Duration) {
    if let Ok(role) = std::env::var(ROLE) {
        child(&role);
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let world = world();
    let port = runtime.block_on(world.listen());
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("credentials");
    let member = {
        let node = at(&store, port);
        let session = node.open_session(gateway());
        let enrolled = node
            .enroll(
                session,
                Enroll::read(&enrollment()).unwrap(),
                Arc::new(Client { gone: false }),
            )
            .unwrap();
        world.enroll(AGENT, &enrolled.member);
        enrolled.member
    };
    let kept = files(&store);
    assert_eq!(kept.len(), 1, "one enrollment, one file");

    for kill in 0..KILLS {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads", "1"])
            .env(ROLE, role)
            .env(DIRECTORY, &store)
            .env(PORT, port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
        // The second marker: the first operation ran whole before it.
        let mut seen = 0;
        while seen < 2 {
            let line = lines
                .next()
                .unwrap_or_else(|| panic!("the child stopped before {marker}"))
                .unwrap();
            if line == marker {
                seen += 1;
            }
        }
        std::thread::sleep(below(most));
        // SAFETY: a signal to the child this test spawned.
        assert_eq!(unsafe { libc::kill(process.id() as i32, libc::SIGKILL) }, 0);
        let status = process.wait().unwrap();
        assert!(!status.success(), "kill {kill}: the child was killed");

        assert_eq!(files(&store), kept, "kill {kill}: the store is as it was");
        let node = at(&store, port);
        let all = node.enrollments().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].member, member);
        let runs = node.runs().unwrap();
        let unfinished = runs.iter().filter(|run| run.finished_ms == 0).count();
        assert!(
            unfinished <= kill + 1,
            "kill {kill}: {unfinished} runs never finished"
        );
        if role == "sync" {
            assert!(!runs.is_empty(), "kill {kill}: the runs are kept");
        }
        let synced = node.sync().unwrap();
        assert_eq!(
            (synced.enrollments, synced.synced, synced.failed),
            (1, 1, 0)
        );
        let last = *node.runs().unwrap().last().unwrap();
        assert!(last.finished_ms >= last.started_ms && last.finished_ms > 0);
        assert_eq!(last.bytes_down, synced.bytes_down);
        let session = node.open_session(gateway());
        node.granted(session).unwrap();
        signed_in(&node, session);
    }
}

#[test]
fn a_facility_killed_during_a_proof_leaves_its_store_whole() {
    killed_during(
        "proof",
        "a_facility_killed_during_a_proof_leaves_its_store_whole",
        "proving",
        Duration::from_millis(1_000),
    );
}

#[test]
fn a_facility_killed_during_a_sync_leaves_its_store_whole() {
    killed_during(
        "sync",
        "a_facility_killed_during_a_sync_leaves_its_store_whole",
        "syncing",
        Duration::from_millis(30),
    );
}

#[test]
fn a_client_gone_during_an_operation_costs_only_that_operation() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let node = node(&world, directory.path(), Arc::new(Phone));
    let session = node.open_session(gateway());
    let enrolled = node
        .enroll(
            session,
            Enroll::read(&enrollment()).unwrap(),
            Arc::new(Client { gone: false }),
        )
        .unwrap();
    world.enroll(AGENT, &enrolled.member);
    node.sync().unwrap();
    let gone = node
        .sign_in(session, login(), Arc::new(Client { gone: true }))
        .unwrap_err();
    assert_eq!(gone.code, Code::Declined);
    // A session of an earlier process names nothing here.
    let stale = node
        .sign_in(session ^ 1, login(), Arc::new(Client { gone: false }))
        .unwrap_err();
    assert_eq!(stale.code, Code::NoSession);
    signed_in(&node, session);
}
