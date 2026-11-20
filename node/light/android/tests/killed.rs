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

use common::phone::signs_in;
use common::*;
use vos_facility::Enroll;
use vos_facility::node::Node;

const ROLE: &str = "S4_CREDENTIAL_KILLED_ROLE";
const DIRECTORY: &str = "S4_CREDENTIAL_KILLED_DIRECTORY";
const PORT: &str = "S4_CREDENTIAL_KILLED_PORT";
/// The kills each scenario makes.
const KILLS: usize = 5;

/// A client whose user confirms everything, its key in memory; it says
/// when a proof is about to start, its key's output handed over. Gone, it
/// declines every prompt. Each process's holds the key the first made.
fn client(gone: bool) -> Arc<Phone> {
    let phone = Phone::restarted(9);
    *phone.evaluating.lock().unwrap() = Some(|| println!("proving"));
    if gone {
        phone.decline(usize::MAX);
    }
    Arc::new(phone)
}

/// The facility under `directory`, through the world's gateway at its
/// loopback `port`.
fn at(directory: &Path, port: u16) -> Node {
    node_over(Arc::new(world::Loopback(port)), directory, client(false))
}

/// Every enrollment row of the store, and its bytes.
fn files(directory: &Path) -> BTreeMap<Vec<u8>, Vec<u8>> {
    vos_facility::kept::Kept::open(directory)
        .unwrap()
        .raw(b"enrollment/")
        .unwrap()
        .into_iter()
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
            "proof" => signs_in(&node, session, || client(false), usize::MAX),
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
            .enroll(session, Enroll::read(&enrollment()).unwrap(), client(false))
            .unwrap();
        world.enroll(AGENT, &enrolled.member);
        enrolled.member
    };
    let kept = files(&store);
    assert_eq!(kept.len(), 1, "one enrollment, one row");

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
        signs_in(&node, session, || client(false), usize::MAX);
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
    let node = node(&world, directory.path(), client(false));
    let session = node.open_session(gateway());
    let enrolled = node
        .enroll(session, Enroll::read(&enrollment()).unwrap(), client(false))
        .unwrap();
    world.enroll(AGENT, &enrolled.member);
    node.sync().unwrap();
    // Signed in on a session of its own: the enrolling one showed the
    // digests.
    let session = node.open_session(gateway());
    let gone = node.sign_in(session, sign_in(), client(true)).unwrap_err();
    assert_eq!(gone.code, Code::Declined);
    // A session of an earlier process names nothing here.
    let stale = node
        .sign_in(session ^ 1, sign_in(), client(false))
        .unwrap_err();
    assert_eq!(stale.code, Code::NoSession);
    signs_in(&node, session, || client(false), usize::MAX);
}
