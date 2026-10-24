//! The audit's carriers and needles, and the audit itself.
//!
//! What leaves the prover role is searched at full strength
//! ([`Reach::Leaves`]): what each venue's client was asked to send, in each
//! venue's layout (`Tapped`); every work package a JAM client sent, as it
//! went, with its extrinsics and the work report a guarantor made of it
//! (anchors, the registration, statements and replays alike: the
//! deployment's `Wire`), and the service's storage accounted for against
//! them, so it holds no outcome of a package not watched; the Kreivo mock's
//! signed envelopes and storage; both venues' anchor chains; the process's
//! logs and standard error.
//! The testnet's own log and database, the chain's record of what it was
//! sent, are searched in every needle's full forms ([`Reach::Recorded`]).
//! Each capture path is shown to capture: a canary through the logs and
//! standard error, and in the chain's record a value the run sent (a
//! statement's encoding and a work report in its database, a report's
//! hash in its log).

use std::time::Duration;

use vos_checker::carriers::{self, Audit, Kind, Reach};
use vos_node::Node;
use vos_statement_service::item::Item;
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;
use vos_wire::result::digest;

use crate::cuts::results;
use crate::run::{CANARY, Jam, Run, Stated};
use crate::venues::hex;

/// How long a sent package's work report is waited for once the run ends.
const REPORTED: Duration = Duration::from_secs(90);

/// Every entry `agent`'s log holds on `node`, its body as the log keeps it.
fn log_entries(node: &Node, agent: AgentId) -> Vec<u8> {
    let through = node.applied(agent).unwrap_or(0);
    (1..=through)
        .filter_map(|index| node.store().log_entry(agent, index).ok().flatten())
        .flat_map(|entry| entry.body)
        .collect()
}

/// What each node holds and sent, and both venues' anchor chains,
/// collected before the nodes stop and the chain's clock moves; then the
/// nodes stopped and their disks read, every file closed and none
/// changing under the read.
pub fn nodes(run: &mut Run) -> Audit {
    let mut audit = Audit::default();
    audit.carrier("the anchor chains", Reach::Leaves, run.anchor_chains());
    for ((to, class), bytes) in run.frames.lock().unwrap().iter() {
        let name = format!("frames to node {to}: {class}");
        audit.carrier(name, Reach::Role, bytes.clone());
    }
    let agents = &run.agents;
    let all = [
        agents.representative,
        agents.balance,
        agents.window,
        agents.reader,
    ];
    for (number, node) in run.cluster.running() {
        for agent in all {
            let name = format!("node {number}: agent {}'s log", agent.0);
            audit.carrier(name, Reach::Role, log_entries(node, agent));
            let results: Vec<u8> = results(node, agent, 0)
                .iter()
                .flat_map(|(_, result)| result.encode())
                .collect();
            let name = format!("node {number}: agent {}'s work results", agent.0);
            audit.carrier(name, Reach::Role, results);
        }
        let jobs: Vec<u8> = node
            .store()
            .prover_jobs()
            .unwrap()
            .into_iter()
            .flat_map(|(_, id, job)| [id.to_vec(), job].concat())
            .collect();
        let name = format!("node {number}: the prover's table");
        audit.carrier(name, Reach::Role, jobs);
        let name = format!("node {number}: the store's rows");
        audit.carrier(name, Reach::Role, carriers::store(node.store()));
    }
    for number in 1..=3 {
        run.cluster.stop(number);
    }
    for (at, dir) in run.cluster.dirs.iter().enumerate() {
        let number = at as NodeNumber + 1;
        for (path, bytes) in carriers::directory(dir.path()) {
            audit.carrier(format!("node {number}: {path}"), Reach::Role, bytes);
        }
    }
    audit
}

/// Every package `jam`'s client sent, its extrinsics and its work report,
/// watched before it went: the reports, as the canaries take them. A
/// package the node answered it took has a report; one whose answer was
/// lost or refused is audited all the same, its report too if the chain
/// holds one.
fn wire(audit: &mut Audit, jam: &Jam) -> Vec<Vec<u8>> {
    let mut reports = Vec::new();
    for (n, sent) in jam.wire.sent().into_iter().enumerate() {
        let name = format!("JAM {}'s package {n}", jam.name);
        audit.carrier(name.clone(), Reach::Leaves, sent.package.clone());
        for (at, extrinsic) in sent.extrinsics.iter().enumerate() {
            let extrinsic = extrinsic.clone();
            audit.carrier(format!("{name}'s extrinsic {at}"), Reach::Leaves, extrinsic);
        }
        let report = sent.report(REPORTED);
        let taken = sent.taken.get().copied().unwrap_or(false);
        assert!(report.is_some() || !taken, "{name}'s work report");
        if let Some(report) = report {
            audit.carrier(
                format!("{name}'s work report"),
                Reach::Leaves,
                report.clone(),
            );
            reports.push(report);
        }
    }
    reports
}

/// The rest of the audit: the needles, what left the role, the chain's
/// record, the logs; each capture path's canary; then the search.
pub fn rest(run: &mut Run, audit: &mut Audit, stated: &[Stated]) {
    audit.needles.debug_outputs();
    let made = run.prover.made();
    assert!(made.len() >= stated.len() + 2, "each statement proved");
    for (n, (attest, internals)) in made.iter().enumerate() {
        assert!(!internals.proofs.is_empty() && !internals.memory_roots.is_empty());
        let name = format!("statement {n}");
        audit.needles.internals(&name, internals);
        let arguments = stated
            .iter()
            .find(|stated| stated.attest == *attest)
            .map_or(attest.witness_input.len(), |stated| stated.asked.arguments);
        audit.needles.attest(&name, attest, arguments);
    }

    run.jam_a.tapped.carriers(audit);
    run.jam_b.tapped.carriers(audit);
    for (number, (.., tapped)) in run.kreivo_clients.lock().unwrap().iter() {
        let mut node = Audit::default();
        tapped.carriers(&mut node);
        for carrier in node.carriers {
            let name = format!("node {number} at Kreivo: {}", carrier.name);
            audit.carrier(name, carrier.reach, carrier.bytes);
        }
    }
    let reports = [wire(audit, &run.jam_a), wire(audit, &run.jam_b)].concat();
    for jam in [&run.jam_a, &run.jam_b] {
        let accounting = jam
            .venue
            .statements
            .account(jam.baseline, || {
                jam.wire
                    .sent()
                    .into_iter()
                    .map(|sent| sent.package)
                    .collect()
            })
            .expect("the service's storage");
        run.record.note(format!(
            "JAM {}'s storage: {} entries, as many named from the packages watched, {} outcomes \
             among them",
            jam.name, accounting.held, accounting.outcomes
        ));
        assert_eq!(
            accounting.held, accounting.named,
            "JAM {}: every outcome the service holds is of a package watched",
            jam.name
        );
    }
    for (n, envelope) in run.kreivo.envelopes().into_iter().enumerate() {
        audit.carrier(format!("Kreivo's extrinsic {n}"), Reach::Leaves, envelope);
    }
    audit.carrier("Kreivo's storage", Reach::Leaves, run.kreivo.storage());
    let log = std::fs::read(&run.testnet.log).expect("the testnet's log");
    audit.carrier("the testnet's log", Reach::Recorded, log);
    let chain = carriers::directory(&run.testnet.chain());
    assert!(!chain.is_empty(), "the testnet's chain holds files");
    for (path, bytes) in chain {
        let name = format!("the testnet's chain: {path}");
        audit.carrier(name, Reach::Recorded, bytes);
    }
    std::thread::spawn(|| eprintln!("{CANARY}: a thread of the process"))
        .join()
        .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    audit.carrier("the logs, every level", Reach::Leaves, run.logs.bytes());
    let stderr = run.stderr.take().expect("standard error captured");
    audit.carrier("standard error", Reach::Leaves, stderr.finish());

    let summary = audit.summary();
    let kinds: Vec<&str> = summary
        .lines()
        .filter(|line| line.ends_with(" needles"))
        .collect();
    run.record.note(format!(
        "the audit: {} carriers, {} JAM packages and their work reports; {}",
        audit.carriers.len(),
        reports.len(),
        kinds.join(", ")
    ));
    std::fs::write(run.testnet.run.join("audit.txt"), &summary).unwrap();

    for carrier in ["the logs", "standard error"] {
        audit.assert_captured(carrier, CANARY.as_bytes());
    }
    // The chain's record holds what it was sent as bytes the search reads:
    // a statement's encoding and a work report in its database, and a
    // report's hash, as its log names it, in its log.
    let statement = &stated.last().expect("a statement").statement;
    let report =
        reports
            .iter()
            .find(|report| {
                let encoded = Item::Submit(statement.encode()).encode();
                run.jam_a.wire.sent().iter().any(|sent| {
                    sent.report.get() == Some(report) && contains(&sent.package, &encoded)
                })
            })
            .expect("the statement's work report");
    audit.assert_captured("the testnet's chain", &statement.encode());
    audit.assert_captured("the testnet's chain", report);
    let named = format!("0x{}", &hex(&digest(report))[..16]);
    audit.assert_captured("the testnet's log", named.as_bytes());

    audit.assert_searchable(&[
        Kind::NodeProof,
        Kind::ServedRow,
        Kind::PrivateHash,
        Kind::StepCount,
        Kind::MemoryRoot,
        Kind::Register,
        Kind::WrapRandomness,
        Kind::DebugOutput,
    ]);
    audit.assert_clean();
    run.record
        .note("the audit clean, every capture path shown; every verdict as expected");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
