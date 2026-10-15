//! Workflows on a replicated agent: started by a client, stepped by the
//! leader's sweeps and by another agent's replies, their snapshots riding
//! the result's blob path, their programs pinned while they live, through
//! upgrades, snapshots and retirements, and a lost page halting the node
//! that lost it.

use std::sync::Arc;
use std::time::Duration;

use vos_checker::calls::{Ran, installed};
use vos_checker::hooks::Holds;
use vos_checker::programs::{actor, method, package};
use vos_node::store::{EntryKind, PersistMode};
use vos_node::{Node, Reply};
use vos_pvm::pool::CodeHash;
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::records::{Workflow, WorkflowState};
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_wire::{Decode, Encode, keys};

use crate::common::{ALICE, Cluster, compacting, log_start, replaced, retired, wait_until};

const SHOP: InstanceId = InstanceId(4);

/// The shop's programs, its workflows in each, and their packages: its
/// own, and the one an upgrade installs.
struct Shop {
    shop: Vec<u8>,
    lean: Vec<u8>,
}

impl Shop {
    fn load() -> Self {
        Self {
            shop: actor("shop"),
            lean: actor("lean"),
        }
    }

    fn method(&self, name: &str) -> MethodId {
        method(&self.shop, name)
    }

    /// Install the shop at `agent`'s leader.
    fn install(&self, cluster: &Cluster, agent: AgentId) {
        cluster.install_package(agent, SHOP, &package("shop"));
    }

    /// Install the shop's upgrade at `agent`'s leader.
    fn upgrade(&self, cluster: &Cluster, agent: AgentId) {
        cluster.install_package(agent, SHOP, &package("lean"));
    }

    /// Alice's request starting workflow `name`, at `sequence` of the
    /// cluster's session.
    fn starting<A: Encode>(
        &self,
        cluster: &Cluster,
        sequence: u64,
        name: &str,
        arguments: A,
    ) -> vos_wire::batch::Request {
        vos_wire::batch::Request {
            instance: SHOP,
            ..cluster.request_of(sequence, self.method(name), arguments.encode())
        }
    }

    /// Start workflow `name` by [`Shop::starting`]'s request at `agent`'s
    /// leader: its id.
    fn start<A: Encode>(
        &self,
        cluster: &Cluster,
        agent: AgentId,
        sequence: u64,
        name: &str,
        arguments: A,
    ) -> WorkflowId {
        let request = self.starting(cluster, sequence, name, arguments);
        let leader = cluster.node(cluster.leader(agent));
        match smol::block_on(leader.call(agent, request)) {
            Ok(Reply::Ran(Outcome::Started(workflow))) => workflow,
            other => panic!("{other:?}"),
        }
    }
}

/// A workflow's record on `node`.
fn record(node: &Node, agent: AgentId, workflow: WorkflowId) -> Option<Workflow> {
    vos_checker::applied(node.store(), agent, &keys::workflow(workflow))
}

/// Wait until every replica holds `workflow` ended: its outcome.
fn ended(cluster: &Cluster, agent: AgentId, workflow: WorkflowId) -> Outcome {
    let mut outcome = None;
    wait_until("the workflow ends on every replica", || {
        let ends: Vec<Option<Outcome>> = cluster
            .running()
            .map(|(_, node)| match record(node, agent, workflow)?.state {
                WorkflowState::Ended(outcome) => Some(outcome),
                _ => None,
            })
            .collect();
        outcome = ends.first().cloned().flatten();
        ends.iter().all(|end| end.is_some() && *end == outcome)
    });
    outcome.unwrap()
}

/// A long computation, its first pause storing 2 MiB of pages: the leader
/// sweeps it through its steps by itself, each result that carries pages
/// past 64 KiB travels as a blob, and every replica ends with the same
/// state.
#[test]
fn a_workflows_snapshots_ride_the_result_blob_path() {
    let cluster = Cluster::new(3);
    let shop = Shop::load();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    shop.install(&cluster, agent);
    let workflow = shop.start(&cluster, agent, 1, "compute", (262_144u32, 16u32));
    let outcome = ended(&cluster, agent, workflow);
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    cluster.converged(agent);
    let leader = cluster.node(cluster.leader(agent));
    let applied = leader.applied(agent).unwrap();
    let large = (1..=applied)
        .filter_map(|index| leader.store().log_entry(agent, index).unwrap())
        .filter(|entry| entry.kind == EntryKind::LargeResult)
        .count();
    assert!(
        large >= 1,
        "a result with the first pause's pages is a blob"
    );
}

/// A long computation with no await, preempted step after step: its
/// leader stops in the middle of it, and a new leader resumes it from its
/// committed snapshot, the due index bringing its next step, until it ends
/// on every running replica with the result the same computation has under
/// a limit five times its own.
#[test]
fn a_preempted_computation_resumes_on_a_new_leader() {
    let mut cluster = Cluster::new(3);
    let shop = Shop::load();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    shop.install(&cluster, agent);
    let arguments = (4096u32, 5000u32);
    let whole = shop.start(&cluster, agent, 1, "grind_whole", arguments);
    let expected = ended(&cluster, agent, whole);
    assert!(matches!(expected, Outcome::Done(_)), "{expected:?}");

    let workflow = shop.start(&cluster, agent, 2, "grind", arguments);
    let leader = cluster.leader(agent);
    wait_until("the leader preempts the computation", || {
        let state = record(cluster.node(leader), agent, workflow).map(|record| record.state);
        matches!(state, Some(WorkflowState::Preempted(_)))
    });
    cluster.stop(leader);
    let preempted = cluster
        .running()
        .filter_map(|(_, node)| record(node, agent, workflow))
        .all(|record| !matches!(record.state, WorkflowState::Ended(_)));
    assert!(preempted, "unfinished when its leader stopped");
    let next = cluster.leader(agent);
    assert_ne!(next, leader);
    assert_eq!(ended(&cluster, agent, workflow), expected);
    cluster.converged(agent);
}

/// A workflow awaits another agent's counter twice, each reply resuming
/// it on whichever replica leads, and ends with both answers; one that
/// lives keeps its program pinned when an upgrade installs another, and
/// one that ended releases its pin.
#[test]
fn a_workflow_awaits_another_agent_and_pins_its_program_while_it_lives() {
    let cluster = Cluster::new(3);
    let shop = Shop::load();
    let risk = cluster.counter_agent(&[1, 2, 3]);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    shop.install(&cluster, agent);
    let saga = shop.start(&cluster, agent, 1, "saga", (risk.0, 2u32));
    let answers: Vec<u64> = vec![1, 3];
    assert_eq!(
        ended(&cluster, agent, saga),
        Outcome::Done(answers.encode())
    );
    assert_eq!(cluster.value(cluster.leader(risk), risk), 3);
    let sales = smol::block_on(cluster.node(cluster.leader(agent)).query(
        agent,
        ALICE,
        SHOP,
        shop.method("sales"),
        Vec::new(),
    ));
    assert_eq!(sales, Ok(Outcome::Done(4u64.encode())));

    let nap = shop.start(&cluster, agent, 2, "nap", 600_000u64);
    shop.upgrade(&cluster, agent);
    let leader = cluster.node(cluster.leader(agent));
    let program = record(leader, agent, nap).unwrap().program;
    assert_eq!(program, record(leader, agent, saga).unwrap().program);
    let upgrade = CodeHash::of(&shop.lean).0;
    wait_until(
        "the replicas pin the living workflow's program and the upgrade",
        || {
            cluster.running().all(|(_, node)| {
                let pinned = node.pinned();
                pinned.contains(&program.0) && pinned.contains(&upgrade)
            })
        },
    );
    // The ended saga released its pin: the living nap's alone holds it.
    let leader = cluster.node(cluster.leader(agent));
    let pins = vos_checker::applied::<u64>(leader.store(), agent, &keys::workflow_pins(&program));
    assert_eq!(pins, Some(1), "the living workflow's pin");
    let living = record(cluster.node(cluster.leader(agent)), agent, nap).unwrap();
    assert!(matches!(living.state, WorkflowState::Sleeping { .. }));
}

/// A workflow sleeping through an upgrade that installs another program
/// wakes on its own, which only its life pins: the agent reads the
/// programs it pins, and no other.
#[test]
fn a_workflow_wakes_on_the_program_only_its_life_pins() {
    let cluster = Cluster::new(3);
    let shop = Shop::load();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    shop.install(&cluster, agent);
    let nap = shop.start(&cluster, agent, 1, "nap", 1_500u64);
    shop.upgrade(&cluster, agent);
    let leader = cluster.node(cluster.leader(agent));
    let program = record(leader, agent, nap).unwrap().program.0;
    assert!(leader.pinned().contains(&program));
    assert!(matches!(ended(&cluster, agent, nap), Outcome::Done(_)));
    wait_until("the ended workflow's program is released", || {
        cluster
            .running()
            .all(|(_, node)| !node.pinned().contains(&program))
    });
}

/// A workflow started in the batch that installs its program loads it,
/// though only the batch's apply pins it.
#[test]
fn a_workflow_starts_in_the_batch_that_installs_its_program() {
    let hold = Arc::new(Holds::default());
    let cluster = Cluster::hooked(3, hold.clone());
    let shop = Shop::load();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.node(cluster.leader(agent));
    let before = leader.applied(agent).unwrap();
    let closed = hold.refines.close();
    let held = leader.call(agent, cluster.request(1, 1));
    wait_until("a batch's refine is held", || hold.refines.reached() > 0);
    let install = leader.install(agent, SHOP, &package("shop"), vec![]);
    let program = CodeHash::of(&shop.shop).0;
    wait_until("the package is stored", || leader.stores_blob(&program));
    // Its install is queued once its program is stored.
    std::thread::sleep(Duration::from_millis(200));
    let started = leader.call(agent, shop.starting(&cluster, 2, "nap", 0u64));
    drop(closed);
    assert!(smol::block_on(held).ran());
    installed(smol::block_on(install));
    let Ok(Reply::Ran(Outcome::Started(nap))) = smol::block_on(started) else {
        panic!("the workflow did not start");
    };
    let together = (before + 1..=leader.applied(agent).unwrap()).any(|index| {
        let Some(entry) = leader.store().log_entry(agent, index).unwrap() else {
            return false;
        };
        let Ok((result, _)) = WorkResult::decode(&entry.body) else {
            return false;
        };
        let ran = |input: fn(&Run) -> bool| {
            result
                .steps
                .iter()
                .any(|step| matches!(step, Step::Ran(run) if input(run)))
        };
        ran(|run| run.input == InputRef::Admin)
            && ran(|run| matches!(run.outcome, Outcome::Started(_)))
    });
    assert!(together, "the install and the start shared no batch");
    assert!(matches!(ended(&cluster, agent, nap), Outcome::Done(_)));
}

/// A workflow that lives pins its program, which an upgrade no longer
/// names: a follower caught up by a snapshot pins it too, fetching it
/// before its switch.
#[test]
fn a_snapshot_carries_a_living_workflows_pin() {
    let mut cluster = Cluster::tuned(3, compacting);
    let shop = Shop::load();
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.stop(follower);
    cluster.install(agent);
    shop.install(&cluster, agent);
    let nap = shop.start(&cluster, agent, 1, "nap", 600_000u64);
    shop.upgrade(&cluster, agent);
    let program = record(cluster.node(leader), agent, nap).unwrap().program.0;
    for sequence in 2..=40 {
        let added = vos_checker::calls::done(cluster.increment(leader, agent, sequence, 1));
        assert_eq!(added, sequence - 1);
    }
    cluster.compacted_past(leader, agent, 20);
    cluster.start(follower);
    cluster.converged(agent);
    let caught_up = cluster.node(follower);
    assert!(log_start(caught_up, agent) > 20, "installed a snapshot");
    assert!(caught_up.pinned().contains(&program));
    assert_eq!(caught_up.pinned(), cluster.node(leader).pinned());
    assert!(caught_up.stores_blob(&program));
}

/// A replica replaced retires its agent's pins, a living workflow's among
/// them; the replica that replaces it pins the workflow's program.
#[test]
fn a_retired_replica_releases_a_living_workflows_pin() {
    let cluster = Cluster::tuned(4, compacting);
    let shop = Shop::load();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    shop.install(&cluster, agent);
    let nap = shop.start(&cluster, agent, 1, "nap", 600_000u64);
    shop.upgrade(&cluster, agent);
    let (leader, removed) = cluster.leader_and_follower(agent);
    let program = record(cluster.node(leader), agent, nap).unwrap().program.0;
    wait_until("every replica pins the workflow's program", || {
        [1, 2, 3]
            .iter()
            .all(|number| cluster.node(*number).pinned().contains(&program))
    });
    let replicas = replaced(&[1, 2, 3], removed, 4);
    assert_eq!(
        cluster.node(leader).replace(agent, removed, 4).unwrap(),
        replicas
    );
    retired(cluster.node(removed), agent);
    assert!(cluster.node(removed).pinned().is_empty());
    cluster.converged(agent);
    assert!(cluster.node(4).pinned().contains(&program));
}

/// A page row a replica's store lost is data lost: its leader halts when a
/// step would restore it, never failing the workflow for it, and another
/// replica takes the lead and runs the step.
#[test]
fn a_lost_page_halts_the_node_that_lost_it() {
    let cluster = Cluster::new(3);
    let shop = Shop::load();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    shop.install(&cluster, agent);
    let leader = cluster.leader(agent);
    let nap = shop.start(&cluster, agent, 1, "nap", 1_000u64);
    let node = cluster.node(leader);
    let held = record(node, agent, nap).unwrap().snapshot.unwrap().pages;
    let lost = Write {
        key: keys::page(nap, held[0].0),
        value: None,
    };
    let epoch = node.store().snapshot().epoch(agent).unwrap();
    let mut batch = node.store().batch();
    batch.rows(agent, epoch, [&lost]);
    batch.commit(PersistMode::SyncAll).unwrap();
    wait_until("the leader halts", || {
        node.replica(agent).is_some_and(|status| status.halted)
    });
    let others: Vec<_> = (1..=3).filter(|number| *number != leader).collect();
    wait_until("another replica ends the workflow", || {
        others.iter().all(|number| {
            matches!(
                record(cluster.node(*number), agent, nap).map(|workflow| workflow.state),
                Some(WorkflowState::Ended(Outcome::Done(_)))
            )
        })
    });
}
