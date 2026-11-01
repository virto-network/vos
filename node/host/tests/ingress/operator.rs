//! The operator's commands, signed by a key the node lists, and a
//! replica's status.

use super::*;

#[test]
fn operator_commands_need_a_listed_key() {
    let served = Served::plain();
    let stranger = served.stranger();
    assert_eq!(
        stranger.create_agent(Vec::new()).unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    let client = served.client(1);
    assert_eq!(
        stranger
            .grant(served.agent, client.principal(), Some(1))
            .unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    assert_eq!(
        served.node.id(),
        vos_node::client::node_id(&served.target).unwrap()
    );
}

/// The operator sets an agent to report every window and back, and a
/// stranger cannot: the agent's state holds the opt-in while it is set.
#[test]
fn the_operator_sets_an_agent_to_report_every_window() {
    let served = Served::plain();
    let stranger = served.stranger();
    assert_eq!(
        stranger.report_every_window(served.agent, true).unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    let operator = served.operator();
    let set = || {
        served
            .node
            .store()
            .snapshot()
            .get(served.agent, &keys::every_window())
            .unwrap()
            .is_some()
    };
    for every in [true, false] {
        let answer = operator.report_every_window(served.agent, every).unwrap();
        assert!(
            matches!(
                answer,
                Response::Ran {
                    outcome: Outcome::Done(_),
                    ..
                }
            ),
            "{answer:?}"
        );
        assert_eq!(set(), every);
    }
}

/// A node's stats count its replica groups: a node of one holds and leads
/// each of its agents, at a term of one at least. They give what its
/// groups' entry caches hold, which a leader's own entries fill.
#[test]
fn the_stats_count_the_groups_a_node_holds_and_leads() {
    let served = Served::plain();
    let operator = served.operator();
    let Ok(Response::Stats(stats)) = operator.stats() else {
        panic!("the stats")
    };
    assert!(stats.groups.replicas >= 1, "{:?}", stats.groups);
    assert_eq!(stats.groups.leading, stats.groups.replicas);
    assert!(stats.groups.terms >= stats.groups.replicas);
    assert!(stats.memory.log_cache > 0, "{:?}", stats.memory);
}

/// The operator reads a replica's status, and a stranger cannot. A node
/// of a space of one whose flush fails outside any log write halts, and
/// its status says so.
#[test]
fn the_status_route_reports_a_replica_and_a_halt() {
    let hooks = Arc::new(FailNextSync::default());
    let served = Served::start(hooks.clone());
    let operator = served.operator();
    let Ok(Response::Status(status)) = operator.status(served.agent) else {
        panic!("a status")
    };
    assert!(status.leads && !status.halted, "{status:?}");
    assert!(status.applied >= 1 && status.commit >= status.applied);
    assert!(status.last_index >= status.commit);
    let stranger = served.stranger();
    assert_eq!(
        stranger.status(served.agent).unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    assert_eq!(operator.status(AgentId(0xdead)).unwrap(), Response::NoAgent);
    hooks.arm();
    assert!(
        served.node.create_agent().is_err(),
        "the record's flush failed"
    );
    wait_until("the node halts", || {
        matches!(
            operator.status(served.agent),
            Ok(Response::Status(status)) if status.halted
        )
    });
}
