//! Committed maps on replicated agents: every replica builds the same root
//! at the same version, the root from scratch over the map's value rows,
//! with no row off the tree, and proves keys against it; a follower that
//! catches up by a snapshot does too; and a build that fails is tried
//! again.

use std::time::Duration;

use vos_checker::calls::done;
use vos_checker::programs::table_tag;
use vos_node::Node;
use vos_node::roots::{self, AgentStore};
use vos_node::store::PersistMode;
use vos_tree::{Blake2b, Hash, value_hash};
use vos_wire::Encode;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, MapId};
use vos_wire::keys;
use vos_wire::peer::NodeNumber;
use vos_wire::records::{unstored, unversioned};
use vos_wire::result::Write;

use crate::common::{
    ALICE, COUNTER, Cluster, compacting, log_start, old_epochs_dropped, wait_until,
};

/// The counter's committed map, as its value rows on `node` name it: its
/// transform is the field's, whichever the SDK's default.
fn entries(node: &Node, agent: AgentId) -> MapId {
    let tag = table_tag("entries");
    node.store()
        .snapshot()
        .scan(agent, &keys::instance_committed(COUNTER), None)
        .find_map(|row| {
            let (key, _) = row.unwrap();
            keys::committed_entry(&key)
                .map(|(map, _)| map)
                .filter(|map| map.tag == tag)
        })
        .expect("a value row of the committed map")
}

/// Request `sequence` of the cluster's session at `agent`: puts and
/// deletes in the committed map, over keys that come back.
fn writes(cluster: &Cluster, agent: AgentId, sequence: u64) -> Request {
    let writes: Vec<(u64, Option<u64>)> = (0..25u64)
        .map(|index| {
            let key = (sequence * 37 + index * 11) % 300;
            (key, (key % 7 != sequence % 7).then_some(sequence))
        })
        .collect();
    Request {
        session: cluster.session(agent),
        sequence,
        caller: ALICE,
        instance: COUNTER,
        method: cluster.programs.method("set_entries"),
        arguments: writes.encode(),
    }
}

/// Each request in `sequences`, at `agent`'s leader, followed as it moves.
fn write(cluster: &Cluster, agent: AgentId, sequences: std::ops::RangeInclusive<u64>) {
    for sequence in sequences {
        let reply = cluster.call_at_leader(agent, writes(cluster, agent, sequence));
        assert_eq!(done(reply), 25, "sequence {sequence}");
    }
}

/// The agent's state version on `node`.
fn version(node: &Node, agent: AgentId) -> u64 {
    vos_checker::applied(node.store(), agent, &keys::version()).unwrap_or(0)
}

/// The map's root on `node`, once built at the agent's version with no key
/// left dirty.
fn settled(node: &Node, agent: AgentId) -> Option<(Hash, u64)> {
    let snapshot = node.store().snapshot();
    let at = version(node, agent);
    let dirty = snapshot
        .scan(agent, &keys::dirty_prefix(), None)
        .next()
        .is_some();
    match roots::root(&snapshot, agent, &entries(node, agent)) {
        Ok((root, built)) if built == at && !dirty => Some((root, built)),
        _ => None,
    }
}

/// On `node`: the map's root and the agent's are the ones from scratch
/// over the value rows, each leaf at its row's key committing the row's
/// bare value, every node and leaf row is on the tree, and a proof of
/// present and absent keys verifies.
fn check(node: &Node, agent: AgentId, root: Hash) {
    let map = entries(node, agent);
    let snapshot = node.store().snapshot();
    let tree = AgentStore::open(&snapshot, agent).unwrap();
    let prefix = keys::committed_rows(&map);
    let mut leaves = Vec::new();
    for row in snapshot.scan(agent, &keys::committed_all(), None) {
        let (key, value) = row.unwrap();
        let (_, value) = unversioned(unstored(&value).unwrap()).unwrap();
        let leaf = vos_tree::NodeStore::leaf(&tree, &key)
            .unwrap()
            .expect("a leaf");
        assert_eq!(value_hash(&Blake2b, &leaf.salt, value), leaf.value_hash);
        leaves.push((key, leaf.value_hash));
    }
    let of_map: Vec<_> = leaves
        .iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .cloned()
        .collect();
    assert!(of_map.len() > 100, "{} entries", of_map.len());
    assert_eq!(vos_tree::root(&Blake2b, &of_map), root);
    assert_eq!(
        roots::agent_root(&snapshot, agent).unwrap().0,
        vos_tree::root(&Blake2b, &leaves)
    );
    assert!(
        roots::rows_match_tree(&snapshot, agent).unwrap(),
        "rows off the tree"
    );
    let stored = |prefix: Vec<u8>| snapshot.scan(agent, &prefix, None).count();
    assert_eq!(stored(keys::seed_prefix()), 0, "seed rows left");
    let asked: Vec<Vec<u8>> = (0..320u64).map(|key| key.to_be_bytes().to_vec()).collect();
    let proven = node.prove(agent, map, &asked).unwrap();
    assert_eq!(proven.root, root);
    let claims: Vec<_> = proven
        .leaves
        .iter()
        .map(|(key, leaf)| (key.clone(), leaf.map(|leaf| leaf.value_hash)))
        .collect();
    assert!(
        claims.iter().any(|(_, held)| held.is_none()),
        "absent keys too"
    );
    proven.proof.verify(&Blake2b, &root, &claims).unwrap();
}

/// Every replica's root at the agent's version, once all have built it:
/// the same on each.
fn same_root(cluster: &Cluster, agent: AgentId, replicas: &[NodeNumber]) -> Hash {
    let mut roots = Vec::new();
    wait_until(
        "every replica builds the root at the agent's version",
        || {
            roots = replicas
                .iter()
                .map(|number| settled(cluster.node(*number), agent))
                .collect();
            roots.iter().all(Option::is_some) && roots.windows(2).all(|pair| pair[0] == pair[1])
        },
    );
    let (root, built) = roots[0].unwrap();
    assert!(built > 1, "built at version {built}");
    root
}

#[test]
fn every_replica_builds_the_same_root() {
    let cluster = Cluster::new(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    write(&cluster, agent, 1..=60);
    let root = same_root(&cluster, agent, &[1, 2, 3]);
    for number in 1..=3 {
        check(cluster.node(number), agent, root);
    }
}

/// A follower down while the log compacts past it installs the leader's
/// rows, the tree's and the dirty ones among them, while its own builder
/// runs, and builds the same root.
#[test]
fn a_follower_caught_up_by_a_snapshot_builds_the_same_root() {
    let mut cluster = Cluster::tuned(3, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    write(&cluster, agent, 1..=10);
    same_root(&cluster, agent, &[1, 2, 3]);
    cluster.stop(follower);
    write(&cluster, agent, 11..=40);
    cluster.compacted_past(leader, agent, 30);
    cluster.start(follower);
    std::thread::scope(|scope| {
        let cluster = &cluster;
        scope.spawn(move || write(cluster, agent, 41..=70));
    });
    let root = same_root(&cluster, agent, &[1, 2, 3]);
    let caught_up = cluster.node(follower);
    assert!(log_start(caught_up, agent) > 30, "installed a snapshot");
    check(caught_up, agent, root);
    old_epochs_dropped(caught_up, agent);
}

/// A build that fails, here on a row the builder wrote that does not read
/// back, is tried again after a backoff, with no write to wake it: once the
/// row reads, the root reaches the agent's version.
#[test]
fn a_failed_build_is_tried_again() {
    let cluster = Cluster::new(1);
    let agent = cluster.counter_agent(&[1]);
    write(&cluster, agent, 1..=8);
    same_root(&cluster, agent, &[1]);
    let node = cluster.node(1);
    let store = node.store();
    let built = store
        .snapshot()
        .get(agent, &keys::built())
        .unwrap()
        .unwrap();
    let set_built = |value: Vec<u8>| {
        let epoch = store.snapshot().epoch(agent).unwrap();
        let mut batch = store.batch();
        let row = Write {
            key: keys::built(),
            value: Some(value),
        };
        batch.rows(agent, epoch, [&row]);
        batch.commit(PersistMode::Buffer).unwrap();
    };
    set_built(vec![0xff]);
    write(&cluster, agent, 9..=9);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        settled(node, agent).is_none(),
        "built over a row it cannot read"
    );
    set_built(built);
    same_root(&cluster, agent, &[1]);
    check(node, agent, settled(node, agent).unwrap().0);
}
