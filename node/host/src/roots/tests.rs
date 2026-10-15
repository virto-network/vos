//! The builder against roots from scratch: batches of any size, builds
//! cut short, and builds across an epoch change.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_tree::{Blake2b, Leaf, value_hash};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MapId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{stored, versioned};
use vos_wire::result::Write;

use super::{Build, Error, prove, root, rows_match_tree};
use crate::NoHooks;
use crate::storage::{Change, StorageThread};
use crate::store::{Fjall, HardState, Membership, Switch};

const AGENT: AgentId = AgentId(3);

/// A committed write: a map, a raw key, and a value or a deletion.
type Committed = (MapId, Vec<u8>, Option<Vec<u8>>);

fn map(tag: u32, transform: Transform) -> MapId {
    MapId {
        instance: InstanceId(1),
        tag,
        transform,
    }
}

fn seed(version: u64) -> [u8; 32] {
    vos_tree::Hasher::hash(&Blake2b, b"test seed", &[&version.to_le_bytes()])
}

/// An agent's committed maps written as accumulate writes them, and the
/// value each key holds, with the version that wrote it.
struct Agent {
    writer: StorageThread,
    store: Fjall,
    epoch: u8,
    applied: u64,
    version: u64,
    values: BTreeMap<(MapId, Vec<u8>), (u64, Vec<u8>)>,
}

impl Agent {
    fn new(dir: &std::path::Path) -> Self {
        let store = Fjall::open(dir).unwrap();
        Self {
            writer: StorageThread::spawn(store.clone(), Arc::new(NoHooks)),
            store,
            epoch: 0,
            applied: 0,
            version: 0,
            values: BTreeMap::new(),
        }
    }

    fn commit(&self, change: Change) -> Result<(), String> {
        smol::block_on(self.writer.commit(vec![change]))
    }

    /// A work result's committed writes, each a raw key and a value or
    /// a deletion, at the next version.
    fn apply(&mut self, writes: &[Committed]) {
        self.applied += 1;
        self.version += 1;
        let version = self.version;
        let mut rows = Vec::new();
        for (map, key, value) in writes {
            let transformed = map.transform.apply(key);
            rows.push(Write {
                key: keys::committed(map, &transformed),
                value: value
                    .as_ref()
                    .map(|value| stored(&versioned(version, value))),
            });
            rows.push(Write {
                key: keys::dirty(version, map, &transformed),
                value: Some(stored(&[])),
            });
            match value {
                Some(value) => self
                    .values
                    .insert((*map, key.clone()), (version, value.clone())),
                None => self.values.remove(&(*map, key.clone())),
            };
        }
        if !writes.is_empty() {
            rows.push(Write {
                key: keys::seed(version),
                value: Some(stored(&seed(version))),
            });
        }
        rows.push(Write {
            key: keys::version(),
            value: Some(stored(&version.encode())),
        });
        self.commit(Change::Apply {
            agent: AGENT,
            epoch: self.epoch,
            index: self.applied,
            writes: rows,
        })
        .unwrap();
    }

    /// Run a build to its end, `batch` keys at a time.
    fn build(&self, batch: usize) {
        let Some(build) = Build::start(&self.store, AGENT).unwrap() else {
            return;
        };
        let mut build = build.in_batches_of(batch);
        while let Some(change) = build.next_batch().unwrap() {
            self.commit(change).unwrap();
        }
    }

    /// The root of `map` from scratch over its values, each salted
    /// from the seed of the version that wrote it.
    fn expected(&self, map: MapId) -> vos_tree::Hash {
        let leaves: BTreeMap<Vec<u8>, vos_tree::Hash> = self
            .values
            .iter()
            .filter(|((at, _), _)| *at == map)
            .map(|((_, key), (version, value))| {
                let key = map.transform.apply(key);
                let leaf = Leaf::salted(&Blake2b, &seed(*version), &key, value);
                (key, leaf.value_hash)
            })
            .collect();
        let leaves: Vec<_> = leaves.into_iter().collect();
        vos_tree::root(&Blake2b, &leaves)
    }

    /// The map's root is the one from scratch at the agent's version,
    /// its rows are exactly the tree's, and no dirty or seed row is
    /// left.
    fn check(&self, map: MapId) {
        let snapshot = self.store.snapshot();
        assert_eq!(
            root(&snapshot, AGENT, &map).unwrap(),
            (self.expected(map), self.version)
        );
        assert!(
            rows_match_tree(&snapshot, AGENT, map).unwrap(),
            "rows off the tree"
        );
        let stored = |prefix: Vec<u8>| snapshot.scan(AGENT, &prefix, None).count();
        assert_eq!(stored(keys::dirty_prefix()), 0, "dirty rows left");
        assert_eq!(stored(keys::seed_prefix()), 0, "seed rows left");
    }
}

fn key(index: u64) -> Vec<u8> {
    index.to_be_bytes().to_vec()
}

/// Inserts, changes and deletes in two maps of either transform, built
/// in one batch or in many, after each version or after several: the
/// root is always the one from scratch, every row is on the tree, and
/// every proof verifies.
#[test]
fn builds_reach_the_root_from_scratch_in_any_batches() {
    for batch in [1, 7, super::BATCH] {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = Agent::new(dir.path());
        let hashed = map(5, Transform::Hashed);
        let ordered = map(5, Transform::Ordered);
        for round in 0..6u64 {
            let writes: Vec<_> = (0..40u64)
                .map(|index| {
                    let at = (index * 7 + round * 13) % 60;
                    let value = (at % 5 != round % 5).then(|| (round * 100 + index).encode());
                    let target = if index.is_multiple_of(3) {
                        ordered
                    } else {
                        hashed
                    };
                    (target, key(at), value)
                })
                .collect();
            agent.apply(&writes);
            if round % 2 == 1 {
                agent.build(batch);
                agent.check(hashed);
                agent.check(ordered);
            }
        }
        let snapshot = agent.store.snapshot();
        let asked: Vec<Vec<u8>> = (0..70).map(key).collect();
        for target in [hashed, ordered] {
            let proven = prove(&snapshot, AGENT, target, &asked).unwrap();
            assert_eq!(proven.version, agent.version);
            let claims: Vec<_> = proven
                .leaves
                .iter()
                .map(|(key, leaf)| (key.clone(), leaf.map(|leaf| leaf.value_hash)))
                .collect();
            proven
                .proof
                .verify(&Blake2b, &proven.root, &claims)
                .unwrap();
            for ((key, leaf), raw) in proven.leaves.iter().zip(&asked) {
                let held = agent.values.get(&(target, raw.clone()));
                assert_eq!(leaf.is_some(), held.is_some());
                if let (
                    Some(Leaf {
                        salt,
                        value_hash: commitment,
                    }),
                    Some((_, value)),
                ) = (leaf, held)
                {
                    assert_eq!(value_hash(&Blake2b, salt, value), *commitment);
                }
                assert_eq!(*key, target.transform.apply(raw));
            }
        }
    }
}

/// A build stopped part-way, its batches committed until then, is
/// finished by a later build, after more applies: the root from scratch,
/// with no row off the tree. Between its batches the map proves nothing,
/// while a map it never touched proves against its root.
#[test]
fn a_build_cut_short_is_finished_by_the_next() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = Agent::new(dir.path());
    let target = map(9, Transform::Hashed);
    let untouched = map(10, Transform::Ordered);
    agent.apply(&[(untouched, key(1), Some(vec![1]))]);
    let writes = |round: u64| -> Vec<_> {
        (0..50u64)
            .map(|index| (target, key((index * 3 + round) % 80), Some(round.encode())))
            .collect()
    };
    agent.apply(&writes(0));
    agent.build(super::BATCH);
    agent.apply(&writes(1));
    agent.apply(&[(target, key(1), None), (target, key(4), None)]);
    let mut build = Build::start(&agent.store, AGENT)
        .unwrap()
        .unwrap()
        .in_batches_of(10);
    for _ in 0..2 {
        agent.commit(build.next_batch().unwrap().unwrap()).unwrap();
    }
    let snapshot = agent.store.snapshot();
    assert!(matches!(
        root(&snapshot, AGENT, &target),
        Err(Error::Building)
    ));
    assert!(matches!(
        prove(&snapshot, AGENT, target, &[key(1)]),
        Err(Error::Building)
    ));
    let proven = prove(&snapshot, AGENT, untouched, &[key(1), key(2)]).unwrap();
    assert_eq!(proven.root, agent.expected(untouched));
    let claims: Vec<_> = proven
        .leaves
        .iter()
        .map(|(key, leaf)| (key.clone(), leaf.map(|leaf| leaf.value_hash)))
        .collect();
    proven
        .proof
        .verify(&Blake2b, &proven.root, &claims)
        .unwrap();
    assert!(claims[0].1.is_some() && claims[1].1.is_none());
    drop(build);
    agent.apply(&writes(2));
    agent.build(10);
    agent.check(target);
    agent.check(untouched);
}

/// A build cut short after its batches consumed a map's every dirty row
/// leaves that map part-way; the next build finishes it though it has no
/// write left to touch it.
#[test]
fn a_map_left_part_way_is_finished_without_a_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = Agent::new(dir.path());
    let early = map(4, Transform::Hashed);
    let late = map(5, Transform::Hashed);
    agent.apply(&[
        (early, key(1), Some(vec![1])),
        (early, key(2), Some(vec![2])),
    ]);
    agent.apply(&[(late, key(3), Some(vec![3]))]);
    let mut build = Build::start(&agent.store, AGENT)
        .unwrap()
        .unwrap()
        .in_batches_of(2);
    agent.commit(build.next_batch().unwrap().unwrap()).unwrap();
    assert!(matches!(
        root(&agent.store.snapshot(), AGENT, &early),
        Err(Error::Building)
    ));
    drop(build);
    agent.apply(&[(late, key(4), Some(vec![4]))]);
    agent.build(super::BATCH);
    agent.check(early);
    agent.check(late);
}

/// A build's batch, once a snapshot switched the agent to another
/// epoch, is refused, and nothing it read lands in the old epoch; the
/// next build runs on the new one.
#[test]
fn a_build_across_an_epoch_change_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = Agent::new(dir.path());
    let target = map(2, Transform::Ordered);
    agent.apply(&[
        (target, key(1), Some(vec![1])),
        (target, key(2), Some(vec![2])),
    ]);
    let mut build = Build::start(&agent.store, AGENT)
        .unwrap()
        .unwrap()
        .in_batches_of(1);
    let stale = build.next_batch().unwrap().unwrap();
    // The leader's state, the agent's rows as they are, staged into
    // epoch 1 and switched to, as a snapshot install does.
    let snapshot = agent.store.snapshot();
    let owners = [[0x00], [0x01], [0x02]];
    let rows: Vec<_> = owners
        .iter()
        .flat_map(|owner| snapshot.scan(AGENT, owner, None))
        .map(Result::unwrap)
        .collect();
    agent
        .commit(Change::Stage {
            agent: AGENT,
            epoch: 1,
            first: true,
            rows,
        })
        .unwrap();
    agent
        .commit(Change::Switch {
            agent: AGENT,
            switch: Switch {
                epoch: 1,
                index: 5,
                term: 1,
                hard: HardState::default(),
                membership: Membership::default(),
                log_start_membership: None,
                truncate_after: None,
            },
        })
        .unwrap();
    agent.epoch = 1;
    agent.applied = 5;
    let refused = agent.commit(stale).unwrap_err();
    assert!(refused.contains("stale"), "{refused}");
    assert!(matches!(build.next_batch(), Err(Error::Moved)));
    agent
        .commit(Change::DropEpoch {
            agent: AGENT,
            epoch: 0,
            limit: usize::MAX,
        })
        .unwrap();
    assert!(agent.store.stale_epochs(AGENT).unwrap().is_empty());
    agent.build(super::BATCH);
    agent.check(target);
}
