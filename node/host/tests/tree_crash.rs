//! Root builds killed mid-way: a builder resumes to the root from scratch,
//! with no node or leaf row left off the tree.
//!
//! A child process applies work results of committed writes in a loop, as
//! accumulate leaves them (value rows, dirty rows and a seed row), and every
//! few versions builds the roots in small batches, each its own commit, as
//! the node's builder does. The test kills it at random moments and reopens
//! the store; later rounds tear the journal's tail first, which may cut a
//! build between batches. After each, a build to the end gives:
//!
//! - the agent's root, the root of the tree over the values at the
//!   recovered version, each leaf salted from the seed of the version that
//!   wrote it, and each map's, at that version;
//! - exactly the tree's node and leaf rows, and no dirty or seed row;
//! - the state of every apply reported, but for a tear's reach.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use vos_checker::crash::{Round, Rounds, journal};
use vos_node::NoHooks;
use vos_node::roots::{self, Build};
use vos_node::storage::{Change, StorageThread};
use vos_node::store::Fjall;
use vos_tree::{Blake2b, Hash, Hasher, Leaf};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MapId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{stored, versioned};
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const MAPS: [MapId; 2] = [
    MapId {
        instance: InstanceId(1),
        tag: 7,
        transform: Transform::Hashed,
    },
    MapId {
        instance: InstanceId(1),
        tag: 8,
        transform: Transform::Ordered,
    },
];
const KEYS: u64 = 2_000;
const WRITES: u64 = 250;
/// A build every this many versions, in batches of `BATCH` keys.
const BUILD_EVERY: u64 = 4;
const BATCH: usize = 64;
/// Twelve rounds, the last six tearing the journal before reopening.
const ROUNDS: Rounds = Rounds {
    kill_within: Duration::from_millis(30),
    ..Rounds::twelve("VOS_TREE_CRASH_WRITER", "", 12)
};
/// At most this many bytes of the journal are torn: less than a build's
/// batch, so a tear reaches at most the last apply.
const TEAR: u64 = 4096;

fn seed(version: u64) -> [u8; 32] {
    Blake2b.hash(b"tree crash seed", &[&version.to_le_bytes()])
}

/// Version `version`'s committed writes: a raw key in a map, and a value
/// or a deletion.
fn writes(version: u64) -> Vec<(MapId, Vec<u8>, Option<Vec<u8>>)> {
    (0..WRITES)
        .map(|index| {
            let slot = (version * 7919 + index * 31) % KEYS;
            let value = (!(version + index).is_multiple_of(9)).then(|| version.encode());
            (
                MAPS[(slot % 2) as usize],
                slot.to_be_bytes().to_vec(),
                value,
            )
        })
        .collect()
}

/// The rows accumulate leaves for `version`'s writes.
fn rows(version: u64) -> Vec<Write> {
    let mut rows = Vec::new();
    for (map, key, value) in writes(version) {
        let row = keys::committed(&map, &map.transform.apply(&key));
        rows.push(Write {
            key: keys::dirty(version, &row),
            value: Some(stored(&[])),
        });
        rows.push(Write {
            key: row,
            value: value.map(|value| stored(&versioned(version, &value))),
        });
    }
    rows.push(Write {
        key: keys::seed(version),
        value: Some(stored(&seed(version))),
    });
    rows.push(Write {
        key: keys::version(),
        value: Some(stored(&version.encode())),
    });
    rows
}

/// Build the roots to the end, a small batch at a time.
fn build(store: &Fjall, writer: &StorageThread) {
    if let Some(build) = Build::start(store, AGENT).unwrap() {
        let mut build = build.in_batches_of(BATCH);
        while let Some(change) = build.next_batch().unwrap() {
            smol::block_on(writer.commit(vec![change])).unwrap();
        }
    }
}

fn writer(dir: &Path) {
    let store = Fjall::open(dir).unwrap();
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    let mut version = store.snapshot().applied(AGENT).unwrap().unwrap_or(0);
    loop {
        version += 1;
        let apply = Change::Apply {
            agent: AGENT,
            epoch: 0,
            index: version,
            writes: rows(version),
        };
        smol::block_on(writer.commit(vec![apply])).unwrap();
        println!("{version}");
        if version.is_multiple_of(BUILD_EVERY) {
            build(&store, &writer);
        }
    }
}

/// A map's values, by their committed rows' keys: each value and the
/// version that wrote it.
type Values = BTreeMap<Vec<u8>, (u64, Vec<u8>)>;

/// Each map's values at `version`.
fn values(version: u64) -> BTreeMap<MapId, Values> {
    let mut values: BTreeMap<MapId, Values> = BTreeMap::new();
    for at in 1..=version {
        for (map, key, value) in writes(at) {
            let held = values.entry(map).or_default();
            let key = keys::committed(&map, &map.transform.apply(&key));
            match value {
                Some(value) => held.insert(key, (at, value)),
                None => held.remove(&key),
            };
        }
    }
    values
}

fn main() {
    let mut last = 0;
    let mut cut = 0;
    ROUNDS.run(writer, journal(TEAR), |round| {
        cut += usize::from(check(round, &mut last))
    });
    assert!(cut > 0, "no round was killed between a build's batches");
    println!(
        "tree crash: {} rounds resumed to the root from scratch, {cut} of them cut mid-build",
        ROUNDS.rounds
    );
}

/// Check a round, and say whether it was cut between a build's batches.
fn check(round: Round, last: &mut u64) -> bool {
    let reported = round.reported.unwrap_or(*last);
    let (floor, how) = (round.floor(reported, 1), round.how());
    let Round {
        number: round, dir, ..
    } = round;
    let store = Fjall::open(dir).unwrap();
    let version = store.snapshot().applied(AGENT).unwrap().unwrap_or(0);
    assert!(
        version >= floor,
        "round {round}: at {version}, but {reported} was reported applied"
    );
    let before = store.snapshot();
    let cut = matches!(
        roots::agent_root(&before, AGENT),
        Err(roots::Error::Building)
    );
    drop(before);
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    build(&store, &writer);
    let snapshot = store.snapshot();
    let expected = values(version);
    // A round killed before its first apply recovers at version 0, with no
    // values in either map.
    let leaves = |of: Option<MapId>| -> Vec<(Vec<u8>, Hash)> {
        let mut leaves: Vec<(Vec<u8>, Hash)> = expected
            .iter()
            .filter(|(map, _)| of.is_none_or(|of| of == **map))
            .flat_map(|(_, values)| values)
            .map(|(key, (at, value))| {
                let leaf = Leaf::salted(&Blake2b, &seed(*at), key, value);
                (key.clone(), leaf.value_hash)
            })
            .collect();
        leaves.sort();
        leaves
    };
    assert_eq!(
        roots::agent_root(&snapshot, AGENT).unwrap(),
        (vos_tree::root(&Blake2b, &leaves(None)), version),
        "round {round}: the agent's root"
    );
    for map in MAPS {
        assert_eq!(
            roots::root(&snapshot, AGENT, &map).unwrap(),
            (vos_tree::root(&Blake2b, &leaves(Some(map))), version),
            "round {round}: the root of {map:?}"
        );
    }
    assert!(
        roots::rows_match_tree(&snapshot, AGENT).unwrap(),
        "round {round}: rows off the tree"
    );
    for prefix in [keys::dirty_prefix(), keys::seed_prefix()] {
        assert!(
            snapshot.scan(AGENT, &prefix, None).next().is_none(),
            "round {round}: dirty or seed rows left"
        );
    }
    let mid = if cut { ", mid-build" } else { "" };
    println!("round {round}: {how} after {reported}{mid}, resumed at {version}");
    *last = version;
    cut
}
