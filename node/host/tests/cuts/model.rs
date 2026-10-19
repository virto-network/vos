//! An agent in a space on the node's store, driven a work result at a time
//! as a replica applies them, beside a model of what it must hold.
//!
//! A result is applied as the node applies one: accumulate's writes, made
//! here by the agent's own apply ([`vos_wire::apply`]) over the store's
//! snapshot, and the node-local rows the node's apply commits beside them
//! ([`roots::undo`]), in one commit. Builds run as the node's builder runs
//! them, one after another, each to its end, in batches of a few keys.
//!
//! The model's terms, which every cut test speaks:
//! - **the cut** of window w, `cut(w)`: the state version before the first
//!   result applied with a time at or past `B_w`, the window's boundary.
//!   A result timed t, applied after one timed p (the agent's batch-time
//!   mark), records `cut(w)` = its version − 1 for every w with
//!   p < `B_w` ≤ t, once the agent's record names a space, at most the
//!   newest `MAX_CUTS` of them;
//! - **the cut's build**: the build whose target is `cut(w)`; it is done
//!   once the replica holds the agent's root at `cut(w)`
//!   ([`roots::cut_root`]), the root over the committed values the agent
//!   held at `cut(w)`;
//! - **the proofs**: for each pending request of window w
//!   ([`keys::request`]), the rows it reads as they stood at `cut(w)`, each
//!   with its leaf's salt, and one batch proof of them against the root at
//!   `cut(w)` ([`roots::cut_proof`]), persisted by every replica in the
//!   commit that marks the cut built.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use vos_node::NoHooks;
use vos_node::roots::{self, Build, CutProof, ReadRow};
use vos_node::storage::{Change, StorageThread};
use vos_node::store::{Fjall, Snapshot};
use vos_tree::{Blake2b, Hash, Hasher, Leaf, value_hash};
use vos_wire::abi::cap::Target;
use vos_wire::apply::{Host, State, apply};
use vos_wire::defaults::MAX_CUTS;
use vos_wire::ids::{AgentId, InstanceId, MapId, RequestId, WorkflowId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{PendingRead, unstored};
use vos_wire::result::{CommittedWrite, InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

pub const AGENT: AgentId = AgentId(1);
/// The instance whose committed maps the results write and the requests
/// read.
pub const READER: InstanceId = InstanceId(1);
pub const MAPS: [MapId; 2] = [
    MapId {
        instance: READER,
        tag: 7,
        transform: Transform::Hashed,
    },
    MapId {
        instance: READER,
        tag: 8,
        transform: Transform::Ordered,
    },
];
pub const SPACE: SpaceId = SpaceId([0x5a; 32]);
/// Windows of a second from time zero: the results' times are the model's
/// own, never a clock's.
pub const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 1_000,
};

/// The seed of the result that makes `version`.
pub fn seed(version: u64) -> [u8; 32] {
    Blake2b.hash(b"cuts seed", &[&version.to_le_bytes()])
}

/// The full key of the committed row of `key` in `map`.
pub fn row(map: MapId, key: &[u8]) -> Vec<u8> {
    keys::committed(&map, &map.transform.apply(key))
}

/// A committed write: a map, a raw key, and a value or a deletion.
pub type Committed = (MapId, Vec<u8>, Option<Vec<u8>>);

/// A request of `rows` by the workflow numbered `workflow`, its first
/// await.
pub fn pending(workflow: u64, rows: Vec<Vec<u8>>) -> (RequestId, PendingRead) {
    let mut rows = rows;
    rows.sort();
    rows.dedup();
    (
        RequestId {
            workflow: WorkflowId(workflow),
            awaits: 0,
        },
        PendingRead {
            instance: READER,
            rows,
        },
    )
}

/// What the model applies: a result's time, its committed writes, its
/// other writes, and the request it records, if any, in the window of its
/// time.
#[derive(Clone, Default)]
pub struct Entry {
    pub time: u64,
    pub committed: Vec<Committed>,
    pub writes: Vec<Write>,
    pub request: Option<(RequestId, PendingRead)>,
}

impl Entry {
    /// The first install's record of an agent in `space`: its target, its
    /// space and its clock, at `time`.
    pub fn install(time: u64, space: SpaceId) -> Self {
        let write = |key: Vec<u8>, value: Vec<u8>| Write {
            key,
            value: Some(value),
        };
        Self {
            time,
            writes: vec![
                write(keys::target(), Target::Vos.encode()),
                write(keys::space(), space.encode()),
                write(keys::clock(), CLOCK.encode()),
            ],
            ..Self::default()
        }
    }

    pub fn at(time: u64, committed: Vec<Committed>) -> Self {
        Self {
            time,
            committed,
            ..Self::default()
        }
    }

    /// The work result of this entry at state version `version`, as a
    /// refine at `version` would make it: one step, an operator's.
    pub fn result(&self, version: u64) -> WorkResult {
        let mut writes = self.writes.clone();
        if let Some((id, read)) = &self.request {
            let window = CLOCK.window(self.time).expect("a time in a window");
            writes.push(Write {
                key: keys::request(window, *id),
                value: Some(read.encode()),
            });
        }
        let committed = self
            .committed
            .iter()
            .map(|(map, key, value)| CommittedWrite {
                map: *map,
                key: map.transform.apply(key),
                value: value.clone(),
            })
            .collect();
        WorkResult {
            version,
            time: self.time,
            seed: seed(version + 1),
            steps: vec![Step::Ran(Run {
                input: InputRef::Admin,
                outcome: Outcome::Done(Vec::new()),
                instances: Vec::new(),
                writes,
                committed,
                messages: Vec::new(),
                attests: Vec::new(),
                pages: Vec::new(),
                gas_used: 0,
            })],
        }
    }
}

/// The agent's rows as its apply reads them: the snapshot's, under the
/// writes made so far.
struct Overlay<'a> {
    snapshot: &'a Snapshot,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl State for Overlay<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        match self.writes.get(key) {
            Some(value) => value.clone(),
            None => self.snapshot.get(AGENT, key).unwrap(),
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.writes.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}

/// One replica's store of the agent, and its writer.
pub struct Replica {
    pub store: Fjall,
    pub writer: StorageThread,
}

impl Replica {
    pub fn open(dir: &Path) -> Self {
        let store = Fjall::open(dir).unwrap();
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        Self { store, writer }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.store.snapshot()
    }

    /// The agent's state version.
    pub fn version(&self) -> u64 {
        value(&self.snapshot(), &keys::version()).unwrap_or(0)
    }

    /// Apply `result` at log index `index` as the node does: the agent's
    /// apply over the applied state, and the node's undo rows beside its
    /// writes, in one commit. Whether it applied.
    pub fn apply(&self, index: u64, result: &WorkResult) -> bool {
        let (snapshot, mut writes, applied) = self.accumulate(result);
        if applied {
            let undo = roots::undo(&snapshot, AGENT, &writes).unwrap();
            for row in &undo {
                assert!(
                    row.key.starts_with(&keys::undo_prefix()),
                    "the node's apply writes its undo rows alone"
                );
            }
            writes.extend(undo);
        }
        self.commit(index, writes);
        applied
    }

    /// The writes the agent's apply makes of `result` on the applied
    /// state, the snapshot it read, and whether it applied.
    pub fn accumulate(&self, result: &WorkResult) -> (Snapshot, Vec<Write>, bool) {
        let snapshot = self.snapshot();
        let mut overlay = Overlay {
            snapshot: &snapshot,
            writes: BTreeMap::new(),
        };
        let applied = apply(&mut overlay, result, Host::Vos { pages: &[] });
        let writes = overlay
            .writes
            .into_iter()
            .map(|(key, value)| Write { key, value })
            .collect();
        (snapshot, writes, applied)
    }

    /// Commit `writes` as the apply at log index `index`.
    pub fn commit(&self, index: u64, writes: Vec<Write>) {
        let change = Change::Apply {
            agent: AGENT,
            epoch: 0,
            index,
            writes,
        };
        smol::block_on(self.writer.commit(vec![change])).unwrap();
    }

    /// One build, as the node's builder runs one, in batches of `batch`
    /// keys: the version it built at, or `None` when none was due.
    pub fn build(&self, batch: usize) -> Option<u64> {
        self.build_read(batch).map(|(version, _)| version)
    }

    /// One build, as [`Replica::build`] runs it: the version it built at,
    /// and the dirty rows it read.
    pub fn build_read(&self, batch: usize) -> Option<(u64, u64)> {
        let mut build = Build::start(&self.store, AGENT)
            .unwrap()?
            .in_batches_of(batch);
        let target = build.version();
        while let Some(change) = build.next_batch().unwrap() {
            smol::block_on(self.writer.commit(vec![change])).unwrap();
        }
        Some((target, build.dirty_read()))
    }

    /// Builds one after another until none is due: the version each built
    /// at.
    pub fn build_all(&self, batch: usize) -> Vec<u64> {
        let mut built = Vec::new();
        while let Some(version) = self.build(batch) {
            built.push(version);
            assert!(built.len() < 10_000, "builds never end: {built:?}");
        }
        built
    }
}

/// The value the agent stored under `key`, decoded.
pub fn value<T: Decode>(snapshot: &Snapshot, key: &[u8]) -> Option<T> {
    let bytes = snapshot.get(AGENT, key).unwrap()?;
    Some(T::decode_exact(unstored(&bytes).expect("a stored value")).expect("decodes"))
}

/// Every row under `prefix`.
pub fn scan(snapshot: &Snapshot, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    snapshot
        .scan(AGENT, prefix, None)
        .map(Result::unwrap)
        .collect()
}

/// The cuts the agent recorded: each window's cut version.
pub fn cuts(snapshot: &Snapshot) -> BTreeMap<u64, u64> {
    scan(snapshot, &keys::cuts())
        .into_iter()
        .map(|(key, bytes)| {
            let window = keys::cut_entry(&key).expect("a cut row");
            let version = u64::decode_exact(unstored(&bytes).unwrap()).unwrap();
            (window, version)
        })
        .collect()
}

/// The pending requests the agent holds: each request's window and read.
pub fn requests(snapshot: &Snapshot) -> BTreeMap<RequestId, (u64, PendingRead)> {
    scan(snapshot, &keys::request_prefix())
        .into_iter()
        .map(|(key, bytes)| {
            let (window, id) = keys::request_entry(&key).expect("a request row");
            let read = PendingRead::decode_exact(unstored(&bytes).unwrap()).unwrap();
            (id, (window, read))
        })
        .collect()
}

/// The undo rows the replica holds: by window and committed row, each the
/// row's stored bytes.
pub fn undos(snapshot: &Snapshot) -> BTreeMap<(u64, Vec<u8>), Vec<u8>> {
    let prefix = keys::undo_prefix();
    scan(snapshot, &prefix)
        .into_iter()
        .map(|(key, bytes)| {
            let rest = &key[prefix.len()..];
            let (window, row) = rest.split_first_chunk::<8>().expect("an undo row");
            ((u64::from_be_bytes(*window), row.to_vec()), bytes)
        })
        .collect()
}

/// The agent's replicated rows ([`keys::is_replicated`]).
pub fn replicated(snapshot: &Snapshot) -> Vec<(Vec<u8>, Vec<u8>)> {
    [[0x00u8], [0x01], [0x03]]
        .iter()
        .flat_map(|prefix| scan(snapshot, prefix))
        .filter(|(key, _)| keys::is_replicated(key))
        .collect()
}

/// What the agent applied, in order: the model every check compares with.
#[derive(Default)]
pub struct History {
    pub entries: Vec<Entry>,
}

impl History {
    /// Record `entry` as the next version's.
    pub fn push(&mut self, entry: Entry) {
        if let Some(last) = self.entries.last() {
            assert!(entry.time >= last.time, "results never go back in time");
        }
        self.entries.push(entry);
    }

    /// The latest version.
    pub fn version(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The time of `version`'s result.
    pub fn time(&self, version: u64) -> u64 {
        self.entries[version as usize - 1].time
    }

    /// The committed rows at `version`: each row's writing version and bare
    /// value.
    pub fn values(&self, version: u64) -> BTreeMap<Vec<u8>, (u64, Vec<u8>)> {
        let mut values = BTreeMap::new();
        for (at, entry) in (1..=version).zip(&self.entries) {
            for (map, key, value) in &entry.committed {
                let row = row(*map, key);
                match value {
                    Some(value) => values.insert(row, (at, value.clone())),
                    None => values.remove(&row),
                };
            }
        }
        values
    }

    /// The agent's root at `version`, from scratch.
    pub fn root(&self, version: u64) -> Hash {
        let leaves: Vec<(Vec<u8>, Hash)> = self
            .values(version)
            .into_iter()
            .map(|(row, (at, value))| {
                (
                    row.clone(),
                    Leaf::salted(&Blake2b, &seed(at), &row, &value).value_hash,
                )
            })
            .collect();
        vos_tree::root(&Blake2b, &leaves)
    }

    /// The cuts the agent must have recorded through `version`: each window
    /// whose boundary a result crossed, after the agent's record named a
    /// space, at the version before that result; of a result crossing more
    /// than `MAX_CUTS` boundaries, the newest `MAX_CUTS` alone.
    pub fn cuts(&self, version: u64) -> BTreeMap<u64, u64> {
        let mut cuts = BTreeMap::new();
        let mut spaced = false;
        let mut mark = 0;
        for (at, entry) in (1..=version).zip(&self.entries) {
            if spaced {
                let mut crossed = Vec::new();
                let mut window = CLOCK.window(mark).map_or(0, |window| window);
                while let Some(boundary) = CLOCK.boundary(window) {
                    if boundary > entry.time {
                        break;
                    }
                    if boundary > mark {
                        crossed.push(window);
                    }
                    window += 1;
                }
                let skipped = crossed.len().saturating_sub(MAX_CUTS as usize);
                for window in &crossed[skipped..] {
                    cuts.insert(*window, at - 1);
                }
            }
            spaced |= entry.writes.iter().any(|write| {
                write.key == keys::space() && write.value != Some(SpaceId::NONE.encode())
            });
            mark = mark.max(entry.time);
        }
        cuts
    }

    /// The requests recorded through `version`: each one's window and read.
    pub fn requests(&self, version: u64) -> BTreeMap<RequestId, (u64, PendingRead)> {
        (1..=version)
            .zip(&self.entries)
            .filter_map(|(_, entry)| {
                let (id, read) = entry.request.clone()?;
                Some((id, (CLOCK.window(entry.time).unwrap(), read)))
            })
            .collect()
    }

    /// The rows `read` names as they stood at `version`, each with its
    /// leaf's salt and bare value, `None` if absent.
    pub fn rows(&self, read: &PendingRead, version: u64) -> Vec<ReadRow> {
        let values = self.values(version);
        read.rows
            .iter()
            .map(|row| {
                let held = values.get(row).map(|(at, value)| {
                    (
                        Leaf::salted(&Blake2b, &seed(*at), row, value).salt,
                        value.clone(),
                    )
                });
                (row.clone(), held)
            })
            .collect()
    }
}

/// `proof` is the proof of `read` at window `window`'s cut, `cut`: its rows
/// the model's there, its root the model's, and its batch proof verifying
/// them against that root from its encoding.
pub fn check_proof(history: &History, proof: &CutProof, window: u64, cut: u64, read: &PendingRead) {
    assert_eq!(
        (proof.window, proof.version),
        (window, cut),
        "the proof's cut"
    );
    assert_eq!(proof.agent_root, history.root(cut), "the root at the cut");
    assert_eq!(proof.rows, history.rows(read, cut), "the rows at the cut");
    let claims: Vec<(Vec<u8>, Option<Hash>)> = proof
        .rows
        .iter()
        .map(|(row, held)| {
            let held = held
                .as_ref()
                .map(|(salt, value)| value_hash(&Blake2b, salt, value));
            (row.clone(), held)
        })
        .collect();
    vos_tree::verify_encoded(&Blake2b, &proof.rows_proof, &proof.agent_root, &claims)
        .expect("the rows' proof verifies against the root at the cut");
}
