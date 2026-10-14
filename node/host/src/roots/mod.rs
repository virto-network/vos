//! Committed maps' roots: each map's tree, kept as rows beside its value
//! rows, built in the background from the dirty rows accumulate leaves, and
//! the proofs it serves.
//!
//! A [`Build`] runs at the agent's state version V, from one store snapshot
//! at V, over every version past the last complete build's, W. It reads
//! the dirty rows of those versions in batches of at most [`BATCH`] keys,
//! and gives each key's leaf the value its row holds at V, salted from the
//! seed of the version that wrote it. Each batch rewrites its keys' paths,
//! map by map, with [`vos_tree::update`], reading the trees' rows from a
//! newer snapshot (only builds write them), and deletes the dirty rows it
//! read and the seeds of the versions whose rows it has all read. It is
//! one [`Change::Tree`], which the writer refuses once the agent's epoch
//! has moved. The last batch writes each map's root at V and moves W to V.
//! No build holds, or commits, more than a batch's worth of rows, however
//! far behind it starts.
//!
//! One invariant carries correctness: every tree row whose subtree holds no
//! dirty key matches the value rows at the version the build reads. A batch
//! rewrites its keys' paths from those values before it deletes their dirty
//! rows, in one commit, and a row above them that a later batch's key also
//! reaches stays under that key until its own batch; so a build cut short,
//! by a crash or a moved epoch, leaves every row it wrote either matching or
//! under a key still dirty, and the next build, at a later version, rewrites
//! what changed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use vos_tree::{
    BatchProof, Blake2b, Child, Hash, Leaf, Node, NodeStore, empty_root, salt, value_hash,
};
use vos_wire::ids::{AgentId, MapId};
use vos_wire::keys;
use vos_wire::records::{unstored, unversioned};
use vos_wire::result::Write;
use vos_wire::{Decode, Encode, scale};

use crate::group::Shared;
use crate::node::Inner;
use crate::storage::Change;
use crate::store::{Fjall, Snapshot};

/// The most distinct keys one batch rebuilds.
pub const BATCH: usize = 10_000;

/// The most dirty rows one batch reads, per key it may rebuild: a key
/// written at many versions has a row for each.
const ROWS_PER_KEY: usize = 4;

/// Why a build or a proof stopped.
#[derive(Debug)]
pub enum Error {
    Store(fjall::Error),
    Tree(vos_tree::Error),
    /// A row accumulate or a build wrote does not read back.
    Corrupt(&'static str),
    /// The agent's epoch moved under the build: a snapshot was installed,
    /// or the agent retired.
    Moved,
    /// The map's tree is part-way through a build: its rows match no root
    /// until the build's last batch.
    Building,
    /// The node could not run or commit a batch.
    Halted(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Store(error) => write!(f, "the store failed: {error}"),
            Error::Tree(error) => write!(f, "the tree refused: {error}"),
            Error::Corrupt(what) => write!(f, "{what} does not read back"),
            Error::Moved => f.write_str("the agent's epoch moved"),
            Error::Building => f.write_str("the map's tree is part-way through a build"),
            Error::Halted(why) => write!(f, "the build stopped: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error)
    }
}

impl From<vos_tree::Error> for Error {
    fn from(error: vos_tree::Error) -> Self {
        Error::Tree(error)
    }
}

/// A map's root row: the tree's top, and the root its last complete build
/// left. Between a build's batches the top has moved on and the root has
/// not.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RootRow {
    pub top: Option<Child>,
    pub root: Hash,
}

impl RootRow {
    /// The row a complete build leaves: its root the top's.
    fn complete(top: Option<Child>) -> Self {
        let root = top
            .as_ref()
            .map_or_else(|| empty_root(&Blake2b), |top| *top.hash());
        Self { top, root }
    }

    /// Whether a build is part-way through the tree.
    fn building(&self) -> bool {
        *self != Self::complete(self.top.clone())
    }
}

/// A map's root row, as `snapshot` holds it.
pub fn root_row(
    snapshot: &Snapshot,
    agent: AgentId,
    map: &MapId,
) -> Result<Option<RootRow>, Error> {
    let Some(bytes) = snapshot.get(agent, &keys::tree_root(map))? else {
        return Ok(None);
    };
    match RootRow::decode(&bytes) {
        Ok((row, used)) if used == bytes.len() => Ok(Some(row)),
        _ => Err(Error::Corrupt("a root row")),
    }
}

/// A map's root and the state version it holds, as `snapshot` has them:
/// the agent's version when none of the map's writes waits for a build,
/// else the last complete build's.
pub fn root(snapshot: &Snapshot, agent: AgentId, map: &MapId) -> Result<(Hash, u64), Error> {
    let root = match root_row(snapshot, agent, map)? {
        Some(row) if row.building() => return Err(Error::Building),
        Some(row) => row.root,
        None => empty_root(&Blake2b),
    };
    let built = built(snapshot, agent)?;
    // The writes past the last complete build, a batch's worth at most:
    // past that, the map is taken to have some among them.
    let (prefix, after) = (keys::dirty_prefix(), keys::dirty_from(built + 1));
    let mut pending = snapshot.scan(agent, &prefix, Some(&after)).take(BATCH);
    let mut scanned = 0;
    let waits = loop {
        match pending.next().transpose()? {
            None => break scanned == BATCH,
            Some((key, _)) => {
                scanned += 1;
                let (_, of, _) = keys::dirty_entry(&key).ok_or(Error::Corrupt("a dirty row"))?;
                if of == *map {
                    break true;
                }
            }
        }
    };
    let version = match waits {
        true => built,
        false => state_version(snapshot, agent)?,
    };
    Ok((root, version))
}

/// The version every map's tree is built through.
fn built(snapshot: &Snapshot, agent: AgentId) -> Result<u64, Error> {
    match snapshot.get(agent, &keys::built())? {
        Some(bytes) => match u64::decode(&bytes) {
            Ok((version, 8)) => Ok(version),
            _ => Err(Error::Corrupt("the built version")),
        },
        None => Ok(0),
    }
}

/// The agent's state version.
fn state_version(snapshot: &Snapshot, agent: AgentId) -> Result<u64, Error> {
    match snapshot.get(agent, &keys::version())? {
        Some(bytes) => unstored(&bytes)
            .and_then(|value| u64::decode(value).ok())
            .map(|(version, _)| version)
            .ok_or(Error::Corrupt("the state version")),
        None => Ok(0),
    }
}

/// Whether a map's stored node and leaf rows are exactly those its tree
/// reaches from its top.
#[doc(hidden)]
pub fn rows_match_tree(snapshot: &Snapshot, agent: AgentId, map: MapId) -> Result<bool, Error> {
    let tree = MapStore::open(snapshot, agent, map)?;
    let reached = vos_tree::reachable(&tree)?;
    let stored = |prefix: Vec<u8>| -> Result<BTreeSet<Vec<u8>>, Error> {
        snapshot
            .scan(agent, &prefix, None)
            .map(|row| Ok(row?.0[prefix.len()..].to_vec()))
            .collect()
    };
    let nodes: BTreeSet<Vec<u8>> = reached
        .nodes
        .iter()
        .map(|(level, prefix)| [&level.to_be_bytes()[..], prefix].concat())
        .collect();
    let leaves: BTreeSet<Vec<u8>> = reached.leaves.into_iter().collect();
    Ok(stored(keys::tree_nodes(&map))? == nodes && stored(keys::tree_leaves(&map))? == leaves)
}

/// A committed map's latest root, the state version it holds, and a proof
/// of some keys against it.
#[derive(Clone, Debug)]
pub struct Proven {
    pub root: Hash,
    pub version: u64,
    pub proof: BatchProof,
    /// Each key asked for: its key in the tree (transformed), and its leaf
    /// at `version` when present, whose salt opens the value's commitment.
    pub leaves: Vec<(Vec<u8>, Option<Leaf>)>,
}

/// The proof of `keys`, raw as the map's handler wrote them, from one
/// storage snapshot.
pub fn prove<K: AsRef<[u8]>>(
    snapshot: &Snapshot,
    agent: AgentId,
    map: MapId,
    keys: &[K],
) -> Result<Proven, Error> {
    let (root, version) = root(snapshot, agent, &map)?;
    let store = MapStore::open(snapshot, agent, map)?;
    let transformed: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| map.transform.apply(key.as_ref()))
        .collect();
    let proof = BatchProof::generate(&store, &transformed)?;
    let leaves = transformed
        .into_iter()
        .map(|key| {
            let leaf = store.leaf(&key)?;
            Ok((key, leaf))
        })
        .collect::<Result<_, Error>>()?;
    Ok(Proven {
        root,
        version,
        proof,
        leaves,
    })
}

/// One map's tree over a store snapshot: reads from the snapshot, writes
/// gathered for one commit. [`vos_tree::update`] reads every row it needs
/// before it writes any, so the snapshot never lags the writes.
pub struct MapStore<'a> {
    snapshot: &'a Snapshot,
    agent: AgentId,
    map: MapId,
    top: Option<Child>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> MapStore<'a> {
    pub fn open(snapshot: &'a Snapshot, agent: AgentId, map: MapId) -> Result<Self, Error> {
        let top = root_row(snapshot, agent, &map)?.and_then(|row| row.top);
        Ok(Self::new(snapshot, agent, map, top))
    }

    fn new(snapshot: &'a Snapshot, agent: AgentId, map: MapId, top: Option<Child>) -> Self {
        Self {
            snapshot,
            agent,
            map,
            top,
            writes: BTreeMap::new(),
        }
    }

    fn read<T: Decode>(&self, key: &[u8], what: &'static str) -> Result<Option<T>, Error> {
        let Some(bytes) = self.snapshot.get(self.agent, key)? else {
            return Ok(None);
        };
        match T::decode(&bytes) {
            Ok((value, used)) if used == bytes.len() => Ok(Some(value)),
            _ => Err(Error::Corrupt(what)),
        }
    }
}

impl NodeStore for MapStore<'_> {
    type Error = Error;

    fn top(&self) -> Result<Option<Child>, Error> {
        Ok(self.top.clone())
    }

    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Error> {
        self.read(&keys::tree_node(&self.map, level, prefix), "a node row")
    }

    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Error> {
        self.read(&keys::tree_leaf(&self.map, key), "a leaf row")
    }

    fn set_top(&mut self, top: Option<Child>) -> Result<(), Error> {
        self.top = top;
        Ok(())
    }

    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Error> {
        let key = keys::tree_node(&self.map, level, prefix);
        self.writes.insert(key, Some(node.encode()));
        Ok(())
    }

    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Error> {
        self.writes
            .insert(keys::tree_node(&self.map, level, prefix), None);
        Ok(())
    }

    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Error> {
        let key = keys::tree_leaf(&self.map, key);
        self.writes.insert(key, Some(leaf.encode()));
        Ok(())
    }

    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Error> {
        self.writes.insert(keys::tree_leaf(&self.map, key), None);
        Ok(())
    }
}

/// Keys to rebuild, by map, each map's sorted.
type Keys = BTreeMap<MapId, Vec<Vec<u8>>>;

/// A build of an agent's roots at its state version, a batch at a time.
pub struct Build {
    store: Fjall,
    agent: AgentId,
    epoch: u8,
    version: u64,
    /// The agent's state at `version`.
    at: Snapshot,
    batch: usize,
    /// The last dirty row read.
    cursor: Vec<u8>,
    /// The seeds through this version are deleted.
    seeds_through: u64,
    /// How many dirty rows were read.
    read: u64,
    /// Each map the build touched, with its tree's top as last written.
    tops: BTreeMap<MapId, Option<Child>>,
    done: bool,
}

impl Build {
    /// A build of `agent`'s roots at the state version `store` holds now,
    /// or `None` when no write waits for one.
    pub fn start(store: &Fjall, agent: AgentId) -> Result<Option<Self>, Error> {
        let at = store.snapshot();
        let from = built(&at, agent)?;
        let pending = |prefix: Vec<u8>, after: Vec<u8>| -> Result<bool, Error> {
            Ok(at
                .scan(agent, &prefix, Some(&after))
                .next()
                .transpose()?
                .is_some())
        };
        if !pending(keys::dirty_prefix(), keys::dirty_from(from + 1))?
            && !pending(keys::seed_prefix(), keys::seed(from))?
        {
            return Ok(None);
        }
        Ok(Some(Self {
            store: store.clone(),
            agent,
            epoch: at.epoch(agent)?,
            version: state_version(&at, agent)?,
            at,
            batch: BATCH,
            cursor: keys::dirty_from(from + 1),
            seeds_through: from,
            read: 0,
            tops: BTreeMap::new(),
            done: false,
        }))
    }

    /// Build in batches of at most `keys` keys instead of [`BATCH`].
    #[doc(hidden)]
    pub fn in_batches_of(mut self, keys: usize) -> Self {
        self.batch = keys.max(1);
        self
    }

    /// The state version the build is at.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The agent's epoch the build reads and writes.
    pub fn epoch(&self) -> u8 {
        self.epoch
    }

    /// The dirty rows the build has read.
    pub fn dirty_read(&self) -> u64 {
        self.read
    }

    /// The next batch's commit, or `None` once the build is done.
    pub fn next_batch(&mut self) -> Result<Option<Change>, Error> {
        if self.done {
            return Ok(None);
        }
        let (batch, rows, last) = self.read_batch()?;
        let fresh = self.store.snapshot();
        if fresh.epoch(self.agent)? != self.epoch {
            return Err(Error::Moved);
        }
        let mut seeds = HashMap::new();
        let mut writes = BTreeMap::new();
        for (map, keys) in batch {
            let before = root_row(&fresh, self.agent, &map)?;
            let top = before.as_ref().and_then(|row| row.top.clone());
            let mut tree = MapStore::new(&fresh, self.agent, map, top);
            let leaves = keys
                .into_iter()
                .map(|key| {
                    let leaf = self.leaf(&mut seeds, &map, &key)?;
                    Ok((key, leaf))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            vos_tree::update(&Blake2b, &mut tree, &leaves)?;
            // Until the last batch, the root stays the last complete build's.
            let root = before.map_or_else(|| empty_root(&Blake2b), |row| row.root);
            let row = RootRow {
                top: tree.top.clone(),
                root,
            };
            writes.extend(tree.writes);
            writes.insert(keys::tree_root(&map), Some(row.encode()));
            self.tops.insert(map, tree.top);
        }
        writes.extend(rows.into_iter().map(|row| (row, None)));
        // The seeds of the versions whose dirty rows are all read. A batch
        // before the last keeps its cursor version's seed even once that
        // version's rows are read: an interrupted build then always leaves
        // a seed past the watermark, so the next build starts and finishes
        // the maps it left part-way.
        let through = match last {
            true => self.version,
            false => {
                let (version, _, _) =
                    keys::dirty_entry(&self.cursor).ok_or(Error::Corrupt("a dirty row"))?;
                version.saturating_sub(1)
            }
        };
        let after = keys::seed(self.seeds_through);
        for row in self.at.scan(self.agent, &keys::seed_prefix(), Some(&after)) {
            let (key, _) = row?;
            if key > keys::seed(through) {
                break;
            }
            writes.insert(key, None);
        }
        self.seeds_through = self.seeds_through.max(through);
        if last {
            self.finish(&fresh, &mut writes)?;
        }
        Ok(Some(Change::Tree {
            agent: self.agent,
            epoch: self.epoch,
            writes: writes
                .into_iter()
                .map(|(key, value)| Write { key, value })
                .collect(),
        }))
    }

    /// The last batch's root rows, each complete at the build's version:
    /// every map the build touched, and every map an earlier build cut
    /// short left part-way, which has no write past it, or this build would
    /// have touched it. Then the version every tree is built through.
    fn finish(
        &mut self,
        fresh: &Snapshot,
        writes: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<(), Error> {
        for row in fresh.scan(self.agent, &keys::tree_roots(), None) {
            let (key, _) = row?;
            let map = keys::tree_root_entry(&key).ok_or(Error::Corrupt("a root row"))?;
            if let Some(row) = root_row(fresh, self.agent, &map)?
                && row.building()
            {
                self.tops.entry(map).or_insert(row.top);
            }
        }
        for (map, top) in core::mem::take(&mut self.tops) {
            let row = RootRow::complete(top);
            writes.insert(keys::tree_root(&map), Some(row.encode()));
        }
        writes.insert(keys::built(), Some(self.version.encode()));
        self.done = true;
        Ok(())
    }

    /// The next keys to rebuild, by map and sorted, and the dirty rows read
    /// for them: rows read until `batch` keys, or as many rows as
    /// [`ROWS_PER_KEY`] allows them, or none remain; and whether none
    /// remains.
    fn read_batch(&mut self) -> Result<(Keys, Vec<Vec<u8>>, bool), Error> {
        let mut batch: BTreeMap<MapId, BTreeSet<Vec<u8>>> = BTreeMap::new();
        let mut found = 0;
        let mut rows = Vec::new();
        let prefix = keys::dirty_prefix();
        let after = self.cursor.clone();
        let mut scan = self.at.scan(self.agent, &prefix, Some(&after));
        let last = loop {
            if found == self.batch || rows.len() == self.batch * ROWS_PER_KEY {
                break scan.next().is_none();
            }
            let Some(row) = scan.next() else {
                break true;
            };
            let (row, _) = row?;
            let (_, map, key) = keys::dirty_entry(&row).ok_or(Error::Corrupt("a dirty row"))?;
            if batch.entry(map).or_default().insert(key.to_vec()) {
                found += 1;
            }
            self.cursor.clone_from(&row);
            rows.push(row);
        };
        self.read += rows.len() as u64;
        let batch = batch
            .into_iter()
            .map(|(map, keys)| (map, keys.into_iter().collect()))
            .collect();
        Ok((batch, rows, last))
    }

    /// The leaf of `key` at the build's version: its value's commitment
    /// under the salt of the version that wrote it, or `None` if deleted.
    fn leaf(
        &self,
        seeds: &mut HashMap<u64, [u8; 32]>,
        map: &MapId,
        key: &[u8],
    ) -> Result<Option<Leaf>, Error> {
        let Some(bytes) = self.at.get(self.agent, &keys::committed(map, key))? else {
            return Ok(None);
        };
        let (version, value) = unstored(&bytes)
            .and_then(unversioned)
            .ok_or(Error::Corrupt("a value row"))?;
        let seed = match seeds.get(&version) {
            Some(seed) => *seed,
            None => {
                let seed: [u8; 32] = self
                    .at
                    .get(self.agent, &keys::seed(version))?
                    .and_then(|bytes| unstored(&bytes)?.try_into().ok())
                    .ok_or(Error::Corrupt("a seed row"))?;
                *seeds.entry(version).or_insert(seed)
            }
        };
        let salt = salt(&Blake2b, &seed, key);
        Ok(Some(Leaf {
            salt,
            value_hash: value_hash(&Blake2b, &salt, value),
        }))
    }
}

/// The first wait before a failed build is tried again, doubled each time
/// up to [`MAX_BACKOFF`].
const BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Build `shared`'s agent's roots after its applies that leave dirty rows,
/// until its group stops: one build at a time, each at the latest state
/// version, so builds coalesce the applies made meanwhile. The batches run
/// on the executors, off the apply path. The first build runs at once,
/// catching up after a restart. A build that fails, on a store error or a
/// row that does not read back, is tried again after a backoff: building
/// pauses until it succeeds.
pub(crate) async fn build(inner: Arc<Inner>, shared: Arc<Shared>) {
    let agent = shared.agent;
    let mut seen = None;
    let mut backoff = BACKOFF;
    // A build is due whatever the writer says: at the start, and after one
    // failed.
    let mut due = true;
    loop {
        let state = shared
            .wait(|state| state.stopped || due || Some(state.applied) != seen)
            .await;
        if state.stopped {
            return;
        }
        seen = Some(state.applied);
        if !inner.storage.take_dirtied(agent) && !std::mem::take(&mut due) {
            continue;
        }
        match run(&inner, &shared).await {
            Ok(()) => backoff = BACKOFF,
            // The new epoch's switch marks it dirty, and its state wakes
            // the next build.
            Err(Error::Moved) => {}
            Err(error) => {
                tracing::warn!(
                    agent = agent.0,
                    "a root build failed ({error}); trying again in {backoff:?}"
                );
                crate::timeout(backoff, shared.wait(|state| state.stopped)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                due = true;
            }
        }
    }
}

async fn run(inner: &Inner, shared: &Shared) -> Result<(), Error> {
    let agent = shared.agent;
    let Some(mut build) = Build::start(&inner.store, agent)? else {
        return Ok(());
    };
    while !shared.state().stopped {
        let (returned, change) = inner
            .offload(move || {
                let change = build.next_batch();
                (build, change)
            })
            .await
            .ok_or_else(|| Error::Halted("the executors stopped".into()))?;
        build = returned;
        let Some(change) = change? else {
            return Ok(());
        };
        if let Err(refusal) = inner.storage.commit(vec![change]).await {
            return Err(match inner.store.snapshot().epoch(agent) {
                Ok(epoch) if epoch != build.epoch() => Error::Moved,
                _ => Error::Halted(refusal),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
