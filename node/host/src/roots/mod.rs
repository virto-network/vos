//! The agent's root: one tree over its committed rows, the keys under
//! `0x03` ([`keys::committed`]), kept as rows beside them, built in the
//! background from the dirty rows accumulate leaves, and the proofs it
//! serves. A leaf commits its row's bare value, salted from the seed of the
//! version that wrote it and the row's whole key, as JAM's tree over the
//! whole keyspace commits it, so the agent's root is the node of JAM's tree
//! at `0x03`, and a committed map's root the node at the map's prefix, in
//! either tree ([`vos_tree::node_at`]).
//!
//! A [`Build`] runs at the agent's state version V, from one store snapshot
//! at V, over every version past the last complete build's, W. It reads
//! the dirty rows of those versions in batches of at most `BATCH` keys,
//! and gives each key's leaf the value its row holds at V, salted from the
//! seed of the version that wrote it. Each batch rewrites its keys' paths
//! with [`vos_tree::update`], reading the tree's rows from a newer snapshot
//! (only builds write them), and deletes the dirty rows it read and the
//! seeds of the versions whose rows it has all read. It is one
//! [`Change::Tree`](crate::storage::Change::Tree), which the writer refuses
//! once the agent's epoch has moved. The last batch writes the agent's root
//! at V and moves W to V. No build holds, or commits, more than a batch's
//! worth of rows, however far behind it starts.
//!
//! One invariant carries correctness: every tree row whose subtree holds no
//! dirty key matches the value rows at the version the build reads. A batch
//! rewrites its keys' paths from those values before it deletes their dirty
//! rows, in one commit, and a row above them that a later batch's key also
//! reaches stays under that key until its own batch; so a build cut short,
//! by a crash or a moved epoch, leaves every row it wrote either matching or
//! under a key still dirty, and the next build, at a later version, rewrites
//! what changed.
//!
//! In an agent of a space a build runs at the earliest window cut pending
//! instead, and the commit that finishes it keeps the root and the pending
//! requests' proofs there ([`cut_root`], [`cut_proof`]).

use std::collections::{BTreeMap, BTreeSet};

use vos_tree::{BatchProof, Blake2b, Child, Hash, Leaf, Node, NodeStore, empty_root, node_at};
use vos_wire::ids::{AgentId, MapId};
use vos_wire::keys;
use vos_wire::records::{unstored, unversioned};
use vos_wire::{Decode, Encode, scale};

use crate::store::Snapshot;

mod build;
mod cuts;

pub use build::Build;
pub(crate) use build::build;

pub use cuts::{
    CutProof, ReadRow, cut_proof, cut_proof_at, cut_root, latest_built, served_at, undo,
};
pub(crate) use cuts::{answered, closing_of, cut_roots, serving_windows};

/// The most distinct keys one batch rebuilds.
pub(crate) const BATCH: usize = 10_000;

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
    /// The tree is part-way through a build: its rows match no root until
    /// the build's last batch, and a map's match none while a write to it
    /// waits.
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
            Error::Building => f.write_str("the tree is part-way through a build"),
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

/// The agent's root row: the tree's top, and the root its last complete
/// build left. Between a build's batches the top has moved on and the root
/// has not.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct RootRow {
    pub(crate) top: Option<Child>,
    pub(crate) root: Hash,
}

impl RootRow {
    /// The row a complete build leaves: its root the top's.
    fn complete(top: Option<Child>) -> Self {
        let root = root_of(top.as_ref());
        Self { top, root }
    }

    /// Whether a build is part-way through the tree.
    fn building(&self) -> bool {
        *self != Self::complete(self.top.clone())
    }
}

/// `bytes`, when there are any, as exactly one `T`; `what` corrupt
/// otherwise.
fn decoded<T: Decode>(bytes: Option<Vec<u8>>, what: &'static str) -> Result<Option<T>, Error> {
    bytes
        .map(|bytes| T::decode_exact(&bytes).ok_or(Error::Corrupt(what)))
        .transpose()
}

/// A stored value row's version and value.
fn value_row(stored: &[u8]) -> Result<(u64, &[u8]), Error> {
    unstored(stored)
        .and_then(unversioned)
        .ok_or(Error::Corrupt("a value row"))
}

/// The root of the tree whose top is `top`: the empty tree's when none.
fn root_of(top: Option<&Child>) -> Hash {
    top.map_or_else(|| empty_root(&Blake2b), |top| *top.hash())
}

/// The agent's root row, as `snapshot` holds it.
pub(crate) fn root_row(snapshot: &Snapshot, agent: AgentId) -> Result<Option<RootRow>, Error> {
    decoded(snapshot.get(agent, &keys::tree_root())?, "a root row")
}

/// The agent's root, over its committed rows, and the state version it
/// holds, as `snapshot` has them: the agent's version when no committed
/// write waits for a build, else the last complete build's.
pub fn agent_root(snapshot: &Snapshot, agent: AgentId) -> Result<(Hash, u64), Error> {
    let root = match root_row(snapshot, agent)? {
        Some(row) if row.building() => return Err(Error::Building),
        Some(row) => row.root,
        None => empty_root(&Blake2b),
    };
    let built = built(snapshot, agent)?;
    let version = if waits(snapshot, agent, built, None)? {
        built
    } else {
        state_version(snapshot, agent)?
    };
    Ok((root, version))
}

/// A committed map's root, the node of the agent's tree at the map's
/// prefix, and the state version it holds, as `snapshot` has them.
pub fn root(snapshot: &Snapshot, agent: AgentId, map: &MapId) -> Result<(Hash, u64), Error> {
    let (top, version) = map_top(snapshot, agent, map)?;
    Ok((root_of(top.as_ref()), version))
}

/// The node at `map`'s prefix, `None` while the map is empty, and the
/// state version it holds: the agent's version when none of the map's
/// writes waits for a build, else the last complete build's. While a build
/// is part-way, a map none of whose writes waits is read from the tree's
/// top as it stands: every key of the map a build has taken was rebuilt
/// from its value at the build's version, which no later write changed.
/// One whose writes wait matches no root until the build ends.
fn map_top(
    snapshot: &Snapshot,
    agent: AgentId,
    map: &MapId,
) -> Result<(Option<Child>, u64), Error> {
    let row = root_row(snapshot, agent)?;
    let built = built(snapshot, agent)?;
    let waits = waits(snapshot, agent, built, Some(map))?;
    if waits && row.as_ref().is_some_and(RootRow::building) {
        return Err(Error::Building);
    }
    let tree = AgentStore::new(snapshot, agent, row.and_then(|row| row.top));
    let top = node_at(&tree, &keys::committed_rows(map))?;
    let version = if waits {
        built
    } else {
        state_version(snapshot, agent)?
    };
    Ok((top, version))
}

/// Whether a committed write past `built`, to `map` or (`None`) to any
/// map, waits for a build. Past a batch's worth of dirty rows, the map is
/// taken to have some among them.
fn waits(
    snapshot: &Snapshot,
    agent: AgentId,
    built: u64,
    map: Option<&MapId>,
) -> Result<bool, Error> {
    let rows = map.map_or_else(keys::committed_all, keys::committed_rows);
    let (prefix, after) = (keys::dirty_prefix(), keys::dirty_from(built + 1));
    let mut pending = snapshot.scan(agent, &prefix, Some(&after)).take(BATCH);
    let mut scanned = 0;
    loop {
        let Some((key, _)) = pending.next().transpose()? else {
            return Ok(scanned == BATCH);
        };
        scanned += 1;
        let (_, row) = keys::dirty_entry(&key).ok_or(Error::Corrupt("a dirty row"))?;
        if row.starts_with(&rows) {
            return Ok(true);
        }
    }
}

/// The version the agent's tree is built through.
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

/// Whether the agent's stored node and leaf rows are exactly those its tree
/// reaches from its top.
#[doc(hidden)]
pub fn rows_match_tree(snapshot: &Snapshot, agent: AgentId) -> Result<bool, Error> {
    let tree = AgentStore::open(snapshot, agent)?;
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
    Ok(stored(keys::tree_nodes())? == nodes && stored(keys::tree_leaves())? == leaves)
}

/// A committed map's latest root, the state version it holds, and a proof
/// of some keys against it.
#[derive(Clone, Debug)]
pub struct Proven {
    pub root: Hash,
    pub version: u64,
    pub proof: BatchProof,
    /// Each key asked for: its key in the tree, its committed row's
    /// ([`keys::committed`]), and its leaf at `version` when present, whose
    /// salt opens the value's commitment.
    pub leaves: Vec<(Vec<u8>, Option<Leaf>)>,
}

/// The proof of `keys`, raw as the map's handler wrote them, from one
/// storage snapshot, against the map's root: the node of the agent's tree
/// at its prefix.
pub(crate) fn prove<K: AsRef<[u8]>>(
    snapshot: &Snapshot,
    agent: AgentId,
    map: MapId,
    keys: &[K],
) -> Result<Proven, Error> {
    let (top, version) = map_top(snapshot, agent, &map)?;
    let root = root_of(top.as_ref());
    let store = AgentStore::new(snapshot, agent, top);
    let rows: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| keys::committed(&map, &map.transform.apply(key.as_ref())))
        .collect();
    let proof = BatchProof::generate(&store, &rows)?;
    let leaves = rows
        .into_iter()
        .map(|row| {
            let leaf = store.leaf(&row)?;
            Ok((row, leaf))
        })
        .collect::<Result<_, Error>>()?;
    Ok(Proven {
        root,
        version,
        proof,
        leaves,
    })
}

/// The agent's tree over a store snapshot, from a top: the tree's own, or
/// a node of it, a map's. Reads come from the snapshot, writes are gathered
/// for one commit. [`vos_tree::update`] reads every row it needs before it
/// writes any, so the snapshot never lags the writes.
pub struct AgentStore<'a> {
    snapshot: &'a Snapshot,
    agent: AgentId,
    top: Option<Child>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> AgentStore<'a> {
    /// The tree from the top its root row holds.
    pub fn open(snapshot: &'a Snapshot, agent: AgentId) -> Result<Self, Error> {
        let top = root_row(snapshot, agent)?.and_then(|row| row.top);
        Ok(Self::new(snapshot, agent, top))
    }

    /// The tree below `top`.
    pub fn new(snapshot: &'a Snapshot, agent: AgentId, top: Option<Child>) -> Self {
        Self {
            snapshot,
            agent,
            top,
            writes: BTreeMap::new(),
        }
    }

    /// A row as this store's writes leave it, else as the snapshot holds
    /// it.
    fn read<T: Decode>(&self, key: &[u8], what: &'static str) -> Result<Option<T>, Error> {
        let bytes = match self.writes.get(key) {
            Some(written) => written.clone(),
            None => self.snapshot.get(self.agent, key)?,
        };
        decoded(bytes, what)
    }
}

impl NodeStore for AgentStore<'_> {
    type Error = Error;

    fn top(&self) -> Result<Option<Child>, Error> {
        Ok(self.top.clone())
    }

    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Error> {
        self.read(&keys::tree_node(level, prefix), "a node row")
    }

    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Error> {
        self.read(&keys::tree_leaf(key), "a leaf row")
    }

    fn set_top(&mut self, top: Option<Child>) -> Result<(), Error> {
        self.top = top;
        Ok(())
    }

    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Error> {
        let key = keys::tree_node(level, prefix);
        self.writes.insert(key, Some(node.encode()));
        Ok(())
    }

    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Error> {
        self.writes.insert(keys::tree_node(level, prefix), None);
        Ok(())
    }

    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Error> {
        let key = keys::tree_leaf(key);
        self.writes.insert(key, Some(leaf.encode()));
        Ok(())
    }

    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Error> {
        self.writes.insert(keys::tree_leaf(key), None);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
