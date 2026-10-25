//! The agent's root built a batch at a time ([`Build`]), and the task that
//! keeps building it after its applies ([`build`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use vos_tree::{Blake2b, Child, Leaf, empty_root};
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::records::unstored;
use vos_wire::result::Write;
use vos_wire::{Encode, SpaceId, WindowClock};

use super::{
    AgentStore, BATCH, Error, ROWS_PER_KEY, RootRow, built, cuts, root_row, state_version,
};
use crate::Backoff;
use crate::group::Shared;
use crate::node::Inner;
use crate::storage::Change;
use crate::store::{Fjall, Snapshot};

/// Committed rows' keys to rebuild, sorted.
type Keys = BTreeSet<Vec<u8>>;

/// A build of the agent's root, a batch at a time: at its state version,
/// or at the earliest cut pending, whichever comes first.
pub struct Build {
    store: Fjall,
    agent: AgentId,
    epoch: u8,
    /// The version it builds at.
    version: u64,
    /// The cut it builds, when it builds one: at its version.
    cut: Option<cuts::Cut>,
    /// The agent's state, as the build started.
    at: Snapshot,
    batch: usize,
    /// The last dirty row read.
    cursor: Vec<u8>,
    /// Where the dirty rows past `version` start.
    bound: Vec<u8>,
    /// The seeds through this version are deleted.
    seeds_through: u64,
    /// How many dirty rows were read.
    read: u64,
    /// The tree's top as the build last wrote it, once it has.
    top: Option<Option<Child>>,
    /// Undo rows of cuts already built, deleted by the first batch.
    orphans: Vec<Vec<u8>>,
    /// The space and its clock, when the agent is its representative.
    representative: Option<(SpaceId, WindowClock)>,
    done: bool,
}

impl Build {
    /// A build of `agent`'s root at the earliest cut pending, or else at
    /// the state version `store` holds now; `None` when nothing waits for
    /// one: no committed write, no cut and no orphaned undo row.
    pub fn start(store: &Fjall, agent: AgentId) -> Result<Option<Self>, Error> {
        let at = store.snapshot();
        let from = built(&at, agent)?;
        let cut = cuts::pending(&at, agent)?.first().copied();
        let version = match cut {
            Some(cut) if cut.version < from => return Err(Error::Corrupt("a cut behind the tree")),
            Some(cut) => cut.version,
            None => state_version(&at, agent)?,
        };
        let orphans = cuts::orphans(&at, agent)?;
        let bound = keys::dirty_from(version + 1);
        let dirty = at
            .scan(
                agent,
                &keys::dirty_prefix(),
                Some(&keys::dirty_from(from + 1)),
            )
            .next()
            .transpose()?
            .is_some_and(|(key, _)| key < bound);
        let seeds = at
            .scan(agent, &keys::seed_prefix(), Some(&keys::seed(from)))
            .next()
            .transpose()?
            .is_some();
        if !dirty && !seeds && cut.is_none() && orphans.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            store: store.clone(),
            agent,
            epoch: at.epoch(agent)?,
            version,
            cut,
            at,
            batch: BATCH,
            cursor: keys::dirty_from(from + 1),
            bound,
            seeds_through: from,
            read: 0,
            top: None,
            orphans,
            representative: None,
            done: false,
        }))
    }

    /// Build in batches of at most `keys` keys instead of [`BATCH`].
    #[doc(hidden)]
    pub fn in_batches_of(mut self, keys: usize) -> Self {
        self.batch = keys.max(1);
        self
    }

    /// The state version the build builds the tree at: the agent's latest,
    /// or the earliest cut not yet built, whichever comes first.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Whether the build was of a window's cut, and its last batch is
    /// taken: its root and its proofs are in that batch's commit.
    pub(crate) fn finished_cut(&self) -> bool {
        self.done && self.cut.is_some()
    }

    /// Build as the representative's of `space`, timed by `clock`: the
    /// commit that finishes a cut keeps its close ([`keys::closing`]) and
    /// the space's root of the window ([`keys::anchor`]).
    pub(crate) fn representing(mut self, space: SpaceId, clock: WindowClock) -> Self {
        self.representative = Some((space, clock));
        self
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
        let before = root_row(&fresh, self.agent)?;
        let mut tree = AgentStore::new(
            &fresh,
            self.agent,
            before.as_ref().and_then(|row| row.top.clone()),
        );
        if !batch.is_empty() {
            let leaves = batch
                .into_iter()
                .map(|key| {
                    let leaf = self.leaf(&mut seeds, &key)?;
                    Ok((key, leaf))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            vos_tree::update(&Blake2b, &mut tree, &leaves)?;
            // Until the last batch, the root stays the last complete build's.
            let root = before
                .as_ref()
                .map_or_else(|| empty_root(&Blake2b), |row| row.root);
            let row = RootRow {
                top: tree.top.clone(),
                root,
            };
            tree.writes.insert(keys::tree_root(), Some(row.encode()));
            self.top = Some(tree.top.clone());
        }
        let mut writes = BTreeMap::new();
        writes.extend(rows.into_iter().map(|row| (row, None)));
        writes.extend(self.orphans.drain(..).map(|row| (row, None)));
        // The seeds of the versions whose dirty rows are all read. A batch
        // before the last keeps its cursor version's seed even once that
        // version's rows are read: an interrupted build then always leaves
        // a seed past the watermark, so the next build starts and finishes
        // the tree it left part-way.
        let through = if last {
            self.version
        } else {
            let (version, _) =
                keys::dirty_entry(&self.cursor).ok_or(Error::Corrupt("a dirty row"))?;
            version.saturating_sub(1)
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
            self.finish(&fresh, before, &mut tree, &mut writes)?;
        }
        writes.extend(tree.writes);
        Ok(Some(Change::Tree {
            agent: self.agent,
            epoch: self.epoch,
            writes: writes
                .into_iter()
                .map(|(key, value)| Write { key, value })
                .collect(),
        }))
    }

    /// The last batch's writes: the root row, complete at the build's
    /// version, from the tree as this build left it, or as an earlier
    /// build cut short left it, which has no write past it, or this build
    /// would have touched it; the version the tree is built through; and,
    /// building a cut, what finishes it ([`cuts::finish`]).
    fn finish(
        &mut self,
        fresh: &Snapshot,
        before: Option<RootRow>,
        tree: &mut AgentStore<'_>,
        writes: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<(), Error> {
        let top = match self.top.take() {
            Some(top) => Some(top),
            None => before.filter(RootRow::building).map(|row| row.top),
        };
        if let Some(top) = top {
            let row = RootRow::complete(top);
            tree.writes.insert(keys::tree_root(), Some(row.encode()));
        }
        writes.insert(keys::built(), Some(self.version.encode()));
        if let Some(cut) = self.cut {
            let root = super::root_of(tree.top.as_ref());
            let finish = cuts::Finish {
                agent: self.agent,
                cut,
                root,
                representative: self.representative,
            };
            finish.write([&self.at, fresh], tree, writes)?;
        }
        self.done = true;
        Ok(())
    }

    /// The next keys to rebuild, sorted, and the dirty rows read for them:
    /// rows through the build's version read until `batch` keys, or as
    /// many rows as [`ROWS_PER_KEY`] allows them, or none remain; and
    /// whether none remains.
    fn read_batch(&mut self) -> Result<(Keys, Vec<Vec<u8>>, bool), Error> {
        let mut batch = Keys::new();
        let mut found = 0;
        let mut rows = Vec::new();
        let prefix = keys::dirty_prefix();
        let after = self.cursor.clone();
        let bound = &self.bound;
        let mut scan = self
            .at
            .scan(self.agent, &prefix, Some(&after))
            .take_while(|row| !matches!(row, Ok((key, _)) if key >= bound));
        let last = loop {
            if found == self.batch || rows.len() == self.batch * ROWS_PER_KEY {
                break scan.next().is_none();
            }
            let Some(row) = scan.next() else {
                break true;
            };
            let (row, _) = row?;
            let (_, key) = keys::dirty_entry(&row).ok_or(Error::Corrupt("a dirty row"))?;
            if batch.insert(key.to_vec()) {
                found += 1;
            }
            self.cursor.clone_from(&row);
            rows.push(row);
        };
        self.read += rows.len() as u64;
        Ok((batch, rows, last))
    }

    /// The leaf of the committed row `key` at the build's version: its
    /// bare value's commitment under the salt of the version that wrote it,
    /// or `None` if absent there. Building a cut, the value at the cut
    /// ([`cuts::at_cut`]).
    fn leaf(&self, seeds: &mut HashMap<u64, [u8; 32]>, key: &[u8]) -> Result<Option<Leaf>, Error> {
        let bytes = match self.cut {
            Some(cut) => cuts::at_cut(&self.at, self.agent, cut, key)?,
            None => self.at.get(self.agent, key)?,
        };
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let (version, value) = super::value_row(&bytes)?;
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
        Ok(Some(Leaf::salted(&Blake2b, &seed, key, value)))
    }
}

/// Build `shared`'s agent's root after its applies that leave dirty rows,
/// until its group stops: one build at a time, each at the latest state
/// version, so builds coalesce the applies made meanwhile. The batches run
/// on the executors, off the apply path. The first build runs at once,
/// catching up after a restart. A build that fails, on a store error or a
/// row that does not read back, is tried again after a backoff: building
/// pauses until it succeeds.
pub(crate) async fn build(inner: Arc<Inner>, shared: Arc<Shared>) {
    let agent = shared.agent;
    let mut seen = None;
    let mut backoff = Backoff::default();
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
            Ok(()) => backoff.reset(),
            // The new epoch's switch marks it dirty, and its state wakes
            // the next build.
            Err(Error::Moved) => {}
            Err(error) => {
                let wait = backoff.next();
                tracing::warn!(
                    agent = agent.0,
                    "a root build failed ({error}); trying again in {wait:?}"
                );
                crate::timeout(wait, shared.wait(|state| state.stopped)).await;
                due = true;
            }
        }
    }
}

/// Builds one after another until none is due: a cut's, the next cut's,
/// then the latest version's.
async fn run(inner: &Inner, shared: &Shared) -> Result<(), Error> {
    let agent = shared.agent;
    while !shared.state().stopped {
        let Some(mut build) = Build::start(&inner.store, agent)? else {
            return Ok(());
        };
        if inner.representative() == Some(agent) {
            let (space, clock) = inner.space_and_clock();
            build = build.representing(space, clock);
        }
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
                break;
            };
            if let Err(refusal) = inner.storage.commit(vec![change]).await {
                return Err(match inner.store.snapshot().epoch(agent) {
                    Ok(epoch) if epoch != build.epoch() => Error::Moved,
                    _ => Error::Halted(refusal),
                });
            }
            if build.finished_cut() {
                shared.update(|state| state.cuts_built += 1);
            }
        }
    }
    Ok(())
}
