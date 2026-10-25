//! Window cuts: the agent's root at each window's cut, and the proofs of
//! the reads pending at it.
//!
//! The agent's apply records `cut(w)` ([`keys::cut`]), the state version
//! before the first result past the window's boundary; the builder then
//! builds the tree at that version before any later one. A cut is
//! *pending* while it is past the latest cut this replica built, the one
//! whose root it keeps ([`keys::cut_root`]); all are while it has built
//! none.
//!
//! Until a cut is built, the values later results overwrite are kept: the
//! node's apply, beside the agent's writes and in their commit, writes
//! [`keys::undo`] of each pending cut for each committed row the writes
//! rewrite or delete that the cut's version still held ([`undo`]). Those
//! rows are node-local: whether a cut is pending is the replica's own, so
//! the agent's apply never writes them. The cut's build reads a dirty
//! key's value at the cut as its undo row, else its row while its version
//! is at or before the cut, else absent.
//!
//! The commit that finishes a cut's build writes the root at the cut,
//! keeps it and the one before, drops the window's undo rows, and persists,
//! for each request pending at the cut ([`keys::request`], asked in the
//! window), its rows as they stood at the cut with their salts, under one
//! proof against that root ([`CutProof`]):
//! the same bytes on every replica. The space's representative's also keeps
//! its close of the window, once some agent reported it: its root, and the
//! path of each agent that reported ([`keys::closing`]); the same bytes on
//! every replica that builds the cut within a few windows, since the
//! reports are a plain table read where the build starts, and pruned: a
//! replica far behind omits paths only dead reads need. Its close writes
//! the space's root of the window too ([`keys::anchor`]), the only root its
//! leader signs, kept for `MaxRootAge`: a window no one reported is not
//! anchored. An undo row an apply wrote racing that commit, of a
//! window built, is garbage the next build deletes, as are a request's
//! proof once it is answered and a close once sent.

use std::collections::{BTreeMap, BTreeSet};

use vos_tree::{BatchProof, Hash, NodeStore};
use vos_wire::ids::{AgentId, RequestId};
use vos_wire::keys;
use vos_wire::records::{PendingRead, unstored};
use vos_wire::result::Write;
use vos_wire::served::{
    Closing, representative_ask_entry, representative_asks_of, representative_row,
};
use vos_wire::vos_anchor::{MAX_ROOT_AGE_MS, RootKind, space_root};
use vos_wire::{Decode, Encode, SpaceId, WindowClock, scale};

use super::{AgentStore, Error, decoded, value_row};
use crate::store::Snapshot;

pub use vos_wire::served::ReadRow;

/// What every replica persists for a pending request once its window's cut
/// is built ([`keys::cut_proof`]): the window, the cut's version and the
/// agent's root there, and each row the request reads, by its full key in
/// the request's order, with its leaf's salt and bare value at the cut
/// (`None`: absent), and one [`BatchProof`] of them against that root, as
/// encoded. Its bytes are the same on every replica.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CutProof {
    pub window: u64,
    pub version: u64,
    pub agent_root: Hash,
    pub rows: Vec<ReadRow>,
    pub rows_proof: Vec<u8>,
}

/// The root at the cut of a window: the root, and the cut's version.
pub(crate) type CutRoot = (Hash, u64);

/// A window's cut: the window, and the cut's version.
#[derive(Clone, Copy, Debug)]
pub(super) struct Cut {
    pub(super) window: u64,
    pub(super) version: u64,
}

/// The cuts whose roots this replica keeps, by window.
pub(crate) fn cut_roots(
    snapshot: &Snapshot,
    agent: AgentId,
) -> Result<BTreeMap<u64, CutRoot>, Error> {
    snapshot
        .scan(agent, &keys::cut_roots(), None)
        .map(|row| {
            let (key, value) = row?;
            let window = keys::cut_root_entry(&key).ok_or(Error::Corrupt("a cut root's key"))?;
            let root = CutRoot::decode_exact(&value).ok_or(Error::Corrupt("a cut root"))?;
            Ok((window, root))
        })
        .collect()
}

/// The window of the latest cut this replica built.
pub fn latest_built(snapshot: &Snapshot, agent: AgentId) -> Result<Option<u64>, Error> {
    Ok(cut_roots(snapshot, agent)?.keys().next_back().copied())
}

/// A cut row's version.
fn cut_version(stored: &[u8]) -> Result<u64, Error> {
    unstored(stored)
        .and_then(u64::decode_exact)
        .ok_or(Error::Corrupt("a cut"))
}

/// The cuts pending a build, in window order: each window and its cut's
/// version.
pub(super) fn pending(snapshot: &Snapshot, agent: AgentId) -> Result<Vec<Cut>, Error> {
    let after = latest_built(snapshot, agent)?.map(keys::cut);
    snapshot
        .scan(agent, &keys::cuts(), after.as_deref())
        .map(|row| {
            let (key, value) = row?;
            let window = keys::cut_entry(&key).ok_or(Error::Corrupt("a cut's key"))?;
            Ok(Cut {
                window,
                version: cut_version(&value)?,
            })
        })
        .collect()
}

/// The undo rows of windows this replica has built, and the proofs of
/// requests answered: garbage an apply racing a cut's finishing commit
/// left.
pub(super) fn orphans(snapshot: &Snapshot, agent: AgentId) -> Result<Vec<Vec<u8>>, Error> {
    let mut orphans = Vec::new();
    if let Some(latest) = latest_built(snapshot, agent)? {
        for row in snapshot.scan(agent, &keys::undo_prefix(), None) {
            let (key, _) = row?;
            let (window, _) = keys::undo_entry(&key).ok_or(Error::Corrupt("an undo row's key"))?;
            if window > latest {
                break;
            }
            orphans.push(key);
        }
    }
    for row in snapshot.scan(agent, &keys::cut_proofs(), None) {
        let (key, _) = row?;
        let (id, window) =
            keys::cut_proof_entry(&key).ok_or(Error::Corrupt("a cut proof's key"))?;
        if snapshot.get(agent, &keys::request(window, id))?.is_none() {
            orphans.push(key);
        }
    }
    // The closes the representative has sent: before its mark's window.
    let mark = snapshot
        .get(agent, &keys::close_mark())?
        .as_deref()
        .and_then(unstored)
        .and_then(<(u64, Option<AgentId>)>::decode_exact);
    if let Some((closed, _)) = mark {
        for row in snapshot.scan(agent, &keys::closings(), None) {
            let (key, _) = row?;
            match keys::closing_entry(&key) {
                Some(window) if window < closed => orphans.push(key),
                Some(_) => break,
                None => return Err(Error::Corrupt("a close's key")),
            }
        }
    }
    Ok(orphans)
}

/// The node-local rows the node's apply deletes beside `writes`: the
/// proof of each pending request they delete, now answered.
pub fn answered(writes: &[Write]) -> Vec<Write> {
    writes
        .iter()
        .filter(|write| write.value.is_none())
        .filter_map(|write| keys::request_entry(&write.key))
        .map(|(window, id)| Write {
            key: keys::cut_proof(id, window),
            value: None,
        })
        .collect()
}

/// The node-local rows the node's apply commits beside `writes`, the rows
/// accumulate made of a work result, as `snapshot` holds the agent's
/// state before them: for each committed row `writes` overwrite or delete
/// whose current version is at or before a cut whose build is pending,
/// its stored bytes as [`keys::undo`] of that window. A cut `writes`
/// record themselves counts. Never written by the agent's apply: whether
/// a build is pending is the replica's own.
pub fn undo(snapshot: &Snapshot, agent: AgentId, writes: &[Write]) -> Result<Vec<Write>, Error> {
    let mut cuts = pending(snapshot, agent)?;
    for write in writes {
        if let (Some(window), Some(value)) = (keys::cut_entry(&write.key), &write.value) {
            cuts.push(Cut {
                window,
                version: cut_version(value)?,
            });
        }
    }
    if cuts.is_empty() {
        return Ok(Vec::new());
    }
    let rows: BTreeSet<&[u8]> = writes
        .iter()
        .map(|write| write.key.as_slice())
        .filter(|key| keys::is_committed(key))
        .collect();
    let mut undo = Vec::new();
    for row in rows {
        let Some(stored) = snapshot.get(agent, row)? else {
            continue;
        };
        let (version, _) = value_row(&stored)?;
        for cut in &cuts {
            if version <= cut.version {
                undo.push(Write {
                    key: keys::undo(cut.window, row),
                    value: Some(stored.clone()),
                });
            }
        }
    }
    Ok(undo)
}

/// The agent's root at the window `window`'s cut and the cut's version,
/// once the cut's build is done, while it is among the two latest cuts.
pub fn cut_root(
    snapshot: &Snapshot,
    agent: AgentId,
    window: u64,
) -> Result<Option<CutRoot>, Error> {
    decoded(snapshot.get(agent, &keys::cut_root(window))?, "a cut root")
}

/// The rows and proof this replica persisted for `request` at the cut of
/// the window it was asked in, once that cut is built.
pub fn cut_proof(
    snapshot: &Snapshot,
    agent: AgentId,
    request: RequestId,
) -> Result<Option<CutProof>, Error> {
    let proof = snapshot
        .scan(agent, &keys::cut_proofs_of(request), None)
        .next()
        .transpose()?;
    decoded(proof.map(|(_, bytes)| bytes), "a cut proof")
}

/// The stored bytes of the committed row `row` at `cut`, as `at` holds the
/// agent's state: its undo row, else the row while its version is at or
/// before the cut, else absent.
pub(super) fn at_cut(
    at: &Snapshot,
    agent: AgentId,
    cut: Cut,
    row: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    if let Some(stored) = at.get(agent, &keys::undo(cut.window, row))? {
        return Ok(Some(stored));
    }
    let Some(stored) = at.get(agent, row)? else {
        return Ok(None);
    };
    let (written, _) = value_row(&stored)?;
    Ok((written <= cut.version).then_some(stored))
}

/// What finishes the build of a cut: the agent, the cut, its root, and,
/// when the agent is the space's representative, its space and clock.
pub(super) struct Finish {
    pub(super) agent: AgentId,
    pub(super) cut: Cut,
    pub(super) root: Hash,
    pub(super) representative: Option<(SpaceId, WindowClock)>,
}

impl Finish {
    /// The writes that finish the build: the root at the cut, the cut
    /// roots kept (this one and the latest before it), the window's undo
    /// rows dropped, as `fresh` holds them, and the proof of each request
    /// pending at the cut ([`requests_at`]), read off `tree`, the agent's
    /// tree at the cut, its values off `at`; the representative's, its
    /// close of the window too, and the space's root of the window, those
    /// of windows past `MaxRootAge` dropped.
    pub(super) fn write(
        &self,
        [at, fresh]: [&Snapshot; 2],
        tree: &AgentStore<'_>,
        writes: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<(), Error> {
        let Self {
            agent,
            cut,
            root,
            representative,
        } = *self;
        writes.insert(
            keys::cut_root(cut.window),
            Some((root, cut.version).encode()),
        );
        let kept = cut_roots(fresh, agent)?;
        let older = kept.keys().filter(|kept| **kept < cut.window).copied();
        for stale in older.rev().skip(1) {
            writes.insert(keys::cut_root(stale), None);
        }
        for row in fresh.scan(agent, &keys::undos(cut.window), None) {
            writes.insert(row?.0, None);
        }
        for (id, value) in requests_at(at, agent, cut.window)? {
            let read = unstored(&value).and_then(PendingRead::decode_exact);
            let Some(read) =
                read.filter(|read| read.rows.iter().all(|row| keys::is_committed(row)))
            else {
                tracing::warn!(
                    agent = agent.0,
                    ?id,
                    "a pending request does not read as committed rows; it is not proved"
                );
                continue;
            };
            match prove(at, agent, cut, tree, root, &read) {
                Ok(proof) => {
                    writes.insert(keys::cut_proof(id, cut.window), Some(proof.encode()));
                }
                // A row the request names that is no value row, or one the
                // tree holds otherwise: skipped alike on every replica, so
                // the cut's root and the other proofs still land.
                Err(Error::Corrupt(what)) => {
                    tracing::warn!(
                        agent = agent.0,
                        ?id,
                        "{what} does not read back; the request is not proved"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        if let Some((space, clock)) = representative {
            let closing = closing(at, agent, cut, tree, root)?;
            // A window no agent's row reaches closes nothing, and is not
            // anchored.
            if !closing.paths.is_empty() {
                writes.insert(keys::closing(cut.window), Some(closing.encode()));
                let space_root = space_root(&space, cut.window, &root);
                writes.insert(keys::anchor(cut.window), Some(space_root.to_vec()));
            }
            let kept = MAX_ROOT_AGE_MS.div_ceil(clock.length_ms.max(1));
            let first = keys::anchor(cut.window.saturating_sub(kept));
            for row in fresh.scan(agent, &keys::anchors(), None) {
                let (key, _) = row?;
                if key >= first {
                    break;
                }
                writes.insert(key, None);
            }
        }
        Ok(())
    }
}

/// The requests pending at window `window`'s cut, as `at` holds them, those
/// asked in it: each its id and its row as stored. A key that does not
/// read is skipped, and logged.
pub fn requests_at(
    at: &Snapshot,
    agent: AgentId,
    window: u64,
) -> Result<Vec<(RequestId, Vec<u8>)>, Error> {
    let mut requests = Vec::new();
    for row in at.scan(agent, &keys::requests(window), None) {
        let (key, value) = row?;
        let Some((_, id)) = keys::request_entry(&key) else {
            tracing::warn!(
                agent = agent.0,
                "a pending request's key does not read; it is not proved"
            );
            continue;
        };
        requests.push((id, value));
    }
    Ok(requests)
}

/// The representative's close of `cut`: its root there, `root`, and the
/// path of each agent that reported the window whose row its tree at the
/// cut holds, in agent order. The reports are those the cut holds: the
/// asks of the window whose rows stood at the cut, read off `at` and its
/// undo rows, so a replica that builds the cut late finds the same. A
/// report whose row the cut lacks, applied after the close, gets none: the
/// agent's reads end `NotClosed`.
fn closing(
    at: &Snapshot,
    agent: AgentId,
    cut: Cut,
    tree: &AgentStore<'_>,
    root: Hash,
) -> Result<Closing, Error> {
    let prefix = representative_asks_of(cut.window);
    let mut asks = BTreeSet::new();
    for row in at.scan(agent, &prefix, None) {
        asks.insert(row?.0);
    }
    let undone = keys::undo(cut.window, &prefix);
    for row in at.scan(agent, &undone, None) {
        let (key, _) = row?;
        if let Some((_, row)) = keys::undo_entry(&key) {
            asks.insert(row.to_vec());
        }
    }
    let mut paths = Vec::new();
    for ask in asks {
        let Some((window, of)) = representative_ask_entry(&ask) else {
            continue;
        };
        if window != cut.window || at_cut(at, agent, cut, &ask)?.is_none() {
            continue;
        }
        let row = representative_row(of, RootKind::Space, window);
        let Some(leaf) = tree.leaf(&row)? else {
            continue;
        };
        let path = BatchProof::generate(tree, &[row])?.encode();
        paths.push((of, leaf.salt, path));
    }
    Ok(Closing { root, paths })
}

/// The space's roots the representative's closes made ([`keys::anchor`]),
/// by window, past `after` when given.
pub fn anchors(
    snapshot: &Snapshot,
    agent: AgentId,
    after: Option<u64>,
) -> Result<BTreeMap<u64, [u8; 32]>, Error> {
    let after = after.map(keys::anchor);
    snapshot
        .scan(agent, &keys::anchors(), after.as_deref())
        .map(|row| {
            let (key, value) = row?;
            let window = keys::anchor_entry(&key).ok_or(Error::Corrupt("an anchor row's key"))?;
            let root = value[..]
                .try_into()
                .map_err(|_| Error::Corrupt("an anchor row"))?;
            Ok((window, root))
        })
        .collect()
}

/// The space's root of window `window` the representative's close made.
pub fn anchor_of(
    snapshot: &Snapshot,
    agent: AgentId,
    window: u64,
) -> Result<Option<[u8; 32]>, Error> {
    snapshot
        .get(agent, &keys::anchor(window))?
        .map(|value| {
            value[..]
                .try_into()
                .map_err(|_| Error::Corrupt("an anchor row"))
        })
        .transpose()
}

/// The proof of `read` at `cut`: each row's leaf off `tree`, its value off
/// `at`, and one proof of them all.
fn prove(
    at: &Snapshot,
    agent: AgentId,
    cut: Cut,
    tree: &AgentStore<'_>,
    root: Hash,
    read: &PendingRead,
) -> Result<CutProof, Error> {
    let mut rows = Vec::with_capacity(read.rows.len());
    for row in &read.rows {
        let leaf = tree.leaf(row)?;
        let value = at_cut(at, agent, cut, row)?;
        let held = match (leaf, value) {
            (Some(leaf), Some(stored)) => {
                let (_, value) = value_row(&stored)?;
                Some((leaf.salt, value.to_vec()))
            }
            (None, None) => None,
            _ => return Err(Error::Corrupt("a leaf at a cut")),
        };
        rows.push((row.clone(), held));
    }
    let proof = BatchProof::generate(tree, &read.rows)?;
    Ok(CutProof {
        window: cut.window,
        version: cut.version,
        agent_root: root,
        rows,
        rows_proof: proof.encode(),
    })
}
