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
//! for each pending request of the window ([`keys::request`]), its rows as
//! they stood at the cut with their salts, under one proof against that
//! root ([`CutProof`]): the same bytes on every replica. An undo row an
//! apply wrote racing that commit, of a window built, is garbage the next
//! build deletes.

use std::collections::{BTreeMap, BTreeSet};

use vos_tree::{BatchProof, Hash, NodeStore};
use vos_wire::ids::{AgentId, RequestId};
use vos_wire::keys;
use vos_wire::records::{PendingRead, unstored, unversioned};
use vos_wire::result::Write;
use vos_wire::{Decode, Encode, scale};

use super::{AgentStore, Error};
use crate::store::Snapshot;

/// A row a request reads, by its full key, with its leaf's salt and bare
/// value, or `None` when absent: as `Served` carries it.
pub type ReadRow = (Vec<u8>, Option<([u8; 16], Vec<u8>)>);

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
type CutRoot = (Hash, u64);

/// A window's cut: the window, and the cut's version.
#[derive(Clone, Copy, Debug)]
pub(super) struct Cut {
    pub(super) window: u64,
    pub(super) version: u64,
}

/// The cuts whose roots this replica keeps, by window.
fn cut_roots(snapshot: &Snapshot, agent: AgentId) -> Result<BTreeMap<u64, CutRoot>, Error> {
    let prefix = keys::cut_roots();
    snapshot
        .scan(agent, &prefix, None)
        .map(|row| {
            let (key, value) = row?;
            let window = key[prefix.len()..]
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::Corrupt("a cut root's key"))?;
            let root = CutRoot::decode_exact(&value).ok_or(Error::Corrupt("a cut root"))?;
            Ok((window, root))
        })
        .collect()
}

/// The window of the latest cut this replica built.
pub(super) fn latest_built(snapshot: &Snapshot, agent: AgentId) -> Result<Option<u64>, Error> {
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

/// The undo rows of windows this replica has built: garbage an apply
/// racing a cut's finishing commit left.
pub(super) fn orphans(snapshot: &Snapshot, agent: AgentId) -> Result<Vec<Vec<u8>>, Error> {
    let Some(latest) = latest_built(snapshot, agent)? else {
        return Ok(Vec::new());
    };
    let prefix = keys::undo_prefix();
    let mut orphans = Vec::new();
    for row in snapshot.scan(agent, &prefix, None) {
        let (key, _) = row?;
        let window = key
            .get(prefix.len()..prefix.len() + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(Error::Corrupt("an undo row's key"))?;
        if window > latest {
            break;
        }
        orphans.push(key);
    }
    Ok(orphans)
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
        let (version, _) = unstored(&stored)
            .and_then(unversioned)
            .ok_or(Error::Corrupt("a value row"))?;
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
) -> Result<Option<(Hash, u64)>, Error> {
    let Some(bytes) = snapshot.get(agent, &keys::cut_root(window))? else {
        return Ok(None);
    };
    CutRoot::decode_exact(&bytes)
        .map(Some)
        .ok_or(Error::Corrupt("a cut root"))
}

/// The rows and proof this replica persisted for `request` at its window's
/// cut, once that cut is built.
pub fn cut_proof(
    snapshot: &Snapshot,
    agent: AgentId,
    request: RequestId,
) -> Result<Option<CutProof>, Error> {
    let Some(bytes) = snapshot.get(agent, &keys::cut_proof(request))? else {
        return Ok(None);
    };
    CutProof::decode_exact(&bytes)
        .map(Some)
        .ok_or(Error::Corrupt("a cut proof"))
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
    let (written, _) = unstored(&stored)
        .and_then(unversioned)
        .ok_or(Error::Corrupt("a value row"))?;
    Ok((written <= cut.version).then_some(stored))
}

/// The writes that finish the build of `cut`: the root there, the cut
/// roots kept (this one and the latest before it), the window's undo rows
/// dropped, as `fresh` holds them, and each pending request's proof, read
/// off `tree`, the agent's tree at the cut, its values off `at`.
pub(super) fn finish(
    snapshots: [&Snapshot; 2],
    agent: AgentId,
    cut: Cut,
    tree: &AgentStore<'_>,
    root: Hash,
    writes: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
) -> Result<(), Error> {
    let [at, fresh] = snapshots;
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
    for row in at.scan(agent, &keys::requests(cut.window), None) {
        let (key, value) = row?;
        let (_, id) = keys::request_entry(&key).ok_or(Error::Corrupt("a request's key"))?;
        let read = unstored(&value)
            .and_then(PendingRead::decode_exact)
            .ok_or(Error::Corrupt("a pending request"))?;
        let proof = prove(at, agent, cut, tree, root, &read)?;
        writes.insert(keys::cut_proof(id), Some(proof.encode()));
    }
    Ok(())
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
                let (_, value) = unstored(&stored)
                    .and_then(unversioned)
                    .ok_or(Error::Corrupt("a value row"))?;
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
