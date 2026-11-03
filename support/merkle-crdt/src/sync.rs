//! Batched fetching, in the two shapes a scope is served in:
//!
//! - **from a peer that walks the DAG** (a plaintext scope): the replica
//!   sends the CIDs it wants and what it has, as each author's highest
//!   sequence number; the peer answers with the wanted nodes and their
//!   ancestors the replica lacks, up to a byte budget ([`serve`]). A round
//!   trip brings a budget's worth of nodes, however deep;
//! - **from a cursor** (a sealed scope): the server cannot read the DAG,
//!   only number what it accepted; the replica reads `since(position)` a
//!   page at a time, and stores the position with the nodes it applied,
//!   in one commit ([`Feed`]).
//!
//! Either way nodes may arrive before their parents: the replica holds
//! them until the parents arrive.
//!
//! The library does no I/O. An asynchronous client asks [`Replica::want`]
//! (or [`Replica::cursor`]) what to request, makes the round trip itself, and hands the answer to
//! [`Replica::ingest`]; [`Replica::sync`] and [`Replica::catch_up`] are
//! that loop over a blocking [`Source`] or [`Feed`].

use crate::replica::{Error, Ingested, Replica};
use crate::{Apply, Author, Cid, Decode, Encode, Hasher, Header, Store};
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

/// What a replica asks a peer for.
#[derive(Debug, Clone)]
pub struct Want<H: Hasher> {
    /// The nodes wanted: a peer's heads, or the parents held nodes wait on.
    pub ids: Vec<Cid<H>>,
    /// Each author's highest sequence number the replica has applied. An
    /// author's chain is linked, so the replica has every earlier node of
    /// it on that chain, and the peer skips them.
    pub have: BTreeMap<Author, u64>,
}

/// A peer that walks the DAG.
pub trait Source<H: Hasher> {
    /// Why fetching failed.
    type Error;
    /// One round trip: nodes' bytes for `want`, in any order.
    fn fetch(&mut self, want: &Want<H>) -> Result<Vec<Vec<u8>>, Self::Error>;
}

/// Answer `want` from `store`: each wanted node the store holds, and its
/// ancestors the asker lacks by `want.have`, oldest first, until `budget`
/// bytes are taken (at least one node, if any). The walk reads only the
/// nodes' headers, so a peer serves nodes whose operations it cannot
/// decode.
///
/// A walk the budget cuts short returns its newest nodes; the asker holds
/// them and asks next for the parents they wait on.
pub fn serve<H: Hasher, S: Store<H>>(
    store: &S,
    want: &Want<H>,
    budget: usize,
) -> Result<Vec<Vec<u8>>, S::Error> {
    let covered = |header: &Header<H>| {
        want.have
            .get(&header.author)
            .is_some_and(|seq| header.seq <= *seq)
    };
    let mut queue: VecDeque<(Cid<H>, bool)> =
        want.ids.iter().map(|cid| (cid.clone(), true)).collect();
    let mut seen = BTreeSet::new();
    let mut taken: Linked<H, Vec<u8>> = BTreeMap::new();
    let mut bytes_taken = 0;
    while let Some((cid, asked)) = queue.pop_front() {
        if bytes_taken >= budget && !taken.is_empty() {
            break;
        }
        if !seen.insert(cid.clone()) {
            continue;
        }
        let Some(bytes) = store.node(&cid)? else {
            continue;
        };
        let Some(header) = Header::<H>::read(&bytes) else {
            continue;
        };
        if !asked && covered(&header) {
            continue;
        }
        queue.extend(header.parents.iter().map(|parent| (parent.clone(), false)));
        bytes_taken += bytes.len();
        taken.insert(cid, (header.parents, bytes));
    }
    Ok(causal_order(taken))
}

/// Nodes by CID, each with its parents.
pub(crate) type Linked<H, T> = BTreeMap<Cid<H>, (BTreeSet<Cid<H>>, T)>;

/// Order nodes so each comes after those of its parents among them.
pub(crate) fn causal_order<H: Hasher, T>(mut nodes: Linked<H, T>) -> Vec<T> {
    let mut remaining: BTreeMap<Cid<H>, usize> = BTreeMap::new();
    let mut children: BTreeMap<Cid<H>, Vec<Cid<H>>> = BTreeMap::new();
    for (cid, (parents, _)) in &nodes {
        let inside = parents.iter().filter(|p| nodes.contains_key(*p));
        let mut count = 0;
        for parent in inside {
            children
                .entry(parent.clone())
                .or_default()
                .push(cid.clone());
            count += 1;
        }
        remaining.insert(cid.clone(), count);
    }
    let mut ready: VecDeque<Cid<H>> = remaining
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(cid, _)| cid.clone())
        .collect();
    let mut ordered = Vec::with_capacity(nodes.len());
    while let Some(cid) = ready.pop_front() {
        for child in children.get(&cid).into_iter().flatten() {
            let count = remaining.get_mut(child).expect("every child is counted");
            *count -= 1;
            if *count == 0 {
                ready.push_back(child.clone());
            }
        }
        ordered.push(nodes.remove(&cid).expect("each node is ordered once").1);
    }
    ordered
}

/// One page a feed returns: nodes' bytes with the positions the server
/// gave them, ascending, and whether more follow.
#[derive(Debug, Clone, Default)]
pub struct Page {
    /// `(position, node bytes)`, positions ascending.
    pub items: Vec<(u64, Vec<u8>)>,
    /// Whether the server holds positions past the page.
    pub more: bool,
}

/// A server that numbers a scope's nodes in the order it accepted them and
/// cannot read them: `since(position)` returns a page after `position`
/// (from the start for `None`). For a sealed scope the feed opens each
/// envelope and returns the node inside.
pub trait Feed {
    /// Why reading failed.
    type Error;
    /// One round trip: the page after `position`.
    fn since(&mut self, position: Option<u64>) -> Result<Page, Self::Error>;
}

impl<H: Hasher, O: Encode + Decode, S: Store<H>> Replica<H, O, S> {
    /// Fetch from a peer that walks the DAG until the replica holds
    /// nothing waiting: first `heads` (the peer's), then the parents held
    /// nodes wait on. One commit a round trip.
    #[allow(clippy::type_complexity)]
    pub fn sync<A: Apply<H, O>, R: Source<H>>(
        &mut self,
        heads: impl IntoIterator<Item = Cid<H>>,
        source: &mut R,
        crdt: &mut A,
    ) -> Result<Ingested<H>, Error<S::Error, A::Error, R::Error>> {
        let mut report = Ingested::default();
        let mut want = self.want(heads).map_err(Error::Store)?;
        while !want.ids.is_empty() {
            let nodes = source.fetch(&want).map_err(Error::Source)?;
            let round = self.ingest(nodes, None, crdt).map_err(widen)?;
            let progressed = !round.applied.is_empty() || !round.held.is_empty();
            report.absorb(round);
            if !progressed {
                return Err(Error::Stalled);
            }
            want = self.want([]).map_err(Error::Store)?;
        }
        Ok(report)
    }

    /// What to ask a peer that walks the DAG for: those of the peer's
    /// `heads` the replica has not applied, held or refused, and the
    /// parents its held nodes wait on; with what it has.
    pub fn want(&self, heads: impl IntoIterator<Item = Cid<H>>) -> Result<Want<H>, S::Error> {
        let mut ids = Vec::new();
        for cid in heads {
            if !self.known(&cid)? {
                ids.push(cid);
            }
        }
        ids.extend(self.wanted());
        Ok(Want {
            ids,
            have: self.have(),
        })
    }

    /// Read a feed from the replica's cursor to its end, one commit a
    /// page, each storing the page's last position with its nodes.
    #[allow(clippy::type_complexity)]
    pub fn catch_up<A: Apply<H, O>, F: Feed>(
        &mut self,
        feed: &mut F,
        crdt: &mut A,
    ) -> Result<Ingested<H>, Error<S::Error, A::Error, F::Error>> {
        let mut report = Ingested::default();
        loop {
            let page = feed.since(self.cursor()).map_err(Error::Source)?;
            let Some(last) = page.items.last().map(|(position, _)| *position) else {
                return Ok(report);
            };
            let mut after = self.cursor();
            for (position, _) in &page.items {
                if after.is_some_and(|after| *position <= after) {
                    return Err(Error::Disordered);
                }
                after = Some(*position);
            }
            let items = page.items.into_iter().map(|(_, bytes)| bytes);
            report.absorb(self.ingest(items, Some(last), crdt).map_err(widen)?);
            if !page.more {
                return Ok(report);
            }
        }
    }
}

fn widen<S, A, R>(error: Error<S, A>) -> Error<S, A, R> {
    match error {
        Error::Store(error) => Error::Store(error),
        Error::Apply(error) => Error::Apply(error),
        Error::Corrupt => Error::Corrupt,
        Error::Stalled => Error::Stalled,
        Error::Disordered => Error::Disordered,
        Error::Source(never) => match never {},
    }
}
