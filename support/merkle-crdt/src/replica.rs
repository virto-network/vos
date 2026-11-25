use crate::apply::Overlay;
use crate::signed::{self, validate};
use crate::store::{Applied, Changes};
use crate::{
    Apply, Author, Cid, Decode, Encode, Event, Hasher, Header, MAX_PARENTS, Node, Refusal, Scope,
    Store,
};
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::convert::Infallible;
use core::marker::PhantomData;
use ed25519_dalek::SigningKey;

/// The most nodes a replica holds for missing parents. Past it a node that
/// would be held is dropped ([`Ingested::dropped`]).
pub const MAX_HELD: usize = 4096;

/// The most nodes of one author a replica holds.
pub const MAX_HELD_PER_AUTHOR: usize = 256;

/// The most bytes of held nodes a replica keeps.
pub const MAX_HELD_BYTES: usize = 32 << 20;

/// How many refused nodes a replica remembers, the latest. A node naming
/// one of them is refused at once; a node naming one it has forgotten is
/// held, within the bounds above, as a node whose parent has not arrived.
const MAX_REFUSED: usize = 4096;

/// Why a replica's operation failed. The replica's memory and store are
/// as they were before it.
#[derive(Debug)]
pub enum Error<S, A = Infallible> {
    /// The store failed.
    Store(S),
    /// The CRDT refused to apply a node.
    Apply(A),
    /// A node the store holds is missing, or does not validate.
    Corrupt,
    /// The CRDT wrote a row no store takes ([`Rows::write`](crate::Rows::write)).
    Row,
    /// The operations make a node that does not decode: their [`Encode`]
    /// writes what their [`Decode`] refuses.
    Unencodable,
}

impl<S: core::fmt::Debug, A: core::fmt::Debug> core::fmt::Display for Error<S, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Store(error) => write!(f, "the store failed: {error:?}"),
            Error::Apply(error) => write!(f, "applying a node failed: {error:?}"),
            Error::Corrupt => f.write_str("a stored node is missing or does not validate"),
            Error::Row => f.write_str("a row's key or value is past what a store takes"),
            Error::Unencodable => f.write_str("the operations make a node that does not decode"),
        }
    }
}

#[cfg(feature = "std")]
impl<S: core::fmt::Debug, A: core::fmt::Debug> std::error::Error for Error<S, A> {}

/// Two applied nodes of one author at one sequence number. Both stay in
/// the DAG, since other authors' nodes may name either; the CRDT's reads
/// filter the author's operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation<H: Hasher> {
    /// The author.
    pub author: Author,
    /// The sequence number signed twice.
    pub seq: u64,
    /// A node applied before at the number, and the one found equivocating.
    pub nodes: [Cid<H>; 2],
}

/// The nodes of one ingest not yet applied, with their bytes.
type Fresh<H, O> = BTreeMap<Cid<H>, (Node<H, O>, Vec<u8>)>;

/// A local node not yet pushed.
#[derive(Debug, Clone)]
pub struct Outgoing<H: Hasher> {
    /// Its author.
    pub author: Author,
    /// Its sequence number.
    pub seq: u64,
    /// Its CID.
    pub cid: Cid<H>,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// What one ingest did.
#[derive(Debug)]
pub struct Ingested<H: Hasher> {
    /// The nodes applied, in the order applied.
    pub applied: Vec<Cid<H>>,
    /// The nodes held until their parents arrive.
    pub held: Vec<Cid<H>>,
    /// The nodes that would be held, dropped: the replica holds
    /// [`MAX_HELD`] nodes, [`MAX_HELD_PER_AUTHOR`] of the author's or
    /// [`MAX_HELD_BYTES`] already. Not refused: delivered again once their
    /// parents are applied, they apply. A cursor given with the batch
    /// passes them.
    pub dropped: Vec<Cid<H>>,
    /// The nodes refused, with their CIDs where they decode.
    pub refused: Vec<(Option<Cid<H>>, Refusal)>,
    /// The equivocations found.
    pub equivocations: Vec<Equivocation<H>>,
    /// The nodes already applied, held or refused.
    pub duplicates: usize,
}

impl<H: Hasher> Default for Ingested<H> {
    fn default() -> Self {
        Self {
            applied: Vec::new(),
            held: Vec::new(),
            dropped: Vec::new(),
            refused: Vec::new(),
            equivocations: Vec::new(),
            duplicates: 0,
        }
    }
}

/// A held node: its author, its size, and its parents not applied when it
/// was held.
struct Holding<H: Hasher> {
    author: Author,
    len: usize,
    waits: Vec<Cid<H>>,
}

/// One scope's replica: its DAG applied onto its CRDT, incrementally.
///
/// It keeps in memory the heads, each author's latest sequence number, the
/// equivocations, the cursor, the outbox, the held nodes' missing parents
/// (at most [`MAX_HELD`] nodes) and the latest refused nodes' CIDs; the
/// nodes and the CRDT's rows stay in the store. One replica a store.
///
/// - [`ingest`](Self::ingest) validates and applies only the nodes it is
///   given, in causal order, onto the current rows; a node whose parents
///   have not arrived is held, durably, and applied in the batch that
///   brings its last parent. The heads move by the applied nodes'
///   parents alone.
/// - [`record`](Self::record) applies a local operation in place.
///
/// Every method that writes commits one [`Changes`] batch, and moves
/// the replica's memory only once it is committed.
pub struct Replica<H: Hasher, O, S: Store<H>> {
    store: S,
    heads: BTreeMap<Cid<H>, (Author, u64)>,
    latest: BTreeMap<Author, (u64, Cid<H>)>,
    equivocations: BTreeSet<(Author, u64)>,
    cursor: Option<u64>,
    outbox: BTreeMap<(Author, u64), Cid<H>>,
    /// The scope the nodes are signed for.
    scope: Scope,
    /// Each held node's count of parents not applied.
    missing: BTreeMap<Cid<H>, usize>,
    /// Each held node's author, size and parents not applied when it was
    /// held.
    holding: BTreeMap<Cid<H>, Holding<H>>,
    /// For each parent not applied, the held nodes waiting on it.
    waiting: BTreeMap<Cid<H>, BTreeSet<Cid<H>>>,
    /// The held nodes of each author.
    held_by: BTreeMap<Author, usize>,
    /// The held nodes' bytes.
    held_bytes: usize,
    /// The latest nodes refused since the replica opened, at most
    /// [`MAX_REFUSED`], oldest first in `refused_order`.
    refused: BTreeSet<Cid<H>>,
    refused_order: VecDeque<Cid<H>>,
    ops: PhantomData<fn() -> O>,
}

impl<H: Hasher, O: Encode + Decode, S: Store<H>> Replica<H, O, S> {
    /// Open the replica of `scope` its store holds; an empty store is an
    /// empty scope. The held nodes are read one at a time, for their
    /// headers.
    pub fn open(store: S, scope: Scope) -> Result<Self, Error<S::Error>> {
        let loaded = store.load().map_err(Error::Store)?;
        let mut replica = Self {
            scope,
            store,
            heads: loaded.heads,
            latest: loaded.latest,
            equivocations: loaded.equivocations,
            cursor: loaded.cursor,
            outbox: loaded.outbox,
            missing: BTreeMap::new(),
            holding: BTreeMap::new(),
            waiting: BTreeMap::new(),
            held_by: BTreeMap::new(),
            held_bytes: 0,
            refused: BTreeSet::new(),
            refused_order: VecDeque::new(),
            ops: PhantomData,
        };
        for cid in loaded.held {
            let bytes = replica
                .store
                .held(&cid)
                .map_err(Error::Store)?
                .ok_or(Error::Corrupt)?;
            let header = Header::<H>::read(&bytes).ok_or(Error::Corrupt)?;
            let mut waits = Vec::new();
            for parent in header.parents {
                if !replica.store.contains(&parent).map_err(Error::Store)? {
                    waits.push(parent);
                }
            }
            replica.hold(
                cid,
                Holding {
                    author: header.author,
                    len: bytes.len(),
                    waits,
                },
            );
        }
        Ok(replica)
    }

    /// The applied nodes no applied node follows, each with its author and
    /// sequence number.
    pub fn heads(&self) -> &BTreeMap<Cid<H>, (Author, u64)> {
        &self.heads
    }

    /// The (author, sequence number) pairs signed more than once: the
    /// authors whose operations the CRDT's reads filter.
    pub fn equivocations(&self) -> &BTreeSet<(Author, u64)> {
        &self.equivocations
    }

    /// Each author's highest sequence number applied: what the replica
    /// tells a peer it has.
    pub fn have(&self) -> BTreeMap<Author, u64> {
        self.latest
            .iter()
            .map(|(author, (seq, _))| (*author, *seq))
            .collect()
    }

    /// The last position ingested from a feed.
    pub fn cursor(&self) -> Option<u64> {
        self.cursor
    }

    /// The number of nodes held for missing parents.
    pub fn held(&self) -> usize {
        self.missing.len()
    }

    /// The parents the held nodes wait on that are not held themselves:
    /// what to ask a peer for.
    pub fn wanted(&self) -> Vec<Cid<H>> {
        self.waiting
            .keys()
            .filter(|cid| !self.missing.contains_key(*cid))
            .cloned()
            .collect()
    }

    /// The store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The store, to stage writes of its own that its next commit carries
    /// (a wrapper's rows beside the replica's). What the replica has
    /// applied is not to be changed through it. A call that changes
    /// nothing commits nothing (an ingest of duplicates only, a `pushed`
    /// of nodes already pushed), so a wrapper that stages writes for a call
    /// checks whether it committed.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The store, given back.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Whether `cid` is applied, held or refused.
    fn known(&self, cid: &Cid<H>) -> Result<bool, S::Error> {
        Ok(self.missing.contains_key(cid)
            || self.refused.contains(cid)
            || self.store.contains(cid)?)
    }

    /// Keep `cid` as held, its parents in `holding.waits` not applied.
    fn hold(&mut self, cid: Cid<H>, holding: Holding<H>) {
        for parent in &holding.waits {
            self.waiting
                .entry(parent.clone())
                .or_default()
                .insert(cid.clone());
        }
        self.missing.insert(cid.clone(), holding.waits.len());
        *self.held_by.entry(holding.author).or_default() += 1;
        self.held_bytes += holding.len;
        self.holding.insert(cid, holding);
    }

    /// Forget `cid` as held, if it is.
    fn unhold(&mut self, cid: &Cid<H>) {
        self.missing.remove(cid);
        let Some(holding) = self.holding.remove(cid) else {
            return;
        };
        self.held_bytes -= holding.len;
        if let Some(count) = self.held_by.get_mut(&holding.author) {
            *count -= 1;
            if *count == 0 {
                self.held_by.remove(&holding.author);
            }
        }
        for parent in holding.waits {
            if let Some(kids) = self.waiting.get_mut(&parent) {
                kids.remove(cid);
                if kids.is_empty() {
                    self.waiting.remove(&parent);
                }
            }
        }
    }

    /// Remember `cid` as refused, forgetting the oldest past
    /// [`MAX_REFUSED`].
    fn remember_refused(&mut self, cid: Cid<H>) {
        if !self.refused.insert(cid.clone()) {
            return;
        }
        self.refused_order.push_back(cid);
        if self.refused_order.len() > MAX_REFUSED
            && let Some(oldest) = self.refused_order.pop_front()
        {
            self.refused.remove(&oldest);
        }
    }

    /// The parents of a local node after `previous`, its author's previous
    /// node: it, then the heads whose authors never equivocated, then the
    /// others, [`MAX_PARENTS`] in all.
    fn parents_after(&self, previous: Option<&Cid<H>>) -> BTreeSet<Cid<H>> {
        let mut parents: BTreeSet<Cid<H>> = previous.into_iter().cloned().collect();
        let forked = |author: &Author| {
            self.equivocations
                .range((*author, 0)..=(*author, u64::MAX))
                .next()
                .is_some()
        };
        let honest = self.heads.iter().filter(|(_, (author, _))| !forked(author));
        let forks = self.heads.iter().filter(|(_, (author, _))| forked(author));
        for (cid, _) in honest.chain(forks) {
            if parents.len() == MAX_PARENTS {
                break;
            }
            parents.insert(cid.clone());
        }
        parents
    }

    /// Record a local operation: a node of `ops` signed by `key`, after its
    /// author's previous node and as many heads as the node names
    /// ([`MAX_PARENTS`] parents in all, heads of authors that never
    /// equivocated first), applied in place and queued in the outbox, in
    /// one commit. The heads it does not name stay heads, for the next
    /// local node.
    pub fn record<A: Apply<H, O>>(
        &mut self,
        key: &SigningKey,
        ops: O,
        crdt: &mut A,
    ) -> Result<Cid<H>, Error<S::Error, A::Error>> {
        let author = Author::from(key);
        let (seq, previous) = match self.latest.get(&author) {
            Some((seq, previous)) => (seq + 1, Some(previous)),
            None => (0, None),
        };
        let parents = self.parents_after(previous);
        let node = Node::<H, O>::sign(key, &self.scope, seq, ops, parents);
        let bytes = node.to_bytes();
        if signed::decode::<H, O>(&bytes).is_none() {
            return Err(Error::Unencodable);
        }
        let cid = Cid(H::hash(&bytes));
        let mut rows = Overlay::new(&self.store);
        let event = Event {
            cid: &cid,
            author: &author,
            seq,
            parents: &node.parents,
            ops: &node.payload.ops,
            equivocation: false,
        };
        let result = crdt.apply(event, &mut rows);
        settle(&mut rows, result)?;
        let unheaded: Vec<Cid<H>> = node
            .parents
            .iter()
            .filter(|parent| self.heads.contains_key(*parent))
            .cloned()
            .collect();
        self.store
            .commit(Changes {
                applied: alloc::vec![Applied {
                    cid: cid.clone(),
                    author,
                    seq,
                    bytes,
                }],
                heads_added: alloc::vec![(cid.clone(), author, seq)],
                heads_removed: unheaded.clone(),
                latest: alloc::vec![(author, seq, cid.clone())],
                outbox: alloc::vec![(author, seq, cid.clone())],
                rows: rows.written,
                ..Changes::default()
            })
            .map_err(Error::Store)?;
        for parent in &unheaded {
            self.heads.remove(parent);
        }
        self.heads.insert(cid.clone(), (author, seq));
        self.latest.insert(author, (seq, cid.clone()));
        self.outbox.insert((author, seq), cid.clone());
        Ok(cid)
    }

    /// The local nodes not yet pushed, each author's oldest first, with
    /// their bytes.
    pub fn outbox(&self) -> Result<Vec<Outgoing<H>>, Error<S::Error>> {
        self.outbox
            .iter()
            .map(|((author, seq), cid)| match self.store.node(cid) {
                Ok(Some(bytes)) => Ok(Outgoing {
                    author: *author,
                    seq: *seq,
                    cid: cid.clone(),
                    bytes,
                }),
                Ok(None) => Err(Error::Corrupt),
                Err(error) => Err(Error::Store(error)),
            })
            .collect()
    }

    /// Mark local nodes pushed: each `(author, seq)` given and its
    /// author's earlier nodes.
    pub fn pushed(&mut self, nodes: &[(Author, u64)]) -> Result<(), S::Error> {
        let pushed: Vec<(Author, u64)> = self
            .outbox
            .keys()
            .filter(|(author, seq)| nodes.iter().any(|(a, s)| a == author && seq <= s))
            .copied()
            .collect();
        if pushed.is_empty() {
            return Ok(());
        }
        self.store.commit(Changes {
            pushed: pushed.clone(),
            ..Changes::default()
        })?;
        for node in pushed {
            self.outbox.remove(&node);
        }
        Ok(())
    }

    /// Drop held nodes: `author`'s, or every one for `None`, in one commit.
    /// They are not refused: delivered again once their parents are
    /// applied, they apply. The number dropped.
    pub fn drop_held(&mut self, author: Option<&Author>) -> Result<usize, S::Error> {
        let dropped: Vec<Cid<H>> = self
            .holding
            .iter()
            .filter(|(_, holding)| author.is_none_or(|author| *author == holding.author))
            .map(|(cid, _)| cid.clone())
            .collect();
        if dropped.is_empty() {
            return Ok(0);
        }
        self.store.commit(Changes {
            released: dropped.clone(),
            ..Changes::default()
        })?;
        for cid in &dropped {
            self.unhold(cid);
        }
        Ok(dropped.len())
    }

    /// Validate and apply nodes from a peer or a feed, in one commit.
    ///
    /// Each node's bytes are checked statelessly first ([`validate`]); then
    /// the nodes whose parents are all applied are applied in causal
    /// order, each after its author's chain is checked and the
    /// equivocations found, and the nodes they release with them. The
    /// rest are held, within the held nodes' bounds, and dropped past
    /// them. Duplicates are counted and skipped. `cursor`, when given, is
    /// stored in the same commit: the position the nodes were read to.
    pub fn ingest<A: Apply<H, O>>(
        &mut self,
        items: impl IntoIterator<Item = Vec<u8>>,
        cursor: Option<u64>,
        crdt: &mut A,
    ) -> Result<Ingested<H>, Error<S::Error, A::Error>> {
        let mut report = Ingested::default();
        let mut refused = BTreeSet::new();
        let mut forged = BTreeSet::new();
        let mut fresh: Fresh<H, O> = BTreeMap::new();
        for bytes in items {
            match validate::<H, O>(&self.scope, &bytes) {
                Err((None, refusal)) => report.refused.push((None, refusal)),
                Err((Some(cid), _)) => {
                    if self.refused.contains(&cid) || !forged.insert(cid) {
                        report.duplicates += 1;
                    }
                }
                Ok((cid, node)) => {
                    if fresh.contains_key(&cid) || self.known(&cid).map_err(Error::Store)? {
                        report.duplicates += 1;
                    } else {
                        fresh.insert(cid, (node, bytes));
                    }
                }
            }
        }

        // Each fresh node's parents not applied, the fresh nodes waiting on
        // each, and the nodes ready to apply.
        let mut remaining: BTreeMap<Cid<H>, usize> = BTreeMap::new();
        let mut children: BTreeMap<Cid<H>, Vec<Cid<H>>> = BTreeMap::new();
        let mut waits: BTreeMap<Cid<H>, Vec<Cid<H>>> = BTreeMap::new();
        let mut ready = VecDeque::new();
        let mut dead = Vec::new();
        for (cid, (node, _)) in &fresh {
            let mut count = 0;
            for parent in &node.parents {
                if self.refused.contains(parent) || forged.contains(parent) {
                    dead.push(cid.clone());
                }
                if !self.store.contains(parent).map_err(Error::Store)? {
                    children
                        .entry(parent.clone())
                        .or_default()
                        .push(cid.clone());
                    waits.entry(cid.clone()).or_default().push(parent.clone());
                    count += 1;
                }
            }
            remaining.insert(cid.clone(), count);
            if count == 0 {
                ready.push_back(cid.clone());
            }
        }
        ready.extend(
            self.missing
                .iter()
                .filter(|(_, count)| **count == 0)
                .map(|(cid, _)| cid.clone()),
        );

        let mut changes = Changes::default();
        let mut heads_added: BTreeMap<Cid<H>, (Author, u64)> = BTreeMap::new();
        let mut heads_removed: BTreeSet<Cid<H>> = BTreeSet::new();
        let mut latest: BTreeMap<Author, (u64, Cid<H>)> = BTreeMap::new();
        // The nodes the batch applies, by author and number: one at each
        // number, and each.
        let mut firsts: BTreeMap<(Author, u64), Cid<H>> = BTreeMap::new();
        let mut authored: BTreeSet<(Author, u64, Cid<H>)> = BTreeSet::new();
        let mut equivocations = BTreeSet::new();
        let mut rows = Overlay::new(&self.store);
        let mut released = BTreeSet::new();

        // A refused node's descendants among the fresh and held nodes are
        // refused with it.
        let refuse = |cid: Cid<H>,
                      refusal: Refusal,
                      report: &mut Ingested<H>,
                      refused: &mut BTreeSet<Cid<H>>,
                      released: &mut BTreeSet<Cid<H>>| {
            let mut stack = alloc::vec![(cid, refusal)];
            while let Some((cid, refusal)) = stack.pop() {
                if !refused.insert(cid.clone()) {
                    continue;
                }
                if self.missing.contains_key(&cid) {
                    released.insert(cid.clone());
                }
                report.refused.push((Some(cid.clone()), refusal));
                let kids = children.get(&cid).into_iter().flatten();
                let held = self.waiting.get(&cid).into_iter().flatten();
                for kid in kids.chain(held) {
                    stack.push((kid.clone(), Refusal::RefusedParent));
                }
            }
        };
        // A forged node releases the held nodes waiting on it, refused.
        for cid in forged {
            refuse(
                cid,
                Refusal::BadSignature,
                &mut report,
                &mut refused,
                &mut released,
            );
        }
        for cid in dead {
            refuse(
                cid,
                Refusal::RefusedParent,
                &mut report,
                &mut refused,
                &mut released,
            );
        }

        while let Some(cid) = ready.pop_front() {
            if refused.contains(&cid) {
                continue;
            }
            let (node, bytes) = match fresh.remove(&cid) {
                Some(entry) => entry,
                None => {
                    released.insert(cid.clone());
                    let bytes = self
                        .store
                        .held(&cid)
                        .map_err(Error::Store)?
                        .ok_or(Error::Corrupt)?;
                    let node = signed::decode::<H, O>(&bytes).ok_or(Error::Corrupt)?;
                    (node, bytes)
                }
            };
            let author = node.payload.author;
            let seq = node.payload.seq;
            // One of its parents is its author's node at `seq - 1`: a point
            // lookup a parent, at most [`MAX_PARENTS`].
            if seq > 0 {
                let mut follows = false;
                for parent in &node.parents {
                    if authored.contains(&(author, seq - 1, parent.clone()))
                        || self
                            .store
                            .is_authored(&author, seq - 1, parent)
                            .map_err(Error::Store)?
                    {
                        follows = true;
                        break;
                    }
                }
                if !follows {
                    refuse(
                        cid,
                        Refusal::BrokenChain,
                        &mut report,
                        &mut refused,
                        &mut released,
                    );
                    continue;
                }
            }
            let same = match self.store.authored(&author, seq).map_err(Error::Store)? {
                Some(applied) => Some(applied),
                None => firsts.get(&(author, seq)).cloned(),
            };
            let equivocation = same.is_some();
            if let Some(first) = same
                && !self.equivocations.contains(&(author, seq))
                && equivocations.insert((author, seq))
            {
                report.equivocations.push(Equivocation {
                    author,
                    seq,
                    nodes: [first, cid.clone()],
                });
            }
            firsts.entry((author, seq)).or_insert_with(|| cid.clone());
            authored.insert((author, seq, cid.clone()));
            for parent in &node.parents {
                if heads_added.remove(parent).is_none() && self.heads.contains_key(parent) {
                    heads_removed.insert(parent.clone());
                }
            }
            heads_added.insert(cid.clone(), (author, seq));
            let higher = |known: Option<&(u64, Cid<H>)>| known.is_none_or(|(at, _)| seq > *at);
            if higher(latest.get(&author)) && higher(self.latest.get(&author)) {
                latest.insert(author, (seq, cid.clone()));
            }
            let event = Event {
                cid: &cid,
                author: &author,
                seq,
                parents: &node.parents,
                ops: &node.payload.ops,
                equivocation,
            };
            let result = crdt.apply(event, &mut rows);
            settle(&mut rows, result)?;
            changes.applied.push(Applied {
                cid: cid.clone(),
                author,
                seq,
                bytes,
            });
            report.applied.push(cid.clone());

            let kids = children.get(&cid).into_iter().flatten();
            let held = self.waiting.get(&cid).into_iter().flatten();
            for kid in kids.chain(held) {
                let count = match remaining.get_mut(kid) {
                    Some(count) => count,
                    None => match self.missing.get(kid) {
                        Some(count) => remaining.entry(kid.clone()).or_insert(*count),
                        // Refused since it waited.
                        None => continue,
                    },
                };
                *count -= 1;
                if *count == 0 {
                    ready.push_back(kid.clone());
                }
            }
        }

        // The fresh nodes neither applied nor refused are held, within the
        // bounds the held nodes the batch leaves take up.
        let mut count = self.missing.len() - released.len();
        let mut bytes = self.held_bytes;
        let mut by = self.held_by.clone();
        for cid in &released {
            if let Some(holding) = self.holding.get(cid) {
                bytes -= holding.len;
                if let Some(theirs) = by.get_mut(&holding.author) {
                    *theirs -= 1;
                }
            }
        }
        let mut kept: BTreeMap<Cid<H>, (Author, usize)> = BTreeMap::new();
        for (cid, (node, node_bytes)) in fresh {
            if refused.contains(&cid) {
                continue;
            }
            let author = node.payload.author;
            let theirs = by.entry(author).or_default();
            if count >= MAX_HELD
                || *theirs >= MAX_HELD_PER_AUTHOR
                || bytes + node_bytes.len() > MAX_HELD_BYTES
            {
                waits.remove(&cid);
                report.dropped.push(cid);
                continue;
            }
            count += 1;
            *theirs += 1;
            bytes += node_bytes.len();
            kept.insert(cid.clone(), (author, node_bytes.len()));
            report.held.push(cid.clone());
            changes.held.push((cid, node_bytes));
        }

        changes.released = released.iter().cloned().collect();
        changes.heads_added = heads_added
            .iter()
            .map(|(cid, (author, seq))| (cid.clone(), *author, *seq))
            .collect();
        changes.heads_removed = heads_removed.iter().cloned().collect();
        changes.latest = latest
            .iter()
            .map(|(author, (seq, cid))| (*author, *seq, cid.clone()))
            .collect();
        changes.equivocations = equivocations.iter().copied().collect();
        if cursor != self.cursor {
            changes.cursor = cursor;
        }
        changes.rows = rows.written;
        if !changes.is_empty() {
            self.store.commit(changes).map_err(Error::Store)?;
        }

        // The commit stands: move the replica's memory.
        for cid in &heads_removed {
            self.heads.remove(cid);
        }
        self.heads.extend(heads_added);
        self.latest.extend(latest);
        self.equivocations.extend(equivocations);
        if cursor.is_some() {
            self.cursor = cursor;
        }
        for cid in report.applied.iter().chain(&refused) {
            self.waiting.remove(cid);
            self.unhold(cid);
        }
        for (cid, count) in remaining {
            if self.missing.contains_key(&cid) {
                self.missing.insert(cid, count);
            }
        }
        let applied: BTreeSet<&Cid<H>> = report.applied.iter().collect();
        for cid in &report.held {
            let parents: Vec<Cid<H>> = waits
                .remove(cid)
                .into_iter()
                .flatten()
                .filter(|parent| !applied.contains(parent))
                .collect();
            let (author, len) = kept[cid];
            self.hold(
                cid.clone(),
                Holding {
                    author,
                    len,
                    waits: parents,
                },
            );
        }
        for cid in refused {
            self.remember_refused(cid);
        }
        Ok(report)
    }
}

/// The outcome of one node's apply: the store's error first, which the
/// CRDT may have seen as a missing row, then the CRDT's, then a row no
/// store takes.
fn settle<H: Hasher, S: Store<H>, A>(
    rows: &mut Overlay<'_, H, S>,
    result: Result<(), A>,
) -> Result<(), Error<S::Error, A>> {
    if let Some(error) = rows.error.take() {
        return Err(Error::Store(error));
    }
    result.map_err(Error::Apply)?;
    if rows.unfit {
        return Err(Error::Row);
    }
    Ok(())
}
