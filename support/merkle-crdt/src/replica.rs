use crate::apply::Overlay;
use crate::signed::{self, validate};
use crate::store::{Applied, Changes};
use crate::{
    Apply, Author, Cid, Decode, Encode, Hasher, Header, MAX_PARENTS, Node, Refusal, Scope, Store,
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

/// Why a replica's operation failed. The replica's memory is as it was
/// before it, and so is its store but after [`Error::Store`] from a commit,
/// when it is not known until the store is opened again.
#[derive(Debug)]
pub enum Error<S, A = Infallible> {
    /// The store failed.
    Store(S),
    /// The CRDT refused to apply a node.
    Apply(A),
    /// A node the store holds is missing, or does not validate.
    Corrupt,
    /// The CRDT wrote a row past the row bounds ([`Rows::write`](crate::Rows::write)).
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
            Error::Row => f.write_str("a row's key or value is past the row bounds"),
            Error::Unencodable => f.write_str("the operations make a node that does not decode"),
        }
    }
}

#[cfg(feature = "std")]
impl<S: core::fmt::Debug, A: core::fmt::Debug> std::error::Error for Error<S, A> {}

/// Two applied nodes of one author at one sequence number. Both stay in
/// the DAG, since other authors' nodes may name either; the CRDT's reads
/// filter the author's operations.
#[derive(Debug)]
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

/// The nodes of one ingest not yet known: those that validate, and the
/// CIDs of those whose signature is not their author's.
struct Admitted<H: Hasher, O> {
    fresh: Fresh<H, O>,
    forged: BTreeSet<Cid<H>>,
}

/// A local node not yet pushed.
#[derive(Debug)]
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

/// A held node: its author, its size, its parents not applied when it was
/// held, and how many of them are still not applied.
struct Holding<H: Hasher> {
    author: Author,
    len: usize,
    waits: Vec<Cid<H>>,
    missing: usize,
}

impl<H: Hasher> Holding<H> {
    fn new(author: Author, len: usize, waits: Vec<Cid<H>>) -> Self {
        let missing = waits.len();
        Self {
            author,
            len,
            waits,
            missing,
        }
    }
}

/// What one ingest has done so far, committed at its end.
struct Batch<H: Hasher> {
    report: Ingested<H>,
    /// Each fresh node's parents not applied, and each held node's the
    /// batch has applied one of.
    remaining: BTreeMap<Cid<H>, usize>,
    /// Each fresh node's parents not applied when the batch began.
    waits: BTreeMap<Cid<H>, Vec<Cid<H>>>,
    /// For each parent not applied, the fresh nodes naming it.
    children: BTreeMap<Cid<H>, Vec<Cid<H>>>,
    /// The nodes whose parents are all applied, to apply.
    ready: VecDeque<Cid<H>>,
    /// The nodes refused, fresh or held.
    refused: BTreeSet<Cid<H>>,
    /// The held nodes applied or refused.
    released: BTreeSet<Cid<H>>,
    applied: Vec<Applied<H>>,
    held: Vec<(Cid<H>, Vec<u8>)>,
    /// The nodes the batch applied at each (author, number).
    authored: BTreeMap<(Author, u64), BTreeSet<Cid<H>>>,
    heads_added: BTreeMap<Cid<H>, (Author, u64)>,
    heads_removed: BTreeSet<Cid<H>>,
    latest: BTreeMap<Author, (u64, Cid<H>)>,
    equivocations: BTreeSet<(Author, u64)>,
}

/// One scope's replica: its DAG applied onto its CRDT, incrementally, by
/// [`ingest`](Self::ingest) and [`record`](Self::record).
///
/// It keeps in memory the heads, each author's latest sequence number, the
/// equivocations, the cursor, the outbox, the held nodes' missing parents
/// (at most [`MAX_HELD`] nodes) and the latest refused nodes' CIDs; the
/// nodes and the CRDT's rows stay in the store. One replica a store. Every
/// method that writes commits one [`Changes`] batch, and moves the
/// replica's memory only once it is committed.
pub struct Replica<H: Hasher, O, S: Store<H>> {
    store: S,
    heads: BTreeMap<Cid<H>, (Author, u64)>,
    latest: BTreeMap<Author, (u64, Cid<H>)>,
    equivocations: BTreeSet<(Author, u64)>,
    cursor: Option<u64>,
    outbox: BTreeMap<(Author, u64), Cid<H>>,
    /// The scope the nodes are signed for.
    scope: Scope,
    /// The held nodes.
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
    /// headers; a replica holds no more than its bounds, so neither does a
    /// store only replicas wrote.
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
            replica.hold(cid, Holding::new(header.author, bytes.len(), waits));
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
        self.holding.len()
    }

    /// The parents the held nodes wait on that are not held themselves:
    /// what to ask a peer for.
    pub fn wanted(&self) -> Vec<Cid<H>> {
        self.waiting
            .keys()
            .filter(|cid| !self.holding.contains_key(*cid))
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
        Ok(self.holding.contains_key(cid)
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
        *self.held_by.entry(holding.author).or_default() += 1;
        self.held_bytes += holding.len;
        self.holding.insert(cid, holding);
    }

    /// Forget `cid` as held, if it is.
    fn unhold(&mut self, cid: &Cid<H>) {
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

    /// The parents `record` names after `previous`, its author's previous
    /// node.
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
        rows.apply(crdt, &cid, &node, false)?;
        let unheaded: BTreeSet<Cid<H>> = node
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
                heads_added: BTreeMap::from([(cid.clone(), (author, seq))]),
                heads_removed: unheaded.clone(),
                latest: BTreeMap::from([(author, (seq, cid.clone()))]),
                outbox: BTreeMap::from([((author, seq), cid.clone())]),
                rows: rows.into_written(),
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
            .map(|((author, seq), cid)| {
                let bytes = self
                    .store
                    .node(cid)
                    .map_err(Error::Store)?
                    .ok_or(Error::Corrupt)?;
                Ok(Outgoing {
                    author: *author,
                    seq: *seq,
                    cid: cid.clone(),
                    bytes,
                })
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
            released: dropped.iter().cloned().collect(),
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
        let Admitted { mut fresh, forged } =
            self.admit(items, &mut report).map_err(Error::Store)?;
        let mut batch = self.plan(report, &fresh, forged).map_err(Error::Store)?;

        let mut rows = Overlay::new(&self.store);
        while let Some(cid) = batch.ready.pop_front() {
            if batch.refused.contains(&cid) {
                continue;
            }
            let (node, bytes) = match fresh.remove(&cid) {
                Some(entry) => entry,
                None => {
                    batch.released.insert(cid.clone());
                    let bytes = self
                        .store
                        .held(&cid)
                        .map_err(Error::Store)?
                        .ok_or(Error::Corrupt)?;
                    let node = signed::decode::<H, O>(&bytes).ok_or(Error::Corrupt)?;
                    (node, bytes)
                }
            };
            if !self.follows(&batch, &node).map_err(Error::Store)? {
                self.refuse(&mut batch, cid, Refusal::BrokenChain);
                continue;
            }
            let equivocation = self.place(&mut batch, &cid, &node).map_err(Error::Store)?;
            rows.apply(crdt, &cid, &node, equivocation)?;
            for kid in self.kids(&batch.children, &cid) {
                let count = match batch.remaining.get_mut(kid) {
                    Some(count) => count,
                    None => match self.holding.get(kid) {
                        Some(held) => batch.remaining.entry(kid.clone()).or_insert(held.missing),
                        // Refused since it waited.
                        None => continue,
                    },
                };
                *count -= 1;
                if *count == 0 {
                    batch.ready.push_back(kid.clone());
                }
            }
            batch.applied.push(Applied {
                cid: cid.clone(),
                author: node.author,
                seq: node.seq,
                bytes,
            });
            batch.report.applied.push(cid);
        }
        let held = self.hold_fresh(fresh, &mut batch);

        let changes = Changes {
            applied: core::mem::take(&mut batch.applied),
            held: core::mem::take(&mut batch.held),
            released: core::mem::take(&mut batch.released),
            heads_added: batch.heads_added.clone(),
            heads_removed: batch.heads_removed.clone(),
            latest: batch.latest.clone(),
            equivocations: batch.equivocations.clone(),
            cursor: if cursor != self.cursor { cursor } else { None },
            rows: rows.into_written(),
            ..Changes::default()
        };
        if !changes.is_empty() {
            self.store.commit(changes).map_err(Error::Store)?;
        }
        Ok(self.settle(batch, held, cursor))
    }

    /// The nodes of `items` neither known nor repeated; the rest go in
    /// `report`.
    fn admit(
        &self,
        items: impl IntoIterator<Item = Vec<u8>>,
        report: &mut Ingested<H>,
    ) -> Result<Admitted<H, O>, S::Error> {
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
                    if fresh.contains_key(&cid) || self.known(&cid)? {
                        report.duplicates += 1;
                    } else {
                        fresh.insert(cid, (node, bytes));
                    }
                }
            }
        }
        Ok(Admitted { fresh, forged })
    }

    /// The batch that applies `fresh`: the nodes whose parents are all
    /// applied, held nodes too, ready; the rest waiting on their parents;
    /// and the forged nodes refused, with every node naming one or a node
    /// refused before.
    fn plan(
        &self,
        report: Ingested<H>,
        fresh: &Fresh<H, O>,
        forged: BTreeSet<Cid<H>>,
    ) -> Result<Batch<H>, S::Error> {
        let mut batch = Batch {
            report,
            remaining: BTreeMap::new(),
            waits: BTreeMap::new(),
            children: BTreeMap::new(),
            ready: VecDeque::new(),
            refused: BTreeSet::new(),
            released: BTreeSet::new(),
            applied: Vec::new(),
            held: Vec::new(),
            authored: BTreeMap::new(),
            heads_added: BTreeMap::new(),
            heads_removed: BTreeSet::new(),
            latest: BTreeMap::new(),
            equivocations: BTreeSet::new(),
        };
        let mut dead = Vec::new();
        for (cid, (node, _)) in fresh {
            let refused =
                |parent: &Cid<H>| self.refused.contains(parent) || forged.contains(parent);
            if node.parents.iter().any(refused) {
                dead.push(cid.clone());
            }
            let mut count = 0;
            for parent in &node.parents {
                if !self.store.contains(parent)? {
                    batch
                        .children
                        .entry(parent.clone())
                        .or_default()
                        .push(cid.clone());
                    batch
                        .waits
                        .entry(cid.clone())
                        .or_default()
                        .push(parent.clone());
                    count += 1;
                }
            }
            batch.remaining.insert(cid.clone(), count);
            if count == 0 {
                batch.ready.push_back(cid.clone());
            }
        }
        batch.ready.extend(
            self.holding
                .iter()
                .filter(|(_, held)| held.missing == 0)
                .map(|(cid, _)| cid.clone()),
        );
        // A forged node releases the held nodes waiting on it, refused.
        for cid in forged {
            self.refuse(&mut batch, cid, Refusal::BadSignature);
        }
        for cid in dead {
            self.refuse(&mut batch, cid, Refusal::RefusedParent);
        }
        Ok(batch)
    }

    /// The fresh nodes (`children`) and held nodes waiting on `cid`.
    fn kids<'a>(
        &'a self,
        children: &'a BTreeMap<Cid<H>, Vec<Cid<H>>>,
        cid: &Cid<H>,
    ) -> impl Iterator<Item = &'a Cid<H>> + use<'a, H, O, S> {
        let fresh = children.get(cid).into_iter().flatten();
        let held = self.waiting.get(cid).into_iter().flatten();
        fresh.chain(held)
    }

    /// Refuse `cid`, and its descendants among the fresh and held nodes
    /// with it.
    fn refuse(&self, batch: &mut Batch<H>, cid: Cid<H>, refusal: Refusal) {
        let mut stack = alloc::vec![(cid, refusal)];
        while let Some((cid, refusal)) = stack.pop() {
            if !batch.refused.insert(cid.clone()) {
                continue;
            }
            if self.holding.contains_key(&cid) {
                batch.released.insert(cid.clone());
            }
            batch.report.refused.push((Some(cid.clone()), refusal));
            let kids = self.kids(&batch.children, &cid);
            stack.extend(kids.map(|kid| (kid.clone(), Refusal::RefusedParent)));
        }
    }

    /// Whether `node` follows its author's previous node: its first, or
    /// one of its parents is its author's node at the number before, one
    /// point lookup a parent.
    fn follows(&self, batch: &Batch<H>, node: &Node<H, O>) -> Result<bool, S::Error> {
        let (author, seq) = (node.author, node.seq);
        let Some(before) = seq.checked_sub(1) else {
            return Ok(true);
        };
        let in_batch = batch.authored.get(&(author, before));
        for parent in &node.parents {
            if in_batch.is_some_and(|cids| cids.contains(parent))
                || self.store.is_authored(&author, before, parent)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Place the applied `cid` among its author's nodes, the heads and the
    /// latest numbers, reporting an equivocation it is the first to show;
    /// whether it equivocates.
    fn place(
        &self,
        batch: &mut Batch<H>,
        cid: &Cid<H>,
        node: &Node<H, O>,
    ) -> Result<bool, S::Error> {
        let (author, seq) = (node.author, node.seq);
        // The batch's earlier node is reported only while it is the one:
        // a third at the number finds the pair reported.
        let earlier = self.store.authored(&author, seq)?.or_else(|| {
            let cids = batch.authored.get(&(author, seq))?;
            cids.first().cloned()
        });
        let equivocation = earlier.is_some();
        if let Some(first) = earlier
            && !self.equivocations.contains(&(author, seq))
            && batch.equivocations.insert((author, seq))
        {
            batch.report.equivocations.push(Equivocation {
                author,
                seq,
                nodes: [first, cid.clone()],
            });
        }
        batch
            .authored
            .entry((author, seq))
            .or_default()
            .insert(cid.clone());
        for parent in &node.parents {
            if batch.heads_added.remove(parent).is_none() && self.heads.contains_key(parent) {
                batch.heads_removed.insert(parent.clone());
            }
        }
        batch.heads_added.insert(cid.clone(), (author, seq));
        let higher = |known: Option<&(u64, Cid<H>)>| known.is_none_or(|(at, _)| seq > *at);
        if higher(batch.latest.get(&author)) && higher(self.latest.get(&author)) {
            batch.latest.insert(author, (seq, cid.clone()));
        }
        Ok(equivocation)
    }

    /// Hold the fresh nodes neither applied nor refused, within the bounds
    /// the held nodes the batch leaves take up, and drop the rest: what to
    /// hold once the batch commits.
    fn hold_fresh(&self, fresh: Fresh<H, O>, batch: &mut Batch<H>) -> Vec<(Cid<H>, Holding<H>)> {
        let mut count = self.holding.len() - batch.released.len();
        let mut bytes = self.held_bytes;
        let mut by = self.held_by.clone();
        for cid in &batch.released {
            if let Some(holding) = self.holding.get(cid) {
                bytes -= holding.len;
                if let Some(theirs) = by.get_mut(&holding.author) {
                    *theirs -= 1;
                }
            }
        }
        let applied: BTreeSet<&Cid<H>> = batch.report.applied.iter().collect();
        let mut held = Vec::new();
        for (cid, (node, node_bytes)) in fresh {
            if batch.refused.contains(&cid) {
                continue;
            }
            let author = node.author;
            let theirs = by.entry(author).or_default();
            if count >= MAX_HELD
                || *theirs >= MAX_HELD_PER_AUTHOR
                || bytes + node_bytes.len() > MAX_HELD_BYTES
            {
                batch.report.dropped.push(cid);
                continue;
            }
            count += 1;
            *theirs += 1;
            bytes += node_bytes.len();
            let parents = batch.waits.remove(&cid).into_iter().flatten();
            let waits = parents.filter(|parent| !applied.contains(parent)).collect();
            held.push((cid.clone(), Holding::new(author, node_bytes.len(), waits)));
            batch.report.held.push(cid.clone());
            batch.held.push((cid, node_bytes));
        }
        held
    }

    /// Move the replica's memory by a committed batch, which holds `held`.
    fn settle(
        &mut self,
        batch: Batch<H>,
        held: Vec<(Cid<H>, Holding<H>)>,
        cursor: Option<u64>,
    ) -> Ingested<H> {
        for cid in &batch.heads_removed {
            self.heads.remove(cid);
        }
        self.heads.extend(batch.heads_added);
        self.latest.extend(batch.latest);
        self.equivocations.extend(batch.equivocations);
        if cursor.is_some() {
            self.cursor = cursor;
        }
        for cid in batch.report.applied.iter().chain(&batch.refused) {
            self.waiting.remove(cid);
            self.unhold(cid);
        }
        for (cid, count) in batch.remaining {
            if let Some(holding) = self.holding.get_mut(&cid) {
                holding.missing = count;
            }
        }
        for (cid, holding) in held {
            self.hold(cid, holding);
        }
        for cid in batch.refused {
            self.remember_refused(cid);
        }
        batch.report
    }
}
