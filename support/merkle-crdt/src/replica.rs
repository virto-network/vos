use crate::apply::Overlay;
use crate::signed::{self, validate};
use crate::store::{Applied, Changes};
use crate::{Apply, Author, Cid, Decode, Encode, Event, Hasher, Node, Refusal, Scope, Store};
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::convert::Infallible;
use core::marker::PhantomData;
use ed25519_dalek::SigningKey;

/// Why a replica's operation failed. The replica's memory and store are
/// as they were before it.
#[derive(Debug)]
pub enum Error<S, A = Infallible, R = Infallible> {
    /// The store failed.
    Store(S),
    /// The CRDT refused to apply a node.
    Apply(A),
    /// The peer or the feed failed.
    Source(R),
    /// A node the store holds is missing, or does not validate.
    Corrupt,
    /// A source answered with nothing the replica wanted.
    Stalled,
    /// A feed returned positions not after the cursor, or not ascending.
    Disordered,
}

impl<S: core::fmt::Debug, A: core::fmt::Debug, R: core::fmt::Debug> core::fmt::Display
    for Error<S, A, R>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Store(error) => write!(f, "the store failed: {error:?}"),
            Error::Apply(error) => write!(f, "applying a node failed: {error:?}"),
            Error::Source(error) => write!(f, "the source failed: {error:?}"),
            Error::Corrupt => f.write_str("a stored node is missing or does not validate"),
            Error::Stalled => f.write_str("the source sent nothing that was wanted"),
            Error::Disordered => f.write_str("the feed's positions do not ascend from the cursor"),
        }
    }
}

#[cfg(feature = "std")]
impl<S: core::fmt::Debug, A: core::fmt::Debug, R: core::fmt::Debug> std::error::Error
    for Error<S, A, R>
{
}

/// Two applied nodes of one author at one sequence number. Both stay in
/// the DAG, since other authors' nodes may name either; the CRDT's reads
/// filter the author's operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation<H: Hasher> {
    /// The author.
    pub author: Author,
    /// The sequence number signed twice.
    pub seq: u64,
    /// The node applied first, and the one found equivocating.
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
            refused: Vec::new(),
            equivocations: Vec::new(),
            duplicates: 0,
        }
    }
}

impl<H: Hasher> Ingested<H> {
    pub(crate) fn absorb(&mut self, other: Ingested<H>) {
        self.applied.extend(other.applied);
        self.held.extend(other.held);
        self.refused.extend(other.refused);
        self.equivocations.extend(other.equivocations);
        self.duplicates += other.duplicates;
    }
}

/// One scope's replica: its DAG applied onto its CRDT, incrementally.
///
/// It keeps in memory only the heads, each author's latest sequence
/// number, the equivocations, the cursor, the outbox and the held nodes'
/// missing parents; the nodes and the CRDT's rows stay in the store.
///
/// - [`ingest`](Self::ingest) validates and applies only the nodes it is
///   given, in causal order, onto the current rows; a node whose parents
///   have not arrived is held, durably, and applied in the batch that
///   brings its last parent. The heads move by the applied nodes'
///   parents alone.
/// - [`record`](Self::record) applies a local operation in place.
/// - [`rebuild`](crate::rebuild) is the full validation and replay, for
///   recovery and audits.
///
/// Every method that writes commits one [`Changes`] batch, and moves
/// the replica's memory only once it is committed.
pub struct Replica<H: Hasher, O, S: Store<H>> {
    store: S,
    heads: BTreeSet<Cid<H>>,
    latest: BTreeMap<Author, (u64, Cid<H>)>,
    equivocations: BTreeSet<(Author, u64)>,
    cursor: Option<u64>,
    outbox: BTreeMap<(Author, u64), Cid<H>>,
    /// The scope the nodes are signed for.
    scope: Scope,
    /// Each held node's count of parents not applied.
    missing: BTreeMap<Cid<H>, usize>,
    /// Each held node's parents not applied when it was held.
    waits: BTreeMap<Cid<H>, Vec<Cid<H>>>,
    /// For each parent not applied, the held nodes waiting on it.
    waiting: BTreeMap<Cid<H>, BTreeSet<Cid<H>>>,
    /// Nodes refused since the replica opened.
    refused: BTreeSet<Cid<H>>,
    ops: PhantomData<fn() -> O>,
}

impl<H: Hasher, O: Encode + Decode, S: Store<H>> Replica<H, O, S> {
    /// Open the replica of `scope` its store holds; an empty store is an
    /// empty scope.
    pub fn open(store: S, scope: Scope) -> Result<Self, Error<S::Error>> {
        let loaded = store.load().map_err(Error::Store)?;
        let mut replica = Self {
            scope,
            waits: BTreeMap::new(),
            store,
            heads: loaded.heads,
            latest: loaded.latest,
            equivocations: loaded.equivocations,
            cursor: loaded.cursor,
            outbox: loaded.outbox,
            missing: BTreeMap::new(),
            waiting: BTreeMap::new(),
            refused: BTreeSet::new(),
            ops: PhantomData,
        };
        for (cid, bytes) in loaded.held {
            let header = crate::Header::<H>::read(&bytes).ok_or(Error::Corrupt)?;
            let mut waits = Vec::new();
            for parent in header.parents {
                if !replica.store.contains(&parent).map_err(Error::Store)? {
                    replica
                        .waiting
                        .entry(parent.clone())
                        .or_default()
                        .insert(cid.clone());
                    waits.push(parent);
                }
            }
            replica.missing.insert(cid.clone(), waits.len());
            replica.waits.insert(cid, waits);
        }
        Ok(replica)
    }

    /// The applied nodes no applied node follows.
    pub fn heads(&self) -> &BTreeSet<Cid<H>> {
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

    /// The store, given back.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Whether `cid` is applied, held or refused.
    pub(crate) fn known(&self, cid: &Cid<H>) -> Result<bool, S::Error> {
        Ok(self.missing.contains_key(cid)
            || self.refused.contains(cid)
            || self.store.contains(cid)?)
    }

    /// Record a local operation: a node of `ops` signed by `key`, after
    /// every head and the author's previous node, applied in place and
    /// queued in the outbox, in one commit.
    pub fn record<A: Apply<H, O>>(
        &mut self,
        key: &SigningKey,
        ops: O,
        crdt: &mut A,
    ) -> Result<Cid<H>, Error<S::Error, A::Error>> {
        let author = Author::from(key);
        let mut parents = self.heads.clone();
        let seq = match self.latest.get(&author) {
            Some((seq, previous)) => {
                parents.insert(previous.clone());
                seq + 1
            }
            None => 0,
        };
        let node = Node::<H, O>::sign(key, &self.scope, seq, ops, parents);
        let bytes = node.to_bytes();
        let cid = Cid(H::hash(&bytes));
        let mut rows = Overlay::new(Some(&self.store));
        let event = Event {
            cid: &cid,
            author: &author,
            seq,
            parents: &node.parents,
            ops: &node.payload.ops,
        };
        crdt.apply(event, &mut rows).map_err(Error::Apply)?;
        if let Some(error) = rows.error {
            return Err(Error::Store(error));
        }
        let heads = BTreeSet::from([cid.clone()]);
        self.store
            .commit(Changes {
                applied: alloc::vec![Applied {
                    cid: cid.clone(),
                    author,
                    seq,
                    bytes,
                }],
                heads: Some(heads.clone()),
                latest: alloc::vec![(author, seq, cid.clone())],
                outbox: alloc::vec![(author, seq, cid.clone())],
                rows: rows.written,
                ..Changes::default()
            })
            .map_err(Error::Store)?;
        self.heads = heads;
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

    /// Validate and apply nodes from a peer or a feed, in one commit.
    ///
    /// Each node's bytes are checked statelessly first ([`validate`]); then
    /// the nodes whose parents are all applied are applied in causal
    /// order, each after its author's chain is checked and the
    /// equivocations found, and the nodes they release with them. The
    /// rest are held. Duplicates are counted and skipped. `cursor`, when
    /// given, is stored in the same commit: the position the nodes were
    /// read to.
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
        let mut heads = self.heads.clone();
        let mut latest: BTreeMap<Author, (u64, Cid<H>)> = BTreeMap::new();
        let mut authored: BTreeMap<(Author, u64), Vec<Cid<H>>> = BTreeMap::new();
        let mut equivocations = BTreeSet::new();
        let mut rows = Overlay::new(Some(&self.store));
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
            let lookup = |seq: u64| -> Result<Vec<Cid<H>>, S::Error> {
                let mut cids = self.store.authored(&author, seq)?;
                cids.extend(authored.get(&(author, seq)).into_iter().flatten().cloned());
                Ok(cids)
            };
            if seq > 0 {
                let previous = lookup(seq - 1).map_err(Error::Store)?;
                if !previous.iter().any(|cid| node.parents.contains(cid)) {
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
            let same = lookup(seq).map_err(Error::Store)?;
            if let Some(first) = same.first()
                && !self.equivocations.contains(&(author, seq))
                && equivocations.insert((author, seq))
            {
                report.equivocations.push(Equivocation {
                    author,
                    seq,
                    nodes: [first.clone(), cid.clone()],
                });
            }
            authored.entry((author, seq)).or_default().push(cid.clone());
            for parent in &node.parents {
                heads.remove(parent);
            }
            heads.insert(cid.clone());
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
            };
            crdt.apply(event, &mut rows).map_err(Error::Apply)?;
            if let Some(error) = rows.error.take() {
                return Err(Error::Store(error));
            }
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

        // The fresh nodes neither applied nor refused are held.
        for (cid, (_, bytes)) in fresh {
            if !refused.contains(&cid) {
                report.held.push(cid.clone());
                changes.held.push((cid, bytes));
            }
        }

        changes.released = released.iter().cloned().collect();
        if heads != self.heads {
            changes.heads = Some(heads.clone());
        }
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
        self.heads = heads;
        self.latest.extend(latest);
        self.equivocations.extend(equivocations);
        if cursor.is_some() {
            self.cursor = cursor;
        }
        for cid in report.applied.iter().chain(&refused) {
            self.missing.remove(cid);
            self.waiting.remove(cid);
            for parent in self.waits.remove(cid).into_iter().flatten() {
                if let Some(kids) = self.waiting.get_mut(&parent) {
                    kids.remove(cid);
                    if kids.is_empty() {
                        self.waiting.remove(&parent);
                    }
                }
            }
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
            for parent in &parents {
                self.waiting
                    .entry(parent.clone())
                    .or_default()
                    .insert(cid.clone());
            }
            self.missing.insert(cid.clone(), parents.len());
            self.waits.insert(cid.clone(), parents);
        }
        self.refused.extend(refused);
        Ok(report)
    }
}
