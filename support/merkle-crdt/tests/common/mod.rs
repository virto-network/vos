//! What the suites share: a hasher, a CRDT whose result does not depend on
//! the order concurrent nodes arrive in and that catches a node applied
//! twice, a generator of signed DAGs, and the full replay of a set of
//! nodes an incremental replica is checked against.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::SigningKey;
use merkle_crdt::{Author, Cid, Event, Hasher, MAX_PARENTS, Node, Rows, Scope};

pub struct Blake2b256;

impl Hasher for Blake2b256 {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] {
        Blake2b::<U32>::digest(data).into()
    }
}

pub type H = Blake2b256;
/// The scope every generated node is signed for.
pub const SCOPE: Scope = Scope([7; 16]);
/// A node's operations: (key, value) pairs.
pub type Ops = Vec<(u64, u64)>;

pub fn key(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[index.wrapping_add(1); 32])
}

/// The CRDT: per key, the sum of every value (so a node applied twice
/// shows) and the last writer by (seq, author, index, value), the value
/// ordering an equivocation's two writes; and a row per node
/// applied, which a second apply would find and panic on.
pub fn crdt(event: Event<'_, H, Ops>, rows: &mut dyn Rows) {
    let applied = [b"n/".as_slice(), event.cid.as_ref()].concat();
    assert!(rows.read(&applied).is_none(), "a node applied twice");
    rows.write(&applied, Some(&[]));
    for (index, (key, value)) in event.ops.iter().enumerate() {
        let sum_key = [b"s/".as_slice(), &key.to_be_bytes()].concat();
        let sum = rows
            .read(&sum_key)
            .map_or(0, |bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
        rows.write(&sum_key, Some(&sum.wrapping_add(*value).to_le_bytes()));

        let lww_key = [b"w/".as_slice(), &key.to_be_bytes()].concat();
        let mut write = Vec::with_capacity(56);
        write.extend_from_slice(&event.seq.to_be_bytes());
        write.extend_from_slice(&event.author.0);
        write.extend_from_slice(&(index as u64).to_be_bytes());
        write.extend_from_slice(&value.to_le_bytes());
        if rows.read(&lww_key).is_none_or(|old| old < write) {
            rows.write(&lww_key, Some(&write));
        }
    }
}

/// One step of a generated history.
#[derive(Debug, Clone)]
pub enum Step {
    /// `author` records `ops` after the heads of its view picked by `pick`'s
    /// bits, and its own previous node.
    Record { author: u8, ops: Ops, pick: u64 },
    /// `to` learns everything `from` has seen.
    Learn { from: u8, to: u8 },
    /// `author` signs a second node at its latest sequence number.
    Equivocate { author: u8, value: u64 },
    /// `author` signs a node that skips its previous one.
    BreakChain { author: u8 },
    /// A node with a forged signature, and a node after it.
    Forge { value: u64 },
}

/// A generated DAG: every node's bytes, the equivocations signed, and the
/// nodes no honest replica applies (a broken chain and its descendants).
pub struct Dag {
    pub nodes: Vec<(Cid<H>, Vec<u8>)>,
    pub equivocations: BTreeSet<(Author, u64)>,
    pub refused: BTreeSet<Cid<H>>,
}

pub fn generate(authors: u8, steps: &[Step]) -> Dag {
    let keys: Vec<SigningKey> = (0..authors).map(key).collect();
    let mut views: Vec<BTreeSet<Cid<H>>> = vec![BTreeSet::new(); authors as usize];
    let mut latest: Vec<Option<(u64, Cid<H>)>> = vec![None; authors as usize];
    let mut parents_of: BTreeMap<Cid<H>, BTreeSet<Cid<H>>> = BTreeMap::new();
    let mut dag = Dag {
        nodes: Vec::new(),
        equivocations: BTreeSet::new(),
        refused: BTreeSet::new(),
    };
    let heads = |view: &BTreeSet<Cid<H>>, parents_of: &BTreeMap<Cid<H>, BTreeSet<Cid<H>>>| {
        let cited: BTreeSet<&Cid<H>> = view.iter().flat_map(|c| &parents_of[c]).collect();
        view.iter()
            .filter(|c| !cited.contains(c))
            .cloned()
            .collect::<Vec<_>>()
    };
    let add = |dag: &mut Dag, node: Node<H, Ops>, parents_of: &mut BTreeMap<_, _>| {
        let bytes = node.to_bytes();
        let cid = Cid(H::hash(&bytes));
        parents_of.insert(cid.clone(), node.parents.clone());
        dag.nodes.push((cid.clone(), bytes));
        cid
    };
    for step in steps {
        match step {
            Step::Record { author, ops, pick } => {
                let a = (*author % authors) as usize;
                let mut parents: BTreeSet<Cid<H>> = heads(&views[a], &parents_of)
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| pick >> (i % 64) & 1 == 1)
                    .map(|(_, c)| c)
                    .take(MAX_PARENTS - 1)
                    .collect();
                let seq = match &latest[a] {
                    Some((seq, previous)) => {
                        parents.insert(previous.clone());
                        seq + 1
                    }
                    None => 0,
                };
                let node = Node::<H, Ops>::sign(&keys[a], &SCOPE, seq, ops.clone(), parents);
                let cid = add(&mut dag, node, &mut parents_of);
                views[a].insert(cid.clone());
                latest[a] = Some((seq, cid));
            }
            Step::Learn { from, to } => {
                let (from, to) = ((*from % authors) as usize, (*to % authors) as usize);
                let learned = views[from].clone();
                views[to].extend(learned);
            }
            Step::Equivocate { author, value } => {
                let a = (*author % authors) as usize;
                let Some((seq, cid)) = latest[a].clone() else {
                    continue;
                };
                let parents = parents_of[&cid].clone();
                let node = Node::<H, Ops>::sign(&keys[a], &SCOPE, seq, vec![(0, *value)], parents);
                let twin = add(&mut dag, node, &mut parents_of);
                if twin != cid {
                    views[a].insert(twin);
                    dag.equivocations.insert((Author::from(&keys[a]), seq));
                }
            }
            Step::Forge { value } => {
                let mut forged =
                    Node::<H, Ops>::sign(&key(200), &SCOPE, 0, vec![(3, *value)], BTreeSet::new());
                forged.payload.ops.push((4, 4));
                let forged = add(&mut dag, forged, &mut parents_of);
                let after = Node::<H, Ops>::sign(
                    &key(201),
                    &SCOPE,
                    0,
                    vec![(5, *value)],
                    BTreeSet::from([forged.clone()]),
                );
                let after = add(&mut dag, after, &mut parents_of);
                dag.refused.insert(forged);
                dag.refused.insert(after);
            }
            Step::BreakChain { author } => {
                // A key of its own, so the honest chains stay valid: its
                // second node names no previous node, and a node after it
                // descends from a refused node.
                let rogue = key(100 + *author);
                let first = Node::<H, Ops>::sign(&rogue, &SCOPE, 0, vec![(9, 9)], BTreeSet::new());
                let first = add(&mut dag, first, &mut parents_of);
                let broken = Node::<H, Ops>::sign(&rogue, &SCOPE, 1, vec![(9, 1)], BTreeSet::new());
                let broken = add(&mut dag, broken, &mut parents_of);
                let after = Node::<H, Ops>::sign(
                    &rogue,
                    &SCOPE,
                    2,
                    vec![(9, 2)],
                    BTreeSet::from([broken.clone()]),
                );
                let after = add(&mut dag, after, &mut parents_of);
                dag.refused.insert(broken);
                dag.refused.insert(after);
                let _ = first;
            }
        }
    }
    dag
}

/// A small deterministic generator for delivery orders.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// `items` delivered in a random order, some twice, cut into random
/// batches.
pub fn deliveries(items: &[Vec<u8>], seed: u64) -> Vec<Vec<Vec<u8>>> {
    let mut rng = Rng(seed | 1);
    let mut all: Vec<Vec<u8>> = items.to_vec();
    for _ in 0..items.len() / 3 {
        all.push(items[rng.below(items.len())].clone());
    }
    rng.shuffle(&mut all);
    let mut batches = Vec::new();
    while !all.is_empty() {
        let take = 1 + rng.below(all.len().min(8));
        batches.push(all.drain(..take).collect());
    }
    batches
}

/// A key of its own for each `index`, beyond the 256 of [`key`].
pub fn wide_key(index: u32) -> SigningKey {
    let mut seed = [0xa5; 32];
    seed[..4].copy_from_slice(&index.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

/// What a whole set of nodes yields, replayed from nothing.
#[derive(Debug)]
pub struct Replayed {
    /// The rows the CRDT wrote.
    pub rows: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The heads, each with its author and sequence number.
    pub heads: BTreeMap<Cid<H>, (Author, u64)>,
    /// The (author, sequence number) pairs signed more than once.
    pub equivocations: BTreeSet<(Author, u64)>,
    /// Each author's highest sequence number.
    pub latest: BTreeMap<Author, u64>,
    /// The number of nodes replayed.
    pub nodes: usize,
}

/// Rows in memory, starting empty.
#[derive(Default)]
struct Fresh(BTreeMap<Vec<u8>, Option<Vec<u8>>>);

impl Rows for Fresh {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned().flatten()
    }
    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.0.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}

/// The full validation and replay of `nodes`, the applied nodes of a
/// store: each checked as an ingest would (canonical bytes, signature in
/// [`SCOPE`], every parent among them, its author's chain), all applied in
/// causal order onto empty rows. Panics on a node a replica should not
/// have applied.
pub fn replay(
    nodes: impl IntoIterator<Item = Vec<u8>>,
    crdt: &mut impl FnMut(Event<'_, H, Ops>, &mut dyn Rows),
) -> Replayed {
    let mut all = BTreeMap::new();
    for bytes in nodes {
        let (cid, node) = merkle_crdt::validate::<H, Ops>(&SCOPE, &bytes).expect("a valid node");
        all.insert(cid, node);
    }
    let mut remaining: BTreeMap<Cid<H>, usize> = BTreeMap::new();
    let mut children: BTreeMap<Cid<H>, Vec<Cid<H>>> = BTreeMap::new();
    for (cid, node) in &all {
        for parent in &node.parents {
            assert!(all.contains_key(parent), "a parent is missing");
            children
                .entry(parent.clone())
                .or_default()
                .push(cid.clone());
        }
        remaining.insert(cid.clone(), node.parents.len());
    }
    let mut ready: VecDeque<Cid<H>> = remaining
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(cid, _)| cid.clone())
        .collect();
    let mut rows = Fresh::default();
    let mut authored: BTreeMap<(Author, u64), Vec<Cid<H>>> = BTreeMap::new();
    let mut replayed = Replayed {
        rows: BTreeMap::new(),
        heads: BTreeMap::new(),
        equivocations: BTreeSet::new(),
        latest: BTreeMap::new(),
        nodes: 0,
    };
    while let Some(cid) = ready.pop_front() {
        let node = &all[&cid];
        let signed = &node.payload;
        if signed.seq > 0 {
            let previous = authored.get(&(signed.author, signed.seq - 1));
            assert!(
                previous
                    .into_iter()
                    .flatten()
                    .any(|cid| node.parents.contains(cid)),
                "a broken chain"
            );
        }
        let same = authored.entry((signed.author, signed.seq)).or_default();
        let equivocation = !same.is_empty();
        if equivocation {
            replayed.equivocations.insert((signed.author, signed.seq));
        }
        same.push(cid.clone());
        let at = replayed.latest.entry(signed.author).or_insert(signed.seq);
        *at = (*at).max(signed.seq);
        for parent in &node.parents {
            replayed.heads.remove(parent);
        }
        replayed
            .heads
            .insert(cid.clone(), (signed.author, signed.seq));
        let event = Event {
            cid: &cid,
            author: &signed.author,
            seq: signed.seq,
            parents: &node.parents,
            ops: &signed.ops,
            equivocation,
        };
        crdt(event, &mut rows);
        replayed.nodes += 1;
        for child in children.get(&cid).into_iter().flatten() {
            let count = remaining.get_mut(child).unwrap();
            *count -= 1;
            if *count == 0 {
                ready.push_back(child.clone());
            }
        }
    }
    assert_eq!(replayed.nodes, all.len(), "a cycle");
    replayed.rows = rows
        .0
        .into_iter()
        .filter_map(|(key, value)| Some((key, value?)))
        .collect();
    replayed
}

/// A server that numbers nodes as it accepted them and serves a page of
/// at most `page` after a position.
pub struct Server {
    pub items: Vec<(u64, Vec<u8>)>,
    pub page: usize,
    pub trips: usize,
}

impl Server {
    /// The page after `position`, and whether more follow.
    pub fn since(&mut self, position: Option<u64>) -> (Vec<(u64, Vec<u8>)>, bool) {
        self.trips += 1;
        let start = self
            .items
            .iter()
            .position(|(at, _)| position.is_none_or(|p| *at > p))
            .unwrap_or(self.items.len());
        let end = (start + self.page).min(self.items.len());
        (self.items[start..end].to_vec(), end < self.items.len())
    }
}

/// Read `server` from `replica`'s cursor to its end, a page a commit.
pub fn read<S: merkle_crdt::Store<H>>(
    replica: &mut merkle_crdt::Replica<H, Ops, S>,
    server: &mut Server,
) {
    loop {
        let (items, more) = server.since(replica.cursor());
        let Some(last) = items.last().map(|(position, _)| *position) else {
            return;
        };
        replica
            .ingest(
                items.into_iter().map(|(_, bytes)| bytes),
                Some(last),
                &mut crdt,
            )
            .unwrap();
        if !more {
            return;
        }
    }
}
