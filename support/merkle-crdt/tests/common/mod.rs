//! What the suites share: a hasher, a CRDT whose result does not depend on
//! the order concurrent nodes arrive in and that catches a node applied
//! twice, and a generator of signed DAGs.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::SigningKey;
use merkle_crdt::{Author, Cid, Event, Hasher, Node, Rows, Scope};

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
