//! The merge fields converge (`vos_wire::merge`): signed histories of three
//! authors, with equivocations, delivered to three replicas in random
//! orders and chunks through the light node's node apply
//! (`vos_light::sync::apply_node`), each operation's writes made as the
//! agent makes them; every replica reads every element alike, filtered by
//! the equivocations it found and the removals it is given, and as a model
//! computed from the whole history reads it.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use merkle_crdt::{Apply, Author, Event, MemStore, Node, Replica, Rows};
use proptest::prelude::*;
use vos_light::sync::{self, Blake2b256, Call, Cid, Op, Ops};
use vos_wire::abi::MergeRows;
use vos_wire::ids::{InstanceId, MethodId};
use vos_wire::keys::{self, Transform};
use vos_wire::merge::{self, Cutoff, Entry, Keep, Origin};
use vos_wire::records::{stored, unstored};
use vos_wire::{Decode, Encode};

const INSTANCE: InstanceId = InstanceId(3);
const AUTHORS: usize = 3;
/// Elements a field's operations name.
const ELEMENTS: u8 = 4;

/// A field's kind: a grow-only set's, an add/remove set's, a map's.
const FIELDS: [(u32, Keep); 3] = [(1, Keep::Earliest), (2, Keep::Latest), (3, Keep::Latest)];

/// One write of a model operation: field, element, value (`None` a
/// removal; a grow-only set's always a value).
type Write = (u8, u8, Option<u8>);

fn field_rows(field: u8) -> MergeRows {
    let (tag, keep) = FIELDS[field as usize];
    MergeRows {
        tag,
        transform: Transform::Hashed,
        keep,
    }
}

fn element_row(field: u8, element: u8) -> Vec<u8> {
    keys::merge_element(INSTANCE, field_rows(field), &[element]).unwrap()
}

/// An operation's writes, as the agent makes a merge handler's: each the
/// operation's entry, kept against the author's stored one.
fn run(_: &Cid, origin: &Origin, call: &Call, rows: &mut dyn Rows) -> Result<(), sync::CorruptRow> {
    let writes = Vec::<Write>::decode_exact(&call.arguments).expect("a model operation");
    for (at, (field, element, value)) in writes.into_iter().enumerate() {
        let keep = FIELDS[field as usize].1;
        let value = value.map(|value| [value]);
        let entry = Entry::new(origin, at as u32, value.as_ref().map(|v| &v[..])).encode();
        let key = keys::merge_entry(&element_row(field, element), &origin.author);
        let old = rows.read(&key);
        let old = old.as_deref().map(|bytes| unstored(bytes).unwrap());
        if merge::replaces(&entry, old, keep) {
            rows.write(&key, Some(&stored(&entry)));
        }
    }
    Ok(())
}

/// The light node's node apply, its operations run by [`run`].
struct Model;

impl Apply<Blake2b256, Ops> for Model {
    type Error = sync::CorruptRow;

    fn apply(
        &mut self,
        event: Event<'_, Blake2b256, Ops>,
        rows: &mut dyn Rows,
    ) -> Result<(), Self::Error> {
        sync::apply_node(INSTANCE, &event, rows, run)
    }
}

/// What every element of every field reads on `rows`, its authors cut off
/// by the equivocations the rows hold and by `removed`.
fn reads(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    removed: &BTreeMap<Author, u64>,
) -> Vec<Option<Option<Vec<u8>>>> {
    let mut all = Vec::new();
    for field in 0..FIELDS.len() as u8 {
        for element in 0..ELEMENTS {
            let row = element_row(field, element);
            let entries: Vec<([u8; 32], &[u8])> = rows
                .range(row.clone()..)
                .take_while(|(key, _)| key.starts_with(&row))
                .map(|(key, value)| {
                    let author = key[row.len()..].try_into().unwrap();
                    (author, unstored(value).unwrap())
                })
                .collect();
            let cutoff = |author: &[u8; 32]| {
                let stored = rows
                    .get(&keys::cutoff(INSTANCE, author))
                    .map(|bytes| Cutoff::decode_exact(unstored(bytes).unwrap()).unwrap());
                let removal = removed.get(&Author(*author)).map(|from| Cutoff(*from));
                stored.into_iter().chain(removal).min()
            };
            let latest = merge::latest(entries, cutoff).unwrap();
            all.push(latest.map(|entry| entry.value.map(<[u8]>::to_vec)));
        }
    }
    all
}

/// One step of a generated history.
#[derive(Clone, Debug)]
enum Step {
    /// An author records an operation after the heads it knows.
    Record { author: usize, writes: Vec<Write> },
    /// An author learns what another knows.
    Learn { from: usize, to: usize },
    /// An author signs a second node at its latest sequence number.
    Equivocate { author: usize, writes: Vec<Write> },
}

fn write() -> impl Strategy<Value = Write> {
    (0..FIELDS.len() as u8, 0..ELEMENTS, any::<Option<u8>>()).prop_map(|(field, element, value)| {
        // A grow-only set is only added to.
        let value = if field == 0 {
            Some(value.unwrap_or(0))
        } else {
            value
        };
        (field, element, value)
    })
}

fn step() -> impl Strategy<Value = Step> {
    let author = 0..AUTHORS;
    prop_oneof![
        6 => (author.clone(), prop::collection::vec(write(), 1..4))
            .prop_map(|(author, writes)| Step::Record { author, writes }),
        3 => (author.clone(), author.clone()).prop_map(|(from, to)| Step::Learn { from, to }),
        1 => (author, prop::collection::vec(write(), 1..3))
            .prop_map(|(author, writes)| Step::Equivocate { author, writes }),
    ]
}

/// A generated history: every node, by CID, with its author, sequence
/// number, parents and operations' writes.
struct History {
    nodes: BTreeMap<Cid, Generated>,
    /// In the order they were signed, as bytes.
    signed: Vec<Vec<u8>>,
}

struct Generated {
    author: Author,
    seq: u64,
    parents: BTreeSet<Cid>,
    writes: Vec<Write>,
}

fn scope() -> merkle_crdt::Scope {
    merkle_crdt::Scope(vos_light::group::archive::scope_id(
        &[0; 32],
        &sync::scope_name(INSTANCE),
    ))
}

fn generate(steps: &[Step]) -> History {
    let keys: Vec<SigningKey> = (0..AUTHORS)
        .map(|index| SigningKey::from_bytes(&[index as u8 + 1; 32]))
        .collect();
    // Each author's known nodes, and its latest node with its parents.
    let mut known: Vec<BTreeSet<Cid>> = vec![BTreeSet::new(); AUTHORS];
    let mut latest: Vec<Option<(u64, Cid, BTreeSet<Cid>)>> = vec![None; AUTHORS];
    let mut history = History {
        nodes: BTreeMap::new(),
        signed: Vec::new(),
    };
    let mut time = 0;
    let mut sign = |history: &mut History,
                    author: usize,
                    seq: u64,
                    parents: BTreeSet<Cid>,
                    writes: Vec<Write>| {
        time += 1;
        let ops: Ops = vec![Op::Call(Call {
            method: MethodId(7),
            arguments: writes.encode(),
            time,
            seed: [0; 32],
        })];
        let node =
            Node::<Blake2b256, Ops>::sign(&keys[author], &scope(), seq, ops, parents.clone());
        let bytes = node.to_bytes();
        let cid = node.cid();
        history.signed.push(bytes);
        history.nodes.insert(
            cid.clone(),
            Generated {
                author: Author::from(&keys[author]),
                seq,
                parents,
                writes,
            },
        );
        cid
    };
    for step in steps {
        match step.clone() {
            Step::Record { author, writes } => {
                let view = &known[author];
                let named: BTreeSet<&Cid> = view
                    .iter()
                    .flat_map(|cid| &history.nodes[cid].parents)
                    .collect();
                let mut parents: BTreeSet<Cid> = view
                    .iter()
                    .filter(|cid| !named.contains(cid))
                    .cloned()
                    .collect();
                let seq = match &latest[author] {
                    Some((seq, previous, _)) => {
                        parents.insert(previous.clone());
                        seq + 1
                    }
                    None => 0,
                };
                let cid = sign(&mut history, author, seq, parents.clone(), writes);
                known[author].insert(cid.clone());
                latest[author] = Some((seq, cid, parents));
            }
            Step::Learn { from, to } => {
                let learned = known[from].clone();
                known[to].extend(learned);
            }
            Step::Equivocate { author, writes } => {
                let Some((seq, _, parents)) = latest[author].clone() else {
                    continue;
                };
                let cid = sign(&mut history, author, seq, parents, writes);
                // Its author never builds on it, but others may learn it.
                known[(author + 1) % AUTHORS].insert(cid);
            }
        }
    }
    history
}

/// What the whole history reads, computed apart from any replica: each
/// node's Lamport clock from its parents; each (field, element, author)'s
/// kept entry among all its writes; the authors cut off at their first
/// equivocation and by `removed`; the latest admitted entry by Lamport
/// clock, then author.
fn model(history: &History, removed: &BTreeMap<Author, u64>) -> Vec<Option<Option<Vec<u8>>>> {
    let mut lamport: BTreeMap<Cid, u64> = BTreeMap::new();
    while lamport.len() < history.nodes.len() {
        for (cid, node) in &history.nodes {
            if lamport.contains_key(cid) {
                continue;
            }
            if let Some(clocks) = node
                .parents
                .iter()
                .map(|parent| lamport.get(parent).copied())
                .collect::<Option<Vec<u64>>>()
            {
                lamport.insert(cid.clone(), clocks.into_iter().max().unwrap_or(0) + 1);
            }
        }
    }
    let mut seqs: BTreeMap<(Author, u64), usize> = BTreeMap::new();
    for node in history.nodes.values() {
        *seqs.entry((node.author, node.seq)).or_default() += 1;
    }
    let mut cutoffs: BTreeMap<Author, u64> = removed.clone();
    for ((author, seq), count) in seqs {
        if count > 1 {
            let cutoff = cutoffs.entry(author).or_insert(seq);
            *cutoff = (*cutoff).min(seq);
        }
    }
    let mut kept: BTreeMap<(u8, u8, Author), Vec<u8>> = BTreeMap::new();
    for (cid, node) in &history.nodes {
        let origin = Origin {
            author: node.author.0,
            seq: node.seq,
            lamport: lamport[cid],
            index: 0,
        };
        for (at, (field, element, value)) in node.writes.iter().enumerate() {
            let value = value.map(|value| [value]);
            let entry = Entry::new(&origin, at as u32, value.as_ref().map(|v| &v[..])).encode();
            let keep = FIELDS[*field as usize].1;
            let slot = kept.entry((*field, *element, node.author));
            match slot {
                std::collections::btree_map::Entry::Vacant(vacant) => {
                    vacant.insert(entry);
                }
                std::collections::btree_map::Entry::Occupied(mut occupied) => {
                    if merge::replaces(&entry, Some(occupied.get()), keep) {
                        occupied.insert(entry);
                    }
                }
            }
        }
    }
    let mut all = Vec::new();
    for field in 0..FIELDS.len() as u8 {
        for element in 0..ELEMENTS {
            let mut best: Option<(u64, Author, Option<Vec<u8>>)> = None;
            for ((_, _, author), bytes) in
                kept.range((field, element, Author([0; 32]))..=(field, element, Author([0xff; 32])))
            {
                let entry = Entry::read(bytes).unwrap();
                if cutoffs
                    .get(author)
                    .is_some_and(|cutoff| entry.seq >= *cutoff)
                {
                    continue;
                }
                if best
                    .as_ref()
                    .is_none_or(|(lamport, best, _)| (entry.lamport, *author) > (*lamport, *best))
                {
                    best = Some((entry.lamport, *author, entry.value.map(<[u8]>::to_vec)));
                }
            }
            all.push(best.map(|(_, _, value)| value));
        }
    }
    all
}

fn deliver(history: &History, order: &[usize], chunks: &[usize]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut replica = Replica::<Blake2b256, Ops, _>::open(MemStore::new(), scope()).unwrap();
    let mut nodes: Vec<Vec<u8>> = order
        .iter()
        .map(|index| history.signed[*index].clone())
        .collect();
    let mut sizes = chunks.iter().cycle();
    while !nodes.is_empty() {
        let size = (*sizes.next().unwrap()).min(nodes.len());
        let chunk: Vec<Vec<u8>> = nodes.drain(..size).collect();
        replica.ingest(chunk, None, &mut Model).unwrap();
    }
    assert_eq!(replica.held(), 0, "every node's parents arrived");
    replica.store().rows().clone()
}

/// A permutation of `0..len` from `keys`.
fn permutation(len: usize, keys: &[u64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    order.sort_by_key(|index| keys.get(*index).copied().unwrap_or(*index as u64));
    order
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn merge_fields_converge_whatever_the_delivery(
        steps in prop::collection::vec(step(), 1..40),
        orders in prop::collection::vec(prop::collection::vec(any::<u64>(), 60), 3),
        chunks in prop::collection::vec(1usize..6, 1..4),
        removals in prop::collection::vec(prop::option::of(0u64..6), AUTHORS),
    ) {
        let history = generate(&steps);
        let removed: BTreeMap<Author, u64> = (0..AUTHORS)
            .zip(&removals)
            .filter_map(|(index, from)| {
                let author = Author::from(&SigningKey::from_bytes(&[index as u8 + 1; 32]));
                from.map(|from| (author, from))
            })
            .collect();
        let expected = model(&history, &removed);
        for keys in &orders {
            let order = permutation(history.signed.len(), keys);
            let rows = deliver(&history, &order, &chunks);
            prop_assert_eq!(reads(&rows, &removed), expected.clone());
        }
    }
}

/// Unfiltered, the merge fields read as their types say: a grow-only set
/// holds every element added; a set or map's element is its latest write
/// by Lamport clock, here a chain's last.
#[test]
fn one_author_reads_its_last_writes() {
    let steps = vec![
        Step::Record {
            author: 0,
            writes: vec![(0, 1, Some(1)), (1, 2, Some(1)), (2, 3, Some(5))],
        },
        Step::Record {
            author: 0,
            writes: vec![(1, 2, None), (2, 3, Some(6)), (2, 3, Some(7))],
        },
        Step::Record {
            author: 0,
            writes: vec![(0, 1, Some(9))],
        },
    ];
    let history = generate(&steps);
    let rows = deliver(&history, &[2, 0, 1], &[1]);
    let read = reads(&rows, &BTreeMap::new());
    let at = |field: usize, element: usize| read[field * ELEMENTS as usize + element].clone();
    assert_eq!(
        at(0, 1),
        Some(Some(vec![1])),
        "a grow-only set keeps its first add"
    );
    assert_eq!(at(1, 2), Some(None), "removed");
    assert_eq!(at(2, 3), Some(Some(vec![7])), "the operation's last write");
    assert_eq!(at(2, 0), None);
}
