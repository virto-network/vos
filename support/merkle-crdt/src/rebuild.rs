use crate::apply::Overlay;
use crate::replica::Error;
use crate::signed::validate;
use crate::sync::causal_order;
use crate::{Apply, Author, Cid, Decode, Encode, Event, Hasher, Store};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// A scope replayed from nothing: the rows, heads and equivocations its
/// stored DAG yields.
#[derive(Debug)]
pub struct Rebuilt<H: Hasher> {
    /// The rows the CRDT wrote.
    pub rows: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The heads of the DAG reached.
    pub heads: BTreeSet<Cid<H>>,
    /// The (author, sequence number) pairs signed more than once.
    pub equivocations: BTreeSet<(Author, u64)>,
    /// The number of nodes replayed.
    pub nodes: usize,
}

/// The full validation and replay, for recovery and audits: walk the whole
/// DAG from the store's heads, check every node as an ingest would (its
/// bytes, its CID, its signature, its author's chain), and apply all of
/// them in causal order onto empty rows. The store is only read.
///
/// An incremental replica's rows equal the rows this returns for its store;
/// a recovery writes them back.
pub fn rebuild<H: Hasher, O: Encode + Decode, S: Store<H>, A: Apply<H, O>>(
    store: &S,
    crdt: &mut A,
) -> Result<Rebuilt<H>, Error<S::Error, A::Error>> {
    let loaded = store.load().map_err(Error::Store)?;
    let mut nodes = BTreeMap::new();
    let mut stack: Vec<Cid<H>> = loaded.heads.into_iter().collect();
    while let Some(cid) = stack.pop() {
        if nodes.contains_key(&cid) {
            continue;
        }
        let bytes = store
            .node(&cid)
            .map_err(Error::Store)?
            .ok_or(Error::Corrupt)?;
        let (found, node) = validate::<H, O>(&bytes).map_err(|_| Error::Corrupt)?;
        if found != cid {
            return Err(Error::Corrupt);
        }
        stack.extend(node.parents.iter().cloned());
        nodes.insert(cid.clone(), (node.parents.clone(), (cid, node)));
    }

    let mut rows = Overlay::<H, S>::new(None);
    let mut authored: BTreeMap<(Author, u64), Vec<Cid<H>>> = BTreeMap::new();
    let mut heads = BTreeSet::new();
    let mut equivocations = BTreeSet::new();
    let count = nodes.len();
    for (cid, node) in causal_order(nodes) {
        let signed = &node.payload;
        if signed.seq > 0 {
            let previous = authored.get(&(signed.author, signed.seq - 1));
            if !previous
                .into_iter()
                .flatten()
                .any(|cid| node.parents.contains(cid))
            {
                return Err(Error::Corrupt);
            }
        }
        let same = authored.entry((signed.author, signed.seq)).or_default();
        if !same.is_empty() {
            equivocations.insert((signed.author, signed.seq));
        }
        same.push(cid.clone());
        for parent in &node.parents {
            heads.remove(parent);
        }
        heads.insert(cid.clone());
        let event = Event {
            cid: &cid,
            author: &signed.author,
            seq: signed.seq,
            parents: &node.parents,
            ops: &signed.ops,
        };
        crdt.apply(event, &mut rows).map_err(Error::Apply)?;
    }
    Ok(Rebuilt {
        rows: rows
            .written
            .into_iter()
            .filter_map(|(key, value)| Some((key, value?)))
            .collect(),
        heads,
        equivocations,
        nodes: count,
    })
}
