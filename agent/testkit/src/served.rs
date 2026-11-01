//! Committed rows as a node serves them, for tests: a tree of rows each
//! salted from a seed, and a representative's tree of agents' roots with a
//! row's salt and path in it.

use vos_tree::{BatchProof, Blake2b, Hash, Leaf, MemStore};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::served::representative_row;
use vos_wire::vos_anchor::RootKind;

/// A tree over `rows` (full keys and stored values), each leaf salted from
/// `seed`, into `store`: its root.
pub fn salted_tree(store: &mut MemStore, seed: &[u8; 32], rows: &[(Vec<u8>, Vec<u8>)]) -> Hash {
    if rows.is_empty() {
        return vos_tree::empty_root(&Blake2b);
    }
    let mut leaves: Vec<(Vec<u8>, Option<Leaf>)> = rows
        .iter()
        .map(|(key, value)| (key.clone(), Some(Leaf::salted(&Blake2b, seed, key, value))))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let mut root = [0; 32];
    for batch in leaves.chunks(1 << 16) {
        root = vos_tree::update(&Blake2b, store, batch).expect("the tree updates");
    }
    root
}

/// A representative's tree over `roots`, each an agent's root at a window,
/// salted from `seed`: its root, and the salt and path of `of`'s row in it
/// (or of its absence).
pub fn representative(
    seed: &[u8; 32],
    roots: &[(AgentId, u64, Hash)],
    of: (AgentId, u64),
) -> (Hash, [u8; 16], Vec<u8>) {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = roots
        .iter()
        .map(|&(agent, window, root)| {
            (
                representative_row(agent, RootKind::Space, window),
                root.to_vec(),
            )
        })
        .collect();
    let mut store = MemStore::default();
    let root = salted_tree(&mut store, seed, &rows);
    let row = representative_row(of.0, RootKind::Space, of.1);
    let salt = vos_tree::salt(&Blake2b, seed, &row);
    let path = BatchProof::generate(&store, std::slice::from_ref(&row))
        .expect("proves")
        .encode();
    (root, salt, path)
}
