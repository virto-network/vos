//! The root a proof's memory starts from: the page tree over a standard
//! program's initial memory.
//!
//! The tree is the prover's (`vos_pvm_proof::page_merkle`): a complete binary
//! tree of depth [`DEPTH`] over the 32-bit address space, keyed by page,
//! each leaf the BLAKE2b-256 of a domain block and the page, each node of a
//! domain block and its two children, and a page of zeros the empty leaf.
//! So the root covers the initial memory's contents: the read-only and
//! read-write data where the standard layout places them, and zeros in the
//! heap, the stack and every other page. The prover's tests pin the two
//! implementations to each other.

use alloc::vec::Vec;

use crate::{PAGE_SIZE, StandardProgram};

/// The tree's depth: a leaf per page of the 32-bit address space.
pub const DEPTH: u32 = 32 - PAGE_SIZE.trailing_zeros();

const BLOCK: usize = 128;
const LEAF: &[u8] = b"zkpvm/page-merkle/leaf/v1";
const NODE: &[u8] = b"zkpvm/page-merkle/node/v1";

/// BLAKE2b-256 of `tag` zero-padded to a block, then `payload`.
fn tagged(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut message = Vec::with_capacity(BLOCK + payload.len());
    message.extend_from_slice(tag);
    message.resize(BLOCK, 0);
    message.extend_from_slice(payload);
    vos_pvm_precompiles::blake2b_256(&message)
}

/// A page's leaf.
pub fn leaf_hash(page: &[u8]) -> [u8; 32] {
    debug_assert_eq!(page.len(), PAGE_SIZE as usize);
    tagged(LEAF, page)
}

/// A node over its two children.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left);
    payload[32..].copy_from_slice(right);
    tagged(NODE, &payload)
}

/// The root of a tree whose leaves are `leaves`, sorted by page and each
/// differing from a page of zeros, and every other page zeros.
pub fn root(leaves: &[(u32, [u8; 32])]) -> [u8; 32] {
    let mut empty = [[0u8; 32]; DEPTH as usize + 1];
    empty[DEPTH as usize] = leaf_hash(&[0u8; PAGE_SIZE as usize]);
    for level in (0..DEPTH as usize).rev() {
        empty[level] = node_hash(&empty[level + 1], &empty[level + 1]);
    }
    subtree(0, 0, leaves, &empty)
}

/// The root of the subtree at `level` and `index`, `leaves` those under it.
fn subtree(level: u32, index: u64, leaves: &[(u32, [u8; 32])], empty: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty[level as usize];
    }
    if level == DEPTH {
        return leaves[0].1;
    }
    let middle = (2 * index + 1) << (DEPTH - level - 1);
    let split = leaves.partition_point(|&(page, _)| u64::from(page) < middle);
    let (left, right) = leaves.split_at(split);
    node_hash(
        &subtree(level + 1, 2 * index, left, empty),
        &subtree(level + 1, 2 * index + 1, right, empty),
    )
}

impl StandardProgram {
    /// The root of the page tree over the program's initial memory, laid out
    /// with no arguments: what a proof of a run of it from its start begins
    /// at. `None` when its regions do not fit the address space.
    pub fn image_root(&self) -> Option<[u8; 32]> {
        let layout = self.layout(&[])?;
        let page = PAGE_SIZE as usize;
        let mut leaves = Vec::new();
        for (base, data) in [
            (layout.ro.base, layout.ro_data),
            (layout.rw.base, layout.rw_data),
        ] {
            let first = u32::try_from(base / u64::from(PAGE_SIZE)).ok()?;
            for (offset, chunk) in data.chunks(page).enumerate() {
                if chunk.iter().all(|&byte| byte == 0) {
                    continue;
                }
                let mut bytes = alloc::vec![0u8; page];
                bytes[..chunk.len()].copy_from_slice(chunk);
                leaves.push((first + offset as u32, leaf_hash(&bytes)));
            }
        }
        leaves.sort_unstable_by_key(|&(page, _)| page);
        Some(root(&leaves))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree of zeros has the empty root, whatever its data's length; one
    /// non-zero byte changes it, wherever it lies.
    #[test]
    fn zeros_have_the_empty_root_and_a_byte_moves_it() {
        let program = |ro_data: Vec<u8>, rw_data: Vec<u8>| StandardProgram {
            ro_data,
            rw_data,
            heap_pages: 2,
            stack_size: 4096,
            code: crate::CodeBlob {
                jump_table: Vec::new(),
                code: alloc::vec![0],
                bitmask: alloc::vec![1],
            },
        };
        let empty = root(&[]);
        assert_eq!(program(Vec::new(), Vec::new()).image_root(), Some(empty));
        assert_eq!(
            program(alloc::vec![0; 5000], alloc::vec![0; 9000]).image_root(),
            Some(empty)
        );
        let mut roots = alloc::collections::BTreeSet::new();
        for at in [0usize, 4095, 4096, 8191] {
            let mut ro = alloc::vec![0u8; 9000];
            ro[at] = 1;
            assert!(roots.insert(program(ro.clone(), Vec::new()).image_root().unwrap()));
            assert!(roots.insert(program(Vec::new(), ro).image_root().unwrap()));
        }
        assert!(!roots.contains(&empty));
    }
}
