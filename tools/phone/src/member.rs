//! The bench's member: fixed, public values its every cell proves with,
//! which its outputs' audit (`tests/outputs.rs`) searches for.

use vos_wire::credentials::{DEPTH, EMPTY, Words};

/// The space's handle and the secret source's output.
pub const HANDLE: [u8; 32] = [0x48; 32];
pub const SOURCE_OUTPUT: [u8; 32] = [0x6f; 32];
/// The member's slot in the tree.
pub const SLOT: u32 = 0x1234_5678;

/// The member's path's siblings in a tree whose other leaves are a few
/// fixed digests: the siblings at levels 0, 5 and 17 occupied.
pub fn siblings() -> [Words; DEPTH] {
    let mut siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    for (n, level) in [0, 5, 17].into_iter().enumerate() {
        siblings[level] = core::array::from_fn(|i| (n as u32 + 1) * 1_000_003 + i as u32);
    }
    siblings
}
