//! A vos-tree batch proof checked as it is read: its encoding streamed
//! once, its nodes hashed bottom-up on a stack of the branches still open,
//! nothing of it decoded into memory. A kernel's memory then stays within
//! a few pages, where the tree's own `BatchProof::verify` builds the
//! pruned tree first; its segments are cut by steps rather than by pages.
//!
//! The proof's format and the checks are `vos_tree`'s (its crate
//! documentation), and so are the hashes: a leaf's by its own function, and
//! a branch's, the most frequent, as one block of words handed to the
//! compression precompile. Digests move as words: the guest target has no
//! misaligned access, so a byte array moves byte by byte. Every claim's path
//! must end in the proof: at its own leaf, with the claimed commitment, or,
//! claimed absent, at another leaf, which the key neither prefixes nor
//! extends, or at the empty tree. A proof this accepts, `vos_tree`'s
//! accepts for the same claims.

use vos_pvm_precompiles::blake2b_compress;
use vos_tree::{Blake2b, Hash, MAX_KEY};

/// A digest as its four little-endian words.
type Digest = [u64; 4];

/// "vos/tree", the first word of every tag.
const VOS_TREE: u64 = u64::from_le_bytes(*b"vos/tree");
/// "/branch", the rest of a branch's tag, in its block's second word.
const SLASH_BRANCH: u64 = u64::from_le_bytes(*b"/branch\0");

/// BLAKE2b's state before the first block of an unkeyed 32-byte digest.
const H0: [u64; 8] = [
    0x6A09_E667_F3BC_C908 ^ 0x0101_0020,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

fn words(hash: &Hash) -> Digest {
    let word = |k: usize| u64::from_le_bytes(hash[k * 8..k * 8 + 8].try_into().unwrap());
    [word(0), word(1), word(2), word(3)]
}

/// `vos_tree::branch_hash`: BLAKE2b-256 of the tag's 15 bytes, the level's
/// 2, big-endian, then the children's 32 each, from byte 17 on, one block
/// of 81 bytes.
fn branch_hash(level: u16, left: &Digest, right: &Digest) -> Digest {
    let [high, low] = level.to_be_bytes();
    let block: [u64; 16] = [
        VOS_TREE,
        SLASH_BRANCH | u64::from(high) << 56,
        u64::from(low) | left[0] << 8,
        left[0] >> 56 | left[1] << 8,
        left[1] >> 56 | left[2] << 8,
        left[2] >> 56 | left[3] << 8,
        left[3] >> 56 | right[0] << 8,
        right[0] >> 56 | right[1] << 8,
        right[1] >> 56 | right[2] << 8,
        right[2] >> 56 | right[3] << 8,
        right[3] >> 56,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut h = H0;
    // SAFETY: the bytes of word arrays, little-endian on the PVM and on
    // every host this builds for, as BLAKE2b reads its words.
    let (state, block) = unsafe {
        (
            &mut *(&mut h as *mut [u64; 8] as *mut [u8; 64]),
            &*(&block as *const [u64; 16] as *const [u8; 128]),
        )
    };
    blake2b_compress(state, block, 81, true);
    [h[0], h[1], h[2], h[3]]
}

/// A key's bit at `level`, most significant first within each byte, a bit
/// past its end reading 0.
fn bit(key: &[u8], level: u16) -> u8 {
    let level = usize::from(level);
    key.get(level / 8)
        .map_or(0, |byte| (byte >> (7 - level % 8)) & 1)
}

/// Whether one of two keys prefixes the other.
fn prefixed(a: &[u8], b: &[u8]) -> bool {
    a.iter().zip(b).all(|(x, y)| x == y)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.array()?))
    }
}

/// A branch whose children are being read: its level, the side being read,
/// and its left child's hash once read.
struct Open {
    level: u16,
    side: u8,
    left: Digest,
    left_closed: bool,
}

/// Whether `key`'s path takes every open branch on the side being read.
fn placed(key: &[u8], open: &[Open]) -> bool {
    open.iter()
        .all(|branch| bit(key, branch.level) == branch.side)
}

/// Check `proof`, a `vos_tree::BatchProof`'s encoding, against `root` for
/// `claims`: keys in strictly increasing order, each with its value's
/// commitment if present, or `None` if absent.
pub fn verify(proof: &[u8], root: &Hash, claims: &[(&[u8], Option<Hash>)]) -> bool {
    let ordered = claims.windows(2).all(|pair| pair[0].0 < pair[1].0);
    let valid = claims
        .iter()
        .all(|(key, _)| !key.is_empty() && key.len() <= MAX_KEY);
    ordered && valid && verified(proof, root, claims) == Some(true)
}

fn verified(proof: &[u8], root: &Hash, claims: &[(&[u8], Option<Hash>)]) -> Option<bool> {
    let mut reader = Reader(proof);
    let count = reader.u32()?;
    let mut open: alloc::vec::Vec<Open> = alloc::vec::Vec::with_capacity(64);
    // The claims resolved so far: paths end in key order, so a claim's
    // ends at or after the one before it.
    let mut resolved = 0;
    let mut last: Option<&[u8]> = None;
    let mut top: Option<Digest> = None;
    for _ in 0..count {
        if top.is_some() {
            return Some(false);
        }
        let (mut node, mut closed) = match reader.array::<1>()?[0] {
            0 => {
                let level = u16::from_le_bytes(reader.array()?);
                if open.last().is_some_and(|parent| level <= parent.level) {
                    return Some(false);
                }
                open.push(Open {
                    level,
                    side: 0,
                    left: [0; 4],
                    left_closed: false,
                });
                continue;
            }
            1 => {
                // No claim's path may end in a closed subtree.
                if claims
                    .get(resolved)
                    .is_some_and(|(key, _)| placed(key, &open))
                {
                    return Some(false);
                }
                (words(&reader.array()?), true)
            }
            2 => {
                let len = reader.u32()? as usize;
                let key = reader.take(len)?;
                let value_hash: Hash = reader.array()?;
                let on_path = open.iter().all(|branch| {
                    usize::from(branch.level) < key.len() * 8
                        && bit(key, branch.level) == branch.side
                });
                if key.is_empty()
                    || key.len() > MAX_KEY
                    || !on_path
                    || last.is_some_and(|last| last >= key)
                {
                    return Some(false);
                }
                last = Some(key);
                while let Some((claimed, value)) = claims.get(resolved) {
                    if !placed(claimed, &open) {
                        break;
                    }
                    let shown = if *claimed == key {
                        Some(value_hash)
                    } else if prefixed(claimed, key) {
                        return Some(false);
                    } else {
                        None
                    };
                    if shown != *value {
                        return Some(false);
                    }
                    resolved += 1;
                }
                (
                    words(&vos_tree::leaf_hash(&Blake2b, key, &value_hash)),
                    false,
                )
            }
            3 if count == 1 => {
                if claims.iter().any(|(_, value)| value.is_some()) {
                    return Some(false);
                }
                resolved = claims.len();
                (words(&vos_tree::empty_root(&Blake2b)), false)
            }
            _ => return Some(false),
        };
        loop {
            match open.last_mut() {
                None => {
                    top = Some(node);
                    break;
                }
                Some(branch) if branch.side == 0 => {
                    branch.left = node;
                    branch.left_closed = closed;
                    branch.side = 1;
                    break;
                }
                Some(branch) => {
                    // A canonical proof closes a branch it does not open.
                    if branch.left_closed && closed {
                        return Some(false);
                    }
                    node = branch_hash(branch.level, &branch.left, &node);
                    closed = false;
                    open.pop();
                }
            }
        }
    }
    Some(
        reader.0.is_empty()
            && open.is_empty()
            && top == Some(words(root))
            && resolved == claims.len(),
    )
}
