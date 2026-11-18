//! A batch proof checked from its encoding as it is read: the bytes streamed
//! once, the nodes hashed bottom-up on a stack of the branches still open,
//! no entry decoded into memory. A PVM program's memory then stays within a
//! few pages, where [`BatchProof::verify`](crate::BatchProof::verify) builds
//! the pruned tree first.

use alloc::vec::Vec;

use crate::hash::{Hasher, empty_root, leaf_hash};
use crate::keys::{bit, first_difference};
use crate::proof::EntryTag;
use crate::{Error, Hash, valid_key};

/// A node's hash in aligned words, which a hasher inlined over it reads as
/// words: the guest target has no misaligned access, so a byte array moves
/// byte by byte.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C, align(8))]
struct Digest(Hash);

/// A branch whose children are being read.
struct Open {
    level: u16,
    /// Whether its right child is being read.
    right: bool,
    /// Its left child's hash once read, and whether that child is closed.
    left: Digest,
    left_closed: bool,
    /// The claims whose paths take its right child: `order[mid..end]`.
    mid: usize,
    end: usize,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

/// Check `proof`, a [`BatchProof`](crate::BatchProof)'s encoding and
/// nothing more, against `root` and each claim: a key and its value's
/// commitment if present, or `None` if absent.
///
/// The same judgment as decoding the proof and calling
/// [`BatchProof::verify`](crate::BatchProof::verify), with the same error:
/// bytes that are not one proof's encoding are [`Error::Malformed`], and a
/// refused claim's error is the first refused claim's, in the claims'
/// order, reported once the proof is well formed and rebuilds `root`.
///
/// The claims are taken in any order. At each branch the claims whose paths
/// reach it are split by their bit at its level, as
/// [`BatchProof::generate`](crate::BatchProof::generate) splits the keys
/// it proves: paths end in the proof's order, which is not the keys' when
/// an absent key differs from a subtree at a bit no branch splits on.
pub fn verify_encoded<H: Hasher, K: AsRef<[u8]>>(
    hasher: &H,
    proof: &[u8],
    root: &Hash,
    claims: &[(K, Option<Hash>)],
) -> Result<(), Error> {
    let mut reader = Reader(proof);
    let count = reader.u32()?;
    // The claims by index, grouped by the subtrees their paths enter: those
    // of the node being read are `order[from..to]`.
    let mut order: Vec<usize> = (0..claims.len()).collect();
    let (mut from, mut to) = (0, claims.len());
    let mut open: Vec<Open> = Vec::new();
    let mut last: Option<&[u8]> = None;
    let mut top: Option<Digest> = None;
    let mut refused: Option<(usize, Error)> = None;
    let mut refuse = |at: usize, error: Error| {
        if refused.is_none_or(|(first, _)| at < first) {
            refused = Some((at, error));
        }
    };
    for _ in 0..count {
        if top.is_some() {
            return Err(Error::Malformed);
        }
        let (mut node, mut closed) = match EntryTag::of(reader.array::<1>()?[0]) {
            Some(EntryTag::Branch) => {
                let level = u16::from_le_bytes(reader.array()?);
                if open.last().is_some_and(|parent| level <= parent.level) {
                    return Err(Error::Malformed);
                }
                let mid = from
                    + split(&mut order[from..to], |at| {
                        bit(claims[at].0.as_ref(), level) == 1
                    });
                open.push(Open {
                    level,
                    right: false,
                    left: Digest([0; 32]),
                    left_closed: false,
                    mid,
                    end: to,
                });
                to = mid;
                continue;
            }
            Some(EntryTag::Hash) => {
                let hash = reader.array()?;
                for &at in &order[from..to] {
                    let valid = valid_key(claims[at].0.as_ref());
                    refuse(at, if valid { Error::Uncovered } else { Error::Key });
                }
                (Digest(hash), true)
            }
            Some(EntryTag::Leaf) => {
                let len = reader.u32()? as usize;
                let key = reader.take(len)?;
                let value_hash: Hash = reader.array()?;
                let placed = open.iter().all(|branch| {
                    usize::from(branch.level) < key.len() * 8
                        && bit(key, branch.level) == usize::from(branch.right)
                });
                if !valid_key(key) || !placed || last.is_some_and(|last| last >= key) {
                    return Err(Error::Malformed);
                }
                last = Some(key);
                for &at in &order[from..to] {
                    let (claimed, value) = &claims[at];
                    let claimed = claimed.as_ref();
                    let shown = if !valid_key(claimed) {
                        Err(Error::Key)
                    } else if claimed == key {
                        Ok(Some(value_hash))
                    } else if first_difference(claimed, key).is_none() {
                        // The leaf a path reaches shares the longest prefix
                        // with the key: if any key of the tree prefixes this
                        // one or is prefixed by it, this one does.
                        Err(Error::Key)
                    } else {
                        Ok(None)
                    };
                    match shown {
                        Ok(shown) if shown == *value => {}
                        Ok(_) => refuse(at, Error::Claim),
                        Err(error) => refuse(at, error),
                    }
                }
                (Digest(leaf_hash(hasher, key, &value_hash)), false)
            }
            Some(EntryTag::Empty) if count == 1 => {
                for &at in &order[from..to] {
                    let (claimed, value) = &claims[at];
                    if !valid_key(claimed.as_ref()) {
                        refuse(at, Error::Key);
                    } else if value.is_some() {
                        refuse(at, Error::Claim);
                    }
                }
                (Digest(empty_root(hasher)), false)
            }
            _ => return Err(Error::Malformed),
        };
        // A leaf or a closed subtree completes its parent's child, and
        // perhaps the parent, and so on up.
        loop {
            match open.last_mut() {
                None => {
                    top = Some(node);
                    break;
                }
                Some(branch) if !branch.right => {
                    branch.left = node;
                    branch.left_closed = closed;
                    branch.right = true;
                    (from, to) = (branch.mid, branch.end);
                    break;
                }
                Some(branch) => {
                    // A canonical proof closes a branch it does not open.
                    if branch.left_closed && closed {
                        return Err(Error::Malformed);
                    }
                    let left = branch.left;
                    node = Digest(hasher.branch(branch.level, &left.0, &node.0));
                    closed = false;
                    open.pop();
                }
            }
        }
    }
    let Some(top) = top else {
        return Err(Error::Malformed);
    };
    if !reader.0.is_empty() || !open.is_empty() {
        return Err(Error::Malformed);
    }
    if top.0 != *root {
        return Err(Error::Root);
    }
    refused.map_or(Ok(()), |(_, error)| Err(error))
}

/// Split `order` into the claims whose paths take a branch's left child,
/// then those that take its right, as `right` tells: the left's count. The
/// order within each side does not matter, as a refusal is reported by the
/// claim's index.
fn split(order: &mut [usize], right: impl Fn(usize) -> bool) -> usize {
    let mut mid = 0;
    for at in 0..order.len() {
        if !right(order[at]) {
            order.swap(at, mid);
            mid += 1;
        }
    }
    mid
}
