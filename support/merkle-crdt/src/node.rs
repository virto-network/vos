use crate::{Author, Cid, Decode, Encode, Hasher};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// A node in the Merkle-DAG: a payload and the CIDs of its parents, the
/// earlier events it follows.
///
/// The node's [`Cid`] is the hash of its bytes ([`to_bytes`](Self::to_bytes)),
/// so the DAG is self-verifying and content-addressed. A node has no author
/// field: a replica's nodes carry their author in the payload
/// ([`Signed`](crate::Signed)).
pub struct DagNode<H: Hasher, P> {
    /// The payload: in a replica, the author's signed operations.
    pub payload: P,
    /// The CIDs of the events this node follows.
    pub parents: BTreeSet<Cid<H>>,
}

impl<H: Hasher, P: Clone> Clone for DagNode<H, P> {
    fn clone(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            parents: self.parents.clone(),
        }
    }
}

impl<H: Hasher, P: core::fmt::Debug> core::fmt::Debug for DagNode<H, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DagNode")
            .field("payload", &self.payload)
            .field("parents", &self.parents)
            .finish()
    }
}

impl<H: Hasher, P: Encode> DagNode<H, P> {
    /// The node's content identifier: the hash of its bytes.
    pub fn cid(&self) -> Cid<H> {
        Cid(H::hash(&self.to_bytes()))
    }

    /// The node's bytes:
    /// `[payload_len: u64 LE][payload][parent_count: u64 LE][parent CIDs, ascending]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let payload = self.payload.encode();
        buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(&(self.parents.len() as u64).to_le_bytes());
        for parent in &self.parents {
            buf.extend_from_slice(parent.as_ref());
        }
        buf
    }
}

impl<H: Hasher, P: Decode> DagNode<H, P> {
    /// Decode a node from its bytes: the inverse of
    /// [`to_bytes`](DagNode::to_bytes), refusing trailing bytes and a
    /// parent named twice.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (payload, parents) = split::<H>(bytes)?;
        Some(DagNode {
            payload: P::decode(payload)?,
            parents: distinct(parents)?,
        })
    }
}

/// A node's bytes split into its payload's bytes and its parents, which
/// are checked for count and order only when collected.
fn split<H: Hasher>(bytes: &[u8]) -> Option<(&[u8], impl Iterator<Item = Option<Cid<H>>> + '_)> {
    let (len, rest) = bytes.split_first_chunk::<8>()?;
    let len = usize::try_from(u64::from_le_bytes(*len)).ok()?;
    let payload = rest.get(..len)?;
    let (count, parents) = rest[len..].split_first_chunk::<8>()?;
    let count = usize::try_from(u64::from_le_bytes(*count)).ok()?;
    let width = core::mem::size_of::<H::Output>();
    if parents.len() != count.checked_mul(width)? {
        return None;
    }
    Some((
        payload,
        parents
            .chunks_exact(width)
            .map(|cid| H::Output::decode(cid).map(Cid)),
    ))
}

/// The parents as a set, refusing one named twice.
fn distinct<H: Hasher>(parents: impl Iterator<Item = Option<Cid<H>>>) -> Option<BTreeSet<Cid<H>>> {
    let mut set = BTreeSet::new();
    for parent in parents {
        if !set.insert(parent?) {
            return None;
        }
    }
    Some(set)
}

/// What a node's bytes say in clear without decoding its operations: its
/// author, sequence number and parents. A peer serving the DAG reads only
/// this; the operations and the signature are its reader's to check.
#[derive(Debug)]
pub struct Header<H: Hasher> {
    /// The author's key.
    pub author: Author,
    /// The author's sequence number.
    pub seq: u64,
    /// The node's parents.
    pub parents: BTreeSet<Cid<H>>,
}

impl<H: Hasher> Header<H> {
    /// Read the header of a replica's node bytes
    /// (`DagNode<H, Signed<O>>`) of any operation type.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let (payload, parents) = split::<H>(bytes)?;
        let (author, rest) = payload.split_first_chunk::<32>()?;
        let (seq, _) = rest.split_first_chunk::<8>()?;
        Some(Header {
            author: Author(*author),
            seq: u64::from_le_bytes(*seq),
            parents: distinct(parents)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHasher;
    impl Hasher for TestHasher {
        type Output = [u8; 32];
        fn hash(data: &[u8]) -> Self::Output {
            let mut out = [0; 32];
            for (i, byte) in data.iter().enumerate() {
                out[i % 32] ^= byte;
            }
            out
        }
    }

    #[test]
    fn decode_rejects_truncation_trailing_bytes_and_duplicate_parents() {
        assert!(DagNode::<TestHasher, u64>::from_bytes(&[]).is_none());
        let node = DagNode::<TestHasher, u64> {
            payload: 7,
            parents: BTreeSet::new(),
        };
        let mut trailing = node.to_bytes();
        trailing.push(0);
        assert!(DagNode::<TestHasher, u64>::from_bytes(&trailing).is_none());

        let parent = Cid::<TestHasher>([1; 32]);
        let mut duplicate = Vec::new();
        duplicate.extend_from_slice(&8u64.to_le_bytes());
        duplicate.extend_from_slice(&7u64.to_le_bytes());
        duplicate.extend_from_slice(&2u64.to_le_bytes());
        duplicate.extend_from_slice(parent.as_ref());
        duplicate.extend_from_slice(parent.as_ref());
        assert!(DagNode::<TestHasher, u64>::from_bytes(&duplicate).is_none());
        assert!(Header::<TestHasher>::read(&duplicate).is_none());

        let mut huge = Vec::new();
        huge.extend_from_slice(&8u64.to_le_bytes());
        huge.extend_from_slice(&7u64.to_le_bytes());
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(DagNode::<TestHasher, u64>::from_bytes(&huge).is_none());
    }
}
