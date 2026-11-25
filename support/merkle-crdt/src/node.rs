use crate::{Author, Cid, Decode, Encode, Hasher};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// The most parents a node names. A node naming more does not decode, so
/// no replica applies it; a replica's own node names its author's previous
/// node and at most this many in all ([`Replica::record`](crate::Replica::record)).
pub const MAX_PARENTS: usize = 64;

/// A node of the Merkle-DAG: an author's operations at a position of its
/// chain, signed, and the CIDs of its parents, the earlier events it
/// follows.
///
/// The node's [`Cid`] is the hash of its bytes ([`to_bytes`](Self::to_bytes)),
/// so the DAG is self-verifying and content-addressed. An author's nodes are
/// numbered from 0, and each node after the first names its author's
/// previous node among its parents, so an author's chain is linked and has
/// no gaps. Two nodes of one author with one sequence number are an
/// equivocation.
pub struct Node<H: Hasher, O> {
    /// The author's key.
    pub author: Author,
    /// The node's position in its author's chain.
    pub seq: u64,
    /// The author's signature over the scope, the author, the sequence
    /// number, the operations and the parents.
    pub signature: [u8; 64],
    /// The operations.
    pub ops: O,
    /// The CIDs of the events this node follows.
    pub parents: BTreeSet<Cid<H>>,
}

impl<H: Hasher, O: Clone> Clone for Node<H, O> {
    fn clone(&self) -> Self {
        Self {
            author: self.author,
            seq: self.seq,
            signature: self.signature,
            ops: self.ops.clone(),
            parents: self.parents.clone(),
        }
    }
}

impl<H: Hasher, O: core::fmt::Debug> core::fmt::Debug for Node<H, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("author", &self.author)
            .field("seq", &self.seq)
            .field("signature", &self.signature)
            .field("ops", &self.ops)
            .field("parents", &self.parents)
            .finish()
    }
}

impl<H: Hasher, O: Encode> Node<H, O> {
    /// The node's content identifier: the hash of its bytes.
    pub fn cid(&self) -> Cid<H> {
        Cid(H::hash(&self.to_bytes()))
    }

    /// The node's bytes:
    /// `[payload_len: u64 LE][payload][parent_count: u64 LE][parent CIDs, ascending]`,
    /// the payload `[author][seq: u64 LE][signature][ops]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = alloc::vec![0; 8];
        buf.extend_from_slice(&self.author.0);
        self.seq.encode_to(&mut buf);
        buf.extend_from_slice(&self.signature);
        self.ops.encode_to(&mut buf);
        let len = (buf.len() - 8) as u64;
        buf[..8].copy_from_slice(&len.to_le_bytes());
        (self.parents.len() as u64).encode_to(&mut buf);
        for parent in &self.parents {
            buf.extend_from_slice(parent.as_ref());
        }
        buf
    }
}

impl<H: Hasher, O: Decode> Node<H, O> {
    /// Decode a node from its bytes: the inverse of
    /// [`to_bytes`](Node::to_bytes), refusing trailing bytes, a parent
    /// named twice and more than [`MAX_PARENTS`]. Not a check of canonical
    /// form: that is [`validate`](crate::validate)'s.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (head, parents) = split::<H>(bytes)?;
        let (signature, ops) = head.rest.split_first_chunk::<64>()?;
        Some(Node {
            author: head.author,
            seq: head.seq,
            signature: *signature,
            ops: O::decode(ops)?,
            parents: distinct(parents)?,
        })
    }
}

/// The start of a node's payload: its author, its sequence number, and the
/// rest (the signature and the operations).
struct Head<'a> {
    author: Author,
    seq: u64,
    rest: &'a [u8],
}

/// A node's bytes split into its payload's head and its parents, at most
/// [`MAX_PARENTS`], which are checked for order only when collected.
fn split<H: Hasher>(bytes: &[u8]) -> Option<(Head<'_>, impl Iterator<Item = Option<Cid<H>>> + '_)> {
    let (len, rest) = bytes.split_first_chunk::<8>()?;
    let len = usize::try_from(u64::from_le_bytes(*len)).ok()?;
    let payload = rest.get(..len)?;
    let (author, payload_rest) = payload.split_first_chunk::<32>()?;
    let (seq, payload_rest) = payload_rest.split_first_chunk::<8>()?;
    let head = Head {
        author: Author(*author),
        seq: u64::from_le_bytes(*seq),
        rest: payload_rest,
    };
    let (count, parents) = rest[len..].split_first_chunk::<8>()?;
    let count = usize::try_from(u64::from_le_bytes(*count)).ok()?;
    if count > MAX_PARENTS {
        return None;
    }
    let width = core::mem::size_of::<H::Output>();
    if parents.len() != count.checked_mul(width)? {
        return None;
    }
    Some((
        head,
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
/// author, sequence number and parents. A caller that admits only some
/// authors reads it after [`validate`](crate::validate), before an ingest.
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
    /// Read the header of a node's bytes, of any operation type.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let (head, parents) = split::<H>(bytes)?;
        Some(Header {
            author: head.author,
            seq: head.seq,
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

    /// The bytes of a node of 7 before its parents: its length and payload.
    fn payload() -> Vec<u8> {
        let mut bytes = node(BTreeSet::new()).to_bytes();
        bytes.truncate(bytes.len() - 8);
        bytes
    }

    fn node(parents: BTreeSet<Cid<TestHasher>>) -> Node<TestHasher, u64> {
        Node {
            author: Author([3; 32]),
            seq: 1,
            signature: [5; 64],
            ops: 7,
            parents,
        }
    }

    #[test]
    fn decode_rejects_truncation_trailing_bytes_and_duplicate_parents() {
        assert!(Node::<TestHasher, u64>::from_bytes(&[]).is_none());
        let mut trailing = node(BTreeSet::new()).to_bytes();
        trailing.push(0);
        assert!(Node::<TestHasher, u64>::from_bytes(&trailing).is_none());

        let parent = Cid::<TestHasher>([1; 32]);
        let mut duplicate = payload();
        duplicate.extend_from_slice(&2u64.to_le_bytes());
        duplicate.extend_from_slice(parent.as_ref());
        duplicate.extend_from_slice(parent.as_ref());
        assert!(Node::<TestHasher, u64>::from_bytes(&duplicate).is_none());
        assert!(Header::<TestHasher>::read(&duplicate).is_none());

        let mut huge = payload();
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(Node::<TestHasher, u64>::from_bytes(&huge).is_none());

        let once = node(BTreeSet::from([parent])).to_bytes();
        assert!(Node::<TestHasher, u64>::from_bytes(&once).is_some());
    }
}
