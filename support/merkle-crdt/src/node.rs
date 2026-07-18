use crate::{Cid, Decode, Encode, Hasher};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// A node in the Merkle-DAG.
///
/// Each node contains an arbitrary payload and references to its children (previous events).
/// The node's content identifier ([`Cid`]) is computed by hashing the payload and children,
/// making the DAG self-verifying and content-addressed.
///
/// Corresponds to the node triple `(α, P, C)` from the paper where `α` is the CID,
/// `P` is the payload, and `C` is the set of children CIDs.
pub struct DagNode<H: Hasher, P> {
    /// The payload carried by this node (a CRDT operation or state).
    pub payload: P,
    /// CIDs of this node's children (older events / previous roots).
    pub children: BTreeSet<Cid<H>>,
}

impl<H: Hasher, P: Clone> Clone for DagNode<H, P> {
    fn clone(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            children: self.children.clone(),
        }
    }
}

impl<H: Hasher, P: core::fmt::Debug> core::fmt::Debug for DagNode<H, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DagNode")
            .field("payload", &self.payload)
            .field("children", &self.children)
            .finish()
    }
}

impl<H: Hasher, P> DagNode<H, P> {
    /// Create a new node with the given payload and children.
    pub fn new(payload: P, children: BTreeSet<Cid<H>>) -> Self {
        Self { payload, children }
    }

    /// Create a leaf node (no children).
    pub fn leaf(payload: P) -> Self {
        Self {
            payload,
            children: BTreeSet::new(),
        }
    }
}

impl<H: Hasher, P: Encode> DagNode<H, P> {
    /// Compute the content identifier for this node.
    ///
    /// The CID is `Hash(len(payload_bytes) || payload_bytes || num_children || child_cids...)`.
    /// This encoding is deterministic and unambiguous.
    pub fn cid(&self) -> Cid<H> {
        Cid(H::hash(&self.to_bytes()))
    }

    /// Serialize this node to bytes. The format matches the CID input:
    /// `[payload_len:u64 LE][payload_bytes][children_count:u64 LE][child_cids...]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let payload_bytes = self.payload.encode();
        buf.extend_from_slice(&(payload_bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&payload_bytes);
        buf.extend_from_slice(&(self.children.len() as u64).to_le_bytes());
        for child in &self.children {
            buf.extend_from_slice(child.as_ref());
        }
        buf
    }
}

impl<H: Hasher, P: Decode> DagNode<H, P> {
    /// Deserialize a node from bytes (inverse of `to_bytes`).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut pos: usize = 0;
        let payload_len = {
            let b = bytes.get(pos..pos.checked_add(8)?)?;
            pos += 8;
            u64::from_le_bytes(b.try_into().ok()?) as usize
        };
        let payload_end = pos.checked_add(payload_len)?;
        if payload_end > bytes.len() {
            return None;
        }
        let payload_bytes = &bytes[pos..payload_end];
        let mut payload_pos = 0;
        let payload = P::decode_from(payload_bytes, &mut payload_pos)?;
        if payload_pos != payload_bytes.len() {
            return None;
        }
        pos = payload_end;
        let count = {
            if pos + 8 > bytes.len() {
                return None;
            }
            let b = &bytes[pos..pos + 8];
            pos += 8;
            u64::from_le_bytes(b.try_into().ok()?) as usize
        };
        let hash_len = core::mem::size_of::<H::Output>();
        let mut children = BTreeSet::new();
        for _ in 0..count {
            if pos + hash_len > bytes.len() {
                return None;
            }
            let h = H::Output::decode_from(bytes, &mut pos)?;
            children.insert(Cid(h));
        }
        if pos != bytes.len() || children.len() != count {
            return None;
        }
        Some(DagNode { payload, children })
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
    fn decode_rejects_truncation_trailing_bytes_and_duplicate_children() {
        assert!(DagNode::<TestHasher, u64>::from_bytes(&[]).is_none());
        let node = DagNode::<TestHasher, u64>::leaf(7);
        let mut trailing = node.to_bytes();
        trailing.push(0);
        assert!(DagNode::<TestHasher, u64>::from_bytes(&trailing).is_none());

        let child = Cid::<TestHasher>([1; 32]);
        let mut duplicate = Vec::new();
        duplicate.extend_from_slice(&8u64.to_le_bytes());
        duplicate.extend_from_slice(&7u64.to_le_bytes());
        duplicate.extend_from_slice(&2u64.to_le_bytes());
        duplicate.extend_from_slice(child.as_ref());
        duplicate.extend_from_slice(child.as_ref());
        assert!(DagNode::<TestHasher, u64>::from_bytes(&duplicate).is_none());
    }
}
