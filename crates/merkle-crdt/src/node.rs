use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use crate::{Cid, Encode, Hasher};

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
        let mut buf = Vec::new();
        let payload_bytes = self.payload.encode();
        buf.extend_from_slice(&(payload_bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&payload_bytes);
        buf.extend_from_slice(&(self.children.len() as u64).to_le_bytes());
        for child in &self.children {
            buf.extend_from_slice(child.as_ref());
        }
        Cid(H::hash(&buf))
    }
}
