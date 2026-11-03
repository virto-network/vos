//! A replica's node: the author's key, sequence number and signature
//! travel in the payload, beside the operations, and the stateless checks
//! a node passes before any replica state is read.

use crate::{Cid, DagNode, Decode, Encode, Hasher};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// An author: the ed25519 key its nodes are signed with. A device or node
/// takes a fresh one on every install, start or restore, so a sequence
/// number is never reused under one key by a backup.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Author(pub [u8; 32]);

impl core::fmt::Debug for Author {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Author(")?;
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

impl From<&SigningKey> for Author {
    fn from(key: &SigningKey) -> Self {
        Author(key.verifying_key().to_bytes())
    }
}

/// A node's payload: the operations, and who wrote them at which position
/// of their chain, signed.
///
/// An author's nodes are numbered from 0, and each node after the first
/// names its author's previous node among its parents, so an author's chain
/// is linked and has no gaps. Two nodes of one author with one sequence
/// number are an equivocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<O> {
    /// The author's key.
    pub author: Author,
    /// The node's position in its author's chain.
    pub seq: u64,
    /// The author's signature over [`message`]: the author, the sequence
    /// number, the operations and the parents.
    pub signature: [u8; 64],
    /// The operations.
    pub ops: O,
}

/// A replica's node.
pub type Node<H, O> = DagNode<H, Signed<O>>;

impl<O: Encode> Encode for Signed<O> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.author.0);
        self.seq.encode_to(buf);
        buf.extend_from_slice(&self.signature);
        self.ops.encode_to(buf);
    }
}

impl<O: Decode> Decode for Signed<O> {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        Some(Signed {
            author: Author(<[u8; 32]>::decode_from(buf, pos)?),
            seq: u64::decode_from(buf, pos)?,
            signature: <[u8; 64]>::decode_from(buf, pos)?,
            ops: O::decode_from(buf, pos)?,
        })
    }
}

const DOMAIN: &[u8] = b"merkle-crdt/node\0";

/// The bytes an author signs: a domain tag, the author, the sequence
/// number, the operations' bytes and the parents. The parents are signed,
/// so the author attests to where in the DAG its operations stand.
pub fn message<H: Hasher>(
    author: &Author,
    seq: u64,
    ops: &[u8],
    parents: &BTreeSet<Cid<H>>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN.len() + 56 + ops.len() + 32 * parents.len());
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(&author.0);
    buf.extend_from_slice(&seq.to_le_bytes());
    ops.encode_to(&mut buf);
    buf.extend_from_slice(&(parents.len() as u64).to_le_bytes());
    for parent in parents {
        buf.extend_from_slice(parent.as_ref());
    }
    buf
}

impl<H: Hasher, O: Encode> DagNode<H, Signed<O>> {
    /// A node of `ops` at `seq` in `key`'s chain, after `parents`, signed.
    pub fn sign(key: &SigningKey, seq: u64, ops: O, parents: BTreeSet<Cid<H>>) -> Self {
        use ed25519_dalek::Signer;
        let author = Author::from(key);
        let signature = key
            .sign(&message(&author, seq, &ops.encode(), &parents))
            .to_bytes();
        DagNode {
            payload: Signed {
                author,
                seq,
                signature,
                ops,
            },
            parents,
        }
    }

    /// Whether the signature is the author's over the node. Strict: a
    /// signature with a non-canonical scalar, or a weak key, is refused, so
    /// no third party can turn one signed node into a second that verifies
    /// and so frame its author as equivocating.
    pub fn verify(&self) -> bool {
        let Signed {
            author,
            seq,
            signature,
            ops,
        } = &self.payload;
        let Ok(key) = VerifyingKey::from_bytes(&author.0) else {
            return false;
        };
        key.verify_strict(
            &message(author, *seq, &ops.encode(), &self.parents),
            &Signature::from_bytes(signature),
        )
        .is_ok()
    }
}

/// Why a node is refused. A refused node is never stored or applied; a
/// node naming a refused node among its parents is refused too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Its bytes do not decode, or are not the canonical encoding of what
    /// they decode to.
    Malformed,
    /// The signature is not its author's over it.
    BadSignature,
    /// It is not its author's first node, and none of its parents is its
    /// author's previous one.
    BrokenChain,
    /// One of its parents was refused.
    RefusedParent,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Refusal::Malformed => "the node's bytes are not a node's canonical encoding",
            Refusal::BadSignature => "the node's signature is not its author's",
            Refusal::BrokenChain => "the node does not follow its author's previous node",
            Refusal::RefusedParent => "a parent of the node was refused",
        })
    }
}

/// The stateless checks of a node's bytes: they decode, canonically, and the
/// signature is the author's. Returns the node and its CID; the CID is known
/// for a node refused for its signature.
#[allow(clippy::type_complexity)]
pub fn validate<H: Hasher, O: Encode + Decode>(
    bytes: &[u8],
) -> Result<(Cid<H>, Node<H, O>), (Option<Cid<H>>, Refusal)> {
    let node = decode::<H, O>(bytes).ok_or((None, Refusal::Malformed))?;
    let cid = Cid(H::hash(bytes));
    if !node.verify() {
        return Err((Some(cid), Refusal::BadSignature));
    }
    Ok((cid, node))
}

/// Decode a node, accepting only bytes that are its canonical encoding.
pub(crate) fn decode<H: Hasher, O: Encode + Decode>(bytes: &[u8]) -> Option<Node<H, O>> {
    let node = Node::<H, O>::from_bytes(bytes)?;
    (node.to_bytes() == bytes).then_some(node)
}
