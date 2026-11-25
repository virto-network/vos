//! A node's signature, and the stateless checks a node passes before any
//! replica state is read.

use crate::{Cid, Decode, Encode, Hasher, Node};
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

/// A sync scope's id: one DAG. Every signature names it, so a node signed
/// for one scope does not verify in another, where replaying it could
/// frame its author as equivocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(pub [u8; 16]);

const DOMAIN: &[u8] = b"merkle-crdt/node\0";

/// The bytes an author signs: a domain tag, the scope, the author, the
/// sequence number, the operations' bytes and the parents. The parents are
/// signed, so the author attests to where in the DAG its operations stand.
pub fn message<H: Hasher>(
    scope: &Scope,
    author: &Author,
    seq: u64,
    ops: &[u8],
    parents: &BTreeSet<Cid<H>>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN.len() + 56 + ops.len() + 32 * parents.len());
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(&scope.0);
    buf.extend_from_slice(&author.0);
    buf.extend_from_slice(&seq.to_le_bytes());
    ops.encode_to(&mut buf);
    buf.extend_from_slice(&(parents.len() as u64).to_le_bytes());
    for parent in parents {
        buf.extend_from_slice(parent.as_ref());
    }
    buf
}

impl<H: Hasher, O: Encode> Node<H, O> {
    /// A node of `ops` at `seq` in `key`'s chain of `scope`, after
    /// `parents`, signed.
    pub fn sign(
        key: &SigningKey,
        scope: &Scope,
        seq: u64,
        ops: O,
        parents: BTreeSet<Cid<H>>,
    ) -> Self {
        use ed25519_dalek::Signer;
        let author = Author::from(key);
        let signature = key
            .sign(&message(scope, &author, seq, &ops.encode(), &parents))
            .to_bytes();
        Node {
            author,
            seq,
            signature,
            ops,
            parents,
        }
    }

    /// Whether the signature is the author's over the node in `scope`. Strict: a
    /// signature with a non-canonical scalar, or a weak key, is refused, so
    /// no third party can turn one signed node into a second that verifies
    /// and so frame its author as equivocating.
    pub fn verify(&self, scope: &Scope) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.author.0) else {
            return false;
        };
        let message = message(
            scope,
            &self.author,
            self.seq,
            &self.ops.encode(),
            &self.parents,
        );
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .is_ok()
    }
}

/// Why a node is refused. A refused node is never stored or applied; a
/// node naming a refused node among its parents is refused too while the
/// replica remembers the refusal (the latest few thousand, since it
/// opened), and held as waiting on it after.
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

/// A node validated, with its CID; or why it was refused, with its CID where
/// it decodes.
pub type Validated<H, O> = Result<(Cid<H>, Node<H, O>), (Option<Cid<H>>, Refusal)>;

/// The stateless checks of a node's bytes: they decode, canonically, and the
/// signature is the author's over it in `scope`. Returns the node and its
/// CID; the CID is known for a node refused for its signature.
pub fn validate<H: Hasher, O: Encode + Decode>(scope: &Scope, bytes: &[u8]) -> Validated<H, O> {
    let node = decode::<H, O>(bytes).ok_or((None, Refusal::Malformed))?;
    let cid = Cid(H::hash(bytes));
    if !node.verify(scope) {
        return Err((Some(cid), Refusal::BadSignature));
    }
    Ok((cid, node))
}

/// Decode a node, accepting only bytes that are its canonical encoding.
pub(crate) fn decode<H: Hasher, O: Encode + Decode>(bytes: &[u8]) -> Option<Node<H, O>> {
    let node = Node::<H, O>::from_bytes(bytes)?;
    (node.to_bytes() == bytes).then_some(node)
}
