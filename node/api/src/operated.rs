//! An operator's request: the kind's body in an envelope an operator key
//! signs for one node, one kind, once (by its nonce) and until an expiry.

use scale::{Decode, Encode};
use vos_wire::ingress::NodeId;

use crate::Kind;

/// What an operator's signature starts with, apart from a client's call,
/// query or workflow read.
pub const OPERATOR_DOMAIN: &[u8] = b"vos/operator/1";

/// An operator kind's body: `body`, the kind's request, signed by `key`
/// for node `node`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Operated {
    /// The node it is signed for.
    pub node: NodeId,
    /// An operator key the node lists.
    pub key: [u8; 32],
    /// The operator's, at random: a command runs once by it.
    pub nonce: [u8; 16],
    /// The last moment it is good, by the node's clock, in milliseconds.
    pub expires_ms: u64,
    /// The kind's request, in SCALE.
    pub body: Vec<u8>,
    /// `key`'s ed25519 signature over [`Operated::message`].
    pub signature: [u8; 64],
}

/// The envelope's fields but its body, as an HTTP header carries them:
/// the node, the key, the nonce, the expiry (8 bytes LE) and the
/// signature.
pub const CREDENTIALS: usize = 32 + 32 + 16 + 8 + 64;

impl Operated {
    /// What `key` signs for a request of `kind`.
    pub fn message(&self, kind: Kind) -> Vec<u8> {
        operator_message(&self.node, kind, &self.nonce, self.expires_ms, &self.body)
    }

    /// Its fields but its body, as an HTTP `Authorization` header carries
    /// them.
    pub fn credentials(&self) -> [u8; CREDENTIALS] {
        let mut bytes = [0u8; CREDENTIALS];
        bytes[..32].copy_from_slice(&self.node.0);
        bytes[32..64].copy_from_slice(&self.key);
        bytes[64..80].copy_from_slice(&self.nonce);
        bytes[80..88].copy_from_slice(&self.expires_ms.to_le_bytes());
        bytes[88..].copy_from_slice(&self.signature);
        bytes
    }

    /// The envelope of `body` with `credentials`' fields.
    pub fn with_credentials(credentials: &[u8; CREDENTIALS], body: Vec<u8>) -> Self {
        let part = |range: core::ops::Range<usize>| &credentials[range];
        Self {
            node: NodeId(part(0..32).try_into().expect("32 bytes")),
            key: part(32..64).try_into().expect("32 bytes"),
            nonce: part(64..80).try_into().expect("16 bytes"),
            expires_ms: u64::from_le_bytes(part(80..88).try_into().expect("8 bytes")),
            body,
            signature: part(88..CREDENTIALS).try_into().expect("64 bytes"),
        }
    }
}

/// What an operator key signs for a request of `kind` to node `node`:
/// the domain, the node, the kind (2 bytes LE), the nonce, the expiry (8
/// bytes LE) and the body as SCALE (a `u32` LE length, then its bytes).
pub fn operator_message(
    node: &NodeId,
    kind: Kind,
    nonce: &[u8; 16],
    expires_ms: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OPERATOR_DOMAIN.len() + 62 + body.len());
    bytes.extend_from_slice(OPERATOR_DOMAIN);
    bytes.extend_from_slice(&node.0);
    bytes.extend_from_slice(&(kind as u16).to_le_bytes());
    bytes.extend_from_slice(nonce);
    expires_ms.encode_to(&mut bytes);
    body.encode_to(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operated() -> Operated {
        Operated {
            node: NodeId([1; 32]),
            key: [2; 32],
            nonce: [3; 16],
            expires_ms: 0x0102_0304_0506_0708,
            body: vec![9, 9],
            signature: [4; 64],
        }
    }

    /// The signed message, byte for byte.
    #[test]
    fn the_message_is_pinned() {
        let message = operated().message(Kind::Install);
        let mut expected = b"vos/operator/1".to_vec();
        expected.extend([1; 32]);
        expected.extend([0x05, 0x02]);
        expected.extend([3; 16]);
        expected.extend([8, 7, 6, 5, 4, 3, 2, 1]);
        expected.extend([2, 0, 0, 0, 9, 9]);
        assert_eq!(message, expected);
        // Another kind or node, another message.
        assert_ne!(operated().message(Kind::Grant), message);
    }

    /// The envelope's encoding: its fields in order, the body with its
    /// length; 156 bytes beside the body.
    #[test]
    fn the_envelope_is_pinned() {
        let bytes = operated().encode();
        assert_eq!(bytes.len(), crate::OPERATED as usize + 2);
        assert_eq!(&bytes[..32], &[1; 32]);
        assert_eq!(&bytes[88..94], &[2, 0, 0, 0, 9, 9]);
        assert_eq!(Operated::decode_exact(&bytes), Some(operated()));
    }

    #[test]
    fn credentials_round_trip() {
        let operated = operated();
        let credentials = operated.credentials();
        assert_eq!(
            Operated::with_credentials(&credentials, operated.body.clone()),
            operated
        );
        assert_eq!(&credentials[80..88], &[8, 7, 6, 5, 4, 3, 2, 1]);
    }
}
