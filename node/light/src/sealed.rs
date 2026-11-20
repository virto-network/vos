//! Sealed envelopes (`light-node.md` §3.6): what a device pushes to the
//! personal agent, opaque to it but for a clear header.
//!
//! ```text
//! envelope  = header ‖ sealed
//! header    = { scope: [u8; 16], epoch: u64, nonce: [u8; 24], len_class: u8 }   (clear; AAD)
//! sealed    = XChaCha20-Poly1305(key, nonce, Padmé(body), AAD = header ‖ agent id)
//! ```
//!
//! - **Padmé** ([`padme`]): the body framed by its length and padded with
//!   zeros to the Padmé length of the frame, at most 12% over it, so a
//!   size says no more than its class; `len_class` is the padded length's
//!   bit length less one, checked on open against the bytes.
//! - **The nonce** is the operating system's, 24 bytes: no counter to keep
//!   across devices or crashes.
//! - **The agent's identity** is bound, so an envelope replayed to another
//!   agent does not open there.
//!
//! A data scope's body ([`Body`]) is a node of its DAG (its author, sequence
//! number, signature, parents and operations, `merkle_crdt::Node`'s bytes),
//! the writer's view of the control log and its `seen` positions, sealed
//! under `k(scope, epoch)`. The archive scope's and the recovery scope's
//! bodies are theirs ([`crate::personal`]).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use vos_abi::{Decode, Encode};
use vos_wire::personal::{Header, MAX_ENVELOPE, Scope};
use zeroize::Zeroizing;

/// The AEAD's tag.
pub const TAG: usize = 16;

/// The frame's length prefix: the body's length, little-endian.
const FRAME: usize = 4;

/// Padmé's length for `len` bytes: `len` rounded up so that only the top
/// `⌊log₂ E⌋ + 1` bits of its `E = ⌊log₂ len⌋` bits vary, which leaks
/// `O(log log len)` bits of it and pads by at most 12%.
pub const fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = len.ilog2();
    let s = e.ilog2() + 1;
    let mask = (1usize << (e - s)) - 1;
    (len + mask) & !mask
}

/// The largest padded frame an envelope holds: its header, the frame and
/// the tag within [`MAX_ENVELOPE`].
const MAX_PADDED: usize = {
    let room = MAX_ENVELOPE - Header::BYTES - TAG;
    let mut len = room;
    while padme(len) != len {
        len -= 1;
    }
    len
};

/// The largest body an envelope seals.
pub const MAX_BODY: usize = MAX_PADDED - FRAME;

const _: () = assert!(Header::BYTES + MAX_PADDED + TAG <= MAX_ENVELOPE);
const _: () = assert!(Header::BYTES + padme(MAX_PADDED + 1) + TAG > MAX_ENVELOPE);

/// The class of a padded frame of `padded` bytes, as the header carries it.
pub fn len_class(padded: usize) -> u8 {
    padded.max(1).ilog2() as u8
}

/// Why an envelope does not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Shorter than a header and a tag, or its class is not its length's.
    Malformed,
    /// No key given opens it: forged, garbage, or sealed under a key this
    /// device does not hold.
    Unopened,
    /// It opens, and its frame or its padding is not one a device seals.
    Framing,
}

/// A body too large for an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLarge;

/// The header of an envelope of `scope` at `epoch` holding a padded frame
/// of `padded` bytes, its nonce drawn from the operating system; `None`
/// without randomness.
fn header(scope: Scope, epoch: u64, padded: usize) -> Option<Header> {
    let mut nonce = [0; 24];
    getrandom::getrandom(&mut nonce).ok()?;
    Some(Header {
        scope,
        epoch,
        nonce,
        len_class: len_class(padded),
    })
}

fn aad(header: &Header, agent: &[u8; 32]) -> Vec<u8> {
    let mut aad = header.to_bytes().to_vec();
    aad.extend_from_slice(agent);
    aad
}

/// Seal `body` for scope `scope` at `epoch` under `key`, for the agent whose
/// identity is `agent`. [`TooLarge`] past [`MAX_BODY`]; a panic without the
/// operating system's randomness, as a nonce must never repeat.
pub fn seal(
    key: &[u8; 32],
    agent: &[u8; 32],
    scope: Scope,
    epoch: u64,
    body: &[u8],
) -> Result<Vec<u8>, TooLarge> {
    if body.len() > MAX_BODY {
        return Err(TooLarge);
    }
    let padded = padme(body.len() + FRAME);
    let mut frame = Zeroizing::new(Vec::with_capacity(padded));
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    frame.resize(padded, 0);
    let header = header(scope, epoch, padded).expect("the operating system's randomness");
    let sealed = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &frame,
                aad: &aad(&header, agent),
            },
        )
        .expect("a frame within the bound seals");
    let mut envelope = header.to_bytes().to_vec();
    envelope.extend_from_slice(&sealed);
    Ok(envelope)
}

/// An envelope's clear header, if it has one whose class is its length's.
pub fn header_of(envelope: &[u8]) -> Result<Header, OpenError> {
    let header = Header::parse(envelope).ok_or(OpenError::Malformed)?;
    let padded = envelope
        .len()
        .checked_sub(Header::BYTES + TAG)
        .ok_or(OpenError::Malformed)?;
    if padme(padded) != padded || header.len_class != len_class(padded) {
        return Err(OpenError::Malformed);
    }
    Ok(header)
}

/// Open `envelope`, sealed for the agent whose identity is `agent`, under
/// the first of `keys` that opens it: its header and its body.
pub fn open(
    keys: &[[u8; 32]],
    agent: &[u8; 32],
    envelope: &[u8],
) -> Result<(Header, Zeroizing<Vec<u8>>), OpenError> {
    let header = header_of(envelope)?;
    let aad = aad(&header, agent);
    let sealed = &envelope[Header::BYTES..];
    let frame = keys
        .iter()
        .find_map(|key| {
            XChaCha20Poly1305::new(key.into())
                .decrypt(
                    XNonce::from_slice(&header.nonce),
                    Payload {
                        msg: sealed,
                        aad: &aad,
                    },
                )
                .ok()
        })
        .map(Zeroizing::new)
        .ok_or(OpenError::Unopened)?;
    let (len, rest) = frame
        .split_first_chunk::<FRAME>()
        .ok_or(OpenError::Framing)?;
    let len = u32::from_le_bytes(*len) as usize;
    if len > rest.len() || rest[len..].iter().any(|byte| *byte != 0) {
        return Err(OpenError::Framing);
    }
    Ok((header, Zeroizing::new(rest[..len].to_vec())))
}

/// The writer's view of the control log: the next index it would read, and
/// the log's chain through the entry before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct View {
    pub index: u64,
    pub chain: [u8; 32],
}

/// A data scope's body: a node of its DAG, the writer's view of the control
/// log, and, each scope it reads, the highest position it had read there.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Body {
    pub node: Vec<u8>,
    pub view: View,
    pub seen: Vec<(Scope, u64)>,
}

impl Body {
    /// Its encoding, within [`MAX_BODY`]: the `seen` positions cut to the
    /// envelope's own scope's when all of them do not fit beside the node.
    pub fn sealable(mut self, scope: &Scope) -> Result<Vec<u8>, TooLarge> {
        let bytes = self.encode();
        if bytes.len() <= MAX_BODY {
            return Ok(bytes);
        }
        self.seen.retain(|(seen, _)| seen == scope);
        let bytes = self.encode();
        if bytes.len() <= MAX_BODY {
            Ok(bytes)
        } else {
            Err(TooLarge)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_pads_by_at_most_twelve_percent_and_is_stable() {
        for len in 2..200_000usize {
            let padded = padme(len);
            assert!(padded >= len);
            assert!((padded - len) * 100 <= len * 12, "{len} → {padded}");
            assert_eq!(padme(padded), padded);
        }
        assert_eq!(MAX_PADDED, 59_392);
    }

    #[test]
    fn an_envelope_opens_under_its_key_and_agent_alone() {
        let key = [7; 32];
        let agent = [9; 32];
        for len in [0, 1, 100, 1000, MAX_BODY] {
            let body = vec![0xab; len];
            let envelope = seal(&key, &agent, [3; 16], 4, &body).unwrap();
            assert!(envelope.len() <= MAX_ENVELOPE);
            assert_eq!(header_of(&envelope).unwrap().scope, [3; 16]);
            let (header, opened) = open(&[[1; 32], key], &agent, &envelope).unwrap();
            assert_eq!((header.scope, header.epoch), ([3; 16], 4));
            assert_eq!(&opened[..], &body[..]);
            assert_eq!(open(&[key], &[8; 32], &envelope), Err(OpenError::Unopened));
            assert_eq!(
                open(&[[1; 32]], &agent, &envelope),
                Err(OpenError::Unopened)
            );
            let mut moved = envelope.clone();
            moved[16] ^= 1;
            assert_eq!(open(&[key], &agent, &moved), Err(OpenError::Unopened));
            let mut cut = envelope.clone();
            cut.pop();
            assert!(open(&[key], &agent, &cut).is_err());
        }
        assert_eq!(
            seal(&key, &agent, [3; 16], 4, &vec![0; MAX_BODY + 1]),
            Err(TooLarge)
        );
        assert_eq!(open(&[key], &agent, &[0; 60]), Err(OpenError::Malformed));
        let one = seal(&key, &agent, [3; 16], 4, b"x").unwrap();
        let two = seal(&key, &agent, [3; 16], 4, b"x").unwrap();
        assert_ne!(one, two, "a fresh nonce each seal");
    }
}
