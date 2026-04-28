//! Wire format for inter-node messages over libp2p.
//!
//! All multi-byte integers are little-endian. The first byte of each
//! frame is a tag that discriminates the kind. There is no separate
//! envelope around frames — the libp2p `request_response` codec
//! length-prefixes the bytes for us.
//!
//! Cycle 2 frames:
//!
//! - [`Frame::Hello`] — exchanged once per connection so peers learn
//!   each other's `node_prefix`. Sent as a request; the receiver's
//!   own `Hello` rides back as the response.
//! - [`Frame::Tell`] — fire-and-forget envelope addressed to a
//!   service on the remote node. The response slot carries
//!   [`Frame::Ack`].
//! - [`Frame::InvokeRequest`] / [`Frame::InvokeReply`] — synchronous
//!   request/reply pair, one round trip per call. Reuses the
//!   `chain` field from [`crate::node`] for cross-node cycle and
//!   depth detection.
//!
//! The encoding is deliberately hand-rolled (no serde / rkyv): the
//! schema is small, framing the wire format ourselves makes
//! versioning explicit, and we sidestep pulling another serializer
//! into the network feature's dep tree.

const TAG_HELLO: u8 = 0x10;
const TAG_TELL: u8 = 0x01;
const TAG_INVOKE_REQ: u8 = 0x02;
const TAG_INVOKE_REPLY: u8 = 0x03;
const TAG_ACK: u8 = 0x04;

/// Hard cap on a single encoded frame. Matches the producer-side
/// reply cap in `node.rs` so an oversized payload is rejected at
/// the same boundary regardless of whether it's local or networked.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum number of hops carried in an `InvokeRequest` chain.
/// Mirrors `MAX_CROSS_AGENT_DEPTH` in `node.rs`. Encoded as a u32
/// length prefix; this cap stops a malicious peer from triggering
/// gigabyte allocations by claiming an absurd chain length.
const MAX_CHAIN_LEN: usize = 32;

/// One frame on the wire. See module docs for tag layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello { node_prefix: u16 },
    Tell {
        from: u32,
        to: u32,
        payload: Vec<u8>,
    },
    InvokeRequest {
        from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
    },
    InvokeReply { payload: Vec<u8> },
    /// Empty acknowledgement — used as the response slot for
    /// fire-and-forget `Tell` so the request_response behaviour
    /// has something to deliver.
    Ack,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Frame::Hello { node_prefix } => {
                out.push(TAG_HELLO);
                out.extend_from_slice(&node_prefix.to_le_bytes());
            }
            Frame::Tell { from, to, payload } => {
                out.push(TAG_TELL);
                out.extend_from_slice(&from.to_le_bytes());
                out.extend_from_slice(&to.to_le_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
            Frame::InvokeRequest { from, to, chain, msg } => {
                out.push(TAG_INVOKE_REQ);
                out.extend_from_slice(&from.to_le_bytes());
                out.extend_from_slice(&to.to_le_bytes());
                out.extend_from_slice(&(chain.len() as u32).to_le_bytes());
                for hop in chain {
                    out.extend_from_slice(&hop.to_le_bytes());
                }
                out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
                out.extend_from_slice(msg);
            }
            Frame::InvokeReply { payload } => {
                out.push(TAG_INVOKE_REPLY);
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
            Frame::Ack => {
                out.push(TAG_ACK);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let frame = match tag {
            TAG_HELLO => Frame::Hello {
                node_prefix: r.u16()?,
            },
            TAG_TELL => Frame::Tell {
                from: r.u32()?,
                to: r.u32()?,
                payload: r.bytes_with_len_prefix()?,
            },
            TAG_INVOKE_REQ => {
                let from = r.u32()?;
                let to = r.u32()?;
                let chain_len = r.u32()? as usize;
                if chain_len > MAX_CHAIN_LEN {
                    return Err(FrameError::ChainTooLong(chain_len));
                }
                let mut chain = Vec::with_capacity(chain_len);
                for _ in 0..chain_len {
                    chain.push(r.u32()?);
                }
                let msg = r.bytes_with_len_prefix()?;
                Frame::InvokeRequest { from, to, chain, msg }
            }
            TAG_INVOKE_REPLY => Frame::InvokeReply {
                payload: r.bytes_with_len_prefix()?,
            },
            TAG_ACK => Frame::Ack,
            other => return Err(FrameError::UnknownTag(other)),
        };
        if !r.is_empty() {
            return Err(FrameError::TrailingBytes(r.remaining()));
        }
        Ok(frame)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    UnknownTag(u8),
    ChainTooLong(usize),
    PayloadTooLarge(usize),
    TrailingBytes(usize),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "frame truncated"),
            FrameError::UnknownTag(t) => write!(f, "unknown frame tag {t:#04x}"),
            FrameError::ChainTooLong(n) => {
                write!(f, "chain length {n} exceeds cap {MAX_CHAIN_LEN}")
            }
            FrameError::PayloadTooLarge(n) => {
                write!(f, "payload length {n} exceeds cap {MAX_FRAME_BYTES}")
            }
            FrameError::TrailingBytes(n) => write!(f, "{n} trailing bytes after frame"),
        }
    }
}

impl std::error::Error for FrameError {}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        if self.pos + n > self.buf.len() {
            return Err(FrameError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, FrameError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, FrameError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn bytes_with_len_prefix(&mut self) -> Result<Vec<u8>, FrameError> {
        let len = self.u32()? as usize;
        if len > MAX_FRAME_BYTES {
            return Err(FrameError::PayloadTooLarge(len));
        }
        Ok(self.take(len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn hello_roundtrip() {
        roundtrip(Frame::Hello { node_prefix: 0x42AB });
        roundtrip(Frame::Hello { node_prefix: 0 });
        roundtrip(Frame::Hello { node_prefix: u16::MAX });
    }

    #[test]
    fn tell_roundtrip() {
        roundtrip(Frame::Tell {
            from: 0x00010002,
            to: 0x00030004,
            payload: vec![],
        });
        roundtrip(Frame::Tell {
            from: 0xDEADBEEF,
            to: 0xCAFEF00D,
            payload: b"hello world".to_vec(),
        });
    }

    #[test]
    fn invoke_request_roundtrip() {
        roundtrip(Frame::InvokeRequest {
            from: 1,
            to: 2,
            chain: vec![],
            msg: vec![],
        });
        roundtrip(Frame::InvokeRequest {
            from: 1,
            to: 2,
            chain: vec![1, 2, 3, 4],
            msg: b"payload".to_vec(),
        });
    }

    #[test]
    fn invoke_reply_roundtrip() {
        roundtrip(Frame::InvokeReply { payload: vec![] });
        roundtrip(Frame::InvokeReply {
            payload: vec![0x00, 0xFF, 0x42],
        });
    }

    #[test]
    fn ack_roundtrip() {
        roundtrip(Frame::Ack);
    }

    #[test]
    fn truncated_input_rejected() {
        // Just the tag, no body.
        assert!(matches!(
            Frame::decode(&[TAG_HELLO]),
            Err(FrameError::Truncated)
        ));
        // Tell with zero-length payload but missing the length field.
        assert!(matches!(
            Frame::decode(&[TAG_TELL, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn unknown_tag_rejected() {
        assert!(matches!(
            Frame::decode(&[0xFE]),
            Err(FrameError::UnknownTag(0xFE))
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bad = Frame::Ack.encode();
        bad.push(0x99);
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::TrailingBytes(1))
        ));
    }

    #[test]
    fn chain_length_capped() {
        // Forge a frame claiming a chain of 1_000 entries.
        let mut bad = Vec::new();
        bad.push(TAG_INVOKE_REQ);
        bad.extend_from_slice(&0u32.to_le_bytes()); // from
        bad.extend_from_slice(&0u32.to_le_bytes()); // to
        bad.extend_from_slice(&(1_000u32).to_le_bytes()); // chain_len
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::ChainTooLong(1_000))
        ));
    }

    #[test]
    fn payload_length_capped() {
        // Forge a frame claiming a 10 MiB payload.
        let mut bad = Vec::new();
        bad.push(TAG_TELL);
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&(10 * 1024 * 1024u32).to_le_bytes());
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::PayloadTooLarge(_))
        ));
    }
}
