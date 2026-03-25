//! Message encoding format for cross-boundary communication.
//!
//! Messages are passed as byte slices across the executor↔child boundary.
//! The format is a simple fixed header + payload — no allocator needed
//! to decode.
//!
//! **Byte order**: All multi-byte fields use **little-endian** encoding.
//! This matches the PVM target (RISC-V little-endian) and avoids byte
//! swapping on the most common host architectures (x86, ARM in LE mode).
//! If a big-endian host is ever needed, the encoding functions handle
//! the conversion — callers always work with native types.
//!
//! ```text
//! ┌──────────┬──────────┬─────────────────┐
//! │ sender   │ payload  │ payload bytes... │
//! │ (4 LE)   │ len(4 LE)│ (variable)      │
//! └──────────┴──────────┴─────────────────┘
//! ```

use crate::actor::ActorId;

/// Message header. Appears at the start of every encoded message.
///
/// The message type discriminant is encoded inside the rkyv payload,
/// so the header only carries the sender and payload length.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// Who sent this message.
    pub sender: ActorId,
    /// Length of the payload in bytes (following the header).
    pub payload_len: u32,
}

impl Header {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Decode a header from a byte slice. Returns `None` if too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let sender = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let payload_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Some(Self {
            sender: ActorId(sender),
            payload_len,
        })
    }

    /// Encode the header into a byte array.
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.sender.0.to_le_bytes());
        buf[4..8].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }
}

/// A borrowed message: header + payload reference. Zero-copy decode.
#[derive(Debug)]
pub struct Msg<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

impl<'a> Msg<'a> {
    /// Decode a message from a byte slice. Zero-copy — payload is a
    /// sub-slice of the input.
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        let header = Header::from_bytes(bytes)?;
        let payload_start = Header::SIZE;
        let payload_end = payload_start + header.payload_len as usize;
        if bytes.len() < payload_end {
            return None;
        }
        Some(Self {
            header,
            payload: &bytes[payload_start..payload_end],
        })
    }

    /// Encode a message into a fixed-size buffer. Returns the number
    /// of bytes written, or `None` if the buffer is too small.
    pub fn encode(
        sender: ActorId,
        payload: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        let total = Header::SIZE + payload.len();
        if buf.len() < total {
            return None;
        }
        let header = Header {
            sender,
            payload_len: payload.len() as u32,
        };
        buf[..Header::SIZE].copy_from_slice(&header.to_bytes());
        buf[Header::SIZE..total].copy_from_slice(payload);
        Some(total)
    }
}
