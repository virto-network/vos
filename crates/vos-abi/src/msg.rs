//! Transfer memo — metadata passed with each inter-service transfer.
//!
//! 128 bytes, fixed layout. Carried alongside the transfer hostcall.
//! The full payload is stored as a preimage keyed by `hash`.

use crate::service::ServiceId;

/// Metadata for an inter-service transfer.
///
/// The actual message payload is stored separately as a preimage.
/// The receiver uses `fetch(hash)` to retrieve the full payload.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransferMemo {
    /// Blake2b hash of the full payload (preimage key).
    pub hash: [u8; 32],
    /// The sending service.
    pub sender: ServiceId,
    /// Length of the full payload in bytes.
    pub payload_len: u32,
    /// Reserved for future use.
    pub _reserved: [u8; 88],
}

impl TransferMemo {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new memo with the given hash, sender, and payload length.
    pub fn new(hash: [u8; 32], sender: ServiceId, payload_len: u32) -> Self {
        Self {
            hash,
            sender,
            payload_len,
            _reserved: [0u8; 88],
        }
    }
}
