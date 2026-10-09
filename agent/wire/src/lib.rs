//! Wire types shared by the VOS node, the default agent program and the
//! actor SDK.
//!
//! Everything here is SCALE-coded with the workspace codec, the encoding JAM
//! uses, except the Gray Paper structures in [`jam`], which follow the Gray
//! Paper's own encoding.

#![no_std]

extern crate alloc;

pub mod abi;
pub mod batch;
pub mod ids;
pub mod jam;
pub mod keys;
pub mod result;

pub use scale::{Decode, DecodeError, Encode};

/// Defaults the owner set for slice 2. Each is a constant, cheap to change.
pub mod defaults {
    /// Replies kept per (session, agent), so a pipelining client can recover
    /// any lost reply.
    pub const REPLY_WINDOW: u64 = 64;
    /// A session expires after this much work-result time without a
    /// request, in milliseconds.
    pub const SESSION_EXPIRY_MS: u64 = 60 * 60 * 1000;
    /// A handler's gas limit when its schema declares none: about 20,000
    /// ABI operations at their placeholder price, or about 16,000 BLAKE2b
    /// compressions.
    pub const HANDLER_GAS: u64 = 10_000_000;
    /// A refine's gas budget: a hundred handlers at their default limit.
    pub const REFINE_GAS: u64 = 1_000_000_000;
}
