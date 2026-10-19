//! Wire types shared by the VOS node, the default agent program and the
//! actor SDK.
//!
//! Everything here is SCALE-coded with the workspace codec, the encoding JAM
//! uses, except the Gray Paper structures in [`jam`], which follow the Gray
//! Paper's own encoding.

#![no_std]

extern crate alloc;

pub mod abi;
pub mod apply;
pub mod batch;
pub mod ids;
pub mod ingress;
pub mod jam;
pub mod keys;
pub mod package;
pub mod peer;
pub mod records;
pub mod result;
pub mod schema;

/// When a session's row in the due index is due: sessions are filed by the
/// bucket of their last activity, so one sweep collects many.
pub mod expiry;

pub use scale;
pub use scale::{Decode, DecodeError, Encode};
pub use vos_anchor::{self, SpaceGenesis, SpaceId, WindowClock};

/// The node's and the agent's defaults. Each is a constant, cheap to change.
pub mod defaults;
