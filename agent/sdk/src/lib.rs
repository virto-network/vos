//! The VOS actor SDK.
//!
//! An actor is a standard PVM program that an agent runs as an inner
//! machine. This crate is its side of the actor ABI ([`vos_wire::abi`]).
//!
//! An actor crate starts with `use vos_sdk::prelude::*;`: the derived
//! encodings name `scale` and `Vec`, which the prelude brings into scope.

#![no_std]

extern crate alloc;

pub mod context;
pub mod heap;
pub mod host;
pub mod mem;
pub mod runtime;
pub mod state;
pub mod table;

pub use alloc::vec::Vec;
pub use vos_sdk_macros::{actor, messages};
pub use vos_wire::{Decode, Encode, scale};

/// What an actor crate needs in scope: the macros, the contexts, tables,
/// and the names the derived encodings use.
pub mod prelude {
    pub use alloc::string::String;
    pub use alloc::vec::Vec;

    pub use crate::context::{CallError, Command, Level, Query, Ref};
    pub use crate::table::Table;
    pub use crate::{Decode, Encode, actor, messages, scale};
    pub use vos_wire::ids::{AgentId, InstanceId, Principal};
}
