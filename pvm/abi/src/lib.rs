//! The actor ABI: what an actor's program and the agent that runs it agree
//! on, and what the compiler and the prover read of an install. The host
//! calls and their bounds ([`abi`]), the identifiers ([`ids`]), the key
//! layout of an agent's rows ([`keys`]), a program's schema ([`schema`]),
//! the records of an install and of a workflow ([`records`]), a step's
//! result ([`result`]), the messages between agents ([`message`]), the rows
//! a read at a cut is served ([`served`]), the storage-backed types'
//! merges ([`merge`]), the credential tree a device kernel proves over
//! ([`credentials`]), and the arguments a JAM node invokes a program with
//! ([`jam`]).
//!
//! Everything here is SCALE-coded with the workspace codec, the encoding JAM
//! uses, except the Gray Paper structures in [`jam`], which follow the Gray
//! Paper's own encoding.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod abi;
pub mod credentials;
pub mod ids;
pub mod jam;
pub mod keys;
pub mod merge;
pub mod message;
pub mod records;
pub mod result;
pub mod schema;
pub mod served;

pub use scale;
pub use scale::{Decode, DecodeError, Encode};
pub use vos_anchor::{self, SpaceGenesis, SpaceId, WindowClock};

/// The defaults the ABI's bounds are set by: a handler's gas, the serving
/// prices, a read at a cut's rows and windows, an await's deadline and a
/// sweep's bindings. Each is a constant, cheap to change.
pub mod defaults;
