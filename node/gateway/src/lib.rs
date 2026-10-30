//! The gateway (`docs/design/node-api.md` §6): today's HTTP routes, byte
//! for byte, onto the node API of the nodes behind it, with public TLS,
//! limits per address and leader-aware routing; with the `ssh` feature,
//! s4's SSH port and its `vos-api` subsystem. It holds no authority: every
//! signature, proof and check is a node's.

pub mod app;
pub mod config;
#[cfg(feature = "ssh")]
pub mod demo;
pub mod front;
pub mod limits;
pub mod routing;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod upstream;

pub use routing::Gateway;
