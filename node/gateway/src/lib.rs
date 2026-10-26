//! The gateway (`docs/design/node-api.md` §6): today's HTTP routes, byte
//! for byte, onto the node API of the nodes behind it, with public TLS,
//! limits per address and leader-aware routing. It holds no authority:
//! every signature, proof and check is a node's.

pub mod config;
pub mod front;
pub mod limits;
pub mod routing;
pub mod upstream;

pub use routing::Gateway;
