//! The gateway (`docs/design/node-api.md` §6): VOS's HTTP routes onto the
//! node API of the nodes behind it, with public TLS,
//! limits per address and leader-aware routing; with the `ssh` feature,
//! s4's SSH port and its `vos-api` subsystem; with the `tor` feature, an
//! onion service in process serving the same SSH and HTTP and nothing
//! else (`light-node.md` §6.1). It holds no authority: every signature,
//! proof and check is a node's.

pub mod app;
pub mod caps;
pub mod circuits;
pub mod config;
#[cfg(feature = "ssh")]
pub mod demo;
pub mod front;
pub mod limits;
#[cfg(feature = "tor")]
pub mod onion;
pub mod routing;
#[cfg(feature = "tor")]
pub mod served;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod upstream;

pub use routing::Gateway;
