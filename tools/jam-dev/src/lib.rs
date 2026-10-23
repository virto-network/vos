//! JAM as VOS's development and test tooling reaches it; no VOS node
//! links this crate. A JAM deployment is JAM's tooling's: an agent's
//! service blob, or the statements service's, is deployed with PolkaJam's
//! or another team's tools, and a VOS agent reaches an agent on JAM only
//! through an extension.
//!
//! [`live`] drives a PolkaJam node: its JSON-RPC, `jamt`, work packages
//! with extrinsics, and a JAM statements service's client. [`JamVenue`] is
//! that service as a node's venue (`vos_venue::VenueClient`), which the
//! end to end on chain anchors and submits at. The `vos-jam-dev` binary
//! runs the recipes' testnets (`testnet.sh`).

pub mod live;
pub mod venue;

pub use venue::{Jam, JamVenue};
