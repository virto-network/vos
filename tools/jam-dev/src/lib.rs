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

use vos_pvm_compiler::{ServiceMetadata, service_blob};

/// `code` as a JAM service's code blob, `metadata` first: refused past the
/// Gray Paper's bound on it (`W_C`, `vos_pvm::spi::MAX_SERVICE_CODE`),
/// which counts the looked-up blob whole, its metadata among it, and past
/// which JAM refines and accumulates the service as `BIG`.
pub fn service_code(code: &[u8], metadata: &ServiceMetadata) -> Result<Vec<u8>, String> {
    let blob = service_blob(code, metadata);
    if !vos_pvm::spi::service_fits(&blob) {
        return Err(format!(
            "the service's code is {} bytes, past W_C ({}): JAM refines and accumulates it as BIG",
            blob.len(),
            vos_pvm::spi::MAX_SERVICE_CODE
        ));
    }
    Ok(blob)
}
