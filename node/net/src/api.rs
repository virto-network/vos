//! QUIC for the node API: TLS 1.3 with raw ed25519 keys both ways, as
//! between peers, under a protocol of its own (`vos-api/1`) and an
//! allowlist of its own, on an executor of its own. The peers' endpoint
//! and the API's never share a port, a protocol or a thread.

use std::sync::Arc;

use crate::NodeKey;
pub use crate::quic::executor::{Runner, Runtime, Spawner};
use crate::tls::{Expect, Identity};

/// The node API's protocol.
pub const ALPN: &[u8] = b"vos-api/1";

/// The accepting side, the node whose secret seed is `secret`: a client
/// whose key `allowed` takes. No session resumes: every handshake checks
/// the key.
pub fn server_config(
    secret: &[u8; 32],
    allowed: impl Fn(&NodeKey) -> bool + Send + Sync + 'static,
    transport: Arc<quinn::TransportConfig>,
) -> quinn::ServerConfig {
    Identity::new(secret).server_with(Expect::Listed(Arc::new(allowed)), ALPN, transport)
}

/// The dialing side, the client whose secret seed is `secret`, pinned to
/// the node whose key is `node`.
pub fn client_config(
    secret: &[u8; 32],
    node: NodeKey,
    transport: Arc<quinn::TransportConfig>,
) -> quinn::ClientConfig {
    Identity::new(secret).client_with(ALPN, node, transport)
}

/// The dialing side of another protocol: for a test that a node refuses
/// it.
pub fn client_config_for(
    secret: &[u8; 32],
    alpn: &[u8],
    node: NodeKey,
    transport: Arc<quinn::TransportConfig>,
) -> quinn::ClientConfig {
    Identity::new(secret).client_with(alpn, node, transport)
}

/// The endpoint's configuration for the node whose secret seed is
/// `secret`: its stateless resets keyed by it, as the peers' are.
pub fn endpoint_config(secret: &[u8; 32]) -> quinn::EndpointConfig {
    Identity::new(secret).endpoint()
}
