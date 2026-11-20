//! The demo app's client key: an ordinary VOS client key, apart from the
//! gateway's own, with which the app reads the space for its screens. It
//! holds no credential bytes and makes no call: a member's claim is the
//! operator's invitation's (`LocalSpace::invite`).

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use vos_abi::Encode;
use vos_abi::ids::{AgentId, InstanceId, MethodId};
use vos_api::client::Answer;
use vos_api::{Kind, Mark};
use vos_wire::ingress::{Consistency, QueryCall};

use vos_gateway::Gateway;

/// The app's key, the gateway its requests go through, and the mark they
/// go with: the transport of the port its screens are served on.
pub struct AppClient {
    key: SigningKey,
    gateway: Arc<Gateway>,
    mark: Mark,
}

impl AppClient {
    pub fn new(seed: [u8; 32], gateway: Arc<Gateway>, mark: Mark) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            gateway,
            mark,
        }
    }

    /// The app's public key, the principal its queries carry.
    pub fn key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// A query by the app's key, good until `not_after` by the node's
    /// clock: its answer frame.
    pub async fn query(
        &self,
        agent: AgentId,
        identity: &[u8; 32],
        not_after: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Answer {
        let mut query = QueryCall {
            key: self.key(),
            not_after,
            consistency: Consistency::Applied { at: 0 },
            instance,
            method,
            arguments,
            signature: [0; 64],
        };
        query.signature = self.key.sign(&query.message(identity)).to_bytes();
        self.gateway
            .relay(Kind::Query, self.mark, &(agent, query).encode())
            .await
    }
}
