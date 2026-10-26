//! The s4 app's client key: an ordinary VOS client key, apart from the
//! gateway's own, with which the gateway's s4 app sends the claims of
//! members who have no key of their own. Its authority is the registrar's
//! invitations, which name the digests; it holds no credential bytes. Its
//! calls run in one session per agent, so the app sends one claim at a
//! time to an agent, in order.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use vos_api::Kind;
use vos_api::client::Answer;
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session};
use vos_wire::ingress::{Call, Consistency, QueryCall};

use crate::Gateway;

/// The app's key, and the gateway its requests go through.
pub struct AppClient {
    key: SigningKey,
    gateway: Arc<Gateway>,
}

impl AppClient {
    pub fn new(seed: [u8; 32], gateway: Arc<Gateway>) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            gateway,
        }
    }

    /// The app's public key, the principal its calls carry.
    pub fn key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The call at `sequence` of the app's `session` with the agent whose
    /// id is `agent` and identity `identity`: its answer frame.
    #[allow(clippy::too_many_arguments)]
    pub async fn call(
        &self,
        agent: AgentId,
        identity: &[u8; 32],
        session: Session,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Answer {
        let mut call = Call {
            session,
            sequence,
            instance,
            method,
            arguments,
            signature: [0; 64],
        };
        call.signature = self.key.sign(&call.message(identity)).to_bytes();
        self.gateway
            .relay(Kind::Call, &(agent, call).encode())
            .await
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
            .relay(Kind::Query, &(agent, query).encode())
            .await
    }
}
