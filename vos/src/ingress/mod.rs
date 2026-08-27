//! Built-in, protocol-specific ingress adapters.
//!
//! Ingress is intentionally separate from actor extensions. An adapter owns
//! sockets, framing, TLS, authentication, limits, and shutdown. It hands the
//! runtime only a canonical actor invocation plus an authenticated
//! [`SubjectId`](crate::service::SubjectId). HTTP lives here; a future SSH
//! adapter can reuse the same [`IngressHandle`](crate::node::IngressHandle)
//! without becoming part of the actor DSL.

mod json;
mod limits;
mod routing;
mod server;
mod state;
mod types;

use std::time::Duration;

use crate::actors::context::ServiceId;
use crate::node::IngressHandle;

pub(crate) use server::start;
pub use server::{HttpIngressConfig, HttpIngressError, HttpTlsConfig};

/// Parse the canonical HTTP bearer into its 32 secret bytes. The token is a
/// presentation credential only; callers must still resolve its hashed ID
/// against the live authority before treating it as authenticated.
pub fn decode_access_token(token: &str) -> Option<[u8; 32]> {
    let hex = token.strip_prefix("vos-access-")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[index] = (hi << 4) | lo;
    }
    Some(out)
}

pub fn encode_access_token(secret: &[u8; 32]) -> String {
    let mut out = String::with_capacity(75);
    out.push_str("vos-access-");
    for byte in secret {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Clone)]
pub(crate) struct HttpIngressContext {
    handle: IngressHandle,
    access: Option<crate::IngressAccessStatus>,
}

impl HttpIngressContext {
    pub(crate) fn new(handle: IngressHandle, access: Option<crate::IngressAccessStatus>) -> Self {
        Self { handle, access }
    }

    pub(crate) fn is_authenticated(&self) -> bool {
        self.access.is_some()
    }

    pub(crate) fn has_capability(&self, name: &str) -> bool {
        self.access
            .as_ref()
            .is_some_and(|access| access.has_capability(crate::CapabilityId::named(name)))
    }

    pub(crate) fn ask_registry(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        self.handle.invoke_host_service(
            ServiceId::REGISTRY,
            payload.to_vec(),
            Duration::from_secs(10),
        )
    }

    pub(crate) fn invoke_actor(
        &mut self,
        target: crate::service::ActorId,
        payload: &[u8],
        proof_requested: bool,
        idempotency_key: Option<&str>,
    ) -> Result<Vec<u8>, crate::ClientError> {
        let subject = crate::service::SubjectId(
            self.access
                .as_ref()
                .ok_or(crate::ClientError::Forbidden)?
                .subject,
        );
        match idempotency_key {
            Some(key) => self.handle.invoke_actor_idempotent(
                subject,
                target,
                payload.to_vec(),
                proof_requested,
                key,
            ),
            None => self
                .handle
                .invoke_actor(subject, target, payload.to_vec(), proof_requested),
        }
    }

    pub(crate) fn resolve_actor(&self, name: &str) -> Option<crate::service::ActorId> {
        self.handle.resolve_actor(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_round_trips() {
        let secret = [0xab; 32];
        assert_eq!(
            decode_access_token(&encode_access_token(&secret)),
            Some(secret)
        );
    }

    #[test]
    fn malformed_access_token_is_rejected() {
        assert_eq!(decode_access_token("abc"), None);
        assert_eq!(decode_access_token("vos-access-00"), None);
    }
}
