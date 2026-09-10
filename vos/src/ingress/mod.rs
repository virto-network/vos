//! Built-in, protocol-specific ingress adapters.
//!
//! Ingress is intentionally separate from actor extensions. An adapter owns
//! sockets, framing, TLS, authentication, limits, and shutdown. It hands the
//! runtime only a canonical actor invocation plus an authenticated
//! [`SubjectId`](crate::service::SubjectId). HTTP and SSH reuse the same
//! [`IngressHandle`](crate::node::IngressHandle), but retain independent
//! framing, limits, and lifecycle without becoming part of the actor DSL.

mod json;
mod limits;
mod routing;
mod server;
mod state;
mod types;

use std::time::Duration;

use crate::actors::context::ServiceId;
use crate::node::IngressHandle;
use ed25519_dalek::{Signer as _, SigningKey};

pub(crate) use server::start;
pub use server::{HttpIngressConfig, HttpIngressError, HttpTlsConfig};

const ACCESS_TOKEN_PREFIX: &str = "vos-access-v1-";

/// Secret-bearing API ingress credential reconstructed from a canonical
/// bearer token.
///
/// The 32 token bytes are an Ed25519 seed, not an opaque value to hash. The
/// durable [`CredentialId`](crate::agent::sdk::CredentialId) is derived from
/// the public key so the authority can verify request signatures without
/// retaining bearer material. Debug output never exposes the seed.
pub struct ApiAccessCredential(SigningKey);

impl std::fmt::Debug for ApiAccessCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiAccessCredential")
            .field("credential_id", &self.credential_id())
            .finish_non_exhaustive()
    }
}

impl ApiAccessCredential {
    pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
        let signing = SigningKey::from_bytes(&seed);
        (!signing.verifying_key().is_weak()).then_some(Self(signing))
    }

    pub fn generate() -> Result<Self, getrandom::Error> {
        loop {
            let mut seed = [0_u8; 32];
            getrandom::getrandom(&mut seed)?;
            if let Some(credential) = Self::from_seed(seed) {
                return Ok(credential);
            }
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn credential_id(&self) -> crate::agent::sdk::CredentialId {
        crate::agent::sdk::CredentialId::of_public_key(&self.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }

    /// Build and sign one exact clean system-authority projection query.
    ///
    /// The bearer seed never enters actor arguments. Only its public key and
    /// a signature over the complete authority target, nonce, selector, and
    /// authentication kind cross the ingress boundary.
    pub fn sign_projection_query(
        &self,
        authority: crate::agent::sdk::authority::AuthorityActorTarget,
        nonce: crate::agent::sdk::Hash,
        selector: crate::agent::sdk::authority::AuthorityProjectionSelector,
    ) -> Result<
        crate::agent::sdk::authority::AuthorityProjectionQuery,
        crate::agent::sdk::authority::AuthorityActorProtocolError,
    > {
        use crate::agent::sdk::authority::{
            AuthorityIngressAuthentication, AuthorityProjectionQuery,
        };

        let mut query = AuthorityProjectionQuery {
            authority,
            credential: self.credential_id(),
            nonce,
            selector,
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: self.public_key(),
                signature: [0; 64],
            },
        };
        let signature = self.sign(&query.signing_bytes());
        query.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: self.public_key(),
            signature,
        };
        query.validate_shape()?;
        Ok(query)
    }

    pub fn encode_token(&self) -> String {
        let mut out = String::with_capacity(ACCESS_TOKEN_PREFIX.len() + 64);
        out.push_str(ACCESS_TOKEN_PREFIX);
        for byte in self.0.to_bytes() {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// Parse only the current canonical, lower-case API bearer generation.
/// Legacy opaque tokens and non-canonical hex fail closed.
pub fn decode_access_token(token: &str) -> Option<ApiAccessCredential> {
    let hex = token.strip_prefix(ACCESS_TOKEN_PREFIX)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = lower_hex_nibble(pair[0])?;
        let lo = lower_hex_nibble(pair[1])?;
        out[index] = (hi << 4) | lo;
    }
    ApiAccessCredential::from_seed(out)
}

pub fn encode_access_token(seed: &[u8; 32]) -> Option<String> {
    ApiAccessCredential::from_seed(*seed).map(|credential| credential.encode_token())
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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
                "http",
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

    fn authority_target() -> crate::agent::sdk::authority::AuthorityActorTarget {
        use crate::agent::sdk::authority::{
            AgentAuthorityBinding, AuthorityActorTarget, AuthorityIssuer,
        };
        use crate::agent::sdk::{
            ActorId, AgentId, DeploymentId, Hash, PrincipalId, ProducerId, ProgramId, SpaceId,
        };

        let authority_key = SigningKey::from_bytes(&[0x31; 32]);
        let public_key = authority_key.verifying_key().to_bytes();
        AuthorityActorTarget {
            space: SpaceId([0x11; 32]),
            system_agent: AgentId([0x12; 32]),
            system_runtime_deployment: DeploymentId([0x13; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x14; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x15; 32]),
                    actor: ActorId([0x16; 32]),
                    deployment: DeploymentId([0x17; 32]),
                    program: ProgramId([0x18; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
        }
    }

    #[test]
    fn access_token_round_trips() {
        let secret = [0xab; 32];
        let encoded = encode_access_token(&secret).unwrap();
        assert!(encoded.starts_with(ACCESS_TOKEN_PREFIX));
        let decoded = decode_access_token(&encoded).unwrap();
        assert_eq!(
            decoded.public_key(),
            SigningKey::from_bytes(&secret).verifying_key().to_bytes()
        );
        assert_eq!(
            decoded.credential_id(),
            crate::agent::sdk::CredentialId::of_public_key(&decoded.public_key())
        );
        assert_ne!(
            decoded.credential_id().0,
            crate::ingress_credential_id(&secret),
            "the clean credential identity must not retain the opaque-secret hash"
        );
    }

    #[test]
    fn malformed_legacy_and_noncanonical_access_tokens_are_rejected() {
        assert!(decode_access_token("abc").is_none());
        assert!(decode_access_token("vos-access-00").is_none());
        assert!(decode_access_token(&format!("{ACCESS_TOKEN_PREFIX}00")).is_none());
        assert!(
            decode_access_token(&format!("{ACCESS_TOKEN_PREFIX}{}", "AB".repeat(32))).is_none()
        );
        assert!(decode_access_token(&format!("vos-access-{}", "ab".repeat(32))).is_none());
    }

    #[test]
    fn access_credential_signatures_match_the_public_identity() {
        let credential = ApiAccessCredential::from_seed([0x5a; 32]).unwrap();
        let message = b"canonical authority projection query";
        let signature = ed25519_dalek::Signature::from_bytes(&credential.sign(message));
        credential
            .0
            .verifying_key()
            .verify_strict(message, &signature)
            .unwrap();
    }

    #[test]
    fn access_credential_signs_the_exact_clean_projection_query() {
        use crate::agent::sdk::authority::{
            AuthorityIngressAuthentication, AuthorityProjectionSelector,
        };
        use crate::agent::sdk::{AgentId, Hash};

        let credential = ApiAccessCredential::from_seed([0x5b; 32]).unwrap();
        let query = credential
            .sign_projection_query(
                authority_target(),
                Hash([0x41; 32]),
                AuthorityProjectionSelector::Agents {
                    after: None,
                    limit: 4,
                },
            )
            .unwrap();
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key,
            signature,
        } = query.authentication
        else {
            panic!("API credential must use direct credential authentication");
        };
        assert_eq!(credential_public_key, credential.public_key());
        credential
            .0
            .verifying_key()
            .verify_strict(
                &query.signing_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .unwrap();

        let mut substituted = query;
        substituted.selector = AuthorityProjectionSelector::Agents {
            after: Some(AgentId([0x42; 32])),
            limit: 4,
        };
        assert!(
            credential
                .0
                .verifying_key()
                .verify_strict(
                    &substituted.signing_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .is_err(),
            "one signed projection selector must not authorize another page"
        );
    }
}
