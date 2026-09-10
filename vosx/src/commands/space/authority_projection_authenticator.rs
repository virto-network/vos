//! Operator-key authentication for clean system-authority projections.
//!
//! The caller supplies the long-lived operator key explicitly. This adapter
//! neither discovers nor persists it, and every query receives independent OS
//! entropy before the exact canonical query preimage is signed.

use libp2p::identity::{KeyType, Keypair};
use vos::agent::production_owner::{
    AgentProductionOwnerError, AuthorityProjectionQueryAuthenticator,
};
use vos::agent::sdk::authority::{
    AuthorityCredentialKind, AuthorityIngressAuthentication, AuthorityProjectionQuery,
    AuthorityProjectionSelector,
};
use vos::agent::sdk::{CredentialId, Hash};

const NONCE_ATTEMPTS: usize = 8;

/// API-credential projection authenticator backed by one explicit Ed25519
/// operator identity.
pub(crate) struct OperatorAuthorityProjectionAuthenticator {
    operator: Keypair,
    public_key: [u8; 32],
    credential: CredentialId,
}

impl OperatorAuthorityProjectionAuthenticator {
    pub(crate) fn new(operator: Keypair) -> Result<Self, AgentProductionOwnerError> {
        require_ed25519(operator.key_type())?;
        let public_key = operator
            .public()
            .try_into_ed25519()
            .map_err(|_| AgentProductionOwnerError::Authentication)?
            .to_bytes();
        Ok(Self {
            operator,
            public_key,
            credential: CredentialId::of_public_key(&public_key),
        })
    }

    fn fresh_nonce() -> Result<Hash, AgentProductionOwnerError> {
        for _ in 0..NONCE_ATTEMPTS {
            let mut nonce = [0_u8; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|_| AgentProductionOwnerError::Authentication)?;
            if nonce != [0; 32] {
                return Ok(Hash(nonce));
            }
        }
        Err(AgentProductionOwnerError::Authentication)
    }
}

impl AuthorityProjectionQueryAuthenticator for OperatorAuthorityProjectionAuthenticator {
    fn expected_kind(&self) -> AuthorityCredentialKind {
        AuthorityCredentialKind::Api
    }

    fn authenticate(
        &mut self,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        selector: AuthorityProjectionSelector,
    ) -> Result<AuthorityProjectionQuery, AgentProductionOwnerError> {
        if !authority.is_valid() || !selector.validate_shape() {
            return Err(AgentProductionOwnerError::Authentication);
        }
        let mut query = AuthorityProjectionQuery {
            authority,
            credential: self.credential,
            nonce: Self::fresh_nonce()?,
            selector,
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: self.public_key,
                signature: [0; 64],
            },
        };
        let signature: [u8; 64] = self
            .operator
            .sign(&query.signing_bytes())
            .map_err(|_| AgentProductionOwnerError::Authentication)?
            .try_into()
            .map_err(|_| AgentProductionOwnerError::Authentication)?;
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: query_signature,
            ..
        } = &mut query.authentication
        else {
            return Err(AgentProductionOwnerError::Authentication);
        };
        *query_signature = signature;
        query
            .validate_shape()
            .map_err(|_| AgentProductionOwnerError::Authentication)?;
        Ok(query)
    }
}

fn require_ed25519(key_type: KeyType) -> Result<(), AgentProductionOwnerError> {
    match key_type {
        KeyType::Ed25519 => Ok(()),
        KeyType::RSA | KeyType::Secp256k1 | KeyType::Ecdsa => {
            Err(AgentProductionOwnerError::Authentication)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use vos::agent::sdk::authority::{
        AgentAuthorityBinding, AuthorityActorTarget, AuthorityIssuer,
    };
    use vos::agent::sdk::{
        ActorId, AgentId, DeploymentId, NodeId, PrincipalId, ProducerId, ProgramId, SpaceId,
    };

    use super::*;

    const OPERATOR_SEED: [u8; 32] = [0x51; 32];

    fn operator() -> Keypair {
        Keypair::ed25519_from_bytes(OPERATOR_SEED).expect("valid Ed25519 fixture seed")
    }

    fn target() -> AuthorityActorTarget {
        let authority_public_key = SigningKey::from_bytes(&[0x52; 32])
            .verifying_key()
            .to_bytes();
        AuthorityActorTarget {
            space: SpaceId([0x53; 32]),
            system_agent: AgentId([0x54; 32]),
            system_runtime_deployment: DeploymentId([0x55; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x56; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x57; 32]),
                    actor: ActorId([0x58; 32]),
                    deployment: DeploymentId([0x59; 32]),
                    program: ProgramId([0x5a; 32]),
                    producer: ProducerId::of_public_key(&authority_public_key),
                },
                public_key: authority_public_key,
                initial_epoch: 1,
            },
        }
    }

    #[test]
    fn exact_target_and_selector_are_bound_and_invalid_shapes_fail_closed() {
        let target = target();
        let selectors = [
            AuthorityProjectionSelector::Credential,
            AuthorityProjectionSelector::Agents {
                after: Some(AgentId([0x61; 32])),
                limit: 7,
            },
            AuthorityProjectionSelector::AgentReplicas {
                agent: AgentId([0x62; 32]),
                after: Some(NodeId([0x63; 32])),
                limit: 13,
            },
            AuthorityProjectionSelector::Actors {
                agent: AgentId([0x64; 32]),
                after: Some(ActorId([0x65; 32])),
                limit: 5,
            },
        ];
        let mut authenticator = OperatorAuthorityProjectionAuthenticator::new(operator()).unwrap();
        assert_eq!(authenticator.expected_kind(), AuthorityCredentialKind::Api);
        for selector in selectors {
            let query = authenticator.authenticate(target, selector).unwrap();
            assert_eq!(query.authority, target);
            assert_eq!(query.selector, selector);
            assert_eq!(query.validate_shape(), Ok(()));
        }

        let mut invalid_target = target;
        invalid_target.space = SpaceId::ZERO;
        assert_eq!(
            authenticator.authenticate(invalid_target, AuthorityProjectionSelector::Credential),
            Err(AgentProductionOwnerError::Authentication)
        );
        assert_eq!(
            authenticator.authenticate(
                target,
                AuthorityProjectionSelector::Agents {
                    after: None,
                    limit: 0,
                },
            ),
            Err(AgentProductionOwnerError::Authentication)
        );
    }

    #[test]
    fn signs_the_exact_query_preimage_with_the_operator_ed25519_key() {
        let mut authenticator = OperatorAuthorityProjectionAuthenticator::new(operator()).unwrap();
        let query = authenticator
            .authenticate(target(), AuthorityProjectionSelector::Credential)
            .unwrap();
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key,
            signature,
        } = query.authentication
        else {
            panic!("operator authenticator must emit API authentication")
        };
        assert_eq!(
            query.credential,
            CredentialId::of_public_key(&credential_public_key)
        );
        let verifying_key = VerifyingKey::from_bytes(&credential_public_key).unwrap();
        verifying_key
            .verify_strict(&query.signing_bytes(), &Signature::from_bytes(&signature))
            .unwrap();
    }

    #[test]
    fn every_query_uses_a_unique_nonzero_os_nonce() {
        let mut authenticator = OperatorAuthorityProjectionAuthenticator::new(operator()).unwrap();
        let mut nonces = BTreeSet::new();
        for _ in 0..64 {
            let query = authenticator
                .authenticate(target(), AuthorityProjectionSelector::Credential)
                .unwrap();
            assert_ne!(query.nonce, Hash::ZERO);
            assert!(nonces.insert(query.nonce.0));
        }
    }

    #[test]
    fn every_non_ed25519_key_type_is_rejected_as_authentication() {
        for key_type in [KeyType::RSA, KeyType::Secp256k1, KeyType::Ecdsa] {
            assert_eq!(
                require_ed25519(key_type),
                Err(AgentProductionOwnerError::Authentication)
            );
        }
        assert_eq!(require_ed25519(KeyType::Ed25519), Ok(()));
    }
}
