//! Explicit identity adapters for clean space genesis.
//!
//! These adapters do not discover, load, generate, clone, or serialize private
//! key material. The caller owns both identities: an operator/root Ed25519
//! keypair used for clean management receipts and an authenticated libp2p
//! [`PeerId`] used for the transport node. Keeping those inputs explicit also
//! prevents a compact legacy node prefix from becoming an authorization
//! identity during the clean cutover.

use core::fmt;

use libp2p::PeerId;
use libp2p::identity::{KeyType, Keypair};
use vos::agent::clean_authority_issuer::CleanManagementReceiptSigner;
use vos::agent::sdk::{CredentialId, NodeId, PrincipalId};

/// Stable failure surface for the explicit clean operator signer.
///
/// Underlying libp2p errors are deliberately not exposed: callers may log this
/// value without formatting implementation-specific cryptographic state, and
/// a library upgrade cannot silently change the persisted/control-plane error
/// contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanIdentitySignerError {
    NonEd25519Key,
    PublicKeyUnavailable,
    SigningFailed,
    InvalidSignatureLength,
}

impl fmt::Display for CleanIdentitySignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NonEd25519Key => "clean operator identity is not Ed25519",
            Self::PublicKeyUnavailable => "clean operator Ed25519 public key is unavailable",
            Self::SigningFailed => "clean operator Ed25519 signing failed",
            Self::InvalidSignatureLength => {
                "clean operator Ed25519 signer returned a non-64-byte signature"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CleanIdentitySignerError {}

/// Borrowed clean operator identity and management-receipt signer.
///
/// The founding Principal and initial Credential intentionally use the same
/// authenticator at genesis while remaining distinct, domain-separated SDK
/// identities. The credential can consequently be revoked or replaced without
/// changing the long-lived Principal identity. Only the public key and derived
/// identifiers are copied into this adapter; private bytes remain inside the
/// caller-owned libp2p keypair and are never exposed for persistence.
pub(crate) struct CleanOperatorIdentitySigner<'key> {
    keypair: &'key Keypair,
    public_key: [u8; 32],
    principal: PrincipalId,
    credential: CredentialId,
}

impl<'key> CleanOperatorIdentitySigner<'key> {
    pub(crate) fn new(keypair: &'key Keypair) -> Result<Self, CleanIdentitySignerError> {
        require_ed25519_key_type(keypair.key_type())?;
        let public_key = keypair
            .public()
            .try_into_ed25519()
            .map_err(|_| CleanIdentitySignerError::PublicKeyUnavailable)?
            .to_bytes();
        Ok(Self {
            keypair,
            public_key,
            principal: PrincipalId::of_public_key(&public_key),
            credential: CredentialId::of_public_key(&public_key),
        })
    }

    pub(crate) const fn raw_public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub(crate) const fn principal(&self) -> PrincipalId {
        self.principal
    }

    pub(crate) const fn credential(&self) -> CredentialId {
        self.credential
    }
}

impl CleanManagementReceiptSigner for CleanOperatorIdentitySigner<'_> {
    type Error = CleanIdentitySignerError;

    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
        self.keypair
            .sign(message)
            .map_err(|_| CleanIdentitySignerError::SigningFailed)?
            .try_into()
            .map_err(|_| CleanIdentitySignerError::InvalidSignatureLength)
    }
}

/// Derive the clean Node identity from every byte of an already-authenticated
/// libp2p PeerId. Compact routing hints are deliberately not accepted here.
pub(crate) fn node_id_from_authenticated_peer(peer_id: &PeerId) -> NodeId {
    NodeId::of_authenticated_peer(&peer_id.to_bytes())
}

fn require_ed25519_key_type(key_type: KeyType) -> Result<(), CleanIdentitySignerError> {
    match key_type {
        KeyType::Ed25519 => Ok(()),
        KeyType::RSA | KeyType::Secp256k1 | KeyType::Ecdsa => {
            Err(CleanIdentitySignerError::NonEd25519Key)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::{Signature, VerifyingKey};
    use vos::agent::sdk::authority::{
        AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
        AuthorityReceipt, AuthorityReceiptSelector, AuthorityVerifier,
    };
    use vos::agent::sdk::{ActorId, AgentId, DeploymentId, Hash, ProducerId, ProgramId, SpaceId};

    use super::*;

    const OPERATOR_SEED: [u8; 32] = [0x5c; 32];

    fn operator_keypair() -> Keypair {
        Keypair::ed25519_from_bytes(OPERATOR_SEED).expect("valid Ed25519 fixture seed")
    }

    #[test]
    fn one_authenticator_derives_distinct_principal_and_credential_roles() {
        let keypair = operator_keypair();
        let identity = CleanOperatorIdentitySigner::new(&keypair).expect("clean operator");
        let expected_public_key = keypair
            .public()
            .try_into_ed25519()
            .expect("fixture is Ed25519")
            .to_bytes();

        assert_eq!(identity.raw_public_key(), expected_public_key);
        assert_eq!(
            identity.principal(),
            PrincipalId::of_public_key(&expected_public_key)
        );
        assert_eq!(
            identity.credential(),
            CredentialId::of_public_key(&expected_public_key)
        );
        assert_ne!(
            identity.principal().as_bytes(),
            identity.credential().as_bytes()
        );
    }

    #[test]
    fn node_identity_uses_the_full_peer_even_when_compact_hints_collide() {
        let mut peers_by_prefix = BTreeMap::new();
        let (first, second, prefix) = (1u64..=4_096)
            .find_map(|counter| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&counter.to_le_bytes());
                seed[8..16].copy_from_slice(&counter.rotate_left(17).to_le_bytes());
                seed[16..24].copy_from_slice(&counter.rotate_left(31).to_le_bytes());
                seed[24..].copy_from_slice(&counter.rotate_left(47).to_le_bytes());
                let keypair = Keypair::ed25519_from_bytes(seed).expect("valid fixture seed");
                let peer = keypair.public().to_peer_id();
                let prefix = vos::network::derive_node_prefix(&peer);
                peers_by_prefix
                    .insert(prefix, peer)
                    .map(|previous| (previous, peer, prefix))
            })
            .expect("deterministic fixture range contains a compact-prefix collision");

        assert_ne!(first, second);
        assert_eq!(vos::network::derive_node_prefix(&first), prefix);
        assert_eq!(vos::network::derive_node_prefix(&second), prefix);
        assert_ne!(
            node_id_from_authenticated_peer(&first),
            node_id_from_authenticated_peer(&second)
        );
    }

    struct StrictRawVerifier;

    impl AuthorityVerifier for StrictRawVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            VerifyingKey::from_bytes(public_key)
                .map(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
                .is_ok_and(|result| result.is_ok())
        }
    }

    #[test]
    fn signing_is_deterministic_and_verifies_as_a_valid_authority_receipt() {
        let keypair = operator_keypair();
        let mut signer = CleanOperatorIdentitySigner::new(&keypair).expect("clean operator");
        let public_key = signer.raw_public_key();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash([0x11; 32]),
                issuer: AuthorityIssuer {
                    principal: signer.principal(),
                    actor: ActorId([0x12; 32]),
                    deployment: DeploymentId([0x13; 32]),
                    program: ProgramId([0x14; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                space: SpaceId([0x15; 32]),
                agent: AgentId([0x16; 32]),
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: DeploymentId([0x17; 32]),
                actor: Some(ActorId([0x18; 32])),
                actor_deployment: Some(DeploymentId([0x19; 32])),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x1a; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 7,
                expires_at: 9,
                request: Hash([0x1b; 32]),
            },
            public_key,
            signature: [0; 64],
        };
        let message = receipt.signing_bytes();
        let first = signer
            .sign_authority_receipt(&message)
            .expect("sign exact receipt");
        let repeated = signer
            .sign_authority_receipt(&message)
            .expect("repeat exact receipt signing");
        assert_eq!(first, repeated);
        receipt.signature = first;
        assert_eq!(receipt.verify_at(8, &StrictRawVerifier), Ok(()));

        let mut tampered = receipt;
        tampered.selector.request.0[0] ^= 1;
        assert!(tampered.verify_at(8, &StrictRawVerifier).is_err());
    }

    #[test]
    fn every_non_ed25519_key_type_is_rejected_by_the_constructor_gate() {
        for key_type in [KeyType::RSA, KeyType::Secp256k1, KeyType::Ecdsa] {
            assert_eq!(
                require_ed25519_key_type(key_type),
                Err(CleanIdentitySignerError::NonEd25519Key)
            );
        }
        assert_eq!(require_ed25519_key_type(KeyType::Ed25519), Ok(()));
    }
}
