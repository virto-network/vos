//! Operation-bound authorization for agent lifecycle changes.
//!
//! Package signatures authenticate software producers. Authority receipts
//! independently authenticate who may mutate one agent. A receipt is scoped
//! to one exact lifecycle request and therefore cannot be replayed for a
//! different actor, package, profile, or runtime. Receipt sequences share one
//! monotone namespace across the complete authority binding; rotating the
//! caller credential does not reset replay protection.

use alloc::vec::Vec;

use super::execution::{ActorInvocation, ActorInvocationAuth};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, CapabilityId, CredentialId, DeploymentId, Hash, PrincipalId, ProducerId,
    ProgramId, SpaceId,
};

pub const CAPABILITY_AGENT_CREATE_PRIVATE: &str = "agent.create.private";
pub const CAPABILITY_AGENT_CREATE_LOCAL: &str = "agent.create.local";
pub const CAPABILITY_AGENT_CREATE_SHARED: &str = "agent.create.shared";
pub const CAPABILITY_ACTOR_INSTALL: &str = "actor.install";
pub const CAPABILITY_ACTOR_UPGRADE: &str = "actor.upgrade";
pub const CAPABILITY_ACTOR_LIFECYCLE: &str = "actor.lifecycle";
pub const CAPABILITY_AGENT_RUNTIME_UPGRADE: &str = "agent.runtime.upgrade";
pub const ED25519_PUBLIC_KEY_WIRE_BYTES: usize = 36;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// Canonical libp2p protobuf wrapper for one raw Ed25519 public key.
pub fn ed25519_public_key_wire(raw: [u8; 32]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(ED25519_PUBLIC_KEY_WIRE_BYTES);
    wire.extend_from_slice(&[0x08, 0x01, 0x12, 0x20]);
    wire.extend_from_slice(&raw);
    wire
}

fn decode_ed25519_public_key(wire: &[u8]) -> Option<[u8; 32]> {
    wire.strip_prefix(&[0x08, 0x01, 0x12, 0x20])?
        .try_into()
        .ok()
}

#[cfg(any(feature = "std", feature = "agent-runtime"))]
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Some(raw) = decode_ed25519_public_key(public_key) else {
        return false;
    };
    let Ok(public_key) = ed25519_dalek::VerifyingKey::from_bytes(&raw) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    public_key.verify_strict(message, &signature).is_ok()
}

// Receipt wire types remain available to ordinary no-std actors, but only a
// host or the standard agent runtime carries the cryptographic implementation.
// Any accidental verification attempt in another feature set must fail
// closed rather than accepting host-authenticated input as authoritative.
#[cfg(not(any(feature = "std", feature = "agent-runtime")))]
fn verify_ed25519(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
    false
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorityBinding {
    pub agent: AgentId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub producer: ProducerId,
    pub public_key: Vec<u8>,
}

impl AgentAuthorityBinding {
    pub fn validate(&self) -> bool {
        self.agent != AgentId::ZERO
            && self.actor != ActorId::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.producer != ProducerId::ZERO
            && decode_ed25519_public_key(&self.public_key).is_some()
            && ProducerId::of_public_key(&self.public_key) == self.producer
    }

    /// Stable identity of the complete authority deployment selected by an
    /// agent. Lifecycle replay state is keyed by this commitment rather than
    /// by a short actor or producer identifier.
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encode_binding(&mut encoder, self);
        Hash::digest(b"vos/agent/authority-binding", &[&bytes])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorityClaim {
    pub authority: AgentAuthorityBinding,
    pub space: SpaceId,
    pub agent: AgentId,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub capability: CapabilityId,
    pub operation: Hash,
    /// Strictly monotone sequence allocated across this complete authority
    /// binding. It is not a per-credential nonce: changing credentials never
    /// resets the sequence, so the agent can keep one bounded replay journal
    /// without retaining every credential ever used.
    pub sequence: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl AgentAuthorityClaim {
    pub fn signing_message(&self) -> Hash {
        Hash::digest(b"vos/agent/authority-receipt", &[&self.encode()])
    }
}

impl ServiceWire for AgentAuthorityClaim {
    const MAGIC: [u8; 4] = *b"AGAC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_binding(&mut encoder, &self.authority);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.agent.0);
        encoder.fixed(&self.principal.0);
        encoder.fixed(&self.credential.0);
        encoder.fixed(&self.capability.0);
        encoder.fixed(&self.operation.0);
        encoder.u64(self.sequence);
        encoder.u64(self.valid_from);
        encoder.u64(self.valid_until);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let claim = Self {
            authority: decode_binding(decoder)?,
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            principal: PrincipalId(decoder.fixed()?),
            credential: CredentialId(decoder.fixed()?),
            capability: CapabilityId(decoder.fixed()?),
            operation: Hash(decoder.fixed()?),
            sequence: decoder.u64()?,
            valid_from: decoder.u64()?,
            valid_until: decoder.u64()?,
        };
        if !claim.authority.validate()
            || claim.space == SpaceId::ZERO
            || claim.agent == AgentId::ZERO
            || claim.principal == PrincipalId::ZERO
            || claim.credential == CredentialId::ZERO
            || claim.capability == CapabilityId::ZERO
            || claim.operation == Hash::ZERO
            || claim.sequence == 0
            || claim.valid_until < claim.valid_from
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(claim)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorityReceipt {
    pub claim: AgentAuthorityClaim,
    pub signature: Vec<u8>,
}

/// Authority-signed caller context for one exact actor invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocationClaim {
    pub authority: AgentAuthorityBinding,
    pub space: SpaceId,
    pub agent: AgentId,
    pub principal: Option<PrincipalId>,
    pub credential: Option<CredentialId>,
    pub authorization: Hash,
    pub auth: ActorInvocationAuth,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl ActorInvocationClaim {
    pub fn signing_message(&self) -> Hash {
        Hash::digest(b"vos/agent/invocation-receipt", &[&self.encode()])
    }
}

impl ServiceWire for ActorInvocationClaim {
    const MAGIC: [u8; 4] = *b"AGIC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_binding(&mut encoder, &self.authority);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.agent.0);
        encoder.option(&self.principal, |encoder, principal| {
            encoder.fixed(&principal.0)
        });
        encoder.option(&self.credential, |encoder, credential| {
            encoder.fixed(&credential.0)
        });
        encoder.fixed(&self.authorization.0);
        encode_invocation_auth(&mut encoder, &self.auth);
        encoder.u64(self.valid_from);
        encoder.u64(self.valid_until);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let claim = Self {
            authority: decode_binding(decoder)?,
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            principal: decoder.option(|decoder| Ok(PrincipalId(decoder.fixed()?)))?,
            credential: decoder.option(|decoder| Ok(CredentialId(decoder.fixed()?)))?,
            authorization: Hash(decoder.fixed()?),
            auth: decode_invocation_auth(decoder)?,
            valid_from: decoder.u64()?,
            valid_until: decoder.u64()?,
        };
        let authenticated = matches!(
            claim.auth.origin,
            crate::service::Origin::Member(_) | crate::service::Origin::Actor(_)
        );
        if claim.space == SpaceId::ZERO
            || claim.agent == AgentId::ZERO
            || claim.principal == Some(PrincipalId::ZERO)
            || claim.credential == Some(CredentialId::ZERO)
            || authenticated != claim.principal.is_some()
            || authenticated != claim.credential.is_some()
            || claim.authorization == Hash::ZERO
            || claim.valid_until < claim.valid_from
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(claim)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocationReceipt {
    pub claim: ActorInvocationClaim,
    pub signature: Vec<u8>,
}

impl ActorInvocationReceipt {
    pub fn verify_guest_signature(
        &self,
        expected: &AgentAuthorityBinding,
    ) -> Result<(), AuthorityError> {
        if self.claim.authority != *expected {
            return Err(AuthorityError::WrongAuthority);
        }
        if self.signature.len() != ED25519_SIGNATURE_BYTES
            || !verify_ed25519(
                &expected.public_key,
                &self.claim.signing_message().0,
                &self.signature,
            )
        {
            return Err(AuthorityError::InvalidSignature);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        expected: &AgentAuthorityBinding,
        space: SpaceId,
        agent: AgentId,
        invocation: &ActorInvocation,
    ) -> Result<(), AuthorityError> {
        self.verify_guest_signature(expected)?;
        if self.claim.space != space {
            return Err(AuthorityError::WrongSpace);
        }
        if self.claim.agent != agent {
            return Err(AuthorityError::WrongAgent);
        }
        if self.claim.authorization != invocation.authorization_message()
            || self.claim.auth != invocation.auth
            || invocation.auth.principal != self.claim.principal
        {
            return Err(AuthorityError::WrongOperation);
        }
        Ok(())
    }
}

impl ServiceWire for ActorInvocationReceipt {
    const MAGIC: [u8; 4] = *b"AGIR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.bytes(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let receipt = Self {
            claim: ActorInvocationClaim::decode(&decoder.bytes()?)?,
            signature: decoder.bytes()?,
        };
        if receipt.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical);
        }
        Ok(receipt)
    }
}

fn encode_invocation_auth(encoder: &mut Encoder<'_>, auth: &ActorInvocationAuth) {
    crate::service::encode_origin(encoder, auth.origin);
    encoder.option(&auth.principal, |encoder, principal| {
        encoder.fixed(&principal.0)
    });
    encoder.option(&auth.origin_service, crate::service::encode_service);
    encoder.option(&auth.space_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.actor_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.capability, |encoder, capability| {
        encoder.fixed(&capability.0)
    });
}

fn decode_invocation_auth(decoder: &mut Decoder<'_>) -> Result<ActorInvocationAuth, DecodeError> {
    let auth = ActorInvocationAuth {
        origin: crate::service::decode_origin(decoder)?,
        principal: decoder.option(|decoder| Ok(PrincipalId(decoder.fixed()?)))?,
        origin_service: decoder.option(crate::service::decode_service)?,
        space_role: decoder.option(Decoder::u8)?,
        actor_role: decoder.option(Decoder::u8)?,
        capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
    };
    auth.validate()
        .then_some(auth)
        .ok_or(DecodeError::NonCanonical)
}

impl AgentAuthorityReceipt {
    /// Verify the canonical signature using software available inside the
    /// standard no-std runtime. Host verification may reject work earlier,
    /// but is never authoritative for a guest transition.
    pub fn verify_guest_signature(
        &self,
        expected: &AgentAuthorityBinding,
    ) -> Result<(), AuthorityError> {
        if self.claim.authority != *expected {
            return Err(AuthorityError::WrongAuthority);
        }
        if self.signature.len() != ED25519_SIGNATURE_BYTES
            || !verify_ed25519(
                &expected.public_key,
                &self.claim.signing_message().0,
                &self.signature,
            )
        {
            return Err(AuthorityError::InvalidSignature);
        }
        Ok(())
    }
}

impl ServiceWire for AgentAuthorityReceipt {
    const MAGIC: [u8; 4] = *b"AGAR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.bytes(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let receipt = Self {
            claim: AgentAuthorityClaim::decode(&decoder.bytes()?)?,
            signature: decoder.bytes()?,
        };
        if receipt.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical);
        }
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    WrongAuthority,
    WrongSpace,
    WrongAgent,
    WrongCapability,
    WrongOperation,
    Expired,
    InvalidSignature,
}

pub(crate) fn encode_binding(encoder: &mut Encoder<'_>, binding: &AgentAuthorityBinding) {
    encoder.fixed(&binding.agent.0);
    encoder.fixed(&binding.actor.0);
    encoder.fixed(&binding.deployment.0);
    encoder.fixed(&binding.program.0);
    encoder.fixed(&binding.producer.0);
    encoder.bytes(&binding.public_key);
}

pub(crate) fn decode_binding(
    decoder: &mut Decoder<'_>,
) -> Result<AgentAuthorityBinding, DecodeError> {
    let binding = AgentAuthorityBinding {
        agent: AgentId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        public_key: decoder.bytes()?,
    };
    if !binding.validate() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::LifecycleRequest;
    use crate::agent::MethodMode;
    use crate::agent::execution::{ActorInvocation, ActorInvocationAuth};
    use crate::service::{InvocationId, Origin, SubjectId};

    use ed25519_dalek::{Signer as _, SigningKey};

    fn binding(key: &SigningKey) -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire(key.verifying_key().to_bytes());
        AgentAuthorityBinding {
            agent: AgentId([1; 32]),
            actor: ActorId([2; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId([4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    #[test]
    fn receipt_binds_the_exact_lifecycle_operation() {
        let request = LifecycleRequest::Suspend {
            actor: ActorId([9; 32]),
            expected_deployment: DeploymentId([10; 32]),
        };
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let claim = AgentAuthorityClaim {
            authority: binding(&key),
            space: SpaceId([5; 32]),
            agent: AgentId([6; 32]),
            principal: PrincipalId([7; 32]),
            credential: CredentialId([8; 32]),
            capability: CapabilityId::named("actor.lifecycle"),
            operation: request.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 20,
        };
        let receipt = AgentAuthorityReceipt {
            signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
            claim,
        };
        assert_eq!(
            AgentAuthorityReceipt::decode(&receipt.encode()).unwrap(),
            receipt
        );
        assert_eq!(receipt.verify_guest_signature(&binding(&key)), Ok(()));
        let mut wrong_deployment = receipt.clone();
        wrong_deployment.claim.operation = LifecycleRequest::Suspend {
            actor: ActorId([9; 32]),
            expected_deployment: DeploymentId([11; 32]),
        }
        .commitment();
        assert_eq!(
            wrong_deployment.verify_guest_signature(&binding(&key)),
            Err(AuthorityError::InvalidSignature)
        );
        let mut forged = receipt;
        forged.claim.operation = LifecycleRequest::Resume {
            actor: ActorId([9; 32]),
            expected_deployment: DeploymentId([10; 32]),
        }
        .commitment();
        assert_eq!(
            forged.verify_guest_signature(&binding(&key)),
            Err(AuthorityError::InvalidSignature)
        );
    }

    fn invocation(auth: ActorInvocationAuth) -> ActorInvocation {
        ActorInvocation {
            invocation: InvocationId([0x31; 32]),
            actor: ActorId([0x32; 32]),
            deployment: DeploymentId([0x33; 32]),
            program: ProgramId([0x34; 32]),
            mode: MethodMode::Query,
            auth,
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        }
    }

    fn invocation_receipt(
        key: &SigningKey,
        invocation: &ActorInvocation,
        principal: Option<PrincipalId>,
        credential: Option<CredentialId>,
    ) -> ActorInvocationReceipt {
        let claim = ActorInvocationClaim {
            authority: binding(key),
            space: SpaceId([0x35; 32]),
            agent: AgentId([0x36; 32]),
            principal,
            credential,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from: 10,
            valid_until: 20,
        };
        ActorInvocationReceipt {
            signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
            claim,
        }
    }

    #[test]
    fn anonymous_invocation_receipt_has_no_forged_identity() {
        let key = SigningKey::from_bytes(&[0x43; 32]);
        let invocation = invocation(ActorInvocationAuth::anonymous());
        let receipt = invocation_receipt(&key, &invocation, None, None);
        assert_eq!(
            ActorInvocationReceipt::decode(&receipt.encode()).unwrap(),
            receipt
        );
        assert_eq!(
            receipt.validate_for(
                &binding(&key),
                SpaceId([0x35; 32]),
                AgentId([0x36; 32]),
                &invocation,
            ),
            Ok(())
        );
    }

    #[test]
    fn member_invocation_receipt_binds_the_principal() {
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let principal = PrincipalId([0x45; 32]);
        let invocation = invocation(ActorInvocationAuth {
            origin: Origin::Member(SubjectId([0x46; 32])),
            principal: Some(principal),
            origin_service: None,
            space_role: Some(1),
            actor_role: None,
            capability: None,
        });
        let receipt = invocation_receipt(
            &key,
            &invocation,
            Some(principal),
            Some(CredentialId([0x47; 32])),
        );
        assert_eq!(
            receipt.validate_for(
                &binding(&key),
                SpaceId([0x35; 32]),
                AgentId([0x36; 32]),
                &invocation,
            ),
            Ok(())
        );

        let mut mismatched = receipt;
        mismatched.claim.principal = Some(PrincipalId([0x48; 32]));
        mismatched.signature = key
            .sign(&mismatched.claim.signing_message().0)
            .to_bytes()
            .to_vec();
        assert_eq!(
            mismatched.validate_for(
                &binding(&key),
                SpaceId([0x35; 32]),
                AgentId([0x36; 32]),
                &invocation,
            ),
            Err(AuthorityError::WrongOperation)
        );
    }
}
