//! Operation-bound authorization for agent lifecycle changes.
//!
//! Package signatures authenticate software producers. Authority receipts
//! independently authenticate who may mutate one agent. A receipt is scoped
//! to one exact lifecycle request and therefore cannot be replayed for a
//! different actor, package, profile, or runtime. Receipt sequences share one
//! monotone namespace across the complete authority binding; rotating the
//! caller credential does not reset replay protection.

use alloc::vec::Vec;

use super::LifecycleRequest;
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
pub const MAX_AUTHORITY_PUBLIC_KEY_BYTES: usize = 4 * 1024;
pub const MAX_AUTHORITY_SIGNATURE_BYTES: usize = 4 * 1024;

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
            && !self.public_key.is_empty()
            && self.public_key.len() <= MAX_AUTHORITY_PUBLIC_KEY_BYTES
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

impl AgentAuthorityReceipt {
    pub fn verify<V: AgentAuthorityVerifier>(
        self,
        expected: &AgentAuthorityBinding,
        observation_slot: u64,
        verifier: &V,
    ) -> Result<VerifiedAgentAuthorityReceipt, AuthorityError> {
        if self.claim.authority != *expected {
            return Err(AuthorityError::WrongAuthority);
        }
        if observation_slot < self.claim.valid_from || observation_slot > self.claim.valid_until {
            return Err(AuthorityError::Expired);
        }
        if self.signature.is_empty()
            || self.signature.len() > MAX_AUTHORITY_SIGNATURE_BYTES
            || !verifier.verify(expected, &self.claim.signing_message().0, &self.signature)
        {
            return Err(AuthorityError::InvalidSignature);
        }
        Ok(VerifiedAgentAuthorityReceipt(self))
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
        if receipt.signature.is_empty() || receipt.signature.len() > MAX_AUTHORITY_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical);
        }
        Ok(receipt)
    }
}

pub trait AgentAuthorityVerifier {
    fn verify(&self, authority: &AgentAuthorityBinding, message: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "network")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ed25519AgentAuthorityVerifier;

#[cfg(feature = "network")]
impl AgentAuthorityVerifier for Ed25519AgentAuthorityVerifier {
    fn verify(&self, authority: &AgentAuthorityBinding, message: &[u8], signature: &[u8]) -> bool {
        libp2p::identity::PublicKey::try_decode_protobuf(&authority.public_key)
            .is_ok_and(|public_key| public_key.verify(message, signature))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentAuthorityReceipt(AgentAuthorityReceipt);

impl VerifiedAgentAuthorityReceipt {
    pub fn claim(&self) -> &AgentAuthorityClaim {
        &self.0.claim
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

/// Bind a verified claim to one lifecycle operation at the node's current
/// durable logical slot.
///
/// `current_slot` is a trusted host observation, not caller input. The
/// operation must not be queued after this check without carrying that same
/// admitted authority record into the runtime transition.
pub fn authorize_lifecycle(
    receipt: &VerifiedAgentAuthorityReceipt,
    authority: &AgentAuthorityBinding,
    space: SpaceId,
    agent: AgentId,
    capability: CapabilityId,
    request: &LifecycleRequest,
    current_slot: u64,
) -> Result<(), AuthorityError> {
    let claim = receipt.claim();
    if claim.authority != *authority {
        return Err(AuthorityError::WrongAuthority);
    }
    if claim.space != space {
        return Err(AuthorityError::WrongSpace);
    }
    if claim.agent != agent {
        return Err(AuthorityError::WrongAgent);
    }
    if claim.capability != capability {
        return Err(AuthorityError::WrongCapability);
    }
    if claim.operation != request.commitment() {
        return Err(AuthorityError::WrongOperation);
    }
    // Verification authenticates the signature, but a verified value may be
    // retained by its caller. Recheck validity at the trusted admission slot
    // immediately before the operation enters durable runtime state.
    if current_slot < claim.valid_from || current_slot > claim.valid_until {
        return Err(AuthorityError::Expired);
    }
    Ok(())
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

    struct Accept;

    impl AgentAuthorityVerifier for Accept {
        fn verify(&self, _: &AgentAuthorityBinding, _: &[u8], _: &[u8]) -> bool {
            true
        }
    }

    fn binding() -> AgentAuthorityBinding {
        AgentAuthorityBinding {
            agent: AgentId([1; 32]),
            actor: ActorId([2; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId([4; 32]),
            producer: ProducerId::of_public_key(b"authority-key"),
            public_key: b"authority-key".to_vec(),
        }
    }

    #[test]
    fn receipt_binds_the_exact_lifecycle_operation() {
        let request = LifecycleRequest::Suspend(ActorId([9; 32]));
        let receipt = AgentAuthorityReceipt {
            claim: AgentAuthorityClaim {
                authority: binding(),
                space: SpaceId([5; 32]),
                agent: AgentId([6; 32]),
                principal: PrincipalId([7; 32]),
                credential: CredentialId([8; 32]),
                capability: CapabilityId::named("actor.lifecycle"),
                operation: request.commitment(),
                sequence: 1,
                valid_from: 10,
                valid_until: 20,
            },
            signature: vec![1],
        };
        assert_eq!(
            AgentAuthorityReceipt::decode(&receipt.encode()).unwrap(),
            receipt
        );
        let verified = receipt.verify(&binding(), 15, &Accept).unwrap();
        assert_eq!(
            authorize_lifecycle(
                &verified,
                &binding(),
                SpaceId([5; 32]),
                AgentId([6; 32]),
                CapabilityId::named("actor.lifecycle"),
                &request,
                15,
            ),
            Ok(())
        );
        assert_eq!(
            authorize_lifecycle(
                &verified,
                &binding(),
                SpaceId([5; 32]),
                AgentId([6; 32]),
                CapabilityId::named("actor.lifecycle"),
                &LifecycleRequest::Resume(ActorId([9; 32])),
                15,
            ),
            Err(AuthorityError::WrongOperation)
        );

        assert_eq!(
            authorize_lifecycle(
                &verified,
                &binding(),
                SpaceId([5; 32]),
                AgentId([6; 32]),
                CapabilityId::named("actor.lifecycle"),
                &request,
                21,
            ),
            Err(AuthorityError::Expired)
        );
    }
}
