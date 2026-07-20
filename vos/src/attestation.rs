//! Portable v3 attestations and the verifier-only path.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::v2::wire::{Decoder, Encoder};
use crate::v2::{
    AccumulationReceiptV2, ActorId, DecodeError, DeploymentId, Hash, InvocationId, MethodPolicyV2,
    ProducerId, ProgramId, SpaceId, TransitionV2, V2Wire, WorkEnvelopeV2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateCommitmentV3 {
    Linear(Hash),
    Crdt(Vec<Hash>),
}

/// Consensus-visible statement proved by an attested actor method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationStatementV3 {
    pub statement_version: u16,
    pub space: SpaceId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub actor_program: ProgramId,
    pub method: String,
    pub schema: Hash,
    pub invocation: InvocationId,
    pub before: StateCommitmentV3,
    pub after: StateCommitmentV3,
    pub claim_commitment: Hash,
    pub input_commitment: Hash,
    pub authorization_policy: Hash,
    pub accumulation_receipt: AccumulationReceiptV2,
}

impl AttestationStatementV3 {
    /// Construct the one canonical statement for a prepared actor transition.
    /// Both the prover and guest Accumulate use this function, preventing a
    /// host from substituting different public inputs at proof time.
    pub fn for_transition(
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
        policy: &MethodPolicyV2,
        receipt: AccumulationReceiptV2,
    ) -> Result<Self, AttestationError> {
        if work.service != transition.service
            || work.service != receipt.service
            || work.target_program != transition.target_program
            || work.input_id() != transition.consumed_input
            || work.base != transition.base
            || work.method != policy.method
            || receipt.accepted_transition != transition.commitment()
            || receipt.checkpoint != work.workflow_step
            || receipt.consistency != work.consistency
        {
            return Err(AttestationError::InvalidStatement);
        }
        let reply = transition
            .reply
            .as_ref()
            .filter(|reply| reply.producer == work.target)
            .ok_or(AttestationError::InvalidStatement)?;
        let before = match &work.base {
            crate::v2::ConsistencyBaseV2::Linear { state_root, .. } => {
                StateCommitmentV3::Linear(*state_root)
            }
            crate::v2::ConsistencyBaseV2::Crdt { heads } => StateCommitmentV3::Crdt(heads.clone()),
        };
        let after = match receipt.consistency {
            crate::v2::ConsistencyModeV2::Crdt => {
                StateCommitmentV3::Crdt(receipt.resulting_crdt_heads.clone())
            }
            _ => StateCommitmentV3::Linear(
                receipt
                    .resulting_state_root
                    .ok_or(AttestationError::InvalidStatement)?,
            ),
        };
        let authorization_input = match &work.authorization {
            crate::v2::AuthorizationEvidenceV2::Public => Hash::ZERO,
            crate::v2::AuthorizationEvidenceV2::Credential {
                credential_commitment,
                ..
            }
            | crate::v2::AuthorizationEvidenceV2::PrivateCredential {
                credential_commitment,
                ..
            } => *credential_commitment,
            crate::v2::AuthorizationEvidenceV2::SystemCapability { capability, .. } => {
                Hash(capability.0)
            }
        };
        let value = Self {
            statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
            space: work.service.space,
            actor: work.target,
            deployment: work.service.deployment,
            actor_program: work.target_program,
            method: work.method.clone(),
            schema: policy.schema,
            invocation: work.invocation,
            before,
            after,
            claim_commitment: Hash::digest(b"vos/attestation-claim/v3", &[&reply.result]),
            input_commitment: Hash::digest(
                b"vos/attestation-input/v3",
                &[&work.arguments, &authorization_input.0],
            ),
            authorization_policy: policy.policy,
            accumulation_receipt: receipt,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/attestation-statement/v3", &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.statement_version != crate::v2::ATTESTATION_STATEMENT_VERSION {
            return Err(AttestationError::WrongStatementVersion);
        }
        if self.method.is_empty()
            || self.accumulation_receipt.service.service_abi != crate::v2::ABI_VERSION
            || self.accumulation_receipt.service.execution_semantics
                != crate::v2::EXECUTION_SEMANTICS_ID
        {
            return Err(AttestationError::InvalidStatement);
        }
        if self.space != self.accumulation_receipt.service.space
            || self.deployment != self.accumulation_receipt.service.deployment
            || self.accumulation_receipt.accepted_transition == Hash::ZERO
        {
            return Err(AttestationError::ReceiptMismatch);
        }
        match (&self.before, &self.after) {
            (StateCommitmentV3::Linear(_), StateCommitmentV3::Linear(after))
                if self.accumulation_receipt.consistency != crate::v2::ConsistencyModeV2::Crdt
                    && self.accumulation_receipt.resulting_state_root == Some(*after)
                    && self.accumulation_receipt.resulting_crdt_heads.is_empty() =>
            {
                Ok(())
            }
            (StateCommitmentV3::Crdt(before), StateCommitmentV3::Crdt(after))
                if self.accumulation_receipt.consistency == crate::v2::ConsistencyModeV2::Crdt
                    && self.accumulation_receipt.resulting_state_root.is_none()
                    && self.accumulation_receipt.resulting_crdt_heads == *after
                    && hashes_are_canonical(before)
                    && hashes_are_canonical(after) =>
            {
                Ok(())
            }
            _ => Err(AttestationError::StateCommitmentMismatch),
        }
    }
}

impl V2Wire for AttestationStatementV3 {
    const MAGIC: [u8; 4] = *b"VOSA";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.u16(self.statement_version);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.actor.0);
        encoder.fixed(&self.deployment.0);
        encoder.fixed(&self.actor_program.0);
        encoder.string(&self.method);
        encoder.fixed(&self.schema.0);
        encoder.fixed(&self.invocation.0);
        encode_state(&mut encoder, &self.before);
        encode_state(&mut encoder, &self.after);
        encoder.fixed(&self.claim_commitment.0);
        encoder.fixed(&self.input_commitment.0);
        encoder.fixed(&self.authorization_policy.0);
        encoder.bytes(&self.accumulation_receipt.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            statement_version: decoder.u16()?,
            space: SpaceId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            deployment: DeploymentId(decoder.fixed()?),
            actor_program: ProgramId(decoder.fixed()?),
            method: decoder.string()?,
            schema: Hash(decoder.fixed()?),
            invocation: InvocationId(decoder.fixed()?),
            before: decode_state(decoder)?,
            after: decode_state(decoder)?,
            claim_commitment: Hash(decoder.fixed()?),
            input_commitment: Hash(decoder.fixed()?),
            authorization_policy: Hash(decoder.fixed()?),
            accumulation_receipt: AccumulationReceiptV2::decode(&decoder.bytes()?)?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

fn hashes_are_canonical(values: &[Hash]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_state(encoder: &mut Encoder<'_>, state: &StateCommitmentV3) {
    match state {
        StateCommitmentV3::Linear(root) => {
            encoder.u8(0);
            encoder.fixed(&root.0);
        }
        StateCommitmentV3::Crdt(heads) => {
            encoder.u8(1);
            encoder.list(heads, |encoder, head| encoder.fixed(&head.0));
        }
    }
}

fn decode_state(decoder: &mut Decoder<'_>) -> Result<StateCommitmentV3, DecodeError> {
    match decoder.u8()? {
        0 => Ok(StateCommitmentV3::Linear(Hash(decoder.fixed()?))),
        1 => Ok(StateCommitmentV3::Crdt(
            decoder.list(|decoder| decoder.fixed().map(Hash))?,
        )),
        _ => Err(DecodeError::InvalidTag),
    }
}

/// Application proof package. `M` is the generated method marker. There is
/// deliberately no `claim()` accessor; previews are explicitly unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation<T, M> {
    producer_name: String,
    producer: ProducerId,
    statement: AttestationStatementV3,
    preview: T,
    proof: Vec<u8>,
    _method: PhantomData<M>,
}

impl<T, M> Attestation<T, M> {
    #[doc(hidden)]
    pub fn __from_runtime(
        producer_name: String,
        producer: ProducerId,
        statement: AttestationStatementV3,
        preview: T,
        proof: Vec<u8>,
    ) -> Self {
        Self {
            producer_name,
            producer,
            statement,
            preview,
            proof,
            _method: PhantomData,
        }
    }

    /// UI/transport preview. Never use it for authorization or state changes.
    pub fn unverified_preview(&self) -> &T {
        &self.preview
    }

    pub fn statement(&self) -> &AttestationStatementV3 {
        &self.statement
    }

    pub fn producer(&self) -> ProducerId {
        self.producer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> core::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    CannotSuspend,
    WrongStatementVersion,
    InvalidStatement,
    WrongProducer,
    ClaimCommitmentMismatch,
    ReceiptMismatch,
    StateCommitmentMismatch,
    InvalidProof,
    Replay,
}

impl core::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "attestation failed: {self:?}")
    }
}

impl core::error::Error for AttestationError {}

/// Proof engine seam. Implementations verify the canonical actor PVM proof
/// against the exact statement and execution-semantics identity.
pub trait ProofVerifier {
    fn verify(
        &self,
        actor_program: ProgramId,
        execution_semantics: Hash,
        statement: Hash,
        proof: &[u8],
    ) -> bool;
}

impl<F> ProofVerifier for F
where
    F: Fn(ProgramId, Hash, Hash, &[u8]) -> bool,
{
    fn verify(
        &self,
        actor_program: ProgramId,
        execution_semantics: Hash,
        statement: Hash,
        proof: &[u8],
    ) -> bool {
        self(actor_program, execution_semantics, statement, proof)
    }
}

#[derive(Debug, Default)]
pub struct AttestationReplayGuard {
    seen: BTreeSet<(ActorId, InvocationId)>,
}

/// Verify an already-produced package. This path never invokes the producer.
pub fn verify_once<T: crate::Encode, M>(
    package: Attestation<T, M>,
    expected_producer_name: &str,
    expected_producer: ProducerId,
    replay: &mut AttestationReplayGuard,
    verifier: &impl ProofVerifier,
) -> Result<Verified<T>, AttestationError> {
    if package.producer_name != expected_producer_name || package.producer != expected_producer {
        return Err(AttestationError::WrongProducer);
    }
    package.statement.validate()?;
    if Hash::digest(b"vos/attestation-claim/v3", &[&package.preview.encode()])
        != package.statement.claim_commitment
    {
        return Err(AttestationError::ClaimCommitmentMismatch);
    }
    if !verifier.verify(
        package.statement.actor_program,
        package
            .statement
            .accumulation_receipt
            .service
            .execution_semantics,
        package.statement.commitment(),
        &package.proof,
    ) {
        return Err(AttestationError::InvalidProof);
    }
    let key = (package.statement.actor, package.statement.invocation);
    if !replay.seen.insert(key) {
        return Err(AttestationError::Replay);
    }
    Ok(Verified(package.preview))
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use crate::Encode;
    use crate::v2::{ConsistencyModeV2, RootServiceId, ServiceIdentityV2};

    use super::*;

    enum Method {}

    fn package(claim: u64) -> Attestation<u64, Method> {
        let deployment = DeploymentId([3; 32]);
        let receipt = AccumulationReceiptV2 {
            service: ServiceIdentityV2 {
                space: SpaceId([6; 32]),
                root_service: RootServiceId([1; 32]),
                deployment,
                service_program: ProgramId([2; 32]),
                service_abi: crate::v2::ABI_VERSION,
                execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
            },
            accepted_transition: Hash([4; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(Hash([5; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 1,
            consistency: ConsistencyModeV2::Local,
        };
        let statement = AttestationStatementV3 {
            statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
            space: SpaceId([6; 32]),
            actor: ActorId([7; 32]),
            deployment,
            actor_program: ProgramId([8; 32]),
            method: "is_adult".to_string(),
            schema: Hash([9; 32]),
            invocation: InvocationId([10; 32]),
            before: StateCommitmentV3::Linear(Hash([11; 32])),
            after: StateCommitmentV3::Linear(Hash([5; 32])),
            claim_commitment: Hash::digest(b"vos/attestation-claim/v3", &[&claim.encode()]),
            input_commitment: Hash([13; 32]),
            authorization_policy: Hash([14; 32]),
            accumulation_receipt: receipt,
        };
        Attestation::__from_runtime(
            "private-age".to_string(),
            ProducerId([15; 32]),
            statement,
            claim,
            vec![1],
        )
    }

    #[test]
    fn verification_is_separate_tamper_evident_and_once_only() {
        let verifier = |_: ProgramId, _: Hash, _: Hash, proof: &[u8]| proof == [1];
        let mut replay = AttestationReplayGuard::default();
        assert_eq!(
            verify_once(
                package(21),
                "private-age",
                ProducerId([15; 32]),
                &mut replay,
                &verifier,
            )
            .unwrap()
            .into_inner(),
            21,
        );
        assert_eq!(
            verify_once(
                package(21),
                "private-age",
                ProducerId([15; 32]),
                &mut replay,
                &verifier,
            ),
            Err(AttestationError::Replay),
        );

        let mut tampered = package(21);
        tampered.preview = 20;
        assert_eq!(
            verify_once(
                tampered,
                "private-age",
                ProducerId([15; 32]),
                &mut AttestationReplayGuard::default(),
                &verifier,
            ),
            Err(AttestationError::ClaimCommitmentMismatch),
        );

        assert_eq!(
            verify_once(
                package(22),
                "private-age",
                ProducerId([99; 32]),
                &mut AttestationReplayGuard::default(),
                &verifier,
            ),
            Err(AttestationError::WrongProducer),
        );

        let mut wrong_state = package(23);
        wrong_state.statement.after = StateCommitmentV3::Linear(Hash([99; 32]));
        assert_eq!(
            verify_once(
                wrong_state,
                "private-age",
                ProducerId([15; 32]),
                &mut AttestationReplayGuard::default(),
                &verifier,
            ),
            Err(AttestationError::StateCommitmentMismatch),
        );
    }
}
