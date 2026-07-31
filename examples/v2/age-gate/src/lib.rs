//! A verifier consumes an already-produced package; it cannot invoke or prove
//! the private-age method.

use private_age::{AgeClaim, IsAdult};
use vos::{
    Attestation, AttestationError, AttestationReplayStore, AttestationSourceResolver,
    ProofVerifier, ReceiptVerifier, VerificationContext, Verified,
};

pub async fn verify_age<R, F, V, S>(
    context: &mut VerificationContext<'_, R, F, V, S>,
    package: Attestation<AgeClaim, IsAdult>,
) -> Result<Verified<AgeClaim>, AttestationError>
where
    R: AttestationSourceResolver,
    F: ReceiptVerifier,
    V: ProofVerifier,
    S: AttestationReplayStore,
{
    context.verify(package).from("private-age").once().await
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::pin,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };

    use vos::v2::{
        AccumulationReceiptV2, ActorId, ConsistencyModeV2, DeploymentId, Hash, InvocationId,
        ProducerId, ProgramId, ReceiptVerificationV2, ReplyRecordV2, RootServiceId,
        ServiceIdentityV2, SpaceId,
    };
    use vos::{
        AttestationReplayGuard, AttestationSource, AttestationStatementV3, AttestedMethod,
        StateCommitmentV3,
    };

    use super::*;

    fn block_on<F: Future>(future: F) -> F::Output {
        struct NoopWake;

        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn package(invocation: InvocationId) -> Attestation<AgeClaim, IsAdult> {
        let claim = AgeClaim {
            minimum_age: 18,
            adult: true,
        };
        let actor = ActorId([7; 32]);
        let reply_call = invocation.root_reply_id();
        let claim_wire = <IsAdult as AttestedMethod<AgeClaim>>::claim_wire(&claim);
        let deployment = DeploymentId([3; 32]);
        let receipt = AccumulationReceiptV2 {
            service: ServiceIdentityV2 {
                space: SpaceId([6; 32]),
                root_service: RootServiceId([1; 32]),
                deployment,
                service_program: ProgramId([2; 32]),
                service_abi: vos::v2::ABI_VERSION,
                execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            },
            accepted_transition: Hash([4; 32]),
            reply_commitment: Some(
                ReplyRecordV2 {
                    call_id: reply_call,
                    producer: actor,
                    result: claim_wire.clone(),
                }
                .commitment(),
            ),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([5; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 1,
            consistency: ConsistencyModeV2::Local,
        };
        let statement = AttestationStatementV3 {
            statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
            space: SpaceId([6; 32]),
            actor,
            deployment,
            actor_program: ProgramId([8; 32]),
            method: "is_adult".into(),
            schema: Hash([9; 32]),
            invocation,
            reply_call,
            before: StateCommitmentV3::Linear(Hash([11; 32])),
            after: StateCommitmentV3::Linear(Hash([5; 32])),
            claim_commitment: Hash::digest(
                b"vos/attestation-claim/v3",
                &[&claim_wire],
            ),
            input_commitment: Hash([13; 32]),
            authorization_policy: Hash([14; 32]),
            accumulation_receipt: receipt,
        };
        Attestation::__from_runtime(
            "private-age".into(),
            ProducerId([15; 32]),
            statement,
            Hash([16; 32]),
            claim,
            vec![1],
        )
        .unwrap()
    }

    #[test]
    fn gate_verifies_without_invoking_the_producer_and_rejects_replay() {
        let expected = package(InvocationId([10; 32]));
        let source = AttestationSource {
            service: expected.statement().accumulation_receipt.service.clone(),
            actor: expected.statement().actor,
            actor_program: expected.statement().actor_program,
            producer: expected.producer(),
            schema: expected.statement().schema,
            authorization_policy: expected.statement().authorization_policy,
        };
        let resolver = move |name: &str, method: &str| {
            (name == "private-age" && method == IsAdult::METHOD).then(|| source.clone())
        };
        let finalized = |_: &vos::v2::ReceiptVerificationRequestV2| ReceiptVerificationV2::Valid;
        let verifier = |_: ProgramId, _: Hash, _: Hash, proof: &[u8]| proof == [1];
        let mut replay = AttestationReplayGuard::default();
        let mut context =
            VerificationContext::new(&resolver, &finalized, &verifier, &mut replay);
        let invocation = InvocationId([10; 32]);

        let claim = block_on(verify_age(&mut context, package(invocation))).unwrap();
        assert!(claim.adult);
        assert_eq!(
            block_on(verify_age(&mut context, package(invocation))),
            Err(AttestationError::Replay)
        );
    }
}
