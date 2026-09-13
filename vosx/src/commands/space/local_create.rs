//! Preparation of an exact signed Local Create request for the native operator.
//!
//! Sequence allocation and durable request-file publication belong to the
//! caller. This module never reads a clock, generates a nonce, loads a key, or
//! submits a request: retries must reuse the persisted LCQ1 bytes.

use std::num::NonZeroU64;

use libp2p::identity::Keypair;
use vos::agent::local_lifecycle::LocalCreateSubmission;
use vos::agent::package_admission::AdmittedRuntimePackage;
use vos::agent::sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialCall, ManagedAgentTarget,
};
use vos::agent::sdk::{AgentDescriptor, InvocationId, ManagementRequest};

use super::clean_identity::CleanOperatorIdentitySigner;

pub(crate) fn prepare(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    descriptor: AgentDescriptor,
    runtime: AdmittedRuntimePackage,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<LocalCreateSubmission> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        descriptor.identity.owner == identity.principal(),
        "operator Local Create requires the operator as owner"
    );
    let managed = ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let mut call = AuthorityCredentialCall {
        invocation: InvocationId::ZERO,
        authority,
        managed,
        principal: identity.principal(),
        credential: identity.credential(),
        request_sequence: sequence,
        credential_public_key: identity.raw_public_key(),
        authenticated_node: None,
        requested_valid_from: valid_from,
        requested_expires_at: expires_at,
        plan: request
            .authorization_plan()
            .ok_or_else(|| anyhow::anyhow!("invalid Local Create authorization plan"))?,
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = operator
        .sign(&call.signing_bytes())
        .map_err(|_| anyhow::anyhow!("Local Create signing failed"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Local Create signature must be Ed25519"))?;
    LocalCreateSubmission::new(descriptor, call, runtime)
        .map_err(|error| anyhow::anyhow!("invalid signed Local Create: {error:?}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use vos::agent::sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
    use vos::agent::sdk::{
        ActorId, AgentId, AgentIdentity, AgentProfile, AgentReplica, DeploymentId, Hash, NodeId,
        ProducerId, ProgramId, ReplicaRole, SpaceId,
    };

    pub(crate) fn fixture() -> (
        Keypair,
        AuthorityActorTarget,
        AgentDescriptor,
        AdmittedRuntimePackage,
    ) {
        let operator = Keypair::ed25519_from_bytes([0x63; 32]).unwrap();
        let signer = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let runtime = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
        let space = SpaceId([1; 32]);
        let nonce = Hash([2; 32]);
        let binding = AgentAuthorityBinding {
            policy: Hash([3; 32]),
            issuer: AuthorityIssuer {
                principal: signer.principal(),
                actor: ActorId([4; 32]),
                deployment: DeploymentId([5; 32]),
                program: ProgramId([6; 32]),
                producer: ProducerId::of_public_key(&signer.raw_public_key()),
            },
            public_key: signer.raw_public_key(),
            initial_epoch: 1,
        };
        let authority = AuthorityActorTarget {
            space,
            system_agent: AgentId([7; 32]),
            system_runtime_deployment: runtime.deployment(),
            binding,
        };
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, signer.principal(), nonce.as_bytes()),
                owner: signer.principal(),
                profile: AgentProfile::Local,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: ProducerId([8; 32]),
            },
            creation_nonce: nonce,
            authority: binding,
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![AgentReplica {
                node: NodeId([9; 32]),
                principal: signer.principal(),
                role: ReplicaRole::Voter,
            }],
        };
        (operator, authority, descriptor, runtime)
    }

    #[test]
    fn exact_inputs_produce_identical_http_compatible_signed_submissions() {
        let (operator, authority, descriptor, runtime) = fixture();
        let sequence = NonZeroU64::new(2).unwrap();
        let first = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            sequence,
            10,
            30,
        )
        .unwrap()
        .encode();
        let repeated = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            sequence,
            10,
            30,
        )
        .unwrap()
        .encode();
        assert_eq!(first, repeated);
        assert!(first.len() <= 1024 * 1024);
        let (_, call, _) = LocalCreateSubmission::decode(&first).unwrap().into_parts();
        assert_eq!(call.authenticated_node, None);
        assert_eq!(call.request_sequence, sequence);
        assert_eq!(
            (call.requested_valid_from, call.requested_expires_at),
            (10, 30)
        );
        let changed = prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            NonZeroU64::new(3).unwrap(),
            10,
            30,
        )
        .unwrap();
        assert_ne!(changed.into_parts().1.invocation, call.invocation);
    }

    #[test]
    fn preparation_rejects_wrong_owner_scope_window_and_runtime() {
        let (operator, authority, descriptor, runtime) = fixture();
        let sequence = NonZeroU64::new(2).unwrap();
        let other = Keypair::ed25519_from_bytes([0x64; 32]).unwrap();
        assert!(
            prepare(
                &other,
                authority,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                10,
                30
            )
            .is_err()
        );
        assert!(
            prepare(
                &operator,
                authority,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                30,
                10
            )
            .is_err()
        );
        let mut wrong_scope = authority;
        wrong_scope.space = SpaceId([99; 32]);
        assert!(
            prepare(
                &operator,
                wrong_scope,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                10,
                30
            )
            .is_err()
        );
        let wrong_runtime = crate::bundled::root_signed_agent_runtime_package(&other).unwrap();
        assert!(
            prepare(
                &operator,
                authority,
                descriptor,
                wrong_runtime,
                sequence,
                10,
                30
            )
            .is_err()
        );
    }
}
