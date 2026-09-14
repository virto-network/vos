//! Sign exact prepared invocation intent. Discovery is not policy approval;
//! callers retain their reservation, preparation and AOQ1 before dispatch.
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialKind, AuthorityCredentialProjection,
    AuthorityCredentialStatus, AuthorityIngressAuthentication, AuthorityProjectionSelector,
    ManagedAgentTarget,
};
use vos::agent::sdk::authority_operation::{AuthorityOperationCall, AuthorityOperationIntent};
use vos::agent::sdk::{
    AgentDescriptor, InvocationContext, InvocationId, InvocationOrigin, InvocationRoleClaims,
    MethodMode,
};
use vos::agent::supervisor_adapters::PreparedAgentInvocation;

/// Select once, before signing; exact retry must never replace these slots
/// with a newly read clock. No wall clock or random ID is read by this module.
#[derive(Clone, Copy)]
pub(crate) struct Timing {
    pub authorization_slot: u64,
    pub issued_at: u64,
    pub valid_from: u64,
    pub expires_at: u64,
}

pub(crate) fn prepare(
    operator: &libp2p::identity::Keypair,
    authority: AuthorityActorTarget,
    descriptor: &AgentDescriptor,
    credential: &AuthorityCredentialProjection,
    prepared: &PreparedAgentInvocation,
    timing: Timing,
) -> anyhow::Result<AuthorityOperationSubmission> {
    anyhow::ensure!(
        descriptor.validate().is_ok()
            && descriptor.authority == authority.binding
            && descriptor.identity.space == authority.space
            && prepared.profile() == descriptor.identity.profile
            && prepared.runtime_program() == descriptor.identity.runtime_program
            && prepared.runtime_package() == &descriptor.runtime_package
            && timing.authorization_slot >= prepared.observed_slot(),
        "prepared runtime, Authority binding or observation does not match the selected Agent"
    );
    let identity = &descriptor.identity;
    let managed = ManagedAgentTarget {
        space: identity.space,
        agent: identity.agent,
        owner: identity.owner,
        profile: identity.profile,
        runtime_deployment: identity.runtime_deployment,
        transition_producer: identity.transition_producer,
    };
    let intent = AuthorityOperationIntent::invoke(managed, prepared.work())
        .map_err(|e| anyhow::anyhow!("prepared work differs from the selected Agent: {e:?}"))?;
    sign_call(operator, authority, credential, intent, timing)
}

fn sign_call(
    operator: &libp2p::identity::Keypair,
    authority: AuthorityActorTarget,
    credential: &AuthorityCredentialProjection,
    intent: AuthorityOperationIntent,
    timing: Timing,
) -> anyhow::Result<AuthorityOperationSubmission> {
    let identity =
        crate::commands::space::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        credential.validate_shape().is_ok()
            && credential.query.authority == authority
            && credential.query.selector == AuthorityProjectionSelector::Credential
            && credential.query.credential == identity.credential()
            && credential.principal == identity.principal()
            && credential.status == AuthorityCredentialStatus::Active
            && credential.kind == AuthorityCredentialKind::Api
            && credential
                .query
                .verify_api_with(&crate::commands::space::local_create::CredentialVerifier)
                .is_ok(),
        "operation requires the selected operator's active API credential projection"
    );
    let sequence = credential
        .operation_request_high_water
        .checked_add(1)
        .and_then(core::num::NonZeroU64::new)
        .ok_or_else(|| anyhow::anyhow!("operation credential sequence exhausted"))?;
    anyhow::ensure!(
        timing.authorization_slot <= timing.issued_at
            && timing.valid_from <= timing.issued_at
            && timing.issued_at <= timing.expires_at,
        "invalid retained operation timing"
    );
    let mut call = AuthorityOperationCall {
        invocation: InvocationId::ZERO,
        authority,
        principal: identity.principal(),
        credential: identity.credential(),
        request_sequence: sequence,
        authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: identity.raw_public_key(),
            signature: [1; 64],
        },
        requested_valid_from: timing.valid_from,
        requested_expires_at: timing.expires_at,
        intent,
    };
    call.invocation = call.expected_invocation();
    // Reject a mismatched prepared caller before invoking the signing key.
    call.validate_shape()
        .map_err(|e| anyhow::anyhow!("invalid prepared operation: {e:?}"))?;
    let signature = operator
        .sign(&call.signing_bytes())
        .map_err(|_| anyhow::anyhow!("operation signing failed"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("operation signer must be Ed25519"))?;
    call.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
        credential_public_key: identity.raw_public_key(),
        signature,
    };
    let context = InvocationContext {
        invocation: call.invocation,
        actor: authority.binding.issuer.actor,
        mode: MethodMode::Linear,
        origin: InvocationOrigin {
            principal: Some(identity.principal()),
            credential: Some(identity.credential()),
            transport_node: None,
            actor: None,
            capability: None,
        },
        roles: InvocationRoleClaims::none(),
        observed_slot: timing.authorization_slot,
    };
    AuthorityOperationSubmission::new(call, context, timing.issued_at)
        .map_err(|e| anyhow::anyhow!("invalid signed operation submission: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;
    use vos::agent::sdk::authority::*;
    use vos::agent::sdk::wire::CanonicalWire as _;
    use vos::agent::sdk::*;

    fn fixture() -> (
        libp2p::identity::Keypair,
        AuthorityActorTarget,
        AuthorityCredentialProjection,
        AuthorityOperationIntent,
        Timing,
    ) {
        let (key, authority, descriptor, _) =
            crate::commands::space::local_create::tests::fixture();
        let identity =
            crate::commands::space::clean_identity::CleanOperatorIdentitySigner::new(&key).unwrap();
        let mut signer = crate::commands::space::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator::new(key.clone()).unwrap();
        let query = signer
            .authenticate(authority, AuthorityProjectionSelector::Credential)
            .unwrap();
        let one = core::num::NonZeroU64::new(1).unwrap();
        let credential = AuthorityCredentialProjection {
            query,
            head: AuthorityProjectionHead {
                state_revision: one,
                epoch: one,
                authorization_sequence: one,
                administration_generation: one,
                state_commitment: Hash([20; 32]),
            },
            principal: identity.principal(),
            status: AuthorityCredentialStatus::Active,
            kind: AuthorityCredentialKind::Api,
            builtin_role: AuthorityBuiltinRole::Admin,
            management_request_high_water: 99,
            operation_request_high_water: 7,
            admin_request_high_water: 999,
            space_roles: vec![],
            actor_roles: vec![],
            capabilities: vec![],
        };
        let work = InvocationWork {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            invocation: InvocationId([21; 32]),
            actor: ActorId([22; 32]),
            incarnation: Hash([23; 32]),
            deployment: DeploymentId([24; 32]),
            program: ProgramId([25; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(identity.principal()),
                credential: Some(identity.credential()),
                transport_node: None,
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            message: vec![1],
            installation_data: None,
            availability: vec![],
            gas: 100,
            recovery_only: false,
        };
        let managed = ManagedAgentTarget {
            space: work.space,
            agent: work.agent,
            runtime_deployment: work.runtime_deployment,
            owner: descriptor.identity.owner,
            profile: descriptor.identity.profile,
            transition_producer: descriptor.identity.transition_producer,
        };
        let intent = AuthorityOperationIntent::invoke(managed, &work).unwrap();
        (
            key,
            authority,
            credential,
            intent,
            Timing {
                authorization_slot: 20,
                issued_at: 21,
                valid_from: 10,
                expires_at: 100,
            },
        )
    }

    #[test]
    fn operation_preparation_signs_identical_inputs_in_the_operation_sequence_domain() {
        let (key, authority, mut credential, intent, timing) = fixture();
        let first = sign_call(&key, authority, &credential, intent.clone(), timing).unwrap();
        assert_eq!(first.call().request_sequence.get(), 8);
        assert_eq!(first.call().intent, intent);
        assert_eq!(first.context().observed_slot, 20);
        assert_eq!(first.issued_at(), 21);
        assert!(
            first
                .call()
                .verify_api_with(&crate::commands::space::local_create::CredentialVerifier)
                .is_ok()
        );
        assert_eq!(
            first.encode().unwrap(),
            sign_call(&key, authority, &credential, intent.clone(), timing)
                .unwrap()
                .encode()
                .unwrap()
        );
        credential.management_request_high_water = u64::MAX;
        credential.admin_request_high_water = u64::MAX;
        assert_eq!(
            first.encode().unwrap(),
            sign_call(&key, authority, &credential, intent, timing)
                .unwrap()
                .encode()
                .unwrap()
        );
    }

    #[test]
    fn operation_preparation_rejects_wrong_identity_scope_counter_and_timing() {
        let (key, authority, credential, intent, timing) = fixture();
        for case in 0..6 {
            let mut changed = credential.clone();
            match case {
                0 => changed.status = AuthorityCredentialStatus::Revoked,
                1 => changed.kind = AuthorityCredentialKind::Ssh,
                2 => changed.principal = PrincipalId([77; 32]),
                3 => changed.operation_request_high_water = u64::MAX,
                4 => changed.query.authority.space = SpaceId([78; 32]),
                _ => changed.query.nonce = Hash([79; 32]),
            }
            assert!(sign_call(&key, authority, &changed, intent.clone(), timing).is_err());
        }
        let other = libp2p::identity::Keypair::ed25519_from_bytes([80; 32]).unwrap();
        assert!(sign_call(&other, authority, &credential, intent.clone(), timing).is_err());
        for changed in [
            Timing {
                issued_at: 19,
                ..timing
            },
            Timing {
                expires_at: 20,
                ..timing
            },
            Timing {
                valid_from: 22,
                ..timing
            },
        ] {
            assert!(sign_call(&key, authority, &credential, intent.clone(), changed).is_err());
        }
        let mut wrong_caller = intent;
        let AuthorityOperationIntent::InvokeActor { origin, .. } = &mut wrong_caller else {
            unreachable!()
        };
        origin.principal = Some(PrincipalId([81; 32]));
        assert!(sign_call(&key, authority, &credential, wrong_caller, timing).is_err());
    }
}
