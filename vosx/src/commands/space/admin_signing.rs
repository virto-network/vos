//! Deterministic admin signing from selected, verified discovery and NAP1.
use super::{clean_identity::CleanOperatorIdentitySigner, local_create::CredentialVerifier};
use vos::agent::clean_bootstrap::{
    NativeAuthorityAdminPreparation, NativeAuthorityAdminSubmission,
};
use vos::agent::sdk::{InvocationId, NodeId, authority::*};

/// Discovery is not policy approval. The caller owns a credential-local admin
/// lease and must durably retain this draft before host preparation.
pub(crate) fn draft(
    operator: &libp2p::identity::Keypair,
    authority: AuthorityActorTarget,
    node: NodeId,
    credential: &AuthorityCredentialProjection,
    operation: AuthorityAdminOperation,
) -> anyhow::Result<AuthorityAdminCall> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        credential.validate_shape().is_ok()
            && credential.query.authority == authority
            && credential.query.credential == identity.credential()
            && credential.query.selector == AuthorityProjectionSelector::Credential
            && credential.principal == identity.principal()
            && credential.status == AuthorityCredentialStatus::Active
            && credential.kind == AuthorityCredentialKind::Api
            && credential.builtin_role == AuthorityBuiltinRole::Admin
            && credential
                .query
                .verify_api_with(&CredentialVerifier)
                .is_ok(),
        "admin signing requires the selected operator's active Admin API credential projection"
    );
    let request_sequence = credential
        .admin_request_high_water
        .checked_add(1)
        .and_then(core::num::NonZeroU64::new)
        .ok_or_else(|| anyhow::anyhow!("admin sequence exhausted"))?;
    let mut call = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority,
        administrator: identity.principal(),
        credential: identity.credential(),
        request_sequence,
        credential_public_key: identity.raw_public_key(),
        authenticated_node: node,
        observed_slot: 0,
        expected_generation: credential.head.administration_generation,
        operation,
        signature: [1; 64],
    };
    call.invocation = call.expected_invocation();
    call.validate_shape()
        .map_err(|e| anyhow::anyhow!("invalid admin draft: {e:?}"))?;
    call.signature = operator
        .sign(&call.signing_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid admin signature length"))?;
    call.verify_with(&CredentialVerifier)
        .map_err(|e| anyhow::anyhow!("invalid signed admin draft: {e:?}"))?;
    Ok(call)
}

/// Only the retained draft and retained host response participate in final
/// signing. No clock, random ID, discovery or generation is refreshed here.
pub(crate) fn prepared(
    operator: &libp2p::identity::Keypair,
    draft: &AuthorityAdminCall,
    preparation: &NativeAuthorityAdminPreparation,
) -> anyhow::Result<NativeAuthorityAdminSubmission> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        draft.credential_public_key == identity.raw_public_key()
            && draft.credential == identity.credential()
            && draft.administrator == identity.principal(),
        "admin draft belongs to another operator"
    );
    let mut call = preparation
        .call_to_sign(draft)
        .map_err(|e| anyhow::anyhow!("invalid admin preparation: {e:?}"))?;
    call.signature = operator
        .sign(&call.signing_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid admin signature length"))?;
    NativeAuthorityAdminSubmission::new(call, preparation.clone())
        .map_err(|e| anyhow::anyhow!("invalid signed admin submission: {e:?}"))
}
