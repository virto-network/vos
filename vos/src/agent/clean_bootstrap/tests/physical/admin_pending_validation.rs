//! Validate detached authenticated candidates without adopting their custody.
//! The real fixed-three fixture supplies its live slot and genuine release.

use super::*;
use crate::agent::clean_bootstrap::admin_dispatch::RetainedAuthorityAdminDispatch;
use crate::agent::shared_commit::ReplicaCommitSignature;
use crate::agent::shared_recovery::management::{
    management_last_position, SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
    SharedManagementRecoveryRegistrationRequest, SharedManagementRecoverySlot,
};
use crate::agent::shared_recovery::SharedRecoveryManifest;
use crate::agent_sdk::wire::CanonicalWire as _;

fn sign_registration(
    manifest: &SharedRecoveryManifest,
    owner: HostNodeId,
    origin: HostNodeId,
    members: Vec<SharedManagementRecoveryMember>,
) -> SharedManagementRecoveryRegistration {
    let previous = manifest.management_slot(owner);
    let request = SharedManagementRecoveryRegistrationRequest::new(
        manifest.generation(),
        manifest.committee().id(),
        owner,
        origin,
        previous.map(|slot| slot.sequence() + 1).unwrap_or(1),
        previous.map(|slot| slot.commitment()),
        members,
    )
    .unwrap();
    let expected_key = manifest
        .committee()
        .member_by_node(owner)
        .unwrap()
        .ed25519_public_key();
    let key = [NODE_SEED, 0xd2, 0xd3]
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .into_iter()
        .find(|key| key.verifying_key().to_bytes() == *expected_key)
        .expect("candidate signer must be an actual fixture replica");
    let signature =
        ReplicaCommitSignature::new(owner, key.sign(&request.signing_message().0).to_bytes())
            .unwrap();
    let registration = SharedManagementRecoveryRegistration::new(request, signature).unwrap();
    registration
        .verify(manifest.generation(), manifest.committee())
        .unwrap();
    registration
}

fn apply_detached(
    manifest: &mut SharedRecoveryManifest,
    registration: &SharedManagementRecoveryRegistration,
) -> Result<bool, crate::agent::shared_recovery::SharedRecoveryError> {
    let position = management_last_position(manifest.management_slots());
    manifest.apply_management_registration(registration, position.0 + 1, position.1.max(1))
}

pub(super) fn pending<J: NativeAuthorityAdminJournalStore>(
    owner: &mut MemoryBootstrapOwner,
    retained: &SharedManagementRecoverySlot,
    expected: &RetainedAuthorityAdminDispatch,
    absent: &NativeAuthorityAdminSubmission,
    journal: &mut J,
) -> NativeAuthorityAdminSubmission
where
    J::Error: core::fmt::Debug,
{
    let agent = HostAgentId(owner.pins.agent.0);
    let node = HostNodeId(owner.pins.node.0);
    let submission =
        NativeAuthorityAdminSubmission::new(expected.call.clone(), expected.preparation.clone())
            .unwrap();
    let attempt_before = owner.unpublished_admin_attempt.clone();
    assert_eq!(
        attempt_before.as_ref(),
        Some(&(submission.clone(), expected.envelope.clone()))
    );
    let pending_before = owner
        ._network_host
        .current_management_pending(agent, expected.call.invocation)
        .unwrap();
    let physical_before = native_owner_physical_state(owner);
    let source = owner.host.lock().unwrap().recovery_manifest(agent).unwrap();
    assert_eq!(source.management_slot(node), Some(retained));
    assert!(journal.load(expected.call.invocation).unwrap().is_none());
    let validate = |slot: &SharedManagementRecoverySlot, work: &RuntimeWork, local: HostNodeId| {
        RetainedAuthorityAdminDispatch::from_live_pending_slot(
            &submission,
            work,
            local,
            slot,
            &[],
            &[],
        )
    };
    assert_eq!(
        validate(retained, &expected.envelope, node).unwrap(),
        *expected
    );
    let shadow_owner = source
        .committee()
        .members()
        .iter()
        .map(|member| member.replica().node)
        .find(|candidate| *candidate != node)
        .unwrap();
    assert!(source
        .management_slot(shadow_owner)
        .is_none_or(|slot| slot.is_released()));
    {
        let mut shadow = source.clone();
        let registration =
            sign_registration(&shadow, shadow_owner, node, retained.members().to_vec());
        assert!(apply_detached(&mut shadow, &registration).unwrap());
        let authenticated_before = shadow.clone();
        let slot = shadow.management_slot(shadow_owner).unwrap();
        assert_eq!(slot.origin_owner(), node);
        for local in [node, shadow_owner] {
            assert!(matches!(
                validate(slot, &expected.envelope, local),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
        }
        assert_eq!(shadow, authenticated_before);
    }
    let child_work = {
        // Add one valid signed dependency to the complete immutable prefix.
        // This is an authenticated candidate, not a guest execution or commit.
        let mut child_work = expected.envelope.clone();
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } = &mut child_work
        else {
            unreachable!()
        };
        invocation.invocation = absent.call().invocation;
        invocation.message = dynamic_message(
            "administer",
            "call",
            crate::actors::value::Value::Bytes(absent.call().encode().unwrap()),
        );
        *observed_slot = absent.preparation().observed_slot();
        **authorization = InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
        );
        let child_record = RetainedAuthorityAdminDispatch {
            call: absent.call().clone(),
            preparation: absent.preparation().clone(),
            envelope: child_work.clone(),
            anchor: expected.anchor.clone(),
        };
        child_record.encode().unwrap();
        let child = SharedManagementRecoveryMember::new(
            Some(retained.members()[0].commitment()),
            expected.anchor.clone(),
            child_work.clone(),
        )
        .unwrap();
        let mut family = source.clone();
        let registration = sign_registration(
            &family,
            node,
            node,
            vec![retained.members()[0].clone(), child],
        );
        assert!(apply_detached(&mut family, &registration).unwrap());
        let authenticated_before = family.clone();
        let slot = family.management_slot(node).unwrap();
        assert_eq!(slot.members().len(), 2);
        assert!(matches!(
            validate(slot, &expected.envelope, node),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
        assert_eq!(family, authenticated_before);
        child_work
    };
    {
        // Keep the otherwise admissible shadow registration unchanged while
        // substituting only its claimed original owner.
        let registration = sign_registration(
            &source,
            shadow_owner,
            shadow_owner,
            retained.members().to_vec(),
        );
        let mut wrong_origin = source.clone();
        assert!(apply_detached(&mut wrong_origin, &registration).is_err());
        assert_eq!(wrong_origin, source);
    }
    let pair = (expected.anchor.clone(), expected.envelope.clone());
    assert!(matches!(
        RetainedAuthorityAdminDispatch::from_live_pending_slot(
            &submission,
            &expected.envelope,
            node,
            retained,
            core::slice::from_ref(&pair),
            &[],
        ),
        Err(SharedAgentHostError::Conflict)
    ));
    // Both envelopes are canonical signed members of the admitted detached
    // family above. This is a pure exclusion check, not a live retirement cut.
    let retiring = [[expected.envelope.clone(), child_work]];
    assert!(matches!(
        RetainedAuthorityAdminDispatch::from_live_pending_slot(
            &submission,
            &expected.envelope,
            node,
            retained,
            &[],
            &retiring,
        ),
        Err(SharedAgentHostError::Conflict)
    ));
    let mut changed_work = expected.envelope.clone();
    let RuntimeWork::Invoke {
        invocation,
        authorization,
        observed_slot,
        ..
    } = &mut changed_work
    else {
        unreachable!()
    };
    assert!(invocation.gas > 1);
    invocation.gas -= 1;
    **authorization = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
    );
    let substituted = RetainedAuthorityAdminDispatch {
        envelope: changed_work.clone(),
        ..expected.clone()
    };
    substituted.encode().unwrap();
    assert!(matches!(
        validate(retained, &changed_work, node),
        Err(SharedAgentHostError::ScopeMismatch)
    ));
    for (anchor, envelope) in [
        (expected.anchor.clone(), changed_work.clone()),
        (
            {
                let mut anchor = expected.anchor.clone();
                anchor.ordered.index += 1;
                anchor
            },
            expected.envelope.clone(),
        ),
    ] {
        let member = SharedManagementRecoveryMember::new(None, anchor, envelope).unwrap();
        let registration = sign_registration(&source, shadow_owner, node, vec![member]);
        let mut substituted = source.clone();
        assert!(apply_detached(&mut substituted, &registration).is_err());
        assert_eq!(substituted, source);
    }
    if pending_before.is_none() {
        // Exercise the real B restore seam with a rejected pure validator.
        // The following original positive retry must still recover normally.
        assert!(matches!(
            owner
                ._network_host
                .retained_management_pending_with_validation(
                    agent,
                    expected.call.invocation,
                    |slot, pending, retiring| {
                        RetainedAuthorityAdminDispatch::from_live_pending_slot(
                            &submission,
                            &changed_work,
                            node,
                            slot,
                            pending,
                            retiring,
                        )
                        .map(|_| ())
                    },
                ),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
    }
    assert_eq!(owner.unpublished_admin_attempt, attempt_before);
    assert_eq!(
        owner
            ._network_host
            .current_management_pending(agent, expected.call.invocation)
            .unwrap(),
        pending_before
    );
    assert_eq!(native_owner_physical_state(owner), physical_before);
    assert_eq!(
        owner.host.lock().unwrap().recovery_manifest(agent).unwrap(),
        source
    );
    assert!(journal.load(expected.call.invocation).unwrap().is_none());
    assert!(journal.load(absent.call().invocation).unwrap().is_none());
    submission
}

pub(super) fn released(
    submission: &NativeAuthorityAdminSubmission,
    work: &RuntimeWork,
    node: HostNodeId,
    slot: &SharedManagementRecoverySlot,
) {
    assert!(slot.is_released());
    assert!(slot.members_evidence()[0].invoke().is_some());
    assert!(slot.members_evidence()[0].acknowledgement().is_some());
    let before = slot.clone();
    assert!(matches!(
        RetainedAuthorityAdminDispatch::from_live_pending_slot(
            submission,
            work,
            node,
            slot,
            &[],
            &[]
        ),
        Err(SharedAgentHostError::ScopeMismatch)
    ));
    assert_eq!(*slot, before);
}
