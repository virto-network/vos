//! Detached authenticated Local Install families and guarded refusal-before-restore.
//! No candidate below is published to the live replicated custody manifest.

use super::super::admin_pending_validation::{apply_detached, sign_registration};
use super::*;
use crate::agent::clean_management_intent::CleanManagementIntent;
use crate::agent::shared_recovery::management::{
    SharedManagementRecoveryMember, SharedManagementRecoverySlot,
};

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn pending(
    controller: &mut Controller,
    retained: &SharedManagementRecoverySlot,
    intent: &CleanManagementIntent,
    expected_work: &RuntimeWork,
    intent_store: &IssuerMemoryStore,
    issuer_store: &IssuerMemoryStore,
) {
    let mut owner = controller.system_for_test();
    let agent = HostAgentId(owner.pins.agent.0);
    let node = HostNodeId(owner.pins.node.0);
    let marker_before = owner.unpublished_local_install_attempt.clone();
    assert!(marker_before == Some((intent.clone(), Some(expected_work.clone()))));
    let pending_before = owner
        ._network_host
        .current_management_pending(agent, intent.call().invocation)
        .unwrap();
    let state_before = owner
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    let source = owner.host.lock().unwrap().recovery_manifest(agent).unwrap();
    assert!(source.management_slot(node) == Some(retained));
    let intent_before = intent_store.image.lock().unwrap().clone();
    let actor_before = intent_store.actor.lock().unwrap().clone();
    let issuer_before = issuer_store.image.lock().unwrap().clone();
    let validate = |slot: &SharedManagementRecoverySlot, work: &RuntimeWork, local: HostNodeId| {
        MemoryBootstrapOwner::validate_live_local_install_member(
            intent,
            work,
            local,
            slot,
            &[],
            &[],
        )
    };
    validate(retained, expected_work, node).unwrap();
    let shadow_owner = source
        .committee()
        .members()
        .iter()
        .map(|member| member.replica().node)
        .find(|candidate| *candidate != node)
        .unwrap();
    assert!(
        source
            .management_slot(shadow_owner)
            .is_none_or(|slot| slot.is_released())
    );
    {
        let mut shadow = source.clone();
        let signed = sign_registration(&shadow, shadow_owner, node, retained.members().to_vec());
        assert!(apply_detached(&mut shadow, &signed).unwrap());
        let authenticated_before = shadow.clone();
        let slot = shadow.management_slot(shadow_owner).unwrap();
        for local in [node, shadow_owner] {
            assert!(matches!(
                validate(slot, expected_work, local),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
        }
        assert!(shadow == authenticated_before);
    }
    let child_work = {
        // A complete separately signed Install call creates a canonical
        // dependency member. It is never authorized or executed by this test.
        let mut call = intent.call().clone();
        call.request_sequence = NonZeroU64::new(call.request_sequence.get() + 1).unwrap();
        call.invocation = call.expected_invocation();
        call.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
            .sign(&call.signing_bytes())
            .to_bytes();
        call.verify_with(&RawCredentialVerifier).unwrap();
        let child_intent = CleanManagementIntent::new(
            call.authority,
            call.managed,
            intent.request().clone(),
            call,
            &RawCredentialVerifier,
        )
        .unwrap();
        let mut work = expected_work.clone();
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } = &mut work
        else {
            unreachable!()
        };
        invocation.invocation = child_intent.call().invocation;
        invocation.origin = child_intent.authorization_origin();
        invocation.message = child_intent.authorization_message();
        **authorization = InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
        );
        assert!(
            child_intent.validates_unpledged_authorization(&work, retained.members()[0].anchor())
        );
        let child = SharedManagementRecoveryMember::new(
            Some(retained.members()[0].commitment()),
            retained.members()[0].anchor().clone(),
            work.clone(),
        )
        .unwrap();
        let mut family = source.clone();
        let signed = sign_registration(
            &family,
            node,
            node,
            vec![retained.members()[0].clone(), child],
        );
        assert!(apply_detached(&mut family, &signed).unwrap());
        let authenticated_before = family.clone();
        let slot = family.management_slot(node).unwrap();
        assert_eq!(slot.members().len(), 2);
        assert!(matches!(
            validate(slot, expected_work, node),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
        assert!(family == authenticated_before);
        work
    };
    {
        // A genuine signature cannot replace the independently retained first
        // original owner. Admission rejects this complete candidate unchanged.
        let signed = sign_registration(
            &source,
            shadow_owner,
            shadow_owner,
            retained.members().to_vec(),
        );
        let mut wrong_origin = source.clone();
        assert!(apply_detached(&mut wrong_origin, &signed).is_err());
        assert!(wrong_origin == source);
    }
    let pair = (
        retained.members()[0].anchor().clone(),
        expected_work.clone(),
    );
    assert!(matches!(
        MemoryBootstrapOwner::validate_live_local_install_member(
            intent,
            expected_work,
            node,
            retained,
            core::slice::from_ref(&pair),
            &[]
        ),
        Err(SharedAgentHostError::Conflict)
    ));
    // This canonical signed dependency pair tests only the pure nonempty
    // retirement exclusion; it is no live terminal/finalization pair.
    let retiring = [[expected_work.clone(), child_work]];
    assert!(matches!(
        MemoryBootstrapOwner::validate_live_local_install_member(
            intent,
            expected_work,
            node,
            retained,
            &[],
            &retiring
        ),
        Err(SharedAgentHostError::Conflict)
    ));
    let mut gas_changed = expected_work.clone();
    let RuntimeWork::Invoke {
        invocation,
        authorization,
        observed_slot,
        ..
    } = &mut gas_changed
    else {
        unreachable!()
    };
    assert!(invocation.gas > 1);
    invocation.gas -= 1;
    **authorization = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
    );
    let mut clock_changed = expected_work.clone();
    let RuntimeWork::Invoke {
        invocation,
        authorization,
        observed_slot,
        ..
    } = &mut clock_changed
    else {
        unreachable!()
    };
    *observed_slot += 1;
    **authorization = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
    );
    let mut wrong_anchor = retained.members()[0].anchor().clone();
    wrong_anchor.ordered.index += 1;
    for (anchor, work) in [
        (retained.members()[0].anchor().clone(), gas_changed.clone()),
        (retained.members()[0].anchor().clone(), clock_changed),
        (wrong_anchor, expected_work.clone()),
    ] {
        assert_eq!(
            match &work {
                RuntimeWork::Invoke { invocation, .. } => invocation.invocation,
                _ => unreachable!(),
            },
            intent.call().invocation,
        );
        let member = SharedManagementRecoveryMember::new(None, anchor, work.clone()).unwrap();
        let signed = sign_registration(&source, shadow_owner, node, vec![member]);
        let mut substituted = source.clone();
        assert!(apply_detached(&mut substituted, &signed).is_err());
        assert!(substituted == source);
        if &work != expected_work {
            assert!(matches!(
                validate(retained, &work, node),
                Err(SharedAgentHostError::ScopeMismatch)
            ));
        }
    }
    if pending_before.is_none() {
        // Exercise the actual B guarded-restore method with a rejected pure
        // validator. No reservation or proposal may be restored on refusal.
        assert!(matches!(
            owner
                ._network_host
                .retained_management_pending_with_validation(
                    agent,
                    intent.call().invocation,
                    |slot, pending, retiring| {
                        MemoryBootstrapOwner::validate_live_local_install_member(
                            intent,
                            &gas_changed,
                            node,
                            slot,
                            pending,
                            retiring,
                        )
                    },
                ),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
    }
    assert!(owner.unpublished_local_install_attempt == marker_before);
    assert!(
        owner
            ._network_host
            .current_management_pending(agent, intent.call().invocation)
            .unwrap()
            == pending_before
    );
    assert!(
        owner
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap()
            == state_before
    );
    assert!(owner.host.lock().unwrap().recovery_manifest(agent).unwrap() == source);
    assert!(intent_store.image.lock().unwrap().clone() == intent_before);
    assert!(intent_store.actor.lock().unwrap().clone() == actor_before);
    assert!(issuer_store.image.lock().unwrap().clone() == issuer_before);
}

pub(super) fn released(
    intent: &CleanManagementIntent,
    expected_work: &RuntimeWork,
    node: HostNodeId,
    slot: &SharedManagementRecoverySlot,
) {
    assert!(slot.is_released());
    assert!(
        slot.members_evidence()
            .iter()
            .all(|evidence| evidence.invoke().is_some() && evidence.acknowledgement().is_some())
    );
    let before = slot.clone();
    assert!(matches!(
        MemoryBootstrapOwner::validate_live_local_install_member(
            intent,
            expected_work,
            node,
            slot,
            &[],
            &[]
        ),
        Err(SharedAgentHostError::ScopeMismatch)
    ));
    assert!(*slot == before);
}
