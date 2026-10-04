//! Detached authenticated candidates and refusal before volatile restoration.
//! Every live input comes from the actual fixed-three preparation cut. These
//! copied registrations are never published, executed, issued or released.

use super::*;
use super::super::admin_pending_validation::{apply_detached, sign_registration};
use crate::agent::clean_management_intent::ManagementJournalAnchor;
use crate::agent::shared_recovery::management::{
    SharedManagementRecoveryMember, SharedManagementRecoverySlot,
};
use crate::agent_sdk::wire::CanonicalWire as _;

fn variant(
    request: &AuthorityOperationActorDispatch,
    envelope: &RuntimeWork,
    anchor: &ManagementJournalAnchor,
) -> RetainedAuthorityOperationDispatch {
    // Reuse the canonical existing NOD1 frame; no production constructor or
    // signature-admission path is bypassed. Decode verifies its whole shape.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&RetainedAuthorityOperationDispatch::MAGIC);
    bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = vos_protocol::wire::Encoder(&mut bytes);
    encoder.u8(request.method as u8);
    encoder.bytes(&request.request);
    encoder.bytes(&envelope.encode().unwrap());
    encoder.bytes(&anchor.encode());
    let record = RetainedAuthorityOperationDispatch::decode(&bytes).unwrap();
    assert!(record.encode().unwrap() == bytes);
    assert!(record.request() == request);
    record
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn pending(
    owner: &mut MemoryBootstrapOwner,
    operations: &mut NativeAuthorityOperationController<OperationTestImageFile, OperationTestImageFile, Journal>,
    slot: &SharedManagementRecoverySlot,
    request: &AuthorityOperationActorDispatch,
    original_work: &RuntimeWork,
    original_anchor: &ManagementJournalAnchor,
    absent_call: &AuthorityOperationCall,
    changed_call: &AuthorityOperationCall,
    journal_path: &std::path::Path,
    coordinator_path: &std::path::Path,
    issuer_path: &std::path::Path,
    writes: &AtomicUsize,
    original_journal: Option<&[u8]>,
) {
    let agent = HostAgentId(owner.pins.agent.0);
    let node = HostNodeId(owner.pins.node.0);
    let expected = owner.unpublished_operation_attempt.clone().unwrap();
    assert!(expected.request() == request);
    assert!(expected.envelope() == original_work);
    assert!(expected.anchor() == original_anchor);
    let pending_before = owner._network_host.current_management_pending(agent, request.context.invocation).unwrap();
    let state_before = owner.host.lock().unwrap().clean_state_commitment(agent).unwrap();
    let position_before = owner.host.lock().unwrap().journal_position(agent).unwrap();
    let source = owner.host.lock().unwrap().recovery_manifest(agent).unwrap();
    assert!(source.management_slot(node) == Some(slot));
    let writes_before = writes.load(Ordering::Acquire);
    let validate = |candidate: &SharedManagementRecoverySlot, expected: &RetainedAuthorityOperationDispatch, local: HostNodeId| {
        RetainedAuthorityOperationDispatch::from_live_pending_slot(expected, local, candidate, &[], &[])
    };
    assert!(validate(slot, &expected, node).unwrap() == expected);
    let original_pair = (original_anchor.clone(), original_work.clone());
    // The actual prewrite member may remain in the map. Its exact singleton
    // is admissible, while complete-family checks must still execute.
    assert!(RetainedAuthorityOperationDispatch::from_live_pending_slot(
        &expected, node, slot, core::slice::from_ref(&original_pair), &[],
    ).unwrap() == expected);
    let shadow_owner = source.committee().members().iter().map(|member| member.replica().node)
        .find(|candidate| *candidate != node).unwrap();
    assert!(source.management_slot(shadow_owner).is_none_or(|slot| slot.is_released()));
    {
        let mut shadow = source.clone();
        let signed = sign_registration(&shadow, shadow_owner, node, slot.members().to_vec());
        assert!(apply_detached(&mut shadow, &signed).unwrap());
        let authenticated_before = shadow.clone();
        let shadow_slot = shadow.management_slot(shadow_owner).unwrap();
        for local in [node, shadow_owner] {
            assert!(matches!(validate(shadow_slot, &expected, local), Err(SharedAgentHostError::ScopeMismatch)));
        }
        assert!(shadow == authenticated_before);
    }
    let child_work = {
        // This separately signed call creates a canonical dependency member,
        // with no assertion that its policy was authorized or executed.
        absent_call.verify_api_with(&RawCredentialVerifier).unwrap();
        let mut child_work = original_work.clone();
        let RuntimeWork::Invoke { invocation, authorization, observed_slot, .. } = &mut child_work else { unreachable!() };
        invocation.invocation = absent_call.invocation;
        invocation.message = dynamic_message("authorize_operation", "call", crate::actors::value::Value::Bytes(absent_call.encode().unwrap()));
        **authorization = InvocationAuthorization::PublicPreflight(crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot));
        let child_request = AuthorityOperationActorDispatch {
            context: InvocationContext { invocation: absent_call.invocation, ..request.context },
            request: absent_call.encode().unwrap(),
            ..request.clone()
        };
        variant(&child_request, &child_work, original_anchor);
        let child = SharedManagementRecoveryMember::new(
            Some(slot.members()[0].commitment()), original_anchor.clone(), child_work.clone(),
        ).unwrap();
        let mut family = source.clone();
        let signed = sign_registration(&family, node, node, vec![slot.members()[0].clone(), child]);
        assert!(apply_detached(&mut family, &signed).unwrap());
        let authenticated_before = family.clone();
        let family_slot = family.management_slot(node).unwrap();
        assert_eq!(family_slot.members().len(), 2);
        assert!(matches!(validate(family_slot, &expected, node), Err(SharedAgentHostError::ScopeMismatch)));
        assert!(family == authenticated_before);
        child_work
    };
    {
        let signed = sign_registration(&source, shadow_owner, shadow_owner, slot.members().to_vec());
        let mut wrong_origin = source.clone();
        assert!(apply_detached(&mut wrong_origin, &signed).is_err());
        assert!(wrong_origin == source);
    }
    let child_pair = (original_anchor.clone(), child_work.clone());
    for pending in [vec![child_pair], vec![original_pair.clone(), original_pair.clone()]] {
        assert!(matches!(RetainedAuthorityOperationDispatch::from_live_pending_slot(
            &expected, node, slot, &pending, &[],
        ), Err(SharedAgentHostError::Conflict)));
    }
    // Only pure nonempty-retirement exclusion is tested. These canonical
    // signed dependency envelopes are no live Invoke/positive-ACK pair.
    let retiring = [[original_work.clone(), child_work]];
    assert!(matches!(RetainedAuthorityOperationDispatch::from_live_pending_slot(
        &expected, node, slot, &[], &retiring,
    ), Err(SharedAgentHostError::Conflict)));
    let mut gas_changed = original_work.clone();
    let RuntimeWork::Invoke { invocation, authorization, observed_slot, .. } = &mut gas_changed else { unreachable!() };
    assert!(invocation.gas > 1);
    invocation.gas -= 1;
    **authorization = InvocationAuthorization::PublicPreflight(crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot));
    let gas_record = variant(request, &gas_changed, original_anchor);
    let mut clock_changed = original_work.clone();
    let RuntimeWork::Invoke { invocation, authorization, observed_slot, .. } = &mut clock_changed else { unreachable!() };
    let signed_call = AuthorityOperationCall::decode(&request.request).unwrap();
    *observed_slot = if *observed_slot < signed_call.requested_expires_at {
        observed_slot.checked_add(1).unwrap()
    } else {
        assert!(*observed_slot > signed_call.requested_valid_from);
        observed_slot.checked_sub(1).unwrap()
    };
    **authorization = InvocationAuthorization::PublicPreflight(crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot));
    let clock_request = AuthorityOperationActorDispatch {
        context: InvocationContext { observed_slot: *observed_slot, ..request.context },
        ..request.clone()
    };
    let clock_record = variant(&clock_request, &clock_changed, original_anchor);
    let mut anchor_changed = original_anchor.clone();
    anchor_changed.ordered.index = anchor_changed.ordered.index.checked_add(1).unwrap();
    let anchor_record = variant(request, original_work, &anchor_changed);
    for substituted in [&gas_record, &clock_record, &anchor_record] {
        assert!(matches!(validate(slot, substituted, node), Err(SharedAgentHostError::ScopeMismatch)));
        // Exercise the actual strict host seam both with a held prewrite map
        // and without a map after a late registration. Refusal restores none.
        assert!(matches!(owner._network_host.retained_management_pending_with_validation(
            agent, request.context.invocation, |slot, pending, retiring| {
                RetainedAuthorityOperationDispatch::from_live_pending_slot(substituted, node, slot, pending, retiring).map(|_| ())
            },
        ), Err(SharedAgentHostError::ScopeMismatch)));
    }
    for unmatched in [absent_call, changed_call] {
        unmatched.verify_api_with(&RawCredentialVerifier).unwrap();
        assert!(matches!(operations.prepare_call(owner, unmatched), Err(SharedAgentHostError::Conflict)));
    }
    assert!(owner.unpublished_operation_attempt.as_ref() == Some(&expected));
    assert!(owner._network_host.current_management_pending(agent, request.context.invocation).unwrap() == pending_before);
    assert!(owner.host.lock().unwrap().recovery_manifest(agent).unwrap() == source);
    assert!(owner.host.lock().unwrap().clean_state_commitment(agent).unwrap() == state_before);
    assert!(owner.host.lock().unwrap().journal_position(agent).unwrap() == position_before);
    assert_eq!(writes.load(Ordering::Acquire), writes_before);
    let mut view = OperationTestJournal(journal_path.to_path_buf());
    assert!(view.load(request.context.invocation).unwrap().as_deref() == original_journal);
    for id in [absent_call.invocation, changed_call.invocation] {
        assert!(view.load(id).unwrap().is_none());
    }
    assert!(!coordinator_path.exists());
    assert!(!issuer_path.exists());
}
