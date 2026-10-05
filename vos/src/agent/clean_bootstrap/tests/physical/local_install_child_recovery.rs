//! Genuine registered finalization child before its independent CMI pledge.
//! Uses the existing fixed-three transports/images and original non-clone
//! MEMORY LeaseStores; no filesystem lease or public CLI qualification claim.

use super::*;
use crate::actors::codec::Decode as _;
use crate::agent_sdk::wire::CanonicalWire as _;
use ed25519_dalek::Signer as _;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn exercise(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    mut controller: Controller,
    descriptor: &AgentDescriptor,
    install: &crate::agent_sdk::InstallActor,
    call: &AuthorityCredentialCall,
    package: &AdmittedActorPackage,
    request: &ManagementRequest,
    intent_store: &IssuerMemoryStore,
    issuer_store: &IssuerMemoryStore,
    intent_fault: &Arc<Mutex<Fault>>,
    issuer_fault: &Arc<Mutex<Fault>>,
    opens: &Arc<AtomicUsize>,
    live: &Arc<AtomicUsize>,
    image_path: &std::path::Path,
    request_path: &std::path::Path,
    preceding_issuer: &Option<Vec<u8>>,
    started: std::time::Instant,
    deadline: std::time::Instant,
) {
    intent_fault.lock().unwrap().refuse_install_finalization_before_write_once();
    retry_until(deadline, "Local finalization pledge prewrite cut", || {
        let result = controller.install(install.clone(), call.clone(), package.clone());
        if intent_fault.lock().unwrap().install_finalization_prewrite_failures() == 1 {
            assert!(matches!(result, Err(SharedAgentHostError::Unavailable)));
            Ok(())
        } else {
            result.map(|_| panic!("finalization cut must precede independent CMI pledge"))
        }
    });
    let slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    let intent = slot.intent().unwrap();
    assert!(intent.request() == request && intent.call() == call);
    let root_anchor = slot.authorization_anchor().unwrap().unwrap().clone();
    let root_work = slot.authorization_work().unwrap().unwrap().clone();
    assert!(slot.finalization_anchor().unwrap().is_none());
    assert!(slot.finalization_work().unwrap().is_none());
    assert!(!slot.retirement_complete().unwrap());
    assert!(slot.load_actor().unwrap().unwrap().exact_bytes() == package.exact_bytes());
    let (host, agent, node, retained, state, root_pending, child_pending) = {
        let original = controller.system_for_test();
        let agent = HostAgentId(original.pins.agent.0);
        let node = HostNodeId(original.pins.node.0);
        let host = Arc::clone(&original.host);
        let manifest = original._network_host.management_recovery_manifest(agent).unwrap();
        let retained = manifest.management_slot(node).unwrap().clone();
        assert!(retained.owner() == node && retained.origin_owner() == node);
        assert!(!retained.is_released());
        assert_eq!(retained.members().len(), 2);
        assert!(retained.members()[0].parent().is_none());
        assert!(retained.members()[0].anchor() == &root_anchor);
        assert!(retained.members()[0].envelope() == &root_work);
        assert!(retained.members()[1].parent() == Some(retained.members()[0].commitment()));
        assert!(retained.members_evidence()[0].invoke().is_some());
        assert!(retained.members_evidence()[1].invoke().is_none());
        assert!(retained.members_evidence()[1].acknowledgement().is_none());
        let root_pending = original._network_host
            .current_management_pending(agent, call.invocation).unwrap();
        let child_pending = original._network_host.current_management_pending(
            agent, retained.members()[1].work().invocation,
        ).unwrap();
        assert!(root_pending == Some((root_anchor.clone(), root_work.clone())));
        assert!(child_pending == Some((
            retained.members()[1].anchor().clone(), retained.members()[1].envelope().clone(),
        )));
        let state = host.lock().unwrap().clean_state_commitment(agent).unwrap();
        (host, agent, node, retained, state, root_pending, child_pending)
    };
    let child = retained.members()[1].clone();
    let message = crate::actors::value::Msg::try_decode(&child.work().message[1..]).unwrap();
    let Some(crate::actors::value::Value::Bytes(bytes)) = message.args.get("ack") else {
        panic!("real finalization child requires canonical ACK bytes");
    };
    let acknowledgement = ManagementApplicationAck::decode(bytes).unwrap();
    acknowledgement.verify_with(&RawCredentialVerifier).unwrap();
    let issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(), descriptor.authority, descriptor.identity.space, descriptor.identity.agent,
    ).unwrap();
    let (receipt, saved) = issuer.recover_observed_application(
        call.authority, call.managed, request, call, &RawCredentialVerifier,
    ).unwrap().unwrap();
    assert!(saved == acknowledgement);
    assert!(!issuer.application_finalization_status(&saved).unwrap());
    drop(issuer);
    let intent_image = intent_store.image.lock().unwrap().clone();
    let issuer_image = issuer_store.image.lock().unwrap().clone();
    let physical_image = std::fs::read(image_path).unwrap();
    let original_request = std::fs::read(request_path).unwrap();
    let intent_writes = intent_fault.lock().unwrap().committed_writes();
    let issuer_writes = issuer_fault.lock().unwrap().committed_writes();
    let unchanged = |controller: &Controller, issuer_bytes: &Option<Vec<u8>>, image: &[u8]| {
        assert!(std::time::Instant::now() <= deadline);
        assert!(intent_store.image.lock().unwrap().clone() == intent_image);
        assert!(intent_store.actor.lock().unwrap().as_deref() == Some(package.exact_bytes()));
        assert!(issuer_store.image.lock().unwrap().clone() == *issuer_bytes);
        assert!(std::fs::read(image_path).unwrap() == image);
        assert!(std::fs::read(request_path).unwrap() == original_request);
        assert_eq!(intent_fault.lock().unwrap().committed_writes(), intent_writes);
        assert_eq!(issuer_fault.lock().unwrap().committed_writes(), issuer_writes);
        assert_eq!(opens.load(Ordering::Acquire), 1);
        assert_eq!(live.load(Ordering::Acquire), 2);
        let original = controller.system_for_test();
        assert!(original._network_host.management_recovery_manifest(agent).unwrap()
            .management_slot(node) == Some(&retained));
        assert!(original._network_host.current_management_pending(agent, call.invocation).unwrap()
            == root_pending);
        assert!(original._network_host.current_management_pending(agent, child.work().invocation).unwrap()
            == child_pending);
        assert!(host.lock().unwrap().clean_state_commitment(agent).unwrap() == state);
        assert!(std::time::Instant::now() <= deadline);
    };
    assert!(matches!(controller.system_for_test().retained_local_install_family(&slot),
        Err(SharedAgentHostError::ScopeMismatch)));
    drop(slot);
    let reads = issuer_fault.lock().unwrap().loaded_reads();
    assert!(controller.retains_local_install(install, call, package).unwrap());
    assert_eq!(issuer_fault.lock().unwrap().loaded_reads(), reads + 1);
    unchanged(&controller, &issuer_image, &physical_image);

    // Remove only this disposable fixture's observed ACK by substituting its
    // authentic earlier Create journal. Restore exact original bytes afterward;
    // this fault restoration is not a supported recovery or adoption mechanism.
    *issuer_store.image.lock().unwrap() = preceding_issuer.clone();
    let reads = issuer_fault.lock().unwrap().loaded_reads();
    assert!(matches!(controller.retains_local_install(install, call, package),
        Err(SharedAgentHostError::ScopeMismatch)));
    assert_eq!(issuer_fault.lock().unwrap().loaded_reads(), reads + 1);
    unchanged(&controller, preceding_issuer, &physical_image);
    *issuer_store.image.lock().unwrap() = issuer_image.clone();

    // A validly signed alternate ACK for the same call/receipt is canonical
    // issuer data, but cannot replace the actual registered child's exact ACK.
    let mut changed = acknowledgement.clone();
    changed.reopened_state.0[0] ^= 1;
    changed.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&changed.signing_bytes()).to_bytes();
    changed.verify_with(&RawCredentialVerifier).unwrap();
    let original_ack = acknowledgement.encode().unwrap();
    let changed_ack = changed.encode().unwrap();
    assert_eq!(original_ack.len(), changed_ack.len());
    let mut changed_image = issuer_image.clone().unwrap();
    let positions = changed_image.windows(original_ack.len()).enumerate()
        .filter_map(|(index, bytes)| (bytes == original_ack).then_some(index)).collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    changed_image[positions[0]..positions[0] + changed_ack.len()].copy_from_slice(&changed_ack);
    *issuer_store.image.lock().unwrap() = Some(changed_image.clone());
    let alternate = DurableCleanManagementIssuer::open(
        issuer_store.clone(), descriptor.authority, descriptor.identity.space, descriptor.identity.agent,
    ).unwrap();
    assert!(alternate.recover_observed_application(
        call.authority, call.managed, request, call, &RawCredentialVerifier,
    ).unwrap() == Some((receipt, changed)));
    drop(alternate);
    let reads = issuer_fault.lock().unwrap().loaded_reads();
    assert!(matches!(controller.retains_local_install(install, call, package),
        Err(SharedAgentHostError::ScopeMismatch)));
    assert_eq!(issuer_fault.lock().unwrap().loaded_reads(), reads + 1);
    unchanged(&controller, &Some(changed_image), &physical_image);
    *issuer_store.image.lock().unwrap() = issuer_image.clone();

    // The real callback reaches the normal physical observer (issuer read
    // counted), which must refuse a substituted disk image. This proves
    // corruption refusal, not each typed result/state/clock comparison branch.
    let mut damaged = physical_image.clone();
    *damaged.last_mut().unwrap() ^= 1;
    std::fs::write(image_path, &damaged).unwrap();
    let reads = issuer_fault.lock().unwrap().loaded_reads();
    assert!(matches!(controller.retains_local_install(install, call, package),
        Err(SharedAgentHostError::Unavailable)));
    assert_eq!(issuer_fault.lock().unwrap().loaded_reads(), reads + 1);
    unchanged(&controller, &issuer_image, &damaged);
    std::fs::write(image_path, &physical_image).unwrap();
    assert!(controller.retains_local_install(install, call, package).unwrap());
    unchanged(&controller, &issuer_image, &physical_image);
    eprintln!("fixed_three_local_install phase=registered_child_callback_verified elapsed_ms={}",
        started.elapsed().as_millis());

    let result = retry_until(deadline, "Local original child exact retry", || {
        controller.install(install.clone(), call.clone(), package.clone())
    });
    assert!(result == acknowledgement);
    let slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    assert!(slot.authorization_anchor().unwrap() == Some(&root_anchor));
    assert!(slot.authorization_work().unwrap() == Some(&root_work));
    assert!(slot.finalization_anchor().unwrap() == Some(child.anchor()));
    assert!(slot.finalization_work().unwrap() == Some(child.envelope()));
    assert!(slot.retirement_complete().unwrap());
    let completed = host.lock().unwrap().recovery_manifest(agent).unwrap();
    let released = completed.management_slot(node).unwrap();
    assert!(released.is_released());
    assert!(released.members() == retained.members());
    assert!(released.members_evidence().iter().all(|evidence| {
        evidence.invoke().is_some() && evidence.acknowledgement().is_some()
    }));
    assert!(retry_until(deadline, "Local released exact child retry", || {
        controller.install(install.clone(), call.clone(), package.clone())
    }) == acknowledgement);
    assert!(std::time::Instant::now() <= deadline);
    drop(slot);
    let (original, local, _, counted_signer) = controller.into_parts_for_test();
    // Exactly Create receipt/ACK plus Install receipt/ACK; admission and both
    // terminal retries must not sign any additional receipt or acknowledgement.
    assert_eq!(counted_signer.calls, 4);
    assert_eq!(live.load(Ordering::Acquire), 0);
    owners[origin] = Some(original);
    drop(local);
    assert!(std::time::Instant::now() <= deadline);
    eprintln!("fixed_three_local_install phase=registered_child_exact_retry_completed elapsed_ms={}",
        started.elapsed().as_millis());
}
