//! Genuine owner drop/reopen with missing complete Local authorization work.
//! MEMORY lifecycle records remain the same backing; both physical roots use
//! their normal constructors. No old-owner marker or pending map is copied.

use super::*;
use crate::agent::local_lifecycle::discover_local_lifecycle_recovery;
use std::path::Path;

struct ColdStores {
    space: SpaceId,
    agent: AgentId,
    intent: IssuerMemoryStore,
    issuer: IssuerMemoryStore,
    opens: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
}
impl LocalLifecycleStoreFactory for ColdStores {
    type Intent = LeaseStore;
    type Issuer = LeaseStore;
    type Error = ();
    fn discover(&mut self, space: SpaceId, maximum: usize) -> Result<Vec<AgentId>, ()> {
        assert_eq!(space, self.space);
        assert!(maximum >= 1);
        assert_eq!(self.opens.load(Ordering::Acquire), 0);
        assert_eq!(self.live.load(Ordering::Acquire), 0);
        Ok(vec![self.agent])
    }
    fn open(&mut self, _: SpaceId, _: AgentId) -> Result<(Self::Intent, Self::Issuer), ()> {
        panic!("cold Local retry must not initialize lifecycle stores")
    }
    fn open_existing(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), ()> {
        assert!((space, agent) == (self.space, self.agent));
        assert_eq!(self.live.load(Ordering::Acquire), 0);
        assert_eq!(self.opens.fetch_add(1, Ordering::AcqRel), 0);
        Ok((
            LeaseStore::new(
                self.intent.clone(),
                Arc::new(Mutex::new(Fault::default())),
                Arc::clone(&self.live),
            ),
            LeaseStore::new(
                self.issuer.clone(),
                Arc::new(Mutex::new(Fault::default())),
                Arc::clone(&self.live),
            ),
        ))
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn exercise(
    origin: usize,
    owners: &[Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    bootstrap_stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &[Arc<Network>],
    signer: &mut CountingSigner,
    controller: Controller,
    descriptor: &AgentDescriptor,
    local_root: &Path,
    image_path: &Path,
    request_path: &Path,
    install: &crate::agent_sdk::InstallActor,
    call: &AuthorityCredentialCall,
    package: &AdmittedActorPackage,
    intent_store: &IssuerMemoryStore,
    issuer_store: &IssuerMemoryStore,
    retained: &crate::agent::shared_recovery::SharedManagementRecoverySlot,
    live: Arc<AtomicUsize>,
    recovery_started: std::time::Instant,
    deadline: std::time::Instant,
) {
    let agent = HostAgentId(fixtures[origin].plan.pins.agent.0);
    let node = fixtures[origin].plan.pins.node;
    let target = call.authority;
    let bare_intent = intent_store.image.lock().unwrap().clone();
    let saved_actor = intent_store.actor.lock().unwrap().clone();
    let saved_issuer = issuer_store.image.lock().unwrap().clone();
    let saved_image = std::fs::read(image_path).unwrap();
    let exact_request = std::fs::read(request_path).unwrap();
    let bootstrap_snapshot = || {
        (
            bootstrap_stores[origin].0.image(),
            bootstrap_stores[origin].0.commits(),
            bootstrap_stores[origin].1.image(),
            bootstrap_stores[origin].1.commits(),
            bootstrap_stores[origin].2.image.lock().unwrap().clone(),
        )
    };
    let snapshot_before = bootstrap_snapshot();
    let (record_before, state_before) = {
        let original = controller.system_for_test();
        assert!(original.unpublished_local_install_attempt.is_some());
        assert!(
            original
                ._network_host
                .current_management_pending(agent, call.invocation)
                .unwrap()
                .is_none()
        );
        let record = original.record.encode();
        let state = original
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap();
        (record, state)
    };
    controller
        .system_for_test()
        ._network_host
        .retire_attachment_for_test(agent)
        .unwrap();
    let (original, local, old_factory, old_signer) = controller.into_parts_for_test();
    // This consumes the complete old owner, including its per-open memento.
    // The original two non-clone lifecycle handles have already been dropped.
    assert_eq!(live.load(Ordering::Acquire), 0);
    drop(original);
    drop(local);
    drop(old_factory);
    drop(old_signer);
    assert!(std::time::Instant::now() <= deadline);
    let assert_no_adoption = || {
        assert!(bootstrap_snapshot() == snapshot_before);
        assert!(intent_store.image.lock().unwrap().clone() == bare_intent);
        assert!(intent_store.actor.lock().unwrap().clone() == saved_actor);
        assert!(issuer_store.image.lock().unwrap().clone() == saved_issuer);
        assert!(std::fs::read(image_path).unwrap() == saved_image);
        assert!(std::fs::read(request_path).unwrap() == exact_request);
        for surviving in owners.iter().flatten() {
            retry_until(deadline, "cold Local survivor exact family", || {
                let manifest = surviving
                    ._network_host
                    .management_recovery_manifest(agent)?;
                match manifest.management_slot(retained.owner()) {
                    Some(slot) if slot == retained => {
                        if surviving
                            .host
                            .lock()
                            .unwrap()
                            .clean_state_commitment(agent)?
                            == state_before
                        {
                            Ok(())
                        } else {
                            Err(SharedAgentHostError::ScopeMismatch)
                        }
                    }
                    Some(slot) if slot.sequence() >= retained.sequence() => {
                        Err(SharedAgentHostError::ScopeMismatch)
                    }
                    _ => Err(SharedAgentHostError::Unavailable),
                }
            });
        }
    };
    let opens = Arc::new(AtomicUsize::new(0));
    let mut factory = ColdStores {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        intent: intent_store.clone(),
        issuer: issuer_store.clone(),
        opens: Arc::clone(&opens),
        live: Arc::clone(&live),
    };
    let recovery = discover_local_lifecycle_recovery(&mut factory, target, 1).unwrap();
    assert_eq!(recovery.entries.len(), 1);
    assert!(recovery.entries[0].intent.intent().unwrap().call() == call);
    assert!(
        recovery.entries[0]
            .intent
            .authorization_work()
            .unwrap()
            .is_none()
    );
    assert!(!recovery.entries[0].unissued_authorization);
    assert!(recovery.entries[0].issued.is_none());
    assert!(recovery.entries[0].observed.is_none());
    assert!(recovery.entries[0].finalized.is_none());
    let admission = recovery.startup_admission().unwrap();
    assert!(admission.is_empty());
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert_eq!(live.load(Ordering::Acquire), 2);
    assert_no_adoption();
    // Normal startup verifies the actual signed pins/records and retained
    // bootstrap plan. The empty admission supplies no invented pending work.
    let reopened = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
        bootstrap_stores[origin].0.clone(),
        bootstrap_stores[origin].1.clone(),
        bootstrap_stores[origin].2.clone(),
        signer,
        || panic!("cold Local reopen must retain its original bootstrap plan"),
        directories[origin].host(),
        directories[origin].lock(),
        fixtures[origin].plan.pins.space,
        node,
        fixtures[origin].trust.clone(),
        fixtures[origin].merge.clone(),
        fixtures[origin].finality.clone(),
        providers[origin].clone(),
        networks[origin].clone(),
        Some(&admission),
        None,
    );
    assert!(std::time::Instant::now() <= deadline);
    let mut pending = match reopened {
        Ok(pending) => pending,
        Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::ScopeMismatch)) => {
            drop(recovery);
            assert_eq!(live.load(Ordering::Acquire), 0);
            assert_no_adoption();
            assert!(std::time::Instant::now() <= deadline);
            eprintln!(
                "fixed_three_local_install phase=cold_startup_refusal missing_authorization=true elapsed_ms={}",
                recovery_started.elapsed().as_millis()
            );
            return;
        }
        Err(error) => {
            panic!("cold Local normal startup failed before its admission check: {error:?}")
        }
    };
    let reopened = loop {
        assert!(std::time::Instant::now() < deadline);
        let result = pending.try_complete(signer);
        assert!(std::time::Instant::now() <= deadline);
        match result {
            Ok(Some(owner)) => break owner,
            Ok(None) => panic!("cold Local pending owner disappeared"),
            Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::Unavailable)) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::ScopeMismatch)) => {
                drop(pending);
                drop(recovery);
                assert_eq!(live.load(Ordering::Acquire), 0);
                assert_no_adoption();
                assert!(std::time::Instant::now() <= deadline);
                eprintln!(
                    "fixed_three_local_install phase=cold_startup_refusal missing_authorization=true elapsed_ms={}",
                    recovery_started.elapsed().as_millis()
                );
                return;
            }
            Err(error) => panic!("cold Local normal completion failed: {error:?}"),
        }
    };
    drop(pending);
    assert!(reopened.record.encode() == record_before);
    assert!(reopened.unpublished_local_install_attempt.is_none());
    assert!(reopened.management_admission_held().unwrap());
    assert!(
        reopened
            ._network_host
            .current_management_pending(agent, call.invocation)
            .unwrap()
            .is_none()
    );
    let cold_host = Arc::clone(&reopened.host);
    let local = LocalAgentHost::open(
        local_root,
        descriptor.identity.space,
        node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    assert!(local.show(descriptor.identity.agent).unwrap() == descriptor);
    let lifecycle = LocalLifecycleController::with_recovery(
        reopened,
        local,
        factory,
        CountingSigner::new(),
        recovery,
    )
    .unwrap();
    assert!(std::time::Instant::now() <= deadline);
    assert_eq!(live.load(Ordering::Acquire), 2);
    assert!(
        lifecycle
            .system_for_test()
            .unpublished_local_install_attempt
            .is_none()
    );
    assert_no_adoption();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut production = AgentProductionOwner::start_local(
        node,
        AgentSupervisorLimits::default(),
        Box::new(lifecycle),
        4,
        Box::new(InventoryAuthenticator {
            index: origin,
            node,
            sequence: 0,
            calls: Arc::clone(&calls),
        }),
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert!(std::time::Instant::now() <= deadline);
    assert!(!production.is_ready());
    assert!(matches!(
        production.ingress(),
        Err(AgentProductionOwnerError::ProjectionNotReady)
    ));
    let mut changed = call.clone();
    changed.request_sequence = NonZeroU64::new(call.request_sequence.get() + 1).unwrap();
    changed.invocation = changed.expected_invocation();
    changed.signature = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
        .sign(&changed.signing_bytes())
        .to_bytes();
    changed.verify_with(&RawCredentialVerifier).unwrap();
    for refused_call in [call, &changed] {
        assert!(matches!(
            submit(&mut production, install, refused_call, package),
            Err(AgentProductionOwnerError::ProjectionNotReady
                | AgentProductionOwnerError::Lifecycle(SharedAgentHostError::ScopeMismatch))
        ));
        assert!(std::time::Instant::now() <= deadline);
        assert_no_adoption();
        let mut hosted = cold_host.lock().unwrap();
        assert!(hosted.clean_state_commitment(agent).unwrap() == state_before);
        assert!(
            hosted
                .recovery_manifest(agent)
                .unwrap()
                .management_slot(retained.owner())
                == Some(retained)
        );
        assert_eq!(opens.load(Ordering::Acquire), 1);
        assert_eq!(live.load(Ordering::Acquire), 2);
    }
    assert_eq!(calls.load(Ordering::Acquire), 0);
    production.shutdown_and_join().unwrap();
    drop(cold_host);
    assert_eq!(live.load(Ordering::Acquire), 0);
    assert_no_adoption();
    assert!(std::time::Instant::now() <= deadline);
    eprintln!(
        "fixed_three_local_install phase=cold_original_refusal marker=false no_invoke=true elapsed_ms={}",
        recovery_started.elapsed().as_millis()
    );
}
