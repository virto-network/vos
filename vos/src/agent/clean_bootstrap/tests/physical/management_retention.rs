//! Real image Local lifecycle under the fixed-three System owner. This proves
//! parent management retention, not ordinary Shared/public lifecycle admission.
//! The two surviving voters preserve evidence; they never execute the origin's
//! retained mutation or declare its independent lifecycle terminal.

use super::*;
use crate::agent::clean_management_intent::{CleanManagementIntent, CleanManagementIntentSlot};
use crate::agent::local_lifecycle::{
    LocalLifecycleStoreFactory, discover_local_lifecycle_recovery,
};
use crate::agent::local_sdk_host::LocalAgentHost;
use crate::service::wire::ServiceWire as _;

pub(super) fn exact_management_retry<T>(
    phase: &str,
    mut operation: impl FnMut() -> Result<T, SharedAgentHostError>,
) -> T {
    let started = std::time::Instant::now();
    let bound = std::time::Duration::from_secs(30);
    loop {
        assert!(
            started.elapsed() < bound,
            "exact {phase} exceeded its phase bound"
        );
        let result = operation();
        assert!(
            started.elapsed() <= bound,
            "exact {phase} exceeded its phase bound: {:?}",
            started.elapsed()
        );
        match result {
            Ok(value) => {
                tracing::debug!(
                    phase,
                    elapsed_ms = started.elapsed().as_millis(),
                    "Exact management retry completed"
                );
                return value;
            }
            Err(SharedAgentHostError::Unavailable | SharedAgentHostError::Conflict) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("exact {phase} retry failed: {error:?}"),
        }
    }
}

struct LifecycleStores {
    space: SpaceId,
    agent: AgentId,
    intent: IssuerMemoryStore,
    issuer: IssuerMemoryStore,
}

impl LocalLifecycleStoreFactory for LifecycleStores {
    type Intent = IssuerMemoryStore;
    type Issuer = IssuerMemoryStore;
    type Error = ();
    fn discover(&mut self, space: SpaceId, maximum: usize) -> Result<Vec<AgentId>, ()> {
        if space != self.space || maximum < 1 {
            return Err(());
        }
        Ok(vec![self.agent])
    }
    fn open(&mut self, _: SpaceId, _: AgentId) -> Result<(Self::Intent, Self::Issuer), ()> {
        panic!("restart must retain the original lifecycle stores")
    }
    fn open_existing(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), ()> {
        assert_eq!((space, agent), (self.space, self.agent));
        Ok((self.intent.clone(), self.issuer.clone()))
    }
}

// Fail the first exact authorization-envelope write, not the already signed
// pristine intent. A retained registration must exist before this fails, while
// no runtime Invoke or issuer approval may have been published.
struct RefuseAuthorizationOnce {
    inner: IssuerMemoryStore,
    refuse: bool,
}

impl CleanManagementIssuerStore for RefuseAuthorizationOnce {
    type Error = MemoryError;
    fn load(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        self.inner.load()
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        if core::mem::take(&mut self.refuse) {
            let saved = CleanManagementIntent::decode(bytes).unwrap();
            assert!(saved.authorization_work().is_some());
            return Err(MemoryError);
        }
        self.inner.commit(bytes)
    }
}

fn local_runtime() -> AdmittedRuntimePackage {
    // Keep production Local's pinned image runtime independent of the fresh
    // System IMAGE candidate selected by the enclosing physical fixture.
    let mut envelope = PackageEnvelope::decode(shape_only_runtime().exact_bytes()).unwrap();
    let bytes = include_bytes!("../../../../../../vosx/blobs/agent_runtime.pvm").to_vec();
    let reference = BlobRef::of_bytes(&bytes);
    let crate::agent_sdk::package::PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest
    else {
        unreachable!()
    };
    manifest.outer_program = reference.clone();
    envelope.artifacts = vec![PackageArtifact {
        identity: reference,
        bytes,
    }];
    envelope.manifest.signing_mut().signature = SigningKey::from_bytes(&[0x63; 32])
        .sign(&envelope.signing_bytes().unwrap())
        .to_bytes();
    admit_runtime_package(&envelope.encode().unwrap()).unwrap()
}

fn assert_local_actor_count(local: LocalAgentHost, agent: AgentId, count: usize) -> LocalAgentHost {
    // Use the real per-Agent checkout and authenticated physical directory.
    // This fixture never suspends actors, so each installed actor has one route.
    let owner = Arc::new(Mutex::new(local));
    let execution = LocalAgentHost::checkout(&owner, agent).unwrap();
    assert_eq!(execution.route_identities().unwrap().len(), count);
    drop(execution);
    let Ok(owner) = Arc::try_unwrap(owner) else {
        panic!("physical directory inspection must not retain the Local owner")
    };
    owner.into_inner().unwrap()
}

pub(super) fn elect_origin(
    owners: &mut [Option<MemoryBootstrapOwner>],
    origin: usize,
    agent: HostAgentId,
) {
    if owners[origin]
        .as_ref()
        .unwrap()
        ._network_host
        .bootstrap_is_local_leader(agent)
        .unwrap()
    {
        return;
    }
    // Control transport attachments only. Every successful attempt still needs
    // the genuine committee's vote and committed current-term no-op.
    for _ in 0..8 {
        for index in 0..3 {
            if index != origin {
                owners[index]
                    .as_mut()
                    .unwrap()
                    ._network_host
                    .retire_attachment_for_test(agent)
                    .unwrap();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(350));
        let voter = (origin + 1) % 3;
        owners[voter]
            .as_mut()
            .unwrap()
            ._network_host
            .refresh()
            .unwrap();
        if wait_until(std::time::Duration::from_secs(3), || {
            owners[origin]
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
        }) {
            owners[(origin + 2) % 3]
                .as_mut()
                .unwrap()
                ._network_host
                .refresh()
                .unwrap();
            return;
        }
    }
    panic!("origin did not regain genuine quorum leadership for its native terminal pledge");
}

fn assert_origin_follower(
    owners: &[Option<MemoryBootstrapOwner>],
    origin: usize,
    survivor: usize,
    agent: HostAgentId,
) -> usize {
    assert_ne!(origin, survivor);
    let mut leader = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        let role = owners[origin]
            .as_ref()
            .unwrap()
            ._network_host
            .bootstrap_raft_role_for_test(agent)
            .unwrap();
        assert_ne!(
            role,
            vos_raft::Role::Leader,
            "the original owner must recover without taking leadership"
        );
        leader = owners.iter().enumerate().find_map(|(index, owner)| {
            (index != origin
                && owner.as_ref().is_some_and(|owner| {
                    owner
                        ._network_host
                        .bootstrap_is_local_leader(agent)
                        .unwrap()
                }))
            .then_some(index)
        });
        leader.is_some() && role == vos_raft::Role::Follower
    }));
    let leader = leader.unwrap();
    if leader != survivor {
        eprintln!(
            "management follower recovery: surviving leader changed {survivor}->{leader}; origin {origin} remains Follower"
        );
    }
    leader
}

fn assert_management_recovery_budget(owner: &MemoryBootstrapOwner, expected_management: usize) {
    // Call the actual host/driver budget while genuine signed management
    // custody is retained. Observations consume no replay rows or reservation.
    let agent = HostAgentId(owner.pins.agent.0);
    let before = native_owner_physical_state(owner);
    let mut host = owner.host.lock().unwrap();
    let manifest = host.recovery_manifest(agent).unwrap();
    let retained = manifest
        .management_slot(HostNodeId(owner.pins.node.0))
        .unwrap();
    assert!(!retained.is_released());
    let root = &retained.members()[0];
    assert!(retained.members_evidence()[0].acknowledgement().is_none());
    let root_entries = if retained.members_evidence()[0].invoke().is_some() {
        1
    } else {
        2
    };
    assert_eq!(
        host.management_pending_admission_requirement(agent, &[(root.anchor(), root.envelope())])
            .unwrap(),
        Some(root_entries),
        "the actual retained first capsule determines the exact remaining root cost"
    );
    assert_eq!(
        host.management_pending_admission_requirement(agent, &[(root.anchor(), root.envelope())])
            .unwrap(),
        Some(root_entries),
        "a separate exact budget retry must independently verify the same result"
    );
    let expected_input = retained.members_evidence()[0]
        .invoke()
        .map(|first| first.input_id());
    assert_eq!(
        host.management_invocation_after_anchor(agent, root.anchor(), root.envelope())
            .unwrap(),
        expected_input
    );
    assert_eq!(
        host.management_pending_admission_with_input(agent, root.anchor(), root.envelope())
            .unwrap(),
        (Some(root_entries), expected_input),
        "one drained singleton calculation must agree with separate exact budget and anchor reads"
    );
    assert_eq!(
        host.management_pending_admission_with_input(agent, root.anchor(), root.envelope())
            .unwrap(),
        (Some(root_entries), expected_input),
        "a separate combined retry must reauthenticate the same first input or fresh absence"
    );
    let mut wrong_anchor = root.anchor().clone();
    wrong_anchor.runtime = crate::service::Hash([0xec; 32]);
    assert!(
        host.management_pending_admission_requirement(agent, &[(&wrong_anchor, root.envelope())])
            .is_err(),
        "call-local reuse cannot substitute a different runtime anchor"
    );
    assert!(
        host.management_pending_admission_with_input(agent, &wrong_anchor, root.envelope())
            .is_err()
    );
    let mut wrong_interval = root.anchor().clone();
    wrong_interval.ordered.index += 1;
    assert!(
        host.management_pending_admission_with_input(agent, &wrong_interval, root.envelope())
            .is_err(),
        "a retained capsule cannot qualify a substituted pre-dispatch interval"
    );
    let mut changed_envelope = root.envelope().clone();
    let RuntimeWork::Invoke { observed_slot, .. } = &mut changed_envelope else {
        unreachable!()
    };
    *observed_slot += 1;
    assert!(
        host.management_pending_admission_requirement(agent, &[(root.anchor(), &changed_envelope)])
            .is_err(),
        "call-local reuse must retain the exact immutable preflight clock"
    );
    assert!(
        host.management_pending_admission_with_input(agent, root.anchor(), &changed_envelope)
            .is_err()
    );
    assert!(
        host.management_pending_admission_requirement(
            agent,
            &[
                (root.anchor(), root.envelope()),
                (root.anchor(), root.envelope())
            ],
        )
        .is_err(),
        "a repeated member cannot double-spend the same retained evidence"
    );
    assert_eq!(
        host.management_retention_admission_requirement(agent, None)
            .unwrap(),
        Some(expected_management)
    );
    assert_eq!(
        host.recovery_manifest(agent).unwrap(),
        manifest,
        "budget reads cannot publish or alter retained first evidence"
    );
    drop(host);
    assert_eq!(native_owner_physical_state(owner), before);
}

#[allow(clippy::too_many_arguments)]
fn reopen_with_lifecycle(
    origin: usize,
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    network: Arc<Network>,
    lifecycle: &mut LifecycleStores,
    signer: &mut CountingSigner,
) -> MemoryBootstrapOwner {
    let fixture = &fixtures[origin];
    let target = fixture.plan.authority_target();
    let recovery = discover_local_lifecycle_recovery(lifecycle, target, 1).unwrap();
    let admission = recovery.startup_admission().unwrap();
    let mut pending = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
        stores[origin].0.clone(),
        stores[origin].1.clone(),
        stores[origin].2.clone(),
        signer,
        || panic!("management restart must not recreate System genesis"),
        directories[origin].host(),
        directories[origin].lock(),
        fixture.plan.pins.space,
        fixture.plan.pins.node,
        fixture.trust.clone(),
        fixture.merge.clone(),
        fixture.finality.clone(),
        providers[origin].clone(),
        network,
        Some(&admission),
        None,
    )
    .unwrap();
    pending.try_complete(signer).unwrap().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn prune_and_catch_up_offline_management(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    offline_host: &Arc<Mutex<SharedAgentHost>>,
    retained: &crate::agent::shared_recovery::management::SharedManagementRecoverySlot,
    intent_store: &IssuerMemoryStore,
    saved_intent: &Option<Vec<u8>>,
    nonce: u8,
) -> usize {
    let system = HostAgentId(fixtures[origin].plan.pins.agent.0);
    let node = fixtures[origin].plan.pins.node;
    assert!(owners[origin].is_none());
    assert_eq!(retained.members().len(), 1);
    let original = &retained.members()[0];
    let first = retained.members_evidence()[0].invoke().unwrap();
    assert!(retained.members_evidence()[0].acknowledgement().is_none());
    let limits = SharedAgentPortableBackupLimits {
        max_objects: 4096,
        max_blobs: 4096,
        max_index_nodes: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    for cycle in 0..2u8 {
        let mut source = None;
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            source = owners.iter().position(|owner| {
                owner.as_ref().is_some_and(|owner| {
                    owner
                        ._network_host
                        .bootstrap_is_local_leader(system)
                        .unwrap()
                })
            });
            source.is_some()
        }));
        let source = source.unwrap();
        assert_ne!(source, origin);
        let owner = owners[source].as_mut().unwrap();
        // Read-only evidence on survivors is not mutation execution authority.
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .management_invocation_after_anchor(system, original.anchor(), original.envelope())
                .unwrap(),
            Some(first.input_id())
        );
        // Qualify the real candidate's same-call audited-manifest handoff
        // before QC collection, so a later vote timeout cannot mask whether
        // this exact source/read-count assertion ran.
        owner
            .host
            .lock()
            .unwrap()
            .assert_common_candidate_reuses_audited_manifest_for_test(system);
        let (work, authorization, _) =
            public_query_work(owner, &query(owner, source, nonce + cycle));
        let committee = owner.pins.replicas.clone();
        let mut certificate = None;
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            match owner
                ._network_host
                .certified_common_checkpoint_for_admission(
                    system,
                    &work,
                    &authorization,
                    &committee,
                    fixtures[source].merge.as_ref(),
                ) {
                Ok(value) => {
                    certificate = Some(value);
                    true
                }
                Err(SharedAgentHostError::Unavailable) => false,
                other => panic!("management checkpoint refused: {other:?}"),
            }
        }));
        let certificate = certificate.unwrap();
        assert!(certificate.claim().recovery_manifest().is_some());
        let exported = owner
            .host
            .lock()
            .unwrap()
            .export_common_checkpoint(system, limits)
            .unwrap();
        let current = owner
            ._network_host
            .management_recovery_manifest(system)
            .unwrap();
        assert_eq!(current.management_slot(HostNodeId(node.0)), Some(retained));
        // These are genuine independently signed management families, not a
        // fabricated duplicate of the surviving first capsule. A is still
        // awaiting ACK; the completed other root is retained through its ACK
        // and release in the same certified baseline.
        let completed = current
            .management_slots()
            .iter()
            .filter(|slot| slot.is_released())
            .find_map(|slot| {
                slot.members()
                    .first()
                    .zip(slot.members_evidence().first())
                    .filter(|(_, evidence)| {
                        evidence.invoke().is_some() && evidence.acknowledgement().is_some()
                    })
                    .map(|(member, _)| member)
            })
            .expect("a distinct completed policy-denial root remains certified");
        assert_ne!(completed.commitment(), original.commitment());
        let physical_before = native_owner_physical_state(owner);
        {
            let mut host = owner.host.lock().unwrap();
            let pending = [
                (original.anchor(), original.envelope()),
                (completed.anchor(), completed.envelope()),
            ];
            for attempt in 0..2 {
                let audits_before = host.common_recovery_audits_for_test(system).unwrap();
                assert_eq!(
                    host.management_pending_admission_requirement(system, &pending)
                        .unwrap(),
                    Some(1),
                    "only the original unACKed family has remaining Ordered work"
                );
                assert_eq!(
                    host.common_recovery_audits_for_test(system).unwrap() - audits_before,
                    1,
                    "each budget independently audits common authority once for both exact families"
                );
                assert_eq!(host.recovery_manifest(system).unwrap(), current);
                if attempt == 0 {
                    host.assert_management_budget_rechecks_common_closure_for_test(
                        system, &pending,
                    );
                }
            }
        }
        assert_eq!(native_owner_physical_state(owner), physical_before);
        let before = owner.ordered_index_for_test().unwrap();
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .management_invocation_after_anchor(system, original.anchor(), original.envelope())
                .unwrap(),
            Some(first.input_id())
        );
        assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .replay_durable_management_denial(system, original.anchor(), original.envelope())
                .unwrap(),
            *first.outcome(),
            "survivors retain the original response without reexecuting the mutation"
        );
        assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        let offline_database = offline_host.lock().unwrap().raft_database(system).unwrap();
        let offline_raft = crate::raft::RaftMeta::load(&offline_database).unwrap();
        drop(offline_database);
        let offline_applied = offline_host.lock().unwrap().capacity(system).unwrap().0;
        let target = certificate.claim().ordered();
        offline_host
            .lock()
            .unwrap()
            .restore_common_checkpoint(&exported, limits)
            .unwrap_or_else(|error| {
                panic!(
                    "offline management restore refused: cycle={cycle} source={source} origin={origin} target={}/{} offline_applied={} worker_applied={} committed={} snapshot={}/{} current_term={} error={error:?}",
                    target.raft_index(),
                    target.raft_term(),
                    offline_applied,
                    offline_raft.last_applied,
                    offline_raft.commit_index,
                    offline_raft.snap_last_index,
                    offline_raft.snap_last_term,
                    offline_raft.current_term,
                );
            });
        assert_eq!(
            offline_host
                .lock()
                .unwrap()
                .recovery_manifest(system)
                .unwrap(),
            current
        );
        assert_eq!(&*intent_store.image.lock().unwrap(), saved_intent);
    }
    // Checkpoint transport reattachment may elect either survivor. Neither
    // change is permission for the offline origin to resume as Leader.
    let mut leader = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        leader = owners.iter().position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(system)
                    .unwrap()
            })
        });
        leader.is_some()
    }));
    let leader = leader.unwrap();
    assert_ne!(leader, origin);
    leader
}

struct ClockPeerIntent {
    peer: usize,
    call: AuthorityCredentialCall,
    slot: CleanManagementIntentSlot<IssuerMemoryStore>,
    intent_store: IssuerMemoryStore,
    issuer: DurableCleanManagementIssuer<IssuerMemoryStore>,
    local: LocalAgentHost,
    runtime: AdmittedRuntimePackage,
}

fn clock_peer_intent(
    peer: usize,
    nonce: u8,
    request_sequence: u64,
    descriptor: &AgentDescriptor,
    owners: &[Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
) -> ClockPeerIntent {
    let owner = owners[peer].as_ref().unwrap();
    let mut descriptor = descriptor.clone();
    descriptor.creation_nonce = Hash([nonce; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    descriptor.replicas[0].node = owner.pins.node;
    descriptor.validate().unwrap();
    let runtime = local_runtime();
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let credential = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &credential);
    call.authority = owner.authority_target();
    // These are genuine signed competing Root calls. The actual Authority
    // sequence/pending-application policy, not a synthetic host receipt, must
    // return their terminal denial without publishing a host-clock rejection.
    call.request_sequence = NonZeroU64::new(request_sequence).unwrap();
    call.invocation = call.expected_invocation();
    call.signature = credential.sign(&call.signing_bytes()).to_bytes();
    let intent_store = IssuerMemoryStore::default();
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    slot.pledge(
        CleanManagementIntent::new(
            call.authority,
            call.managed,
            request,
            call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap(),
    )
    .unwrap();
    slot.retain_runtime(runtime.exact_bytes()).unwrap();
    let issuer = DurableCleanManagementIssuer::open(
        IssuerMemoryStore::default(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    let local = LocalAgentHost::create(
        &directories[peer]
            .0
            .join(format!("clock-peer-{nonce:02x}-local")),
        descriptor.identity.space,
        owner.pins.node,
        fixtures[peer].trust.clone(),
    )
    .unwrap();
    ClockPeerIntent {
        peer,
        call,
        slot,
        intent_store,
        issuer,
        local,
        runtime,
    }
}

fn hold_clock_peer_before_earlier_invoke(
    peer: &mut ClockPeerIntent,
    owners: &mut [Option<MemoryBootstrapOwner>],
    earlier: &crate::agent::shared_recovery::management::SharedManagementRecoverySlot,
    signer: &mut CountingSigner,
) {
    let owner = owners[peer.peer].as_mut().unwrap();
    let system = HostAgentId(owner.pins.agent.0);
    assert!(
        !owner
            ._network_host
            .bootstrap_is_local_leader(system)
            .unwrap(),
        "the competing origin must exercise the real leader receiver"
    );
    let before = native_owner_physical_state(owner);
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        assert_eq!(
            owner.create_local_from_management_intent_with_admission(
                &mut peer.slot,
                peer.call.managed,
                &mut peer.local,
                peer.runtime.clone(),
                &mut peer.issuer,
                signer,
                true,
            ),
            Err(SharedAgentHostError::Unavailable),
            "later work must not pass an earlier accepted immutable clock"
        );
        peer.slot.authorization_work().unwrap().is_some()
    }));
    // Metadata custody may apply, but neither runtime/Ordered work nor an
    // actor installation may be published by this refused first execution.
    assert_eq!(native_owner_physical_state(owner).0, before.0);
    assert_eq!(native_owner_physical_state(owner).1, before.1);
    let manifest = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let held = manifest
        .management_slot(HostNodeId(owner.pins.node.0))
        .unwrap();
    assert!(held.members_evidence()[0].invoke().is_none());
    assert_eq!(manifest.management_slot(earlier.owner()), Some(earlier));
    assert!(peer.local.list().unwrap().is_empty());
    assert_eq!(peer.issuer.sequence_high_water(), 0);
}

fn finish_clock_peer_denial(
    peer: &mut ClockPeerIntent,
    owners: &mut [Option<MemoryBootstrapOwner>],
    signer: &mut CountingSigner,
) {
    let owner = owners[peer.peer].as_mut().unwrap();
    let mut denied = false;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        match owner.create_local_from_management_intent_with_admission(
            &mut peer.slot,
            peer.call.managed,
            &mut peer.local,
            peer.runtime.clone(),
            &mut peer.issuer,
            signer,
            true,
        ) {
            Err(SharedAgentHostError::Unavailable) => false,
            Err(SharedAgentHostError::ScopeMismatch) => {
                denied = true;
                true
            }
            result => panic!("competing Root call must have a real policy denial: {result:?}"),
        }
    }));
    assert!(denied);
    assert!(peer.local.list().unwrap().is_empty());
    assert_eq!(peer.issuer.sequence_high_water(), 0);
    assert!(exact_management_retry("competing clock denial", || {
        owner.finish_denied_management_intent(&mut peer.slot, &peer.issuer, &peer.local, signer)
    }));
    assert!(peer.slot.denial_complete().unwrap());
    let manifest = owner
        ._network_host
        .management_recovery_manifest(HostAgentId(owner.pins.agent.0))
        .unwrap();
    let slot = manifest
        .management_slot(HostNodeId(owner.pins.node.0))
        .unwrap();
    assert!(slot.is_released());
    assert!(slot.all_acknowledged());
    // Reuse the exact genuinely completed signed denial release. The host
    // guard excludes its background application while counting the receiver's
    // actual ledger preflight; this is not a mock or publication permission.
    {
        let system = HostAgentId(owner.pins.agent.0);
        let release = slot.release().unwrap();
        let before = native_owner_physical_state(owner);
        let mut host = owner.host.lock().unwrap();
        let audits = host.management_preflight_audits_for_test(system).unwrap();
        host.validate_management_recovery_release(system, release)
            .unwrap();
        assert_eq!(
            host.management_preflight_audits_for_test(system).unwrap(),
            audits + 1,
            "signed receiver release validation must audit the exact request once"
        );
        assert_eq!(host.recovery_manifest(system).unwrap(), manifest);
        drop(host);
        assert_eq!(native_owner_physical_state(owner), before);
    }
    assert!(matches!(
        slot.members_evidence()[0].invoke().unwrap().outcome(),
        RuntimeOutcome::Completed(Ok(reply)) if reply.status == InvocationStatus::Done
    ));
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn exercise(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &mut Vec<Arc<Network>>,
    signer: &mut CountingSigner,
    origin_returns_follower: bool,
) {
    let system = HostAgentId(fixtures[origin].plan.pins.agent.0);
    let node = fixtures[origin].plan.pins.node;
    let runtime = local_runtime();
    let mut descriptor = fixtures[origin].plan.pins.descriptor.clone();
    descriptor.identity.profile = AgentProfile::Local;
    descriptor.creation_nonce = Hash([0xe3; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    descriptor.identity.runtime_deployment = runtime.deployment();
    descriptor.identity.runtime_program = runtime.program();
    descriptor.identity.runtime_producer = runtime.producer();
    descriptor.runtime_package = runtime.package_ref().clone();
    descriptor.runtime_contract = runtime.manifest().contract;
    descriptor.capabilities = runtime.capabilities();
    descriptor.replicas = vec![AgentReplica {
        node,
        principal: descriptor.identity.owner,
        role: ReplicaRole::Voter,
    }];
    descriptor.validate().unwrap();
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let credential = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &credential);
    call.authority = owners[origin].as_ref().unwrap().authority_target();
    call.authenticated_node = Some(node);
    // Root catalog bootstrap consumed sequence one for this credential.
    call.request_sequence = NonZeroU64::new(2).unwrap();
    call.invocation = call.expected_invocation();
    call.signature = credential.sign(&call.signing_bytes()).to_bytes();
    let intent_store = IssuerMemoryStore::default();
    let issuer_store = IssuerMemoryStore::default();
    let mut lifecycle = LifecycleStores {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        intent: intent_store.clone(),
        issuer: issuer_store.clone(),
    };
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    slot.pledge(
        CleanManagementIntent::new(
            call.authority,
            call.managed,
            request.clone(),
            call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap(),
    )
    .unwrap();
    slot.retain_runtime(runtime.exact_bytes()).unwrap();
    drop(slot);
    let pristine = intent_store.image.lock().unwrap().clone();
    let mut slot = CleanManagementIntentSlot::open(RefuseAuthorizationOnce {
        inner: intent_store.clone(),
        refuse: true,
    })
    .unwrap();
    let mut issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    let local_root = directories[origin].0.join("retained-local");
    let mut local = LocalAgentHost::create(
        &local_root,
        descriptor.identity.space,
        node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    // Reproduce the maintenance race: the hint is genuinely clear when B
    // starts this exact signed query, before A's remote MRQ2 becomes durable.
    let probe_index = (origin + 2) % 3;
    let probe = owners[probe_index].as_ref().unwrap();
    assert!(
        !probe
            ._network_host
            .management_admission_held(system)
            .unwrap()
    );
    let deferred = query(probe, probe_index, 0xe7);
    let owner = owners[origin].as_mut().unwrap();
    // Completing System bootstrap advances this fixture's trusted clock.
    // Capture the actual admission slot rather than its initial seed value.
    let accepted_slot = fixtures[origin]
        .logical_slot
        .as_ref()
        .unwrap()
        .load(Ordering::Acquire);
    assert_eq!(
        owner.create_local_from_management_intent_with_admission(
            &mut slot,
            call.managed,
            &mut local,
            runtime.clone(),
            &mut issuer,
            signer,
            true
        ),
        Err(SharedAgentHostError::Unavailable)
    );
    assert_eq!(*intent_store.image.lock().unwrap(), pristine);
    assert!(local.list().unwrap().is_empty());
    assert_eq!(issuer.sequence_high_water(), 0);
    let manifest = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let registered = manifest
        .management_slot(HostNodeId(node.0))
        .unwrap()
        .clone();
    assert_eq!(registered.members().len(), 1);
    assert_eq!(registered.origin_owner(), HostNodeId(node.0));
    assert!(registered.observations().next().is_none());
    assert!(!registered.is_released());
    // Exercise the real driver admission seam, independently of publication.
    // Signature and complete runtime binding still precede the final ledger
    // preflight after removing its duplicated request-only call.
    {
        use crate::agent::shared_commit::ReplicaCommitSignature;
        use crate::agent::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
            SharedManagementRecoveryRegistrationRequest,
        };
        let before = native_owner_physical_state(owner);
        let mut host = owner.host.lock().unwrap();
        host.validate_management_recovery_registration(system, registered.registration())
            .unwrap();
        let mut signature = *registered.registration().signature().signature();
        signature[0] ^= 1;
        let substituted = SharedManagementRecoveryRegistration::new(
            registered.registration().request().clone(),
            ReplicaCommitSignature::new(registered.owner(), signature).unwrap(),
        )
        .unwrap();
        assert!(
            host.validate_management_recovery_registration(system, &substituted)
                .is_err()
        );

        let root = &registered.members()[0];
        let mut anchor = root.anchor().clone();
        anchor.runtime = crate::service::Hash([0xeb; 32]);
        let member =
            SharedManagementRecoveryMember::new(root.parent(), anchor, root.envelope().clone())
                .unwrap();
        let original = registered.registration().request();
        let request = SharedManagementRecoveryRegistrationRequest::new(
            original.generation(),
            original.committee(),
            original.owner(),
            original.origin_owner(),
            original.sequence(),
            original.previous(),
            vec![member],
        )
        .unwrap();
        let node_key = SigningKey::from_bytes(&[[NODE_SEED, 0xd2, 0xd3][origin]; 32]);
        let substituted = SharedManagementRecoveryRegistration::new(
            request.clone(),
            ReplicaCommitSignature::new(
                original.owner(),
                node_key.sign(&request.signing_message().0).to_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        substituted
            .verify(manifest.generation(), manifest.committee())
            .unwrap();
        assert_eq!(
            host.validate_management_recovery_registration(system, &substituted),
            Err(SharedAgentHostError::CorruptResidue),
            "a genuine voter signature cannot replace the admitted runtime anchor"
        );
        assert_eq!(host.recovery_manifest(system).unwrap(), manifest);
        drop(host);
        assert_eq!(native_owner_physical_state(owner), before);
    }
    let original = registered.members()[0].clone();
    let RuntimeWork::Invoke { observed_slot, .. } = original.envelope() else {
        unreachable!()
    };
    assert_eq!(*observed_slot, accepted_slot);
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        original.anchor().ordered.index,
        "metadata registration does not execute an Ordered Invoke"
    );
    assert!(
        owner.host.lock().unwrap().capacity(system).unwrap().0 >= registered.raft_index(),
        "the metadata registration's physical Raft position has applied"
    );
    assert_management_recovery_budget(owner, 4);
    {
        let probe = owners[probe_index].as_mut().unwrap();
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            probe
                ._network_host
                .management_recovery_manifest(system)
                .unwrap()
                .management_slot(HostNodeId(node.0))
                .is_some_and(|slot| slot.registration() == registered.registration())
        }));
        assert!(
            probe
                ._network_host
                .management_admission_held(system)
                .unwrap(),
            "remote replicated custody must suppress maintenance without a local intent map",
        );
        let before_record = probe.record.encode();
        let before_wal = probe
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap();
        let before_manifest = probe
            ._network_host
            .management_recovery_manifest(system)
            .unwrap();
        let before_physical = native_owner_physical_state(probe);
        // A retained mutation excludes checkpoint retirement, not pure
        // Authority observations. The signed request captured before custody
        // is freshly authenticated against this receiver's current guest state.
        let bytes = probe
            .invoke_authority_observation(deferred.clone())
            .unwrap();
        let credential =
            crate::agent_sdk::authority::AuthorityCredentialProjection::decode(&bytes).unwrap();
        assert_eq!(credential.query.credential, deferred.credential);
        assert_eq!(
            credential.status,
            crate::agent_sdk::authority::AuthorityCredentialStatus::Active
        );
        assert_eq!(probe.record.encode(), before_record);
        assert_eq!(
            probe
                .record_store
                .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                .unwrap(),
            before_wal
        );
        assert_eq!(
            probe
                ._network_host
                .management_recovery_manifest(system)
                .unwrap(),
            before_manifest
        );
        assert_eq!(native_owner_physical_state(probe), before_physical);
    }
    // Register genuine B at a later clock while accepted A is still unseen.
    // These are distinct original owners, not a globally single issuer test.
    let peer_slot = fixtures
        .iter()
        .map(|fixture| {
            fixture
                .logical_slot
                .as_ref()
                .unwrap()
                .load(Ordering::Acquire)
        })
        .max()
        .unwrap()
        .max(accepted_slot)
        .checked_add(1)
        .unwrap();
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .fetch_max(peer_slot, Ordering::AcqRel);
    }
    let mut competing = clock_peer_intent(
        (origin + 1) % 3,
        0xf1,
        3,
        &descriptor,
        owners,
        fixtures,
        directories,
    );
    let mut late = clock_peer_intent(
        (origin + 2) % 3,
        0xf2,
        3,
        &descriptor,
        owners,
        fixtures,
        directories,
    );
    // Capture an older *unadmitted* C envelope before B advances the runtime.
    // Its signed caller intent remains unchanged; only host preflight is old.
    let mut late_envelope = original.envelope().clone();
    let RuntimeWork::Invoke {
        invocation,
        authorization,
        observed_slot,
        ..
    } = &mut late_envelope
    else {
        unreachable!()
    };
    let late_intent = late.slot.intent().unwrap();
    invocation.invocation = late.call.invocation;
    invocation.origin = late_intent.authorization_origin();
    invocation.message = late_intent.authorization_message();
    *observed_slot = accepted_slot;
    **authorization = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(invocation, accepted_slot),
    );
    hold_clock_peer_before_earlier_invoke(&mut competing, owners, &registered, signer);
    let RuntimeWork::Invoke { observed_slot, .. } =
        competing.slot.authorization_work().unwrap().unwrap()
    else {
        unreachable!()
    };
    assert!(*observed_slot > accepted_slot);
    let owner = owners[origin].as_mut().unwrap();
    let stale_absence_retry = owner
        ._network_host
        .stage_management_custody_retry_for_test(system, node, &original);
    drop(slot);
    // Exact retry must recover the original captured clock and anchor, even
    // though the failed authorization WAL did not contain those fields.
    fixtures[origin]
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_max(accepted_slot + 1, Ordering::AcqRel);
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    owner.finalization_failure_once = Some(6);
    assert_eq!(
        owner.create_local_from_management_intent_with_admission(
            &mut slot,
            call.managed,
            &mut local,
            runtime.clone(),
            &mut issuer,
            signer,
            true
        ),
        Err(SharedAgentHostError::Unavailable)
    );
    assert_eq!(
        slot.authorization_work().unwrap(),
        Some(original.envelope())
    );
    assert_eq!(
        slot.authorization_anchor().unwrap(),
        Some(original.anchor())
    );
    assert!(local.list().unwrap().is_empty());
    assert_eq!(issuer.sequence_high_water(), 0);
    let manifest = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let retained = manifest
        .management_slot(HostNodeId(node.0))
        .unwrap()
        .clone();
    assert_eq!(retained.origin_owner(), registered.origin_owner());
    let first = retained.members_evidence()[0].invoke().unwrap().clone();
    assert!(retained.members_evidence()[0].acknowledgement().is_none());
    let first_outcome = first.outcome().clone();
    assert!(matches!(first_outcome, RuntimeOutcome::Completed(Ok(_))));
    // A's actual first Invoke discharges the clock fence, not its ACK/release.
    // B now receives a real Authority denial and completes exact ACK+CND1.
    finish_clock_peer_denial(&mut competing, owners, signer);
    let owner = owners[late.peer].as_mut().unwrap();
    let competing_node = fixtures[competing.peer].plan.pins.node;
    assert!(
        wait_until(std::time::Duration::from_secs(30), || {
            owner
                ._network_host
                .management_recovery_manifest(system)
                .unwrap()
                .management_slot(HostNodeId(competing_node.0))
                .is_some_and(|slot| slot.is_released())
        }),
        "late preview must observe B's genuine first execution and release"
    );
    let manifest = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    // B's terminal custody is released, but A intentionally remains retained
    // for the offline recovery exercise below. The maintenance hint covers
    // all replicated owners, not just this late peer's local admission.
    let original_retained = manifest.management_slot(HostNodeId(node.0)).unwrap();
    assert_eq!(original_retained, &retained);
    assert!(!original_retained.is_released());
    assert_eq!(
        original_retained.members_evidence()[0].invoke(),
        Some(&first)
    );
    assert!(
        original_retained.members_evidence()[0]
            .acknowledgement()
            .is_none()
    );
    let competing_retired = manifest
        .management_slot(HostNodeId(competing_node.0))
        .unwrap();
    assert!(competing_retired.is_released());
    assert!(competing_retired.all_acknowledged());
    assert!(
        owner
            ._network_host
            .management_admission_held(system)
            .unwrap()
    );
    let before = native_owner_physical_state(owner);
    let pristine = late.intent_store.image.lock().unwrap().clone();
    let caller = late.slot.intent().unwrap().call().clone();
    let expected_committee = owner.pins.replicas.clone();
    let snapshot_signer = owner.snapshot_signer.clone();
    let refused: Result<(), SharedAgentHostError> = owner
        ._network_host
        .capture_management_pending_with_checkpoint(
            system,
            &late_envelope,
            &expected_committee,
            snapshot_signer.as_ref(),
            |_| panic!("a late unadmitted clock must refuse before its independent WAL"),
        );
    assert_eq!(refused, Err(SharedAgentHostError::Unavailable));
    assert_eq!(native_owner_physical_state(owner), before);
    assert_eq!(
        owner
            ._network_host
            .management_recovery_manifest(system)
            .unwrap(),
        manifest
    );
    assert_eq!(*late.intent_store.image.lock().unwrap(), pristine);
    assert!(late.slot.authorization_work().unwrap().is_none());
    assert!(late.slot.authorization_anchor().unwrap().is_none());
    assert!(
        owner
            ._network_host
            .management_admission_held(system)
            .unwrap()
    );
    assert!(late.local.list().unwrap().is_empty());
    assert_eq!(late.issuer.sequence_high_water(), 0);
    // Normal native retry keeps the exact signed call, sampling a fresh host
    // preflight only because no custody or authorization WAL was acquired.
    finish_clock_peer_denial(&mut late, owners, signer);
    assert_eq!(late.slot.intent().unwrap().call(), &caller);
    let RuntimeWork::Invoke { observed_slot, .. } =
        late.slot.authorization_work().unwrap().unwrap()
    else {
        unreachable!()
    };
    assert!(*observed_slot > accepted_slot);
    let owner = owners[origin].as_mut().unwrap();
    assert_management_recovery_budget(owner, 3);
    stale_absence_retry();
    let saved_intent = intent_store.image.lock().unwrap().clone();
    drop(slot);
    drop(issuer);
    drop(local);
    let offline_host = owners[origin].as_ref().unwrap().host.clone();
    drop(owners[origin].take());
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    stop_network(live_networks[origin].take().unwrap());
    let offline_peer =
        libp2p::identity::Keypair::ed25519_from_bytes([[NODE_SEED, 0xd2, 0xd3][origin]; 32])
            .unwrap()
            .public()
            .to_peer_id();
    assert!(wait_until(std::time::Duration::from_secs(10), || {
        live_networks
            .iter()
            .flatten()
            .all(|network| !network.connected_peers().contains(&offline_peer))
    }));
    let mut survivor = prune_and_catch_up_offline_management(
        origin,
        owners,
        fixtures,
        &offline_host,
        &retained,
        &intent_store,
        &saved_intent,
        0xe4,
    );
    if origin_returns_follower {
        use crate::network::agent_protocol::{
            ManagementRecoveryOperation, ManagementRecoveryOperationRequest,
        };
        let impostor = (0..3)
            .find(|index| *index != origin && *index != survivor)
            .unwrap();
        let route = AgentGenerationRoute {
            space: fixtures[origin].plan.pins.space,
            agent: fixtures[origin].plan.pins.agent,
            generation: Hash(
                retained
                    .registration()
                    .request()
                    .generation()
                    .replication_id(),
            ),
        };
        let target = live_networks[survivor].as_ref().unwrap().agent_node_id();
        let owner = owners[survivor].as_ref().unwrap();
        let before = owner.ordered_index_for_test().unwrap();
        let manifest = owner
            ._network_host
            .management_recovery_manifest(system)
            .unwrap();
        for operation in [
            ManagementRecoveryOperation::Invoke,
            ManagementRecoveryOperation::Acknowledge,
        ] {
            let accepted = live_networks[impostor]
                .as_ref()
                .unwrap()
                .send_agent_management_recovery_operation(
                    target,
                    route,
                    ManagementRecoveryOperationRequest {
                        registration: Hash(retained.registration().commitment().0),
                        member: Hash(original.commitment().0),
                        operation,
                    },
                )
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap()
                .unwrap();
            assert!(
                !accepted,
                "another authenticated voter must not dispatch the offline owner's member"
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
            assert_eq!(
                owner
                    ._network_host
                    .management_recovery_manifest(system)
                    .unwrap(),
                manifest
            );
            assert_eq!(*intent_store.image.lock().unwrap(), saved_intent);
        }
    }
    // Origin's independently owned WAL has not been rewritten by catch-up.
    let before_reopen = offline_host
        .lock()
        .unwrap()
        .journal_position(system)
        .unwrap()
        .ordered_index;
    drop(offline_host);
    live_networks[origin] = Some(restart_network(origin));
    for index in 0..3 {
        if index != origin {
            live_networks[origin]
                .as_ref()
                .unwrap()
                .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
        }
    }
    owners[origin] = Some(reopen_with_lifecycle(
        origin,
        fixtures,
        directories,
        stores,
        providers,
        live_networks[origin].as_ref().unwrap().clone(),
        &mut lifecycle,
        signer,
    ));
    assert_eq!(*intent_store.image.lock().unwrap(), saved_intent);
    assert!(
        owners[origin]
            .as_ref()
            .unwrap()
            .ordered_index_for_test()
            .unwrap()
            >= before_reopen
    );
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    } else {
        elect_origin(owners, origin, system);
    }
    let owner = owners[origin].as_mut().unwrap();
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    let mut issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    let before_retry = owner.ordered_index_for_test().unwrap();
    let receipt = owner
        .issue_management_intent_with_admission(&mut slot, call.managed, &mut issuer, signer, true)
        .unwrap();
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before_retry,
        "recovered approval must not append a replacement Invoke"
    );
    assert_eq!(
        slot.authorization_work().unwrap(),
        Some(original.envelope())
    );
    assert_eq!(
        slot.authorization_anchor().unwrap(),
        Some(original.anchor())
    );
    let native_replay = owner
        .host
        .lock()
        .unwrap()
        .replay_durable_management_denial(system, original.anchor(), original.envelope())
        .unwrap();
    // The historical helper name does not classify the reply: the exact
    // approved parent must still reconstruct its first physical outcome.
    assert_eq!(native_replay, first_outcome);
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_retry);
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    }
    let owner = owners[origin].as_mut().unwrap();
    assert_eq!(
        owner
            ._network_host
            .management_recovery_manifest(system)
            .unwrap()
            .management_slot(HostNodeId(node.0))
            .unwrap()
            .members_evidence()[0]
            .invoke()
            .unwrap()
            .outcome(),
        &first_outcome
    );
    let mut local = LocalAgentHost::open(
        &local_root,
        descriptor.identity.space,
        node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    let (created, acknowledgement) = owner
        .create_local_from_management_intent_with_admission(
            &mut slot,
            call.managed,
            &mut local,
            runtime,
            &mut issuer,
            signer,
            true,
        )
        .unwrap();
    assert_eq!(created, descriptor.identity.agent);
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_retry);
    assert_eq!(acknowledgement.receipt, receipt);
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    }
    let owner = owners[origin].as_mut().unwrap();
    // Exercise the same clock fence for an accepted finalization child, not
    // merely roots. This existing cut is after its durable extension/WAL and
    // before first Invoke; no failure mechanism or clock rewrite is added.
    owner.fail_finalization_once_for_test(0);
    assert_eq!(
        owner.finalize_management_intent_with_admission(
            &mut slot,
            call.managed,
            &acknowledgement,
            &mut issuer,
            true,
        ),
        Err(SharedAgentHostError::Unavailable),
    );
    let saved_finalization = slot.finalization_work().unwrap().unwrap().clone();
    let held = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap()
        .management_slot(HostNodeId(node.0))
        .unwrap()
        .clone();
    assert_eq!(held.members().len(), 2);
    assert!(held.members_evidence()[1].invoke().is_none());
    let RuntimeWork::Invoke { observed_slot, .. } = &saved_finalization else {
        unreachable!()
    };
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .fetch_max(*observed_slot + 1, Ordering::AcqRel);
    }
    let peer = (0..3)
        .find(|index| {
            *index != origin
                && !owners[*index]
                    .as_ref()
                    .unwrap()
                    ._network_host
                    .bootstrap_is_local_leader(system)
                    .unwrap()
        })
        .unwrap();
    // Sequence four is intentionally ahead of the now-next sequence three.
    // Its real signed Authority denial leaves the original Install workflow's
    // sequence untouched while still exercising first-Invoke clock ordering.
    let mut later_child_peer =
        clock_peer_intent(peer, 0xf3, 4, &descriptor, owners, fixtures, directories);
    hold_clock_peer_before_earlier_invoke(&mut later_child_peer, owners, &held, signer);
    let owner = owners[origin].as_mut().unwrap();
    // A peer can commit after its transport reply window. Exercise the
    // supported exact retry, retaining the original signed application and
    // intent; do not increase the per-request deadline or retake leadership.
    exact_management_retry("Create finalization", || {
        owner.finalize_management_intent_with_admission(
            &mut slot,
            call.managed,
            &acknowledgement,
            &mut issuer,
            true,
        )
    });
    assert_eq!(slot.finalization_work().unwrap(), Some(&saved_finalization));
    finish_clock_peer_denial(&mut later_child_peer, owners, signer);
    let owner = owners[origin].as_mut().unwrap();
    {
        let before = native_owner_physical_state(owner);
        owner
            .host
            .lock()
            .unwrap()
            .assert_terminal_retirement_reuses_manifest_for_test(
                system,
                [
                    slot.authorization_work().unwrap().unwrap(),
                    slot.finalization_work().unwrap().unwrap(),
                ],
                2,
                true,
            );
        assert_eq!(native_owner_physical_state(owner), before);
    }
    owner
        .handoff_recovered_management(&[[
            slot.authorization_work().unwrap().unwrap(),
            slot.finalization_work().unwrap().unwrap(),
        ]])
        .unwrap();
    // Retirement also returns retryable unavailability if its exact ACK
    // commits after the unchanged peer reply window. Keep the same intent
    // and signed terminal, and prove completion before any native release.
    exact_management_retry("Create ACK retirement", || {
        owner.retire_management_intent_results(&slot, call.managed, &acknowledgement, &issuer)
    });
    let terminal_manifest = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let terminal_scope = terminal_manifest
        .management_slot(HostNodeId(node.0))
        .unwrap();
    assert!(terminal_scope.all_acknowledged());
    assert!(
        !terminal_scope.is_released(),
        "all ACKs alone cannot close a lifecycle"
    );
    {
        let before = native_owner_physical_state(owner);
        owner
            .host
            .lock()
            .unwrap()
            .assert_terminal_retirement_reuses_manifest_for_test(
                system,
                [
                    slot.authorization_work().unwrap().unwrap(),
                    slot.finalization_work().unwrap().unwrap(),
                ],
                0,
                false,
            );
        assert_eq!(native_owner_physical_state(owner), before);
    }
    {
        let before = native_owner_physical_state(owner);
        let host = owner.host.lock().unwrap();
        for (member, evidence) in terminal_scope
            .members()
            .iter()
            .zip(terminal_scope.members_evidence())
        {
            let required = host
                .management_pending_admission_requirement(
                    system,
                    &[(member.anchor(), member.envelope())],
                )
                .unwrap();
            let input = host
                .management_invocation_after_anchor(system, member.anchor(), member.envelope())
                .unwrap();
            assert_eq!(required, Some(0));
            assert_eq!(input, Some(evidence.invoke().unwrap().input_id()));
            assert_eq!(
                host.management_pending_admission_with_input(
                    system,
                    member.anchor(),
                    member.envelope()
                )
                .unwrap(),
                (required, input),
                "positive ACK retains the exact original input with zero remaining Ordered rows"
            );
            let mut wrong_anchor = member.anchor().clone();
            wrong_anchor.ordered.index += 1;
            assert!(
                host.management_pending_admission_with_input(
                    system,
                    &wrong_anchor,
                    member.envelope()
                )
                .is_err()
            );
        }
        assert_eq!(
            terminal_scope.members_evidence()[0]
                .invoke()
                .unwrap()
                .input_id(),
            first.input_id()
        );
        drop(host);
        assert_eq!(native_owner_physical_state(owner), before);
        assert!(!terminal_scope.is_released());
    }
    assert!(!slot.retirement_complete().unwrap());
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    }
    let owner = owners[origin].as_mut().unwrap();
    drop(slot);
    let terminal_fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut slot = CleanManagementIntentSlot::open(IssuerMemoryStore {
        fail_retirement_after_commit: Some(terminal_fail),
        ..intent_store.clone()
    })
    .unwrap();
    let before_terminal = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        owner.finish_management_intent_retirement(
            &mut slot,
            call.managed,
            &acknowledgement,
            &issuer
        ),
        Err(SharedAgentHostError::Unavailable)
    );
    assert!(
        intent_store
            .image
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .starts_with(b"CMR2")
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_terminal);
    assert_eq!(
        owner
            ._network_host
            .management_recovery_manifest(system)
            .unwrap(),
        terminal_manifest
    );
    if origin_returns_follower {
        use crate::agent::shared_recovery::management::{
            SharedManagementRecoveryRelease, SharedManagementRecoveryReleaseRequest,
        };
        // CMR2 is actually durable and every retained member has a positive
        // ACK. This mints only its exact owner's typed release; no other voter
        // may transport it under that voter's authenticated identity.
        let request = SharedManagementRecoveryReleaseRequest::for_slot(terminal_scope).unwrap();
        let command = {
            let mut host = owner.host.lock().unwrap();
            let (candidate, signature) = host
                .prepare_signed_management_recovery_release(system, &request)
                .unwrap();
            let release =
                SharedManagementRecoveryRelease::new(candidate.request().clone(), signature)
                    .unwrap();
            crate::agent::shared_raft::AgentRaftCommand::ReleaseManagementRecovery {
                route: host
                    .supervisor_attachment_status(system)
                    .unwrap()
                    .unwrap()
                    .route,
                release,
            }
        };
        survivor = assert_origin_follower(owners, origin, survivor, system);
        let impostor = (0..3)
            .find(|index| *index != origin && *index != survivor)
            .unwrap();
        let route = AgentGenerationRoute {
            space: fixtures[origin].plan.pins.space,
            agent: fixtures[origin].plan.pins.agent,
            generation: Hash(
                retained
                    .registration()
                    .request()
                    .generation()
                    .replication_id(),
            ),
        };
        let refusal = live_networks[impostor]
            .as_ref()
            .unwrap()
            .send_agent_management_recovery_command(
                live_networks[survivor].as_ref().unwrap().agent_node_id(),
                route,
                command,
            )
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(
            refusal.is_err(),
            "a release frame must refuse a sender other than the signed scope owner"
        );
        let owner = owners[origin].as_ref().unwrap();
        assert_eq!(owner.ordered_index_for_test().unwrap(), before_terminal);
        assert_eq!(
            owner
                ._network_host
                .management_recovery_manifest(system)
                .unwrap(),
            terminal_manifest
        );
    }
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    }
    drop(slot);
    drop(issuer);
    drop(local);
    drop(owners[origin].take());
    owners[origin] = Some(reopen_with_lifecycle(
        origin,
        fixtures,
        directories,
        stores,
        providers,
        live_networks[origin].as_ref().unwrap().clone(),
        &mut lifecycle,
        signer,
    ));
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    } else {
        elect_origin(owners, origin, system);
    }
    let owner = owners[origin].as_mut().unwrap();
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    assert!(slot.retirement_complete().unwrap());
    let mut issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    exact_management_retry("Create custody release", || {
        owner.finish_management_intent_retirement(
            &mut slot,
            call.managed,
            &acknowledgement,
            &issuer,
        )
    });
    let released = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let released = released
        .management_slot(HostNodeId(node.0))
        .unwrap()
        .clone();
    assert!(released.is_released());
    assert!(released.all_acknowledged());
    let before = owner.ordered_index_for_test().unwrap();
    owner
        .finish_management_intent_retirement(&mut slot, call.managed, &acknowledgement, &issuer)
        .unwrap();
    assert_eq!(owner.ordered_index_for_test().unwrap(), before);
    if origin_returns_follower {
        survivor = assert_origin_follower(owners, origin, survivor, system);
    }
    let owner = owners[origin].as_mut().unwrap();
    // A real next Install uses monotonic replacement of that full signed
    // terminal scope, not absence of the old intent or a fresh read slot.
    fixtures[origin]
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::AcqRel);
    let package = admit_actor_package(include_bytes!(
        "../../../../../../vosx/blobs/system_catalog.vos"
    ))
    .unwrap();
    let configuration = system_catalog::SystemCatalogConfiguration {
        space: descriptor.identity.space.0,
        system_agent: descriptor.identity.agent.0,
        system_runtime_deployment: descriptor.identity.runtime_deployment.0,
        actor: ActorId::top_level(descriptor.identity.agent, &package.manifest().name).0,
        deployment: package.deployment().0,
        program: package.program().0,
        authority: system_catalog::CatalogAuthorityState {
            policy: descriptor.authority.policy.0,
            issuer: system_catalog::CatalogIssuerState {
                principal: descriptor.authority.issuer.principal.0,
                actor: descriptor.authority.issuer.actor.0,
                deployment: descriptor.authority.issuer.deployment.0,
                program: descriptor.authority.issuer.program.0,
                producer: descriptor.authority.issuer.producer.0,
            },
            public_key: descriptor.authority.public_key,
            initial_epoch: descriptor.authority.initial_epoch,
        },
    };
    let install = install_request(
        descriptor.identity.agent,
        &package,
        0xeb,
        Some(configuration.encode()),
    );
    let mut install_call = call.clone();
    install_call.request_sequence = NonZeroU64::new(3).unwrap();
    install_call.plan = install.authorization_plan().unwrap();
    install_call.invocation = install_call.expected_invocation();
    install_call.signature = credential.sign(&install_call.signing_bytes()).to_bytes();
    let previous = slot.intent().unwrap().clone();
    slot.handoff_retired(
        &previous,
        CleanManagementIntent::new(
            owner.authority_target(),
            install_call.managed,
            install.clone(),
            install_call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap(),
        &RawCredentialVerifier,
    )
    .unwrap();
    let mut local = LocalAgentHost::open(
        &local_root,
        descriptor.identity.space,
        node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    assert_eq!(local.list().unwrap(), vec![descriptor.identity.agent]);
    let empty_local = local
        .observe_management_application(
            descriptor.identity.agent,
            &request,
            &acknowledgement.receipt,
        )
        .unwrap();
    let installed_actor = ActorId::top_level(descriptor.identity.agent, &package.manifest().name);
    assert!(matches!(
        local.supervisor_invocation_material(descriptor.identity.agent, installed_actor),
        Err(crate::agent::local_sdk_host::LocalAgentHostError::Driver(
            crate::agent::driver::AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::NotFound
            )
        ))
    ));
    let accepted_install_slot = fixtures[origin]
        .logical_slot
        .as_ref()
        .unwrap()
        .load(Ordering::Acquire);
    local = assert_local_actor_count(local, descriptor.identity.agent, 0);
    let prior_issuer_sequence = issuer.sequence_high_water();
    owner.finalization_failure_once = Some(6);
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        assert_eq!(
            owner.install_local_from_management_intent(
                &mut slot,
                &mut local,
                &package,
                &mut issuer,
                signer
            ),
            Err(SharedAgentHostError::Unavailable)
        );
        // A transport timeout may precede the deliberate issuer-write crash.
        // Reach that exact crash with the retained intent, never proceed past
        // it to publish the actor before the offline/reopen assertions.
        owner.finalization_failure_once.is_none()
    }));
    let active = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let active = active.management_slot(HostNodeId(node.0)).unwrap().clone();
    assert!(active.sequence() > released.sequence());
    assert_eq!(
        active.registration().request().previous(),
        Some(released.commitment())
    );
    assert!(!active.is_released());
    assert_eq!(active.members().len(), 1);
    let install_original = active.members()[0].clone();
    let RuntimeWork::Invoke { observed_slot, .. } = install_original.envelope() else {
        unreachable!()
    };
    assert_eq!(*observed_slot, accepted_install_slot);
    assert_eq!(
        slot.authorization_work().unwrap(),
        Some(install_original.envelope())
    );
    assert_eq!(
        slot.authorization_anchor().unwrap(),
        Some(install_original.anchor())
    );
    let install_first = active.members_evidence()[0].invoke().unwrap().clone();
    assert!(matches!(
        install_first.outcome(),
        RuntimeOutcome::Completed(Ok(_))
    ));
    assert!(active.members_evidence()[0].acknowledgement().is_none());
    assert_eq!(issuer.sequence_high_water(), prior_issuer_sequence);
    assert_eq!(
        local
            .observe_management_application(
                descriptor.identity.agent,
                &request,
                &acknowledgement.receipt,
            )
            .unwrap(),
        empty_local,
        "authorization must not publish a Local actor"
    );
    let saved_install_intent = intent_store.image.lock().unwrap().clone();
    let saved_install_issuer = issuer_store.image.lock().unwrap().clone();
    fixtures[origin]
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::AcqRel);
    drop(slot);
    drop(issuer);
    drop(local);
    let offline_host = owners[origin].as_ref().unwrap().host.clone();
    drop(owners[origin].take());
    stop_network(live_networks[origin].take().unwrap());
    assert!(wait_until(std::time::Duration::from_secs(10), || {
        live_networks
            .iter()
            .flatten()
            .all(|network| !network.connected_peers().contains(&offline_peer))
    }));
    survivor = prune_and_catch_up_offline_management(
        origin,
        owners,
        fixtures,
        &offline_host,
        &active,
        &intent_store,
        &saved_install_intent,
        0xee,
    );
    assert_eq!(*issuer_store.image.lock().unwrap(), saved_install_issuer);
    drop(offline_host);
    live_networks[origin] = Some(restart_network(origin));
    for index in 0..3 {
        if index != origin {
            live_networks[origin]
                .as_ref()
                .unwrap()
                .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
        }
    }
    owners[origin] = Some(reopen_with_lifecycle(
        origin,
        fixtures,
        directories,
        stores,
        providers,
        live_networks[origin].as_ref().unwrap().clone(),
        &mut lifecycle,
        signer,
    ));
    // Both cases now qualify unfinished Install through the original online
    // Follower. No election or transport retirement is used to regain leadership.
    survivor = assert_origin_follower(owners, origin, survivor, system);
    assert_eq!(*intent_store.image.lock().unwrap(), saved_install_intent);
    assert_eq!(*issuer_store.image.lock().unwrap(), saved_install_issuer);
    let owner = owners[origin].as_mut().unwrap();
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    let mut issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    let mut local = LocalAgentHost::open(
        &local_root,
        descriptor.identity.space,
        node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    assert_eq!(local.list().unwrap(), vec![descriptor.identity.agent]);
    assert_eq!(
        local
            .observe_management_application(
                descriptor.identity.agent,
                &request,
                &acknowledgement.receipt,
            )
            .unwrap(),
        empty_local
    );
    assert!(matches!(
        local.supervisor_invocation_material(descriptor.identity.agent, installed_actor),
        Err(crate::agent::local_sdk_host::LocalAgentHostError::Driver(
            crate::agent::driver::AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::NotFound
            )
        ))
    ));
    local = assert_local_actor_count(local, descriptor.identity.agent, 0);
    let before_install_retry = owner.ordered_index_for_test().unwrap();
    let install_receipt = exact_management_retry("retained Install approval", || {
        owner.issue_management_intent_with_admission(
            &mut slot,
            install_call.managed,
            &mut issuer,
            signer,
            true,
        )
    });
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before_install_retry
    );
    assert_eq!(
        slot.authorization_work().unwrap(),
        Some(install_original.envelope())
    );
    assert_eq!(
        slot.authorization_anchor().unwrap(),
        Some(install_original.anchor())
    );
    assert_eq!(
        owner
            .host
            .lock()
            .unwrap()
            .replay_durable_management_denial(
                system,
                install_original.anchor(),
                install_original.envelope(),
            )
            .unwrap(),
        *install_first.outcome()
    );
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before_install_retry
    );
    survivor = assert_origin_follower(owners, origin, survivor, system);
    let owner = owners[origin].as_mut().unwrap();
    let installed = exact_management_retry("retained Local Install", || {
        owner.install_local_from_management_intent(
            &mut slot,
            &mut local,
            &package,
            &mut issuer,
            signer,
        )
    });
    assert_eq!(installed.receipt, install_receipt);
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before_install_retry
    );
    assert_eq!(
        local
            .supervisor_invocation_material(descriptor.identity.agent, installed_actor)
            .unwrap()
            .actor
            .entry
            .actor,
        installed_actor
    );
    local = assert_local_actor_count(local, descriptor.identity.agent, 1);
    let active = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let active = active.management_slot(HostNodeId(node.0)).unwrap();
    assert!(active.sequence() > released.sequence());
    assert_eq!(
        active.registration().request().previous(),
        Some(released.commitment())
    );
    assert!(!active.is_released());
    exact_management_retry("Install finalization", || {
        owner.finalize_management_intent_with_admission(
            &mut slot,
            install_call.managed,
            &installed,
            &mut issuer,
            true,
        )
    });
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before_install_retry + 1
    );
    survivor = assert_origin_follower(owners, origin, survivor, system);
    let owner = owners[origin].as_mut().unwrap();
    exact_management_retry("Install ACKs and custody release", || {
        owner.finish_live_management_intent(&mut slot, install_call.managed, &installed, &issuer)
    });
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before_install_retry + 3
    );
    let finished = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    assert!(
        finished
            .management_slot(HostNodeId(node.0))
            .unwrap()
            .is_released()
    );
    assert!(slot.retirement_complete().unwrap());
    let before = owner.ordered_index_for_test().unwrap();
    let observation = local
        .observe_management_application(descriptor.identity.agent, &install, &installed.receipt)
        .unwrap();
    assert_eq!(observation.result(), &Ok(installed.application.clone()));
    assert_eq!(
        owner
            .install_local_actor(
                intent_store.clone(),
                issuer_store.clone(),
                install,
                install_call,
                &mut local,
                &package,
                signer
            )
            .unwrap(),
        installed
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before);
    assert_origin_follower(owners, origin, survivor, system);
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}
