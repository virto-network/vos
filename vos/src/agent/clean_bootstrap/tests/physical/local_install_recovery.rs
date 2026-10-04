//! Same-open IMAGE Local Install recovery after genuine late metadata commit.
//! System/Local images and authenticated transport are physical. Lifecycle
//! intent/issuer stores use the existing owned, non-clone MEMORY LeaseStore
//! wrappers, retained by the original controller. This is not filesystem
//! lifecycle durability, cold-adoption, or released main/CLI qualification.

use super::super::genesis_readmission::{Fault, LeaseStore};
use super::*;
use crate::actors::codec::{Decode as _, Encode as _};
use crate::agent::clean_management_intent::CleanManagementIntentSlot;
use crate::agent::local_lifecycle::{
    LocalInstallSubmission, LocalLifecycleController, LocalLifecycleStoreFactory,
};
use crate::agent::local_sdk_host::LocalAgentHost;
use crate::agent::production_owner::{
    AgentProductionOwner, AgentProductionOwnerError, AuthorityProjectionQueryAuthenticator,
};
use crate::agent::supervisor::{AgentRouteKey, AgentSupervisorLimits};
use crate::agent_sdk::wire::CanonicalWire as _;
use crate::service::wire::ServiceWire as _;
use ed25519_dalek::Signer as _;
use std::os::unix::fs::OpenOptionsExt as _;

struct Stores {
    space: SpaceId,
    agent: AgentId,
    intent: IssuerMemoryStore,
    issuer: IssuerMemoryStore,
    opens: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
}
impl LocalLifecycleStoreFactory for Stores {
    type Intent = LeaseStore;
    type Issuer = LeaseStore;
    type Error = ();
    fn discover(&mut self, _: SpaceId, _: usize) -> Result<Vec<AgentId>, ()> {
        panic!("same-open Local retry must not discover lifecycle stores")
    }
    fn open(&mut self, space: SpaceId, agent: AgentId) -> Result<(Self::Intent, Self::Issuer), ()> {
        assert!((space, agent) == (self.space, self.agent));
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
    fn open_existing(
        &mut self,
        _: SpaceId,
        _: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), ()> {
        panic!("same-open Local retry must retain its already-held lifecycle stores")
    }
}
type Controller = TestLocalLifecycle<Stores>;

// The cut uses only the existing authenticated Raft isolation seam. Restore
// every actual peer on any later assertion/panic, including the original owner
// already moved into the same lifecycle controller.
struct RestoreIsolationOnDrop<'a> {
    original: &'a mut Controller,
    owners: &'a [Option<MemoryBootstrapOwner>],
    agent: HostAgentId,
    armed: bool,
}
impl RestoreIsolationOnDrop<'_> {
    fn restore_checked(&mut self) -> Result<(), SharedAgentHostError> {
        let mut failed = self
            .original
            .system_for_test()
            ._network_host
            .set_raft_isolated_for_test(self.agent, false)
            .err();
        for owner in self.owners.iter().flatten() {
            if let Err(error) = owner
                ._network_host
                .set_raft_isolated_for_test(self.agent, false)
            {
                if failed.is_none() {
                    failed = Some(error);
                }
            }
        }
        if let Some(error) = failed {
            return Err(error);
        }
        self.armed = false;
        Ok(())
    }
}
impl Drop for RestoreIsolationOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.restore_checked();
        }
    }
}

struct InventoryAuthenticator {
    index: usize,
    node: NodeId,
    sequence: u8,
    calls: Arc<AtomicUsize>,
}
impl AuthorityProjectionQueryAuthenticator for InventoryAuthenticator {
    fn expected_kind(&self) -> AuthorityCredentialKind {
        AuthorityCredentialKind::Ssh
    }
    fn authenticate(
        &mut self,
        authority: AuthorityActorTarget,
        selector: AuthorityProjectionSelector,
    ) -> Result<AuthorityProjectionQuery, AgentProductionOwnerError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(AgentProductionOwnerError::InventoryLimit)?;
        self.calls.fetch_add(1, Ordering::AcqRel);
        let public = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
            .verifying_key()
            .to_bytes();
        let key = SigningKey::from_bytes(&[[NODE_SEED, 0xd2, 0xd3][self.index]; 32]);
        let mut request = AuthorityProjectionQuery {
            authority,
            credential: CredentialId::of_public_key(&public),
            nonce: inventory_nonce(0x6b, self.sequence),
            selector,
            recovery: None,
            authentication: AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key: public,
                node: self.node,
                request_binding: Hash([0x6c; 32]),
                signature: [1; 64],
            },
        };
        let signature = key.sign(&request.signing_bytes()).to_bytes();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            signature: actual, ..
        } = &mut request.authentication
        else {
            unreachable!()
        };
        *actual = signature;
        Ok(request)
    }
}

fn retry_until<T>(
    deadline: std::time::Instant,
    phase: &str,
    mut operation: impl FnMut() -> Result<T, SharedAgentHostError>,
) -> T {
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "{phase} exceeded its whole bound"
        );
        let result = operation();
        assert!(
            std::time::Instant::now() <= deadline,
            "{phase} exceeded its whole bound"
        );
        match result {
            Ok(value) => return value,
            Err(SharedAgentHostError::Unavailable | SharedAgentHostError::Conflict) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("{phase} failed: {error:?}"),
        }
    }
}

// Keep this normal production call in one place when the ingress patch adds
// the recovery-only flag. The baseline deliberately exercises today's guard.
fn submit(
    owner: &mut AgentProductionOwner,
    install: &crate::agent_sdk::InstallActor,
    call: &AuthorityCredentialCall,
    package: &AdmittedActorPackage,
) -> Result<ManagementApplicationAck, AgentProductionOwnerError> {
    owner.install_local_actor(install.clone(), call.clone(), package.clone())
}

#[allow(clippy::too_many_lines)]
pub(super) fn exercise(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
) {
    assert_eq!(owners.len(), 3);
    let agent = HostAgentId(fixtures[origin].plan.pins.agent.0);
    for owner in owners.iter().flatten() {
        assert_eq!(owner.pins.replicas.members().len(), 3);
        assert!(!owner.management_admission_held().unwrap());
    }
    let original = owners[origin].as_ref().unwrap();
    assert!(
        original
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap()
    );
    let node = original.pins.node;
    let target = original.authority_target();
    let current = {
        let request = query(original, origin, 0x67);
        let work = original
            .prepare_authority_observation_work(&request)
            .unwrap();
        let outcome =
            management_retention::exact_management_retry("Local initial credential", || {
                original._network_host.with_authority_observation(
                    agent,
                    request.commitment(),
                    |host| host.observe_system_authority(agent, &work),
                )
            });
        let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            panic!("Local credential observation did not complete");
        };
        assert_eq!(reply.status, InvocationStatus::Done);
        let Some(crate::actors::value::Value::Bytes(bytes)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            panic!("Local credential observation returned no projection bytes");
        };
        let projection = AuthorityCredentialProjection::decode(&bytes).unwrap();
        assert!(projection.query == request);
        assert_eq!(projection.status, AuthorityCredentialStatus::Active);
        projection
    };
    // Ordinary Local uses its canonical bundled IMAGE runtime, independently
    // of the System-observation candidate selected for the three-node fixture.
    let mut runtime = PackageEnvelope::decode(shape_only_runtime().exact_bytes()).unwrap();
    let program = include_bytes!("../../../../../../vosx/blobs/agent_runtime.pvm").to_vec();
    let program_ref = BlobRef::of_bytes(&program);
    let PackageManifest::AgentRuntime(manifest) = &mut runtime.manifest else {
        unreachable!()
    };
    manifest.outer_program = program_ref.clone();
    runtime.artifacts = vec![PackageArtifact {
        identity: program_ref,
        bytes: program,
    }];
    runtime.manifest.signing_mut().signature = SigningKey::from_bytes(&[0x63; 32])
        .sign(&runtime.signing_bytes().unwrap())
        .to_bytes();
    let runtime = admit_runtime_package(&runtime.encode().unwrap()).unwrap();
    let mut descriptor = original.pins.descriptor.clone();
    descriptor.identity.profile = AgentProfile::Local;
    descriptor.identity.runtime_deployment = runtime.deployment();
    descriptor.identity.runtime_program = runtime.program();
    descriptor.identity.runtime_producer = runtime.producer();
    descriptor.runtime_package = runtime.package_ref().clone();
    descriptor.runtime_contract = runtime.manifest().contract;
    descriptor.capabilities = runtime.capabilities();
    descriptor.creation_nonce = Hash([0x68; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    let mut replica = descriptor
        .replicas
        .iter()
        .find(|replica| replica.node == node)
        .unwrap()
        .clone();
    replica.principal = descriptor.identity.owner;
    descriptor.replicas = vec![replica];
    descriptor.validate().unwrap();
    assert_eq!(descriptor.identity.owner, current.principal);
    let credential = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let sign = |call: &mut AuthorityCredentialCall| {
        call.invocation = call.expected_invocation();
        call.signature = credential.sign(&call.signing_bytes()).to_bytes();
        call.verify_with(&RawCredentialVerifier).unwrap();
    };
    let create_request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let (mut create_call, _) =
        credential_call_and_approval(&descriptor, &create_request, &credential);
    create_call.authority = target;
    create_call.request_sequence =
        NonZeroU64::new(current.management_request_high_water + 1).unwrap();
    sign(&mut create_call);
    let local_root = directories[origin].0.join("same-open-image-local");
    let local = LocalAgentHost::create(
        &local_root,
        descriptor.identity.space,
        node,
        fixtures[origin].trust.clone(),
    )
    .unwrap();
    let intent_store = IssuerMemoryStore::default();
    let issuer_store = IssuerMemoryStore::default();
    let opens = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));
    let stores = Stores {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        intent: intent_store.clone(),
        issuer: issuer_store.clone(),
        opens: Arc::clone(&opens),
        live: Arc::clone(&live),
    };
    let mut controller = LocalLifecycleController::new(
        owners[origin].take().unwrap(),
        local,
        stores,
        CountingSigner::new(),
    )
    .unwrap();
    let setup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let (created, create_ack) = retry_until(setup_deadline, "ordinary Local Create", || {
        controller.create(descriptor.clone(), create_call.clone(), runtime.clone())
    });
    assert_eq!(created, descriptor.identity.agent);
    create_ack.verify_with(&RawCredentialVerifier).unwrap();
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert_eq!(live.load(Ordering::Acquire), 2);
    // This is a genuinely new Install after Create, rather than altering a
    // captured retry's clock. Keep this normal later slot for every exact retry.
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .fetch_add(1, Ordering::AcqRel);
    }
    let package = admit_actor_package(include_bytes!(
        "../../../../../../vosx/blobs/system_catalog.vos"
    ))
    .unwrap();
    let binding = descriptor.authority;
    let configuration = system_catalog::SystemCatalogConfiguration {
        space: descriptor.identity.space.0,
        system_agent: descriptor.identity.agent.0,
        system_runtime_deployment: descriptor.identity.runtime_deployment.0,
        actor: ActorId::top_level(descriptor.identity.agent, &package.manifest().name).0,
        deployment: package.deployment().0,
        program: package.program().0,
        authority: system_catalog::CatalogAuthorityState {
            policy: binding.policy.0,
            issuer: system_catalog::CatalogIssuerState {
                principal: binding.issuer.principal.0,
                actor: binding.issuer.actor.0,
                deployment: binding.issuer.deployment.0,
                program: binding.issuer.program.0,
                producer: binding.issuer.producer.0,
            },
            public_key: binding.public_key,
            initial_epoch: binding.initial_epoch,
        },
    };
    assert!(configuration.is_valid());
    let request = install_request(
        descriptor.identity.agent,
        &package,
        0x69,
        Some(configuration.encode()),
    );
    validate_actor_install(&descriptor, &request, &package).unwrap();
    let ManagementRequest::Install(install) = &request else {
        unreachable!()
    };
    let install = (**install).clone();
    let mut call = create_call.clone();
    call.request_sequence = NonZeroU64::new(create_call.request_sequence.get() + 1).unwrap();
    call.plan = request.authorization_plan().unwrap();
    sign(&mut call);
    let submission =
        LocalInstallSubmission::new(install.clone(), call.clone(), package.clone()).unwrap();
    let exact_request = submission.encode();
    let request_path = directories[origin].0.join("retained-local-install.liq1");
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&request_path)
            .unwrap();
        file.write_all(&exact_request).unwrap();
        file.sync_all().unwrap();
    }
    assert!(
        LocalInstallSubmission::decode(&std::fs::read(&request_path).unwrap())
            .unwrap()
            .encode()
            == exact_request
    );
    let image_path = local_root
        .join(
            descriptor
                .identity
                .agent
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .join("image");
    let image_before = std::fs::read(&image_path).unwrap();
    let issuer_before = issuer_store.image.lock().unwrap().clone();
    let issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        binding,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    assert_eq!(issuer.sequence_high_water(), 1);
    assert_eq!(issuer.acknowledged_through(), 1);
    assert!(!issuer.has_pending_decision());
    assert!(
        issuer
            .recover_finalized_application(
                target,
                call.managed,
                &request,
                &call,
                &RawCredentialVerifier
            )
            .unwrap()
            .is_none()
    );
    drop(issuer);
    let (host, database, state_before) = {
        let original = controller.system_for_test();
        assert!(
            original
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap()
        );
        assert!(!original.management_admission_held().unwrap());
        let host = Arc::clone(&original.host);
        let database = host.lock().unwrap().raft_database(agent).unwrap();
        let state = host.lock().unwrap().clean_state_commitment(agent).unwrap();
        (host, database, state)
    };
    retry_until(setup_deadline, "Local pre-cut committed log", || {
        let meta = crate::raft::RaftMeta::load(&database).unwrap();
        let last = crate::raft::RaftLog::open(Arc::clone(&database))
            .unwrap()
            .last_index();
        if meta.commit_index == last {
            Ok(())
        } else {
            Err(SharedAgentHostError::Unavailable)
        }
    });
    let meta_before = crate::raft::RaftMeta::load(&database).unwrap();
    let last_before = crate::raft::RaftLog::open(Arc::clone(&database))
        .unwrap()
        .last_index();
    let recovery_started = std::time::Instant::now();
    let deadline = recovery_started + std::time::Duration::from_secs(30);
    let mut restore = RestoreIsolationOnDrop {
        original: &mut controller,
        owners,
        agent,
        armed: true,
    };
    restore
        .original
        .system_for_test()
        ._network_host
        .set_raft_isolated_for_test(agent, true)
        .unwrap();
    for owner in owners.iter().flatten() {
        owner
            ._network_host
            .set_raft_isolated_for_test(agent, true)
            .unwrap();
    }
    let cut_started = std::time::Instant::now();
    let cut = restore
        .original
        .install(install.clone(), call.clone(), package.clone());
    let cut_elapsed = cut_started.elapsed();
    let observed = (|| {
        let meta = crate::raft::RaftMeta::load(&database)?;
        let log = crate::raft::RaftLog::open(Arc::clone(&database))?;
        let last = log.last_index();
        let entries = log.entries(last, last)?;
        Ok::<_, crate::commit::CommitError>((meta, last, entries))
    })();
    // A quorum must include the original longer-log owner until its exact
    // append commits; the two shorter logs may legitimately discard it.
    restore
        .original
        .system_for_test()
        ._network_host
        .set_raft_isolated_for_test(agent, false)
        .unwrap();
    owners[(origin + 1) % 3]
        .as_ref()
        .unwrap()
        ._network_host
        .set_raft_isolated_for_test(agent, false)
        .unwrap();
    let (meta_after, last_after, entries) = observed.unwrap();
    assert!(matches!(cut, Err(SharedAgentHostError::Unavailable)));
    assert!(cut_elapsed >= std::time::Duration::from_millis(1_800));
    assert!(std::time::Instant::now() < deadline);
    assert_eq!(meta_after.commit_index, meta_before.commit_index);
    assert_eq!(last_after, last_before + 1);
    assert_eq!(entries.len(), 1);
    let vos_raft::EntryKind::Data { payload } =
        crate::agent::shared_raft::decode_agent_raft_entry_kind(&entries[0].payload).unwrap()
    else {
        panic!("Local cut must append actual signed metadata");
    };
    let crate::agent::shared_raft::AgentRaftCommand::RegisterManagementRecovery {
        registration,
        ..
    } = crate::agent::shared_raft::AgentRaftCommand::decode(&payload).unwrap()
    else {
        panic!("Local cut must append RegisterManagementRecovery");
    };
    let retained = retry_until(deadline, "Local committed original registration", || {
        let original = restore.original.system_for_test();
        let manifest = original._network_host.management_recovery_manifest(agent)?;
        let Some(slot) = manifest.management_slot(HostNodeId(node.0)).filter(|slot| {
            !slot.is_released()
                && slot
                    .members()
                    .first()
                    .is_some_and(|member| member.work().invocation == call.invocation)
        }) else {
            return Err(SharedAgentHostError::Unavailable);
        };
        assert!(slot.registration() == &registration);
        Ok(slot.clone())
    });
    restore.restore_checked().unwrap();
    drop(restore);
    assert!(std::time::Instant::now() <= deadline);
    assert_eq!(retained.owner(), HostNodeId(node.0));
    assert_eq!(retained.origin_owner(), retained.owner());
    assert!(!retained.is_released());
    assert_eq!(retained.members().len(), 1);
    assert!(retained.members()[0].parent().is_none());
    assert!(retained.members_evidence()[0].invoke().is_none());
    assert!(retained.members_evidence()[0].acknowledgement().is_none());
    let saved_anchor = retained.members()[0].anchor().clone();
    let saved_work = retained.members()[0].envelope().clone();
    {
        let original = controller.system_for_test();
        assert!(original.management_admission_held().unwrap());
        assert!(
            original
                ._network_host
                .current_management_pending(agent, call.invocation)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            original._network_host.ensure_management_pending_member(
                agent,
                &saved_anchor,
                &saved_work
            ),
            Err(SharedAgentHostError::Conflict)
        ));
        let mut hosted = original.host.lock().unwrap();
        let mut wrong_anchor = saved_anchor.clone();
        wrong_anchor.ordered.index += 1;
        assert!(
            hosted
                .management_pending_admission_requirement(agent, &[(&wrong_anchor, &saved_work)])
                .is_err()
        );
        let mut changed_work = saved_work.clone();
        let RuntimeWork::Invoke { observed_slot, .. } = &mut changed_work else {
            unreachable!()
        };
        *observed_slot += 1;
        assert!(
            hosted
                .management_pending_admission_requirement(agent, &[(&saved_anchor, &changed_work)])
                .is_err()
        );
        assert!(hosted.clean_state_commitment(agent).unwrap() == state_before);
    }
    let bare_intent = intent_store.image.lock().unwrap().clone();
    assert!(bare_intent.as_ref().unwrap().starts_with(b"CMI4"));
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    let current = slot.intent().unwrap();
    assert!(current.request() == &request && current.call() == &call);
    assert!(slot.authorization_work().unwrap().is_none());
    assert!(slot.authorization_anchor().unwrap().is_none());
    assert!(slot.finalization_work().unwrap().is_none());
    assert!(slot.finalization_anchor().unwrap().is_none());
    assert!(!slot.retirement_complete().unwrap());
    assert!(slot.load_actor().unwrap().unwrap().exact_bytes() == package.exact_bytes());
    drop(slot);
    assert!(issuer_store.image.lock().unwrap().clone() == issuer_before);
    assert!(std::fs::read(&image_path).unwrap() == image_before);
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert_eq!(live.load(Ordering::Acquire), 2);
    eprintln!(
        "fixed_three_local_install phase=late_registration bare_intent=true current_pending=false elapsed_ms={}",
        recovery_started.elapsed().as_millis()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut production = AgentProductionOwner::start_local(
        node,
        AgentSupervisorLimits::default(),
        Box::new(controller),
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
    assert!(std::time::Instant::now() < deadline);
    assert!(production.is_running());
    assert!(!production.is_ready());
    assert!(matches!(
        production.ingress(),
        Err(AgentProductionOwnerError::ProjectionNotReady)
    ));
    assert_eq!(calls.load(Ordering::Acquire), 0);
    // Every substitute is a complete signed request or a separately admitted
    // package. It must not acquire fresh custody through the quarantine gate.
    let mut absent_call = call.clone();
    absent_call.request_sequence = NonZeroU64::new(call.request_sequence.get() + 1).unwrap();
    sign(&mut absent_call);
    let mut wrong_node = call.clone();
    wrong_node.authenticated_node = Some(fixtures[(origin + 1) % 3].plan.pins.node);
    sign(&mut wrong_node);
    let mut missing_node = call.clone();
    missing_node.authenticated_node = None;
    sign(&mut missing_node);
    let mut changed_install = install.clone();
    changed_install.installation_id = InstallationId([0x6d; 32]);
    let mut changed_call = call.clone();
    changed_call.plan = ManagementRequest::Install(Box::new(changed_install.clone()))
        .authorization_plan()
        .unwrap();
    sign(&mut changed_call);
    let wrong_package =
        admitted_standard_actor_for_test("other-image-install", StateLane::Linear, 0x6e);
    assert!(
        LocalInstallSubmission::new(install.clone(), call.clone(), wrong_package.clone()).is_err()
    );
    for (refused_install, refused_call, refused_package) in [
        (&install, &absent_call, &package),
        (&install, &wrong_node, &package),
        (&install, &missing_node, &package),
        (&changed_install, &changed_call, &package),
        (&install, &call, &wrong_package),
    ] {
        let refusal = submit(
            &mut production,
            refused_install,
            refused_call,
            refused_package,
        );
        assert!(matches!(
            refusal,
            Err(AgentProductionOwnerError::InvalidConfiguration
                | AgentProductionOwnerError::ProjectionNotReady
                | AgentProductionOwnerError::Lifecycle(
                    SharedAgentHostError::ScopeMismatch | SharedAgentHostError::Conflict
                ))
        ));
        assert!(std::time::Instant::now() <= deadline);
        assert!(intent_store.image.lock().unwrap().clone() == bare_intent);
        assert!(issuer_store.image.lock().unwrap().clone() == issuer_before);
        assert!(intent_store.actor.lock().unwrap().as_deref() == Some(package.exact_bytes()));
        assert!(std::fs::read(&image_path).unwrap() == image_before);
        assert!(std::fs::read(&request_path).unwrap() == exact_request);
        assert_eq!(opens.load(Ordering::Acquire), 1);
        assert_eq!(live.load(Ordering::Acquire), 2);
        let mut hosted = host.lock().unwrap();
        assert!(hosted.clean_state_commitment(agent).unwrap() == state_before);
        assert!(
            hosted
                .recovery_manifest(agent)
                .unwrap()
                .management_slot(retained.owner())
                == Some(&retained)
        );
    }
    eprintln!(
        "fixed_three_local_install phase=normal_guard_negatives no_invoke=true elapsed_ms={}",
        recovery_started.elapsed().as_millis()
    );
    // The baseline guard currently refuses here. A conservative same-open map
    // predicate alone also cannot complete this genuine map-absent late commit.
    // Keep the positive expectation so neither refusal is called qualification.
    let acknowledgement = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "normal retained Local recovery exceeded whole30"
        );
        let result = submit(&mut production, &install, &call, &package);
        assert!(
            std::time::Instant::now() <= deadline,
            "normal retained Local recovery exceeded whole30"
        );
        match result {
            Ok(acknowledgement) => break acknowledgement,
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Unavailable | SharedAgentHostError::Conflict,
            )) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => {
                production.shutdown_and_join().unwrap();
                panic!("normal retained Local recovery refused: {error:?}");
            }
        }
    };
    acknowledgement.verify_with(&RawCredentialVerifier).unwrap();
    let mut slot = CleanManagementIntentSlot::open(intent_store.clone()).unwrap();
    assert!(slot.intent().unwrap().request() == &request && slot.intent().unwrap().call() == &call);
    assert!(slot.authorization_anchor().unwrap() == Some(&saved_anchor));
    assert!(slot.authorization_work().unwrap() == Some(&saved_work));
    assert!(slot.finalization_anchor().unwrap().is_some());
    assert!(slot.finalization_work().unwrap().is_some());
    assert!(slot.retirement_complete().unwrap());
    assert!(slot.load_actor().unwrap().unwrap().exact_bytes() == package.exact_bytes());
    drop(slot);
    let issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        binding,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    assert_eq!(issuer.sequence_high_water(), 2);
    assert_eq!(issuer.acknowledged_through(), 2);
    assert!(!issuer.has_pending_decision());
    let (_, recorded) = issuer
        .recover_finalized_application(
            target,
            call.managed,
            &request,
            &call,
            &RawCredentialVerifier,
        )
        .unwrap()
        .unwrap();
    assert!(recorded == acknowledgement);
    drop(issuer);
    assert!(production.is_ready());
    let key = AgentRouteKey::new(
        descriptor.identity.space,
        descriptor.identity.agent,
        install.entry.actor,
    )
    .unwrap();
    let identity = production.handle().snapshot(key).unwrap().identity();
    assert_eq!(identity.profile(), AgentProfile::Local);
    assert_eq!(
        identity.runtime_deployment(),
        descriptor.identity.runtime_deployment
    );
    assert_eq!(identity.actor_deployment(), install.entry.deployment);
    assert_eq!(identity.actor_program(), install.entry.program);
    let manifest = host.lock().unwrap().recovery_manifest(agent).unwrap();
    let final_slot = manifest.management_slot(retained.owner()).unwrap();
    assert!(final_slot.is_released());
    assert_eq!(final_slot.origin_owner(), retained.origin_owner());
    assert_eq!(final_slot.members().len(), 2);
    assert!(final_slot.members()[0] == retained.members()[0]);
    assert!(final_slot.members()[1].parent() == Some(final_slot.members()[0].commitment()));
    assert!(
        final_slot
            .members_evidence()
            .iter()
            .all(|evidence| evidence.invoke().is_some() && evidence.acknowledgement().is_some())
    );
    let completed_position = host.lock().unwrap().journal_position(agent).unwrap();
    let completed_state = host.lock().unwrap().clean_state_commitment(agent).unwrap();
    let completed_intent = intent_store.image.lock().unwrap().clone();
    let completed_issuer = issuer_store.image.lock().unwrap().clone();
    let completed_image = std::fs::read(&image_path).unwrap();
    assert!(completed_image != image_before);
    let retry = submit(&mut production, &install, &call, &package).unwrap();
    assert!(std::time::Instant::now() <= deadline);
    assert!(retry == acknowledgement);
    assert!(host.lock().unwrap().journal_position(agent).unwrap() == completed_position);
    assert!(host.lock().unwrap().clean_state_commitment(agent).unwrap() == completed_state);
    assert!(intent_store.image.lock().unwrap().clone() == completed_intent);
    assert!(issuer_store.image.lock().unwrap().clone() == completed_issuer);
    assert!(std::fs::read(&image_path).unwrap() == completed_image);
    assert!(std::fs::read(&request_path).unwrap() == exact_request);
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert_eq!(live.load(Ordering::Acquire), 2);
    assert!(recovery_started.elapsed() <= std::time::Duration::from_secs(30));
    eprintln!(
        "fixed_three_local_install phase=terminal_exact_retry released=true elapsed_ms={}",
        recovery_started.elapsed().as_millis()
    );
    production.shutdown_and_join().unwrap();
    assert_eq!(live.load(Ordering::Acquire), 0);
}
