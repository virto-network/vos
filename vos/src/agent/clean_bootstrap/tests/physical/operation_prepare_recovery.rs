//! Preparation-only recovery after a real fixed-three late metadata commit.
//! The registered API credential is enrolled through signed Admin Invoke/ACK.
//! The native owner and its System host/ledger leases remain original at the
//! live cut. Operation images/journal reuse the existing non-clone fsync test
//! stores; hardened CSF1 filesystem lease qualification remains separate.
//! The cut originates on the actual leader and does not reproduce follower
//! forwarding timing or qualify a released-bundle public workflow.

use super::*;
use crate::agent::authority_operation_coordinator::{
    AuthorityOperationActorDispatch, AuthorityOperationActorMethod,
};
use crate::agent::authority_operation_issuer::AuthorityOperationEvidenceSigner;
use crate::agent::clean_bootstrap::operation_dispatch::{
    RetainedAuthorityOperationDispatch, matches_operation_envelope,
};
use crate::agent::local_lifecycle::{LocalLifecycleController, LocalLifecycleStoreFactory};
use crate::agent::production_owner::{AgentProductionOwner, AgentProductionOwnerError};
use crate::agent_sdk::authority::AuthorityCredentialProjection;
use crate::agent_sdk::authority_operation::{AuthorityOperationCall, AuthorityOperationIntent};
use crate::agent_sdk::InvocationContext;
use crate::agent_sdk::wire::CanonicalWire as _;
use crate::actors::codec::{Decode as _, Encode as _};

struct NoLifecycleStores;
impl LocalLifecycleStoreFactory for NoLifecycleStores {
    type Intent = IssuerMemoryStore;
    type Issuer = IssuerMemoryStore;
    type Error = ();
    fn discover(&mut self, _: SpaceId, _: usize) -> Result<Vec<AgentId>, ()> {
        panic!("operation preparation must not discover lifecycle stores")
    }
    fn open(&mut self, _: SpaceId, _: AgentId) -> Result<(Self::Intent, Self::Issuer), ()> {
        panic!("operation preparation must not create lifecycle stores")
    }
    fn open_existing(&mut self, _: SpaceId, _: AgentId) -> Result<(Self::Intent, Self::Issuer), ()> {
        panic!("operation preparation must not reopen lifecycle stores")
    }
}

struct NoSigning([u8; 32]);
impl AuthorityOperationEvidenceSigner for NoSigning {
    type Error = core::convert::Infallible;
    fn public_key(&self) -> [u8; 32] { self.0 }
    fn sign_authority_receipt(&mut self, _: &[u8]) -> Result<[u8; 64], Self::Error> {
        panic!("preparation must not sign a receipt")
    }
    fn sign_issuance_ack(&mut self, _: &[u8]) -> Result<[u8; 64], Self::Error> {
        panic!("preparation must not sign issuance")
    }
}
impl NativeAuthorityOperationCompletionSigner for NoSigning {
    type Error = core::convert::Infallible;
    fn public_key(&self) -> [u8; 32] { self.0 }
    fn sign_native_operation_completion(&mut self, _: &[u8]) -> Result<[u8; 64], Self::Error> {
        panic!("preparation must not sign completion")
    }
}
impl NativeAuthorityOperationRetirementSigner for NoSigning {
    type Error = core::convert::Infallible;
    fn public_key(&self) -> [u8; 32] { self.0 }
    fn sign_native_operation_retirement(&mut self, _: &[u8]) -> Result<[u8; 64], Self::Error> {
        panic!("preparation must not sign retirement")
    }
}
impl NativeAuthorityOperationDenialSigner for NoSigning {
    type Error = core::convert::Infallible;
    fn public_key(&self) -> [u8; 32] { self.0 }
    fn sign_native_operation_denial(&mut self, _: &[u8]) -> Result<[u8; 64], Self::Error> {
        panic!("preparation must not sign denial")
    }
}

struct Journal {
    inner: OperationTestJournal,
    writes: Arc<AtomicUsize>,
}
impl NativeAuthorityOperationJournalStore for Journal {
    type Error = std::io::Error;
    fn load(&mut self, id: InvocationId) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.load(id)
    }
    fn retain(&mut self, id: InvocationId, bytes: &[u8]) -> Result<(), Self::Error> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        self.inner.retain(id, bytes)
    }
}

fn retry_until<T>(
    deadline: std::time::Instant,
    phase: &str,
    mut operation: impl FnMut() -> Result<T, SharedAgentHostError>,
) -> T {
    loop {
        assert!(std::time::Instant::now() < deadline, "{phase} exceeded whole recovery bound");
        let result = operation();
        assert!(std::time::Instant::now() <= deadline, "{phase} exceeded whole recovery bound");
        match result {
            Ok(value) => return value,
            Err(SharedAgentHostError::Unavailable | SharedAgentHostError::Conflict) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("{phase} failed: {error:?}"),
        }
    }
}

// Reuse only the existing authenticated Raft isolation seam. Panic paths must
// restore all actual peers; no altered quorum or replacement registration.
struct RestoreIsolationOnDrop<'a> {
    owners: &'a mut [Option<MemoryBootstrapOwner>],
    agent: HostAgentId,
    armed: bool,
}
impl RestoreIsolationOnDrop<'_> {
    fn restore_checked(&mut self) -> Result<(), SharedAgentHostError> {
        let mut failed = None;
        for owner in self.owners.iter().flatten() {
            if let Err(error) = owner._network_host.set_raft_isolated_for_test(self.agent, false) {
                if failed.is_none() { failed = Some(error); }
            }
        }
        if let Some(error) = failed { return Err(error); }
        self.armed = false;
        Ok(())
    }
}
impl Drop for RestoreIsolationOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed { let _ = self.restore_checked(); }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn exercise(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(BootstrapMemoryStore, BootstrapMemoryStore, IssuerMemoryStore)],
    providers: &[Arc<MemoryProvider>],
    networks: &[Arc<Network>],
    signer: &mut CountingSigner,
    cold_reopen: bool,
) {
    assert_eq!(owners.len(), 3);
    let agent = HostAgentId(fixtures[origin].plan.pins.agent.0);
    for owner in owners.iter().flatten() {
        assert_eq!(owner.pins.replicas.members().len(), 3);
        assert!(!owner.management_admission_held().unwrap());
    }
    assert!(owners[origin].as_ref().unwrap()._network_host.bootstrap_is_local_leader(agent).unwrap());
    let api_key = SigningKey::from_bytes(&[0x94; 32]);
    let owner = owners[origin].as_ref().unwrap();
    authority_observation::enroll_api_projection_credential(owner, origin, &api_key);
    let public = api_key.verifying_key().to_bytes();
    let target = owner.authority_target();
    let mut query = AuthorityProjectionQuery {
        authority: target,
        credential: CredentialId::of_public_key(&public),
        nonce: Hash([0x95; 32]),
        selector: AuthorityProjectionSelector::Credential,
        recovery: None,
        authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public,
            signature: [1; 64],
        },
    };
    let signature = api_key.sign(&query.signing_bytes()).to_bytes();
    query.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
        credential_public_key: public,
        signature,
    };
    query.verify_api_with(&RawCredentialVerifier).unwrap();
    let bytes = management_retention::exact_management_retry("operation API credential", || {
        owner.invoke_authority_observation(query.clone())
    });
    let current = AuthorityCredentialProjection::decode(&bytes).unwrap();
    assert!(current.query == query);
    assert_eq!(current.status, AuthorityCredentialStatus::Active);
    assert_eq!(current.kind, AuthorityCredentialKind::Api);
    let state_before = owner.host.lock().unwrap().clean_state_commitment(agent).unwrap();
    // Enrollment/setup is separate from the recovery window. Every replica
    // must apply that genuine signed state before the following actual cut.
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        owners.iter().flatten().all(|owner| {
            !owner.management_admission_held().unwrap()
                && owner.host.lock().unwrap().clean_state_commitment(agent).unwrap() == state_before
        })
    }));
    let ManagementRequest::Install(catalog) = &fixtures[origin].plan.catalog_request else {
        panic!("actual installed catalog is required");
    };
    let material = owner.supervisor_invocation_material(owner.pins.agent, catalog.entry.actor).unwrap();
    let slot = owner.supervisor_invocation_material(owner.pins.agent, target.binding.issuer.actor).unwrap().observed_slot;
    let origin_context = InvocationOrigin {
        principal: Some(current.principal),
        credential: Some(query.credential),
        transport_node: None,
        actor: None,
        capability: None,
    };
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
    let mut message = vec![crate::actors::value::TAG_DYNAMIC];
    message.extend(crate::actors::value::Msg::new("read").encode());
    // A real installed actor supplies the signed business intent. This test
    // stops at native preparation; it claims no policy decision/application.
    let work = InvocationWork {
        space: target.space,
        agent: target.system_agent,
        runtime_deployment: target.system_runtime_deployment,
        invocation: InvocationId([0x96; 32]),
        actor: material.actor.entry.actor,
        incarnation: material.actor.incarnation,
        deployment: material.actor.entry.deployment,
        program: material.actor.entry.program,
        mode: MethodMode::Query,
        origin: origin_context,
        roles: InvocationRoleClaims::none(),
        message,
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: owner.invocation_gas,
        recovery_only: false,
    };
    assert!(work.validate());
    let sign = |call: &mut AuthorityOperationCall| {
        call.invocation = call.expected_invocation();
        call.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public,
            signature: api_key.sign(&call.signing_bytes()).to_bytes(),
        };
        call.verify_api_with(&RawCredentialVerifier).unwrap();
        assert!(call.authenticated_node().is_none());
    };
    let mut call = AuthorityOperationCall {
        invocation: InvocationId::ZERO,
        authority: target,
        principal: current.principal,
        credential: query.credential,
        request_sequence: NonZeroU64::new(current.operation_request_high_water.checked_add(1).unwrap()).unwrap(),
        authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public,
            signature: [1; 64],
        },
        requested_valid_from: slot,
        requested_expires_at: slot.checked_add(10).unwrap(),
        intent: AuthorityOperationIntent::invoke(fixtures[origin].plan.managed_target(), &work).unwrap(),
    };
    sign(&mut call);
    let exact_call = call.encode().unwrap();
    assert!(exact_call.starts_with(b"AOC5"));
    let template_context = InvocationContext {
        invocation: call.invocation,
        actor: target.binding.issuer.actor,
        mode: MethodMode::Linear,
        origin: origin_context,
        roles: InvocationRoleClaims::none(),
        observed_slot: slot,
    };
    let template_request = AuthorityOperationActorDispatch {
        target,
        method: AuthorityOperationActorMethod::AuthorizeOperation,
        context: template_context,
        request: exact_call.clone(),
    };
    assert!(template_request.has_valid_request());
    let template_work = owner.prepare_authority_operation_dispatch(&template_request).unwrap();
    assert!(matches_operation_envelope(&template_request, &template_work));
    let mut absent_call = call.clone();
    absent_call.request_sequence = NonZeroU64::new(call.request_sequence.get().checked_add(1).unwrap()).unwrap();
    sign(&mut absent_call);
    let mut changed_work = work.clone();
    changed_work.gas = changed_work.gas.checked_sub(1).unwrap();
    let mut changed_call = call.clone();
    changed_call.intent = AuthorityOperationIntent::invoke(fixtures[origin].plan.managed_target(), &changed_work).unwrap();
    sign(&mut changed_call);
    let mut bad_signature = call.clone();
    let AuthorityIngressAuthentication::ApiCredentialSignature { signature, .. } = &mut bad_signature.authentication else {
        unreachable!()
    };
    signature[0] ^= 1;
    assert!(bad_signature.verify_api_with(&RawCredentialVerifier).is_err());
    let journal_path = directories[origin].0.clone();
    let coordinator_path = directories[origin].0.join("prepare-operation-coordinator");
    let issuer_path = directories[origin].0.join("prepare-operation-issuer");
    let writes = Arc::new(AtomicUsize::new(0));
    let mut operations = NativeAuthorityOperationController::new(
        target,
        OperationTestImageFile(coordinator_path.clone()),
        OperationTestImageFile(issuer_path.clone()),
        Journal { inner: OperationTestJournal(journal_path.clone()), writes: Arc::clone(&writes) },
    );
    assert!(!operations.retains_call(&call, None).unwrap());
    assert!(owner._network_host.current_management_pending(agent, call.invocation).unwrap().is_none());
    let position_before = owner.host.lock().unwrap().journal_position(agent).unwrap();
    let recovery_started = std::time::Instant::now();
    let deadline = recovery_started + std::time::Duration::from_secs(30);
    let database = owner.host.lock().unwrap().raft_database(agent).unwrap();
    let meta_before = crate::raft::RaftMeta::load(&database).unwrap();
    let last_before = crate::raft::RaftLog::open(Arc::clone(&database)).unwrap().last_index();
    assert_eq!(meta_before.commit_index, last_before);
    let mut restore = RestoreIsolationOnDrop { owners, agent, armed: true };
    for owner in restore.owners.iter().flatten() {
        owner._network_host.set_raft_isolated_for_test(agent, true).unwrap();
    }
    let cut_started = std::time::Instant::now();
    let cut = operations.prepare_call(restore.owners[origin].as_mut().unwrap(), &call);
    let cut_elapsed = cut_started.elapsed();
    // Decode the exact actual append before permitting replication. A delayed
    // response alone would not prove commit occurred after preparation returned
    // without reaching the journal callback.
    let observed = (|| {
        let meta = crate::raft::RaftMeta::load(&database)?;
        let raw = crate::raft::RaftLog::open(Arc::clone(&database))?;
        let last = raw.last_index();
        let entries = raw.entries(last, last)?;
        Ok::<_, crate::commit::CommitError>((meta, last, entries))
    })();
    for index in [origin, (origin + 1) % 3] {
        restore.owners[index].as_ref().unwrap()._network_host.set_raft_isolated_for_test(agent, false).unwrap();
    }
    let (meta_after, last_after, entries) = observed.unwrap();
    assert!(matches!(cut, Err(SharedAgentHostError::Unavailable)));
    assert!(cut_elapsed >= std::time::Duration::from_millis(1_800));
    assert!(std::time::Instant::now() < deadline);
    assert_eq!(writes.load(Ordering::Acquire), 0);
    assert_eq!(meta_after.commit_index, meta_before.commit_index);
    assert_eq!(last_after, last_before + 1);
    assert_eq!(entries.len(), 1);
    let vos_raft::EntryKind::Data { payload } = crate::agent::shared_raft::decode_agent_raft_entry_kind(&entries[0].payload).unwrap() else {
        panic!("operation cut must append actual signed metadata");
    };
    let crate::agent::shared_raft::AgentRaftCommand::RegisterManagementRecovery { registration, .. } = crate::agent::shared_raft::AgentRaftCommand::decode(&payload).unwrap() else {
        panic!("operation cut must append RegisterManagementRecovery");
    };
    drop(database);
    let retained = {
        let owner = restore.owners[origin].as_ref().unwrap();
        retry_until(deadline, "operation original late registration", || {
        let manifest = owner._network_host.management_recovery_manifest(agent)?;
        let Some(slot) = manifest.management_slot(HostNodeId(owner.pins.node.0)).filter(|slot| {
            !slot.is_released() && slot.members().first().is_some_and(|member| member.work().invocation == call.invocation)
        }) else { return Err(SharedAgentHostError::Unavailable); };
        assert!(slot.registration() == &registration);
        Ok(slot.clone())
        })
    };
    restore.restore_checked().unwrap();
    drop(restore);
    let owner = owners[origin].as_ref().unwrap();
    assert_eq!(retained.owner(), HostNodeId(owner.pins.node.0));
    assert_eq!(retained.origin_owner(), retained.owner());
    assert!(!retained.is_released());
    assert_eq!(retained.members().len(), 1);
    let member = retained.members().first().unwrap();
    assert!(member.parent().is_none());
    let original_work = member.envelope().clone();
    let RuntimeWork::Invoke { observed_slot: original_slot, .. } = &original_work else {
        panic!("registered original operation must be an Invoke");
    };
    let original_slot = *original_slot;
    assert!(original_slot >= call.requested_valid_from && original_slot <= call.requested_expires_at);
    let context = InvocationContext { observed_slot: original_slot, ..template_context };
    let request = AuthorityOperationActorDispatch { context, ..template_request };
    assert!(matches_operation_envelope(&request, &original_work));
    // Compare the independently prepared physical body with the actual first
    // capture's authenticated clock. This changes only expected test data;
    // no live clock, signed call, store or retained envelope is reconstructed.
    let mut expected_work = template_work;
    let RuntimeWork::Invoke { invocation, authorization, observed_slot, .. } = &mut expected_work else { unreachable!() };
    *observed_slot = original_slot;
    **authorization = InvocationAuthorization::PublicPreflight(crate::agent_sdk::PublicPreflight::for_work(invocation, original_slot));
    assert!(original_work == expected_work);
    let original_anchor = member.anchor().clone();
    assert!(retained.members_evidence()[0].invoke().is_none());
    assert!(retained.members_evidence()[0].acknowledgement().is_none());
    assert!(owner._network_host.current_management_pending(agent, call.invocation).unwrap().is_none());
    assert!(matches!(owner._network_host.ensure_management_pending_member(agent, &original_anchor, &original_work), Err(SharedAgentHostError::Conflict)));
    assert!(!operations.retains_call(&call, None).unwrap());
    let mut view = OperationTestJournal(journal_path.clone());
    assert!(view.load(call.invocation).unwrap().is_none());
    assert_eq!(writes.load(Ordering::Acquire), 0);
    assert!(!coordinator_path.exists());
    assert!(!issuer_path.exists());
    assert!(owner.management_admission_held().unwrap());
    assert!(owner.host.lock().unwrap().journal_position(agent).unwrap() == position_before);
    assert!(owner.host.lock().unwrap().clean_state_commitment(agent).unwrap() == state_before);
    assert!(call.encode().unwrap() == exact_call);
    eprintln!("fixed_three_operation_prepare phase=late_exact_root nod_present=false map_present=false elapsed_ms={}", recovery_started.elapsed().as_millis());
    let bootstrap_bytes = || (stores[origin].0.image(), stores[origin].0.commits(), stores[origin].1.image(), stores[origin].1.commits(), stores[origin].2.image.lock().unwrap().clone());
    let durable_before = bootstrap_bytes();
    let record_before = owner.record.encode();
    let chosen = if cold_reopen {
        owners[origin].as_mut().unwrap()._network_host.retire_attachment_for_test(agent).unwrap();
        drop(owners[origin].take().unwrap());
        let assert_no_adoption = || {
            assert!(bootstrap_bytes() == durable_before);
            assert_eq!(writes.load(Ordering::Acquire), 0);
            let mut view = OperationTestJournal(journal_path.clone());
            for call in [&call, &absent_call, &changed_call] {
                assert!(view.load(call.invocation).unwrap().is_none());
            }
            assert!(!coordinator_path.exists());
            assert!(!issuer_path.exists());
            for surviving in owners.iter().flatten() {
                let slot = retry_until(deadline, "cold operation survivor root", || {
                    let manifest = surviving._network_host.management_recovery_manifest(agent)?;
                    let Some(slot) = manifest.management_slot(retained.owner()) else { return Err(SharedAgentHostError::Unavailable); };
                    Ok(slot.clone())
                });
                assert!(slot == retained);
                assert!(surviving.host.lock().unwrap().clean_state_commitment(agent).unwrap() == state_before);
            }
        };
        assert!(std::time::Instant::now() < deadline);
        let reopened = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
            stores[origin].0.clone(), stores[origin].1.clone(), stores[origin].2.clone(), signer,
            || panic!("cold operation must retain durable bootstrap plan"),
            directories[origin].host(), directories[origin].lock(),
            fixtures[origin].plan.pins.space, fixtures[origin].plan.pins.node,
            fixtures[origin].trust.clone(), fixtures[origin].merge.clone(), fixtures[origin].finality.clone(),
            providers[origin].clone(), networks[origin].clone(), None, None,
        );
        assert!(std::time::Instant::now() <= deadline);
        let mut pending = match reopened {
            Ok(pending) => pending,
            Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::ScopeMismatch)) => {
                assert_no_adoption();
                eprintln!("fixed_three_operation_prepare phase=cold_startup_refusal elapsed_ms={}", recovery_started.elapsed().as_millis());
                return;
            }
            Err(error) => panic!("cold operation reopen failed before admission: {error:?}"),
        };
        let reopened = loop {
            assert!(std::time::Instant::now() < deadline);
            let result = pending.try_complete(signer);
            assert!(std::time::Instant::now() <= deadline);
            match result {
                Ok(Some(owner)) => break owner,
                Ok(None) => panic!("cold operation owner disappeared"),
                Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::Unavailable)) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(CleanSystemAgentBootstrapError::Host(SharedAgentHostError::ScopeMismatch)) => {
                    drop(pending);
                    assert_no_adoption();
                    eprintln!("fixed_three_operation_prepare phase=cold_startup_refusal elapsed_ms={}", recovery_started.elapsed().as_millis());
                    return;
                }
                Err(error) => panic!("cold operation completion failed: {error:?}"),
            }
        };
        drop(pending);
        assert!(reopened.record.encode() == record_before);
        assert!(reopened.management_admission_held().unwrap());
        assert!(reopened._network_host.current_management_pending(agent, call.invocation).unwrap().is_none());
        assert!(reopened._network_host.management_recovery_manifest(agent).unwrap().management_slot(retained.owner()) == Some(&retained));
        assert_no_adoption();
        // Drop the old controller's open lifetime too, preserving its exact
        // original non-clone stores; no retained record or live proof exists.
        let (coordinator, issuer, journal) = operations.into_parts();
        operations = NativeAuthorityOperationController::new(target, coordinator, issuer, journal);
        reopened
    } else {
        owners[origin].take().unwrap()
    };
    let host = Arc::clone(&chosen.host);
    let local = crate::agent::local_sdk_host::LocalAgentHost::create(
        directories[origin].0.join("operation-preparation-local-host"), target.space,
        fixtures[origin].plan.pins.node, fixtures[origin].trust.clone(),
    ).unwrap();
    let lifecycle = LocalLifecycleController::new(chosen, local, NoLifecycleStores, CountingSigner::new()).unwrap()
        .with_operations(operations, NoSigning(target.binding.public_key)).unwrap();
    let observations = Arc::new(AtomicUsize::new(0));
    let mut production = AgentProductionOwner::start_local(
        fixtures[origin].plan.pins.node,
        crate::agent::supervisor::AgentSupervisorLimits::default(),
        Box::new(lifecycle), 4, Box::new(NeverProjectionAuthenticator(Arc::clone(&observations))),
        std::time::Duration::from_secs(5),
    ).unwrap();
    assert!(std::time::Instant::now() < deadline);
    assert!(production.is_running());
    assert!(!production.is_ready());
    assert!(matches!(production.ingress(), Err(AgentProductionOwnerError::ProjectionNotReady)));
    let assert_no_dispatch = || {
        assert!(bootstrap_bytes() == durable_before);
        let mut view = OperationTestJournal(journal_path.clone());
        for call in [&call, &absent_call, &changed_call] { assert!(view.load(call.invocation).unwrap().is_none()); }
        assert_eq!(writes.load(Ordering::Acquire), 0);
        assert!(!coordinator_path.exists());
        assert!(!issuer_path.exists());
        let hosted = host.lock().unwrap();
        // Genuine cold reopen can apply current-term metadata no-ops. Exact
        // family/opaque state and absent Invoke/ACK remain the cold boundary.
        if !cold_reopen { assert!(hosted.journal_position(agent).unwrap() == position_before); }
        assert!(hosted.clean_state_commitment(agent).unwrap() == state_before);
        assert!(hosted.recovery_manifest(agent).unwrap().management_slot(retained.owner()) == Some(&retained));
        assert_eq!(observations.load(Ordering::Acquire), 0);
    };
    for refused in [&absent_call, &changed_call, &bad_signature] {
        assert!(matches!(production.prepare_operation(refused), Err(SharedAgentHostError::ScopeMismatch)));
        assert!(std::time::Instant::now() <= deadline);
        assert_no_dispatch();
    }
    if cold_reopen {
        assert!(matches!(production.prepare_operation(&call), Err(SharedAgentHostError::ScopeMismatch)));
        assert_no_dispatch();
        assert!(!production.is_ready());
        production.shutdown_and_join().unwrap();
        assert_no_dispatch();
        assert!(std::time::Instant::now() <= deadline);
        eprintln!("fixed_three_operation_prepare phase=cold_exact_refusal elapsed_ms={}", recovery_started.elapsed().as_millis());
        return;
    }
    assert_no_dispatch();
    eprintln!("fixed_three_operation_prepare phase=normal_guard_retry nod_present=false elapsed_ms={}", recovery_started.elapsed().as_millis());
    // The supported BEFORE reproduction reaches this real unready owner
    // guard. Preparation must repair the original exact native input; issuing
    // a receipt or executing guest policy is deliberately outside this test.
    let prepared = retry_until(deadline, "normal exact operation preparation", || {
        assert!(call.encode().unwrap() == exact_call);
        production.prepare_operation(&call)
    });
    assert!(prepared.call() == &call);
    assert!(prepared.context() == &context);
    assert_eq!(prepared.issued_at(), context.observed_slot);
    let saved = view.load(call.invocation).unwrap().unwrap();
    let nod = RetainedAuthorityOperationDispatch::decode(&saved).unwrap();
    assert!(nod.encode().unwrap() == saved);
    assert!(nod.request() == &request);
    assert!(nod.envelope() == &original_work);
    assert!(nod.anchor() == &original_anchor);
    assert_eq!(writes.load(Ordering::Acquire), 1);
    assert!(host.lock().unwrap().journal_position(agent).unwrap() == position_before);
    assert!(host.lock().unwrap().clean_state_commitment(agent).unwrap() == state_before);
    assert!(host.lock().unwrap().recovery_manifest(agent).unwrap().management_slot(retained.owner()) == Some(&retained));
    assert!(!coordinator_path.exists());
    assert!(!issuer_path.exists());
    assert!(!production.is_ready());
    let repeated = retry_until(deadline, "prepared exact operation retry", || production.prepare_operation(&call));
    assert!(repeated == prepared);
    assert!(view.load(call.invocation).unwrap() == Some(saved));
    assert_eq!(writes.load(Ordering::Acquire), 2);
    assert!(view.load(absent_call.invocation).unwrap().is_none());
    assert!(view.load(changed_call.invocation).unwrap().is_none());
    assert!(host.lock().unwrap().journal_position(agent).unwrap() == position_before);
    assert!(host.lock().unwrap().clean_state_commitment(agent).unwrap() == state_before);
    assert!(host.lock().unwrap().recovery_manifest(agent).unwrap().management_slot(retained.owner()) == Some(&retained));
    assert_eq!(observations.load(Ordering::Acquire), 0);
    production.shutdown_and_join().unwrap();
    assert!(std::time::Instant::now() <= deadline);
    eprintln!("fixed_three_operation_prepare phase=prepared_exact_retry nod_present=true no_guest_dispatch=true checked_shutdown=true elapsed_ms={}", recovery_started.elapsed().as_millis());
}
