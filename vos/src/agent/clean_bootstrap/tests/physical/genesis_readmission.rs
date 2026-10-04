//! Exact same-controller recovery of failed preparation, not lifecycle finality.
//! Store-object lifetime is asserted here; the public filesystem/fixed-three
//! workflow remains the independent integration qualification.

use super::*;
use crate::agent::clean_authority_issuer::{
    CleanExternalLocalCreateArchiveStore, CleanManagementActorStore, CleanManagementRuntimeStore,
    CleanSharedGenesisReplicaStore, CleanSharedManagementIntentStore,
};
use crate::agent::clean_management_intent::CleanManagementIntent;

#[derive(Default)]
pub(super) struct Fault {
    load_once: bool,
    commit_then_error_at: Option<usize>,
    committed_writes: usize,
    commit_then_error_failures: usize,
    install_authorization_prewrite_once: bool,
    install_authorization_prewrite_failures: usize,
}

impl Fault {
    pub(super) fn fail_next_commit_after_write(&mut self) -> usize {
        assert!(self.commit_then_error_at.is_none());
        self.commit_then_error_at = Some(1);
        self.committed_writes
    }

    pub(super) fn committed_writes(&self) -> usize {
        self.committed_writes
    }

    pub(super) fn commit_then_error_failures(&self) -> usize {
        self.commit_then_error_failures
    }

    pub(super) fn refuse_install_authorization_before_write_once(&mut self) {
        assert!(!self.install_authorization_prewrite_once);
        assert_eq!(self.install_authorization_prewrite_failures, 0);
        self.install_authorization_prewrite_once = true;
    }

    pub(super) fn install_authorization_prewrite_failures(&self) -> usize {
        self.install_authorization_prewrite_failures
    }
}

/// Non-clone owner used to observe that borrowed reload never releases or
/// replaces the original six leases. The underlying observer is not a writer.
pub(super) struct LeaseStore {
    inner: IssuerMemoryStore,
    fault: Arc<Mutex<Fault>>,
    live: Arc<AtomicUsize>,
}

impl LeaseStore {
    pub(super) fn new(
        inner: IssuerMemoryStore,
        fault: Arc<Mutex<Fault>>,
        live: Arc<AtomicUsize>,
    ) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self { inner, fault, live }
    }
}

impl Drop for LeaseStore {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl CleanManagementIssuerStore for LeaseStore {
    type Error = MemoryError;
    fn load(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        if core::mem::take(&mut self.fault.lock().unwrap().load_once) {
            return Err(MemoryError);
        }
        self.inner.load()
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        {
            let mut fault = self.fault.lock().unwrap();
            if fault.install_authorization_prewrite_once {
                if let Ok(next) = CleanManagementIntent::decode(bytes) {
                    if matches!(next.request(), ManagementRequest::Install(_))
                        && next.authorization_work().is_some()
                        && next.finalization_work().is_none()
                    {
                        let current = CleanManagementIntent::decode(
                            &self.inner.load()?.expect("prewrite cut requires retained bare CMI"),
                        )
                        .unwrap();
                        assert!(current.request() == next.request());
                        assert!(current.call() == next.call());
                        assert!(current.authorization_work().is_none());
                        assert!(current.finalization_work().is_none());
                        current.call().verify_with(&RawCredentialVerifier).unwrap();
                        fault.install_authorization_prewrite_once = false;
                        fault.install_authorization_prewrite_failures += 1;
                        return Err(MemoryError);
                    }
                }
            }
        }
        self.inner.commit(bytes)?;
        let mut fault = self.fault.lock().unwrap();
        fault.committed_writes += 1;
        if let Some(remaining) = fault.commit_then_error_at.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                fault.commit_then_error_at = None;
                fault.commit_then_error_failures += 1;
                return Err(MemoryError);
            }
        }
        Ok(())
    }
    fn issuance_disabled(&mut self) -> Result<bool, MemoryError> {
        self.inner.issuance_disabled()
    }
}

impl CleanManagementRuntimeStore for LeaseStore {
    fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        self.inner.load_runtime()
    }
    fn commit_runtime(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.commit_runtime(bytes)
    }
}

impl CleanSharedGenesisReplicaStore for LeaseStore {
    fn load_replicas(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        self.inner.load_replicas()
    }
    fn commit_replicas(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.commit_replicas(bytes)
    }
}

impl CleanManagementActorStore for LeaseStore {
    fn load_actor(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        self.inner.load_actor()
    }
    fn commit_actor(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.commit_actor(bytes)
    }
}

impl CleanExternalLocalCreateArchiveStore for LeaseStore {
    fn load_external_create_archive(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        self.inner.load_external_create_archive()
    }
    fn commit_external_create_archive(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.commit_external_create_archive(bytes)
    }
}

impl CleanSharedManagementIntentStore for LeaseStore {
    fn load_shared_install_handoff(&mut self) -> Result<Option<Vec<u8>>, MemoryError> {
        self.inner.load_shared_install_handoff()
    }
    fn commit_shared_install_handoff(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.commit_shared_install_handoff(bytes)
    }
    fn management_intent_continuation(&mut self) -> Result<Self, MemoryError> {
        // These tests recover an empty controller and a pre-archive Create;
        // opening a continuing Install owner would violate their boundary.
        Err(MemoryError)
    }
}

type Recovery = NativeSharedGenesisRecovery<
    LeaseStore,
    LeaseStore,
    LeaseStore,
    LeaseStore,
    LeaseStore,
    LeaseStore,
>;
type Controller = NativeSharedGenesisController<
    LeaseStore,
    LeaseStore,
    LeaseStore,
    LeaseStore,
    LeaseStore,
    LeaseStore,
    MixedSharedArchive,
>;

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; genuine System PVM and file journal"]
fn candidate_shared_create_inplace_readmission_preserves_lease_and_signed_receipt() {
    check_readmission(false, false);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; genuine System PVM and file journal"]
fn candidate_shared_create_inplace_readmission_recovers_commit_then_error_without_resigning() {
    check_readmission(true, false);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; genuine System PVM and file journal"]
fn candidate_shared_create_inplace_readmission_refuses_loss_and_substitution_before_retry() {
    check_readmission(false, true);
}

fn check_readmission(ambiguous_issuer: bool, corruptions: bool) {
    check_readmission_case(ambiguous_issuer, corruptions);
}

fn check_readmission_case(ambiguous_issuer: bool, corruptions: bool) {
    let fixture = native_authority_package_fixture(false, &candidate_authority_package());
    let mut harness = NativeProjectionOwnerHarness::with_real_bootstrap(
        "shared-create-inplace-readmission",
        fixture,
    );
    let mut owner = harness.owner.take().unwrap();
    let target = owner.authority_target();
    // Ordinary runtime is only admitted here; no physical generation is opened.
    let runtime = test_runtime_package(true);
    let mut descriptor = owner.pins.descriptor.clone();
    descriptor.creation_nonce = Hash([0xb7; 32]);
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
    descriptor.replicas[0].principal = descriptor.identity.owner;
    let original = &owner.pins.replicas.members()[0];
    let mut replica = original.replica();
    replica.principal = crate::service::PrincipalId(descriptor.identity.owner.0);
    let replicas = AgentReplicaCommittee::new(
        crate::service::SpaceId(descriptor.identity.space.0),
        HostAgentId(descriptor.identity.agent.0),
        crate::agent::AgentProfile::Shared,
        vec![
            crate::agent::genesis::AgentReplicaMember::new(
                replica,
                original.peer_id().to_vec(),
                *original.ed25519_public_key(),
                original.raft_slot(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &key);
    call.request_sequence = NonZeroU64::new(2).unwrap();
    call.authority = target;
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    let locator = crate::agent::genesis::AgentGenesisLocator {
        space: crate::service::SpaceId(descriptor.identity.space.0),
        agent: HostAgentId(descriptor.identity.agent.0),
    };
    let images: [IssuerMemoryStore; 6] = core::array::from_fn(|_| IssuerMemoryStore::default());
    let faults: [Arc<Mutex<Fault>>; 6] =
        core::array::from_fn(|_| Arc::new(Mutex::new(Fault::default())));
    let live = Arc::new(AtomicUsize::new(0));
    let mut controller = Controller::new(target, vec![]).unwrap();
    let mut signer = CountingSigner::new();
    controller.recover(&mut owner, &mut signer).unwrap();
    controller
        .reserve_create_with(&descriptor, &call, &runtime, &replicas, || {
            let lease = |index: usize| {
                LeaseStore::new(images[index].clone(), faults[index].clone(), live.clone())
            };
            Ok((
                Recovery::reserve_create_with_replicas(
                    target,
                    locator,
                    descriptor.clone(),
                    call.clone(),
                    runtime.clone(),
                    replicas.clone(),
                    (lease(0), lease(1), lease(2), lease(3), lease(4), lease(5)),
                )?,
                Some(MixedSharedArchive::default()),
            ))
        })
        .unwrap();
    assert_eq!(live.load(Ordering::SeqCst), 6);
    if ambiguous_issuer {
        faults[1].lock().unwrap().commit_then_error_at = Some(2);
    } else {
        faults[2].lock().unwrap().load_once = true;
    }
    assert!(
        controller
            .prepare_pending_create(&mut owner, locator, &mut signer)
            .is_err()
    );
    assert_eq!(live.load(Ordering::SeqCst), 6);
    let signatures = signer.calls;
    assert_eq!(signatures, 1, "the first receipt really was signed");
    let retained_intent = images[0].image.lock().unwrap().clone().unwrap();
    let retained_issuer = images[1].image.lock().unwrap().clone().unwrap();
    let retained_runtime = images[0].runtime.lock().unwrap().clone();
    let original_ordered = owner.ordered_index_for_test().unwrap();
    let selected_runtime =
        crate::agent::clean_bootstrap::SharedGenesisRuntimePackage::Image(runtime.clone());
    let before_lookup = images
        .iter()
        .map(|store| {
            (
                store.image.lock().unwrap().clone(),
                store.runtime.lock().unwrap().clone(),
                store.shared_replicas.lock().unwrap().clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        controller
            .retained_create_locator(&descriptor, &call, &selected_runtime, &replicas)
            .unwrap(),
        Some(locator)
    );
    // Caller-side exact retry must use the very same controller and leases.
    assert_eq!(
        controller
            .reserve_create_with(&descriptor, &call, &runtime, &replicas, || panic!(
                "exact retry must not acquire replacement leases"
            ))
            .unwrap(),
        locator
    );
    let mut another_call = call.clone();
    another_call.request_sequence = NonZeroU64::new(3).unwrap();
    another_call.invocation = another_call.expected_invocation();
    another_call.signature = key.sign(&another_call.signing_bytes()).to_bytes();
    assert!(
        controller
            .reserve_create_with(&descriptor, &another_call, &runtime, &replicas, || panic!(
                "substitution must not acquire leases"
            ))
            .is_err()
    );
    assert!(
        controller
            .retained_create_locator(&descriptor, &another_call, &selected_runtime, &replicas)
            .is_err()
    );
    let other_runtime = crate::agent::clean_bootstrap::SharedGenesisRuntimePackage::Image(
        test_runtime_package_with_actor_limit(true, crate::agent_sdk::STANDARD_MAX_ACTORS - 1),
    );
    assert!(
        controller
            .retained_create_locator(&descriptor, &call, &other_runtime, &replicas)
            .is_err()
    );
    let original = &owner.pins.replicas.members()[0];
    let mut changed_replica = original.replica();
    changed_replica.principal = crate::service::PrincipalId([0xb9; 32]);
    let changed_replicas = AgentReplicaCommittee::new(
        crate::service::SpaceId(descriptor.identity.space.0),
        locator.agent,
        crate::agent::AgentProfile::Shared,
        vec![
            crate::agent::genesis::AgentReplicaMember::new(
                changed_replica,
                original.peer_id().to_vec(),
                *original.ed25519_public_key(),
                original.raft_slot(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    assert!(
        controller
            .retained_create_locator(&descriptor, &call, &selected_runtime, &changed_replicas)
            .is_err()
    );
    let saved_replicas = images[2].shared_replicas.lock().unwrap().clone();
    *images[2].shared_replicas.lock().unwrap() = None;
    assert!(
        controller
            .retained_create_locator(&descriptor, &call, &selected_runtime, &replicas)
            .is_err()
    );
    *images[2].shared_replicas.lock().unwrap() = saved_replicas;
    // A fully valid distinct Create has no retained owner; lookup must return
    // absence, not execute the fresh storage factory while quarantined.
    let mut fresh_descriptor = descriptor.clone();
    fresh_descriptor.creation_nonce = Hash([0xb8; 32]);
    fresh_descriptor.identity.agent = AgentId::derive(
        fresh_descriptor.identity.space,
        fresh_descriptor.identity.owner,
        fresh_descriptor.creation_nonce.as_bytes(),
    );
    let original = &owner.pins.replicas.members()[0];
    let mut replica = original.replica();
    replica.principal = crate::service::PrincipalId(fresh_descriptor.identity.owner.0);
    let fresh_replicas = AgentReplicaCommittee::new(
        crate::service::SpaceId(fresh_descriptor.identity.space.0),
        HostAgentId(fresh_descriptor.identity.agent.0),
        crate::agent::AgentProfile::Shared,
        vec![
            crate::agent::genesis::AgentReplicaMember::new(
                replica,
                original.peer_id().to_vec(),
                *original.ed25519_public_key(),
                original.raft_slot(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let fresh_request = ManagementRequest::Create(Box::new(fresh_descriptor.clone()));
    let (mut fresh_call, _) = credential_call_and_approval(&fresh_descriptor, &fresh_request, &key);
    fresh_call.authority = target;
    fresh_call.request_sequence = NonZeroU64::new(3).unwrap();
    fresh_call.invocation = fresh_call.expected_invocation();
    fresh_call.signature = key.sign(&fresh_call.signing_bytes()).to_bytes();
    assert_eq!(
        controller
            .retained_create_locator(
                &fresh_descriptor,
                &fresh_call,
                &selected_runtime,
                &fresh_replicas
            )
            .unwrap(),
        None
    );
    assert_eq!(
        images
            .iter()
            .map(|store| (
                store.image.lock().unwrap().clone(),
                store.runtime.lock().unwrap().clone(),
                store.shared_replicas.lock().unwrap().clone(),
            ))
            .collect::<Vec<_>>(),
        before_lookup
    );
    assert_eq!(live.load(Ordering::SeqCst), 6);
    assert_eq!(signer.calls, signatures);
    assert_eq!(owner.ordered_index_for_test().unwrap(), original_ordered);
    if corruptions {
        // Canonical open alone permits a lost initial issuer as a fresh image;
        // this live owner's monotonic cache guard must reject that rollback.
        *images[1].image.lock().unwrap() = None;
        assert!(
            controller
                .prepare_pending_create(&mut owner, locator, &mut signer)
                .is_err()
        );
        assert_eq!(signer.calls, signatures);
        assert_eq!(owner.ordered_index_for_test().unwrap(), original_ordered);
        assert_eq!(live.load(Ordering::SeqCst), 6);
        *images[1].image.lock().unwrap() = Some(retained_issuer.clone());
        *images[0].runtime.lock().unwrap() = None;
        assert!(
            controller
                .prepare_pending_create(&mut owner, locator, &mut signer)
                .is_err()
        );
        assert_eq!(signer.calls, signatures);
        assert_eq!(owner.ordered_index_for_test().unwrap(), original_ordered);
        assert_eq!(live.load(Ordering::SeqCst), 6);
        *images[0].runtime.lock().unwrap() = retained_runtime;
        // A different but validly signed same-Agent Create cannot replace the
        // cached original, even when its otherwise pristine set opens cleanly.
        let substituted = CleanManagementIntent::new(
            target,
            call.managed,
            request.clone(),
            another_call,
            &RawCredentialVerifier,
        )
        .unwrap();
        *images[0].image.lock().unwrap() = Some(substituted.encode());
        *images[1].image.lock().unwrap() = None;
        assert!(
            controller
                .prepare_pending_create(&mut owner, locator, &mut signer)
                .is_err()
        );
        assert_eq!(signer.calls, signatures);
        assert_eq!(owner.ordered_index_for_test().unwrap(), original_ordered);
        assert_eq!(live.load(Ordering::SeqCst), 6);
        *images[0].image.lock().unwrap() = Some(retained_intent.clone());
        *images[1].image.lock().unwrap() = Some(retained_issuer.clone());
    }
    let prepared = controller
        .prepare_pending_create(&mut owner, locator, &mut signer)
        .unwrap();
    assert_eq!(
        signer.calls, signatures,
        "durable first receipt must be reused"
    );
    assert_eq!(live.load(Ordering::SeqCst), 6);
    assert_eq!(*images[0].image.lock().unwrap(), Some(retained_intent));
    assert_eq!(*images[1].image.lock().unwrap(), Some(retained_issuer));
    let completed_ordered = owner.ordered_index_for_test().unwrap();
    assert!(
        completed_ordered > original_ordered,
        "real committee Invoke/ACK completed after reload"
    );
    assert_eq!(
        controller
            .prepare_pending_create(&mut owner, locator, &mut signer)
            .unwrap(),
        prepared
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), completed_ordered);
    assert_eq!(signer.calls, signatures);
    assert_eq!(live.load(Ordering::SeqCst), 6);
    assert!(
        owner
            .host
            .lock()
            .unwrap()
            .clean_genesis_is_absent(locator.agent)
            .unwrap()
    );
    drop(controller);
    assert_eq!(live.load(Ordering::SeqCst), 0);
    harness.owner = Some(owner);
    harness.stop();
}
