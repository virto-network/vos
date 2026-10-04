//! Fixed-three, same-controller publication and parent-finalization exact retry.
use super::super::genesis_readmission::{Fault, LeaseStore};
use super::*;
use crate::agent::clean_bootstrap::{GenesisClaimSigner, SharedGenesisRuntimePackage};
use crate::agent::genesis_archive::AgentGenesisArchiveStore;
use crate::agent::package_admission::admit_state_runtime_package;
#[derive(Clone, Default)]
struct AmbiguousArchive {
    inner: MixedSharedArchive,
    fail_once: Arc<std::sync::atomic::AtomicBool>,
}
impl AgentGenesisArchiveStore for AmbiguousArchive {
    type Error = ();
    fn load(
        &self,
        locator: crate::agent::genesis::AgentGenesisLocator,
    ) -> Result<Option<Vec<u8>>, ()> {
        self.inner.load(locator)
    }
    fn insert_if_absent(
        &self,
        locator: crate::agent::genesis::AgentGenesisLocator,
        bytes: &[u8],
    ) -> Result<(), ()> {
        self.inner.insert_if_absent(locator, bytes)?;
        if self.fail_once.swap(false, Ordering::AcqRel) {
            Err(())
        } else {
            Ok(())
        }
    }
}

struct ClaimSigner {
    key: SigningKey,
    calls: usize,
}
impl GenesisClaimSigner for ClaimSigner {
    type Error = ();
    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> Result<[u8; 64], ()> {
        self.calls += 1;
        Ok(self.key.sign(message).to_bytes())
    }
}

pub(super) fn exercise(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    signer: &mut CountingSigner,
) {
    let owner = owners[leader].as_mut().unwrap();
    let target = owner.authority_target();
    super::authority_observation::enroll_api_projection_credential(owner, leader, &signer.key);
    // Use the emitted signed Shared role unchanged, never a relabelled image.
    let runtime = admit_state_runtime_package(include_bytes!(
        "../../../../../../vosx/blobs/shared_external_runtime.vos"
    ))
    .unwrap();
    let selected = SharedGenesisRuntimePackage::External(runtime.clone());
    let mut descriptor = owner.pins.descriptor.clone();
    descriptor.creation_nonce = Hash([0xe8; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    descriptor.identity.runtime_deployment = runtime.deployment();
    descriptor.identity.runtime_program = runtime.program();
    descriptor.identity.runtime_producer = runtime.manifest().signing.producer;
    let origin = owner
        .pins
        .replicas
        .member_by_node(crate::service::NodeId(owner.pins.node.0))
        .unwrap();
    descriptor.identity.transition_producer =
        ProducerId::of_public_key(origin.ed25519_public_key());
    descriptor.runtime_package = runtime.package_ref().clone();
    descriptor.runtime_contract = runtime.manifest().contract;
    descriptor.capabilities = runtime.manifest().capabilities;
    // Certified System placement uses transport principals; the signed SAC7
    // enrollments assign all three nodes to this Root. Ordinary Create must
    // bind enrolled owners, which the real Authority guest rechecks below.
    let members = owner
        .pins
        .replicas
        .members()
        .iter()
        .map(|member| {
            let mut replica = member.replica();
            replica.principal = crate::service::PrincipalId(descriptor.identity.owner.0);
            crate::agent::genesis::AgentReplicaMember::new(
                replica,
                member.peer_id().to_vec(),
                *member.ed25519_public_key(),
                member.raft_slot(),
            )
            .unwrap()
        })
        .collect();
    let replicas = AgentReplicaCommittee::new(
        crate::service::SpaceId(descriptor.identity.space.0),
        HostAgentId(descriptor.identity.agent.0),
        crate::agent::AgentProfile::Shared,
        members,
    )
    .unwrap();
    descriptor.replicas = replicas
        .members()
        .iter()
        .map(|member| {
            let replica = member.replica();
            AgentReplica {
                node: NodeId(replica.node.0),
                principal: PrincipalId(replica.principal.0),
                role: ReplicaRole::Voter,
            }
        })
        .collect();
    descriptor.validate().unwrap();
    replicas.validate_for_clean_descriptor(&descriptor).unwrap();
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &key);
    call.authority = target;
    call.authenticated_node = None;
    call.request_sequence = NonZeroU64::new(2).unwrap();
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    let locator = crate::agent::genesis::AgentGenesisLocator {
        space: crate::service::SpaceId(descriptor.identity.space.0),
        agent: HostAgentId(descriptor.identity.agent.0),
    };
    let images: [IssuerMemoryStore; 6] = core::array::from_fn(|_| IssuerMemoryStore::default());
    let live = Arc::new(AtomicUsize::new(0));
    let archive = AmbiguousArchive::default();
    let mut controller = NativeSharedGenesisController::<
        LeaseStore,
        LeaseStore,
        LeaseStore,
        LeaseStore,
        LeaseStore,
        LeaseStore,
        AmbiguousArchive,
    >::new(target, vec![])
    .unwrap();
    controller.recover(owner, signer).unwrap();
    controller
        .reserve_create_with_runtime(&descriptor, &call, &selected, &replicas, || {
            let lease = |index: usize| {
                LeaseStore::new(
                    images[index].clone(),
                    Arc::new(Mutex::new(Fault::default())),
                    live.clone(),
                )
            };
            Ok((
                NativeSharedGenesisRecovery::reserve_create_with_replicas_runtime(
                    target,
                    locator,
                    descriptor.clone(),
                    call.clone(),
                    selected.clone(),
                    replicas.clone(),
                    (lease(0), lease(1), lease(2), lease(3), lease(4), lease(5)),
                )?,
                Some(archive.clone()),
            ))
        })
        .unwrap();
    assert_eq!(live.load(Ordering::SeqCst), 6);
    let mut claim_signer = ClaimSigner { key, calls: 0 };
    let mut signature_store = IssuerMemoryStore::default();
    let prepared_candidate =
        management_retention::exact_management_retry("publication retry preparation", || {
            controller.prepare_pending_create(owner, locator, signer)
        });
    let signature = prepared_candidate
        .endorse(&mut signature_store, &mut claim_signer)
        .expect("the configured credential signer must endorse its exact sealed committee claim");
    let prepared = owner.ordered_index_for_test().unwrap();
    let receipt_signatures = signer.calls;
    let intent_bytes = images[0].image.lock().unwrap().clone().unwrap();
    let issuer_bytes = images[1].image.lock().unwrap().clone().unwrap();
    let runtime_bytes = images[0].runtime.lock().unwrap().clone().unwrap();
    archive.fail_once.store(true, Ordering::Release);
    assert_eq!(
        controller.publish_pending_create(owner, locator, vec![signature], signer),
        Err(SharedAgentHostError::Unavailable)
    );
    let archive_bytes = archive.load(locator).unwrap().unwrap();
    assert_eq!(
        controller
            .create_archive(locator)
            .unwrap()
            .unwrap()
            .encode(),
        archive_bytes
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), prepared);
    assert!(images[4].image.lock().unwrap().is_none());
    // Lost/substituted preimages must fail before publication or new leases.
    let substituted = shape_only_runtime().exact_bytes().to_vec();
    for invalid in [None, Some(substituted)] {
        *images[0].runtime.lock().unwrap() = invalid;
        assert_eq!(
            controller.publish_pending_create(owner, locator, vec![], signer),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        assert_eq!(owner.ordered_index_for_test().unwrap(), prepared);
        assert_eq!(signer.calls, receipt_signatures);
        assert_eq!(claim_signer.calls, 1);
        assert_eq!(live.load(Ordering::SeqCst), 6);
        assert_eq!(archive.load(locator).unwrap().unwrap(), archive_bytes);
    }
    *images[0].runtime.lock().unwrap() = Some(runtime_bytes.clone());
    assert_eq!(
        controller
            .reserve_create_with_runtime(&descriptor, &call, &selected, &replicas, || panic!(
                "exact retry must retain all six leases"
            ))
            .unwrap(),
        locator
    );
    let record =
        management_retention::exact_management_retry("publication same-controller retry", || {
            controller.publish_pending_create(owner, locator, vec![], signer)
        });
    let published = owner.ordered_index_for_test().unwrap();
    assert_eq!(published, prepared + 2, "exact publication Invoke/ACK only");
    assert_eq!(record.encode(), archive_bytes);
    assert_eq!(signer.calls, receipt_signatures);
    assert_eq!(claim_signer.calls, 1);
    assert_eq!(live.load(Ordering::SeqCst), 6);
    assert_eq!(*images[0].image.lock().unwrap(), Some(intent_bytes));
    assert_eq!(*images[1].image.lock().unwrap(), Some(issuer_bytes));
    assert_eq!(*images[0].runtime.lock().unwrap(), Some(runtime_bytes));
    let record_again = management_retention::exact_management_retry(
        "publication acknowledged exact retry",
        || controller.publish_pending_create(owner, locator, vec![], signer),
    );
    assert_eq!(record_again, record);
    assert_eq!(owner.ordered_index_for_test().unwrap(), published);
    assert_eq!(archive.load(locator).unwrap().unwrap(), archive_bytes);
    assert!(owner
        .host
        .lock()
        .unwrap()
        .clean_genesis_is_absent(locator.agent)
        .unwrap());
    // Keep all publication/parent evidence through an interrupted finalization
    // extension. The existing cut is after the exact finalization pledge and
    // before its Invoke, so no timing or new fault mechanism is needed.
    owner.fail_finalization_once_for_test(0);
    management_retention::exact_management_retry("pre-Invoke finalization cut", || {
        controller.publish_pending_create(owner, locator, vec![], signer)?;
        match controller.complete_pending_create(owner, locator, signer) {
            Err(SharedAgentHostError::Unavailable) if owner.finalization_failure_once.is_none() => {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => panic!("finalization must stop at the armed pre-Invoke cut"),
        }
    });
    assert_eq!(owner.finalization_failure_once, None);
    let extended = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        extended,
        published,
        "finalization registration adds no Ordered execution"
    );
    assert!(owner.management_admission_held().unwrap());
    assert_eq!(live.load(Ordering::SeqCst), 6);
    let record_after_extension = management_retention::exact_management_retry(
        "publication retry after finalization extension",
        || controller.publish_pending_create(owner, locator, vec![], signer),
    );
    assert_eq!(record_after_extension, record);
    assert_eq!(owner.ordered_index_for_test().unwrap(), extended);

    // Handoff moves the original/finalization pair out of pending admission.
    // A retry must consume the exact durable finalized ACK and retirement pair,
    // rather than trying to authorize the original invocation anew.
    owner.fail_finalization_once_for_test(7);
    management_retention::exact_management_retry("post-handoff finalization cut", || {
        controller.publish_pending_create(owner, locator, vec![], signer)?;
        match controller.complete_pending_create(owner, locator, signer) {
            Err(SharedAgentHostError::Unavailable) if owner.finalization_failure_once.is_none() => {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => panic!("finalization must stop at the armed post-handoff cut"),
        }
    });
    assert_eq!(owner.finalization_failure_once, None);
    let handed_off = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        handed_off,
        extended + 1,
        "one exact finalization Invoke only"
    );
    assert!(owner.management_admission_held().unwrap());
    assert_eq!(live.load(Ordering::SeqCst), 6);
    let record_after_handoff = management_retention::exact_management_retry(
        "publication retry after parent retirement handoff",
        || controller.publish_pending_create(owner, locator, vec![], signer),
    );
    assert_eq!(record_after_handoff, record);
    let retired = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        retired,
        handed_off + 2,
        "only exact parent ACKs; custody release adds no Ordered execution"
    );
    let acknowledgement = management_retention::exact_management_retry(
        "complete finalized publication retry",
        || controller.complete_pending_create(owner, locator, signer),
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), retired);
    assert!(!owner.management_admission_held().unwrap());
    // The public owner treats this already-retired publication Conflict as the
    // retained archive and completes the exact terminal again.
    assert_eq!(
        controller.publish_pending_create(owner, locator, vec![], signer),
        Err(SharedAgentHostError::Conflict)
    );
    let acknowledgement_again = management_retention::exact_management_retry(
        "already-completed parent exact retry",
        || controller.complete_pending_create(owner, locator, signer),
    );
    assert_eq!(acknowledgement_again, acknowledgement);
    assert_eq!(owner.ordered_index_for_test().unwrap(), retired);
    assert_eq!(archive.load(locator).unwrap().unwrap(), archive_bytes);
    assert_eq!(claim_signer.calls, 1);
    assert_eq!(live.load(Ordering::SeqCst), 6);
    drop(controller);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}
