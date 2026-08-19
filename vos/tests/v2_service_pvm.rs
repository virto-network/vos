//! Physical generic-service PVM integration gate.
//!
//! Build the service and actor guests first with:
//! `just build-v2-pvm-test-artifacts`.
//!
//! Missing guests are hard failures: these tests are a consensus-path gate,
//! not optional smoke tests.
#![allow(unexpected_cfgs)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vos::attestation::{
    AttestationProofHostV2, AttestationProofProducerV2, AttestationProofRequestV2,
    AttestationProofVerifierV2, ProducedAttestationProofV2,
};
use vos::network::RaftRpcHandler;
use vos::node::{AgentResult, V2NodeRegistrationError, VosNode};
use vos::raft::{RaftAccumulateLogV2, RaftConfig, RaftWorker, Role, WorkerConfig};
use vos::v2::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulatedReplyV2, AccumulatedRoleAssertionV2,
    AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2,
    ActorGenesisV2, ActorId, ActorUpgradeV2, ActorWriteV2, AttestedRootTreeInvokeErrorV2,
    AuthorizationEvidenceV2, BlobRefV2, CallId, CausalCallContextV2, CommittedAccumulateBatchV2,
    CommittedAccumulateEntryV2, CommittedAccumulateLogV2, CommittedImageStoreV2,
    CommittedServiceImageHostV2, CommittedServiceSnapshotV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationChangeV2, ContinuationSnapshotV2, CrdtChangeV2, DeploymentId, DirectIngressV2,
    DurableJamStoreV2, ExternalActorBindingV2, FileCommittedImageStoreV2, GasAccountingV2,
    GasScheduleV2, Hash, ImportedActorV2, ImportedBlobV2, ImportedProgramV2, InboxDrainOutcomeV2,
    InvocationId, JamServiceV2, LocalJamStoreHostV2, LocalJamStoreSnapshotV2, LocalJamStoreV2,
    LocalRootTreeConfigErrorV2, LocalRootTreeConfigV2, LocalRootTreeInvokeErrorV2,
    LocalRootTreeOpenErrorV2, LocalRootTreeServiceV2, LocalTransportV2, LocalWorkRequestV2,
    LocalWorkSchedulerV2, MessageRecordV2, MethodPolicyV2, NoRefineProtocolHostV2, Origin,
    PackageManifestV2, PackageRolePoliciesV2, PackageTaskDependencyV2, PrivateIngressStagingV2,
    ProducerId, ProductionTrustDecisionV2, ProductionTrustErrorV2, ProductionTrustV2, ProgramId,
    ProofArtifactStoreV2, ProofVerificationRequestV2, PublishedEffectsV2,
    ReceiptVerificationRequestV2, RefineImportsV2, RefineOutputV2, ReplicatedJamServiceV2,
    ReplicatedServiceErrorV2, ReplyRecordV2, RoleAuthorityBindingV2,
    RoleAuthorityInviteRedemptionV2, RoleAuthorityMutationV2, RoleAuthorizationClaimV2,
    RoleCredentialV2, RoleCredentialVerificationRequestV2, RootServiceId, RootTreeAttestedResultV2,
    RootTreeInvocationV2, ScheduleErrorV2, ServiceDispatchError, ServiceGenesisV2,
    ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, StateKeyV2, SubjectId, SystemCapabilityId,
    TaskDependencyV2, TransitionV2, V2Wire, VosPackageV2, WorkEnvelopeV2, WorkflowOperationV2,
    artifact_hash, public_policy_hash, space_role_policy_hash,
};
use vos::{
    Decode, Encode,
    actors::{client::ClientError, context::ServiceId},
    value::{Msg, Value},
};

const TEST_GAS_SCHEDULE: GasScheduleV2 = GasScheduleV2::new(1_000_000_000, 5_000_000_000);

mod host_greeter_surface {
    use vos::prelude::*;

    #[actor]
    pub struct Greeter;

    #[messages]
    impl Greeter {
        fn new() -> Self {
            Self
        }

        #[msg]
        async fn start(&self, _ctx: &mut Context<Self>) {}

        #[msg]
        async fn origin_kind(&self, _ctx: &mut Context<Self>) -> u8 {
            0
        }
    }
}

fn role_policies(mut methods: Vec<MethodPolicyV2>) -> Vec<u8> {
    methods.sort_by(|left, right| left.method.cmp(&right.method));
    PackageRolePoliciesV2 {
        methods,
        task_dependencies: vec![],
    }
    .encode()
}

fn direct_linear_ingress(work: &WorkEnvelopeV2) -> AccumulateRequestV2 {
    assert!(matches!(work.base, ConsistencyBaseV2::Linear { .. }));
    AccumulateRequestV2::AdmitIngress(DirectIngressV2 {
        service: work.service.clone(),
        invocation: work.invocation,
        logical_timeslot: work.logical_timeslot,
        target: work.target,
        method: work.method.clone(),
        arguments: work.arguments.clone(),
        private_arguments: work.private_arguments.clone(),
        origin: work.origin,
        authorization: work.authorization.clone(),
        imported_blobs: work.imported_blobs.clone(),
        proof_requested: work.proof_requested,
        base: work.base.clone(),
        base_causal_height: work.base_causal_height,
        crdt_change: None,
    })
}

fn admit_linear_work<A>(
    service: &mut JamServiceV2<NoRefineProtocolHostV2, A>,
    work: &WorkEnvelopeV2,
) where
    A: AccumulateProtocolHostV2,
{
    let admitted = service
        .accumulate(&direct_linear_ingress(work))
        .unwrap()
        .result;
    assert!(
        matches!(
            admitted,
            AccumulationResultV2::IngressAdmitted {
                duplicate: false,
                ..
            }
        ),
        "direct test ingress was rejected: {admitted:?}"
    );
}

fn request_from_work(work: &WorkEnvelopeV2) -> LocalWorkRequestV2 {
    LocalWorkRequestV2 {
        invocation: work.invocation,
        workflow_step: work.workflow_step,
        logical_timeslot: work.logical_timeslot,
        target: work.target,
        method: work.method.clone(),
        arguments: work.arguments.clone(),
        origin: work.origin,
        authorization: work.authorization.clone(),
        causal_parent: work.causal_parent,
        parent_call: work.parent_call,
        causal_context: work.causal_context.clone(),
        awaited_reply: work.awaited_reply.clone(),
        awaited_timeout: work.awaited_timeout.as_deref().cloned(),
        imported_blobs: work.imported_blobs.clone(),
        proof_requested: work.proof_requested,
    }
}

fn admit_direct_request<A>(
    service: &mut JamServiceV2<NoRefineProtocolHostV2, A>,
    request: &LocalWorkRequestV2,
) where
    A: AccumulateProtocolHostV2 + LocalJamStoreHostV2,
{
    let service_identity = service
        .accumulate_host()
        .local_store()
        .header()
        .unwrap()
        .unwrap()
        .service;
    let ingress = LocalWorkSchedulerV2::prepare_direct_ingress(
        service.accumulate_host().local_store(),
        &service_identity,
        request,
    )
    .unwrap();
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::AdmitIngress(ingress))
            .unwrap()
            .result,
        AccumulationResultV2::IngressAdmitted {
            duplicate: false,
            ..
        }
    ));
}

fn admit_and_prepare<A>(
    service: &mut JamServiceV2<NoRefineProtocolHostV2, A>,
    request: LocalWorkRequestV2,
) -> vos::v2::PreparedWorkV2
where
    A: AccumulateProtocolHostV2 + LocalJamStoreHostV2,
{
    admit_direct_request(service, &request);
    LocalWorkSchedulerV2::prepare(service.accumulate_host().local_store(), request).unwrap()
}

#[derive(Debug, Default)]
struct FailableCommittedImages {
    image: Option<Vec<u8>>,
    proofs: BTreeMap<[u8; 32], Vec<u8>>,
    private_ingresses: BTreeMap<InvocationId, Vec<u8>>,
    private_ingress_staging: BTreeMap<InvocationId, PrivateIngressStagingV2>,
    producer_records: BTreeMap<(ActorId, [u8; 32]), Vec<u8>>,
    fail_next_commit: bool,
    fail_next_proof_commit: bool,
    fail_next_record_commit: bool,
    fail_next_private_delete: bool,
    private_delete_attempts: usize,
}

#[derive(Debug, Clone, Default)]
struct SharedCommittedImages(Arc<Mutex<Option<Vec<u8>>>>);

#[derive(Debug, Clone, Default)]
struct SharedProofCommittedImages(Arc<Mutex<SharedProofCommittedImageState>>);

#[derive(Debug, Default)]
struct SharedProofCommittedImageState {
    image: Option<Vec<u8>>,
    proofs: BTreeMap<[u8; 32], Vec<u8>>,
}

#[derive(Debug, Default)]
struct SharedFailingImageState {
    image: Option<Vec<u8>>,
    commit_attempts: u64,
    fail_at: Option<u64>,
    failures: u64,
}

/// Shareable backend used to fail one exact durable commit after ownership has
/// moved into a node root thread.
#[derive(Debug, Clone, Default)]
struct SharedFailingCommittedImages(Arc<Mutex<SharedFailingImageState>>);

impl SharedFailingCommittedImages {
    fn fail_at(&self, commit_attempt: u64) {
        self.0.lock().unwrap().fail_at = Some(commit_attempt);
    }
}

impl CommittedImageStoreV2 for SharedCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        *self.0.lock().unwrap() = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStoreV2 for SharedCommittedImages {
    type Error = ();

    fn load_proof(&self, _reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn commit_proof(&mut self, _reference: &BlobRefV2, _proof: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRefV2)],
        _terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        if retained.is_empty() { Ok(()) } else { Err(()) }
    }
}

impl CommittedImageStoreV2 for SharedProofCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.lock().unwrap().image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.lock().unwrap().image = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStoreV2 for SharedProofCommittedImages {
    type Error = ();

    fn load_proof(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .proofs
            .get(&reference.hash.0)
            .filter(|proof| reference.matches(proof))
            .cloned())
    }

    fn commit_proof(&mut self, reference: &BlobRefV2, proof: &[u8]) -> Result<(), Self::Error> {
        if !reference.matches(proof) {
            return Err(());
        }
        self.0
            .lock()
            .unwrap()
            .proofs
            .insert(reference.hash.0, proof.to_vec());
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRefV2)],
        _terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        if retained.is_empty() { Ok(()) } else { Err(()) }
    }
}

impl CommittedImageStoreV2 for SharedFailingCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.lock().unwrap().image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        let mut state = self.0.lock().unwrap();
        state.commit_attempts += 1;
        if state.fail_at == Some(state.commit_attempts) {
            state.fail_at = None;
            state.failures += 1;
            return Err(());
        }
        state.image = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStoreV2 for SharedFailingCommittedImages {
    type Error = ();

    fn load_proof(&self, _reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn commit_proof(&mut self, _reference: &BlobRefV2, _proof: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRefV2)],
        _terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        if retained.is_empty() { Ok(()) } else { Err(()) }
    }
}

#[derive(Debug)]
struct CanonicalTestProofProducer {
    proof: Vec<u8>,
    calls: usize,
}

impl AttestationProofProducerV2 for CanonicalTestProofProducer {
    type Error = ();

    fn prove(
        &mut self,
        request: &AttestationProofRequestV2<'_>,
    ) -> Result<ProducedAttestationProofV2, Self::Error> {
        request.validate().map_err(|_| ())?;
        assert_eq!(
            request
                .imports
                .programs
                .iter()
                .find(|program| program.program == request.work.target_program)
                .map(|program| ProgramId::of_pvm(&program.pvm)),
            Some(request.work.target_program),
            "the proof request carries the live canonical actor PVM"
        );
        self.calls += 1;
        Ok(ProducedAttestationProofV2 {
            trace: request.refine_trace,
            proof: self.proof.clone(),
        })
    }
}

impl AttestationProofVerifierV2 for CanonicalTestProofProducer {
    type Error = ();

    fn verify(
        &mut self,
        request: &ProofVerificationRequestV2,
        proof: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(request.proof_blob.matches(proof) && proof == self.proof)
    }
}

fn canonical_test_proof_manifest(tag: u8) -> Vec<u8> {
    vos::v2::AttestationProofManifestV2 {
        proof_system: vos::v2::AttestationProofManifestV2::proof_system(),
        initial_root: Hash([tag.wrapping_add(1); 32]),
        segments: vec![vos::v2::ProofArtifactIdV2([tag; 32])],
    }
    .encode()
}

#[derive(Debug)]
struct MismatchedTraceProofProducer;

impl AttestationProofProducerV2 for MismatchedTraceProofProducer {
    type Error = ();

    fn prove(
        &mut self,
        request: &AttestationProofRequestV2<'_>,
    ) -> Result<ProducedAttestationProofV2, Self::Error> {
        request.validate().map_err(|_| ())?;
        let mut trace = request.refine_trace;
        trace.0[0] ^= 1;
        Ok(ProducedAttestationProofV2 {
            trace,
            proof: b"proof for the wrong trace".to_vec(),
        })
    }
}

impl CommittedImageStoreV2 for FailableCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        if std::mem::take(&mut self.fail_next_commit) {
            return Err(());
        }
        self.image = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStoreV2 for FailableCommittedImages {
    type Error = ();

    fn load_proof(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .proofs
            .get(&reference.hash.0)
            .filter(|bytes| reference.matches(bytes))
            .cloned())
    }

    fn commit_proof(&mut self, reference: &BlobRefV2, proof: &[u8]) -> Result<(), Self::Error> {
        if std::mem::take(&mut self.fail_next_proof_commit) || !reference.matches(proof) {
            return Err(());
        }
        match self.proofs.get(&reference.hash.0) {
            Some(existing) if existing != proof => Err(()),
            Some(_) => Ok(()),
            None => {
                self.proofs.insert(reference.hash.0, proof.to_vec());
                Ok(())
            }
        }
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(self.private_ingresses.len())
    }

    fn load_private_ingress(
        &self,
        invocation: InvocationId,
        reference: &BlobRefV2,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .private_ingresses
            .get(&invocation)
            .filter(|bytes| reference.matches(bytes))
            .cloned())
    }

    fn commit_private_ingress(
        &mut self,
        invocation: InvocationId,
        reference: &BlobRefV2,
        arguments: &[u8],
        staging: PrivateIngressStagingV2,
    ) -> Result<bool, Self::Error> {
        if !reference.matches(arguments) {
            return Err(());
        }
        match self.private_ingresses.get(&invocation) {
            Some(existing) if existing != arguments => Err(()),
            Some(_) => {
                if staging == PrivateIngressStagingV2::Replicated {
                    self.private_ingress_staging.insert(invocation, staging);
                }
                Ok(true)
            }
            None => {
                self.private_ingresses
                    .insert(invocation, arguments.to_vec());
                self.private_ingress_staging.insert(invocation, staging);
                Ok(true)
            }
        }
    }

    fn delete_private_ingress(&mut self, invocation: InvocationId) -> Result<bool, Self::Error> {
        self.private_delete_attempts += 1;
        if std::mem::take(&mut self.fail_next_private_delete) {
            return Err(());
        }
        self.private_ingress_staging.remove(&invocation);
        Ok(self.private_ingresses.remove(&invocation).is_some())
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRefV2)],
        terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        for (invocation, reference) in retained {
            let Some(arguments) = self.private_ingresses.get(invocation) else {
                return Err(());
            };
            if !reference.matches(arguments) {
                return Err(());
            }
        }
        self.private_ingresses.retain(|invocation, _| {
            terminal.binary_search(invocation).is_err()
                && (retained
                    .binary_search_by_key(invocation, |(candidate, _)| *candidate)
                    .is_ok()
                    || self.private_ingress_staging.get(invocation)
                        == Some(&PrivateIngressStagingV2::Replicated))
        });
        self.private_ingress_staging
            .retain(|invocation, _| self.private_ingresses.contains_key(invocation));
        Ok(())
    }

    fn load_producer_record(
        &self,
        actor: ActorId,
        tag: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.producer_records.get(&(actor, *tag)).cloned())
    }

    fn commit_producer_record(
        &mut self,
        actor: ActorId,
        tag: &[u8; 32],
        record: &[u8],
    ) -> Result<bool, Self::Error> {
        if std::mem::take(&mut self.fail_next_record_commit)
            || vos::provable::ProofRecordEntry::decode(record).is_none()
        {
            return Err(());
        }
        match self.producer_records.get(&(actor, *tag)) {
            Some(existing) if existing != record => Err(()),
            Some(_) => Ok(true),
            None => {
                self.producer_records.insert((actor, *tag), record.to_vec());
                Ok(true)
            }
        }
    }

    fn delete_producer_record(
        &mut self,
        actor: ActorId,
        tag: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        Ok(self.producer_records.remove(&(actor, *tag)).is_some())
    }
}

type DurableTestService =
    JamServiceV2<NoRefineProtocolHostV2, DurableJamStoreV2<FailableCommittedImages>>;

fn restart_durable_service(
    service: DurableTestService,
    service_pvm: &[u8],
    service_program: ProgramId,
) -> DurableTestService {
    let (_, host) = service.into_hosts();
    let (_, backend) = host.into_parts();
    JamServiceV2::new(
        service_pvm.to_vec(),
        service_program,
        NoRefineProtocolHostV2,
        DurableJamStoreV2::open(backend).expect("committed service image reopens"),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestLogError {
    NotLeader,
    InvalidCursor,
}

#[derive(Debug, Default)]
struct SharedCommittedLog {
    entries: Vec<CommittedAccumulateEntryV2>,
}

struct TestCommittedLog {
    shared: Arc<Mutex<SharedCommittedLog>>,
    applied: u64,
    leader: bool,
    before_next_read_index: Vec<Vec<u8>>,
    before_next_proposal: Vec<Vec<u8>>,
    installed_snapshot: Option<CommittedServiceSnapshotV2>,
    committed_index_floor: Option<u64>,
}

impl TestCommittedLog {
    fn new(shared: Arc<Mutex<SharedCommittedLog>>, leader: bool) -> Self {
        Self {
            shared,
            applied: 0,
            leader,
            before_next_read_index: Vec::new(),
            before_next_proposal: Vec::new(),
            installed_snapshot: None,
            committed_index_floor: None,
        }
    }

    fn with_installed_snapshot(mut self, snapshot: CommittedServiceSnapshotV2) -> Self {
        self.installed_snapshot = Some(snapshot);
        self
    }

    fn with_applied(mut self, applied: u64) -> Self {
        self.applied = applied;
        self
    }

    fn with_committed_index_floor(mut self, index: u64) -> Self {
        self.committed_index_floor = Some(index);
        self
    }

    fn commit_before_next_proposal(&mut self, request: Vec<u8>) {
        self.before_next_proposal.push(request);
    }

    fn commit_before_next_read_index(&mut self, request: Vec<u8>) {
        self.before_next_read_index.push(request);
    }

    fn committed_len(&self) -> usize {
        self.shared.lock().unwrap().entries.len()
    }
}

impl CommittedAccumulateLogV2 for TestCommittedLog {
    type Error = TestLogError;

    fn leader_read_index(&mut self) -> Result<u64, Self::Error> {
        if !self.leader {
            return Err(TestLogError::NotLeader);
        }
        let mut shared = self.shared.lock().unwrap();
        for request in core::mem::take(&mut self.before_next_read_index) {
            let entry = CommittedAccumulateEntryV2 {
                index: shared.entries.len() as u64 + 1,
                request,
                logical_timeslot: None,
                production_trust_policy: None,
                availability_programs: vec![],
                availability_blobs: vec![],
                receipt_verifications: vec![],
            };
            shared.entries.push(entry);
        }
        Ok(shared.entries.len() as u64)
    }

    fn propose_at_with_availability(
        &mut self,
        request: &[u8],
        logical_timeslot: Option<u64>,
        production_trust_policy: Option<Hash>,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
        receipt_verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        if !self.leader {
            return Err(TestLogError::NotLeader);
        }
        let mut shared = self.shared.lock().unwrap();
        for request in core::mem::take(&mut self.before_next_proposal) {
            let entry = CommittedAccumulateEntryV2 {
                index: shared.entries.len() as u64 + 1,
                request,
                logical_timeslot: None,
                production_trust_policy: None,
                availability_programs: vec![],
                availability_blobs: vec![],
                receipt_verifications: vec![],
            };
            shared.entries.push(entry);
        }
        let entry = CommittedAccumulateEntryV2 {
            index: shared.entries.len() as u64 + 1,
            request: request.to_vec(),
            logical_timeslot,
            production_trust_policy,
            availability_programs: programs.to_vec(),
            availability_blobs: blobs.to_vec(),
            receipt_verifications: receipt_verifications.to_vec(),
        };
        shared.entries.push(entry.clone());
        Ok(entry)
    }

    fn committed_after(
        &mut self,
        applied_index: u64,
    ) -> Result<CommittedAccumulateBatchV2, Self::Error> {
        if applied_index != self.applied {
            return Err(TestLogError::InvalidCursor);
        }
        let shared = self.shared.lock().unwrap();
        let committed_index = self
            .committed_index_floor
            .unwrap_or(shared.entries.len() as u64);
        Ok(CommittedAccumulateBatchV2 {
            entries: shared
                .entries
                .iter()
                .filter(|entry| entry.index > applied_index)
                .cloned()
                .collect(),
            committed_index,
        })
    }

    fn applied_index(&mut self) -> Result<u64, Self::Error> {
        Ok(self.applied)
    }

    fn installed_snapshot_after(
        &mut self,
        applied_index: u64,
    ) -> Result<Option<CommittedServiceSnapshotV2>, Self::Error> {
        if applied_index != self.applied {
            return Err(TestLogError::InvalidCursor);
        }
        Ok(self
            .installed_snapshot
            .as_ref()
            .filter(|snapshot| snapshot.applied_index > applied_index)
            .cloned())
    }

    fn mark_applied(
        &mut self,
        index: u64,
        _service_image: &[u8],
        _proof_artifacts: &[vos::v2::CommittedProofArtifactV2],
    ) -> Result<(), Self::Error> {
        let committed = self
            .committed_index_floor
            .unwrap_or_else(|| self.shared.lock().unwrap().entries.len() as u64);
        if index < self.applied || index > committed {
            return Err(TestLogError::InvalidCursor);
        }
        self.applied = index;
        Ok(())
    }
}

fn authorize_install<A: LocalJamStoreHostV2>(
    service: &mut JamServiceV2<NoRefineProtocolHostV2, A>,
    request: &AccumulateRequestV2,
) {
    let AccumulateRequestV2::Install(genesis) = request else {
        panic!("install authorization requires a genesis request")
    };
    service
        .accumulate_host_mut()
        .local_store_mut()
        .allow_install(genesis);
}

const CANONICAL_SERVICE_PVM: &[u8] = include_bytes!("../../services/vos-service/vos-service.pvm");
const SERVICE_BUILD_CONFIG: &str = include_str!("../../services/vos-service/.cargo/config.toml");
const SERVICE_RUSTC_WRAPPER: &str = include_str!("../../services/vos-service/rustc-remap.sh");

fn required_elf(relative_path: &str, build_command: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "required guest ELF is unavailable at {}: {error}\nbuild it with `{build_command}`",
            path.display()
        )
    })
}

#[test]
#[should_panic(expected = "required guest ELF is unavailable")]
fn missing_required_guest_is_a_hard_failure() {
    required_elf(
        "tests/fixtures/definitely-missing-v2-guest.elf",
        "just build-v2-pvm-test-artifacts",
    );
}

fn service_elf() -> Vec<u8> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let service_dir = manifest_dir.join("../services/vos-service");
    let path = service_dir.join("target/riscv64em-javm/release/vos_service.elf");
    let elf = required_elf(
        "../services/vos-service/target/riscv64em-javm/release/vos_service.elf",
        "just build-v2-pvm-test-artifacts",
    );
    let built_at = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .expect("read canonical service artifact modification time");
    let inputs = [
        manifest_dir.join("src"),
        manifest_dir.join("Cargo.toml"),
        manifest_dir.join("../Cargo.toml"),
        manifest_dir.join("../Cargo.lock"),
        service_dir.join("src"),
        service_dir.join("Cargo.toml"),
        service_dir.join("Cargo.lock"),
        service_dir.join("riscv64em-javm.json"),
        service_dir.join("rust-toolchain.toml"),
        service_dir.join(".cargo/config.toml"),
        service_dir.join("rustc-remap.sh"),
    ];
    if let Some(newer) = newer_build_input(&inputs, built_at) {
        panic!(
            "canonical service artifact is stale: {} is newer than {}; rebuild with \
             `just build-vos-service`",
            newer.display(),
            path.display(),
        );
    }
    elf
}

fn newer_build_input(inputs: &[PathBuf], built_at: std::time::SystemTime) -> Option<PathBuf> {
    let mut pending = inputs.to_vec();
    while let Some(path) = pending.pop() {
        let metadata = std::fs::metadata(&path).unwrap_or_else(|error| {
            panic!(
                "inspect canonical service build input {}: {error}",
                path.display()
            )
        });
        if metadata.is_dir() {
            let entries = std::fs::read_dir(&path).unwrap_or_else(|error| {
                panic!(
                    "enumerate canonical service build input {}: {error}",
                    path.display()
                )
            });
            pending.extend(entries.map(|entry| {
                entry
                    .unwrap_or_else(|error| {
                        panic!(
                            "enumerate canonical service build input {}: {error}",
                            path.display()
                        )
                    })
                    .path()
            }));
        } else if metadata
            .modified()
            .is_ok_and(|modified| modified > built_at)
        {
            return Some(path);
        }
    }
    None
}

#[test]
fn canonical_service_artifact_has_the_protocol_identity() {
    assert_eq!(
        ProgramId::of_pvm(CANONICAL_SERVICE_PVM),
        vos::v2::VOS_SERVICE_PROGRAM_ID
    );
    ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .expect("committed service PVM has the canonical Refine/Accumulate entries");
}

#[test]
fn canonical_service_artifact_matches_a_fresh_build() {
    let elf = service_elf();
    let fresh = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    assert!(
        fresh == CANONICAL_SERVICE_PVM,
        "fresh vos-service build differs: fresh ProgramId {:?}, committed ProgramId {:?}",
        ProgramId::of_pvm(&fresh),
        ProgramId::of_pvm(CANONICAL_SERVICE_PVM)
    );
}

#[test]
fn canonical_service_build_pins_path_independent_crate_identity() {
    assert!(SERVICE_BUILD_CONFIG.contains("rustc-wrapper = \"./rustc-remap.sh\""));
    assert!(SERVICE_BUILD_CONFIG.contains("-Zremap-cwd-prefix=."));
    assert!(SERVICE_RUSTC_WRAPPER.contains("-Cmetadata=vos-service-v2"));
    assert!(SERVICE_RUSTC_WRAPPER.contains("--remap-path-prefix=$repository_root=vos-source"));
}

fn greeter_elf() -> Vec<u8> {
    required_elf(
        "../tests/fixtures/legacy-v1/actors/greeter/target/riscv64em-javm/release/greeter.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn probe_elf() -> Vec<u8> {
    required_elf(
        "../tests/fixtures/legacy-v1/actors/probe/target/riscv64em-javm/release/probe.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn tally_elf() -> Vec<u8> {
    required_elf(
        "../tests/fixtures/legacy-v1/actors/tally/target/riscv64em-javm/release/tally.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn crdt_counter_v2_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/crdt-counter-v2/target/riscv64em-javm/release/crdt_counter_v2_fixture.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn workflow_v2_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/workflow-v2/target/riscv64em-javm/release/workflow_v2_fixture.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn cycle_v2_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/cycle-v2/target/riscv64em-javm/release/cycle_v2_fixture.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn space_authority_elf() -> Vec<u8> {
    required_elf(
        "../actors/space-authority/target/riscv64em-javm/release/space_authority.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn canonical_clerk_package() -> VosPackageV2 {
    let bytes = required_elf(
        "../target/v2-clerk/clerk-ledger.vos",
        "just build-v2-pvm-test-artifacts",
    );
    let package = VosPackageV2::decode(&bytes).expect("canonical Clerk package decodes");
    package
        .validate()
        .expect("canonical Clerk package signature and contents validate");
    package
}

fn install_test_voter_registry(
    node: &mut VosNode,
    registry_pvm: Vec<u8>,
    voters: &[(u16, Vec<u8>)],
) {
    use ed25519_dalek::{Signer, SigningKey};
    use space_registry::{
        NODE_ROLE_VOTER, SpaceRegistryRef, Status, canonical_op_bytes, pack_auth,
    };

    node.register_at_id(
        vos::node::AgentConfig::new(registry_pvm),
        ServiceId::REGISTRY,
    );
    let registry = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let root_key = SigningKey::from_bytes(&[0xB9; 32]);
    let mut root_peer = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
    root_peer.extend_from_slice(&root_key.verifying_key().to_bytes());
    assert_eq!(
        vos::block_on(registry.set_root(&mut &*node, root_peer.clone())).unwrap(),
        Status::Ok,
    );
    for (prefix, peer) in voters {
        let prefix = u32::from(*prefix);
        let canonical = canonical_op_bytes(
            "add_node",
            &[&prefix.to_le_bytes(), peer, &[NODE_ROLE_VOTER]],
        );
        let authorization = pack_auth(&root_peer, &root_key.sign(&canonical).to_bytes());
        assert_eq!(
            vos::block_on(registry.add_node(
                &mut &*node,
                prefix,
                peer.clone(),
                NODE_ROLE_VOTER,
                authorization,
            ))
            .unwrap(),
            Status::Ok,
        );
    }
}

fn actor_pvm(result: u64) -> Vec<u8> {
    let mut assembler = grey_transpiler::assembler::Assembler::new();
    assembler
        .load_imm_64(grey_transpiler::assembler::Reg::A0, result)
        .ecalli(0);
    assembler.build()
}

fn work(actor_program: ProgramId, state: BlobRefV2) -> WorkEnvelopeV2 {
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("start").encode());
    WorkEnvelopeV2 {
        external_actors: vec![],
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        invocation: InvocationId([4; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: ActorId([5; 32]),
        target_deployment: DeploymentId([2; 32]),
        target_program: actor_program,
        private_arguments: None,
        method: "start".into(),
        arguments: message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        consistency: ConsistencyModeV2::Local,
        base: ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: Hash([8; 32]),
        },
        base_causal_height: None,
        imported_actors: vec![ImportedActorV2 {
            actor: ActorId([5; 32]),
            name: "root".into(),
            parent: None,
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            task_dependencies: vec![],
            state,
            causal_states: vec![],
            continuation: None,
            storage_rows: vec![],
        }],
        imported_blobs: vec![],
        proof_requested: false,
    }
}

fn external_binding(
    name: &str,
    service: ServiceIdentityV2,
    actor: ActorId,
    producer: ProducerId,
    program: ProgramId,
) -> ExternalActorBindingV2 {
    let actor_deployment = service.deployment;
    ExternalActorBindingV2 {
        name: name.into(),
        service,
        actor,
        producer,
        actor_deployment,
        program,
    }
}

fn bound_peer_service(service: &ServiceIdentityV2) -> ServiceIdentityV2 {
    let mut peer = service.clone();
    peer.root_service = RootServiceId([45; 32]);
    peer.deployment = DeploymentId([46; 32]);
    peer
}

fn private_age_binding(service: &ServiceIdentityV2) -> ExternalActorBindingV2 {
    external_binding(
        "private-age",
        bound_peer_service(service),
        ActorId([44; 32]),
        ProducerId([98; 32]),
        ProgramId([92; 32]),
    )
}

fn peer_reply(
    service: &ServiceIdentityV2,
    call_id: CallId,
    value: u32,
    discriminator: u8,
) -> AccumulatedReplyV2 {
    let reply = ReplyRecordV2 {
        call_id,
        producer: ActorId([44; 32]),
        result: Value::U32(value).encode(),
    };
    let producer_service = bound_peer_service(service);
    AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: producer_service,
            accepted_transition: Hash([discriminator.wrapping_add(2); 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([discriminator.wrapping_add(3); 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply,
        attestation: None,
    }
}

#[test]
fn canonical_guest_refine_runs_at_ic0_and_returns_nested_transition() {
    let elf = service_elf();
    let actor_elf = greeter_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm))
        .expect("generic service has the GP IC0/IC5 entries");
    let actor = grey_transpiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRefV2::of_bytes(&state_bytes);
    let mut work = work(actor_program, state.clone());
    work.imported_actors.push(ImportedActorV2 {
        actor: ActorId([6; 32]),
        name: "child".into(),
        parent: Some(work.target),
        deployment: work.target_deployment,
        program: actor_program,
        task_dependencies: vec![],
        state: state.clone(),
        causal_states: vec![],
        continuation: None,
        storage_rows: vec![],
    });
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        }],
        private_blobs: vec![],
    };

    let output = service
        .refine_actor_tree(
            &work.encode(),
            &imports,
            100_000_000,
            &NoRefineProtocolHostV2,
        )
        .expect("generic Refine completes");
    let transition = RefineOutputV2::decode(&output.bytes)
        .expect("Refine returns RefineOutputV2")
        .transition;
    assert_eq!(transition.service, work.service);
    assert_eq!(transition.consumed_input, work.input_id());
    assert_eq!(transition.target_program, work.target_program);
    assert_eq!(transition.base, work.base);
    assert_eq!(transition.writes.len(), 1);
    assert_eq!(transition.writes[0].actor, work.target);
    assert_eq!(transition.writes[0].key, vos::lifecycle::STATE_KEY_BYTES);
    assert!(
        transition.writes[0]
            .value
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(
        transition.reply.as_ref().map(|reply| reply.call_id),
        Some(work.invocation.root_reply_id())
    );
}

fn signed_test_package(
    actor_elf: &[u8],
    signer: &libp2p::identity::Keypair,
) -> (VosPackageV2, String) {
    let actor_pvm = grey_transpiler::link_elf(actor_elf).expect("actor transpiles");
    let schemas = vos::metadata::raw_section_from_elf(actor_elf).expect("actor metadata");
    let metadata = vos::metadata::decode(&schemas).expect("valid actor metadata");
    let policies = PackageRolePoliciesV2::from_metadata(&metadata)
        .expect("actor policies")
        .encode();
    let public_key = signer.public().encode_protobuf();
    let mut package = VosPackageV2 {
        manifest: PackageManifestV2 {
            name: metadata.actor_name.clone(),
            version: "2.0.0".into(),
            service_abi: vos::v2::ABI_VERSION,
            snapshot_version: vos::v2::SNAPSHOT_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            actor_program: ProgramId::of_pvm(&actor_pvm),
            crdt: metadata.crdt,
            interfaces_hash: artifact_hash(b"interfaces", &[]),
            role_policies_hash: artifact_hash(b"role-policies", &policies),
            schemas_hash: artifact_hash(b"schemas", &schemas),
            task_dependencies_hash: vos::v2::task_dependencies_hash(&[]),
        },
        actor_pvm,
        generated_interfaces: vec![],
        role_policies: policies,
        schemas,
        task_dependencies: vec![],
        diagnostics: None,
        deployment_signature: vos::v2::DeploymentSignatureV2 {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: vec![1],
        },
    };
    package.deployment_signature.signature = signer
        .sign(&package.signing_message())
        .expect("sign canonical deployment");
    package.validate().expect("package structure is canonical");
    (package, metadata.actor_name)
}

fn attested_root_fixture(
    consistency: ConsistencyModeV2,
    salt: u8,
) -> (LocalRootTreeConfigV2, LocalWorkRequestV2) {
    let actor_elf = workflow_v2_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([salt; 32]);
    let service = ServiceIdentityV2 {
        space: vos::v2::SpaceId([salt.wrapping_add(1); 32]),
        root_service: RootServiceId([salt.wrapping_add(2); 32]),
        deployment: package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service,
        root_actor: actor,
        actor_name,
        consistency,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([salt.wrapping_add(3); 32]),
            authenticator: vec![salt.wrapping_add(4)],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("attested_value").encode());
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([salt.wrapping_add(5); 32]),
        workflow_step: 0,
        logical_timeslot: 11,
        target: actor,
        method: "attested_value".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: true,
    };
    (config, request)
}

struct TestProductionTrust {
    policy: Hash,
    slot: AtomicU64,
    allow: bool,
}

impl TestProductionTrust {
    fn new(policy: u8, slot: u64, allow: bool) -> Self {
        Self {
            policy: Hash([policy; 32]),
            slot: AtomicU64::new(slot),
            allow,
        }
    }
}

impl ProductionTrustV2 for TestProductionTrust {
    fn policy_id(&self) -> Hash {
        self.policy
    }

    fn logical_timeslot(&self) -> Option<u64> {
        Some(self.slot.load(Ordering::Relaxed))
    }

    fn verify_logical_timeslot(&self, logical_timeslot: u64) -> ProductionTrustDecisionV2 {
        if !self.allow {
            ProductionTrustDecisionV2::Denied
        } else if logical_timeslot <= self.slot.load(Ordering::Relaxed) {
            ProductionTrustDecisionV2::Authorized
        } else {
            ProductionTrustDecisionV2::Denied
        }
    }

    fn verify_proof(
        &self,
        _request: &ProofVerificationRequestV2,
        _proof: &[u8],
    ) -> ProductionTrustDecisionV2 {
        if self.allow {
            ProductionTrustDecisionV2::Authorized
        } else {
            ProductionTrustDecisionV2::Denied
        }
    }

    fn verify_install(&self, _genesis: &ServiceGenesisV2) -> ProductionTrustDecisionV2 {
        if self.allow {
            ProductionTrustDecisionV2::Authorized
        } else {
            ProductionTrustDecisionV2::Denied
        }
    }

    fn verify_upgrade(&self, _upgrade: &ActorUpgradeV2) -> ProductionTrustDecisionV2 {
        if self.allow {
            ProductionTrustDecisionV2::Authorized
        } else {
            ProductionTrustDecisionV2::Denied
        }
    }

    fn verify_role_credential(
        &self,
        _request: &RoleCredentialVerificationRequestV2,
    ) -> ProductionTrustDecisionV2 {
        if self.allow {
            ProductionTrustDecisionV2::Authorized
        } else {
            ProductionTrustDecisionV2::Denied
        }
    }

    fn verify_receipt(&self, _request: &ReceiptVerificationRequestV2) -> ProductionTrustDecisionV2 {
        if self.allow {
            ProductionTrustDecisionV2::Authorized
        } else {
            ProductionTrustDecisionV2::Denied
        }
    }
}

#[test]
fn production_root_requires_the_same_durable_trust_policy_after_restart() {
    let (config, mut request) = attested_root_fixture(ConsistencyModeV2::Local, 0x39);
    let backend = SharedCommittedImages::default();
    let trust = Arc::new(TestProductionTrust::new(0x81, 77, true));
    let mut service =
        LocalRootTreeServiceV2::open_production(config.clone(), backend.clone(), trust.clone())
            .expect("production authority approves physical guest installation");
    assert_eq!(service.production_trust_policy_id(), Some(trust.policy));
    request.method = "increment".into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new("increment").with("amount", 1_u32).encode());
        arguments
    };
    request.proof_requested = false;
    request.logical_timeslot = 76;
    let before = service.store().header().unwrap().unwrap();
    assert!(matches!(
        service.invoke(request.clone()),
        Err(LocalRootTreeInvokeErrorV2::Service(
            ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateHostRejected(slot)),
        )) if slot == vos::abi::hostcall::ACCUMULATION_TIMESLOT as u8,
    ));
    assert_eq!(
        service.store().header().unwrap().unwrap(),
        before,
        "an unverified embedded slot reaches neither guest state nor dedup",
    );
    request.logical_timeslot = 77;
    let mut regressed = request.clone();
    service
        .invoke(request)
        .expect("the consensus-verified embedded slot reaches physical IC-5");
    trust.slot.store(76, Ordering::Relaxed);
    regressed.invocation = InvocationId([0x7c; 32]);
    regressed.logical_timeslot = 76;
    assert!(matches!(
        service.invoke(regressed),
        Err(LocalRootTreeInvokeErrorV2::Service(
            ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateHostRejected(slot)),
        )) if slot == vos::abi::hostcall::ACCUMULATION_TIMESLOT as u8,
    ));
    trust.slot.store(77, Ordering::Relaxed);
    drop(service);

    assert!(matches!(
        LocalRootTreeServiceV2::open(config.clone(), backend.clone()),
        Err(LocalRootTreeOpenErrorV2::ProductionTrust(
            ProductionTrustErrorV2::TrustRequired,
        )),
    ));
    assert!(matches!(
        LocalRootTreeServiceV2::open_production(
            config.clone(),
            backend.clone(),
            Arc::new(TestProductionTrust::new(0x82, 77, true)),
        ),
        Err(LocalRootTreeOpenErrorV2::ProductionTrust(
            ProductionTrustErrorV2::PolicyMismatch,
        )),
    ));
    let reopened = LocalRootTreeServiceV2::open_production(config, backend, trust)
        .expect("the identical production policy reopens its sealed image");
    assert_eq!(
        reopened.production_trust_policy_id(),
        Some(Hash([0x81; 32]))
    );

    let (denied_config, _) = attested_root_fixture(ConsistencyModeV2::Local, 0x38);
    assert!(matches!(
        LocalRootTreeServiceV2::open_production(
            denied_config,
            SharedCommittedImages::default(),
            Arc::new(TestProductionTrust::new(0x83, 78, false)),
        ),
        Err(LocalRootTreeOpenErrorV2::InstallRejected(
            AccumulationRejectionV2::Unauthorized,
        )),
    ));
}

#[test]
fn raft_replay_rejects_a_different_production_trust_policy_before_genesis() {
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial_state = BlobRefV2::of_bytes(&initial_bytes);
    let actor = ActorId([0x84; 32]);
    let service = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0x85; 32]),
        root_service: RootServiceId([0x86; 32]),
        deployment: DeploymentId([0x87; 32]),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor,
            name: "root".into(),
            parent: None,
            producer: ProducerId([0x88; 32]),
            deployment: service.deployment,
            program: actor_program,
            initial_state: initial_state.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([0x89; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0x8a; 32]),
            authenticator: vec![0x8b],
        },
    };
    let programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let blobs = vec![ImportedBlobV2 {
        reference: initial_state,
        bytes: initial_bytes,
    }];
    let shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let make_replica = |policy: u8, leader: bool| {
        let mut host = LocalJamStoreV2::default();
        host.install_production_trust(Arc::new(TestProductionTrust::new(policy, 20, true)))
            .unwrap();
        ReplicatedJamServiceV2::new(
            JamServiceV2::new(
                CANONICAL_SERVICE_PVM.to_vec(),
                vos::v2::VOS_SERVICE_PROGRAM_ID,
                NoRefineProtocolHostV2,
                host,
                TEST_GAS_SCHEDULE.refine,
                TEST_GAS_SCHEDULE.accumulate,
            )
            .unwrap(),
            TestCommittedLog::new(shared.clone(), leader),
        )
    };
    let mut leader = make_replica(0x91, true);
    assert!(matches!(
        leader
            .accumulate_with_availability(
                &AccumulateRequestV2::Install(genesis),
                &programs,
                &blobs,
            )
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_),
    ));
    assert_eq!(
        shared.lock().unwrap().entries[0].production_trust_policy,
        Some(Hash([0x91; 32])),
    );

    let mut matching_follower = make_replica(0x91, false);
    assert_eq!(matching_follower.catch_up().unwrap(), 1);
    assert!(
        matching_follower
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_some()
    );

    let mut mismatched_follower = make_replica(0x92, false);
    assert!(matches!(
        mismatched_follower.catch_up(),
        Err(ReplicatedServiceErrorV2::InvalidCommittedLog),
    ));
    assert_eq!(mismatched_follower.log_mut().applied_index().unwrap(), 0);
    assert!(
        mismatched_follower
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none()
    );
}

#[test]
fn node_raft_registration_installs_production_trust_before_replay_and_promotion() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Raft, 0x93);
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-node-production-trust-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db = Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap());
    let backend = SharedProofCommittedImages::default();
    let member = 0x93u16;
    let route = ServiceId::new(member, 0x3393);
    let raft_config = RaftConfig {
        me: member,
        members: vec![member],
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id: [0x94; 32],
        propose_timeout_ms: 2_000,
    };
    let trust = Arc::new(TestProductionTrust::new(0x95, 77, true));
    let proof = canonical_test_proof_manifest(0x96);

    let mut node = VosNode::with_prefix(member);
    node.register_v2_raft_root_at_id_production_with_producer(
        "production-attested-root-v2".into(),
        config.clone(),
        backend.clone(),
        db.clone(),
        raft_config.clone(),
        route,
        false,
        trust.clone(),
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .expect("the node installs production trust before Raft genesis");
    std::thread::sleep(Duration::from_millis(350));
    let attested = node
        .invoke_actor_attested(request.target, request.arguments)
        .expect("the production policy verifies the leader-produced proof");
    assert_eq!(attested.value, Value::U32(7));
    assert_eq!(attested.proof, proof);
    assert!(node.collect().iter().all(AgentResult::is_ok));

    let mut mismatched = VosNode::with_prefix(member);
    let reopened = mismatched.register_v2_raft_root_at_id_production(
        "production-attested-root-v2".into(),
        config,
        backend,
        db,
        raft_config,
        route,
        false,
        Arc::new(TestProductionTrust::new(0x97, 77, true)),
    );
    assert!(matches!(
        reopened,
        Err(vos::node::V2RaftNodeRegistrationError::Open(
            LocalRootTreeOpenErrorV2::ProductionTrust(ProductionTrustErrorV2::PolicyMismatch),
        )),
    ));
    assert!(
        mismatched.collect().is_empty(),
        "a mismatched policy never exposes a root route",
    );

    let (denied_config, _) = attested_root_fixture(ConsistencyModeV2::Raft, 0x98);
    let denied_db = Arc::new(redb::Database::create(directory.join("denied-join.redb")).unwrap());
    let promoted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_ran = promoted.clone();
    let mut denied = VosNode::with_prefix(member);
    let denied_open = denied.register_v2_raft_root_at_id_after_local_attach_production(
        "denied-production-joiner-v2".into(),
        denied_config,
        SharedProofCommittedImages::default(),
        denied_db,
        RaftConfig {
            me: member,
            members: vec![member],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0x99; 32],
            propose_timeout_ms: 2_000,
        },
        ServiceId::new(member, 0x3394),
        false,
        Arc::new(TestProductionTrust::new(0x9a, 77, false)),
        move |_, _| {
            callback_ran.store(true, Ordering::Relaxed);
            Ok(())
        },
    );
    assert!(matches!(
        denied_open,
        Err(vos::node::V2RaftNodeRegistrationError::Open(
            LocalRootTreeOpenErrorV2::InstallRejected(AccumulationRejectionV2::Unauthorized),
        )),
    ));
    assert!(!promoted.load(Ordering::Relaxed));
    assert!(denied.collect().is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn same_actor_storage_reads_observe_earlier_inline_writes() {
    let (config, template) = attested_root_fixture(ConsistencyModeV2::Local, 0x3a);
    let mut service =
        LocalRootTreeServiceV2::open(config, FailableCommittedImages::default()).unwrap();

    let mut spawn_arguments = vec![vos::value::TAG_DYNAMIC];
    spawn_arguments.extend_from_slice(
        &Msg::new("spawn_child")
            .with("name", "child")
            .with("initial", 0u32)
            .encode(),
    );
    let spawned = service
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([0x3b; 32]),
            workflow_step: 0,
            logical_timeslot: 12,
            target: template.target,
            method: "spawn_child".into(),
            arguments: spawn_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the child is committed before inline storage calls");
    assert_eq!(
        spawned
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::Bool(true))
    );

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("call_child_storage_twice").encode());
    let committed = service
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([0x3c; 32]),
            workflow_step: 0,
            logical_timeslot: 13,
            target: template.target,
            method: "call_child_storage_twice".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the root invokes the same child twice in one Refine slice");
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(2)),
        "the second read observes the first accepted write, not the base row"
    );
}

#[test]
fn attested_root_driver_recovers_queued_and_committed_proofs_across_restart() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Local, 0x41);
    let mut service =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("the attested root installs");
    assert!(
        !service
            .admit_ingress(&request)
            .expect("attested ingress is durable before proof production")
    );

    let mut backend = service.into_backend();
    backend.fail_next_proof_commit = true;
    let mut service = LocalRootTreeServiceV2::open(config.clone(), backend)
        .expect("queued attested ingress reopens from the durable image");
    let before_invalid_proof = service.store().snapshot();
    assert!(matches!(
        service.invoke_admitted_attested(request.invocation, &mut MismatchedTraceProofProducer),
        Err(AttestedRootTreeInvokeErrorV2::InvalidProducedProof)
    ));
    assert_eq!(
        service.store().snapshot(),
        before_invalid_proof,
        "a proof for another trace cannot mutate the admitted workflow"
    );

    let mut producer = CanonicalTestProofProducer {
        proof: b"durable-root-attestation-proof".to_vec(),
        calls: 0,
    };
    let before_failed_cas = service.store().snapshot();
    assert!(matches!(
        service.invoke_admitted_attested(request.invocation, &mut producer),
        Err(AttestedRootTreeInvokeErrorV2::ProofUnavailable)
    ));
    assert_eq!(
        service.store().snapshot(),
        before_failed_cas,
        "proof-side-CAS failure leaves the admitted service image retryable"
    );
    let committed = service
        .invoke_admitted_attested(request.invocation, &mut producer)
        .expect("the queued invocation proves and commits");
    assert!(!committed.duplicate);
    assert_eq!(producer.calls, 2);
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(7))
    );
    let proof = committed
        .published
        .proof
        .as_ref()
        .expect("the publication commits the proof");
    assert_eq!(
        committed
            .published
            .attestation
            .as_ref()
            .map(|attestation| &attestation.proof),
        Some(proof)
    );
    assert_eq!(
        service
            .attestation_proof(&proof.proof_blob)
            .map(|artifact| artifact.bytes),
        Some(b"durable-root-attestation-proof".to_vec())
    );

    let backend = service.into_backend();
    let mut service = LocalRootTreeServiceV2::open(config, backend)
        .expect("the proof side-CAS and publication reopen together");
    assert_eq!(
        service
            .attestation_proof(&proof.proof_blob)
            .map(|artifact| artifact.bytes),
        Some(b"durable-root-attestation-proof".to_vec())
    );
    let retry = service
        .invoke_admitted_attested(request.invocation, &mut producer)
        .expect("an invocation-only retry reattaches the committed attestation");
    assert!(retry.duplicate);
    assert_eq!(retry.refine_gas_used, 0);
    assert_eq!(retry.accumulate_gas_used, 0);
    assert_eq!(producer.calls, 2, "retry never re-enters the producer");
}

#[test]
fn raft_attested_root_orders_only_the_final_proved_apply() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Raft, 0x51);
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-attested-root-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeServiceV2::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .expect("the Raft attested root installs");
    let mut producer = CanonicalTestProofProducer {
        proof: b"raft-root-attestation-proof".to_vec(),
        calls: 0,
    };
    let committed = service
        .invoke_attested(request.clone(), &mut producer)
        .expect("the final proof-bearing Apply commits through Raft");
    assert!(!committed.duplicate);
    let proof = committed.published.proof.clone().unwrap();
    let backend = service.into_backend();

    let mut log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(
        log.applied_index().unwrap(),
        3,
        "genesis, ingress admission, and the final proved Apply are the only ordered requests"
    );
    assert!(log.committed_after(3).unwrap().entries.is_empty());
    drop(log);

    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut service = LocalRootTreeServiceV2::open_raft(config, backend, log)
        .expect("the Raft root reopens at the proof-bearing apply cursor");
    assert_eq!(
        service
            .attestation_proof(&proof.proof_blob)
            .map(|artifact| artifact.bytes),
        Some(b"raft-root-attestation-proof".to_vec())
    );
    let retry = service
        .invoke_admitted_attested(request.invocation, &mut producer)
        .expect("the committed Raft attestation reattaches after the opening barrier");
    assert!(retry.duplicate);
    assert_eq!(retry.refine_gas_used, 0);
    assert_eq!(retry.accumulate_gas_used, 0);
    assert_eq!(producer.calls, 1);
    drop(service);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn signed_task_dependencies_install_and_survive_durable_reopen() {
    let task_pvm = grey_transpiler::assembler::Assembler::new().build();
    let (config, binding) =
        signed_task_dependency_config(task_pvm.clone(), ConsistencyModeV2::Local);
    let service = LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
        .expect("install root and its signed Task program");
    assert_eq!(
        service.store().program(binding.program),
        Some(task_pvm.as_slice())
    );

    let backend = service.into_backend();
    let reopened = LocalRootTreeServiceV2::open(config.clone(), backend)
        .expect("reopen from the committed service image");
    assert_eq!(
        reopened.store().program(binding.program),
        Some(task_pvm.as_slice())
    );

    let mut backend = reopened.into_backend();
    let image = backend.image.take().expect("committed service image");
    let missing_dependency = snapshot_without_program(&image, binding.program);
    LocalJamStoreSnapshotV2::decode(&missing_dependency)
        .expect("the dependency-free snapshot remains canonically encoded");
    backend.image = Some(missing_dependency);
    assert!(matches!(
        LocalRootTreeServiceV2::open(config, backend),
        Err(LocalRootTreeOpenErrorV2::MissingInstalledProgram(program))
            if program == binding.program
    ));
}

#[test]
fn signed_task_refine_redacts_actor_memory_and_reopens_local_producer_sidecar() {
    let task_elf = tally_elf();
    let (witness_address, witness_capacity) =
        vos::zk::witness_symbol(&task_elf).expect("tally exports its witness window");
    let task_pvm = grey_transpiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyModeV2::Local,
    );
    let actor = config.root_actor;
    let tag = [0xD6; 32];
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("run_provable_task")
            .with("task_hash", binding.task.0.to_vec())
            .with("tag", tag.to_vec())
            .with("n", 9u64)
            .encode(),
    );
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([0xD7; 32]),
        workflow_step: 0,
        logical_timeslot: 9,
        target: actor,
        method: "run_provable_task".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("signed Local Task root installs");
    assert!(!service.admit_ingress(&request).unwrap());
    let admitted_snapshot = service.store().snapshot_bytes();
    assert!(
        !admitted_snapshot
            .windows(tag.len())
            .any(|window| window == tag),
        "private argument constituents must not enter the admitted service image",
    );
    let backend = service.into_backend();
    assert_eq!(
        backend.private_ingresses.get(&request.invocation),
        Some(&request.arguments),
        "the pending plaintext belongs only to the durable host-private sidecar",
    );
    let mut service = LocalRootTreeServiceV2::open(config.clone(), backend)
        .expect("private ingress rehydrates after a durable reopen");
    let mut divergent = request.clone();
    divergent.method = "different_method".into();
    assert!(matches!(
        service.admit_ingress(&divergent),
        Err(LocalRootTreeInvokeErrorV2::Rejected(
            AccumulationRejectionV2::DivergentDuplicate
        ))
    ));
    assert_eq!(
        service
            .store()
            .backend()
            .private_ingresses
            .get(&request.invocation),
        Some(&request.arguments),
        "a divergent retry cannot retire the admitted invocation's private input",
    );
    let mut prepared = LocalWorkSchedulerV2::prepare(service.store(), request.clone()).unwrap();
    prepared.work.private_arguments = Some(BlobRefV2::of_bytes(&request.arguments));
    let physical = ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .unwrap();
    let ordinary = physical
        .refine_actor_tree_with_backend(
            &prepared.work.encode(),
            &prepared.imports,
            TEST_GAS_SCHEDULE.refine,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .expect("recompiler executes signed Task Refine");
    let traced = physical
        .refine_actor_tree_traced(
            &prepared.work.encode(),
            &prepared.imports,
            TEST_GAS_SCHEDULE.refine,
            &NoRefineProtocolHostV2,
        )
        .expect("interpreter traces the exact nested Task execution");
    assert_eq!(traced.bytes, ordinary.bytes);
    assert_eq!(traced.gas_used, ordinary.gas_used);
    assert_eq!(traced.exported_blobs, ordinary.exported_blobs);
    assert_eq!(traced.producer_records, ordinary.producer_records);
    let trace = traced.trace.expect("traced Refine returns a commitment");
    assert!(trace.instruction_count > 0);
    assert!(
        trace.code_hashes.len() >= 3,
        "service, parent actor, and signed Task programs all enter the exact trace",
    );
    assert_eq!(service.producer_record(actor, &tag), None);
    service.store_mut().backend_mut().fail_next_record_commit = true;
    assert!(matches!(
        service.invoke_admitted(request.invocation),
        Err(LocalRootTreeInvokeErrorV2::ProducerRecordUnavailable)
    ));
    assert_eq!(service.producer_record(actor, &tag), None);
    service.store_mut().backend_mut().fail_next_private_delete = true;
    let committed = service
        .invoke_admitted(request.invocation)
        .expect("post-commit cleanup debt cannot rewrite an accepted invocation as failed");
    assert!(!committed.duplicate);
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U64(9)),
    );
    assert_eq!(
        service.store().private_ingress_retirement_debt(),
        vec![request.invocation],
    );
    assert_eq!(service.store().backend().private_delete_attempts, 1);
    let record_bytes = service
        .producer_record(actor, &tag)
        .expect("producer-private record committed before Apply proposal");
    let record = vos::provable::ProofRecordEntry::decode(&record_bytes)
        .expect("sidecar stores a canonical record");
    assert_eq!(record.input.task_hash, binding.task.0);
    assert_eq!(record.record.task_hash, binding.task.0);
    assert!(record.record.io_consistent());
    assert!(
        !service
            .store()
            .snapshot_bytes()
            .windows(tag.len())
            .any(|window| window == tag),
        "private argument constituents must remain absent after execution",
    );
    assert!(
        !service
            .store()
            .snapshot_bytes()
            .windows(record_bytes.len())
            .any(|window| window == record_bytes),
        "producer witness must not enter the recoverable service image",
    );
    service.store_mut().backend_mut().fail_next_private_delete = true;
    let recovered = service
        .invoke_admitted(request.invocation)
        .expect("invocation-only recovery remains successful while retrying cleanup debt");
    assert!(recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    assert_eq!(service.store().backend().private_delete_attempts, 2);
    assert_eq!(
        service.store().private_ingress_retirement_debt(),
        vec![request.invocation],
    );
    let mut backend = service.into_backend();
    assert_eq!(
        backend.private_ingresses.get(&request.invocation),
        Some(&request.arguments),
        "cleanup debt leaves the artifact available for startup reconciliation",
    );
    backend.private_ingresses.insert(
        InvocationId([0xD8; 32]),
        b"crash before guest admission".to_vec(),
    );
    let mut reopened = LocalRootTreeServiceV2::open(config, backend)
        .expect("startup retires terminal and pre-admission private sidecars");
    assert!(reopened.store().backend().private_ingresses.is_empty());
    let recovered = reopened
        .invoke_admitted(request.invocation)
        .expect("invocation-only recovery needs no retired private preimage");
    assert!(recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    assert!(
        reopened
            .store()
            .private_ingress_retirement_debt()
            .is_empty()
    );
    assert_eq!(
        recovered
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U64(9)),
    );
    assert_eq!(reopened.producer_record(actor, &tag), Some(record_bytes));
    assert!(reopened.prune_producer_record(actor, &tag));
    assert_eq!(reopened.producer_record(actor, &tag), None);
}

#[test]
fn deferred_provable_task_is_rejected_before_apply_proposal() {
    let task_elf = tally_elf();
    let (witness_address, witness_capacity) =
        vos::zk::witness_symbol(&task_elf).expect("tally exports its witness window");
    let task_pvm = grey_transpiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyModeV2::Local,
    );
    let actor = config.root_actor;
    let tag = [0xD8; 32];
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("defer_provable_task")
            .with("task_hash", binding.task.0.to_vec())
            .with("tag", tag.to_vec())
            .encode(),
    );
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([0xD9; 32]),
        workflow_step: 0,
        logical_timeslot: 10,
        target: actor,
        method: "defer_provable_task".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeServiceV2::open(config, FailableCommittedImages::default()).unwrap();
    assert!(matches!(
        service.invoke(request),
        Err(LocalRootTreeInvokeErrorV2::Service(ServiceDispatchError::Pvm(
            ServicePvmErrorV2::RefineHostRejected(slot)
        ))) if slot == vos::abi::hostcall::ACTOR_EFFECT_EXPORT as u8
    ));
    assert_eq!(service.producer_record(actor, &tag), None);
    let backend = service.into_backend();
    assert_eq!(backend.producer_records.len(), 0);
}

#[test]
fn completed_recorded_task_cannot_export_parent_checkpoint_memory() {
    let task_elf = tally_elf();
    let (witness_address, witness_capacity) =
        vos::zk::witness_symbol(&task_elf).expect("tally exports its witness window");
    let task_pvm = grey_transpiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyModeV2::Local,
    );
    let actor = config.root_actor;
    let tag = [0xDA; 32];
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("run_provable_task_then_yield")
            .with("task_hash", binding.task.0.to_vec())
            .with("tag", tag.to_vec())
            .encode(),
    );
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([0xDB; 32]),
        workflow_step: 0,
        logical_timeslot: 11,
        target: actor,
        method: "run_provable_task_then_yield".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeServiceV2::open(config, FailableCommittedImages::default()).unwrap();
    assert!(matches!(
        service.invoke(request),
        Err(LocalRootTreeInvokeErrorV2::Service(ServiceDispatchError::Pvm(
            ServicePvmErrorV2::RefineHostRejected(slot)
        ))) if slot == vos::abi::hostcall::SUSPEND as u8
    ));
    assert_eq!(service.producer_record(actor, &tag), None);
    assert!(service.store().pending_publications().unwrap().is_empty());
}

#[test]
fn producer_record_capture_is_count_bounded_per_slice() {
    let task_elf = tally_elf();
    let (witness_address, witness_capacity) =
        vos::zk::witness_symbol(&task_elf).expect("tally exports its witness window");
    let task_pvm = grey_transpiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyModeV2::Local,
    );
    let actor = config.root_actor;
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("overproduce_provable_tasks")
            .with("task_hash", binding.task.0.to_vec())
            .encode(),
    );
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([0xDD; 32]),
        workflow_step: 0,
        logical_timeslot: 12,
        target: actor,
        method: "overproduce_provable_tasks".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeServiceV2::open(config, FailableCommittedImages::default()).unwrap();
    assert!(matches!(
        service.invoke(request),
        Err(LocalRootTreeInvokeErrorV2::Service(ServiceDispatchError::Pvm(
            ServicePvmErrorV2::RefineHostRejected(slot)
        ))) if slot == vos::abi::hostcall::INVOKE as u8
    ));
    assert!(
        (0u8..17).all(|ordinal| {
            let mut tag = [0xDC; 32];
            tag[31] = ordinal;
            service.producer_record(actor, &tag).is_none()
        }),
        "a rejected over-limit slice must persist no partial record batch",
    );
}

#[test]
fn raft_task_dependencies_use_private_ingress_while_crdt_remains_rejected() {
    let task_pvm = vec![0xa5; 4096];
    let (config, _) = signed_task_dependency_config(task_pvm.clone(), ConsistencyModeV2::Raft);
    assert!(config.validate().is_ok());
    let (config, _) = signed_task_dependency_actor_config(
        &crdt_counter_v2_elf(),
        task_pvm,
        0x1_0000,
        4096,
        ConsistencyModeV2::Crdt,
    );
    assert_eq!(
        config.validate(),
        Err(LocalRootTreeConfigErrorV2::ReplicatedPrivateTaskUnsupported)
    );
}

#[test]
fn single_voter_raft_task_ingress_is_private_durable_and_retryable() {
    let task_pvm = grey_transpiler::assembler::Assembler::new().build();
    let (config, _) = signed_task_dependency_config(task_pvm, ConsistencyModeV2::Raft);
    let actor = config.root_actor;
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-raft-private-ingress-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeServiceV2::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .expect("single-voter Raft Task root installs");
    let private_sentinel = [0xE1; 32];
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("start")
            .with("private_sentinel", private_sentinel.to_vec())
            .encode(),
    );
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([0xDE; 32]),
        workflow_step: 0,
        logical_timeslot: 13,
        target: actor,
        method: "start".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let committed = service
        .invoke(request.clone())
        .expect("single voter durably stages before admitting");
    assert!(!committed.duplicate);
    let ingress_record = service
        .store()
        .local_store()
        .ingress_record(request.invocation)
        .unwrap()
        .expect("guest retains the redacted ingress identity");
    assert!(ingress_record.consumed);
    assert!(ingress_record.ingress.arguments.is_empty());
    assert_eq!(
        ingress_record.ingress.private_arguments,
        Some(BlobRefV2::of_bytes(&request.arguments)),
    );
    assert!(service.store().backend().private_ingresses.is_empty());
    assert!(
        !service
            .store()
            .snapshot_bytes()
            .windows(private_sentinel.len())
            .any(|window| window == private_sentinel),
        "private arguments never enter the replicated service image",
    );

    let backend = service.into_backend();
    let committed_log_bytes = std::fs::read(&log_path).unwrap();
    assert!(
        !committed_log_bytes
            .windows(private_sentinel.len())
            .any(|window| window == private_sentinel),
        "private argument constituents never enter the ordered Raft log",
    );
    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut reopened = LocalRootTreeServiceV2::open_raft(config, backend, log)
        .expect("Raft Task root reopens without a retired preimage");
    let retry = reopened
        .invoke(request)
        .expect("exact committed retry needs no sidecar recreation");
    assert!(retry.duplicate);
    assert_eq!(retry.refine_gas_used, 0);
    assert_eq!(retry.accumulate_gas_used, 0);
    assert!(reopened.store().backend().private_ingresses.is_empty());
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

fn clerk_operator_request(
    service: &mut LocalRootTreeServiceV2<FailableCommittedImages>,
    actor: ActorId,
    invocation: InvocationId,
    logical_timeslot: u64,
    message: Msg,
) -> LocalWorkRequestV2 {
    let method = message.name.clone();
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&message.encode());
    let origin = Origin::Member(SubjectId([0x63; 32]));
    let mut request = LocalWorkRequestV2 {
        invocation,
        workflow_step: 0,
        logical_timeslot,
        target: actor,
        method: method.clone(),
        arguments: arguments.clone(),
        origin,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let policy = service
        .root_method_policy(&method)
        .unwrap()
        .expect("Clerk package carries the requested method policy");
    assert_eq!(
        policy.actor_role,
        Some(clerk_ledger::ClerkLedgerRole::Operator as u8)
    );
    let private_arguments = BlobRefV2::of_bytes(&arguments);
    let mut scoped = LocalWorkSchedulerV2::prepare(service.store().local_store(), request.clone())
        .unwrap()
        .work;
    scoped.private_arguments = Some(private_arguments.clone());
    let credential = RoleCredentialV2 {
        holder: origin,
        scope: scoped.authorization_scope(),
        space_role: None,
        actor_role: Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
        authenticator: b"test authority over exact Clerk work scope".to_vec(),
    };
    request.authorization = credential.disclosed_evidence(policy.policy);
    let mut authorized =
        LocalWorkSchedulerV2::prepare(service.store().local_store(), request.clone())
            .unwrap()
            .work;
    authorized.private_arguments = Some(private_arguments);
    let verification = RoleCredentialVerificationRequestV2::for_work(&authorized)
        .expect("disclosed Clerk operator credential is canonical");
    service
        .store_mut()
        .local_store_mut()
        .allow_role_credential(&verification);
    request
}

fn clerk_status(committed: &vos::v2::CommittedRootTreeSliceV2) -> clerk_ledger::Status {
    let reply = committed
        .published
        .reply
        .as_ref()
        .expect("Clerk handler publishes one direct reply");
    let Value::Bytes(bytes) = Value::try_decode(&reply.result).expect("Clerk reply is a Value")
    else {
        panic!("Clerk status is encoded as Value::Bytes")
    };
    vos::rkyv::from_bytes::<clerk_ledger::Status, vos::rkyv::rancor::Error>(&bytes)
        .expect("Clerk status archive decodes")
}

#[test]
fn canonical_clerk_package_executes_a_private_provable_transfer_through_raft() {
    use cipher_clerk::conventions::{BankCode, Iso4217};
    use cipher_clerk::crypto::{Amount, Blinding, Keypair};
    use cipher_clerk::ids::JournalId;
    use cipher_clerk::kernel::CreateAccount as CcCreateAccount;
    use cipher_clerk::types::{Account, Layer, Transfer};

    let package = canonical_clerk_package();
    let binding = package.task_dependencies[0].binding.clone();
    assert_eq!(binding.task.0, clerk_ledger::CLERK_APPLY_TASK_HASH);
    let actor_name = vos::metadata::decode(&package.schemas)
        .expect("Clerk package carries generated actor metadata")
        .actor_name;
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([121; 32]),
            root_service: RootServiceId([122; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: ActorId([123; 32]),
        actor_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([124; 32]),
            authenticator: vec![125],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let actor = config.root_actor;
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-raft-clerk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeServiceV2::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .expect("the signed Clerk Raft root installs with its Task dependency");

    let registrar = Keypair::generate();
    let journal = JournalId::random();
    let bootstrap = clerk_operator_request(
        &mut service,
        actor,
        InvocationId([0x64; 32]),
        1,
        Msg::new("bootstrap")
            .with("journal_id", journal.0.to_vec())
            .with("registrar_pubkey", registrar.public.0.to_vec())
            .with("code", 1u32),
    );
    assert_eq!(
        clerk_status(
            &service
                .invoke(bootstrap)
                .expect("bootstrap commits through Raft")
        ),
        clerk_ledger::Status::Ok,
    );

    let alice_key = Keypair::generate();
    let alice = Account::asset(journal, alice_key.public, Iso4217::USD, BankCode::Checking);
    let pool = Account::asset(
        journal,
        Keypair::generate().public,
        Iso4217::USD,
        BankCode::Vault,
    );
    for (ordinal, account) in [alice.clone(), pool.clone()].into_iter().enumerate() {
        let create = CcCreateAccount::signed(account, &registrar.secret);
        let create_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create)
            .unwrap()
            .to_vec();
        let request = clerk_operator_request(
            &mut service,
            actor,
            InvocationId([0x65 + ordinal as u8; 32]),
            2 + ordinal as u64,
            Msg::new("create_account")
                .with("create_account_bytes", create_bytes)
                .with("batch_seed_timestamp", 10u64 + ordinal as u64),
        );
        assert_eq!(
            clerk_status(&service.invoke(request).expect("account creation commits")),
            clerk_ledger::Status::Ok,
        );
    }

    let blinding = Blinding::from_bytes([0x06; 32]).expect("test blinding is canonical");
    let amount = Amount::commit(100, &blinding);
    let transfer = Transfer::builder(journal)
        .debit(&alice, Layer::Settled, amount)
        .credit(&pool, Layer::Settled, amount)
        .signed_with(&[(&alice, &alice_key.secret)]);
    let transfer_id = transfer.id.0;
    let transfer_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&transfer)
        .unwrap()
        .to_vec();
    let openings = vec![clerk_ledger::Opening {
        amount,
        value: 100,
        blinding,
    }];
    let openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings)
        .unwrap()
        .to_vec();
    let apply = clerk_operator_request(
        &mut service,
        actor,
        InvocationId([0x67; 32]),
        4,
        Msg::new("apply_transfer_provable")
            .with("transfer_bytes", transfer_bytes)
            .with("openings_bytes", openings_bytes.clone())
            .with("batch_seed_timestamp", 20u64),
    );
    let committed = service
        .invoke(apply.clone())
        .expect("the real Clerk Task and live ledger mutation commit through Raft");
    assert_eq!(clerk_status(&committed), clerk_ledger::Status::Ok);
    let tag = clerk_ledger::transfer_record_tag(&transfer_id);
    let record_bytes = service
        .producer_record(actor, &tag)
        .expect("the producing replica durably captures the proof record");
    let record = vos::provable::ProofRecordEntry::decode(&record_bytes)
        .expect("the captured Clerk record is canonical");
    assert_eq!(record.record.task_hash, clerk_ledger::CLERK_APPLY_TASK_HASH);
    assert!(record.record.io_consistent());

    let retry = service
        .invoke(apply.clone())
        .expect("an exact Clerk retry reattaches without rerunning the Task");
    assert!(retry.duplicate);
    assert_eq!(retry.refine_gas_used, 0);
    assert_eq!(retry.accumulate_gas_used, 0);

    let backend = service.into_backend();
    let image = backend
        .image
        .as_ref()
        .expect("the Clerk service image is durable");
    assert!(
        !image
            .windows(openings_bytes.len())
            .any(|window| window == openings_bytes),
        "private commitment openings never enter the replicated service image",
    );
    let raft_bytes = std::fs::read(&log_path).unwrap();
    assert!(
        !raft_bytes
            .windows(openings_bytes.len())
            .any(|window| window == openings_bytes),
        "private commitment openings never enter the ordered Raft log",
    );
    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut reopened = LocalRootTreeServiceV2::open_raft(config, backend, log)
        .expect("the Clerk root and producer sidecar reopen together");
    assert_eq!(reopened.producer_record(actor, &tag), Some(record_bytes));
    let recovered = reopened
        .invoke(apply)
        .expect("the committed Clerk result recovers after restart");
    assert!(recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

fn signed_task_dependency_config(
    task_pvm: Vec<u8>,
    consistency: ConsistencyModeV2,
) -> (LocalRootTreeConfigV2, TaskDependencyV2) {
    signed_task_dependency_actor_config(&greeter_elf(), task_pvm, 0x1_0000, 4096, consistency)
}

fn signed_task_dependency_actor_config(
    actor_elf: &[u8],
    task_pvm: Vec<u8>,
    witness_address: u32,
    witness_capacity: u32,
    consistency: ConsistencyModeV2,
) -> (LocalRootTreeConfigV2, TaskDependencyV2) {
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (mut package, actor_name) = signed_test_package(actor_elf, &signer);
    let binding = TaskDependencyV2 {
        task: Hash(vos::provable::task_blob_hash(&task_pvm)),
        program: ProgramId::of_pvm(&task_pvm),
        witness_address,
        witness_capacity,
    };
    package.task_dependencies = vec![PackageTaskDependencyV2 {
        binding: binding.clone(),
        pvm: task_pvm.clone(),
    }];
    let mut policies = PackageRolePoliciesV2::decode(&package.role_policies).unwrap();
    policies.task_dependencies = vec![binding.clone()];
    package.role_policies = policies.encode();
    package.manifest.role_policies_hash = artifact_hash(b"role-policies", &package.role_policies);
    package.manifest.task_dependencies_hash =
        vos::v2::task_dependencies_hash(&package.task_dependencies);
    package.deployment_signature.signature = signer
        .sign(&package.signing_message())
        .expect("sign package carrying the Task dependency");
    package.validate().expect("Task package is canonical");

    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([121; 32]),
            root_service: RootServiceId([122; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: ActorId([123; 32]),
        actor_name,
        consistency,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([124; 32]),
            authenticator: vec![125],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    (config, binding)
}

fn snapshot_without_program(snapshot: &[u8], removed: ProgramId) -> Vec<u8> {
    fn u32_at(bytes: &[u8], position: &mut usize) -> u32 {
        let value = u32::from_le_bytes(bytes[*position..*position + 4].try_into().unwrap());
        *position += 4;
        value
    }

    fn skip_bytes(bytes: &[u8], position: &mut usize) {
        let len = u32_at(bytes, position) as usize;
        *position += len;
    }

    let mut position = 4 + 2 + 8;
    let rows = u32_at(snapshot, &mut position);
    for _ in 0..rows {
        skip_bytes(snapshot, &mut position);
        skip_bytes(snapshot, &mut position);
    }
    let blobs = u32_at(snapshot, &mut position);
    for _ in 0..blobs {
        position += 32;
        skip_bytes(snapshot, &mut position);
    }
    let program_count_offset = position;
    let programs = u32_at(snapshot, &mut position);
    let mut encoded = snapshot[..program_count_offset].to_vec();
    encoded.extend_from_slice(&(programs - 1).to_le_bytes());
    let mut found = false;
    for _ in 0..programs {
        let entry_start = position;
        let program = ProgramId(snapshot[position..position + 32].try_into().unwrap());
        position += 32;
        skip_bytes(snapshot, &mut position);
        if program == removed {
            found = true;
        } else {
            encoded.extend_from_slice(&snapshot[entry_start..position]);
        }
    }
    assert!(found, "snapshot contains the Task dependency program");
    encoded.extend_from_slice(&snapshot[position..]);
    encoded
}

#[test]
fn durable_root_tree_host_restores_guest_state_and_pending_publications() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([91; 32]),
        root_service: RootServiceId([92; 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let actor = ActorId([93; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: identity,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([94; 32]),
            authenticator: vec![95],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let mut replicated_config = config.clone();
    replicated_config.consistency = ConsistencyModeV2::Raft;
    assert!(replicated_config.validate().is_ok());
    assert!(matches!(
        LocalRootTreeServiceV2::open(replicated_config, FailableCommittedImages::default()),
        Err(vos::v2::LocalRootTreeOpenErrorV2::InvalidConfig(
            LocalRootTreeConfigErrorV2::ReplicationDriverRequired
        ))
    ));
    let mut forged_config = config.clone();
    forged_config.package.deployment_signature.signature[0] ^= 0x80;
    assert_eq!(
        forged_config.validate(),
        Err(LocalRootTreeConfigErrorV2::InvalidPackageSignature),
        "installation authority must be cryptographically authenticated"
    );

    let mut wrong_gas_schedule = config.clone();
    wrong_gas_schedule.service.gas_schedule.accumulate -= 1;
    assert_eq!(
        wrong_gas_schedule.validate(),
        Err(LocalRootTreeConfigErrorV2::WrongGasSchedule),
        "the declared service identity must match the executing host limits"
    );

    let mut invalid_layout = config.clone();
    let parsed = javm::program::parse_blob(&invalid_layout.package.actor_pvm)
        .expect("canonical actor PVM parses");
    let mut caps = parsed.caps.clone();
    caps.push(javm::program::CapManifestEntry {
        cap_index: vos::v2::ACTOR_CALLABLE_BASE_SLOT,
        cap_type: javm::program::CapEntryType::Data,
        base_page: 0,
        page_count: 0,
        init_access: javm::cap::Access::RW,
        data_offset: 0,
        data_len: 0,
    });
    invalid_layout.package.actor_pvm = javm::program::build_blob(
        parsed.header.memory_pages,
        parsed.header.invoke_cap,
        parsed.header.stack_top,
        &caps,
        parsed.data_section,
    );
    invalid_layout.package.manifest.actor_program =
        ProgramId::of_pvm(&invalid_layout.package.actor_pvm);
    invalid_layout.package.deployment_signature.signature = signer
        .sign(&invalid_layout.package.signing_message())
        .expect("sign invalid-layout package for a focused layout check");
    invalid_layout.service.deployment = invalid_layout.package.deployment_id();
    assert_eq!(
        invalid_layout.validate(),
        Err(LocalRootTreeConfigErrorV2::InvalidActorProgramLayout),
        "reserved scheduler capabilities must fail before installation"
    );

    let mut service =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("fresh service installs through physical Accumulate");
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([96; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: actor,
        method: "start".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut unsupported_attested = request.clone();
    unsupported_attested.invocation = InvocationId([95; 32]);
    unsupported_attested.proof_requested = true;
    let before_attested = service.store().snapshot();
    assert!(matches!(
        service.invoke(unsupported_attested),
        Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired)
    ));
    assert_eq!(
        service.store().snapshot(),
        before_attested,
        "unsupported attested work must be rejected before ingress admission"
    );
    assert!(
        !service
            .admit_ingress(&request)
            .expect("direct ingress commits before Refine")
    );
    let queued = service
        .store()
        .ingress_record(request.invocation)
        .unwrap()
        .expect("guest owns the admitted request");
    assert!(!queued.consumed);
    assert_eq!(queued.ingress.logical_timeslot, request.logical_timeslot);
    let first = service
        .invoke_admitted(request.invocation)
        .expect("slice consumes ingress through physical Accumulate");
    assert!(
        service
            .store()
            .ingress_record(request.invocation)
            .unwrap()
            .expect("consumed ingress remains a durable retry guard")
            .consumed
    );
    let committed_header = service.store().header().unwrap().unwrap();
    let committed_checkpoint = vos::v2::WorkflowCheckpointV2::decode(
        &service
            .store()
            .state_row(
                committed_header.service_root,
                &StateKeyV2::Workflow(request.invocation),
            )
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let committed_dedup = vos::v2::DedupRecordV2::decode(
        service
            .store()
            .row(&vos::v2::dedup_storage_key(committed_checkpoint.input))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        committed_checkpoint.transition_hash, committed_dedup.transition_commitment,
        "linear retry recovery must bind the workflow checkpoint to its dedup record"
    );
    assert_eq!(
        first.published.reply.as_ref().map(|reply| &reply.result),
        Some(&Value::Unit.encode())
    );
    let publication = first
        .publication
        .clone()
        .expect("committed reply remains recoverable until acknowledgement");
    assert_eq!(service.store().header().unwrap().unwrap().revision, 1);
    assert_eq!(
        service
            .store()
            .header()
            .unwrap()
            .unwrap()
            .admission_timeslot_high_water,
        1
    );

    let backend = service.into_backend();
    let mut restarted = LocalRootTreeServiceV2::open(config.clone(), backend)
        .expect("exact service image restores without reinstalling");
    assert_eq!(restarted.store().header().unwrap().unwrap().revision, 1);
    assert_eq!(
        restarted
            .store()
            .header()
            .unwrap()
            .unwrap()
            .admission_timeslot_high_water,
        1
    );
    assert_eq!(
        restarted.pending_publications().unwrap(),
        vec![publication.clone()]
    );
    let mut retry = request.clone();
    retry.logical_timeslot = 9_999;
    let recovered = restarted
        .invoke(retry)
        .expect("lost committed result reattaches after restart");
    assert!(recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    assert_eq!(recovered.input, first.input);
    assert_eq!(recovered.receipt, first.receipt);
    assert_eq!(recovered.published, first.published);
    assert_eq!(recovered.publication, Some(publication.clone()));
    assert_eq!(
        restarted
            .store()
            .header()
            .unwrap()
            .unwrap()
            .admission_timeslot_high_water,
        1,
        "a duplicate retry retains the originally committed admission slot"
    );

    let mut divergent = request;
    divergent.arguments.push(0);
    assert!(matches!(
        restarted.invoke(divergent),
        Err(LocalRootTreeInvokeErrorV2::DivergentInvocation)
    ));
    assert!(!restarted.acknowledge_publication(&publication).unwrap());

    let backend = restarted.into_backend();
    let restarted = LocalRootTreeServiceV2::open(config, backend)
        .expect("acknowledged image restores through the same service identity");
    assert!(restarted.pending_publications().unwrap().is_empty());
    assert_eq!(restarted.store().header().unwrap().unwrap().revision, 1);
}

#[test]
fn canonical_space_authority_authorizes_a_physical_target_and_exact_retry() {
    let actor_elf = space_authority_elf();
    let package_signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &package_signer);
    let authority_actor = ActorId([184; 32]);
    let service = ServiceIdentityV2 {
        space: vos::v2::SpaceId([183; 32]),
        root_service: RootServiceId([185; 32]),
        deployment: package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let root = libp2p::identity::Keypair::generate_ed25519();
    let root_peer_id = libp2p::PeerId::from(root.public()).to_bytes();
    let authority_replication_id = [0xa6; 32];
    let initial_state =
        space_authority::initial_state(service.space, root_peer_id, authority_replication_id)
            .expect("the authority genesis pins an Ed25519 space root and replication incarnation");
    let binding = RoleAuthorityBindingV2 {
        service: service.clone(),
        actor: authority_actor,
    };
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service,
        root_actor: authority_actor,
        actor_name,
        consistency: ConsistencyModeV2::Local,
        initial_state,
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([186; 32]),
            authenticator: vec![187],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let mut authority = LocalRootTreeServiceV2::open(config, FailableCommittedImages::default())
        .expect("the canonical authority installs through guest Accumulate");

    let holder = Origin::Member(SubjectId([188; 32]));
    let grant = RoleAuthorityMutationV2::Grant {
        space: binding.service.space,
        holder,
        role: vos::SpaceRole::Developer,
        epoch: 1,
    };
    let signature = root
        .sign(&grant.encode())
        .expect("the space root signs the canonical mutation wire");
    let mut grant_arguments = vec![vos::value::TAG_DYNAMIC];
    grant_arguments.extend_from_slice(
        &Msg::new("mutate_role")
            .with("mutation", grant.encode())
            .with("signature", signature)
            .encode(),
    );
    let grant_result = authority
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([189; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: authority_actor,
            method: "mutate_role".into(),
            arguments: grant_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the signed grant commits before the authority decision");
    let expected_grant_reply = Value::Bool(true).encode();
    assert_eq!(
        grant_result
            .published
            .reply
            .as_ref()
            .map(|reply| reply.result.as_slice()),
        Some(expected_grant_reply.as_slice())
    );

    let token = libp2p::identity::Keypair::generate_ed25519();
    let invited = libp2p::identity::Keypair::generate_ed25519();
    let invited_peer_id = libp2p::PeerId::from(invited.public()).to_bytes();
    let token_pub = vos::registry::ed25519_pubkey_from_peer_id(
        &libp2p::PeerId::from(token.public()).to_bytes(),
    )
    .expect("the invite token is Ed25519");
    let expires_at = 1_000u64;
    let invite = vos::registry::invite_signed_bytes(
        &binding.service.space.0,
        vos::SpaceRole::Member.as_u8(),
        expires_at,
        &token_pub,
        Some(&authority_replication_id),
    );
    let redeem =
        vos::registry::canonical_op_bytes("redeem_invite", &[&token_pub, &invited_peer_id]);
    let redemption = RoleAuthorityInviteRedemptionV2 {
        space: binding.service.space,
        authority_replication_id,
        token_pub,
        role: vos::SpaceRole::Member,
        expires_at,
        admin_peer_id: libp2p::PeerId::from(root.public()).to_bytes(),
        admin_signature: root.sign(&invite).unwrap().try_into().unwrap(),
        holder_peer_id: invited_peer_id.clone(),
        redeem_signature: token.sign(&redeem).unwrap().try_into().unwrap(),
        holder_signature: invited.sign(&redeem).unwrap().try_into().unwrap(),
    };
    let mut redemption_arguments = vec![vos::value::TAG_DYNAMIC];
    redemption_arguments.extend_from_slice(
        &Msg::new("redeem_invite")
            .with("redemption", redemption.encode())
            .encode(),
    );
    let redemption_result = authority
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([197; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: authority_actor,
            method: "redeem_invite".into(),
            arguments: redemption_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the canonical actor PVM verifies and commits the invite chain");
    assert_eq!(
        redemption_result
            .published
            .reply
            .as_ref()
            .map(|reply| reply.result.as_slice()),
        Some(Value::Bool(true).encode().as_slice()),
    );

    let second_invited = libp2p::identity::Keypair::generate_ed25519();
    let second_peer_id = libp2p::PeerId::from(second_invited.public()).to_bytes();
    let second_redeem =
        vos::registry::canonical_op_bytes("redeem_invite", &[&token_pub, &second_peer_id]);
    let second_redemption = RoleAuthorityInviteRedemptionV2 {
        holder_peer_id: second_peer_id,
        redeem_signature: token.sign(&second_redeem).unwrap().try_into().unwrap(),
        holder_signature: second_invited
            .sign(&second_redeem)
            .unwrap()
            .try_into()
            .unwrap(),
        ..redemption
    };
    let mut second_arguments = vec![vos::value::TAG_DYNAMIC];
    second_arguments.extend_from_slice(
        &Msg::new("redeem_invite")
            .with("redemption", second_redemption.encode())
            .encode(),
    );
    let second_result = authority
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([205; 32]),
            workflow_step: 0,
            logical_timeslot: 3,
            target: authority_actor,
            method: "redeem_invite".into(),
            arguments: second_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("a second proven holder may redeem the same partitioned token");
    assert_eq!(
        second_result
            .published
            .reply
            .as_ref()
            .map(|reply| reply.result.as_slice()),
        Some(Value::Bool(true).encode().as_slice()),
    );

    let invited_holder = Origin::Member(SubjectId::of_authenticated_peer(&invited_peer_id));
    let invited_claim = vos::v2::RoleAuthorizationClaimV2 {
        space: binding.service.space,
        holder: invited_holder,
        role: vos::SpaceRole::Member,
        audience: ServiceIdentityV2 {
            root_service: RootServiceId([198; 32]),
            deployment: DeploymentId([199; 32]),
            service_program: ProgramId([200; 32]),
            ..binding.service.clone()
        },
        invocation: InvocationId([201; 32]),
        scope: Hash([202; 32]),
        target: ActorId([203; 32]),
        method: "restricted".into(),
        policy: Hash([204; 32]),
    };
    let mut invited_arguments = vec![vos::value::TAG_DYNAMIC];
    invited_arguments.extend_from_slice(
        &Msg::new("authorize_role")
            .with("claim", invited_claim.encode())
            .encode(),
    );
    let invited_result = authority
        .invoke(LocalWorkRequestV2 {
            invocation: invited_claim.authority_invocation(),
            workflow_step: 0,
            logical_timeslot: 4,
            target: authority_actor,
            method: "authorize_role".into(),
            arguments: invited_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the invited member receives an authority decision");
    assert_eq!(
        invited_result
            .published
            .reply
            .as_ref()
            .map(|reply| reply.result.as_slice()),
        Some(Value::Bytes(invited_claim.encode()).encode().as_slice()),
    );

    let claim = vos::v2::RoleAuthorizationClaimV2 {
        space: binding.service.space,
        holder,
        role: vos::SpaceRole::Member,
        audience: ServiceIdentityV2 {
            root_service: RootServiceId([190; 32]),
            deployment: DeploymentId([191; 32]),
            service_program: ProgramId([192; 32]),
            ..binding.service.clone()
        },
        invocation: InvocationId([193; 32]),
        scope: Hash([194; 32]),
        target: ActorId([195; 32]),
        method: "restricted".into(),
        policy: Hash([196; 32]),
    };
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("authorize_role")
            .with("claim", claim.encode())
            .encode(),
    );
    let committed = authority
        .invoke(LocalWorkRequestV2 {
            invocation: claim.authority_invocation(),
            workflow_step: 0,
            logical_timeslot: 5,
            target: authority_actor,
            method: "authorize_role".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the canonical authority decision commits before publication");
    let assertion = committed
        .role_assertion(claim.clone(), &binding)
        .expect("the actor reply and guest receipt form the exact role assertion");
    assert_eq!(assertion.claim, claim);
    assert!(assertion.matches_authority(&binding));
    authority
        .acknowledge_publication(
            committed
                .publication
                .as_ref()
                .expect("the decision remains published before acknowledgement"),
        )
        .expect("guest Accumulate acknowledges the authority reply");
    assert_eq!(
        authority
            .recover_role_assertion(claim, &binding)
            .expect("durable workflow and receipt rows recover the assertion"),
        assertion
    );

    let target_signer = libp2p::identity::Keypair::generate_ed25519();
    let (target_package, target_name) = signed_test_package(&cycle_v2_elf(), &target_signer);
    let target_actor = ActorId([206; 32]);
    let target_identity = ServiceIdentityV2 {
        space: binding.service.space,
        root_service: RootServiceId([207; 32]),
        deployment: target_package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let target_config = LocalRootTreeConfigV2 {
        role_authority: Some(binding.clone()),
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: target_package,
        service: target_identity,
        root_actor: target_actor,
        actor_name: target_name,
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([208; 32]),
            authenticator: vec![209],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut target =
        LocalRootTreeServiceV2::open(target_config.clone(), FailableCommittedImages::default())
            .expect("the Local target pins the canonical Raft authority at install");
    let policy = target
        .root_method_policy("member_only")
        .unwrap()
        .expect("the signed package retains its Member policy");
    assert_eq!(policy.space_role, Some(vos::SpaceRole::Member.as_u8()));
    assert!(!policy.public);

    let mut member_arguments = vec![vos::value::TAG_DYNAMIC];
    member_arguments.extend_from_slice(&Msg::new("member_only").encode());
    let provisional = LocalWorkRequestV2 {
        invocation: InvocationId([210; 32]),
        workflow_step: 0,
        logical_timeslot: 6,
        target: target_actor,
        method: "member_only".into(),
        arguments: member_arguments,
        origin: holder,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let target_claim = target
        .role_authorization_claim(&provisional, vos::SpaceRole::Member, &policy)
        .expect("the target scheduler derives the exact authority scope");
    let mut decision_arguments = vec![vos::value::TAG_DYNAMIC];
    decision_arguments.extend_from_slice(
        &Msg::new("authorize_role")
            .with("claim", target_claim.encode())
            .encode(),
    );
    let decision = authority
        .invoke(LocalWorkRequestV2 {
            invocation: target_claim.authority_invocation(),
            workflow_step: 0,
            logical_timeslot: 6,
            target: authority_actor,
            method: "authorize_role".into(),
            arguments: decision_arguments,
            origin: Origin::System,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the canonical authority finalizes the invocation-scoped decision");
    let target_assertion = decision
        .role_assertion(target_claim.clone(), &binding)
        .expect("the authority reply shape and receipt are bound exactly");
    target
        .store_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: authority_actor,
            receipt: target_assertion.receipt.clone(),
        });
    let credential = RoleCredentialV2 {
        holder,
        scope: target_claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        actor_role: None,
        authenticator: target_assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let mut authorized = provisional.clone();
    authorized.authorization = credential.clone();
    let committed = target
        .invoke(authorized.clone())
        .expect("guest Accumulate accepts the finalized authority assertion");
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(99)),
    );

    let target_backend = target.into_backend();
    let mut target = LocalRootTreeServiceV2::open(target_config, target_backend)
        .expect("the target reopens from its durable image");
    assert_eq!(
        target
            .role_authorization_claim(&provisional, vos::SpaceRole::Member, &policy)
            .expect("retry scope is recovered from guest-owned ingress"),
        target_claim,
    );
    let mut divergent = provisional.clone();
    divergent.arguments.push(0);
    assert!(matches!(
        target.role_authorization_claim(&divergent, vos::SpaceRole::Member, &policy),
        Err(LocalRootTreeInvokeErrorV2::DivergentInvocation),
    ));
    target
        .store_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: authority_actor,
            receipt: target_assertion.receipt.clone(),
        });
    let retried = target
        .invoke(authorized)
        .expect("the exact role-authorized retry reattaches after restart");
    assert!(retried.duplicate);
    assert_eq!(retried.refine_gas_used, 0);
    assert_eq!(retried.accumulate_gas_used, 0);
    assert_eq!(
        retried
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(99)),
    );
}

#[test]
fn crdt_role_authorization_survives_causal_sync_restart_and_exact_retry() {
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&crdt_counter_v2_elf(), &signer);
    let actor = ActorId([0xD1; 32]);
    let authority_actor = ActorId([0xD2; 32]);
    let service = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xD3; 32]),
        root_service: RootServiceId([0xD4; 32]),
        deployment: package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let authority = RoleAuthorityBindingV2 {
        service: ServiceIdentityV2 {
            root_service: RootServiceId([0xD5; 32]),
            deployment: DeploymentId([0xD6; 32]),
            ..service.clone()
        },
        actor: authority_actor,
    };
    let config = LocalRootTreeConfigV2 {
        role_authority: Some(authority.clone()),
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        package,
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0xD7; 32]),
            authenticator: vec![0xD8],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut source =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("the authority-bound CRDT source installs");
    let policy = source
        .root_method_policy("member_only")
        .unwrap()
        .expect("the CRDT package retains its Member policy");
    assert_eq!(policy.space_role, Some(vos::SpaceRole::Member.as_u8()));

    let holder = Origin::Member(SubjectId([0xD9; 32]));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("member_only").encode());
    let provisional = LocalWorkRequestV2 {
        invocation: InvocationId([0xDA; 32]),
        workflow_step: 0,
        logical_timeslot: 10,
        target: actor,
        method: "member_only".into(),
        arguments,
        origin: holder,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let claim = source
        .role_authorization_claim(&provisional, vos::SpaceRole::Member, &policy)
        .expect("the CRDT scheduler derives a frontier-independent authority scope");
    let assertion = AccumulatedRoleAssertionV2 {
        receipt: AccumulationReceiptV2 {
            service: authority.service.clone(),
            accepted_transition: Hash([0xDB; 32]),
            reply_commitment: Some(claim.authority_reply(authority_actor).commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([0xDC; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Raft,
        },
        claim: claim.clone(),
    };
    assert!(assertion.matches_authority(&authority));
    let authority_verification = ReceiptVerificationRequestV2 {
        expected_producer: authority_actor,
        receipt: assertion.receipt.clone(),
    };
    source.store_mut().allow_receipt(&authority_verification);
    let mut authorized = provisional.clone();
    authorized.authorization = RoleCredentialV2 {
        holder,
        scope: claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        actor_role: None,
        authenticator: assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let (credential_policy, expected_credential_commitment, credential_bytes) =
        match &authorized.authorization {
            AuthorizationEvidenceV2::Credential {
                policy,
                credential_commitment,
                bytes,
            } => (*policy, *credential_commitment, bytes.clone()),
            _ => unreachable!("the authorized request carries a disclosed credential"),
        };
    let authorization_blob = BlobRefV2::of_bytes(&credential_bytes);
    assert!(!source.admit_ingress(&authorized).unwrap());
    let committed = source
        .invoke_admitted(authorized.invocation)
        .expect("guest Accumulate admits and executes the scoped CRDT assertion");
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(99)),
    );

    let sync = source
        .crdt_sync_envelope()
        .unwrap()
        .expect("the authorized ingress and execution export causally");
    assert!(sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperationV2::Ingress(ingress)
                if ingress.invocation == authorized.invocation
                    && ingress.authorization_blob == Some(authorization_blob.clone())
                    && matches!(&ingress.authorization,
                        AuthorizationEvidenceV2::Credential {
                            policy,
                            credential_commitment,
                            bytes,
                        } if *policy == credential_policy
                            && *credential_commitment == expected_credential_commitment
                            && bytes.is_empty()))
        })
    }));
    assert!(
        sync.provided_blobs
            .iter()
            .any(|blob| { blob.reference == authorization_blob && blob.bytes == credential_bytes })
    );
    let sink_backend = SharedCommittedImages::default();
    let mut sink = LocalRootTreeServiceV2::open(config.clone(), sink_backend.clone())
        .expect("an independent CRDT replica installs without verifier cache state");
    assert!(matches!(
        sink.sync_finalized_crdt(sync.clone()),
        Err(LocalRootTreeInvokeErrorV2::Rejected(
            vos::v2::AccumulationRejectionV2::ReceiptUnavailable,
        ))
    ));
    for node in &sync.nodes {
        sink.store_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: node
                    .change
                    .expected_producer()
                    .expect("every authorized causal node names its producer"),
                receipt: node.receipt.clone(),
            });
    }
    let mut missing_sink =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("the missing-blob adversary starts from an independent replica");
    for node in &sync.nodes {
        missing_sink
            .store_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: node
                    .change
                    .expected_producer()
                    .expect("every authorized causal node names its producer"),
                receipt: node.receipt.clone(),
            });
    }
    let mut missing_authorization = sync.clone();
    missing_authorization
        .provided_blobs
        .retain(|blob| blob.reference != authorization_blob);
    assert!(matches!(
        missing_sink.sync_finalized_crdt(missing_authorization),
        Err(LocalRootTreeInvokeErrorV2::Rejected(
            vos::v2::AccumulationRejectionV2::MissingBlob(hash),
        )) if hash == authorization_blob.hash
    ));
    sink.sync_finalized_crdt(sync)
        .expect("finalized causal receipts transitively authenticate the admitted assertion");
    drop(sink);
    let mut sink = LocalRootTreeServiceV2::open(config, sink_backend)
        .expect("the synchronized authorized replica reopens durably");
    assert_eq!(
        sink.role_authorization_claim(&provisional, vos::SpaceRole::Member, &policy)
            .expect("restart recovers the original scoped claim from causal ingress"),
        claim,
    );
    let recovered = sink
        .invoke(authorized.clone())
        .expect("the synchronized exact retry needs no authority re-execution");
    assert!(recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    let mut divergent = authorized;
    divergent.arguments.push(0);
    assert!(matches!(
        sink.invoke(divergent),
        Err(LocalRootTreeInvokeErrorV2::DivergentInvocation),
    ));
}

#[test]
fn node_ingress_uses_canonical_authority_for_raft_and_crdt_targets() {
    let node_key = libp2p::identity::Keypair::generate_ed25519();
    let granted_key = libp2p::identity::Keypair::generate_ed25519();
    let denied_key = libp2p::identity::Keypair::generate_ed25519();
    let node_peer = libp2p::PeerId::from(node_key.public());
    let granted_peer = libp2p::PeerId::from(granted_key.public());
    let denied_peer = libp2p::PeerId::from(denied_key.public());
    let node_prefix = vos::network::derive_node_prefix(&node_peer);

    let space = vos::v2::SpaceId([211; 32]);
    let authority_actor = ActorId([212; 32]);
    let authority_signer = libp2p::identity::Keypair::generate_ed25519();
    let (authority_package, authority_name) =
        signed_test_package(&space_authority_elf(), &authority_signer);
    let root = libp2p::identity::Keypair::generate_ed25519();
    let replication_id = [213; 32];
    let authority_identity = ServiceIdentityV2 {
        space,
        root_service: RootServiceId([214; 32]),
        deployment: authority_package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let authority_binding = RoleAuthorityBindingV2 {
        service: authority_identity.clone(),
        actor: authority_actor,
    };
    let authority_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: authority_package,
        service: authority_identity,
        root_actor: authority_actor,
        actor_name: authority_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: space_authority::initial_state(
            space,
            libp2p::PeerId::from(root.public()).to_bytes(),
            replication_id,
        )
        .unwrap(),
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([215; 32]),
            authenticator: vec![216],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-role-ingress-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let authority_log = RaftAccumulateLogV2::open(
        &directory.join("authority.redb"),
        RaftConfig {
            me: node_prefix,
            members: vec![node_prefix],
            replication_id,
            ..RaftConfig::default()
        },
    )
    .unwrap();
    let mut authority = LocalRootTreeServiceV2::open_raft(
        authority_config,
        FailableCommittedImages::default(),
        authority_log,
    )
    .expect("the single-voter authority installs through its request log");
    let holder = Origin::Member(SubjectId::of_authenticated_peer(&granted_peer.to_bytes()));
    let grant = RoleAuthorityMutationV2::Grant {
        space,
        holder,
        role: vos::SpaceRole::Member,
        epoch: 1,
    };
    let mut grant_arguments = vec![vos::value::TAG_DYNAMIC];
    grant_arguments.extend_from_slice(
        &Msg::new("mutate_role")
            .with("mutation", grant.encode())
            .with("signature", root.sign(&grant.encode()).unwrap())
            .encode(),
    );
    let grant = authority
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([217; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: authority_actor,
            method: "mutate_role".into(),
            arguments: grant_arguments,
            origin: Origin::System,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the root-signed Member grant commits before ingress");
    authority
        .acknowledge_publication(grant.publication.as_ref().unwrap())
        .unwrap();

    let target_actor = ActorId([218; 32]);
    let target_signer = libp2p::identity::Keypair::generate_ed25519();
    let (target_package, target_name) = signed_test_package(&cycle_v2_elf(), &target_signer);
    let target_identity = ServiceIdentityV2 {
        space,
        root_service: RootServiceId([219; 32]),
        deployment: target_package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let target_replication_id = [0xE0; 32];
    let target_log = RaftAccumulateLogV2::open(
        &directory.join("target.redb"),
        RaftConfig {
            me: node_prefix,
            members: vec![node_prefix],
            replication_id: target_replication_id,
            ..RaftConfig::default()
        },
    )
    .unwrap();
    let target = LocalRootTreeServiceV2::open_raft(
        LocalRootTreeConfigV2 {
            role_authority: Some(authority_binding.clone()),
            service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
            service: target_identity.clone(),
            package: target_package,
            root_actor: target_actor,
            actor_name: target_name,
            consistency: ConsistencyModeV2::Raft,
            initial_state: vec![],
            external_actors: vec![],
            install_authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: SystemCapabilityId([220; 32]),
                authenticator: vec![221],
            },
            refine_gas: TEST_GAS_SCHEDULE.refine,
            accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
        },
        FailableCommittedImages::default(),
        target_log,
    )
    .expect("the Raft target pins the authority identity in guest-owned state");

    let crdt_actor = ActorId([0xE1; 32]);
    let crdt_signer = libp2p::identity::Keypair::generate_ed25519();
    let (crdt_package, crdt_name) = signed_test_package(&crdt_counter_v2_elf(), &crdt_signer);
    let crdt_identity = ServiceIdentityV2 {
        space,
        root_service: RootServiceId([0xE2; 32]),
        deployment: crdt_package.deployment_id(),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let crdt_config = LocalRootTreeConfigV2 {
        role_authority: Some(authority_binding.clone()),
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: crdt_identity,
        package: crdt_package,
        root_actor: crdt_actor,
        actor_name: crdt_name,
        consistency: ConsistencyModeV2::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0xE3; 32]),
            authenticator: vec![0xE4],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let crdt_backend = SharedCommittedImages::default();
    let crdt_target = LocalRootTreeServiceV2::open(crdt_config.clone(), crdt_backend.clone())
        .expect("the CRDT target pins the same authority identity in guest-owned state");

    let authority_route = ServiceId::new(node_prefix, 0x3a00);
    let target_route = ServiceId::new(node_prefix, 0x3a01);
    let crdt_route = ServiceId::new(node_prefix, 0x3a02);
    let mut node = VosNode::with_prefix(node_prefix);
    let registry_pvm =
        grey_transpiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
            .expect("the bundled registry transpiles for the legacy-role adversary");
    install_test_voter_registry(&mut node, registry_pvm, &[]);
    {
        use ed25519_dalek::{Signer, SigningKey};
        use space_registry::{SpaceRegistryRef, Status, canonical_op_bytes, pack_auth};

        let root_key = SigningKey::from_bytes(&[0xB9; 32]);
        let mut root_peer = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
        root_peer.extend_from_slice(&root_key.verifying_key().to_bytes());
        let denied_bytes = denied_peer.to_bytes();
        let role = space_registry::AUTH_ROLE_ADMIN;
        let epoch = 1u64;
        let canonical = canonical_op_bytes(
            "grant_role",
            &[&denied_bytes, &[role], &epoch.to_le_bytes()],
        );
        let authorization = pack_auth(&root_peer, &root_key.sign(&canonical).to_bytes());
        assert_eq!(
            vos::block_on(SpaceRegistryRef::at(ServiceId::REGISTRY).grant_role(
                &mut &node,
                denied_bytes,
                role,
                epoch,
                authorization,
            ))
            .unwrap(),
            Status::Ok,
            "the adversary holds legacy ADMIN bytes but no canonical authority grant",
        );
    }
    node.register_v2_root_at_id("space-authority", authority, authority_route, true)
        .unwrap();
    node.register_v2_root_at_id("role-target", target, target_route, true)
        .unwrap();
    node.register_v2_root_at_id("crdt-role-target", crdt_target, crdt_route, true)
        .unwrap();

    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let node_network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: node_key,
        local_prefix: node_prefix,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let node_address = loop {
        if let Some(address) = node_network.listen_addrs().into_iter().next() {
            break address.with(libp2p::multiaddr::Protocol::P2p(node_peer));
        }
        assert!(std::time::Instant::now() < deadline, "node did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    let granted_network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: granted_key,
        local_prefix: vos::network::derive_node_prefix(&granted_peer),
        listen: vec![listen.clone()],
        bootstrap: vec![node_address.clone()],
        auto_dial_mdns: false,
    });
    let denied_network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: denied_key,
        local_prefix: vos::network::derive_node_prefix(&denied_peer),
        listen: vec![listen],
        bootstrap: vec![node_address],
        auto_dial_mdns: false,
    });
    node.attach_network(node_network);
    let shutdown = node.shutdown_handle();
    let runner = std::thread::spawn(move || {
        node.run_forever();
        node.collect()
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while (granted_network.peer_for_prefix(node_prefix).is_none()
        || denied_network.peer_for_prefix(node_prefix).is_none())
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(granted_network.peer_for_prefix(node_prefix).is_some());
    assert!(denied_network.peer_for_prefix(node_prefix).is_some());

    let ordinary_claim = RoleAuthorizationClaimV2 {
        space,
        holder,
        role: vos::SpaceRole::Member,
        audience: target_identity,
        invocation: InvocationId([0xDA; 32]),
        scope: Hash([0xDB; 32]),
        target: target_actor,
        method: "member_only".into(),
        policy: Hash([0xDC; 32]),
    };
    let mut ordinary_arguments = vec![vos::value::TAG_DYNAMIC];
    ordinary_arguments.extend_from_slice(
        &Msg::new("authorize_role")
            .with("claim", ordinary_claim.encode())
            .encode(),
    );
    let ordinary_authority_reply = granted_network
        .send_invoke(
            node_peer,
            ServiceId::REGISTRY.0,
            authority_route.0,
            vec![],
            RootTreeInvocationV2 {
                invocation: ordinary_claim.authority_invocation(),
                target: authority_actor,
                method: "authorize_role".into(),
                arguments: ordinary_arguments,
                proof_requested: false,
            }
            .encode(),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("an ordinary authorize_role call commits its declared actor reply");
    let Some(Value::Bytes(ordinary_reply_bytes)) = Value::try_decode(&ordinary_authority_reply)
    else {
        panic!("ordinary authorize_role must return its declared Vec<u8> reply")
    };
    assert_eq!(ordinary_reply_bytes, ordinary_claim.encode());
    assert!(
        AccumulatedRoleAssertionV2::decode(&ordinary_reply_bytes).is_err(),
        "method-name coincidence must not activate the host-private assertion override",
    );

    let ingress = |target, invocation| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new("member_only").encode());
        RootTreeInvocationV2 {
            invocation,
            target,
            method: "member_only".into(),
            arguments,
            proof_requested: false,
        }
        .encode()
    };
    let granted = granted_network
        .send_invoke(
            node_peer,
            ServiceId::REGISTRY.0,
            target_route.0,
            vec![],
            ingress(target_actor, InvocationId([222; 32])),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("the member call reaches the local target through its Raft authority");
    assert_eq!(Value::try_decode(&granted), Some(Value::U32(99)));

    let crdt_invocation = InvocationId([0xE5; 32]);
    let crdt_granted = granted_network
        .send_invoke(
            node_peer,
            ServiceId::REGISTRY.0,
            crdt_route.0,
            vec![],
            ingress(crdt_actor, crdt_invocation),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("the member call reaches the CRDT target through the canonical authority");
    assert_eq!(Value::try_decode(&crdt_granted), Some(Value::U32(99)));
    let crdt_retry = granted_network
        .send_invoke(
            node_peer,
            ServiceId::REGISTRY.0,
            crdt_route.0,
            vec![],
            ingress(crdt_actor, crdt_invocation),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("the exact CRDT retry recovers its admitted authority evidence");
    assert_eq!(crdt_retry, crdt_granted);

    let denied = denied_network
        .send_invoke(
            node_peer,
            ServiceId::REGISTRY.0,
            target_route.0,
            vec![],
            ingress(target_actor, InvocationId([223; 32])),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("an ungranted peer receives an explicit refusal");
    assert_eq!(denied.first().copied(), Some(vos::STATUS_FORBIDDEN));
    let crdt_denied = denied_network
        .send_invoke(
            node_peer,
            ServiceId::REGISTRY.0,
            crdt_route.0,
            vec![],
            ingress(crdt_actor, InvocationId([0xE6; 32])),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("an ungranted peer receives an explicit CRDT refusal");
    assert_eq!(crdt_denied.first().copied(), Some(vos::STATUS_FORBIDDEN));

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        runner
            .join()
            .unwrap()
            .into_iter()
            .all(|result| result.is_ok())
    );
    granted_network.join();
    denied_network.join();
    let reopened_crdt = LocalRootTreeServiceV2::open(crdt_config, crdt_backend)
        .expect("the role-authorized CRDT root reopens from its durable causal state");
    let sync = reopened_crdt
        .crdt_sync_envelope()
        .expect("the reopened CRDT causal frontier is readable")
        .expect("the authorized ingress and execution remain exportable");
    assert!(sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperationV2::Ingress(ingress)
                if ingress.invocation == crdt_invocation
                    && matches!(&ingress.authorization, AuthorizationEvidenceV2::Credential { .. }))
        })
    }));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn raft_root_tree_orders_genesis_apply_and_ack_through_physical_accumulate() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([113; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([114; 32]),
            root_service: RootServiceId([115; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([116; 32]),
            authenticator: vec![117],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    assert!(matches!(
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default()),
        Err(vos::v2::LocalRootTreeOpenErrorV2::InvalidConfig(
            LocalRootTreeConfigErrorV2::ReplicationDriverRequired
        ))
    ));

    let directory = std::env::temp_dir().join(format!(
        "vos-v2-root-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeServiceV2::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .expect("Raft root genesis is ordered through physical Accumulate");
    assert_eq!(service.consistency(), ConsistencyModeV2::Raft);
    assert_eq!(
        service.store().header().unwrap().unwrap().consistency,
        ConsistencyModeV2::Raft
    );

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([118; 32]),
        workflow_step: 0,
        logical_timeslot: 5,
        target: actor,
        method: "start".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let committed = service
        .invoke(request.clone())
        .expect("actor Apply is ordered before guest execution");
    let publication = committed.publication.clone().unwrap();
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .map(|reply| &reply.result),
        Some(&Value::Unit.encode())
    );
    assert!(!service.acknowledge_publication(&publication).unwrap());

    let backend = service.into_backend();
    let mut log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(log.applied_index().unwrap(), 4);
    assert!(log.committed_after(4).unwrap().entries.is_empty());
    let mut reopened = LocalRootTreeServiceV2::open_raft(config, backend, log)
        .expect("root reopens at the durable Raft apply cursor");
    assert!(reopened.catch_up().unwrap());
    let retry = reopened
        .invoke(request)
        .expect("a lost result reattaches without another Refine or log entry");
    assert!(retry.duplicate);
    assert_eq!(retry.refine_gas_used, 0);
    assert_eq!(retry.accumulate_gas_used, 0);
    assert!(retry.publication.is_none());
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_registers_a_raft_root_through_the_canonical_request_log() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([0xA1; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([0xA2; 32]),
            root_service: RootServiceId([0xA3; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0xA4; 32]),
            authenticator: vec![0xA5],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-node-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let member = 0xA109;

    // Route validation is part of local attachment and must happen before a
    // join callback can change the existing cluster's membership. Model the
    // leader-side membership set in the callback and occupy the route first:
    // a failed local attachment leaves that set byte-for-byte unchanged.
    let occupied_path = directory.join("occupied.redb");
    let occupied_db = Arc::new(redb::Database::create(&occupied_path).unwrap());
    let occupied_route = ServiceId::new(member, 208);
    let mut unavailable = VosNode::new();
    unavailable.register_at_id(
        vos::node::AgentConfig::new(actor_elf.clone()),
        occupied_route,
    );
    let membership = Arc::new(std::sync::Mutex::new(vec![member]));
    let changed_membership = membership.clone();
    let failed = unavailable.register_v2_raft_root_at_id_after_local_attach(
        "unavailable-root".into(),
        config.clone(),
        FailableCommittedImages::default(),
        occupied_db,
        RaftConfig {
            me: member,
            members: vec![member],
            replication_id: [0xA0; 32],
            ..RaftConfig::default()
        },
        occupied_route,
        true,
        move |_, _| {
            changed_membership.lock().unwrap().push(0xA10A);
            Ok(())
        },
    );
    assert!(matches!(
        failed,
        Err(vos::node::V2RaftNodeRegistrationError::Registration(
            vos::node::V2NodeRegistrationError::ServiceRouteOccupied(id),
        )) if id == occupied_route
    ));
    assert_eq!(*membership.lock().unwrap(), vec![member]);
    unavailable
        .shutdown_handle()
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = unavailable.collect();

    // A duplicate replication identity is rejected without replacing the
    // already-live handler. This drives the node registration facade, not
    // merely Network's map primitive: preparation must be atomic even when
    // route validation would happen later.
    struct ExistingHandler;
    impl RaftRpcHandler for ExistingHandler {
        fn append_entries(
            &self,
            _replication_id: &[u8; 32],
            _from_prefix: u16,
            term: u64,
            _prev_log_index: u64,
            _prev_log_term: u64,
            _leader_commit: u64,
            _entries: Vec<vos::network::RaftEntry>,
        ) -> vos::network::RaftAppendResult {
            vos::network::RaftAppendResult {
                term,
                success: false,
                match_index: 0,
            }
        }

        fn request_vote(
            &self,
            _replication_id: &[u8; 32],
            _from_prefix: u16,
            term: u64,
            _last_log_index: u64,
            _last_log_term: u64,
        ) -> vos::network::RaftVoteResult {
            vos::network::RaftVoteResult {
                term,
                vote_granted: false,
            }
        }

        fn handle_status(&self, _replication_id: &[u8; 32]) -> vos::network::RaftStatusReply {
            vos::network::RaftStatusReply {
                present: true,
                role: vos::network::RaftRole::Leader,
                current_term: 77,
                commit_index: 11,
                last_log_index: 11,
                members: vec![0xA109],
                leader_hint: Some(0xA109),
            }
        }
    }

    let duplicate_network = vos::network::Network::start(vos::network::NetworkConfig::default());
    let duplicate_prefix = duplicate_network.local_prefix();
    let duplicate_replication_id = [0xAE; 32];
    duplicate_network.register_raft_handler(duplicate_replication_id, Arc::new(ExistingHandler));
    let mut duplicate_node = VosNode::with_prefix(duplicate_prefix);
    duplicate_node.attach_network(duplicate_network);
    let duplicate_network = duplicate_node.network().unwrap();
    let duplicate_db =
        Arc::new(redb::Database::create(directory.join("duplicate-handler.redb")).unwrap());
    let duplicate = duplicate_node.register_v2_raft_root_at_id(
        "duplicate-root".into(),
        config.clone(),
        FailableCommittedImages::default(),
        duplicate_db.clone(),
        RaftConfig {
            me: duplicate_prefix,
            members: vec![duplicate_prefix],
            replication_id: duplicate_replication_id,
            ..RaftConfig::default()
        },
        ServiceId::new(duplicate_prefix, 211),
        true,
    );
    assert!(matches!(
        duplicate,
        Err(vos::node::V2RaftNodeRegistrationError::ReplicationHandlerOccupied(id))
            if id == duplicate_replication_id
    ));
    let live_status = duplicate_network
        .local_raft_status(&duplicate_replication_id)
        .expect("the prior handler remains registered");
    assert_eq!(live_status.current_term, 77);
    assert_eq!(live_status.commit_index, 11);
    assert!(
        duplicate_db
            .begin_read()
            .unwrap()
            .open_table(vos::raft::RAFT_META)
            .is_err(),
        "the rejected duplicate never starts a worker or initializes Raft storage",
    );
    drop(duplicate_network);
    let _ = duplicate_node.collect();

    // Voter promotion is node-owned background state: registering it must not
    // stall the router, it remains unexposed while pending, and node shutdown
    // cancels and joins the worker promptly.
    let pending_path = directory.join("pending.redb");
    let pending_db = Arc::new(redb::Database::create(&pending_path).unwrap());
    let pending_route = ServiceId::new(member, 210);
    let mut pending = VosNode::new();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let promotion_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_finished = promotion_finished.clone();
    pending
        .register_v2_raft_root_at_id_after_local_attach(
            "pending-root".into(),
            config.clone(),
            FailableCommittedImages::default(),
            pending_db,
            RaftConfig {
                me: member,
                members: vec![member],
                replication_id: [0xAF; 32],
                ..RaftConfig::default()
            },
            pending_route,
            true,
            move |_, shutdown| {
                let _ = started_tx.send(());
                while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                callback_finished.store(true, std::sync::atomic::Ordering::Relaxed);
                Err("cancelled by shutdown".into())
            },
        )
        .expect("local preparation returns before voter promotion completes");
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("background promotion started");
    assert!(
        !promotion_finished.load(std::sync::atomic::Ordering::Relaxed),
        "registration returns while the promotion callback is still pending",
    );
    assert!(pending.has_agent(pending_route));
    let mut pending_arguments = vec![vos::value::TAG_DYNAMIC];
    pending_arguments.extend_from_slice(&Msg::new("start").encode());
    assert!(
        matches!(
            pending.invoke_actor(actor, pending_arguments),
            Err(ClientError::NotFound)
        ),
        "a prepared voter is reserved but not publicly routable",
    );
    let shutdown_at = std::time::Instant::now();
    let _ = pending.collect();
    assert!(shutdown_at.elapsed() < Duration::from_secs(1));

    let log_path = directory.join("raft.redb");
    let db = Arc::new(redb::Database::create(&log_path).unwrap());
    let route = ServiceId::new(member, 209);
    let mut node = VosNode::new();
    node.register_v2_raft_root_at_id(
        "raft-root".into(),
        config,
        FailableCommittedImages::default(),
        db,
        RaftConfig {
            me: member,
            members: vec![member],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0xA6; 32],
            propose_timeout_ms: 2_000,
        },
        route,
        true,
    )
    .expect("node attaches the v2 Raft worker and root-tree owner");
    let handle = node.invoke_handle();
    let shutdown = node.shutdown_handle();
    let router = std::thread::spawn(move || {
        node.run_forever();
        node.collect()
    });

    std::thread::sleep(Duration::from_millis(350));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let ingress = RootTreeInvocationV2 {
        invocation: InvocationId([0xA7; 32]),
        target: actor,
        method: "start".into(),
        arguments,
        proof_requested: false,
    };
    let reply = handle
        .invoke_with_timeout(route, ingress.encode(), Duration::from_secs(120))
        .expect("the elected root orders admission, apply, and ACK before replying");
    assert_eq!(Value::try_decode(&reply), Some(Value::Unit));

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        router
            .join()
            .unwrap()
            .into_iter()
            .all(|result| result.is_ok())
    );
    let mut log = RaftAccumulateLogV2::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(
        log.applied_index().unwrap(),
        5,
        "the elected worker's no-op precedes four IC-5 requests"
    );
    drop(log);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn network_ingress_to_a_raft_root_follower_redirects_to_the_leader() {
    let task_pvm = grey_transpiler::assembler::Assembler::new().build();
    let (config, _) = signed_task_dependency_config(task_pvm, ConsistencyModeV2::Raft);
    let actor = config.root_actor;

    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let peer_a = libp2p::PeerId::from(key_a.public());
    let prefix_a = vos::network::derive_node_prefix(&peer_a);
    let (key_b, peer_b, prefix_b) = loop {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = libp2p::PeerId::from(key.public());
        let prefix = vos::network::derive_node_prefix(&peer);
        if prefix != prefix_a {
            break (key, peer, prefix);
        }
    };
    let (key_client, prefix_client) = loop {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let prefix = vos::network::derive_node_prefix(&libp2p::PeerId::from(key.public()));
        if prefix != prefix_a && prefix != prefix_b {
            break (key, prefix);
        }
    };

    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let network_a = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let address_a = loop {
        if let Some(address) = network_a.listen_addrs().into_iter().next() {
            break address.with(libp2p::multiaddr::Protocol::P2p(network_a.peer_id()));
        }
        assert!(std::time::Instant::now() < deadline, "node A did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    let network_b = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_b,
        local_prefix: prefix_b,
        listen: vec![listen.clone()],
        bootstrap: vec![address_a.clone()],
        auto_dial_mdns: true,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let address_b = loop {
        if let Some(address) = network_b.listen_addrs().into_iter().next() {
            break address.with(libp2p::multiaddr::Protocol::P2p(network_b.peer_id()));
        }
        assert!(std::time::Instant::now() < deadline, "node B did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    let client_network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_client,
        local_prefix: prefix_client,
        listen: vec![listen],
        bootstrap: vec![address_a, address_b],
        auto_dial_mdns: true,
    });

    let mut node_a = VosNode::with_prefix(prefix_a);
    let mut node_b = VosNode::with_prefix(prefix_b);
    let registry_pvm =
        grey_transpiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
            .expect("committed space-registry ELF transpiles");
    let voters = [(prefix_a, peer_a.to_bytes()), (prefix_b, peer_b.to_bytes())];
    install_test_voter_registry(&mut node_a, registry_pvm.clone(), &voters);
    install_test_voter_registry(&mut node_b, registry_pvm, &voters);
    node_a.attach_network(network_a);
    node_b.attach_network(network_b);
    let network_a = node_a.network().unwrap();
    let network_b = node_b.network().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while (network_a.peer_for_prefix(prefix_b).is_none()
        || network_b.peer_for_prefix(prefix_a).is_none()
        || client_network.peer_for_prefix(prefix_a).is_none()
        || client_network.peer_for_prefix(prefix_b).is_none())
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(client_network.peer_for_prefix(prefix_a).is_some());
    assert!(client_network.peer_for_prefix(prefix_b).is_some());

    let directory = std::env::temp_dir().join(format!(
        "vos-v2-root-follower-redirect-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db_a = Arc::new(redb::Database::create(directory.join("a.redb")).unwrap());
    let db_b = Arc::new(redb::Database::create(directory.join("b.redb")).unwrap());
    let image_a = directory.join("a.service");
    let image_b = directory.join("b.service");
    let backend_a = FileCommittedImageStoreV2::new(&image_a);
    let backend_b = FileCommittedImageStoreV2::new(&image_b);
    let replication_id = [0xB6; 32];
    let members = vec![prefix_a, prefix_b];
    // This test is about typed redirect/status preservation, not election
    // churn. Give B the deterministic short election window and keep A's
    // follower timeout beyond the test's request sequence, then observe a
    // sustained leader before publishing either root route.
    let election_timeout_for = |me| {
        if me == prefix_b {
            (50, 100)
        } else {
            (30_000, 40_000)
        }
    };
    let raft_config = |me| RaftConfig {
        me,
        members: members.clone(),
        election_timeout_ms: election_timeout_for(me),
        heartbeat_interval_ms: 20,
        replication_id,
        propose_timeout_ms: 5_000,
    };
    let (apply_a_tx, apply_a_rx) = std::sync::mpsc::channel();
    let (apply_b_tx, apply_b_rx) = std::sync::mpsc::channel();
    let worker_a = RaftWorker::spawn(
        db_a.clone(),
        WorkerConfig {
            me: prefix_a,
            members: members.clone(),
            replication_id,
            election_timeout_ms: election_timeout_for(prefix_a),
            heartbeat_interval_ms: 20,
        },
        Some(network_a.clone()),
        Some(apply_a_tx),
    );
    let worker_b = RaftWorker::spawn(
        db_b.clone(),
        WorkerConfig {
            me: prefix_b,
            members: members.clone(),
            replication_id,
            election_timeout_ms: election_timeout_for(prefix_b),
            heartbeat_interval_ms: 20,
        },
        Some(network_b.clone()),
        Some(apply_b_tx),
    );
    let handle_a = worker_a.handler();
    let handle_b = worker_b.handler();
    network_a.register_raft_handler(replication_id, Arc::new(handle_a.clone()));
    network_b.register_raft_handler(replication_id, Arc::new(handle_b.clone()));
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let leader = loop {
        if handle_b.role() == Role::Leader {
            break prefix_b;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "two-node Raft root did not elect a leader"
        );
        std::thread::sleep(Duration::from_millis(15));
    };
    assert_eq!(leader, prefix_b, "the asymmetric election elects B");
    let stable_until = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < stable_until {
        assert_eq!(handle_b.role(), Role::Leader);
        assert_ne!(handle_a.role(), Role::Leader);
        std::thread::sleep(Duration::from_millis(20));
    }

    let log_a = RaftAccumulateLogV2::from_worker(db_a, raft_config(prefix_a), worker_a, apply_a_rx)
        .unwrap();
    let log_b = RaftAccumulateLogV2::from_worker(db_b, raft_config(prefix_b), worker_b, apply_b_rx)
        .unwrap();
    let local_id = 0x3600;
    if leader == prefix_a {
        let service_a =
            LocalRootTreeServiceV2::open_raft(config.clone(), backend_a.clone(), log_a).unwrap();
        node_a
            .register_v2_root_at_id(
                "raft-root-a",
                service_a,
                ServiceId::new(prefix_a, local_id),
                true,
            )
            .unwrap();
        let service_b =
            LocalRootTreeServiceV2::open_raft(config, backend_b.clone(), log_b).unwrap();
        node_b
            .register_v2_root_at_id(
                "raft-root-b",
                service_b,
                ServiceId::new(prefix_b, local_id),
                true,
            )
            .unwrap();
    } else {
        let service_b =
            LocalRootTreeServiceV2::open_raft(config.clone(), backend_b.clone(), log_b).unwrap();
        node_b
            .register_v2_root_at_id(
                "raft-root-b",
                service_b,
                ServiceId::new(prefix_b, local_id),
                true,
            )
            .unwrap();
        let service_a =
            LocalRootTreeServiceV2::open_raft(config, backend_a.clone(), log_a).unwrap();
        node_a
            .register_v2_root_at_id(
                "raft-root-a",
                service_a,
                ServiceId::new(prefix_a, local_id),
                true,
            )
            .unwrap();
    }

    let follower = if leader == prefix_a {
        prefix_b
    } else {
        prefix_a
    };
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let ingress = RootTreeInvocationV2 {
        invocation: InvocationId([0xB7; 32]),
        target: actor,
        method: "start".into(),
        arguments,
        proof_requested: false,
    };
    let follower_peer = client_network.peer_for_prefix(follower).unwrap();
    let reply = client_network
        .send_invoke(
            follower_peer,
            ServiceId::REGISTRY.0,
            ServiceId::new(follower, local_id).0,
            Vec::new(),
            ingress.encode(),
        )
        .recv_timeout(Duration::from_secs(120))
        .expect("follower ingress redirects and commits through the leader");
    assert_eq!(Value::try_decode(&reply), Some(Value::Unit));

    // The delegation wire is node-internal. A normal authenticated client is
    // not a voter and therefore cannot assert System (or any other origin) to
    // the leader directly.
    let mut forged_arguments = vec![vos::value::TAG_DYNAMIC];
    forged_arguments.extend_from_slice(&Msg::new("origin_kind").encode());
    let forged_ingress = RootTreeInvocationV2 {
        invocation: InvocationId([0xB8; 32]),
        target: actor,
        method: "origin_kind".into(),
        arguments: forged_arguments,
        proof_requested: false,
    };
    let mut forged_delegation = b"VRD2".to_vec();
    forged_delegation.extend_from_slice(&[1, 3]); // preserve envelope + Origin::System
    forged_delegation.extend_from_slice(&forged_ingress.encode());
    let leader_peer = client_network.peer_for_prefix(leader).unwrap();
    let refused = client_network
        .send_invoke(
            leader_peer,
            ServiceId::REGISTRY.0,
            ServiceId::new(leader, local_id).0,
            Vec::new(),
            forged_delegation,
        )
        .recv_timeout(Duration::from_secs(10))
        .expect("the leader answers an unauthorized delegation fail-closed");
    assert!(refused.is_empty());

    let follower_node = if follower == prefix_a {
        &node_a
    } else {
        &node_b
    };
    {
        use vos::ActorReference;

        let mut invoker = follower_node;
        let mut handle = host_greeter_surface::GreeterRef::bind(actor, &mut invoker);
        vos::block_on(handle.start())
            .expect("the typed actor API follows a follower redirect to the leader");
        assert_eq!(
            vos::block_on(handle.origin_kind())
                .expect("the redirected typed call returns the actor result"),
            3,
            "a local System origin must remain observable after Raft forwarding",
        );
    }
    let mut missing = vec![vos::value::TAG_DYNAMIC];
    missing.extend_from_slice(&Msg::new("missing_method").encode());
    let missing_result = follower_node.invoke_actor(actor, missing);
    assert!(
        matches!(missing_result, Err(ClientError::NotFound)),
        "a redirected typed call preserves the leader's failure status; got {missing_result:?}",
    );

    let results_a = node_a.collect();
    let results_b = node_b.collect();
    assert!(results_a.into_iter().all(|result| result.is_ok()));
    assert!(results_b.into_iter().all(|result| result.is_ok()));
    for image in [&image_a, &image_b] {
        let mut name = image.file_name().unwrap().to_os_string();
        name.push(".private-inputs");
        let private_dir = image.with_file_name(name);
        let retained = std::fs::read_dir(private_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(
            retained, 0,
            "every voter retires its private ingress after applying the terminal entry",
        );
    }
    client_network.join();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn raft_follower_registers_before_genesis_and_restores_caught_up_admission_time() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([119; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([120; 32]),
            root_service: RootServiceId([121; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([122; 32]),
            authenticator: vec![123],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-root-follower-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();

    // Build the leader's authoritative image with a floor deliberately ahead
    // of wall time. The follower must learn this floor from catch-up, not from
    // registration or its local clock.
    let source_log_path = directory.join("source.redb");
    let source_log = RaftAccumulateLogV2::open(&source_log_path, RaftConfig::default()).unwrap();
    let mut source = LocalRootTreeServiceV2::open_raft(
        config.clone(),
        FailableCommittedImages::default(),
        source_log,
    )
    .unwrap();
    source.store_mut().install_proof_verifier(|_, _| false);
    let committed_floor = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    source
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([124; 32]),
            workflow_step: 0,
            logical_timeslot: committed_floor,
            target: actor,
            method: "start".into(),
            arguments: arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .unwrap();
    let source_image = source.store().snapshot_bytes();
    drop(source.into_backend());
    let mut source_log =
        RaftAccumulateLogV2::open(&source_log_path, RaftConfig::default()).unwrap();
    let source_index = source_log.applied_index().unwrap();
    assert_eq!(source_index, 3);
    drop(source_log);

    // Start a real non-writable worker with no committed genesis. Opening the
    // root returns an intentionally headerless service, which registration
    // must retain until a leader snapshot arrives.
    let follower_db = Arc::new(redb::Database::create(directory.join("follower.redb")).unwrap());
    let raft_config = RaftConfig {
        me: 0xBEEF,
        members: vec![0xBEEF],
        election_timeout_ms: (5_000, 6_000),
        heartbeat_interval_ms: 100,
        replication_id: [0xE2; 32],
        propose_timeout_ms: 2_000,
    };
    let (apply_tx, apply_rx) = std::sync::mpsc::channel();
    let worker = RaftWorker::spawn(
        follower_db.clone(),
        WorkerConfig {
            me: raft_config.me,
            members: raft_config.members.clone(),
            replication_id: raft_config.replication_id,
            election_timeout_ms: raft_config.election_timeout_ms,
            heartbeat_interval_ms: raft_config.heartbeat_interval_ms,
        },
        None,
        Some(apply_tx),
    );
    let worker_handle = worker.handler();
    assert_eq!(worker_handle.role(), Role::Follower);
    let follower_log =
        RaftAccumulateLogV2::from_worker(follower_db, raft_config, worker, apply_rx).unwrap();
    let backend = SharedCommittedImages::default();
    let follower =
        LocalRootTreeServiceV2::open_raft(config, backend.clone(), follower_log).unwrap();
    assert!(follower.store().header().unwrap().is_none());

    let route = ServiceId::new(0, 0x3400);
    let mut node = VosNode::new();
    node.register_v2_root_at_id("raft-follower-v2", follower, route, false)
        .expect("a Raft follower may register while waiting for genesis");

    let snapshot = CommittedServiceSnapshotV2 {
        applied_index: source_index,
        service_image: source_image,
        proof_artifacts: vec![],
    };
    let installed = worker_handle.install_snapshot(
        &[0xE2; 32],
        0xCAFE,
        1,
        source_index,
        1,
        0,
        true,
        snapshot.encode(),
        vec![0xBEEF],
        None,
    );
    assert_eq!(installed.term, 1);
    let election_deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while worker_handle.role() != Role::Leader && std::time::Instant::now() < election_deadline {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert_eq!(worker_handle.role(), Role::Leader);

    use vos::ActorReference;
    let mut invoker = &node;
    let mut handle = host_greeter_surface::GreeterRef::bind(actor, &mut invoker);
    vos::block_on(handle.start()).expect("caught-up follower admits work after taking leadership");
    let results = node.collect();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());
    drop(worker_handle);

    let image = backend.0.lock().unwrap().clone().unwrap();
    let restored = LocalJamStoreV2::from_snapshot(LocalJamStoreSnapshotV2::decode(&image).unwrap());
    assert_eq!(
        restored
            .header()
            .unwrap()
            .unwrap()
            .admission_timeslot_high_water,
        committed_floor + 1,
        "post-catch-up ingress must allocate strictly above the replicated floor"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_routes_canonical_actor_ids_through_the_guest_owned_root_service() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([103; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([104; 32]),
            root_service: RootServiceId([105; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([106; 32]),
            authenticator: vec![107],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let backend = SharedCommittedImages::default();
    let mut service = LocalRootTreeServiceV2::open(config.clone(), backend.clone())
        .expect("signed root installs before node registration");
    assert_eq!(
        service
            .root_method_policy("start")
            .unwrap()
            .map(|policy| (policy.public, policy.attested)),
        Some((true, false))
    );

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let durable_floor = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 10_000;
    let seeded = service
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([111; 32]),
            workflow_step: 0,
            logical_timeslot: durable_floor,
            target: actor,
            method: "start".into(),
            arguments: arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("seed a durable admission floor above the next wall-clock slot");
    service
        .acknowledge_publication(seeded.publication.as_ref().unwrap())
        .unwrap();
    assert_eq!(
        service
            .store()
            .header()
            .unwrap()
            .unwrap()
            .admission_timeslot_high_water,
        durable_floor
    );

    let route = ServiceId::new(0, 0x3300);
    let mut node = VosNode::new();
    node.register_v2_root_at_id("greeter-v2", service, route, false)
        .expect("canonical root route registers");

    use vos::ActorReference;
    let mut invoker = &node;
    let mut handle = host_greeter_surface::GreeterRef::bind(actor, &mut invoker);
    vos::block_on(handle.start())
        .expect("bound ActorId handle crosses physical Refine and Accumulate");
    assert!(matches!(
        node.invoke_actor(ActorId([108; 32]), arguments.clone()),
        Err(ClientError::NotFound)
    ));

    let malformed = vos::v2::RootTreeInvocationV2 {
        invocation: InvocationId([109; 32]),
        target: actor,
        method: "other".into(),
        arguments,
        proof_requested: false,
    };
    assert!(
        node.invoke(route, malformed.encode()).is_none(),
        "the route rejects a method that does not match the canonical actor message"
    );

    let mut duplicate_config = config.clone();
    duplicate_config.service.root_service = RootServiceId([110; 32]);
    let duplicate =
        LocalRootTreeServiceV2::open(duplicate_config, SharedCommittedImages::default())
            .expect("independent service installs before duplicate-identity check");
    assert!(matches!(
        node.register_v2_root_at_id(
            "duplicate-greeter-v2",
            duplicate,
            ServiceId::new(0, 0x3301),
            false,
        ),
        Err(V2NodeRegistrationError::ActorAlreadyRegistered(found)) if found == actor
    ));

    let results = node.collect();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());

    let reopened = LocalRootTreeServiceV2::open(config, backend)
        .expect("node-owned service state reopens from committed bytes");
    let header = reopened.store().header().unwrap().unwrap();
    assert_eq!(header.revision, 2);
    assert!(
        header.admission_timeslot_high_water > durable_floor,
        "registration must restore the node allocator above durable work"
    );
    assert!(
        reopened.pending_publications().unwrap().is_empty(),
        "the direct reply is acknowledged only after its channel accepts it"
    );
}

#[test]
fn node_attested_root_requires_an_explicit_producer_and_returns_the_committed_package() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Local, 0x71);
    let backend = SharedCommittedImages::default();
    let service = LocalRootTreeServiceV2::open(config.clone(), backend.clone()).unwrap();
    let route = ServiceId::new(0, 0x3310);

    let mut unavailable = VosNode::new();
    unavailable
        .register_v2_root_at_id("attested-root-v2", service, route, false)
        .unwrap();
    assert!(
        matches!(
            unavailable.invoke_actor_attested(request.target, request.arguments.clone()),
            Err(ClientError::Forbidden)
        ),
        "ordinary registration remains fail-closed for signed attested methods"
    );
    assert!(unavailable.collect().iter().all(AgentResult::is_ok));

    let service = LocalRootTreeServiceV2::open(config.clone(), backend.clone()).unwrap();
    let proof = canonical_test_proof_manifest(0x81);
    let mut node = VosNode::new();
    node.register_v2_root_at_id_with_producer(
        "attested-root-v2",
        service,
        route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    let result = node
        .invoke_actor_attested(request.target, request.arguments)
        .expect("the node proves and returns one guest-committed package");
    assert_eq!(result.value, Value::U32(7));
    assert_eq!(result.proof, proof);
    assert_eq!(result.statement.actor, request.target);
    assert_eq!(result.statement.method, "attested_value");
    assert_eq!(result.statement.producer, result.producer);
    assert_eq!(result.statement.producer_name, result.producer_name);
    assert!(node.collect().iter().all(AgentResult::is_ok));

    let reopened = LocalRootTreeServiceV2::open(config, backend)
        .expect("the node's proof and acknowledgement survive its root thread");
    assert!(reopened.pending_publications().unwrap().is_empty());
}

#[test]
fn local_registration_reverifies_conformance_proof_history_before_exposing_the_root() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Local, 0x72);
    let backend = SharedProofCommittedImages::default();
    let mut service = LocalRootTreeServiceV2::open(config, backend).unwrap();
    let conformance_proof = canonical_test_proof_manifest(0x91);
    service
        .invoke_attested(
            request,
            &mut CanonicalTestProofProducer {
                proof: conformance_proof,
                calls: 0,
            },
        )
        .expect("the explicit conformance seam accepts its locally produced proof");
    assert_eq!(service.pending_publications().unwrap().len(), 1);

    let mut node = VosNode::new();
    assert!(matches!(
        node.register_v2_root_at_id_with_producer(
            "attested-root-v2",
            service,
            ServiceId::new(0, 0x3311),
            false,
            CanonicalTestProofProducer {
                proof: canonical_test_proof_manifest(0x92),
                calls: 0,
            },
        ),
        Err(V2NodeRegistrationError::CorruptServiceStore)
    ));
    assert!(
        node.collect().is_empty(),
        "the rejected root was never exposed"
    );
}

#[test]
fn local_registration_reverifies_pending_proofs_despite_image_provenance() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Local, 0x75);
    let backend = SharedProofCommittedImages::default();
    let mut service = LocalRootTreeServiceV2::open(config.clone(), backend).unwrap();
    let proof = canonical_test_proof_manifest(0x95);
    let expected_proof = proof.clone();
    service
        .store_mut()
        .install_proof_verifier(move |request, candidate| {
            request.proof_blob.matches(candidate) && candidate == expected_proof
        });
    service
        .invoke_attested(
            request,
            &mut CanonicalTestProofProducer {
                proof: proof.clone(),
                calls: 0,
            },
        )
        .expect("the production verifier seals the proof-bearing publication");
    assert_eq!(service.pending_publications().unwrap().len(), 1);

    let backend = service.into_backend();
    let persisted = backend.0.lock().unwrap();
    let image = persisted.image.clone();
    let mut corrupt_proofs = persisted.proofs.clone();
    drop(persisted);
    *corrupt_proofs.values_mut().next().unwrap() = b"corrupt proof".to_vec();

    for (case, proofs) in [("missing", BTreeMap::new()), ("corrupt", corrupt_proofs)] {
        let backend =
            SharedProofCommittedImages(Arc::new(Mutex::new(SharedProofCommittedImageState {
                image: image.clone(),
                proofs,
            })));
        let service = LocalRootTreeServiceV2::open(config.clone(), backend)
            .expect("the marked service image itself remains recoverable");
        let mut node = VosNode::new();
        assert!(
            matches!(
                node.register_v2_root_at_id_with_producer(
                    "attested-root-v2",
                    service,
                    ServiceId::new(0, 0x3314),
                    false,
                    CanonicalTestProofProducer {
                        proof: proof.clone(),
                        calls: 0,
                    },
                ),
                Err(V2NodeRegistrationError::CorruptServiceStore)
            ),
            "a {case} live publication proof must reject registration"
        );
        assert!(
            node.collect().is_empty(),
            "a root with a {case} live publication proof was never exposed"
        );
    }
}

#[test]
fn raft_registration_reverifies_current_conformance_proof_history_before_exposing_the_root() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Raft, 0x74);
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-raft-proof-cutover-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db = Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap());
    let backend = SharedProofCommittedImages::default();
    let member = 0x76u16;
    let raft_config = RaftConfig {
        me: member,
        members: vec![member],
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id: [0x77; 32],
        propose_timeout_ms: 2_000,
    };
    let log = RaftAccumulateLogV2::from_db_arc(db.clone(), raft_config.clone()).unwrap();
    let mut service = LocalRootTreeServiceV2::open_raft(config.clone(), backend.clone(), log)
        .expect("the explicit conformance seam opens the Raft root");
    service
        .invoke_attested(
            request,
            &mut CanonicalTestProofProducer {
                proof: canonical_test_proof_manifest(0x93),
                calls: 0,
            },
        )
        .expect("conformance accepts and applies its locally produced proof");
    assert_eq!(service.pending_publications().unwrap().len(), 1);
    let backend = service.into_backend();

    let mut node = VosNode::new();
    assert!(
        node.register_v2_raft_root_at_id_with_producer(
            "attested-raft-root-v2".into(),
            config,
            backend,
            db,
            raft_config,
            ServiceId::new(member, 0x3313),
            false,
            CanonicalTestProofProducer {
                proof: canonical_test_proof_manifest(0x94),
                calls: 0,
            },
        )
        .is_err(),
        "a current apply cursor cannot bypass production revalidation"
    );
    assert!(
        node.collect().is_empty(),
        "the rejected Raft root was never exposed"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_attested_raft_root_orders_the_proved_apply() {
    let (config, request) = attested_root_fixture(ConsistencyModeV2::Raft, 0x73);
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-node-attested-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db = Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap());
    let member = 0x77u16;
    let route = ServiceId::new(member, 0x3312);
    let mut node = VosNode::new();
    let proof = canonical_test_proof_manifest(0x82);
    node.register_v2_raft_root_at_id_with_producer(
        "attested-raft-root-v2".into(),
        config,
        FailableCommittedImages::default(),
        db,
        RaftConfig {
            me: member,
            members: vec![member],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0x78; 32],
            propose_timeout_ms: 2_000,
        },
        route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(350));
    let result = node
        .invoke_actor_attested(request.target, request.arguments)
        .expect("the current leader proves before proposing the final Apply");
    assert_eq!(result.value, Value::U32(7));
    assert_eq!(result.proof, proof);
    assert!(node.collect().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

fn attested_node_transport_fixture(
    consistency: ConsistencyModeV2,
    salt: u8,
) -> (
    LocalRootTreeConfigV2,
    LocalRootTreeConfigV2,
    ActorId,
    ActorId,
) {
    let actor_elf = workflow_v2_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([salt; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([salt.wrapping_add(1); 32]),
        root_service: RootServiceId([salt.wrapping_add(2); 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([salt.wrapping_add(3); 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidenceV2::SystemCapability {
        capability: SystemCapabilityId([salt.wrapping_add(4); 32]),
        authenticator: vec![salt.wrapping_add(5)],
    };
    let source = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity,
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "private-age",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        install_authorization: install_authorization.clone(),
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let destination = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name: "private-age".into(),
        consistency,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    (source, destination, source_actor, destination_actor)
}

#[test]
fn node_routes_an_attested_durable_call_and_proof_back_into_the_waiting_actor() {
    let (source_config, destination_config, source_actor, _) =
        attested_node_transport_fixture(ConsistencyModeV2::Local, 0xD1);
    let source_backend = SharedProofCommittedImages::default();
    let destination_backend = SharedProofCommittedImages::default();
    let source =
        LocalRootTreeServiceV2::open(source_config.clone(), source_backend.clone()).unwrap();
    let destination =
        LocalRootTreeServiceV2::open(destination_config.clone(), destination_backend.clone())
            .unwrap();
    let source_route = ServiceId::new(0, 0x3510);
    let destination_route = ServiceId::new(0, 0x3511);
    let proof = canonical_test_proof_manifest(0x83);
    let mut node = VosNode::new();
    node.register_v2_root_at_id_with_verifier(
        "attested-source-v2",
        source,
        source_route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    node.register_v2_root_at_id_with_producer(
        "private-age",
        destination,
        destination_route,
        false,
        CanonicalTestProofProducer { proof, calls: 0 },
    )
    .unwrap();

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
    let ingress = RootTreeInvocationV2 {
        invocation: InvocationId([0xD7; 32]),
        target: source_actor,
        method: "root_await_attested_peer".into(),
        arguments,
        proof_requested: false,
    };
    let invoker = node.invoke_handle();
    let shutdown = node.shutdown_handle();
    let request = std::thread::spawn(move || {
        let result =
            invoker.invoke_with_timeout(source_route, ingress.encode(), Duration::from_secs(30));
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        result
    });
    node.run_forever();
    let results = node.collect();
    assert!(results.iter().all(AgentResult::is_ok));
    let reply = request.join().unwrap();
    let source = LocalRootTreeServiceV2::open(source_config, source_backend).unwrap();
    let destination =
        LocalRootTreeServiceV2::open(destination_config, destination_backend).unwrap();
    let source_publications = source.pending_publications().unwrap();
    let destination_publications = destination.pending_publications().unwrap();
    let destination_inbox = destination.store().pending_inbox_calls().unwrap();
    assert_eq!(
        reply,
        Some(Value::Bool(true).encode()),
        "the destination proof reaches the exact suspended caller",
    );
    assert!(source_publications.is_empty());
    assert!(destination_publications.is_empty());
    assert!(destination_inbox.is_empty());
}

#[test]
fn node_raft_transport_orders_attested_inbox_and_reply_proof_on_both_roots() {
    let (source_config, destination_config, source_actor, _) =
        attested_node_transport_fixture(ConsistencyModeV2::Raft, 0xE1);
    let source_backend = SharedProofCommittedImages::default();
    let destination_backend = SharedProofCommittedImages::default();
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-node-attested-raft-route-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source_db = Arc::new(redb::Database::create(directory.join("source.redb")).unwrap());
    let destination_db =
        Arc::new(redb::Database::create(directory.join("destination.redb")).unwrap());
    let member = 0x79u16;
    let source_route = ServiceId::new(member, 0x3520);
    let destination_route = ServiceId::new(member, 0x3521);
    let raft_config = |replication_id| RaftConfig {
        me: member,
        members: vec![member],
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id,
        propose_timeout_ms: 2_000,
    };
    let proof = canonical_test_proof_manifest(0x84);
    let mut node = VosNode::new();
    node.register_v2_raft_root_at_id_with_verifier(
        "attested-raft-source-v2".into(),
        source_config.clone(),
        source_backend.clone(),
        source_db.clone(),
        raft_config([0xEA; 32]),
        source_route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    node.register_v2_raft_root_at_id_with_producer(
        "attested-raft-destination-v2".into(),
        destination_config,
        destination_backend.clone(),
        destination_db,
        raft_config([0xEB; 32]),
        destination_route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(500));

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
    let ingress = RootTreeInvocationV2 {
        invocation: InvocationId([0xEC; 32]),
        target: source_actor,
        method: "root_await_attested_peer".into(),
        arguments,
        proof_requested: false,
    };
    let invoker = node.invoke_handle();
    let shutdown = node.shutdown_handle();
    let request = std::thread::spawn(move || {
        let result =
            invoker.invoke_with_timeout(source_route, ingress.encode(), Duration::from_secs(45));
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        result
    });
    node.run_forever();
    let results = node.collect();
    assert!(results.iter().all(AgentResult::is_ok));
    assert_eq!(
        request.join().unwrap(),
        Some(Value::Bool(true).encode()),
        "the exact package reaches the caller after both roots order their Apply"
    );
    assert!(
        source_backend
            .0
            .lock()
            .unwrap()
            .proofs
            .values()
            .any(|candidate| candidate == &proof),
        "the caller replica durably hydrates the proof before ordering resume"
    );
    assert!(
        destination_backend
            .0
            .lock()
            .unwrap()
            .proofs
            .values()
            .any(|candidate| candidate == &proof),
        "the producer replica retains the proof until reply acknowledgement"
    );

    // Model a follower which installed the compacted service image but did
    // not retain the proof for a completed reply admission. The exact image
    // carries durable production-verifier provenance, so reopening at the
    // current Raft cursor must not demand intentionally pruned history.
    let snapshot_only_backend =
        SharedProofCommittedImages(Arc::new(Mutex::new(SharedProofCommittedImageState {
            image: source_backend.0.lock().unwrap().image.clone(),
            proofs: BTreeMap::new(),
        })));
    let mut restarted = VosNode::new();
    restarted
        .register_v2_raft_root_at_id_with_verifier(
            "attested-raft-source-v2".into(),
            source_config,
            snapshot_only_backend.clone(),
            source_db,
            raft_config([0xEA; 32]),
            source_route,
            false,
            CanonicalTestProofProducer { proof, calls: 0 },
        )
        .expect("a snapshot-caught production replica reopens without pruned admission proofs");
    assert!(snapshot_only_backend.0.lock().unwrap().proofs.is_empty());
    assert!(restarted.collect().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn promoted_raft_voter_keeps_its_producer_after_taking_leadership() {
    let (source_config, destination_config, source_actor, destination_actor) =
        attested_node_transport_fixture(ConsistencyModeV2::Raft, 0xF1);
    let source_backend = SharedProofCommittedImages::default();
    let destination_backend = SharedProofCommittedImages::default();
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-promoted-attested-voter-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source_db = Arc::new(redb::Database::create(directory.join("source.redb")).unwrap());
    let destination_db =
        Arc::new(redb::Database::create(directory.join("destination.redb")).unwrap());
    let member = 0x7Au16;
    let source_route = ServiceId::new(member, 0x3530);
    let destination_route = ServiceId::new(member, 0x3531);
    let proof = canonical_test_proof_manifest(0x85);
    let mut node = VosNode::new();
    node.register_v2_raft_root_at_id_with_verifier(
        "promoted-attested-source-v2".into(),
        source_config,
        source_backend,
        source_db,
        RaftConfig {
            me: member,
            members: vec![member],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0xFA; 32],
            propose_timeout_ms: 2_000,
        },
        source_route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    node.register_v2_raft_root_at_id_after_local_attach_with_producer(
        "promoted-attested-destination-v2".into(),
        destination_config,
        destination_backend.clone(),
        destination_db,
        RaftConfig {
            me: member,
            members: vec![member],
            // Ensure preparation observes a follower. The promotion callback
            // then waits for this replica to take leadership before its route
            // and proof capability become public together.
            election_timeout_ms: (400, 600),
            heartbeat_interval_ms: 20,
            replication_id: [0xFB; 32],
            propose_timeout_ms: 2_000,
        },
        destination_route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
        move |worker, shutdown| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while worker.role() != Role::Leader {
                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("cancelled while waiting for leadership".into());
                }
                if std::time::Instant::now() >= deadline {
                    return Err("promoted voter did not take leadership".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        },
    )
    .unwrap();

    let invoker = node.invoke_handle();
    let shutdown = node.shutdown_handle();
    let request = std::thread::spawn(move || {
        let direct_arguments = {
            let mut arguments = vec![vos::value::TAG_DYNAMIC];
            arguments.extend_from_slice(&Msg::new("attested_peer_value").encode());
            arguments
        };
        let direct_ingress = RootTreeInvocationV2 {
            invocation: InvocationId([0xFC; 32]),
            target: destination_actor,
            method: "attested_peer_value".into(),
            arguments: direct_arguments,
            proof_requested: true,
        }
        .encode();
        let route_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let direct = loop {
            if let Some(reply) = invoker.invoke_with_timeout(
                destination_route,
                direct_ingress.clone(),
                Duration::from_secs(30),
            ) {
                break reply;
            }
            assert!(
                std::time::Instant::now() < route_deadline,
                "promoted root route was not published"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let direct = RootTreeAttestedResultV2::decode(&direct)
            .expect("the promoted leader returns its committed attestation");

        let mut durable_arguments = vec![vos::value::TAG_DYNAMIC];
        durable_arguments.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
        let durable = invoker.invoke_with_timeout(
            source_route,
            RootTreeInvocationV2 {
                invocation: InvocationId([0xFD; 32]),
                target: source_actor,
                method: "root_await_attested_peer".into(),
                arguments: durable_arguments,
                proof_requested: false,
            }
            .encode(),
            Duration::from_secs(45),
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        (direct, durable)
    });
    node.run_forever();
    assert!(node.collect().iter().all(AgentResult::is_ok));
    let (direct, durable) = request.join().unwrap();
    assert_eq!(Value::try_decode(&direct.reply), Some(Value::U32(7)));
    assert_eq!(direct.proof, proof);
    assert_eq!(durable, Some(Value::Bool(true).encode()));
    assert!(
        destination_backend
            .0
            .lock()
            .unwrap()
            .proofs
            .values()
            .any(|candidate| candidate == &proof),
        "the promoted leader durably produces both direct and inbox proofs"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_routes_an_ordinary_cross_root_await_through_guest_accumulate() {
    let actor_elf = probe_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([0xB1; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xB3; 32]),
        root_service: RootServiceId([0xB4; 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([0xB5; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidenceV2::SystemCapability {
        capability: SystemCapabilityId([0xB6; 32]),
        authenticator: vec![0xB7],
    };
    let source_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        install_authorization: install_authorization.clone(),
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let destination_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let source_backend = SharedCommittedImages::default();
    let destination_backend = SharedCommittedImages::default();
    let source = LocalRootTreeServiceV2::open(source_config.clone(), source_backend.clone())
        .expect("source root installs");

    let source_route = ServiceId::new(0, 0x3500);
    let destination_route = ServiceId::new(0, 0x3501);
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer_without_deadline").encode());
    let invocation = RootTreeInvocationV2 {
        invocation: InvocationId([0xB8; 32]),
        target: source_actor,
        method: "await_peer_without_deadline".into(),
        arguments,
        proof_requested: false,
    };
    let invocation_bytes = invocation.encode();

    // First run: the source commits its exact await checkpoint while the
    // destination route is unavailable. Shutdown drops only the process-local
    // waiting channel; the guest-owned publication remains recoverable.
    let mut first_node = VosNode::new();
    first_node
        .register_v2_root_at_id("workflow-source-v2", source, source_route, false)
        .unwrap();
    let first_invoker = first_node.invoke_handle();
    let first_invocation = invocation_bytes.clone();
    let first_request = std::thread::spawn(move || {
        first_invoker.invoke_with_timeout(source_route, first_invocation, Duration::from_secs(20))
    });
    // Physical Refine/Accumulate work can remain inside one root thread for
    // longer than the router's ordinary 500 ms unit-test idle window.
    first_node.run_until_idle(Duration::from_secs(3));
    let first_results = first_node.collect();
    assert_eq!(first_results.len(), 1);
    assert!(first_results.iter().all(AgentResult::is_ok));
    assert!(first_request.join().unwrap().is_none());

    let source = LocalRootTreeServiceV2::open(source_config.clone(), source_backend.clone())
        .expect("source root reopens with its suspended publication");
    assert_eq!(source.pending_publications().unwrap().len(), 1);
    let destination =
        LocalRootTreeServiceV2::open(destination_config.clone(), destination_backend.clone())
            .expect("destination root installs");

    // Second run: the caller retries the exact InvocationId. The root
    // reattaches it to the committed checkpoint without replaying PC 0, then
    // the node redrives delivery and the finalized reply across both roots.
    let mut node = VosNode::new();
    node.register_v2_root_at_id("workflow-source-v2", source, source_route, false)
        .unwrap();
    node.register_v2_root_at_id(
        "workflow-destination-v2",
        destination,
        destination_route,
        false,
    )
    .unwrap();
    let invoker = node.invoke_handle();
    let request = std::thread::spawn(move || {
        invoker.invoke_with_timeout(source_route, invocation_bytes, Duration::from_secs(20))
    });
    node.run_until_idle(Duration::from_secs(3));
    let results = node.collect();
    let reply = request.join().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(AgentResult::is_ok));
    let source = LocalRootTreeServiceV2::open(source_config, source_backend)
        .expect("source root reopens after routed reply");
    let destination = LocalRootTreeServiceV2::open(destination_config, destination_backend)
        .expect("destination root reopens after routed reply");
    assert!(
        reply.is_some(),
        "durable cross-root workflow returns to its original caller: {reply:?}"
    );
    let reply = reply.unwrap();
    assert_eq!(reply, Value::U32(8).encode());

    assert!(source.pending_publications().unwrap().is_empty());
    assert!(destination.pending_publications().unwrap().is_empty());
    assert!(
        destination
            .store()
            .pending_inbox_calls()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn node_routes_a_crdt_cross_root_await_and_acknowledges_both_publications() {
    let actor_elf = crdt_counter_v2_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([0xE1; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xE2; 32]),
        root_service: RootServiceId([0xE3; 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([0xE4; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidenceV2::SystemCapability {
        capability: SystemCapabilityId([0xE5; 32]),
        authenticator: vec![0xE6],
    };
    let source_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyModeV2::Crdt,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        install_authorization: install_authorization.clone(),
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let destination_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyModeV2::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let source_backend = SharedCommittedImages::default();
    let destination_backend = SharedCommittedImages::default();
    let source = LocalRootTreeServiceV2::open(source_config.clone(), source_backend.clone())
        .expect("CRDT source root installs");
    let destination =
        LocalRootTreeServiceV2::open(destination_config.clone(), destination_backend.clone())
            .expect("CRDT destination root installs");

    let source_route = ServiceId::new(0, 0x3510);
    let destination_route = ServiceId::new(0, 0x3511);
    let mut node = VosNode::new();
    node.register_v2_root_at_id("crdt-workflow-source-v2", source, source_route, false)
        .unwrap();
    node.register_v2_root_at_id(
        "crdt-workflow-destination-v2",
        destination,
        destination_route,
        false,
    )
    .unwrap();

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("increment_around_peer")
            .with("before", 1u64)
            .with("after", 2u64)
            .encode(),
    );
    let invoker = node.invoke_handle();
    let request = std::thread::spawn(move || {
        invoker.invoke_with_timeout(
            source_route,
            RootTreeInvocationV2 {
                invocation: InvocationId([0xE7; 32]),
                target: source_actor,
                method: "increment_around_peer".into(),
                arguments,
                proof_requested: false,
            }
            .encode(),
            Duration::from_secs(60),
        )
    });
    node.run_until_idle(Duration::from_secs(15));
    let results = node.collect();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(AgentResult::is_ok));
    assert_eq!(request.join().unwrap(), Some(Value::I64(3).encode()));

    let source = LocalRootTreeServiceV2::open(source_config, source_backend)
        .expect("CRDT source reopens after routed reply");
    let destination = LocalRootTreeServiceV2::open(destination_config, destination_backend)
        .expect("CRDT destination reopens after routed reply");
    assert!(source.pending_publications().unwrap().is_empty());
    assert!(destination.pending_publications().unwrap().is_empty());
    assert!(
        destination
            .store()
            .pending_inbox_calls()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn node_routes_networkless_single_voter_raft_roots() {
    let actor_elf = probe_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([0xBA; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xBB; 32]),
        root_service: RootServiceId([0xBC; 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([0xBD; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidenceV2::SystemCapability {
        capability: SystemCapabilityId([0xBE; 32]),
        authenticator: vec![0xBF],
    };
    let source_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        install_authorization: install_authorization.clone(),
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let destination_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };

    let directory = std::env::temp_dir().join(format!(
        "vos-v2-networkless-raft-transport-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let member = 0xCAFE;
    let source_route = ServiceId::new(member, 0x3600);
    let destination_route = ServiceId::new(member, 0x3601);
    let raft_config = |replication_id| RaftConfig {
        me: member,
        members: vec![member],
        election_timeout_ms: (25, 50),
        heartbeat_interval_ms: 10,
        replication_id,
        propose_timeout_ms: 5_000,
    };
    let mut node = VosNode::new();
    node.register_v2_raft_root_at_id(
        "networkless-raft-source".into(),
        source_config,
        FailableCommittedImages::default(),
        Arc::new(redb::Database::create(directory.join("source.redb")).unwrap()),
        raft_config([0xC1; 32]),
        source_route,
        false,
    )
    .unwrap();
    node.register_v2_raft_root_at_id(
        "networkless-raft-destination".into(),
        destination_config,
        FailableCommittedImages::default(),
        Arc::new(redb::Database::create(directory.join("destination.redb")).unwrap()),
        raft_config([0xC2; 32]),
        destination_route,
        false,
    )
    .unwrap();
    assert!(
        node.network().is_none(),
        "the regression must not accidentally attach a network"
    );

    let shutdown = node.shutdown_handle();
    let invoke = node.invoke_handle();
    let runner = std::thread::spawn(move || {
        node.run_forever();
        node.collect()
    });
    std::thread::sleep(Duration::from_millis(250));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer_without_deadline").encode());
    let reply = invoke
        .invoke_with_timeout(
            source_route,
            RootTreeInvocationV2 {
                invocation: InvocationId([0xC3; 32]),
                target: source_actor,
                method: "await_peer_without_deadline".into(),
                arguments,
                proof_requested: false,
            }
            .encode(),
            Duration::from_secs(120),
        )
        .expect("networkless Raft roots complete delivery, reply, and acknowledgements");
    assert_eq!(reply, Value::U32(8).encode());

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(runner.join().unwrap().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_routes_raft_cross_root_reply_between_different_leaders() {
    let actor_elf = probe_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([0xC1; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xC2; 32]),
        root_service: RootServiceId([0xC3; 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([0xC4; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidenceV2::SystemCapability {
        capability: SystemCapabilityId([0xC5; 32]),
        authenticator: vec![0xC6],
    };
    let source_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        install_authorization: install_authorization.clone(),
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let destination_config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity.clone(),
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyModeV2::Raft,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };

    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let peer_a = libp2p::PeerId::from(key_a.public());
    let prefix_a = vos::network::derive_node_prefix(&peer_a);
    let (key_b, peer_b, prefix_b) = loop {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = libp2p::PeerId::from(key.public());
        let prefix = vos::network::derive_node_prefix(&peer);
        if prefix != prefix_a {
            break (key, peer, prefix);
        }
    };
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let network_a = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let address_a = loop {
        if let Some(address) = network_a.listen_addrs().into_iter().next() {
            break address.with(libp2p::multiaddr::Protocol::P2p(peer_a));
        }
        assert!(std::time::Instant::now() < deadline, "node A did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    let network_b = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![address_a],
        auto_dial_mdns: false,
    });

    let mut node_a = VosNode::with_prefix(prefix_a);
    let mut node_b = VosNode::with_prefix(prefix_b);
    let registry_pvm =
        grey_transpiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
            .expect("committed space-registry ELF transpiles");
    let voters = [(prefix_a, peer_a.to_bytes()), (prefix_b, peer_b.to_bytes())];
    install_test_voter_registry(&mut node_a, registry_pvm.clone(), &voters);
    install_test_voter_registry(&mut node_b, registry_pvm, &voters);
    node_a.attach_network(network_a);
    node_b.attach_network(network_b);
    let network_a = node_a.network().unwrap();
    let network_b = node_b.network().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while (network_a.peer_for_prefix(prefix_b).is_none()
        || network_b.peer_for_prefix(prefix_a).is_none())
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(network_a.peer_for_prefix(prefix_b).is_some());
    assert!(network_b.peer_for_prefix(prefix_a).is_some());

    let directory = std::env::temp_dir().join(format!(
        "vos-v2-raft-root-transport-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source_replication = [0xC7; 32];
    let destination_replication = [0xC8; 32];
    let source_route = ServiceId::new(prefix_a, 0x3700);
    let destination_route = ServiceId::new(prefix_b, 0x3800);
    let raft_config = |me, replication_id| RaftConfig {
        me,
        members: vec![me],
        election_timeout_ms: (50, 100),
        heartbeat_interval_ms: 20,
        replication_id,
        propose_timeout_ms: 5_000,
    };
    node_a
        .register_v2_raft_root_at_id(
            "raft-workflow-source".into(),
            source_config,
            FailableCommittedImages::default(),
            Arc::new(redb::Database::create(directory.join("source.redb")).unwrap()),
            raft_config(prefix_a, source_replication),
            source_route,
            true,
        )
        .unwrap();
    node_b
        .register_v2_raft_root_at_id(
            "raft-workflow-destination".into(),
            destination_config,
            FailableCommittedImages::default(),
            Arc::new(redb::Database::create(directory.join("destination.redb")).unwrap()),
            raft_config(prefix_b, destination_replication),
            destination_route,
            true,
        )
        .unwrap();
    node_a
        .bind_v2_raft_actor_route(
            destination_actor,
            destination_identity,
            destination_replication,
            destination_route,
            peer_b.to_bytes(),
        )
        .unwrap();
    node_b
        .bind_v2_raft_actor_route(
            source_actor,
            source_identity,
            source_replication,
            source_route,
            peer_a.to_bytes(),
        )
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while (network_a
        .local_raft_status(&source_replication)
        .is_none_or(|status| status.role != vos::network::RaftRole::Leader)
        || network_b
            .local_raft_status(&destination_replication)
            .is_none_or(|status| status.role != vos::network::RaftRole::Leader))
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(15));
    }
    assert_eq!(
        network_a
            .local_raft_status(&source_replication)
            .map(|status| status.role),
        Some(vos::network::RaftRole::Leader)
    );
    assert_eq!(
        network_b
            .local_raft_status(&destination_replication)
            .map(|status| status.role),
        Some(vos::network::RaftRole::Leader)
    );

    let shutdown_a = node_a.shutdown_handle();
    let shutdown_b = node_b.shutdown_handle();
    let invoke = node_a.invoke_handle();
    let runner_a = std::thread::spawn(move || {
        node_a.run_forever();
        node_a.collect()
    });
    let runner_b = std::thread::spawn(move || {
        node_b.run_forever();
        node_b.collect()
    });
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer_without_deadline").encode());
    let reply = invoke
        .invoke_with_timeout(
            source_route,
            RootTreeInvocationV2 {
                invocation: InvocationId([0xC9; 32]),
                target: source_actor,
                method: "await_peer_without_deadline".into(),
                arguments,
                proof_requested: false,
            }
            .encode(),
            Duration::from_secs(120),
        )
        .expect("different Raft leaders complete delivery, reply, and both acknowledgements");
    assert_eq!(reply, Value::U32(8).encode());

    std::thread::sleep(Duration::from_millis(500));
    shutdown_a.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown_b.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(runner_a.join().unwrap().iter().all(AgentResult::is_ok));
    assert!(runner_b.join().unwrap().iter().all(AgentResult::is_ok));
    drop(network_a);
    drop(network_b);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_retries_a_direct_reply_publication_ack_after_the_caller_is_gone() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([0xD1; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([0xD2; 32]),
            root_service: RootServiceId([0xD3; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0xD4; 32]),
            authenticator: vec![0xD5],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let backend = SharedFailingCommittedImages::default();
    let service = LocalRootTreeServiceV2::open(config.clone(), backend.clone())
        .expect("direct-reply root installs");

    let route = ServiceId::new(0, 0x3700);
    let mut node = VosNode::new();
    node.register_v2_root_at_id("direct-ack-retry-v2", service, route, false)
        .unwrap();
    let registered_commits = backend.0.lock().unwrap().commit_attempts;
    // Admission and Apply are the next two commits; fail the publication Ack
    // after the reply has already reached and removed the direct caller. The
    // registration-time provenance commit is deliberately outside this
    // invocation fault sequence.
    backend.fail_at(registered_commits + 3);
    use vos::ActorReference;
    let mut invoker = &node;
    let mut handle = host_greeter_surface::GreeterRef::bind(actor, &mut invoker);
    vos::block_on(handle.start()).unwrap();

    // The caller channel is already consumed. A periodic retry must classify
    // its durable acceptance and retry only the failed acknowledgement.
    node.run_until_idle(Duration::from_secs(2));
    assert!(node.collect().iter().all(AgentResult::is_ok));
    let state = backend.0.lock().unwrap();
    assert_eq!(
        state.failures, 1,
        "commit attempts {}, pending failure {:?}",
        state.commit_attempts, state.fail_at
    );
    drop(state);
    let reopened = LocalRootTreeServiceV2::open(config, backend)
        .expect("the acknowledgement retry is durably recoverable");
    assert!(reopened.pending_publications().unwrap().is_empty());
}

#[test]
fn node_expires_and_resumes_an_unreachable_durable_call() {
    let actor_elf = probe_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([0xC1; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xC2; 32]),
        root_service: RootServiceId([0xC3; 32]),
        deployment,
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([0xC4; 32]),
        ..source_identity.clone()
    };
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: source_identity,
        root_actor: source_actor,
        actor_name,
        consistency: ConsistencyModeV2::Local,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity,
            destination_actor,
            producer,
            program,
        )],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0xC5; 32]),
            authenticator: vec![0xC6],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let backend = SharedFailingCommittedImages::default();
    let service = LocalRootTreeServiceV2::open(config.clone(), backend.clone())
        .expect("timeout source root installs");
    let installed_commits = backend.0.lock().unwrap().commit_attempts;
    // Admission, suspend, and expiration commit first. Fail the exact timeout
    // resume commit once: the deadline row is already gone, so recovery must
    // rediscover the durable expiration row independently on the next poll.
    backend.fail_at(installed_commits + 4);
    let route = ServiceId::new(0, 0x3600);
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 1_000;
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("await_peer_until")
            .with("deadline", deadline)
            .encode(),
    );
    let invocation = RootTreeInvocationV2 {
        invocation: InvocationId([0xC7; 32]),
        target: source_actor,
        method: "await_peer_until".into(),
        arguments,
        proof_requested: false,
    };

    let mut node = VosNode::new();
    node.register_v2_root_at_id("timeout-source-v2", service, route, false)
        .unwrap();
    let invoker = node.invoke_handle();
    let request = std::thread::spawn(move || {
        invoker.invoke_with_timeout(route, invocation.encode(), Duration::from_secs(20))
    });
    node.run_until_idle(Duration::from_secs(10));
    let results = node.collect();
    let reply = request.join().unwrap().unwrap_or_else(|| {
        let state = backend.0.lock().unwrap();
        panic!(
            "the node did not resume the exact handler with CallError::Timeout: \
             commit_attempts={}, failures={}, pending_failure={:?}",
            state.commit_attempts, state.failures, state.fail_at
        )
    });
    assert_eq!(reply, Value::U32(1).encode());
    assert!(results.iter().all(AgentResult::is_ok));
    assert_eq!(backend.0.lock().unwrap().failures, 1);

    let reopened = LocalRootTreeServiceV2::open(config, backend)
        .expect("timed-out source reopens from its durable image");
    assert!(reopened.pending_publications().unwrap().is_empty());
    assert!(
        reopened
            .store()
            .pending_call_deadlines()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn durable_crdt_root_tree_reattaches_an_exact_invocation_after_restart() {
    let actor_elf = crdt_counter_v2_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([97; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([98; 32]),
            root_service: RootServiceId([99; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([100; 32]),
            authenticator: vec![101],
        },
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("increment_around_two_yields")
            .with("amount", 2u64)
            .encode(),
    );
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([102; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: actor,
        method: "increment_around_two_yields".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };

    let mut service =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("fresh CRDT root installs through physical Accumulate");
    let committed = service
        .invoke(request.clone())
        .expect("CRDT slice commits through physical Refine and Accumulate");
    assert!(!committed.duplicate);
    assert!(!committed.receipt.resulting_crdt_heads.is_empty());

    let mut replica =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("independent CRDT replica installs the same root tree");
    let mut prior_arguments = vec![vos::value::TAG_DYNAMIC];
    prior_arguments.extend_from_slice(&Msg::new("increment").with("amount", 5u64).encode());
    replica
        .invoke(LocalWorkRequestV2 {
            invocation: InvocationId([103; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: actor,
            method: "increment".into(),
            arguments: prior_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        })
        .expect("the replica establishes a different causal actor state");
    let mut replica_request = request.clone();
    replica_request.logical_timeslot = 2;
    let replica_committed = replica
        .invoke(replica_request.clone())
        .expect("the exact logical invocation executes on an independent causal branch");
    assert!(!replica_committed.duplicate);
    assert_ne!(
        committed.published.exported_blobs, replica_committed.published.exported_blobs,
        "each yielded retry captures its exact branch-local physical work frame"
    );
    let source_resumed = service
        .resume_yield(request.invocation, 3)
        .expect("source resumes its physical retry branch before synchronization");
    let replica_resumed = replica
        .resume_yield(request.invocation, 4)
        .expect("replica resumes the other physical retry branch before synchronization");
    assert_eq!(source_resumed.input.workflow_step, 1);
    assert_eq!(replica_resumed.input.workflow_step, 1);
    assert_ne!(
        source_resumed.published.exported_blobs, replica_resumed.published.exported_blobs,
        "step-1 descendants retain their branch-local checkpoint frames"
    );
    let source_sync = service
        .crdt_sync_envelope()
        .expect("source causal frontier is readable")
        .expect("committed CRDT descendants export a sync envelope");
    let replica_sync = replica
        .crdt_sync_envelope()
        .expect("replica causal frontier is readable")
        .expect("independently committed CRDT work exports a sync envelope");
    let source_execution = source_sync
        .nodes
        .iter()
        .find(|node| {
            node.change.workflow.iter().any(|operation| {
                matches!(operation, WorkflowOperationV2::Checkpoint(work) if work.invocation == request.invocation)
            })
        })
        .expect("source exports the yielded invocation node");
    let replica_execution = replica_sync
        .nodes
        .iter()
        .find(|node| {
            node.change.workflow.iter().any(|operation| {
                matches!(operation, WorkflowOperationV2::Checkpoint(work) if work.invocation == request.invocation)
            })
        })
        .expect("replica exports the yielded invocation node");
    assert_ne!(
        source_execution.change.materializations, replica_execution.change.materializations,
        "the retry really executed over different causal actor state"
    );
    assert!(source_sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperationV2::Checkpoint(work)
                if work.invocation == request.invocation && work.workflow_step == 1)
        })
    }));
    assert!(replica_sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperationV2::Checkpoint(work)
                if work.invocation == request.invocation && work.workflow_step == 1)
        })
    }));
    assert!(
        source_sync.nodes.iter().all(|left| replica_sync
            .nodes
            .iter()
            .all(|right| left.change.cid() != right.change.cid())),
        "independent scheduling slots and causal bases produce distinct physical DAG nodes"
    );

    let before_untrusted_sync = replica.store().snapshot();
    assert!(matches!(
        replica.sync_finalized_crdt(source_sync.clone()),
        Err(LocalRootTreeInvokeErrorV2::Rejected(
            vos::v2::AccumulationRejectionV2::ReceiptUnavailable
        ))
    ));
    assert_eq!(
        replica.store().snapshot(),
        before_untrusted_sync,
        "a sync envelope must not authorize its own claimed receipts"
    );
    for node in &source_sync.nodes {
        replica
            .store_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: node
                    .change
                    .expected_producer()
                    .expect("every exported workflow node names its producer"),
                receipt: node.receipt.clone(),
            });
    }
    let replica_synced = replica
        .sync_finalized_crdt(source_sync)
        .expect("independently finalized causal nodes synchronize");
    assert!(!replica_synced.duplicate);
    for node in &replica_sync.nodes {
        service
            .store_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: node
                    .change
                    .expected_producer()
                    .expect("every exported workflow node names its producer"),
                receipt: node.receipt.clone(),
            });
    }
    let source_synced = service
        .sync_finalized_crdt(replica_sync)
        .expect("the source imports the independently finalized retry branch");
    assert!(!source_synced.duplicate);
    let source_header = service.store().header().unwrap().unwrap();
    let replica_header = replica.store().header().unwrap().unwrap();
    assert_eq!(
        source_header.service_root, replica_header.service_root,
        "both roots materialize the same canonical service state"
    );
    assert_eq!(
        source_header.crdt_heads, replica_header.crdt_heads,
        "both roots retain the same concurrent causal frontier"
    );
    assert_eq!(
        service.crdt_sync_envelope().unwrap(),
        replica.crdt_sync_envelope().unwrap(),
        "both roots export every physical retry branch"
    );

    let source_recovery = service
        .invoke(request.clone())
        .expect("source dedup reattaches after branch convergence");
    let replica_recovery = replica
        .invoke(replica_request.clone())
        .expect("replica dedup reattaches after branch convergence");
    assert!(source_recovery.duplicate);
    assert!(replica_recovery.duplicate);
    assert_eq!(source_recovery.receipt, replica_recovery.receipt);
    assert_eq!(
        source_recovery.published, replica_recovery.published,
        "both roots recover the canonical continuation export, not their branch-local snapshot"
    );
    assert_eq!(source_recovery.refine_gas_used, 0);
    assert_eq!(source_recovery.accumulate_gas_used, 0);
    assert_eq!(replica_recovery.refine_gas_used, 0);
    assert_eq!(replica_recovery.accumulate_gas_used, 0);

    let backend = service.into_backend();
    let replica_backend = replica.into_backend();
    let mut restarted = LocalRootTreeServiceV2::open(config.clone(), backend)
        .expect("CRDT service image restores without reinstalling");
    let mut restarted_replica = LocalRootTreeServiceV2::open(config, replica_backend)
        .expect("converged replica restores without reinstalling");
    let recovered = restarted
        .invoke(request)
        .expect("normalized CRDT workflow reattaches to the admitted work");
    let replica_recovered = restarted_replica
        .invoke(replica_request)
        .expect("replica reattaches the same canonical result after restart");
    assert!(recovered.duplicate);
    assert!(replica_recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    assert_eq!(replica_recovered.refine_gas_used, 0);
    assert_eq!(replica_recovered.accumulate_gas_used, 0);
    assert_eq!(recovered.input, source_recovery.input);
    assert_eq!(recovered.receipt, source_recovery.receipt);
    assert_eq!(recovered.published, source_recovery.published);
    assert_eq!(recovered.publication, source_recovery.publication);
    assert_eq!(recovered.receipt, replica_recovered.receipt);
}

#[test]
fn node_anti_entropy_converges_authenticated_crdt_roots_across_restart() {
    let actor_elf = crdt_counter_v2_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([0x51; 32]);
    let config = LocalRootTreeConfigV2 {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([0x52; 32]),
            root_service: RootServiceId([0x53; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyModeV2::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        install_authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0x54; 32]),
            authenticator: vec![0x55],
        },
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let backend_a = SharedCommittedImages::default();
    let backend_b = SharedCommittedImages::default();
    let mut service_a = LocalRootTreeServiceV2::open(config.clone(), backend_a.clone()).unwrap();
    let mut service_b = LocalRootTreeServiceV2::open(config.clone(), backend_b.clone()).unwrap();
    let increment_request = |invocation, logical_timeslot, amount| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new("increment").with("amount", amount).encode());
        LocalWorkRequestV2 {
            invocation,
            workflow_step: 0,
            logical_timeslot,
            target: actor,
            method: "increment".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        }
    };
    service_a
        .invoke(increment_request(InvocationId([0x56; 32]), 1, 2u64))
        .expect("first physical CRDT branch commits");
    service_b
        .invoke(increment_request(InvocationId([0x57; 32]), 1, 5u64))
        .expect("second physical CRDT branch commits");
    assert_ne!(
        service_a.store().header().unwrap().unwrap().crdt_heads,
        service_b.store().header().unwrap().unwrap().crdt_heads,
        "the transport starts from independently committed causal branches"
    );

    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let peer_a = libp2p::PeerId::from(key_a.public());
    let prefix_a = vos::network::derive_node_prefix(&peer_a);
    let (key_b, peer_b, prefix_b) = loop {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = libp2p::PeerId::from(key.public());
        let prefix = vos::network::derive_node_prefix(&peer);
        if prefix != prefix_a {
            break (key, peer, prefix);
        }
    };
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let network_a = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let address_a = loop {
        if let Some(address) = network_a.listen_addrs().into_iter().next() {
            break address.with(libp2p::multiaddr::Protocol::P2p(peer_a));
        }
        assert!(std::time::Instant::now() < deadline, "node A did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    let network_b = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![address_a],
        auto_dial_mdns: false,
    });

    let mut node_a = VosNode::with_prefix(prefix_a);
    let mut node_b = VosNode::with_prefix(prefix_b);
    let registry_pvm =
        grey_transpiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
            .expect("committed space-registry ELF transpiles");
    let voters = [(prefix_a, peer_a.to_bytes()), (prefix_b, peer_b.to_bytes())];
    install_test_voter_registry(&mut node_a, registry_pvm.clone(), &voters);
    install_test_voter_registry(&mut node_b, registry_pvm, &voters);
    node_a.attach_network(network_a);
    node_b.attach_network(network_b);
    let network_a = node_a.network().unwrap();
    let network_b = node_b.network().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while (network_a.peer_for_prefix(prefix_b).is_none()
        || network_b.peer_for_prefix(prefix_a).is_none())
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(network_a.peer_for_prefix(prefix_b).is_some());
    assert!(network_b.peer_for_prefix(prefix_a).is_some());

    let local_id = 0x3951;
    let route_a = ServiceId::new(prefix_a, local_id);
    let route_b = ServiceId::new(prefix_b, local_id);
    node_a
        .register_v2_root_at_id("", service_a, route_a, true)
        .unwrap();
    node_b
        .register_v2_root_at_id("", service_b, route_b, true)
        .unwrap();
    let shutdown_a = node_a.shutdown_handle();
    let shutdown_b = node_b.shutdown_handle();
    let runner_a = std::thread::spawn(move || {
        node_a.run_forever();
        node_a.collect()
    });
    let runner_b = std::thread::spawn(move || {
        node_b.run_forever();
        node_b.collect()
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let reopened_a = LocalRootTreeServiceV2::open(config.clone(), backend_a.clone()).unwrap();
        let reopened_b = LocalRootTreeServiceV2::open(config.clone(), backend_b.clone()).unwrap();
        let header_a = reopened_a.store().header().unwrap().unwrap();
        let header_b = reopened_b.store().header().unwrap().unwrap();
        if header_a.crdt_heads == header_b.crdt_heads
            && header_a.service_root == header_b.service_root
            && header_a.crdt_heads.len() >= 2
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "authenticated v2 CRDT roots did not converge"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    shutdown_a.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown_b.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(runner_a.join().unwrap().iter().all(AgentResult::is_ok));
    assert!(runner_b.join().unwrap().iter().all(AgentResult::is_ok));
    let reopened_a = LocalRootTreeServiceV2::open(config.clone(), backend_a).unwrap();
    let reopened_b = LocalRootTreeServiceV2::open(config, backend_b).unwrap();
    assert_eq!(
        reopened_a.crdt_sync_envelope().unwrap(),
        reopened_b.crdt_sync_envelope().unwrap(),
        "durable reopen retains the same authenticated causal history"
    );
    drop(network_a);
    drop(network_b);
}

#[test]
fn same_package_child_spawn_commits_before_the_child_becomes_callable() {
    let actor_pvm = grey_transpiler::link_elf(&workflow_v2_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let availability_programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlobV2 {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let host = LocalJamStoreV2::default();
    let mut service = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: seed.target_deployment,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![
                MethodPolicyV2 {
                    method: "increment".into(),
                    schema: Hash([151; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                },
                MethodPolicyV2 {
                    method: "spawn_child".into(),
                    schema: Hash([152; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                },
            ]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([153; 32]),
            authenticator: vec![154],
        },
    });
    assert_eq!(
        service
            .accumulate_with_availability(&install, &availability_programs, &availability_blobs,)
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert!(service.accumulate_host().program(actor_program).is_none());
    assert!(service.accumulate_host().blob(&initial).is_none());
    authorize_install(&mut service, &install);
    assert!(matches!(
        service
            .accumulate_with_availability(&install, &availability_programs, &availability_blobs,)
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));

    let mut spawn_arguments = vec![vos::value::TAG_DYNAMIC];
    spawn_arguments.extend_from_slice(
        &Msg::new("spawn_child")
            .with("name", "worker")
            .with("initial", 9u32)
            .encode(),
    );
    let spawn_work = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([155; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed.target,
            method: "spawn_child".into(),
            arguments: spawn_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut service, &spawn_work.work);
    let spawned = service
        .refine_actor_tree(&spawn_work.work, &spawn_work.imports)
        .expect("the canonical actor emits one child creation effect");
    let child = ActorId::owned_child(seed.target, "worker");
    assert_eq!(spawned.transition.spawns.len(), 1);
    assert_eq!(spawned.transition.spawns[0].actor, child);
    assert_eq!(spawned.transition.spawns[0].parent, seed.target);
    assert_eq!(spawned.transition.spawns[0].name, "worker");
    assert_eq!(
        spawned
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::Bool(true))
    );
    let spawn_apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: spawn_work.work,
        transition: spawned.transition,
        provided_blobs: spawned.exported_blobs,
    });
    assert!(matches!(
        service.accumulate(&spawn_apply).unwrap().result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let before_retry = service.accumulate_host().snapshot();
    assert!(matches!(
        service.accumulate(&spawn_apply).unwrap().result,
        AccumulationResultV2::Accepted {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(service.accumulate_host().snapshot(), before_retry);

    let mut increment_arguments = vec![vos::value::TAG_DYNAMIC];
    increment_arguments.extend_from_slice(&Msg::new("increment").with("amount", 2u32).encode());
    let child_work = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([156; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: child,
            method: "increment".into(),
            arguments: increment_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("the committed child is schedulable in the next slice");
    admit_linear_work(&mut service, &child_work.work);
    let imported_child = child_work
        .work
        .imported_actors
        .iter()
        .find(|actor| actor.actor == child)
        .unwrap();
    assert_eq!(imported_child.parent, Some(seed.target));
    assert_eq!(imported_child.name, "worker");
    assert_eq!(imported_child.deployment, seed.target_deployment);
    assert_eq!(imported_child.program, actor_program);
    let child_result = service
        .refine_actor_tree(&child_work.work, &child_work.imports)
        .expect("a fresh Refine installs and executes the spawned child");
    assert_eq!(
        child_result
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(11))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: child_work.work,
                transition: child_result.transition,
                provided_blobs: child_result.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn same_tree_calls_resume_exact_stacks_and_allocate_tree_wide_call_ids() {
    let actor_pvm = grey_transpiler::link_elf(&workflow_v2_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let child = ActorId([36; 32]);
    let sibling = ActorId([37; 32]);
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![private_age_binding(&seed.service)],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "call_child".into(),
                        schema: Hash([61; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "root_child_await".into(),
                        schema: Hash([65; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "root_child_two_awaits".into(),
                        schema: Hash([73; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "root_child_then_peer".into(),
                        schema: Hash([81; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "root_child_then_sibling".into(),
                        schema: Hash([91; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "call_child_repeatedly".into(),
                        schema: Hash([82; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "sibling_ipc_tail".into(),
                        schema: Hash([83; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "child_await_peer".into(),
                        schema: Hash([66; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "child_two_awaits".into(),
                        schema: Hash([74; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([62; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "wide_reply".into(),
                        schema: Hash([84; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesisV2 {
                actor: sibling,
                name: "sibling".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "child_await_peer".into(),
                        schema: Hash([92; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "ipc_tail".into(),
                        schema: Hash([85; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([63; 32]),
            authenticator: vec![64],
        },
    });
    authorize_install(&mut service, &install);
    let install_result = service.accumulate(&install).unwrap().result;
    assert!(
        matches!(install_result, AccumulationResultV2::Installed(_)),
        "root-tree fixture install rejected: {install_result:?}"
    );

    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("call_child").encode());
    let scheduled = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: seed.invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed.target,
            method: "call_child".into(),
            arguments: message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut service, &scheduled.work);
    let refined = service
        .refine_actor_tree(&scheduled.work, &scheduled.imports)
        .expect("root calls its child through an ordinary JAR CALLABLE");
    assert_eq!(
        refined
            .transition
            .writes
            .iter()
            .map(|write| (write.actor, u32::decode(write.value.as_ref().unwrap())))
            .collect::<Vec<_>>(),
        vec![(seed.target, 11), (child, 1)]
    );
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(11))
    );

    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: scheduled.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut scrub_message = vec![vos::value::TAG_DYNAMIC];
    scrub_message.extend_from_slice(&Msg::new("sibling_ipc_tail").encode());
    let scrub = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([86; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: seed.target,
            method: "sibling_ipc_tail".into(),
            arguments: scrub_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut service, &scrub.work);
    let scrubbed = service
        .refine_actor_tree(&scrub.work, &scrub.imports)
        .expect("a long sibling reply is followed by a short sibling call");
    assert_eq!(
        scrubbed
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U8(0)),
        "the next sibling cannot observe bytes beyond its own IPC input"
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: scrub.work,
                transition: scrubbed.transition,
                provided_blobs: scrubbed.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let invocation = InvocationId([67; 32]);
    let mut nested_message = vec![vos::value::TAG_DYNAMIC];
    nested_message.extend_from_slice(&Msg::new("root_child_await").encode());
    let nested = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation,
            workflow_step: 0,
            logical_timeslot: 3,
            target: seed.target,
            method: "root_child_await".into(),
            arguments: nested_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("the completed inline invocation leaves both actors idle");
    admit_linear_work(&mut service, &nested.work);
    let runner = ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .unwrap();
    let first_bytes = runner
        .refine_actor_tree_traced(
            &nested.work.encode(),
            &nested.imports,
            1_000_000_000,
            &NoRefineProtocolHostV2,
        )
        .expect("the child suspends inside the root's nested CALL");
    assert_eq!(
        runner
            .refine_actor_tree_traced(
                &nested.work.encode(),
                &nested.imports,
                1_000_000_000,
                &NoRefineProtocolHostV2,
            )
            .unwrap(),
        first_bytes,
        "the exact nested trace must be deterministic"
    );
    let trace = first_bytes
        .trace
        .as_ref()
        .expect("traced Refine returns its execution commitment");
    assert!(trace.instruction_count > 0);
    assert!(trace.protocol_call_count > 0);
    assert!(trace.vm_switch_count >= 2);
    assert!(
        trace.code_hashes.len() >= 2,
        "the trace covers both the service and actor code"
    );
    let recompiled = runner
        .refine_actor_tree_with_backend(
            &nested.work.encode(),
            &nested.imports,
            1_000_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(recompiled.bytes, first_bytes.bytes);
    assert_eq!(recompiled.gas_used, first_bytes.gas_used);
    assert_eq!(
        recompiled.exported_blobs, first_bytes.exported_blobs,
        "nested JAR checkpoints must be backend-independent"
    );
    assert!(recompiled.trace.is_none());
    let first_output = RefineOutputV2::decode(&first_bytes.bytes).unwrap();
    let first = &first_output.transition;
    assert!(first.reply.is_none());
    assert_eq!(first.outbox.len(), 1);
    let call_id = invocation.call_id(0);
    assert_eq!(first.outbox[0].call_id, call_id);
    assert_eq!(first.outbox[0].from, child);
    assert_eq!(first.outbox[0].to, ActorId([44; 32]));
    assert_eq!(first.outbox[0].deadline_timeslot, Some(100));
    assert_eq!(
        first
            .continuations
            .iter()
            .map(|change| change.actor)
            .collect::<Vec<_>>(),
        vec![seed.target, child]
    );
    let continuation = first.continuations[0]
        .replacement
        .clone()
        .expect("the complete nested machine stack is exported");
    assert!(
        first
            .continuations
            .iter()
            .all(|change| change.expected.is_none()
                && change.replacement.as_ref() == Some(&continuation))
    );
    assert_eq!(
        first
            .writes
            .iter()
            .map(|write| u32::decode(write.value.as_ref().unwrap()))
            .collect::<Vec<_>>(),
        vec![21, 2],
        "each pre-await mutation is materialized exactly once"
    );
    for artifact in first_output
        .candidate_blobs
        .iter()
        .chain(first_bytes.exported_blobs.iter())
    {
        assert_eq!(
            service
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }

    let mut forged_sender = first.clone();
    forged_sender.outbox[0].from = seed.target;
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: nested.work.clone(),
                transition: forged_sender,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidWorkflowTransition),
        "guest Accumulate binds the outbox sender to JAR's exact pending actor"
    );

    let mut incomplete_checkpoint = first.clone();
    incomplete_checkpoint.continuations.pop();
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: nested.work.clone(),
                transition: incomplete_checkpoint,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidWorkflowTransition),
        "guest Accumulate rejects a checkpoint that omits an active child"
    );
    let first_result = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: nested.work,
            transition: first.clone(),
            provided_blobs: vec![],
        }))
        .unwrap()
        .result;
    assert!(
        matches!(
            first_result,
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ),
        "complete nested checkpoint rejected: {first_result:?}"
    );

    let mut child_message = vec![vos::value::TAG_DYNAMIC];
    child_message.extend_from_slice(&Msg::new("increment").with("amount", 1u32).encode());
    let child_request = LocalWorkRequestV2 {
        invocation: InvocationId([72; 32]),
        workflow_step: 0,
        logical_timeslot: 4,
        target: child,
        method: "increment".into(),
        arguments: child_message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    assert_eq!(
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), child_request.clone()),
        Err(ScheduleErrorV2::ActorBusy(child)),
        "the active child is non-reentrant while its caller stack is suspended"
    );

    let persisted = service.accumulate_host().snapshot_bytes();
    let restarted_store = LocalJamStoreV2::from_snapshot_bytes(&persisted)
        .expect("the complete tree checkpoint survives a process restart");
    let mut restarted = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        restarted_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let awaited_reply = peer_reply(&seed.service, call_id, 7, 68);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: awaited_reply.receipt.clone(),
        });
    let resumed = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        invocation,
        3,
        Some(awaited_reply),
    )
    .expect("the scheduler reconstructs the nested workflow from guest state");
    assert!(
        resumed
            .work
            .imported_actors
            .iter()
            .filter(|actor| actor.actor == seed.target || actor.actor == child)
            .all(|actor| actor.continuation.as_ref() == Some(&continuation))
    );
    assert!(
        resumed
            .work
            .imported_actors
            .iter()
            .find(|actor| actor.actor == sibling)
            .is_some_and(|actor| actor.continuation.is_none()),
        "an idle sibling remains outside the suspended stack"
    );
    let resumed_bytes = runner
        .refine_actor_tree_with_backend(
            &resumed.work.encode(),
            &resumed.imports,
            1_000_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .expect("the reply resumes the child and then its suspended root caller");
    assert_eq!(
        runner
            .refine_actor_tree_with_backend(
                &resumed.work.encode(),
                &resumed.imports,
                1_000_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        resumed_bytes,
        "nested reply injection must be backend-independent"
    );
    let resumed_output = RefineOutputV2::decode(&resumed_bytes.bytes).unwrap();
    let mut resumed_candidates = resumed_output.candidate_blobs.clone();
    resumed_candidates.extend(resumed_bytes.exported_blobs.clone());
    assert!(resumed_output.transition.outbox.is_empty());
    assert_eq!(
        resumed_output
            .transition
            .continuations
            .iter()
            .map(|change| (change.actor, change.expected, change.replacement.clone()))
            .collect::<Vec<_>>(),
        vec![
            (seed.target, Some(continuation.hash), None),
            (child, Some(continuation.hash), None),
        ]
    );
    assert_eq!(
        resumed_output
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(30))
    );
    assert_eq!(
        resumed_output
            .transition
            .writes
            .iter()
            .map(|write| u32::decode(write.value.as_ref().unwrap()))
            .collect::<Vec<_>>(),
        vec![30, 9]
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: resumed.work,
                transition: resumed_output.transition,
                provided_blobs: resumed_candidates,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert!(
        LocalWorkSchedulerV2::prepare(restarted.accumulate_host(), child_request).is_ok(),
        "completion unlocks every actor from the exact suspended stack"
    );

    let second_invocation = InvocationId([75; 32]);
    let mut twice_message = vec![vos::value::TAG_DYNAMIC];
    twice_message.extend_from_slice(&Msg::new("root_child_two_awaits").encode());
    let twice = LocalWorkSchedulerV2::prepare(
        restarted.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: second_invocation,
            workflow_step: 0,
            logical_timeslot: 4,
            target: seed.target,
            method: "root_child_two_awaits".into(),
            arguments: twice_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut restarted, &twice.work);
    let first_wait = restarted
        .refine_actor_tree(&twice.work, &twice.imports)
        .expect("the nested child reaches its first peer await");
    let first_call = second_invocation.call_id(0);
    assert_eq!(
        first_wait
            .transition
            .outbox
            .first()
            .map(|message| message.call_id),
        Some(first_call)
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: twice.work,
                transition: first_wait.transition,
                provided_blobs: first_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let persisted = restarted.accumulate_host().snapshot_bytes();
    restarted = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        LocalJamStoreV2::from_snapshot_bytes(&persisted).unwrap(),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let first_reply = peer_reply(&seed.service, first_call, 1, 76);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: first_reply.receipt.clone(),
        });
    let after_first = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        second_invocation,
        5,
        Some(first_reply),
    )
    .unwrap();
    let second_wait = restarted
        .refine_actor_tree(&after_first.work, &after_first.imports)
        .expect("the restored child advances to its second peer await");
    let second_call = second_invocation.call_id(1);
    assert_eq!(second_wait.transition.reply, None);
    assert_eq!(second_wait.transition.outbox.len(), 1);
    assert_eq!(second_wait.transition.outbox[0].call_id, second_call);
    assert_ne!(first_call, second_call);
    assert_eq!(
        second_wait
            .transition
            .writes
            .iter()
            .map(|write| u32::decode(write.value.as_ref().unwrap()))
            .collect::<Vec<_>>(),
        vec![40, 11],
        "the first await resumes mid-stack without replaying pre-await code"
    );
    let second_continuation = second_wait.transition.continuations[0]
        .replacement
        .clone()
        .expect("the second await replaces the first exact snapshot");
    assert!(
        second_wait
            .transition
            .continuations
            .iter()
            .all(|change| change.expected.is_some()
                && change.replacement.as_ref() == Some(&second_continuation))
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: after_first.work,
                transition: second_wait.transition,
                provided_blobs: second_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let persisted = restarted.accumulate_host().snapshot_bytes();
    restarted = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        LocalJamStoreV2::from_snapshot_bytes(&persisted).unwrap(),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let second_reply = peer_reply(&seed.service, second_call, 2, 80);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: second_reply.receipt.clone(),
        });
    let after_second = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        second_invocation,
        6,
        Some(second_reply),
    )
    .unwrap();
    let finished = restarted
        .refine_actor_tree(&after_second.work, &after_second.imports)
        .expect("the second reply completes the original root handler");
    assert!(finished.transition.outbox.is_empty());
    assert_eq!(
        finished
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(53))
    );
    assert_eq!(
        finished
            .transition
            .writes
            .iter()
            .map(|write| u32::decode(write.value.as_ref().unwrap()))
            .collect::<Vec<_>>(),
        vec![53, 13],
        "both await boundaries preserve the exact root and child locals"
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: after_second.work,
                transition: finished.transition,
                provided_blobs: finished.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let chained_invocation = InvocationId([87; 32]);
    let mut chained_message = vec![vos::value::TAG_DYNAMIC];
    chained_message.extend_from_slice(&Msg::new("root_child_then_peer").encode());
    let chained = LocalWorkSchedulerV2::prepare(
        restarted.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: chained_invocation,
            workflow_step: 0,
            logical_timeslot: 7,
            target: seed.target,
            method: "root_child_then_peer".into(),
            arguments: chained_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut restarted, &chained.work);
    let child_wait = restarted
        .refine_actor_tree(&chained.work, &chained.imports)
        .expect("the child reaches its await");
    let child_call = chained_invocation.call_id(0);
    assert_eq!(child_wait.transition.outbox[0].call_id, child_call);
    assert_eq!(child_wait.transition.outbox[0].from, child);
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: chained.work,
                transition: child_wait.transition,
                provided_blobs: child_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let child_reply = peer_reply(&seed.service, child_call, 3, 88);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: child_reply.receipt.clone(),
        });
    let after_child = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        chained_invocation,
        8,
        Some(child_reply),
    )
    .unwrap();
    let root_wait = restarted
        .refine_actor_tree(&after_child.work, &after_child.imports)
        .expect("the child completes and its root reaches a later await");
    let root_call = chained_invocation.call_id(1);
    assert_eq!(root_wait.transition.reply, None);
    assert_eq!(root_wait.transition.outbox.len(), 1);
    assert_eq!(root_wait.transition.outbox[0].call_id, root_call);
    assert_eq!(root_wait.transition.outbox[0].from, seed.target);
    assert_eq!(
        root_wait
            .transition
            .writes
            .iter()
            .map(|write| u32::decode(write.value.as_ref().unwrap()))
            .collect::<Vec<_>>(),
        vec![80, 17],
        "the completed child's deletion token cannot replace the root's later checkpoint"
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: after_child.work,
                transition: root_wait.transition,
                provided_blobs: root_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let root_reply = peer_reply(&seed.service, root_call, 4, 89);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: root_reply.receipt.clone(),
        });
    let after_root = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        chained_invocation,
        9,
        Some(root_reply),
    )
    .unwrap();
    let chained_done = restarted
        .refine_actor_tree(&after_root.work, &after_root.imports)
        .expect("the root resumes after its post-child await");
    assert_eq!(
        chained_done
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(84))
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: after_root.work,
                transition: chained_done.transition,
                provided_blobs: chained_done.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut repeated_message = vec![vos::value::TAG_DYNAMIC];
    repeated_message.extend_from_slice(&Msg::new("call_child_repeatedly").encode());
    let repeated = LocalWorkSchedulerV2::prepare(
        restarted.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([90; 32]),
            workflow_step: 0,
            logical_timeslot: 10,
            target: seed.target,
            method: "call_child_repeatedly".into(),
            arguments: repeated_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut restarted, &repeated.work);
    let repeated_done = restarted
        .refine_actor_tree(&repeated.work, &repeated.imports)
        .expect("repeated legal CALLs reuse the callee arena");
    assert_eq!(
        repeated_done
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(81))
    );

    let locked_invocation = InvocationId([93; 32]);
    let mut locked_message = vec![vos::value::TAG_DYNAMIC];
    locked_message.extend_from_slice(&Msg::new("root_child_then_sibling").encode());
    let locked = LocalWorkSchedulerV2::prepare(
        restarted.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: locked_invocation,
            workflow_step: 0,
            logical_timeslot: 11,
            target: seed.target,
            method: "root_child_then_sibling".into(),
            arguments: locked_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut restarted, &locked.work);
    let locked_wait = restarted
        .refine_actor_tree(&locked.work, &locked.imports)
        .expect("the root and child suspend while the sibling is idle");
    let locked_call = locked_invocation.call_id(0);
    assert_eq!(locked_wait.transition.outbox[0].call_id, locked_call);
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: locked.work,
                transition: locked_wait.transition,
                provided_blobs: locked_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let sibling_invocation = InvocationId([94; 32]);
    let mut sibling_message = vec![vos::value::TAG_DYNAMIC];
    sibling_message.extend_from_slice(&Msg::new("child_await_peer").encode());
    let sibling_work = LocalWorkSchedulerV2::prepare(
        restarted.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: sibling_invocation,
            workflow_step: 0,
            logical_timeslot: 12,
            target: sibling,
            method: "child_await_peer".into(),
            arguments: sibling_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("the idle sibling may start another workflow");
    admit_linear_work(&mut restarted, &sibling_work.work);
    let sibling_wait = restarted
        .refine_actor_tree(&sibling_work.work, &sibling_work.imports)
        .expect("the sibling independently suspends");
    assert_eq!(sibling_wait.transition.outbox[0].from, sibling);
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: sibling_work.work,
                transition: sibling_wait.transition,
                provided_blobs: sibling_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let locked_reply = peer_reply(&seed.service, locked_call, 2, 95);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: locked_reply.receipt.clone(),
        });
    let locked_resume = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        locked_invocation,
        13,
        Some(locked_reply),
    )
    .unwrap();
    let locked_done = restarted
        .refine_actor_tree(&locked_resume.work, &locked_resume.imports)
        .expect("resume reconciles CALLABLEs against current committed locks");
    assert_eq!(
        locked_done
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(0)),
        "a snapshot-frozen CALLABLE cannot enter a sibling locked by another workflow"
    );
    assert!(
        locked_done
            .transition
            .writes
            .iter()
            .all(|write| write.actor != sibling)
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: locked_resume.work,
                transition: locked_done.transition,
                provided_blobs: locked_done.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn private_actor_input_is_bounded_before_entering_the_compact_guest_heap() {
    let actor_elf = greeter_elf();
    let actor = grey_transpiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = vec![0; vos::v2::ACTOR_SLICE_INPUT_MAX_BYTES];
    let state = BlobRefV2::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        }],
        private_blobs: vec![],
    };
    let service = ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .expect("canonical service program");

    assert_eq!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::ActorInputTooLarge)
    );
}

#[test]
fn same_tree_causal_cycles_return_an_explicit_guest_error() {
    let actor_pvm = grey_transpiler::link_elf(&cycle_v2_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let child = ActorId([36; 32]);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "root_cycle".into(),
                        schema: Hash([81; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "root_forbidden".into(),
                        schema: Hash([86; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "child_cycle".into(),
                        schema: Hash([82; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "member_only".into(),
                        schema: Hash([87; 32]),
                        policy: space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap(),
                        public: false,
                        attested: false,
                        space_role: Some(vos::SpaceRole::Member.as_u8()),
                        actor_role: None,
                    },
                ]),
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([83; 32]),
            authenticator: vec![84],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("root_cycle").encode());
    let scheduled = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([85; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed.target,
            method: "root_cycle".into(),
            arguments: message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut service, &scheduled.work);
    let refined = service
        .refine_actor_tree(&scheduled.work, &scheduled.imports)
        .expect("A -> B -> A returns Cycle before re-entering A");
    assert!(refined.transition.outbox.is_empty());
    assert!(refined.transition.continuations.is_empty());
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(1))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: scheduled.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("root_forbidden").encode());
    let scheduled = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([88; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: seed.target,
            method: "root_forbidden".into(),
            arguments: message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut service, &scheduled.work);
    let refined = service
        .refine_actor_tree(&scheduled.work, &scheduled.imports)
        .expect("a same-tree role denial remains distinct from a child panic");
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(1))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: scheduled.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn canonical_crdt_slice_refines_and_accumulates_without_native_apply() {
    let service_elf = service_elf();
    let actor_elf = crdt_counter_v2_elf();
    let service_pvm = vos::v2::transpile_service_elf(&service_elf).unwrap();
    let actor_pvm = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut work = work(actor_program, initial.clone());
    work.method = "increment".into();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("increment").with("amount", 2u64).encode());
    work.arguments = message;
    work.consistency = ConsistencyModeV2::Crdt;
    work.base = ConsistencyBaseV2::Crdt { heads: vec![] };
    work.base_causal_height = Some(0);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor: work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: true,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "increment".into(),
                schema: Hash([44; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([46; 32]),
            authenticator: vec![1],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let first_request = request_from_work(&work);
    let mut right_template = work.clone();
    right_template.invocation = InvocationId([47; 32]);
    let mut right_message = vec![vos::value::TAG_DYNAMIC];
    right_message.extend_from_slice(&Msg::new("increment").with("amount", 3u64).encode());
    right_template.arguments = right_message;
    let right_request = request_from_work(&right_template);
    // Prepare both ingress nodes from the same empty frontier, then commit
    // them before either actor Refine. Both actor slices therefore observe
    // the same authenticated two-branch admission frontier.
    let service_identity = service.accumulate_host().header().unwrap().unwrap().service;
    let ingresses = [&first_request, &right_request].map(|request| {
        LocalWorkSchedulerV2::prepare_direct_ingress(
            service.accumulate_host(),
            &service_identity,
            request,
        )
        .unwrap()
    });
    for ingress in ingresses {
        assert!(matches!(
            service
                .accumulate(&AccumulateRequestV2::AdmitIngress(ingress))
                .unwrap()
                .result,
            AccumulationResultV2::IngressAdmitted {
                duplicate: false,
                ..
            }
        ));
    }
    let scheduled = LocalWorkSchedulerV2::prepare(service.accumulate_host(), first_request)
        .expect("scheduler imports the authenticated CRDT ingress frontier");
    let right_scheduled = LocalWorkSchedulerV2::prepare(service.accumulate_host(), right_request)
        .expect("concurrent retry observes the same admitted frontier");
    work = scheduled.work;
    let imports = scheduled.imports;

    let refined = service.refine_actor_tree(&work, &imports).unwrap();
    assert!(refined.transition.writes.is_empty());
    let change = refined.transition.crdt_change.as_ref().unwrap();
    assert_eq!(change.causal_height, 2);
    assert_eq!(change.operations.len(), 1);
    assert_eq!(change.materializations.len(), 1);
    assert_eq!(refined.exported_blobs.len(), 1);
    assert_eq!(
        refined.exported_blobs[0].reference,
        change.materializations[0].state
    );
    let cid = change.cid();
    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: work.clone(),
        transition: refined.transition.clone(),
        provided_blobs: refined.exported_blobs.clone(),
    });
    let applied = service.accumulate(&apply).unwrap().result;
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = applied
    else {
        panic!("CRDT transition rejected")
    };
    assert!(!duplicate);
    assert_eq!(receipt.resulting_crdt_heads, vec![cid]);
    assert!(published.reply.is_some());
    assert!(
        service
            .accumulate_host()
            .blob(&refined.exported_blobs[0].reference)
            .is_some()
    );

    // A second replica imports the authenticated DAG node through physical
    // IC-5. The host only supplies receipt verification and atomic storage;
    // the service guest validates and materializes the synced workflow.
    let mut replica_host = LocalJamStoreV2::default();
    assert_eq!(replica_host.import_blob(initial_bytes), initial);
    assert_eq!(replica_host.import_program(actor_pvm), actor_program);
    let mut replica = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        replica_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    replica.accumulate_host_mut().allow_install(genesis);
    assert!(matches!(
        replica.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));
    let sync_envelope = LocalWorkSchedulerV2::prepare_crdt_sync(service.accumulate_host())
        .expect("source scheduler exports the authenticated causal DAG");
    for node in &sync_envelope.nodes {
        replica
            .accumulate_host_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: node.change.expected_producer().unwrap(),
                receipt: node.receipt.clone(),
            });
    }
    let sync = AccumulateRequestV2::SyncCrdt(sync_envelope);
    let synced = replica.accumulate(&sync).unwrap().result;
    assert!(matches!(
        synced,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        replica
            .accumulate_host()
            .header()
            .unwrap()
            .unwrap()
            .crdt_heads,
        vec![cid]
    );
    assert!(
        replica
            .accumulate_host()
            .blob(&refined.exported_blobs[0].reference)
            .is_some()
    );

    let duplicate = service.accumulate(&apply).unwrap().result;
    let AccumulationResultV2::Accepted {
        published,
        duplicate,
        ..
    } = duplicate
    else {
        panic!("CRDT retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffectsV2::default());

    // Refine the other admitted invocation from the same causal base after
    // the first branch has committed. CRDT Accumulate preserves both heads.
    let right_refined = service
        .refine_actor_tree(&right_scheduled.work, &right_scheduled.imports)
        .unwrap();
    let right_cid = right_refined.transition.crdt_change.as_ref().unwrap().cid();
    let right = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: right_scheduled.work,
            transition: right_refined.transition.clone(),
            provided_blobs: right_refined.exported_blobs.clone(),
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = right else {
        panic!("concurrent CRDT branch rejected")
    };
    let mut heads = vec![cid, right_cid];
    heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, heads);

    // The scheduler walks both complete branches and imports the exact
    // materialization frontier. The generated actor merger folds both counters
    // before the handler observes state, so 2 + 3 + 4 becomes 9.
    let mut merge_message = vec![vos::value::TAG_DYNAMIC];
    merge_message.extend_from_slice(&Msg::new("increment").with("amount", 4u64).encode());
    let merge = admit_and_prepare(
        &mut service,
        LocalWorkRequestV2 {
            invocation: InvocationId([48; 32]),
            workflow_step: 0,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: merge_message,
            origin: work.origin,
            authorization: work.authorization.clone(),
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    );
    let merge_work = merge.work;
    let merge_imports = merge.imports;
    let ConsistencyBaseV2::Crdt { heads: merge_heads } = &merge_work.base else {
        unreachable!()
    };
    assert_eq!(
        merge_heads.len(),
        1,
        "admission causally joins both branches"
    );
    assert_ne!(merge_heads, &heads);
    assert_eq!(merge_work.base_causal_height, Some(3));
    assert_eq!(merge_work.imported_actors[0].causal_states.len(), 1);
    assert_eq!(merge_imports.blobs.len(), 2);
    let merged = service
        .refine_actor_tree(&merge_work, &merge_imports)
        .unwrap();
    let reply = merged.transition.reply.as_ref().unwrap();
    assert_eq!(vos::value::Value::decode(&reply.result).as_i64(), Some(9));
    let merged_cid = merged.transition.crdt_change.as_ref().unwrap().cid();
    let accepted = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: merge_work,
            transition: merged.transition,
            provided_blobs: merged.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
        panic!("merged CRDT child rejected")
    };
    assert_eq!(receipt.resulting_crdt_heads, vec![merged_cid]);

    let admission_request = LocalWorkRequestV2 {
        invocation: InvocationId([59; 32]),
        workflow_step: 0,
        logical_timeslot: 6,
        target: work.target,
        method: "increment".into(),
        arguments: {
            let mut arguments = vec![vos::value::TAG_DYNAMIC];
            arguments.extend_from_slice(&Msg::new("increment").with("amount", 1u64).encode());
            arguments
        },
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let admission = LocalWorkSchedulerV2::prepare_direct_ingress(
        service.accumulate_host(),
        &work.service,
        &admission_request,
    )
    .expect("scheduler binds direct ingress to the current causal frontier");
    let admission_cid = admission.crdt_change.as_ref().unwrap().cid();
    let admitted = service
        .accumulate(&AccumulateRequestV2::AdmitIngress(admission))
        .unwrap()
        .result;
    assert!(matches!(
        admitted,
        AccumulationResultV2::IngressAdmitted {
            duplicate: false,
            ..
        }
    ));
    assert!(
        service
            .accumulate_host()
            .header()
            .unwrap()
            .unwrap()
            .crdt_heads
            .contains(&admission_cid)
    );

    let sync = LocalWorkSchedulerV2::prepare_crdt_sync(service.accumulate_host())
        .expect("the exported DAG includes the causal ingress admission");
    for node in &sync.nodes {
        replica
            .accumulate_host_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: node.change.expected_producer().unwrap(),
                receipt: node.receipt.clone(),
            });
    }
    let synced = replica
        .accumulate(&AccumulateRequestV2::SyncCrdt(sync))
        .unwrap()
        .result;
    assert!(matches!(
        synced,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert!(
        !replica
            .accumulate_host()
            .ingress_record(admission_request.invocation)
            .unwrap()
            .expect("synced admission is rematerialized as queued input")
            .consumed
    );
}

#[test]
fn crdt_root_tree_aggregates_repeated_child_dispatches_privately() {
    let actor_elf = crdt_counter_v2_elf();
    let actor_pvm = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let child = ActorId([36; 32]);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![private_age_binding(&seed.service)],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![
            ActorGenesisV2 {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: true,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([49; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "increment_child_twice".into(),
                        schema: Hash([50; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "call_yielding_child".into(),
                        schema: Hash([55; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "increment_child_around_peer".into(),
                        schema: Hash([57; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "increment_peer_then_yield".into(),
                        schema: Hash([67; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: true,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([51; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "increment_around_yield".into(),
                        schema: Hash([56; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "increment_around_peer".into(),
                        schema: Hash([58; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([52; 32]),
            authenticator: vec![1],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let missing_workflow = InvocationId([73; 32]);
    assert_eq!(
        LocalWorkSchedulerV2::prepare(
            service.accumulate_host(),
            LocalWorkRequestV2 {
                invocation: missing_workflow,
                workflow_step: 1,
                logical_timeslot: 1,
                target: seed.target,
                method: "increment".into(),
                arguments: vec![],
                origin: Origin::Anonymous,
                authorization: AuthorizationEvidenceV2::Public,
                causal_parent: None,
                parent_call: None,
                causal_context: None,
                awaited_reply: None,
                awaited_timeout: None,
                imported_blobs: vec![],
                proof_requested: false,
            },
        ),
        Err(ScheduleErrorV2::InvalidWorkflowStep(missing_workflow)),
        "a direct CRDT resume without a committed workflow row fails closed"
    );

    let request = |invocation, timeslot, method: &str| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new(method).with("amount", 3u64).encode());
        LocalWorkRequestV2 {
            invocation,
            workflow_step: 0,
            logical_timeslot: timeslot,
            target: seed.target,
            method: method.into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        }
    };

    let first = admit_and_prepare(
        &mut service,
        request(InvocationId([53; 32]), 1, "increment_child_twice"),
    );
    let runner = ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .unwrap();
    let interpreted = runner
        .refine_actor_tree_with_backend(
            &first.work.encode(),
            &first.imports,
            1_000_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        runner
            .refine_actor_tree_with_backend(
                &first.work.encode(),
                &first.imports,
                1_000_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        interpreted,
        "private CRDT dispatch allocation is backend-independent"
    );
    let refined = service
        .refine_actor_tree(&first.work, &first.imports)
        .unwrap();
    let change = refined.transition.crdt_change.as_ref().unwrap();
    assert_eq!(
        change
            .operations
            .iter()
            .map(|operation| (
                operation.actor,
                operation.dispatch_ordinal,
                operation.ordinal
            ))
            .collect::<Vec<_>>(),
        vec![(child, 0, 0), (child, 1, 0)]
    );
    let mut expected_actors = vec![seed.target, child];
    expected_actors.sort_unstable();
    assert_eq!(
        change
            .materializations
            .iter()
            .map(|materialization| materialization.actor)
            .collect::<Vec<_>>(),
        expected_actors
    );
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::I64(6))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: first.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let second = admit_and_prepare(
        &mut service,
        request(InvocationId([54; 32]), 2, "increment_child_twice"),
    );
    let refined = service
        .refine_actor_tree(&second.work, &second.imports)
        .unwrap();
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::I64(12)),
        "the next slice privately imports the child's committed materialization"
    );

    // Refine a suspended child workflow and a concurrent root update from the
    // same causal base. Resumption must select the checkpoint's branch rather
    // than injecting the concurrent materialization into the captured heap.
    let mut around_arguments = vec![vos::value::TAG_DYNAMIC];
    around_arguments.extend_from_slice(
        &Msg::new("increment_child_around_peer")
            .with("before", 5u64)
            .with("after", 7u64)
            .with("parent_after", 13u64)
            .encode(),
    );
    let around_request = LocalWorkRequestV2 {
        invocation: InvocationId([59; 32]),
        workflow_step: 0,
        logical_timeslot: 3,
        target: seed.target,
        method: "increment_child_around_peer".into(),
        arguments: around_arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut concurrent_arguments = vec![vos::value::TAG_DYNAMIC];
    concurrent_arguments.extend_from_slice(&Msg::new("increment").with("amount", 11u64).encode());
    let concurrent_request = LocalWorkRequestV2 {
        invocation: InvocationId([60; 32]),
        workflow_step: 0,
        logical_timeslot: 3,
        target: seed.target,
        method: "increment".into(),
        arguments: concurrent_arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let service_identity = service.accumulate_host().header().unwrap().unwrap().service;
    let ingresses = [&around_request, &concurrent_request].map(|request| {
        LocalWorkSchedulerV2::prepare_direct_ingress(
            service.accumulate_host(),
            &service_identity,
            request,
        )
        .unwrap()
    });
    for ingress in ingresses {
        assert!(matches!(
            service
                .accumulate(&AccumulateRequestV2::AdmitIngress(ingress))
                .unwrap()
                .result,
            AccumulationResultV2::IngressAdmitted {
                duplicate: false,
                ..
            }
        ));
    }
    let around = LocalWorkSchedulerV2::prepare(service.accumulate_host(), around_request).unwrap();
    let concurrent =
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), concurrent_request).unwrap();
    assert_eq!(around.work.base, concurrent.work.base);
    let around_refined = service
        .refine_actor_tree(&around.work, &around.imports)
        .expect("CRDT child workflow checkpoints after its pre-await mutation");
    let concurrent_refined = service
        .refine_actor_tree(&concurrent.work, &concurrent.imports)
        .expect("concurrent CRDT work refines from the same causal base");
    let checkpoint_change = around_refined.transition.crdt_change.as_ref().unwrap();
    let checkpoint_height = checkpoint_change.causal_height;
    assert_eq!(checkpoint_change.operations.len(), 1);
    assert_eq!(checkpoint_change.operations[0].actor, child);
    assert_eq!(checkpoint_change.operations[0].ordinal, 0);
    assert!(around_refined.transition.reply.is_none());
    assert_eq!(around_refined.transition.outbox.len(), 1);
    let pending_call = around_refined.transition.outbox[0].call_id;
    let checkpoint_cid = checkpoint_change.cid();
    let concurrent_cid = concurrent_refined
        .transition
        .crdt_change
        .as_ref()
        .unwrap()
        .cid();

    let checkpoint_apply = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: around.work.clone(),
            transition: around_refined.transition,
            provided_blobs: around_refined.exported_blobs,
        }))
        .unwrap()
        .result;
    assert!(matches!(
        checkpoint_apply,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let concurrent_apply = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: concurrent.work,
            transition: concurrent_refined.transition,
            provided_blobs: concurrent_refined.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = &concurrent_apply else {
        panic!("concurrent CRDT branch was rejected: {concurrent_apply:?}")
    };
    let mut concurrent_heads = vec![checkpoint_cid, concurrent_cid];
    concurrent_heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, concurrent_heads);

    let reply = ReplyRecordV2 {
        call_id: pending_call,
        producer: ActorId([44; 32]),
        result: Value::U32(0).encode(),
    };
    let remote_service = bound_peer_service(&around.work.service);
    let awaited = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: remote_service,
            accepted_transition: Hash([64; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([65; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply,
        attestation: None,
    };
    service
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: awaited.receipt.clone(),
        });
    let resumed = LocalWorkSchedulerV2::prepare_resume(
        service.accumulate_host(),
        around.work.invocation,
        4,
        Some(awaited),
    )
    .expect("CRDT resume selects only the checkpoint's causal branch");
    assert_eq!(
        resumed.work.base,
        ConsistencyBaseV2::Crdt {
            heads: vec![checkpoint_cid]
        }
    );
    assert_eq!(resumed.work.base_causal_height, Some(checkpoint_height));
    assert!(resumed.work.imported_actors[0].causal_states.is_empty());
    let resumed_refined = service
        .refine_actor_tree(&resumed.work, &resumed.imports)
        .expect("restored CRDT machines rebind to the new slice change");
    let resumed_change = resumed_refined.transition.crdt_change.as_ref().unwrap();
    assert_eq!(resumed_change.causal_dependencies, vec![checkpoint_cid]);
    assert!(
        resumed_change
            .workflow
            .contains(&WorkflowOperationV2::ConsumeOutbox(pending_call))
    );
    assert_eq!(resumed_change.operations.len(), 2);
    let resumed_operation_scope = CrdtChangeV2::derive_operation_scope(&resumed.work).unwrap();
    assert!(resumed_change.operations.iter().all(|operation| {
        operation.ordinal == 0
            && operation.id
                == resumed_operation_scope.operation(
                    operation.actor,
                    operation.dispatch_ordinal,
                    operation.field,
                    0,
                )
    }));
    assert!(
        resumed_change
            .operations
            .iter()
            .any(|operation| operation.actor == seed.target)
    );
    assert!(
        resumed_change
            .operations
            .iter()
            .any(|operation| operation.actor == child)
    );
    assert_eq!(
        resumed_refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::I64(13)),
        "the suspended root heap must not observe the concurrent +11 branch"
    );
    let resumed_cid = resumed_change.cid();
    let resumed_apply = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed.work,
            transition: resumed_refined.transition,
            provided_blobs: resumed_refined.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = resumed_apply else {
        panic!("resumed CRDT transition was rejected: {resumed_apply:?}")
    };
    let mut final_heads = vec![concurrent_cid, resumed_cid];
    final_heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, final_heads);

    let mut merged_arguments = vec![vos::value::TAG_DYNAMIC];
    merged_arguments.extend_from_slice(&Msg::new("increment").with("amount", 1u64).encode());
    let merged = admit_and_prepare(
        &mut service,
        LocalWorkRequestV2 {
            invocation: InvocationId([66; 32]),
            workflow_step: 0,
            logical_timeslot: 5,
            target: seed.target,
            method: "increment".into(),
            arguments: merged_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    );
    assert_eq!(merged.work.imported_actors[0].causal_states.len(), 1);
    let merged_refined = service
        .refine_actor_tree(&merged.work, &merged.imports)
        .unwrap();
    assert_eq!(
        merged_refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::I64(25))
    );

    // A reply is consumed by the resumed slice even when that slice creates a
    // replacement continuation at an explicit yield. Consumption belongs to
    // the incoming reply, not to the shape of the outgoing checkpoint.
    let mut yield_arguments = vec![vos::value::TAG_DYNAMIC];
    yield_arguments.extend_from_slice(
        &Msg::new("increment_peer_then_yield")
            .with("before", 2u64)
            .with("after", 3u64)
            .encode(),
    );
    let await_then_yield = admit_and_prepare(
        &mut service,
        LocalWorkRequestV2 {
            invocation: InvocationId([68; 32]),
            workflow_step: 0,
            logical_timeslot: 6,
            target: seed.target,
            method: "increment_peer_then_yield".into(),
            arguments: yield_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    );
    let awaiting = service
        .refine_actor_tree(&await_then_yield.work, &await_then_yield.imports)
        .expect("the first slice checkpoints at its peer await");
    assert_eq!(awaiting.transition.outbox.len(), 1);
    let first_call = awaiting.transition.outbox[0].call_id;
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: await_then_yield.work.clone(),
                transition: awaiting.transition,
                provided_blobs: awaiting.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let reply = ReplyRecordV2 {
        call_id: first_call,
        producer: ActorId([44; 32]),
        result: Value::U32(0).encode(),
    };
    let remote_service = bound_peer_service(&await_then_yield.work.service);
    let awaited = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: remote_service,
            accepted_transition: Hash([71; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([72; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply,
        attestation: None,
    };
    service
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: ActorId([44; 32]),
            receipt: awaited.receipt.clone(),
        });
    let resumed = LocalWorkSchedulerV2::prepare_resume(
        service.accumulate_host(),
        await_then_yield.work.invocation,
        7,
        Some(awaited),
    )
    .unwrap();
    let yielded = service
        .refine_actor_tree(&resumed.work, &resumed.imports)
        .expect("the resumed slice checkpoints again at its explicit yield");
    assert!(yielded.transition.reply.is_none());
    assert!(yielded.transition.outbox.is_empty());
    assert!(
        yielded
            .transition
            .continuations
            .iter()
            .any(|change| change.replacement.is_some())
    );
    assert!(
        yielded
            .transition
            .crdt_change
            .as_ref()
            .unwrap()
            .workflow
            .contains(&WorkflowOperationV2::ConsumeOutbox(first_call))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: resumed.work,
                transition: yielded.transition,
                provided_blobs: yielded.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn canonical_crdt_resume_rebinds_the_post_await_change_identity() {
    let service_elf = service_elf();
    let actor_elf = crdt_counter_v2_elf();
    let service_pvm = vos::v2::transpile_service_elf(&service_elf).unwrap();
    let actor_pvm = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut first_work = work(actor_program, initial.clone());
    first_work.invocation = InvocationId([49; 32]);
    first_work.method = "increment_around_yield".into();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(
        &Msg::new("increment_around_yield")
            .with("amount", 2u64)
            .encode(),
    );
    first_work.arguments = message;
    first_work.consistency = ConsistencyModeV2::Crdt;
    first_work.base = ConsistencyBaseV2::Crdt { heads: vec![] };
    first_work.base_causal_height = Some(0);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: first_work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor: first_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial,
            crdt: true,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "increment_around_yield".into(),
                schema: Hash([50; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([52; 32]),
            authenticator: vec![1],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let prepared = admit_and_prepare(&mut service, request_from_work(&first_work));
    first_work = prepared.work;
    let first_imports = prepared.imports;

    let first = service
        .refine_actor_tree(&first_work, &first_imports)
        .unwrap();
    assert!(first.transition.reply.is_none());
    let first_change = first.transition.crdt_change.as_ref().unwrap();
    assert_eq!(first_change.operations.len(), 1);
    assert_eq!(first_change.operations[0].ordinal, 0);
    let first_change_id = first_change.id;
    let first_change_height = first_change.causal_height;
    let first_cid = first_change.cid();
    let state = first_change.materializations[0].state.clone();
    let continuation = first.transition.continuations[0]
        .replacement
        .clone()
        .expect("first slice publishes a continuation");
    let first_result = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_work.clone(),
            transition: first.transition,
            provided_blobs: first.exported_blobs.clone(),
        }))
        .unwrap()
        .result;
    assert!(
        matches!(
            first_result,
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ),
        "first CRDT accumulation result: {first_result:?}"
    );

    let mut second_work = first_work;
    second_work.workflow_step = 1;
    second_work.base = ConsistencyBaseV2::Crdt {
        heads: vec![first_cid],
    };
    second_work.base_causal_height = Some(first_change_height);
    second_work.imported_actors[0].state = state;
    second_work.imported_actors[0].continuation = Some(continuation);
    let second_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor_pvm,
        }],
        blobs: first.exported_blobs,
        private_blobs: vec![],
    };
    let second = service
        .refine_actor_tree(&second_work, &second_imports)
        .unwrap();
    let second_change = second.transition.crdt_change.as_ref().unwrap();
    assert_ne!(second_change.id, first_change_id);
    assert_eq!(second_change.operations.len(), 1);
    let second_operation_scope = CrdtChangeV2::derive_operation_scope(&second_work).unwrap();
    assert_eq!(
        second_change.operations[0].id,
        second_operation_scope.operation(
            second_work.target,
            second_change.operations[0].dispatch_ordinal,
            second_change.operations[0].field,
            0,
        )
    );
    assert_eq!(
        second
            .transition
            .reply
            .as_ref()
            .and_then(|reply| vos::value::Value::decode(&reply.result).as_i64()),
        Some(4)
    );
    assert_eq!(
        second.transition.continuations[0].replacement, None,
        "the resumed slice consumes its durable continuation"
    );
    assert_eq!(second.transition.consumed_input, second_work.input_id());
    assert_eq!(second.transition.base, second_work.base);
    assert_eq!(second_change.work_hash, second_work.hash());
    assert_eq!(
        second_change.workflow,
        second.transition.workflow_operations(&second_work)
    );
    let second_cid = second_change.cid();
    let accepted = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: second_work,
            transition: second.transition,
            provided_blobs: second.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
        panic!("resumed CRDT slice rejected: {accepted:?}")
    };
    assert_eq!(receipt.resulting_crdt_heads, vec![second_cid]);
}

#[test]
fn canonical_guest_rejects_a_nested_actor_without_the_reply_abi() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRefV2::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        }],
        private_blobs: vec![],
    };

    assert!(matches!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::Panic { .. })
    ));
}

#[test]
fn actor_tree_refuses_to_replay_a_continuation_from_pc_zero() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRefV2::of_bytes(&state_bytes);
    let continuation_bytes = b"portable-kernel-snapshot".to_vec();
    let continuation = BlobRefV2::of_bytes(&continuation_bytes);
    let mut work = work(actor_program, state.clone());
    work.imported_actors[0].continuation = Some(continuation.clone());
    let mut blobs = vec![
        ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        },
        ImportedBlobV2 {
            reference: continuation,
            bytes: continuation_bytes,
        },
    ];
    blobs.sort_by_key(|blob| blob.reference.hash);
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs,
        private_blobs: vec![],
    };

    assert_eq!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::InvalidContinuation)
    );
}

#[test]
fn yielding_actor_restores_exactly_from_committed_snapshot() {
    let service_elf = service_elf();
    let actor_elf = probe_elf();
    let service_pvm = vos::v2::transpile_service_elf(&service_elf).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvmV2::new(service_pvm.clone(), service_program).unwrap();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let mut first_work = work(actor_program, initial_state_ref.clone());
    let mut ping = vec![vos::value::TAG_DYNAMIC];
    ping.extend_from_slice(&Msg::new("ping").encode());
    first_work.method = "ping".into();
    first_work.arguments = ping;
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
    assert_eq!(host.import_program(actor.clone()), actor_program);
    let mut committed = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: first_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: first_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial_state_ref.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "ping".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    authorize_install(&mut committed, &install);
    let installed = committed.accumulate(&install).unwrap();
    let AccumulationResultV2::Installed(installed) = installed.result else {
        panic!("guest install rejected")
    };
    let request = LocalWorkRequestV2 {
        invocation: first_work.invocation,
        workflow_step: 0,
        logical_timeslot: first_work.logical_timeslot,
        target: first_work.target,
        method: first_work.method,
        arguments: first_work.arguments,
        origin: first_work.origin,
        authorization: first_work.authorization,
        causal_parent: first_work.causal_parent,
        parent_call: first_work.parent_call,
        causal_context: first_work.causal_context,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: first_work.imported_blobs,
        proof_requested: first_work.proof_requested,
    };
    let prepared = LocalWorkSchedulerV2::prepare(committed.accumulate_host(), request.clone())
        .expect("scheduler reconstructs initial work from guest-owned state");
    first_work = prepared.work;
    let first_imports = prepared.imports;
    admit_linear_work(&mut committed, &first_work);
    assert_eq!(
        first_work.base,
        ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        }
    );

    let first_output = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    let deterministic_retry = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        deterministic_retry, first_output,
        "checkpoint bytes and transition must be deterministic"
    );
    let recompiled_first = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(
        recompiled_first, first_output,
        "interpreter and recompiler checkpoints must be identical"
    );
    let refined_first = RefineOutputV2::decode(&first_output.bytes).unwrap();
    let first = refined_first.transition;
    let mut first_candidate_blobs = refined_first.candidate_blobs;
    first_candidate_blobs.extend(first_output.exported_blobs.clone());
    first_candidate_blobs.sort_by_key(|blob| blob.reference.hash);
    first_candidate_blobs.dedup();
    assert!(first.reply.is_none(), "yield must not publish a reply");
    assert_eq!(first.continuations.len(), 1);
    let first_continuation = first.continuations[0].replacement.clone().unwrap();
    assert_eq!(first.exported_blobs, vec![first_continuation.clone()]);
    assert_eq!(first_output.exported_blobs.len(), 1);
    assert_eq!(first_output.exported_blobs[0].reference, first_continuation);
    let checkpoint_state = first
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.clone())
        .expect("checkpoint commits the mutation before await");
    assert_eq!(u32::decode(&checkpoint_state), 1);
    let checkpoint_request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: first_work.clone(),
        transition: first.clone(),
        provided_blobs: first_candidate_blobs,
    });
    let mut interpreted_host = committed.accumulate_host().clone();
    let mut recompiled_host = interpreted_host.clone();
    let interpreted_accumulate = service
        .accumulate_with_backend(
            &checkpoint_request.encode(),
            5_000_000_000,
            &mut interpreted_host,
            javm::PvmBackend::ForceInterpreter,
        )
        .expect("the canonical Accumulate guest runs in the interpreter");
    let recompiled_accumulate = service
        .accumulate_with_backend(
            &checkpoint_request.encode(),
            5_000_000_000,
            &mut recompiled_host,
            javm::PvmBackend::ForceRecompiler,
        )
        .expect("the canonical Accumulate guest runs in the recompiler");
    assert_eq!(
        interpreted_accumulate, recompiled_accumulate,
        "the physical IC-5 output and gas accounting are backend-independent"
    );
    assert_eq!(
        interpreted_host, recompiled_host,
        "both backends commit the same guest-owned service image"
    );
    let checkpoint_outcome = committed.accumulate(&checkpoint_request).unwrap();
    let AccumulationResultV2::Accepted {
        receipt: checkpoint_receipt,
        published,
        duplicate,
    } = checkpoint_outcome.result
    else {
        panic!("guest rejected the transition emitted by its own Refine entry")
    };
    assert!(!duplicate);
    assert!(published.reply.is_none());
    let checkpoint_state_ref = BlobRefV2::of_bytes(&checkpoint_state);
    assert_eq!(
        committed.accumulate_host().blob(&checkpoint_state_ref),
        Some(checkpoint_state.as_slice()),
        "guest Accumulate must durably record the checkpoint state"
    );

    // Reconstruct the runtime from an in-memory committed snapshot after
    // Accumulate commits slice 0. The scheduler must recover the exact program,
    // actor state, and continuation rather than use this test's local values.
    let reopened = LocalJamStoreV2::from_snapshot(committed.accumulate_host().snapshot());
    let mut resume_request = request;
    resume_request.workflow_step = 1;
    let mut changed_identity = resume_request.clone();
    changed_identity.origin = Origin::System;
    assert_eq!(
        LocalWorkSchedulerV2::prepare(&reopened, changed_identity),
        Err(ScheduleErrorV2::InvalidWorkflowStep(first_work.invocation)),
        "a continuation cannot resume under a different caller identity"
    );
    let mut alternate_arguments = resume_request.clone();
    alternate_arguments.arguments = b"ignored resume arguments".to_vec();
    let alternate = LocalWorkSchedulerV2::prepare(&reopened, alternate_arguments)
        .expect("dead resume arguments are canonicalized");
    let prepared = LocalWorkSchedulerV2::prepare(&reopened, resume_request)
        .expect("scheduler reconstructs the exact next continuation slice");
    assert_eq!(
        alternate, prepared,
        "resume retries cannot mint divergent work identities from dead arguments"
    );
    let resumed_work = prepared.work;
    let resumed_imports = prepared.imports;
    assert!(resumed_work.arguments.is_empty());
    assert_eq!(
        resumed_work.base,
        ConsistencyBaseV2::Linear {
            revision: checkpoint_receipt.sequence,
            state_root: checkpoint_receipt.resulting_state_root.unwrap(),
        }
    );
    assert_eq!(resumed_work.imported_actors[0].state, checkpoint_state_ref);
    assert_eq!(
        resumed_work.imported_actors[0].continuation,
        Some(first_continuation.clone())
    );
    let mut committed = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .expect("snapshot reopens the canonical service PVM over committed state");

    let resumed_output = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    let recompiled_resumed = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(
        recompiled_resumed, resumed_output,
        "interpreter and recompiler resumes must be identical"
    );
    let refined_resumed = RefineOutputV2::decode(&resumed_output.bytes).unwrap();
    let resumed = refined_resumed.transition;
    let mut resumed_candidate_blobs = refined_resumed.candidate_blobs;
    resumed_candidate_blobs.extend(resumed_output.exported_blobs.clone());
    resumed_candidate_blobs.sort_by_key(|blob| blob.reference.hash);
    resumed_candidate_blobs.dedup();
    assert!(
        resumed.reply.is_some(),
        "handler completes after exact resume"
    );
    assert_eq!(resumed.consumed_input, resumed_work.input_id());
    assert_eq!(resumed.base, resumed_work.base);
    assert_eq!(resumed.continuations.len(), 1);
    assert_eq!(
        resumed.continuations[0].expected,
        Some(first_continuation.hash)
    );
    assert_eq!(resumed.continuations[0].replacement, None);
    assert!(resumed_output.exported_blobs.is_empty());
    let resumed_state = resumed
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .expect("resumed actor reports its retained state");
    assert_eq!(
        u32::decode(resumed_state),
        1,
        "code before .await must not execute again"
    );
    let committed_before_resume = committed.accumulate_host().snapshot();
    let completed = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed_work,
            transition: resumed.clone(),
            provided_blobs: resumed_candidate_blobs,
        }))
        .unwrap();
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = completed.result
    else {
        panic!("guest rejected its own resumed transition")
    };
    assert!(!duplicate);
    assert_eq!(receipt.sequence, checkpoint_receipt.sequence + 1);
    assert_eq!(published.reply, resumed.reply);
    assert!(
        !committed
            .accumulate_host()
            .snapshot()
            .same_service_state(&committed_before_resume)
    );
    let resumed_state_ref = BlobRefV2::of_bytes(resumed_state);
    assert_eq!(
        committed.accumulate_host().blob(&resumed_state_ref),
        Some(resumed_state.as_slice())
    );
}

#[test]
fn awaited_reply_is_injected_at_the_exact_machine_boundary() {
    let service_pvm = vos::v2::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvmV2::new(service_pvm.clone(), service_program).unwrap();
    let actor_elf = probe_elf();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let mut seed_work = work(actor_program, initial_state_ref.clone());
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer").encode());
    seed_work.method = "await_peer".into();
    seed_work.arguments = arguments;

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_state), initial_state_ref);
    assert_eq!(host.import_program(actor), actor_program);
    let mut committed = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install_request = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![private_age_binding(&seed_work.service)],
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial_state_ref,
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "await_peer".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    authorize_install(&mut committed, &install_request);
    let install = committed.accumulate(&install_request).unwrap();
    assert!(matches!(install.result, AccumulationResultV2::Installed(_)));
    let request = LocalWorkRequestV2 {
        invocation: seed_work.invocation,
        workflow_step: 0,
        logical_timeslot: seed_work.logical_timeslot,
        target: seed_work.target,
        method: seed_work.method,
        arguments: seed_work.arguments,
        origin: seed_work.origin,
        authorization: seed_work.authorization,
        causal_parent: seed_work.causal_parent,
        parent_call: seed_work.parent_call,
        causal_context: seed_work.causal_context,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: seed_work.imported_blobs,
        proof_requested: seed_work.proof_requested,
    };
    let prepared = LocalWorkSchedulerV2::prepare(committed.accumulate_host(), request.clone())
        .expect("scheduler reconstructs the initial actor slice");
    let first_work = prepared.work;
    let first_imports = prepared.imports;
    admit_linear_work(&mut committed, &first_work);

    let first_output = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &first_work.encode(),
                &first_imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        first_output,
        "both JAR backends must capture the same awaited-call boundary"
    );
    let first = RefineOutputV2::decode(&first_output.bytes)
        .unwrap()
        .transition;
    assert!(first.reply.is_none());
    assert_eq!(first.outbox.len(), 1);
    let call_id = first_work.invocation.call_id(0);
    assert_eq!(first.outbox[0].call_id, call_id);
    assert_eq!(first.outbox[0].to, ActorId([44; 32]));
    assert_eq!(first.outbox[0].deadline_timeslot, Some(100));
    let first_continuation = first.continuations[0].replacement.clone().unwrap();
    let continuation = ContinuationSnapshotV2::decode(&first_output.exported_blobs[0].bytes)
        .expect("checkpoint exports the exact continuation envelope");
    assert_eq!(continuation.await_ordinal, 0);
    assert_eq!(continuation.pending_call, Some(call_id));
    let checkpoint_state = first
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.clone())
        .expect("pre-await mutation is part of the checkpoint transition");
    assert_eq!(u32::decode(&checkpoint_state), 1);

    let refined_first = RefineOutputV2::decode(&first_output.bytes).unwrap();
    let mut first_candidate_blobs = refined_first.candidate_blobs;
    first_candidate_blobs.extend(first_output.exported_blobs.clone());
    first_candidate_blobs.sort_by_key(|blob| blob.reference.hash);
    first_candidate_blobs.dedup();
    let checkpointed = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_work.clone(),
            transition: first,
            provided_blobs: first_candidate_blobs,
        }))
        .expect("checkpoint and durable outbox commit atomically");
    assert!(matches!(
        checkpointed.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let checkpoint_state_ref = BlobRefV2::of_bytes(&checkpoint_state);

    // Fork from the committed checkpoint and prove that timeout is itself a
    // durable guest transition before the exact machine is restored. A crash
    // at either boundary must not replay code before `.await`.
    let persisted_checkpoint = committed.accumulate_host().snapshot_bytes();
    let timeout_store = LocalJamStoreV2::from_snapshot_bytes(&persisted_checkpoint)
        .expect("the checkpoint image starts an independent timeout branch");
    let timeout_jam = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        timeout_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let timeout_follower_store = LocalJamStoreV2::from_snapshot_bytes(&persisted_checkpoint)
        .expect("the follower starts from the identical checkpoint image");
    let timeout_follower_jam = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        timeout_follower_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let timeout_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut timeout_service = ReplicatedJamServiceV2::new(
        timeout_jam,
        TestCommittedLog::new(timeout_log.clone(), true),
    );
    let mut timeout_follower = ReplicatedJamServiceV2::new(
        timeout_follower_jam,
        TestCommittedLog::new(timeout_log, false),
    );
    assert!(
        LocalWorkSchedulerV2::prepare_due_call_expirations(
            timeout_service.service().accumulate_host(),
            99,
        )
        .unwrap()
        .is_empty(),
        "a logical timeslot before the deadline cannot expire the call"
    );
    let due = LocalWorkSchedulerV2::prepare_due_call_expirations(
        timeout_service.service().accumulate_host(),
        100,
    )
    .expect("durable deadline rows are restart-discoverable");
    assert_eq!(due.len(), 1);
    let expiration = due.into_iter().next().unwrap();
    assert_eq!(expiration.timeout.caller_invocation, first_work.invocation);
    let before_untrusted_expiration = timeout_service.service().accumulate_host().snapshot();
    assert!(matches!(
        timeout_service
            .accumulate(&AccumulateRequestV2::ExpireCall(expiration.clone()))
            .unwrap_err(),
        ReplicatedServiceErrorV2::LogicalTimeslotRequired
    ));
    assert_eq!(timeout_service.log().committed_len(), 0);
    assert_eq!(
        timeout_service.service().accumulate_host().snapshot(),
        before_untrusted_expiration
    );
    let expired = timeout_service
        .accumulate_at(&AccumulateRequestV2::ExpireCall(expiration), 100)
        .expect("the Raft entry and physical guest Accumulate commit the timeout");
    assert_eq!(timeout_follower.catch_up().unwrap(), 1);
    assert!(
        timeout_service
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&timeout_follower.service().accumulate_host().snapshot()),
        "the follower replays the committed ambient JAM slot through IC-5"
    );
    let AccumulationResultV2::CallExpired {
        timeout,
        duplicate: false,
    } = expired.result
    else {
        panic!("due call expiration was rejected")
    };
    assert_eq!(timeout.expiration.timeout.call_id, call_id);
    assert_eq!(
        timeout_service
            .service()
            .accumulate_host()
            .outbox_message(call_id)
            .unwrap(),
        None,
        "expiration atomically retires the live transport effect"
    );
    assert!(
        timeout_service
            .service()
            .accumulate_host()
            .pending_call_deadlines()
            .unwrap()
            .is_empty(),
        "expiration retires the restart deadline index atomically"
    );
    assert!(
        timeout_service
            .service()
            .accumulate_host()
            .pending_publications()
            .unwrap()
            .is_empty(),
        "an undelivered publication is terminally retired with its timeout"
    );

    let timeout_persisted = timeout_service.service().accumulate_host().snapshot_bytes();
    let timeout_restarted_store = LocalJamStoreV2::from_snapshot_bytes(&timeout_persisted)
        .expect("the expiration outcome survives a second process restart");
    let mut timeout_restarted_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        timeout_restarted_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    assert_eq!(
        LocalWorkSchedulerV2::pending_timeout_resumes(timeout_restarted_service.accumulate_host()),
        Ok(vec![first_work.invocation]),
        "expiration outcomes remain enumerable after their deadline rows are gone"
    );
    let timed_out = LocalWorkSchedulerV2::prepare_timeout_resume(
        timeout_restarted_service.accumulate_host(),
        first_work.invocation,
        100,
    )
    .expect("guest-owned expiration state is readable")
    .expect("the exact suspended workflow is ready to resume");
    assert_eq!(timed_out.work.awaited_timeout.as_deref(), Some(&timeout));
    assert!(timed_out.work.awaited_reply.is_none());
    let timed_out_output = service
        .refine_actor_tree_with_backend(
            &timed_out.work.encode(),
            &timed_out.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .expect("the interpreter injects the committed timeout");
    let recompiled_timeout = service
        .refine_actor_tree_with_backend(
            &timed_out.work.encode(),
            &timed_out.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .expect("the recompiler injects the same committed timeout");
    assert_eq!(timed_out_output, recompiled_timeout);

    // A different runnable actor may have spawned a child while this kernel
    // was suspended. The current work import must include the complete newer
    // directory, while JAR restoration still uses only the exact dormant
    // program layout captured by the continuation.
    let mut expanded = timed_out.clone();
    // Sort before the existing target to prove current directory order does
    // not renumber the VMs captured by the older continuation.
    let new_child = ActorId([3; 32]);
    let new_child_state_bytes = b"late child state".to_vec();
    let new_child_state = BlobRefV2::of_bytes(&new_child_state_bytes);
    expanded
        .work
        .imported_actors
        .push(vos::v2::ImportedActorV2 {
            actor: new_child,
            name: "late-child".into(),
            parent: Some(first_work.target),
            deployment: first_work.target_deployment,
            program: actor_program,
            task_dependencies: vec![],
            state: new_child_state.clone(),
            causal_states: vec![],
            continuation: None,
            storage_rows: vec![],
        });
    expanded
        .work
        .imported_actors
        .sort_by_key(|actor| actor.actor);
    expanded.imports.blobs.push(ImportedBlobV2 {
        reference: new_child_state,
        bytes: new_child_state_bytes,
    });
    expanded
        .imports
        .blobs
        .sort_by_key(|blob| blob.reference.hash);
    let expanded_timeout = service
        .refine_actor_tree_with_backend(
            &expanded.work.encode(),
            &expanded.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .expect("a newer tree directory does not rewrite the suspended JAR layout");
    assert_eq!(expanded_timeout.bytes, timed_out_output.bytes);
    assert_eq!(
        expanded_timeout.exported_blobs,
        timed_out_output.exported_blobs
    );
    assert_eq!(expanded_timeout.trace, timed_out_output.trace);

    let timed_out_refined = RefineOutputV2::decode(&timed_out_output.bytes).unwrap();
    let timed_out_transition = timed_out_refined.transition;
    let timed_out_state = timed_out_transition
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .expect("the timed-out handler returns its checkpointed state");
    assert_eq!(
        u32::decode(timed_out_state),
        1,
        "code before the timed-out await executes exactly once"
    );
    assert_eq!(
        timed_out_transition
            .reply
            .as_ref()
            .map(|reply| vos::value::Value::decode(&reply.result)),
        Some(vos::value::Value::U32(1))
    );
    let timed_out_work = timed_out.work;
    let completed_timeout = timeout_restarted_service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: timed_out_work,
            transition: timed_out_transition,
            provided_blobs: timed_out_refined.candidate_blobs,
        }))
        .expect("guest Accumulate accepts only the committed timeout outcome");
    assert!(matches!(
        completed_timeout.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        LocalWorkSchedulerV2::prepare_timeout_resume(
            timeout_restarted_service.accumulate_host(),
            first_work.invocation,
            101,
        ),
        Ok(None),
        "the completed continuation cannot consume the timeout twice"
    );
    assert!(
        LocalWorkSchedulerV2::pending_timeout_resumes(timeout_restarted_service.accumulate_host())
            .unwrap()
            .is_empty(),
        "historical expiration rows do not requeue a completed workflow"
    );

    // Reconstruct the service from committed state before the peer reply
    // arrives. No live handler future or warm actor VM survives this boundary.
    let reopened = LocalJamStoreV2::from_snapshot(committed.accumulate_host().snapshot());

    let reply = ReplyRecordV2 {
        call_id,
        producer: ActorId([44; 32]),
        result: vos::value::Value::U32(7).encode(),
    };
    let mut remote_service = first_work.service.clone();
    remote_service.root_service = RootServiceId([45; 32]);
    remote_service.deployment = DeploymentId([46; 32]);
    let awaited_reply = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: remote_service,
            accepted_transition: Hash([47; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([48; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply,
        attestation: None,
    };
    let mut resume_request = request;
    resume_request.workflow_step = 1;
    resume_request.logical_timeslot = 2;
    resume_request.awaited_reply = Some(awaited_reply.clone());
    let prepared = LocalWorkSchedulerV2::prepare(&reopened, resume_request)
        .expect("scheduler imports the committed state and exact continuation");
    let resumed_work = prepared.work;
    let resumed_imports = prepared.imports;
    assert_eq!(resumed_work.imported_actors[0].state, checkpoint_state_ref);
    assert_eq!(
        resumed_work.imported_actors[0].continuation,
        Some(first_continuation.clone())
    );

    let mut wrong_work = resumed_work.clone();
    let wrong_reply = wrong_work.awaited_reply.as_mut().unwrap();
    wrong_reply.reply.call_id = InvocationId([49; 32]).call_id(0);
    wrong_reply.receipt.reply_commitment = Some(wrong_reply.reply.commitment());
    assert_eq!(
        service.refine_actor_tree_with_backend(
            &wrong_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        ),
        Err(ServicePvmErrorV2::ContinuationMismatch),
        "a different accumulated CallId cannot resume this machine"
    );

    let resumed_output = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &resumed_work.encode(),
                &resumed_imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        resumed_output,
        "both JAR backends must inject the same reply into the same snapshot"
    );
    let mut committed = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .expect("reopened state drives the same canonical service PVM");
    let resumed = RefineOutputV2::decode(&resumed_output.bytes)
        .unwrap()
        .transition;
    assert!(resumed.outbox.is_empty());
    assert_eq!(resumed.continuations.len(), 1);
    assert_eq!(
        resumed.continuations[0].expected,
        Some(first_continuation.hash)
    );
    assert_eq!(resumed.continuations[0].replacement, None);
    let resumed_state = resumed
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .expect("post-await state is returned by the original handler");
    assert_eq!(
        u32::decode(resumed_state),
        8,
        "pre-await code runs once and the committed reply is observed once"
    );
    assert_eq!(
        resumed
            .reply
            .as_ref()
            .map(|reply| vos::value::Value::decode(&reply.result)),
        Some(vos::value::Value::U32(8))
    );

    committed
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: awaited_reply.reply.producer,
            receipt: awaited_reply.receipt,
        });
    let completed = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed_work,
            transition: resumed.clone(),
            provided_blobs: vec![],
        }))
        .expect("guest Accumulate accepts the exact injected reply");
    let AccumulationResultV2::Accepted {
        published,
        duplicate: false,
        ..
    } = completed.result
    else {
        panic!("guest rejected the completed await")
    };
    assert_eq!(published.reply, resumed.reply);
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Outbox(call_id))
            .unwrap(),
        None,
        "reply commit consumes the exact pending outbox"
    );
}

#[test]
fn durable_inbox_work_survives_two_exact_awaits_and_two_restarts() {
    let service_pvm = vos::v2::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvmV2::new(service_pvm.clone(), service_program).unwrap();
    let actor = grey_transpiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let identity = work(actor_program, initial_state_ref.clone()).service;
    let caller = ActorId([4; 32]);
    let target = ActorId([5; 32]);
    let mut first_remote_service = identity.clone();
    first_remote_service.root_service = RootServiceId([70; 32]);
    first_remote_service.deployment = DeploymentId([71; 32]);
    let mut second_remote_service = identity.clone();
    second_remote_service.root_service = RootServiceId([74; 32]);
    second_remote_service.deployment = DeploymentId([75; 32]);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_state), initial_state_ref);
    assert_eq!(host.import_program(actor), actor_program);
    let mut committed = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install_request = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![
            external_binding(
                "peer-1",
                first_remote_service.clone(),
                ActorId([44; 32]),
                ProducerId([44; 32]),
                actor_program,
            ),
            external_binding(
                "peer-2",
                second_remote_service.clone(),
                ActorId([45; 32]),
                ProducerId([45; 32]),
                actor_program,
            ),
        ],
        service: identity.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: caller,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial_state_ref.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "seed".into(),
                    schema: Hash([31; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
            },
            ActorGenesisV2 {
                actor: target,
                name: "child".into(),
                parent: Some(caller),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial_state_ref,
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "await_two_peers".into(),
                    schema: Hash([33; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([35; 32]),
            authenticator: vec![36],
        },
    });
    authorize_install(&mut committed, &install_request);
    let installed = committed.accumulate(&install_request).unwrap();
    assert!(matches!(
        installed.result,
        AccumulationResultV2::Installed(_)
    ));

    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&Msg::new("await_two_peers").encode());
    let caller_invocation = InvocationId([60; 32]);
    let inbound_call = caller_invocation.call_id(0);
    let inbound = MessageRecordV2 {
        call_id: inbound_call,
        caller_invocation,
        await_ordinal: 0,
        from_service: identity.clone(),
        from: caller,
        to_service: identity.clone(),
        to: target,
        parent: None,
        payload: payload.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        proof_requested: false,
        deadline_timeslot: Some(200),
    };
    let mut seed_payload = vec![vos::value::TAG_DYNAMIC];
    seed_payload.extend_from_slice(&Msg::new("seed").encode());
    let seed_request = LocalWorkRequestV2 {
        invocation: InvocationId([61; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: caller,
        method: "seed".into(),
        arguments: seed_payload,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let seeded = LocalWorkSchedulerV2::prepare(committed.accumulate_host(), seed_request).unwrap();
    admit_linear_work(&mut committed, &seeded.work);
    let seed_transition = TransitionV2 {
        service: seeded.work.service.clone(),
        consumed_input: seeded.work.input_id(),
        target_deployment: seeded.work.target_deployment,
        target_program: seeded.work.target_program,
        base: seeded.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![inbound.clone()],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let seeded = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: seeded.work,
            transition: seed_transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    assert!(matches!(
        seeded.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let initial = LocalWorkSchedulerV2::prepare_inbox(committed.accumulate_host(), inbound_call, 2)
        .expect("committed inbox reconstructs the initial callee slice");
    assert_eq!(
        initial.work.causal_context,
        Some(vos::v2::CausalCallContextV2::from(&inbound))
    );
    let initial_output = service
        .refine_actor_tree_with_backend(
            &initial.work.encode(),
            &initial.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &initial.work.encode(),
                &initial.imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        initial_output
    );
    let initial_refined = RefineOutputV2::decode(&initial_output.bytes).unwrap();
    let initial_transition = initial_refined.transition;
    let first_call = initial.work.invocation.call_id(0);
    assert_eq!(initial_transition.outbox.len(), 1);
    assert_eq!(initial_transition.outbox[0].call_id, first_call);
    assert_eq!(initial_transition.outbox[0].parent, Some(inbound_call));
    assert_eq!(initial_transition.outbox[0].to, ActorId([44; 32]));
    let first_state = initial_transition
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .unwrap();
    assert_eq!(u32::decode(first_state), 1);
    let first_continuation = initial_transition.continuations[0]
        .replacement
        .clone()
        .unwrap();
    let first_snapshot = ContinuationSnapshotV2::decode(
        &initial_output
            .exported_blobs
            .iter()
            .find(|blob| blob.reference == first_continuation)
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(first_snapshot.await_ordinal, 0);
    assert_eq!(first_snapshot.pending_call, Some(first_call));
    assert_eq!(first_snapshot.causal_context, initial.work.causal_context);
    let mut first_blobs = initial_refined.candidate_blobs;
    first_blobs.extend(initial_output.exported_blobs);
    first_blobs.sort_by_key(|blob| blob.reference.hash);
    first_blobs.dedup();
    let checkpointed = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: initial.work.clone(),
            transition: initial_transition,
            provided_blobs: first_blobs,
        }))
        .unwrap();
    assert!(matches!(
        checkpointed.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Inbox(inbound_call))
            .unwrap(),
        None,
        "step 0 consumes the only live copy of the inbound inbox row"
    );

    // A timeout may resume directly into another await. The new checkpoint
    // must consume call 0 and publish call 1 in the same guest transaction;
    // tying consumption to handler completion would wedge this saga.
    let timeout_branch =
        LocalJamStoreV2::from_snapshot_bytes(&committed.accumulate_host().snapshot_bytes())
            .unwrap();
    let mut timeout_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        timeout_branch,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let expiration = LocalWorkSchedulerV2::prepare_call_expiration(
        timeout_service.accumulate_host(),
        initial.work.invocation,
        100,
    )
    .unwrap()
    .expect("the first peer call is due");
    assert!(matches!(
        timeout_service
            .accumulate_at(&AccumulateRequestV2::ExpireCall(expiration), 100)
            .unwrap()
            .result,
        AccumulationResultV2::CallExpired {
            duplicate: false,
            ..
        }
    ));
    let mut timeout_resume = LocalWorkSchedulerV2::prepare_timeout_resume(
        timeout_service.accumulate_host(),
        initial.work.invocation,
        100,
    )
    .unwrap()
    .expect("the timed-out first await is resumable");
    let timeout_output = loop {
        match service.refine_actor_tree_with_backend(
            &timeout_resume.work.encode(),
            &timeout_resume.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        ) {
            Ok(output) => break output,
            Err(ServicePvmErrorV2::ActorStorageWitnessRequired(requests)) => {
                LocalWorkSchedulerV2::hydrate_actor_storage_rows(
                    timeout_service.accumulate_host(),
                    &mut timeout_resume,
                    &requests,
                )
                .unwrap();
            }
            Err(error) => panic!("timeout resume Refine failed: {error:?}"),
        }
    };
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &timeout_resume.work.encode(),
                &timeout_resume.imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        timeout_output
    );
    let timeout_refined = RefineOutputV2::decode(&timeout_output.bytes).unwrap();
    let timeout_transition = timeout_refined.transition;
    let second_timeout_call = initial.work.invocation.call_id(1);
    assert_eq!(timeout_transition.outbox.len(), 1);
    assert_eq!(timeout_transition.outbox[0].call_id, second_timeout_call);
    let timeout_state = timeout_transition
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .unwrap();
    assert_eq!(
        u32::decode(timeout_state),
        11,
        "the first timeout skips its value, then execution reaches await 2 exactly once"
    );
    let mut timeout_blobs = timeout_refined.candidate_blobs;
    timeout_blobs.extend(timeout_output.exported_blobs);
    timeout_blobs.sort_by_key(|blob| blob.reference.hash);
    timeout_blobs.dedup();
    let timeout_checkpoint = timeout_service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: timeout_resume.work,
            transition: timeout_transition,
            provided_blobs: timeout_blobs,
        }))
        .expect("timeout resume atomically replaces the awaited checkpoint");
    assert!(
        matches!(
            timeout_checkpoint.result,
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ),
        "timeout resume was rejected: {:?}",
        timeout_checkpoint.result
    );
    let timeout_header = timeout_service.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        timeout_service
            .accumulate_host()
            .state_row(timeout_header.service_root, &StateKeyV2::Outbox(first_call))
            .unwrap(),
        None
    );
    assert!(
        timeout_service
            .accumulate_host()
            .state_row(
                timeout_header.service_root,
                &StateKeyV2::Outbox(second_timeout_call),
            )
            .unwrap()
            .is_some()
    );

    let first_reply = ReplyRecordV2 {
        call_id: first_call,
        producer: ActorId([44; 32]),
        result: vos::value::Value::U32(7).encode(),
    };
    let first_awaited = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: first_remote_service,
            accepted_transition: Hash([72; 32]),
            reply_commitment: Some(first_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([73; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply: first_reply,
        attestation: None,
    };

    let reopened = LocalJamStoreV2::from_snapshot(committed.accumulate_host().snapshot());
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(&reopened, initial.work.invocation, 3, None),
        Err(ScheduleErrorV2::MissingAwaitedReply(first_call))
    );
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(
            &reopened,
            initial.work.invocation,
            200,
            Some(first_awaited.clone()),
        ),
        Err(ScheduleErrorV2::DeadlineExpired(inbound_call))
    );
    let mut wrong_first_reply = first_awaited.clone();
    wrong_first_reply.reply.call_id = InvocationId([78; 32]).call_id(0);
    wrong_first_reply.receipt.reply_commitment = Some(wrong_first_reply.reply.commitment());
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(
            &reopened,
            initial.work.invocation,
            3,
            Some(wrong_first_reply.clone()),
        ),
        Err(ScheduleErrorV2::UnexpectedAwaitedReply(
            wrong_first_reply.reply.call_id
        ))
    );
    let mut first_resume = LocalWorkSchedulerV2::prepare_resume(
        &reopened,
        initial.work.invocation,
        3,
        Some(first_awaited.clone()),
    )
    .expect("guest-owned workflow state reconstructs the first resume");
    assert_eq!(first_resume.work.workflow_step, 1);
    assert_eq!(
        first_resume.work.causal_context,
        initial.work.causal_context
    );
    assert!(first_resume.work.arguments.is_empty());
    let mut expired_resume_work = first_resume.work.clone();
    expired_resume_work.logical_timeslot = 200;
    let expired_resume_transition = TransitionV2 {
        service: expired_resume_work.service.clone(),
        consumed_input: expired_resume_work.input_id(),
        target_deployment: expired_resume_work.target_deployment,
        target_program: expired_resume_work.target_program,
        base: expired_resume_work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let before_expired_resume = committed.accumulate_host().snapshot();
    let expired_resume = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: expired_resume_work,
            transition: expired_resume_transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    assert_eq!(
        expired_resume.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidWorkflowTransition)
    );
    assert_eq!(
        committed.accumulate_host().snapshot(),
        before_expired_resume,
        "guest Accumulate must enforce the retained parent deadline after the inbox row is gone"
    );
    let first_resumed_output = loop {
        match service.refine_actor_tree_with_backend(
            &first_resume.work.encode(),
            &first_resume.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        ) {
            Ok(output) => break output,
            Err(ServicePvmErrorV2::ActorStorageWitnessRequired(requests)) => {
                LocalWorkSchedulerV2::hydrate_actor_storage_rows(
                    &reopened,
                    &mut first_resume,
                    &requests,
                )
                .unwrap();
            }
            Err(error) => panic!("first reply resume Refine failed: {error:?}"),
        }
    };
    assert_eq!(
        first_resume
            .work
            .imported_actors
            .iter()
            .map(|actor| actor.storage_rows.len())
            .sum::<usize>(),
        vos::v2::MAX_ACTOR_STORAGE_WITNESSES,
    );
    assert!(
        first_resume.work.encode().len() > vos::v2::CHECKPOINT_TOKEN_CAPACITY,
        "the physical resume must exceed the old inline-token capacity"
    );
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &first_resume.work.encode(),
                &first_resume.imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        first_resumed_output
    );
    let first_resumed_refined = RefineOutputV2::decode(&first_resumed_output.bytes).unwrap();
    let first_resumed_transition = first_resumed_refined.transition;
    let second_call = initial.work.invocation.call_id(1);
    assert_eq!(first_resumed_transition.outbox.len(), 1);
    assert_eq!(first_resumed_transition.outbox[0].call_id, second_call);
    assert_eq!(
        first_resumed_transition.outbox[0].parent,
        Some(inbound_call)
    );
    assert_eq!(first_resumed_transition.outbox[0].to, ActorId([45; 32]));
    let second_state = first_resumed_transition
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .unwrap();
    assert_eq!(
        u32::decode(second_state),
        18,
        "the first reply and the mutation before await 2 execute once"
    );
    let second_continuation = first_resumed_transition.continuations[0]
        .replacement
        .clone()
        .unwrap();
    assert_ne!(second_continuation, first_continuation);
    let second_snapshot = ContinuationSnapshotV2::decode(
        &first_resumed_output
            .exported_blobs
            .iter()
            .find(|blob| blob.reference == second_continuation)
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(second_snapshot.await_ordinal, 1);
    assert_eq!(second_snapshot.pending_call, Some(second_call));
    assert_eq!(second_snapshot.causal_context, initial.work.causal_context);

    let mut first_resume_blobs = first_resumed_refined.candidate_blobs;
    first_resume_blobs.extend(first_resumed_output.exported_blobs);
    first_resume_blobs.sort_by_key(|blob| blob.reference.hash);
    first_resume_blobs.dedup();
    let mut committed = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    committed
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: first_awaited.reply.producer,
            receipt: first_awaited.receipt,
        });
    let second_checkpoint = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_resume.work,
            transition: first_resumed_transition,
            provided_blobs: first_resume_blobs,
        }))
        .expect("retained causal context validates await 2 after inbox consumption");
    assert!(matches!(
        second_checkpoint.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Outbox(first_call))
            .unwrap(),
        None
    );
    assert!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Outbox(second_call))
            .unwrap()
            .is_some()
    );

    let second_reply = ReplyRecordV2 {
        call_id: second_call,
        producer: ActorId([45; 32]),
        result: vos::value::Value::U32(5).encode(),
    };
    let second_awaited = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: second_remote_service,
            accepted_transition: Hash([76; 32]),
            reply_commitment: Some(second_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([77; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply: second_reply,
        attestation: None,
    };

    let reopened = LocalJamStoreV2::from_snapshot(committed.accumulate_host().snapshot());
    let second_resume = LocalWorkSchedulerV2::prepare_resume(
        &reopened,
        initial.work.invocation,
        4,
        Some(second_awaited.clone()),
    )
    .expect("guest-owned workflow state reconstructs the second resume");
    assert_eq!(second_resume.work.workflow_step, 2);
    assert_eq!(
        second_resume.work.causal_context,
        initial.work.causal_context
    );
    let completed_output = service
        .refine_actor_tree_with_backend(
            &second_resume.work.encode(),
            &second_resume.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &second_resume.work.encode(),
                &second_resume.imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        completed_output
    );
    let completed_refined = RefineOutputV2::decode(&completed_output.bytes).unwrap();
    let completed_transition = completed_refined.transition;
    assert!(completed_transition.outbox.is_empty());
    assert_eq!(
        completed_transition.continuations[0].expected,
        Some(second_continuation.hash)
    );
    assert_eq!(completed_transition.continuations[0].replacement, None);
    let completed_state = completed_transition
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .unwrap();
    assert_eq!(u32::decode(completed_state), 23);
    assert_eq!(
        completed_transition
            .reply
            .as_ref()
            .map(|reply| vos::value::Value::decode(&reply.result)),
        Some(vos::value::Value::U32(23))
    );

    let mut committed = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    committed
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: second_awaited.reply.producer,
            receipt: second_awaited.receipt,
        });
    let completed = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: second_resume.work,
            transition: completed_transition,
            provided_blobs: completed_refined.candidate_blobs,
        }))
        .unwrap();
    assert!(matches!(
        completed.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Outbox(second_call))
            .unwrap(),
        None
    );
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Continuation(target))
            .unwrap(),
        None
    );
}

#[test]
fn canonical_guest_accumulate_installs_applies_and_deduplicates_at_ic5() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = b"canonical actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
    assert_eq!(host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();

    let mut wrong_refine_service = seed_work.clone();
    wrong_refine_service.service.service_program = ProgramId([3; 32]);
    assert_eq!(
        service.refine_actor_tree(&wrong_refine_service, &RefineImportsV2::default()),
        Err(ServiceDispatchError::ServiceProgramMismatch {
            expected: vos::v2::VOS_SERVICE_PROGRAM_ID,
            declared: ProgramId([3; 32]),
        }),
        "platform dispatch must bind work to the PVM executing Refine"
    );

    let child = ActorId([36; 32]);
    let peer = ActorId([81; 32]);
    let mut remote_service = seed_work.service.clone();
    remote_service.root_service = RootServiceId([82; 32]);
    remote_service.deployment = DeploymentId([83; 32]);
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![external_binding(
            "peer-81",
            remote_service.clone(),
            peer,
            ProducerId([81; 32]),
            actor_program,
        )],
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed_work.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicyV2 {
                        method: "start".into(),
                        schema: Hash([32; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    },
                    MethodPolicyV2 {
                        method: "attested-start".into(),
                        schema: Hash([32; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: true,
                        space_role: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(seed_work.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![]),
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    let mut wrong_service_program = install.clone();
    let AccumulateRequestV2::Install(wrong_genesis) = &mut wrong_service_program else {
        unreachable!()
    };
    wrong_genesis.service.service_program = ProgramId([3; 32]);
    authorize_install(&mut service, &wrong_service_program);
    assert_eq!(
        service.accumulate(&wrong_service_program),
        Err(ServiceDispatchError::ServiceProgramMismatch {
            expected: vos::v2::VOS_SERVICE_PROGRAM_ID,
            declared: ProgramId([3; 32]),
        }),
        "platform dispatch must bind genesis to the PVM executing Accumulate"
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);

    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
    assert!(
        service.accumulate_host().backend().image.is_none(),
        "unauthorized genesis cannot create a durable recovery image"
    );

    authorize_install(&mut service, &install);
    service = restart_durable_service(service, &pvm, ProgramId::of_pvm(&pvm));
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized),
        "host authorization policy is not laundered through durable service state"
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(
        service.accumulate_host_mut().import_blob(initial_bytes),
        initial
    );
    assert_eq!(
        service
            .accumulate_host_mut()
            .import_program(actor_pvm.clone()),
        actor_program
    );
    authorize_install(&mut service, &install);

    let mut tampered_install = install.clone();
    let AccumulateRequestV2::Install(tampered_genesis) = &mut tampered_install else {
        unreachable!()
    };
    let AuthorizationEvidenceV2::SystemCapability { authenticator, .. } =
        &mut tampered_genesis.authorization
    else {
        unreachable!()
    };
    authenticator.push(99);
    assert_eq!(
        service.accumulate(&tampered_install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized),
        "authorization is bound to every exact genesis byte"
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);

    let installed_output = service
        .accumulate(&install)
        .expect("guest install completes");
    let AccumulationResultV2::Installed(installed) = installed_output.result else {
        panic!("guest install rejected")
    };
    assert_eq!(service.accumulate_host().commit_sequence(), 1);
    let installed_rows = service.accumulate_host().row_count();

    let request = LocalWorkRequestV2 {
        invocation: seed_work.invocation,
        workflow_step: 0,
        logical_timeslot: seed_work.logical_timeslot,
        target: seed_work.target,
        method: seed_work.method.clone(),
        arguments: seed_work.arguments.clone(),
        origin: seed_work.origin,
        authorization: seed_work.authorization.clone(),
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let prepared = LocalWorkSchedulerV2::prepare(service.accumulate_host(), request.clone())
        .expect("scheduler reads the installed guest state");
    assert_eq!(prepared.work.service, seed_work.service);
    assert_eq!(prepared.work.target_program, actor_program);
    assert_eq!(
        prepared.work.base,
        ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        }
    );
    assert_eq!(prepared.work.imported_actors[0].state, initial);
    assert_eq!(
        prepared
            .work
            .imported_actors
            .iter()
            .map(|actor| actor.actor)
            .collect::<Vec<_>>(),
        vec![seed_work.target, child]
    );
    assert_eq!(
        prepared.imports.programs.len(),
        1,
        "program bytes are deduplicated when root and child share code"
    );
    assert_eq!(prepared.imports.programs[0].pvm, actor_pvm);
    let work = prepared.work;
    let continuation = ContinuationSnapshotV2 {
        snapshot_version: vos::v2::SNAPSHOT_VERSION,
        jar_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        vos_abi: vos::v2::ABI_VERSION,
        service: work.service.clone(),
        invocation: work.invocation,
        checkpoint_step: 0,
        actor: work.target,
        actor_deployment: work.target_deployment,
        actor_program,
        programs: work
            .imported_actors
            .iter()
            .map(|actor| vos::v2::ContinuationProgramV2 {
                actor: actor.actor,
                deployment: actor.deployment,
                program: actor.program,
            })
            .collect(),
        await_ordinal: 0,
        pending_call: None,
        pending_actor: None,
        causal_context: work.causal_context.clone(),
        suspended_actors: vec![work.target],
        kernel_snapshot: vec![1],
    };
    let continuation_bytes = continuation.encode();
    let continuation_ref = BlobRefV2::of_bytes(&continuation_bytes);
    let caller_invocation = InvocationId([70; 32]);
    let call_id = caller_invocation.call_id(0);
    let inbox = MessageRecordV2 {
        call_id,
        caller_invocation,
        await_ordinal: 0,
        from_service: work.service.clone(),
        from: work.target,
        to_service: work.service.clone(),
        to: work.target,
        parent: None,
        payload: work.arguments.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        proof_requested: false,
        deadline_timeslot: Some(100),
    };
    let transition = TransitionV2 {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_deployment: work.target_deployment,
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"committed actor state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChangeV2 {
            actor: work.target,
            expected: None,
            replacement: Some(continuation_ref.clone()),
        }],
        inbox: vec![inbox.clone()],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![continuation_ref.clone()],
        gas: GasAccountingV2::default(),
        proof: None,
    };

    let mut proof_work = work.clone();
    proof_work.invocation = InvocationId([0x33; 32]);
    proof_work.method = "attested-start".into();
    proof_work.proof_requested = true;
    let mut proof_transition = transition.clone();
    proof_transition.consumed_input = proof_work.input_id();
    proof_transition.continuations.clear();
    proof_transition.inbox.clear();
    proof_transition.exported_blobs.clear();
    proof_transition.reply = Some(ReplyRecordV2 {
        call_id: proof_work.invocation.root_reply_id(),
        producer: proof_work.target,
        result: b"attested result".to_vec(),
    });
    let proof_host = LocalJamStoreV2::from_snapshot(service.accumulate_host().snapshot());
    let mut proof_service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        proof_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    admit_linear_work(&mut proof_service, &proof_work);
    let before_prepare = proof_service.accumulate_host().snapshot();
    let commit_sequence_before_prepare = proof_service.accumulate_host().commit_sequence();
    let prepared_attestation = proof_service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: proof_work.clone(),
                transition: proof_transition.clone(),
                provided_blobs: vec![],
            },
        ))
        .expect("guest predicts the attested receipt without committing");
    let AccumulationResultV2::Prepared(preparation) = prepared_attestation.result else {
        panic!("guest did not prepare the attested transition")
    };
    assert_eq!(
        preparation.receipt.accepted_transition,
        proof_transition.commitment()
    );
    assert_eq!(preparation.receipt.sequence, 1);
    assert_eq!(
        preparation,
        vos::v2::AttestationPreparationV2::for_transition(
            &proof_work,
            &proof_transition,
            &MethodPolicyV2 {
                method: proof_work.method.clone(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: true,
                space_role: None,
                actor_role: None,
            },
            "root",
            ProducerId([53; 32]),
            preparation.receipt.clone(),
        )
        .unwrap()
    );
    assert!(
        proof_service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_prepare)
    );
    assert_eq!(
        proof_service.accumulate_host().commit_sequence(),
        commit_sequence_before_prepare
    );

    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: work.clone(),
        transition: transition.clone(),
        provided_blobs: vec![ImportedBlobV2 {
            reference: continuation_ref.clone(),
            bytes: continuation_bytes,
        }],
    });
    admit_linear_work(&mut service, &work);
    let before_failed_commit = service.accumulate_host().snapshot();
    let durable_before_failed_commit = service.accumulate_host().backend().image.clone();
    service.accumulate_host_mut().backend_mut().fail_next_commit = true;
    assert!(matches!(
        service.accumulate(&apply),
        Err(ServiceDispatchError::Pvm(
            ServicePvmErrorV2::AccumulateCommitRejected
        ))
    ));
    assert_eq!(
        service.accumulate_host().snapshot(),
        before_failed_commit,
        "a failed durable commit cannot expose staged guest rows or blobs"
    );
    assert_eq!(
        service.accumulate_host().backend().image,
        durable_before_failed_commit,
        "the previously durable image remains the recovery point"
    );

    let applied_output = service.accumulate(&apply).expect("guest apply completes");
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = applied_output.result
    else {
        panic!("guest apply rejected")
    };
    assert!(!duplicate);
    assert_eq!(receipt.sequence, 1);
    assert_eq!(published.reply, transition.reply);
    assert!(service.accumulate_host().row_count() > installed_rows);
    assert_eq!(service.accumulate_host().commit_sequence(), 3);
    let committed_state = BlobRefV2::of_bytes(b"committed actor state");
    assert_eq!(
        service.accumulate_host().blob(&committed_state),
        Some(b"committed actor state".as_slice())
    );

    let snapshot_after_apply = service.accumulate_host().snapshot();
    let duplicate_output = service.accumulate(&apply).expect("guest retry completes");
    let AccumulationResultV2::Accepted {
        published,
        duplicate,
        ..
    } = duplicate_output.result
    else {
        panic!("guest retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffectsV2::default());
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&snapshot_after_apply)
    );
    assert_eq!(
        service.accumulate_host().commit_sequence(),
        3,
        "a read-only duplicate transaction must not commit"
    );

    let persisted = service
        .accumulate_host()
        .backend()
        .image
        .clone()
        .expect("the accepted guest transition is durable before it returns");
    let reopened = LocalJamStoreV2::from_snapshot_bytes(&persisted)
        .expect("canonical guest state survives a process-style restart");
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(&reopened, call_id, 50),
        Err(ScheduleErrorV2::ActorBusy(work.target))
    );
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(&reopened, call_id, 100),
        Err(ScheduleErrorV2::DeadlineExpired(call_id))
    );
    let mut queued = request.clone();
    queued.invocation = InvocationId([99; 32]);
    assert_eq!(
        LocalWorkSchedulerV2::prepare(&reopened, queued),
        Err(ScheduleErrorV2::ActorBusy(work.target))
    );

    let mut resume = request;
    resume.workflow_step = 1;
    let resumed = LocalWorkSchedulerV2::prepare(&reopened, resume)
        .expect("snapshot reconstructs the next exact continuation slice");
    assert_eq!(
        resumed.work.base,
        ConsistencyBaseV2::Linear {
            revision: 1,
            state_root: receipt.resulting_state_root.unwrap(),
        }
    );
    assert_eq!(
        resumed.work.imported_actors[0].continuation,
        Some(continuation_ref)
    );
    assert_eq!(
        resumed.imports.blobs.len(),
        3,
        "root state, child state, and continuation bytes are imported after snapshot reopen"
    );

    let resumed_transition = TransitionV2 {
        service: resumed.work.service.clone(),
        consumed_input: resumed.work.input_id(),
        target_deployment: resumed.work.target_deployment,
        target_program: resumed.work.target_program,
        base: resumed.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChangeV2 {
            actor: resumed.work.target,
            expected: Some(
                resumed.work.imported_actors[0]
                    .continuation
                    .as_ref()
                    .unwrap()
                    .hash,
            ),
            replacement: None,
        }],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let completed = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed.work,
            transition: resumed_transition,
            provided_blobs: vec![],
        }))
        .unwrap()
        .result;
    assert!(matches!(completed, AccumulationResultV2::Accepted { .. }));

    let delivered = LocalWorkSchedulerV2::prepare_inbox(service.accumulate_host(), call_id, 50)
        .expect("queued inbox becomes runnable only after the actor is idle");
    assert_eq!(delivered.work.invocation, InvocationId::for_call(call_id));
    assert_eq!(delivered.work.parent_call, Some(call_id));
    assert_eq!(delivered.work.causal_parent, Some(caller_invocation));
    assert_eq!(delivered.work.origin, Origin::Actor(inbox.from));
    assert_eq!(delivered.work.authorization, inbox.authorization);

    let mut expired_work = delivered.work.clone();
    expired_work.logical_timeslot = 100;
    let expired_transition = TransitionV2 {
        service: expired_work.service.clone(),
        consumed_input: expired_work.input_id(),
        target_deployment: expired_work.target_deployment,
        target_program: expired_work.target_program,
        base: expired_work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id,
            producer: expired_work.target,
            result: b"expired".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let before_expired = service.accumulate_host().snapshot();
    let expired = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: expired_work,
            transition: expired_transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    assert_eq!(
        expired.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidWorkflowTransition)
    );
    assert_eq!(service.accumulate_host().snapshot(), before_expired);

    let delivery_continuation = ContinuationSnapshotV2 {
        snapshot_version: vos::v2::SNAPSHOT_VERSION,
        jar_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        vos_abi: vos::v2::ABI_VERSION,
        service: delivered.work.service.clone(),
        invocation: delivered.work.invocation,
        checkpoint_step: 0,
        actor: delivered.work.target,
        actor_deployment: delivered.work.target_deployment,
        actor_program,
        programs: delivered
            .work
            .imported_actors
            .iter()
            .map(|actor| vos::v2::ContinuationProgramV2 {
                actor: actor.actor,
                deployment: actor.deployment,
                program: actor.program,
            })
            .collect(),
        await_ordinal: 0,
        pending_call: None,
        pending_actor: None,
        causal_context: delivered.work.causal_context.clone(),
        suspended_actors: vec![delivered.work.target],
        kernel_snapshot: vec![2],
    };
    let delivery_continuation_bytes = delivery_continuation.encode();
    let delivery_continuation_ref = BlobRefV2::of_bytes(&delivery_continuation_bytes);
    let delivery_checkpoint = TransitionV2 {
        service: delivered.work.service.clone(),
        consumed_input: delivered.work.input_id(),
        target_deployment: delivered.work.target_deployment,
        target_program: delivered.work.target_program,
        base: delivered.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChangeV2 {
            actor: delivered.work.target,
            expected: None,
            replacement: Some(delivery_continuation_ref.clone()),
        }],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![delivery_continuation_ref.clone()],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let checkpointed = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: delivered.work.clone(),
            transition: delivery_checkpoint,
            provided_blobs: vec![ImportedBlobV2 {
                reference: delivery_continuation_ref,
                bytes: delivery_continuation_bytes,
            }],
        }))
        .expect("guest atomically consumes the inbox and checkpoints the callee");
    assert!(matches!(
        checkpointed.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(service.accumulate_host(), call_id, 51),
        Err(ScheduleErrorV2::MissingInbox(call_id))
    );

    let delivery_request = LocalWorkRequestV2 {
        invocation: delivered.work.invocation,
        workflow_step: 1,
        logical_timeslot: 51,
        target: delivered.work.target,
        method: delivered.work.method,
        arguments: b"dead resume input".to_vec(),
        origin: delivered.work.origin,
        authorization: delivered.work.authorization,
        causal_parent: delivered.work.causal_parent,
        parent_call: delivered.work.parent_call,
        causal_context: delivered.work.causal_context,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let delivery_resume =
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), delivery_request)
            .expect("callee resumes from workflow state after its inbox was consumed");
    assert!(delivery_resume.work.arguments.is_empty());
    let delivery_reply = ReplyRecordV2 {
        call_id,
        producer: delivery_resume.work.target,
        result: b"durable inbox reply".to_vec(),
    };
    let delivery_completion = TransitionV2 {
        service: delivery_resume.work.service.clone(),
        consumed_input: delivery_resume.work.input_id(),
        target_deployment: delivery_resume.work.target_deployment,
        target_program: delivery_resume.work.target_program,
        base: delivery_resume.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChangeV2 {
            actor: delivery_resume.work.target,
            expected: Some(
                delivery_resume.work.imported_actors[0]
                    .continuation
                    .as_ref()
                    .unwrap()
                    .hash,
            ),
            replacement: None,
        }],
        inbox: vec![],
        outbox: vec![],
        reply: Some(delivery_reply.clone()),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let delivery_apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: delivery_resume.work,
        transition: delivery_completion,
        provided_blobs: vec![],
    });
    let delivered_result = service
        .accumulate(&delivery_apply)
        .expect("guest commits the resumed callee reply");
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = delivered_result.result
    else {
        panic!("guest rejected the resumed callee")
    };
    assert!(!duplicate);
    assert_eq!(published.reply, Some(delivery_reply.clone()));
    assert_eq!(receipt.reply_commitment, Some(delivery_reply.commitment()));

    let duplicate_delivery = service
        .accumulate(&delivery_apply)
        .expect("exact delivery retry resolves through dedup");
    let AccumulationResultV2::Accepted {
        receipt: duplicate_receipt,
        published: duplicate_published,
        duplicate: true,
    } = duplicate_delivery.result
    else {
        panic!("guest did not deduplicate the resumed callee")
    };
    assert_eq!(duplicate_receipt, receipt);
    assert_eq!(duplicate_published, PublishedEffectsV2::default());

    let caller_request = LocalWorkRequestV2 {
        invocation: InvocationId([80; 32]),
        workflow_step: 0,
        logical_timeslot: 60,
        target: seed_work.target,
        method: seed_work.method,
        arguments: seed_work.arguments,
        origin: seed_work.origin,
        authorization: seed_work.authorization,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let caller = LocalWorkSchedulerV2::prepare(service.accumulate_host(), caller_request)
        .expect("idle caller is schedulable");
    admit_linear_work(&mut service, &caller.work);
    let awaited_call = caller.work.invocation.call_id(0);
    let continuation_bytes = ContinuationSnapshotV2 {
        snapshot_version: vos::v2::SNAPSHOT_VERSION,
        jar_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        vos_abi: vos::v2::ABI_VERSION,
        service: caller.work.service.clone(),
        invocation: caller.work.invocation,
        checkpoint_step: 0,
        actor: caller.work.target,
        actor_deployment: caller.work.target_deployment,
        actor_program,
        programs: caller
            .work
            .imported_actors
            .iter()
            .map(|actor| vos::v2::ContinuationProgramV2 {
                actor: actor.actor,
                deployment: actor.deployment,
                program: actor.program,
            })
            .collect(),
        await_ordinal: 0,
        pending_call: Some(awaited_call),
        pending_actor: Some(caller.work.target),
        causal_context: caller.work.causal_context.clone(),
        suspended_actors: vec![caller.work.target],
        kernel_snapshot: vec![4],
    }
    .encode();
    let continuation = BlobRefV2::of_bytes(&continuation_bytes);
    let outbound = MessageRecordV2 {
        call_id: awaited_call,
        caller_invocation: caller.work.invocation,
        await_ordinal: 0,
        from_service: caller.work.service.clone(),
        from: caller.work.target,
        to_service: remote_service.clone(),
        to: peer,
        parent: None,
        payload: caller.work.arguments.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        proof_requested: false,
        deadline_timeslot: Some(90),
    };
    let checkpoint = TransitionV2 {
        service: caller.work.service.clone(),
        consumed_input: caller.work.input_id(),
        target_deployment: caller.work.target_deployment,
        target_program: caller.work.target_program,
        base: caller.work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: caller.work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"awaiting reply state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChangeV2 {
            actor: caller.work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        }],
        inbox: vec![],
        outbox: vec![outbound],
        reply: None,
        exported_blobs: vec![continuation.clone()],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let checkpointed = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: caller.work.clone(),
            transition: checkpoint,
            provided_blobs: vec![ImportedBlobV2 {
                reference: continuation.clone(),
                bytes: continuation_bytes,
            }],
        }))
        .expect("guest commits the pending call and caller continuation");
    let AccumulationResultV2::Accepted {
        receipt: checkpoint_receipt,
        duplicate: false,
        ..
    } = checkpointed.result
    else {
        panic!("guest rejected the pending call")
    };

    let remote_reply = ReplyRecordV2 {
        call_id: awaited_call,
        producer: peer,
        result: b"remote result".to_vec(),
    };
    let awaited = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: remote_service,
            accepted_transition: Hash([84; 32]),
            reply_commitment: Some(remote_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([85; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply: remote_reply,
        attestation: None,
    };
    let resume_request = LocalWorkRequestV2 {
        invocation: caller.work.invocation,
        workflow_step: 1,
        logical_timeslot: 70,
        target: caller.work.target,
        method: caller.work.method,
        arguments: b"ignored resume arguments".to_vec(),
        origin: caller.work.origin,
        authorization: caller.work.authorization,
        causal_parent: caller.work.causal_parent,
        parent_call: caller.work.parent_call,
        causal_context: caller.work.causal_context,
        awaited_reply: Some(awaited.clone()),
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let resume = LocalWorkSchedulerV2::prepare(service.accumulate_host(), resume_request)
        .expect("scheduler binds the accumulated reply to the exact continuation");
    let before_resume_header = service.accumulate_host().header().unwrap().unwrap();
    let persisted_outbox = MessageRecordV2::decode(
        &service
            .accumulate_host()
            .state_row(
                before_resume_header.service_root,
                &StateKeyV2::Outbox(awaited_call),
            )
            .unwrap()
            .expect("pending outbox row remains committed"),
    )
    .unwrap();
    assert_eq!(persisted_outbox.call_id, awaited_call);
    assert_eq!(persisted_outbox.caller_invocation, resume.work.invocation);
    assert_eq!(persisted_outbox.await_ordinal, 0);
    assert_eq!(persisted_outbox.from, resume.work.target);
    assert_eq!(persisted_outbox.to, awaited.reply.producer);
    assert!(persisted_outbox.deadline_timeslot.unwrap() > resume.work.logical_timeslot);
    assert_eq!(
        awaited.receipt.reply_commitment,
        Some(awaited.reply.commitment())
    );
    assert_eq!(awaited.receipt.service.service_abi, vos::v2::ABI_VERSION);
    assert_eq!(
        awaited.receipt.service.execution_semantics,
        vos::v2::EXECUTION_SEMANTICS_ID
    );
    assert_ne!(
        awaited.receipt.service.root_service,
        resume.work.service.root_service
    );
    let completion = TransitionV2 {
        service: resume.work.service.clone(),
        consumed_input: resume.work.input_id(),
        target_deployment: resume.work.target_deployment,
        target_program: resume.work.target_program,
        base: resume.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChangeV2 {
            actor: resume.work.target,
            expected: Some(continuation.hash),
            replacement: None,
        }],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let apply_reply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: resume.work,
        transition: completion,
        provided_blobs: vec![],
    });
    let before_receipt = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate(&apply_reply)
            .expect("unavailable receipt is a typed guest rejection")
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::ReceiptUnavailable)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_receipt),
        "an unavailable receipt leaves no guest storage trace"
    );

    service
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: awaited.reply.producer,
            receipt: awaited.receipt,
        });
    let accepted = service
        .accumulate(&apply_reply)
        .expect("finalized reply resumes through physical guest Accumulate");
    let AccumulationResultV2::Accepted {
        receipt: accepted_receipt,
        duplicate: false,
        ..
    } = accepted.result
    else {
        panic!("guest rejected the finalized reply")
    };
    let header = service.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::Outbox(awaited_call))
            .unwrap(),
        None,
        "accepted reply consumes the pending outbox atomically"
    );
    assert_eq!(
        service
            .accumulate(&apply_reply)
            .expect("exact reply retry resolves through work dedup")
            .result,
        AccumulationResultV2::Accepted {
            receipt: accepted_receipt,
            published: PublishedEffectsV2::default(),
            duplicate: true,
        }
    );
    assert_eq!(checkpoint_receipt.sequence + 1, header.revision);
}

#[test]
fn physical_guest_accumulate_upgrades_only_an_idle_authorized_actor() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let initial_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&initial_pvm);
    let replacement_pvm = actor_pvm(1);
    let replacement_program = ProgramId::of_pvm(&replacement_pvm);
    let initial_bytes = b"state survives upgrade".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;

    let mut store = DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
    assert_eq!(store.import_blob(initial_bytes), initial);
    assert_eq!(store.import_program(initial_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([31; 32]),
            deployment: seed.target_deployment,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        external_actors: vec![],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([33; 32]),
            authenticator: vec![34],
        },
    });
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
    let AccumulationResultV2::Installed(installed) = service.accumulate(&install).unwrap().result
    else {
        panic!("service install rejected")
    };
    let upgrade = ActorUpgradeV2 {
        service: seed.service.clone(),
        actor: seed.target,
        expected_deployment: seed.target_deployment,
        expected_program: actor_program,
        replacement_deployment: DeploymentId([37; 32]),
        replacement_program,
        producer: ProducerId([35; 32]),
        role_policies: role_policies(vec![MethodPolicyV2 {
            method: "next".into(),
            schema: Hash([36; 32]),
            policy: public_policy_hash(),
            public: true,
            attested: false,
            space_role: None,
            actor_role: None,
        }]),
        base: ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        },
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([37; 32]),
            authenticator: vec![38],
        },
    };
    let upgrade_programs = vec![ImportedProgramV2 {
        program: replacement_program,
        pvm: replacement_pvm.clone(),
    }];
    let before = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate_with_availability(
                &AccumulateRequestV2::UpgradeActor(upgrade.clone()),
                &upgrade_programs,
                &[],
            )
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert_eq!(service.accumulate_host().snapshot(), before);
    assert!(
        service
            .accumulate_host()
            .program(replacement_program)
            .is_none()
    );

    assert!(service.accumulate_host_mut().allow_upgrade(&upgrade));
    let before_failed_commit = service.accumulate_host().snapshot();
    service.accumulate_host_mut().backend_mut().fail_next_commit = true;
    assert!(matches!(
        service.accumulate_with_availability(
            &AccumulateRequestV2::UpgradeActor(upgrade.clone()),
            &upgrade_programs,
            &[],
        ),
        Err(ServiceDispatchError::Pvm(
            ServicePvmErrorV2::AccumulateCommitRejected
        ))
    ));
    assert_eq!(service.accumulate_host().snapshot(), before_failed_commit);
    assert!(
        service
            .accumulate_host()
            .program(replacement_program)
            .is_none()
    );

    let upgraded = service
        .accumulate_with_availability(
            &AccumulateRequestV2::UpgradeActor(upgrade.clone()),
            &upgrade_programs,
            &[],
        )
        .unwrap();
    let AccumulationResultV2::ActorUpgraded {
        previous_program,
        program,
        receipt,
        duplicate,
        ..
    } = upgraded.result
    else {
        panic!("authorized idle upgrade rejected")
    };
    assert_eq!(previous_program, actor_program);
    assert_eq!(program, replacement_program);
    assert_eq!(receipt.sequence, 1);
    assert!(!duplicate);
    assert_eq!(service.accumulate_host().commit_sequence(), 2);
    assert_eq!(
        service.accumulate_host().program(actor_program),
        Some(initial_pvm.as_slice())
    );
    assert_eq!(
        service.accumulate_host().program(replacement_program),
        Some(replacement_pvm.as_slice())
    );

    let prepared = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([39; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: seed.target,
            method: "next".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("scheduler loads the replacement descriptor and PVM");
    assert_eq!(prepared.work.target_program, replacement_program);
    assert_eq!(prepared.imports.programs[0].pvm, replacement_pvm);
    assert_eq!(prepared.work.imported_actors[0].state, initial);

    let before_retry = service.accumulate_host().snapshot();
    assert!(matches!(
        service
            .accumulate_with_availability(
                &AccumulateRequestV2::UpgradeActor(upgrade),
                &upgrade_programs,
                &[],
            )
            .unwrap()
            .result,
        AccumulationResultV2::ActorUpgraded {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(service.accumulate_host().snapshot(), before_retry);
}

#[test]
fn disclosed_role_credentials_require_authority_verification_in_physical_accumulate() {
    let elf = service_elf();

    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = b"canonical role-gated actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"role-gated initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut work = work(actor_program, initial.clone());
    work.service.service_program = service_program;
    let origin = Origin::Member(SubjectId([0x81; 32]));
    work.origin = origin;
    let policy = space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap();

    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: work.method.clone(),
                schema: Hash([0x82; 32]),
                policy,
                public: false,
                attested: false,
                space_role: Some(vos::SpaceRole::Member.as_u8()),
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([0x83; 32]),
            authenticator: vec![0x84],
        },
    };
    let install = AccumulateRequestV2::Install(genesis);
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    authorize_install(&mut service, &install);
    let AccumulationResultV2::Installed(installed) = service.accumulate(&install).unwrap().result
    else {
        panic!("role-gated service install failed")
    };
    work.base = ConsistencyBaseV2::Linear {
        revision: 0,
        state_root: installed.resulting_state_root.unwrap(),
    };
    let credential = RoleCredentialV2 {
        holder: origin,
        scope: work.authorization_scope(),
        space_role: Some(vos::SpaceRole::Developer),
        actor_role: None,
        authenticator: b"authority signature over exact work scope".to_vec(),
    };
    work.authorization = credential.disclosed_evidence(policy);
    let transition = TransitionV2 {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_deployment: work.target_deployment,
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: work.invocation.root_reply_id(),
            producer: work.target,
            result: b"authorized".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: work.clone(),
        transition,
        provided_blobs: vec![],
    });
    let before = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate(&direct_linear_ingress(&work))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before)
    );

    let mut malformed_resume = work.clone();
    malformed_resume.workflow_step = 1;
    malformed_resume.authorization = RoleCredentialV2 {
        holder: origin,
        scope: Hash::ZERO,
        space_role: Some(vos::SpaceRole::Developer),
        actor_role: None,
        authenticator: b"malformed authority grant".to_vec(),
    }
    .disclosed_evidence(policy);
    let malformed_transition = TransitionV2 {
        service: malformed_resume.service.clone(),
        consumed_input: malformed_resume.input_id(),
        target_deployment: malformed_resume.target_deployment,
        target_program: malformed_resume.target_program,
        base: malformed_resume.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: malformed_resume.invocation.root_reply_id(),
            producer: malformed_resume.target,
            result: b"must not execute".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let before_malformed = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: malformed_resume,
                transition: malformed_transition,
                provided_blobs: vec![],
            }))
            .expect("malformed credential is a guest rejection, not a dispatch error")
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_malformed)
    );

    let verification = RoleCredentialVerificationRequestV2::for_work(&work).unwrap();
    service
        .accumulate_host_mut()
        .allow_role_credential(&verification);
    admit_linear_work(&mut service, &work);
    assert!(matches!(
        service.accumulate(&apply).unwrap().result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn attested_driver_rejects_a_transition_not_produced_by_exact_refine() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = grey_transpiler::link_elf(&greeter_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;
    let private_origin = Origin::Member(SubjectId([0xA7; 32]));
    seed.origin = private_origin;
    seed.proof_requested = true;
    let private_policy = space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap();
    let private_credential = RoleCredentialV2 {
        holder: private_origin,
        scope: seed.authorization_scope(),
        space_role: Some(vos::SpaceRole::Developer),
        actor_role: None,
        authenticator: b"authenticated private role grant".to_vec(),
    };
    let (private_authorization, private_witness) =
        private_credential.private_evidence(private_policy);

    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: seed.method.clone(),
                schema: Hash([0xA1; 32]),
                policy: private_policy,
                public: false,
                attested: true,
                space_role: Some(vos::SpaceRole::Member.as_u8()),
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([0xA3; 32]),
            authenticator: vec![0xA4],
        },
    };
    let install = AccumulateRequestV2::Install(genesis);
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(
        host.import_private_witness(private_witness.bytes.clone()),
        private_witness.reference
    );
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    authorize_install(&mut service, &install);
    let AccumulationResultV2::Installed(installed) = service.accumulate(&install).unwrap().result
    else {
        panic!("attested service install failed")
    };
    let installed_blob_count = service.accumulate_host().blob_count();

    let prepared = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: seed.invocation,
            workflow_step: 0,
            logical_timeslot: seed.logical_timeslot,
            target: seed.target,
            method: seed.method,
            arguments: seed.arguments,
            origin: private_origin,
            authorization: private_authorization,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: true,
        },
    )
    .expect("attested work is schedulable");
    assert_eq!(
        prepared.work.base,
        ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        }
    );
    assert!(prepared.imports.private_blobs.contains(&private_witness));
    assert!(!prepared.imports.blobs.contains(&private_witness));
    assert!(
        !prepared
            .work
            .encode()
            .windows(private_witness.bytes.len())
            .any(|window| window == private_witness.bytes),
        "the work wire carries only the private witness commitment and content reference"
    );
    admit_linear_work(&mut service, &prepared.work);
    let refined = service
        .refine_actor_tree(&prepared.work, &prepared.imports)
        .expect("the executable actor produces a genuine Refine transition");
    let genuine = AccumulationEnvelopeV2 {
        work: prepared.work,
        transition: refined.transition,
        provided_blobs: refined.exported_blobs,
    };
    let before = service.accumulate_host().snapshot();
    let mut control = CanonicalTestProofProducer {
        proof: vec![],
        calls: 0,
    };
    assert!(matches!(
        service.accumulate_attested(genuine.clone(), &prepared.imports, &mut control),
        Err(vos::v2::AttestedServiceErrorV2::InvalidProducedProof)
    ));
    assert_eq!(
        control.calls, 1,
        "the genuine Refine output reaches proof production"
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before),
        "an empty proof cannot commit the genuine transition"
    );

    let mut forged = genuine;
    forged
        .transition
        .reply
        .as_mut()
        .expect("the genuine completed actor slice has a reply")
        .result
        .push(0xff);
    let mut invalid = CanonicalTestProofProducer {
        proof: vec![1],
        calls: 0,
    };
    assert!(matches!(
        service.accumulate_attested(forged, &prepared.imports, &mut invalid),
        Err(vos::v2::AttestedServiceErrorV2::InvalidPreparation)
    ));
    assert_eq!(invalid.calls, 0);
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before),
        "a transition not produced by exact Refine cannot reach the prover or commit"
    );
    assert_eq!(service.accumulate_host().blob_count(), installed_blob_count);
}

#[test]
fn physical_guest_install_rejects_an_unavailable_actor_program() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_program = ProgramId::of_pvm(b"canonical actor bytes not imported into the service");
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    let mut service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed_work.service,
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial,
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    };

    let install = AccumulateRequestV2::Install(genesis);
    authorize_install(&mut service, &install);
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::WrongProgram)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
}

#[test]
fn physical_guest_rejects_the_missing_preimage_length_sentinel() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = b"available canonical actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let seed_work = work(
        actor_program,
        BlobRefV2 {
            hash: Hash([30; 32]),
            len: u64::MAX,
        },
    );
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed_work.service,
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: seed_work.imported_actors[0].state.clone(),
            crdt: false,
            role_policies: role_policies(vec![]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([31; 32]),
            authenticator: vec![32],
        },
    };

    let install = AccumulateRequestV2::Install(genesis);
    authorize_install(&mut service, &install);
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::NonCanonical)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
    assert_eq!(service.accumulate_host().blob_count(), 0);
}

#[test]
fn attested_cross_root_transport_proves_and_resumes_the_bound_package() {
    let actor_pvm = grey_transpiler::link_elf(&workflow_v2_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let service_program = vos::v2::VOS_SERVICE_PROGRAM_ID;
    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([201; 32]),
        root_service: RootServiceId([202; 32]),
        deployment: DeploymentId([203; 32]),
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([204; 32]),
        deployment: DeploymentId([205; 32]),
        ..source_identity.clone()
    };
    let source_actor = ActorId([5; 32]);
    let destination_actor = ActorId([44; 32]);
    let destination_producer = ProducerId([98; 32]);

    let install_service = |identity: ServiceIdentityV2,
                           actor: ActorId,
                           name: &str,
                           method: &str,
                           attested: bool,
                           producer: ProducerId,
                           external_actors: Vec<ExternalActorBindingV2>| {
        let mut host = DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
        assert_eq!(host.import_blob(initial_bytes.clone()), initial);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = JamServiceV2::new(
            CANONICAL_SERVICE_PVM.to_vec(),
            service_program,
            NoRefineProtocolHostV2,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
            role_authority: None,
            external_actors,
            service: identity.clone(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor,
                name: name.into(),
                parent: None,
                producer,
                deployment: identity.deployment,
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: method.into(),
                    schema: Hash([206; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested,
                    space_role: None,
                    actor_role: None,
                }]),
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: vos::v2::SystemCapabilityId([207; 32]),
                authenticator: vec![208],
            },
        });
        authorize_install(&mut service, &install);
        assert!(matches!(
            service.accumulate(&install).unwrap().result,
            AccumulationResultV2::Installed(_)
        ));
        service
    };

    let mut source = install_service(
        source_identity,
        source_actor,
        "workflow",
        "root_await_attested_peer",
        false,
        ProducerId([53; 32]),
        vec![external_binding(
            "private-age",
            destination_identity.clone(),
            destination_actor,
            destination_producer,
            actor_program,
        )],
    );
    let mut destination = install_service(
        destination_identity,
        destination_actor,
        "private-age",
        "attested_peer_value",
        true,
        destination_producer,
        vec![],
    );

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
    let prepared = LocalWorkSchedulerV2::prepare(
        source.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([209; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_actor,
            method: "root_await_attested_peer".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut source, &prepared.work);
    let refined = source
        .refine_actor_tree(&prepared.work, &prepared.imports)
        .unwrap();
    assert_eq!(refined.transition.outbox.len(), 1);
    assert!(refined.transition.outbox[0].proof_requested);
    let call = refined.transition.outbox[0].call_id;
    assert!(matches!(
        source
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let source_publication = LocalTransportV2::pending_publications(&source)
        .unwrap()
        .pop()
        .unwrap();
    LocalTransportV2::deliver(&source, &mut destination, &source_publication, call, 2).unwrap();
    let before_mismatched_trace = destination.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransportV2::drain_pending_attested(
            &mut destination,
            3,
            &mut MismatchedTraceProofProducer,
        ),
        Err(vos::v2::AttestedTransportErrorV2::Attested(
            vos::v2::AttestedServiceErrorV2::InvalidProducedProof
        ))
    ));
    assert!(
        destination
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_mismatched_trace),
        "a proof for a different Refine trace cannot commit"
    );
    let proof_bytes = canonical_test_proof_manifest(0x98);
    let mut proof_producer = CanonicalTestProofProducer {
        proof: proof_bytes.clone(),
        calls: 0,
    };
    let drained =
        LocalTransportV2::drain_pending_attested(&mut destination, 3, &mut proof_producer).unwrap();
    let [InboxDrainOutcomeV2::Committed(committed)] = drained.as_slice() else {
        panic!("the attested destination did not commit its inbox slice")
    };
    assert_eq!(proof_producer.calls, 1);
    let attestation = committed
        .published
        .attestation
        .as_ref()
        .expect("guest Accumulate publishes the receipt-bound attestation");
    assert_eq!(attestation.producer_name, "private-age");
    assert_eq!(attestation.producer, destination_producer);
    assert_eq!(attestation.statement.producer, destination_producer);
    assert_eq!(attestation.statement.producer_name, "private-age");
    let proof_reference = attestation.proof.proof_blob.clone();

    destination = restart_durable_service(destination, CANONICAL_SERVICE_PVM, service_program);
    assert_eq!(
        destination
            .accumulate_host()
            .proof_bytes(&proof_reference)
            .as_deref(),
        Some(proof_bytes.as_slice()),
        "the proved publication's side-CAS survives a producer restart"
    );
    let reply_publication = LocalTransportV2::pending_publications(&destination)
        .unwrap()
        .pop()
        .unwrap();
    let resumed =
        LocalTransportV2::resume_reply(&destination, &mut source, &reply_publication, 4).unwrap();
    assert_eq!(
        resumed.published.reply.as_ref().map(|reply| &reply.result),
        Some(&Value::Bool(true).encode()),
        "the exact restored caller receives the proof package, not only the claim bytes"
    );
    let admission = source
        .accumulate_host()
        .reply_admission(call)
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        admission
            .awaited_reply
            .attestation
            .as_ref()
            .map(|package| package.producer),
        Some(destination_producer)
    );
}

#[test]
fn crdt_delivery_is_causal_physical_and_restart_drainable_after_sync() {
    let service_pvm = vos::v2::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = grey_transpiler::link_elf(&crdt_counter_v2_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0xD1; 32]),
        root_service: RootServiceId([0xD2; 32]),
        deployment: DeploymentId([0xD3; 32]),
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let actor = ActorId([0xD4; 32]);
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: identity.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor,
            name: "root".into(),
            parent: None,
            producer: ProducerId([0xD5; 32]),
            deployment: identity.deployment,
            program: actor_program,
            initial_state: initial_state_ref.clone(),
            crdt: true,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "inc".into(),
                schema: Hash([0xD6; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0xD7; 32]),
            authenticator: vec![0xD8],
        },
    });
    let open = || {
        let mut host = DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
        assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = JamServiceV2::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHostV2,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        authorize_install(&mut service, &install);
        assert!(matches!(
            service.accumulate(&install).unwrap().result,
            AccumulationResultV2::Installed(_)
        ));
        service
    };
    let mut destination = open();
    let replica = open();
    let source = ServiceIdentityV2 {
        root_service: RootServiceId([0xD9; 32]),
        deployment: DeploymentId([0xDA; 32]),
        ..identity.clone()
    };
    let sender = ActorId([0xDB; 32]);
    let invocation = InvocationId([0xDC; 32]);
    let message = MessageRecordV2 {
        call_id: invocation.call_id(0),
        caller_invocation: invocation,
        await_ordinal: 0,
        from_service: source.clone(),
        from: sender,
        to_service: identity.clone(),
        to: actor,
        parent: None,
        payload: {
            let mut payload = vec![vos::value::TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new("inc").encode());
            payload
        },
        authorization: AuthorizationEvidenceV2::Public,
        proof_requested: false,
        deadline_timeslot: Some(100),
    };
    let source_receipt = AccumulationReceiptV2 {
        service: source,
        accepted_transition: Hash([0xDD; 32]),
        reply_commitment: None,
        outbox_commitment: MessageRecordV2::outbox_commitment(core::slice::from_ref(&message)),
        resulting_state_root: Some(Hash([0xDE; 32])),
        resulting_crdt_heads: vec![],
        sequence: 1,
        checkpoint: 0,
        consistency: ConsistencyModeV2::Local,
    };
    destination
        .accumulate_host_mut()
        .local_store_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: sender,
            receipt: source_receipt.clone(),
        });
    let delivery = LocalWorkSchedulerV2::prepare_delivery(
        destination.accumulate_host().local_store(),
        2,
        message.clone(),
        vec![message.clone()],
        source_receipt,
    )
    .unwrap();
    let AccumulationResultV2::Accepted {
        receipt: delivery_receipt,
        duplicate: false,
        ..
    } = destination
        .accumulate(&AccumulateRequestV2::Deliver(delivery))
        .unwrap()
        .result
    else {
        panic!("physical CRDT delivery was rejected")
    };
    assert_eq!(delivery_receipt.consistency, ConsistencyModeV2::Crdt);
    assert_eq!(delivery_receipt.resulting_crdt_heads.len(), 1);

    let sync = LocalWorkSchedulerV2::prepare_crdt_sync(destination.accumulate_host().local_store())
        .unwrap();
    let mut replica = restart_durable_service(replica, &service_pvm, service_program);
    for node in &sync.nodes {
        replica
            .accumulate_host_mut()
            .local_store_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: actor,
                receipt: node.receipt.clone(),
            });
    }
    assert!(matches!(
        replica
            .accumulate(&AccumulateRequestV2::SyncCrdt(sync))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let replica = restart_durable_service(replica, &service_pvm, service_program);
    assert_eq!(
        replica.accumulate_host().pending_inbox_calls().unwrap(),
        vec![(message.call_id, 2)]
    );
}

#[test]
fn finalized_outbox_is_durably_routed_across_service_restarts() {
    let service_pvm = vos::v2::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = grey_transpiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);

    let install_service = |identity: ServiceIdentityV2,
                           actor: ActorId,
                           method: &str,
                           external_actors: Vec<ExternalActorBindingV2>| {
        let mut host = DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
        assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = JamServiceV2::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHostV2,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
            role_authority: None,
            external_actors,
            service: identity.clone(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: identity.deployment,
                program: actor_program,
                initial_state: initial_state_ref.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: method.into(),
                    schema: Hash([91; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: vos::v2::SystemCapabilityId([93; 32]),
                authenticator: vec![94],
            },
        });
        authorize_install(&mut service, &install);
        let installed = service.accumulate(&install).unwrap();
        assert!(matches!(
            installed.result,
            AccumulationResultV2::Installed(_)
        ));
        service
    };

    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([79; 32]),
        root_service: RootServiceId([80; 32]),
        deployment: DeploymentId([81; 32]),
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([79; 32]),
        root_service: RootServiceId([82; 32]),
        deployment: DeploymentId([83; 32]),
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let source_actor = ActorId([5; 32]);
    let destination_actor = ActorId([44; 32]);
    let mut source = install_service(
        source_identity,
        source_actor,
        "await_storage_peer",
        vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            ProducerId([53; 32]),
            actor_program,
        )],
    );
    let destination = install_service(
        destination_identity.clone(),
        destination_actor,
        "peer_value_storage",
        vec![],
    );
    let expiring_destination = install_service(
        destination_identity.clone(),
        destination_actor,
        "peer_value_storage",
        vec![],
    );
    let impostor_identity = ServiceIdentityV2 {
        root_service: RootServiceId([96; 32]),
        deployment: DeploymentId([97; 32]),
        ..destination_identity
    };
    let impostor = install_service(
        impostor_identity,
        destination_actor,
        "peer_value_storage",
        vec![],
    );

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_storage_peer").encode());
    let source_work = LocalWorkSchedulerV2::prepare(
        source.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([84; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_actor,
            method: "await_storage_peer".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut source, &source_work.work);
    let refined = source
        .refine_actor_tree(&source_work.work, &source_work.imports)
        .unwrap();
    assert_eq!(refined.transition.outbox.len(), 1);
    let call = refined.transition.outbox[0].call_id;
    let source_result = source
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: source_work.work,
            transition: refined.transition,
            provided_blobs: refined.exported_blobs,
        }))
        .unwrap();
    assert!(matches!(
        source_result.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut source = restart_durable_service(source, &service_pvm, service_program);
    let publications = LocalTransportV2::pending_publications(&source).unwrap();
    assert_eq!(publications.len(), 1);
    let publication = publications[0].clone();
    assert_eq!(publication.published.outbox[0].call_id, call);

    // A destination which admits immediately before the deadline but does
    // not execute in time must durably retire the inbox through physical IC-5.
    // Restart proves discovery comes from the committed delivery row, and a
    // lost source acknowledgement remains an exact duplicate afterward.
    let mut expiring_destination =
        restart_durable_service(expiring_destination, &service_pvm, service_program);
    assert!(
        !LocalTransportV2::deliver(&source, &mut expiring_destination, &publication, call, 99,)
            .unwrap()
            .duplicate
    );
    let mut expiring_destination =
        restart_durable_service(expiring_destination, &service_pvm, service_program);
    let retired = LocalTransportV2::drain_pending(&mut expiring_destination, 100).unwrap();
    assert!(matches!(
        retired.as_slice(),
        [InboxDrainOutcomeV2::Retired {
            call: retired_call,
            duplicate: false,
            ..
        }] if *retired_call == call
    ));
    let mut expiring_destination =
        restart_durable_service(expiring_destination, &service_pvm, service_program);
    assert!(
        expiring_destination
            .accumulate_host()
            .pending_inbox_calls()
            .unwrap()
            .is_empty()
    );
    assert!(
        LocalTransportV2::deliver(&source, &mut expiring_destination, &publication, call, 99,)
            .unwrap()
            .duplicate,
        "retirement keeps the permanent delivery identity for lost acknowledgements"
    );

    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    let mut impostor = restart_durable_service(impostor, &service_pvm, service_program);
    let before_impostor = impostor.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransportV2::deliver(&source, &mut impostor, &publication, call, 2),
        Err(vos::v2::LocalTransportErrorV2::Rejected(
            vos::v2::AccumulationRejectionV2::WrongService
        ))
    ));
    assert!(
        impostor
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_impostor),
        "an actor-id collision in another root cannot admit the bound message"
    );
    let mut forged_publication = publication.clone();
    forged_publication.receipt.accepted_transition = Hash([95; 32]);
    let before_forged = destination.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransportV2::deliver(&source, &mut destination, &forged_publication, call, 2,),
        Err(vos::v2::LocalTransportErrorV2::NonCanonicalPublication)
    ));
    assert!(
        destination
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_forged)
    );

    let before_failed_delivery = destination.accumulate_host().snapshot();
    let durable_before_failed_delivery = destination.accumulate_host().backend().image.clone();
    destination
        .accumulate_host_mut()
        .backend_mut()
        .fail_next_commit = true;
    assert!(matches!(
        LocalTransportV2::deliver(&source, &mut destination, &publication, call, 2),
        Err(vos::v2::LocalTransportErrorV2::Service(
            ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateCommitRejected)
        ))
    ));
    assert_eq!(
        destination.accumulate_host().snapshot(),
        before_failed_delivery,
        "a failed destination commit cannot expose the admitted inbox"
    );
    assert_eq!(
        destination.accumulate_host().backend().image,
        durable_before_failed_delivery,
        "a failed delivery retains the prior recovery image"
    );

    let delivery =
        LocalTransportV2::deliver(&source, &mut destination, &publication, call, 2).unwrap();
    assert!(!delivery.duplicate);
    assert_eq!(
        destination.accumulate_host().pending_inbox_calls().unwrap(),
        vec![(call, 2)]
    );

    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    let before_regressed_timeslot = destination.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransportV2::drain_pending(&mut destination, 2),
        Err(vos::v2::LocalTransportErrorV2::TimeslotNotAfterAdmission {
            call: rejected_call,
            admitted_at: 2,
            requested: 2,
        }) if rejected_call == call
    ));
    assert!(
        destination
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_regressed_timeslot)
    );

    let drained = LocalTransportV2::drain_pending(&mut destination, 3).unwrap();
    let [InboxDrainOutcomeV2::Committed(committed)] = drained.as_slice() else {
        panic!("one durable inbox row must execute after restart")
    };
    assert_eq!(committed.call, call);
    let reply = committed
        .published
        .reply
        .as_ref()
        .expect("the destination publishes its committed reply");
    assert_eq!(reply.call_id, call);
    assert_eq!(reply.producer, destination_actor);
    assert_eq!(reply.result, vos::value::Value::U32(7).encode());

    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    assert!(
        destination
            .accumulate_host()
            .pending_inbox_calls()
            .unwrap()
            .is_empty()
    );
    let destination_publications = LocalTransportV2::pending_publications(&destination).unwrap();
    assert_eq!(destination_publications.len(), 1);
    assert_eq!(
        destination_publications[0].published.reply,
        Some(reply.clone())
    );
    let reply_publication = destination_publications[0].clone();

    let retry =
        LocalTransportV2::deliver(&source, &mut destination, &publication, call, 2).unwrap();
    assert!(
        retry.duplicate,
        "the stable delivery identity survives destination base advancement"
    );

    assert!(!LocalTransportV2::acknowledge(&mut source, &publication).unwrap());
    assert!(
        LocalTransportV2::pending_publications(&source)
            .unwrap()
            .is_empty()
    );
    let source_header = source.accumulate_host().header().unwrap().unwrap();
    assert!(
        source
            .accumulate_host()
            .state_row(source_header.service_root, &StateKeyV2::Outbox(call))
            .unwrap()
            .is_some(),
        "publication acknowledgement does not erase the awaited-reply route"
    );

    // Reopen both roots before routing the reply. The caller invocation and
    // exact continuation must be recovered exclusively from guest-owned
    // service state; no warm handler or process-local return table survives.
    let mut source = restart_durable_service(source, &service_pvm, service_program);
    let destination = restart_durable_service(destination, &service_pvm, service_program);

    let mut forged_reply_publication = reply_publication.clone();
    forged_reply_publication
        .published
        .reply
        .as_mut()
        .unwrap()
        .result = vos::value::Value::U32(99).encode();
    let before_forged_reply = source.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransportV2::resume_reply(&destination, &mut source, &forged_reply_publication, 4,),
        Err(vos::v2::LocalTransportErrorV2::NonCanonicalPublication)
    ));
    assert!(
        source
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_forged_reply)
    );

    let before_expired_reply = source.accumulate_host().snapshot();
    let expired_reply =
        LocalTransportV2::resume_reply(&destination, &mut source, &reply_publication, 100);
    assert!(
        matches!(
            &expired_reply,
            Err(vos::v2::LocalTransportErrorV2::Schedule(
                ScheduleErrorV2::DeadlineExpired(expired_call)
            )) if *expired_call == call
        ),
        "unexpected expired-reply result: {expired_reply:?}"
    );
    assert!(
        source
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_expired_reply)
    );

    let before_failed_resume = source.accumulate_host().snapshot();
    let durable_before_failed_resume = source.accumulate_host().backend().image.clone();
    source.accumulate_host_mut().backend_mut().fail_next_commit = true;
    assert!(matches!(
        LocalTransportV2::resume_reply(&destination, &mut source, &reply_publication, 4),
        Err(vos::v2::LocalTransportErrorV2::Service(
            ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateCommitRejected)
        ))
    ));
    assert_eq!(
        source.accumulate_host().snapshot(),
        before_failed_resume,
        "a failed caller commit cannot expose reply admission or resumed effects"
    );
    assert_eq!(
        source.accumulate_host().backend().image,
        durable_before_failed_resume,
        "a failed reply resume retains the prior caller recovery image"
    );

    let resumed =
        LocalTransportV2::resume_reply(&destination, &mut source, &reply_publication, 4).unwrap();
    assert!(!resumed.duplicate);
    assert_eq!(resumed.call, call);
    assert_eq!(resumed.caller_invocation, InvocationId([84; 32]));
    assert_eq!(
        resumed.published.reply.as_ref().map(|reply| &reply.result),
        Some(&vos::value::Value::U32(8).encode()),
        "the restored caller continues after await without replaying its pre-await mutation"
    );
    let (reply_admission, admission_receipt) = source
        .accumulate_host()
        .reply_admission(call)
        .unwrap()
        .expect("guest Accumulate records the exact finalized reply admission");
    assert_eq!(reply_admission.input.invocation, InvocationId([84; 32]));
    assert_eq!(reply_admission.awaited_reply.reply, reply.clone());
    assert_eq!(admission_receipt, resumed.receipt);
    assert!(
        CommittedServiceSnapshotV2::decode(
            &CommittedServiceSnapshotV2 {
                applied_index: 1,
                service_image: source.accumulate_host().committed_service_image(),
                proof_artifacts: vec![],
            }
            .encode(),
        )
        .is_ok(),
        "a completed reply admission does not retain its proof in Raft snapshots"
    );
    let source_header = source.accumulate_host().header().unwrap().unwrap();
    assert!(
        source
            .accumulate_host()
            .state_row(source_header.service_root, &StateKeyV2::Outbox(call))
            .unwrap()
            .is_none(),
        "the reply route is consumed atomically with the exact resume"
    );
    let caller_publications = LocalTransportV2::pending_publications(&source).unwrap();
    assert_eq!(caller_publications.len(), 1);
    assert_eq!(caller_publications[0].published, resumed.published);

    // Lose the transport acknowledgement and restart both roots again. The
    // permanent guest-owned admission row, not the latest workflow row,
    // classifies an exact retry even at a different transport timeslot.
    let mut source = restart_durable_service(source, &service_pvm, service_program);
    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    let before_reply_retry = source.accumulate_host().snapshot();
    let reply_retry =
        LocalTransportV2::resume_reply(&destination, &mut source, &reply_publication, 5).unwrap();
    assert!(reply_retry.duplicate);
    assert_eq!(reply_retry.call, call);
    assert_eq!(reply_retry.refine_gas_used, 0);
    assert_eq!(reply_retry.accumulate_gas_used, 0);
    assert!(
        source
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_reply_retry),
        "an acknowledged reply retry never re-enters the suspended actor"
    );

    assert!(!LocalTransportV2::acknowledge(&mut destination, &reply_publication).unwrap());
    assert!(
        LocalTransportV2::pending_publications(&destination)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        LocalTransportV2::pending_publications(&source).unwrap(),
        caller_publications,
        "the caller's newly committed publication is independent of the callee acknowledgement"
    );
}

#[test]
fn raft_delivery_and_reply_verifiers_replay_before_physical_accumulate() {
    let service_pvm = vos::v2::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = grey_transpiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);

    let install_service = |identity: ServiceIdentityV2,
                           actor: ActorId,
                           method: &str,
                           external_actors: Vec<ExternalActorBindingV2>| {
        let mut host = LocalJamStoreV2::default();
        assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = JamServiceV2::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHostV2,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
            role_authority: None,
            external_actors,
            service: identity.clone(),
            consistency: ConsistencyModeV2::Raft,
            actors: vec![ActorGenesisV2 {
                actor,
                name: "root".into(),
                parent: None,
                producer: ProducerId([0x91; 32]),
                deployment: identity.deployment,
                program: actor_program,
                initial_state: initial_state_ref.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: method.into(),
                    schema: Hash([0x92; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: SystemCapabilityId([0x93; 32]),
                authenticator: vec![0x94],
            },
        });
        authorize_install(&mut service, &install);
        assert!(matches!(
            service.accumulate(&install).unwrap().result,
            AccumulationResultV2::Installed(_)
        ));
        service
    };

    let source_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0x81; 32]),
        root_service: RootServiceId([0x82; 32]),
        deployment: DeploymentId([0x83; 32]),
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentityV2 {
        root_service: RootServiceId([0x84; 32]),
        deployment: DeploymentId([0x85; 32]),
        ..source_identity.clone()
    };
    let source_actor = ActorId([0x86; 32]);
    let destination_actor = ActorId([44; 32]);
    let mut source = install_service(
        source_identity,
        source_actor,
        "await_peer",
        vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            ProducerId([0x91; 32]),
            actor_program,
        )],
    );
    let destination = install_service(
        destination_identity,
        destination_actor,
        "peer_value",
        vec![],
    );

    let invocation = InvocationId([0x88; 32]);
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer").encode());
    let source_work = LocalWorkSchedulerV2::prepare(
        source.accumulate_host(),
        LocalWorkRequestV2 {
            invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_actor,
            method: "await_peer".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    admit_linear_work(&mut source, &source_work.work);
    let source_refined = source
        .refine_actor_tree(&source_work.work, &source_work.imports)
        .unwrap();
    assert_eq!(
        source_refined.transition.outbox.len(),
        1,
        "await_peer must suspend with one durable call: {:?}",
        source_refined.transition
    );
    let call = source_refined.transition.outbox[0].call_id;
    source
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: source_work.work,
            transition: source_refined.transition,
            provided_blobs: source_refined.exported_blobs,
        }))
        .unwrap();
    let source_publication = LocalTransportV2::pending_publications(&source)
        .unwrap()
        .pop()
        .unwrap();

    let source_snapshot = source.accumulate_host().snapshot();
    let source_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut source_leader =
        ReplicatedJamServiceV2::new(source, TestCommittedLog::new(source_log.clone(), true));
    let mut source_follower = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHostV2,
            LocalJamStoreV2::from_snapshot(source_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(source_log.clone(), false),
    );
    let destination_snapshot = destination.accumulate_host().snapshot();
    let destination_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut destination_leader = ReplicatedJamServiceV2::new(
        destination,
        TestCommittedLog::new(destination_log.clone(), true),
    );
    let mut destination_follower = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm,
            service_program,
            NoRefineProtocolHostV2,
            LocalJamStoreV2::from_snapshot(destination_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(destination_log.clone(), false),
    );

    let delivery = LocalWorkSchedulerV2::prepare_delivery(
        destination_leader.service().accumulate_host(),
        2,
        source_publication.published.outbox[0].clone(),
        source_publication.published.outbox.clone(),
        source_publication.receipt.clone(),
    )
    .unwrap();
    let delivery_request = AccumulateRequestV2::Deliver(delivery);
    let delivery_verification = ReceiptVerificationRequestV2 {
        expected_producer: source_actor,
        receipt: source_publication.receipt.clone(),
    };
    destination_leader
        .service_mut()
        .accumulate_host_mut()
        .allow_receipt(&delivery_verification);
    assert!(matches!(
        destination_leader.accumulate(&delivery_request),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::InvalidAvailabilityArtifacts
        ))
    ));
    assert!(destination_log.lock().unwrap().entries.is_empty());
    destination_leader
        .log_mut()
        .propose_at_with_availability(
            &delivery_request.encode(),
            None,
            None,
            &[],
            &[],
            core::slice::from_ref(&delivery_verification),
        )
        .unwrap();
    assert_eq!(destination_leader.catch_up().unwrap(), 1);
    assert_eq!(destination_follower.catch_up().unwrap(), 1);
    assert_eq!(
        destination_leader
            .service()
            .accumulate_host()
            .pending_inbox_calls()
            .unwrap(),
        vec![(call, 2)]
    );
    assert!(
        destination_leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&destination_follower.service().accumulate_host().snapshot())
    );

    let inbox = LocalWorkSchedulerV2::prepare_inbox(
        destination_leader.service().accumulate_host(),
        call,
        3,
    )
    .unwrap();
    let destination_refined = destination_leader
        .refine_actor_tree(&inbox.work, &inbox.imports)
        .unwrap();
    let destination_applied = destination_leader
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: inbox.work,
            transition: destination_refined.transition,
            provided_blobs: destination_refined.exported_blobs,
        }))
        .unwrap();
    assert_eq!(destination_follower.catch_up().unwrap(), 1);
    let AccumulationResultV2::Accepted {
        receipt: destination_receipt,
        published: destination_published,
        duplicate: false,
    } = destination_applied.result
    else {
        panic!("destination inbox must commit a reply")
    };
    let reply = destination_published.reply.clone().unwrap();
    let awaited_reply = AccumulatedReplyV2 {
        reply,
        receipt: destination_receipt.clone(),
        attestation: None,
    };
    let resumed = LocalWorkSchedulerV2::prepare_resume(
        source_leader.service().accumulate_host(),
        invocation,
        4,
        Some(awaited_reply),
    )
    .unwrap();
    let source_resumed = source_leader
        .refine_actor_tree(&resumed.work, &resumed.imports)
        .unwrap();
    let resume_request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: resumed.work,
        transition: source_resumed.transition,
        provided_blobs: source_resumed.exported_blobs,
    });
    let reply_verification = ReceiptVerificationRequestV2 {
        expected_producer: destination_actor,
        receipt: destination_receipt,
    };
    source_leader
        .service_mut()
        .accumulate_host_mut()
        .allow_receipt(&reply_verification);
    assert!(matches!(
        source_leader.accumulate(&resume_request),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::InvalidAvailabilityArtifacts
        ))
    ));
    assert!(source_log.lock().unwrap().entries.is_empty());
    source_leader
        .log_mut()
        .propose_at_with_availability(
            &resume_request.encode(),
            None,
            None,
            &[],
            &[],
            core::slice::from_ref(&reply_verification),
        )
        .unwrap();
    assert_eq!(source_leader.catch_up().unwrap(), 1);
    assert_eq!(source_follower.catch_up().unwrap(), 1);
    assert!(
        source_leader
            .service()
            .accumulate_host()
            .reply_admission(call)
            .unwrap()
            .is_some()
    );
    assert!(
        source_leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&source_follower.service().accumulate_host().snapshot())
    );
    assert_eq!(
        destination_log.lock().unwrap().entries[0].receipt_verifications,
        vec![delivery_verification]
    );
    assert_eq!(
        source_log.lock().unwrap().entries[0].receipt_verifications,
        vec![reply_verification]
    );
}

#[test]
fn raft_authority_receipts_replay_on_a_fresh_follower_before_actor_apply() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft role initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let actor = ActorId([0x61; 32]);
    let authority_actor = ActorId([0x62; 32]);
    let service = ServiceIdentityV2 {
        space: vos::v2::SpaceId([0x63; 32]),
        root_service: RootServiceId([0x64; 32]),
        deployment: DeploymentId([0x65; 32]),
        service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let authority = RoleAuthorityBindingV2 {
        service: ServiceIdentityV2 {
            root_service: RootServiceId([0x66; 32]),
            deployment: DeploymentId([0x67; 32]),
            ..service.clone()
        },
        actor: authority_actor,
    };
    let policy = MethodPolicyV2 {
        method: "member_only".into(),
        schema: Hash([0x68; 32]),
        policy: space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap(),
        public: false,
        attested: false,
        space_role: Some(vos::SpaceRole::Member.as_u8()),
        actor_role: None,
    };
    let genesis = ServiceGenesisV2 {
        role_authority: Some(authority.clone()),
        external_actors: vec![],
        service: service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor,
            name: "root".into(),
            parent: None,
            producer: ProducerId([0x69; 32]),
            deployment: service.deployment,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![policy.clone()]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId([0x6A; 32]),
            authenticator: vec![0x6B],
        },
    };
    let programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let blobs = vec![ImportedBlobV2 {
        reference: initial,
        bytes: initial_bytes,
    }];
    let mut leader_host = LocalJamStoreV2::default();
    leader_host.allow_install(&genesis);
    let mut follower_host = LocalJamStoreV2::default();
    follower_host.allow_install(&genesis);
    let shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut leader = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHostV2,
            leader_host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), true),
    );
    let mut follower = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHostV2,
            follower_host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false),
    );
    assert!(matches!(
        leader
            .accumulate_with_availability(
                &AccumulateRequestV2::Install(genesis),
                &programs,
                &blobs,
            )
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
    let fresh_follower_snapshot = follower.service().accumulate_host().snapshot();
    let fresh_follower_applied = follower.log_mut().applied_index().unwrap();
    drop(follower);
    let mut follower = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHostV2,
            LocalJamStoreV2::from_snapshot(fresh_follower_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false).with_applied(fresh_follower_applied),
    );

    let holder = Origin::Member(SubjectId([0x6C; 32]));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("member_only").encode());
    let provisional = LocalWorkRequestV2 {
        invocation: InvocationId([0x6D; 32]),
        workflow_step: 0,
        logical_timeslot: 7,
        target: actor,
        method: policy.method.clone(),
        arguments,
        origin: holder,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let provisional_work =
        LocalWorkSchedulerV2::prepare(leader.service().accumulate_host(), provisional.clone())
            .unwrap()
            .work;
    let claim = RoleAuthorizationClaimV2 {
        space: service.space,
        holder,
        role: vos::SpaceRole::Member,
        audience: service,
        invocation: provisional.invocation,
        scope: provisional_work.authorization_scope(),
        target: actor,
        method: policy.method.clone(),
        policy: policy.policy,
    };
    let authority_reply = claim.authority_reply(authority_actor);
    let assertion = AccumulatedRoleAssertionV2 {
        claim: claim.clone(),
        receipt: AccumulationReceiptV2 {
            service: authority.service.clone(),
            accepted_transition: Hash([0x6E; 32]),
            reply_commitment: Some(authority_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([0x6F; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Raft,
        },
    };
    assert!(assertion.matches_authority(&authority));
    let verification = ReceiptVerificationRequestV2 {
        expected_producer: authority_actor,
        receipt: assertion.receipt.clone(),
    };
    let credential = RoleCredentialV2 {
        holder,
        scope: claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        actor_role: None,
        authenticator: assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let mut authorized = provisional;
    authorized.authorization = credential;
    let work = LocalWorkSchedulerV2::prepare(leader.service().accumulate_host(), authorized)
        .unwrap()
        .work;
    let ingress = direct_linear_ingress(&work);
    leader
        .service_mut()
        .accumulate_host_mut()
        .allow_receipt(&verification);
    let leader_before_unordered = leader.service().accumulate_host().snapshot();
    let follower_before_unordered = follower.service().accumulate_host().snapshot();
    assert!(matches!(
        leader.accumulate(&ingress),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::InvalidAvailabilityArtifacts,
        ))
    ));
    assert_eq!(
        shared.lock().unwrap().entries.len(),
        1,
        "a leader-local receipt decision never enters the replicated log",
    );
    assert_eq!(follower.catch_up().unwrap(), 0);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&leader_before_unordered),
        "the rejected sidecar-free leader path leaves guest state unchanged",
    );
    assert!(
        follower
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower_before_unordered),
        "the fresh follower never observes a leader-local verifier decision",
    );
    let mut forged_verification = verification.clone();
    forged_verification.expected_producer = ActorId([0x70; 32]);
    let rejection_path = std::env::temp_dir().join(format!(
        "vos-v2-raft-authority-sidecar-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let mut canonical_log =
        RaftAccumulateLogV2::open(&rejection_path, RaftConfig::default()).unwrap();
    assert!(
        canonical_log
            .propose_at_with_availability(
                &ingress.encode(),
                None,
                None,
                &[],
                &[],
                core::slice::from_ref(&forged_verification),
            )
            .is_err(),
        "the log rejects a verifier decision that does not bind the assertion reply",
    );
    drop(canonical_log);
    std::fs::remove_file(rejection_path).unwrap();
    assert_eq!(
        shared.lock().unwrap().entries.len(),
        1,
        "invalid verifier inputs never become a poison entry",
    );
    leader
        .log_mut()
        .propose_at_with_availability(
            &ingress.encode(),
            None,
            None,
            &[],
            &[],
            core::slice::from_ref(&verification),
        )
        .unwrap();
    assert_eq!(leader.catch_up().unwrap(), 1);
    assert_eq!(follower.catch_up().unwrap(), 1);
    assert!(
        follower
            .service()
            .accumulate_host()
            .ingress_record(work.invocation)
            .unwrap()
            .is_some(),
        "the follower guest admits the exact authority assertion from the ordered verifier sidecar",
    );

    // Reopen the follower from only its committed service image. Receipt
    // verifier allowlists are process-local and therefore empty here. The
    // subsequent Apply must authenticate from the guest-owned ingress row.
    let follower_snapshot = follower.service().accumulate_host().snapshot();
    let follower_applied = follower.log_mut().applied_index().unwrap();
    drop(follower);
    let follower_host = LocalJamStoreV2::from_snapshot(follower_snapshot);
    let mut follower = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHostV2,
            follower_host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false).with_applied(follower_applied),
    );
    let transition = TransitionV2 {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_deployment: work.target_deployment,
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"authorized follower state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: work.invocation.root_reply_id(),
            producer: actor,
            result: Value::U32(99).encode(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let applied = leader
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work,
            transition,
            provided_blobs: vec![],
        }))
        .expect("the leader applies the admitted role-authorized invocation");
    assert!(matches!(
        applied.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot()),
        "a fresh follower applies the actor slice without any process-local receipt allowlist",
    );
    {
        let entries = &shared.lock().unwrap().entries;
        assert_eq!(entries[1].receipt_verifications, vec![verification]);
        assert!(entries[2].receipt_verifications.is_empty());
    }

    // The same ordered authority decision must compose with the finalized
    // source receipt of a durable cross-root delivery. The source message is
    // immutable and public; the destination credential is a separate field
    // in the delivery request and both receipts are quorum-ordered.
    let destination_service = leader
        .service()
        .accumulate_host()
        .header()
        .unwrap()
        .unwrap()
        .service;
    let source_service = ServiceIdentityV2 {
        root_service: RootServiceId([0x71; 32]),
        deployment: DeploymentId([0x72; 32]),
        ..destination_service.clone()
    };
    let sender = ActorId([0x73; 32]);
    let caller_invocation = InvocationId([0x74; 32]);
    let call = caller_invocation.call_id(0);
    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&Msg::new("member_only").encode());
    let message = MessageRecordV2 {
        call_id: call,
        caller_invocation,
        await_ordinal: 0,
        from_service: source_service.clone(),
        from: sender,
        to_service: destination_service.clone(),
        to: actor,
        parent: None,
        payload: payload.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        proof_requested: false,
        deadline_timeslot: Some(100),
    };
    let source_outbox = vec![message.clone()];
    let source_receipt = AccumulationReceiptV2 {
        service: source_service,
        accepted_transition: Hash([0x75; 32]),
        reply_commitment: None,
        outbox_commitment: MessageRecordV2::outbox_commitment(&source_outbox),
        resulting_state_root: Some(Hash([0x76; 32])),
        resulting_crdt_heads: vec![],
        sequence: 7,
        checkpoint: 0,
        consistency: ConsistencyModeV2::Raft,
    };
    let delivery_work = LocalWorkSchedulerV2::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId::for_call(call),
            workflow_step: 0,
            logical_timeslot: 10,
            target: actor,
            method: policy.method.clone(),
            arguments: payload,
            origin: Origin::Actor(sender),
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: Some(caller_invocation),
            parent_call: Some(call),
            causal_context: Some(CausalCallContextV2::from(&message)),
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let delivery_claim = RoleAuthorizationClaimV2 {
        space: destination_service.space,
        holder: Origin::Actor(sender),
        role: vos::SpaceRole::Member,
        audience: destination_service,
        invocation: delivery_work.invocation,
        scope: delivery_work.authorization_scope(),
        target: actor,
        method: policy.method.clone(),
        policy: policy.policy,
    };
    let delivery_assertion = AccumulatedRoleAssertionV2 {
        claim: delivery_claim.clone(),
        receipt: AccumulationReceiptV2 {
            service: authority.service.clone(),
            accepted_transition: Hash([0x77; 32]),
            reply_commitment: Some(delivery_claim.authority_reply(authority_actor).commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([0x78; 32])),
            resulting_crdt_heads: vec![],
            sequence: 4,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Raft,
        },
    };
    let delivery_authorization = RoleCredentialV2 {
        holder: Origin::Actor(sender),
        scope: delivery_claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        actor_role: None,
        authenticator: delivery_assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let delivery = LocalWorkSchedulerV2::prepare_authorized_delivery(
        leader.service().accumulate_host(),
        10,
        delivery_authorization,
        message,
        source_outbox,
        source_receipt.clone(),
    )
    .unwrap();
    let delivery_request = AccumulateRequestV2::Deliver(delivery);
    let mut delivery_verifications = vec![
        ReceiptVerificationRequestV2 {
            expected_producer: sender,
            receipt: source_receipt,
        },
        ReceiptVerificationRequestV2 {
            expected_producer: authority_actor,
            receipt: delivery_assertion.receipt,
        },
    ];
    delivery_verifications.sort_by_key(ReceiptVerificationRequestV2::hash);
    assert!(matches!(
        leader.accumulate(&delivery_request),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::InvalidAvailabilityArtifacts,
        ))
    ));
    leader
        .log_mut()
        .propose_at_with_availability(
            &delivery_request.encode(),
            None,
            None,
            &[],
            &[],
            &delivery_verifications,
        )
        .unwrap();
    assert_eq!(leader.catch_up().unwrap(), 1);
    assert_eq!(follower.catch_up().unwrap(), 1);
    assert_eq!(
        follower
            .service()
            .accumulate_host()
            .pending_inbox_calls()
            .unwrap(),
        vec![(call, 10)]
    );

    let follower_snapshot = follower.service().accumulate_host().snapshot();
    let follower_applied = follower.log_mut().applied_index().unwrap();
    drop(follower);
    let mut follower = ReplicatedJamServiceV2::new(
        JamServiceV2::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHostV2,
            LocalJamStoreV2::from_snapshot(follower_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false).with_applied(follower_applied),
    );
    let prepared =
        LocalWorkSchedulerV2::prepare_inbox(leader.service().accumulate_host(), call, 11).unwrap();
    let inbox_work = prepared.work;
    let inbox_transition = TransitionV2 {
        service: inbox_work.service.clone(),
        consumed_input: inbox_work.input_id(),
        target_deployment: inbox_work.target_deployment,
        target_program: inbox_work.target_program,
        base: inbox_work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"authorized delivery follower state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: call,
            producer: actor,
            result: Value::U32(100).encode(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    assert!(matches!(
        leader
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: inbox_work,
                transition: inbox_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot()),
        "the fresh follower drains an authorized inbox without a process-local verifier cache",
    );
    let entries = &shared.lock().unwrap().entries;
    assert_eq!(entries[3].receipt_verifications, delivery_verifications);
    assert!(entries[4].receipt_verifications.is_empty());
}

#[test]
fn raft_failover_applies_committed_requests_through_the_physical_guest() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([121; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([123; 32]),
            authenticator: vec![124],
        },
    };

    let availability_programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlobV2 {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let mut leader_host = LocalJamStoreV2::default();
    leader_host.allow_install(&genesis);
    let mut follower_host = LocalJamStoreV2::default();
    follower_host.allow_install(&genesis);

    let shared_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let leader_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        leader_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let follower_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        follower_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut leader = ReplicatedJamServiceV2::new(
        leader_service,
        TestCommittedLog::new(shared_log.clone(), true),
    );
    let mut follower =
        ReplicatedJamServiceV2::new(follower_service, TestCommittedLog::new(shared_log, false));

    let mut wrong_program = genesis.clone();
    wrong_program.service.service_program = ProgramId([0xFF; 32]);
    assert!(matches!(
        leader.accumulate(&AccumulateRequestV2::Install(wrong_program)),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::ServiceProgramMismatch { .. }
        ))
    ));
    assert_eq!(
        leader.log().committed_len(),
        0,
        "a locally detectable service-program mismatch never enters Raft"
    );

    assert!(matches!(
        leader
            .accumulate_with_availability(
                &AccumulateRequestV2::Install(genesis),
                &availability_programs,
                &availability_blobs,
            )
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
    assert_eq!(
        follower.service().accumulate_host().program(actor_program),
        Some(availability_programs[0].pvm.as_slice()),
        "a follower with no node-local program cache replays Install from the ordered sidecar"
    );
    assert_eq!(
        follower.service().accumulate_host().blob(&initial),
        Some(availability_blobs[0].bytes.as_slice()),
        "genesis bytes are replayable from the same committed entry"
    );
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot())
    );

    // Model leadership transfer with a prior-term application tail becoming
    // committed together with the new leader's promotion no-op. The VOS read
    // barrier must apply that tail before the node restores its admission
    // clock and allocates the next slot.
    let promotion_floor = 50_000;
    let promotion_tail = LocalWorkSchedulerV2::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([123; 32]),
            workflow_step: 0,
            logical_timeslot: promotion_floor,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let promotion_transition = TransitionV2 {
        service: promotion_tail.service.clone(),
        consumed_input: promotion_tail.input_id(),
        target_deployment: promotion_tail.target_deployment,
        target_program: promotion_tail.target_program,
        base: promotion_tail.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: promotion_tail.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"prior-term state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: promotion_tail.invocation.root_reply_id(),
            producer: promotion_tail.target,
            result: b"prior-term reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    leader
        .log_mut()
        .commit_before_next_read_index(direct_linear_ingress(&promotion_tail).encode());
    assert_eq!(leader.leadership_barrier_and_catch_up().unwrap(), 1);
    assert!(
        leader
            .service()
            .accumulate_host()
            .pending_ingresses()
            .unwrap()
            .iter()
            .any(|ingress| ingress.invocation == promotion_tail.invocation),
        "a current-term barrier exposes a prior-term admission before join quiescence is decided",
    );
    let caught_up_header = leader
        .service()
        .accumulate_host()
        .header()
        .unwrap()
        .unwrap();
    assert_eq!(caught_up_header.revision, 0);
    assert_eq!(
        caught_up_header.admission_timeslot_high_water,
        promotion_floor
    );
    assert!(matches!(
        leader
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: promotion_tail,
                transition: promotion_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let caught_up_header = leader
        .service()
        .accumulate_host()
        .header()
        .unwrap()
        .unwrap();
    assert_eq!(caught_up_header.revision, 1);
    assert_eq!(
        caught_up_header.admission_timeslot_high_water,
        promotion_floor
    );

    let first = LocalWorkSchedulerV2::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([125; 32]),
            workflow_step: 0,
            logical_timeslot: promotion_floor + 1,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let first_transition = TransitionV2 {
        service: first.service.clone(),
        consumed_input: first.input_id(),
        target_deployment: first.target_deployment,
        target_program: first.target_program,
        base: first.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: first.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"leader state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: first.invocation.root_reply_id(),
            producer: first.target,
            result: b"leader reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };

    // Another client can reach the Raft worker between this service's
    // catch-up and its proposal. The wrapper must apply that earlier entry
    // before its own committed request instead of jumping the cursor past it.
    let mut prior = first.clone();
    prior.invocation = InvocationId([124; 32]);
    for candidate in [&first, &prior] {
        assert!(matches!(
            leader
                .accumulate(&direct_linear_ingress(candidate))
                .unwrap()
                .result,
            AccumulationResultV2::IngressAdmitted {
                duplicate: false,
                ..
            }
        ));
    }
    let prior_transition = TransitionV2 {
        service: prior.service.clone(),
        consumed_input: prior.input_id(),
        target_deployment: prior.target_deployment,
        target_program: prior.target_program,
        base: prior.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: prior.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"interleaved state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: prior.invocation.root_reply_id(),
            producer: prior.target,
            result: b"interleaved reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    leader.log_mut().commit_before_next_proposal(
        AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: prior,
            transition: prior_transition,
            provided_blobs: vec![],
        })
        .encode(),
    );
    assert!(matches!(
        leader
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: first,
                transition: first_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::StaleLinearWork {
            expected_revision: 1,
            actual_revision: 2,
        })
    ));
    assert_eq!(
        leader
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .unwrap()
            .revision,
        2,
        "the earlier committed request is applied before the caller's proposal"
    );
    assert_eq!(follower.catch_up().unwrap(), 6);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot())
    );

    leader.log_mut().leader = false;
    follower.log_mut().leader = true;
    let second = LocalWorkSchedulerV2::prepare(
        follower.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([126; 32]),
            workflow_step: 0,
            logical_timeslot: promotion_floor + 2,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let second_transition = TransitionV2 {
        service: second.service.clone(),
        consumed_input: second.input_id(),
        target_deployment: second.target_deployment,
        target_program: second.target_program,
        base: second.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: second.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"failover state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: second.invocation.root_reply_id(),
            producer: second.target,
            result: b"failover reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    assert!(matches!(
        follower
            .accumulate(&direct_linear_ingress(&second))
            .unwrap()
            .result,
        AccumulationResultV2::IngressAdmitted {
            duplicate: false,
            ..
        }
    ));
    let failover_apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: second,
        transition: second_transition,
        provided_blobs: vec![],
    });
    assert!(matches!(
        follower.accumulate(&failover_apply).unwrap().result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(leader.catch_up().unwrap(), 2);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot())
    );
    assert_eq!(leader.log_mut().applied_index().unwrap(), 9);
    assert_eq!(follower.log_mut().applied_index().unwrap(), 9);

    follower.log_mut().leader = false;
    leader.log_mut().leader = true;
    assert!(matches!(
        leader.accumulate(&failover_apply).unwrap().result,
        AccumulationResultV2::Accepted {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot()),
        "an exact retry remains convergent after leadership returns to the first replica"
    );
}

#[test]
fn deterministic_raft_dispatch_failure_advances_but_commit_failure_retries() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft failure classification".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    let poison_gas_schedule = GasScheduleV2::new(100_000_000, 9_000_000);
    seed.service.gas_schedule = poison_gas_schedule;
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service,
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([0xD1; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([0xD3; 32]),
            authenticator: vec![0xD4],
        },
    };

    let availability_programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlobV2 {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let mut poison_host = LocalJamStoreV2::default();
    poison_host.allow_install(&genesis);
    let poison_shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let poison_log = TestCommittedLog::new(poison_shared.clone(), true);
    let mut poison_follower_host = LocalJamStoreV2::default();
    poison_follower_host.allow_install(&genesis);
    let poison_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        poison_host,
        poison_gas_schedule.refine,
        poison_gas_schedule.accumulate,
    )
    .unwrap();
    let mut poisoned = ReplicatedJamServiceV2::new(poison_service, poison_log);
    let poison_follower_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        poison_follower_host,
        poison_gas_schedule.refine,
        poison_gas_schedule.accumulate,
    )
    .unwrap();
    let mut poison_follower = ReplicatedJamServiceV2::new(
        poison_follower_service,
        TestCommittedLog::new(poison_shared.clone(), false),
    );
    let poison_result = poisoned.accumulate_with_availability(
        &AccumulateRequestV2::Install(genesis.clone()),
        &availability_programs,
        &availability_blobs,
    );
    assert!(
        matches!(
            poison_result,
            Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
                ServiceDispatchError::Pvm(ServicePvmErrorV2::OutOfGas { .. })
            ))
        ),
        "unexpected deterministic failure: {poison_result:?}"
    );
    assert_eq!(
        poisoned.log_mut().applied_index().unwrap(),
        1,
        "a deterministic guest failure is recorded as an ordered no-op"
    );
    assert_eq!(
        poisoned.catch_up().unwrap(),
        0,
        "the poisoned entry is not replayed forever"
    );
    assert_eq!(
        poison_follower.catch_up().unwrap(),
        1,
        "a second replica classifies the same committed guest failure"
    );
    assert_eq!(poison_follower.log_mut().applied_index().unwrap(), 1);
    assert!(
        poisoned
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&poison_follower.service().accumulate_host().snapshot()),
        "both replicas converge on the same ordered no-op"
    );
    assert!(
        poisoned
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none()
    );

    let mut mismatched_host = LocalJamStoreV2::default();
    mismatched_host.allow_install(&genesis);
    let mismatched_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        mismatched_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut mismatched_follower = ReplicatedJamServiceV2::new(
        mismatched_service,
        TestCommittedLog::new(poison_shared, false),
    );
    let mismatch = mismatched_follower.catch_up();
    assert!(matches!(
        mismatch,
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::ServiceGasScheduleMismatch {
                expected: TEST_GAS_SCHEDULE,
                declared,
            }
        )) if declared == poison_gas_schedule
    ));
    assert_eq!(
        mismatched_follower.log_mut().applied_index().unwrap(),
        0,
        "a replica with the wrong gas schedule must not advance past the entry"
    );

    let mut retry_genesis = genesis.clone();
    retry_genesis.service.gas_schedule = TEST_GAS_SCHEDULE;
    let mut retry_host = DurableJamStoreV2::open(FailableCommittedImages {
        fail_next_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    retry_host.allow_install(&retry_genesis);
    let retry_log =
        TestCommittedLog::new(Arc::new(Mutex::new(SharedCommittedLog::default())), true);
    let retry_service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        retry_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut retryable = ReplicatedJamServiceV2::new(retry_service, retry_log);
    assert!(matches!(
        retryable.accumulate_with_availability(
            &AccumulateRequestV2::Install(retry_genesis),
            &availability_programs,
            &availability_blobs,
        ),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateCommitRejected)
        ))
    ));
    assert_eq!(
        retryable.log_mut().applied_index().unwrap(),
        0,
        "a transient durable-host failure leaves the cursor for exact replay"
    );
    assert_eq!(retryable.log().committed_len(), 1);
    assert!(
        retryable
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none()
    );
    retryable
        .service_mut()
        .accumulate_host_mut()
        .backend_mut()
        .fail_next_commit = false;
    assert_eq!(retryable.catch_up().unwrap(), 1);
    assert_eq!(retryable.log_mut().applied_index().unwrap(), 1);
    assert!(
        retryable
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_some()
    );
}

#[test]
fn raft_orders_only_the_proved_attested_apply_and_followers_verify_it() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = grey_transpiler::link_elf(&greeter_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([131; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: true,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([133; 32]),
            authenticator: vec![134],
        },
    };

    let availability_programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlobV2 {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let proof_bytes = canonical_test_proof_manifest(0x87);
    let mut leader_host = LocalJamStoreV2::default();
    leader_host.allow_install(&genesis);
    let leader_proof = proof_bytes.clone();
    leader_host.install_proof_verifier(move |_, candidate| candidate == leader_proof);
    let mut follower_host = DurableJamStoreV2::open(FailableCommittedImages {
        fail_next_proof_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    follower_host.allow_install(&genesis);
    let follower_verifications = Arc::new(AtomicUsize::new(0));
    let follower_verification_count = follower_verifications.clone();
    let follower_proof = proof_bytes.clone();
    follower_host.install_proof_verifier(move |_, candidate| {
        follower_verification_count.fetch_add(1, Ordering::Relaxed);
        candidate == follower_proof
    });

    let shared_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let leader_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        leader_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let follower_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        follower_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut leader = ReplicatedJamServiceV2::new(
        leader_service,
        TestCommittedLog::new(shared_log.clone(), true),
    );
    let mut follower = ReplicatedJamServiceV2::new(
        follower_service,
        TestCommittedLog::new(shared_log.clone(), false),
    );
    assert!(matches!(
        leader
            .accumulate_with_availability(
                &AccumulateRequestV2::Install(genesis),
                &availability_programs,
                &availability_blobs,
            )
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));

    let prepared = LocalWorkSchedulerV2::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([135; 32]),
            workflow_step: 0,
            logical_timeslot: 20,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: true,
        },
    )
    .unwrap();
    assert!(matches!(
        leader
            .accumulate(&direct_linear_ingress(&prepared.work))
            .unwrap()
            .result,
        AccumulationResultV2::IngressAdmitted {
            duplicate: false,
            ..
        }
    ));
    let refined = leader
        .service()
        .refine_actor_tree(&prepared.work, &prepared.imports)
        .expect("the leader obtains the exact Refine transition before proving it");
    let input = prepared.work.input_id();
    let mut producer = CanonicalTestProofProducer {
        proof: proof_bytes,
        calls: 0,
    };
    let envelope = AccumulationEnvelopeV2 {
        work: prepared.work,
        transition: refined.transition,
        provided_blobs: refined.exported_blobs,
    };
    let committed = leader
        .accumulate_attested(envelope.clone(), &prepared.imports, &mut producer)
        .expect("leader proves before proposing Apply");
    assert_eq!(producer.calls, 1);
    assert_eq!(committed.published.proof, Some(committed.proof.clone()));

    let entries = shared_log.lock().unwrap().entries.clone();
    assert_eq!(entries.len(), 3, "PrepareAttested must not enter Raft");
    let AccumulateRequestV2::Apply(logged) =
        AccumulateRequestV2::decode(&entries[2].request).unwrap()
    else {
        panic!("the third Raft entry was not the proved Apply")
    };
    assert_eq!(logged.transition.proof, Some(committed.proof.clone()));

    let retried = leader
        .accumulate_attested(envelope, &prepared.imports, &mut producer)
        .expect("an exact retry resolves from the committed publication");
    assert_eq!(producer.calls, 1, "the cached proof is reused");
    assert_eq!(retried.proof, committed.proof);
    assert_eq!(retried.proof_bytes, committed.proof_bytes);
    assert_eq!(retried.accumulate_gas_used, 0);
    assert_eq!(
        shared_log.lock().unwrap().entries.len(),
        3,
        "a duplicate attestation never proposes another Apply"
    );

    assert!(matches!(
        follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::ProofUnavailable)
    ));
    assert_eq!(
        follower.log_mut().applied_index().unwrap(),
        2,
        "a failed follower proof-CAS write leaves the proved Apply unapplied"
    );
    assert_eq!(
        follower.catch_up().unwrap(),
        1,
        "the identical committed proof entry is retried after CAS recovery"
    );
    assert_eq!(follower.log_mut().applied_index().unwrap(), 3);
    assert!(
        follower_verifications.load(Ordering::Relaxed) >= 2,
        "the follower independently verifies both the failed hydration and exact retry"
    );
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot())
    );
    let follower_publication = follower
        .service()
        .accumulate_host()
        .pending_publications()
        .unwrap()
        .into_iter()
        .find(|publication| publication.input == input)
        .expect("follower verifies and commits the recoverable proof publication");
    assert_eq!(
        follower_publication.published.proof,
        logged.transition.proof
    );

    let snapshot_attestation = committed
        .published
        .attestation
        .as_deref()
        .expect("attested commit publishes verifier inputs");
    let snapshot_proofs = vec![vos::v2::CommittedProofArtifactV2 {
        verification: ProofVerificationRequestV2 {
            actor_program: snapshot_attestation.statement.actor_program,
            execution_semantics: snapshot_attestation
                .statement
                .accumulation_receipt
                .service
                .execution_semantics,
            statement: snapshot_attestation.proof.statement,
            trace: snapshot_attestation.proof.trace,
            proof_blob: snapshot_attestation.proof.proof_blob.clone(),
        },
        bytes: committed.proof_bytes.clone(),
    }];
    let snapshot = CommittedServiceSnapshotV2 {
        applied_index: 3,
        service_image: leader.service().accumulate_host().committed_service_image(),
        proof_artifacts: snapshot_proofs,
    };
    let mut missing_proof_snapshot = snapshot.clone();
    missing_proof_snapshot.proof_artifacts.clear();
    assert_eq!(
        CommittedServiceSnapshotV2::decode(&missing_proof_snapshot.encode()),
        Err(vos::v2::DecodeError::NonCanonical),
        "a snapshot cannot omit an artifact referenced by its publication"
    );
    let mut substituted_request_snapshot = snapshot.clone();
    substituted_request_snapshot.proof_artifacts[0]
        .verification
        .actor_program = ProgramId([0xF1; 32]);
    assert_eq!(
        CommittedServiceSnapshotV2::decode(&substituted_request_snapshot.encode()),
        Err(vos::v2::DecodeError::NonCanonical),
        "snapshot proof bytes cannot be rebound to substituted public inputs"
    );
    let mut surplus_proof_snapshot = snapshot.clone();
    let mut surplus = surplus_proof_snapshot.proof_artifacts[0].clone();
    surplus.verification.statement = Hash([0xF2; 32]);
    surplus_proof_snapshot.proof_artifacts.push(surplus);
    surplus_proof_snapshot
        .proof_artifacts
        .sort_unstable_by_key(|artifact| artifact.verification.hash());
    assert_eq!(
        CommittedServiceSnapshotV2::decode(&surplus_proof_snapshot.encode()),
        Err(vos::v2::DecodeError::NonCanonical),
        "a snapshot cannot carry unrelated proof verification work"
    );

    let mismatched_schedule =
        GasScheduleV2::new(TEST_GAS_SCHEDULE.refine, TEST_GAS_SCHEDULE.accumulate - 1);
    let mismatched_snapshot_host =
        DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
    let mismatched_snapshot_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        mismatched_snapshot_host,
        mismatched_schedule.refine,
        mismatched_schedule.accumulate,
    )
    .unwrap();
    let mut mismatched_snapshot_follower = ReplicatedJamServiceV2::new(
        mismatched_snapshot_service,
        TestCommittedLog::new(shared_log.clone(), false).with_installed_snapshot(snapshot.clone()),
    );
    let empty_service_image = mismatched_snapshot_follower
        .service()
        .accumulate_host()
        .committed_service_image();
    assert!(matches!(
        mismatched_snapshot_follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::ServiceGasScheduleMismatch {
                expected,
                declared,
            }
        )) if expected == mismatched_schedule && declared == TEST_GAS_SCHEDULE
    ));
    assert_eq!(
        mismatched_snapshot_follower
            .service()
            .accumulate_host()
            .committed_service_image(),
        empty_service_image,
        "a mismatched snapshot cannot replace the fresh service image"
    );
    assert_eq!(
        mismatched_snapshot_follower
            .service()
            .accumulate_host()
            .proof_bytes(&committed.proof.proof_blob),
        None,
        "snapshot identity is checked before the proof side-CAS is hydrated"
    );
    assert_eq!(
        mismatched_snapshot_follower
            .log_mut()
            .applied_index()
            .unwrap(),
        0,
        "snapshot identity is checked before the cursor advances"
    );

    let mut rejecting_snapshot_host =
        DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
    rejecting_snapshot_host.install_proof_verifier(|_, _| false);
    let rejecting_snapshot_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        rejecting_snapshot_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut rejecting_snapshot_follower = ReplicatedJamServiceV2::new(
        rejecting_snapshot_service,
        TestCommittedLog::new(shared_log.clone(), false).with_installed_snapshot(snapshot.clone()),
    );
    assert!(matches!(
        rejecting_snapshot_follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::ProofUnavailable)
    ));
    assert_eq!(
        rejecting_snapshot_follower
            .log_mut()
            .applied_index()
            .unwrap(),
        0
    );
    assert!(
        rejecting_snapshot_follower
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none(),
        "a verifier denial leaves the service image untouched"
    );
    assert_eq!(
        rejecting_snapshot_follower
            .service()
            .accumulate_host()
            .proof_bytes(&committed.proof.proof_blob),
        None,
        "a verifier denial leaves the proof side-CAS untouched"
    );

    let mark_only_host = LocalJamStoreV2::from_snapshot_bytes(&snapshot.service_image).unwrap();
    let mark_only_image = mark_only_host.committed_service_image();
    let mark_only_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        mark_only_host,
        mismatched_schedule.refine,
        mismatched_schedule.accumulate,
    )
    .unwrap();
    let mut mark_only_follower = ReplicatedJamServiceV2::new(
        mark_only_service,
        TestCommittedLog::new(Arc::new(Mutex::new(SharedCommittedLog::default())), false)
            .with_committed_index_floor(1),
    );
    assert!(matches!(
        mark_only_follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::Dispatch(
            ServiceDispatchError::ServiceGasScheduleMismatch {
                expected,
                declared,
            }
        )) if expected == mismatched_schedule && declared == TEST_GAS_SCHEDULE
    ));
    assert_eq!(mark_only_follower.log_mut().applied_index().unwrap(), 0);
    assert_eq!(
        mark_only_follower
            .service()
            .accumulate_host()
            .committed_service_image(),
        mark_only_image,
        "cursor-only advancement cannot bless a mismatched existing image"
    );

    let mut snapshot_host = DurableJamStoreV2::open(FailableCommittedImages {
        fail_next_proof_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    let snapshot_verifications = Arc::new(AtomicUsize::new(0));
    let snapshot_verification_count = snapshot_verifications.clone();
    let expected_snapshot_proof = committed.proof_bytes.clone();
    snapshot_host.install_proof_verifier(move |_, candidate| {
        snapshot_verification_count.fetch_add(1, Ordering::Relaxed);
        candidate == expected_snapshot_proof
    });
    let snapshot_service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        snapshot_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut snapshot_follower = ReplicatedJamServiceV2::new(
        snapshot_service,
        TestCommittedLog::new(shared_log, false).with_installed_snapshot(snapshot),
    );
    assert!(matches!(
        snapshot_follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::ProofUnavailable)
    ));
    assert_eq!(snapshot_follower.log_mut().applied_index().unwrap(), 0);
    assert!(
        snapshot_follower
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none(),
        "a snapshot is not installed before all proof artifacts are durable"
    );
    assert_eq!(snapshot_follower.catch_up().unwrap(), 0);
    assert_eq!(snapshot_follower.log_mut().applied_index().unwrap(), 3);
    assert_eq!(
        snapshot_follower
            .service()
            .accumulate_host()
            .proof_bytes(&committed.proof.proof_blob),
        Some(committed.proof_bytes.clone())
    );
    assert!(
        snapshot_follower
            .service()
            .accumulate_host()
            .pending_publications()
            .unwrap()
            .iter()
            .any(|publication| publication.input == input),
        "the installed publication remains routable after snapshot-only catch-up"
    );
    assert!(
        snapshot_verifications.load(Ordering::Relaxed) >= 2,
        "snapshot retry independently verifies before each side-CAS attempt"
    );
}

#[test]
fn redb_raft_log_drives_physical_guest_accumulate() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft-backed initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesisV2 {
        role_authority: None,
        external_actors: vec![],
        service: seed.service,
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([127; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([129; 32]),
            authenticator: vec![130],
        },
    };

    let availability_programs = vec![ImportedProgramV2 {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlobV2 {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let mut host = LocalJamStoreV2::default();
    host.allow_install(&genesis);
    let service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let directory = std::env::temp_dir().join(format!(
        "vos-v2-physical-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("raft.redb");
    let log = RaftAccumulateLogV2::open(&path, RaftConfig::default()).unwrap();
    let mut replicated = ReplicatedJamServiceV2::new(service, log);

    assert!(matches!(
        replicated
            .accumulate_with_availability(
                &AccumulateRequestV2::Install(genesis),
                &availability_programs,
                &availability_blobs,
            )
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));
    assert_eq!(replicated.log_mut().applied_index().unwrap(), 1);
    let header = replicated
        .service()
        .accumulate_host()
        .header()
        .unwrap()
        .expect("physical guest committed the service header");
    assert_eq!(header.consistency, ConsistencyModeV2::Raft);
    assert_eq!(header.revision, 0);
    let source_snapshot = replicated.service().accumulate_host().snapshot();
    let source_image = replicated.service().accumulate_host().snapshot_bytes();

    drop(replicated);
    let mut reopened = RaftAccumulateLogV2::open(&path, RaftConfig::default()).unwrap();
    assert_eq!(reopened.applied_index().unwrap(), 1);
    assert!(reopened.committed_after(1).unwrap().entries.is_empty());
    drop(reopened);

    // Deliver the exact snapshot through the real inbound vos-raft worker.
    // The worker owns only the log/snapshot database at this point; catch-up
    // must install the canonical image into the physical service host before
    // advancing its application cursor.
    let follower_db = Arc::new(redb::Database::create(directory.join("follower.redb")).unwrap());
    let snapshot = CommittedServiceSnapshotV2 {
        applied_index: 1,
        service_image: source_image,
        proof_artifacts: vec![],
    };
    let raft_config = RaftConfig {
        me: 0xBBBB,
        members: vec![0xAAAA, 0xBBBB],
        election_timeout_ms: (5_000, 10_000),
        heartbeat_interval_ms: 500,
        replication_id: [0xD1; 32],
        propose_timeout_ms: 2_000,
    };
    let (apply_tx, apply_rx) = std::sync::mpsc::channel();
    let worker = RaftWorker::spawn(
        follower_db.clone(),
        WorkerConfig {
            me: raft_config.me,
            members: raft_config.members.clone(),
            replication_id: raft_config.replication_id,
            election_timeout_ms: raft_config.election_timeout_ms,
            heartbeat_interval_ms: raft_config.heartbeat_interval_ms,
        },
        None,
        Some(apply_tx),
    );
    let installed = worker.handler().install_snapshot(
        &raft_config.replication_id,
        0xAAAA,
        1,
        1,
        1,
        0,
        true,
        snapshot.encode(),
        raft_config.members.clone(),
        None,
    );
    assert_eq!(installed.term, 1);

    let follower_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        DurableJamStoreV2::open(FailableCommittedImages {
            fail_next_commit: true,
            ..FailableCommittedImages::default()
        })
        .unwrap(),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let follower_log =
        RaftAccumulateLogV2::from_worker(follower_db, raft_config, worker, apply_rx).unwrap();
    let mut follower = ReplicatedJamServiceV2::new(follower_service, follower_log);
    assert!(matches!(
        follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::ServiceImage(
            vos::v2::ServiceImageInstallErrorV2::PersistenceRejected
        ))
    ));
    assert_eq!(follower.log_mut().applied_index().unwrap(), 0);
    assert!(
        follower
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none()
    );
    follower
        .service_mut()
        .accumulate_host_mut()
        .backend_mut()
        .fail_next_commit = false;
    assert_eq!(follower.catch_up().unwrap(), 0);
    assert_eq!(follower.log_mut().applied_index().unwrap(), 1);
    assert!(
        follower
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&source_snapshot)
    );
    drop(follower);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn malformed_guest_accumulate_returns_a_rejection_without_storage_effects() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let mut host = LocalJamStoreV2::default();

    let output = service
        .accumulate(b"not a v2 request", 10_000_000, &mut host)
        .unwrap();
    assert_eq!(
        AccumulationResultV2::decode(&output.bytes).unwrap(),
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::NonCanonical)
    );
    assert_eq!(host.row_count(), 0);
    assert_eq!(host.blob_count(), 0);
}
