//! Physical generic-service PVM integration gate.
//!
//! Build the service and actor guests first with:
//! `just build-pvm-test-artifacts`.
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
    AttestationProofHost, AttestationProofProducer, AttestationProofRequest,
    AttestationProofVerifier, ProducedAttestationProof,
};
use vos::network::RaftRpcHandler;
use vos::node::{AgentResult, NodeRegistrationError, VosNode};
use vos::raft::{RaftAccumulateLog, RaftConfig, RaftWorker, Role, WorkerConfig};
use vos::service::{
    AccumulateProtocolHost, AccumulateRequest, AccumulatedReply, AccumulatedRoleAssertion,
    AccumulationEnvelope, AccumulationReceipt, AccumulationRejection, AccumulationResult,
    ActorGenesis, ActorId, ActorUpgrade, ActorWrite, AttestedRootTreeInvokeError,
    AuthorizationEvidence, BlobRef, CallId, CausalCallContext, CommittedAccumulateBatch,
    CommittedAccumulateEntry, CommittedAccumulateLog, CommittedImageStore,
    CommittedServiceImageHost, CommittedServiceSnapshot, ConsistencyBase, ConsistencyMode,
    ContinuationChange, ContinuationSnapshot, CrdtChange, DeploymentId, DeviceSecret,
    DeviceSignerRefineHost, DirectIngress, DurableServiceStore, ExternalActorBinding,
    FileCommittedImageStore, GasAccounting, GasSchedule, Hash, ImportedActor, ImportedBlob,
    ImportedProgram, InboxDrainOutcome, InvocationId, LocalRootTreeConfig,
    LocalRootTreeConfigError, LocalRootTreeInvokeError, LocalRootTreeOpenError,
    LocalRootTreeService, LocalTransport, LocalWorkRequest, LocalWorkScheduler, MemoryServiceHost,
    MemoryServiceSnapshot, MemoryServiceStore, MessageRecord, MethodPolicy, NoRefineProtocolHost,
    Origin, PackageManifest, PackageRolePolicies, PackageTaskDependency, PrivateIngressStaging,
    ProducerId, ProductionTrust, ProductionTrustDecision, ProductionTrustError, ProgramId,
    ProofArtifactStore, ProofVerificationRequest, PublishedEffects, ReceiptVerificationRequest,
    RefineImports, RefineOutput, RefineProtocolHost, ReplicatedServiceError,
    ReplicatedServiceRuntime, ReplyRecord, RoleAuthorityBinding, RoleAuthorityInviteRedemption,
    RoleAuthorityMutation, RoleAuthorizationClaim, RoleCredential,
    RoleCredentialVerificationRequest, RootServiceId, RootTreeAttestedResult, RootTreeInvocation,
    RootTreeUpgradeRequest, ScheduleError, ServiceDispatchError, ServiceGenesis, ServiceIdentity,
    ServicePvm, ServicePvmError, ServiceRuntime, ServiceWire, StateKey, SubjectId,
    SystemCapabilityId, TaskDependency, Transition, VosPackage, WorkEnvelope, WorkflowOperation,
    artifact_hash, public_policy_hash, space_role_policy_hash,
};
use vos::{
    Decode, Encode,
    actors::{client::ClientError, context::ServiceId},
    value::{Msg, Value},
};

const TEST_GAS_SCHEDULE: GasSchedule = GasSchedule::new(1_000_000_000, 5_000_000_000);

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

fn role_policies(mut methods: Vec<MethodPolicy>) -> Vec<u8> {
    methods.sort_by(|left, right| left.method.cmp(&right.method));
    PackageRolePolicies {
        methods,
        task_dependencies: vec![],
    }
    .encode()
}

fn direct_linear_ingress(work: &WorkEnvelope) -> AccumulateRequest {
    assert!(matches!(work.base, ConsistencyBase::Linear { .. }));
    AccumulateRequest::AdmitIngress(DirectIngress {
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

fn admit_linear_work<R, A>(service: &mut ServiceRuntime<R, A>, work: &WorkEnvelope)
where
    R: RefineProtocolHost,
    A: AccumulateProtocolHost,
{
    let admitted = service
        .accumulate(&direct_linear_ingress(work))
        .unwrap()
        .result;
    assert!(
        matches!(
            admitted,
            AccumulationResult::IngressAdmitted {
                duplicate: false,
                ..
            }
        ),
        "direct test ingress was rejected: {admitted:?}"
    );
}

fn request_from_work(work: &WorkEnvelope) -> LocalWorkRequest {
    LocalWorkRequest {
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
    service: &mut ServiceRuntime<NoRefineProtocolHost, A>,
    request: &LocalWorkRequest,
) where
    A: AccumulateProtocolHost + MemoryServiceHost,
{
    let service_identity = service
        .accumulate_host()
        .local_store()
        .header()
        .unwrap()
        .unwrap()
        .service;
    let ingress = LocalWorkScheduler::prepare_direct_ingress(
        service.accumulate_host().local_store(),
        &service_identity,
        request,
    )
    .unwrap();
    assert!(matches!(
        service
            .accumulate(&AccumulateRequest::AdmitIngress(ingress))
            .unwrap()
            .result,
        AccumulationResult::IngressAdmitted {
            duplicate: false,
            ..
        }
    ));
}

fn admit_and_prepare<A>(
    service: &mut ServiceRuntime<NoRefineProtocolHost, A>,
    request: LocalWorkRequest,
) -> vos::service::PreparedWork
where
    A: AccumulateProtocolHost + MemoryServiceHost,
{
    admit_direct_request(service, &request);
    LocalWorkScheduler::prepare(service.accumulate_host().local_store(), request).unwrap()
}

#[derive(Debug, Default)]
struct FailableCommittedImages {
    image: Option<Vec<u8>>,
    proofs: BTreeMap<[u8; 32], Vec<u8>>,
    private_ingresses: BTreeMap<InvocationId, Vec<u8>>,
    private_ingress_staging: BTreeMap<InvocationId, PrivateIngressStaging>,
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

#[derive(Debug, Default)]
struct TransientOpenImageState {
    image: Option<Vec<u8>>,
    load_attempts: usize,
    remaining_load_failures: usize,
}

#[derive(Debug, Clone, Default)]
struct TransientOpenCommittedImages(Arc<Mutex<TransientOpenImageState>>);

impl TransientOpenCommittedImages {
    fn fail_loads(&self, count: usize) {
        let mut state = self.0.lock().unwrap();
        state.load_attempts = 0;
        state.remaining_load_failures = count;
    }

    fn load_attempts(&self) -> usize {
        self.0.lock().unwrap().load_attempts
    }
}

impl CommittedImageStore for TransientOpenCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        let mut state = self.0.lock().unwrap();
        state.load_attempts += 1;
        if state.remaining_load_failures > 0 {
            state.remaining_load_failures -= 1;
            return Err(());
        }
        Ok(state.image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.lock().unwrap().image = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStore for TransientOpenCommittedImages {
    type Error = ();

    fn load_proof(&self, _reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn commit_proof(&mut self, _reference: &BlobRef, _proof: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reconcile_proof_artifacts(&mut self, _retained: &[BlobRef]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRef)],
        _terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        if retained.is_empty() { Ok(()) } else { Err(()) }
    }
}

impl CommittedImageStore for SharedCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        *self.0.lock().unwrap() = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStore for SharedCommittedImages {
    type Error = ();

    fn load_proof(&self, _reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn commit_proof(&mut self, _reference: &BlobRef, _proof: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reconcile_proof_artifacts(&mut self, _retained: &[BlobRef]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRef)],
        _terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        if retained.is_empty() { Ok(()) } else { Err(()) }
    }
}

impl CommittedImageStore for SharedProofCommittedImages {
    type Error = ();

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.lock().unwrap().image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.lock().unwrap().image = Some(image.to_vec());
        Ok(())
    }
}

impl ProofArtifactStore for SharedProofCommittedImages {
    type Error = ();

    fn load_proof(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .proofs
            .get(&reference.hash.0)
            .filter(|proof| reference.matches(proof))
            .cloned())
    }

    fn commit_proof(&mut self, reference: &BlobRef, proof: &[u8]) -> Result<(), Self::Error> {
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

    fn reconcile_proof_artifacts(&mut self, retained: &[BlobRef]) -> Result<(), Self::Error> {
        let retained: std::collections::BTreeSet<_> =
            retained.iter().map(|reference| reference.hash.0).collect();
        self.0
            .lock()
            .unwrap()
            .proofs
            .retain(|hash, _| retained.contains(hash));
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRef)],
        _terminal: &[InvocationId],
    ) -> Result<(), Self::Error> {
        if retained.is_empty() { Ok(()) } else { Err(()) }
    }
}

impl CommittedImageStore for SharedFailingCommittedImages {
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

impl ProofArtifactStore for SharedFailingCommittedImages {
    type Error = ();

    fn load_proof(&self, _reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn commit_proof(&mut self, _reference: &BlobRef, _proof: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reconcile_proof_artifacts(&mut self, _retained: &[BlobRef]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(InvocationId, BlobRef)],
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

impl AttestationProofProducer for CanonicalTestProofProducer {
    type Error = ();

    fn prove(
        &mut self,
        request: &AttestationProofRequest<'_>,
    ) -> Result<ProducedAttestationProof, Self::Error> {
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
        Ok(ProducedAttestationProof {
            trace: request.refine_trace,
            proof: self.proof.clone(),
        })
    }
}

impl AttestationProofVerifier for CanonicalTestProofProducer {
    type Error = ();

    fn verify(
        &mut self,
        request: &ProofVerificationRequest,
        proof: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(request.proof_blob.matches(proof) && proof == self.proof)
    }
}

fn canonical_test_proof_manifest(tag: u8) -> Vec<u8> {
    vos::service::AttestationProofManifest {
        proof_system: vos::service::AttestationProofManifest::proof_system(),
        initial_root: Hash([tag.wrapping_add(1); 32]),
        segments: vec![vos::service::ProofArtifactId([tag; 32])],
    }
    .encode()
}

#[derive(Debug)]
struct MismatchedTraceProofProducer;

impl AttestationProofProducer for MismatchedTraceProofProducer {
    type Error = ();

    fn prove(
        &mut self,
        request: &AttestationProofRequest<'_>,
    ) -> Result<ProducedAttestationProof, Self::Error> {
        request.validate().map_err(|_| ())?;
        let mut trace = request.refine_trace;
        trace.0[0] ^= 1;
        Ok(ProducedAttestationProof {
            trace,
            proof: b"proof for the wrong trace".to_vec(),
        })
    }
}

impl CommittedImageStore for FailableCommittedImages {
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

impl ProofArtifactStore for FailableCommittedImages {
    type Error = ();

    fn load_proof(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .proofs
            .get(&reference.hash.0)
            .filter(|bytes| reference.matches(bytes))
            .cloned())
    }

    fn commit_proof(&mut self, reference: &BlobRef, proof: &[u8]) -> Result<(), Self::Error> {
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

    fn reconcile_proof_artifacts(&mut self, retained: &[BlobRef]) -> Result<(), Self::Error> {
        let retained: std::collections::BTreeSet<_> =
            retained.iter().map(|reference| reference.hash.0).collect();
        self.proofs.retain(|hash, _| retained.contains(hash));
        Ok(())
    }

    fn private_ingress_artifact_count(&self) -> Result<usize, Self::Error> {
        Ok(self.private_ingresses.len())
    }

    fn load_private_ingress(
        &self,
        invocation: InvocationId,
        reference: &BlobRef,
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
        reference: &BlobRef,
        arguments: &[u8],
        staging: PrivateIngressStaging,
    ) -> Result<bool, Self::Error> {
        if !reference.matches(arguments) {
            return Err(());
        }
        match self.private_ingresses.get(&invocation) {
            Some(existing) if existing != arguments => Err(()),
            Some(_) => {
                if staging == PrivateIngressStaging::Replicated {
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
        retained: &[(InvocationId, BlobRef)],
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
                        == Some(&PrivateIngressStaging::Replicated))
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
    ServiceRuntime<NoRefineProtocolHost, DurableServiceStore<FailableCommittedImages>>;

fn restart_durable_service(
    service: DurableTestService,
    service_pvm: &[u8],
    service_program: ProgramId,
) -> DurableTestService {
    let (_, host) = service.into_hosts();
    let (_, backend) = host.into_parts();
    ServiceRuntime::new(
        service_pvm.to_vec(),
        service_program,
        NoRefineProtocolHost,
        DurableServiceStore::open(backend).expect("committed service image reopens"),
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
    entries: Vec<CommittedAccumulateEntry>,
}

struct TestCommittedLog {
    shared: Arc<Mutex<SharedCommittedLog>>,
    applied: u64,
    leader: bool,
    before_next_read_index: Vec<Vec<u8>>,
    before_next_proposal: Vec<Vec<u8>>,
    installed_snapshot: Option<CommittedServiceSnapshot>,
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

    fn with_installed_snapshot(mut self, snapshot: CommittedServiceSnapshot) -> Self {
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

impl CommittedAccumulateLog for TestCommittedLog {
    type Error = TestLogError;

    fn leader_read_index(&mut self) -> Result<u64, Self::Error> {
        if !self.leader {
            return Err(TestLogError::NotLeader);
        }
        let mut shared = self.shared.lock().unwrap();
        for request in core::mem::take(&mut self.before_next_read_index) {
            let entry = CommittedAccumulateEntry {
                index: shared.entries.len() as u64 + 1,
                request,
                host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
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
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
        receipt_verifications: &[ReceiptVerificationRequest],
    ) -> Result<CommittedAccumulateEntry, Self::Error> {
        if !self.leader {
            return Err(TestLogError::NotLeader);
        }
        let mut shared = self.shared.lock().unwrap();
        for request in core::mem::take(&mut self.before_next_proposal) {
            let entry = CommittedAccumulateEntry {
                index: shared.entries.len() as u64 + 1,
                request,
                host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
                logical_timeslot: None,
                production_trust_policy: None,
                availability_programs: vec![],
                availability_blobs: vec![],
                receipt_verifications: vec![],
            };
            shared.entries.push(entry);
        }
        let entry = CommittedAccumulateEntry {
            index: shared.entries.len() as u64 + 1,
            request: request.to_vec(),
            host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
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
    ) -> Result<CommittedAccumulateBatch, Self::Error> {
        if applied_index != self.applied {
            return Err(TestLogError::InvalidCursor);
        }
        let shared = self.shared.lock().unwrap();
        let committed_index = self
            .committed_index_floor
            .unwrap_or(shared.entries.len() as u64);
        Ok(CommittedAccumulateBatch {
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
    ) -> Result<Option<CommittedServiceSnapshot>, Self::Error> {
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
        _proof_artifacts: &[vos::service::CommittedProofArtifact],
        _result_artifacts: &[vos::service::CommittedResultArtifact],
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

fn authorize_install<R, A: MemoryServiceHost>(
    service: &mut ServiceRuntime<R, A>,
    request: &AccumulateRequest,
) {
    let AccumulateRequest::Install(genesis) = request else {
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
const SERVICE_TOOLCHAIN: &str = include_str!("../../services/vos-service/rust-toolchain.toml");
const PRODUCTION_ARTIFACT_PROVENANCE: &str =
    include_str!("../../support/production-artifacts.toml");
const PINNED_ARTIFACT_BUILDER: &str = include_str!("../../scripts/build-production-artifacts.sh");

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
        "tests/fixtures/definitely-missing-guest.elf",
        "just build-pvm-test-artifacts",
    );
}

fn service_elf() -> Vec<u8> {
    required_elf(
        "../target/pinned-production-artifacts/vos_service.elf",
        "just build-vos-service",
    )
}

fn freshly_transpiled_service_pvm() -> Vec<u8> {
    required_elf(
        "../target/pinned-production-artifacts/vos-service.pvm",
        "just build-vos-service",
    )
}

#[test]
fn canonical_service_artifact_has_the_protocol_identity() {
    assert_eq!(
        ProgramId::of_pvm(CANONICAL_SERVICE_PVM),
        vos::service::VOS_SERVICE_PROGRAM_ID
    );
    ServicePvm::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
    )
    .expect("committed service PVM has the canonical Refine/Accumulate entries");
}

#[test]
fn canonical_service_artifact_matches_a_fresh_build() {
    let fresh = freshly_transpiled_service_pvm();
    assert!(
        fresh == CANONICAL_SERVICE_PVM,
        "pinned source/transpiler output differs: fresh ProgramId {:?}, committed ProgramId {:?}",
        ProgramId::of_pvm(&fresh),
        ProgramId::of_pvm(CANONICAL_SERVICE_PVM)
    );
}

#[test]
fn canonical_service_build_pins_path_independent_crate_identity() {
    assert!(SERVICE_BUILD_CONFIG.contains("rustc-wrapper = \"./rustc-remap.sh\""));
    assert!(SERVICE_BUILD_CONFIG.contains("-Zremap-cwd-prefix=."));
    assert!(SERVICE_RUSTC_WRAPPER.contains("-Cmetadata=vos-service"));
    assert!(SERVICE_RUSTC_WRAPPER.contains("--remap-path-prefix=$repository_root=vos-source"));
}

#[test]
fn canonical_production_artifacts_pin_source_and_toolchains() {
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("format byte as hex");
            output
        })
    }

    assert!(
        PRODUCTION_ARTIFACT_PROVENANCE
            .contains("source_revision = \"54ec5cca7dc5be3fc80f2f89247233719f790b95\"")
    );
    assert!(
        PRODUCTION_ARTIFACT_PROVENANCE.contains(
            "agent_runtime_source_revision = \"38c563b75da473a8ce0529f96d749519c149a9c4\""
        )
    );
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains("guest_toolchain = \"nightly-2026-03-20\""));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains("host_toolchain = \"nightly-2025-05-09\""));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "service_program_id = \"38207480731d47af5194a3e1e61b0f9667983edbbf16c90f2bde7d2153de4481\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "service_elf_blake2b_256 = \"e7b9a82d22702e8522e8b36faa1118fcced759cb6632b4377f4d8475890a32f0\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "service_pvm_blake2b_256 = \"1911c5b7f5ee746cfe231a81f9ec2d5355e725faad7c578514b5580e5baf1cc6\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "authority_program_id = \"da1c25f9b2c18144a0ef346b873930a53e881429fd11cdbcbf3a3182189aba79\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "authority_pvm_blake2b_256 = \"f91f993dd459a6a8107b85dc3a0b12776191faaf9cab494a443d12b92c745ac6\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "agent_runtime_program_id = \"cb3391e5adb78421b444a59d42227ed7010be1dd396a85582fbd0fdb62b6e386\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "agent_runtime_elf_blake2b_256 = \"7ba7d5360fa6835213d5d649e11c6db72fae4adde7a5240c171428b67188f4c0\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "agent_runtime_pvm_blake2b_256 = \"489b20fb3c79bef8f6fd7e4ed77d2cd7a7eb991f8dc175a7af0868c47e03cf33\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "registry_elf_blake2b_256 = \"461f2b368dd653698c8650b07800b81634b3072b37fd7a5f3708581021bbbd32\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "clerk_actor_program_id = \"8103683319d274216ce16df5a50d83778a375b7ebed36cd7ec7e5f9b92198186\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "clerk_deployment_id = \"983e31b8ac71d086e4cfc5892cf742ff1eedb1f2cd0cefc69cada61e5741495d\""
    ));
    assert!(PRODUCTION_ARTIFACT_PROVENANCE.contains(
        "clerk_task_hash = \"9e7ff9caee2bdb73b1defa1217a8b14524e3c9239a4926f203affcb98df7f7a9\""
    ));
    assert!(SERVICE_TOOLCHAIN.contains("channel = \"nightly-2026-03-20\""));
    for key in [
        "source_revision",
        "agent_runtime_source_revision",
        "guest_toolchain",
        "host_toolchain",
        "service_program_id",
        "service_elf_blake2b_256",
        "service_pvm_blake2b_256",
        "authority_program_id",
        "authority_pvm_blake2b_256",
        "agent_runtime_program_id",
        "agent_runtime_elf_blake2b_256",
        "agent_runtime_pvm_blake2b_256",
        "registry_elf_blake2b_256",
        "clerk_actor_program_id",
        "clerk_deployment_id",
        "clerk_task_hash",
    ] {
        assert!(PINNED_ARTIFACT_BUILDER.contains(key));
    }
    assert!(PINNED_ARTIFACT_BUILDER.contains("service-pvm"));
    assert!(PINNED_ARTIFACT_BUILDER.contains("fresh_service_pvm"));
    assert!(PINNED_ARTIFACT_BUILDER.contains("explicit libp2p signer key path"));
    assert!(PINNED_ARTIFACT_BUILDER.contains("clerk-test"));

    let clerk = canonical_clerk_package();
    assert_eq!(
        hex(&clerk.manifest.actor_program.0),
        "8103683319d274216ce16df5a50d83778a375b7ebed36cd7ec7e5f9b92198186",
    );
    assert_eq!(
        hex(&clerk.deployment_id().0),
        "983e31b8ac71d086e4cfc5892cf742ff1eedb1f2cd0cefc69cada61e5741495d",
    );
    assert_eq!(
        hex(&clerk.task_dependencies[0].binding.task.0),
        "9e7ff9caee2bdb73b1defa1217a8b14524e3c9239a4926f203affcb98df7f7a9",
    );
}

fn greeter_elf() -> Vec<u8> {
    required_elf(
        "../vos/tests/fixtures/greeter/target/riscv64em-vos/release/greeter.elf",
        "just build-pvm-test-artifacts",
    )
}

fn probe_elf() -> Vec<u8> {
    required_elf(
        "../vos/tests/fixtures/probe/target/riscv64em-vos/release/probe.elf",
        "just build-pvm-test-artifacts",
    )
}

fn tally_elf() -> Vec<u8> {
    required_elf(
        "../vos/tests/fixtures/tally/target/riscv64em-vos/release/tally.elf",
        "just build-pvm-test-artifacts",
    )
}

fn crdt_counter_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/crdt-counter/target/riscv64em-vos/release/crdt_counter_fixture.elf",
        "just build-pvm-test-artifacts",
    )
}

fn workflow_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/workflow/target/riscv64em-vos/release/workflow_fixture.elf",
        "just build-pvm-test-artifacts",
    )
}

fn cycle_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/cycle/target/riscv64em-vos/release/cycle_fixture.elf",
        "just build-pvm-test-artifacts",
    )
}

fn space_authority_elf() -> Vec<u8> {
    required_elf(
        "../actors/space-authority/target/riscv64em-vos/release/space_authority.elf",
        "just build-pvm-test-artifacts",
    )
}

fn clerk_ledger_elf() -> Vec<u8> {
    required_elf(
        "../actors/clerk-ledger/target/riscv64em-vos/release/clerk_ledger.elf",
        "just build-pvm-test-artifacts",
    )
}

fn clerk_bridge_elf() -> Vec<u8> {
    required_elf(
        "../actors/clerk-bridge/target/riscv64em-vos/release/clerk_bridge.elf",
        "just build-pvm-test-artifacts",
    )
}

fn canonical_clerk_package() -> VosPackage {
    let bytes = required_elf(
        "../target/clerk/clerk-ledger.vos",
        "just build-pvm-test-artifacts",
    );
    let package = VosPackage::decode(&bytes).expect("canonical Clerk package decodes");
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
    use space_registry::{NODE_ROLE_VOTER, Status, pack_auth, registry_mutation_signed_bytes};

    node.register_at_id(
        vos::node::AgentConfig::new(registry_pvm),
        ServiceId::REGISTRY,
    );
    let registry = vos::registry::RegistryRef::at(ServiceId::REGISTRY);
    let root_key = SigningKey::from_bytes(&[0xB9; 32]);
    let mut root_peer = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
    root_peer.extend_from_slice(&root_key.verifying_key().to_bytes());
    assert_eq!(
        vos::block_on(registry.set_root(&mut &*node, root_peer.clone())).unwrap(),
        Status::Ok,
    );
    let space_id = [0xb8; 32];
    assert_eq!(
        vos::block_on(registry.set_space_id(&mut &*node, space_id.to_vec())).unwrap(),
        Status::Ok,
    );
    for (prefix, peer) in voters {
        let prefix = u32::from(*prefix);
        let canonical = registry_mutation_signed_bytes(
            &space_id,
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
    let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
    assembler
        .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, result)
        .ecalli(0);
    assembler.build()
}

fn work(actor_program: ProgramId, state: BlobRef) -> WorkEnvelope {
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("start").encode());
    WorkEnvelope {
        external_actors: vec![],
        service: ServiceIdentity {
            space: vos::service::SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
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
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        consistency: ConsistencyMode::Local,
        base: ConsistencyBase::Linear {
            revision: 0,
            state_root: Hash([8; 32]),
        },
        base_causal_height: None,
        imported_actors: vec![ImportedActor {
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
    service: ServiceIdentity,
    actor: ActorId,
    producer: ProducerId,
    program: ProgramId,
) -> ExternalActorBinding {
    let actor_deployment = service.deployment;
    ExternalActorBinding {
        name: name.into(),
        service,
        actor,
        producer,
        actor_deployment,
        program,
    }
}

fn bound_peer_service(service: &ServiceIdentity) -> ServiceIdentity {
    let mut peer = service.clone();
    peer.root_service = RootServiceId([45; 32]);
    peer.deployment = DeploymentId([46; 32]);
    peer
}

fn private_age_binding(service: &ServiceIdentity) -> ExternalActorBinding {
    external_binding(
        "private-age",
        bound_peer_service(service),
        ActorId([44; 32]),
        ProducerId([98; 32]),
        ProgramId([92; 32]),
    )
}

fn peer_reply(
    service: &ServiceIdentity,
    call_id: CallId,
    value: u32,
    discriminator: u8,
) -> AccumulatedReply {
    let reply = ReplyRecord {
        call_id,
        producer: ActorId([44; 32]),
        result: Value::U32(value).encode(),
    };
    let producer_service = bound_peer_service(service);
    AccumulatedReply {
        receipt: AccumulationReceipt {
            service: producer_service,
            accepted_transition: Hash([discriminator.wrapping_add(2); 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([discriminator.wrapping_add(3); 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply,
        attestation: None,
    }
}

#[test]
fn canonical_guest_refine_runs_at_ic0_and_returns_nested_transition() {
    let elf = service_elf();
    let actor_elf = greeter_elf();
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvm::new(pvm.clone(), ProgramId::of_pvm(&pvm))
        .expect("generic service has the GP IC0/IC5 entries");
    let actor = vos_pvm_compiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRef::of_bytes(&state_bytes);
    let mut work = work(actor_program, state.clone());
    work.imported_actors.push(ImportedActor {
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
    let imports = RefineImports {
        programs: vec![ImportedProgram {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlob {
            reference: state,
            bytes: state_bytes,
        }],
        private_blobs: vec![],
    };

    let output = service
        .refine_actor_tree(&work.encode(), &imports, 100_000_000, &NoRefineProtocolHost)
        .expect("generic Refine completes");
    let transition = RefineOutput::decode(&output.bytes)
        .expect("Refine returns RefineOutput")
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
) -> (VosPackage, String) {
    let actor_pvm = vos_pvm_compiler::link_elf(actor_elf).expect("actor transpiles");
    let schemas = vos::metadata::raw_section_from_elf(actor_elf).expect("actor metadata");
    let metadata = vos::metadata::decode(&schemas).expect("valid actor metadata");
    let policies = PackageRolePolicies::from_metadata(&metadata)
        .expect("actor policies")
        .encode();
    let public_key = signer.public().encode_protobuf();
    let mut package = VosPackage {
        manifest: PackageManifest {
            name: metadata.actor_name.clone(),
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            actor_program: ProgramId::of_pvm(&actor_pvm),
            crdt: metadata.crdt,
            interfaces_hash: artifact_hash(b"interfaces", &[]),
            role_policies_hash: artifact_hash(b"role-policies", &policies),
            schemas_hash: artifact_hash(b"schemas", &schemas),
            task_dependencies_hash: vos::service::task_dependencies_hash(&[]),
        },
        actor_pvm,
        generated_interfaces: vec![],
        role_policies: policies,
        schemas,
        task_dependencies: vec![],
        diagnostics: None,
        deployment_signature: vos::service::DeploymentSignature {
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

fn replacement_test_package(
    original: &VosPackage,
    signer: &libp2p::identity::Keypair,
) -> VosPackage {
    let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
    assembler
        .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, 0)
        .ecalli(0);
    let mut replacement = original.clone();
    replacement.actor_pvm = assembler.build();
    replacement.manifest.actor_program = ProgramId::of_pvm(&replacement.actor_pvm);
    replacement.deployment_signature.signature = signer
        .sign(&replacement.signing_message())
        .expect("sign replacement package");
    replacement
        .validate()
        .expect("replacement package is canonical");
    assert_ne!(replacement.deployment_id(), original.deployment_id());
    replacement
}

fn attested_root_fixture(
    consistency: ConsistencyMode,
    salt: u8,
) -> (LocalRootTreeConfig, LocalWorkRequest) {
    let actor_elf = workflow_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([salt; 32]);
    let service = ServiceIdentity {
        space: vos::service::SpaceId([salt.wrapping_add(1); 32]),
        root_service: RootServiceId([salt.wrapping_add(2); 32]),
        deployment: package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service,
        root_actor: actor,
        actor_name,
        consistency,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([salt.wrapping_add(3); 32]),
            authenticator: vec![salt.wrapping_add(4)],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("attested_value").encode());
    let mut invocation = [salt.wrapping_add(5); 32];
    invocation[..8].copy_from_slice(b"VOSINGR!");
    let request = LocalWorkRequest {
        invocation: InvocationId(invocation),
        workflow_step: 0,
        logical_timeslot: 11,
        target: actor,
        method: "attested_value".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
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

fn decode_device_signature(committed: &vos::service::CommittedRootTreeSlice) -> Vec<u8> {
    let reply = committed
        .published
        .reply
        .as_ref()
        .expect("device signer publishes one direct reply");
    let Value::Bytes(bytes) = Value::try_decode(&reply.result).expect("reply is a Value") else {
        panic!("device signature is encoded as Value::Bytes")
    };
    bytes
}

#[derive(Default)]
struct RecordingNativeExtension {
    calls: Mutex<Vec<(String, InvocationId, Vec<u8>)>>,
}

impl vos::service::NativeExtensionInvoker for RecordingNativeExtension {
    fn invoke(
        &self,
        target: &str,
        invocation: InvocationId,
        payload: &[u8],
    ) -> Result<Vec<u8>, u8> {
        self.calls
            .lock()
            .unwrap()
            .push((target.into(), invocation, payload.to_vec()));
        Ok(Value::U32(7).encode())
    }
}

#[derive(Default)]
struct MalformedReplyNativeExtension {
    calls: AtomicUsize,
}

impl vos::service::NativeExtensionInvoker for MalformedReplyNativeExtension {
    fn invoke(
        &self,
        _target: &str,
        _invocation: InvocationId,
        _payload: &[u8],
    ) -> Result<Vec<u8>, u8> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(vec![0xff])
    }
}

fn set_workflow_request(request: &mut LocalWorkRequest, method: &str, message: Msg) {
    request.method = method.into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&message.encode());
        arguments
    };
}

#[test]
fn service_actor_native_extension_hostcall_preserves_typed_wire_and_stable_identity() {
    let (mut config, mut request) = attested_root_fixture(ConsistencyMode::Local, 0x61);
    config.intra_caps = vec![vos::IntraCap::parse("native-peer:member").unwrap()];
    set_workflow_request(
        &mut request,
        "extension_peer_value",
        Msg::new("extension_peer_value"),
    );
    request.proof_requested = false;
    let parent_invocation = request.invocation;
    let actor = config.root_actor;

    let recorder = Arc::new(RecordingNativeExtension::default());
    let mut service = LocalRootTreeService::open(config, SharedCommittedImages::default())
        .expect("native extension hostcall fixture opens");
    service.set_native_extension_invoker(recorder.clone());
    let committed = service
        .invoke(request)
        .expect("typed native extension call completes");
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(7)),
    );

    let calls = recorder.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (target, invocation, payload) = &calls[0];
    assert_eq!(target, "native-peer");
    assert_eq!(payload.first(), Some(&vos::value::TAG_DYNAMIC));
    let typed = <Msg as Decode>::decode(&payload[1..]);
    assert_eq!(typed.name, "peer_value");
    let mut nonce = Vec::new();
    nonce.extend_from_slice(parent_invocation.as_bytes());
    nonce.extend_from_slice(&actor.0);
    nonce.extend_from_slice(&0u64.to_le_bytes());
    nonce.extend_from_slice(b"native-peer");
    assert_eq!(
        *invocation,
        InvocationId::derive(b"vos/native-extension-call/service", &nonce),
    );
}

#[test]
fn service_actor_native_extension_malformed_reply_is_a_typed_failure() {
    let (mut config, mut request) = attested_root_fixture(ConsistencyMode::Local, 0x65);
    config.intra_caps = vec![vos::IntraCap::parse("native-peer:member").unwrap()];
    set_workflow_request(
        &mut request,
        "extension_peer_value",
        Msg::new("extension_peer_value"),
    );
    request.proof_requested = false;

    let mut service = LocalRootTreeService::open(config, SharedCommittedImages::default())
        .expect("native extension malformed-reply fixture opens");
    let extension = Arc::new(MalformedReplyNativeExtension::default());
    service.set_native_extension_invoker(extension.clone());
    let committed = service
        .invoke(request)
        .expect("the actor handles a malformed extension reply as a typed failure");
    assert_eq!(extension.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        committed
            .published
            .reply
            .as_ref()
            .and_then(|reply| Value::try_decode(&reply.result)),
        Some(Value::U32(0)),
    );
}

#[test]
fn native_extension_hostcall_is_rejected_for_proofs_and_over_quota() {
    let (mut proof_config, mut proof_request) = attested_root_fixture(ConsistencyMode::Local, 0x62);
    proof_config.intra_caps = vec![vos::IntraCap::parse("native-peer:member").unwrap()];
    set_workflow_request(
        &mut proof_request,
        "attested_extension_peer_value",
        Msg::new("attested_extension_peer_value"),
    );
    let proof_recorder = Arc::new(RecordingNativeExtension::default());
    let mut proof_service =
        LocalRootTreeService::open(proof_config, SharedCommittedImages::default()).unwrap();
    proof_service.set_native_extension_invoker(proof_recorder.clone());
    let mut producer = CanonicalTestProofProducer {
        proof: canonical_test_proof_manifest(0x63),
        calls: 0,
    };
    assert!(matches!(
        proof_service.invoke_attested(proof_request, &mut producer),
        Err(AttestedRootTreeInvokeError::Root(
            LocalRootTreeInvokeError::Service(ServiceDispatchError::Pvm(
                ServicePvmError::RefineHostRejected(slot),
            )),
        )) if slot == vos::abi::hostcall::NATIVE_EXTENSION_INVOKE as u8,
    ));
    assert!(proof_recorder.calls.lock().unwrap().is_empty());
    assert_eq!(producer.calls, 0);

    let (mut quota_config, mut quota_request) = attested_root_fixture(ConsistencyMode::Local, 0x64);
    quota_config.intra_caps = vec![vos::IntraCap::parse("native-peer:member").unwrap()];
    set_workflow_request(
        &mut quota_request,
        "extension_peer_value_repeatedly",
        Msg::new("extension_peer_value_repeatedly").with(
            "calls",
            vos::service::NATIVE_EXTENSION_MAX_CALLS_PER_REFINE + 1,
        ),
    );
    quota_request.proof_requested = false;
    let quota_recorder = Arc::new(RecordingNativeExtension::default());
    let mut quota_service =
        LocalRootTreeService::open(quota_config, SharedCommittedImages::default()).unwrap();
    quota_service.set_native_extension_invoker(quota_recorder.clone());
    assert!(matches!(
        quota_service.invoke(quota_request),
        Err(LocalRootTreeInvokeError::Service(
            ServiceDispatchError::Pvm(ServicePvmError::RefineHostRejected(slot)),
        )) if slot == vos::abi::hostcall::NATIVE_EXTENSION_INVOKE as u8,
    ));
    assert_eq!(
        quota_recorder.calls.lock().unwrap().len(),
        vos::service::NATIVE_EXTENSION_MAX_CALLS_PER_REFINE as usize,
    );
}

#[test]
fn host_private_device_signer_survives_reopen_without_entering_the_service_image() {
    let (mut config, mut request) = attested_root_fixture(ConsistencyMode::Local, 0x6a);
    let seed = [0xd3; 32];
    let payload = b"vos/test/device-signature/service".to_vec();
    config.device_secret = Some(DeviceSecret::new(seed));
    request.method = "device_signature".into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(
            &Msg::new("device_signature")
                .with("payload", payload.clone())
                .encode(),
        );
        arguments
    };
    request.proof_requested = false;

    let backend = SharedCommittedImages::default();
    let mut service = LocalRootTreeService::open(config.clone(), backend.clone())
        .expect("device signer config opens a Local root");
    let first = decode_device_signature(
        &service
            .invoke(request.clone())
            .expect("physical actor reaches DEVICE_SIGN"),
    );
    assert_eq!(first.len(), 96);
    cipher_clerk::proof::signature::verify(
        &payload,
        &cipher_clerk::crypto::AuthKey(first[..32].try_into().unwrap()),
        &cipher_clerk::proof::Proof {
            mode: cipher_clerk::proof::Mode::Signature,
            bytes: first[32..].to_vec(),
        },
    )
    .expect("the public actor result is a valid cipher-clerk signature");
    let image = backend.0.lock().unwrap().clone().expect("committed image");
    assert!(
        !image.windows(seed.len()).any(|window| window == seed),
        "the raw device seed must not enter the recoverable service image",
    );
    drop(service);

    request.invocation = InvocationId([0x6b; 32]);
    request.logical_timeslot += 1;
    let mut reopened = LocalRootTreeService::open(config, backend)
        .expect("the root reopens with its host-private seed");
    let second = decode_device_signature(
        &reopened
            .invoke(request)
            .expect("reopened root still reaches DEVICE_SIGN"),
    );
    assert_eq!(
        second, first,
        "the domain-separated deterministic nonce makes exact re-execution stable",
    );
    cipher_clerk::proof::signature::verify(
        &payload,
        &cipher_clerk::crypto::AuthKey(second[..32].try_into().unwrap()),
        &cipher_clerk::proof::Proof {
            mode: cipher_clerk::proof::Mode::Signature,
            bytes: second[32..].to_vec(),
        },
    )
    .expect("reopened signer retains the same public identity");
}

#[test]
fn raft_device_signing_replays_only_the_public_result() {
    let (mut config, mut request) = attested_root_fixture(ConsistencyMode::Raft, 0x6c);
    let seed = [0xe7; 32];
    let payload = b"vos/test/raft-device-signature/service".to_vec();
    config.device_secret = Some(DeviceSecret::new(seed));
    request.method = "device_signature".into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(
            &Msg::new("device_signature")
                .with("payload", payload.clone())
                .encode(),
        );
        arguments
    };
    request.proof_requested = false;

    let directory = std::env::temp_dir().join(format!(
        "vos-device-signer-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let backend = SharedCommittedImages::default();
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service = LocalRootTreeService::open_raft(config.clone(), backend, log)
        .expect("single-voter Raft root installs with the host signer");
    let signature = decode_device_signature(
        &service
            .invoke(request)
            .expect("Raft Refine commits the public signature"),
    );
    cipher_clerk::proof::signature::verify(
        &payload,
        &cipher_clerk::crypto::AuthKey(signature[..32].try_into().unwrap()),
        &cipher_clerk::proof::Proof {
            mode: cipher_clerk::proof::Mode::Signature,
            bytes: signature[32..].to_vec(),
        },
    )
    .unwrap();
    let backend = service.into_backend();
    let log_bytes = std::fs::read(&log_path).unwrap();
    assert!(
        !log_bytes.windows(seed.len()).any(|window| window == seed),
        "the device seed must not enter ordered Raft entries",
    );

    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    LocalRootTreeService::open_raft(config, backend, log)
        .expect("Raft recovery reconstructs the signer only from host config");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn device_signing_is_rejected_from_unreproducible_attested_traces() {
    let (mut config, mut request) = attested_root_fixture(ConsistencyMode::Local, 0x6d);
    config.device_secret = Some(DeviceSecret::new([0xb4; 32]));
    request.method = "attested_device_signature".into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(
            &Msg::new("attested_device_signature")
                .with("payload", b"not-a-proof-oracle".to_vec())
                .encode(),
        );
        arguments
    };
    let mut service = LocalRootTreeService::open(config, SharedCommittedImages::default())
        .expect("attested policy installs independently of invocation");
    let mut producer = CanonicalTestProofProducer {
        proof: canonical_test_proof_manifest(0x6e),
        calls: 0,
    };
    assert!(matches!(
        service.invoke_attested(request, &mut producer),
        Err(AttestedRootTreeInvokeError::Root(
            LocalRootTreeInvokeError::Service(ServiceDispatchError::Pvm(
                ServicePvmError::RefineHostRejected(slot),
            )),
        )) if slot == vos::abi::hostcall::DEVICE_SIGN as u8,
    ));
    assert_eq!(
        producer.calls, 0,
        "the runtime refuses the trace before invoking a proof producer",
    );
}

#[test]
fn device_signing_bounds_payload_and_host_work_per_refine_slice() {
    fn assert_signer_rejected(
        result: Result<vos::service::CommittedRootTreeSlice, LocalRootTreeInvokeError>,
    ) {
        assert!(matches!(
            result,
            Err(LocalRootTreeInvokeError::Service(
                ServiceDispatchError::Pvm(ServicePvmError::RefineHostRejected(slot)),
            )) if slot == vos::abi::hostcall::DEVICE_SIGN as u8,
        ));
    }

    let (mut config, mut request) = attested_root_fixture(ConsistencyMode::Local, 0x6f);
    config.device_secret = Some(DeviceSecret::new([0xc5; 32]));
    request.method = "device_signature".into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(
            &Msg::new("device_signature")
                .with(
                    "payload",
                    vec![0x41u8; vos::service::DEVICE_SIGN_MAX_PAYLOAD_BYTES + 1],
                )
                .encode(),
        );
        arguments
    };
    request.proof_requested = false;
    let mut oversized =
        LocalRootTreeService::open(config.clone(), SharedCommittedImages::default())
            .expect("device signer root opens");
    assert_signer_rejected(oversized.invoke(request.clone()));

    request.invocation = InvocationId([0x70; 32]);
    request.method = "device_sign_repeatedly".into();
    request.arguments = {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(
            &Msg::new("device_sign_repeatedly")
                .with("calls", vos::service::DEVICE_SIGN_MAX_CALLS_PER_REFINE + 1)
                .encode(),
        );
        arguments
    };
    let mut overquota =
        LocalRootTreeService::open(config, SharedCommittedImages::default()).unwrap();
    assert_signer_rejected(overquota.invoke(request));
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

impl ProductionTrust for TestProductionTrust {
    fn policy_id(&self) -> Hash {
        self.policy
    }

    fn logical_timeslot(&self) -> Option<u64> {
        Some(self.slot.load(Ordering::Relaxed))
    }

    fn verify_logical_timeslot(&self, logical_timeslot: u64) -> ProductionTrustDecision {
        if !self.allow {
            ProductionTrustDecision::Denied
        } else if logical_timeslot <= self.slot.load(Ordering::Relaxed) {
            ProductionTrustDecision::Authorized
        } else {
            ProductionTrustDecision::Denied
        }
    }

    fn verify_proof(
        &self,
        _request: &ProofVerificationRequest,
        _proof: &[u8],
    ) -> ProductionTrustDecision {
        if self.allow {
            ProductionTrustDecision::Authorized
        } else {
            ProductionTrustDecision::Denied
        }
    }

    fn verify_install(&self, _genesis: &ServiceGenesis) -> ProductionTrustDecision {
        if self.allow {
            ProductionTrustDecision::Authorized
        } else {
            ProductionTrustDecision::Denied
        }
    }

    fn verify_upgrade(&self, _upgrade: &ActorUpgrade) -> ProductionTrustDecision {
        if self.allow {
            ProductionTrustDecision::Authorized
        } else {
            ProductionTrustDecision::Denied
        }
    }

    fn verify_role_credential(
        &self,
        _request: &RoleCredentialVerificationRequest,
    ) -> ProductionTrustDecision {
        if self.allow {
            ProductionTrustDecision::Authorized
        } else {
            ProductionTrustDecision::Denied
        }
    }

    fn verify_receipt(&self, _request: &ReceiptVerificationRequest) -> ProductionTrustDecision {
        if self.allow {
            ProductionTrustDecision::Authorized
        } else {
            ProductionTrustDecision::Denied
        }
    }
}

#[test]
fn production_root_requires_the_same_durable_trust_policy_after_restart() {
    let (config, mut request) = attested_root_fixture(ConsistencyMode::Local, 0x39);
    let backend = SharedCommittedImages::default();
    let trust = Arc::new(TestProductionTrust::new(0x81, 77, true));
    let mut service =
        LocalRootTreeService::open_production(config.clone(), backend.clone(), trust.clone())
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
        Err(LocalRootTreeInvokeError::Service(
            ServiceDispatchError::Pvm(ServicePvmError::AccumulateHostRejected(slot)),
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
        Err(LocalRootTreeInvokeError::Service(
            ServiceDispatchError::Pvm(ServicePvmError::AccumulateHostRejected(slot)),
        )) if slot == vos::abi::hostcall::ACCUMULATION_TIMESLOT as u8,
    ));
    trust.slot.store(77, Ordering::Relaxed);
    drop(service);

    assert!(matches!(
        LocalRootTreeService::open(config.clone(), backend.clone()),
        Err(LocalRootTreeOpenError::ProductionTrust(
            ProductionTrustError::TrustRequired,
        )),
    ));
    assert!(matches!(
        LocalRootTreeService::open_production(
            config.clone(),
            backend.clone(),
            Arc::new(TestProductionTrust::new(0x82, 77, true)),
        ),
        Err(LocalRootTreeOpenError::ProductionTrust(
            ProductionTrustError::PolicyMismatch,
        )),
    ));
    let reopened = LocalRootTreeService::open_production(config, backend, trust)
        .expect("the identical production policy reopens its sealed image");
    assert_eq!(
        reopened.production_trust_policy_id(),
        Some(Hash([0x81; 32]))
    );

    let (denied_config, _) = attested_root_fixture(ConsistencyMode::Local, 0x38);
    assert!(matches!(
        LocalRootTreeService::open_production(
            denied_config,
            SharedCommittedImages::default(),
            Arc::new(TestProductionTrust::new(0x83, 78, false)),
        ),
        Err(LocalRootTreeOpenError::InstallRejected(
            AccumulationRejection::Unauthorized,
        )),
    ));
}

#[test]
fn raft_replay_binds_production_trust_and_host_machine_before_genesis() {
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial_state = BlobRef::of_bytes(&initial_bytes);
    let actor = ActorId([0x84; 32]);
    let service = ServiceIdentity {
        space: vos::service::SpaceId([0x85; 32]),
        root_service: RootServiceId([0x86; 32]),
        deployment: DeploymentId([0x87; 32]),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: service.clone(),
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
            actor,
            name: "root".into(),
            parent: None,
            producer: ProducerId([0x88; 32]),
            deployment: service.deployment,
            program: actor_program,
            initial_state: initial_state.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([0x89; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x8a; 32]),
            authenticator: vec![0x8b],
        },
    };
    let programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let blobs = vec![ImportedBlob {
        reference: initial_state,
        bytes: initial_bytes,
    }];
    let shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let make_replica = |policy: u8, leader: bool| {
        let mut host = MemoryServiceStore::default();
        host.install_production_trust(Arc::new(TestProductionTrust::new(policy, 20, true)))
            .unwrap();
        ReplicatedServiceRuntime::new(
            ServiceRuntime::new(
                CANONICAL_SERVICE_PVM.to_vec(),
                vos::service::VOS_SERVICE_PROGRAM_ID,
                NoRefineProtocolHost,
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
            .accumulate_with_availability(&AccumulateRequest::Install(genesis), &programs, &blobs,)
            .unwrap()
            .result,
        AccumulationResult::Installed(_),
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
        Err(ReplicatedServiceError::InvalidCommittedLog),
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

    shared.lock().unwrap().entries[0].host_state_machine = None;
    let mut incompatible_host_follower = make_replica(0x91, false);
    assert!(matches!(
        incompatible_host_follower.catch_up(),
        Err(ReplicatedServiceError::InvalidCommittedLog),
    ));
    assert_eq!(
        incompatible_host_follower
            .log_mut()
            .applied_index()
            .unwrap(),
        0
    );
    assert!(
        incompatible_host_follower
            .service()
            .accumulate_host()
            .header()
            .unwrap()
            .is_none(),
        "a voter must reject an entry from another host state machine before guest mutation",
    );
}

#[test]
fn node_raft_registration_installs_production_trust_before_replay_and_promotion() {
    let (config, request) = attested_root_fixture(ConsistencyMode::Raft, 0x93);
    let directory = std::env::temp_dir().join(format!(
        "vos-node-production-trust-{}-{}",
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
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id: [0x94; 32],
        propose_timeout_ms: 2_000,
    };
    let trust = Arc::new(TestProductionTrust::new(0x95, 77, true));
    let proof = canonical_test_proof_manifest(0x96);

    let mut node = VosNode::with_prefix(member);
    node.register_service_raft_root_at_id_production_with_producer(
        "production-attested-root".into(),
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
    let reopened = mismatched.register_service_raft_root_at_id_production(
        "production-attested-root".into(),
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
        Err(vos::node::RaftNodeRegistrationError::Open(
            LocalRootTreeOpenError::ProductionTrust(ProductionTrustError::PolicyMismatch),
        )),
    ));
    assert!(
        mismatched.collect().is_empty(),
        "a mismatched policy never exposes a root route",
    );

    let (denied_config, _) = attested_root_fixture(ConsistencyMode::Raft, 0x98);
    let denied_db = Arc::new(redb::Database::create(directory.join("denied-join.redb")).unwrap());
    let promoted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_ran = promoted.clone();
    let mut denied = VosNode::with_prefix(member);
    let denied_open = denied.register_service_raft_root_at_id_after_local_attach_production(
        "denied-production-joiner".into(),
        denied_config,
        SharedProofCommittedImages::default(),
        denied_db,
        RaftConfig {
            me: member,
            members: vec![member],
            voter_peer_ids: Vec::new(),
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0x99; 32],
            propose_timeout_ms: 2_000,
        },
        ServiceId::new(member, 0x3394),
        false,
        Arc::new(TestProductionTrust::new(0x9a, 77, false)),
        move |_, _, _| {
            callback_ran.store(true, Ordering::Relaxed);
            Ok(())
        },
    );
    assert!(matches!(
        denied_open,
        Err(vos::node::RaftNodeRegistrationError::Open(
            LocalRootTreeOpenError::InstallRejected(AccumulationRejection::Unauthorized),
        )),
    ));
    assert!(!promoted.load(Ordering::Relaxed));
    assert!(denied.collect().is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn fresh_production_joiner_must_match_policy_before_voter_promotion() {
    let (config, _) = attested_root_fixture(ConsistencyMode::Raft, 0x9b);
    let leader_key = libp2p::identity::Keypair::generate_ed25519();
    let leader_peer = libp2p::PeerId::from(leader_key.public());
    let leader_prefix = vos::network::derive_node_prefix(&leader_peer);
    let (joiner_key, joiner_peer, joiner_prefix) = loop {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = libp2p::PeerId::from(key.public());
        let prefix = vos::network::derive_node_prefix(&peer);
        if prefix != leader_prefix {
            break (key, peer, prefix);
        }
    };
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let leader_network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: leader_key,
        local_prefix: leader_prefix,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let leader_address = loop {
        if let Some(address) = leader_network.listen_addrs().into_iter().next() {
            break address.with(libp2p::multiaddr::Protocol::P2p(leader_peer));
        }
        assert!(std::time::Instant::now() < deadline, "leader did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    let joiner_network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: joiner_key,
        local_prefix: joiner_prefix,
        listen: vec![listen],
        bootstrap: vec![leader_address],
        auto_dial_mdns: false,
    });

    let directory = std::env::temp_dir().join(format!(
        "vos-fresh-production-policy-join-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let replication_id = [0x9c; 32];
    let route = ServiceId::new(leader_prefix, 0x3395);

    let mut leader = VosNode::with_prefix(leader_prefix);
    let registry_pvm =
        vos_pvm_compiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
            .expect("the bundled registry transpiles");
    install_test_voter_registry(
        &mut leader,
        registry_pvm.clone(),
        &[
            (leader_prefix, leader_peer.to_bytes()),
            (joiner_prefix, joiner_peer.to_bytes()),
        ],
    );
    leader.attach_network(leader_network);
    let leader_network = leader.network().unwrap();
    leader
        .register_service_raft_root_at_id_production(
            "policy-bound-leader".into(),
            config.clone(),
            FileCommittedImageStore::new(directory.join("leader.service")),
            Arc::new(redb::Database::create(directory.join("leader.redb")).unwrap()),
            RaftConfig {
                me: leader_prefix,
                members: vec![leader_prefix],
                voter_peer_ids: Vec::new(),
                election_timeout_ms: (10, 30),
                heartbeat_interval_ms: 5,
                replication_id,
                propose_timeout_ms: 2_000,
            },
            route,
            true,
            Arc::new(TestProductionTrust::new(0x9d, 77, true)),
        )
        .expect("the production leader seals its policy before serving joins");
    let leader_shutdown = leader.shutdown_handle();
    let leader_runner = std::thread::spawn(move || {
        leader.run_forever();
        leader.collect()
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while (joiner_network.peer_for_prefix(leader_prefix).is_none()
        || leader_network.peer_for_prefix(joiner_prefix).is_none())
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(joiner_network.peer_for_prefix(leader_prefix).is_some());
    assert!(leader_network.peer_for_prefix(joiner_prefix).is_some());

    let mut joiner = VosNode::with_prefix(joiner_prefix);
    install_test_voter_registry(
        &mut joiner,
        registry_pvm,
        &[
            (leader_prefix, leader_peer.to_bytes()),
            (joiner_prefix, joiner_peer.to_bytes()),
        ],
    );
    joiner.attach_network(joiner_network);
    let joiner_network = joiner.network().unwrap();
    let joiner_route = ServiceId::new(joiner_prefix, 0x3395);
    let promotion_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_finished = promotion_finished.clone();
    joiner
        .register_service_raft_root_at_id_after_local_attach_production(
            "policy-mismatched-joiner".into(),
            config,
            FileCommittedImageStore::new(directory.join("joiner.service")),
            Arc::new(redb::Database::create(directory.join("joiner.redb")).unwrap()),
            RaftConfig {
                me: joiner_prefix,
                members: vec![leader_prefix],
                voter_peer_ids: Vec::new(),
                election_timeout_ms: (30_000, 40_000),
                heartbeat_interval_ms: 20,
                replication_id,
                propose_timeout_ms: 2_000,
            },
            joiner_route,
            true,
            Arc::new(TestProductionTrust::new(0x9e, 77, true)),
            move |_, _, policy| {
                let pending_result = leader_network
                    .send_raft_join_req_with_policy(
                        joiner_peer,
                        replication_id,
                        leader_prefix,
                        None,
                    )
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|error| error.to_string())?;
                if pending_result != vos::network::RaftJoinResult::PolicyMismatch {
                    return Err(format!(
                        "pending production replica admitted a policy-less join: {pending_result:?}"
                    ));
                }
                let result = joiner_network
                    .send_raft_join_req_with_policy(
                        leader_peer,
                        replication_id,
                        joiner_prefix,
                        Some(policy.into()),
                    )
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|error| error.to_string())?;
                callback_finished.store(true, Ordering::Relaxed);
                match result {
                    vos::network::RaftJoinResult::PolicyMismatch => {
                        Err("production policy mismatch".into())
                    }
                    other => Err(format!("unexpected join result: {other:?}")),
                }
            },
        )
        .expect("the fresh follower is prepared without exposing a route");
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while !promotion_finished.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(promotion_finished.load(Ordering::Relaxed));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while joiner.has_agent(joiner_route) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!joiner.has_agent(joiner_route));
    let status = joiner
        .network()
        .unwrap()
        .send_raft_status_req(leader_peer, replication_id)
        .recv_timeout(Duration::from_secs(5))
        .expect("leader status remains available");
    assert_eq!(status.members, vec![leader_prefix]);

    leader_shutdown.store(true, Ordering::Relaxed);
    assert!(leader_runner.join().unwrap().iter().all(AgentResult::is_ok));
    assert!(joiner.collect().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn promoted_voter_keeps_raft_handler_while_application_catch_up_retries() {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = libp2p::PeerId::from(key.public());
    let member = vos::network::derive_node_prefix(&peer);
    let other_member = if member == u16::MAX {
        member - 1
    } else {
        member + 1
    };
    let replication_id = [0x9f; 32];
    let route = ServiceId::new(member, 0x3396);
    let network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key,
        local_prefix: member,
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let directory = std::env::temp_dir().join(format!(
        "vos-promoted-catch-up-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let mut node = VosNode::with_prefix(member);
    node.attach_network(network);
    let promotion_committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_committed = promotion_committed.clone();
    node.register_service_raft_root_at_id_after_local_attach_production(
        "promoted-recovering-voter".into(),
        attested_root_fixture(ConsistencyMode::Raft, 0xa0).0,
        FileCommittedImageStore::new(directory.join("service.image")),
        Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap()),
        RaftConfig {
            me: member,
            members: vec![other_member],
            voter_peer_ids: Vec::new(),
            election_timeout_ms: (30_000, 40_000),
            heartbeat_interval_ms: 20,
            replication_id,
            propose_timeout_ms: 2_000,
        },
        route,
        true,
        Arc::new(TestProductionTrust::new(0xa1, 77, true)),
        move |_, _, _| {
            // Returning success is the callback contract that final
            // membership has committed. This fresh follower deliberately has
            // no application genesis yet, so its first catch-up cannot make
            // the root publishable.
            callback_committed.store(true, Ordering::Release);
            Ok(())
        },
    )
    .expect("the promoted follower is retained privately while catching up");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !promotion_committed.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(promotion_committed.load(Ordering::Acquire));
    std::thread::sleep(Duration::from_millis(250));
    assert!(
        node.network()
            .unwrap()
            .local_raft_status(&replication_id)
            .is_some(),
        "a committed voter must keep serving Raft while application catch-up retries",
    );
    assert!(
        node.has_agent(route),
        "the route remains reserved until the promoted root is publishable",
    );

    assert!(node.collect().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn persisted_voter_keeps_raft_handler_while_service_open_retries() {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = libp2p::PeerId::from(key.public());
    let member = vos::network::derive_node_prefix(&peer);
    let replication_id = [0xa2; 32];
    let route = ServiceId::new(member, 0x3397);
    let network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key,
        local_prefix: member,
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let directory = std::env::temp_dir().join(format!(
        "vos-persisted-open-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db = Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap());
    vos::raft::log::seed_active_config(&db, &[member]).unwrap();
    let backend = TransientOpenCommittedImages::default();
    let config = attested_root_fixture(ConsistencyMode::Raft, 0xa3).0;
    let raft_config = RaftConfig {
        me: member,
        members: vec![member],
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id,
        propose_timeout_ms: 2_000,
    };
    let trust = Arc::new(TestProductionTrust::new(0xa4, 77, true));
    let log = RaftAccumulateLog::from_db_arc(db.clone(), raft_config.clone()).unwrap();
    let installed = LocalRootTreeService::open_raft_production(
        config.clone(),
        backend.clone(),
        log,
        trust.clone(),
    )
    .expect("the persisted voter has a policy-bound service image");
    drop(installed);
    backend.fail_loads(3);
    let observer = backend.clone();

    let mut node = VosNode::with_prefix(member);
    node.attach_network(network);
    node.register_service_raft_root_at_id_production(
        "persisted-recovering-voter".into(),
        config,
        backend,
        db,
        raft_config,
        route,
        true,
        trust,
    )
    .expect("a persisted voter remains registered while service open retries");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while observer.load_attempts() < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(observer.load_attempts() >= 2, "service open was retried");
    assert!(
        node.network()
            .unwrap()
            .local_raft_status(&replication_id)
            .is_some(),
        "the persisted voter serves Raft throughout application recovery",
    );
    assert!(
        node.has_agent(route),
        "the recovering root reserves but does not expose its route",
    );

    node.run_until_idle(Duration::from_millis(250));
    assert!(node.collect().iter().all(AgentResult::is_ok));
    assert!(observer.0.lock().unwrap().image.is_some());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn speculative_removal_keeps_persisted_voter_while_recovery_retries() {
    use vos_raft::{ActiveConfigRecord, LogEntry, Meta, Storage, WriteBatch};

    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = libp2p::PeerId::from(key.public());
    let member = vos::network::derive_node_prefix(&peer);
    let survivor = if member == u16::MAX {
        member - 1
    } else {
        member + 1
    };
    let replication_id = [0xa5; 32];
    let route = ServiceId::new(member, 0x3398);
    let network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key,
        local_prefix: member,
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let directory = std::env::temp_dir().join(format!(
        "vos-speculative-removal-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db = Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap());
    vos::raft::log::seed_active_config(&db, &[member, survivor]).unwrap();

    // Persist the committed joint configuration followed by its speculative
    // final removal. Raft must operate against the latest view, but the node
    // must retain the local handler because the committed joint configuration
    // still requires it.
    let mut storage = vos::raft::RedbStorage::open(db.clone()).unwrap();
    vos::block_on(storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::config_change(1, 1, Some(vec![member, survivor]), vec![survivor]),
            LogEntry::config_change(2, 1, None, vec![survivor]),
        ],
        meta: Some(Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 1,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(2),
            current: vec![survivor],
            joint_old: None,
        }),
        ..Default::default()
    }))
    .unwrap();
    drop(storage);
    assert_eq!(vos::raft::RaftMeta::load(&db).unwrap().commit_index, 1);

    let backend = TransientOpenCommittedImages::default();
    backend.fail_loads(1_000);
    let observer = backend.clone();
    let mut node = VosNode::with_prefix(member);
    node.attach_network(network);
    node.register_service_raft_root_at_id_production(
        "speculatively-removed-recovering-voter".into(),
        attested_root_fixture(ConsistencyMode::Raft, 0xa6).0,
        backend,
        db,
        RaftConfig {
            me: member,
            members: vec![member, survivor],
            voter_peer_ids: Vec::new(),
            election_timeout_ms: (30_000, 40_000),
            heartbeat_interval_ms: 20,
            replication_id,
            propose_timeout_ms: 2_000,
        },
        route,
        true,
        Arc::new(TestProductionTrust::new(0xa7, 77, true)),
    )
    .expect("an uncommitted removal cannot tear down a persisted voter");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while observer.load_attempts() < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = node
        .network()
        .unwrap()
        .local_raft_status(&replication_id)
        .expect("the voter required by committed membership remains available");
    assert_eq!(status.commit_index, 1);
    assert_eq!(status.members, vec![survivor]);
    assert!(
        node.has_agent(route),
        "application recovery keeps its private route reservation",
    );

    assert!(node.collect().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn immediate_registration_keeps_speculative_joint_inclusion_private() {
    use vos_raft::{ActiveConfigRecord, LogEntry, Meta, Storage, WriteBatch};

    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = libp2p::PeerId::from(key.public());
    let member = vos::network::derive_node_prefix(&peer);
    let survivor = if member == u16::MAX {
        member - 1
    } else {
        member + 1
    };
    let replication_id = [0xa8; 32];
    let route = ServiceId::new(member, 0x3399);
    let network = vos::network::Network::start(vos::network::NetworkConfig {
        keypair: key,
        local_prefix: member,
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    });
    let directory = std::env::temp_dir().join(format!(
        "vos-speculative-inclusion-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let (config, _) = attested_root_fixture(ConsistencyMode::Raft, 0xa9);
    let actor = config.root_actor;
    let trust = Arc::new(TestProductionTrust::new(0xaa, 77, true));
    let backend = TransientOpenCommittedImages::default();
    let db = Arc::new(redb::Database::create(directory.join("raft.redb")).unwrap());
    vos::raft::log::seed_active_config(&db, &[member]).unwrap();
    let install_raft_config = RaftConfig {
        me: member,
        members: vec![member],
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id,
        propose_timeout_ms: 2_000,
    };
    drop(
        LocalRootTreeService::open_raft_production(
            config.clone(),
            backend.clone(),
            RaftAccumulateLog::from_db_arc(db.clone(), install_raft_config).unwrap(),
            trust.clone(),
        )
        .expect("the application image exists before the modeled restart"),
    );

    let last_index = vos::raft::RaftLog::open(db.clone()).unwrap().last_index();
    let committed_final_index = last_index + 1;
    let speculative_joint_index = committed_final_index + 1;
    let persisted_meta = vos::raft::RaftMeta::load(&db).unwrap();
    let meta = Meta {
        current_term: persisted_meta.current_term,
        voted_for: persisted_meta.voted_for,
        commit_index: committed_final_index,
        snap_last_index: persisted_meta.snap_last_index,
        snap_last_term: persisted_meta.snap_last_term,
    };
    let mut storage = vos::raft::RedbStorage::open(db.clone()).unwrap();
    vos::block_on(storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::config_change(
                committed_final_index,
                meta.current_term,
                None,
                vec![survivor],
            ),
            LogEntry::config_change(
                speculative_joint_index,
                meta.current_term,
                Some(vec![survivor]),
                vec![member, survivor],
            ),
        ],
        meta: Some(meta),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(speculative_joint_index),
            current: vec![member, survivor],
            joint_old: Some(vec![survivor]),
        }),
        ..Default::default()
    }))
    .unwrap();
    drop(storage);

    let mut node = VosNode::with_prefix(member);
    node.attach_network(network);
    node.register_service_raft_root_at_id_production(
        "speculatively-included-recovering-voter".into(),
        config,
        backend,
        db,
        RaftConfig {
            me: member,
            members: vec![survivor],
            voter_peer_ids: Vec::new(),
            election_timeout_ms: (30_000, 40_000),
            heartbeat_interval_ms: 20,
            replication_id,
            propose_timeout_ms: 2_000,
        },
        route,
        true,
        trust,
    )
    .expect("immediate registration keeps speculative inclusion private and recoverable");

    std::thread::sleep(Duration::from_millis(250));
    assert!(node.has_agent(route), "the private route remains reserved");
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("increment").with("amount", 1_u32).encode());
    assert!(
        matches!(
            node.invoke_actor(actor, arguments),
            Err(ClientError::NotFound)
        ),
        "uncommitted joint inclusion must not publish the actor route",
    );
    assert!(node.collect().iter().all(AgentResult::is_ok));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn same_actor_storage_reads_observe_earlier_inline_writes() {
    let (config, template) = attested_root_fixture(ConsistencyMode::Local, 0x3a);
    let mut service =
        LocalRootTreeService::open(config, FailableCommittedImages::default()).unwrap();

    let mut spawn_arguments = vec![vos::value::TAG_DYNAMIC];
    spawn_arguments.extend_from_slice(
        &Msg::new("spawn_child")
            .with("name", "child")
            .with("initial", 0u32)
            .encode(),
    );
    let spawned = service
        .invoke(LocalWorkRequest {
            invocation: InvocationId([0x3b; 32]),
            workflow_step: 0,
            logical_timeslot: 12,
            target: template.target,
            method: "spawn_child".into(),
            arguments: spawn_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([0x3c; 32]),
            workflow_step: 0,
            logical_timeslot: 13,
            target: template.target,
            method: "call_child_storage_twice".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let (config, request) = attested_root_fixture(ConsistencyMode::Local, 0x41);
    let mut service =
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
            .expect("the attested root installs");
    assert!(
        !service
            .admit_ingress(&request)
            .expect("attested ingress is durable before proof production")
    );

    let mut backend = service.into_backend();
    backend.fail_next_proof_commit = true;
    let mut service = LocalRootTreeService::open(config.clone(), backend)
        .expect("queued attested ingress reopens from the durable image");
    let before_invalid_proof = service.store().snapshot();
    assert!(matches!(
        service.invoke_admitted_attested(request.invocation, &mut MismatchedTraceProofProducer),
        Err(AttestedRootTreeInvokeError::InvalidProducedProof)
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
        Err(AttestedRootTreeInvokeError::ProofUnavailable)
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
    let publication = committed.publication.as_ref().unwrap().clone();

    let backend = service.into_backend();
    let mut service = LocalRootTreeService::open(config.clone(), backend)
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
    assert!(!service.acknowledge_publication(&publication).unwrap());
    let backend = service.into_backend();
    let mut service = LocalRootTreeService::open(config, backend)
        .expect("the acknowledged attested result reopens without its publication");
    assert!(service.pending_publications().unwrap().is_empty());
    assert!(
        service
            .store()
            .row(&vos::service::publication_storage_key(committed.input))
            .is_none(),
    );
    let recovered = service
        .invoke_admitted_attested(request.invocation, &mut producer)
        .expect("the exact attested response survives acknowledgement and restart");
    let result = recovered
        .recovered_result
        .expect("attested recovery uses the independent result record");
    assert!(result.attested);
    RootTreeAttestedResult::decode(&result.bytes)
        .expect("the retained caller response is the canonical attested wire");
    assert_eq!(producer.calls, 2);
}

#[test]
fn raft_attested_root_orders_only_the_final_proved_apply() {
    let (config, request) = attested_root_fixture(ConsistencyMode::Raft, 0x51);
    let directory = std::env::temp_dir().join(format!(
        "vos-attested-root-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeService::open_raft(config.clone(), FailableCommittedImages::default(), log)
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

    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(
        log.applied_index().unwrap(),
        3,
        "genesis, ingress admission, and the final proved Apply are the only ordered requests"
    );
    assert!(log.committed_after(3).unwrap().entries.is_empty());
    drop(log);

    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service = LocalRootTreeService::open_raft(config, backend, log)
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
    let task_pvm = vos_pvm_compiler::assembler::Assembler::new().build();
    let (config, binding) = signed_task_dependency_config(task_pvm.clone(), ConsistencyMode::Local);
    let service = LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
        .expect("install root and its signed Task program");
    assert_eq!(
        service.store().program(binding.program),
        Some(task_pvm.as_slice())
    );

    let backend = service.into_backend();
    let reopened = LocalRootTreeService::open(config.clone(), backend)
        .expect("reopen from the committed service image");
    assert_eq!(
        reopened.store().program(binding.program),
        Some(task_pvm.as_slice())
    );

    let mut backend = reopened.into_backend();
    let image = backend.image.take().expect("committed service image");
    let missing_dependency = snapshot_without_program(&image, binding.program);
    MemoryServiceSnapshot::decode(&missing_dependency)
        .expect("the dependency-free snapshot remains canonically encoded");
    backend.image = Some(missing_dependency);
    assert!(matches!(
        LocalRootTreeService::open(config, backend),
        Err(LocalRootTreeOpenError::MissingInstalledProgram(program))
            if program == binding.program
    ));
}

#[test]
fn signed_task_refine_redacts_actor_memory_and_reopens_local_producer_sidecar() {
    let task_elf = tally_elf();
    let (witness_address, witness_capacity) =
        vos::zk::witness_symbol(&task_elf).expect("tally exports its witness window");
    let task_pvm = vos_pvm_compiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyMode::Local,
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
    let request = LocalWorkRequest {
        invocation: InvocationId([0xD7; 32]),
        workflow_step: 0,
        logical_timeslot: 9,
        target: actor,
        method: "run_provable_task".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
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
    let mut service = LocalRootTreeService::open(config.clone(), backend)
        .expect("private ingress rehydrates after a durable reopen");
    let mut divergent = request.clone();
    divergent.method = "different_method".into();
    assert!(matches!(
        service.admit_ingress(&divergent),
        Err(LocalRootTreeInvokeError::Rejected(
            AccumulationRejection::DivergentDuplicate
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
    let mut prepared = LocalWorkScheduler::prepare(service.store(), request.clone()).unwrap();
    prepared.work.private_arguments = Some(BlobRef::of_bytes(&request.arguments));
    let physical = ServicePvm::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
    )
    .unwrap();
    let ordinary = physical
        .refine_actor_tree_with_backend(
            &prepared.work.encode(),
            &prepared.imports,
            TEST_GAS_SCHEDULE.refine,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceRecompiler,
        )
        .expect("recompiler executes signed Task Refine");
    let traced = physical
        .refine_actor_tree_traced(
            &prepared.work.encode(),
            &prepared.imports,
            TEST_GAS_SCHEDULE.refine,
            &NoRefineProtocolHost,
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
        Err(LocalRootTreeInvokeError::ProducerRecordUnavailable)
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
    let mut reopened = LocalRootTreeService::open(config, backend)
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
    let task_pvm = vos_pvm_compiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyMode::Local,
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
    let request = LocalWorkRequest {
        invocation: InvocationId([0xD9; 32]),
        workflow_step: 0,
        logical_timeslot: 10,
        target: actor,
        method: "defer_provable_task".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeService::open(config, FailableCommittedImages::default()).unwrap();
    assert!(matches!(
        service.invoke(request),
        Err(LocalRootTreeInvokeError::Service(ServiceDispatchError::Pvm(
            ServicePvmError::RefineHostRejected(slot)
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
    let task_pvm = vos_pvm_compiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyMode::Local,
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
    let request = LocalWorkRequest {
        invocation: InvocationId([0xDB; 32]),
        workflow_step: 0,
        logical_timeslot: 11,
        target: actor,
        method: "run_provable_task_then_yield".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeService::open(config, FailableCommittedImages::default()).unwrap();
    assert!(matches!(
        service.invoke(request),
        Err(LocalRootTreeInvokeError::Service(ServiceDispatchError::Pvm(
            ServicePvmError::RefineHostRejected(slot)
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
    let task_pvm = vos_pvm_compiler::link_elf(&task_elf).expect("tally Task transpiles");
    let (config, binding) = signed_task_dependency_actor_config(
        &probe_elf(),
        task_pvm,
        witness_address as u32,
        witness_capacity as u32,
        ConsistencyMode::Local,
    );
    let actor = config.root_actor;
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("overproduce_provable_tasks")
            .with("task_hash", binding.task.0.to_vec())
            .encode(),
    );
    let request = LocalWorkRequest {
        invocation: InvocationId([0xDD; 32]),
        workflow_step: 0,
        logical_timeslot: 12,
        target: actor,
        method: "overproduce_provable_tasks".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let mut service =
        LocalRootTreeService::open(config, FailableCommittedImages::default()).unwrap();
    assert!(matches!(
        service.invoke(request),
        Err(LocalRootTreeInvokeError::Service(ServiceDispatchError::Pvm(
            ServicePvmError::RefineHostRejected(slot)
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
    let (config, _) = signed_task_dependency_config(task_pvm.clone(), ConsistencyMode::Raft);
    assert!(config.validate().is_ok());
    let (config, _) = signed_task_dependency_actor_config(
        &crdt_counter_elf(),
        task_pvm,
        0x1_0000,
        4096,
        ConsistencyMode::Crdt,
    );
    assert_eq!(
        config.validate(),
        Err(LocalRootTreeConfigError::ReplicatedPrivateTaskUnsupported)
    );
}

#[test]
fn single_voter_raft_task_ingress_is_private_durable_and_retryable() {
    let task_pvm = vos_pvm_compiler::assembler::Assembler::new().build();
    let (config, _) = signed_task_dependency_config(task_pvm, ConsistencyMode::Raft);
    let actor = config.root_actor;
    let directory = std::env::temp_dir().join(format!(
        "vos-raft-private-ingress-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeService::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .expect("single-voter Raft Task root installs");
    let private_sentinel = [0xE1; 32];
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("start")
            .with("private_sentinel", private_sentinel.to_vec())
            .encode(),
    );
    let request = LocalWorkRequest {
        invocation: InvocationId([0xDE; 32]),
        workflow_step: 0,
        logical_timeslot: 13,
        target: actor,
        method: "start".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
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
        Some(BlobRef::of_bytes(&request.arguments)),
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
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut reopened = LocalRootTreeService::open_raft(config, backend, log)
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
    service: &mut LocalRootTreeService<FailableCommittedImages>,
    actor: ActorId,
    invocation: InvocationId,
    logical_timeslot: u64,
    message: Msg,
) -> LocalWorkRequest {
    let method = message.name.clone();
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&message.encode());
    let origin = Origin::Member(SubjectId([0x63; 32]));
    let mut request = LocalWorkRequest {
        invocation,
        workflow_step: 0,
        logical_timeslot,
        target: actor,
        method: method.clone(),
        arguments: arguments.clone(),
        origin,
        authorization: AuthorizationEvidence::Public,
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
    let private_arguments = BlobRef::of_bytes(&arguments);
    let mut scoped = LocalWorkScheduler::prepare(service.store().local_store(), request.clone())
        .unwrap()
        .work;
    scoped.private_arguments = Some(private_arguments.clone());
    let credential = RoleCredential {
        holder: origin,
        scope: scoped.authorization_scope(),
        space_role: None,
        capability: None,
        actor_role: Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
        authenticator: b"test authority over exact Clerk work scope".to_vec(),
    };
    request.authorization = credential.disclosed_evidence(policy.policy);
    let mut authorized =
        LocalWorkScheduler::prepare(service.store().local_store(), request.clone())
            .unwrap()
            .work;
    authorized.private_arguments = Some(private_arguments);
    let verification = RoleCredentialVerificationRequest::for_work(&authorized)
        .expect("disclosed Clerk operator credential is canonical");
    service
        .store_mut()
        .local_store_mut()
        .allow_role_credential(&verification);
    request
}

fn clerk_status(committed: &vos::service::CommittedRootTreeSlice) -> clerk_ledger::Status {
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

fn physical_operator_request<R, A>(
    service: &mut ServiceRuntime<R, A>,
    actor: ActorId,
    invocation: InvocationId,
    logical_timeslot: u64,
    message: Msg,
    actor_role: Option<u8>,
) -> LocalWorkRequest
where
    R: RefineProtocolHost,
    A: MemoryServiceHost + AccumulateProtocolHost,
{
    let method = message.name.clone();
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&message.encode());
    let origin = Origin::Member(SubjectId([0x79; 32]));
    let mut request = LocalWorkRequest {
        invocation,
        workflow_step: 0,
        logical_timeslot,
        target: actor,
        method: method.clone(),
        arguments,
        origin,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let store = service.accumulate_host().local_store();
    let header = store.header().unwrap().expect("installed service header");
    let descriptor = store
        .state_row(header.service_root, &StateKey::ActorDescriptor(actor))
        .unwrap()
        .and_then(|bytes| ActorGenesis::decode(&bytes).ok())
        .expect("installed actor descriptor");
    let policies = PackageRolePolicies::decode(&descriptor.role_policies)
        .expect("installed role policies decode");
    let policy = policies
        .methods
        .iter()
        .find(|candidate| candidate.method == method)
        .expect("requested method is signed into the package");
    assert_eq!(policy.actor_role, actor_role);
    if actor_role.is_none() {
        assert!(policy.public);
        return request;
    }
    let actor_role = actor_role.expect("checked above");
    let scoped = LocalWorkScheduler::prepare(store, request.clone())
        .unwrap()
        .work;
    let credential = RoleCredential {
        holder: origin,
        scope: scoped.authorization_scope(),
        space_role: None,
        capability: None,
        actor_role: Some(actor_role),
        authenticator: b"physical operator authority over exact work scope".to_vec(),
    };
    request.authorization = credential.disclosed_evidence(policy.policy);
    let authorized = LocalWorkScheduler::prepare(store, request.clone())
        .unwrap()
        .work;
    let verification = RoleCredentialVerificationRequest::for_work(&authorized)
        .expect("physical operator credential is canonical");
    service
        .accumulate_host_mut()
        .local_store_mut()
        .allow_role_credential(&verification);
    request
}

fn invoke_physical_actor<R, A>(
    service: &mut ServiceRuntime<R, A>,
    request: LocalWorkRequest,
) -> PublishedEffects
where
    R: RefineProtocolHost,
    A: MemoryServiceHost + AccumulateProtocolHost,
{
    let mut prepared =
        LocalWorkScheduler::prepare(service.accumulate_host().local_store(), request)
            .expect("physical actor request schedules");
    admit_linear_work(service, &prepared.work);
    let refined = loop {
        match service.refine_actor_tree(&prepared.work, &prepared.imports) {
            Ok(refined) => break refined,
            Err(ServiceDispatchError::Pvm(ServicePvmError::ActorStorageWitnessRequired(
                requests,
            ))) => LocalWorkScheduler::hydrate_actor_storage_rows(
                service.accumulate_host().local_store(),
                &mut prepared,
                &requests,
            )
            .expect("storage witnesses hydrate"),
            Err(error) => panic!("physical actor Refine failed: {error:?}"),
        }
    };
    match service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: prepared.work,
            transition: refined.transition,
            provided_blobs: refined.exported_blobs,
        }))
        .expect("physical actor Accumulate completes")
        .result
    {
        AccumulationResult::Accepted {
            published,
            duplicate: false,
            ..
        } => published,
        other => panic!("physical actor Apply was not accepted: {other:?}"),
    }
}

fn physical_reply_bytes(published: &PublishedEffects) -> Vec<u8> {
    let result = &published
        .reply
        .as_ref()
        .expect("physical handler publishes a reply")
        .result;
    let Value::Bytes(bytes) = Value::try_decode(result).expect("physical reply is a Value") else {
        panic!("physical reply is encoded as Value::Bytes")
    };
    bytes
}

fn attempt_voucher_anchor_from_unbound_actor(
    source: &mut ServiceRuntime<NoRefineProtocolHost, MemoryServiceStore>,
    ledger: &mut ServiceRuntime<NoRefineProtocolHost, MemoryServiceStore>,
    source_actor: ActorId,
    ledger_actor: ActorId,
    transfer_id: [u8; 16],
    amount_commit: [u8; 32],
    invocation: InvocationId,
    source_slot: u64,
    delivery_slot: u64,
    drain_slot: u64,
    resume_slot: u64,
) -> bool {
    let request = physical_operator_request(
        source,
        source_actor,
        invocation,
        source_slot,
        Msg::new("attempt_voucher_anchor")
            .with("target", ledger_actor.0.to_vec())
            .with("transfer_id", transfer_id.to_vec())
            .with("amount_commit", amount_commit.to_vec()),
        None,
    );
    let suspended = invoke_physical_actor(source, request);
    let [message] = suspended.outbox.as_slice() else {
        panic!("unbound actor must suspend on one ledger anchor attempt")
    };
    let call = message.call_id;
    let publication = LocalTransport::pending_publications(source)
        .unwrap()
        .into_iter()
        .find(|publication| {
            publication
                .published
                .outbox
                .iter()
                .any(|row| row.call_id == call)
        })
        .unwrap();
    LocalTransport::deliver(source, ledger, &publication, call, delivery_slot).unwrap();
    assert!(matches!(
        LocalTransport::drain_pending(ledger, drain_slot)
            .unwrap()
            .as_slice(),
        [InboxDrainOutcome::Committed(_)]
    ));
    let reply = LocalTransport::pending_publications(ledger)
        .unwrap()
        .into_iter()
        .find(|publication| {
            publication
                .published
                .reply
                .as_ref()
                .is_some_and(|reply| reply.call_id == call)
        })
        .unwrap();
    let resumed = LocalTransport::resume_reply(ledger, source, &reply, resume_slot).unwrap();
    let result = &resumed
        .published
        .reply
        .as_ref()
        .expect("probe publishes its boolean result")
        .result;
    matches!(Value::try_decode(result), Some(Value::Bool(true)))
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
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([121; 32]),
            root_service: RootServiceId([122; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: ActorId([123; 32]),
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([124; 32]),
            authenticator: vec![125],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let actor = config.root_actor;
    let directory = std::env::temp_dir().join(format!(
        "vos-raft-clerk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeService::open_raft(config.clone(), FailableCommittedImages::default(), log)
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
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut reopened = LocalRootTreeService::open_raft(config, backend, log)
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

#[test]
fn clerk_bridge_issues_once_from_bound_ledger_and_signs_the_closed_window_claim() {
    use cipher_clerk::conventions::{BankCode, Iso4217};
    use cipher_clerk::crypto::{Amount, Blinding, Keypair, Signature};
    use cipher_clerk::ids::{JournalId, TransferId};
    use cipher_clerk::kernel::CreateAccount as CcCreateAccount;
    use cipher_clerk::proof::Proof;
    use cipher_clerk::settlement::SettlementClaim;
    use cipher_clerk::types::{Account, Layer, Transfer};
    use cipher_clerk::viewing_keys::{EncryptedEnvelope, IncomingViewingKey};
    use cipher_clerk::voucher::Voucher;

    let package_signer = libp2p::identity::Keypair::generate_ed25519();
    let (ledger_package, ledger_name) = signed_test_package(&clerk_ledger_elf(), &package_signer);
    let (bridge_package, bridge_name) = signed_test_package(&clerk_bridge_elf(), &package_signer);
    let ledger_actor = ActorId([0x41; 32]);
    let bridge_actor = ActorId([0x42; 32]);
    let ledger_identity = ServiceIdentity {
        space: vos::service::SpaceId([0x43; 32]),
        root_service: RootServiceId([0x44; 32]),
        deployment: ledger_package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let bridge_identity = ServiceIdentity {
        root_service: RootServiceId([0x45; 32]),
        deployment: bridge_package.deployment_id(),
        ..ledger_identity.clone()
    };
    let initial = Vec::new();
    let initial_ref = BlobRef::of_bytes(&initial);

    let mut ledger_store = MemoryServiceStore::default();
    assert_eq!(ledger_store.import_blob(initial.clone()), initial_ref);
    assert_eq!(
        ledger_store.import_program(ledger_package.actor_pvm.clone()),
        ledger_package.manifest.actor_program,
    );
    let mut ledger = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        ledger_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let ledger_install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![external_binding(
            "clerk-bridge",
            bridge_identity.clone(),
            bridge_actor,
            bridge_package.deployment_signature.producer,
            bridge_package.manifest.actor_program,
        )],
        service: ledger_identity.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: ledger_actor,
            name: ledger_name,
            parent: None,
            producer: ledger_package.deployment_signature.producer,
            deployment: ledger_identity.deployment,
            program: ledger_package.manifest.actor_program,
            initial_state: initial_ref.clone(),
            crdt: false,
            role_policies: ledger_package.role_policies.clone(),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x46; 32]),
            authenticator: vec![0x47],
        },
    });
    authorize_install(&mut ledger, &ledger_install);
    assert!(matches!(
        ledger.accumulate(&ledger_install).unwrap().result,
        AccumulationResult::Installed(_)
    ));

    let device_secret = DeviceSecret::new([0x48; 32]);
    let bank_public = device_secret.public_key();
    let mut bridge_store = MemoryServiceStore::default();
    assert_eq!(bridge_store.import_blob(initial), initial_ref);
    assert_eq!(
        bridge_store.import_program(bridge_package.actor_pvm.clone()),
        bridge_package.manifest.actor_program,
    );
    let mut bridge = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        DeviceSignerRefineHost::new(Some(device_secret)),
        bridge_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let bridge_install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![external_binding(
            "clerk-ledger",
            ledger_identity.clone(),
            ledger_actor,
            ledger_package.deployment_signature.producer,
            ledger_package.manifest.actor_program,
        )],
        service: bridge_identity,
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: bridge_actor,
            name: bridge_name,
            parent: None,
            producer: bridge_package.deployment_signature.producer,
            deployment: bridge_package.deployment_id(),
            program: bridge_package.manifest.actor_program,
            initial_state: initial_ref.clone(),
            crdt: false,
            role_policies: bridge_package.role_policies.clone(),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x49; 32]),
            authenticator: vec![0x4a],
        },
    });
    authorize_install(&mut bridge, &bridge_install);
    assert!(matches!(
        bridge.accumulate(&bridge_install).unwrap().result,
        AccumulationResult::Installed(_)
    ));

    let (rogue_package, rogue_name) = signed_test_package(&probe_elf(), &package_signer);
    // Actor IDs are root-local application identities. Deliberately reuse the
    // legitimate bridge's ID under another service to prove the ledger binds
    // both halves of MessageRecord's authenticated source.
    let rogue_actor = bridge_actor;
    let rogue_identity = ServiceIdentity {
        root_service: RootServiceId([0x3b; 32]),
        deployment: rogue_package.deployment_id(),
        ..ledger_identity.clone()
    };
    let mut rogue_store = MemoryServiceStore::default();
    assert_eq!(rogue_store.import_blob(Vec::new()), initial_ref);
    assert_eq!(
        rogue_store.import_program(rogue_package.actor_pvm.clone()),
        rogue_package.manifest.actor_program,
    );
    let mut rogue = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        rogue_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let rogue_install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![external_binding(
            "clerk-ledger",
            ledger_identity.clone(),
            ledger_actor,
            ledger_package.deployment_signature.producer,
            ledger_package.manifest.actor_program,
        )],
        service: rogue_identity,
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: rogue_actor,
            name: rogue_name,
            parent: None,
            producer: rogue_package.deployment_signature.producer,
            deployment: rogue_package.deployment_id(),
            program: rogue_package.manifest.actor_program,
            initial_state: initial_ref,
            crdt: false,
            role_policies: rogue_package.role_policies.clone(),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x3c; 32]),
            authenticator: vec![0x3d],
        },
    });
    authorize_install(&mut rogue, &rogue_install);
    assert!(matches!(
        rogue.accumulate(&rogue_install).unwrap().result,
        AccumulationResult::Installed(_)
    ));

    let ledger_status = |published: &PublishedEffects| {
        vos::rkyv::from_bytes::<clerk_ledger::Status, vos::rkyv::rancor::Error>(
            &physical_reply_bytes(published),
        )
        .unwrap()
    };
    let bridge_status = |published: &PublishedEffects| {
        vos::rkyv::from_bytes::<clerk_bridge::Status, vos::rkyv::rancor::Error>(
            &physical_reply_bytes(published),
        )
        .unwrap()
    };

    let registrar = Keypair::generate();
    let journal = JournalId::random();
    let boot = physical_operator_request(
        &mut ledger,
        ledger_actor,
        InvocationId([0x4b; 32]),
        1,
        Msg::new("bootstrap")
            .with("journal_id", journal.0.to_vec())
            .with("registrar_pubkey", registrar.public.0.to_vec())
            .with("code", 1u32),
        Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
    );
    assert_eq!(
        ledger_status(&invoke_physical_actor(&mut ledger, boot)),
        clerk_ledger::Status::Ok
    );
    let alice_key = Keypair::generate();
    let alice = Account::asset(journal, alice_key.public, Iso4217::USD, BankCode::Checking);
    let pool_key = Keypair::generate();
    let pool = Account::asset(journal, pool_key.public, Iso4217::USD, BankCode::Vault);
    for (ordinal, account) in [alice.clone(), pool.clone()].into_iter().enumerate() {
        let create = CcCreateAccount::signed(account, &registrar.secret);
        let create = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create)
            .unwrap()
            .to_vec();
        let request = physical_operator_request(
            &mut ledger,
            ledger_actor,
            InvocationId([0x4c + ordinal as u8; 32]),
            2 + ordinal as u64,
            Msg::new("create_account")
                .with("create_account_bytes", create)
                .with("batch_seed_timestamp", 10u64 + ordinal as u64),
            Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
        );
        assert_eq!(
            ledger_status(&invoke_physical_actor(&mut ledger, request)),
            clerk_ledger::Status::Ok
        );
    }
    let root_before_request = physical_operator_request(
        &mut ledger,
        ledger_actor,
        InvocationId([0x4e; 32]),
        4,
        Msg::new("state_root"),
        Some(clerk_ledger::ClerkLedgerRole::Member as u8),
    );
    let root_before: [u8; 32] =
        physical_reply_bytes(&invoke_physical_actor(&mut ledger, root_before_request))
            .try_into()
            .unwrap();

    let blinding = Blinding::from_bytes([0x05; 32]).unwrap();
    let amount = Amount::commit(17, &blinding);
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
        value: 17,
        blinding,
    }];
    let openings = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings)
        .unwrap()
        .to_vec();
    let void_openings = openings.clone();
    let apply = physical_operator_request(
        &mut ledger,
        ledger_actor,
        InvocationId([0x4f; 32]),
        5,
        Msg::new("apply_transfer")
            .with("transfer_bytes", transfer_bytes)
            .with("openings_bytes", openings)
            .with("batch_seed_timestamp", 20u64),
        Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
    );
    assert_eq!(
        ledger_status(&invoke_physical_actor(&mut ledger, apply)),
        clerk_ledger::Status::Ok
    );
    let root_after_request = physical_operator_request(
        &mut ledger,
        ledger_actor,
        InvocationId([0x50; 32]),
        6,
        Msg::new("state_root"),
        Some(clerk_ledger::ClerkLedgerRole::Member as u8),
    );
    let root_after: [u8; 32] =
        physical_reply_bytes(&invoke_physical_actor(&mut ledger, root_after_request))
            .try_into()
            .unwrap();
    assert_ne!(root_before, root_after);

    let receiver_ivk = IncomingViewingKey::from_bytes(&[1u8; 32]).unwrap();
    let peer = Keypair::generate();
    let bridge_boot = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x51; 32]),
        1,
        Msg::new("bootstrap").with("ivk_secret", receiver_ivk.to_bytes().to_vec()),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    assert_eq!(
        bridge_status(&invoke_physical_actor(&mut bridge, bridge_boot)),
        clerk_bridge::Status::Ok
    );
    let bind = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x52; 32]),
        2,
        Msg::new("bind_device_signer").with("public_key", bank_public.to_vec()),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    assert_eq!(
        bridge_status(&invoke_physical_actor(&mut bridge, bind)),
        clerk_bridge::Status::Ok
    );
    let register = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x53; 32]),
        3,
        Msg::new("register_peer")
            .with("peer_name", b"bank-b".to_vec())
            .with("clerk_pubkey", peer.public.0.to_vec())
            .with("node_prefix", 0u32),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    assert_eq!(
        bridge_status(&invoke_physical_actor(&mut bridge, register)),
        clerk_bridge::Status::Ok
    );

    let voucher_template = Voucher {
        amount_commit: amount,
        envelope: EncryptedEnvelope::seal(17, &blinding, &receiver_ivk.public()).unwrap(),
        state_root_before: root_before,
        state_root_after: root_after,
        proof: Proof::default(),
        signature: Signature::ZERO,
    }
    .to_bytes();
    let issue_message = Msg::new("issue_voucher")
        .with("transfer_id", transfer_id.to_vec())
        .with("peer_name", b"bank-b".to_vec())
        .with("voucher_template", voucher_template.clone());

    assert!(
        !attempt_voucher_anchor_from_unbound_actor(
            &mut rogue,
            &mut ledger,
            rogue_actor,
            ledger_actor,
            transfer_id,
            amount.0,
            InvocationId([0x3e; 32]),
            1,
            7,
            8,
            2,
        ),
        "the bridge actor id under another root cannot create the lock",
    );

    let issue = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x54; 32]),
        4,
        issue_message.clone(),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    let suspended = invoke_physical_actor(&mut bridge, issue);
    let [message] = suspended.outbox.as_slice() else {
        panic!("voucher issuance must suspend on one authenticated ledger query")
    };
    let call = message.call_id;
    let bridge_publication = LocalTransport::pending_publications(&bridge)
        .unwrap()
        .into_iter()
        .find(|publication| {
            publication
                .published
                .outbox
                .iter()
                .any(|row| row.call_id == call)
        })
        .unwrap();
    LocalTransport::deliver(&bridge, &mut ledger, &bridge_publication, call, 10).unwrap();
    let drained = LocalTransport::drain_pending(&mut ledger, 11).unwrap();
    assert!(matches!(
        drained.as_slice(),
        [InboxDrainOutcome::Committed(_)]
    ));

    let build_void = || {
        let void = Transfer::builder(journal)
            .voiding(TransferId(transfer_id))
            .credit(&alice, Layer::Settled, amount)
            .debit(&pool, Layer::Settled, amount)
            .signed_with(&[(&pool, &pool_key.secret)]);
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&void)
            .unwrap()
            .to_vec()
    };

    // The ledger has committed the anchor reply, but the bridge has not
    // resumed or signed yet. The anchor itself is the durable linearization
    // point: a reversal in this window must already be rejected.
    let void_while_bridge_suspended = physical_operator_request(
        &mut ledger,
        ledger_actor,
        InvocationId([0x59; 32]),
        12,
        Msg::new("apply_transfer")
            .with("transfer_bytes", build_void())
            .with("openings_bytes", void_openings.clone())
            .with("batch_seed_timestamp", 21u64),
        Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
    );
    assert_eq!(
        ledger_status(&invoke_physical_actor(
            &mut ledger,
            void_while_bridge_suspended,
        )),
        clerk_ledger::Status::VoucherLocked,
    );

    let ledger_publication = LocalTransport::pending_publications(&ledger)
        .unwrap()
        .into_iter()
        .find(|publication| {
            publication
                .published
                .reply
                .as_ref()
                .is_some_and(|r| r.call_id == call)
        })
        .unwrap();
    let resumed =
        LocalTransport::resume_reply(&ledger, &mut bridge, &ledger_publication, 12).unwrap();
    let issued =
        vos::rkyv::from_bytes::<clerk_bridge::IssueVoucherReply, vos::rkyv::rancor::Error>(
            &physical_reply_bytes(&resumed.published),
        )
        .unwrap();
    assert_eq!(issued.status, clerk_bridge::Status::Ok);
    assert_eq!(issued.window, 0);
    let voucher = Voucher::from_bytes(&issued.voucher).unwrap();
    assert_eq!(voucher.amount_commit, amount);
    assert_eq!(voucher.state_root_before, root_before);
    assert_eq!(voucher.state_root_after, root_after);
    voucher
        .verify_signature(&cipher_clerk::crypto::AuthKey(bank_public))
        .unwrap();
    assert_eq!(issued.redemption_key, voucher.redemption_key());

    assert!(
        !attempt_voucher_anchor_from_unbound_actor(
            &mut rogue,
            &mut ledger,
            rogue_actor,
            ledger_actor,
            transfer_id,
            amount.0,
            InvocationId([0x3f; 32]),
            3,
            13,
            14,
            4,
        ),
        "the bridge actor id under another root cannot reuse the committed lock",
    );

    // Signing and caching do not weaken the lock. A later independent void
    // remains rejected, so the redeemable voucher cannot outlive its settled
    // backing transfer.
    let void_after_issue = physical_operator_request(
        &mut ledger,
        ledger_actor,
        InvocationId([0x5a; 32]),
        15,
        Msg::new("apply_transfer")
            .with("transfer_bytes", build_void())
            .with("openings_bytes", void_openings)
            .with("batch_seed_timestamp", 22u64),
        Some(clerk_ledger::ClerkLedgerRole::Operator as u8),
    );
    assert_eq!(
        ledger_status(&invoke_physical_actor(&mut ledger, void_after_issue)),
        clerk_ledger::Status::VoucherLocked,
    );

    // A fresh invocation after response loss reuses the actor-owned issuance
    // record. It must not query the ledger or add the amount twice.
    let retry = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x55; 32]),
        13,
        issue_message,
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    let retried = invoke_physical_actor(&mut bridge, retry);
    assert!(retried.outbox.is_empty());
    let retried =
        vos::rkyv::from_bytes::<clerk_bridge::IssueVoucherReply, vos::rkyv::rancor::Error>(
            &physical_reply_bytes(&retried),
        )
        .unwrap();
    assert_eq!(retried, issued);

    // Reusing the transfer id with any different request is a terminal
    // conflict, not a second ledger query or another issuer accumulator
    // update.
    let mut divergent_template = voucher_template;
    divergent_template.push(0xff);
    let divergent = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x56; 32]),
        16,
        Msg::new("issue_voucher")
            .with("transfer_id", transfer_id.to_vec())
            .with("peer_name", b"bank-b".to_vec())
            .with("voucher_template", divergent_template),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    let divergent = invoke_physical_actor(&mut bridge, divergent);
    assert!(divergent.outbox.is_empty());
    let divergent = vos::rkyv::from_bytes::<
        clerk_bridge::IssueVoucherReply,
        vos::rkyv::rancor::Error,
    >(&physical_reply_bytes(&divergent))
    .unwrap();
    assert_eq!(divergent.status, clerk_bridge::Status::IssuanceConflict);

    let rotate = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x57; 32]),
        17,
        Msg::new("window_rotate").with("peer_name", b"bank-b".to_vec()),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    assert_eq!(
        bridge_status(&invoke_physical_actor(&mut bridge, rotate)),
        clerk_bridge::Status::Ok
    );
    let sign = physical_operator_request(
        &mut bridge,
        bridge_actor,
        InvocationId([0x58; 32]),
        18,
        Msg::new("sign_claim")
            .with("peer_name", b"bank-b".to_vec())
            .with("currency", clerk_bridge::SETTLEMENT_CURRENCY)
            .with("window", 0u64),
        Some(clerk_bridge::ClerkBridgeRole::Operator as u8),
    );
    let signed = invoke_physical_actor(&mut bridge, sign);
    let signed = vos::rkyv::from_bytes::<clerk_bridge::SignClaimReply, vos::rkyv::rancor::Error>(
        &physical_reply_bytes(&signed),
    )
    .unwrap();
    assert_eq!(signed.status, clerk_bridge::Status::Ok);
    let claim = SettlementClaim::from_bytes(&signed.claim).unwrap();
    assert_eq!(claim.claimant_clerk.0, bank_public);
    assert_eq!(claim.peer_clerk, peer.public);
    assert_eq!(claim.currency, clerk_bridge::SETTLEMENT_CURRENCY);
    assert_eq!((claim.window_start, claim.window_end), (0, 1));
    assert_eq!(claim.net_flow, amount, "issuance contributes exactly once");
    claim.verify_signature().unwrap();
}

fn signed_task_dependency_config(
    task_pvm: Vec<u8>,
    consistency: ConsistencyMode,
) -> (LocalRootTreeConfig, TaskDependency) {
    signed_task_dependency_actor_config(&greeter_elf(), task_pvm, 0x1_0000, 4096, consistency)
}

fn signed_task_dependency_actor_config(
    actor_elf: &[u8],
    task_pvm: Vec<u8>,
    witness_address: u32,
    witness_capacity: u32,
    consistency: ConsistencyMode,
) -> (LocalRootTreeConfig, TaskDependency) {
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (mut package, actor_name) = signed_test_package(actor_elf, &signer);
    let binding = TaskDependency {
        task: Hash(vos::provable::task_blob_hash(&task_pvm)),
        program: ProgramId::of_pvm(&task_pvm),
        witness_address,
        witness_capacity,
    };
    package.task_dependencies = vec![PackageTaskDependency {
        binding: binding.clone(),
        pvm: task_pvm.clone(),
    }];
    let mut policies = PackageRolePolicies::decode(&package.role_policies).unwrap();
    policies.task_dependencies = vec![binding.clone()];
    package.role_policies = policies.encode();
    package.manifest.role_policies_hash = artifact_hash(b"role-policies", &package.role_policies);
    package.manifest.task_dependencies_hash =
        vos::service::task_dependencies_hash(&package.task_dependencies);
    package.deployment_signature.signature = signer
        .sign(&package.signing_message())
        .expect("sign package carrying the Task dependency");
    package.validate().expect("Task package is canonical");

    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([121; 32]),
            root_service: RootServiceId([122; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: ActorId([123; 32]),
        actor_name,
        consistency,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([124; 32]),
            authenticator: vec![125],
        },
        device_secret: None,
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

    let mut position = 4 + 32 + 8;
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
    let identity = ServiceIdentity {
        space: vos::service::SpaceId([91; 32]),
        root_service: RootServiceId([92; 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let actor = ActorId([93; 32]);
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: identity,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([94; 32]),
            authenticator: vec![95],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let mut replicated_config = config.clone();
    replicated_config.consistency = ConsistencyMode::Raft;
    assert!(replicated_config.validate().is_ok());
    assert!(matches!(
        LocalRootTreeService::open(replicated_config, FailableCommittedImages::default()),
        Err(vos::service::LocalRootTreeOpenError::InvalidConfig(
            LocalRootTreeConfigError::ReplicationDriverRequired
        ))
    ));
    let mut forged_config = config.clone();
    forged_config.package.deployment_signature.signature[0] ^= 0x80;
    assert_eq!(
        forged_config.validate(),
        Err(LocalRootTreeConfigError::InvalidPackageSignature),
        "installation authority must be cryptographically authenticated"
    );

    let mut wrong_gas_schedule = config.clone();
    wrong_gas_schedule.service.gas_schedule.accumulate -= 1;
    assert_eq!(
        wrong_gas_schedule.validate(),
        Err(LocalRootTreeConfigError::WrongGasSchedule),
        "the declared service identity must match the executing host limits"
    );

    let mut invalid_layout = config.clone();
    let parsed = vos_pvm::program::parse_blob(&invalid_layout.package.actor_pvm)
        .expect("canonical actor PVM parses");
    let mut caps = parsed.caps.clone();
    caps.push(vos_pvm::program::CapManifestEntry {
        cap_index: vos::service::ACTOR_CALLABLE_BASE_SLOT,
        cap_type: vos_pvm::program::CapEntryType::Data,
        base_page: 0,
        page_count: 0,
        init_access: vos_pvm::cap::Access::RW,
        data_offset: 0,
        data_len: 0,
    });
    invalid_layout.package.actor_pvm = vos_pvm::program::build_blob(
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
        Err(LocalRootTreeConfigError::InvalidActorProgramLayout),
        "reserved scheduler capabilities must fail before installation"
    );

    let mut service =
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
            .expect("fresh service installs through physical Accumulate");
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let mut invocation = [96; 32];
    invocation[..8].copy_from_slice(b"VOSINGR!");
    let request = LocalWorkRequest {
        invocation: InvocationId(invocation),
        workflow_step: 0,
        logical_timeslot: 1,
        target: actor,
        method: "start".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
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
        Err(LocalRootTreeInvokeError::ProofProducerRequired)
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
    let committed_checkpoint = vos::service::WorkflowCheckpoint::decode(
        &service
            .store()
            .state_row(
                committed_header.service_root,
                &StateKey::Workflow(request.invocation),
            )
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let committed_dedup = vos::service::DedupRecord::decode(
        service
            .store()
            .row(&vos::service::dedup_storage_key(committed_checkpoint.input))
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
    let mut restarted = LocalRootTreeService::open(config.clone(), backend)
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

    let mut divergent = request.clone();
    divergent.arguments.push(0);
    assert!(matches!(
        restarted.invoke(divergent),
        Err(LocalRootTreeInvokeError::DivergentInvocation)
    ));
    assert!(!restarted.acknowledge_publication(&publication).unwrap());

    let backend = restarted.into_backend();
    let mut restarted = LocalRootTreeService::open(config, backend)
        .expect("acknowledged image restores through the same service identity");
    assert!(restarted.pending_publications().unwrap().is_empty());
    assert!(
        restarted
            .store()
            .row(&vos::service::publication_storage_key(first.input))
            .is_none(),
        "transport acknowledgement removes the publication independently of result retention",
    );
    assert_eq!(restarted.store().header().unwrap().unwrap().revision, 1);
    let mut retry = request.clone();
    retry.logical_timeslot = 10_000;
    let recovered = restarted
        .invoke(retry)
        .expect("an acknowledged terminal reply remains recoverable after restart");
    assert!(recovered.duplicate);
    assert_eq!(recovered.published, first.published);
    assert_eq!(recovered.publication, None);
    assert_eq!(
        recovered
            .recovered_result
            .as_ref()
            .map(|result| result.bytes.as_slice()),
        first
            .published
            .reply
            .as_ref()
            .map(|reply| reply.result.as_slice()),
    );
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
}

#[test]
fn canonical_space_authority_authorizes_a_physical_target_and_exact_retry() {
    let actor_elf = space_authority_elf();
    let package_signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &package_signer);
    let authority_actor = ActorId([184; 32]);
    let service = ServiceIdentity {
        space: vos::service::SpaceId([183; 32]),
        root_service: RootServiceId([185; 32]),
        deployment: package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let root = libp2p::identity::Keypair::generate_ed25519();
    let root_peer_id = libp2p::PeerId::from(root.public()).to_bytes();
    let authority_replication_id = [0xa6; 32];
    let initial_state =
        space_authority::initial_state(service.space, root_peer_id, authority_replication_id)
            .expect("the authority genesis pins an Ed25519 space root and replication incarnation");
    let binding = RoleAuthorityBinding {
        service: service.clone(),
        actor: authority_actor,
    };
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service,
        root_actor: authority_actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state,
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([186; 32]),
            authenticator: vec![187],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let mut authority = LocalRootTreeService::open(config, FailableCommittedImages::default())
        .expect("the canonical authority installs through guest Accumulate");

    let holder = Origin::Member(SubjectId([188; 32]));
    let grant = RoleAuthorityMutation::Grant {
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([189; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: authority_actor,
            method: "mutate_role".into(),
            arguments: grant_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        &authority_replication_id,
    );
    let redeem = vos::registry::registry_mutation_signed_bytes(
        &binding.service.space.0,
        "redeem_invite",
        &[&token_pub, &invited_peer_id],
    );
    let redemption = RoleAuthorityInviteRedemption {
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([197; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: authority_actor,
            method: "redeem_invite".into(),
            arguments: redemption_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let second_redeem = vos::registry::registry_mutation_signed_bytes(
        &binding.service.space.0,
        "redeem_invite",
        &[&token_pub, &second_peer_id],
    );
    let second_redemption = RoleAuthorityInviteRedemption {
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([205; 32]),
            workflow_step: 0,
            logical_timeslot: 3,
            target: authority_actor,
            method: "redeem_invite".into(),
            arguments: second_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let invited_claim = vos::service::RoleAuthorizationClaim {
        space: binding.service.space,
        holder: invited_holder,
        role: Some(vos::SpaceRole::Member),
        capability: None,
        audience: ServiceIdentity {
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
        .invoke(LocalWorkRequest {
            invocation: invited_claim.authority_invocation(),
            workflow_step: 0,
            logical_timeslot: 4,
            target: authority_actor,
            method: "authorize_role".into(),
            arguments: invited_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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

    let claim = vos::service::RoleAuthorizationClaim {
        space: binding.service.space,
        holder,
        role: Some(vos::SpaceRole::Member),
        capability: None,
        audience: ServiceIdentity {
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
        .invoke(LocalWorkRequest {
            invocation: claim.authority_invocation(),
            workflow_step: 0,
            logical_timeslot: 5,
            target: authority_actor,
            method: "authorize_role".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let (target_package, target_name) = signed_test_package(&cycle_elf(), &target_signer);
    let target_actor = ActorId([206; 32]);
    let target_identity = ServiceIdentity {
        space: binding.service.space,
        root_service: RootServiceId([207; 32]),
        deployment: target_package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let target_config = LocalRootTreeConfig {
        role_authority: Some(binding.clone()),
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: target_package,
        service: target_identity,
        root_actor: target_actor,
        actor_name: target_name,
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([208; 32]),
            authenticator: vec![209],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut target =
        LocalRootTreeService::open(target_config.clone(), FailableCommittedImages::default())
            .expect("the Local target pins the canonical Raft authority at install");
    let policy = target
        .root_method_policy("member_only")
        .unwrap()
        .expect("the signed package retains its Member policy");
    assert_eq!(policy.space_role, Some(vos::SpaceRole::Member.as_u8()));
    assert!(!policy.public);

    let mut member_arguments = vec![vos::value::TAG_DYNAMIC];
    member_arguments.extend_from_slice(&Msg::new("member_only").encode());
    let provisional = LocalWorkRequest {
        invocation: InvocationId([210; 32]),
        workflow_step: 0,
        logical_timeslot: 6,
        target: target_actor,
        method: "member_only".into(),
        arguments: member_arguments,
        origin: holder,
        authorization: AuthorizationEvidence::Public,
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
        .invoke(LocalWorkRequest {
            invocation: target_claim.authority_invocation(),
            workflow_step: 0,
            logical_timeslot: 6,
            target: authority_actor,
            method: "authorize_role".into(),
            arguments: decision_arguments,
            origin: Origin::System,
            authorization: AuthorizationEvidence::Public,
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
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: authority_actor,
            receipt: target_assertion.receipt.clone(),
        });
    let credential = RoleCredential {
        holder,
        scope: target_claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        capability: None,
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
    let mut target = LocalRootTreeService::open(target_config, target_backend)
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
        Err(LocalRootTreeInvokeError::DivergentInvocation),
    ));
    target
        .store_mut()
        .allow_receipt(&ReceiptVerificationRequest {
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
    let (package, actor_name) = signed_test_package(&crdt_counter_elf(), &signer);
    let actor = ActorId([0xD1; 32]);
    let authority_actor = ActorId([0xD2; 32]);
    let service = ServiceIdentity {
        space: vos::service::SpaceId([0xD3; 32]),
        root_service: RootServiceId([0xD4; 32]),
        deployment: package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let authority = RoleAuthorityBinding {
        service: ServiceIdentity {
            root_service: RootServiceId([0xD5; 32]),
            deployment: DeploymentId([0xD6; 32]),
            ..service.clone()
        },
        actor: authority_actor,
    };
    let config = LocalRootTreeConfig {
        role_authority: Some(authority.clone()),
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        package,
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xD7; 32]),
            authenticator: vec![0xD8],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut source = LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
        .expect("the authority-bound CRDT source installs");
    let policy = source
        .root_method_policy("member_only")
        .unwrap()
        .expect("the CRDT package retains its Member policy");
    assert_eq!(policy.space_role, Some(vos::SpaceRole::Member.as_u8()));

    let holder = Origin::Member(SubjectId([0xD9; 32]));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("member_only").encode());
    let provisional = LocalWorkRequest {
        invocation: InvocationId([0xDA; 32]),
        workflow_step: 0,
        logical_timeslot: 10,
        target: actor,
        method: "member_only".into(),
        arguments,
        origin: holder,
        authorization: AuthorizationEvidence::Public,
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
    let assertion = AccumulatedRoleAssertion {
        receipt: AccumulationReceipt {
            service: authority.service.clone(),
            accepted_transition: Hash([0xDB; 32]),
            reply_commitment: Some(claim.authority_reply(authority_actor).commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([0xDC; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Raft,
        },
        claim: claim.clone(),
    };
    assert!(assertion.matches_authority(&authority));
    let authority_verification = ReceiptVerificationRequest {
        expected_producer: authority_actor,
        receipt: assertion.receipt.clone(),
    };
    source.store_mut().allow_receipt(&authority_verification);
    let mut authorized = provisional.clone();
    authorized.authorization = RoleCredential {
        holder,
        scope: claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        capability: None,
        actor_role: None,
        authenticator: assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let (credential_policy, expected_credential_commitment, credential_bytes) =
        match &authorized.authorization {
            AuthorizationEvidence::Credential {
                policy,
                credential_commitment,
                bytes,
            } => (*policy, *credential_commitment, bytes.clone()),
            _ => unreachable!("the authorized request carries a disclosed credential"),
        };
    let authorization_blob = BlobRef::of_bytes(&credential_bytes);
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
            matches!(operation, WorkflowOperation::Ingress(ingress)
                if ingress.invocation == authorized.invocation
                    && ingress.authorization_blob == Some(authorization_blob.clone())
                    && matches!(&ingress.authorization,
                        AuthorizationEvidence::Credential {
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
    let mut sink = LocalRootTreeService::open(config.clone(), sink_backend.clone())
        .expect("an independent CRDT replica installs without verifier cache state");
    assert!(matches!(
        sink.sync_finalized_crdt(sync.clone()),
        Err(LocalRootTreeInvokeError::Rejected(
            vos::service::AccumulationRejection::ReceiptUnavailable,
        ))
    ));
    for node in &sync.nodes {
        sink.store_mut().allow_receipt(&ReceiptVerificationRequest {
            expected_producer: node
                .change
                .expected_producer()
                .expect("every authorized causal node names its producer"),
            receipt: node.receipt.clone(),
        });
    }
    let mut missing_sink =
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
            .expect("the missing-blob adversary starts from an independent replica");
    for node in &sync.nodes {
        missing_sink
            .store_mut()
            .allow_receipt(&ReceiptVerificationRequest {
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
        Err(LocalRootTreeInvokeError::Rejected(
            vos::service::AccumulationRejection::MissingBlob(hash),
        )) if hash == authorization_blob.hash
    ));
    sink.sync_finalized_crdt(sync)
        .expect("finalized causal receipts transitively authenticate the admitted assertion");
    drop(sink);
    let mut sink = LocalRootTreeService::open(config, sink_backend)
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
        Err(LocalRootTreeInvokeError::DivergentInvocation),
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

    let space = vos::service::SpaceId([211; 32]);
    let authority_actor = ActorId([212; 32]);
    let authority_signer = libp2p::identity::Keypair::generate_ed25519();
    let (authority_package, authority_name) =
        signed_test_package(&space_authority_elf(), &authority_signer);
    let root = libp2p::identity::Keypair::generate_ed25519();
    let replication_id = [213; 32];
    let authority_identity = ServiceIdentity {
        space,
        root_service: RootServiceId([214; 32]),
        deployment: authority_package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let authority_binding = RoleAuthorityBinding {
        service: authority_identity.clone(),
        actor: authority_actor,
    };
    let authority_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: authority_package,
        service: authority_identity,
        root_actor: authority_actor,
        actor_name: authority_name,
        consistency: ConsistencyMode::Raft,
        initial_state: space_authority::initial_state(
            space,
            libp2p::PeerId::from(root.public()).to_bytes(),
            replication_id,
        )
        .unwrap(),
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([215; 32]),
            authenticator: vec![216],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-role-ingress-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let authority_log = RaftAccumulateLog::open(
        &directory.join("authority.redb"),
        RaftConfig {
            me: node_prefix,
            members: vec![node_prefix],
            replication_id,
            ..RaftConfig::default()
        },
    )
    .unwrap();
    let mut authority = LocalRootTreeService::open_raft(
        authority_config,
        FailableCommittedImages::default(),
        authority_log,
    )
    .expect("the single-voter authority installs through its request log");
    let holder = Origin::Member(SubjectId::of_authenticated_peer(&granted_peer.to_bytes()));
    let grant = RoleAuthorityMutation::Grant {
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([217; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: authority_actor,
            method: "mutate_role".into(),
            arguments: grant_arguments,
            origin: Origin::System,
            authorization: AuthorizationEvidence::Public,
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
    let (target_package, target_name) = signed_test_package(&cycle_elf(), &target_signer);
    let target_identity = ServiceIdentity {
        space,
        root_service: RootServiceId([219; 32]),
        deployment: target_package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let target_replication_id = [0xE0; 32];
    let target_log = RaftAccumulateLog::open(
        &directory.join("target.redb"),
        RaftConfig {
            me: node_prefix,
            members: vec![node_prefix],
            replication_id: target_replication_id,
            ..RaftConfig::default()
        },
    )
    .unwrap();
    let target = LocalRootTreeService::open_raft(
        LocalRootTreeConfig {
            role_authority: Some(authority_binding.clone()),
            service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
            service: target_identity.clone(),
            package: target_package,
            root_actor: target_actor,
            actor_name: target_name,
            consistency: ConsistencyMode::Raft,
            initial_state: vec![],
            external_actors: vec![],
            intra_caps: vec![],
            install_authorization: AuthorizationEvidence::SystemCapability {
                capability: SystemCapabilityId([220; 32]),
                authenticator: vec![221],
            },
            device_secret: None,
            refine_gas: TEST_GAS_SCHEDULE.refine,
            accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
        },
        FailableCommittedImages::default(),
        target_log,
    )
    .expect("the Raft target pins the authority identity in guest-owned state");

    let crdt_actor = ActorId([0xE1; 32]);
    let crdt_signer = libp2p::identity::Keypair::generate_ed25519();
    let (crdt_package, crdt_name) = signed_test_package(&crdt_counter_elf(), &crdt_signer);
    let crdt_identity = ServiceIdentity {
        space,
        root_service: RootServiceId([0xE2; 32]),
        deployment: crdt_package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let crdt_config = LocalRootTreeConfig {
        role_authority: Some(authority_binding.clone()),
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: crdt_identity,
        package: crdt_package,
        root_actor: crdt_actor,
        actor_name: crdt_name,
        consistency: ConsistencyMode::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xE3; 32]),
            authenticator: vec![0xE4],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let mut signed_crdt_config = crdt_config.clone();
    signed_crdt_config.device_secret = Some(DeviceSecret::new([0xc7; 32]));
    assert_eq!(
        signed_crdt_config.validate(),
        Err(LocalRootTreeConfigError::CrdtDeviceSignerUnsupported),
        "CRDT cannot depend on a signer that is absent from its causal inputs",
    );
    let crdt_backend = SharedCommittedImages::default();
    let crdt_target = LocalRootTreeService::open(crdt_config.clone(), crdt_backend.clone())
        .expect("the CRDT target pins the same authority identity in guest-owned state");

    let authority_route = ServiceId::new(node_prefix, 0x3a00);
    let target_route = ServiceId::new(node_prefix, 0x3a01);
    let crdt_route = ServiceId::new(node_prefix, 0x3a02);
    let mut node = VosNode::with_prefix(node_prefix);
    let registry_pvm =
        vos_pvm_compiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
            .expect("the bundled registry transpiles for the ungranted peer");
    install_test_voter_registry(&mut node, registry_pvm, &[]);
    node.register_service_root_at_id("space-authority", authority, authority_route, true)
        .unwrap();
    node.register_service_root_at_id("role-target", target, target_route, true)
        .unwrap();
    node.register_service_root_at_id("crdt-role-target", crdt_target, crdt_route, true)
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

    let ordinary_claim = RoleAuthorizationClaim {
        space,
        holder,
        role: Some(vos::SpaceRole::Member),
        capability: None,
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
            RootTreeInvocation {
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
        AccumulatedRoleAssertion::decode(&ordinary_reply_bytes).is_err(),
        "method-name coincidence must not activate the host-private assertion override",
    );

    let ingress = |target, invocation| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new("member_only").encode());
        RootTreeInvocation {
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
    let reopened_crdt = LocalRootTreeService::open(crdt_config, crdt_backend)
        .expect("the role-authorized CRDT root reopens from its durable causal state");
    let sync = reopened_crdt
        .crdt_sync_envelope()
        .expect("the reopened CRDT causal frontier is readable")
        .expect("the authorized ingress and execution remain exportable");
    assert!(sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperation::Ingress(ingress)
                if ingress.invocation == crdt_invocation
                    && matches!(&ingress.authorization, AuthorizationEvidence::Credential { .. }))
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
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([114; 32]),
            root_service: RootServiceId([115; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([116; 32]),
            authenticator: vec![117],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    assert!(matches!(
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default()),
        Err(vos::service::LocalRootTreeOpenError::InvalidConfig(
            LocalRootTreeConfigError::ReplicationDriverRequired
        ))
    ));

    let directory = std::env::temp_dir().join(format!(
        "vos-root-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeService::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .expect("Raft root genesis is ordered through physical Accumulate");
    assert_eq!(service.consistency(), ConsistencyMode::Raft);
    assert_eq!(
        service.store().header().unwrap().unwrap().consistency,
        ConsistencyMode::Raft
    );

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let request = LocalWorkRequest {
        invocation: InvocationId([118; 32]),
        workflow_step: 0,
        logical_timeslot: 5,
        target: actor,
        method: "start".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
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
    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(log.applied_index().unwrap(), 4);
    assert!(log.committed_after(4).unwrap().entries.is_empty());
    let mut reopened = LocalRootTreeService::open_raft(config, backend, log)
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
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([0xA2; 32]),
            root_service: RootServiceId([0xA3; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xA4; 32]),
            authenticator: vec![0xA5],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-node-raft-{}-{}",
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
    let failed = unavailable.register_service_raft_root_at_id_after_local_attach(
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
        Err(vos::node::RaftNodeRegistrationError::Registration(
            vos::node::NodeRegistrationError::ServiceRouteOccupied(id),
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

        fn pre_vote(
            &self,
            _replication_id: &[u8; 32],
            _from_prefix: u16,
            next_term: u64,
            _last_log_index: u64,
            _last_log_term: u64,
        ) -> vos::network::RaftPreVoteResult {
            vos::network::RaftPreVoteResult {
                term: next_term.saturating_sub(1),
                vote_granted: false,
            }
        }

        fn handle_status(&self, _replication_id: &[u8; 32]) -> vos::network::RaftStatusReply {
            vos::network::RaftStatusReply {
                present: true,
                role: vos::network::RaftRole::Leader,
                current_term: 77,
                commit_index: 11,
                last_applied: 11,
                last_log_index: 11,
                members: vec![0xA109],
                joint_old: None,
                active_config_index: Some(11),
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
    let duplicate = duplicate_node.register_service_raft_root_at_id(
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
        Err(vos::node::RaftNodeRegistrationError::ReplicationHandlerOccupied(id))
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
        .register_service_raft_root_at_id_after_local_attach(
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
    node.register_service_raft_root_at_id(
        "raft-root".into(),
        config,
        FailableCommittedImages::default(),
        db,
        RaftConfig {
            me: member,
            members: vec![member],
            voter_peer_ids: Vec::new(),
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0xA6; 32],
            propose_timeout_ms: 2_000,
        },
        route,
        true,
    )
    .expect("node attaches the service Raft worker and root-tree owner");
    let handle = node.invoke_handle();
    let shutdown = node.shutdown_handle();
    let router = std::thread::spawn(move || {
        node.run_forever();
        node.collect()
    });

    std::thread::sleep(Duration::from_millis(350));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("start").encode());
    let ingress = RootTreeInvocation {
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
    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
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
    let task_pvm = vos_pvm_compiler::assembler::Assembler::new().build();
    let (mut config, _) = signed_task_dependency_config(task_pvm, ConsistencyMode::Raft);
    let authority_signer = libp2p::identity::Keypair::generate_ed25519();
    config.actor_name = vos::service::ROLE_AUTHORITY_INSTANCE_.into();
    config.package.manifest.name = vos::service::ROLE_AUTHORITY_INSTANCE_.into();
    config.package.deployment_signature.public_key = authority_signer.public().encode_protobuf();
    config.package.deployment_signature.producer =
        ProducerId::of_public_key(&config.package.deployment_signature.public_key);
    config.package.deployment_signature.signature = authority_signer
        .sign(&config.package.signing_message())
        .expect("sign authority redirect fixture");
    config.service.deployment = config.package.deployment_id();
    config.package.validate().unwrap();
    let authority_package = config.package.clone();
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
        vos_pvm_compiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
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
        "vos-root-follower-redirect-{}-{}",
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
    let backend_a = FileCommittedImageStore::new(&image_a);
    let backend_b = FileCommittedImageStore::new(&image_b);
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
        voter_peer_ids: Vec::new(),
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

    let log_a =
        RaftAccumulateLog::from_worker(db_a, raft_config(prefix_a), worker_a, apply_a_rx).unwrap();
    let log_b =
        RaftAccumulateLog::from_worker(db_b, raft_config(prefix_b), worker_b, apply_b_rx).unwrap();
    let trust = Arc::new(TestProductionTrust::new(0xB6, 100, true));
    let local_id = 0x3600;
    if leader == prefix_a {
        let service_a = LocalRootTreeService::open_raft_production(
            config.clone(),
            backend_a.clone(),
            log_a,
            trust.clone(),
        )
        .unwrap();
        node_a
            .register_service_root_at_id(
                "raft-root-a",
                service_a,
                ServiceId::new(prefix_a, local_id),
                true,
            )
            .unwrap();
        let service_b =
            LocalRootTreeService::open_raft_production(config, backend_b.clone(), log_b, trust)
                .unwrap();
        node_b
            .register_service_root_at_id(
                "raft-root-b",
                service_b,
                ServiceId::new(prefix_b, local_id),
                true,
            )
            .unwrap();
    } else {
        let service_b = LocalRootTreeService::open_raft_production(
            config.clone(),
            backend_b.clone(),
            log_b,
            trust.clone(),
        )
        .unwrap();
        node_b
            .register_service_root_at_id(
                "raft-root-b",
                service_b,
                ServiceId::new(prefix_b, local_id),
                true,
            )
            .unwrap();
        let service_a =
            LocalRootTreeService::open_raft_production(config, backend_a.clone(), log_a, trust)
                .unwrap();
        node_a
            .register_service_root_at_id(
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
    let ingress = RootTreeInvocation {
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
    let forged_ingress = RootTreeInvocation {
        invocation: InvocationId([0xB8; 32]),
        target: actor,
        method: "origin_kind".into(),
        arguments: forged_arguments,
        proof_requested: false,
    };
    let mut forged_delegation = b"VRDW".to_vec();
    // preserve envelope + no authority/upgrade marker + Origin::System
    forged_delegation.extend_from_slice(&[1, 0, 0, 3]);
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

    // A genuinely enrolled voter may carry the host-private upgrade marker,
    // but that marker authenticates only the forwarding hop. It cannot replace
    // the immutable space-root package signature enforced by the root driver.
    let attacker = libp2p::identity::Keypair::generate_ed25519();
    let mut attacker_signed = authority_package.clone();
    attacker_signed.deployment_signature.public_key = attacker.public().encode_protobuf();
    attacker_signed.deployment_signature.producer =
        ProducerId::of_public_key(&attacker_signed.deployment_signature.public_key);
    attacker_signed.deployment_signature.signature = attacker
        .sign(&attacker_signed.signing_message())
        .expect("sign voter-forged authority package");
    attacker_signed.validate().unwrap();
    let upgrade_ingress = RootTreeInvocation {
        invocation: InvocationId([0xB9; 32]),
        target: actor,
        method: vos::service::ROOT_UPGRADE_METHOD_.into(),
        arguments: RootTreeUpgradeRequest {
            expected_deployment: authority_package.deployment_id(),
            expected_program: authority_package.manifest.actor_program,
            replacement: attacker_signed,
        }
        .encode(),
        proof_requested: false,
    };
    let mut delegated_upgrade = b"VRDW".to_vec();
    // preserve envelope + no authority marker + upgrade marker + System origin
    delegated_upgrade.extend_from_slice(&[1, 0, 1, 3]);
    delegated_upgrade.extend_from_slice(&upgrade_ingress.encode());
    let (forwarding_network, leader_peer) = if leader == prefix_a {
        (
            network_b.clone(),
            network_b.peer_for_prefix(prefix_a).unwrap(),
        )
    } else {
        (
            network_a.clone(),
            network_a.peer_for_prefix(prefix_b).unwrap(),
        )
    };
    let leader_handle = if leader == prefix_a {
        &handle_a
    } else {
        &handle_b
    };
    let committed_before = leader_handle
        .snapshot()
        .expect("leader status before forged delegated upgrade")
        .commit_index;
    let refused = forwarding_network
        .send_invoke(
            leader_peer,
            ServiceId::REGISTRY.0,
            ServiceId::new(leader, local_id).0,
            Vec::new(),
            delegated_upgrade,
        )
        .recv_timeout(Duration::from_secs(10))
        .expect("leader answers the voter-delegated forged upgrade fail-closed");
    assert_ne!(
        refused.first().copied(),
        Some(vos::actors::run::STATUS_DONE),
        "the leader must not report a committed upgrade: {refused:?}",
    );
    assert_eq!(
        leader_handle
            .snapshot()
            .expect("leader status after forged delegated upgrade")
            .commit_index,
        committed_before,
        "the voter-delegated forged authority upgrade never enters Raft",
    );

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
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([120; 32]),
            root_service: RootServiceId([121; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([122; 32]),
            authenticator: vec![123],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-root-follower-{}-{}",
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
    let source_log = RaftAccumulateLog::open(&source_log_path, RaftConfig::default()).unwrap();
    let mut source = LocalRootTreeService::open_raft(
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([124; 32]),
            workflow_step: 0,
            logical_timeslot: committed_floor,
            target: actor,
            method: "start".into(),
            arguments: arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let mut source_log = RaftAccumulateLog::open(&source_log_path, RaftConfig::default()).unwrap();
    let source_index = source_log.applied_index().unwrap();
    assert_eq!(source_index, 3);
    drop(source_log);

    // Start a real non-writable worker with no committed genesis. Opening the
    // root returns an intentionally headerless service, which registration
    // must retain until a leader snapshot arrives.
    let follower_db = Arc::new(redb::Database::create(directory.join("follower.redb")).unwrap());
    let raft_config = RaftConfig {
        me: 0xBEEF,
        // A second unavailable voter keeps this worker non-writable while
        // the relatively expensive root open validates the headerless path.
        // The installed snapshot below then commits the final singleton
        // membership and permits election deterministically.
        members: vec![0xBEEF, 0xCAFE],
        voter_peer_ids: Vec::new(),
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
        RaftAccumulateLog::from_worker(follower_db, raft_config, worker, apply_rx).unwrap();
    let backend = SharedCommittedImages::default();
    let follower = LocalRootTreeService::open_raft(config, backend.clone(), follower_log).unwrap();
    assert!(follower.store().header().unwrap().is_none());

    let route = ServiceId::new(0, 0x3400);
    let mut node = VosNode::new();
    node.register_service_root_at_id("raft-follower", follower, route, false)
        .expect("a Raft follower may register while waiting for genesis");

    let snapshot = CommittedServiceSnapshot {
        applied_index: source_index,
        service_image: source_image,
        proof_artifacts: vec![],
        result_artifacts: vec![],
        host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
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
        Some(source_index),
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
    let restored =
        MemoryServiceStore::from_snapshot(MemoryServiceSnapshot::decode(&image).unwrap());
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
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([104; 32]),
            root_service: RootServiceId([105; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([106; 32]),
            authenticator: vec![107],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let backend = SharedCommittedImages::default();
    let mut service = LocalRootTreeService::open(config.clone(), backend.clone())
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
        .invoke(LocalWorkRequest {
            invocation: InvocationId([111; 32]),
            workflow_step: 0,
            logical_timeslot: durable_floor,
            target: actor,
            method: "start".into(),
            arguments: arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    node.register_service_root_at_id("greeter", service, route, false)
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

    let malformed = vos::service::RootTreeInvocation {
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
    let duplicate = LocalRootTreeService::open(duplicate_config, SharedCommittedImages::default())
        .expect("independent service installs before duplicate-identity check");
    assert!(matches!(
        node.register_service_root_at_id(
            "duplicate-greeter",
            duplicate,
            ServiceId::new(0, 0x3301),
            false,
        ),
        Err(NodeRegistrationError::ActorAlreadyRegistered(found)) if found == actor
    ));

    let results = node.collect();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());

    let reopened = LocalRootTreeService::open(config, backend)
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
fn root_upgrade_is_exactly_once_and_reopens_across_the_catalog_cutover() {
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&greeter_elf(), &signer);
    let actor = ActorId([0x61; 32]);
    let original_service = ServiceIdentity {
        space: vos::service::SpaceId([0x62; 32]),
        root_service: RootServiceId([0x63; 32]),
        deployment: package.deployment_id(),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: original_service.clone(),
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state: b"preserved application state".to_vec(),
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x64; 32]),
            authenticator: vec![0x65],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let backend = SharedCommittedImages::default();
    let mut service = LocalRootTreeService::open(config.clone(), backend.clone()).unwrap();
    let before_header = service.store().header().unwrap().unwrap();
    let before_state = service
        .store()
        .state_row(
            before_header.service_root,
            &StateKey::ActorRow {
                actor,
                key: vos::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
            },
        )
        .unwrap();

    let replacement = replacement_test_package(&package, &signer);
    let request = RootTreeUpgradeRequest {
        expected_deployment: package.deployment_id(),
        expected_program: package.manifest.actor_program,
        replacement: replacement.clone(),
    };
    let upgraded = service.upgrade_root(request.clone()).unwrap();
    assert!(matches!(
        upgraded,
        AccumulationResult::ActorUpgraded {
            deployment,
            duplicate: false,
            ..
        } if deployment == replacement.deployment_id()
    ));
    let package_reference = BlobRef::of_bytes(&replacement.encode());
    assert_eq!(
        service.store().blob(&package_reference),
        Some(replacement.encode().as_slice()),
        "the exact signed package is committed before the catalog can move",
    );
    let after_header = service.store().header().unwrap().unwrap();
    assert_eq!(after_header.service, original_service);
    assert_eq!(
        service
            .store()
            .state_row(
                after_header.service_root,
                &StateKey::ActorRow {
                    actor,
                    key: vos::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                },
            )
            .unwrap(),
        before_state,
        "UpgradeActor preserves application state"
    );
    drop(service);

    // Crash before the catalog CAS: the old package still opens because the
    // permanent guest record proves the exact old -> new descriptor edge.
    let mut pre_catalog = LocalRootTreeService::open(config.clone(), backend.clone()).unwrap();
    assert!(matches!(
        pre_catalog.upgrade_root(request.clone()).unwrap(),
        AccumulationResult::ActorUpgraded {
            deployment,
            duplicate: true,
            ..
        } if deployment == replacement.deployment_id()
    ));
    let rollback = RootTreeUpgradeRequest {
        expected_deployment: replacement.deployment_id(),
        expected_program: replacement.manifest.actor_program,
        replacement: package.clone(),
    };
    assert!(matches!(
        pre_catalog.upgrade_root(rollback).unwrap(),
        AccumulationResult::ActorUpgraded {
            deployment,
            duplicate: false,
            ..
        } if deployment == package.deployment_id()
    ));
    assert!(matches!(
        pre_catalog.upgrade_root(request).unwrap(),
        AccumulationResult::ActorUpgraded {
            deployment,
            duplicate: false,
            ..
        } if deployment == replacement.deployment_id()
    ));
    drop(pre_catalog);

    // After the registry CAS, configuration names the replacement actor
    // package while the root service keeps its genesis deployment identity.
    let mut replacement_config = config;
    replacement_config.package = replacement.clone();
    replacement_config.service.deployment = replacement.deployment_id();
    let mut reopened = LocalRootTreeService::open(replacement_config, backend).unwrap();
    assert_eq!(reopened.identity(), &original_service);
    assert_eq!(
        reopened
            .root_method_policy("start")
            .unwrap()
            .map(|policy| policy.public),
        Some(true)
    );
    let terminal_retry = RootTreeUpgradeRequest {
        expected_deployment: replacement.deployment_id(),
        expected_program: replacement.manifest.actor_program,
        replacement,
    };
    assert!(matches!(
        reopened.upgrade_root(terminal_retry).unwrap(),
        AccumulationResult::ActorUpgraded {
            duplicate: true,
            ..
        }
    ));
}

#[test]
fn conformance_raft_and_role_authority_shape_changes_are_refused_before_upgrade() {
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&greeter_elf(), &signer);
    let actor = ActorId([0xB1; 32]);
    let mut config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([0xB2; 32]),
            root_service: RootServiceId([0xB3; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xB4; 32]),
            authenticator: vec![0xB5],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let replacement = replacement_test_package(&package, &signer);
    let request = RootTreeUpgradeRequest {
        expected_deployment: package.deployment_id(),
        expected_program: package.manifest.actor_program,
        replacement,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-conformance-upgrade-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut raft =
        LocalRootTreeService::open_raft(config.clone(), FailableCommittedImages::default(), log)
            .unwrap();
    assert!(matches!(
        raft.upgrade_root(request),
        Err(LocalRootTreeInvokeError::UpgradeUnsupported)
    ));
    drop(raft);
    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(log.applied_index().unwrap(), 1, "only genesis was ordered");
    drop(log);
    std::fs::remove_dir_all(directory).unwrap();

    let protected_signer = libp2p::identity::Keypair::generate_ed25519();
    let (protected, protected_name) = signed_test_package(&cycle_elf(), &protected_signer);
    let authority = RoleAuthorityBinding {
        service: ServiceIdentity {
            space: vos::service::SpaceId([0xB6; 32]),
            root_service: RootServiceId([0xB7; 32]),
            deployment: vos::service::DeploymentId([0xB8; 32]),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        actor: ActorId([0xB9; 32]),
    };
    config.role_authority = Some(authority);
    config.package = protected.clone();
    config.service.space = vos::service::SpaceId([0xB6; 32]);
    config.service.root_service = RootServiceId([0xBA; 32]);
    config.service.deployment = protected.deployment_id();
    config.root_actor = ActorId([0xBB; 32]);
    config.actor_name = protected_name;
    config.consistency = ConsistencyMode::Local;
    let mut protected_root =
        LocalRootTreeService::open(config, FailableCommittedImages::default()).unwrap();
    let public_signer = libp2p::identity::Keypair::generate_ed25519();
    let (public, _) = signed_test_package(&greeter_elf(), &public_signer);
    assert!(matches!(
        protected_root.upgrade_root(RootTreeUpgradeRequest {
            expected_deployment: protected.deployment_id(),
            expected_program: protected.manifest.actor_program,
            replacement: public,
        }),
        Err(LocalRootTreeInvokeError::InvalidUpgradeTarget)
    ));
}

#[test]
fn production_raft_authority_upgrade_is_ordered_once_and_preserves_service_identity() {
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (mut package, _) = signed_test_package(&greeter_elf(), &signer);
    package.manifest.name = vos::service::ROLE_AUTHORITY_INSTANCE_.into();
    package.deployment_signature.signature = signer
        .sign(&package.signing_message())
        .expect("sign authority package");
    package.validate().unwrap();
    let actor_name = vos::service::ROLE_AUTHORITY_INSTANCE_.into();
    let actor = ActorId([0x66; 32]);
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([0x67; 32]),
            root_service: RootServiceId([0x68; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x69; 32]),
            authenticator: vec![0x6A],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let directory = std::env::temp_dir().join(format!(
        "vos-root-upgrade-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let log_path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let backend = SharedCommittedImages::default();
    let trust = Arc::new(TestProductionTrust::new(0x6B, 100, true));
    let service = LocalRootTreeService::open_raft_production(
        config.clone(),
        backend.clone(),
        log,
        trust.clone(),
    )
    .expect("single-voter production Raft root installs");

    let replacement = replacement_test_package(&package, &signer);
    let request = RootTreeUpgradeRequest {
        expected_deployment: package.deployment_id(),
        expected_program: package.manifest.actor_program,
        replacement: replacement.clone(),
    };

    // The reserved method is intentionally reachable by host System/Admin
    // callers. That caller authorization must not substitute for the
    // immutable space-root signer check at the service proposal boundary.
    let attacker = libp2p::identity::Keypair::generate_ed25519();
    let mut attacker_signed = replacement.clone();
    attacker_signed.deployment_signature.public_key = attacker.public().encode_protobuf();
    attacker_signed.deployment_signature.producer =
        ProducerId::of_public_key(&attacker_signed.deployment_signature.public_key);
    attacker_signed.deployment_signature.signature = attacker
        .sign(&attacker_signed.signing_message())
        .expect("sign attacker authority package");
    attacker_signed.validate().unwrap();
    let attacker_request = RootTreeUpgradeRequest {
        expected_deployment: package.deployment_id(),
        expected_program: package.manifest.actor_program,
        replacement: attacker_signed,
    };
    let route = ServiceId::new(0, 0x36A0);
    let mut node = VosNode::new();
    node.register_service_root_at_id("raw-authority-upgrade", service, route, true)
        .unwrap();
    let raw_system_ingress = RootTreeInvocation {
        invocation: InvocationId([0x6C; 32]),
        target: actor,
        method: vos::service::ROOT_UPGRADE_METHOD_.into(),
        arguments: attacker_request.encode(),
        proof_requested: false,
    };
    assert!(
        node.invoke_with_timeout(route, raw_system_ingress.encode(), Duration::from_secs(10))
            .is_none(),
        "a raw privileged caller cannot install an attacker-signed authority",
    );
    assert!(node.collect().into_iter().all(|result| result.is_ok()));

    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(
        log.applied_index().unwrap(),
        1,
        "the rejected raw upgrade never enters the Raft log",
    );
    drop(log);

    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut service =
        LocalRootTreeService::open_raft_production(config.clone(), backend, log, trust.clone())
            .expect("authority root reopens after rejecting raw ingress");
    let mut incompatible = replacement.clone();
    incompatible.generated_interfaces.push(0xFF);
    incompatible.manifest.interfaces_hash =
        artifact_hash(b"interfaces", &incompatible.generated_interfaces);
    incompatible.deployment_signature.signature = signer
        .sign(&incompatible.signing_message())
        .expect("sign contract-incompatible authority package");
    incompatible.validate().unwrap();
    assert!(matches!(
        service.upgrade_root(RootTreeUpgradeRequest {
            expected_deployment: package.deployment_id(),
            expected_program: package.manifest.actor_program,
            replacement: incompatible,
        }),
        Err(LocalRootTreeInvokeError::InvalidUpgradeTarget)
    ));
    // Voter-authenticated redirects enter this exact service method with a
    // host-private marker; they cannot bypass the same contract policy.
    assert!(matches!(
        service.upgrade_root(request.clone()).unwrap(),
        AccumulationResult::ActorUpgraded {
            deployment,
            duplicate: false,
            ..
        } if deployment == replacement.deployment_id()
    ));
    assert_eq!(
        service.identity(),
        &config.service,
        "upgrading the authority actor preserves its genesis service identity"
    );
    let backend = service.into_backend();

    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(
        log.applied_index().unwrap(),
        2,
        "genesis and one upgrade commit"
    );
    assert!(log.committed_after(2).unwrap().entries.is_empty());
    drop(log);

    let mut replacement_config = config;
    replacement_config.package = replacement.clone();
    replacement_config.service.deployment = replacement.deployment_id();
    let log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    let mut reopened =
        LocalRootTreeService::open_raft_production(replacement_config, backend, log, trust)
            .expect("Raft root reopens through the committed upgrade history");
    assert!(matches!(
        reopened.upgrade_root(request).unwrap(),
        AccumulationResult::ActorUpgraded {
            deployment,
            duplicate: true,
            ..
        } if deployment == replacement.deployment_id()
    ));
    drop(reopened);

    let mut log = RaftAccumulateLog::open(&log_path, RaftConfig::default()).unwrap();
    assert_eq!(
        log.applied_index().unwrap(),
        2,
        "an exact retry never appends a second upgrade"
    );
    drop(log);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn node_attested_root_requires_an_explicit_producer_and_returns_the_committed_package() {
    let (config, request) = attested_root_fixture(ConsistencyMode::Local, 0x71);
    let backend = SharedCommittedImages::default();
    let service = LocalRootTreeService::open(config.clone(), backend.clone()).unwrap();
    let route = ServiceId::new(0, 0x3310);

    let mut unavailable = VosNode::new();
    unavailable
        .register_service_root_at_id("attested-root", service, route, false)
        .unwrap();
    assert!(
        matches!(
            unavailable.invoke_actor_attested(request.target, request.arguments.clone()),
            Err(ClientError::Forbidden)
        ),
        "ordinary registration remains fail-closed for signed attested methods"
    );
    assert!(unavailable.collect().iter().all(AgentResult::is_ok));

    let service = LocalRootTreeService::open(config.clone(), backend.clone()).unwrap();
    let proof = canonical_test_proof_manifest(0x81);
    let mut node = VosNode::new();
    node.register_service_root_at_id_with_producer(
        "attested-root",
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

    let reopened = LocalRootTreeService::open(config, backend)
        .expect("the node's proof and acknowledgement survive its root thread");
    assert!(reopened.pending_publications().unwrap().is_empty());
}

#[test]
fn local_registration_reverifies_conformance_proof_history_before_exposing_the_root() {
    let (config, request) = attested_root_fixture(ConsistencyMode::Local, 0x72);
    let backend = SharedProofCommittedImages::default();
    let mut service = LocalRootTreeService::open(config, backend).unwrap();
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
        node.register_service_root_at_id_with_producer(
            "attested-root",
            service,
            ServiceId::new(0, 0x3311),
            false,
            CanonicalTestProofProducer {
                proof: canonical_test_proof_manifest(0x92),
                calls: 0,
            },
        ),
        Err(NodeRegistrationError::CorruptServiceStore)
    ));
    assert!(
        node.collect().is_empty(),
        "the rejected root was never exposed"
    );
}

#[test]
fn local_registration_reverifies_pending_proofs_despite_image_provenance() {
    let (config, request) = attested_root_fixture(ConsistencyMode::Local, 0x75);
    let backend = SharedProofCommittedImages::default();
    let mut service = LocalRootTreeService::open(config.clone(), backend).unwrap();
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
        let service = LocalRootTreeService::open(config.clone(), backend)
            .expect("the marked service image itself remains recoverable");
        let mut node = VosNode::new();
        assert!(
            matches!(
                node.register_service_root_at_id_with_producer(
                    "attested-root",
                    service,
                    ServiceId::new(0, 0x3314),
                    false,
                    CanonicalTestProofProducer {
                        proof: proof.clone(),
                        calls: 0,
                    },
                ),
                Err(NodeRegistrationError::CorruptServiceStore)
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
    let (config, request) = attested_root_fixture(ConsistencyMode::Raft, 0x74);
    let directory = std::env::temp_dir().join(format!(
        "vos-raft-proof-cutover-{}-{}",
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
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id: [0x77; 32],
        propose_timeout_ms: 2_000,
    };
    let log = RaftAccumulateLog::from_db_arc(db.clone(), raft_config.clone()).unwrap();
    let mut service = LocalRootTreeService::open_raft(config.clone(), backend.clone(), log)
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
        node.register_service_raft_root_at_id_with_producer(
            "attested-raft-root".into(),
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
    let (config, request) = attested_root_fixture(ConsistencyMode::Raft, 0x73);
    let directory = std::env::temp_dir().join(format!(
        "vos-node-attested-raft-{}-{}",
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
    node.register_service_raft_root_at_id_with_producer(
        "attested-raft-root".into(),
        config,
        FailableCommittedImages::default(),
        db,
        RaftConfig {
            me: member,
            members: vec![member],
            voter_peer_ids: Vec::new(),
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
    consistency: ConsistencyMode,
    salt: u8,
) -> (LocalRootTreeConfig, LocalRootTreeConfig, ActorId, ActorId) {
    let actor_elf = workflow_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([salt; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([salt.wrapping_add(1); 32]),
        root_service: RootServiceId([salt.wrapping_add(2); 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([salt.wrapping_add(3); 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidence::SystemCapability {
        capability: SystemCapabilityId([salt.wrapping_add(4); 32]),
        authenticator: vec![salt.wrapping_add(5)],
    };
    let source = LocalRootTreeConfig {
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
        intra_caps: vec![],
        install_authorization: install_authorization.clone(),
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let destination = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name: "private-age".into(),
        consistency,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization,
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    (source, destination, source_actor, destination_actor)
}

#[test]
fn node_routes_an_attested_durable_call_and_proof_back_into_the_waiting_actor() {
    let (source_config, destination_config, source_actor, _) =
        attested_node_transport_fixture(ConsistencyMode::Local, 0xD1);
    let source_backend = SharedProofCommittedImages::default();
    let destination_backend = SharedProofCommittedImages::default();
    let source = LocalRootTreeService::open(source_config.clone(), source_backend.clone()).unwrap();
    let destination =
        LocalRootTreeService::open(destination_config.clone(), destination_backend.clone())
            .unwrap();
    let source_route = ServiceId::new(0, 0x3510);
    let destination_route = ServiceId::new(0, 0x3511);
    let proof = canonical_test_proof_manifest(0x83);
    let mut node = VosNode::new();
    node.register_service_root_at_id_with_verifier(
        "attested-source",
        source,
        source_route,
        false,
        CanonicalTestProofProducer {
            proof: proof.clone(),
            calls: 0,
        },
    )
    .unwrap();
    node.register_service_root_at_id_with_producer(
        "private-age",
        destination,
        destination_route,
        false,
        CanonicalTestProofProducer { proof, calls: 0 },
    )
    .unwrap();

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
    let ingress = RootTreeInvocation {
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
    let source = LocalRootTreeService::open(source_config, source_backend).unwrap();
    let destination = LocalRootTreeService::open(destination_config, destination_backend).unwrap();
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
        attested_node_transport_fixture(ConsistencyMode::Raft, 0xE1);
    let source_backend = SharedProofCommittedImages::default();
    let destination_backend = SharedProofCommittedImages::default();
    let directory = std::env::temp_dir().join(format!(
        "vos-node-attested-raft-route-{}-{}",
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
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (10, 30),
        heartbeat_interval_ms: 5,
        replication_id,
        propose_timeout_ms: 2_000,
    };
    let proof = canonical_test_proof_manifest(0x84);
    let mut node = VosNode::new();
    node.register_service_raft_root_at_id_with_verifier(
        "attested-raft-source".into(),
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
    node.register_service_raft_root_at_id_with_producer(
        "attested-raft-destination".into(),
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
    let ingress = RootTreeInvocation {
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
            .all(|candidate| candidate != &proof),
        "the caller replica prunes a completed reply proof after ordering resume"
    );
    // Proof artifacts are required through verification and reply routing,
    // but may already be pruned once the final acknowledgement races ahead
    // of shutdown. The returned package above is the stable end-to-end
    // assertion; process-local CAS retention is deliberately not one.

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
        .register_service_raft_root_at_id_with_verifier(
            "attested-raft-source".into(),
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
        attested_node_transport_fixture(ConsistencyMode::Raft, 0xF1);
    let source_backend = SharedProofCommittedImages::default();
    let destination_backend = SharedProofCommittedImages::default();
    let directory = std::env::temp_dir().join(format!(
        "vos-promoted-attested-voter-{}-{}",
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
    node.register_service_raft_root_at_id_with_verifier(
        "promoted-attested-source".into(),
        source_config,
        source_backend,
        source_db,
        RaftConfig {
            me: member,
            members: vec![member],
            voter_peer_ids: Vec::new(),
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
    node.register_service_raft_root_at_id_after_local_attach_with_producer(
        "promoted-attested-destination".into(),
        destination_config,
        destination_backend.clone(),
        destination_db,
        RaftConfig {
            me: member,
            members: vec![member],
            voter_peer_ids: Vec::new(),
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
        let direct_ingress = RootTreeInvocation {
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
        let direct = RootTreeAttestedResult::decode(&direct)
            .expect("the promoted leader returns its committed attestation");

        let mut durable_arguments = vec![vos::value::TAG_DYNAMIC];
        durable_arguments.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
        let durable = invoker.invoke_with_timeout(
            source_route,
            RootTreeInvocation {
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
    // The direct package and the completed durable call prove that the
    // promoted leader retained its producer. Its proof CAS may be pruned as
    // soon as both acknowledgement paths finish, so no post-shutdown storage
    // assertion is stable here.
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
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([0xB3; 32]),
        root_service: RootServiceId([0xB4; 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([0xB5; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidence::SystemCapability {
        capability: SystemCapabilityId([0xB6; 32]),
        authenticator: vec![0xB7],
    };
    let source_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        intra_caps: vec![],
        install_authorization: install_authorization.clone(),
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let destination_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization,
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let source_backend = SharedCommittedImages::default();
    let destination_backend = SharedCommittedImages::default();
    let source = LocalRootTreeService::open(source_config.clone(), source_backend.clone())
        .expect("source root installs");

    let source_route = ServiceId::new(0, 0x3500);
    let destination_route = ServiceId::new(0, 0x3501);
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer_without_deadline").encode());
    let invocation = RootTreeInvocation {
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
        .register_service_root_at_id("workflow-source", source, source_route, false)
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

    let source = LocalRootTreeService::open(source_config.clone(), source_backend.clone())
        .expect("source root reopens with its suspended publication");
    assert_eq!(source.pending_publications().unwrap().len(), 1);
    let destination =
        LocalRootTreeService::open(destination_config.clone(), destination_backend.clone())
            .expect("destination root installs");

    // Second run: the caller retries the exact InvocationId. The root
    // reattaches it to the committed checkpoint without replaying PC 0, then
    // the node redrives delivery and the finalized reply across both roots.
    let mut node = VosNode::new();
    node.register_service_root_at_id("workflow-source", source, source_route, false)
        .unwrap();
    node.register_service_root_at_id(
        "workflow-destination",
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
    let source = LocalRootTreeService::open(source_config, source_backend)
        .expect("source root reopens after routed reply");
    let destination = LocalRootTreeService::open(destination_config, destination_backend)
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
    let actor_elf = crdt_counter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let deployment = package.deployment_id();
    let producer = package.deployment_signature.producer;
    let program = package.manifest.actor_program;
    let source_actor = ActorId([0xE1; 32]);
    let destination_actor = ActorId([44; 32]);
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([0xE2; 32]),
        root_service: RootServiceId([0xE3; 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([0xE4; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidence::SystemCapability {
        capability: SystemCapabilityId([0xE5; 32]),
        authenticator: vec![0xE6],
    };
    let source_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyMode::Crdt,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        intra_caps: vec![],
        install_authorization: install_authorization.clone(),
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let destination_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyMode::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization,
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let source_backend = SharedCommittedImages::default();
    let destination_backend = SharedCommittedImages::default();
    let source = LocalRootTreeService::open(source_config.clone(), source_backend.clone())
        .expect("CRDT source root installs");
    let destination =
        LocalRootTreeService::open(destination_config.clone(), destination_backend.clone())
            .expect("CRDT destination root installs");

    let source_route = ServiceId::new(0, 0x3510);
    let destination_route = ServiceId::new(0, 0x3511);
    let mut node = VosNode::new();
    node.register_service_root_at_id("crdt-workflow-source", source, source_route, false)
        .unwrap();
    node.register_service_root_at_id(
        "crdt-workflow-destination",
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
            RootTreeInvocation {
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

    let source = LocalRootTreeService::open(source_config, source_backend)
        .expect("CRDT source reopens after routed reply");
    let destination = LocalRootTreeService::open(destination_config, destination_backend)
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
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([0xBB; 32]),
        root_service: RootServiceId([0xBC; 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([0xBD; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidence::SystemCapability {
        capability: SystemCapabilityId([0xBE; 32]),
        authenticator: vec![0xBF],
    };
    let source_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        intra_caps: vec![],
        install_authorization: install_authorization.clone(),
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let destination_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity,
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization,
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };

    let directory = std::env::temp_dir().join(format!(
        "vos-networkless-raft-transport-{}-{}",
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
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (25, 50),
        heartbeat_interval_ms: 10,
        replication_id,
        propose_timeout_ms: 5_000,
    };
    let mut node = VosNode::new();
    node.register_service_raft_root_at_id(
        "networkless-raft-source".into(),
        source_config,
        FailableCommittedImages::default(),
        Arc::new(redb::Database::create(directory.join("source.redb")).unwrap()),
        raft_config([0xC1; 32]),
        source_route,
        false,
    )
    .unwrap();
    node.register_service_raft_root_at_id(
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
            RootTreeInvocation {
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
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([0xC2; 32]),
        root_service: RootServiceId([0xC3; 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([0xC4; 32]),
        ..source_identity.clone()
    };
    let install_authorization = AuthorizationEvidence::SystemCapability {
        capability: SystemCapabilityId([0xC5; 32]),
        authenticator: vec![0xC6],
    };
    let source_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package: package.clone(),
        service: source_identity.clone(),
        root_actor: source_actor,
        actor_name: actor_name.clone(),
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity.clone(),
            destination_actor,
            producer,
            program,
        )],
        intra_caps: vec![],
        install_authorization: install_authorization.clone(),
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let destination_config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: destination_identity.clone(),
        root_actor: destination_actor,
        actor_name,
        consistency: ConsistencyMode::Raft,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization,
        device_secret: None,
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
        vos_pvm_compiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
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
        "vos-raft-root-transport-{}-{}",
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
        voter_peer_ids: Vec::new(),
        election_timeout_ms: (50, 100),
        heartbeat_interval_ms: 20,
        replication_id,
        propose_timeout_ms: 5_000,
    };
    node_a
        .register_service_raft_root_at_id(
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
        .register_service_raft_root_at_id(
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
        .bind_service_raft_actor_route(
            destination_actor,
            destination_identity,
            destination_replication,
            destination_route,
            peer_b.to_bytes(),
        )
        .unwrap();
    node_b
        .bind_service_raft_actor_route(
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
            RootTreeInvocation {
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
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([0xD2; 32]),
            root_service: RootServiceId([0xD3; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xD4; 32]),
            authenticator: vec![0xD5],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let backend = SharedFailingCommittedImages::default();
    let service = LocalRootTreeService::open(config.clone(), backend.clone())
        .expect("direct-reply root installs");

    let route = ServiceId::new(0, 0x3700);
    let mut node = VosNode::new();
    node.register_service_root_at_id("direct-ack-retry", service, route, false)
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
    let reopened = LocalRootTreeService::open(config, backend)
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
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([0xC2; 32]),
        root_service: RootServiceId([0xC3; 32]),
        deployment,
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([0xC4; 32]),
        ..source_identity.clone()
    };
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        package,
        service: source_identity,
        root_actor: source_actor,
        actor_name,
        consistency: ConsistencyMode::Local,
        initial_state: vec![],
        external_actors: vec![external_binding(
            "peer",
            destination_identity,
            destination_actor,
            producer,
            program,
        )],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xC5; 32]),
            authenticator: vec![0xC6],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let backend = SharedFailingCommittedImages::default();
    let service = LocalRootTreeService::open(config.clone(), backend.clone())
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
    let invocation = RootTreeInvocation {
        invocation: InvocationId([0xC7; 32]),
        target: source_actor,
        method: "await_peer_until".into(),
        arguments,
        proof_requested: false,
    };

    let mut node = VosNode::new();
    node.register_service_root_at_id("timeout-source", service, route, false)
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

    let reopened = LocalRootTreeService::open(config, backend)
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
    let actor_elf = crdt_counter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([97; 32]);
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([98; 32]),
            root_service: RootServiceId([99; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([100; 32]),
            authenticator: vec![101],
        },
        device_secret: None,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &Msg::new("increment_around_two_yields")
            .with("amount", 2u64)
            .encode(),
    );
    let request = LocalWorkRequest {
        invocation: InvocationId([102; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: actor,
        method: "increment_around_two_yields".into(),
        arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };

    let mut service =
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
            .expect("fresh CRDT root installs through physical Accumulate");
    let committed = service
        .invoke(request.clone())
        .expect("CRDT slice commits through physical Refine and Accumulate");
    assert!(!committed.duplicate);
    assert!(!committed.receipt.resulting_crdt_heads.is_empty());

    let mut replica =
        LocalRootTreeService::open(config.clone(), FailableCommittedImages::default())
            .expect("independent CRDT replica installs the same root tree");
    let mut prior_arguments = vec![vos::value::TAG_DYNAMIC];
    prior_arguments.extend_from_slice(&Msg::new("increment").with("amount", 5u64).encode());
    replica
        .invoke(LocalWorkRequest {
            invocation: InvocationId([103; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: actor,
            method: "increment".into(),
            arguments: prior_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
                matches!(operation, WorkflowOperation::Checkpoint(work) if work.invocation == request.invocation)
            })
        })
        .expect("source exports the yielded invocation node");
    let replica_execution = replica_sync
        .nodes
        .iter()
        .find(|node| {
            node.change.workflow.iter().any(|operation| {
                matches!(operation, WorkflowOperation::Checkpoint(work) if work.invocation == request.invocation)
            })
        })
        .expect("replica exports the yielded invocation node");
    assert_ne!(
        source_execution.change.materializations, replica_execution.change.materializations,
        "the retry really executed over different causal actor state"
    );
    assert!(source_sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperation::Checkpoint(work)
                if work.invocation == request.invocation && work.workflow_step == 1)
        })
    }));
    assert!(replica_sync.nodes.iter().any(|node| {
        node.change.workflow.iter().any(|operation| {
            matches!(operation, WorkflowOperation::Checkpoint(work)
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
        Err(LocalRootTreeInvokeError::Rejected(
            vos::service::AccumulationRejection::ReceiptUnavailable
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
            .allow_receipt(&ReceiptVerificationRequest {
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
            .allow_receipt(&ReceiptVerificationRequest {
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
    let mut restarted = LocalRootTreeService::open(config.clone(), backend)
        .expect("CRDT service image restores without reinstalling");
    let mut restarted_replica = LocalRootTreeService::open(config, replica_backend)
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
    let actor_elf = crdt_counter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([0x51; 32]);
    let config = LocalRootTreeConfig {
        role_authority: None,
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentity {
            space: vos::service::SpaceId([0x52; 32]),
            root_service: RootServiceId([0x53; 32]),
            deployment: package.deployment_id(),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        package,
        root_actor: actor,
        actor_name,
        consistency: ConsistencyMode::Crdt,
        initial_state: vec![],
        external_actors: vec![],
        intra_caps: vec![],
        install_authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x54; 32]),
            authenticator: vec![0x55],
        },
        device_secret: None,
        refine_gas: TEST_GAS_SCHEDULE.refine,
        accumulate_gas: TEST_GAS_SCHEDULE.accumulate,
    };
    let backend_a = SharedCommittedImages::default();
    let backend_b = SharedCommittedImages::default();
    let mut service_a = LocalRootTreeService::open(config.clone(), backend_a.clone()).unwrap();
    let mut service_b = LocalRootTreeService::open(config.clone(), backend_b.clone()).unwrap();
    let increment_request = |invocation, logical_timeslot, amount| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new("increment").with("amount", amount).encode());
        LocalWorkRequest {
            invocation,
            workflow_step: 0,
            logical_timeslot,
            target: actor,
            method: "increment".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        vos_pvm_compiler::link_elf(include_bytes!("../../vosx/blobs/space_registry.elf"))
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
        .register_service_root_at_id("", service_a, route_a, true)
        .unwrap();
    node_b
        .register_service_root_at_id("", service_b, route_b, true)
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
        let reopened_a = LocalRootTreeService::open(config.clone(), backend_a.clone()).unwrap();
        let reopened_b = LocalRootTreeService::open(config.clone(), backend_b.clone()).unwrap();
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
            "authenticated service CRDT roots did not converge"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    shutdown_a.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown_b.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(runner_a.join().unwrap().iter().all(AgentResult::is_ok));
    assert!(runner_b.join().unwrap().iter().all(AgentResult::is_ok));
    let reopened_a = LocalRootTreeService::open(config.clone(), backend_a).unwrap();
    let reopened_b = LocalRootTreeService::open(config, backend_b).unwrap();
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
    let actor_pvm = vos_pvm_compiler::link_elf(&workflow_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let availability_programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlob {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let host = MemoryServiceStore::default();
    let mut service = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: seed.target_deployment,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![
                MethodPolicy {
                    method: "increment".into(),
                    schema: Hash([151; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                },
                MethodPolicy {
                    method: "spawn_child".into(),
                    schema: Hash([152; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                },
            ]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([153; 32]),
            authenticator: vec![154],
        },
    });
    assert_eq!(
        service
            .accumulate_with_availability(&install, &availability_programs, &availability_blobs,)
            .unwrap()
            .result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized)
    );
    assert!(service.accumulate_host().program(actor_program).is_none());
    assert!(service.accumulate_host().blob(&initial).is_none());
    authorize_install(&mut service, &install);
    assert!(matches!(
        service
            .accumulate_with_availability(&install, &availability_programs, &availability_blobs,)
            .unwrap()
            .result,
        AccumulationResult::Installed(_)
    ));

    let mut spawn_arguments = vec![vos::value::TAG_DYNAMIC];
    spawn_arguments.extend_from_slice(
        &Msg::new("spawn_child")
            .with("name", "worker")
            .with("initial", 9u32)
            .encode(),
    );
    let spawn_work = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([155; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed.target,
            method: "spawn_child".into(),
            arguments: spawn_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let spawn_apply = AccumulateRequest::Apply(AccumulationEnvelope {
        work: spawn_work.work,
        transition: spawned.transition,
        provided_blobs: spawned.exported_blobs,
    });
    assert!(matches!(
        service.accumulate(&spawn_apply).unwrap().result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    let before_retry = service.accumulate_host().snapshot();
    assert!(matches!(
        service.accumulate(&spawn_apply).unwrap().result,
        AccumulationResult::Accepted {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(service.accumulate_host().snapshot(), before_retry);

    let mut increment_arguments = vec![vos::value::TAG_DYNAMIC];
    increment_arguments.extend_from_slice(&Msg::new("increment").with("amount", 2u32).encode());
    let child_work = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([156; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: child,
            method: "increment".into(),
            arguments: increment_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: child_work.work,
                transition: child_result.transition,
                provided_blobs: child_result.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn same_tree_calls_resume_exact_stacks_and_allocate_tree_wide_call_ids() {
    let actor_pvm = vos_pvm_compiler::link_elf(&workflow_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let child = ActorId([36; 32]);
    let sibling = ActorId([37; 32]);
    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![private_age_binding(&seed.service)],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![
            ActorGenesis {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "call_child".into(),
                        schema: Hash([61; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "root_child_await".into(),
                        schema: Hash([65; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "root_child_two_awaits".into(),
                        schema: Hash([73; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "root_child_then_peer".into(),
                        schema: Hash([81; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "root_child_then_sibling".into(),
                        schema: Hash([91; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "call_child_repeatedly".into(),
                        schema: Hash([82; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "sibling_ipc_tail".into(),
                        schema: Hash([83; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesis {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "child_await_peer".into(),
                        schema: Hash([66; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "child_two_awaits".into(),
                        schema: Hash([74; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "increment".into(),
                        schema: Hash([62; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "wide_reply".into(),
                        schema: Hash([84; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesis {
                actor: sibling,
                name: "sibling".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "child_await_peer".into(),
                        schema: Hash([92; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "ipc_tail".into(),
                        schema: Hash([85; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
        ],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([63; 32]),
            authenticator: vec![64],
        },
    });
    authorize_install(&mut service, &install);
    let install_result = service.accumulate(&install).unwrap().result;
    assert!(
        matches!(install_result, AccumulationResult::Installed(_)),
        "root-tree fixture install rejected: {install_result:?}"
    );

    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("call_child").encode());
    let scheduled = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: seed.invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed.target,
            method: "call_child".into(),
            arguments: message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        .expect("root calls its child through an ordinary PVM CALLABLE");
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: scheduled.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut scrub_message = vec![vos::value::TAG_DYNAMIC];
    scrub_message.extend_from_slice(&Msg::new("sibling_ipc_tail").encode());
    let scrub = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([86; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: seed.target,
            method: "sibling_ipc_tail".into(),
            arguments: scrub_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: scrub.work,
                transition: scrubbed.transition,
                provided_blobs: scrubbed.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let invocation = InvocationId([67; 32]);
    let mut nested_message = vec![vos::value::TAG_DYNAMIC];
    nested_message.extend_from_slice(&Msg::new("root_child_await").encode());
    let nested = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation,
            workflow_step: 0,
            logical_timeslot: 3,
            target: seed.target,
            method: "root_child_await".into(),
            arguments: nested_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let runner = ServicePvm::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
    )
    .unwrap();
    let first_bytes = runner
        .refine_actor_tree_traced(
            &nested.work.encode(),
            &nested.imports,
            1_000_000_000,
            &NoRefineProtocolHost,
        )
        .expect("the child suspends inside the root's nested CALL");
    assert_eq!(
        runner
            .refine_actor_tree_traced(
                &nested.work.encode(),
                &nested.imports,
                1_000_000_000,
                &NoRefineProtocolHost,
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(recompiled.bytes, first_bytes.bytes);
    assert_eq!(recompiled.gas_used, first_bytes.gas_used);
    assert_eq!(
        recompiled.exported_blobs, first_bytes.exported_blobs,
        "nested PVM checkpoints must be backend-independent"
    );
    assert!(recompiled.trace.is_none());
    let first_output = RefineOutput::decode(&first_bytes.bytes).unwrap();
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: nested.work.clone(),
                transition: forged_sender,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResult::Rejected(
            vos::service::AccumulationRejection::InvalidWorkflowTransition
        ),
        "guest Accumulate binds the outbox sender to PVM's exact pending actor"
    );

    let mut incomplete_checkpoint = first.clone();
    incomplete_checkpoint.continuations.pop();
    assert_eq!(
        service
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: nested.work.clone(),
                transition: incomplete_checkpoint,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResult::Rejected(
            vos::service::AccumulationRejection::InvalidWorkflowTransition
        ),
        "guest Accumulate rejects a checkpoint that omits an active child"
    );
    let first_result = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: nested.work,
            transition: first.clone(),
            provided_blobs: vec![],
        }))
        .unwrap()
        .result;
    assert!(
        matches!(
            first_result,
            AccumulationResult::Accepted {
                duplicate: false,
                ..
            }
        ),
        "complete nested checkpoint rejected: {first_result:?}"
    );

    let mut child_message = vec![vos::value::TAG_DYNAMIC];
    child_message.extend_from_slice(&Msg::new("increment").with("amount", 1u32).encode());
    let child_request = LocalWorkRequest {
        invocation: InvocationId([72; 32]),
        workflow_step: 0,
        logical_timeslot: 4,
        target: child,
        method: "increment".into(),
        arguments: child_message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    assert_eq!(
        LocalWorkScheduler::prepare(service.accumulate_host(), child_request.clone()),
        Err(ScheduleError::ActorBusy(child)),
        "the active child is non-reentrant while its caller stack is suspended"
    );

    let persisted = service.accumulate_host().snapshot_bytes();
    let restarted_store = MemoryServiceStore::from_snapshot_bytes(&persisted)
        .expect("the complete tree checkpoint survives a process restart");
    let mut restarted = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        restarted_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let awaited_reply = peer_reply(&seed.service, call_id, 7, 68);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: awaited_reply.receipt.clone(),
        });
    let resumed = LocalWorkScheduler::prepare_resume(
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .expect("the reply resumes the child and then its suspended root caller");
    assert_eq!(
        runner
            .refine_actor_tree_with_backend(
                &resumed.work.encode(),
                &resumed.imports,
                1_000_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        resumed_bytes,
        "nested reply injection must be backend-independent"
    );
    let resumed_output = RefineOutput::decode(&resumed_bytes.bytes).unwrap();
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: resumed.work,
                transition: resumed_output.transition,
                provided_blobs: resumed_candidates,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert!(
        LocalWorkScheduler::prepare(restarted.accumulate_host(), child_request).is_ok(),
        "completion unlocks every actor from the exact suspended stack"
    );

    let second_invocation = InvocationId([75; 32]);
    let mut twice_message = vec![vos::value::TAG_DYNAMIC];
    twice_message.extend_from_slice(&Msg::new("root_child_two_awaits").encode());
    let twice = LocalWorkScheduler::prepare(
        restarted.accumulate_host(),
        LocalWorkRequest {
            invocation: second_invocation,
            workflow_step: 0,
            logical_timeslot: 4,
            target: seed.target,
            method: "root_child_two_awaits".into(),
            arguments: twice_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: twice.work,
                transition: first_wait.transition,
                provided_blobs: first_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let persisted = restarted.accumulate_host().snapshot_bytes();
    restarted = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        MemoryServiceStore::from_snapshot_bytes(&persisted).unwrap(),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let first_reply = peer_reply(&seed.service, first_call, 1, 76);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: first_reply.receipt.clone(),
        });
    let after_first = LocalWorkScheduler::prepare_resume(
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: after_first.work,
                transition: second_wait.transition,
                provided_blobs: second_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let persisted = restarted.accumulate_host().snapshot_bytes();
    restarted = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        MemoryServiceStore::from_snapshot_bytes(&persisted).unwrap(),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let second_reply = peer_reply(&seed.service, second_call, 2, 80);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: second_reply.receipt.clone(),
        });
    let after_second = LocalWorkScheduler::prepare_resume(
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: after_second.work,
                transition: finished.transition,
                provided_blobs: finished.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let chained_invocation = InvocationId([87; 32]);
    let mut chained_message = vec![vos::value::TAG_DYNAMIC];
    chained_message.extend_from_slice(&Msg::new("root_child_then_peer").encode());
    let chained = LocalWorkScheduler::prepare(
        restarted.accumulate_host(),
        LocalWorkRequest {
            invocation: chained_invocation,
            workflow_step: 0,
            logical_timeslot: 7,
            target: seed.target,
            method: "root_child_then_peer".into(),
            arguments: chained_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: chained.work,
                transition: child_wait.transition,
                provided_blobs: child_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let child_reply = peer_reply(&seed.service, child_call, 3, 88);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: child_reply.receipt.clone(),
        });
    let after_child = LocalWorkScheduler::prepare_resume(
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: after_child.work,
                transition: root_wait.transition,
                provided_blobs: root_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let root_reply = peer_reply(&seed.service, root_call, 4, 89);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: root_reply.receipt.clone(),
        });
    let after_root = LocalWorkScheduler::prepare_resume(
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: after_root.work,
                transition: chained_done.transition,
                provided_blobs: chained_done.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut repeated_message = vec![vos::value::TAG_DYNAMIC];
    repeated_message.extend_from_slice(&Msg::new("call_child_repeatedly").encode());
    let repeated = LocalWorkScheduler::prepare(
        restarted.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([90; 32]),
            workflow_step: 0,
            logical_timeslot: 10,
            target: seed.target,
            method: "call_child_repeatedly".into(),
            arguments: repeated_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let locked = LocalWorkScheduler::prepare(
        restarted.accumulate_host(),
        LocalWorkRequest {
            invocation: locked_invocation,
            workflow_step: 0,
            logical_timeslot: 11,
            target: seed.target,
            method: "root_child_then_sibling".into(),
            arguments: locked_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: locked.work,
                transition: locked_wait.transition,
                provided_blobs: locked_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let sibling_invocation = InvocationId([94; 32]);
    let mut sibling_message = vec![vos::value::TAG_DYNAMIC];
    sibling_message.extend_from_slice(&Msg::new("child_await_peer").encode());
    let sibling_work = LocalWorkScheduler::prepare(
        restarted.accumulate_host(),
        LocalWorkRequest {
            invocation: sibling_invocation,
            workflow_step: 0,
            logical_timeslot: 12,
            target: sibling,
            method: "child_await_peer".into(),
            arguments: sibling_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: sibling_work.work,
                transition: sibling_wait.transition,
                provided_blobs: sibling_wait.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let locked_reply = peer_reply(&seed.service, locked_call, 2, 95);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: locked_reply.receipt.clone(),
        });
    let locked_resume = LocalWorkScheduler::prepare_resume(
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: locked_resume.work,
                transition: locked_done.transition,
                provided_blobs: locked_done.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn private_actor_input_is_bounded_before_entering_the_compact_guest_heap() {
    let actor_elf = greeter_elf();
    let actor = vos_pvm_compiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = vec![0; vos::service::ACTOR_SLICE_INPUT_MAX_BYTES];
    let state = BlobRef::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImports {
        programs: vec![ImportedProgram {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlob {
            reference: state,
            bytes: state_bytes,
        }],
        private_blobs: vec![],
    };
    let service = ServicePvm::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
    )
    .expect("canonical service program");

    assert_eq!(
        service.refine_actor_tree(&work.encode(), &imports, 10_000_000, &NoRefineProtocolHost,),
        Err(ServicePvmError::ActorInputTooLarge)
    );
}

#[test]
fn same_tree_causal_cycles_return_an_explicit_guest_error() {
    let actor_pvm = vos_pvm_compiler::link_elf(&cycle_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let child = ActorId([36; 32]);

    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![
            ActorGenesis {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "root_cycle".into(),
                        schema: Hash([81; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "root_forbidden".into(),
                        schema: Hash([86; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesis {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "child_cycle".into(),
                        schema: Hash([82; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "member_only".into(),
                        schema: Hash([87; 32]),
                        policy: space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap(),
                        public: false,
                        attested: false,
                        space_role: Some(vos::SpaceRole::Member.as_u8()),
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
        ],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([83; 32]),
            authenticator: vec![84],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Installed(_)
    ));

    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("root_cycle").encode());
    let scheduled = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([85; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed.target,
            method: "root_cycle".into(),
            arguments: message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: scheduled.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("root_forbidden").encode());
    let scheduled = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([88; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: seed.target,
            method: "root_forbidden".into(),
            arguments: message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: scheduled.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn canonical_crdt_slice_refines_and_accumulates_without_native_apply() {
    let service_elf = service_elf();
    let actor_elf = crdt_counter_elf();
    let service_pvm = vos::service::transpile_service_elf(&service_elf).unwrap();
    let actor_pvm = vos_pvm_compiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let mut work = work(actor_program, initial.clone());
    work.method = "increment".into();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("increment").with("amount", 2u64).encode());
    work.arguments = message;
    work.consistency = ConsistencyMode::Crdt;
    work.base = ConsistencyBase::Crdt { heads: vec![] };
    work.base_causal_height = Some(0);

    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: work.service.clone(),
        consistency: ConsistencyMode::Crdt,
        actors: vec![ActorGenesis {
            actor: work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: true,
            role_policies: role_policies(vec![MethodPolicy {
                method: "increment".into(),
                schema: Hash([44; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([46; 32]),
            authenticator: vec![1],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Installed(_)
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
        LocalWorkScheduler::prepare_direct_ingress(
            service.accumulate_host(),
            &service_identity,
            request,
        )
        .unwrap()
    });
    for ingress in ingresses {
        assert!(matches!(
            service
                .accumulate(&AccumulateRequest::AdmitIngress(ingress))
                .unwrap()
                .result,
            AccumulationResult::IngressAdmitted {
                duplicate: false,
                ..
            }
        ));
    }
    let scheduled = LocalWorkScheduler::prepare(service.accumulate_host(), first_request)
        .expect("scheduler imports the authenticated CRDT ingress frontier");
    let right_scheduled = LocalWorkScheduler::prepare(service.accumulate_host(), right_request)
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
    let apply = AccumulateRequest::Apply(AccumulationEnvelope {
        work: work.clone(),
        transition: refined.transition.clone(),
        provided_blobs: refined.exported_blobs.clone(),
    });
    let applied = service.accumulate(&apply).unwrap().result;
    let AccumulationResult::Accepted {
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
    let mut replica_host = MemoryServiceStore::default();
    assert_eq!(replica_host.import_blob(initial_bytes), initial);
    assert_eq!(replica_host.import_program(actor_pvm), actor_program);
    let mut replica = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        replica_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let AccumulateRequest::Install(genesis) = &install else {
        unreachable!()
    };
    replica.accumulate_host_mut().allow_install(genesis);
    assert!(matches!(
        replica.accumulate(&install).unwrap().result,
        AccumulationResult::Installed(_)
    ));
    let sync_envelope = LocalWorkScheduler::prepare_crdt_sync(service.accumulate_host())
        .expect("source scheduler exports the authenticated causal DAG");
    for node in &sync_envelope.nodes {
        replica
            .accumulate_host_mut()
            .allow_receipt(&ReceiptVerificationRequest {
                expected_producer: node.change.expected_producer().unwrap(),
                receipt: node.receipt.clone(),
            });
    }
    let sync = AccumulateRequest::SyncCrdt(sync_envelope);
    let synced = replica.accumulate(&sync).unwrap().result;
    assert!(matches!(
        synced,
        AccumulationResult::Accepted {
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
    let AccumulationResult::Accepted {
        published,
        duplicate,
        ..
    } = duplicate
    else {
        panic!("CRDT retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffects::default());

    // Refine the other admitted invocation from the same causal base after
    // the first branch has committed. CRDT Accumulate preserves both heads.
    let right_refined = service
        .refine_actor_tree(&right_scheduled.work, &right_scheduled.imports)
        .unwrap();
    let right_cid = right_refined.transition.crdt_change.as_ref().unwrap().cid();
    let right = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: right_scheduled.work,
            transition: right_refined.transition.clone(),
            provided_blobs: right_refined.exported_blobs.clone(),
        }))
        .unwrap()
        .result;
    let AccumulationResult::Accepted { receipt, .. } = right else {
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
        LocalWorkRequest {
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
    let ConsistencyBase::Crdt { heads: merge_heads } = &merge_work.base else {
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: merge_work,
            transition: merged.transition,
            provided_blobs: merged.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResult::Accepted { receipt, .. } = accepted else {
        panic!("merged CRDT child rejected")
    };
    assert_eq!(receipt.resulting_crdt_heads, vec![merged_cid]);

    let admission_request = LocalWorkRequest {
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
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let admission = LocalWorkScheduler::prepare_direct_ingress(
        service.accumulate_host(),
        &work.service,
        &admission_request,
    )
    .expect("scheduler binds direct ingress to the current causal frontier");
    let admission_cid = admission.crdt_change.as_ref().unwrap().cid();
    let admitted = service
        .accumulate(&AccumulateRequest::AdmitIngress(admission))
        .unwrap()
        .result;
    assert!(matches!(
        admitted,
        AccumulationResult::IngressAdmitted {
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

    let sync = LocalWorkScheduler::prepare_crdt_sync(service.accumulate_host())
        .expect("the exported DAG includes the causal ingress admission");
    for node in &sync.nodes {
        replica
            .accumulate_host_mut()
            .allow_receipt(&ReceiptVerificationRequest {
                expected_producer: node.change.expected_producer().unwrap(),
                receipt: node.receipt.clone(),
            });
    }
    let synced = replica
        .accumulate(&AccumulateRequest::SyncCrdt(sync))
        .unwrap()
        .result;
    assert!(matches!(
        synced,
        AccumulationResult::Accepted {
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
    let actor_elf = crdt_counter_elf();
    let actor_pvm = vos_pvm_compiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let child = ActorId([36; 32]);

    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = ServiceRuntime::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![private_age_binding(&seed.service)],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Crdt,
        actors: vec![
            ActorGenesis {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: true,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "increment".into(),
                        schema: Hash([49; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "increment_child_twice".into(),
                        schema: Hash([50; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "call_yielding_child".into(),
                        schema: Hash([55; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "increment_child_around_peer".into(),
                        schema: Hash([57; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "increment_peer_then_yield".into(),
                        schema: Hash([67; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesis {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: true,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "increment".into(),
                        schema: Hash([51; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "increment_around_yield".into(),
                        schema: Hash([56; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "increment_around_peer".into(),
                        schema: Hash([58; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
        ],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([52; 32]),
            authenticator: vec![1],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Installed(_)
    ));

    let missing_workflow = InvocationId([73; 32]);
    assert_eq!(
        LocalWorkScheduler::prepare(
            service.accumulate_host(),
            LocalWorkRequest {
                invocation: missing_workflow,
                workflow_step: 1,
                logical_timeslot: 1,
                target: seed.target,
                method: "increment".into(),
                arguments: vec![],
                origin: Origin::Anonymous,
                authorization: AuthorizationEvidence::Public,
                causal_parent: None,
                parent_call: None,
                causal_context: None,
                awaited_reply: None,
                awaited_timeout: None,
                imported_blobs: vec![],
                proof_requested: false,
            },
        ),
        Err(ScheduleError::InvalidWorkflowStep(missing_workflow)),
        "a direct CRDT resume without a committed workflow row fails closed"
    );

    let request = |invocation, timeslot, method: &str| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new(method).with("amount", 3u64).encode());
        LocalWorkRequest {
            invocation,
            workflow_step: 0,
            logical_timeslot: timeslot,
            target: seed.target,
            method: method.into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let runner = ServicePvm::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::service::VOS_SERVICE_PROGRAM_ID,
    )
    .unwrap();
    let interpreted = runner
        .refine_actor_tree_with_backend(
            &first.work.encode(),
            &first.imports,
            1_000_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        runner
            .refine_actor_tree_with_backend(
                &first.work.encode(),
                &first.imports,
                1_000_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: first.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
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
    let around_request = LocalWorkRequest {
        invocation: InvocationId([59; 32]),
        workflow_step: 0,
        logical_timeslot: 3,
        target: seed.target,
        method: "increment_child_around_peer".into(),
        arguments: around_arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
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
    let concurrent_request = LocalWorkRequest {
        invocation: InvocationId([60; 32]),
        workflow_step: 0,
        logical_timeslot: 3,
        target: seed.target,
        method: "increment".into(),
        arguments: concurrent_arguments,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
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
        LocalWorkScheduler::prepare_direct_ingress(
            service.accumulate_host(),
            &service_identity,
            request,
        )
        .unwrap()
    });
    for ingress in ingresses {
        assert!(matches!(
            service
                .accumulate(&AccumulateRequest::AdmitIngress(ingress))
                .unwrap()
                .result,
            AccumulationResult::IngressAdmitted {
                duplicate: false,
                ..
            }
        ));
    }
    let around = LocalWorkScheduler::prepare(service.accumulate_host(), around_request).unwrap();
    let concurrent =
        LocalWorkScheduler::prepare(service.accumulate_host(), concurrent_request).unwrap();
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: around.work.clone(),
            transition: around_refined.transition,
            provided_blobs: around_refined.exported_blobs,
        }))
        .unwrap()
        .result;
    assert!(matches!(
        checkpoint_apply,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    let concurrent_apply = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: concurrent.work,
            transition: concurrent_refined.transition,
            provided_blobs: concurrent_refined.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResult::Accepted { receipt, .. } = &concurrent_apply else {
        panic!("concurrent CRDT branch was rejected: {concurrent_apply:?}")
    };
    let mut concurrent_heads = vec![checkpoint_cid, concurrent_cid];
    concurrent_heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, concurrent_heads);

    let reply = ReplyRecord {
        call_id: pending_call,
        producer: ActorId([44; 32]),
        result: Value::U32(0).encode(),
    };
    let remote_service = bound_peer_service(&around.work.service);
    let awaited = AccumulatedReply {
        receipt: AccumulationReceipt {
            service: remote_service,
            accepted_transition: Hash([64; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([65; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply,
        attestation: None,
    };
    service
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: awaited.receipt.clone(),
        });
    let resumed = LocalWorkScheduler::prepare_resume(
        service.accumulate_host(),
        around.work.invocation,
        4,
        Some(awaited),
    )
    .expect("CRDT resume selects only the checkpoint's causal branch");
    assert_eq!(
        resumed.work.base,
        ConsistencyBase::Crdt {
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
            .contains(&WorkflowOperation::ConsumeOutbox(pending_call))
    );
    assert_eq!(resumed_change.operations.len(), 2);
    let resumed_operation_scope = CrdtChange::derive_operation_scope(&resumed.work).unwrap();
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: resumed.work,
            transition: resumed_refined.transition,
            provided_blobs: resumed_refined.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResult::Accepted { receipt, .. } = resumed_apply else {
        panic!("resumed CRDT transition was rejected: {resumed_apply:?}")
    };
    let mut final_heads = vec![concurrent_cid, resumed_cid];
    final_heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, final_heads);

    let mut merged_arguments = vec![vos::value::TAG_DYNAMIC];
    merged_arguments.extend_from_slice(&Msg::new("increment").with("amount", 1u64).encode());
    let merged = admit_and_prepare(
        &mut service,
        LocalWorkRequest {
            invocation: InvocationId([66; 32]),
            workflow_step: 0,
            logical_timeslot: 5,
            target: seed.target,
            method: "increment".into(),
            arguments: merged_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        LocalWorkRequest {
            invocation: InvocationId([68; 32]),
            workflow_step: 0,
            logical_timeslot: 6,
            target: seed.target,
            method: "increment_peer_then_yield".into(),
            arguments: yield_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: await_then_yield.work.clone(),
                transition: awaiting.transition,
                provided_blobs: awaiting.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let reply = ReplyRecord {
        call_id: first_call,
        producer: ActorId([44; 32]),
        result: Value::U32(0).encode(),
    };
    let remote_service = bound_peer_service(&await_then_yield.work.service);
    let awaited = AccumulatedReply {
        receipt: AccumulationReceipt {
            service: remote_service,
            accepted_transition: Hash([71; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([72; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply,
        attestation: None,
    };
    service
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: ActorId([44; 32]),
            receipt: awaited.receipt.clone(),
        });
    let resumed = LocalWorkScheduler::prepare_resume(
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
            .contains(&WorkflowOperation::ConsumeOutbox(first_call))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: resumed.work,
                transition: yielded.transition,
                provided_blobs: yielded.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn canonical_crdt_resume_rebinds_the_post_await_change_identity() {
    let service_elf = service_elf();
    let actor_elf = crdt_counter_elf();
    let service_pvm = vos::service::transpile_service_elf(&service_elf).unwrap();
    let actor_pvm = vos_pvm_compiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
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
    first_work.consistency = ConsistencyMode::Crdt;
    first_work.base = ConsistencyBase::Crdt { heads: vec![] };
    first_work.base_causal_height = Some(0);

    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: first_work.service.clone(),
        consistency: ConsistencyMode::Crdt,
        actors: vec![ActorGenesis {
            actor: first_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial,
            crdt: true,
            role_policies: role_policies(vec![MethodPolicy {
                method: "increment_around_yield".into(),
                schema: Hash([50; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([52; 32]),
            authenticator: vec![1],
        },
    });
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Installed(_)
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: first_work.clone(),
            transition: first.transition,
            provided_blobs: first.exported_blobs.clone(),
        }))
        .unwrap()
        .result;
    assert!(
        matches!(
            first_result,
            AccumulationResult::Accepted {
                duplicate: false,
                ..
            }
        ),
        "first CRDT accumulation result: {first_result:?}"
    );

    let mut second_work = first_work;
    second_work.workflow_step = 1;
    second_work.base = ConsistencyBase::Crdt {
        heads: vec![first_cid],
    };
    second_work.base_causal_height = Some(first_change_height);
    second_work.imported_actors[0].state = state;
    second_work.imported_actors[0].continuation = Some(continuation);
    let second_imports = RefineImports {
        programs: vec![ImportedProgram {
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
    let second_operation_scope = CrdtChange::derive_operation_scope(&second_work).unwrap();
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: second_work,
            transition: second.transition,
            provided_blobs: second.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResult::Accepted { receipt, .. } = accepted else {
        panic!("resumed CRDT slice rejected: {accepted:?}")
    };
    assert_eq!(receipt.resulting_crdt_heads, vec![second_cid]);
}

#[test]
fn canonical_guest_rejects_a_nested_actor_without_the_reply_abi() {
    let elf = service_elf();
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvm::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRef::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImports {
        programs: vec![ImportedProgram {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlob {
            reference: state,
            bytes: state_bytes,
        }],
        private_blobs: vec![],
    };

    assert!(matches!(
        service.refine_actor_tree(&work.encode(), &imports, 10_000_000, &NoRefineProtocolHost,),
        Err(ServicePvmError::Panic { .. })
    ));
}

#[test]
fn actor_tree_refuses_to_replay_a_continuation_from_pc_zero() {
    let elf = service_elf();
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvm::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRef::of_bytes(&state_bytes);
    let continuation_bytes = b"portable-kernel-snapshot".to_vec();
    let continuation = BlobRef::of_bytes(&continuation_bytes);
    let mut work = work(actor_program, state.clone());
    work.imported_actors[0].continuation = Some(continuation.clone());
    let mut blobs = vec![
        ImportedBlob {
            reference: state,
            bytes: state_bytes,
        },
        ImportedBlob {
            reference: continuation,
            bytes: continuation_bytes,
        },
    ];
    blobs.sort_by_key(|blob| blob.reference.hash);
    let imports = RefineImports {
        programs: vec![ImportedProgram {
            program: actor_program,
            pvm: actor,
        }],
        blobs,
        private_blobs: vec![],
    };

    assert_eq!(
        service.refine_actor_tree(&work.encode(), &imports, 10_000_000, &NoRefineProtocolHost,),
        Err(ServicePvmError::InvalidContinuation)
    );
}

#[test]
fn yielding_actor_restores_exactly_from_committed_snapshot() {
    let service_elf = service_elf();
    let actor_elf = probe_elf();
    let service_pvm = vos::service::transpile_service_elf(&service_elf).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvm::new(service_pvm.clone(), service_program).unwrap();
    let actor = vos_pvm_compiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRef::of_bytes(&initial_state);
    let mut first_work = work(actor_program, initial_state_ref.clone());
    let mut ping = vec![vos::value::TAG_DYNAMIC];
    ping.extend_from_slice(&Msg::new("ping").encode());
    first_work.method = "ping".into();
    first_work.arguments = ping;
    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
    assert_eq!(host.import_program(actor.clone()), actor_program);
    let mut committed = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: first_work.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: first_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial_state_ref.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "ping".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    authorize_install(&mut committed, &install);
    let installed = committed.accumulate(&install).unwrap();
    let AccumulationResult::Installed(installed) = installed.result else {
        panic!("guest install rejected")
    };
    let request = LocalWorkRequest {
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
    let prepared = LocalWorkScheduler::prepare(committed.accumulate_host(), request.clone())
        .expect("scheduler reconstructs initial work from guest-owned state");
    first_work = prepared.work;
    let first_imports = prepared.imports;
    admit_linear_work(&mut committed, &first_work);
    assert_eq!(
        first_work.base,
        ConsistencyBase::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        }
    );

    let first_output = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    let deterministic_retry = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(
        recompiled_first, first_output,
        "interpreter and recompiler checkpoints must be identical"
    );
    let refined_first = RefineOutput::decode(&first_output.bytes).unwrap();
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
    let checkpoint_request = AccumulateRequest::Apply(AccumulationEnvelope {
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
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .expect("the canonical Accumulate guest runs in the interpreter");
    let recompiled_accumulate = service
        .accumulate_with_backend(
            &checkpoint_request.encode(),
            5_000_000_000,
            &mut recompiled_host,
            vos_pvm::PvmBackend::ForceRecompiler,
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
    let AccumulationResult::Accepted {
        receipt: checkpoint_receipt,
        published,
        duplicate,
    } = checkpoint_outcome.result
    else {
        panic!("guest rejected the transition emitted by its own Refine entry")
    };
    assert!(!duplicate);
    assert!(published.reply.is_none());
    let checkpoint_state_ref = BlobRef::of_bytes(&checkpoint_state);
    assert_eq!(
        committed.accumulate_host().blob(&checkpoint_state_ref),
        Some(checkpoint_state.as_slice()),
        "guest Accumulate must durably record the checkpoint state"
    );

    // Reconstruct the runtime from an in-memory committed snapshot after
    // Accumulate commits slice 0. The scheduler must recover the exact program,
    // actor state, and continuation rather than use this test's local values.
    let reopened = MemoryServiceStore::from_snapshot(committed.accumulate_host().snapshot());
    let mut resume_request = request;
    resume_request.workflow_step = 1;
    let mut changed_identity = resume_request.clone();
    changed_identity.origin = Origin::System;
    assert_eq!(
        LocalWorkScheduler::prepare(&reopened, changed_identity),
        Err(ScheduleError::InvalidWorkflowStep(first_work.invocation)),
        "a continuation cannot resume under a different caller identity"
    );
    let mut alternate_arguments = resume_request.clone();
    alternate_arguments.arguments = b"ignored resume arguments".to_vec();
    let alternate = LocalWorkScheduler::prepare(&reopened, alternate_arguments)
        .expect("dead resume arguments are canonicalized");
    let prepared = LocalWorkScheduler::prepare(&reopened, resume_request)
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
        ConsistencyBase::Linear {
            revision: checkpoint_receipt.sequence,
            state_root: checkpoint_receipt.resulting_state_root.unwrap(),
        }
    );
    assert_eq!(resumed_work.imported_actors[0].state, checkpoint_state_ref);
    assert_eq!(
        resumed_work.imported_actors[0].continuation,
        Some(first_continuation.clone())
    );
    let mut committed = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    let recompiled_resumed = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(
        recompiled_resumed, resumed_output,
        "interpreter and recompiler resumes must be identical"
    );
    let refined_resumed = RefineOutput::decode(&resumed_output.bytes).unwrap();
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: resumed_work,
            transition: resumed.clone(),
            provided_blobs: resumed_candidate_blobs,
        }))
        .unwrap();
    let AccumulationResult::Accepted {
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
    let resumed_state_ref = BlobRef::of_bytes(resumed_state);
    assert_eq!(
        committed.accumulate_host().blob(&resumed_state_ref),
        Some(resumed_state.as_slice())
    );
}

#[test]
fn awaited_reply_is_injected_at_the_exact_machine_boundary() {
    let service_pvm = vos::service::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvm::new(service_pvm.clone(), service_program).unwrap();
    let actor_elf = probe_elf();
    let actor = vos_pvm_compiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRef::of_bytes(&initial_state);
    let mut seed_work = work(actor_program, initial_state_ref.clone());
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer").encode());
    seed_work.method = "await_peer".into();
    seed_work.arguments = arguments;

    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_state), initial_state_ref);
    assert_eq!(host.import_program(actor), actor_program);
    let mut committed = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install_request = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![private_age_binding(&seed_work.service)],
        service: seed_work.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial_state_ref,
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "await_peer".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    authorize_install(&mut committed, &install_request);
    let install = committed.accumulate(&install_request).unwrap();
    assert!(matches!(install.result, AccumulationResult::Installed(_)));
    let request = LocalWorkRequest {
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
    let prepared = LocalWorkScheduler::prepare(committed.accumulate_host(), request.clone())
        .expect("scheduler reconstructs the initial actor slice");
    let first_work = prepared.work;
    let first_imports = prepared.imports;
    admit_linear_work(&mut committed, &first_work);

    let first_output = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &first_work.encode(),
                &first_imports,
                100_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        first_output,
        "both PVM backends must capture the same awaited-call boundary"
    );
    let first = RefineOutput::decode(&first_output.bytes)
        .unwrap()
        .transition;
    assert!(first.reply.is_none());
    assert_eq!(first.outbox.len(), 1);
    let call_id = first_work.invocation.call_id(0);
    assert_eq!(first.outbox[0].call_id, call_id);
    assert_eq!(first.outbox[0].to, ActorId([44; 32]));
    assert_eq!(first.outbox[0].deadline_timeslot, Some(100));
    let first_continuation = first.continuations[0].replacement.clone().unwrap();
    let continuation = ContinuationSnapshot::decode(&first_output.exported_blobs[0].bytes)
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

    let refined_first = RefineOutput::decode(&first_output.bytes).unwrap();
    let mut first_candidate_blobs = refined_first.candidate_blobs;
    first_candidate_blobs.extend(first_output.exported_blobs.clone());
    first_candidate_blobs.sort_by_key(|blob| blob.reference.hash);
    first_candidate_blobs.dedup();
    let checkpointed = committed
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: first_work.clone(),
            transition: first,
            provided_blobs: first_candidate_blobs,
        }))
        .expect("checkpoint and durable outbox commit atomically");
    assert!(matches!(
        checkpointed.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    let checkpoint_state_ref = BlobRef::of_bytes(&checkpoint_state);

    // Fork from the committed checkpoint and prove that timeout is itself a
    // durable guest transition before the exact machine is restored. A crash
    // at either boundary must not replay code before `.await`.
    let persisted_checkpoint = committed.accumulate_host().snapshot_bytes();
    let timeout_store = MemoryServiceStore::from_snapshot_bytes(&persisted_checkpoint)
        .expect("the checkpoint image starts an independent timeout branch");
    let timeout_runtime = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        timeout_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let timeout_follower_store = MemoryServiceStore::from_snapshot_bytes(&persisted_checkpoint)
        .expect("the follower starts from the identical checkpoint image");
    let timeout_follower_runtime = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        timeout_follower_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let timeout_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut timeout_service = ReplicatedServiceRuntime::new(
        timeout_runtime,
        TestCommittedLog::new(timeout_log.clone(), true),
    );
    let mut timeout_follower = ReplicatedServiceRuntime::new(
        timeout_follower_runtime,
        TestCommittedLog::new(timeout_log, false),
    );
    assert!(
        LocalWorkScheduler::prepare_due_call_expirations(
            timeout_service.service().accumulate_host(),
            99,
        )
        .unwrap()
        .is_empty(),
        "a logical timeslot before the deadline cannot expire the call"
    );
    let due = LocalWorkScheduler::prepare_due_call_expirations(
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
            .accumulate(&AccumulateRequest::ExpireCall(expiration.clone()))
            .unwrap_err(),
        ReplicatedServiceError::LogicalTimeslotRequired
    ));
    assert_eq!(timeout_service.log().committed_len(), 0);
    assert_eq!(
        timeout_service.service().accumulate_host().snapshot(),
        before_untrusted_expiration
    );
    let expired = timeout_service
        .accumulate_at(&AccumulateRequest::ExpireCall(expiration), 100)
        .expect("the Raft entry and physical guest Accumulate commit the timeout");
    assert_eq!(timeout_follower.catch_up().unwrap(), 1);
    assert!(
        timeout_service
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&timeout_follower.service().accumulate_host().snapshot()),
        "the follower replays the committed ambient service platform slot through IC-5"
    );
    let AccumulationResult::CallExpired {
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
    let timeout_restarted_store = MemoryServiceStore::from_snapshot_bytes(&timeout_persisted)
        .expect("the expiration outcome survives a second process restart");
    let mut timeout_restarted_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        timeout_restarted_store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    assert_eq!(
        LocalWorkScheduler::pending_timeout_resumes(timeout_restarted_service.accumulate_host()),
        Ok(vec![first_work.invocation]),
        "expiration outcomes remain enumerable after their deadline rows are gone"
    );
    let timed_out = LocalWorkScheduler::prepare_timeout_resume(
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .expect("the interpreter injects the committed timeout");
    let recompiled_timeout = service
        .refine_actor_tree_with_backend(
            &timed_out.work.encode(),
            &timed_out.imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceRecompiler,
        )
        .expect("the recompiler injects the same committed timeout");
    assert_eq!(timed_out_output, recompiled_timeout);

    // A different runnable actor may have spawned a child while this kernel
    // was suspended. The current work import must include the complete newer
    // directory, while PVM restoration still uses only the exact dormant
    // program layout captured by the continuation.
    let mut expanded = timed_out.clone();
    // Sort before the existing target to prove current directory order does
    // not renumber the VMs captured by the older continuation.
    let new_child = ActorId([3; 32]);
    let new_child_state_bytes = b"late child state".to_vec();
    let new_child_state = BlobRef::of_bytes(&new_child_state_bytes);
    expanded
        .work
        .imported_actors
        .push(vos::service::ImportedActor {
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
    expanded.imports.blobs.push(ImportedBlob {
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .expect("a newer tree directory does not rewrite the suspended PVM layout");
    assert_eq!(expanded_timeout.bytes, timed_out_output.bytes);
    assert_eq!(
        expanded_timeout.exported_blobs,
        timed_out_output.exported_blobs
    );
    assert_eq!(expanded_timeout.trace, timed_out_output.trace);

    let timed_out_refined = RefineOutput::decode(&timed_out_output.bytes).unwrap();
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: timed_out_work,
            transition: timed_out_transition,
            provided_blobs: timed_out_refined.candidate_blobs,
        }))
        .expect("guest Accumulate accepts only the committed timeout outcome");
    assert!(matches!(
        completed_timeout.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        LocalWorkScheduler::prepare_timeout_resume(
            timeout_restarted_service.accumulate_host(),
            first_work.invocation,
            101,
        ),
        Ok(None),
        "the completed continuation cannot consume the timeout twice"
    );
    assert!(
        LocalWorkScheduler::pending_timeout_resumes(timeout_restarted_service.accumulate_host())
            .unwrap()
            .is_empty(),
        "historical expiration rows do not requeue a completed workflow"
    );

    // Reconstruct the service from committed state before the peer reply
    // arrives. No live handler future or warm actor VM survives this boundary.
    let reopened = MemoryServiceStore::from_snapshot(committed.accumulate_host().snapshot());

    let reply = ReplyRecord {
        call_id,
        producer: ActorId([44; 32]),
        result: vos::value::Value::U32(7).encode(),
    };
    let mut remote_service = first_work.service.clone();
    remote_service.root_service = RootServiceId([45; 32]);
    remote_service.deployment = DeploymentId([46; 32]);
    let awaited_reply = AccumulatedReply {
        receipt: AccumulationReceipt {
            service: remote_service,
            accepted_transition: Hash([47; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([48; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply,
        attestation: None,
    };
    let mut resume_request = request;
    resume_request.workflow_step = 1;
    resume_request.logical_timeslot = 2;
    resume_request.awaited_reply = Some(awaited_reply.clone());
    let prepared = LocalWorkScheduler::prepare(&reopened, resume_request)
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        ),
        Err(ServicePvmError::ContinuationMismatch),
        "a different accumulated CallId cannot resume this machine"
    );

    let resumed_output = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &resumed_work.encode(),
                &resumed_imports,
                100_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        resumed_output,
        "both PVM backends must inject the same reply into the same snapshot"
    );
    let mut committed = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .expect("reopened state drives the same canonical service PVM");
    let resumed = RefineOutput::decode(&resumed_output.bytes)
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
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: awaited_reply.reply.producer,
            receipt: awaited_reply.receipt,
        });
    let completed = committed
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: resumed_work,
            transition: resumed.clone(),
            provided_blobs: vec![],
        }))
        .expect("guest Accumulate accepts the exact injected reply");
    let AccumulationResult::Accepted {
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
            .state_row(header.service_root, &StateKey::Outbox(call_id))
            .unwrap(),
        None,
        "reply commit consumes the exact pending outbox"
    );
}

#[test]
fn durable_inbox_work_survives_two_exact_awaits_and_two_restarts() {
    let service_pvm = vos::service::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvm::new(service_pvm.clone(), service_program).unwrap();
    let actor = vos_pvm_compiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRef::of_bytes(&initial_state);
    let identity = work(actor_program, initial_state_ref.clone()).service;
    let caller = ActorId([4; 32]);
    let target = ActorId([5; 32]);
    let mut first_remote_service = identity.clone();
    first_remote_service.root_service = RootServiceId([70; 32]);
    first_remote_service.deployment = DeploymentId([71; 32]);
    let mut second_remote_service = identity.clone();
    second_remote_service.root_service = RootServiceId([74; 32]);
    second_remote_service.deployment = DeploymentId([75; 32]);

    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_state), initial_state_ref);
    assert_eq!(host.import_program(actor), actor_program);
    let mut committed = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install_request = AccumulateRequest::Install(ServiceGenesis {
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
        consistency: ConsistencyMode::Local,
        actors: vec![
            ActorGenesis {
                actor: caller,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial_state_ref.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicy {
                    method: "seed".into(),
                    schema: Hash([31; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                }]),
            },
            ActorGenesis {
                actor: target,
                name: "child".into(),
                parent: Some(caller),
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial_state_ref,
                crdt: false,
                role_policies: role_policies(vec![MethodPolicy {
                    method: "await_two_peers".into(),
                    schema: Hash([33; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                }]),
            },
        ],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([35; 32]),
            authenticator: vec![36],
        },
    });
    authorize_install(&mut committed, &install_request);
    let installed = committed.accumulate(&install_request).unwrap();
    assert!(matches!(installed.result, AccumulationResult::Installed(_)));

    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&Msg::new("await_two_peers").encode());
    let caller_invocation = InvocationId([60; 32]);
    let inbound_call = caller_invocation.call_id(0);
    let inbound = MessageRecord {
        call_id: inbound_call,
        caller_invocation,
        await_ordinal: 0,
        from_service: identity.clone(),
        from: caller,
        to_service: identity.clone(),
        to: target,
        parent: None,
        payload: payload.clone(),
        authorization: AuthorizationEvidence::Public,
        proof_requested: false,
        deadline_timeslot: Some(200),
    };
    let mut seed_payload = vec![vos::value::TAG_DYNAMIC];
    seed_payload.extend_from_slice(&Msg::new("seed").encode());
    let seed_request = LocalWorkRequest {
        invocation: InvocationId([61; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: caller,
        method: "seed".into(),
        arguments: seed_payload,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let seeded = LocalWorkScheduler::prepare(committed.accumulate_host(), seed_request).unwrap();
    admit_linear_work(&mut committed, &seeded.work);
    let seed_transition = Transition {
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
        gas: GasAccounting::default(),
        proof: None,
    };
    let seeded = committed
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: seeded.work,
            transition: seed_transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    assert!(matches!(
        seeded.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let initial = LocalWorkScheduler::prepare_inbox(committed.accumulate_host(), inbound_call, 2)
        .expect("committed inbox reconstructs the initial callee slice");
    assert_eq!(
        initial.work.causal_context,
        Some(vos::service::CausalCallContext::from(&inbound))
    );
    let initial_output = service
        .refine_actor_tree_with_backend(
            &initial.work.encode(),
            &initial.imports,
            100_000_000,
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &initial.work.encode(),
                &initial.imports,
                100_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        initial_output
    );
    let initial_refined = RefineOutput::decode(&initial_output.bytes).unwrap();
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
    let first_snapshot = ContinuationSnapshot::decode(
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: initial.work.clone(),
            transition: initial_transition,
            provided_blobs: first_blobs,
        }))
        .unwrap();
    assert!(matches!(
        checkpointed.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKey::Inbox(inbound_call))
            .unwrap(),
        None,
        "step 0 consumes the only live copy of the inbound inbox row"
    );

    // A timeout may resume directly into another await. The new checkpoint
    // must consume call 0 and publish call 1 in the same guest transaction;
    // tying consumption to handler completion would wedge this saga.
    let timeout_branch =
        MemoryServiceStore::from_snapshot_bytes(&committed.accumulate_host().snapshot_bytes())
            .unwrap();
    let mut timeout_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        timeout_branch,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let expiration = LocalWorkScheduler::prepare_call_expiration(
        timeout_service.accumulate_host(),
        initial.work.invocation,
        100,
    )
    .unwrap()
    .expect("the first peer call is due");
    assert!(matches!(
        timeout_service
            .accumulate_at(&AccumulateRequest::ExpireCall(expiration), 100)
            .unwrap()
            .result,
        AccumulationResult::CallExpired {
            duplicate: false,
            ..
        }
    ));
    let mut timeout_resume = LocalWorkScheduler::prepare_timeout_resume(
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        ) {
            Ok(output) => break output,
            Err(ServicePvmError::ActorStorageWitnessRequired(requests)) => {
                LocalWorkScheduler::hydrate_actor_storage_rows(
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
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        timeout_output
    );
    let timeout_refined = RefineOutput::decode(&timeout_output.bytes).unwrap();
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: timeout_resume.work,
            transition: timeout_transition,
            provided_blobs: timeout_blobs,
        }))
        .expect("timeout resume atomically replaces the awaited checkpoint");
    assert!(
        matches!(
            timeout_checkpoint.result,
            AccumulationResult::Accepted {
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
            .state_row(timeout_header.service_root, &StateKey::Outbox(first_call))
            .unwrap(),
        None
    );
    assert!(
        timeout_service
            .accumulate_host()
            .state_row(
                timeout_header.service_root,
                &StateKey::Outbox(second_timeout_call),
            )
            .unwrap()
            .is_some()
    );

    let first_reply = ReplyRecord {
        call_id: first_call,
        producer: ActorId([44; 32]),
        result: vos::value::Value::U32(7).encode(),
    };
    let first_awaited = AccumulatedReply {
        receipt: AccumulationReceipt {
            service: first_remote_service,
            accepted_transition: Hash([72; 32]),
            reply_commitment: Some(first_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([73; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply: first_reply,
        attestation: None,
    };

    let reopened = MemoryServiceStore::from_snapshot(committed.accumulate_host().snapshot());
    assert_eq!(
        LocalWorkScheduler::prepare_resume(&reopened, initial.work.invocation, 3, None),
        Err(ScheduleError::MissingAwaitedReply(first_call))
    );
    assert_eq!(
        LocalWorkScheduler::prepare_resume(
            &reopened,
            initial.work.invocation,
            200,
            Some(first_awaited.clone()),
        ),
        Err(ScheduleError::DeadlineExpired(inbound_call))
    );
    let mut wrong_first_reply = first_awaited.clone();
    wrong_first_reply.reply.call_id = InvocationId([78; 32]).call_id(0);
    wrong_first_reply.receipt.reply_commitment = Some(wrong_first_reply.reply.commitment());
    assert_eq!(
        LocalWorkScheduler::prepare_resume(
            &reopened,
            initial.work.invocation,
            3,
            Some(wrong_first_reply.clone()),
        ),
        Err(ScheduleError::UnexpectedAwaitedReply(
            wrong_first_reply.reply.call_id
        ))
    );
    let mut first_resume = LocalWorkScheduler::prepare_resume(
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
    let expired_resume_transition = Transition {
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
        gas: GasAccounting::default(),
        proof: None,
    };
    let before_expired_resume = committed.accumulate_host().snapshot();
    let expired_resume = committed
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: expired_resume_work,
            transition: expired_resume_transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    assert_eq!(
        expired_resume.result,
        AccumulationResult::Rejected(
            vos::service::AccumulationRejection::InvalidWorkflowTransition
        )
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        ) {
            Ok(output) => break output,
            Err(ServicePvmError::ActorStorageWitnessRequired(requests)) => {
                LocalWorkScheduler::hydrate_actor_storage_rows(
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
        vos::service::MAX_ACTOR_STORAGE_WITNESSES,
    );
    assert!(
        first_resume.work.encode().len() > vos::service::CHECKPOINT_TOKEN_CAPACITY,
        "the physical resume must exceed the old inline-token capacity"
    );
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &first_resume.work.encode(),
                &first_resume.imports,
                100_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        first_resumed_output
    );
    let first_resumed_refined = RefineOutput::decode(&first_resumed_output.bytes).unwrap();
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
    let second_snapshot = ContinuationSnapshot::decode(
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
    let mut committed = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    committed
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: first_awaited.reply.producer,
            receipt: first_awaited.receipt,
        });
    let second_checkpoint = committed
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: first_resume.work,
            transition: first_resumed_transition,
            provided_blobs: first_resume_blobs,
        }))
        .expect("retained causal context validates await 2 after inbox consumption");
    assert!(matches!(
        second_checkpoint.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKey::Outbox(first_call))
            .unwrap(),
        None
    );
    assert!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKey::Outbox(second_call))
            .unwrap()
            .is_some()
    );

    let second_reply = ReplyRecord {
        call_id: second_call,
        producer: ActorId([45; 32]),
        result: vos::value::Value::U32(5).encode(),
    };
    let second_awaited = AccumulatedReply {
        receipt: AccumulationReceipt {
            service: second_remote_service,
            accepted_transition: Hash([76; 32]),
            reply_commitment: Some(second_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([77; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply: second_reply,
        attestation: None,
    };

    let reopened = MemoryServiceStore::from_snapshot(committed.accumulate_host().snapshot());
    let second_resume = LocalWorkScheduler::prepare_resume(
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
            &NoRefineProtocolHost,
            vos_pvm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &second_resume.work.encode(),
                &second_resume.imports,
                100_000_000,
                &NoRefineProtocolHost,
                vos_pvm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        completed_output
    );
    let completed_refined = RefineOutput::decode(&completed_output.bytes).unwrap();
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

    let mut committed = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        reopened,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    committed
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: second_awaited.reply.producer,
            receipt: second_awaited.receipt,
        });
    let completed = committed
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: second_resume.work,
            transition: completed_transition,
            provided_blobs: completed_refined.candidate_blobs,
        }))
        .unwrap();
    assert!(matches!(
        completed.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    let header = committed.accumulate_host().header().unwrap().unwrap();
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKey::Outbox(second_call))
            .unwrap(),
        None
    );
    assert_eq!(
        committed
            .accumulate_host()
            .state_row(header.service_root, &StateKey::Continuation(target))
            .unwrap(),
        None
    );
}

#[test]
fn canonical_guest_accumulate_installs_applies_and_deduplicates_at_ic5() {
    let elf = service_elf();
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = b"canonical actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
    assert_eq!(host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = ServiceRuntime::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();

    let mut wrong_refine_service = seed_work.clone();
    wrong_refine_service.service.service_program = ProgramId([3; 32]);
    assert_eq!(
        service.refine_actor_tree(&wrong_refine_service, &RefineImports::default()),
        Err(ServiceDispatchError::ServiceProgramMismatch {
            expected: vos::service::VOS_SERVICE_PROGRAM_ID,
            declared: ProgramId([3; 32]),
        }),
        "platform dispatch must bind work to the PVM executing Refine"
    );

    let child = ActorId([36; 32]);
    let peer = ActorId([81; 32]);
    let mut remote_service = seed_work.service.clone();
    remote_service.root_service = RootServiceId([82; 32]);
    remote_service.deployment = DeploymentId([83; 32]);
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![external_binding(
            "peer-81",
            remote_service.clone(),
            peer,
            ProducerId([81; 32]),
            actor_program,
        )],
        service: seed_work.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![
            ActorGenesis {
                actor: seed_work.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: DeploymentId([2; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![
                    MethodPolicy {
                        method: "start".into(),
                        schema: Hash([32; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                    MethodPolicy {
                        method: "attested-start".into(),
                        schema: Hash([32; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: true,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    },
                ]),
            },
            ActorGenesis {
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
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    let mut wrong_service_program = install.clone();
    let AccumulateRequest::Install(wrong_genesis) = &mut wrong_service_program else {
        unreachable!()
    };
    wrong_genesis.service.service_program = ProgramId([3; 32]);
    authorize_install(&mut service, &wrong_service_program);
    assert_eq!(
        service.accumulate(&wrong_service_program),
        Err(ServiceDispatchError::ServiceProgramMismatch {
            expected: vos::service::VOS_SERVICE_PROGRAM_ID,
            declared: ProgramId([3; 32]),
        }),
        "platform dispatch must bind genesis to the PVM executing Accumulate"
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);

    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized)
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
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized),
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
    let AccumulateRequest::Install(tampered_genesis) = &mut tampered_install else {
        unreachable!()
    };
    let AuthorizationEvidence::SystemCapability { authenticator, .. } =
        &mut tampered_genesis.authorization
    else {
        unreachable!()
    };
    authenticator.push(99);
    assert_eq!(
        service.accumulate(&tampered_install).unwrap().result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized),
        "authorization is bound to every exact genesis byte"
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);

    let installed_output = service
        .accumulate(&install)
        .expect("guest install completes");
    let AccumulationResult::Installed(installed) = installed_output.result else {
        panic!("guest install rejected")
    };
    assert_eq!(service.accumulate_host().commit_sequence(), 1);
    let installed_rows = service.accumulate_host().row_count();

    let request = LocalWorkRequest {
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
    let prepared = LocalWorkScheduler::prepare(service.accumulate_host(), request.clone())
        .expect("scheduler reads the installed guest state");
    assert_eq!(prepared.work.service, seed_work.service);
    assert_eq!(prepared.work.target_program, actor_program);
    assert_eq!(
        prepared.work.base,
        ConsistencyBase::Linear {
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
    let continuation = ContinuationSnapshot {
        service: work.service.clone(),
        invocation: work.invocation,
        checkpoint_step: 0,
        actor: work.target,
        actor_deployment: work.target_deployment,
        actor_program,
        programs: work
            .imported_actors
            .iter()
            .map(|actor| vos::service::ContinuationProgram {
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
    let continuation_ref = BlobRef::of_bytes(&continuation_bytes);
    let caller_invocation = InvocationId([70; 32]);
    let call_id = caller_invocation.call_id(0);
    let inbox = MessageRecord {
        call_id,
        caller_invocation,
        await_ordinal: 0,
        from_service: work.service.clone(),
        from: work.target,
        to_service: work.service.clone(),
        to: work.target,
        parent: None,
        payload: work.arguments.clone(),
        authorization: AuthorizationEvidence::Public,
        proof_requested: false,
        deadline_timeslot: Some(100),
    };
    let transition = Transition {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_deployment: work.target_deployment,
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWrite {
            actor: work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"committed actor state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChange {
            actor: work.target,
            expected: None,
            replacement: Some(continuation_ref.clone()),
        }],
        inbox: vec![inbox.clone()],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![continuation_ref.clone()],
        gas: GasAccounting::default(),
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
    proof_transition.reply = Some(ReplyRecord {
        call_id: proof_work.invocation.root_reply_id(),
        producer: proof_work.target,
        result: b"attested result".to_vec(),
    });
    let proof_host = MemoryServiceStore::from_snapshot(service.accumulate_host().snapshot());
    let mut proof_service = ServiceRuntime::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHost,
        proof_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    admit_linear_work(&mut proof_service, &proof_work);
    let before_prepare = proof_service.accumulate_host().snapshot();
    let commit_sequence_before_prepare = proof_service.accumulate_host().commit_sequence();
    let prepared_attestation = proof_service
        .accumulate(&AccumulateRequest::PrepareAttested(AccumulationEnvelope {
            work: proof_work.clone(),
            transition: proof_transition.clone(),
            provided_blobs: vec![],
        }))
        .expect("guest predicts the attested receipt without committing");
    let AccumulationResult::Prepared(preparation) = prepared_attestation.result else {
        panic!("guest did not prepare the attested transition")
    };
    assert_eq!(
        preparation.receipt.accepted_transition,
        proof_transition.commitment()
    );
    assert_eq!(preparation.receipt.sequence, 1);
    assert_eq!(
        preparation,
        vos::service::AttestationPreparation::for_transition(
            &proof_work,
            &proof_transition,
            &MethodPolicy {
                method: proof_work.method.clone(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: true,
                space_role: None,
                capability: None,
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

    let apply = AccumulateRequest::Apply(AccumulationEnvelope {
        work: work.clone(),
        transition: transition.clone(),
        provided_blobs: vec![ImportedBlob {
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
            ServicePvmError::AccumulateCommitRejected
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
    let AccumulationResult::Accepted {
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
    let committed_state = BlobRef::of_bytes(b"committed actor state");
    assert_eq!(
        service.accumulate_host().blob(&committed_state),
        Some(b"committed actor state".as_slice())
    );

    let snapshot_after_apply = service.accumulate_host().snapshot();
    let duplicate_output = service.accumulate(&apply).expect("guest retry completes");
    let AccumulationResult::Accepted {
        published,
        duplicate,
        ..
    } = duplicate_output.result
    else {
        panic!("guest retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffects::default());
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
    let reopened = MemoryServiceStore::from_snapshot_bytes(&persisted)
        .expect("canonical guest state survives a process-style restart");
    assert_eq!(
        LocalWorkScheduler::prepare_inbox(&reopened, call_id, 50),
        Err(ScheduleError::ActorBusy(work.target))
    );
    assert_eq!(
        LocalWorkScheduler::prepare_inbox(&reopened, call_id, 100),
        Err(ScheduleError::DeadlineExpired(call_id))
    );
    let mut queued = request.clone();
    queued.invocation = InvocationId([99; 32]);
    assert_eq!(
        LocalWorkScheduler::prepare(&reopened, queued),
        Err(ScheduleError::ActorBusy(work.target))
    );

    let mut resume = request;
    resume.workflow_step = 1;
    let resumed = LocalWorkScheduler::prepare(&reopened, resume)
        .expect("snapshot reconstructs the next exact continuation slice");
    assert_eq!(
        resumed.work.base,
        ConsistencyBase::Linear {
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

    let resumed_transition = Transition {
        service: resumed.work.service.clone(),
        consumed_input: resumed.work.input_id(),
        target_deployment: resumed.work.target_deployment,
        target_program: resumed.work.target_program,
        base: resumed.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChange {
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
        gas: GasAccounting::default(),
        proof: None,
    };
    let completed = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: resumed.work,
            transition: resumed_transition,
            provided_blobs: vec![],
        }))
        .unwrap()
        .result;
    assert!(matches!(completed, AccumulationResult::Accepted { .. }));

    let delivered = LocalWorkScheduler::prepare_inbox(service.accumulate_host(), call_id, 50)
        .expect("queued inbox becomes runnable only after the actor is idle");
    assert_eq!(delivered.work.invocation, InvocationId::for_call(call_id));
    assert_eq!(delivered.work.parent_call, Some(call_id));
    assert_eq!(delivered.work.causal_parent, Some(caller_invocation));
    assert_eq!(delivered.work.origin, Origin::Actor(inbox.from));
    assert_eq!(delivered.work.authorization, inbox.authorization);

    let mut expired_work = delivered.work.clone();
    expired_work.logical_timeslot = 100;
    let expired_transition = Transition {
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
        reply: Some(ReplyRecord {
            call_id,
            producer: expired_work.target,
            result: b"expired".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    let before_expired = service.accumulate_host().snapshot();
    let expired = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: expired_work,
            transition: expired_transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    assert_eq!(
        expired.result,
        AccumulationResult::Rejected(
            vos::service::AccumulationRejection::InvalidWorkflowTransition
        )
    );
    assert_eq!(service.accumulate_host().snapshot(), before_expired);

    let delivery_continuation = ContinuationSnapshot {
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
            .map(|actor| vos::service::ContinuationProgram {
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
    let delivery_continuation_ref = BlobRef::of_bytes(&delivery_continuation_bytes);
    let delivery_checkpoint = Transition {
        service: delivered.work.service.clone(),
        consumed_input: delivered.work.input_id(),
        target_deployment: delivered.work.target_deployment,
        target_program: delivered.work.target_program,
        base: delivered.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChange {
            actor: delivered.work.target,
            expected: None,
            replacement: Some(delivery_continuation_ref.clone()),
        }],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![delivery_continuation_ref.clone()],
        gas: GasAccounting::default(),
        proof: None,
    };
    let checkpointed = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: delivered.work.clone(),
            transition: delivery_checkpoint,
            provided_blobs: vec![ImportedBlob {
                reference: delivery_continuation_ref,
                bytes: delivery_continuation_bytes,
            }],
        }))
        .expect("guest atomically consumes the inbox and checkpoints the callee");
    assert!(matches!(
        checkpointed.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        LocalWorkScheduler::prepare_inbox(service.accumulate_host(), call_id, 51),
        Err(ScheduleError::MissingInbox(call_id))
    );

    let delivery_request = LocalWorkRequest {
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
    let delivery_resume = LocalWorkScheduler::prepare(service.accumulate_host(), delivery_request)
        .expect("callee resumes from workflow state after its inbox was consumed");
    assert!(delivery_resume.work.arguments.is_empty());
    let delivery_reply = ReplyRecord {
        call_id,
        producer: delivery_resume.work.target,
        result: b"durable inbox reply".to_vec(),
    };
    let delivery_completion = Transition {
        service: delivery_resume.work.service.clone(),
        consumed_input: delivery_resume.work.input_id(),
        target_deployment: delivery_resume.work.target_deployment,
        target_program: delivery_resume.work.target_program,
        base: delivery_resume.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChange {
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
        gas: GasAccounting::default(),
        proof: None,
    };
    let delivery_apply = AccumulateRequest::Apply(AccumulationEnvelope {
        work: delivery_resume.work,
        transition: delivery_completion,
        provided_blobs: vec![],
    });
    let delivered_result = service
        .accumulate(&delivery_apply)
        .expect("guest commits the resumed callee reply");
    let AccumulationResult::Accepted {
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
    let AccumulationResult::Accepted {
        receipt: duplicate_receipt,
        published: duplicate_published,
        duplicate: true,
    } = duplicate_delivery.result
    else {
        panic!("guest did not deduplicate the resumed callee")
    };
    assert_eq!(duplicate_receipt, receipt);
    assert_eq!(duplicate_published, PublishedEffects::default());

    let caller_request = LocalWorkRequest {
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
    let caller = LocalWorkScheduler::prepare(service.accumulate_host(), caller_request)
        .expect("idle caller is schedulable");
    admit_linear_work(&mut service, &caller.work);
    let awaited_call = caller.work.invocation.call_id(0);
    let continuation_bytes = ContinuationSnapshot {
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
            .map(|actor| vos::service::ContinuationProgram {
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
    let continuation = BlobRef::of_bytes(&continuation_bytes);
    let outbound = MessageRecord {
        call_id: awaited_call,
        caller_invocation: caller.work.invocation,
        await_ordinal: 0,
        from_service: caller.work.service.clone(),
        from: caller.work.target,
        to_service: remote_service.clone(),
        to: peer,
        parent: None,
        payload: caller.work.arguments.clone(),
        authorization: AuthorizationEvidence::Public,
        proof_requested: false,
        deadline_timeslot: Some(90),
    };
    let checkpoint = Transition {
        service: caller.work.service.clone(),
        consumed_input: caller.work.input_id(),
        target_deployment: caller.work.target_deployment,
        target_program: caller.work.target_program,
        base: caller.work.base.clone(),
        writes: vec![ActorWrite {
            actor: caller.work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"awaiting reply state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChange {
            actor: caller.work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        }],
        inbox: vec![],
        outbox: vec![outbound],
        reply: None,
        exported_blobs: vec![continuation.clone()],
        gas: GasAccounting::default(),
        proof: None,
    };
    let checkpointed = service
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: caller.work.clone(),
            transition: checkpoint,
            provided_blobs: vec![ImportedBlob {
                reference: continuation.clone(),
                bytes: continuation_bytes,
            }],
        }))
        .expect("guest commits the pending call and caller continuation");
    let AccumulationResult::Accepted {
        receipt: checkpoint_receipt,
        duplicate: false,
        ..
    } = checkpointed.result
    else {
        panic!("guest rejected the pending call")
    };

    let remote_reply = ReplyRecord {
        call_id: awaited_call,
        producer: peer,
        result: b"remote result".to_vec(),
    };
    let awaited = AccumulatedReply {
        receipt: AccumulationReceipt {
            service: remote_service,
            accepted_transition: Hash([84; 32]),
            reply_commitment: Some(remote_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([85; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        },
        reply: remote_reply,
        attestation: None,
    };
    let resume_request = LocalWorkRequest {
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
    let resume = LocalWorkScheduler::prepare(service.accumulate_host(), resume_request)
        .expect("scheduler binds the accumulated reply to the exact continuation");
    let before_resume_header = service.accumulate_host().header().unwrap().unwrap();
    let persisted_outbox = MessageRecord::decode(
        &service
            .accumulate_host()
            .state_row(
                before_resume_header.service_root,
                &StateKey::Outbox(awaited_call),
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
    assert_eq!(awaited.receipt.service.platform, vos::service::PLATFORM_ID);
    assert_eq!(
        awaited.receipt.service.execution_semantics,
        vos::service::EXECUTION_SEMANTICS_ID
    );
    assert_ne!(
        awaited.receipt.service.root_service,
        resume.work.service.root_service
    );
    let completion = Transition {
        service: resume.work.service.clone(),
        consumed_input: resume.work.input_id(),
        target_deployment: resume.work.target_deployment,
        target_program: resume.work.target_program,
        base: resume.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![ContinuationChange {
            actor: resume.work.target,
            expected: Some(continuation.hash),
            replacement: None,
        }],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    let apply_reply = AccumulateRequest::Apply(AccumulationEnvelope {
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
        AccumulationResult::Rejected(vos::service::AccumulationRejection::ReceiptUnavailable)
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
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: awaited.reply.producer,
            receipt: awaited.receipt,
        });
    let accepted = service
        .accumulate(&apply_reply)
        .expect("finalized reply resumes through physical guest Accumulate");
    let AccumulationResult::Accepted {
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
            .state_row(header.service_root, &StateKey::Outbox(awaited_call))
            .unwrap(),
        None,
        "accepted reply consumes the pending outbox atomically"
    );
    assert_eq!(
        service
            .accumulate(&apply_reply)
            .expect("exact reply retry resolves through work dedup")
            .result,
        AccumulationResult::Accepted {
            receipt: accepted_receipt,
            published: PublishedEffects::default(),
            duplicate: true,
        }
    );
    assert_eq!(checkpoint_receipt.sequence + 1, header.revision);
}

#[test]
fn physical_guest_accumulate_upgrades_only_an_idle_authorized_actor() {
    let elf = service_elf();
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let initial_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&initial_pvm);
    let replacement_pvm = actor_pvm(1);
    let replacement_program = ProgramId::of_pvm(&replacement_pvm);
    let initial_bytes = b"state survives upgrade".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;

    let mut store = DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
    assert_eq!(store.import_blob(initial_bytes), initial);
    assert_eq!(store.import_program(initial_pvm.clone()), actor_program);
    let mut service = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        store,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        service: seed.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([31; 32]),
            deployment: seed.target_deployment,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        external_actors: vec![],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([33; 32]),
            authenticator: vec![34],
        },
    });
    let AccumulateRequest::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
    let AccumulationResult::Installed(installed) = service.accumulate(&install).unwrap().result
    else {
        panic!("service install rejected")
    };
    let upgrade = ActorUpgrade {
        service: seed.service.clone(),
        actor: seed.target,
        expected_deployment: seed.target_deployment,
        expected_program: actor_program,
        replacement_deployment: DeploymentId([37; 32]),
        replacement_program,
        producer: ProducerId([35; 32]),
        role_policies: role_policies(vec![MethodPolicy {
            method: "next".into(),
            schema: Hash([36; 32]),
            policy: public_policy_hash(),
            public: true,
            attested: false,
            space_role: None,
            capability: None,
            actor_role: None,
        }]),
        base: ConsistencyBase::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        },
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([37; 32]),
            authenticator: vec![38],
        },
    };
    let upgrade_programs = vec![ImportedProgram {
        program: replacement_program,
        pvm: replacement_pvm.clone(),
    }];
    let before = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate_with_availability(
                &AccumulateRequest::UpgradeActor(upgrade.clone()),
                &upgrade_programs,
                &[],
            )
            .unwrap()
            .result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized)
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
            &AccumulateRequest::UpgradeActor(upgrade.clone()),
            &upgrade_programs,
            &[],
        ),
        Err(ServiceDispatchError::Pvm(
            ServicePvmError::AccumulateCommitRejected
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
            &AccumulateRequest::UpgradeActor(upgrade.clone()),
            &upgrade_programs,
            &[],
        )
        .unwrap();
    let AccumulationResult::ActorUpgraded {
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

    let prepared = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([39; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: seed.target,
            method: "next".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
                &AccumulateRequest::UpgradeActor(upgrade),
                &upgrade_programs,
                &[],
            )
            .unwrap()
            .result,
        AccumulationResult::ActorUpgraded {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(service.accumulate_host().snapshot(), before_retry);
}

#[test]
fn disclosed_role_credentials_require_authority_verification_in_physical_accumulate() {
    let elf = service_elf();

    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = b"canonical role-gated actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"role-gated initial state".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let mut work = work(actor_program, initial.clone());
    work.service.service_program = service_program;
    let origin = Origin::Member(SubjectId([0x81; 32]));
    work.origin = origin;
    let policy = space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap();

    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: work.service.clone(),
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: work.method.clone(),
                schema: Hash([0x82; 32]),
                policy,
                public: false,
                attested: false,
                space_role: Some(vos::SpaceRole::Member.as_u8()),
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([0x83; 32]),
            authenticator: vec![0x84],
        },
    };
    let install = AccumulateRequest::Install(genesis);
    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    authorize_install(&mut service, &install);
    let AccumulationResult::Installed(installed) = service.accumulate(&install).unwrap().result
    else {
        panic!("role-gated service install failed")
    };
    work.base = ConsistencyBase::Linear {
        revision: 0,
        state_root: installed.resulting_state_root.unwrap(),
    };
    let credential = RoleCredential {
        holder: origin,
        scope: work.authorization_scope(),
        space_role: Some(vos::SpaceRole::Developer),
        capability: None,
        actor_role: None,
        authenticator: b"authority signature over exact work scope".to_vec(),
    };
    work.authorization = credential.disclosed_evidence(policy);
    let transition = Transition {
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
        reply: Some(ReplyRecord {
            call_id: work.invocation.root_reply_id(),
            producer: work.target,
            result: b"authorized".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    let apply = AccumulateRequest::Apply(AccumulationEnvelope {
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
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before)
    );

    let mut malformed_resume = work.clone();
    malformed_resume.workflow_step = 1;
    malformed_resume.authorization = RoleCredential {
        holder: origin,
        scope: Hash::ZERO,
        space_role: Some(vos::SpaceRole::Developer),
        capability: None,
        actor_role: None,
        authenticator: b"malformed authority grant".to_vec(),
    }
    .disclosed_evidence(policy);
    let malformed_transition = Transition {
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
        reply: Some(ReplyRecord {
            call_id: malformed_resume.invocation.root_reply_id(),
            producer: malformed_resume.target,
            result: b"must not execute".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    let before_malformed = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: malformed_resume,
                transition: malformed_transition,
                provided_blobs: vec![],
            }))
            .expect("malformed credential is a guest rejection, not a dispatch error")
            .result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::Unauthorized)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_malformed)
    );

    let verification = RoleCredentialVerificationRequest::for_work(&work).unwrap();
    service
        .accumulate_host_mut()
        .allow_role_credential(&verification);
    admit_linear_work(&mut service, &work);
    assert!(matches!(
        service.accumulate(&apply).unwrap().result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn attested_driver_rejects_a_transition_not_produced_by_exact_refine() {
    let elf = service_elf();
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = vos_pvm_compiler::link_elf(&greeter_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;
    let private_origin = Origin::Member(SubjectId([0xA7; 32]));
    seed.origin = private_origin;
    seed.proof_requested = true;
    let private_policy = space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap();
    let private_credential = RoleCredential {
        holder: private_origin,
        scope: seed.authorization_scope(),
        space_role: Some(vos::SpaceRole::Developer),
        capability: None,
        actor_role: None,
        authenticator: b"authenticated private role grant".to_vec(),
    };
    let (private_authorization, private_witness) =
        private_credential.private_evidence(private_policy);

    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: seed.method.clone(),
                schema: Hash([0xA1; 32]),
                policy: private_policy,
                public: false,
                attested: true,
                space_role: Some(vos::SpaceRole::Member.as_u8()),
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([0xA3; 32]),
            authenticator: vec![0xA4],
        },
    };
    let install = AccumulateRequest::Install(genesis);
    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(
        host.import_private_witness(private_witness.bytes.clone()),
        private_witness.reference
    );
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    authorize_install(&mut service, &install);
    let AccumulationResult::Installed(installed) = service.accumulate(&install).unwrap().result
    else {
        panic!("attested service install failed")
    };
    let installed_blob_count = service.accumulate_host().blob_count();

    let prepared = LocalWorkScheduler::prepare(
        service.accumulate_host(),
        LocalWorkRequest {
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
        ConsistencyBase::Linear {
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
    let genuine = AccumulationEnvelope {
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
        Err(vos::service::AttestedServiceError::InvalidProducedProof)
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
        Err(vos::service::AttestedServiceError::InvalidPreparation)
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
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_program = ProgramId::of_pvm(b"canonical actor bytes not imported into the service");
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    let mut service = ServiceRuntime::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed_work.service,
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial,
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([32; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    };

    let install = AccumulateRequest::Install(genesis);
    authorize_install(&mut service, &install);
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::WrongProgram)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
}

#[test]
fn physical_guest_rejects_the_missing_preimage_length_sentinel() {
    let elf = service_elf();
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = b"available canonical actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let seed_work = work(
        actor_program,
        BlobRef {
            hash: Hash([30; 32]),
            len: u64::MAX,
        },
    );
    let mut host = MemoryServiceStore::default();
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = ServiceRuntime::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed_work.service,
        consistency: ConsistencyMode::Local,
        actors: vec![ActorGenesis {
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
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([31; 32]),
            authenticator: vec![32],
        },
    };

    let install = AccumulateRequest::Install(genesis);
    authorize_install(&mut service, &install);
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::NonCanonical)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
    assert_eq!(service.accumulate_host().blob_count(), 0);
}

#[test]
fn attested_cross_root_transport_proves_and_resumes_the_bound_package() {
    let actor_pvm = vos_pvm_compiler::link_elf(&workflow_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let service_program = vos::service::VOS_SERVICE_PROGRAM_ID;
    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([201; 32]),
        root_service: RootServiceId([202; 32]),
        deployment: DeploymentId([203; 32]),
        service_program,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        root_service: RootServiceId([204; 32]),
        deployment: DeploymentId([205; 32]),
        ..source_identity.clone()
    };
    let source_actor = ActorId([5; 32]);
    let destination_actor = ActorId([44; 32]);
    let destination_producer = ProducerId([98; 32]);

    let install_service = |identity: ServiceIdentity,
                           actor: ActorId,
                           name: &str,
                           method: &str,
                           attested: bool,
                           producer: ProducerId,
                           external_actors: Vec<ExternalActorBinding>| {
        let mut host = DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
        assert_eq!(host.import_blob(initial_bytes.clone()), initial);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = ServiceRuntime::new(
            CANONICAL_SERVICE_PVM.to_vec(),
            service_program,
            NoRefineProtocolHost,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        let install = AccumulateRequest::Install(ServiceGenesis {
            role_authority: None,
            external_actors,
            service: identity.clone(),
            consistency: ConsistencyMode::Local,
            actors: vec![ActorGenesis {
                actor,
                name: name.into(),
                parent: None,
                producer,
                deployment: identity.deployment,
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicy {
                    method: method.into(),
                    schema: Hash([206; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                }]),
            }],
            authorization: AuthorizationEvidence::SystemCapability {
                capability: vos::service::SystemCapabilityId([207; 32]),
                authenticator: vec![208],
            },
        });
        authorize_install(&mut service, &install);
        assert!(matches!(
            service.accumulate(&install).unwrap().result,
            AccumulationResult::Installed(_)
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
    let prepared = LocalWorkScheduler::prepare(
        source.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([209; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_actor,
            method: "root_await_attested_peer".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let source_publication = LocalTransport::pending_publications(&source)
        .unwrap()
        .pop()
        .unwrap();
    LocalTransport::deliver(&source, &mut destination, &source_publication, call, 2).unwrap();
    let before_mismatched_trace = destination.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransport::drain_pending_attested(
            &mut destination,
            3,
            &mut MismatchedTraceProofProducer,
        ),
        Err(vos::service::AttestedTransportError::Attested(
            vos::service::AttestedServiceError::InvalidProducedProof
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
        LocalTransport::drain_pending_attested(&mut destination, 3, &mut proof_producer).unwrap();
    let [InboxDrainOutcome::Committed(committed)] = drained.as_slice() else {
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
    let reply_publication = LocalTransport::pending_publications(&destination)
        .unwrap()
        .pop()
        .unwrap();
    let resumed =
        LocalTransport::resume_reply(&destination, &mut source, &reply_publication, 4).unwrap();
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
    let service_pvm = vos::service::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = vos_pvm_compiler::link_elf(&crdt_counter_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRef::of_bytes(&initial_state);
    let identity = ServiceIdentity {
        space: vos::service::SpaceId([0xD1; 32]),
        root_service: RootServiceId([0xD2; 32]),
        deployment: DeploymentId([0xD3; 32]),
        service_program,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let actor = ActorId([0xD4; 32]);
    let install = AccumulateRequest::Install(ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: identity.clone(),
        consistency: ConsistencyMode::Crdt,
        actors: vec![ActorGenesis {
            actor,
            name: "root".into(),
            parent: None,
            producer: ProducerId([0xD5; 32]),
            deployment: identity.deployment,
            program: actor_program,
            initial_state: initial_state_ref.clone(),
            crdt: true,
            role_policies: role_policies(vec![MethodPolicy {
                method: "inc".into(),
                schema: Hash([0xD6; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0xD7; 32]),
            authenticator: vec![0xD8],
        },
    });
    let open = || {
        let mut host = DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
        assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = ServiceRuntime::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHost,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        authorize_install(&mut service, &install);
        assert!(matches!(
            service.accumulate(&install).unwrap().result,
            AccumulationResult::Installed(_)
        ));
        service
    };
    let mut destination = open();
    let replica = open();
    let source = ServiceIdentity {
        root_service: RootServiceId([0xD9; 32]),
        deployment: DeploymentId([0xDA; 32]),
        ..identity.clone()
    };
    let sender = ActorId([0xDB; 32]);
    let invocation = InvocationId([0xDC; 32]);
    let message = MessageRecord {
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
        authorization: AuthorizationEvidence::Public,
        proof_requested: false,
        deadline_timeslot: Some(100),
    };
    let source_receipt = AccumulationReceipt {
        service: source,
        accepted_transition: Hash([0xDD; 32]),
        reply_commitment: None,
        outbox_commitment: MessageRecord::outbox_commitment(core::slice::from_ref(&message)),
        resulting_state_root: Some(Hash([0xDE; 32])),
        resulting_crdt_heads: vec![],
        sequence: 1,
        checkpoint: 0,
        consistency: ConsistencyMode::Local,
    };
    destination
        .accumulate_host_mut()
        .local_store_mut()
        .allow_receipt(&ReceiptVerificationRequest {
            expected_producer: sender,
            receipt: source_receipt.clone(),
        });
    let delivery = LocalWorkScheduler::prepare_delivery(
        destination.accumulate_host().local_store(),
        2,
        message.clone(),
        vec![message.clone()],
        source_receipt,
    )
    .unwrap();
    let AccumulationResult::Accepted {
        receipt: delivery_receipt,
        duplicate: false,
        ..
    } = destination
        .accumulate(&AccumulateRequest::Deliver(delivery))
        .unwrap()
        .result
    else {
        panic!("physical CRDT delivery was rejected")
    };
    assert_eq!(delivery_receipt.consistency, ConsistencyMode::Crdt);
    assert_eq!(delivery_receipt.resulting_crdt_heads.len(), 1);

    let sync =
        LocalWorkScheduler::prepare_crdt_sync(destination.accumulate_host().local_store()).unwrap();
    let mut replica = restart_durable_service(replica, &service_pvm, service_program);
    for node in &sync.nodes {
        replica
            .accumulate_host_mut()
            .local_store_mut()
            .allow_receipt(&ReceiptVerificationRequest {
                expected_producer: actor,
                receipt: node.receipt.clone(),
            });
    }
    assert!(matches!(
        replica
            .accumulate(&AccumulateRequest::SyncCrdt(sync))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
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
    let service_pvm = vos::service::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = vos_pvm_compiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRef::of_bytes(&initial_state);

    let install_service = |identity: ServiceIdentity,
                           actor: ActorId,
                           method: &str,
                           external_actors: Vec<ExternalActorBinding>| {
        let mut host = DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
        assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = ServiceRuntime::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHost,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        let install = AccumulateRequest::Install(ServiceGenesis {
            role_authority: None,
            external_actors,
            service: identity.clone(),
            consistency: ConsistencyMode::Local,
            actors: vec![ActorGenesis {
                actor,
                name: "root".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                deployment: identity.deployment,
                program: actor_program,
                initial_state: initial_state_ref.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicy {
                    method: method.into(),
                    schema: Hash([91; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                }]),
            }],
            authorization: AuthorizationEvidence::SystemCapability {
                capability: vos::service::SystemCapabilityId([93; 32]),
                authenticator: vec![94],
            },
        });
        authorize_install(&mut service, &install);
        let installed = service.accumulate(&install).unwrap();
        assert!(matches!(installed.result, AccumulationResult::Installed(_)));
        service
    };

    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([79; 32]),
        root_service: RootServiceId([80; 32]),
        deployment: DeploymentId([81; 32]),
        service_program,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
        space: vos::service::SpaceId([79; 32]),
        root_service: RootServiceId([82; 32]),
        deployment: DeploymentId([83; 32]),
        service_program,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
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
    let impostor_identity = ServiceIdentity {
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
    let source_work = LocalWorkScheduler::prepare(
        source.accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([84; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_actor,
            method: "await_storage_peer".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: source_work.work,
            transition: refined.transition,
            provided_blobs: refined.exported_blobs,
        }))
        .unwrap();
    assert!(matches!(
        source_result.result,
        AccumulationResult::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut source = restart_durable_service(source, &service_pvm, service_program);
    let publications = LocalTransport::pending_publications(&source).unwrap();
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
        !LocalTransport::deliver(&source, &mut expiring_destination, &publication, call, 99,)
            .unwrap()
            .duplicate
    );
    let mut expiring_destination =
        restart_durable_service(expiring_destination, &service_pvm, service_program);
    let retired = LocalTransport::drain_pending(&mut expiring_destination, 100).unwrap();
    assert!(matches!(
        retired.as_slice(),
        [InboxDrainOutcome::Retired {
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
        LocalTransport::deliver(&source, &mut expiring_destination, &publication, call, 99,)
            .unwrap()
            .duplicate,
        "retirement keeps the permanent delivery identity for lost acknowledgements"
    );

    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    let mut impostor = restart_durable_service(impostor, &service_pvm, service_program);
    let before_impostor = impostor.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransport::deliver(&source, &mut impostor, &publication, call, 2),
        Err(vos::service::LocalTransportError::Rejected(
            vos::service::AccumulationRejection::WrongService
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
        LocalTransport::deliver(&source, &mut destination, &forged_publication, call, 2,),
        Err(vos::service::LocalTransportError::NonCanonicalPublication)
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
        LocalTransport::deliver(&source, &mut destination, &publication, call, 2),
        Err(vos::service::LocalTransportError::Service(
            ServiceDispatchError::Pvm(ServicePvmError::AccumulateCommitRejected)
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
        LocalTransport::deliver(&source, &mut destination, &publication, call, 2).unwrap();
    assert!(!delivery.duplicate);
    assert_eq!(
        destination.accumulate_host().pending_inbox_calls().unwrap(),
        vec![(call, 2)]
    );

    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    let before_regressed_timeslot = destination.accumulate_host().snapshot();
    assert!(matches!(
        LocalTransport::drain_pending(&mut destination, 2),
        Err(vos::service::LocalTransportError::TimeslotNotAfterAdmission {
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

    let drained = LocalTransport::drain_pending(&mut destination, 3).unwrap();
    let [InboxDrainOutcome::Committed(committed)] = drained.as_slice() else {
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
    let destination_publications = LocalTransport::pending_publications(&destination).unwrap();
    assert_eq!(destination_publications.len(), 1);
    assert_eq!(
        destination_publications[0].published.reply,
        Some(reply.clone())
    );
    let reply_publication = destination_publications[0].clone();

    let retry = LocalTransport::deliver(&source, &mut destination, &publication, call, 2).unwrap();
    assert!(
        retry.duplicate,
        "the stable delivery identity survives destination base advancement"
    );

    assert!(!LocalTransport::acknowledge(&mut source, &publication).unwrap());
    assert!(
        LocalTransport::pending_publications(&source)
            .unwrap()
            .is_empty()
    );
    let source_header = source.accumulate_host().header().unwrap().unwrap();
    assert!(
        source
            .accumulate_host()
            .state_row(source_header.service_root, &StateKey::Outbox(call))
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
        LocalTransport::resume_reply(&destination, &mut source, &forged_reply_publication, 4,),
        Err(vos::service::LocalTransportError::NonCanonicalPublication)
    ));
    assert!(
        source
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_forged_reply)
    );

    let before_expired_reply = source.accumulate_host().snapshot();
    let expired_reply =
        LocalTransport::resume_reply(&destination, &mut source, &reply_publication, 100);
    assert!(
        matches!(
            &expired_reply,
            Err(vos::service::LocalTransportError::Schedule(
                ScheduleError::DeadlineExpired(expired_call)
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
        LocalTransport::resume_reply(&destination, &mut source, &reply_publication, 4),
        Err(vos::service::LocalTransportError::Service(
            ServiceDispatchError::Pvm(ServicePvmError::AccumulateCommitRejected)
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
        LocalTransport::resume_reply(&destination, &mut source, &reply_publication, 4).unwrap();
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
        CommittedServiceSnapshot::decode(
            &CommittedServiceSnapshot {
                applied_index: 1,
                service_image: source.accumulate_host().committed_service_image(),
                proof_artifacts: vec![],
                result_artifacts: vec![],
                host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
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
            .state_row(source_header.service_root, &StateKey::Outbox(call))
            .unwrap()
            .is_none(),
        "the reply route is consumed atomically with the exact resume"
    );
    let caller_publications = LocalTransport::pending_publications(&source).unwrap();
    assert_eq!(caller_publications.len(), 1);
    assert_eq!(caller_publications[0].published, resumed.published);

    // Lose the transport acknowledgement and restart both roots again. The
    // permanent guest-owned admission row, not the latest workflow row,
    // classifies an exact retry even at a different transport timeslot.
    let mut source = restart_durable_service(source, &service_pvm, service_program);
    let mut destination = restart_durable_service(destination, &service_pvm, service_program);
    let before_reply_retry = source.accumulate_host().snapshot();
    let reply_retry =
        LocalTransport::resume_reply(&destination, &mut source, &reply_publication, 5).unwrap();
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

    assert!(!LocalTransport::acknowledge(&mut destination, &reply_publication).unwrap());
    assert!(
        LocalTransport::pending_publications(&destination)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        LocalTransport::pending_publications(&source).unwrap(),
        caller_publications,
        "the caller's newly committed publication is independent of the callee acknowledgement"
    );
}

#[test]
fn raft_delivery_and_reply_verifiers_replay_before_physical_accumulate() {
    let service_pvm = vos::service::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = vos_pvm_compiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRef::of_bytes(&initial_state);

    let install_service = |identity: ServiceIdentity,
                           actor: ActorId,
                           method: &str,
                           external_actors: Vec<ExternalActorBinding>| {
        let mut host = MemoryServiceStore::default();
        assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
        assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
        let mut service = ServiceRuntime::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHost,
            host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap();
        let install = AccumulateRequest::Install(ServiceGenesis {
            role_authority: None,
            external_actors,
            service: identity.clone(),
            consistency: ConsistencyMode::Raft,
            actors: vec![ActorGenesis {
                actor,
                name: "root".into(),
                parent: None,
                producer: ProducerId([0x91; 32]),
                deployment: identity.deployment,
                program: actor_program,
                initial_state: initial_state_ref.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicy {
                    method: method.into(),
                    schema: Hash([0x92; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    capability: None,
                    actor_role: None,
                }]),
            }],
            authorization: AuthorizationEvidence::SystemCapability {
                capability: SystemCapabilityId([0x93; 32]),
                authenticator: vec![0x94],
            },
        });
        authorize_install(&mut service, &install);
        assert!(matches!(
            service.accumulate(&install).unwrap().result,
            AccumulationResult::Installed(_)
        ));
        service
    };

    let source_identity = ServiceIdentity {
        space: vos::service::SpaceId([0x81; 32]),
        root_service: RootServiceId([0x82; 32]),
        deployment: DeploymentId([0x83; 32]),
        service_program,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let destination_identity = ServiceIdentity {
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
    let source_work = LocalWorkScheduler::prepare(
        source.accumulate_host(),
        LocalWorkRequest {
            invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_actor,
            method: "await_peer".into(),
            arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: source_work.work,
            transition: source_refined.transition,
            provided_blobs: source_refined.exported_blobs,
        }))
        .unwrap();
    let source_publication = LocalTransport::pending_publications(&source)
        .unwrap()
        .pop()
        .unwrap();

    let source_snapshot = source.accumulate_host().snapshot();
    let source_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut source_leader =
        ReplicatedServiceRuntime::new(source, TestCommittedLog::new(source_log.clone(), true));
    let mut source_follower = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm.clone(),
            service_program,
            NoRefineProtocolHost,
            MemoryServiceStore::from_snapshot(source_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(source_log.clone(), false),
    );
    let destination_snapshot = destination.accumulate_host().snapshot();
    let destination_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut destination_leader = ReplicatedServiceRuntime::new(
        destination,
        TestCommittedLog::new(destination_log.clone(), true),
    );
    let mut destination_follower = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm,
            service_program,
            NoRefineProtocolHost,
            MemoryServiceStore::from_snapshot(destination_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(destination_log.clone(), false),
    );

    let delivery = LocalWorkScheduler::prepare_delivery(
        destination_leader.service().accumulate_host(),
        2,
        source_publication.published.outbox[0].clone(),
        source_publication.published.outbox.clone(),
        source_publication.receipt.clone(),
    )
    .unwrap();
    let delivery_request = AccumulateRequest::Deliver(delivery);
    let delivery_verification = ReceiptVerificationRequest {
        expected_producer: source_actor,
        receipt: source_publication.receipt.clone(),
    };
    destination_leader
        .service_mut()
        .accumulate_host_mut()
        .allow_receipt(&delivery_verification);
    assert!(matches!(
        destination_leader.accumulate(&delivery_request),
        Err(vos::service::ReplicatedServiceError::Dispatch(
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

    let inbox =
        LocalWorkScheduler::prepare_inbox(destination_leader.service().accumulate_host(), call, 3)
            .unwrap();
    let destination_refined = destination_leader
        .refine_actor_tree(&inbox.work, &inbox.imports)
        .unwrap();
    let destination_applied = destination_leader
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: inbox.work,
            transition: destination_refined.transition,
            provided_blobs: destination_refined.exported_blobs,
        }))
        .unwrap();
    assert_eq!(destination_follower.catch_up().unwrap(), 1);
    let AccumulationResult::Accepted {
        receipt: destination_receipt,
        published: destination_published,
        duplicate: false,
    } = destination_applied.result
    else {
        panic!("destination inbox must commit a reply")
    };
    let reply = destination_published.reply.clone().unwrap();
    let awaited_reply = AccumulatedReply {
        reply,
        receipt: destination_receipt.clone(),
        attestation: None,
    };
    let resumed = LocalWorkScheduler::prepare_resume(
        source_leader.service().accumulate_host(),
        invocation,
        4,
        Some(awaited_reply),
    )
    .unwrap();
    let source_resumed = source_leader
        .refine_actor_tree(&resumed.work, &resumed.imports)
        .unwrap();
    let resume_request = AccumulateRequest::Apply(AccumulationEnvelope {
        work: resumed.work,
        transition: source_resumed.transition,
        provided_blobs: source_resumed.exported_blobs,
    });
    let reply_verification = ReceiptVerificationRequest {
        expected_producer: destination_actor,
        receipt: destination_receipt,
    };
    source_leader
        .service_mut()
        .accumulate_host_mut()
        .allow_receipt(&reply_verification);
    assert!(matches!(
        source_leader.accumulate(&resume_request),
        Err(vos::service::ReplicatedServiceError::Dispatch(
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
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft role initial state".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let actor = ActorId([0x61; 32]);
    let authority_actor = ActorId([0x62; 32]);
    let service = ServiceIdentity {
        space: vos::service::SpaceId([0x63; 32]),
        root_service: RootServiceId([0x64; 32]),
        deployment: DeploymentId([0x65; 32]),
        service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
        platform: vos::service::PLATFORM_ID,
        execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
        gas_schedule: TEST_GAS_SCHEDULE,
    };
    let authority = RoleAuthorityBinding {
        service: ServiceIdentity {
            root_service: RootServiceId([0x66; 32]),
            deployment: DeploymentId([0x67; 32]),
            ..service.clone()
        },
        actor: authority_actor,
    };
    let policy = MethodPolicy {
        method: "member_only".into(),
        schema: Hash([0x68; 32]),
        policy: space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap(),
        public: false,
        attested: false,
        space_role: Some(vos::SpaceRole::Member.as_u8()),
        capability: None,
        actor_role: None,
    };
    let genesis = ServiceGenesis {
        role_authority: Some(authority.clone()),
        external_actors: vec![],
        service: service.clone(),
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
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
        authorization: AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId([0x6A; 32]),
            authenticator: vec![0x6B],
        },
    };
    let programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let blobs = vec![ImportedBlob {
        reference: initial,
        bytes: initial_bytes,
    }];
    let mut leader_host = MemoryServiceStore::default();
    leader_host.allow_install(&genesis);
    let mut follower_host = MemoryServiceStore::default();
    follower_host.allow_install(&genesis);
    let shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let mut leader = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHost,
            leader_host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), true),
    );
    let mut follower = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHost,
            follower_host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false),
    );
    assert!(matches!(
        leader
            .accumulate_with_availability(&AccumulateRequest::Install(genesis), &programs, &blobs,)
            .unwrap()
            .result,
        AccumulationResult::Installed(_)
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
    let fresh_follower_snapshot = follower.service().accumulate_host().snapshot();
    let fresh_follower_applied = follower.log_mut().applied_index().unwrap();
    drop(follower);
    let mut follower = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHost,
            MemoryServiceStore::from_snapshot(fresh_follower_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false).with_applied(fresh_follower_applied),
    );

    let holder = Origin::Member(SubjectId([0x6C; 32]));
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("member_only").encode());
    let provisional = LocalWorkRequest {
        invocation: InvocationId([0x6D; 32]),
        workflow_step: 0,
        logical_timeslot: 7,
        target: actor,
        method: policy.method.clone(),
        arguments,
        origin: holder,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let provisional_work =
        LocalWorkScheduler::prepare(leader.service().accumulate_host(), provisional.clone())
            .unwrap()
            .work;
    let claim = RoleAuthorizationClaim {
        space: service.space,
        holder,
        role: Some(vos::SpaceRole::Member),
        capability: None,
        audience: service,
        invocation: provisional.invocation,
        scope: provisional_work.authorization_scope(),
        target: actor,
        method: policy.method.clone(),
        policy: policy.policy,
    };
    let authority_reply = claim.authority_reply(authority_actor);
    let assertion = AccumulatedRoleAssertion {
        claim: claim.clone(),
        receipt: AccumulationReceipt {
            service: authority.service.clone(),
            accepted_transition: Hash([0x6E; 32]),
            reply_commitment: Some(authority_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([0x6F; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyMode::Raft,
        },
    };
    assert!(assertion.matches_authority(&authority));
    let verification = ReceiptVerificationRequest {
        expected_producer: authority_actor,
        receipt: assertion.receipt.clone(),
    };
    let credential = RoleCredential {
        holder,
        scope: claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        capability: None,
        actor_role: None,
        authenticator: assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let mut authorized = provisional;
    authorized.authorization = credential;
    let work = LocalWorkScheduler::prepare(leader.service().accumulate_host(), authorized)
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
        Err(vos::service::ReplicatedServiceError::Dispatch(
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
        "vos-raft-authority-sidecar-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let mut canonical_log =
        RaftAccumulateLog::open(&rejection_path, RaftConfig::default()).unwrap();
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
    let follower_host = MemoryServiceStore::from_snapshot(follower_snapshot);
    let mut follower = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHost,
            follower_host,
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false).with_applied(follower_applied),
    );
    let transition = Transition {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_deployment: work.target_deployment,
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWrite {
            actor,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"authorized follower state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecord {
            call_id: work.invocation.root_reply_id(),
            producer: actor,
            result: Value::U32(99).encode(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    let applied = leader
        .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work,
            transition,
            provided_blobs: vec![],
        }))
        .expect("the leader applies the admitted role-authorized invocation");
    assert!(matches!(
        applied.result,
        AccumulationResult::Accepted {
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
    let source_service = ServiceIdentity {
        root_service: RootServiceId([0x71; 32]),
        deployment: DeploymentId([0x72; 32]),
        ..destination_service.clone()
    };
    let sender = ActorId([0x73; 32]);
    let caller_invocation = InvocationId([0x74; 32]);
    let call = caller_invocation.call_id(0);
    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&Msg::new("member_only").encode());
    let message = MessageRecord {
        call_id: call,
        caller_invocation,
        await_ordinal: 0,
        from_service: source_service.clone(),
        from: sender,
        to_service: destination_service.clone(),
        to: actor,
        parent: None,
        payload: payload.clone(),
        authorization: AuthorizationEvidence::Public,
        proof_requested: false,
        deadline_timeslot: Some(100),
    };
    let source_outbox = vec![message.clone()];
    let source_receipt = AccumulationReceipt {
        service: source_service,
        accepted_transition: Hash([0x75; 32]),
        reply_commitment: None,
        outbox_commitment: MessageRecord::outbox_commitment(&source_outbox),
        resulting_state_root: Some(Hash([0x76; 32])),
        resulting_crdt_heads: vec![],
        sequence: 7,
        checkpoint: 0,
        consistency: ConsistencyMode::Raft,
    };
    let delivery_work = LocalWorkScheduler::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId::for_call(call),
            workflow_step: 0,
            logical_timeslot: 10,
            target: actor,
            method: policy.method.clone(),
            arguments: payload,
            origin: Origin::Actor(sender),
            authorization: AuthorizationEvidence::Public,
            causal_parent: Some(caller_invocation),
            parent_call: Some(call),
            causal_context: Some(CausalCallContext::from(&message)),
            awaited_reply: None,
            awaited_timeout: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let delivery_claim = RoleAuthorizationClaim {
        space: destination_service.space,
        holder: Origin::Actor(sender),
        role: Some(vos::SpaceRole::Member),
        capability: None,
        audience: destination_service,
        invocation: delivery_work.invocation,
        scope: delivery_work.authorization_scope(),
        target: actor,
        method: policy.method.clone(),
        policy: policy.policy,
    };
    let delivery_assertion = AccumulatedRoleAssertion {
        claim: delivery_claim.clone(),
        receipt: AccumulationReceipt {
            service: authority.service.clone(),
            accepted_transition: Hash([0x77; 32]),
            reply_commitment: Some(delivery_claim.authority_reply(authority_actor).commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([0x78; 32])),
            resulting_crdt_heads: vec![],
            sequence: 4,
            checkpoint: 0,
            consistency: ConsistencyMode::Raft,
        },
    };
    let delivery_authorization = RoleCredential {
        holder: Origin::Actor(sender),
        scope: delivery_claim.scope,
        space_role: Some(vos::SpaceRole::Member),
        capability: None,
        actor_role: None,
        authenticator: delivery_assertion.encode(),
    }
    .disclosed_evidence(policy.policy);
    let delivery = LocalWorkScheduler::prepare_authorized_delivery(
        leader.service().accumulate_host(),
        10,
        delivery_authorization,
        message,
        source_outbox,
        source_receipt.clone(),
    )
    .unwrap();
    let delivery_request = AccumulateRequest::Deliver(delivery);
    let mut delivery_verifications = vec![
        ReceiptVerificationRequest {
            expected_producer: sender,
            receipt: source_receipt,
        },
        ReceiptVerificationRequest {
            expected_producer: authority_actor,
            receipt: delivery_assertion.receipt,
        },
    ];
    delivery_verifications.sort_by_key(ReceiptVerificationRequest::hash);
    assert!(matches!(
        leader.accumulate(&delivery_request),
        Err(vos::service::ReplicatedServiceError::Dispatch(
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
    let mut follower = ReplicatedServiceRuntime::new(
        ServiceRuntime::new(
            service_pvm.clone(),
            ProgramId::of_pvm(&service_pvm),
            NoRefineProtocolHost,
            MemoryServiceStore::from_snapshot(follower_snapshot),
            TEST_GAS_SCHEDULE.refine,
            TEST_GAS_SCHEDULE.accumulate,
        )
        .unwrap(),
        TestCommittedLog::new(shared.clone(), false).with_applied(follower_applied),
    );
    let prepared =
        LocalWorkScheduler::prepare_inbox(leader.service().accumulate_host(), call, 11).unwrap();
    let inbox_work = prepared.work;
    let inbox_transition = Transition {
        service: inbox_work.service.clone(),
        consumed_input: inbox_work.input_id(),
        target_deployment: inbox_work.target_deployment,
        target_program: inbox_work.target_program,
        base: inbox_work.base.clone(),
        writes: vec![ActorWrite {
            actor,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"authorized delivery follower state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecord {
            call_id: call,
            producer: actor,
            result: Value::U32(100).encode(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    assert!(matches!(
        leader
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: inbox_work,
                transition: inbox_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
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
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft initial state".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([121; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([123; 32]),
            authenticator: vec![124],
        },
    };

    let availability_programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlob {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let mut leader_host = MemoryServiceStore::default();
    leader_host.allow_install(&genesis);
    let mut follower_host = MemoryServiceStore::default();
    follower_host.allow_install(&genesis);

    let shared_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let leader_service = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        leader_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let follower_service = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        follower_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut leader = ReplicatedServiceRuntime::new(
        leader_service,
        TestCommittedLog::new(shared_log.clone(), true),
    );
    let mut follower =
        ReplicatedServiceRuntime::new(follower_service, TestCommittedLog::new(shared_log, false));

    let mut wrong_program = genesis.clone();
    wrong_program.service.service_program = ProgramId([0xFF; 32]);
    assert!(matches!(
        leader.accumulate(&AccumulateRequest::Install(wrong_program)),
        Err(vos::service::ReplicatedServiceError::Dispatch(
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
                &AccumulateRequest::Install(genesis),
                &availability_programs,
                &availability_blobs,
            )
            .unwrap()
            .result,
        AccumulationResult::Installed(_)
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
    let promotion_tail = LocalWorkScheduler::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([123; 32]),
            workflow_step: 0,
            logical_timeslot: promotion_floor,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let promotion_transition = Transition {
        service: promotion_tail.service.clone(),
        consumed_input: promotion_tail.input_id(),
        target_deployment: promotion_tail.target_deployment,
        target_program: promotion_tail.target_program,
        base: promotion_tail.base.clone(),
        writes: vec![ActorWrite {
            actor: promotion_tail.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"prior-term state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecord {
            call_id: promotion_tail.invocation.root_reply_id(),
            producer: promotion_tail.target,
            result: b"prior-term reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
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
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: promotion_tail,
                transition: promotion_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResult::Accepted {
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

    let first = LocalWorkScheduler::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([125; 32]),
            workflow_step: 0,
            logical_timeslot: promotion_floor + 1,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let first_transition = Transition {
        service: first.service.clone(),
        consumed_input: first.input_id(),
        target_deployment: first.target_deployment,
        target_program: first.target_program,
        base: first.base.clone(),
        writes: vec![ActorWrite {
            actor: first.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"leader state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecord {
            call_id: first.invocation.root_reply_id(),
            producer: first.target,
            result: b"leader reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
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
            AccumulationResult::IngressAdmitted {
                duplicate: false,
                ..
            }
        ));
    }
    let prior_transition = Transition {
        service: prior.service.clone(),
        consumed_input: prior.input_id(),
        target_deployment: prior.target_deployment,
        target_program: prior.target_program,
        base: prior.base.clone(),
        writes: vec![ActorWrite {
            actor: prior.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"interleaved state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecord {
            call_id: prior.invocation.root_reply_id(),
            producer: prior.target,
            result: b"interleaved reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    leader.log_mut().commit_before_next_proposal(
        AccumulateRequest::Apply(AccumulationEnvelope {
            work: prior,
            transition: prior_transition,
            provided_blobs: vec![],
        })
        .encode(),
    );
    assert!(matches!(
        leader
            .accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                work: first,
                transition: first_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResult::Rejected(vos::service::AccumulationRejection::StaleLinearWork {
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
    let second = LocalWorkScheduler::prepare(
        follower.service().accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([126; 32]),
            workflow_step: 0,
            logical_timeslot: promotion_floor + 2,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
    let second_transition = Transition {
        service: second.service.clone(),
        consumed_input: second.input_id(),
        target_deployment: second.target_deployment,
        target_program: second.target_program,
        base: second.base.clone(),
        writes: vec![ActorWrite {
            actor: second.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"failover state".to_vec()),
        }],
        crdt_change: None,
        spawns: vec![],
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecord {
            call_id: second.invocation.root_reply_id(),
            producer: second.target,
            result: b"failover reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccounting::default(),
        proof: None,
    };
    assert!(matches!(
        follower
            .accumulate(&direct_linear_ingress(&second))
            .unwrap()
            .result,
        AccumulationResult::IngressAdmitted {
            duplicate: false,
            ..
        }
    ));
    let failover_apply = AccumulateRequest::Apply(AccumulationEnvelope {
        work: second,
        transition: second_transition,
        provided_blobs: vec![],
    });
    assert!(matches!(
        follower.accumulate(&failover_apply).unwrap().result,
        AccumulationResult::Accepted {
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
        AccumulationResult::Accepted {
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
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft failure classification".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    let poison_gas_schedule = GasSchedule::new(100_000_000, 9_000_000);
    seed.service.gas_schedule = poison_gas_schedule;
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service,
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([0xD1; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([0xD3; 32]),
            authenticator: vec![0xD4],
        },
    };

    let availability_programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlob {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let mut poison_host = MemoryServiceStore::default();
    poison_host.allow_install(&genesis);
    let poison_shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let poison_log = TestCommittedLog::new(poison_shared.clone(), true);
    let mut poison_follower_host = MemoryServiceStore::default();
    poison_follower_host.allow_install(&genesis);
    let poison_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        poison_host,
        poison_gas_schedule.refine,
        poison_gas_schedule.accumulate,
    )
    .unwrap();
    let mut poisoned = ReplicatedServiceRuntime::new(poison_service, poison_log);
    let poison_follower_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        poison_follower_host,
        poison_gas_schedule.refine,
        poison_gas_schedule.accumulate,
    )
    .unwrap();
    let mut poison_follower = ReplicatedServiceRuntime::new(
        poison_follower_service,
        TestCommittedLog::new(poison_shared.clone(), false),
    );
    let poison_result = poisoned.accumulate_with_availability(
        &AccumulateRequest::Install(genesis.clone()),
        &availability_programs,
        &availability_blobs,
    );
    assert!(
        matches!(
            poison_result,
            Err(vos::service::ReplicatedServiceError::Dispatch(
                ServiceDispatchError::Pvm(ServicePvmError::OutOfGas { .. })
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

    let mut mismatched_host = MemoryServiceStore::default();
    mismatched_host.allow_install(&genesis);
    let mismatched_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        mismatched_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut mismatched_follower = ReplicatedServiceRuntime::new(
        mismatched_service,
        TestCommittedLog::new(poison_shared, false),
    );
    let mismatch = mismatched_follower.catch_up();
    assert!(matches!(
        mismatch,
        Err(vos::service::ReplicatedServiceError::Dispatch(
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
    let mut retry_host = DurableServiceStore::open(FailableCommittedImages {
        fail_next_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    retry_host.allow_install(&retry_genesis);
    let retry_log =
        TestCommittedLog::new(Arc::new(Mutex::new(SharedCommittedLog::default())), true);
    let retry_service = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        retry_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut retryable = ReplicatedServiceRuntime::new(retry_service, retry_log);
    assert!(matches!(
        retryable.accumulate_with_availability(
            &AccumulateRequest::Install(retry_genesis),
            &availability_programs,
            &availability_blobs,
        ),
        Err(vos::service::ReplicatedServiceError::Dispatch(
            ServiceDispatchError::Pvm(ServicePvmError::AccumulateCommitRejected)
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
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = vos_pvm_compiler::link_elf(&greeter_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service.clone(),
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([131; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: true,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([133; 32]),
            authenticator: vec![134],
        },
    };

    let availability_programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlob {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let proof_bytes = canonical_test_proof_manifest(0x87);
    let mut leader_host = MemoryServiceStore::default();
    leader_host.allow_install(&genesis);
    let leader_proof = proof_bytes.clone();
    leader_host.install_proof_verifier(move |_, candidate| candidate == leader_proof);
    let mut follower_host = DurableServiceStore::open(FailableCommittedImages {
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
    let leader_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        leader_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let follower_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        follower_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut leader = ReplicatedServiceRuntime::new(
        leader_service,
        TestCommittedLog::new(shared_log.clone(), true),
    );
    let mut follower = ReplicatedServiceRuntime::new(
        follower_service,
        TestCommittedLog::new(shared_log.clone(), false),
    );
    assert!(matches!(
        leader
            .accumulate_with_availability(
                &AccumulateRequest::Install(genesis),
                &availability_programs,
                &availability_blobs,
            )
            .unwrap()
            .result,
        AccumulationResult::Installed(_)
    ));

    let prepared = LocalWorkScheduler::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequest {
            invocation: InvocationId([135; 32]),
            workflow_step: 0,
            logical_timeslot: 20,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
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
        AccumulationResult::IngressAdmitted {
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
    let envelope = AccumulationEnvelope {
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
    let AccumulateRequest::Apply(logged) = AccumulateRequest::decode(&entries[2].request).unwrap()
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
        Err(vos::service::ReplicatedServiceError::ProofUnavailable)
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
    let snapshot_proofs = vec![vos::service::CommittedProofArtifact {
        verification: ProofVerificationRequest {
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
    let snapshot = CommittedServiceSnapshot {
        applied_index: 3,
        service_image: leader.service().accumulate_host().committed_service_image(),
        proof_artifacts: snapshot_proofs,
        result_artifacts: vec![],
        host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
    };
    let mut missing_proof_snapshot = snapshot.clone();
    missing_proof_snapshot.proof_artifacts.clear();
    assert_eq!(
        CommittedServiceSnapshot::decode(&missing_proof_snapshot.encode()),
        Err(vos::service::DecodeError::NonCanonical),
        "a snapshot cannot omit an artifact referenced by its publication"
    );
    let mut substituted_request_snapshot = snapshot.clone();
    substituted_request_snapshot.proof_artifacts[0]
        .verification
        .actor_program = ProgramId([0xF1; 32]);
    assert_eq!(
        CommittedServiceSnapshot::decode(&substituted_request_snapshot.encode()),
        Err(vos::service::DecodeError::NonCanonical),
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
        CommittedServiceSnapshot::decode(&surplus_proof_snapshot.encode()),
        Err(vos::service::DecodeError::NonCanonical),
        "a snapshot cannot carry unrelated proof verification work"
    );

    let mismatched_schedule =
        GasSchedule::new(TEST_GAS_SCHEDULE.refine, TEST_GAS_SCHEDULE.accumulate - 1);
    let mismatched_snapshot_host =
        DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
    let mismatched_snapshot_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        mismatched_snapshot_host,
        mismatched_schedule.refine,
        mismatched_schedule.accumulate,
    )
    .unwrap();
    let mut mismatched_snapshot_follower = ReplicatedServiceRuntime::new(
        mismatched_snapshot_service,
        TestCommittedLog::new(shared_log.clone(), false).with_installed_snapshot(snapshot.clone()),
    );
    let empty_service_image = mismatched_snapshot_follower
        .service()
        .accumulate_host()
        .committed_service_image();
    assert!(matches!(
        mismatched_snapshot_follower.catch_up(),
        Err(vos::service::ReplicatedServiceError::Dispatch(
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
        DurableServiceStore::open(FailableCommittedImages::default()).unwrap();
    rejecting_snapshot_host.install_proof_verifier(|_, _| false);
    let rejecting_snapshot_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        rejecting_snapshot_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut rejecting_snapshot_follower = ReplicatedServiceRuntime::new(
        rejecting_snapshot_service,
        TestCommittedLog::new(shared_log.clone(), false).with_installed_snapshot(snapshot.clone()),
    );
    assert!(matches!(
        rejecting_snapshot_follower.catch_up(),
        Err(vos::service::ReplicatedServiceError::ProofUnavailable)
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

    let mark_only_host = MemoryServiceStore::from_snapshot_bytes(&snapshot.service_image).unwrap();
    let mark_only_image = mark_only_host.committed_service_image();
    let mark_only_service = ServiceRuntime::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHost,
        mark_only_host,
        mismatched_schedule.refine,
        mismatched_schedule.accumulate,
    )
    .unwrap();
    let mut mark_only_follower = ReplicatedServiceRuntime::new(
        mark_only_service,
        TestCommittedLog::new(Arc::new(Mutex::new(SharedCommittedLog::default())), false)
            .with_committed_index_floor(1),
    );
    assert!(matches!(
        mark_only_follower.catch_up(),
        Err(vos::service::ReplicatedServiceError::Dispatch(
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

    let mut snapshot_host = DurableServiceStore::open(FailableCommittedImages {
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
    let snapshot_service = ServiceRuntime::new(
        service_pvm,
        service_program,
        NoRefineProtocolHost,
        snapshot_host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let mut snapshot_follower = ReplicatedServiceRuntime::new(
        snapshot_service,
        TestCommittedLog::new(shared_log, false).with_installed_snapshot(snapshot),
    );
    assert!(matches!(
        snapshot_follower.catch_up(),
        Err(vos::service::ReplicatedServiceError::ProofUnavailable)
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
    let service_pvm =
        vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft-backed initial state".to_vec();
    let initial = BlobRef::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesis {
        role_authority: None,
        external_actors: vec![],
        service: seed.service,
        consistency: ConsistencyMode::Raft,
        actors: vec![ActorGenesis {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([53; 32]),
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            role_policies: role_policies(vec![MethodPolicy {
                method: "start".into(),
                schema: Hash([127; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
        }],
        authorization: AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId([129; 32]),
            authenticator: vec![130],
        },
    };

    let availability_programs = vec![ImportedProgram {
        program: actor_program,
        pvm: actor_pvm,
    }];
    let availability_blobs = vec![ImportedBlob {
        reference: initial.clone(),
        bytes: initial_bytes,
    }];
    let mut host = MemoryServiceStore::default();
    host.allow_install(&genesis);
    let service = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        host,
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let directory = std::env::temp_dir().join(format!(
        "vos-physical-raft-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("raft.redb");
    let log = RaftAccumulateLog::open(&path, RaftConfig::default()).unwrap();
    let mut replicated = ReplicatedServiceRuntime::new(service, log);

    assert!(matches!(
        replicated
            .accumulate_with_availability(
                &AccumulateRequest::Install(genesis),
                &availability_programs,
                &availability_blobs,
            )
            .unwrap()
            .result,
        AccumulationResult::Installed(_)
    ));
    assert_eq!(replicated.log_mut().applied_index().unwrap(), 1);
    let header = replicated
        .service()
        .accumulate_host()
        .header()
        .unwrap()
        .expect("physical guest committed the service header");
    assert_eq!(header.consistency, ConsistencyMode::Raft);
    assert_eq!(header.revision, 0);
    let source_snapshot = replicated.service().accumulate_host().snapshot();
    let source_image = replicated.service().accumulate_host().snapshot_bytes();

    drop(replicated);
    let mut reopened = RaftAccumulateLog::open(&path, RaftConfig::default()).unwrap();
    assert_eq!(reopened.applied_index().unwrap(), 1);
    assert!(reopened.committed_after(1).unwrap().entries.is_empty());
    drop(reopened);

    // Deliver the exact snapshot through the real inbound vos-raft worker.
    // The worker owns only the log/snapshot database at this point; catch-up
    // must install the canonical image into the physical service host before
    // advancing its application cursor.
    let follower_db = Arc::new(redb::Database::create(directory.join("follower.redb")).unwrap());
    let snapshot = CommittedServiceSnapshot {
        applied_index: 1,
        service_image: source_image,
        proof_artifacts: vec![],
        result_artifacts: vec![],
        host_state_machine: Some(vos::service::HOST_STATE_MACHINE_ID),
    };
    let raft_config = RaftConfig {
        me: 0xBBBB,
        members: vec![0xAAAA, 0xBBBB],
        voter_peer_ids: Vec::new(),
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
        Some(0),
    );
    assert_eq!(installed.term, 1);

    let follower_service = ServiceRuntime::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHost,
        DurableServiceStore::open(FailableCommittedImages {
            fail_next_commit: true,
            ..FailableCommittedImages::default()
        })
        .unwrap(),
        TEST_GAS_SCHEDULE.refine,
        TEST_GAS_SCHEDULE.accumulate,
    )
    .unwrap();
    let follower_log =
        RaftAccumulateLog::from_worker(follower_db, raft_config, worker, apply_rx).unwrap();
    let mut follower = ReplicatedServiceRuntime::new(follower_service, follower_log);
    assert!(matches!(
        follower.catch_up(),
        Err(vos::service::ReplicatedServiceError::ServiceImage(
            vos::service::ServiceImageInstallError::PersistenceRejected
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
    let pvm = vos::service::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvm::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let mut host = MemoryServiceStore::default();

    let output = service
        .accumulate(b"not a service request", 10_000_000, &mut host)
        .unwrap();
    assert_eq!(
        AccumulationResult::decode(&output.bytes).unwrap(),
        AccumulationResult::Rejected(vos::service::AccumulationRejection::NonCanonical)
    );
    assert_eq!(host.row_count(), 0);
    assert_eq!(host.blob_count(), 0);
}
