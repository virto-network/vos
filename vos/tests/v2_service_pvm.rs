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
use std::sync::{Arc, Mutex};
use vos::attestation::{
    AttestationProofHostV2, AttestationProofProducerV2, AttestationProofRequestV2,
    ProducedAttestationProofV2,
};
use vos::network::RaftRpcHandler;
use vos::node::{V2NodeRegistrationError, VosNode};
use vos::raft::{RaftAccumulateLogV2, RaftConfig, RaftWorker, Role, WorkerConfig};
use vos::v2::{
    AccumulateRequestV2, AccumulatedReplyV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationResultV2, ActorGenesisV2, ActorId, ActorUpgradeV2, ActorWriteV2,
    AuthorizationEvidenceV2, BlobRefV2, CallId, CommittedAccumulateBatchV2,
    CommittedAccumulateEntryV2, CommittedAccumulateLogV2, CommittedImageStoreV2,
    CommittedServiceImageHostV2, CommittedServiceSnapshotV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationChangeV2, ContinuationSnapshotV2, DeploymentId, DurableJamStoreV2,
    ExternalActorBindingV2, GasAccountingV2, Hash, ImportedActorV2, ImportedBlobV2,
    ImportedProgramV2, InboxDrainOutcomeV2, InvocationId, JamServiceV2, LocalJamStoreHostV2,
    LocalJamStoreSnapshotV2, LocalJamStoreV2, LocalRootTreeConfigErrorV2, LocalRootTreeConfigV2,
    LocalRootTreeInvokeErrorV2, LocalRootTreeServiceV2, LocalTransportV2, LocalWorkRequestV2,
    LocalWorkSchedulerV2, MessageRecordV2, MethodPolicyV2, NoRefineProtocolHostV2, Origin,
    PackageManifestV2, PackageRolePoliciesV2, ProducerId, ProgramId, ProofArtifactStoreV2,
    PublishedEffectsV2, ReceiptVerificationRequestV2, RefineImportsV2, RefineOutputV2,
    ReplicatedJamServiceV2, ReplicatedServiceErrorV2, ReplyRecordV2, RoleCredentialV2,
    RoleCredentialVerificationRequestV2, RootServiceId, ScheduleErrorV2, ServiceDispatchError,
    ServiceGenesisV2, ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, StateKeyV2, SubjectId,
    SystemCapabilityId, TransitionV2, V2Wire, VosPackageV2, WorkEnvelopeV2, WorkflowOperationV2,
    artifact_hash, public_policy_hash, space_role_policy_hash,
};
use vos::{
    Decode, Encode,
    actors::{client::ClientError, context::ServiceId},
    value::{Msg, Value},
};

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
    }
}

fn role_policies(mut methods: Vec<MethodPolicyV2>) -> Vec<u8> {
    methods.sort_by(|left, right| left.method.cmp(&right.method));
    PackageRolePoliciesV2 { methods }.encode()
}

#[derive(Debug, Default)]
struct FailableCommittedImages {
    image: Option<Vec<u8>>,
    proofs: BTreeMap<[u8; 32], Vec<u8>>,
    fail_next_commit: bool,
    fail_next_proof_commit: bool,
}

#[derive(Debug, Clone, Default)]
struct SharedCommittedImages(Arc<Mutex<Option<Vec<u8>>>>);

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
        100_000_000,
        5_000_000_000,
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
        }
    }

    fn with_installed_snapshot(mut self, snapshot: CommittedServiceSnapshotV2) -> Self {
        self.installed_snapshot = Some(snapshot);
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
            };
            shared.entries.push(entry);
        }
        Ok(shared.entries.len() as u64)
    }

    fn propose_at(
        &mut self,
        request: &[u8],
        logical_timeslot: Option<u64>,
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
            };
            shared.entries.push(entry);
        }
        let entry = CommittedAccumulateEntryV2 {
            index: shared.entries.len() as u64 + 1,
            request: request.to_vec(),
            logical_timeslot,
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
        Ok(CommittedAccumulateBatchV2 {
            entries: shared
                .entries
                .iter()
                .filter(|entry| entry.index > applied_index)
                .cloned()
                .collect(),
            committed_index: shared.entries.len() as u64,
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
        _proof_artifacts: &[ImportedBlobV2],
    ) -> Result<(), Self::Error> {
        let committed = self.shared.lock().unwrap().entries.len() as u64;
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
    required_elf(
        "../services/vos-service/target/riscv64em-javm/release/vos_service.elf",
        "just build-v2-pvm-test-artifacts",
    )
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
        },
        invocation: InvocationId([4; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: ActorId([5; 32]),
        target_deployment: DeploymentId([2; 32]),
        target_program: actor_program,
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
            state,
            causal_states: vec![],
            continuation: None,
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
        state: state.clone(),
        causal_states: vec![],
        continuation: None,
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
        },
        actor_pvm,
        generated_interfaces: vec![],
        role_policies: policies,
        schemas,
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
    };
    let actor = ActorId([93; 32]);
    let config = LocalRootTreeConfigV2 {
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
fn raft_root_tree_orders_genesis_apply_and_ack_through_physical_accumulate() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([113; 32]);
    let config = LocalRootTreeConfigV2 {
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([114; 32]),
            root_service: RootServiceId([115; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
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
fn raft_follower_registers_before_genesis_and_restores_caught_up_admission_time() {
    let actor_elf = greeter_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([119; 32]);
    let config = LocalRootTreeConfigV2 {
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([120; 32]),
            root_service: RootServiceId([121; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
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
    let installed =
        worker_handle.install_snapshot(&[0xE2; 32], 0xCAFE, 1, source_index, 1, snapshot.encode());
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
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([104; 32]),
            root_service: RootServiceId([105; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
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
fn durable_crdt_root_tree_reattaches_an_exact_invocation_after_restart() {
    let actor_elf = crdt_counter_v2_elf();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let (package, actor_name) = signed_test_package(&actor_elf, &signer);
    let actor = ActorId([97; 32]);
    let config = LocalRootTreeConfigV2 {
        service_pvm: CANONICAL_SERVICE_PVM.to_vec(),
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([98; 32]),
            root_service: RootServiceId([99; 32]),
            deployment: package.deployment_id(),
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
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
    arguments.extend_from_slice(&Msg::new("increment").with("amount", 2u64).encode());
    let request = LocalWorkRequestV2 {
        invocation: InvocationId([102; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
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
    };

    let mut service =
        LocalRootTreeServiceV2::open(config.clone(), FailableCommittedImages::default())
            .expect("fresh CRDT root installs through physical Accumulate");
    let committed = service
        .invoke(request.clone())
        .expect("CRDT slice commits through physical Refine and Accumulate");
    assert!(!committed.duplicate);
    assert!(!committed.receipt.resulting_crdt_heads.is_empty());

    let backend = service.into_backend();
    let mut restarted = LocalRootTreeServiceV2::open(config, backend)
        .expect("CRDT service image restores without reinstalling");
    let recovered = restarted
        .invoke(request)
        .expect("normalized CRDT workflow reattaches to the admitted work");
    assert!(recovered.duplicate);
    assert_eq!(recovered.refine_gas_used, 0);
    assert_eq!(recovered.accumulate_gas_used, 0);
    assert_eq!(recovered.input, committed.input);
    assert_eq!(recovered.receipt, committed.receipt);
    assert_eq!(recovered.published, committed.published);
    assert_eq!(recovered.publication, committed.publication);
}

#[test]
fn same_package_child_spawn_commits_before_the_child_becomes_callable() {
    let actor_pvm = grey_transpiler::link_elf(&workflow_v2_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
            initial_state: initial,
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
    authorize_install(&mut service, &install);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
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
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
        1_000_000_000,
        1_000_000_000,
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
        1_000_000_000,
        1_000_000_000,
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
        1_000_000_000,
        1_000_000_000,
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
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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

    let scheduled = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: work.invocation,
            workflow_step: 0,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: work.arguments.clone(),
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
    )
    .expect("scheduler imports the empty CRDT frontier");
    assert_eq!(scheduled.work, work);
    let imports = scheduled.imports;

    let refined = service.refine_actor_tree(&work, &imports).unwrap();
    assert!(refined.transition.writes.is_empty());
    let change = refined.transition.crdt_change.as_ref().unwrap();
    assert_eq!(change.causal_height, 1);
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
        1_000_000_000,
        1_000_000_000,
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
    replica
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: work.target,
            receipt: receipt.clone(),
        });
    let sync = AccumulateRequestV2::SyncCrdt(
        LocalWorkSchedulerV2::prepare_crdt_sync(service.accumulate_host())
            .expect("source scheduler exports the authenticated causal DAG"),
    );
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

    // Refine a concurrent sibling from the same empty causal base after the
    // first branch has committed. CRDT Accumulate preserves both heads.
    let mut right_work = work.clone();
    right_work.invocation = InvocationId([47; 32]);
    let mut right_message = vec![vos::value::TAG_DYNAMIC];
    right_message.extend_from_slice(&Msg::new("increment").with("amount", 3u64).encode());
    right_work.arguments = right_message;
    let right_refined = service.refine_actor_tree(&right_work, &imports).unwrap();
    let right_cid = right_refined.transition.crdt_change.as_ref().unwrap().cid();
    let right = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: right_work,
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
    let merge = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
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
    )
    .expect("scheduler imports both concurrent CRDT heads");
    let merge_work = merge.work;
    let merge_imports = merge.imports;
    assert_eq!(merge_work.base, ConsistencyBaseV2::Crdt { heads });
    assert_eq!(merge_work.base_causal_height, Some(1));
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
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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

    let prepare = |store: &LocalJamStoreV2, invocation, timeslot, method: &str| {
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&Msg::new(method).with("amount", 3u64).encode());
        LocalWorkSchedulerV2::prepare(
            store,
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
            },
        )
        .unwrap()
    };

    let first = prepare(
        service.accumulate_host(),
        InvocationId([53; 32]),
        1,
        "increment_child_twice",
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

    let second = prepare(
        service.accumulate_host(),
        InvocationId([54; 32]),
        2,
        "increment_child_twice",
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
    let around = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
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
        },
    )
    .unwrap();
    let mut concurrent_arguments = vec![vos::value::TAG_DYNAMIC];
    concurrent_arguments.extend_from_slice(&Msg::new("increment").with("amount", 11u64).encode());
    let concurrent = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
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
        },
    )
    .unwrap();
    assert_eq!(around.work.base, concurrent.work.base);
    let around_refined = service
        .refine_actor_tree(&around.work, &around.imports)
        .expect("CRDT child workflow checkpoints after its pre-await mutation");
    let concurrent_refined = service
        .refine_actor_tree(&concurrent.work, &concurrent.imports)
        .expect("concurrent CRDT work refines from the same causal base");
    let checkpoint_change = around_refined.transition.crdt_change.as_ref().unwrap();
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
    assert_eq!(resumed.work.base_causal_height, Some(2));
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
    assert!(resumed_change.operations.iter().all(|operation| {
        operation.ordinal == 0
            && operation.id
                == resumed_change.id.operation(
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
    let merged = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
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
    )
    .expect("both post-checkpoint branches remain available for a later merge");
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
    let await_then_yield = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
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
    )
    .unwrap();
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

    let first_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor_pvm.clone(),
        }],
        blobs: vec![ImportedBlobV2 {
            reference: initial.clone(),
            bytes: initial_bytes.clone(),
        }],
        private_blobs: vec![],
    };
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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

    let first = service
        .refine_actor_tree(&first_work, &first_imports)
        .unwrap();
    assert!(first.transition.reply.is_none());
    let first_change = first.transition.crdt_change.as_ref().unwrap();
    assert_eq!(first_change.operations.len(), 1);
    assert_eq!(first_change.operations[0].ordinal, 0);
    let first_change_id = first_change.id;
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
    second_work.base_causal_height = Some(1);
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
    assert_eq!(
        second_change.operations[0].id,
        second_change.id.operation(
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
        100_000_000,
        5_000_000_000,
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install_request = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let timeout_follower_store = LocalJamStoreV2::from_snapshot_bytes(&persisted_checkpoint)
        .expect("the follower starts from the identical checkpoint image");
    let timeout_follower_jam = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        timeout_follower_store,
        100_000_000,
        5_000_000_000,
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
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
            state: new_child_state.clone(),
            causal_states: vec![],
            continuation: None,
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
        100_000_000,
        5_000_000_000,
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install_request = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
        100_000_000,
        5_000_000_000,
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
    let timeout_resume = LocalWorkSchedulerV2::prepare_timeout_resume(
        timeout_service.accumulate_host(),
        initial.work.invocation,
        100,
    )
    .unwrap()
    .expect("the timed-out first await is resumable");
    let timeout_output = service
        .refine_actor_tree_with_backend(
            &timeout_resume.work.encode(),
            &timeout_resume.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
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
    let first_resume = LocalWorkSchedulerV2::prepare_resume(
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
    let first_resumed_output = service
        .refine_actor_tree_with_backend(
            &first_resume.work.encode(),
            &first_resume.imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
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
        100_000_000,
        5_000_000_000,
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
        100_000_000,
        5_000_000_000,
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
        100_000_000,
        5_000_000_000,
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
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "start".into(),
                    schema: Hash([32; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
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

    let before_prepare = service.accumulate_host().snapshot();
    let mut proof_work = work.clone();
    proof_work.proof_requested = true;
    let mut proof_transition = transition.clone();
    proof_transition.continuations.clear();
    proof_transition.inbox.clear();
    proof_transition.exported_blobs.clear();
    proof_transition.reply = Some(ReplyRecordV2 {
        call_id: proof_work.invocation.root_reply_id(),
        producer: proof_work.target,
        result: b"attested result".to_vec(),
    });
    let prepared_attestation = service
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
                attested: false,
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
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_prepare)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 1);

    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: work.clone(),
        transition: transition.clone(),
        provided_blobs: vec![ImportedBlobV2 {
            reference: continuation_ref.clone(),
            bytes: continuation_bytes,
        }],
    });
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
    assert_eq!(service.accumulate_host().commit_sequence(), 2);
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
        2,
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
    assert_eq!(
        service
            .accumulate_host_mut()
            .import_program(replacement_pvm.clone()),
        replacement_program
    );

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
    let before = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::UpgradeActor(upgrade.clone()))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert_eq!(service.accumulate_host().snapshot(), before);

    assert!(service.accumulate_host_mut().allow_upgrade(&upgrade));
    let before_failed_commit = service.accumulate_host().snapshot();
    service.accumulate_host_mut().backend_mut().fail_next_commit = true;
    assert!(matches!(
        service.accumulate(&AccumulateRequestV2::UpgradeActor(upgrade.clone())),
        Err(ServiceDispatchError::Pvm(
            ServicePvmErrorV2::AccumulateCommitRejected
        ))
    ));
    assert_eq!(service.accumulate_host().snapshot(), before_failed_commit);

    let upgraded = service
        .accumulate(&AccumulateRequestV2::UpgradeActor(upgrade.clone()))
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
            .accumulate(&AccumulateRequestV2::UpgradeActor(upgrade))
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
        100_000_000,
        5_000_000_000,
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
        service.accumulate(&apply).unwrap().result,
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
        100_000_000,
        5_000_000_000,
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
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
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
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
            1_000_000_000,
            1_000_000_000,
        )
        .unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
                    attested: false,
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
        "peer_value",
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
    let mut proof_producer = CanonicalTestProofProducer {
        proof: b"peer-proof".to_vec(),
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
        Some(b"peer-proof".as_slice()),
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
            100_000_000,
            5_000_000_000,
        )
        .unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
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
    };
    let destination_identity = ServiceIdentityV2 {
        space: vos::v2::SpaceId([79; 32]),
        root_service: RootServiceId([82; 32]),
        deployment: DeploymentId([83; 32]),
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
    };
    let source_actor = ActorId([5; 32]);
    let destination_actor = ActorId([44; 32]);
    let mut source = install_service(
        source_identity,
        source_actor,
        "await_peer",
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
        "peer_value",
        vec![],
    );
    let impostor_identity = ServiceIdentityV2 {
        root_service: RootServiceId([96; 32]),
        deployment: DeploymentId([97; 32]),
        ..destination_identity
    };
    let impostor = install_service(impostor_identity, destination_actor, "peer_value", vec![]);

    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(&Msg::new("await_peer").encode());
    let source_work = LocalWorkSchedulerV2::prepare(
        source.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([84; 32]),
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
fn raft_failover_applies_committed_requests_through_the_physical_guest() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesisV2 {
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

    let mut leader_host = LocalJamStoreV2::default();
    assert_eq!(leader_host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(leader_host.import_program(actor_pvm.clone()), actor_program);
    leader_host.allow_install(&genesis);
    let mut follower_host = LocalJamStoreV2::default();
    assert_eq!(follower_host.import_blob(initial_bytes), initial);
    assert_eq!(follower_host.import_program(actor_pvm), actor_program);
    follower_host.allow_install(&genesis);

    let shared_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let leader_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        leader_host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let follower_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        follower_host,
        100_000_000,
        5_000_000_000,
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
            .accumulate(&AccumulateRequestV2::Install(genesis))
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));
    assert_eq!(follower.catch_up().unwrap(), 1);
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
    leader.log_mut().commit_before_next_read_index(
        AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: promotion_tail,
            transition: promotion_transition,
            provided_blobs: vec![],
        })
        .encode(),
    );
    assert_eq!(leader.leadership_barrier_and_catch_up().unwrap(), 1);
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
    assert_eq!(follower.catch_up().unwrap(), 3);
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
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: second,
                transition: second_transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(leader.catch_up().unwrap(), 1);
    assert!(
        leader
            .service()
            .accumulate_host()
            .snapshot()
            .same_service_state(&follower.service().accumulate_host().snapshot())
    );
    assert_eq!(leader.log_mut().applied_index().unwrap(), 5);
    assert_eq!(follower.log_mut().applied_index().unwrap(), 5);
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
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesisV2 {
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

    let mut poison_host = LocalJamStoreV2::default();
    assert_eq!(poison_host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(poison_host.import_program(actor_pvm.clone()), actor_program);
    poison_host.allow_install(&genesis);
    let poison_shared = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let poison_log = TestCommittedLog::new(poison_shared.clone(), true);
    let mut poison_follower_host = LocalJamStoreV2::default();
    assert_eq!(
        poison_follower_host.import_blob(initial_bytes.clone()),
        initial
    );
    assert_eq!(
        poison_follower_host.import_program(actor_pvm.clone()),
        actor_program
    );
    poison_follower_host.allow_install(&genesis);
    let poison_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        poison_host,
        100_000_000,
        9_000_000,
    )
    .unwrap();
    let mut poisoned = ReplicatedJamServiceV2::new(poison_service, poison_log);
    let poison_follower_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        poison_follower_host,
        100_000_000,
        9_000_000,
    )
    .unwrap();
    let mut poison_follower = ReplicatedJamServiceV2::new(
        poison_follower_service,
        TestCommittedLog::new(poison_shared, false),
    );
    let poison_result = poisoned.accumulate(&AccumulateRequestV2::Install(genesis.clone()));
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

    let mut retry_host = DurableJamStoreV2::open(FailableCommittedImages {
        fail_next_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    assert_eq!(retry_host.import_blob(initial_bytes), initial);
    assert_eq!(retry_host.import_program(actor_pvm), actor_program);
    retry_host.allow_install(&genesis);
    let retry_log =
        TestCommittedLog::new(Arc::new(Mutex::new(SharedCommittedLog::default())), true);
    let retry_service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        retry_host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let mut retryable = ReplicatedJamServiceV2::new(retry_service, retry_log);
    assert!(matches!(
        retryable.accumulate(&AccumulateRequestV2::Install(genesis)),
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

    let mut leader_host = LocalJamStoreV2::default();
    assert_eq!(leader_host.import_blob(initial_bytes.clone()), initial);
    assert_eq!(leader_host.import_program(actor_pvm.clone()), actor_program);
    leader_host.allow_install(&genesis);
    let mut follower_host = DurableJamStoreV2::open(FailableCommittedImages {
        fail_next_proof_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    assert_eq!(follower_host.import_blob(initial_bytes), initial);
    assert_eq!(follower_host.import_program(actor_pvm), actor_program);
    follower_host.allow_install(&genesis);

    let shared_log = Arc::new(Mutex::new(SharedCommittedLog::default()));
    let leader_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        leader_host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let follower_service = JamServiceV2::new(
        service_pvm.clone(),
        service_program,
        NoRefineProtocolHostV2,
        follower_host,
        100_000_000,
        5_000_000_000,
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
            .accumulate(&AccumulateRequestV2::Install(genesis))
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
    let refined = leader
        .service()
        .refine_actor_tree(&prepared.work, &prepared.imports)
        .expect("the leader obtains the exact Refine transition before proving it");
    let input = prepared.work.input_id();
    let mut producer = CanonicalTestProofProducer {
        proof: b"raft canonical proof".to_vec(),
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
    assert_eq!(entries.len(), 2, "PrepareAttested must not enter Raft");
    let AccumulateRequestV2::Apply(logged) =
        AccumulateRequestV2::decode(&entries[1].request).unwrap()
    else {
        panic!("the second Raft entry was not the proved Apply")
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
        2,
        "a duplicate attestation never proposes another Apply"
    );

    assert!(matches!(
        follower.catch_up(),
        Err(vos::v2::ReplicatedServiceErrorV2::ProofUnavailable)
    ));
    assert_eq!(
        follower.log_mut().applied_index().unwrap(),
        1,
        "a failed follower proof-CAS write leaves the proved Apply unapplied"
    );
    assert_eq!(
        follower.catch_up().unwrap(),
        1,
        "the identical committed proof entry is retried after CAS recovery"
    );
    assert_eq!(follower.log_mut().applied_index().unwrap(), 2);
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

    let snapshot_proofs = vec![ImportedBlobV2 {
        reference: committed.proof.proof_blob.clone(),
        bytes: committed.proof_bytes.clone(),
    }];
    let snapshot = CommittedServiceSnapshotV2 {
        applied_index: 2,
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
    let snapshot_host = DurableJamStoreV2::open(FailableCommittedImages {
        fail_next_proof_commit: true,
        ..FailableCommittedImages::default()
    })
    .unwrap();
    let snapshot_service = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        snapshot_host,
        100_000_000,
        5_000_000_000,
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
    assert_eq!(snapshot_follower.log_mut().applied_index().unwrap(), 2);
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

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    host.allow_install(&genesis);
    let service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
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
            .accumulate(&AccumulateRequestV2::Install(genesis))
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
        snapshot.encode(),
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
        100_000_000,
        5_000_000_000,
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
