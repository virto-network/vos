//! Physical generic-service PVM integration gate.
//!
//! Build the guest first with:
//! `cd services/vos-service && cargo +nightly actor`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vos::attestation::{
    AttestationProofProducerV2, AttestationProofRequestV2, AttestationStatementV3,
    ProducedAttestationProofV2,
};
use vos::network::RaftRpcHandler;
use vos::raft::{RaftAccumulateLogV2, RaftConfig, RaftWorker, WorkerConfig};
use vos::v2::{
    AccumulateRequestV2, AccumulatedReplyV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationResultV2, ActorGenesisV2, ActorId, ActorWriteV2, AttestationDeliveryV2,
    AttestationVerificationV2, AuthorizationEvidenceV2, BlobRefV2, CallId,
    CommittedAccumulateBatchV2, CommittedAccumulateEntryV2, CommittedAccumulateLogV2,
    CommittedImageStoreV2, CommittedServiceSnapshotV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationChangeV2, ContinuationSnapshotV2, DeploymentId, DurableJamStoreV2, GasAccountingV2,
    Hash, ImportedActorV2, ImportedBlobV2, ImportedProgramV2, InvocationId, JamServiceV2,
    LocalJamStoreV2, LocalWorkRequestV2, LocalWorkSchedulerV2, MessageRecordV2, MethodPolicyV2,
    NoRefineProtocolHostV2, Origin, ProducerId, ProgramId, ProofCommitmentV2,
    ProofVerificationRequestV2, PublicationAckV2, PublishedEffectsV2, ReceiptVerificationRequestV2,
    RefineImportsV2, RefineOutputV2, ReplicatedJamServiceV2, ReplyRecordV2, RootServiceId,
    ScheduleErrorV2, ServiceDispatchError, ServiceGenesisV2, ServiceIdentityV2, ServicePvmErrorV2,
    ServicePvmV2, SpaceRoleCredentialV2, StateKeyV2, SubjectId, TransitionV2, V2Wire,
    WorkEnvelopeV2, WorkflowOperationV2, public_policy_hash, space_role_policy_hash,
};
use vos::{
    Attestation, AttestedMethod, Decode, Encode, StateCommitmentV3,
    value::{Msg, Value},
};

enum PrivateStart {}

impl AttestedMethod<Vec<u8>> for PrivateStart {
    const METHOD: &'static str = "private_start";

    fn claim_wire(claim: &Vec<u8>) -> Vec<u8> {
        Value::Bytes(claim.clone()).encode()
    }

    fn decode_claim_wire(wire: &[u8]) -> Option<Vec<u8>> {
        match <Value as Decode>::try_decode(wire)? {
            Value::Bytes(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq,
)]
#[rkyv(crate = vos::rkyv)]
struct AgeClaimFixture {
    minimum_age: u8,
    adult: bool,
}

enum IsAdultFixture {}

impl AttestedMethod<AgeClaimFixture> for IsAdultFixture {
    const METHOD: &'static str = "is_adult";

    fn claim_wire(claim: &AgeClaimFixture) -> Vec<u8> {
        Value::Bytes(
            vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(claim)
                .expect("fixture claim encodes")
                .to_vec(),
        )
        .encode()
    }

    fn decode_claim_wire(wire: &[u8]) -> Option<AgeClaimFixture> {
        let Value::Bytes(bytes) = Value::try_decode(wire)? else {
            return None;
        };
        vos::rkyv::from_bytes::<AgeClaimFixture, vos::rkyv::rancor::Error>(&bytes).ok()
    }
}

#[derive(Debug, Default)]
struct FailableCommittedImages {
    image: Option<Vec<u8>>,
    fail_next_commit: bool,
}

#[derive(Debug)]
struct CanonicalTestProofProducer {
    trace: Hash,
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
            trace: self.trace,
            proof: self.proof.clone(),
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
}

impl TestCommittedLog {
    fn new(shared: Arc<Mutex<SharedCommittedLog>>, leader: bool) -> Self {
        Self {
            shared,
            applied: 0,
            leader,
        }
    }
}

impl CommittedAccumulateLogV2 for TestCommittedLog {
    type Error = TestLogError;

    fn propose(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        if !self.leader {
            return Err(TestLogError::NotLeader);
        }
        let mut shared = self.shared.lock().unwrap();
        let entry = CommittedAccumulateEntryV2 {
            index: shared.entries.len() as u64 + 1,
            request: request.to_vec(),
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

    fn mark_applied(&mut self, index: u64, _service_image: &[u8]) -> Result<(), Self::Error> {
        let committed = self.shared.lock().unwrap().entries.len() as u64;
        if index < self.applied || index > committed {
            return Err(TestLogError::InvalidCursor);
        }
        self.applied = index;
        Ok(())
    }
}

fn service_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../services/vos-service/target/riscv64em-javm/release/vos_service.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the generic guest first with `cd services/vos-service && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn greeter_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the actor first with `cd examples/actors/greeter && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn probe_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/probe/target/riscv64em-javm/release/probe.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the actor first with `cd examples/actors/probe && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn crdt_counter_v2_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "tests/fixtures/crdt-counter-v2/target/riscv64em-javm/release/crdt_counter_v2_fixture.elf",
    );
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the v2 CRDT fixture with `cd vos/tests/fixtures/crdt-counter-v2 && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn workflow_v2_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/workflow-v2/target/riscv64em-javm/release/workflow_v2_fixture.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the v2 workflow fixture with `cd vos/tests/fixtures/workflow-v2 && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn cycle_v2_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cycle-v2/target/riscv64em-javm/release/cycle_v2_fixture.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the v2 cycle fixture with `cd vos/tests/fixtures/cycle-v2 && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn age_gate_v2_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/v2/target/riscv64em-javm/release/v2_age_gate.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the v2 age-gate example with \
                 `cd examples/v2 && cargo +nightly actor -p v2-age-gate` ({})",
                path.display()
            );
            None
        }
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
        service: ServiceIdentityV2 {
            space: vos::v2::SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        },
        invocation: InvocationId([4; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: ActorId([5; 32]),
        target_program: actor_program,
        method: "start".into(),
        arguments: message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
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
            program: actor_program,
            state,
            causal_states: vec![],
            continuation: None,
        }],
        external_actors: vec![],
        imported_blobs: vec![],
        proof_requested: false,
    }
}

fn bound_peer_service(service: &ServiceIdentityV2) -> ServiceIdentityV2 {
    let mut peer = service.clone();
    peer.root_service = RootServiceId([45; 32]);
    peer.deployment = DeploymentId([46; 32]);
    peer
}

fn private_age_binding(service: &ServiceIdentityV2) -> vos::v2::ExternalActorBindingV2 {
    vos::v2::ExternalActorBindingV2 {
        name: "private-age".into(),
        service: bound_peer_service(service),
        actor: ActorId([44; 32]),
        producer: ProducerId([98; 32]),
        program: ProgramId([92; 32]),
    }
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
    let Some(elf) = service_elf() else {
        return;
    };
    let Some(actor_elf) = greeter_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
    };

    let output = service
        .refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
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

#[test]
fn same_tree_linear_calls_resume_the_exact_nested_stack() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), workflow_v2_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
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
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([54; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                methods: vec![
                    MethodPolicyV2 {
                        method: "call_child".into(),
                        schema: Hash([61; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "root_await_attested_peer".into(),
                        schema: Hash([86; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "root_child_await".into(),
                        schema: Hash([65; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "root_child_two_awaits".into(),
                        schema: Hash([73; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                ],
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([54; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                methods: vec![
                    MethodPolicyV2 {
                        method: "child_await_peer".into(),
                        schema: Hash([66; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "child_two_awaits".into(),
                        schema: Hash([74; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([62; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                ],
            },
        ],
        external_actors: vec![private_age_binding(&seed.service)],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([63; 32]),
            authenticator: vec![64],
        },
    });
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

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
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("guest-owned directory imports the complete root tree");
    assert_eq!(
        scheduled
            .work
            .imported_actors
            .iter()
            .map(|actor| actor.actor)
            .collect::<Vec<_>>(),
        vec![seed.target, child]
    );

    let refined = service
        .refine_actor_tree(&scheduled.work, &scheduled.imports)
        .expect("root calls its owned child through a JAR CALLABLE");
    assert_eq!(refined.transition.writes.len(), 2);
    assert_eq!(
        refined
            .transition
            .writes
            .iter()
            .map(|write| write.actor)
            .collect::<Vec<_>>(),
        vec![seed.target, child]
    );
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::U32(11))
    );
    assert_eq!(
        refined
            .transition
            .writes
            .iter()
            .map(|write| {
                u32::decode(
                    write
                        .value
                        .as_ref()
                        .expect("both state materializations are writes"),
                )
            })
            .collect::<Vec<_>>(),
        vec![11, 1]
    );

    let accepted = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: scheduled.work,
            transition: refined.transition,
            provided_blobs: refined.exported_blobs,
        }))
        .expect("guest Accumulate accepts the complete-tree transition");
    assert!(matches!(
        accepted.result,
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
            logical_timeslot: 2,
            target: seed.target,
            method: "root_child_await".into(),
            arguments: nested_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("the completed inline invocation leaves both actors idle");
    let runner = ServicePvmV2::new(service_pvm.clone(), ProgramId::of_pvm(&service_pvm)).unwrap();
    let first_bytes = runner
        .refine_actor_tree_with_backend(
            &nested.work.encode(),
            &nested.imports,
            1_000_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .expect("the child suspends inside the root's nested CALL");
    assert_eq!(
        runner
            .refine_actor_tree_with_backend(
                &nested.work.encode(),
                &nested.imports,
                1_000_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        first_bytes,
        "nested JAR checkpoints must be backend-independent"
    );
    let first_output = RefineOutputV2::decode(&first_bytes.bytes).unwrap();
    let first = first_output.transition;
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
            .map(|write| {
                u32::decode(
                    write
                        .value
                        .as_ref()
                        .expect("the checkpoint materializes each changed actor"),
                )
            })
            .collect::<Vec<_>>(),
        vec![21, 2]
    );
    for artifact in &first_bytes.exported_blobs {
        assert_eq!(
            service
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
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
    let first_apply = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: nested.work.clone(),
            transition: first,
            provided_blobs: vec![],
        }))
        .expect("guest Accumulate commits both pre-await mutations and the snapshot");
    assert!(matches!(
        first_apply.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let mut child_message = vec![vos::value::TAG_DYNAMIC];
    child_message.extend_from_slice(&Msg::new("increment").with("amount", 1u32).encode());
    let child_request = LocalWorkRequestV2 {
        invocation: InvocationId([72; 32]),
        workflow_step: 0,
        logical_timeslot: 3,
        target: child,
        method: "increment".into(),
        arguments: child_message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
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
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        restarted_store,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let reply = ReplyRecordV2 {
        call_id,
        producer: ActorId([44; 32]),
        result: Value::U32(7).encode(),
    };
    let peer_service = bound_peer_service(&seed.service);
    let awaited_reply = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: peer_service,
            accepted_transition: Hash([70; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([71; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply,
        attestation: None,
    };
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
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
            .all(|actor| actor.continuation.as_ref() == Some(&continuation))
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
            .map(|write| {
                u32::decode(
                    write
                        .value
                        .as_ref()
                        .expect("the resumed stack materializes both final states"),
                )
            })
            .collect::<Vec<_>>(),
        vec![30, 9]
    );
    let completed = restarted
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed.work,
            transition: resumed_output.transition,
            provided_blobs: vec![],
        }))
        .expect("guest Accumulate atomically completes the nested workflow");
    assert!(matches!(
        completed.result,
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
            awaited_reply: None,
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
    for artifact in &first_wait.exported_blobs {
        assert_eq!(
            restarted
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: twice.work,
                transition: first_wait.transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let first_reply = peer_reply(&seed.service, first_call, 1, 76);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
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
        vec![40, 11]
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
    for artifact in &second_wait.exported_blobs {
        assert_eq!(
            restarted
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: after_first.work,
                transition: second_wait.transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let second_reply = peer_reply(&seed.service, second_call, 2, 80);
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
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
        vec![53, 13]
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

    let attested_invocation = InvocationId([87; 32]);
    let mut attested_message = vec![vos::value::TAG_DYNAMIC];
    attested_message.extend_from_slice(&Msg::new("root_await_attested_peer").encode());
    let attested = LocalWorkSchedulerV2::prepare(
        restarted.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: attested_invocation,
            workflow_step: 0,
            logical_timeslot: 7,
            target: seed.target,
            method: "root_await_attested_peer".into(),
            arguments: attested_message,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    let waiting_for_attestation = restarted
        .refine_actor_tree(&attested.work, &attested.imports)
        .expect("the attested handle checkpoints before observing a package");
    let attested_call = attested_invocation.call_id(0);
    assert_eq!(waiting_for_attestation.transition.outbox.len(), 1);
    assert_eq!(
        waiting_for_attestation.transition.outbox[0].call_id,
        attested_call
    );
    assert!(waiting_for_attestation.transition.outbox[0].proof_requested);
    for artifact in &waiting_for_attestation.exported_blobs {
        assert_eq!(
            restarted
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: attested.work,
                transition: waiting_for_attestation.transition,
                provided_blobs: vec![],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let attested_reply = ReplyRecordV2 {
        call_id: attested_call,
        producer: ActorId([44; 32]),
        result: Value::U32(7).encode(),
    };
    let producer_service = bound_peer_service(&seed.service);
    let producer_receipt = AccumulationReceiptV2 {
        service: producer_service,
        accepted_transition: Hash([90; 32]),
        reply_commitment: Some(attested_reply.commitment()),
        outbox_commitment: None,
        resulting_state_root: Some(Hash([91; 32])),
        resulting_crdt_heads: vec![],
        sequence: 1,
        checkpoint: 0,
        consistency: ConsistencyModeV2::Local,
    };
    let statement = AttestationStatementV3 {
        statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
        space: producer_receipt.service.space,
        actor: attested_reply.producer,
        deployment: producer_receipt.service.deployment,
        actor_program: ProgramId([92; 32]),
        method: "peer_value".into(),
        schema: Hash([93; 32]),
        invocation: InvocationId::for_call(attested_call),
        before: vos::StateCommitmentV3::Linear(Hash([94; 32])),
        after: vos::StateCommitmentV3::Linear(Hash([91; 32])),
        claim_commitment: Hash::digest(b"vos/attestation-claim/v3", &[&attested_reply.result]),
        input_commitment: Hash([95; 32]),
        authorization_policy: Hash([96; 32]),
        accumulation_receipt: producer_receipt.clone(),
    };
    let proof_bytes = b"peer-proof".to_vec();
    let proof = ProofCommitmentV2 {
        statement: statement.commitment(),
        trace: Hash([97; 32]),
        proof_blob: BlobRefV2::of_bytes(&proof_bytes),
        statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
    };
    let accumulated = AccumulatedReplyV2 {
        reply: attested_reply,
        receipt: producer_receipt.clone(),
        attestation: Some(Box::new(AttestationDeliveryV2 {
            producer_name: "private-age".into(),
            producer: ProducerId([98; 32]),
            statement,
            proof: proof.clone(),
        })),
    };
    accumulated.validate().unwrap();
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(
            restarted.accumulate_host(),
            attested_invocation,
            8,
            Some(accumulated.clone()),
        ),
        Err(ScheduleErrorV2::MissingBlob(proof.proof_blob.hash)),
        "a proof commitment alone cannot resume the caller"
    );
    assert_eq!(
        restarted
            .accumulate_host_mut()
            .import_blob(proof_bytes.clone()),
        proof.proof_blob
    );
    restarted
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            receipt: producer_receipt,
        });
    let resumed_attestation = LocalWorkSchedulerV2::prepare_resume(
        restarted.accumulate_host(),
        attested_invocation,
        8,
        Some(accumulated),
    )
    .expect("the scheduler imports the exact content-addressed proof");
    assert!(
        resumed_attestation
            .imports
            .blobs
            .iter()
            .any(|blob| blob.reference == proof.proof_blob && blob.bytes == proof_bytes)
    );
    let attested_finished = restarted
        .refine_actor_tree(&resumed_attestation.work, &resumed_attestation.imports)
        .expect("the restored generated attestation call receives the committed package");
    assert_eq!(
        attested_finished
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::Bool(true))
    );
    assert!(matches!(
        restarted
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: resumed_attestation.work,
                transition: attested_finished.transition,
                provided_blobs: attested_finished.exported_blobs,
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
fn same_tree_causal_cycles_return_an_explicit_guest_error() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), cycle_v2_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
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
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([83; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                methods: vec![MethodPolicyV2 {
                    method: "root_cycle".into(),
                    schema: Hash([81; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                }],
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(seed.target),
                producer: ProducerId([83; 32]),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                methods: vec![MethodPolicyV2 {
                    method: "child_cycle".into(),
                    schema: Hash([82; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                }],
            },
        ],
        external_actors: vec![],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([83; 32]),
            authenticator: vec![84],
        },
    });
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
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
            awaited_reply: None,
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
}

#[test]
fn canonical_crdt_slice_refines_and_accumulates_without_native_apply() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), crdt_counter_v2_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
    let actor_pvm = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut work = work(actor_program, initial.clone());
    work.imported_actors[0].name = "counter".into();
    let child = ActorId([36; 32]);
    work.imported_actors.push(ImportedActorV2 {
        actor: child,
        name: "child".into(),
        parent: Some(work.target),
        program: actor_program,
        state: initial.clone(),
        causal_states: vec![],
        continuation: None,
    });
    work.method = "increment".into();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("increment").with("amount", 2u64).encode());
    work.arguments = message;
    work.consistency = ConsistencyModeV2::Crdt;
    work.base = ConsistencyBaseV2::Crdt { heads: vec![] };
    work.base_causal_height = Some(0);
    work.external_actors = vec![private_age_binding(&work.service)];

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
        service: work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![
            ActorGenesisV2 {
                actor: work.target,
                name: "counter".into(),
                parent: None,
                producer: ProducerId([53; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: true,
                methods: vec![
                    MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([44; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "increment_around_peer".into(),
                        schema: Hash([51; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "increment_child_around_peer".into(),
                        schema: Hash([52; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "increment_child_twice".into(),
                        schema: Hash([49; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                ],
            },
            ActorGenesisV2 {
                actor: child,
                name: "child".into(),
                parent: Some(work.target),
                producer: ProducerId([53; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: true,
                methods: vec![
                    MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([50; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                    MethodPolicyV2 {
                        method: "increment_around_peer".into(),
                        schema: Hash([53; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                ],
            },
        ],
        external_actors: vec![private_age_binding(&work.service)],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([46; 32]),
            authenticator: vec![1],
        },
    });
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
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
            awaited_reply: None,
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
            awaited_reply: None,
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
    assert_eq!(
        merge_imports.blobs.len(),
        3,
        "both root branches and the child's unchanged base are imported"
    );
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

    let mut nested_message = vec![vos::value::TAG_DYNAMIC];
    nested_message.extend_from_slice(
        &Msg::new("increment_child_twice")
            .with("amount", 3u64)
            .encode(),
    );
    let nested = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([51; 32]),
            workflow_step: 0,
            logical_timeslot: 2,
            target: work.target,
            method: "increment_child_twice".into(),
            arguments: nested_message,
            origin: work.origin,
            authorization: work.authorization,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    let nested_refined = service
        .refine_actor_tree(&nested.work, &nested.imports)
        .expect("one CRDT slice calls the same child twice inline");
    let nested_change = nested_refined.transition.crdt_change.as_ref().unwrap();
    assert_eq!(nested_change.operations.len(), 2);
    assert!(
        nested_change
            .operations
            .iter()
            .all(|operation| operation.actor == child)
    );
    let mut child_ordinals = nested_change
        .operations
        .iter()
        .map(|operation| operation.ordinal)
        .collect::<Vec<_>>();
    child_ordinals.sort_unstable();
    assert_eq!(child_ordinals, vec![0, 1]);
    assert_eq!(
        nested_change
            .materializations
            .iter()
            .map(|materialization| materialization.actor)
            .collect::<Vec<_>>(),
        vec![work.target, child]
    );
    assert_eq!(
        nested_refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::I64(6))
    );
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: nested.work,
                transition: nested_refined.transition,
                provided_blobs: nested_refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    // Refine two branches from the same causal base before either commits.
    // One branch checkpoints between two mutations; the other is a genuinely
    // concurrent replica update which must not be injected into the captured
    // heap when the first workflow resumes.
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
            invocation: InvocationId([52; 32]),
            workflow_step: 0,
            logical_timeslot: 3,
            target: work.target,
            method: "increment_child_around_peer".into(),
            arguments: around_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
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
            invocation: InvocationId([53; 32]),
            workflow_step: 0,
            logical_timeslot: 3,
            target: work.target,
            method: "increment".into(),
            arguments: concurrent_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    assert_eq!(around.work.base, concurrent.work.base);
    let around_refined = service
        .refine_actor_tree(&around.work, &around.imports)
        .expect("CRDT workflow checkpoints after its pre-await mutation");
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

    for artifact in &around_refined.exported_blobs {
        assert_eq!(
            service
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }

    let checkpoint_apply = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: around.work.clone(),
            transition: around_refined.transition,
            provided_blobs: vec![],
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
            accepted_transition: Hash([56; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([57; 32])),
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
    assert_eq!(resumed.work.base_causal_height, Some(4));
    assert!(resumed.work.imported_actors[0].causal_states.is_empty());
    let resumed_refined = service
        .refine_actor_tree(&resumed.work, &resumed.imports)
        .expect("restored CRDT machine rebinds to the new slice change");
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
                == resumed_change
                    .id
                    .operation(operation.actor, operation.field, 0)
    }));
    assert!(
        resumed_change
            .operations
            .iter()
            .any(|operation| operation.actor == work.target)
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
        Some(Value::I64(22)),
        "the suspended heap observes its own checkpoint branch, not the concurrent update"
    );
    let resumed_cid = resumed_change.cid();
    for artifact in &resumed_refined.exported_blobs {
        assert_eq!(
            service
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
    let resumed_apply = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed.work,
            transition: resumed_refined.transition,
            provided_blobs: vec![],
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = resumed_apply else {
        panic!("resumed CRDT transition was rejected")
    };
    let mut final_heads = vec![concurrent_cid, resumed_cid];
    final_heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, final_heads);

    let mut merged_arguments = vec![vos::value::TAG_DYNAMIC];
    merged_arguments.extend_from_slice(&Msg::new("increment").with("amount", 1u64).encode());
    let merged = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([58; 32]),
            workflow_step: 0,
            logical_timeslot: 5,
            target: work.target,
            method: "increment".into(),
            arguments: merged_arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
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
        Some(Value::I64(34))
    );
}

#[test]
fn canonical_guest_rejects_a_nested_actor_without_the_reply_abi() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
    };

    assert!(matches!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::Panic { vm: 0, .. })
    ));
}

#[test]
fn actor_tree_refuses_to_replay_a_continuation_from_pc_zero() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
fn yielding_actor_restores_exactly_after_restart() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), probe_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
    let service = ServicePvmV2::new(service_pvm.clone(), ProgramId::of_pvm(&service_pvm)).unwrap();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let seed_work = work(actor_program, initial_state_ref.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_state), initial_state_ref);
    assert_eq!(host.import_program(actor), actor_program);
    let mut committed_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([51; 32]),
            program: actor_program,
            initial_state: initial_state_ref,
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "ping".into(),
                schema: Hash([50; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
            }],
        }],
        external_actors: vec![],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([52; 32]),
            authenticator: vec![53],
        },
    });
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    committed_service
        .accumulate_host_mut()
        .allow_install(genesis);
    assert!(matches!(
        committed_service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let mut ping = vec![vos::value::TAG_DYNAMIC];
    ping.extend_from_slice(&Msg::new("ping").encode());
    let prepared = LocalWorkSchedulerV2::prepare(
        committed_service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: seed_work.invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed_work.target,
            method: "ping".into(),
            arguments: ping,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("guest-installed actor can be scheduled");
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
    let first = RefineOutputV2::decode(&first_output.bytes)
        .unwrap()
        .transition;
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
    for artifact in &first_output.exported_blobs {
        assert_eq!(
            committed_service
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
    let checkpoint = committed_service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_work.clone(),
            transition: first.clone(),
            provided_blobs: vec![],
        }))
        .expect("physical guest Accumulate commits the checkpoint");
    assert!(matches!(
        checkpoint.result,
        AccumulationResultV2::Accepted {
            published: PublishedEffectsV2 { reply: None, .. },
            duplicate: false,
            ..
        }
    ));

    // Simulate a process restart after guest Accumulate committed slice 0.
    // The read-only scheduler reconstructs the next work solely from the
    // canonical committed service image.
    let persisted = committed_service.accumulate_host().snapshot_bytes();
    let restarted_store = LocalJamStoreV2::from_snapshot_bytes(&persisted)
        .expect("canonical committed image survives process restart");
    let mut committed_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        restarted_store,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let resumed_prepared = LocalWorkSchedulerV2::prepare_resume(
        committed_service.accumulate_host(),
        first_work.invocation,
        2,
        None,
    )
    .expect("committed checkpoint reconstructs exact resume work");
    let resumed_work = resumed_prepared.work;
    let resumed_imports = resumed_prepared.imports;
    assert_eq!(
        resumed_work.imported_actors[0].state,
        BlobRefV2::of_bytes(&checkpoint_state)
    );
    assert_eq!(
        resumed_work.imported_actors[0].continuation.as_ref(),
        Some(&first_continuation)
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
    let resumed = RefineOutputV2::decode(&resumed_output.bytes)
        .unwrap()
        .transition;
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
    let header = committed_service
        .accumulate_host()
        .header()
        .unwrap()
        .unwrap();
    let continuation_bytes = committed_service
        .accumulate_host()
        .state_row(
            header.service_root,
            &StateKeyV2::Continuation(first_work.target),
        )
        .unwrap()
        .expect("Refine cannot delete durable continuation state");
    assert_eq!(
        BlobRefV2::decode(&continuation_bytes).unwrap(),
        first_continuation
    );
    let completed = committed_service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed_work,
            transition: resumed.clone(),
            provided_blobs: vec![],
        }))
        .expect("physical guest Accumulate commits completion");
    let AccumulationResultV2::Accepted {
        published,
        duplicate: false,
        ..
    } = completed.result
    else {
        panic!("resumed transition was rejected")
    };
    assert_eq!(published.reply, resumed.reply);

    let header = committed_service
        .accumulate_host()
        .header()
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::Continuation(first_work.target),
            )
            .unwrap(),
        None
    );
    let state_reference = committed_service
        .accumulate_host()
        .state_row(
            header.service_root,
            &StateKeyV2::ActorRow {
                actor: first_work.target,
                key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            },
        )
        .unwrap()
        .and_then(|bytes| BlobRefV2::decode(&bytes).ok())
        .expect("completed actor state remains guest-owned");
    assert_eq!(
        committed_service.accumulate_host().blob(&state_reference),
        Some(resumed_state.as_slice())
    );
}

#[test]
fn awaited_reply_is_injected_at_the_exact_machine_boundary() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), probe_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
    let service = ServicePvmV2::new(service_pvm.clone(), ProgramId::of_pvm(&service_pvm)).unwrap();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let seed_work = work(actor_program, initial_state_ref.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_state), initial_state_ref);
    assert_eq!(host.import_program(actor), actor_program);
    let mut committed_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "awaiting-probe".into(),
            parent: None,
            producer: ProducerId([51; 32]),
            program: actor_program,
            initial_state: initial_state_ref,
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "await_peer".into(),
                schema: Hash([50; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
            }],
        }],
        external_actors: vec![private_age_binding(&seed_work.service)],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([52; 32]),
            authenticator: vec![53],
        },
    });
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    committed_service
        .accumulate_host_mut()
        .allow_install(genesis);
    assert!(matches!(
        committed_service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let mut request = vec![vos::value::TAG_DYNAMIC];
    request.extend_from_slice(&Msg::new("await_peer").encode());
    let prepared = LocalWorkSchedulerV2::prepare(
        committed_service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: seed_work.invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: seed_work.target,
            method: "await_peer".into(),
            arguments: request,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("installed guest state prepares the initial actor slice");
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

    for artifact in &first_output.exported_blobs {
        assert_eq!(
            committed_service
                .accumulate_host_mut()
                .import_blob(artifact.bytes.clone()),
            artifact.reference
        );
    }
    let first_request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: first_work.clone(),
        transition: first.clone(),
        provided_blobs: vec![],
    });
    let first_apply = committed_service
        .accumulate(&first_request)
        .expect("physical guest Accumulate commits the checkpoint");
    let AccumulationResultV2::Accepted {
        published,
        duplicate: false,
        ..
    } = first_apply.result
    else {
        panic!("await checkpoint was rejected")
    };
    assert_eq!(published.outbox, first.outbox);

    // Simulate a complete process restart. The only retained workflow inputs
    // are now the guest-owned service rows and content-addressed blobs.
    let persisted = committed_service.accumulate_host().snapshot_bytes();
    let restarted_store = LocalJamStoreV2::from_snapshot_bytes(&persisted)
        .expect("canonical committed image survives process restart");
    let mut restarted_service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        restarted_store,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();

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
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(
            restarted_service.accumulate_host(),
            first_work.invocation,
            2,
            None,
        ),
        Err(ScheduleErrorV2::MissingAwaitedReply(call_id))
    );
    let mut wrong_awaited_reply = awaited_reply.clone();
    wrong_awaited_reply.reply.call_id = CallId([99; 32]);
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(
            restarted_service.accumulate_host(),
            first_work.invocation,
            2,
            Some(wrong_awaited_reply),
        ),
        Err(ScheduleErrorV2::UnexpectedAwaitedReply(CallId([99; 32])))
    );
    restarted_service
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            receipt: awaited_reply.receipt.clone(),
        });
    let resumed = LocalWorkSchedulerV2::prepare_resume(
        restarted_service.accumulate_host(),
        first_work.invocation,
        2,
        Some(awaited_reply.clone()),
    )
    .expect("restart reconstructs the workflow solely from committed guest state");
    let resumed_work = resumed.work;
    let resumed_imports = resumed.imports;
    assert_eq!(resumed_work.workflow_step, 1);
    assert_eq!(resumed_work.method, first_work.method);
    assert_eq!(resumed_work.arguments, first_work.arguments);
    assert_eq!(resumed_work.origin, first_work.origin);
    assert_eq!(resumed_work.authorization, first_work.authorization);
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
    let completed = restarted_service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed_work.clone(),
            transition: resumed.clone(),
            provided_blobs: resumed_output.exported_blobs,
        }))
        .expect("physical guest validates the remote receipt before commit");
    let AccumulationResultV2::Accepted {
        published,
        duplicate: false,
        ..
    } = completed.result
    else {
        panic!("resumed awaited transition was rejected")
    };
    assert_eq!(published.reply, resumed.reply);
    assert_eq!(
        LocalWorkSchedulerV2::prepare_resume(
            restarted_service.accumulate_host(),
            first_work.invocation,
            3,
            Some(awaited_reply),
        ),
        Err(ScheduleErrorV2::MissingContinuation(first_work.target)),
        "a committed completion cannot be resumed again"
    );
}

#[test]
fn canonical_guest_accumulate_installs_applies_and_deduplicates_at_ic5() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed_work = work(actor_program, initial.clone());
    seed_work.service.service_program = ProgramId::of_pvm(&pvm);
    let mut host = DurableJamStoreV2::open(FailableCommittedImages::default()).unwrap();
    assert_eq!(host.import_blob(initial_bytes), initial);
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

    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed_work.target,
                name: "root".into(),
                parent: None,
                producer: ProducerId([31; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                methods: vec![
                    MethodPolicyV2 {
                        method: "private_start".into(),
                        schema: Hash([32; 32]),
                        policy: space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap(),
                        public: false,
                        attested: true,
                    },
                    MethodPolicyV2 {
                        method: "start".into(),
                        schema: Hash([32; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    },
                ],
            },
            ActorGenesisV2 {
                actor: ActorId([36; 32]),
                name: "child".into(),
                parent: Some(seed_work.target),
                producer: ProducerId([31; 32]),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                methods: vec![],
            },
        ],
        external_actors: vec![],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
    let installed_output = service
        .accumulate(&install)
        .expect("guest install completes");
    let AccumulationResultV2::Installed(installed) = installed_output.result else {
        panic!("guest install rejected")
    };
    assert_eq!(service.accumulate_host().commit_sequence(), 1);
    assert_eq!(
        LocalWorkSchedulerV2::resolve_root(service.accumulate_host(), "root").unwrap(),
        Some(seed_work.target)
    );
    assert_eq!(
        LocalWorkSchedulerV2::resolve_child(service.accumulate_host(), seed_work.target, "child")
            .unwrap(),
        Some(ActorId([36; 32]))
    );
    assert_eq!(
        LocalWorkSchedulerV2::resolve_root(service.accumulate_host(), "child").unwrap(),
        None,
        "a child name cannot escape into the root namespace"
    );
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
        awaited_reply: None,
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
        vec![seed_work.target, ActorId([36; 32])]
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
        actor_program,
        await_ordinal: 0,
        pending_call: None,
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
        from: ActorId([71; 32]),
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
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"committed actor state".to_vec()),
        }],
        crdt_change: None,
        continuations: vec![ContinuationChangeV2 {
            actor: work.target,
            expected: None,
            replacement: Some(continuation_ref.clone()),
        }],
        inbox: vec![inbox.clone()],
        outbox: vec![],
        reply: None,
        attestation_verifications: vec![],
        exported_blobs: vec![continuation_ref.clone()],
        gas: GasAccountingV2::default(),
        proof: None,
    };

    let mut forbidden_attested_work = work.clone();
    forbidden_attested_work.proof_requested = true;
    let forbidden = service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: forbidden_attested_work,
                transition: transition.clone(),
                provided_blobs: vec![ImportedBlobV2 {
                    reference: continuation_ref.clone(),
                    bytes: continuation_bytes.clone(),
                }],
            },
        ))
        .expect("a suspending attested transition returns a stable rejection");
    assert_eq!(
        forbidden.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidWorkflowTransition)
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
        service.accumulate_host().backend().image.clone(),
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
    let pending = service
        .accumulate_host()
        .pending_publications()
        .expect("committed effects are recoverable before acknowledgement");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].input, work.input_id());
    assert_eq!(pending[0].receipt, receipt);
    assert_eq!(pending[0].published, published);
    let publication_commitment = pending[0].commitment();
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
    let snapshot_after_duplicate = service.accumulate_host().snapshot();
    assert!(snapshot_after_duplicate.same_service_state(&snapshot_after_apply));
    assert_eq!(
        service.accumulate_host().commit_sequence(),
        2,
        "a read-only duplicate transaction must not commit"
    );

    let persisted = service.accumulate_host().snapshot_bytes();
    let restarted = LocalJamStoreV2::from_snapshot_bytes(&persisted)
        .expect("guest-owned workflow rows survive durable restart");
    assert_eq!(
        restarted.pending_publications().unwrap(),
        pending,
        "restart must recover effects committed before external delivery"
    );
    let acknowledged = service
        .accumulate(&AccumulateRequestV2::AcknowledgePublication(
            PublicationAckV2 {
                service: work.service.clone(),
                input: work.input_id(),
                publication: publication_commitment,
            },
        ))
        .expect("publication acknowledgement executes through physical IC-5");
    assert_eq!(
        acknowledged.result,
        AccumulationResultV2::PublicationAcknowledged {
            input: work.input_id(),
            duplicate: false,
        }
    );
    assert!(
        service
            .accumulate_host()
            .pending_publications()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(&restarted, call_id, 50),
        Err(ScheduleErrorV2::ActorBusy(work.target))
    );
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(&restarted, call_id, 100),
        Err(ScheduleErrorV2::DeadlineExpired(call_id))
    );
    let mut queued = request.clone();
    queued.invocation = InvocationId([99; 32]);
    assert_eq!(
        LocalWorkSchedulerV2::prepare(&restarted, queued),
        Err(ScheduleErrorV2::ActorBusy(work.target))
    );

    let resumed = LocalWorkSchedulerV2::prepare_resume(&restarted, work.invocation, 51, None)
        .expect("restart reconstructs the next slice without process-local request state");
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
        "root state, child state, and continuation bytes are imported after restart"
    );

    let resumed_transition = TransitionV2 {
        service: resumed.work.service.clone(),
        consumed_input: resumed.work.input_id(),
        target_program: resumed.work.target_program,
        base: resumed.work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
        attestation_verifications: vec![],
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
    let delivered_transition = TransitionV2 {
        service: delivered.work.service.clone(),
        consumed_input: delivered.work.input_id(),
        target_program: delivered.work.target_program,
        base: delivered.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(vos::v2::ReplyRecordV2 {
            call_id,
            producer: delivered.work.target,
            result: b"durable inbox reply".to_vec(),
        }),
        attestation_verifications: vec![],
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let delivered_result = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: delivered.work.clone(),
            transition: delivered_transition,
            provided_blobs: vec![],
        }))
        .expect("guest commits delivery and consumes the inbox atomically");
    assert!(matches!(
        delivered_result.result,
        AccumulationResultV2::Accepted {
            published: PublishedEffectsV2 { reply: Some(_), .. },
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(service.accumulate_host(), call_id, 51).unwrap_err(),
        ScheduleErrorV2::MissingInbox(call_id),
        "a committed delivery cannot be scheduled from its inbox again"
    );

    let private_origin = Origin::Member(SubjectId([111; 32]));
    let private_policy = space_role_policy_hash(vos::SpaceRole::Member.as_u8()).unwrap();
    let private_credential = SpaceRoleCredentialV2 {
        holder: private_origin,
        role: vos::SpaceRole::Member,
        authenticator: b"private member credential".to_vec(),
    };
    let (private_authorization, private_witness) =
        private_credential.private_evidence(private_policy);
    let witness = service
        .accumulate_host_mut()
        .import_blob(private_witness.bytes);
    assert_eq!(witness, private_witness.reference);
    let prepared_proof_work = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([110; 32]),
            workflow_step: 0,
            logical_timeslot: 51,
            target: delivered.work.target,
            method: "private_start".into(),
            arguments: delivered.work.arguments.clone(),
            origin: private_origin,
            authorization: private_authorization,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![witness],
            proof_requested: true,
        },
    )
    .expect("scheduler imports a private role witness without disclosing it");
    let proof_work = prepared_proof_work.work;
    let proof_imports = prepared_proof_work.imports;
    let attested_call = proof_work.invocation.call_id(0);
    let proof_transition = TransitionV2 {
        service: proof_work.service.clone(),
        consumed_input: proof_work.input_id(),
        target_program: proof_work.target_program,
        base: proof_work.base.clone(),
        writes: vec![],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(vos::v2::ReplyRecordV2 {
            call_id: attested_call,
            producer: proof_work.target,
            result: Value::Bytes(b"attested reply".to_vec()).encode(),
        }),
        attestation_verifications: vec![],
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let before_prepare = service.accumulate_host().snapshot();
    let mut denied_work = proof_work.clone();
    let AuthorizationEvidenceV2::PrivateCredential { policy, .. } = &mut denied_work.authorization
    else {
        unreachable!()
    };
    *policy = Hash([200; 32]);
    let denied = service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: denied_work,
                transition: proof_transition.clone(),
                provided_blobs: vec![],
            },
        ))
        .expect("a private credential with the wrong policy is rejected");
    assert_eq!(
        denied.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_prepare)
    );

    let prepared = service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: proof_work.clone(),
                transition: proof_transition.clone(),
                provided_blobs: vec![],
            },
        ))
        .expect("guest predicts the attested receipt without committing");
    let AccumulationResultV2::Prepared(preparation) = prepared.result else {
        panic!("guest did not prepare the attested transition")
    };
    let predicted = preparation.receipt.clone();
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_prepare)
    );

    let policy = MethodPolicyV2 {
        method: "private_start".into(),
        schema: Hash([32; 32]),
        policy: private_policy,
        public: false,
        attested: true,
    };
    let statement = AttestationStatementV3::for_transition(
        &proof_work,
        &proof_transition,
        &policy,
        predicted.clone(),
    )
    .unwrap();
    assert_eq!(preparation.statement, statement);
    let proof_bytes = b"canonical proof bytes".to_vec();
    let proof_blob = BlobRefV2::of_bytes(&proof_bytes);
    let proof = ProofCommitmentV2 {
        statement: statement.commitment(),
        trace: Hash([101; 32]),
        proof_blob: proof_blob.clone(),
        statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
    };
    let verification = ProofVerificationRequestV2 {
        actor_program: proof_work.target_program,
        execution_semantics: proof_work.service.execution_semantics,
        statement: proof.statement,
        trace: proof.trace,
        proof_blob: proof_blob.clone(),
    };
    let before_invalid_proof = service.accumulate_host().snapshot();
    let mut unavailable_transition = proof_transition.clone();
    unavailable_transition.proof = Some(proof.clone());
    assert_eq!(
        unavailable_transition.commitment(),
        proof_transition.commitment(),
        "attaching proof bytes cannot change the proved transition commitment"
    );
    assert_eq!(
        AttestationStatementV3::for_transition(
            &proof_work,
            &unavailable_transition,
            &policy,
            predicted.clone(),
        )
        .unwrap(),
        statement,
        "the Apply statement must equal the guest's prepared public inputs"
    );
    let unavailable = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: proof_work.clone(),
            transition: unavailable_transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: proof_blob.clone(),
                bytes: proof_bytes.clone(),
            }],
        }))
        .expect("an unavailable proof verifier fails closed");
    assert_eq!(
        unavailable.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::ProofUnavailable)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_invalid_proof)
    );

    service.accumulate_host_mut().allow_proof(&verification);
    let mut tampered_transition = proof_transition.clone();
    let mut tampered_proof = proof.clone();
    tampered_proof.statement = Hash([102; 32]);
    tampered_transition.proof = Some(tampered_proof);
    let tampered = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: proof_work.clone(),
            transition: tampered_transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: proof_blob.clone(),
                bytes: proof_bytes.clone(),
            }],
        }))
        .expect("a tampered statement returns a stable rejection");
    assert_eq!(
        tampered.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidProof)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_invalid_proof)
    );

    let proof_input = proof_work.input_id();
    let before_empty_proof = service.accumulate_host().snapshot();
    let mut empty_producer = CanonicalTestProofProducer {
        trace: Hash::ZERO,
        proof: vec![],
        calls: 0,
    };
    assert!(matches!(
        service.accumulate_attested(
            AccumulationEnvelopeV2 {
                work: proof_work.clone(),
                transition: proof_transition.clone(),
                provided_blobs: vec![],
            },
            &proof_imports,
            &mut empty_producer,
        ),
        Err(vos::v2::AttestedServiceErrorV2::InvalidProducedProof)
    ));
    assert_eq!(empty_producer.calls, 1);
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_empty_proof),
        "proof production failure cannot reach committing Apply"
    );

    let mut producer = CanonicalTestProofProducer {
        trace: proof.trace,
        proof: proof_bytes.clone(),
        calls: 0,
    };
    let proved = service
        .accumulate_attested(
            AccumulationEnvelopeV2 {
                work: proof_work,
                transition: proof_transition,
                provided_blobs: vec![],
            },
            &proof_imports,
            &mut producer,
        )
        .expect("the driver proves before guest Accumulate commits");
    assert_eq!(producer.calls, 1);
    let invocation_result = proved
        .clone()
        .into_invocation_result("private-age".into(), ProducerId([112; 32]))
        .expect("committed proof output becomes the generated-handle transport");
    assert_eq!(
        invocation_result.value,
        Value::Bytes(b"attested reply".to_vec())
    );
    let application_package = proved
        .clone()
        .into_attestation::<Vec<u8>, PrivateStart>(
            "private-age".into(),
            ProducerId([112; 32]),
            b"attested reply".to_vec(),
        )
        .expect("a committed reply becomes the portable typed package");
    assert_eq!(application_package.unverified_preview(), b"attested reply");
    assert_eq!(
        application_package.statement(),
        &proved.preparation.statement
    );
    let (accumulated_reply, transported_proof) = proved
        .clone()
        .into_accumulated_reply("private-age".into(), ProducerId([112; 32]))
        .expect("only a committed proof output becomes durable reply input");
    assert_eq!(
        Value::decode(&accumulated_reply.reply.result),
        Value::Bytes(b"attested reply".to_vec())
    );
    assert_eq!(accumulated_reply.receipt, proved.preparation.receipt);
    assert_eq!(transported_proof.reference, proved.proof.proof_blob);
    assert_eq!(transported_proof.bytes, proof_bytes);
    assert_eq!(
        accumulated_reply
            .attestation
            .as_ref()
            .expect("attested reply carries package metadata")
            .statement,
        proved.preparation.statement
    );
    let receipt = proved.preparation.receipt;
    let published = proved.published;
    assert_eq!(receipt, predicted);
    assert_eq!(proved.proof, proof);
    assert_eq!(proved.proof_bytes, proof_bytes);
    assert_eq!(published.proof, Some(proved.proof));
    let pending_proof = service
        .accumulate_host()
        .pending_publications()
        .unwrap()
        .into_iter()
        .find(|publication| publication.input == proof_input)
        .expect("proof package remains recoverable until external acknowledgement");
    assert_eq!(pending_proof.receipt, receipt);
    assert_eq!(pending_proof.published, published);
}

#[test]
fn physical_guest_verifies_consumed_attestations_and_rejects_replay() {
    let Some(elf) = service_elf() else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"gate initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = ProgramId::of_pvm(&service_pvm);
    let source = private_age_binding(&seed.service);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([113; 32]),
            program: actor_program,
            initial_state: initial,
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([114; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
            }],
        }],
        external_actors: vec![source.clone()],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([115; 32]),
            authenticator: vec![116],
        },
    };
    service.accumulate_host_mut().allow_install(&genesis);
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Install(genesis))
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));

    let prepare = |invocation| LocalWorkRequestV2 {
        invocation,
        workflow_step: 0,
        logical_timeslot: 10,
        target: seed.target,
        method: "start".into(),
        arguments: seed.arguments.clone(),
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let prepared =
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), prepare(InvocationId([117; 32])))
            .unwrap();
    let source_after = Hash([118; 32]);
    let statement = AttestationStatementV3 {
        statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
        space: source.service.space,
        actor: source.actor,
        deployment: source.service.deployment,
        actor_program: source.program,
        method: "is_adult".into(),
        schema: Hash([119; 32]),
        invocation: InvocationId([120; 32]),
        before: StateCommitmentV3::Linear(Hash([121; 32])),
        after: StateCommitmentV3::Linear(source_after),
        claim_commitment: Hash([122; 32]),
        input_commitment: Hash([123; 32]),
        authorization_policy: Hash([124; 32]),
        accumulation_receipt: AccumulationReceiptV2 {
            service: source.service.clone(),
            accepted_transition: Hash([125; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(source_after),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
    };
    let proof_bytes = b"consumed attestation proof".to_vec();
    let proof_blob = BlobRefV2::of_bytes(&proof_bytes);
    let verification = AttestationVerificationV2 {
        source_name: source.name,
        producer: source.producer,
        statement,
        trace: Hash([126; 32]),
        proof_blob: proof_blob.clone(),
    };
    let request = ProofVerificationRequestV2 {
        actor_program: source.program,
        execution_semantics: source.service.execution_semantics,
        statement: verification.statement.commitment(),
        trace: verification.trace,
        proof_blob: proof_blob.clone(),
    };
    let transition_for = |work: &WorkEnvelopeV2, state: &[u8]| TransitionV2 {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(state.to_vec()),
        }],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: work.invocation.root_reply_id(),
            producer: work.target,
            result: b"admitted".to_vec(),
        }),
        attestation_verifications: vec![verification.clone()],
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let candidate = ImportedBlobV2 {
        reference: proof_blob,
        bytes: proof_bytes,
    };
    let before_unavailable = service.accumulate_host().snapshot();
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                transition: transition_for(&prepared.work, b"must not commit"),
                work: prepared.work.clone(),
                provided_blobs: vec![candidate.clone()],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::ProofUnavailable,)
    );
    assert_eq!(service.accumulate_host().snapshot(), before_unavailable);
    service.accumulate_host_mut().allow_proof(&request);
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                transition: transition_for(&prepared.work, b"admitted state"),
                work: prepared.work,
                provided_blobs: vec![candidate.clone()],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let commits = service.accumulate_host().commit_sequence();

    let replay =
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), prepare(InvocationId([127; 32])))
            .unwrap();
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                transition: transition_for(&replay.work, b"must not commit"),
                work: replay.work,
                provided_blobs: vec![candidate],
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::AttestationReplay,)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), commits);
}

#[test]
fn age_gate_guest_emits_the_proof_requirement_and_accumulate_enforces_once() {
    let (Some(service_elf), Some(gate_elf)) = (service_elf(), age_gate_v2_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
    let gate_pvm = grey_transpiler::link_elf(&gate_elf).unwrap();
    let gate_program = ProgramId::of_pvm(&gate_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(gate_program, initial.clone());
    seed.service.service_program = ProgramId::of_pvm(&service_pvm);
    let source = private_age_binding(&seed.service);

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(gate_pvm), gate_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        5_000_000_000,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "age-gate".into(),
            parent: None,
            producer: ProducerId([128; 32]),
            program: gate_program,
            initial_state: initial,
            crdt: false,
            methods: vec![
                MethodPolicyV2 {
                    method: "admit".into(),
                    schema: Hash([129; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                },
                MethodPolicyV2 {
                    method: "admitted".into(),
                    schema: Hash([130; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                },
            ],
        }],
        external_actors: vec![source.clone()],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([131; 32]),
            authenticator: vec![132],
        },
    };
    service.accumulate_host_mut().allow_install(&genesis);
    assert!(matches!(
        service
            .accumulate(&AccumulateRequestV2::Install(genesis))
            .unwrap()
            .result,
        AccumulationResultV2::Installed(_)
    ));

    let claim = AgeClaimFixture {
        minimum_age: 18,
        adult: true,
    };
    let source_after = Hash([133; 32]);
    let statement = AttestationStatementV3 {
        statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
        space: source.service.space,
        actor: source.actor,
        deployment: source.service.deployment,
        actor_program: source.program,
        method: IsAdultFixture::METHOD.into(),
        schema: Hash([134; 32]),
        invocation: InvocationId([135; 32]),
        before: StateCommitmentV3::Linear(Hash([136; 32])),
        after: StateCommitmentV3::Linear(source_after),
        claim_commitment: Hash::digest(
            b"vos/attestation-claim/v3",
            &[&IsAdultFixture::claim_wire(&claim)],
        ),
        input_commitment: Hash([137; 32]),
        authorization_policy: Hash([138; 32]),
        accumulation_receipt: AccumulationReceiptV2 {
            service: source.service.clone(),
            accepted_transition: Hash([139; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(source_after),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
    };
    let proof = b"age proof produced by the canonical actor trace".to_vec();
    let trace = Hash([140; 32]);
    let package = Attestation::<AgeClaimFixture, IsAdultFixture>::__from_runtime(
        source.name.clone(),
        source.producer,
        statement.clone(),
        trace,
        claim,
        proof.clone(),
    )
    .unwrap();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(
        &Msg::new("admit")
            .with("package", Value::Bytes(package.to_portable_bytes()))
            .encode(),
    );

    let prepare = |invocation| LocalWorkRequestV2 {
        invocation,
        workflow_step: 0,
        logical_timeslot: 10,
        target: seed.target,
        method: "admit".into(),
        arguments: message.clone(),
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let prepared =
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), prepare(InvocationId([141; 32])))
            .unwrap();
    let refined = service
        .refine_actor_tree(&prepared.work, &prepared.imports)
        .expect("real gate guest verifies without invoking the producer");
    assert_eq!(
        refined
            .transition
            .reply
            .as_ref()
            .map(|reply| Value::decode(&reply.result)),
        Some(Value::Bool(true))
    );
    assert_eq!(refined.transition.attestation_verifications.len(), 1);
    let requirement = &refined.transition.attestation_verifications[0];
    assert_eq!(requirement.source_name, "private-age");
    assert_eq!(requirement.producer, source.producer);
    assert_eq!(requirement.statement, statement);
    assert_eq!(requirement.trace, trace);
    assert_eq!(refined.exported_blobs.len(), 1);
    assert_eq!(refined.exported_blobs[0].bytes, proof);
    assert_eq!(refined.exported_blobs[0].reference, requirement.proof_blob);

    service
        .accumulate_host_mut()
        .allow_proof(&ProofVerificationRequestV2 {
            actor_program: source.program,
            execution_semantics: source.service.execution_semantics,
            statement: requirement.statement.commitment(),
            trace: requirement.trace,
            proof_blob: requirement.proof_blob.clone(),
        });
    let accepted = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: prepared.work,
            transition: refined.transition,
            provided_blobs: refined.exported_blobs,
        }))
        .unwrap();
    assert!(matches!(
        accepted.result,
        AccumulationResultV2::Accepted {
            published: PublishedEffectsV2 { reply: Some(_), .. },
            duplicate: false,
            ..
        }
    ));
    let committed = service.accumulate_host().snapshot();

    let replay_work =
        LocalWorkSchedulerV2::prepare(service.accumulate_host(), prepare(InvocationId([142; 32])))
            .unwrap();
    let replay_refined = service
        .refine_actor_tree(&replay_work.work, &replay_work.imports)
        .expect("Refine remains pure and deterministic against committed gate state");
    assert_eq!(replay_refined.transition.attestation_verifications.len(), 1);
    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: replay_work.work,
                transition: replay_refined.transition,
                provided_blobs: replay_refined.exported_blobs,
            }))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::AttestationReplay,)
    );
    assert_eq!(service.accumulate_host().snapshot(), committed);
}

#[test]
fn raft_failover_applies_committed_requests_through_the_physical_guest() {
    let Some(elf) = service_elf() else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesisV2 {
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([122; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([121; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
            }],
        }],
        external_actors: vec![],
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

    let first = LocalWorkSchedulerV2::prepare(
        leader.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([125; 32]),
            workflow_step: 0,
            logical_timeslot: 10,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let first_transition = TransitionV2 {
        service: first.service.clone(),
        consumed_input: first.input_id(),
        target_program: first.target_program,
        base: first.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: first.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"leader state".to_vec()),
        }],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: first.invocation.root_reply_id(),
            producer: first.target,
            result: b"leader reply".to_vec(),
        }),
        attestation_verifications: vec![],
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    assert!(matches!(
        leader
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: first,
                transition: first_transition,
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
            .same_service_state(&follower.service().accumulate_host().snapshot())
    );

    leader.log_mut().leader = false;
    follower.log_mut().leader = true;
    let second = LocalWorkSchedulerV2::prepare(
        follower.service().accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([126; 32]),
            workflow_step: 0,
            logical_timeslot: 11,
            target: seed.target,
            method: "start".into(),
            arguments: seed.arguments,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap()
    .work;
    let second_transition = TransitionV2 {
        service: second.service.clone(),
        consumed_input: second.input_id(),
        target_program: second.target_program,
        base: second.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: second.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"failover state".to_vec()),
        }],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: second.invocation.root_reply_id(),
            producer: second.target,
            result: b"failover reply".to_vec(),
        }),
        attestation_verifications: vec![],
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
    assert_eq!(leader.log_mut().applied_index().unwrap(), 3);
    assert_eq!(follower.log_mut().applied_index().unwrap(), 3);
}

#[test]
fn raft_orders_only_the_proved_attested_apply_and_followers_verify_it() {
    let Some(elf) = service_elf() else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft attested initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut seed = work(actor_program, initial.clone());
    seed.service.service_program = service_program;
    let genesis = ServiceGenesisV2 {
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([132; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([131; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: true,
            }],
        }],
        external_actors: vec![],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([133; 32]),
            authenticator: vec![134],
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
        service_program,
        NoRefineProtocolHostV2,
        leader_host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let follower_service = JamServiceV2::new(
        service_pvm,
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
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: true,
        },
    )
    .unwrap();
    let transition = TransitionV2 {
        service: prepared.work.service.clone(),
        consumed_input: prepared.work.input_id(),
        target_program: prepared.work.target_program,
        base: prepared.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: prepared.work.invocation.root_reply_id(),
            producer: prepared.work.target,
            result: b"raft attested reply".to_vec(),
        }),
        attestation_verifications: vec![],
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let input = prepared.work.input_id();
    let mut producer = CanonicalTestProofProducer {
        trace: Hash([136; 32]),
        proof: b"raft canonical proof".to_vec(),
        calls: 0,
    };
    let envelope = AccumulationEnvelopeV2 {
        work: prepared.work,
        transition,
        provided_blobs: vec![],
    };
    let committed = leader
        .accumulate_attested(envelope, &prepared.imports, &mut producer)
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
    assert_eq!(logged.transition.proof, Some(committed.proof));

    assert_eq!(follower.catch_up().unwrap(), 2);
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
}

#[test]
fn redb_raft_log_drives_physical_guest_accumulate() {
    let Some(elf) = service_elf() else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"raft-backed initial state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed = work(actor_program, initial.clone());
    let genesis = ServiceGenesisV2 {
        service: seed.service,
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
            producer: ProducerId([128; 32]),
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([127; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
            }],
        }],
        external_actors: vec![],
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
            image: None,
            fail_next_commit: true,
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
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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

#[test]
fn physical_guest_accumulate_authenticates_cross_root_delivery() {
    let Some(elf) = service_elf() else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);

    let mut source_seed = work(actor_program, initial.clone());
    source_seed.method = "start".into();
    let mut destination_identity = source_seed.service.clone();
    destination_identity.root_service = RootServiceId([60; 32]);
    destination_identity.deployment = DeploymentId([61; 32]);
    let destination_actor = ActorId([62; 32]);

    let make_service =
        |identity: ServiceIdentityV2,
         actor: ActorId,
         external_actors: Vec<vos::v2::ExternalActorBindingV2>| {
            let mut store = LocalJamStoreV2::default();
            assert_eq!(store.import_blob(initial_bytes.clone()), initial);
            assert_eq!(store.import_program(actor_pvm.clone()), actor_program);
            let mut service = JamServiceV2::new(
                service_pvm.clone(),
                service_program,
                NoRefineProtocolHostV2,
                store,
                100_000_000,
                5_000_000_000,
            )
            .unwrap();
            let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
                service: identity,
                consistency: ConsistencyModeV2::Local,
                actors: vec![ActorGenesisV2 {
                    actor,
                    name: "root".into(),
                    parent: None,
                    producer: ProducerId([64; 32]),
                    program: actor_program,
                    initial_state: initial.clone(),
                    crdt: false,
                    methods: vec![MethodPolicyV2 {
                        method: "start".into(),
                        schema: Hash([63; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    }],
                }],
                external_actors,
                authorization: AuthorizationEvidenceV2::SystemCapability {
                    capability: vos::v2::SystemCapabilityId([65; 32]),
                    authenticator: vec![66],
                },
            });
            let AccumulateRequestV2::Install(genesis) = &install else {
                unreachable!()
            };
            service.accumulate_host_mut().allow_install(genesis);
            assert!(matches!(
                service.accumulate(&install).unwrap().result,
                AccumulationResultV2::Installed(_)
            ));
            service
        };

    let destination_binding = vos::v2::ExternalActorBindingV2 {
        name: "destination".into(),
        service: destination_identity.clone(),
        actor: destination_actor,
        producer: ProducerId([64; 32]),
        program: actor_program,
    };
    let mut source = make_service(
        source_seed.service.clone(),
        source_seed.target,
        vec![destination_binding],
    );
    let mut destination = make_service(destination_identity, destination_actor, vec![]);
    let prepared = LocalWorkSchedulerV2::prepare(
        source.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: source_seed.invocation,
            workflow_step: 0,
            logical_timeslot: 1,
            target: source_seed.target,
            method: "start".into(),
            arguments: source_seed.arguments.clone(),
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .unwrap();
    let caller_invocation = prepared.work.invocation;
    let message = MessageRecordV2 {
        call_id: caller_invocation.call_id(0),
        caller_invocation,
        await_ordinal: 0,
        from: prepared.work.target,
        to: destination_actor,
        parent: None,
        payload: source_seed.arguments.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        proof_requested: false,
        deadline_timeslot: Some(10),
    };
    let transition = TransitionV2 {
        service: prepared.work.service.clone(),
        consumed_input: prepared.work.input_id(),
        target_program: prepared.work.target_program,
        base: prepared.work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: prepared.work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(initial_bytes),
        }],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![message.clone()],
        reply: None,
        attestation_verifications: vec![],
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let source_result = source
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: prepared.work,
            transition,
            provided_blobs: vec![],
        }))
        .unwrap();
    let AccumulationResultV2::Accepted {
        receipt: source_receipt,
        published,
        duplicate: false,
    } = source_result.result
    else {
        panic!("source outbox transition was rejected")
    };
    assert_eq!(published.outbox, vec![message.clone()]);
    assert_eq!(
        source_receipt.outbox_commitment,
        MessageRecordV2::outbox_commitment(&published.outbox)
    );

    let delivery = LocalWorkSchedulerV2::prepare_delivery(
        destination.accumulate_host(),
        2,
        message.clone(),
        published.outbox,
        source_receipt.clone(),
    )
    .unwrap();
    let before = destination.accumulate_host().snapshot();
    assert_eq!(
        destination
            .accumulate(&AccumulateRequestV2::Deliver(delivery.clone()))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::ReceiptUnavailable)
    );
    assert!(
        destination
            .accumulate_host()
            .snapshot()
            .same_service_state(&before)
    );

    destination
        .accumulate_host_mut()
        .allow_receipt(&ReceiptVerificationRequestV2 {
            receipt: source_receipt,
        });
    let accepted = destination
        .accumulate(&AccumulateRequestV2::Deliver(delivery.clone()))
        .unwrap();
    assert!(matches!(
        accepted.result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));
    let prepared_inbox =
        LocalWorkSchedulerV2::prepare_inbox(destination.accumulate_host(), message.call_id, 3)
            .expect("destination scheduler reads the guest-committed inbox");
    assert_eq!(prepared_inbox.work.target, destination_actor);
    assert_eq!(prepared_inbox.work.parent_call, Some(message.call_id));
    assert_eq!(prepared_inbox.work.origin, Origin::Actor(message.from));

    let sequence = destination.accumulate_host().commit_sequence();
    assert!(matches!(
        destination
            .accumulate(&AccumulateRequestV2::Deliver(delivery))
            .unwrap()
            .result,
        AccumulationResultV2::Accepted {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(destination.accumulate_host().commit_sequence(), sequence);
}
