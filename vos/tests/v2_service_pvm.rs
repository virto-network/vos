//! Physical generic-service PVM integration gate.
//!
//! Build the service and actor guests first with:
//! `just build-v2-pvm-test-artifacts`.
//!
//! Missing guests are hard failures: these tests are a consensus-path gate,
//! not optional smoke tests.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vos::attestation::{
    AttestationProofProducerV2, AttestationProofRequestV2, ProducedAttestationProofV2,
};
use vos::network::RaftRpcHandler;
use vos::raft::{RaftAccumulateLogV2, RaftConfig, RaftWorker, WorkerConfig};
use vos::v2::{
    AccumulateRequestV2, AccumulatedReplyV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationResultV2, ActorGenesisV2, ActorId, ActorWriteV2, AuthorizationEvidenceV2,
    BlobRefV2, CommittedAccumulateBatchV2, CommittedAccumulateEntryV2, CommittedAccumulateLogV2,
    CommittedImageStoreV2, CommittedServiceSnapshotV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationChangeV2, ContinuationSnapshotV2, DeploymentId, DurableJamStoreV2, GasAccountingV2,
    Hash, ImportedActorV2, ImportedBlobV2, ImportedProgramV2, InboxDrainOutcomeV2, InvocationId,
    JamServiceV2, LocalJamStoreHostV2, LocalJamStoreV2, LocalTransportV2, LocalWorkRequestV2,
    LocalWorkSchedulerV2, MessageRecordV2, MethodPolicyV2, NoRefineProtocolHostV2, Origin,
    PackageRolePoliciesV2, ProducerId, ProgramId, PublishedEffectsV2, ReceiptVerificationRequestV2,
    RefineImportsV2, RefineOutputV2, ReplicatedJamServiceV2, ReplyRecordV2, RoleCredentialV2,
    RoleCredentialVerificationRequestV2, RootServiceId, ScheduleErrorV2, ServiceDispatchError,
    ServiceGenesisV2, ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, StateKeyV2, SubjectId,
    TransitionV2, V2Wire, WorkEnvelopeV2, public_policy_hash, space_role_policy_hash,
};
use vos::{
    AttestedMethod, Decode, Encode,
    value::{Msg, Value},
};

enum StartMethod {}

impl AttestedMethod<Vec<u8>> for StartMethod {
    const METHOD: &'static str = "start";

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

fn role_policies(methods: Vec<MethodPolicyV2>) -> Vec<u8> {
    PackageRolePoliciesV2 { methods }.encode()
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
    before_next_proposal: Vec<Vec<u8>>,
}

impl TestCommittedLog {
    fn new(shared: Arc<Mutex<SharedCommittedLog>>, leader: bool) -> Self {
        Self {
            shared,
            applied: 0,
            leader,
            before_next_proposal: Vec::new(),
        }
    }

    fn commit_before_next_proposal(&mut self, request: Vec<u8>) {
        self.before_next_proposal.push(request);
    }

    fn committed_len(&self) -> usize {
        self.shared.lock().unwrap().entries.len()
    }
}

impl CommittedAccumulateLogV2 for TestCommittedLog {
    type Error = TestLogError;

    fn propose(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        if !self.leader {
            return Err(TestLogError::NotLeader);
        }
        let mut shared = self.shared.lock().unwrap();
        for request in core::mem::take(&mut self.before_next_proposal) {
            let entry = CommittedAccumulateEntryV2 {
                index: shared.entries.len() as u64 + 1,
                request,
            };
            shared.entries.push(entry);
        }
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
        "../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn probe_elf() -> Vec<u8> {
    required_elf(
        "../examples/actors/probe/target/riscv64em-javm/release/probe.elf",
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
            service_program: vos::v2::VOS_SERVICE_PROGRAM_ID,
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
        causal_context: None,
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
        imported_blobs: vec![],
        proof_requested: false,
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
fn same_tree_linear_call_aggregates_private_actor_effects_in_the_service_guest() {
    let actor_pvm = grey_transpiler::link_elf(&workflow_v2_elf()).unwrap();
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
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed.target,
                name: "root".into(),
                parent: None,
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "call_child".into(),
                    schema: Hash([61; 32]),
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
                parent: Some(seed.target),
                program: actor_program,
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "increment".into(),
                    schema: Hash([62; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([63; 32]),
            authenticator: vec![64],
        },
    });
    authorize_install(&mut service, &install);
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
            causal_context: None,
            awaited_reply: None,
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
        service: work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor: work.target,
            name: "root".into(),
            parent: None,
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
        service: first_work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor: first_work.target,
            name: "root".into(),
            parent: None,
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
    assert!(matches!(
        first_result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

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

    assert_eq!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::Panic)
    );
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
        service: first_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: first_work.target,
            name: "root".into(),
            parent: None,
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
    let checkpoint_outcome = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_work.clone(),
            transition: first.clone(),
            provided_blobs: first_candidate_blobs,
        }))
        .unwrap();
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
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
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
        service: identity.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: caller,
                name: "root".into(),
                parent: None,
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
        to: target,
        parent: None,
        payload: payload.clone(),
        authorization: AuthorizationEvidenceV2::Public,
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
        imported_blobs: vec![],
        proof_requested: false,
    };
    let seeded = LocalWorkSchedulerV2::prepare(committed.accumulate_host(), seed_request).unwrap();
    let seed_transition = TransitionV2 {
        service: seeded.work.service.clone(),
        consumed_input: seeded.work.input_id(),
        target_program: seeded.work.target_program,
        base: seeded.work.base.clone(),
        writes: vec![],
        crdt_change: None,
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

    let first_reply = ReplyRecordV2 {
        call_id: first_call,
        producer: ActorId([44; 32]),
        result: vos::value::Value::U32(7).encode(),
    };
    let mut first_remote_service = identity.clone();
    first_remote_service.root_service = RootServiceId([70; 32]);
    first_remote_service.deployment = DeploymentId([71; 32]);
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
        target_program: expired_resume_work.target_program,
        base: expired_resume_work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
    let mut second_remote_service = identity;
    second_remote_service.root_service = RootServiceId([74; 32]);
    second_remote_service.deployment = DeploymentId([75; 32]);
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
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![
            ActorGenesisV2 {
                actor: seed_work.target,
                name: "root".into(),
                parent: None,
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
        actor_program,
        await_ordinal: 0,
        pending_call: None,
        causal_context: work.causal_context.clone(),
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
        to: work.target,
        parent: None,
        payload: work.arguments.clone(),
        authorization: AuthorizationEvidenceV2::Public,
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
        target_program: expired_work.target_program,
        base: expired_work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
        actor_program,
        await_ordinal: 0,
        pending_call: None,
        causal_context: delivered.work.causal_context.clone(),
        kernel_snapshot: vec![2],
    };
    let delivery_continuation_bytes = delivery_continuation.encode();
    let delivery_continuation_ref = BlobRefV2::of_bytes(&delivery_continuation_bytes);
    let delivery_checkpoint = TransitionV2 {
        service: delivered.work.service.clone(),
        consumed_input: delivered.work.input_id(),
        target_program: delivered.work.target_program,
        base: delivered.work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
        target_program: delivery_resume.work.target_program,
        base: delivery_resume.work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
        imported_blobs: vec![],
        proof_requested: false,
    };
    let caller = LocalWorkSchedulerV2::prepare(service.accumulate_host(), caller_request)
        .expect("idle caller is schedulable");
    let peer = ActorId([81; 32]);
    let awaited_call = caller.work.invocation.call_id(0);
    let continuation_bytes = ContinuationSnapshotV2 {
        snapshot_version: vos::v2::SNAPSHOT_VERSION,
        jar_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        vos_abi: vos::v2::ABI_VERSION,
        service: caller.work.service.clone(),
        invocation: caller.work.invocation,
        checkpoint_step: 0,
        actor: caller.work.target,
        actor_program,
        await_ordinal: 0,
        pending_call: Some(awaited_call),
        causal_context: caller.work.causal_context.clone(),
        kernel_snapshot: vec![4],
    }
    .encode();
    let continuation = BlobRefV2::of_bytes(&continuation_bytes);
    let outbound = MessageRecordV2 {
        call_id: awaited_call,
        caller_invocation: caller.work.invocation,
        await_ordinal: 0,
        from: caller.work.target,
        to: peer,
        parent: None,
        payload: caller.work.arguments.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        deadline_timeslot: Some(90),
    };
    let checkpoint = TransitionV2 {
        service: caller.work.service.clone(),
        consumed_input: caller.work.input_id(),
        target_program: caller.work.target_program,
        base: caller.work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: caller.work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"awaiting reply state".to_vec()),
        }],
        crdt_change: None,
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
    let mut remote_service = caller.work.service.clone();
    remote_service.root_service = RootServiceId([82; 32]);
    remote_service.deployment = DeploymentId([83; 32]);
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
        target_program: resume.work.target_program,
        base: resume.work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
        service: work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: work.target,
            name: "root".into(),
            parent: None,
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
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![],
        crdt_change: None,
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
        target_program: malformed_resume.target_program,
        base: malformed_resume.base.clone(),
        writes: vec![],
        crdt_change: None,
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
fn attested_driver_proves_before_guest_accumulate_commits() {
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = b"canonical attested actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"attested initial state".to_vec();
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
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
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
            result: Value::Bytes(b"attested claim".to_vec()).encode(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let envelope = AccumulationEnvelopeV2 {
        work: prepared.work,
        transition,
        provided_blobs: vec![],
    };
    let before = service.accumulate_host().snapshot();
    let mut invalid = CanonicalTestProofProducer {
        trace: Hash::ZERO,
        proof: vec![],
        calls: 0,
    };
    assert!(matches!(
        service.accumulate_attested(envelope.clone(), &prepared.imports, &mut invalid),
        Err(vos::v2::AttestedServiceErrorV2::InvalidProducedProof)
    ));
    assert_eq!(invalid.calls, 1);
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before),
        "proof production failure cannot commit the prepared transition"
    );

    let proof_bytes = vec![0xA6; 1024 * 1024];
    let mut producer = CanonicalTestProofProducer {
        trace: Hash([0xA5; 32]),
        proof: proof_bytes.clone(),
        calls: 0,
    };
    let committed = service
        .accumulate_attested(envelope.clone(), &prepared.imports, &mut producer)
        .expect("proof is available before guest Accumulate commits");
    assert_eq!(producer.calls, 1);
    let invocation_result = committed
        .clone()
        .into_invocation_result("attested-actor".into(), ProducerId([0xA8; 32]))
        .expect("committed proof output becomes the generated-handle transport");
    assert_eq!(
        invocation_result.value,
        Value::Bytes(b"attested claim".to_vec())
    );
    let application_package = committed
        .clone()
        .into_attestation::<Vec<u8>, StartMethod>(
            "attested-actor".into(),
            ProducerId([0xA8; 32]),
            b"attested claim".to_vec(),
        )
        .expect("a committed reply becomes the portable typed package");
    assert_eq!(application_package.unverified_preview(), b"attested claim");
    assert_eq!(
        application_package.statement(),
        &committed.preparation.statement
    );
    assert_eq!(committed.proof_bytes, proof_bytes);
    assert_eq!(committed.preparation.receipt.sequence, 1);
    assert_eq!(committed.published.proof, Some(committed.proof.clone()));
    assert_eq!(service.accumulate_host().commit_sequence(), 2);
    assert_eq!(
        service.accumulate_host().blob_count(),
        installed_blob_count,
        "a megabyte proof remains outside the recoverable service image"
    );

    let retried = service
        .accumulate_attested(envelope, &prepared.imports, &mut producer)
        .expect("an exact retry recovers the committed proof publication");
    assert_eq!(producer.calls, 1, "the cached proof is not regenerated");
    assert_eq!(retried.proof, committed.proof);
    assert_eq!(retried.proof_bytes, committed.proof_bytes);
    assert_eq!(retried.published, committed.published);
    assert_eq!(retried.accumulate_gas_used, 0);
    assert_eq!(
        service.accumulate_host().commit_sequence(),
        2,
        "the duplicate preparation neither reapplies nor commits"
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
        service: seed_work.service,
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
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
        service: seed_work.service,
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            name: "root".into(),
            parent: None,
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
fn finalized_outbox_is_durably_routed_across_service_restarts() {
    let service_pvm = vos::v2::transpile_service_elf(&service_elf()).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let actor_pvm = grey_transpiler::link_elf(&probe_elf()).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);

    let install_service = |identity: ServiceIdentityV2, actor: ActorId, method: &str| {
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
            service: identity,
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor,
                name: "root".into(),
                parent: None,
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
    let mut source = install_service(source_identity, source_actor, "await_peer");
    let destination = install_service(destination_identity, destination_actor, "peer_value");

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
        service: seed.service.clone(),
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
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
            causal_context: None,
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
        target_program: prior.target_program,
        base: prior.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: prior.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"interleaved state".to_vec()),
        }],
        crdt_change: None,
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
            expected_revision: 0,
            actual_revision: 1,
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
        1,
        "the earlier committed request is applied before the caller's proposal"
    );
    assert_eq!(follower.catch_up().unwrap(), 2);
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
            causal_context: None,
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
    assert_eq!(leader.log_mut().applied_index().unwrap(), 4);
    assert_eq!(follower.log_mut().applied_index().unwrap(), 4);
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
        service: seed.service,
        consistency: ConsistencyModeV2::Raft,
        actors: vec![ActorGenesisV2 {
            actor: seed.target,
            name: "root".into(),
            parent: None,
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
        image: None,
        fail_next_commit: true,
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
            causal_context: None,
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
    let elf = service_elf();
    let service_pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
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
