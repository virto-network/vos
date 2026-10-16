//! Encodings pinned byte for byte, and Gray Paper structures captured from
//! PolkaJam.

use vos_wire::abi::Failure;
use vos_wire::batch::{Admin, Answer, Await, Batch, Body, Input, Message};
use vos_wire::ids::{
    AgentId, InstanceId, MapId, MethodId, Principal, ProgramHash, Session, SessionId, WorkflowId,
    derive_id,
};
use vos_wire::ingress::Grant;
use vos_wire::jam::{AccumulateInput, RefineArgs, WorkError};
use vos_wire::keys::{Due, Transform};
use vos_wire::records::{Derivation, Snapshot, Workflow, WorkflowState};
use vos_wire::result::{CommittedWrite, InputRef, Outcome, Outgoing, Page, Run, Write};
use vos_wire::{Decode, Encode};

use crate::strategies::{hex, round_trip};

/// Every stored table and every method is keyed by these ids, so a change
/// to their derivation would re-key them all. The values are BLAKE2b-256
/// computed by an implementation independent of the agent's.
#[test]
fn derived_ids_keep_their_values() {
    assert_eq!(derive_id("vos/method/", "increment"), 0xf251_d1d4);
    assert_eq!(derive_id("vos/table/", "counts"), 0xb6e2_e00c);
}

#[test]
fn natural_widths_follow_the_gray_paper() {
    let args = RefineArgs {
        core: 1,
        item: 0,
        service: 0x1234,
        payload: vec![9, 9],
        package_hash: [7; 32],
    };
    let mut expected = vec![1, 0, 0x80 | 0x12, 0x34, 2, 9, 9];
    expected.extend_from_slice(&[7; 32]);
    assert_eq!(args.encode(), expected);
}

/// Accumulate inputs stored by an echo service on a PolkaJam 0.1.29
/// testnet (Gray Paper 0.8.0): its endowment, an item that refined to
/// `vos:hello-jam`, and one refined with too little gas.
const CAPTURED_TRANSFER: &str = "01000000000100000000ca9a3b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001027000000000000";
const CAPTURED_OPERAND: &str = "00a9988cb4521e5f9843656c9c5d9314ec9564947a0636f028b7b473674546c6a100000000000000000000000000000000000000000000000000000000000000002357426f2313559a271d6782dc00197b379f79cbe3c6a1e72f61f7b592c509f855cce8aa97e3102b2cc8d13b3091c667b9d1460673a1ecd9cadc07186da7a56de0809698000d766f733a68656c6c6f2d6a616d00";
const CAPTURED_OUT_OF_GAS: &str = "0078de5d111ce5cfa3c0d499bb4287f771e9754c7cb790b1b44eb3bd81b8a4645e00000000000000000000000000000000000000000000000000000000000000002357426f2313559a271d6782dc00197b379f79cbe3c6a1e72f61f7b592c509f8fd593246befd8ae729199e893747b44a66167f02ebea141997db307719b492fee08096980100";

#[test]
fn captured_inputs_decode_and_reencode() {
    for captured in [CAPTURED_TRANSFER, CAPTURED_OPERAND, CAPTURED_OUT_OF_GAS] {
        let bytes = hex(captured);
        let input = AccumulateInput::decode(&bytes).expect("decodes");
        assert_eq!(input.encode(), bytes);
    }

    let AccumulateInput::Transfer(transfer) =
        AccumulateInput::decode(&hex(CAPTURED_TRANSFER)).unwrap()
    else {
        panic!("a transfer")
    };
    assert_eq!((transfer.source, transfer.destination), (0, 1));
    assert_eq!(transfer.amount, 1_000_000_000);
    assert_eq!(transfer.memo, [0; 128]);

    let AccumulateInput::Operand(operand) =
        AccumulateInput::decode(&hex(CAPTURED_OPERAND)).unwrap()
    else {
        panic!("an operand")
    };
    assert_eq!(
        operand.package_hash[..8],
        hex("a9988cb4521e5f98")[..],
        "the submitted package"
    );
    assert_eq!(operand.segment_root, [0; 32], "no exports");
    assert_eq!(
        operand.payload_hash[..],
        hex("55cce8aa97e3102b2cc8d13b3091c667b9d1460673a1ecd9cadc07186da7a56d")[..],
        "BLAKE2b-256 of the payload"
    );
    assert_eq!(operand.gas_limit, 10_000_000);
    assert_eq!(operand.result, Ok(b"vos:hello-jam".to_vec()));
    assert!(operand.auth_trace.is_empty());

    let AccumulateInput::Operand(starved) =
        AccumulateInput::decode(&hex(CAPTURED_OUT_OF_GAS)).unwrap()
    else {
        panic!("an operand")
    };
    assert_eq!(starved.result, Err(WorkError::OutOfGas));
}

/// An install names the programs derived from its package's ELF, its
/// kernels by method, and their provenance: in the batch, in the installed
/// record the agent keeps, and in the operator's request, which carries the
/// ELF.
#[test]
fn installs_keep_their_bytes() {
    use vos_wire::abi::cap::Target;
    use vos_wire::ingress::Install;
    use vos_wire::records::Installed;
    use vos_wire::schema::Schema;
    let derivation = Derivation {
        program: ProgramHash([3; 32]),
        kernels: vec![
            (MethodId(0x0a0b_0c0d), ProgramHash([1; 32])),
            (MethodId(0x0e0f_1011), ProgramHash([2; 32])),
        ],
        elf: [4; 32],
        transpiler: 5,
    };
    let kernel = |method: u32, program: &[u8]| [&method.to_le_bytes()[..], program].concat();
    let derived = [
        &[3; 32][..],
        &2u32.to_le_bytes(),
        &kernel(0x0a0b_0c0d, &[1; 32]),
        &kernel(0x0e0f_1011, &[2; 32]),
        &[4; 32],
        &5u32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(derivation.encode(), derived);
    let roles = [&1u32.to_le_bytes()[..], &1u32.to_le_bytes(), b"m", &[7]].concat();
    let admin = Admin::Install {
        instance: InstanceId(5),
        derivation: derivation.clone(),
        roles: vec![(b"m".to_vec(), 7)],
        target: Target::Jam,
    };
    let fields = [&5u32.to_le_bytes()[..], &derived, &roles, &[1]].concat();
    assert_eq!(admin.encode(), [&[0][..], &fields].concat());

    let installed = Installed {
        derivation,
        roles: vec![(b"m".to_vec(), 7)],
        schema: Schema { methods: vec![] },
        target: Target::Jam,
    };
    let record = [&derived[..], &roles, &0u32.to_le_bytes(), &[1]].concat();
    assert_eq!(installed.encode(), record);
    assert_eq!(
        installed.programs().collect::<Vec<_>>(),
        [
            ProgramHash([3; 32]),
            ProgramHash([1; 32]),
            ProgramHash([2; 32])
        ],
        "every program the agent pins"
    );
    assert_eq!(
        installed.kernel(MethodId(0x0e0f_1011)),
        Some(ProgramHash([2; 32]))
    );
    assert_eq!(installed.kernel(MethodId(1)), None);

    let install = Install {
        instance: InstanceId(5),
        elf: vec![9, 9],
        roles: vec![],
    };
    let request = [
        &5u32.to_le_bytes()[..],
        &2u32.to_le_bytes(),
        &[9, 9],
        &0u32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(install.encode(), request);
}

/// A run's committed writes follow its writes: each its map (instance, tag,
/// transform's index), its transformed key and its value; its pages follow
/// its attests. A value row holds the version that wrote it,
/// little-endian, then the value.
#[test]
fn committed_writes_keep_their_bytes() {
    let run = Run {
        input: InputRef::Admin,
        outcome: Outcome::Done(vec![]),
        instances: vec![],
        writes: vec![Write {
            key: vec![0xaa],
            value: None,
        }],
        committed: vec![CommittedWrite {
            map: MapId {
                instance: InstanceId(5),
                tag: 6,
                transform: Transform::Ordered,
            },
            key: vec![0xbb],
            value: Some(vec![0xcc]),
        }],
        messages: vec![],
        attests: vec![],
        pages: vec![Page {
            workflow: WorkflowId(3),
            index: 4,
            hash: None,
        }],
        gas_used: 9,
    };
    let bytes = [
        &[2u8, 0, 0, 0, 0, 0][..],
        &[0, 0, 0, 0],
        &[1, 0, 0, 0, 1, 0, 0, 0, 0xaa, 0],
        &[1, 0, 0, 0],
        &[5, 0, 0, 0, 6, 0, 0, 0, 1],
        &[1, 0, 0, 0, 0xbb, 1, 1, 0, 0, 0, 0xcc],
        &[0, 0, 0, 0, 0, 0, 0, 0],
        &[1, 0, 0, 0],
        &3u64.to_le_bytes(),
        &4u32.to_le_bytes(),
        &[0],
        &9u64.to_le_bytes(),
    ]
    .concat();
    assert_eq!(run.encode(), bytes);
    assert_eq!(Run::decode(&bytes).unwrap().0, run);
    assert_eq!(Transform::Hashed.encode(), [0]);
    assert_eq!(
        vos_wire::records::versioned(0x0102, &[0xdd]),
        [0x02, 0x01, 0, 0, 0, 0, 0, 0, 0xdd]
    );
    assert_eq!(
        vos_wire::records::unversioned(&[0x02, 0x01, 0, 0, 0, 0, 0, 0, 0xdd]),
        Some((0x0102, &[0xdd][..]))
    );
}

/// What a client signs: the domain, the agent's identity, then the fields
/// as encoded, the arguments as a byte vector (a little-endian `u32` count,
/// then the bytes).
#[test]
fn signed_messages_keep_their_bytes() {
    use vos_wire::ingress::{
        Call, Consistency, QueryCall, WorkflowRead, call_message, query_message, workflow_message,
    };
    let identity = [7; 32];
    let session = Session {
        key: [1; 32],
        name: [2; 16],
        t0: 3,
    };
    let (instance, method) = (InstanceId(5), MethodId(6));
    let consistency = Consistency::Applied { at: 8 };
    for len in [0usize, 1, 255, 256, 70_000] {
        let arguments: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let call = [
            b"vos/call/1".as_slice(),
            &identity,
            &session.encode(),
            &4u64.encode(),
            &instance.encode(),
            &method.encode(),
            &arguments.encode(),
        ]
        .concat();
        assert_eq!(
            call_message(&identity, &session, 4, instance, method, &arguments),
            call
        );
        let query = [
            b"vos/query/1".as_slice(),
            &identity,
            &[9; 32],
            &10u64.encode(),
            &consistency.encode(),
            &instance.encode(),
            &method.encode(),
            &arguments.encode(),
        ]
        .concat();
        assert_eq!(
            query_message(
                &identity,
                &[9; 32],
                10,
                consistency,
                instance,
                method,
                &arguments
            ),
            query
        );
    }
    let call = call_message(&identity, &session, 4, instance, method, &[0xaa, 0xbb]);
    assert!(call.ends_with(&[5, 0, 0, 0, 6, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb]));
    let read = [
        b"vos/workflow/1".as_slice(),
        &identity,
        &[9; 32],
        &10u64.to_le_bytes(),
        &[0],
        &8u64.to_le_bytes(),
        &11u64.to_le_bytes(),
        &12u64.to_le_bytes(),
    ]
    .concat();
    assert_eq!(
        workflow_message(&identity, &[9; 32], 10, consistency, WorkflowId(11), 12),
        read
    );
    // Each signed request's own message is its fields'.
    let signed = Call {
        session,
        sequence: 4,
        instance,
        method,
        arguments: vec![0xaa, 0xbb],
        signature: [0; 64],
    };
    assert_eq!(signed.message(&identity), call);
    let query = QueryCall {
        key: [9; 32],
        not_after: 10,
        consistency,
        instance,
        method,
        arguments: vec![0xaa, 0xbb],
        signature: [0; 64],
    };
    assert_eq!(
        query.message(&identity),
        query_message(
            &identity,
            &[9; 32],
            10,
            consistency,
            instance,
            method,
            &[0xaa, 0xbb]
        )
    );
    let workflow = WorkflowRead {
        key: [9; 32],
        not_after: 10,
        consistency,
        workflow: WorkflowId(11),
        wait_ms: 12,
        signature: [0; 64],
    };
    assert_eq!(workflow.message(&identity), read);
}

/// A workflow's status as its owner reads it: after the answer's index,
/// the status's, its fields, then the applied index read at.
#[test]
fn workflow_reads_keep_their_bytes() {
    use vos_wire::ingress::{Response, WorkflowStatus};
    let at = 5u64.to_le_bytes();
    let agent = 0x0a0b_0c0du32.to_le_bytes();
    let ended = Outcome::Done(vec![0xbb]);
    for (status, bytes) in [
        (WorkflowStatus::Unknown, vec![0]),
        (WorkflowStatus::Running, vec![1]),
        (
            WorkflowStatus::Awaiting {
                agent: AgentId(0x0a0b_0c0d),
                deadline: 7,
            },
            [&[2][..], &agent, &7u64.to_le_bytes()].concat(),
        ),
        (
            WorkflowStatus::Sleeping { until: 7 },
            [&[3][..], &7u64.to_le_bytes()].concat(),
        ),
        (
            WorkflowStatus::Ended(ended.clone()),
            [&[4][..], &ended.encode()].concat(),
        ),
    ] {
        let answer = Response::Workflow { status, at: 5 };
        assert_eq!(answer.encode(), [&[17][..], &bytes, &at].concat());
    }
}

/// The operator's grant, and the role change it becomes in a batch: the
/// principal, then the role; the batch's after its variant's index.
#[test]
fn role_changes_keep_their_bytes() {
    let principal = Principal::Agent(AgentId(0x0a0b_0c0d));
    for (role, encoded) in [(Some(3), &[0x01, 0x03][..]), (None, &[0x00][..])] {
        let fields = [&[0x01, 0x0d, 0x0c, 0x0b, 0x0a], encoded].concat();
        let grant = Grant { principal, role };
        assert_eq!(grant.encode(), fields);
        assert_eq!(
            Admin::SetRole(grant).encode(),
            [&[0x01], fields.as_slice()].concat()
        );
    }
}

/// A message between agents: its sender and sequence, then its body after
/// the body's index. An await is its workflow, then its counter; a reply's
/// answer follows its await, after the answer's index. A message asserted
/// failed is its sender, sequence and await alone.
#[test]
fn messages_keep_their_bytes() {
    let awaiting = Await {
        workflow: WorkflowId(0x0102_0304_0506_0708),
        counter: 9,
    };
    let await_bytes = [0x0102_0304_0506_0708u64.to_le_bytes(), 9u64.to_le_bytes()].concat();
    let call = |awaiting| Body::Call {
        instance: InstanceId(5),
        method: MethodId(6),
        arguments: vec![0xaa],
        awaiting,
    };
    let call_fields = [5, 0, 0, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0xaa];
    let request = [&[0][..], &call_fields, &[1], &await_bytes].concat();
    assert_eq!(call(Some(awaiting)).encode(), request);
    assert_eq!(call(None).encode(), [&[0][..], &call_fields, &[0]].concat());
    let started = [&[2][..], &4u64.to_le_bytes()].concat();
    let wait = Body::Wait {
        workflow: WorkflowId(4),
        awaiting,
    };
    assert_eq!(
        wait.encode(),
        [&[2][..], &4u64.to_le_bytes(), &await_bytes].concat()
    );
    assert_eq!(wait.awaiting(), Some(awaiting));
    assert_eq!(call(None).awaiting(), None);
    for (answer, bytes) in [
        (Answer::Done(vec![0xbb]), &[0, 1, 0, 0, 0, 0xbb][..]),
        (
            Answer::Failed {
                code: Failure::InRefine,
                detail: vec![],
            },
            &[1, 9, 0, 0, 0, 0, 0, 0, 0][..],
        ),
        (Answer::Started(WorkflowId(4)), &started[..]),
    ] {
        let reply = Body::Reply { awaiting, answer };
        assert_eq!(reply.encode(), [&[1][..], &await_bytes, bytes].concat());
    }

    let agent = 0x0a0b_0c0du32.to_le_bytes();
    let message = Message {
        from: AgentId(0x0a0b_0c0d),
        sequence: 3,
        body: call(Some(awaiting)),
    };
    let message_bytes = [&agent[..], &3u64.to_le_bytes(), &request].concat();
    assert_eq!(message.encode(), message_bytes);
    assert_eq!(
        Input::Message(message.clone()).encode(),
        [&[1][..], &message_bytes].concat()
    );
    // A failed one names its pair's sequence and its await, not its body.
    let failed = |awaiting| Input::Failed {
        from: AgentId(0x0a0b_0c0d),
        sequence: 3,
        awaiting,
    };
    let named = [&[5][..], &agent, &3u64.to_le_bytes()].concat();
    assert_eq!(
        failed(Some(awaiting)).encode(),
        [&named[..], &[1], &await_bytes].concat()
    );
    assert_eq!(failed(None).encode(), [&named[..], &[0]].concat());
    // The outbox holds the target, then the body.
    let outgoing = Outgoing {
        to: AgentId(0x0a0b_0c0d),
        body: message.body,
    };
    assert_eq!(outgoing.encode(), [&agent[..], &request].concat());
}

/// A batch: its version, time, seed and gas budget, then its inputs. A
/// sweep lists its rows of the due index, each its time and entry.
#[test]
fn batches_keep_their_bytes() {
    let batch = Batch {
        version: 1,
        time: 2,
        seed: [3; 32],
        budget: 4,
        inputs: vec![Input::Sweep {
            due: vec![
                (5, Due::Session(SessionId(6))),
                (7, Due::Workflow(WorkflowId(8))),
            ],
        }],
    };
    let bytes = [
        &1u64.to_le_bytes()[..],
        &2u64.to_le_bytes(),
        &[3; 32],
        &4u64.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[4],
        &2u32.to_le_bytes(),
        &5u64.to_le_bytes(),
        &[0],
        &6u64.to_le_bytes(),
        &7u64.to_le_bytes(),
        &[1],
        &8u64.to_le_bytes(),
    ]
    .concat();
    assert_eq!(batch.encode(), bytes);
}

/// A workflow's record and a step's page entries, byte for byte.
#[test]
fn workflows_keep_their_bytes() {
    let page = Page {
        workflow: WorkflowId(1),
        index: 2,
        hash: Some([3; 32]),
    };
    assert_eq!(
        page.encode(),
        [&1u64.to_le_bytes()[..], &2u32.to_le_bytes(), &[1], &[3; 32]].concat()
    );
    let record = Workflow {
        format: Workflow::FORMAT,
        program: ProgramHash([1; 32]),
        instance: InstanceId(2),
        method: MethodId(0x0e0f_1011),
        owner: Principal::Agent(AgentId(3)),
        gas: 4,
        writable: 5,
        awaits: 6,
        due: 7,
        waiter: None,
        state: WorkflowState::Sleeping { until: 8 },
        snapshot: Some(Snapshot {
            counter: 9,
            registers: vec![10],
            pages: vec![(12, [13; 32])],
            pending: Some(11),
        }),
        target: vos_wire::abi::cap::Target::Jam,
    };
    let bytes = [
        &[Workflow::FORMAT][..],
        &[1; 32],
        &2u32.to_le_bytes(),
        &0x0e0f_1011u32.to_le_bytes(),
        &[1],
        &3u32.to_le_bytes(),
        &4u64.to_le_bytes(),
        &5u32.to_le_bytes(),
        &6u64.to_le_bytes(),
        &7u64.to_le_bytes(),
        &[0],
        &[2],
        &8u64.to_le_bytes(),
        &[1],
        &9u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &10u64.to_le_bytes(),
        &1u32.to_le_bytes(),
        &12u32.to_le_bytes(),
        &[13; 32],
        &[1],
        &11u64.to_le_bytes(),
        &[1],
    ]
    .concat();
    assert_eq!(record.encode(), bytes);
    round_trip(&record);
    // Its head is its fields before the snapshot.
    let (head, used) = vos_wire::records::WorkflowHead::decode(&bytes).unwrap();
    assert_eq!(
        (head.method, head.owner, head.state),
        (record.method, record.owner, record.state.clone())
    );
    assert_eq!(
        (head.format, head.awaits, head.due),
        (Workflow::FORMAT, 6, 7)
    );
    assert_eq!(
        &bytes[used..],
        &[record.snapshot.encode(), record.target.encode()].concat()[..]
    );
    let ended = WorkflowState::Ended(Outcome::Started(WorkflowId(1)));
    round_trip(&ended);
    assert_eq!(
        WorkflowState::Preempted(vec![14]).encode(),
        [4, 1, 0, 0, 0, 14]
    );
}

/// An agent's id is its creator's number over 24 bits of its serial.
#[test]
fn an_agent_id_holds_its_creator_and_serial() {
    use vos_wire::peer::CreationRecord;
    let agent = CreationRecord::agent_id(0x0a, 0x0b_0c0d);
    assert_eq!(agent, AgentId(0x0a0b_0c0d));
    assert_eq!(CreationRecord::creator_of(agent), 0x0a);
    assert_eq!(CreationRecord::serial_of(agent), 0x0b_0c0d);
}

/// Every frame between nodes starts with its variant's index, the indexes
/// running from 0 without a gap. A directory acknowledgement's order is
/// its term, index and commitment, and a `Behind` names its pair alone.
#[test]
fn peer_messages_keep_their_bytes() {
    use vos_wire::ingress::{self, Call};
    use vos_wire::peer::{
        CreationRecord, Order, PeerMessage, Placement, Raft, SnapshotAck, SnapshotChunk,
    };
    let agent = AgentId(0x0a0b_0c0d);
    let record = CreationRecord {
        agent,
        replicas: vec![1],
        creator: 1,
        time: 0,
        program: ProgramHash([0; 32]),
        accumulate_gas: 0,
    };
    let order = Order {
        term: 2,
        index: 3,
        committed: true,
    };
    let message = Message {
        from: agent,
        sequence: 1,
        body: Body::Call {
            instance: InstanceId(0),
            method: MethodId(0),
            arguments: vec![],
            awaiting: None,
        },
    };
    let frames = [
        PeerMessage::Raft {
            agent,
            message: Raft::TimeoutNow { term: 1 },
        },
        PeerMessage::SnapshotChunk(SnapshotChunk {
            agent,
            term: 0,
            index: 0,
            snapshot_term: 0,
            sequence: 0,
            manifest: None,
            rows: vec![],
            last: true,
        }),
        PeerMessage::SnapshotAck(SnapshotAck {
            agent,
            term: 0,
            index: 0,
            next: 0,
        }),
        PeerMessage::BlobRequest {
            agent,
            hashes: vec![],
        },
        PeerMessage::Blob {
            hash: [0; 32],
            bytes: vec![],
        },
        PeerMessage::Liveness {
            incarnation: 0,
            round: 0,
            leading: vec![],
        },
        PeerMessage::Directory {
            placement: Placement::created(&record),
            record,
        },
        PeerMessage::DirectoryAck {
            agent,
            order,
            runs: false,
        },
        PeerMessage::DirectoryRequest { agent },
        PeerMessage::Forward {
            agent,
            token: 0,
            term: 0,
            call: Call {
                session: Session {
                    key: [0; 32],
                    name: [0; 16],
                    t0: 0,
                },
                sequence: 1,
                instance: InstanceId(0),
                method: MethodId(0),
                arguments: vec![],
                signature: [0; 64],
            },
        },
        PeerMessage::Forwarded {
            agent,
            token: 0,
            term: 0,
            answer: ingress::Response::Busy,
        },
        PeerMessage::ReadIndex { agent, token: 0 },
        PeerMessage::ReadIndexAnswer {
            agent,
            token: 0,
            index: None,
        },
        PeerMessage::Deliver {
            to: agent,
            message,
            relayed: false,
        },
        PeerMessage::Acknowledge {
            sender: agent,
            receiver: agent,
            sequence: 0,
            relayed: false,
        },
        PeerMessage::Behind {
            sender: agent,
            receiver: AgentId(4),
            relayed: true,
        },
    ];
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(usize::from(frame.encode()[0]), index, "{frame:?}");
    }
    let agent_bytes = 0x0a0b_0c0du32.to_le_bytes();
    assert_eq!(
        frames[7].encode(),
        [
            &[7][..],
            &agent_bytes,
            &2u64.to_le_bytes(),
            &3u64.to_le_bytes(),
            &[1, 0]
        ]
        .concat()
    );
    assert_eq!(
        frames[15].encode(),
        [&[15][..], &agent_bytes, &4u32.to_le_bytes(), &[1]].concat()
    );
}

/// JAM mode's payload and output, byte for byte: a package is the work
/// item's third kind, its batch, root, witness, imports and solicited
/// programs in order; a witness's keys each opened absent, with a value,
/// or by commitment; a range its bounds, rows and proof; the output its
/// roots, time, seed, result hash, export counts and solicited programs;
/// the exports accumulate keeps, their package, root and counts.
#[test]
fn packages_keep_their_bytes() {
    use vos_tree::{BatchProof, Entry, RangeProof};
    use vos_wire::batch::Work;
    use vos_wire::package::{JamOutput, Opened, Package, Row, ScannedRange, StateWitness};
    let batch = Batch {
        version: 1,
        time: 2,
        seed: [3; 32],
        budget: 4,
        inputs: vec![],
    };
    let package = Package {
        batch: batch.clone(),
        root: [5; 32],
        witness: StateWitness {
            keys: vec![
                (vec![6], Opened::Absent),
                (
                    vec![7],
                    Opened::Value {
                        salt: [8; 16],
                        value: vec![9],
                    },
                ),
                (vec![10], Opened::Written([11; 32])),
            ],
            proof: BatchProof {
                entries: vec![Entry::Empty],
            },
            ranges: vec![ScannedRange {
                from: vec![12],
                to: None,
                rows: vec![Row {
                    key: vec![13],
                    salt: [14; 16],
                    value: vec![15],
                }],
                proof: RangeProof {
                    entries: vec![Entry::Hash([16; 32])],
                },
            }],
        },
        imports: vec![(WorkflowId(17), 18)],
        solicit: vec![(ProgramHash([19; 32]), 20)],
    };
    let bytes = [
        &batch.encode()[..],
        &[5; 32],
        &3u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[6, 0],
        &1u32.to_le_bytes(),
        &[7, 1],
        &[8; 16],
        &1u32.to_le_bytes(),
        &[9],
        &1u32.to_le_bytes(),
        &[10, 2],
        &[11; 32],
        &1u32.to_le_bytes(),
        &[3],
        &1u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[12, 0],
        &1u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[13],
        &[14; 16],
        &1u32.to_le_bytes(),
        &[15],
        &1u32.to_le_bytes(),
        &[1],
        &[16; 32],
        &1u32.to_le_bytes(),
        &17u64.to_le_bytes(),
        &18u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[19; 32],
        &20u32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(package.encode(), bytes);
    round_trip(&package);
    let borrowed = Work::encode_package(&package);
    let work = Work::Package(package);
    assert_eq!(work.encode(), [&[2][..], &bytes].concat());
    assert_eq!(borrowed, work.encode());
    assert_eq!(work.batch(), Some(&batch));
    assert_eq!(
        Work::encode_batch(&batch),
        Work::Batch(batch.clone()).encode()
    );
    let output = JamOutput {
        root_before: [1; 32],
        root_after: [2; 32],
        time: 3,
        seed: [4; 32],
        work_result_hash: [5; 32],
        pages: 6,
        exports: 7,
        solicit: vec![(ProgramHash([8; 32]), 9)],
    };
    let bytes = [
        &[1; 32][..],
        &[2; 32],
        &3u64.to_le_bytes(),
        &[4; 32],
        &[5; 32],
        &6u32.to_le_bytes(),
        &7u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[8; 32],
        &9u32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(output.encode(), bytes);
    round_trip(&output);
    let exports = vos_wire::package::Exports {
        package: [4; 32],
        root: [1; 32],
        pages: 2,
        segments: 3,
    };
    let bytes = [
        &[4; 32][..],
        &[1; 32],
        &2u32.to_le_bytes(),
        &3u32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(exports.encode(), bytes);
}
