use proptest::prelude::*;
use vos_wire::abi::{self, Failure, Kind, Refusal, Rows, op};
use vos_wire::batch::{Admin, Answer, Await, Batch, Body, Input, Message, Request};
use vos_wire::ids::{
    AgentId, InstanceId, MapId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
    WorkflowId,
};
use vos_wire::ingress::Grant;
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs, Transfer, WorkError};
use vos_wire::keys::{self, Due, Transform};
use vos_wire::records::{Snapshot, Workflow, WorkflowState};
use vos_wire::result::{
    self, Attest, CommittedWrite, InputRef, InstanceGas, Outcome, Outgoing, Page, ResultWriter,
    Run, Step, WorkResult, Write,
};
use vos_wire::{Decode, Encode};

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..300)
}

fn principal() -> impl Strategy<Value = Principal> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(Principal::Client),
        any::<u32>().prop_map(|id| Principal::Agent(AgentId(id))),
        any::<u32>().prop_map(|id| Principal::Instance(InstanceId(id))),
    ]
}

fn session() -> impl Strategy<Value = Session> {
    (any::<[u8; 32]>(), any::<[u8; 16]>(), any::<u64>()).prop_map(|(key, name, t0)| Session {
        key,
        name,
        t0,
    })
}

fn transform() -> impl Strategy<Value = Transform> {
    prop_oneof![Just(Transform::Hashed), Just(Transform::Ordered)]
}

fn map() -> impl Strategy<Value = MapId> {
    (any::<u32>(), any::<u32>(), transform()).prop_map(|(instance, tag, transform)| MapId {
        instance: InstanceId(instance),
        tag,
        transform,
    })
}

fn failure() -> impl Strategy<Value = Failure> {
    (1u32..=9).prop_map(|code| Failure::from_code(code).unwrap())
}

fn refusal() -> impl Strategy<Value = Refusal> {
    (1u32..=6).prop_map(|code| Refusal::from_code(code).unwrap())
}

fn awaiting() -> impl Strategy<Value = Await> {
    (any::<u64>(), any::<u64>()).prop_map(|(workflow, counter)| Await {
        workflow: WorkflowId(workflow),
        counter,
    })
}

fn body() -> impl Strategy<Value = Body> {
    let answer = prop_oneof![
        bytes().prop_map(Answer::Done),
        (failure(), bytes()).prop_map(|(code, detail)| Answer::Failed { code, detail }),
        any::<u64>().prop_map(|id| Answer::Started(WorkflowId(id))),
    ];
    prop_oneof![
        (
            any::<u32>(),
            any::<u32>(),
            bytes(),
            prop::option::of(awaiting())
        )
            .prop_map(|(instance, method, arguments, awaiting)| Body::Call {
                instance: InstanceId(instance),
                method: MethodId(method),
                arguments,
                awaiting,
            }),
        (awaiting(), answer).prop_map(|(awaiting, answer)| Body::Reply { awaiting, answer }),
        (any::<u64>(), awaiting()).prop_map(|(workflow, awaiting)| Body::Wait {
            workflow: WorkflowId(workflow),
            awaiting,
        }),
    ]
}

fn message() -> impl Strategy<Value = Message> {
    (any::<u32>(), any::<u64>(), body()).prop_map(|(from, sequence, body)| Message {
        from: AgentId(from),
        sequence,
        body,
    })
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Command),
        Just(Kind::Query),
        Just(Kind::Attestable),
        Just(Kind::Workflow),
    ]
}

fn input() -> impl Strategy<Value = Input> {
    prop_oneof![
        (
            session(),
            any::<u64>(),
            principal(),
            any::<u32>(),
            any::<u32>(),
            bytes()
        )
            .prop_map(|(session, sequence, caller, instance, method, arguments)| {
                Input::Request(Request {
                    session,
                    sequence,
                    caller,
                    instance: InstanceId(instance),
                    method: MethodId(method),
                    arguments,
                })
            }),
        message().prop_map(Input::Message),
        (any::<u32>(), any::<u64>(), prop::option::of(awaiting())).prop_map(
            |(from, sequence, awaiting)| Input::Failed {
                from: AgentId(from),
                sequence,
                awaiting,
            }
        ),
        (
            any::<u32>(),
            any::<[u8; 32]>(),
            prop::collection::vec((any::<u32>(), kind(), any::<[u8; 32]>()), 0..3),
            prop::collection::vec((bytes(), any::<u8>()), 0..3),
        )
            .prop_map(|(instance, program, beside, roles)| {
                Input::Admin(Admin::Install {
                    instance: InstanceId(instance),
                    program: ProgramHash(program),
                    beside: beside
                        .into_iter()
                        .map(|(method, kind, program)| {
                            (MethodId(method), kind, ProgramHash(program))
                        })
                        .collect(),
                    roles,
                })
            }),
        (principal(), any::<Option<u8>>())
            .prop_map(|(principal, role)| Input::Admin(Admin::SetRole(Grant { principal, role }))),
        prop::collection::vec((any::<u64>(), due()), 0..4).prop_map(|due| Input::Sweep { due }),
    ]
}

fn due() -> impl Strategy<Value = Due> {
    prop_oneof![
        any::<u64>().prop_map(|id| Due::Session(SessionId(id))),
        any::<u64>().prop_map(|id| Due::Workflow(WorkflowId(id))),
    ]
}

fn step() -> impl Strategy<Value = Step> {
    let input = prop_oneof![
        (any::<u64>(), any::<u64>()).prop_map(|(session, sequence)| InputRef::Request {
            session: SessionRef::Known(SessionId(session)),
            sequence,
        }),
        (session(), any::<u64>()).prop_map(|(session, sequence)| InputRef::Request {
            session: SessionRef::New(Box::new(session)),
            sequence,
        }),
        (any::<u32>(), any::<u64>()).prop_map(|(from, sequence)| InputRef::Message {
            from: AgentId(from),
            sequence,
        }),
        Just(InputRef::Admin),
        any::<u64>().prop_map(|id| InputRef::Due {
            workflow: WorkflowId(id),
        }),
    ];
    let outcome = prop_oneof![
        bytes().prop_map(Outcome::Done),
        (failure(), bytes()).prop_map(|(code, detail)| Outcome::Failed { code, detail }),
        any::<u64>().prop_map(|id| Outcome::Started(WorkflowId(id))),
    ];
    let page = (any::<u64>(), any::<u32>(), any::<Option<[u8; 32]>>()).prop_map(
        |(workflow, index, hash)| Page {
            workflow: WorkflowId(workflow),
            index,
            hash,
        },
    );
    let instance = (any::<u32>(), any::<u64>()).prop_map(|(instance, gas)| InstanceGas {
        instance: InstanceId(instance),
        gas,
    });
    let write = (bytes(), prop::option::of(bytes())).prop_map(|(key, value)| Write { key, value });
    let committed = (map(), bytes(), prop::option::of(bytes()))
        .prop_map(|(map, key, value)| CommittedWrite { map, key, value });
    let outgoing = (any::<u32>(), body()).prop_map(|(to, body)| Outgoing {
        to: AgentId(to),
        body,
    });
    let attest =
        (any::<[u8; 32]>(), bytes(), bytes()).prop_map(|(program, arguments, output)| Attest {
            program: ProgramHash(program),
            arguments,
            output,
        });
    let ran = (
        input.clone(),
        outcome,
        prop::collection::vec(instance, 0..3),
        prop::collection::vec(write, 0..4),
        prop::collection::vec(committed, 0..3),
        prop::collection::vec(outgoing, 0..3),
        prop::collection::vec(attest, 0..2),
        prop::collection::vec(page, 0..3),
        any::<u64>(),
    )
        .prop_map(
            |(input, outcome, instances, writes, committed, messages, attests, pages, gas_used)| {
                Step::Ran(Run {
                    input,
                    outcome,
                    instances,
                    writes,
                    committed,
                    messages,
                    attests,
                    pages,
                    gas_used,
                })
            },
        );
    let refused = (input, refusal()).prop_map(|(input, code)| Step::Refused { input, code });
    prop_oneof![3 => ran, 1 => refused]
}

fn work_error() -> impl Strategy<Value = WorkError> {
    prop_oneof![
        Just(WorkError::OutOfGas),
        Just(WorkError::Panic),
        Just(WorkError::BadExports),
        Just(WorkError::Oversize),
        Just(WorkError::Bad),
        Just(WorkError::Big),
    ]
}

fn round_trip<T: Encode + Decode + PartialEq + std::fmt::Debug>(value: &T) {
    let bytes = value.encode();
    let (decoded, used) = T::decode(&bytes).expect("decode");
    assert_eq!(&decoded, value);
    assert_eq!(used, bytes.len());
}

proptest! {
    #[test]
    fn batches_round_trip(
        version in any::<u64>(),
        time in any::<u64>(),
        seed in any::<[u8; 32]>(),
        budget in any::<u64>(),
        inputs in prop::collection::vec(input(), 0..8),
    ) {
        round_trip(&Batch { version, time, seed, budget, inputs });
    }

    #[test]
    fn work_results_round_trip(
        version in any::<u64>(),
        time in any::<u64>(),
        seed in any::<[u8; 32]>(),
        steps in prop::collection::vec(step(), 0..6),
    ) {
        round_trip(&WorkResult { version, time, seed, steps });
    }

    #[test]
    fn refine_args_round_trip(
        core in any::<u64>(),
        item in any::<u64>(),
        service in any::<u64>(),
        payload in bytes(),
        package_hash in any::<[u8; 32]>(),
    ) {
        let args = RefineArgs { core, item, service, payload, package_hash };
        let bytes = args.encode();
        prop_assert_eq!(RefineArgs::decode(&bytes), Some(args));
        prop_assert_eq!(RefineArgs::decode(&bytes[..bytes.len() - 1]), None);
        let mut longer = bytes.clone();
        longer.push(0);
        prop_assert_eq!(RefineArgs::decode(&longer), None);
    }

    #[test]
    fn accumulate_inputs_round_trip(
        hashes in any::<[[u8; 32]; 4]>(),
        gas_limit in any::<u64>(),
        result in prop_oneof![bytes().prop_map(Ok), work_error().prop_map(Err)],
        auth_trace in bytes(),
        transfer in (any::<u32>(), any::<u32>(), any::<u64>(), any::<[u8; 32]>(), any::<u64>()),
    ) {
        let operand = AccumulateInput::Operand(Operand {
            package_hash: hashes[0],
            segment_root: hashes[1],
            authorizer: hashes[2],
            payload_hash: hashes[3],
            gas_limit,
            result,
            auth_trace,
        });
        let (source, destination, amount, memo, gas) = transfer;
        let mut memo_bytes = [0u8; 128];
        memo_bytes[..32].copy_from_slice(&memo);
        let transfer = AccumulateInput::Transfer(Transfer {
            source,
            destination,
            amount,
            memo: memo_bytes,
            gas,
        });
        for input in [operand, transfer] {
            let bytes = input.encode();
            prop_assert_eq!(AccumulateInput::decode(&bytes), Some(input));
            prop_assert_eq!(AccumulateInput::decode(&bytes[..bytes.len() - 1]), None);
            let mut longer = bytes.clone();
            longer.push(0);
            prop_assert_eq!(AccumulateInput::decode(&longer), None);
        }
    }

    #[test]
    fn instance_keys_never_meet_system_keys_or_other_instances(
        instance in any::<u32>(),
        other in any::<u32>(),
        tag in any::<u32>(),
        session in any::<u64>(),
        triple in session(),
        sequence in any::<u64>(),
        agent in any::<u32>(),
        member in principal(),
    ) {
        let instance = InstanceId(instance);
        let owned = [keys::instance_struct(instance), keys::table_prefix(instance, tag)];
        for key in &owned {
            prop_assert!(keys::owned_by(key, instance));
            prop_assert_eq!(keys::owned_by(key, InstanceId(other)), other == instance.0);
        }
        let system = [
            keys::installed(instance),
            keys::member(&member),
            keys::session(SessionId(session)),
            keys::reply(SessionId(session), sequence),
            keys::session_index(&triple),
            keys::session_of(SessionId(session)),
            keys::next_session(),
            keys::live_sessions(),
            keys::batch_time(),
            keys::pair_in(AgentId(agent)),
            keys::outbox(AgentId(agent), sequence),
            keys::pair_out(AgentId(agent)),
            keys::acked(AgentId(agent)),
            keys::version(),
        ];
        for key in &system {
            prop_assert!(!keys::owned_by(key, instance));
        }
        prop_assert!(keys::outbox(AgentId(agent), sequence).starts_with(&keys::outbox_prefix()));
    }

    /// No row key of any kind is a proper prefix of another, whatever the
    /// parts an actor or a client chooses: a tree over the whole keyspace
    /// needs prefix-free keys. Each kind's fixed parts have fixed widths,
    /// and its one variable part comes last, escaped or hashed.
    #[test]
    fn every_row_key_is_prefix_free(
        parts in prop::collection::vec(
            (any::<u32>(), any::<u32>(), transform(), bytes(), any::<u64>(), principal(), session(), any::<u16>()),
            2..5,
        ),
    ) {
        let mut rows = vec![
            keys::next_session(),
            keys::live_sessions(),
            keys::batch_time(),
            keys::version(),
            keys::next_workflow(),
            keys::live_workflows(),
        ];
        for (a, b, transform, key, number, member, triple, level) in parts {
            let instance = InstanceId(a);
            let map = MapId { instance, tag: b, transform };
            let transformed = transform.apply(&key);
            let level = level % 1024;
            let prefix = (level > 0)
                .then(|| transformed.get(..usize::from(level).div_ceil(8)))
                .flatten()
                .map(|bytes| bytes.to_vec());
            rows.extend([
                keys::instance_struct(instance),
                [keys::table_rows(instance, b, transform), transformed.clone()].concat(),
                keys::committed(&map, &transformed),
                keys::installed(instance),
                keys::member(&member),
                keys::session(SessionId(number)),
                keys::reply(SessionId(number), u64::from(a)),
                keys::pair_in(AgentId(a)),
                keys::outbox(AgentId(a), number),
                keys::pair_out(AgentId(a)),
                keys::acked(AgentId(a)),
                keys::session_index(&triple),
                keys::session_of(SessionId(number)),
                keys::due(number, Due::Session(SessionId(u64::from(b)))),
                keys::due(number, Due::Workflow(WorkflowId(u64::from(a)))),
                keys::workflow(WorkflowId(number)),
                keys::page(WorkflowId(number), a),
                keys::workflow_pins(&ProgramHash(triple.key)),
                keys::key_sessions(&triple.key),
                keys::dirty(number, &map, &transformed),
                keys::seed(number),
                keys::tree_leaf(&map, &transformed),
                keys::tree_root(&map),
                keys::built(),
            ]);
            if let Some(prefix) = prefix {
                rows.push(keys::tree_node(&map, level, &prefix));
            }
        }
        for row in &rows {
            for other in &rows {
                prop_assert!(
                    row == other || !other.starts_with(row),
                    "{row:?} prefixes {other:?}"
                );
            }
        }
    }

    /// A value row, a dirty row and a seed row name back what made them.
    #[test]
    fn committed_rows_name_their_parts(map in map(), key in bytes(), version in any::<u64>()) {
        let transformed = map.transform.apply(&key);
        prop_assert_eq!(map.transform.raw(&transformed), Some(key.clone()));
        let value = keys::committed(&map, &transformed);
        prop_assert!(value.starts_with(&keys::committed_rows(&map)));
        prop_assert!(keys::owned_by(&value, map.instance));
        prop_assert_eq!(keys::committed_entry(&value), Some((map, transformed.as_slice())));
        let dirty = keys::dirty(version, &map, &transformed);
        prop_assert!(dirty.starts_with(&keys::dirty_from(version)));
        prop_assert!(dirty.starts_with(&keys::dirty_prefix()));
        prop_assert_eq!(keys::dirty_entry(&dirty), Some((version, map, transformed.as_slice())));
        prop_assert_eq!(keys::committed_entry(&dirty), None);
        prop_assert!(keys::is_committed(&value) && !keys::is_committed(&dirty));
        let rows = Rows::Committed { tag: map.tag, transform: map.transform };
        if map.transform == Transform::Hashed || key.len() <= abi::cap::ORDERED_KEY {
            prop_assert_eq!(keys::row(map.instance, rows, &key), Ok(value.clone()));
        } else {
            prop_assert_eq!(keys::row(map.instance, rows, &key), Err(Failure::Cap));
        }
        let root = keys::tree_root(&map);
        prop_assert!(root.starts_with(&keys::tree_roots()));
        prop_assert_eq!(keys::tree_root_entry(&root), Some(map));
        let table = [keys::table_rows(map.instance, map.tag, map.transform), transformed].concat();
        prop_assert_eq!(keys::committed_entry(&table), None);
        prop_assert!(!keys::is_committed(&table));
    }

    #[test]
    fn replies_sort_by_session_then_sequence(
        a in any::<(u64, u64)>(),
        b in any::<(u64, u64)>(),
    ) {
        let key = |(session, sequence)| keys::reply(SessionId(session), sequence);
        prop_assert_eq!(key(a).cmp(&key(b)), a.cmp(&b));
    }

    #[test]
    fn session_indexes_sort_by_key_then_name_then_time(a in session(), b in session()) {
        let order = |session: &Session| (session.key, session.name, session.t0);
        prop_assert_eq!(
            keys::session_index(&a).cmp(&keys::session_index(&b)),
            order(&a).cmp(&order(&b))
        );
    }
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

#[test]
fn kinds_reach_only_their_operations() {
    let handlers = [
        op::INPUT,
        op::REPLY,
        op::FAIL,
        op::LOG,
        op::CALLER,
        op::NOW,
        op::RANDOM,
        op::GET,
        op::PUT,
        op::DELETE,
        op::SCAN,
        op::CALL,
        op::SEND,
        op::ATTEST,
        op::SELF_ID,
    ];
    let pauses = [op::REQUEST, op::RESULT, op::SLEEP];
    let writes = [op::PUT, op::DELETE, op::SEND, op::ATTEST];
    // A workflow holds no state and attests nothing: it reaches state
    // through calls, and does not ask who called.
    let stateful = [
        op::CALLER,
        op::GET,
        op::PUT,
        op::DELETE,
        op::SCAN,
        op::ATTEST,
    ];
    for id in handlers {
        assert!(abi::allowed(Kind::Command, id));
        assert_eq!(abi::allowed(Kind::Query, id), !writes.contains(&id));
        assert!(!abi::allowed(Kind::Attestable, id));
        assert_eq!(abi::allowed(Kind::Workflow, id), !stateful.contains(&id));
    }
    for id in pauses {
        assert!(abi::allowed(Kind::Workflow, id));
        assert!(!abi::allowed(Kind::Command, id));
        assert!(!abi::allowed(Kind::Query, id));
        assert!(!abi::allowed(Kind::Attestable, id));
        assert!(abi::surface::workflow(id));
    }
    for unknown in [0, 5, 0x480, 0x4ff, 0x507, 0x524, 0x52f, 0x533, 0x5ff] {
        assert!(!abi::allowed(Kind::Command, unknown));
        assert!(!abi::allowed(Kind::Query, unknown));
        assert!(!abi::allowed(Kind::Workflow, unknown));
    }
    assert!(abi::surface::workflow(abi::precompile::BLAKE2B_COMPRESS));
    assert!(!abi::surface::workflow(op::GET));
}

#[test]
fn result_codes_are_the_hosts() {
    use vos_pvm::refine_host::result;
    assert_eq!(abi::code::NONE, result::NONE);
    assert_eq!(abi::code::WHAT, result::WHAT);
    assert_eq!(abi::code::OOB, result::OOB);
    assert_eq!(abi::code::WHO, result::WHO);
    assert_eq!(abi::code::FULL, result::FULL);
    assert_eq!(abi::code::HUH, result::HUH);
    assert_eq!(abi::code::OK, result::OK);
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
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

#[test]
fn schemas_read_back_from_their_section_and_validate() {
    use vos_wire::schema::{MAGIC, MethodSchema, Schema, SchemaError};
    let method = |id: u32, kind| MethodSchema {
        id: MethodId(id),
        name: b"transfer".to_vec(),
        kind,
        role: Some(b"minter".to_vec()),
        gas: Some(1_000_000),
    };
    let schema = Schema {
        methods: vec![method(7, Kind::Command), method(9, Kind::Query)],
    };
    let mut ro_data = schema.section();
    ro_data.extend_from_slice(b"the rest of the read-only data");
    assert_eq!(Schema::read(&ro_data), Ok(schema.clone()));
    assert_eq!(&ro_data[..4], &MAGIC);
    assert_eq!(schema.method_id("transfer"), Some(MethodId(7)));
    assert_eq!(schema.method_id("mint"), None);

    assert_eq!(Schema::read(b"no schema here"), Err(SchemaError::Missing));
    let section = schema.section();
    assert_eq!(
        Schema::read(&section[..section.len() - 1]),
        Err(SchemaError::Size)
    );
    let duplicate = Schema {
        methods: vec![method(7, Kind::Command), method(7, Kind::Query)],
    };
    assert_eq!(
        Schema::read(&duplicate.section()),
        Err(SchemaError::Duplicate(MethodId(7)))
    );
    let reserved = Schema {
        methods: vec![method(0, Kind::Command)],
    };
    assert_eq!(
        Schema::read(&reserved.section()),
        Err(SchemaError::ReservedId)
    );
}

#[test]
fn kinds_encode_as_the_index_the_agent_passes() {
    assert_eq!(Kind::Command.encode(), [0]);
    assert_eq!(Kind::Query.encode(), [1]);
    assert_eq!(Kind::Attestable.encode(), [2]);
    assert_eq!(Kind::Workflow.encode(), [3]);
    assert!(Kind::decode(&[4]).is_err());
}

/// An install names its programs beside the actor's, each with its method
/// and kind: in the batch, in the installed record the agent keeps, and in
/// the operator's request, which carries the blobs.
#[test]
fn installs_keep_their_bytes() {
    use vos_wire::ingress::Install;
    use vos_wire::records::Installed;
    use vos_wire::schema::Schema;
    let beside = vec![
        (
            MethodId(0x0a0b_0c0d),
            Kind::Attestable,
            ProgramHash([1; 32]),
        ),
        (MethodId(0x0e0f_1011), Kind::Workflow, ProgramHash([2; 32])),
    ];
    let entry = |method: u32, kind: u8, program: &[u8]| {
        [&method.to_le_bytes()[..], &[kind], program].concat()
    };
    let entries = [
        &2u32.to_le_bytes()[..],
        &entry(0x0a0b_0c0d, 2, &[1; 32]),
        &entry(0x0e0f_1011, 3, &[2; 32]),
    ]
    .concat();
    let roles = [&1u32.to_le_bytes()[..], &1u32.to_le_bytes(), b"m", &[7]].concat();
    let admin = Admin::Install {
        instance: InstanceId(5),
        program: ProgramHash([3; 32]),
        beside: beside.clone(),
        roles: vec![(b"m".to_vec(), 7)],
    };
    let fields = [&5u32.to_le_bytes()[..], &[3; 32], &entries, &roles].concat();
    assert_eq!(admin.encode(), [&[0][..], &fields].concat());

    let installed = Installed {
        program: ProgramHash([3; 32]),
        beside: beside.clone(),
        roles: vec![(b"m".to_vec(), 7)],
        schema: Schema { methods: vec![] },
    };
    let record = [&[3; 32][..], &entries, &roles, &0u32.to_le_bytes()].concat();
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
        installed.bound(MethodId(0x0e0f_1011), Kind::Workflow),
        Some(ProgramHash([2; 32]))
    );
    assert_eq!(installed.attestable(MethodId(0x0e0f_1011)), None);

    let install = Install {
        instance: InstanceId(5),
        program: vec![9],
        beside: vec![(MethodId(0x0e0f_1011), Kind::Workflow, vec![8, 8])],
        roles: vec![],
    };
    let request = [
        &5u32.to_le_bytes()[..],
        &1u32.to_le_bytes(),
        &[9],
        &1u32.to_le_bytes(),
        &0x0e0f_1011u32.to_le_bytes(),
        &[3],
        &2u32.to_le_bytes(),
        &[8, 8],
        &0u32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(install.encode(), request);
}

#[test]
fn a_result_written_step_by_step_is_the_work_result_encoding() {
    let step = |sequence| Step::Refused {
        input: InputRef::Request {
            session: SessionRef::Known(SessionId(1)),
            sequence,
        },
        code: Refusal::Sequence,
    };
    let mut writer = ResultWriter::new(3, 4, [5; 32]);
    assert!(writer.push(&step(1), &[]));
    assert!(writer.push(&step(2), &[]));
    let result = WorkResult {
        version: 3,
        time: 4,
        seed: [5; 32],
        steps: vec![step(1), step(2)],
    };
    let output = writer.finish();
    assert_eq!(output, [result.encode(), 0u32.encode()].concat());
    assert_eq!(result::split_output(&output), Some((result, vec![])));

    let ran = |outcome| Run {
        input: InputRef::Admin,
        outcome,
        instances: vec![],
        writes: vec![],
        committed: vec![],
        messages: vec![],
        attests: vec![],
        pages: vec![],
        gas_used: 0,
    };
    let big = Step::Ran(ran(Outcome::Done(vec![0; abi::cap::WORK_RESULT / 3])));
    let mut writer = ResultWriter::new(0, 0, [0; 32]);
    assert!(writer.push(&big, &[]));
    assert!(writer.push(&big, &[]));
    assert!(!writer.push(&big, &[]), "a third would pass the cap");
    let (decoded, _) = WorkResult::decode(&writer.finish()).unwrap();
    assert_eq!(decoded.steps.len(), 2);

    // Pages follow the work result proper, in the order their steps list
    // them; past the section's cap a step waits.
    let pages = abi::cap::RESULT_PAGES / result::PAGE / 2;
    let stored: Vec<Vec<u8>> = (0..pages).map(|page| vec![page as u8; 3]).collect();
    let small = Step::Ran(ran(Outcome::Done(vec![])));
    let mut writer = ResultWriter::new(0, 0, [0; 32]);
    assert!(writer.push(&small, &stored));
    assert!(writer.push(&small, &stored));
    assert!(!writer.push(&small, &stored[..1]), "a page past the cap");
    assert!(writer.push(&small, &[]));
    let (result, section) = result::split_output(&writer.finish()).unwrap();
    assert_eq!(result.steps.len(), 3);
    assert_eq!(section, [stored.clone(), stored].concat());
}

/// A step at every cap, with as many writes (committed ones, the larger)
/// and instances as its gas pays for, and a request's reply, stays within
/// `STEP_RESULT`.
#[test]
fn the_largest_step_fits_its_bound() {
    use abi::cap;
    use vos_wire::defaults::MAX_HANDLER_GAS;
    let largest_await = Await {
        workflow: WorkflowId(u64::MAX),
        counter: u64::MAX,
    };
    let writes = (MAX_HANDLER_GAS / abi::price::PUT) as usize;
    let mut write_bytes = vec![0usize; writes];
    write_bytes[0] = cap::STEP_WRITES - writes;
    let step = Step::Ran(Run {
        input: InputRef::Request {
            session: SessionRef::New(Box::new(Session {
                key: [u8::MAX; 32],
                name: [u8::MAX; 16],
                t0: u64::MAX,
            })),
            sequence: u64::MAX,
        },
        outcome: Outcome::Done(vec![0; cap::REPLY]),
        instances: (0..=MAX_HANDLER_GAS / abi::price::MACHINE)
            .map(|instance| InstanceGas {
                instance: InstanceId(instance as u32),
                gas: 0,
            })
            .collect(),
        writes: vec![],
        committed: write_bytes
            .into_iter()
            .map(|len| CommittedWrite {
                map: MapId {
                    instance: InstanceId(0),
                    tag: 0,
                    transform: Transform::Hashed,
                },
                key: vec![0],
                value: Some(vec![0; len]),
            })
            .collect(),
        messages: (0..cap::MESSAGES)
            .map(|_| Outgoing {
                to: AgentId(0),
                body: Body::Call {
                    instance: InstanceId(0),
                    method: MethodId(0),
                    arguments: vec![0; cap::MESSAGE],
                    awaiting: Some(largest_await),
                },
            })
            .chain([Outgoing {
                to: AgentId(0),
                body: Body::Reply {
                    awaiting: largest_await,
                    answer: Answer::Failed {
                        code: Failure::Handler,
                        detail: vec![0; cap::REPLY],
                    },
                },
            }])
            .collect(),
        attests: (0..cap::ATTESTS)
            .map(|_| Attest {
                program: ProgramHash([0; 32]),
                arguments: vec![0; cap::REQUEST],
                output: vec![0; cap::REPLY],
            })
            .collect(),
        pages: vec![],
        gas_used: u64::MAX,
    });
    assert!(step.encode().len() <= cap::STEP_RESULT);

    // A workflow's step: its record, holding its arguments and a hash for
    // every page it may hold, its rows, and an entry for each page it drops
    // or stores, in place of a handler's attests.
    let workflow = WorkflowId(u64::MAX);
    let record = Workflow {
        format: u8::MAX,
        program: ProgramHash([0; 32]),
        instance: InstanceId(0),
        owner: Principal::Client([0; 32]),
        gas: u64::MAX,
        writable: u32::MAX,
        awaits: u64::MAX,
        due: u64::MAX,
        waiter: Some(largest_await),
        state: WorkflowState::Ready(vec![0; cap::REQUEST]),
        snapshot: Some(Snapshot {
            counter: u32::MAX,
            registers: vec![u64::MAX; 13],
            gas: u64::MAX,
            pages: (0..cap::HELD_PAGES as u32)
                .map(|page| (page, [0; 32]))
                .collect(),
        }),
    };
    let rows = [
        keys::workflow(workflow),
        keys::due(u64::MAX, Due::Workflow(workflow)),
        keys::due(u64::MAX, Due::Workflow(workflow)),
        keys::next_workflow(),
        keys::live_workflows(),
        keys::workflow_pins(&ProgramHash([0; 32])),
    ];
    let mut writes: Vec<Write> = rows
        .into_iter()
        .map(|key| Write {
            key,
            value: Some(u64::MAX.encode()),
        })
        .collect();
    writes[0].value = Some(record.encode());
    let pages: Vec<Page> = (0..2 * cap::HELD_PAGES as u32)
        .map(|index| Page {
            workflow,
            index,
            hash: Some([0; 32]),
        })
        .collect();
    let rows_bytes = writes.encode().len() + pages.encode().len();
    assert!(rows_bytes <= cap::WORKFLOW_ROWS, "{rows_bytes}");
}

/// Every value falls in a bucket that holds it, and the buckets run in
/// order without gaps.
#[test]
fn stage_buckets_hold_their_values_in_order() {
    use vos_wire::ingress::{BUCKETS, bucket, bucket_top};
    let mut previous_top = None;
    for index in 0..BUCKETS {
        let top = bucket_top(index);
        if let Some(previous) = previous_top {
            assert_eq!(
                bucket(previous + 1),
                index,
                "bucket {index} starts after {previous}"
            );
        }
        assert_eq!(bucket(top), index);
        previous_top = Some(top);
    }
    assert_eq!(previous_top, Some(u64::MAX));
    for value in [0, 7, 8, 9, 15, 16, 1_000, 999_999, u64::MAX] {
        assert!(bucket_top(bucket(value)) >= value);
    }
}

/// Every key's layout, byte for byte: each row tag once, the integers
/// big-endian. Stored state is keyed by these bytes.
#[test]
fn keys_keep_their_bytes() {
    let instance = InstanceId(0x1122_3344);
    let agent = AgentId(0x0a0b_0c0d);
    let session = SessionId(0x0102_0304_0506_0708);
    let id = [1, 2, 3, 4, 5, 6, 7, 8];
    let sequence = 0x090a_0b0c_0d0e_0f10u64;
    let at = [9, 10, 11, 12, 13, 14, 15, 16];
    let cat = |parts: &[&[u8]]| parts.concat();
    assert_eq!(
        keys::instance_struct(instance),
        [0x01, 0x11, 0x22, 0x33, 0x44, 0x00]
    );
    assert_eq!(
        keys::table_prefix(instance, 0xa1b2_c3d4),
        [0x01, 0x11, 0x22, 0x33, 0x44, 0x01, 0xa1, 0xb2, 0xc3, 0xd4]
    );
    assert_eq!(
        keys::instance_prefix(instance),
        [0x01, 0x11, 0x22, 0x33, 0x44]
    );
    assert_eq!(
        keys::installed(instance),
        [0x00, 0x01, 0x11, 0x22, 0x33, 0x44]
    );
    assert_eq!(keys::installed_prefix(), [0x00, 0x01]);
    assert_eq!(
        keys::member(&Principal::Agent(agent)),
        [0x00, 0x02, 0x01, 0x0d, 0x0c, 0x0b, 0x0a]
    );
    assert_eq!(keys::session(session), cat(&[&[0x00, 0x03], &id]));
    assert_eq!(
        keys::reply(session, sequence),
        cat(&[&[0x00, 0x04], &id, &at])
    );
    assert_eq!(keys::pair_in(agent), [0x00, 0x05, 0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(
        keys::outbox(agent, sequence),
        cat(&[&[0x00, 0x06, 0x0a, 0x0b, 0x0c, 0x0d], &at])
    );
    assert_eq!(keys::outbox_prefix(), [0x00, 0x06]);
    assert_eq!(keys::pair_out(agent), [0x00, 0x07, 0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(keys::acked(agent), [0x00, 0x08, 0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(keys::version(), [0x00, 0x09]);
    let triple = Session {
        key: [0xee; 32],
        name: [0xdd; 16],
        t0: sequence,
    };
    let index = cat(&[&[0x00, 0x0a], &[0xee; 32], &[0xdd; 16], &at]);
    assert_eq!(keys::session_index(&triple), index);
    assert_eq!(keys::session_index_key(&triple), index.as_slice());
    assert_eq!(keys::next_session(), [0x00, 0x0b]);
    assert_eq!(keys::live_sessions(), [0x00, 0x0c]);
    assert_eq!(keys::batch_time(), [0x00, 0x0d]);
    assert_eq!(keys::session_of(session), cat(&[&[0x00, 0x0e], &id]));
    let due = cat(&[&[0x00, 0x0f], &at, &[0], &id]);
    assert_eq!(keys::due(sequence, Due::Session(session)), due);
    assert_eq!(keys::due_prefix(), [0x00, 0x0f]);
    assert_eq!(
        keys::due_entry(&due),
        Some((sequence, Due::Session(session)))
    );
    let workflow = WorkflowId(session.0);
    let woken = cat(&[&[0x00, 0x0f], &at, &[1], &id]);
    assert_eq!(keys::due(sequence, Due::Workflow(workflow)), woken);
    assert_eq!(
        keys::due_entry(&woken),
        Some((sequence, Due::Workflow(workflow)))
    );
    assert_eq!(keys::due_entry(&keys::session_of(session)), None);
    assert_eq!(
        keys::due_entry(&cat(&[&[0x00, 0x0f], &at, &[2], &id])),
        None
    );
    assert_eq!(
        keys::key_sessions(&[0xee; 32]),
        cat(&[&[0x00, 0x10], &[0xee; 32]])
    );
    assert_eq!(keys::workflow(workflow), cat(&[&[0x00, 0x13], &id]));
    assert_eq!(
        keys::page(workflow, 0x0102_0304),
        cat(&[&[0x00, 0x14], &id, &[1, 2, 3, 4]])
    );
    assert_eq!(keys::next_workflow(), [0x00, 0x15]);
    assert_eq!(keys::live_workflows(), [0x00, 0x16]);
    let pins = keys::workflow_pins(&ProgramHash([0xcc; 32]));
    assert_eq!(pins, cat(&[&[0x00, 0x17], &[0xcc; 32]]));
    assert_eq!(keys::workflow_pins_prefix(), [0x00, 0x17]);
    assert_eq!(
        keys::workflow_pins_entry(&pins),
        Some(ProgramHash([0xcc; 32]))
    );
    assert_eq!(keys::workflow_pins_entry(&keys::workflow(workflow)), None);
}

/// The keys of a table's and a committed map's rows, their builder's rows,
/// and the dirty and seed rows accumulate leaves, byte for byte.
#[test]
fn committed_keys_keep_their_bytes() {
    let instance = InstanceId(0x1122_3344);
    let map = MapId {
        instance,
        tag: 0xa1b2_c3d4,
        transform: Transform::Ordered,
    };
    let id = [0x11, 0x22, 0x33, 0x44, 0xa1, 0xb2, 0xc3, 0xd4, 0x01];
    let version = [1, 2, 3, 4, 5, 6, 7, 8];
    let key = [7, 0, 0xff, 0, 0];
    let cat = |parts: &[&[u8]]| parts.concat();
    assert_eq!(Transform::Ordered.apply(&[7, 0]), key);
    assert_eq!(
        keys::table_rows(instance, 0xa1b2_c3d4, Transform::Hashed),
        [
            0x01, 0x11, 0x22, 0x33, 0x44, 0x01, 0xa1, 0xb2, 0xc3, 0xd4, 0x00
        ]
    );
    assert_eq!(
        keys::committed_rows(&map),
        [
            0x01, 0x11, 0x22, 0x33, 0x44, 0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0x01
        ]
    );
    assert_eq!(
        keys::committed(&map, &key),
        cat(&[&keys::committed_rows(&map), &key])
    );
    assert_eq!(
        keys::dirty(0x0102_0304_0506_0708, &map, &key),
        cat(&[&[0x00, 0x11], &version, &id, &key])
    );
    assert_eq!(keys::dirty_prefix(), [0x00, 0x11]);
    assert_eq!(
        keys::dirty_from(0x0102_0304_0506_0708),
        cat(&[&[0x00, 0x11], &version])
    );
    assert_eq!(
        keys::seed(0x0102_0304_0506_0708),
        cat(&[&[0x00, 0x12], &version])
    );
    assert_eq!(keys::seed_prefix(), [0x00, 0x12]);
    assert_eq!(
        keys::tree_node(&map, 0x0102, &[0xee, 0xf0]),
        cat(&[&[0x02, 0x00], &id, &[0x01, 0x02, 0xee, 0xf0]])
    );
    assert_eq!(keys::tree_nodes(&map), cat(&[&[0x02, 0x00], &id]));
    assert_eq!(
        keys::tree_leaf(&map, &key),
        cat(&[&[0x02, 0x01], &id, &key])
    );
    assert_eq!(keys::tree_leaves(&map), cat(&[&[0x02, 0x01], &id]));
    assert_eq!(keys::tree_root(&map), cat(&[&[0x02, 0x02], &id]));
    assert_eq!(keys::built(), [0x02, 0x03]);
    // The hashed transform: the first 16 bytes of BLAKE2b-256 over
    // `vos/tree/key` and the key, then the key escaped.
    let hashed = Transform::Hashed.apply(&[7, 0]);
    assert_eq!(hashed.len(), 16 + 3 + 2);
    assert_eq!(&hashed[16..], [7, 0, 0xff, 0, 0]);
    assert_eq!(Transform::Hashed.raw(&hashed), Some(vec![7, 0]));
    assert_eq!(
        Transform::Ordered.raw(&[7, 0, 0, 1]),
        None,
        "bytes past the key"
    );
}

/// A row operation's row: the struct under the empty key alone, a table's
/// and a committed map's under their prefix, an ordered key within its cap.
/// The largest row a state scan returns fits its cap exactly.
#[test]
fn rows_are_keyed_by_their_table() {
    let instance = InstanceId(3);
    let table = |transform| Rows::Table { tag: 7, transform };
    assert_eq!(
        keys::row(instance, Rows::Struct, &[]),
        Ok(keys::instance_struct(instance))
    );
    assert_eq!(
        keys::row(instance, Rows::Struct, &[1]),
        Err(Failure::Trapped)
    );
    let zeros = vec![0u8; abi::cap::KEY];
    let hashed = keys::row(instance, table(Transform::Hashed), &zeros).unwrap();
    assert_eq!(
        hashed,
        [
            keys::table_rows(instance, 7, Transform::Hashed),
            Transform::Hashed.apply(&zeros)
        ]
        .concat()
    );
    let long = vec![1u8; abi::cap::ORDERED_KEY + 1];
    assert_eq!(
        keys::row(instance, table(Transform::Ordered), &long),
        Err(Failure::Cap)
    );
    assert!(keys::row(instance, table(Transform::Ordered), &long[1..]).is_ok());
    let value = vos_wire::records::stored_versioned(0, &vec![0; abi::cap::VALUE]);
    let largest = (hashed, value).encode().len();
    assert_eq!(largest, abi::cap::STORED_ROW);
}

/// A row operation's rows register: the tag, the transform's tag, then the
/// kind; any other value is refused.
#[test]
fn rows_registers_keep_their_bits() {
    let table = Rows::Table {
        tag: 0xa1b2_c3d4,
        transform: Transform::Ordered,
    };
    let committed = Rows::Committed {
        tag: 7,
        transform: Transform::Hashed,
    };
    assert_eq!(Rows::Struct.register(), 0);
    assert_eq!(table.register(), 0x0000_0101_a1b2_c3d4);
    assert_eq!(committed.register(), 0x0000_0200_0000_0007);
    for rows in [Rows::Struct, table, committed] {
        assert_eq!(Rows::from_register(rows.register()), Some(rows));
    }
    for refused in [
        1,
        1 << 32,
        2 << 32 | 1 << 40,
        3 << 40,
        1 << 48 | 1 << 40,
        u64::MAX,
    ] {
        assert_eq!(Rows::from_register(refused), None, "{refused:#x}");
    }
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
    use vos_wire::ingress::{Consistency, call_message, query_message};
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

/// The failure and refusal codes keep their values, each a little-endian
/// `u32` wherever it is carried; a code outside its set does not decode.
#[test]
fn codes_keep_their_values() {
    let failures = [
        (Failure::Handler, 1),
        (Failure::Trapped, 2),
        (Failure::OutOfGas, 3),
        (Failure::Cap, 4),
        (Failure::Forbidden, 5),
        (Failure::Unknown, 6),
        (Failure::Cycle, 7),
        (Failure::Depth, 8),
        (Failure::InRefine, 9),
        (Failure::TimedOut, 10),
        (Failure::Unloadable, 11),
    ];
    for (failure, code) in failures {
        assert_eq!(failure.code(), code);
        assert_eq!(Failure::from_code(code), Some(failure));
        assert_eq!(failure.encode(), code.to_le_bytes());
    }
    let refusals = [
        (Refusal::Sequence, 1),
        (Refusal::Expired, 2),
        (Refusal::Unreadable, 3),
        (Refusal::StaleSession, 4),
        (Refusal::SessionsFull, 5),
        (Refusal::KeySessionsFull, 6),
    ];
    for (refusal, code) in refusals {
        assert_eq!(refusal.code(), code);
        assert_eq!(Refusal::from_code(code), Some(refusal));
        assert_eq!(refusal.encode(), code.to_le_bytes());
    }
    for outside in [0u32, 12, u32::MAX] {
        assert!(Failure::decode(&outside.to_le_bytes()).is_err());
    }
    for outside in [0u32, 7, u32::MAX] {
        assert!(Refusal::decode(&outside.to_le_bytes()).is_err());
    }
    let failed = Outcome::Failed {
        code: Failure::Forbidden,
        detail: vec![7],
    };
    assert_eq!(failed.encode(), [1, 5, 0, 0, 0, 1, 0, 0, 0, 7]);
    let refused = Step::Refused {
        input: InputRef::Admin,
        code: Refusal::Expired,
    };
    assert_eq!(refused.encode(), [1, 2, 2, 0, 0, 0]);
    let started = Outcome::Started(WorkflowId(7));
    assert_eq!(started.encode(), [&[2][..], &7u64.to_le_bytes()].concat());
    let due = InputRef::Due {
        workflow: WorkflowId(7),
    };
    assert_eq!(due.encode(), [&[4][..], &7u64.to_le_bytes()].concat());
    assert_eq!(
        vos_wire::ingress::Answer::Refused(Refusal::Sequence).encode(),
        [1, 1, 0, 0, 0]
    );
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
            gas: 11,
            pages: vec![(12, [13; 32])],
        }),
    };
    let bytes = [
        &[Workflow::FORMAT][..],
        &[1; 32],
        &2u32.to_le_bytes(),
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
        &11u64.to_le_bytes(),
        &1u32.to_le_bytes(),
        &12u32.to_le_bytes(),
        &[13; 32],
    ]
    .concat();
    assert_eq!(record.encode(), bytes);
    round_trip(&record);
    let ended = WorkflowState::Ended(Outcome::Started(WorkflowId(1)));
    round_trip(&ended);
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
            answer: ingress::Answer::Busy,
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
