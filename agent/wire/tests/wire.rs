use proptest::prelude::*;
use vos_wire::abi::{self, Kind, op};
use vos_wire::batch::{Admin, Batch, Input, Message, Request};
use vos_wire::ids::{
    AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs, Transfer, WorkError};
use vos_wire::keys;
use vos_wire::result::{
    Attest, InputRef, InstanceGas, Outcome, Outgoing, ResultWriter, Run, Step, WorkResult, Write,
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
        (
            any::<u32>(),
            any::<u64>(),
            any::<u32>(),
            any::<u32>(),
            bytes()
        )
            .prop_map(|(from, sequence, instance, method, arguments)| {
                Input::Message(Message {
                    from: AgentId(from),
                    sequence,
                    instance: InstanceId(instance),
                    method: MethodId(method),
                    arguments,
                })
            }),
        (
            any::<u32>(),
            any::<[u8; 32]>(),
            prop::collection::vec((any::<u32>(), any::<[u8; 32]>()), 0..3),
            prop::collection::vec((bytes(), any::<u8>()), 0..3),
        )
            .prop_map(|(instance, program, attestables, roles)| {
                Input::Admin(Admin::Install {
                    instance: InstanceId(instance),
                    program: ProgramHash(program),
                    attestables: attestables
                        .into_iter()
                        .map(|(method, program)| (MethodId(method), ProgramHash(program)))
                        .collect(),
                    roles,
                })
            }),
        (principal(), any::<Option<u8>>())
            .prop_map(|(principal, role)| Input::Admin(Admin::SetRole { principal, role })),
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
    ];
    let outcome = prop_oneof![
        bytes().prop_map(Outcome::Done),
        (any::<u32>(), bytes()).prop_map(|(code, detail)| Outcome::Failed { code, detail }),
    ];
    let instance = (any::<u32>(), any::<u64>()).prop_map(|(instance, gas)| InstanceGas {
        instance: InstanceId(instance),
        gas,
    });
    let write = (bytes(), prop::option::of(bytes())).prop_map(|(key, value)| Write { key, value });
    let outgoing = (any::<u32>(), any::<u32>(), any::<u32>(), bytes()).prop_map(
        |(to, instance, method, arguments)| Outgoing {
            to: AgentId(to),
            instance: InstanceId(instance),
            method: MethodId(method),
            arguments,
        },
    );
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
        prop::collection::vec(outgoing, 0..3),
        prop::collection::vec(attest, 0..2),
        any::<u64>(),
    )
        .prop_map(
            |(input, outcome, instances, writes, messages, attests, gas_used)| {
                Step::Ran(Run {
                    input,
                    outcome,
                    instances,
                    writes,
                    messages,
                    attests,
                    gas_used,
                })
            },
        );
    let refused = (input, any::<u32>()).prop_map(|(input, code)| Step::Refused { input, code });
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
        inputs in prop::collection::vec(input(), 0..8),
    ) {
        round_trip(&Batch { version, time, seed, inputs });
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
    let all = [
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
    let writes = [op::PUT, op::DELETE, op::SEND, op::ATTEST];
    for id in all {
        assert!(abi::allowed(Kind::Command, id));
        assert_eq!(abi::allowed(Kind::Query, id), !writes.contains(&id));
        assert!(!abi::allowed(Kind::Attestable, id));
    }
    for unknown in [0, 5, 0x480, 0x4ff, 0x507, 0x524, 0x5ff] {
        assert!(!abi::allowed(Kind::Command, unknown));
        assert!(!abi::allowed(Kind::Query, unknown));
    }
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
}

#[test]
fn a_result_written_step_by_step_is_the_work_result_encoding() {
    let step = |sequence| Step::Refused {
        input: InputRef::Request {
            session: SessionRef::Known(SessionId(1)),
            sequence,
        },
        code: 1,
    };
    let mut writer = ResultWriter::new(3, 4, [5; 32]);
    assert!(writer.push(&step(1)));
    assert!(writer.push(&step(2)));
    let result = WorkResult {
        version: 3,
        time: 4,
        seed: [5; 32],
        steps: vec![step(1), step(2)],
    };
    assert_eq!(writer.finish(), result.encode());

    let big = Step::Ran(Run {
        input: InputRef::Admin,
        outcome: Outcome::Done(vec![0; abi::cap::WORK_RESULT / 3]),
        instances: vec![],
        writes: vec![],
        messages: vec![],
        attests: vec![],
        gas_used: 0,
    });
    let mut writer = ResultWriter::new(0, 0, [0; 32]);
    assert!(writer.push(&big));
    assert!(writer.push(&big));
    assert!(!writer.push(&big), "a third would pass the cap");
    let (decoded, _) = WorkResult::decode(&writer.finish()).unwrap();
    assert_eq!(decoded.steps.len(), 2);
}

/// A step at every cap, with as many writes and instances as its gas pays
/// for, stays within `STEP_RESULT`.
#[test]
fn the_largest_step_fits_its_bound() {
    use abi::cap;
    use vos_wire::defaults::MAX_HANDLER_GAS;
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
        writes: write_bytes
            .into_iter()
            .map(|len| Write {
                key: vec![0],
                value: Some(vec![0; len]),
            })
            .collect(),
        messages: (0..cap::MESSAGES)
            .map(|_| Outgoing {
                to: AgentId(0),
                instance: InstanceId(0),
                method: MethodId(0),
                arguments: vec![0; cap::MESSAGE],
            })
            .collect(),
        attests: (0..cap::ATTESTS)
            .map(|_| Attest {
                program: ProgramHash([0; 32]),
                arguments: vec![0; cap::REQUEST],
                output: vec![0; cap::REPLY],
            })
            .collect(),
        gas_used: u64::MAX,
    });
    assert!(step.encode().len() <= cap::STEP_RESULT);
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
