//! Strategies for the wire types, and a round trip through their encoding.

use proptest::prelude::*;
use vos_wire::abi::cap::Target;
use vos_wire::abi::{Failure, Refusal};
use vos_wire::batch::{Admin, Answer, Await, Body, Input, Message, Request};
use vos_wire::ids::{
    AgentId, InstanceId, MapId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
    WorkflowId,
};
use vos_wire::ingress::Grant;
use vos_wire::jam::WorkError;
use vos_wire::keys::{Due, Transform};
use vos_wire::records::Derivation;
use vos_wire::result::{
    Attest, CommittedWrite, InputRef, InstanceGas, Outcome, Outgoing, Page, Run, Step, Write,
};
use vos_wire::{Decode, Encode};

pub(crate) fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..300)
}

pub(crate) fn principal() -> impl Strategy<Value = Principal> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(Principal::Client),
        any::<u32>().prop_map(|id| Principal::Agent(AgentId(id))),
        any::<u32>().prop_map(|id| Principal::Instance(InstanceId(id))),
    ]
}

pub(crate) fn session() -> impl Strategy<Value = Session> {
    (any::<[u8; 32]>(), any::<[u8; 16]>(), any::<u64>()).prop_map(|(key, name, t0)| Session {
        key,
        name,
        t0,
    })
}

pub(crate) fn transform() -> impl Strategy<Value = Transform> {
    prop_oneof![Just(Transform::Hashed), Just(Transform::Ordered)]
}

pub(crate) fn map() -> impl Strategy<Value = MapId> {
    (any::<u32>(), any::<u32>(), transform()).prop_map(|(instance, tag, transform)| MapId {
        instance: InstanceId(instance),
        tag,
        transform,
    })
}

pub(crate) fn failure() -> impl Strategy<Value = Failure> {
    (1u32..=9).prop_map(|code| Failure::from_code(code).unwrap())
}

pub(crate) fn refusal() -> impl Strategy<Value = Refusal> {
    (1u32..=6).prop_map(|code| Refusal::from_code(code).unwrap())
}

pub(crate) fn awaiting() -> impl Strategy<Value = Await> {
    (any::<u64>(), any::<u64>()).prop_map(|(workflow, counter)| Await {
        workflow: WorkflowId(workflow),
        counter,
    })
}

pub(crate) fn body() -> impl Strategy<Value = Body> {
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

pub(crate) fn message() -> impl Strategy<Value = Message> {
    (any::<u32>(), any::<u64>(), body()).prop_map(|(from, sequence, body)| Message {
        from: AgentId(from),
        sequence,
        body,
    })
}

pub(crate) fn input() -> impl Strategy<Value = Input> {
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
            (
                any::<[u8; 32]>(),
                prop::collection::vec((any::<u32>(), any::<[u8; 32]>()), 0..3),
                any::<[u8; 32]>(),
                any::<u32>(),
            ),
            prop::collection::vec((bytes(), any::<u8>()), 0..3),
            prop_oneof![Just(Target::Vos), Just(Target::Jam)],
        )
            .prop_map(
                |(instance, (program, kernels, elf, transpiler), roles, target)| {
                    Input::Admin(Admin::Install {
                        instance: InstanceId(instance),
                        derivation: Derivation {
                            program: ProgramHash(program),
                            kernels: kernels
                                .into_iter()
                                .map(|(method, kernel)| (MethodId(method), ProgramHash(kernel)))
                                .collect(),
                            elf,
                            transpiler,
                        },
                        roles,
                        target,
                    })
                }
            ),
        (principal(), any::<Option<u8>>())
            .prop_map(|(principal, role)| Input::Admin(Admin::SetRole(Grant { principal, role }))),
        prop::collection::vec((any::<u64>(), due()), 0..4).prop_map(|due| Input::Sweep { due }),
    ]
}

pub(crate) fn due() -> impl Strategy<Value = Due> {
    prop_oneof![
        any::<u64>().prop_map(|id| Due::Session(SessionId(id))),
        any::<u64>().prop_map(|id| Due::Workflow(WorkflowId(id))),
    ]
}

pub(crate) fn step() -> impl Strategy<Value = Step> {
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

pub(crate) fn work_error() -> impl Strategy<Value = WorkError> {
    prop_oneof![
        Just(WorkError::OutOfGas),
        Just(WorkError::Panic),
        Just(WorkError::BadExports),
        Just(WorkError::Oversize),
        Just(WorkError::Bad),
        Just(WorkError::Big),
    ]
}

pub(crate) fn round_trip<T: Encode + Decode + PartialEq + std::fmt::Debug>(value: &T) {
    let bytes = value.encode();
    let (decoded, used) = T::decode(&bytes).expect("decode");
    assert_eq!(&decoded, value);
    assert_eq!(used, bytes.len());
}

pub(crate) fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}
