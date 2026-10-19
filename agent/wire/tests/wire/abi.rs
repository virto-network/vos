//! The actor ABI: kinds, operations, codes and schemas.

use vos_wire::abi::{self, Failure, Kind, Op, Refusal, Rows};
use vos_wire::ids::{MethodId, WorkflowId};
use vos_wire::keys::Transform;
use vos_wire::result::{InputRef, Outcome, Step};
use vos_wire::{Decode, Encode};

use crate::strategies::hex;

#[test]
fn kinds_reach_only_their_operations() {
    let handlers = [
        Op::Input,
        Op::Reply,
        Op::Fail,
        Op::Log,
        Op::Caller,
        Op::Now,
        Op::Random,
        Op::Get,
        Op::Put,
        Op::Delete,
        Op::Scan,
        Op::Call,
        Op::Send,
        Op::Attest,
        Op::SelfId,
    ];
    let pauses = [Op::Request, Op::Result, Op::Sleep, Op::AttestAt];
    let sections = [Op::Open, Op::Close];
    let writes = [Op::Put, Op::Delete, Op::Send, Op::Attest];
    // A workflow attests nothing, and does not ask who called.
    let stateful = [Op::Caller, Op::Attest];
    // Its instance's rows it reaches only inside a section.
    let rows = [Op::Get, Op::Put, Op::Delete, Op::Scan];
    for op in handlers {
        assert!(abi::allowed(Kind::Command, op));
        assert_eq!(abi::allowed(Kind::Query, op), !writes.contains(&op));
        for kind in [Kind::Attestable, Kind::Stating, Kind::Reading] {
            assert!(!abi::allowed(kind, op));
        }
        assert_eq!(abi::allowed(Kind::Workflow, op), !stateful.contains(&op));
        assert_eq!(
            abi::in_section(op),
            rows.contains(&op) || [Op::Now, Op::Log].contains(&op),
            "{op:?}"
        );
    }
    for op in pauses.into_iter().chain(sections) {
        assert!(abi::allowed(Kind::Workflow, op));
        assert!(!abi::allowed(Kind::Command, op));
        assert!(!abi::allowed(Kind::Query, op));
        assert!(!abi::allowed(Kind::Attestable, op));
        assert_eq!(abi::in_section(op), op == Op::Close, "{op:?}");
    }
    let every: Vec<Op> = handlers.into_iter().chain(pauses).chain(sections).collect();
    assert_eq!(every, Op::ALL, "every operation is classed, in id order");
    for unknown in [0, 5, 0x480, 0x4ff, 0x507, 0x524, 0x52f, 0x534, 0x542, 0x5ff] {
        assert_eq!(Op::from_id(unknown), None, "{unknown:#x}");
    }
    // A workflow's rows and a close only inside a section; inside one, its
    // rows, the time, logs and the close alone.
    for &op in Op::ALL {
        let rows_or_close = rows.contains(&op) || op == Op::Close;
        assert_eq!(
            abi::workflow_may_use(false, op),
            abi::allowed(Kind::Workflow, op) && !rows_or_close,
            "{op:?}"
        );
        assert_eq!(
            abi::workflow_may_use(true, op),
            abi::in_section(op),
            "{op:?}"
        );
    }
}

/// An operation's id names it, and no other id names one: the actor ABI's
/// block holds them all.
#[test]
fn operations_are_their_ids() {
    for &op in Op::ALL {
        assert_eq!(Op::from_id(op.id()), Some(op));
        assert!(abi::surface::ACTOR_ABI.contains(&op.id()), "{op:?}");
    }
    let ids: Vec<u64> = (0..0x1000u64)
        .filter(|&id| Op::from_id(id).is_some())
        .collect();
    assert_eq!(
        ids,
        [
            0x500, 0x501, 0x502, 0x503, 0x504, 0x505, 0x506, 0x510, 0x511, 0x512, 0x513, 0x520,
            0x521, 0x522, 0x523, 0x530, 0x531, 0x532, 0x533, 0x540, 0x541
        ]
    );
}

/// A kind's index is its encoding's byte, which the agent passes in φ8.
#[test]
fn kinds_index_as_they_encode() {
    let kinds = [
        Kind::Command,
        Kind::Query,
        Kind::Attestable,
        Kind::Workflow,
        Kind::Stating,
        Kind::Reading,
    ];
    for kind in kinds {
        assert_eq!(kind.encode(), [kind.index()]);
        assert_eq!(
            kind.is_handler(),
            matches!(kind, Kind::Command | Kind::Query)
        );
        assert_eq!(
            kind.is_attestable(),
            matches!(kind, Kind::Attestable | Kind::Stating | Kind::Reading)
        );
    }
}

/// Every operation a workflow may use is classed: an effect, which a unit
/// makes only with the step's whole limit, or one that reads, sets
/// registers or pauses, before which a unit may be preempted. A new
/// operation must be classed here.
#[test]
fn a_workflows_operations_are_effects_or_not() {
    let effects = [
        Op::Call,
        Op::Send,
        Op::Request,
        Op::Result,
        Op::AttestAt,
        Op::Reply,
        Op::Fail,
        Op::Open,
    ];
    // The row operations and a section's close come only after its open.
    let others = [
        Op::Input,
        Op::Log,
        Op::Now,
        Op::Random,
        Op::SelfId,
        Op::Sleep,
        Op::Get,
        Op::Put,
        Op::Delete,
        Op::Scan,
        Op::Close,
    ];
    for &op in Op::ALL {
        if !abi::allowed(Kind::Workflow, op) {
            continue;
        }
        match (effects.contains(&op), others.contains(&op)) {
            (true, false) => assert!(abi::is_effect(op), "{op:?}"),
            (false, true) => assert!(!abi::is_effect(op), "{op:?}"),
            _ => panic!("operation {op:?} is not classed"),
        }
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

#[test]
fn schemas_read_back_from_their_section_and_validate() {
    use vos_wire::schema::{MAGIC, MethodSchema, Schema, SchemaError};
    let method = |id: u32, kind| MethodSchema {
        id: MethodId(id),
        name: b"transfer".to_vec(),
        kind,
        role: Some(b"minter".to_vec()),
        gas: Some(1_000_000),
        linearizable: false,
    };
    let linearizable = MethodSchema {
        linearizable: true,
        ..method(9, Kind::Query)
    };
    let schema = Schema {
        methods: vec![method(7, Kind::Command), linearizable],
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
    let command = Schema {
        methods: vec![MethodSchema {
            linearizable: true,
            ..method(7, Kind::Command)
        }],
    };
    assert_eq!(
        Schema::read(&command.section()),
        Err(SchemaError::Linearizable(MethodId(7)))
    );
}

/// A method's schema encodes as the agent and the node read it: its id,
/// name, kind, role, gas and marking, in that order.
#[test]
fn method_schemas_encode_field_by_field() {
    use vos_wire::schema::MethodSchema;
    let method = MethodSchema {
        id: MethodId(0x0102_0304),
        name: b"get".to_vec(),
        kind: Kind::Query,
        role: Some(b"r".to_vec()),
        gas: Some(5),
        linearizable: true,
    };
    assert_eq!(
        method.encode(),
        hex("04030201030000006765740101010000007201050000000000000001")
    );
}

#[test]
fn kinds_encode_as_the_index_the_agent_passes() {
    assert_eq!(Kind::Command.encode(), [0]);
    assert_eq!(Kind::Query.encode(), [1]);
    assert_eq!(Kind::Attestable.encode(), [2]);
    assert_eq!(Kind::Workflow.encode(), [3]);
    assert_eq!(Kind::Stating.encode(), [4]);
    assert_eq!(Kind::Reading.encode(), [5]);
    assert!(Kind::decode(&[6]).is_err());
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
        (Failure::Expired, 12),
        (Failure::Target, 13),
        (Failure::Space, 14),
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
    for outside in [0u32, 15, u32::MAX] {
        assert!(Failure::decode(&outside.to_le_bytes()).is_err());
    }
    // An install's refusal, its failure's detail.
    use vos_wire::abi::cap::{Refused, Target};
    let target = Refused::Target { agent: Target::Jam };
    assert_eq!(target.encode(), [0, 1]);
    assert_eq!(target.failure(), Failure::Target);
    let space = Refused::Space {
        space: vos_wire::SpaceId([0xa1; 32]),
        clock: vos_wire::WindowClock {
            origin_ms: 1,
            length_ms: 600_000,
        },
    };
    assert_eq!(
        space.encode(),
        [
            &[5u8][..],
            &[0xa1; 32],
            &1u64.to_le_bytes(),
            &600_000u64.to_le_bytes()
        ]
        .concat()
    );
    assert_eq!(space.failure(), Failure::Space);
    let gas = Refused::KernelGas {
        method: vos_wire::ids::MethodId(3),
        gas: 5,
        most: 4,
    };
    assert_eq!(
        gas.encode(),
        [
            &[4u8, 3, 0, 0, 0][..],
            &5u64.to_le_bytes(),
            &4u64.to_le_bytes()
        ]
        .concat()
    );
    assert_eq!(gas.failure(), Failure::Cap);
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
        vos_wire::ingress::Response::Refused(Refusal::Sequence).encode(),
        [1, 1, 0, 0, 0]
    );
}
