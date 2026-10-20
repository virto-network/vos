//! The agent's keys, byte for byte.

use vos_wire::Encode;
use vos_wire::abi::{self, Failure, Rows};
use vos_wire::ids::{
    AgentId, InstanceId, MapId, Principal, ProgramHash, RequestId, Session, SessionId, WorkflowId,
};
use vos_wire::keys::{self, Due, Transform};

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
        keys::instance_rows(instance),
        [0x01, 0x11, 0x22, 0x33, 0x44]
    );
    assert_eq!(
        keys::instance_committed(instance),
        [0x03, 0x11, 0x22, 0x33, 0x44]
    );
    assert_eq!(
        keys::instance_prefixes(instance),
        [
            vec![0x01, 0x11, 0x22, 0x33, 0x44],
            vec![0x03, 0x11, 0x22, 0x33, 0x44]
        ]
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
    assert_eq!(keys::outbox_to(agent), [0x00, 0x06, 0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(
        keys::outbox_entry(&keys::outbox(agent, sequence)),
        Some((agent, sequence))
    );
    assert_eq!(keys::outbox_entry(&keys::outbox_to(agent)), None);
    assert_eq!(keys::outbox_entry(&keys::pair_out(agent)), None);
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
    assert_eq!(keys::target(), [0x00, 0x18]);
    assert_eq!(keys::space(), [0x00, 0x19]);
    assert_eq!(keys::clock(), [0x00, 0x1a]);
    assert_eq!(keys::reported(), [0x00, 0x1d]);
    assert_eq!(keys::closed(sequence), cat(&[&[0x00, 0x1e], &at]));
    assert_eq!(keys::closed_prefix(), [0x00, 0x1e]);
    assert_eq!(keys::closed_entry(&keys::closed(sequence)), Some(sequence));
    assert_eq!(keys::closed_entry(&keys::moved(sequence)), None);
    assert_eq!(keys::moved(sequence), cat(&[&[0x00, 0x1f], &at]));
    assert_eq!(keys::serving(), [0x00, 0x20]);
    assert_eq!(keys::close_mark(), [0x00, 0x21]);
    assert_eq!(
        keys::reports(AgentId(0x0102_0304)),
        [0x00, 0x22, 0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(
        keys::proven(&[0xab; 32]),
        cat(&[&[0x00, 0x23], &[0xab; 32]])
    );
    assert_eq!(keys::closing(sequence), cat(&[&[0x02, 0x07], &at]));
    assert_eq!(keys::closings(), [0x02, 0x07]);
    assert_eq!(
        keys::closing_entry(&keys::closing(sequence)),
        Some(sequence)
    );
    assert_eq!(keys::closing_entry(&keys::cut_root(sequence)), None);
    for replicated in [
        keys::reported(),
        keys::closed(1),
        keys::moved(1),
        keys::serving(),
        keys::close_mark(),
        keys::proven(&[1; 32]),
    ] {
        assert!(keys::is_replicated(&replicated));
    }
    assert!(!keys::is_replicated(&keys::closing(1)));
}

/// A sweep's rows: those due by its time, earliest first, as many as it
/// lists, past a key under the index that names no row, and none past the
/// index.
#[test]
fn a_sweep_lists_the_rows_due_by_its_time() {
    let session = |id| Due::Session(SessionId(id));
    let mut stray = keys::due_prefix();
    stray.push(0xff);
    let rows = [
        keys::due(5, session(1)),
        stray,
        keys::due(7, Due::Workflow(WorkflowId(2))),
        keys::due(9, session(3)),
        keys::batch_time(),
    ];
    let due = |time, limit| keys::due_rows(rows.iter().map(Ok::<_, ()>), time, limit).unwrap();
    assert_eq!(
        due(8, 10),
        [(5, session(1)), (7, Due::Workflow(WorkflowId(2)))]
    );
    assert_eq!(due(9, 1), [(5, session(1))]);
    assert_eq!(due(4, 10), []);
    assert_eq!(due(u64::MAX, 10).len(), 3, "none past the index");
    assert_eq!(
        keys::due_rows([Err::<Vec<u8>, _>("unread")], 9, 10),
        Err("unread")
    );
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
        [0x03, 0x11, 0x22, 0x33, 0x44, 0xa1, 0xb2, 0xc3, 0xd4, 0x01]
    );
    assert_eq!(keys::committed_rows(&map).len(), keys::COMMITTED_PREFIX);
    assert_eq!(keys::committed_all(), [0x03]);
    let row = keys::committed(&map, &key);
    assert_eq!(row, cat(&[&keys::committed_rows(&map), &key]));
    assert_eq!(
        keys::dirty(0x0102_0304_0506_0708, &row),
        cat(&[&[0x00, 0x11], &version, &[0x03], &id, &key])
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
        keys::tree_node(0x0102, &[0xee, 0xf0]),
        [0x02, 0x00, 0x01, 0x02, 0xee, 0xf0]
    );
    assert_eq!(keys::tree_nodes(), [0x02, 0x00]);
    assert_eq!(keys::tree_leaf(&row), cat(&[&[0x02, 0x01], &row]));
    assert_eq!(keys::tree_leaves(), [0x02, 0x01]);
    assert_eq!(keys::tree_root(), [0x02, 0x02]);
    assert_eq!(keys::built(), [0x02, 0x03]);
    let request = RequestId {
        workflow: WorkflowId(0x1112_1314_1516_1718),
        awaits: 0x2122_2324_2526_2728,
    };
    let (workflow, awaits) = (
        [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
        [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28],
    );
    assert_eq!(
        keys::cut(0x0102_0304_0506_0708),
        cat(&[&[0x00, 0x1b], &version])
    );
    assert_eq!(keys::cuts(), [0x00, 0x1b]);
    assert_eq!(keys::cut_entry(&keys::cut(9)), Some(9));
    assert_eq!(
        keys::request(0x0102_0304_0506_0708, request),
        cat(&[&[0x00, 0x1c], &version, &workflow, &awaits])
    );
    assert_eq!(keys::request_prefix(), [0x00, 0x1c]);
    assert_eq!(
        keys::requests(0x0102_0304_0506_0708),
        cat(&[&[0x00, 0x1c], &version])
    );
    assert_eq!(
        keys::request_entry(&keys::request(3, request)),
        Some((3, request))
    );
    assert_eq!(
        keys::undo(0x0102_0304_0506_0708, &row),
        cat(&[&[0x02, 0x04], &version, &row])
    );
    assert_eq!(
        keys::undos(0x0102_0304_0506_0708),
        cat(&[&[0x02, 0x04], &version])
    );
    assert_eq!(keys::undo_prefix(), [0x02, 0x04]);
    assert_eq!(
        keys::cut_root(0x0102_0304_0506_0708),
        cat(&[&[0x02, 0x05], &version])
    );
    assert_eq!(keys::cut_roots(), [0x02, 0x05]);
    assert_eq!(
        keys::cut_proof(request, 0x0102_0304_0506_0708),
        cat(&[&[0x02, 0x06], &workflow, &awaits, &version])
    );
    assert_eq!(
        keys::cut_proofs_of(request),
        cat(&[&[0x02, 0x06], &workflow, &awaits])
    );
    assert_eq!(keys::cut_proofs(), [0x02, 0x06]);
    assert_eq!(
        keys::cut_proof_entry(&keys::cut_proof(request, 9)),
        Some((request, 9))
    );
    assert_eq!(keys::cut_proof_entry(&keys::cut_root(9)), None);
    assert_eq!(keys::cut_entry(&keys::cut_root(9)), None);
    assert_eq!(keys::cut_root_entry(&keys::cut_root(9)), Some(9));
    assert_eq!(keys::cut_root_entry(&keys::cut(9)), None);
    assert_eq!(keys::undo_entry(&keys::undo(9, &row)), Some((9, &row[..])));
    assert_eq!(keys::undo_entry(&keys::cut_root(9)), None);
    for (key, replicated) in [
        (keys::cut(9), true),
        (keys::request(9, request), true),
        (keys::version(), true),
        (row.clone(), true),
        (keys::instance_struct(InstanceId(1)), true),
        (keys::dirty(9, &row), false),
        (keys::seed(9), false),
        (keys::undo(9, &row), false),
        (keys::cut_root(9), false),
        (keys::cut_proof(request, 9), false),
        (keys::built(), false),
        (Vec::new(), false),
    ] {
        assert_eq!(keys::is_replicated(&key), replicated, "{key:?}");
    }
    assert_eq!(keys::request_entry(&keys::cut(9)), None);
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

/// A page row's key names its workflow and index, and nothing else does.
#[test]
fn page_rows_name_their_page() {
    let key = keys::page(WorkflowId(7), 9);
    assert_eq!(keys::page_entry(&key), Some((WorkflowId(7), 9)));
    assert_eq!(keys::page_entry(&key[..key.len() - 1]), None);
    assert_eq!(keys::page_entry(&keys::workflow(WorkflowId(7))), None);
}

/// The representative's map: its tag the one its field's name derives,
/// and its rows keyed `agent (4, BE) ‖ kind ‖ w (8, BE)`, ordered.
#[test]
fn the_representatives_rows_keep_their_bytes() {
    use vos_wire::served::{
        REPRESENTATIVE_ROOTS, REPRESENTATIVE_TAG, representative_map, representative_row,
    };
    use vos_wire::vos_anchor::RootKind;
    assert_eq!(
        REPRESENTATIVE_TAG,
        vos_wire::ids::derive_id("vos/table/", REPRESENTATIVE_ROOTS)
    );
    let raw = [&7u32.to_be_bytes()[..], &[0], &9u64.to_be_bytes()].concat();
    assert_eq!(
        representative_row(vos_wire::ids::AgentId(7), RootKind::Space, 9),
        keys::committed(&representative_map(), &Transform::Ordered.apply(&raw))
    );
}
