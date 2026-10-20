//! Every wire type round-trips through its encoding.

use proptest::prelude::*;
use vos_wire::abi::{self, Failure, Rows};
use vos_wire::batch::Batch;
use vos_wire::ids::{
    AgentId, InstanceId, MapId, ProgramHash, RequestId, Session, SessionId, WorkflowId,
};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs, Transfer};
use vos_wire::keys::{self, Due, Transform};
use vos_wire::records::{leaf_value, stored};
use vos_wire::result::WorkResult;

use crate::strategies::*;

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
        let map = MapId { instance, tag, transform: Transform::Hashed };
        let row = keys::committed(&map, &Transform::Hashed.apply(&tag.to_be_bytes()));
        let request = RequestId { workflow: WorkflowId(sequence), awaits: session };
        let owned = [
            keys::instance_struct(instance),
            keys::table_prefix(instance, tag),
            keys::committed_rows(&map),
            row.clone(),
        ];
        for key in &owned {
            prop_assert!(keys::owned_by(key, instance));
            prop_assert_eq!(keys::owned_by(key, InstanceId(other)), other == instance.0);
            prop_assert!(keys::instance_prefixes(instance).iter().any(|prefix| key.starts_with(prefix)));
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
            keys::dirty(sequence, &row),
            keys::seed(sequence),
            keys::tree_leaf(&row),
            keys::tree_root(),
            keys::built(),
            keys::committed_all(),
            keys::cut(sequence),
            keys::request(sequence, request),
            keys::undo(sequence, &row),
            keys::cut_root(sequence),
            keys::cut_proof(request, sequence),
            keys::reported(),
            keys::closed(sequence),
            keys::moved(sequence),
            keys::serving(),
            keys::close_mark(),
            keys::closing(sequence),
            keys::proven(&[agent as u8; 32]),
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
            keys::reported(),
            keys::serving(),
            keys::close_mark(),
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
                keys::dirty(number, &keys::committed(&map, &transformed)),
                keys::seed(number),
                keys::tree_leaf(&keys::committed(&map, &transformed)),
                keys::tree_root(),
                keys::built(),
                keys::cut(number),
                keys::request(number, RequestId { workflow: WorkflowId(u64::from(a)), awaits: u64::from(b) }),
                keys::undo(number, &keys::committed(&map, &transformed)),
                keys::cut_root(number),
                keys::cut_proof(RequestId { workflow: WorkflowId(number), awaits: u64::from(a) }, u64::from(b)),
                keys::closed(number),
                keys::moved(number),
                keys::closing(number),
                keys::proven(&triple.key),
            ]);

            if let Some(prefix) = prefix {
                rows.push(keys::tree_node(level, &prefix));
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
        prop_assert!(value.starts_with(&keys::committed_all()));
        prop_assert!(keys::owned_by(&value, map.instance));
        prop_assert_eq!(keys::committed_entry(&value), Some((map, transformed.as_slice())));
        let dirty = keys::dirty(version, &value);
        prop_assert!(dirty.starts_with(&keys::dirty_from(version)));
        prop_assert!(dirty.starts_with(&keys::dirty_prefix()));
        prop_assert_eq!(keys::dirty_entry(&dirty), Some((version, value.as_slice())));
        prop_assert_eq!(keys::committed_entry(&dirty), None);
        prop_assert!(keys::is_committed(&value) && !keys::is_committed(&dirty));
        let rows = Rows::Committed { tag: map.tag, transform: map.transform };
        if map.transform == Transform::Hashed || key.len() <= abi::cap::ORDERED_KEY {
            prop_assert_eq!(keys::row(map.instance, rows, &key), Ok(value.clone()));
        } else {
            prop_assert_eq!(keys::row(map.instance, rows, &key), Err(Failure::Cap));
        }
        // Every key under 0x03 is committed, however short; one too short
        // to name a map and a key is no value row, and no leaf reads it.
        for short in [vec![0x03], keys::committed_rows(&map)] {
            prop_assert!(keys::is_committed(&short));
            prop_assert_eq!(keys::committed_entry(&short), None);
        }
        let short = stored(&[1]);
        prop_assert_eq!(leaf_value(&[0x03, 1], &short), None);
        let leaf = keys::tree_leaf(&value);
        prop_assert_eq!(keys::committed_entry(&leaf), None);
        prop_assert!(!keys::is_committed(&leaf));
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
