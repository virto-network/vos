//! Work results: written step by step, bounded, applied and hashed.

use vos_wire::abi::{self, Failure, Refusal};
use vos_wire::batch::{Answer, Await, Body};
use vos_wire::ids::{
    AgentId, InstanceId, MapId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
    WorkflowId,
};
use vos_wire::keys::{self, Due, Transform};
use vos_wire::records::{Snapshot, Workflow, WorkflowState};
use vos_wire::result::{
    self, Attest, CommittedWrite, InputRef, InstanceGas, Outcome, Outgoing, Page, PageSection,
    ResultWriter, Run, Step, WorkResult, Write,
};
use vos_wire::{Decode, Encode};

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
    assert!(writer.push(&step(1)));
    assert!(writer.push(&step(2)));
    let result = WorkResult {
        version: 3,
        time: 4,
        seed: [5; 32],
        steps: vec![step(1), step(2)],
    };
    let output = writer.finish(PageSection::new());
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
    assert!(writer.push(&big));
    assert!(writer.push(&big));
    assert!(!writer.push(&big), "a third would pass the cap");
    let (decoded, _) = WorkResult::decode(&writer.finish(PageSection::new())).unwrap();
    assert_eq!(decoded.steps.len(), 2);

    // Pages follow the work result proper, in the order their steps store
    // them; past the section's cap a step's are dropped, and a dropped
    // step's never reach the output.
    let pages = PageSection::PAGES / 2;
    let stored: Vec<Vec<u8>> = (0..pages).map(|page| vec![page as u8; 3]).collect();
    let mut section = PageSection::new();
    let store = |section: &mut PageSection, pages: &[Vec<u8>]| {
        pages.iter().all(|page| {
            let range = section.store(8, |out| {
                out[..page.len()].copy_from_slice(page);
                page.len()
            });
            range.is_some_and(|range| section.page(range) == page.as_slice())
        })
    };
    assert!(store(&mut section, &stored) && section.take());
    assert!(store(&mut section, &[vec![9; 5]]));
    section.drop_running();
    assert!(store(&mut section, &stored) && section.take());
    assert!(!store(&mut section, &stored[..1]), "a page past the cap");
    assert!(!section.take());
    assert!(section.take(), "with nothing running");
    let small = Step::Ran(ran(Outcome::Done(vec![])));
    let mut writer = ResultWriter::new(0, 0, [0; 32]);
    assert!(writer.push(&small));
    let (result, pages) = result::split_output(&writer.finish(section)).unwrap();
    assert_eq!(result.steps.len(), 1);
    assert_eq!(pages, [stored.clone(), stored].concat());
}

/// A step at every cap, with as many writes (committed ones, the larger)
/// and instances as `gas` pays for, and a request's reply: its attests
/// plain, or, `at_cut`, each at a window's cut, its served rows in its
/// witness input, as many as count to the cap.
fn largest_step(gas: u64, at_cut: bool) -> Step {
    use abi::cap;
    let largest_await = Await {
        workflow: WorkflowId(u64::MAX),
        counter: u64::MAX,
    };
    let writes = (gas / abi::price::PUT) as usize;
    let mut write_bytes = vec![0usize; writes];
    write_bytes[0] = cap::STEP_WRITES - writes;
    Step::Ran(Run {
        input: InputRef::Request {
            session: SessionRef::New(Box::new(Session {
                key: [u8::MAX; 32],
                name: [u8::MAX; 16],
                t0: u64::MAX,
            })),
            sequence: u64::MAX,
        },
        outcome: Outcome::Done(vec![0; cap::REPLY]),
        instances: (0..=gas / abi::price::MACHINE)
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
        attests: (0..cap::ATTESTS / if at_cut { cap::AT_CUT } else { 1 })
            .map(|_| Attest {
                program: ProgramHash([0; 32]),
                window: Some(u64::MAX),
                witness_input: vec![0; cap::REQUEST + if at_cut { cap::SERVED } else { 0 }],
                // Its kernel's whole return, at most a reply: its output
                // alone, or its parts with their lengths' prefixes.
                output: vec![0; cap::REPLY],
                public_args: Vec::new(),
                roots: Vec::new(),
            })
            .collect(),
        pages: vec![],
        gas_used: u64::MAX,
    })
}

/// The largest step of a handler stays within `STEP_RESULT`; a workflow's,
/// whose calls may use its limit twice, with its record and rows, within
/// `WORKFLOW_STEP_RESULT`.
#[test]
fn the_largest_step_fits_its_bound() {
    use abi::cap;
    use vos_wire::defaults::MAX_HANDLER_GAS;
    let largest_await = Await {
        workflow: WorkflowId(u64::MAX),
        counter: u64::MAX,
    };
    for at_cut in [false, true] {
        assert!(largest_step(MAX_HANDLER_GAS, at_cut).encode().len() <= cap::STEP_RESULT);
    }

    // A workflow's step: its calls' effects, its record, holding its
    // largest input, a preempted one's answer, and a hash for every page it
    // may hold, its rows, and an entry for each page it drops or stores.
    let effects = [false, true]
        .map(|at_cut| largest_step(2 * MAX_HANDLER_GAS, at_cut).encode().len())
        .into_iter()
        .max()
        .unwrap();
    let largest_answer = Answer::Failed {
        code: Failure::Handler,
        detail: vec![0; cap::REPLY],
    };
    assert!(largest_answer.encode().len() > cap::REQUEST);
    let workflow = WorkflowId(u64::MAX);
    let record = Workflow {
        format: u8::MAX,
        program: ProgramHash([0; 32]),
        instance: InstanceId(0),
        method: MethodId(u32::MAX),
        owner: Principal::Client([0; 32]),
        gas: u64::MAX,
        writable: u32::MAX,
        awaits: u64::MAX,
        due: u64::MAX,
        waiter: Some(largest_await),
        state: WorkflowState::Preempted(largest_answer.encode()),
        snapshot: Some(Snapshot {
            counter: u32::MAX,
            registers: vec![u64::MAX; 13],
            pages: (0..cap::HELD_PAGES as u32)
                .map(|page| (page, [0; 32]))
                .collect(),
            pending: Some(u64::MAX),
        }),
        target: vos_wire::abi::cap::Target::Jam,
        stored: u64::MAX,
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
    assert!(effects + rows_bytes <= cap::WORKFLOW_STEP_RESULT);
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

/// A batch's time fits a slot from the slot's start back by the session
/// skew to its end plus the skew; a work result takes its segments whole.
#[test]
fn a_batchs_time_fits_its_slot_within_the_skew() {
    use vos_wire::defaults::SESSION_SKEW_MS;
    use vos_wire::package::{EPOCH_MS, SEGMENT, SLOT_MS, result_segments, timely};
    let slot = 1_000;
    let start = EPOCH_MS + slot * SLOT_MS;
    assert!(timely(start, slot));
    assert!(timely(start - SESSION_SKEW_MS, slot));
    assert!(!timely(start - SESSION_SKEW_MS - 1, slot));
    assert!(timely(start + SLOT_MS + SESSION_SKEW_MS, slot));
    assert!(!timely(start + SLOT_MS + SESSION_SKEW_MS + 1, slot));
    assert!(!timely(0, slot), "a time before the era");
    assert_eq!(
        [0, 1, SEGMENT, SEGMENT + 1].map(result_segments),
        [0, 1, 1, 2]
    );
}

/// One apply for both hosts: on a VOS node a page row holds the page's
/// LZ4 bytes and a committed write leaves its dirty row and its version's
/// seed; on JAM the page row holds the page's hash, and neither is written.
/// A result for another version applies nothing.
#[test]
fn a_result_applies_to_each_hosts_rows() {
    use std::collections::BTreeMap;
    use vos_wire::apply::{Host, State, apply};
    use vos_wire::records::{stored, stored_versioned};
    struct Rows(BTreeMap<Vec<u8>, Vec<u8>>);
    impl State for Rows {
        fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get(key).cloned()
        }
        fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
            match value {
                Some(value) => self.0.insert(key.to_vec(), value.to_vec()),
                None => self.0.remove(key),
            };
        }
    }
    let map = MapId {
        instance: InstanceId(1),
        tag: 2,
        transform: Transform::Hashed,
    };
    let run = Run {
        input: InputRef::Admin,
        outcome: Outcome::Done(vec![]),
        instances: vec![],
        writes: vec![Write {
            key: vec![1, 0, 0, 0, 1, 0],
            value: Some(vec![3]),
        }],
        committed: vec![CommittedWrite {
            map,
            key: vec![4],
            value: Some(vec![5]),
        }],
        messages: vec![],
        attests: vec![],
        pages: vec![Page {
            workflow: WorkflowId(6),
            index: 7,
            hash: Some([8; 32]),
        }],
        gas_used: 0,
    };
    let result = WorkResult {
        version: 0,
        time: 9,
        seed: [10; 32],
        steps: vec![Step::Ran(run)],
    };
    let page = keys::page(WorkflowId(6), 7);
    let section = vec![vec![11, 12]];
    let mut vos = Rows(BTreeMap::new());
    assert!(apply(&mut vos, &result, Host::Vos { pages: &section }));
    let mut jam = Rows(BTreeMap::new());
    assert!(apply(&mut jam, &result, Host::Jam));
    assert_eq!(vos.0[&page], stored(&[11, 12]));
    assert_eq!(jam.0[&page], stored(&[8; 32]));
    let committed = keys::committed(&map, &[4]);
    assert_eq!(vos.0[&committed], stored_versioned(1, &[5]));
    assert_eq!(jam.0[&committed], vos.0[&committed]);
    let only_vos = [keys::dirty(1, &committed), keys::seed(1)];
    for key in &only_vos {
        assert!(vos.0.contains_key(key) && !jam.0.contains_key(key));
    }
    let shared: BTreeMap<_, _> = vos
        .0
        .iter()
        .filter(|(key, _)| !only_vos.contains(key) && **key != page)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    jam.0.remove(&page);
    assert_eq!(shared, jam.0, "the rows both hosts keep");
    let before = jam.0.clone();
    assert!(!apply(&mut jam, &result, Host::Jam), "another version's");
    assert_eq!(jam.0, before);
}

/// A page's and a work result's digest is BLAKE2b-256 of the bytes, as the
/// tree's hasher computes it under no tag, at every block boundary.
#[test]
fn digests_are_blake2b_256() {
    use vos_tree::{Blake2b, Hasher};
    for len in [0, 1, 127, 128, 129, 4096, 4104] {
        let bytes: Vec<u8> = (0..len).map(|at| (at * 7) as u8).collect();
        assert_eq!(
            vos_wire::result::digest(&bytes),
            Blake2b.hash(&[], &[&bytes]),
            "{len} bytes"
        );
    }
}
