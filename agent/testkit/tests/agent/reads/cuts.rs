//! The window cuts reads wait on: re-cuts, deadlines and pruning, the
//! agent's report of its root, the representative's closes, and a
//! statement's proof recorded.

use super::*;

/// The start of window `window`.
fn start_of(window: u64) -> u64 {
    CLOCK.boundary(window - 1).unwrap()
}

/// A row of the node's state, decoded.
fn row<T: Decode>(reads: &Reads, key: &[u8]) -> Option<T> {
    reads.node.value(key)
}

/// A batch of nothing but a sweep at `time`, in which apply records the
/// cuts its time crosses.
fn tick(reads: &mut Reads, time: u64) {
    let sweep = reads.node.sweep(time);
    reads.batch(time, vec![sweep]);
}

/// The roots of the read `request`'s attest in `result`, and its window.
fn stated(result: &WorkResult, request: RequestId) -> (Option<u64>, Vec<RootRead>) {
    let attest = &resumed(result, request).attests[0];
    (attest.window, attest.roots.clone())
}

/// A window whose close has not applied by the next cut is re-cut there:
/// a read asked in window 10, its window cut and unclosed when window 11's
/// cut is recorded, moves to window 11 ([`keys::moved`]), and is served
/// and stated at window 11's cut, with window 11's close. A window closed
/// in time is not re-cut, its read served at its own cut. A close that
/// comes after the re-cut serves the read at its own window still; a
/// window it never moved through serves it none.
#[test]
fn an_unclosed_window_is_re_cut_at_the_next() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(WINDOW, id, 0);
    tick(&mut reads, start_of(11) + 5);
    assert_eq!(row::<u64>(&reads, &keys::serving()), Some(WINDOW));
    assert_eq!(row::<u64>(&reads, &keys::moved(WINDOW)), None);
    tick(&mut reads, start_of(12) + 5);
    assert_eq!(row::<u64>(&reads, &keys::serving()), Some(11));
    assert_eq!(row::<u64>(&reads, &keys::moved(WINDOW)), Some(11));
    let served = reads.served(11, &read);
    let resume = reads.resume(WINDOW, request, Some(&served));
    let result = reads.batch(start_of(12) + 10, vec![resume]);
    let (window, roots) = stated(&result, request);
    assert_eq!(window, Some(11));
    assert_eq!(roots[0].window, 11);
    assert_eq!(roots[0].root, space_root(&SPACE, 11, &served.rep_root));
    assert_eq!(ended(&reads.record(id)), &Outcome::Done(30u64.encode()));

    // Closed in time: no re-cut.
    let id = reads.start(start_of(12) + 20, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(12, id, 0);
    let served = reads.served(12, &read);
    tick(&mut reads, start_of(13) + 5);
    tick(&mut reads, start_of(14) + 5);
    assert_eq!(row::<u64>(&reads, &keys::moved(12)), None);
    let resume = reads.resume(12, request, Some(&served));
    let result = reads.batch(start_of(14) + 10, vec![resume]);
    assert_eq!(stated(&result, request).0, Some(12));

    // Closed after the re-cut: still served at its own window, as at any
    // window it was moved through; at none past them.
    let id = reads.start(start_of(14) + 20, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(14, id, 0);
    tick(&mut reads, start_of(15) + 5);
    tick(&mut reads, start_of(16) + 5);
    assert_eq!(row::<u64>(&reads, &keys::moved(14)), Some(15));
    let before = reads.served(13, &read);
    let resume = reads.resume(14, request, Some(&before));
    let result = reads.batch(start_of(16) + 10, vec![resume]);
    assert!(
        resumed(&result, request).attests.is_empty(),
        "not of its windows"
    );
    let id = reads.start(start_of(16) + 20, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(16, id, 0);
    tick(&mut reads, start_of(17) + 5);
    tick(&mut reads, start_of(18) + 5);
    assert_eq!(row::<u64>(&reads, &keys::moved(16)), Some(17));
    let late = reads.served(16, &read);
    let resume = reads.resume(16, request, Some(&late));
    let result = reads.batch(start_of(18) + 10, vec![resume]);
    assert_eq!(stated(&result, request).0, Some(16));
}

/// A read re-cut twice and closed at neither ends `NotClosed` at its
/// deadline, `B_{w+3}`, when its third re-cut would come.
#[test]
fn a_read_re_cut_twice_ends_not_closed() {
    let mut reads = Reads::with(&[(1, 10)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64]);
    for window in 11..=13 {
        tick(&mut reads, start_of(window) + 5);
    }
    tick(&mut reads, start_of(14) - 1);
    assert_eq!(row::<u64>(&reads, &keys::moved(WINDOW)), Some(11));
    assert_eq!(row::<u64>(&reads, &keys::moved(11)), Some(12));
    assert!(matches!(
        reads.record(id).state,
        WorkflowState::Attesting { .. }
    ));
    tick(&mut reads, start_of(14));
    assert_eq!(
        ended(&reads.record(id)),
        &failed_with(AttestError::NotClosed)
    );
}

/// A clock's jump past `MAX_CUTS` windows cuts the newest of them: the
/// window a read was asked in is left uncut and its deadline is past, so
/// the next sweep ends it `NotClosed`, its request gone.
#[test]
fn a_read_a_jump_leaves_uncut_ends_not_closed() {
    let mut reads = Reads::with(&[(1, 10)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64]);
    let (request, _) = reads.asked(WINDOW, id, 0);
    let last = WINDOW + defaults::MAX_CUTS + 5;
    let first = last + 1 - defaults::MAX_CUTS;
    tick(&mut reads, start_of(last + 1) + 5);
    assert_eq!(
        reads.node.get(&keys::cut(WINDOW)),
        None,
        "window 10 not cut"
    );
    assert!(reads.node.get(&keys::cut(first)).is_some());
    assert_eq!(row::<u64>(&reads, &keys::serving()), Some(first));
    tick(&mut reads, start_of(last + 1) + 6);
    assert_eq!(
        ended(&reads.record(id)),
        &failed_with(AttestError::NotClosed)
    );
    assert!(reads.node.get(&keys::request(WINDOW, request)).is_none());
}

/// A cut recording window `w` deletes the cut, re-cut and close rows of
/// every window before `w − CUT_KEEP`, and no later one.
#[test]
fn old_cut_rows_are_pruned() {
    let mut reads = Reads::with(&[(1, 10)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64]);
    let (_, read) = reads.asked(WINDOW, id, 0);
    reads.served(WINDOW, &read);
    for window in 11..=20 {
        tick(&mut reads, start_of(window) + 5);
    }
    let first = 19;
    for window in WINDOW..20 {
        let kept = window + defaults::CUT_KEEP >= first;
        assert_eq!(
            reads.node.get(&keys::cut(window)).is_some(),
            kept,
            "cut({window})"
        );
        if window > WINDOW && window < 19 {
            assert_eq!(
                reads.node.get(&keys::moved(window)).is_some(),
                kept,
                "moved({window})"
            );
        }
    }
    assert!(
        reads.node.get(&keys::closed(WINDOW)).is_none(),
        "closed(10)"
    );
    // A close of a window pruned is not taken.
    let stale = Input::Message(Message {
        from: REPRESENTATIVE,
        sequence: reads.closes + 1,
        body: Body::Closed {
            window: 12,
            rep_root: [1; 32],
            rep_salt: [2; 16],
            space_path: vec![3],
        },
    });
    reads.closes += 1;
    let time = reads.time;
    reads.batch(time, vec![stale]);
    assert!(reads.node.get(&keys::closed(12)).is_none());
}

/// The agent's report of its root at a window's cut: a `Body::Report` to
/// the representative with the window, the root and whether reads wait,
/// and the mark; none again for that window or an
/// earlier one, none to itself, and none from an agent of no space.
#[test]
fn a_report_goes_once_a_window() {
    let mut reads = Reads::with(&[(1, 10)]);
    let report = |window, to| Input::Report {
        to,
        window,
        root: [window as u8; 32],
        pending: window == 3,
    };
    let result = reads.batch(T0 + 1, vec![report(3, REPRESENTATIVE)]);
    let call = vos_wire::served::AgentRoot {
        kind: 0,
        window: 3,
        root: [3; 32],
        pending: true,
    };
    assert_eq!(
        ran(&result.steps[0]).messages,
        [vos_wire::result::Outgoing {
            to: REPRESENTATIVE,
            body: Body::Report(call),
        }]
    );
    assert_eq!(
        row::<(u64, AgentId)>(&reads, &keys::reported()),
        Some((3, REPRESENTATIVE))
    );
    let result = reads.batch(
        T0 + 2,
        vec![
            report(3, REPRESENTATIVE),
            report(2, REPRESENTATIVE),
            report(4, AGENT),
        ],
    );
    assert!(
        result
            .steps
            .iter()
            .all(|step| ran(step).messages.is_empty())
    );
    let result = reads.batch(T0 + 3, vec![report(4, REPRESENTATIVE)]);
    assert_eq!(ran(&result.steps[0]).messages.len(), 1);
    let mut spaceless = Reads::new(Target::Vos, SpaceId::NONE);
    let result = spaceless.batch(T0, vec![report(3, REPRESENTATIVE)]);
    assert!(ran(&result.steps[0]).messages.is_empty());
}

/// The representative's close of a window sends each agent that asked its
/// `Closed`, at most `CLOSE_PATHS` a close in agent order, each once
/// across closes of the window; an earlier window's close sends nothing.
#[test]
fn a_close_sends_each_path_once() {
    let mut reads = Reads::with(&[(1, 10)]);
    let count = 2 * defaults::CLOSE_PATHS + 6;
    let paths: Vec<(AgentId, [u8; 16], Vec<u8>)> = (0..count as u32)
        .map(|n| (AgentId(0x0300_0000 + n), [n as u8; 16], vec![n as u8; 5]))
        .collect();
    let close = |window| Input::Close {
        window,
        rep_root: [9; 32],
        paths: paths.clone(),
    };
    let sent = |result: &WorkResult| -> Vec<AgentId> {
        ran(&result.steps[0])
            .messages
            .iter()
            .map(|message| message.to)
            .collect()
    };
    let result = reads.batch(T0 + 1, vec![close(7), close(7)]);
    let first: Vec<AgentId> = result
        .steps
        .iter()
        .flat_map(|step| ran(step).messages.iter().map(|message| message.to))
        .collect();
    assert_eq!(first.len(), 2 * defaults::CLOSE_PATHS);
    let second = sent(&reads.batch(T0 + 2, vec![close(7)]));
    assert_eq!(second.len(), 6);
    assert_eq!(
        [first, second].concat(),
        paths.iter().map(|(agent, ..)| *agent).collect::<Vec<_>>()
    );
    assert!(sent(&reads.batch(T0 + 3, vec![close(7)])).is_empty());
    let result = reads.batch(T0 + 4, vec![close(8), close(6)]);
    assert_eq!(sent(&result).len(), defaults::CLOSE_PATHS);
    assert!(ran(&result.steps[1]).messages.is_empty());
    let empty = Input::Close {
        window: 9,
        rep_root: [9; 32],
        paths: Vec::new(),
    };
    reads.batch(T0 + 5, vec![empty]);
    assert_eq!(
        row::<(u64, Option<AgentId>)>(&reads, &keys::close_mark()),
        Some((9, None))
    );
}

/// A statement's proof is recorded once: the first `Proven` of an id
/// writes its row, a second of the id, another proof, writes nothing, and
/// another id its own.
#[test]
fn a_statement_is_recorded_proven_once() {
    let mut reads = Reads::with(&[(1, 10)]);
    let proven = |id: u8, proof: u8| Input::Proven {
        window: 4,
        id: [id; 32],
        proof: [proof; 32],
    };
    let result = reads.batch(T0 + 1, vec![proven(1, 0xa1), proven(1, 0xa2)]);
    assert_eq!(ran(&result.steps[0]).writes.len(), 1);
    assert!(ran(&result.steps[1]).writes.is_empty());
    reads.batch(T0 + 2, vec![proven(1, 0xa3), proven(2, 0xb1)]);
    assert_eq!(
        row::<[u8; 32]>(&reads, &keys::proven(4, &[1; 32])),
        Some([0xa1; 32])
    );
    assert_eq!(
        row::<[u8; 32]>(&reads, &keys::proven(4, &[2; 32])),
        Some([0xb1; 32])
    );
}

/// A `Closed` is taken from the representative the agent reported to,
/// once a window: a second for the window, other bytes, is ignored, and
/// one from another agent writes nothing.
#[test]
fn a_closed_is_taken_once_from_the_representative() {
    let mut reads = Reads::with(&[(1, 10)]);
    let closed = |from, sequence, root: u8| {
        Input::Message(Message {
            from,
            sequence,
            body: Body::Closed {
                window: WINDOW,
                rep_root: [root; 32],
                rep_salt: [0; 16],
                space_path: vec![root],
            },
        })
    };
    let other = AgentId(0x0700_0000);
    reads.batch(T0 + 1, vec![closed(other, 1, 1)]);
    assert!(
        reads.node.get(&keys::closed(WINDOW)).is_none(),
        "not reported to"
    );
    let report = Input::Report {
        to: REPRESENTATIVE,
        window: WINDOW,
        root: [0; 32],
        pending: true,
    };
    reads.batch(
        T0 + 2,
        vec![report, closed(REPRESENTATIVE, 1, 2), closed(other, 2, 3)],
    );
    reads.closes = 1;
    let held = |reads: &Reads| row::<vos_wire::served::ClosedRow>(reads, &keys::closed(WINDOW));
    assert_eq!(held(&reads).unwrap().rep_root, [2; 32]);
    reads.batch(T0 + 3, vec![closed(REPRESENTATIVE, 2, 4)]);
    reads.closes = 2;
    assert_eq!(held(&reads).unwrap().rep_root, [2; 32], "the first kept");
}
