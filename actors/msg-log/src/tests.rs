use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use vos::Message;
use vos::actors::context::ServiceId;

static NEXT_TEST_INVOCATION: AtomicU64 = AtomicU64::new(1);
static TEST_CHANGE_SCOPE: std::sync::Mutex<()> = std::sync::Mutex::new(());
const TEST_ACTOR: vos::ActorId = vos::ActorId::new([0x4d; 32]);

fn log() -> MsgLog {
    MsgLog::new()
}

#[test]
fn program_declares_crdt_storage() {
    assert!(<MsgLog as vos::Actor>::CRDT);
}

/// Handler futures never await anything external, so a single
/// poll with a no-op waker resolves them — no executor (or
/// vos `std` feature) needed in this crate's unit tests.
fn run<F: core::future::Future>(fut: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        fn noop(_: *const ()) {}
        RawWaker::new(
            core::ptr::null(),
            &RawWakerVTable::new(clone, noop, noop, noop),
        )
    }
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("actor handler future was not immediately ready"),
    }
}

fn test_change(domain: &[u8], identity: &[u8]) -> vos::v2::ChangeId {
    vos::v2::ChangeId::new(vos::InvocationId::derive(domain, identity).0)
}

fn dispatch_with_change<M>(
    l: &mut MsgLog,
    msg: M,
    change: vos::v2::ChangeId,
) -> <MsgLog as Message<M>>::Output
where
    MsgLog: Message<M>,
{
    // `vos` is deliberately built no-std for this actor's host tests, so its
    // guest-style allocator is process-global. Serialise direct dispatches as
    // the real single-threaded actor VM does.
    let _scope = TEST_CHANGE_SCOPE.lock().expect("test change scope lock");
    let dispatch = vos::v2::CrdtDispatchV2 { change, ordinal: 0 };
    let scoped_change = crdt::ChangeId::for_dispatch(change, TEST_ACTOR, dispatch.ordinal);
    let mut ctx: vos::Context<MsgLog> = vos::Context::new(ServiceId(0));
    let output = crdt::with_change(scoped_change, || {
        Ok(run(<MsgLog as Message<M>>::handle(l, msg, &mut ctx)))
    })
    .expect("test dispatch establishes one CRDT change scope");
    crdt::take_operations(TEST_ACTOR, dispatch)
        .expect("test dispatch consumes one contiguous CRDT operation batch");
    output
}

fn dispatch<M>(l: &mut MsgLog, msg: M) -> <MsgLog as Message<M>>::Output
where
    MsgLog: Message<M>,
{
    // Direct dispatch bypasses generated actor entry glue, so give every
    // synthetic invocation its own scoped operation allocator.
    let nonce = NEXT_TEST_INVOCATION.fetch_add(1, Ordering::Relaxed);
    dispatch_with_change(
        l,
        msg,
        test_change(b"msg-log/tests/dispatch", &nonce.to_le_bytes()),
    )
}

/// Wrap a test payload in the minimal MLS PrivateMessage framing
/// the `post` validator requires (version + wire-format prefix).
fn framed(payload: &[u8]) -> Vec<u8> {
    let mut b = MLS_PRIVATE_MESSAGE_PREFIX.to_vec();
    b.extend_from_slice(payload);
    b
}

fn post(l: &mut MsgLog, lamport: u64, body: &[u8]) -> Status {
    let body = framed(body);
    let id = envelope_id(
        EnvelopeKind::App as u8,
        1,
        lamport,
        1000 + lamport,
        &[0u8; 32],
        &body,
    );
    // Distinct envelopes model distinct invocations. Re-posting identical
    // content models an exact retry and deliberately reuses its ChangeId,
    // including when replicas receive envelopes in different orders.
    dispatch_with_change(
        l,
        Post {
            kind: EnvelopeKind::App as u8,
            epoch: 1,
            lamport,
            ts_ms: 1000 + lamport,
            to_hint: Vec::new(),
            body,
        },
        test_change(b"msg-log/tests/post", &id),
    )
}

#[test]
fn post_then_history_round_trips() {
    let mut l = log();
    assert_eq!(post(&mut l, 1, b"ciphertext-a"), Status::Ok);
    assert_eq!(post(&mut l, 2, b"ciphertext-b"), Status::Ok);
    let rows = dispatch(
        &mut l,
        History {
            after_lamport: 0,
            after_id: Vec::new(),
            limit: 10,
        },
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].body, framed(b"ciphertext-a"));
    assert_eq!(rows[1].body, framed(b"ciphertext-b"));
}

#[test]
fn post_rejects_non_mls_framed_body() {
    let mut l = log();
    // A rejected post returns before insertion, so probing several
    // bad bodies against the same log leaves it empty.
    let mut bad = |body: Vec<u8>| {
        dispatch(
            &mut l,
            Post {
                kind: EnvelopeKind::App as u8,
                epoch: 1,
                lamport: 1,
                ts_ms: 1,
                to_hint: Vec::new(),
                body,
            },
        )
    };
    // Arbitrary bytes with no MLS framing are refused.
    assert_eq!(bad(b"not-mls-at-all".to_vec()), Status::InvalidInput);
    // Right version but the wrong wire format (Welcome = 3, not the
    // PrivateMessage = 2 the data plane carries) is refused.
    assert_eq!(
        bad(vec![0x00, 0x01, 0x00, 0x03, 0xAB]),
        Status::InvalidInput
    );
    // A body shorter than the prefix is refused.
    assert_eq!(bad(vec![0x00, 0x01]), Status::InvalidInput);
    assert_eq!(dispatch(&mut l, Stats).count, 0);
    // The same payload under valid framing is accepted and stored.
    assert_eq!(post(&mut l, 1, b"real"), Status::Ok);
    assert_eq!(dispatch(&mut l, Stats).count, 1);
}

#[test]
fn post_is_idempotent_by_content() {
    // A CRDT merge can replay the same event on a replica
    // that already holds it — the log must not duplicate.
    let mut l = log();
    assert_eq!(post(&mut l, 1, b"same"), Status::Ok);
    assert_eq!(post(&mut l, 1, b"same"), Status::Ok);
    assert_eq!(dispatch(&mut l, Stats).count, 1);
}

#[test]
fn order_converges_regardless_of_arrival() {
    // Two replicas receiving the same envelopes in different
    // orders must serve identical history pages.
    let mut a = log();
    let mut b = log();
    post(&mut a, 2, b"two");
    post(&mut a, 1, b"one");
    post(&mut a, 3, b"three");
    post(&mut b, 3, b"three");
    post(&mut b, 1, b"one");
    post(&mut b, 2, b"two");
    let page = |l: &mut MsgLog| {
        dispatch(
            l,
            History {
                after_lamport: 0,
                after_id: Vec::new(),
                limit: 10,
            },
        )
    };
    assert_eq!(page(&mut a), page(&mut b));
}

#[test]
fn equal_lamport_ties_break_by_id() {
    // Concurrent senders legitimately pick the same lamport;
    // the id tiebreak keeps the order total and replica-
    // independent.
    let mut l = log();
    post(&mut l, 1, b"x");
    post(&mut l, 1, b"y");
    let rows = dispatch(
        &mut l,
        History {
            after_lamport: 0,
            after_id: Vec::new(),
            limit: 10,
        },
    );
    assert_eq!(rows.len(), 2);
    assert!(rows[0].id < rows[1].id);
}

#[test]
fn history_cursor_pages_without_overlap() {
    let mut l = log();
    for i in 1..=5u64 {
        post(&mut l, i, format!("m{i}").as_bytes());
    }
    let first = dispatch(
        &mut l,
        History {
            after_lamport: 0,
            after_id: Vec::new(),
            limit: 2,
        },
    );
    assert_eq!(first.len(), 2);
    let cursor = first.last().unwrap();
    let rest = dispatch(
        &mut l,
        History {
            after_lamport: cursor.lamport,
            after_id: cursor.id.to_vec(),
            limit: 10,
        },
    );
    assert_eq!(rest.len(), 3);
    assert_eq!(rest[0].body, framed(b"m3"));
}

#[test]
fn history_respects_byte_budget_but_returns_progress() {
    // Oversized-page protection must still hand back at least
    // one row, or a paging client would spin forever.
    let mut l = log();
    let big = vec![0xAAu8; 8 * 1024];
    post(&mut l, 1, &big);
    post(&mut l, 2, &big);
    let rows = dispatch(
        &mut l,
        History {
            after_lamport: 0,
            after_id: Vec::new(),
            limit: 10,
        },
    );
    assert_eq!(rows.len(), 1, "two 8 KiB bodies exceed the 12 KiB budget");
}

#[test]
fn post_validates_shape() {
    let mut l = log();
    // Empty body (dispatched raw — the `post` helper would frame it
    // into a non-empty body).
    assert_eq!(
        dispatch(
            &mut l,
            Post {
                kind: EnvelopeKind::App as u8,
                epoch: 1,
                lamport: 1,
                ts_ms: 0,
                to_hint: Vec::new(),
                body: Vec::new(),
            },
        ),
        Status::InvalidInput
    );
    // Zero lamport.
    assert_eq!(post(&mut l, 0, b"x"), Status::InvalidInput);
    // Oversized body.
    let huge = vec![0u8; MAX_BODY_BYTES + 1];
    assert_eq!(post(&mut l, 1, &huge), Status::BodyTooLarge);
    // Control-plane kind on the data plane.
    assert_eq!(
        dispatch(
            &mut l,
            Post {
                kind: EnvelopeKind::Commit as u8,
                epoch: 1,
                lamport: 1,
                ts_ms: 0,
                to_hint: Vec::new(),
                body: b"c".to_vec(),
            },
        ),
        Status::InvalidInput,
    );
    // Malformed hint length.
    assert_eq!(
        dispatch(
            &mut l,
            Post {
                kind: EnvelopeKind::App as u8,
                epoch: 1,
                lamport: 1,
                ts_ms: 0,
                to_hint: vec![1, 2, 3],
                body: b"c".to_vec(),
            },
        ),
        Status::InvalidInput,
    );
    assert_eq!(dispatch(&mut l, Stats).count, 0);
}

#[test]
fn stats_reports_count_and_max_lamport() {
    let mut l = log();
    assert_eq!(
        dispatch(&mut l, Stats),
        LogStats {
            count: 0,
            max_lamport: 0
        }
    );
    post(&mut l, 7, b"x");
    post(&mut l, 3, b"y");
    assert_eq!(
        dispatch(&mut l, Stats),
        LogStats {
            count: 2,
            max_lamport: 7
        }
    );
}
