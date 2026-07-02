use super::*;
use vos::Message;
use vos::actors::context::ServiceId;

fn ctl() -> MsgCtl {
    MsgCtl::new()
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

fn dispatch<M>(c: &mut MsgCtl, msg: M) -> <MsgCtl as Message<M>>::Output
where
    MsgCtl: Message<M>,
{
    let mut ctx: vos::Context<MsgCtl> = vos::Context::new(ServiceId(0));
    run(<MsgCtl as Message<M>>::handle(c, msg, &mut ctx))
}

fn submit(c: &mut MsgCtl, epoch: u64, body: &[u8]) -> CommitOutcome {
    dispatch(
        c,
        Commit {
            epoch,
            ts_ms: 1000 + epoch,
            commit_body: body.to_vec(),
            welcome: Vec::new(),
            welcome_hint: Vec::new(),
        },
    )
}

#[test]
fn chain_advances_one_epoch_at_a_time() {
    let mut c = ctl();
    assert_eq!(
        submit(&mut c, 0, b"add-bob"),
        CommitOutcome {
            status: Status::Ok,
            next_epoch: 1
        }
    );
    assert_eq!(
        submit(&mut c, 1, b"add-carol"),
        CommitOutcome {
            status: Status::Ok,
            next_epoch: 2
        }
    );
    assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 2 });
}

#[test]
fn second_commit_for_an_epoch_is_rejected_with_the_winner_intact() {
    // The MLS fork-prevention property: exactly one commit
    // wins each epoch; the loser is told to reprocess.
    let mut c = ctl();
    submit(&mut c, 0, b"alice-wins");
    let outcome = submit(&mut c, 0, b"bob-loses");
    assert_eq!(outcome.status, Status::EpochTaken);
    assert_eq!(outcome.next_epoch, 1);
    let winner = dispatch(&mut c, CommitAt { epoch: 0 }).unwrap();
    assert_eq!(winner.commit_body, b"alice-wins");
}

#[test]
fn resubmitting_the_winner_is_idempotent() {
    let mut c = ctl();
    submit(&mut c, 0, b"same");
    let again = submit(&mut c, 0, b"same");
    assert_eq!(again.status, Status::Ok);
    assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 1 });
}

#[test]
fn epoch_gap_is_refused() {
    // A commit built on unseen epochs means the caller skipped
    // processing the chain — never let a hole into the record.
    let mut c = ctl();
    let outcome = submit(&mut c, 3, b"from-the-future");
    assert_eq!(outcome.status, Status::EpochGap);
    assert_eq!(outcome.next_epoch, 0);
    assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 0 });
}

#[test]
fn welcome_and_hint_must_travel_together() {
    let mut c = ctl();
    let outcome = dispatch(
        &mut c,
        Commit {
            epoch: 0,
            ts_ms: 0,
            commit_body: b"add".to_vec(),
            welcome: b"welcome-bytes".to_vec(),
            welcome_hint: Vec::new(),
        },
    );
    assert_eq!(outcome.status, Status::InvalidInput);
    let outcome = dispatch(
        &mut c,
        Commit {
            epoch: 0,
            ts_ms: 0,
            commit_body: b"add".to_vec(),
            welcome: b"welcome-bytes".to_vec(),
            welcome_hint: vec![7u8; 32],
        },
    );
    assert_eq!(outcome.status, Status::Ok);
    let row = dispatch(&mut c, CommitAt { epoch: 0 }).unwrap();
    assert_eq!(row.welcome, b"welcome-bytes");
    assert_eq!(row.welcome_hint, [7u8; 32]);
}

#[test]
fn size_bounds_are_enforced() {
    let mut c = ctl();
    let over = vec![0u8; MAX_BODY_BYTES + 1];
    assert_eq!(submit(&mut c, 0, &over).status, Status::TooLarge);
    // Each field within bounds but the row over the combined cap.
    let body = vec![0u8; 7 * 1024];
    let welcome = vec![1u8; 7 * 1024];
    let outcome = dispatch(
        &mut c,
        Commit {
            epoch: 0,
            ts_ms: 0,
            commit_body: body,
            welcome,
            welcome_hint: vec![7u8; 32],
        },
    );
    assert_eq!(outcome.status, Status::TooLarge);
    assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 0 });
}

#[test]
fn commits_pages_in_epoch_order() {
    let mut c = ctl();
    for e in 0..5u64 {
        submit(&mut c, e, format!("c{e}").as_bytes());
    }
    let first = dispatch(
        &mut c,
        Commits {
            from_epoch: 0,
            limit: 2,
        },
    );
    assert_eq!(first.len(), 2);
    assert_eq!(first[1].epoch, 1);
    let rest = dispatch(
        &mut c,
        Commits {
            from_epoch: first.last().unwrap().epoch + 1,
            limit: 10,
        },
    );
    assert_eq!(rest.len(), 3);
    assert_eq!(rest[0].commit_body, b"c2");
}

#[test]
fn commits_paging_respects_byte_budget_but_returns_progress() {
    let mut c = ctl();
    let big = vec![0xAAu8; 7 * 1024];
    submit(&mut c, 0, &big);
    submit(&mut c, 1, &big);
    let rows = dispatch(
        &mut c,
        Commits {
            from_epoch: 0,
            limit: 10,
        },
    );
    assert_eq!(rows.len(), 1, "two 7 KiB commits exceed the 12 KiB budget");
}
