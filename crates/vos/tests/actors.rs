#![allow(dead_code)]
use vos::{Actor, Context, Executor, Mailbox, Progress};
use vos::actors::context::ServiceId;

// -- Actor definition --

struct Counter {
    count: i32,
}

impl Actor for Counter {
    type Error = ();
}

// -- Messages (manual, what the macro would generate) --

struct Increment {
    pub amount: i32,
}

struct GetCount;

struct Reset;

impl vos::Message<Increment> for Counter {
    type Reply = i32;
    async fn handle(&mut self, msg: Increment, _ctx: &mut Context<Self>) -> Result<i32, ()> {
        self.count += msg.amount;
        Ok(self.count)
    }
}

impl vos::Message<GetCount> for Counter {
    type Reply = i32;
    async fn handle(&mut self, _msg: GetCount, _ctx: &mut Context<Self>) -> Result<i32, ()> {
        Ok(self.count)
    }
}

impl vos::Message<Reset> for Counter {
    type Reply = ();
    async fn handle(&mut self, _msg: Reset, _ctx: &mut Context<Self>) -> Result<(), ()> {
        self.count = 0;
        Ok(())
    }
}

// -- Aggregated message enum (what #[messages] generates) --

enum CounterMsg {
    Increment(Increment),
    GetCount(GetCount),
    Reset(Reset),
}

impl CounterMsg {
    async fn deliver(self, actor: &mut Counter, ctx: &mut Context<Counter>) {
        match self {
            CounterMsg::Increment(msg) => {
                let _ = <Counter as vos::Message<Increment>>::handle(actor, msg, ctx).await;
            }
            CounterMsg::GetCount(msg) => {
                let _ = <Counter as vos::Message<GetCount>>::handle(actor, msg, ctx).await;
            }
            CounterMsg::Reset(msg) => {
                let _ = <Counter as vos::Message<Reset>>::handle(actor, msg, ctx).await;
            }
        }
    }
}

// -- Actor + Mailbox wrapper for the executor --

struct CounterActor {
    actor: Counter,
    ctx: Context<Counter>,
    mailbox: Mailbox<CounterMsg, 16>,
}

impl CounterActor {
    fn new(id: u32) -> Self {
        Self {
            actor: Counter { count: 0 },
            ctx: Context::new(ServiceId(id)),
            mailbox: Mailbox::new(),
        }
    }
}

// -- Minimal no_std-compatible blocking executor for tests --

fn block_on<F: core::future::Future>(mut fut: F) -> F::Output {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_raw_waker() -> RawWaker {
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => {}
        }
    }
}

async fn poll_counters(exec: &mut Executor<CounterActor, 4>) -> Progress {
    exec.tick(async |_id, slot: &mut CounterActor| {
        if let Some(msg) = slot.mailbox.pop() {
            msg.deliver(&mut slot.actor, &mut slot.ctx).await;
            true
        } else {
            false
        }
    }).await
}

#[test]
fn single_actor_processes_messages() {
    block_on(async {
        let mut exec: Executor<CounterActor, 4> = Executor::new();
        let id = exec.spawn(CounterActor::new(0)).unwrap();

        let actor = exec.get_mut(id).unwrap();
        actor.mailbox.push(CounterMsg::Increment(Increment { amount: 5 })).ok();
        actor.mailbox.push(CounterMsg::Increment(Increment { amount: 3 })).ok();

        assert_eq!(poll_counters(&mut exec).await, Progress::Progressed);
        assert_eq!(exec.get(id).unwrap().actor.count, 5);

        assert_eq!(poll_counters(&mut exec).await, Progress::Progressed);
        assert_eq!(exec.get(id).unwrap().actor.count, 8);

        assert_eq!(poll_counters(&mut exec).await, Progress::Idle);
    });
}

#[test]
fn multiple_actors_round_robin() {
    block_on(async {
        let mut exec: Executor<CounterActor, 4> = Executor::new();
        let a = exec.spawn(CounterActor::new(0)).unwrap();
        let b = exec.spawn(CounterActor::new(1)).unwrap();

        exec.get_mut(a).unwrap().mailbox.push(CounterMsg::Increment(Increment { amount: 10 })).ok();
        exec.get_mut(b).unwrap().mailbox.push(CounterMsg::Increment(Increment { amount: 20 })).ok();

        assert_eq!(poll_counters(&mut exec).await, Progress::Progressed);
        assert_eq!(exec.get(a).unwrap().actor.count, 10);
        assert_eq!(exec.get(b).unwrap().actor.count, 20);
    });
}

#[test]
fn mailbox_ring_buffer() {
    let mut mb: Mailbox<i32, 3> = Mailbox::new();
    assert!(mb.is_empty());

    mb.push(1).unwrap();
    mb.push(2).unwrap();
    mb.push(3).unwrap();
    assert!(mb.is_full());
    assert!(mb.push(4).is_err());

    assert_eq!(mb.pop(), Some(1));
    assert_eq!(mb.len(), 2);

    mb.push(4).unwrap();
    assert_eq!(mb.pop(), Some(2));
    assert_eq!(mb.pop(), Some(3));
    assert_eq!(mb.pop(), Some(4));
    assert!(mb.is_empty());
}

#[test]
fn executor_stop_actor() {
    block_on(async {
        let mut exec: Executor<CounterActor, 4> = Executor::new();
        exec.spawn(CounterActor::new(0)).unwrap();
        assert_eq!(exec.alive_count(), 1);

        exec.stop(0);
        assert_eq!(exec.alive_count(), 0);
        assert_eq!(poll_counters(&mut exec).await, Progress::Done);
    });
}
