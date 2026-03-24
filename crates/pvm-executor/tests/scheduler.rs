use pvm_abi::actor::{ActorId, Status};
use pvm_executor::scheduler::{Driver, Scheduler, TickResult};

/// Test message type.
#[derive(Debug)]
enum TestMsg {
    Ping,
    Add(i32),
}

/// A simple in-process driver for testing. Simulates child actors
/// that live in the same process (no PVM boundary).
struct TestDriver {
    /// Per-actor state: just a counter for testing.
    states: [i32; 4],
    /// Track which actors got initialized.
    initialized: [bool; 4],
}

impl TestDriver {
    fn new() -> Self {
        Self {
            states: [0; 4],
            initialized: [false; 4],
        }
    }

    fn idx(id: ActorId) -> usize {
        (id.0 - 1) as usize
    }
}

impl Driver<TestMsg> for TestDriver {
    fn init(&mut self, id: ActorId) -> Status {
        self.initialized[Self::idx(id)] = true;
        Status::Ready
    }

    fn handle(&mut self, id: ActorId, msg: &TestMsg) -> Status {
        let idx = Self::idx(id);
        match msg {
            TestMsg::Ping => Status::Ready,
            TestMsg::Add(n) => {
                self.states[idx] += n;
                Status::Ready
            }
        }
    }

    fn poll(&mut self, _id: ActorId) -> Status {
        Status::Ready
    }

    fn drop_actor(&mut self, _id: ActorId) {}
}

#[test]
fn spawn_and_init() {
    let mut sched: Scheduler<TestMsg, TestDriver, 4, 16> =
        Scheduler::new(TestDriver::new());

    let id = sched.spawn().unwrap();
    assert_eq!(id, ActorId(1));
    assert!(sched.driver().initialized[0]);
}

#[test]
fn send_and_tick() {
    let mut sched: Scheduler<TestMsg, TestDriver, 4, 16> =
        Scheduler::new(TestDriver::new());

    let a = sched.spawn().unwrap();
    let b = sched.spawn().unwrap();

    sched.send(a, TestMsg::Add(10)).unwrap();
    sched.send(b, TestMsg::Add(20)).unwrap();

    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.driver().states[0], 10);
    assert_eq!(sched.driver().states[1], 20);
}

#[test]
fn multiple_messages_round_robin() {
    let mut sched: Scheduler<TestMsg, TestDriver, 4, 16> =
        Scheduler::new(TestDriver::new());

    let a = sched.spawn().unwrap();
    sched.send(a, TestMsg::Add(1)).unwrap();
    sched.send(a, TestMsg::Add(2)).unwrap();
    sched.send(a, TestMsg::Add(3)).unwrap();

    // Each tick processes one message per actor
    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.driver().states[0], 1);

    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.driver().states[0], 3);

    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.driver().states[0], 6);

    assert_eq!(sched.tick(), TickResult::Idle);
}

#[test]
fn idle_when_no_messages() {
    let mut sched: Scheduler<TestMsg, TestDriver, 4, 16> =
        Scheduler::new(TestDriver::new());

    sched.spawn().unwrap();
    assert_eq!(sched.tick(), TickResult::Idle);
}

#[test]
fn done_when_no_actors() {
    let mut sched: Scheduler<TestMsg, TestDriver, 4, 16> =
        Scheduler::new(TestDriver::new());

    assert_eq!(sched.tick(), TickResult::Done);
}
