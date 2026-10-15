//! The node host with the default agent (`just build-agent`) and the test
//! actors (`just build-test-actors`): batches applied before anything is
//! sent, admission, failing refines, and messages between agents applied
//! exactly once across stops and restarts.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::calls::{done, installed};
use vos_checker::hooks::{Gate, carries};
use vos_checker::programs::Programs;
use vos_checker::spaces::wait_in_process as wait_until;
use vos_node::store::EntryKind;
use vos_node::{CallError, Config, Hooks, Node, Reply};
use vos_wire::abi::Refusal;
use vos_wire::batch::{Batch, Body, Message, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, defaults, keys};

const COUNTER: InstanceId = InstanceId(1);
const ALICE: Principal = Principal::Client([1; 32]);

/// Requests in one new session of Alice's, numbered in order.
struct Requests {
    session: Session,
    sequence: u64,
}

impl Requests {
    fn new() -> Self {
        static NAMES: AtomicU64 = AtomicU64::new(0);
        let name = NAMES.fetch_add(1, Ordering::SeqCst);
        Self {
            session: Session {
                key: [1; 32],
                name: u128::from(name).to_be_bytes(),
                t0: vos_node::wall_clock(),
            },
            sequence: 0,
        }
    }

    fn request<A: Encode>(&mut self, method: MethodId, arguments: A) -> Request {
        self.sequence += 1;
        Request {
            session: self.session,
            sequence: self.sequence,
            caller: ALICE,
            instance: COUNTER,
            method,
            arguments: arguments.encode(),
        }
    }
}

fn config(programs: &Programs, hooks: Arc<dyn Hooks>) -> Config {
    let mut config = Config::new(programs.agent.clone());
    config.executors = 2;
    config.hooks = hooks;
    config
}

/// A node at `dir`, with no hooks.
fn open(dir: &std::path::Path, programs: &Programs) -> Node {
    Node::open(dir, config(programs, Arc::new(vos_node::NoHooks))).unwrap()
}

/// An agent with the counter installed at [`COUNTER`].
fn counter_agent(node: &Node, programs: &Programs) -> AgentId {
    let agent = node.create_agent().unwrap();
    installed(smol::block_on(node.install(
        agent,
        COUNTER,
        &programs.counter_elf,
        vec![],
    )));
    agent
}

fn value(node: &Node, programs: &Programs, agent: AgentId) -> u64 {
    let outcome =
        smol::block_on(node.query(agent, ALICE, COUNTER, programs.method("value"), Vec::new()))
            .unwrap();
    match outcome {
        Outcome::Done(bytes) => u64::decode(&bytes).unwrap().0,
        other => panic!("{other:?}"),
    }
}

fn applied(node: &Node, agent: AgentId) -> u64 {
    node.store().snapshot().applied(agent).unwrap().unwrap_or(0)
}

/// The work results `agent` applied: its batches, not its leaders' no-ops.
fn results(node: &Node, agent: AgentId) -> usize {
    (1..=applied(node, agent))
        .filter(|index| {
            node.store()
                .log_entry(agent, *index)
                .unwrap()
                .is_some_and(|entry| entry.kind == EntryKind::Result)
        })
        .count()
}

/// `agent` has no unacknowledged message to `to`, and acknowledged `sent`.
fn outbox_cleared(node: &Node, agent: AgentId, to: AgentId, sent: u64) -> bool {
    vos_checker::applied::<u64>(node.store(), agent, &keys::acked(to)) == Some(sent)
        && (1..=sent).all(|sequence| {
            vos_checker::applied::<Vec<u8>>(node.store(), agent, &keys::outbox(to, sequence))
                .is_none()
        })
}

#[test]
fn calls_apply_and_survive_a_restart() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let increment = programs.method("increment");
    let mut session = Requests::new();
    let agent = {
        let node = open(dir.path(), &programs);
        let agent = counter_agent(&node, &programs);
        assert_eq!(
            done(smol::block_on(
                node.call(agent, session.request(increment, 5u64))
            )),
            5
        );
        assert_eq!(
            done(smol::block_on(
                node.call(agent, session.request(increment, 2u64))
            )),
            7
        );
        node.shutdown();
        agent
    };
    let node = open(dir.path(), &programs);
    assert_eq!(
        done(smol::block_on(
            node.call(agent, session.request(increment, 1u64))
        )),
        8
    );
    let before = applied(&node, agent);
    assert_eq!(value(&node, &programs, agent), 8);
    assert_eq!(
        applied(&node, agent),
        before,
        "a query never enters the log"
    );
    let entry = node.store().log_entry(agent, before).unwrap();
    assert!(entry.is_some(), "each applied batch is in the log");
    let unknown = smol::block_on(node.call(AgentId(99), session.request(increment, 1u64)));
    assert_eq!(unknown, Err(CallError::NoAgent));
}

#[test]
fn no_reply_before_its_commit_is_durable_and_a_full_queue_is_busy() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(Gate::default());
    let mut config = config(&programs, gate.clone());
    config.queue = 2;
    let node = Node::open(dir.path(), config).unwrap();
    let agent = counter_agent(&node, &programs);
    let increment = programs.method("increment");
    let mut session = Requests::new();

    let closed = gate.close();
    let reached = gate.reached();
    let first = node.call(agent, session.request(increment, 1u64));
    wait_until("the first batch reaches its commit", || {
        gate.reached() > reached
    });
    // In flight, the first is not queued: two more fit, the next does not.
    let second = node.call(agent, session.request(increment, 2u64));
    let third = node.call(agent, session.request(increment, 3u64));
    let busy = smol::block_on(node.call(agent, session.request(increment, 4u64)));
    assert_eq!(busy, Err(CallError::Busy));

    let (sender, answers) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(smol::block_on(first));
    });
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        answers.try_recv().is_err(),
        "no reply while its commit is held"
    );
    drop(closed);
    let first = answers.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(done(first), 1);
    assert_eq!(done(smol::block_on(second)), 3);
    assert_eq!(done(smol::block_on(third)), 6);
}

/// Fails every refine whose batch holds an input, a request or a message,
/// that calls with the poisoned arguments.
struct Poison(Vec<u8>);

impl Hooks for Poison {
    fn fail_refine(&self, _: AgentId, batch: &Batch) -> bool {
        carries(batch, &self.0)
    }
}

#[test]
fn a_failing_refine_isolates_its_input() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let poison = 666u64.encode();
    let node = Node::open(dir.path(), config(&programs, Arc::new(Poison(poison)))).unwrap();
    let agent = counter_agent(&node, &programs);
    let increment = programs.method("increment");
    let mut session = Requests::new();
    // Queued together, they share a batch until it fails.
    let calls: Vec<_> = [1u64, 666, 2, 3]
        .into_iter()
        .map(|by| node.call(agent, session.request(increment, by)))
        .collect();
    let replies: Vec<_> = calls.into_iter().map(smol::block_on).collect();
    assert_eq!(done(replies[0].clone()), 1);
    assert_eq!(replies[1], Ok(Reply::Failed));
    // The dropped request leaves a gap in its session.
    assert_eq!(replies[2], Ok(Reply::Refused(Refusal::Sequence)));
    assert_eq!(replies[3], Ok(Reply::Refused(Refusal::Sequence)));
    assert_eq!(value(&node, &programs, agent), 1);
}

/// Fails the next commits, as a full disk would.
#[derive(Default)]
struct FailCommits(AtomicU64);

impl Hooks for FailCommits {
    fn fail_commit(&self) -> bool {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
    }
}

/// Once armed, panics in the next refine's executor job.
#[derive(Default)]
struct PanicOnce(AtomicBool);

impl Hooks for PanicOnce {
    fn fail_refine(&self, _: AgentId, _: &Batch) -> bool {
        assert!(
            !self.0.swap(false, Ordering::SeqCst),
            "a panicking executor job"
        );
        false
    }
}

/// A duplicate that reaches the leader, past ingress, is answered as its
/// original was, from the reply window, and runs no more; one the window
/// no longer keeps is too old; a gap is refused.
#[test]
fn the_leader_answers_a_duplicate_from_the_reply_window() {
    let programs = Programs::load();
    let increment = programs.method("increment");
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), &programs);
    let agent = counter_agent(&node, &programs);
    let call = |request: &Request| smol::block_on(node.call(agent, request.clone()));
    let mut session = Requests::new();
    let first = session.request(increment, 5u64);
    assert_eq!(done(call(&first)), 5);
    assert_eq!(done(call(&first)), 5, "from the window");
    for _ in 0..defaults::REPLY_WINDOW {
        done(call(&session.request(increment, 1u64)));
    }
    assert_eq!(call(&first), Ok(Reply::TooOld));
    let mut gap = session.request(increment, 1u64);
    gap.sequence += 1;
    assert_eq!(call(&gap), Ok(Reply::Refused(Refusal::Sequence)));
    assert_eq!(
        value(&node, &programs, agent),
        5 + defaults::REPLY_WINDOW,
        "the duplicates ran no more"
    );
}

/// The node, not an input, failed the batch: it is retried whole, as one
/// batch, and no input is dropped.
#[test]
fn a_panicking_executor_retries_the_batch_whole() {
    let programs = Programs::load();
    let increment = programs.method("increment");
    let dir = tempfile::tempdir().unwrap();
    let panics = Arc::new(PanicOnce::default());
    let node = Node::open(dir.path(), config(&programs, panics.clone())).unwrap();
    let agent = counter_agent(&node, &programs);
    panics.0.store(true, Ordering::SeqCst);
    let mut session = Requests::new();
    let calls: Vec<_> = [1u64, 2, 3]
        .into_iter()
        .map(|by| node.call(agent, session.request(increment, by)))
        .collect();
    let totals: Vec<u64> = calls
        .into_iter()
        .map(|call| done(smol::block_on(call)))
        .collect();
    assert_eq!(totals, [1, 3, 6]);
    assert!(!panics.0.load(Ordering::SeqCst), "a job panicked");
    assert_eq!(
        results(&node, agent),
        2,
        "the install, then the three in one batch"
    );
}

/// A failed commit stops the node: storage takes no more. Every call
/// answers `Stopped`, nothing of the batch applies, and a restart goes on.
#[test]
fn a_failed_commit_stops_the_node_and_a_restart_recovers() {
    let programs = Programs::load();
    let increment = programs.method("increment");
    let dir = tempfile::tempdir().unwrap();
    let agent = {
        let commits = Arc::new(FailCommits::default());
        let node = Node::open(dir.path(), config(&programs, commits.clone())).unwrap();
        let agent = counter_agent(&node, &programs);
        commits.0.store(1, Ordering::SeqCst);
        let mut session = Requests::new();
        let calls: Vec<_> = [1u64, 2, 3]
            .into_iter()
            .map(|by| node.call(agent, session.request(increment, by)))
            .collect();
        for call in calls {
            assert_eq!(smol::block_on(call), Err(CallError::Stopped));
        }
        let later = smol::block_on(node.call(agent, session.request(increment, 4u64)));
        assert_eq!(later, Err(CallError::Stopped));
        node.shutdown();
        agent
    };
    let node = open(dir.path(), &programs);
    assert_eq!(value(&node, &programs, agent), 0);
    assert_eq!(results(&node, agent), 1, "only the install applied");
    let mut session = Requests::new();
    assert_eq!(
        done(smol::block_on(
            node.call(agent, session.request(increment, 4u64))
        )),
        4
    );
}

#[test]
fn agents_exchange_messages_and_acks_clear_outboxes() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), &programs);
    let sender = counter_agent(&node, &programs);
    let target = counter_agent(&node, &programs);
    let forward = programs.method("forward");
    let mut session = Requests::new();
    for by in [5u64, 7] {
        let call = node.call(sender, session.request(forward, (target.0, COUNTER.0, by)));
        assert_eq!(done(smol::block_on(call)), by);
    }
    wait_until("the target applies both", || {
        value(&node, &programs, target) == 12
    });
    wait_until("acks clear the outbox", || {
        outbox_cleared(&node, sender, target, 2)
    });
    assert_eq!(
        vos_checker::applied::<u64>(node.store(), target, &keys::pair_in(sender)),
        Some(2)
    );
}

/// Stops `agent`'s leader after its commit of log index `index`, before it
/// sends anything, once.
struct StopAfter {
    agent: AgentId,
    index: u64,
    fired: AtomicBool,
}

impl StopAfter {
    fn new(agent: AgentId, index: u64) -> Arc<Self> {
        Arc::new(Self {
            agent,
            index,
            fired: AtomicBool::new(false),
        })
    }
}

impl Hooks for StopAfter {
    fn after_commit(&self, agent: AgentId, index: u64) -> bool {
        if agent == self.agent && index == self.index {
            self.fired.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }
}

/// Two counter agents, as the node numbers them: the sender, then the
/// target, each with its leader's no-op at log index 1 and its install at
/// 2.
const SENDER: AgentId = AgentId(1);
const TARGET: AgentId = AgentId(2);

fn two_agents(node: &Node, programs: &Programs) {
    assert_eq!(counter_agent(node, programs), SENDER);
    assert_eq!(counter_agent(node, programs), TARGET);
}

#[test]
fn a_stop_before_delivery_delivers_on_restart() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let forward = programs.method("forward");
    let mut session = Requests::new();
    {
        // The sender's second batch, at 3, is the forward: stop before
        // delivery.
        let stop = StopAfter::new(SENDER, 3);
        let node = Node::open(dir.path(), config(&programs, stop.clone())).unwrap();
        two_agents(&node, &programs);
        let call = node.call(
            SENDER,
            session.request(forward, (TARGET.0, COUNTER.0, 5u64)),
        );
        assert_eq!(smol::block_on(call), Err(CallError::Stopped));
        assert!(stop.fired.load(Ordering::SeqCst));
        assert_eq!(value(&node, &programs, TARGET), 0, "nothing was delivered");
        node.shutdown();
    }
    let node = open(dir.path(), &programs);
    wait_until("recovery delivers", || value(&node, &programs, TARGET) == 5);
    wait_until("and the ack clears the outbox", || {
        outbox_cleared(&node, SENDER, TARGET, 1)
    });
}

#[test]
fn a_stop_before_the_ack_redelivers_and_applies_once() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let forward = programs.method("forward");
    let mut session = Requests::new();
    {
        // The target's second batch, at 3, applies the message: stop
        // before its ack.
        let stop = StopAfter::new(TARGET, 3);
        let node = Node::open(dir.path(), config(&programs, stop.clone())).unwrap();
        two_agents(&node, &programs);
        let call = node.call(
            SENDER,
            session.request(forward, (TARGET.0, COUNTER.0, 5u64)),
        );
        assert_eq!(done(smol::block_on(call)), 5);
        wait_until("the target applies and stops", || {
            stop.fired.load(Ordering::SeqCst)
        });
        assert_eq!(value(&node, &programs, TARGET), 5);
        assert!(!outbox_cleared(&node, SENDER, TARGET, 1), "no ack yet");
        node.shutdown();
    }
    let node = open(dir.path(), &programs);
    wait_until("the duplicate is acknowledged", || {
        outbox_cleared(&node, SENDER, TARGET, 1)
    });
    assert_eq!(value(&node, &programs, TARGET), 5, "applied once");
    // Redelivery and new sends interleave: each applies once, in order.
    for by in [10u64, 20] {
        let call = node.call(SENDER, session.request(forward, (TARGET.0, COUNTER.0, by)));
        assert_eq!(done(smol::block_on(call)), by);
    }
    wait_until("the new messages apply", || {
        value(&node, &programs, TARGET) == 35
    });
    wait_until("and are acknowledged", || {
        outbox_cleared(&node, SENDER, TARGET, 3)
    });
}

#[test]
fn redelivery_while_the_sender_sends_more_applies_each_once() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let forward = programs.method("forward");
    let mut session = Requests::new();
    {
        // The target stops after its first commit of messages, at 3,
        // whichever of the three it held.
        let stop = StopAfter::new(TARGET, 3);
        let node = Node::open(dir.path(), config(&programs, stop.clone())).unwrap();
        two_agents(&node, &programs);
        for by in [1u64, 2, 3] {
            let call = node.call(SENDER, session.request(forward, (TARGET.0, COUNTER.0, by)));
            assert_eq!(done(smol::block_on(call)), by);
        }
        wait_until("the target stops", || stop.fired.load(Ordering::SeqCst));
        node.shutdown();
    }
    let node = open(dir.path(), &programs);
    let call = node.call(
        SENDER,
        session.request(forward, (TARGET.0, COUNTER.0, 10u64)),
    );
    assert_eq!(done(smol::block_on(call)), 10);
    wait_until("every message applies once", || {
        value(&node, &programs, TARGET) == 16
    });
    wait_until("and is acknowledged", || {
        outbox_cleared(&node, SENDER, TARGET, 4)
    });
    assert_eq!(
        vos_checker::applied::<u64>(node.store(), TARGET, &keys::pair_in(SENDER)),
        Some(4)
    );
}

/// A message past the next of its pair is a gap: dropped before any batch,
/// so it costs no log entry, and not acknowledged. The sender's next
/// delivery fills it.
#[test]
fn a_gap_is_dropped_unacknowledged_until_it_fills() {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), &programs);
    let target = counter_agent(&node, &programs);
    // A sender with no batches of its own: an ack would be its first.
    let sender = node.create_agent().unwrap();
    wait_until("the sender leads", || {
        node.leads(sender) && results(&node, sender) == 0 && applied(&node, sender) >= 1
    });
    let leading = applied(&node, sender);
    let message = |sequence: u64, by: u64| Message {
        from: sender,
        sequence,
        body: Body::Call {
            instance: COUNTER,
            method: programs.method("increment"),
            arguments: by.encode(),
            awaiting: None,
        },
    };
    let before = applied(&node, target);
    node.deliver(target, message(2, 20)).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(applied(&node, target), before, "a gap reaches no batch");
    assert_eq!(value(&node, &programs, target), 0);
    assert_eq!(applied(&node, sender), leading, "a gap is not acknowledged");
    node.deliver(target, message(1, 1)).unwrap();
    node.deliver(target, message(2, 20)).unwrap();
    wait_until("both apply in order", || {
        value(&node, &programs, target) == 21
    });
    wait_until("and are acknowledged", || {
        vos_checker::applied::<u64>(node.store(), sender, &keys::acked(target)).is_some()
            || applied(&node, sender) > leading
    });
}

#[test]
fn a_node_is_its_public_key_and_never_serves_its_secret() {
    use std::os::unix::fs::PermissionsExt;
    use vos_node::store::Fjall;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    // A new data directory is the owner's alone.
    let data = dir.path().join("new");
    let id = Node::open(&data, Config::new(programs.agent.clone()))
        .unwrap()
        .id();
    assert_eq!(mode(&data), 0o700);
    // A node's directory others could reach is made the owner's alone
    // again.
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(Node::open(&data, Config::new(programs.agent.clone())).unwrap());
    assert_eq!(mode(&data), 0o700);
    // So is an empty directory others could reach. Any other is refused,
    // and left as it is.
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(Node::open(&empty, Config::new(programs.agent.clone())).unwrap());
    assert_eq!(mode(&empty), 0o700);
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::write(shared.join("notes"), b"someone else's").unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Node::open(&shared, Config::new(programs.agent.clone())).is_err());
    assert_eq!(mode(&shared), 0o755);
    let store = Fjall::open(data.join("store")).unwrap();
    let secret = store.node_secret().unwrap().expect("a secret seed");
    drop(store);
    assert_eq!(
        id.0,
        SigningKey::from_bytes(&secret).verifying_key().to_bytes()
    );
    assert_ne!(id.0, secret);
    // The same key on every open.
    let node = Node::open(&data, Config::new(programs.agent)).unwrap();
    assert_eq!(node.id(), id);
}
