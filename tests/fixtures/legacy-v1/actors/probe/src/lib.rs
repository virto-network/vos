//! Runtime-behaviour probe actor for VOS core regression tests.
//!
//! Each handler exercises one host-side invariant the `elf_integration`
//! suite pins:
//!
//! - [`ping`](Probe::ping) — increments `seen` and yields mid-handler,
//!   so a batch of several `ping`s must be delivered across ticks
//!   without dropping the un-fetched remainder.
//! - [`seen`](Probe::seen) — reads back the delivered count.
//! - [`boom`](Probe::boom) — asks a child (which journals a write via
//!   its cold-start hook), then traps; the host must discard the whole
//!   dispatch — the absorbed child write included — so a panicked
//!   handler commits nothing.

use vos::abi::service::ServiceId;
use vos::agent::{TaskStatus, Tasks};
use vos::prelude::*;
use vos::value::Value;

#[actor]
struct Probe {
    seen: u32,
}

#[messages]
impl Probe {
    fn new() -> Self {
        Probe { seen: 0 }
    }

    /// Count this message, then yield. A batch of `ping`s therefore
    /// consumes one message per tick: the host must re-queue the mail
    /// the guest had not yet FETCHed before it yielded.
    #[msg]
    async fn ping(&mut self, ctx: &mut Context<Self>) {
        self.seen += 1;
        ctx.yield_now().await;
    }

    /// Mutate before a durable cross-root await, then incorporate the exact
    /// accumulated peer reply after restart. Runtime v2 integration tests use
    /// this to prove the pre-await code executes once and the return value is
    /// injected into the original handler future rather than replaying PC 0.
    #[msg]
    async fn await_peer(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.seen += 1;
        if let Ok(vos::value::Value::U32(value)) = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), Some(100))
            .await
        {
            self.seen += value;
        }
        self.seen
    }

    /// Production-node transport probe. The older `await_peer` method pins a
    /// small absolute slot for deterministic harness tests; a real node uses
    /// its durable admission clock, so this route intentionally has no
    /// deadline.
    #[msg]
    async fn await_peer_without_deadline(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.seen += 1;
        if let Ok(vos::value::Value::U32(value)) = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), None)
            .await
        {
            self.seen += value;
        }
        self.seen
    }

    /// Node-driver timeout probe. The caller supplies a future trusted node
    /// slot so the transport can prove restart-discoverable expiration rather
    /// than relying on the fixed harness-only deadline above.
    #[msg]
    async fn await_peer_until(&mut self, ctx: &mut Context<Self>, deadline: u64) -> u32 {
        self.seen += 1;
        if let Ok(vos::value::Value::U32(value)) = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("peer_value"), Some(deadline))
            .await
        {
            self.seen += value;
        }
        self.seen
    }

    /// Deterministic cross-root peer used by the v2 durable transport gate.
    #[msg]
    async fn peer_value(&self) -> u32 {
        7
    }

    /// Two durable calls with mutations on both sides of the first resume.
    /// The v2 physical gate restarts the service before each continuation
    /// slice and proves await ordinals and causal authority survive exactly.
    #[msg]
    async fn await_two_peers(&mut self, ctx: &mut Context<Self>) -> u32 {
        self.seen += 1;
        if let Ok(vos::value::Value::U32(value)) = ctx
            .ask_actor(ActorId([44; 32]), &Msg::new("first_value"), Some(100))
            .await
        {
            self.seen += value;
        }
        self.seen += 10;
        if let Ok(vos::value::Value::U32(value)) = ctx
            .ask_actor(ActorId([45; 32]), &Msg::new("second_value"), Some(150))
            .await
        {
            self.seen += value;
        }
        self.seen
    }

    /// Number of `ping`s delivered so far.
    #[msg]
    async fn seen(&self) -> u32 {
        self.seen
    }

    /// Ask `child` (a leaker, whose cold-start hook journals a write into
    /// this dispatch), then trap. The absorbed child write must be
    /// discarded with the rest of the panicked dispatch — nothing commits.
    #[msg]
    async fn boom(&mut self, ctx: &mut Context<Self>, child: u32) {
        let _ = ctx.ask(ServiceId(child), &Msg::new("start")).await;
        panic!("boom: discard-on-panic regression");
    }

    /// Ask `child` and return normally — the baseline companion to
    /// `boom`. The child's absorbed write commits when this dispatch
    /// completes, proving the discard test isn't vacuous.
    #[msg]
    async fn relay(&mut self, ctx: &mut Context<Self>, child: u32) {
        let _ = ctx.ask(ServiceId(child), &Msg::new("start")).await;
    }

    /// Fire a fire-and-forget transfer at `target`. When `target` is not
    /// a service in this runtime it becomes an external transfer the node
    /// routes through its outbox — used to pin commit-then-outbox order.
    #[msg]
    async fn tell_out(&mut self, ctx: &mut Context<Self>, target: u32) {
        ctx.tell(ServiceId(target), &Msg::new("noop"));
    }

    /// Invoke `child` through a deliberately tiny output buffer and
    /// report the resulting status byte, so a test can tell an oversize
    /// reply (`STATUS_TOO_BIG`) from a crash (`STATUS_PANICKED`) or a
    /// reply that fits (`STATUS_DONE`). The small buffer drives the host's
    /// buffer-cap path regardless of the child's actual size.
    #[msg]
    async fn ask_small_buf(&mut self, _ctx: &mut Context<Self>, child: u32) -> u8 {
        let hash = vos::service_code_hash(child);
        let input = [0u8; 4]; // state_len = 0, no message
        let mut out = [0u8; 512];
        let n = vos::hostcalls::invoke(&hash, &input, 0, &mut out) as usize;
        if n >= 1 { out[0] } else { vos::STATUS_DONE }
    }

    /// Execute one signed, package-bound Task and require the invocation-local
    /// producer record to bind the exact Task reply before returning. The v2
    /// physical gate uses this row-free fixture to prove witnesses remain out
    /// of Raft while their sidecar survives a producer restart.
    #[msg]
    async fn run_provable_task(&mut self, task_hash: Vec<u8>, tag: Vec<u8>, n: u64) -> u64 {
        let task_hash: [u8; 32] = task_hash
            .try_into()
            .unwrap_or_else(|_| panic!("task hash must contain 32 bytes"));
        let tag: [u8; 32] = tag
            .try_into()
            .unwrap_or_else(|_| panic!("record tag must contain 32 bytes"));
        let mut tasks = Tasks::new();
        let task = tasks.spawn_provable(task_hash, &Msg::new("add_rooted").with("n", n), tag);
        tasks.drive();
        assert!(
            tasks.status(task) == Some(TaskStatus::Done),
            "signed Task did not complete"
        );
        let reply = tasks
            .reply(task)
            .unwrap_or_else(|| panic!("completed Task omitted its reply"));
        let record = vos::provable::read_record_entry(&tag)
            .and_then(|bytes| vos::provable::ProofRecordEntry::decode(&bytes))
            .unwrap_or_else(|| panic!("completed Task omitted its staged record"));
        assert!(
            record.input.task_hash == task_hash
                && record.record.task_hash == task_hash
                && record.record.reply == reply
                && record.record.io_consistent(),
            "producer record does not bind the exact Task execution"
        );
        match <Value as vos::Decode>::try_decode(reply) {
            Some(Value::U64(value)) => value,
            _ => panic!("Task returned a malformed total"),
        }
    }

    /// Queue without driving and stage the resulting secret-bearing table as
    /// an ordinary actor row. Refine must reject the complete slice before
    /// that row can enter actor state or a replicated transition.
    #[msg]
    async fn defer_provable_task(
        &mut self,
        ctx: &mut Context<Self>,
        task_hash: Vec<u8>,
        tag: Vec<u8>,
    ) {
        let task_hash: [u8; 32] = task_hash
            .try_into()
            .unwrap_or_else(|_| panic!("task hash must contain 32 bytes"));
        let tag: [u8; 32] = tag
            .try_into()
            .unwrap_or_else(|_| panic!("record tag must contain 32 bytes"));
        let mut tasks = Tasks::new();
        let _ = tasks.spawn_provable(task_hash, &Msg::new("add_rooted").with("n", 1u64), tag);
        ctx.store(b"deferred-private-task", &tasks.encode());
    }
}
