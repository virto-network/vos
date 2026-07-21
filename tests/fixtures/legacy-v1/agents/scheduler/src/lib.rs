//! Scheduler agent — orchestrator driving children through
//! `vos::agent::Tasks`.
//!
//! Peers (registered actors discovered from init args or installed at
//! runtime) and anonymous code-hash Tasks share one table: spawn queues
//! a record, `tick` drives every runnable record once, and yielded
//! children stay in the table as data — their state rides inside this
//! agent's own committed state.
//!
//! On start, sends a dynamic `start` message to each configured child.
//! Actors without a `start` handler silently skip it. Children that
//! yield are re-driven in subsequent tick rounds; finished and failed
//! records stay inspectable through the probe handlers.

use vos::agent::{Child, Tasks};
use vos::prelude::*;

#[actor]
struct Agent {
    round: u32,
    tasks: Tasks,
    children: Vec<u32>,
}

#[messages]
impl Agent {
    fn new(children: Vec<u32>) -> Self {
        log::info!("agent: init");
        Agent {
            round: 0,
            tasks: Tasks::new(),
            children,
        }
    }

    /// Register a new peer actor at runtime and drive it immediately.
    #[msg]
    async fn install(&mut self, actor_id: u32, ctx: &mut Context<Self>) {
        self.children.push(actor_id);
        log::info!("agent: installed actor {}", actor_id);
        self.tasks.spawn(Child::Peer(actor_id), &Msg::new("start"));
        self.drive_round(ctx);
    }

    /// Spawn an anonymous code-hash Task with a pre-encoded message
    /// and drive it. Returns the task id for the probe handlers.
    #[msg]
    async fn run_task(
        &mut self,
        code_hash: [u8; 32],
        task_msg: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> u64 {
        let id = self.tasks.spawn_raw(Child::Task(code_hash), task_msg);
        self.drive_round(ctx);
        id
    }

    /// Like `run_task`, additionally naming the storage row keys the
    /// task's witnessed reads need — the host stages those rows from
    /// THIS agent's keyspace into the child's witness buffer.
    /// `row_keys` is an rkyv-encoded `Vec<Vec<u8>>` (the dynamic value
    /// vocabulary has no list-of-bytes).
    #[msg]
    async fn run_task_rows(
        &mut self,
        code_hash: [u8; 32],
        task_msg: Vec<u8>,
        row_keys: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> u64 {
        let keys: Vec<Vec<u8>> =
            vos::rkyv::from_bytes::<Vec<Vec<u8>>, vos::rkyv::rancor::Error>(&row_keys)
                .unwrap_or_default();
        let id = self
            .tasks
            .spawn_raw_with_rows(Child::Task(code_hash), task_msg, keys);
        self.drive_round(ctx);
        id
    }

    /// Drive all configured peers with a dynamic `start` message.
    /// Actors without a `start` handler silently skip it.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        for &child_id in &self.children {
            self.tasks.spawn(Child::Peer(child_id), &Msg::new("start"));
        }
        self.drive_round(ctx);
    }

    /// Re-drive yielded children.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        self.round += 1;
        self.drive_round(ctx);
    }

    fn drive_round(&mut self, ctx: &mut vos::Context<Self>) {
        if self.tasks.drive() > 0 {
            ctx.tell(ctx.id(), &Msg::new("tick"));
        }
    }

    /// Probe — current round counter. Useful for tests that
    /// observe the scheduler's tick activity from outside the
    /// actor (e.g. CRDT-replication tests verifying that
    /// state transitions on one replica reach a peer).
    #[msg]
    async fn get_round(&self) -> u32 {
        self.round
    }

    /// Probe — registered children. Returns the current
    /// `children` list as it stands after any `install` calls.
    #[msg]
    async fn get_children(&self) -> Vec<u32> {
        self.children.clone()
    }

    /// Probe — a task's status discriminant
    /// ([`vos::agent::TaskStatus`]), or 0xFF for an unknown id.
    #[msg]
    async fn task_status(&self, id: u64) -> u32 {
        self.tasks.status(id).map(|s| s as u32).unwrap_or(0xFF)
    }

    /// Probe — a task's most recent reply bytes.
    #[msg]
    async fn task_reply(&self, id: u64) -> Vec<u8> {
        self.tasks.reply(id).map(|r| r.to_vec()).unwrap_or_default()
    }

    /// Probe — a task's saved state (its TaskRecord state as of the
    /// last work-result). The live≡traced gate compares a traced
    /// re-execution's emitted state against exactly these bytes.
    #[msg]
    async fn task_state(&self, id: u64) -> Vec<u8> {
        self.tasks
            .get(id)
            .map(|r| r.state.clone())
            .unwrap_or_default()
    }
}
