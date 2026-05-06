//! Scheduler agent — orchestrator that drives guest actors via invoke().
//!
//! Runs as a full JAM service (refine+accumulate). Discovers registered actors
//! from init args (written to storage by the host), and accepts runtime
//! `install` messages to register new actors dynamically.
//!
//! On start, sends a dynamic `start` message to each child. Actors without
//! a `start` handler silently skip it. Actors that yield get re-invoked in
//! subsequent tick rounds.

use vos::lifecycle::InvokeResult;
use vos::prelude::*;
/// No artificial cap — the runtime's per-tick iteration limit + gas
/// budget provide the safety ceiling. Across ticks, continuations
/// let the scheduler run indefinitely.
const MAX_ROUNDS: u32 = u32::MAX;

/// Invoke a child and handle the result. Returns Some(state) if yielded.
fn invoke_child(svc_id: u32, msg: &Msg, state: &[u8]) -> Option<Vec<u8>> {
    match lifecycle::invoke(svc_id, msg, state) {
        InvokeResult::Yielded { state, .. } => Some(state),
        InvokeResult::Done { .. } => {
            log::info!("agent: child {} completed", svc_id);
            None
        }
        InvokeResult::Panicked => {
            log::info!("agent: child {} panicked, dropping", svc_id);
            None
        }
        InvokeResult::NotFound => {
            log::info!("agent: child {} not found, dropping", svc_id);
            None
        }
        InvokeResult::OutOfGas => {
            log::info!("agent: child {} out of gas, dropping", svc_id);
            None
        }
        InvokeResult::Error(s) => {
            log::info!("agent: child {} error (0x{:02x}), dropping", svc_id, s);
            None
        }
    }
}

#[actor]
struct Agent {
    round: u32,
    /// (service_id, message, actor_state)
    run_queue: Vec<(u32, Msg, Vec<u8>)>,
    children: Vec<u32>,
}

#[messages]
impl Agent {
    fn new(children: Vec<u32>) -> Self {
        log::info!("agent: init");

        // The host kicks us with a dynamic `start` message — no need to
        // self-schedule from the constructor (refine forbids raw
        // TRANSFER hostcalls).

        Agent {
            round: 0,
            run_queue: Vec::new(),
            children,
        }
    }

    /// Register a new actor at runtime and invoke it immediately.
    #[msg]
    async fn install(&mut self, actor_id: u32, ctx: &mut Context<Self>) {
        self.children.push(actor_id);
        log::info!("agent: installed actor {}", actor_id);

        let start_msg = Msg::new("start");
        if let Some(state) = invoke_child(actor_id, &start_msg, &[]) {
            self.run_queue.push((actor_id, start_msg, state));
            self.maybe_schedule_tick(ctx);
        }
    }

    /// Invoke all registered actors with a dynamic `start` message.
    /// Actors without a `start` handler silently skip it.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        let start_msg = Msg::new("start");
        for &child_id in &self.children.clone() {
            if let Some(state) = invoke_child(child_id, &start_msg, &[]) {
                self.run_queue.push((child_id, start_msg.clone(), state));
            }
        }
        self.maybe_schedule_tick(ctx);
    }

    /// Re-invoke yielded children.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        self.round += 1;

        let queue: Vec<_> = self.run_queue.drain(..).collect();
        for (svc_id, msg, prev_state) in queue {
            if let Some(state) = invoke_child(svc_id, &msg, &prev_state) {
                self.run_queue.push((svc_id, msg, state));
            }
        }

        self.maybe_schedule_tick(ctx);
    }

    fn maybe_schedule_tick(&self, ctx: &mut vos::Context<Self>) {
        if !self.run_queue.is_empty() && self.round < MAX_ROUNDS {
            ctx.tell(ctx.id(), &Msg::new("tick"));
        }
    }
}

