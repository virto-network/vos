//! VOS Agent — generic orchestrator that drives guest actors via invoke().
//!
//! Runs as a full JAM service (refine+accumulate). Discovers registered actors
//! from init args (written to storage by the host), and accepts runtime
//! `install` messages to register new actors dynamically.
//!
//! On start, sends a dynamic `run` message to each child. Actors without
//! a `run` handler silently skip it. Actors that yield get re-invoked in
//! subsequent tick rounds.

use vos::actors::context::ServiceId;
use vos::value::{Msg, TAG_DYNAMIC};
use vos::{actor, messages, lifecycle, Encode, STATUS_YIELDED};

const MAX_ROUNDS: u32 = 64;

/// Build the wire bytes for a dynamic message: [TAG_DYNAMIC][rkyv-encoded Msg].
fn dynamic_msg(msg: &Msg) -> Vec<u8> {
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

#[actor]
struct Agent {
    round: u32,
    /// (service_id, message, actor_state)
    run_queue: Vec<(u32, Vec<u8>, Vec<u8>)>,
    children: Vec<u32>,
}

#[messages]
impl Agent {
    fn new(children: Vec<u32>) -> Self {
        println!("agent: init");

        // Self-schedule Start
        let self_id = lifecycle::service_id();
        vos::hostcalls::transfer(ServiceId(self_id), 0, 0, &AgentMsg::Start(Start).to_bytes());

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
        println!("agent: installed actor {}", actor_id);

        let run_msg = dynamic_msg(&Msg::new("run"));
        let r = lifecycle::invoke(actor_id, &run_msg, &[]);
        if r.status == STATUS_YIELDED {
            self.run_queue.push((actor_id, run_msg, r.state));
            self.maybe_schedule_tick(ctx);
        }
    }

    /// Invoke all registered actors with a dynamic `run` message.
    /// Actors without a `run` handler silently skip it.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        let run_msg = dynamic_msg(&Msg::new("run"));
        for &child_id in &self.children.clone() {
            let r = lifecycle::invoke(child_id, &run_msg, &[]);
            if r.status == STATUS_YIELDED {
                self.run_queue.push((child_id, run_msg.clone(), r.state));
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
            let r = lifecycle::invoke(svc_id, &msg, &prev_state);
            if r.status == STATUS_YIELDED {
                self.run_queue.push((svc_id, msg, r.state));
            }
        }

        self.maybe_schedule_tick(ctx);
    }

    fn maybe_schedule_tick(&self, ctx: &mut vos::Context<Self>) {
        if !self.run_queue.is_empty() && self.round < MAX_ROUNDS {
            ctx.send_self(&AgentMsg::Tick(Tick));
        }
    }
}
