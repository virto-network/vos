//! VOS Agent — generic orchestrator that drives guest actors via invoke().
//!
//! Runs as a full JAM service (refine+accumulate). Discovers registered actors
//! from init args (written to storage by the host), and accepts runtime
//! `install` messages to register new actors dynamically.

use vos::actors::context::ServiceId;
use vos::{actor, messages, lifecycle, STATUS_YIELDED};

const MAX_ROUNDS: u32 = 64;

#[actor]
struct Agent {
    round: u32,
    /// (service_id, message, actor_state, yield_index)
    run_queue: Vec<(u32, Vec<u8>, Vec<u8>, u32)>,
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

        let run_msg: Vec<u8> = vec![0];
        let r = lifecycle::invoke(actor_id, &run_msg, &[], 0);
        if r.status == STATUS_YIELDED {
            self.run_queue.push((actor_id, run_msg, r.state, r.yield_index));
            self.maybe_schedule_tick(ctx);
        }
    }

    /// Invoke all registered actors with an initial Run message.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        let run_msg: Vec<u8> = vec![0]; // variant 0 = Run
        for &child_id in &self.children.clone() {
            let r = lifecycle::invoke(child_id, &run_msg, &[], 0);
            if r.status == STATUS_YIELDED {
                self.run_queue.push((child_id, run_msg.clone(), r.state, r.yield_index));
            }
        }
        self.maybe_schedule_tick(ctx);
    }

    /// Re-invoke yielded children.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        self.round += 1;

        let queue: Vec<_> = self.run_queue.drain(..).collect();
        for (svc_id, msg, prev_state, prev_yi) in queue {
            let r = lifecycle::invoke(svc_id, &msg, &prev_state, prev_yi);
            if r.status == STATUS_YIELDED {
                self.run_queue.push((svc_id, msg, r.state, r.yield_index));
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
