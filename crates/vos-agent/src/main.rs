//! VOS Agent — generic orchestrator that drives guest actors via invoke().
//!
//! Runs as a full JAM service (refine+accumulate). Discovers registered actors
//! from storage on init, and accepts runtime `install` messages to register
//! new actors dynamically.
//!
//! ## Bootstrap
//!
//! vosx writes actor IDs to the agent's storage key `__actors` before running:
//! `[id_1:u32 LE][id_2:u32 LE]...`
//!
//! The agent reads this on construction and self-schedules `start`.
//!
//! ## Runtime registration
//!
//! Other services can send `install(actor_id: u32)` messages to register
//! actors at runtime. Installed actors are immediately invoked.
//!
//! ## Invoke protocol (per child)
//!
//! Input:  `[yield_index:u32][state_len:u32][state][message]`
//! Output: `[status:u8][yield_index:u32][state_len:u32][state]`

use vos::actors::context::ServiceId;
use vos::{actor, messages, service_code_hash, STATUS_YIELDED};

const HEADER_SIZE: usize = 8;
const MAX_ROUNDS: u32 = 64;
const ACTORS_KEY: &[u8] = b"__actors";

#[actor]
struct Agent {
    round: u32,
    /// (service_id, message, actor_state, yield_index)
    run_queue: Vec<(u32, Vec<u8>, Vec<u8>, u32)>,
    children: Vec<u32>,
}

#[messages]
impl Agent {
    fn new() -> Self {
        // Read registered actor IDs from storage (written by vosx at bootstrap)
        let mut buf = [0u8; 512];
        let n = vos::hostcalls::read(ACTORS_KEY, &mut buf) as usize;
        let mut children = Vec::new();
        if n <= 512 {
            let mut off = 0;
            while off + 4 <= n {
                children.push(u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]));
                off += 4;
            }
        }

        println!("agent: init");

        // Self-schedule Start
        let self_id = vos::hostcalls::info() as u32;
        let bytes = AgentMsg::Start(Start).to_bytes();
        vos::hostcalls::transfer(ServiceId(self_id), 0, 0, &bytes);

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
        let (status, state, yi) = Self::invoke_child(actor_id, &run_msg, &[], 0);
        if status == STATUS_YIELDED {
            self.run_queue.push((actor_id, run_msg, state, yi));
            self.maybe_schedule_tick(ctx);
        }
    }

    /// Invoke all registered actors with an initial Run message.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        let run_msg: Vec<u8> = vec![0]; // variant 0 = Run
        for &child_id in &self.children.clone() {
            let (status, state, yi) = Self::invoke_child(child_id, &run_msg, &[], 0);
            if status == STATUS_YIELDED {
                self.run_queue.push((child_id, run_msg.clone(), state, yi));
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
            let (status, state, yi) = Self::invoke_child(svc_id, &msg, &prev_state, prev_yi);
            if status == STATUS_YIELDED {
                self.run_queue.push((svc_id, msg, state, yi));
            }
        }

        self.maybe_schedule_tick(ctx);
    }

    /// Invoke a guest actor with the refine protocol.
    fn invoke_child(svc_id: u32, message: &[u8], state: &[u8], yield_index: u32) -> (u8, Vec<u8>, u32) {
        let total = HEADER_SIZE + state.len() + message.len();
        let mut input = vec![0u8; total];
        input[0..4].copy_from_slice(&yield_index.to_le_bytes());
        input[4..8].copy_from_slice(&(state.len() as u32).to_le_bytes());
        input[8..8 + state.len()].copy_from_slice(state);
        input[8 + state.len()..].copy_from_slice(message);

        let hash = service_code_hash(svc_id);
        let mut output = [0u8; 4096];
        let n = vos::hostcalls::invoke(&hash, &input, 0, &mut output) as usize;

        if n < 9 {
            return (0, Vec::new(), 0);
        }

        let status = output[0];
        let new_yi = u32::from_le_bytes([output[1], output[2], output[3], output[4]]);
        let state_len = u32::from_le_bytes([output[5], output[6], output[7], output[8]]) as usize;
        let new_state = if state_len > 0 && 9 + state_len <= n {
            output[9..9 + state_len].to_vec()
        } else {
            Vec::new()
        };

        (status, new_state, new_yi)
    }

    fn maybe_schedule_tick(&self, ctx: &mut vos::Context<Self>) {
        if !self.run_queue.is_empty() && self.round < MAX_ROUNDS {
            let bytes = AgentMsg::Tick(Tick).to_bytes();
            ctx.tell(ctx.id(), &bytes);
        }
    }
}
