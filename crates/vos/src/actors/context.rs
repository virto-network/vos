use super::Actor;
use alloc::vec::Vec;

/// Execution context passed to message handlers.
///
/// Queues effects (transfers, storage writes, spawns) during handler
/// execution. Effects are flushed after each handler via hostcalls.
///
/// Also provides cooperative async primitives:
/// - `tell()` — fire-and-forget message (queues a transfer)
/// - `ask()` — synchronous query (suspends until result available)
/// - `yield_now()` — checkpoint state and yield to other actors
/// - `sleep(n)` — checkpoint state and sleep for N ticks
pub struct Context<A: Actor> {
    id: ServiceId,
    stop_requested: bool,

    // Effect queues (flushed in accumulate)
    pending_tells: Vec<PendingTell>,
    pending_writes: Vec<(Vec<u8>, Vec<u8>)>,
    pending_spawns: Vec<[u8; 32]>,

    // Cooperative execution state
    call_index: usize,
    call_results: Vec<Vec<u8>>,
    pending_ask: Option<PendingAsk>,
    self_schedule: bool,
    sleep_ticks: u32,

    // Durable functions replay state
    yield_replay_index: u32,
    replay_until: u32,
    continue_as_new: bool,

    _phantom: core::marker::PhantomData<A>,
}

pub use vos_abi::service::ServiceId;

/// A queued transfer to another service (fire-and-forget).
#[allow(dead_code)] // Fields read in cfg(pvm) path
struct PendingTell {
    target: ServiceId,
    payload: Vec<u8>,
}

/// A pending synchronous query awaiting execution.
pub struct PendingAsk {
    pub target: ServiceId,
    pub payload: Vec<u8>,
}

impl<A: Actor> Context<A> {
    pub fn new(id: ServiceId) -> Self {
        Self {
            id,
            stop_requested: false,
            pending_tells: Vec::new(),
            pending_writes: Vec::new(),
            pending_spawns: Vec::new(),
            call_index: 0,
            call_results: Vec::new(),
            pending_ask: None,
            self_schedule: false,
            sleep_ticks: 0,
            yield_replay_index: 0,
            replay_until: 0,
            continue_as_new: false,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Create a context with cached call results from a previous invocation (replay).
    pub fn with_call_results(id: ServiceId, call_results: Vec<Vec<u8>>) -> Self {
        Self {
            call_results,
            ..Self::new(id)
        }
    }

    /// Get this actor's service ID.
    pub fn id(&self) -> ServiceId {
        self.id
    }

    // --- Fire-and-forget messaging ---

    /// Send a message to another service (fire-and-forget). The payload is
    /// provided as a preimage and a transfer with the hash is queued.
    ///
    /// This is the renamed version of the old `send()`.
    pub fn tell(&mut self, target: ServiceId, payload: &[u8]) {
        if self.replaying() { return; }
        self.pending_tells.push(PendingTell {
            target,
            payload: payload.to_vec(),
        });
    }

    // --- Synchronous query ---

    /// Synchronous query to another actor. Suspends until result available.
    ///
    /// On first call (no cached result), sets `pending_ask` and returns `None`.
    /// On replay (cached result available), returns `Some(result)`.
    pub fn ask(&mut self, target: ServiceId, payload: &[u8]) -> Option<Vec<u8>> {
        if self.call_index < self.call_results.len() {
            let result = self.call_results[self.call_index].clone();
            self.call_index += 1;
            Some(result)
        } else {
            self.pending_ask = Some(PendingAsk {
                target,
                payload: payload.to_vec(),
            });
            self.call_index += 1;
            None
        }
    }

    // --- Cooperative scheduling ---

    /// Checkpoint state and yield to other actors. Resumes next tick.
    /// Returns a future — during replay, completed yields return instantly.
    pub fn yield_now(&mut self) -> super::run::Yield {
        self.self_schedule = true;
        let idx = self.yield_replay_index;
        self.yield_replay_index += 1;
        if idx < self.replay_until {
            super::run::Yield::skip()
        } else {
            super::run::Yield::once()
        }
    }

    /// Checkpoint state and sleep for N ticks.
    /// Returns a future — during replay, completed yields return instantly.
    pub fn sleep(&mut self, ticks: u32) -> super::run::Yield {
        self.self_schedule = true;
        self.sleep_ticks = ticks;
        let idx = self.yield_replay_index;
        self.yield_replay_index += 1;
        if idx < self.replay_until {
            super::run::Yield::skip()
        } else {
            super::run::Yield::once()
        }
    }

    /// Reset actor state and restart the handler from scratch.
    /// Use this to bound replay cost in long-running loops.
    pub fn continue_as_new(&mut self) {
        self.continue_as_new = true;
    }

    /// Whether continue_as_new was requested.
    pub fn should_continue_as_new(&self) -> bool {
        self.continue_as_new
    }

    /// Whether we're in replay phase (fast-forwarding past completed yields).
    /// True when there are still yield points to skip. Once yield_replay_index
    /// reaches replay_until, we're in the live phase.
    pub fn replaying(&self) -> bool {
        self.yield_replay_index < self.replay_until
    }

    /// Set the yield index to replay up to.
    pub fn set_replay_until(&mut self, n: u32) {
        self.replay_until = n;
    }

    /// Get the current yield replay index (how many yields we've passed).
    pub fn yield_index(&self) -> u32 {
        self.yield_replay_index
    }

    /// Reset yield replay state for re-dispatch (e.g. after ask resolution).
    pub fn reset_yield_state(&mut self) {
        self.yield_replay_index = 0;
        self.self_schedule = false;
        self.sleep_ticks = 0;
    }

    // --- Storage ---

    /// Queue a key-value write to per-service storage.
    pub fn store(&mut self, key: &[u8], value: &[u8]) {
        if self.replaying() { return; }
        self.pending_writes.push((key.to_vec(), value.to_vec()));
    }

    /// Queue a new service spawn from a code hash.
    pub fn spawn(&mut self, code_hash: [u8; 32]) {
        if self.replaying() { return; }
        self.pending_spawns.push(code_hash);
    }

    /// Request the actor to stop after the current message.
    pub fn stop(&mut self) {
        self.stop_requested = true;
    }

    /// Check if a stop has been requested.
    pub fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    /// Check if a yield_now or sleep was requested.
    pub fn self_scheduled(&self) -> bool {
        self.self_schedule
    }

    /// Get the number of ticks to sleep (0 = yield_now).
    pub fn sleep_ticks(&self) -> u32 {
        self.sleep_ticks
    }

    /// Take the pending ask request, if any.
    pub fn take_pending_ask(&mut self) -> Option<PendingAsk> {
        self.pending_ask.take()
    }

    /// Get the current call index (how far we've replayed).
    pub fn call_index(&self) -> usize {
        self.call_index
    }

    /// Get a reference to the cached call results.
    pub fn call_results(&self) -> &[Vec<u8>] {
        &self.call_results
    }

    /// Push a new call result (from a resolved ask) and reset for replay.
    ///
    /// After resolving an ask via invoke(), the framework pushes the result
    /// and resets the call_index so the handler can be replayed from the start.
    pub fn push_call_result_and_reset(&mut self, result: Vec<u8>) {
        self.call_results.push(result);
        self.call_index = 0;
        self.pending_ask = None;
        self.self_schedule = false;
        self.sleep_ticks = 0;
        self.yield_replay_index = 0;
    }

    /// Flush all queued effects via accumulate-phase hostcalls.
    ///
    /// Requires the `service` feature — only service actors (not refine-only
    /// guest actors) can flush effects to the host.
    pub fn flush_effects(&mut self) {
        #[cfg(feature = "service")]
        {
            use vos_abi::pvm::hostcalls;

            for (key, value) in self.pending_writes.drain(..) {
                hostcalls::write(&key, &value);
            }

            for tell in self.pending_tells.drain(..) {
                let hash = [0u8; 32];
                hostcalls::provide(&hash, &tell.payload);
                hostcalls::transfer(tell.target, 0, 0, &tell.payload);
            }

            for code_hash in self.pending_spawns.drain(..) {
                hostcalls::new_service(&code_hash);
            }
        }

        #[cfg(not(feature = "service"))]
        {
            self.pending_writes.clear();
            self.pending_tells.clear();
            self.pending_spawns.clear();
        }
    }
}
