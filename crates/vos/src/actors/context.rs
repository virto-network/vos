use super::Actor;
use alloc::vec::Vec;

/// Execution context passed to message handlers.
///
/// Queues effects (transfers, storage writes, spawns) during handler
/// execution. Effects are flushed after each handler via hostcalls.
///
/// Also provides cooperative async primitives:
/// - `tell()` — fire-and-forget dynamic message
/// - `ask()` — query another actor, suspends until reply (returns `Value`)
/// - `yield_now()` — checkpoint state and yield to other actors
/// - `sleep(n)` — checkpoint state and sleep for N ticks
pub struct Context<A: Actor> {
    id: ServiceId,
    stop_requested: bool,

    // Effect queues (flushed in accumulate)
    pending_tells: Vec<PendingTell>,
    pending_writes: Vec<(Vec<u8>, Vec<u8>)>,
    pending_spawns: Vec<[u8; 32]>,

    // Ask resolution state
    call_index: usize,
    call_results: Vec<Result<Vec<u8>, super::value::InvokeError>>,
    pending_ask: Option<PendingAsk>,
    re_dispatching: bool,

    // Reply data (rkyv-encoded Value, included in refine output)
    reply: Option<Vec<u8>>,

    // Cooperative scheduling
    self_schedule: bool,
    sleep_ticks: u32,

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
            re_dispatching: false,
            reply: None,
            self_schedule: false,
            sleep_ticks: 0,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Create a context with cached call results from a previous invocation (replay).
    pub fn with_call_results(id: ServiceId, call_results: Vec<Result<Vec<u8>, super::value::InvokeError>>) -> Self {
        Self {
            call_results,
            ..Self::new(id)
        }
    }

    /// Get this actor's service ID.
    pub fn id(&self) -> ServiceId {
        self.id
    }

    // --- Storage ---

    /// Read and decode a typed value from per-service storage.
    #[cfg(feature = "service")]
    pub fn load<T: super::codec::Decode>(&self, key: &[u8]) -> Option<T> {
        super::lifecycle::load::<T>(key)
    }

    // --- Fire-and-forget messaging ---

    /// Send raw bytes to another service (fire-and-forget).
    /// Prefer `tell()` for cross-actor dynamic messaging.
    pub fn tell_raw(&mut self, target: ServiceId, payload: &[u8]) {
        if self.re_dispatching { return; }
        self.pending_tells.push(PendingTell {
            target,
            payload: payload.to_vec(),
        });
    }

    /// Send a typed message to another service (auto-encodes).
    pub fn send<M: super::codec::Encode>(&mut self, target: ServiceId, msg: &M) {
        self.tell_raw(target, &msg.encode());
    }

    /// Send a typed message to self (auto-encodes, self-targets).
    pub fn send_self<M: super::codec::Encode>(&mut self, msg: &M) {
        let id = self.id;
        self.tell_raw(id, &msg.encode());
    }

    /// Send a dynamic message to another actor (fire-and-forget).
    ///
    /// The message is encoded with a tag byte so the receiver's `dispatch_one`
    /// decodes it as a `Msg` and converts via `FromDynamic`.
    pub fn tell(&mut self, target: ServiceId, msg: &super::value::Msg) {
        let encoded = super::codec::Encode::encode(msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(super::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.tell_raw(target, &payload);
    }

    // --- Query (ask) ---

    /// Query another actor with a dynamic message. Suspends until reply.
    ///
    /// Returns an `Ask` future — `.await` it to get the reply as a `Value`.
    /// The message is encoded with a tag byte for dynamic dispatch.
    pub fn ask(&mut self, target: ServiceId, msg: &super::value::Msg) -> super::run::Ask {
        let encoded = super::codec::Encode::encode(msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(super::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.ask_raw(target, &payload)
    }

    /// Raw query — takes pre-encoded payload bytes.
    /// Used internally by the framework. Prefer `ask()` for cross-actor queries.
    pub fn ask_raw(&mut self, target: ServiceId, payload: &[u8]) -> super::run::Ask {
        if self.call_index < self.call_results.len() {
            let result = self.call_results[self.call_index].clone();
            self.call_index += 1;
            // Last cached result consumed — we're live again
            if self.call_index >= self.call_results.len() {
                self.re_dispatching = false;
                #[cfg(feature = "pvm")]
                super::run::set_suppressing_io(false);
            }
            match result {
                Ok(bytes) => super::run::Ask::ready(bytes),
                Err(e) => super::run::Ask::ready_err(e),
            }
        } else {
            self.pending_ask = Some(PendingAsk {
                target,
                payload: payload.to_vec(),
            });
            self.call_index += 1;
            super::run::Ask::pending()
        }
    }

    // --- Cooperative scheduling ---

    /// Checkpoint state and yield to other actors. Resumes next tick.
    /// Each invocation runs one iteration; state is saved automatically.
    pub fn yield_now(&mut self) -> super::run::Yield {
        self.self_schedule = true;
        if self.re_dispatching {
            super::run::Yield::skip()
        } else {
            super::run::Yield::once()
        }
    }

    /// Checkpoint state and sleep for N ticks.
    /// Each invocation runs one iteration; state is saved automatically.
    pub fn sleep(&mut self, ticks: u32) -> super::run::Yield {
        self.self_schedule = true;
        self.sleep_ticks = ticks;
        if self.re_dispatching {
            super::run::Yield::skip()
        } else {
            super::run::Yield::once()
        }
    }

    // --- Storage ---

    /// Queue a key-value write to per-service storage.
    pub fn store(&mut self, key: &[u8], value: &[u8]) {
        if self.re_dispatching { return; }
        self.pending_writes.push((key.to_vec(), value.to_vec()));
    }

    /// Queue a new service spawn from a code hash.
    pub fn spawn(&mut self, code_hash: [u8; 32]) {
        if self.re_dispatching { return; }
        self.pending_spawns.push(code_hash);
    }

    /// Request the actor to stop after the current message.
    pub fn stop(&mut self) {
        self.stop_requested = true;
    }

    // --- Reply (framework-internal) ---

    /// Set the reply value for the current invocation.
    /// Called by macro-generated code after the handler returns.
    /// The value is rkyv-encoded and included in the refine output.
    #[doc(hidden)]
    pub fn __set_reply(&mut self, value: super::value::Value) {
        if self.re_dispatching { return; }
        // Don't store Unit replies — they carry no information
        if matches!(value, super::value::Value::Unit) { return; }
        self.reply = Some(super::codec::Encode::encode(&value));
    }

    /// Take the reply as raw bytes (rkyv-encoded Value).
    /// Used by `run_refine` to pack the output.
    pub fn take_reply_bytes(&mut self) -> Vec<u8> {
        self.reply.take().unwrap_or_default()
    }

    // --- Introspection ---

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
    pub fn call_results(&self) -> &[Result<Vec<u8>, super::value::InvokeError>] {
        &self.call_results
    }

    /// Push a successful call result and reset for replay.
    pub fn push_call_result_ok(&mut self, result: Vec<u8>) {
        self.push_call_result_inner(Ok(result));
    }

    /// Push a failed call result and reset for replay.
    pub fn push_call_result_err(&mut self, err: super::value::InvokeError) {
        self.push_call_result_inner(Err(err));
    }

    fn push_call_result_inner(&mut self, result: Result<Vec<u8>, super::value::InvokeError>) {
        self.call_results.push(result);
        self.call_index = 0;
        self.pending_ask = None;
        self.re_dispatching = true;
        self.self_schedule = false;
        self.sleep_ticks = 0;
        #[cfg(feature = "pvm")]
        super::run::set_suppressing_io(true);
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
