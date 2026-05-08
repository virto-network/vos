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
/// - `yield_now()` — commit state and yield to other actors
/// - `sleep(n)` — commit state and sleep for N ticks
pub struct Context<A: Actor> {
    id: ServiceId,
    stop_requested: bool,

    // Effect queues (flushed in accumulate)
    pending_tells: Vec<PendingTell>,
    pending_writes: Vec<(Vec<u8>, Vec<u8>)>,
    pending_spawns: Vec<[u8; 32]>,
    pending_provides: Vec<([u8; 32], Vec<u8>)>,

    // Reply data (rkyv-encoded Value, included in refine output)
    reply: Option<Vec<u8>>,

    // Cooperative scheduling
    self_schedule: bool,
    sleep_ticks: u32,

    // Worker host I/O: the handler yields with a request, the host
    // fulfills it and provides the result before re-polling.
    host_io_request: Option<Vec<u8>>,
    host_io_result: Option<Vec<u8>>,

    _phantom: core::marker::PhantomData<A>,
}

pub use crate::abi::service::ServiceId;

/// A queued transfer to another service (fire-and-forget).
#[allow(dead_code)] // Fields read in cfg(pvm) path
struct PendingTell {
    target: ServiceId,
    payload: Vec<u8>,
}

impl<A: Actor> Context<A> {
    pub fn new(id: ServiceId) -> Self {
        Self {
            id,
            stop_requested: false,
            pending_tells: Vec::new(),
            pending_writes: Vec::new(),
            pending_spawns: Vec::new(),
            pending_provides: Vec::new(),
            reply: None,
            self_schedule: false,
            sleep_ticks: 0,
            host_io_request: None,
            host_io_result: None,
            _phantom: core::marker::PhantomData,
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
    ///
    /// On guest builds (`pvm`) this issues an `INVOKE` hostcall
    /// synchronously: the host runs the child to completion and writes
    /// the reply into our buffer before returning. The returned `Ask`
    /// is `Ready` from the first poll. No replay, no snapshots, no
    /// pending state — the parent PVM is suspended at the ecall by the
    /// host loop and resumes here with the reply already in hand.
    ///
    /// On non-guest builds (host tests, etc.) this returns
    /// `InvokeError::NotFound` since there is no PVM to dispatch into.
    pub fn ask_raw(&mut self, target: ServiceId, payload: &[u8]) -> super::run::Ask {
        #[cfg(feature = "pvm")]
        {
            use super::lifecycle::{invoke_raw, InvokeResult};
            use super::value::InvokeError;
            match invoke_raw(target.0, payload, &[]) {
                InvokeResult::Done { reply, .. } | InvokeResult::Yielded { reply, .. } => {
                    super::run::Ask::ready(reply)
                }
                InvokeResult::Panicked => super::run::Ask::ready_err(InvokeError::Panicked),
                InvokeResult::NotFound => super::run::Ask::ready_err(InvokeError::NotFound),
                InvokeResult::OutOfGas => super::run::Ask::ready_err(InvokeError::OutOfGas),
                InvokeResult::Error(s) => super::run::Ask::ready_err(InvokeError::Unknown(s)),
            }
        }
        #[cfg(not(feature = "pvm"))]
        {
            // Worker / WASM: yield to host with an EFFECT_ASK request.
            // Wire format: [tag:u8=EFFECT_ASK][target:u32 LE][payload...]
            let mut request = Vec::with_capacity(5 + payload.len());
            request.push(crate::effects::EFFECT_ASK);
            request.extend_from_slice(&target.0.to_le_bytes());
            request.extend_from_slice(payload);
            super::run::Ask::host_io(self.host_call(request))
        }
    }

    /// Resolve an installed agent's name to its node-local
    /// `ServiceId` (packed as u32) by asking the well-known
    /// `ServiceId::REGISTRY` service. Returns 0 when no agent
    /// with that name is installed.
    ///
    /// Thin convenience over `ctx.ask(REGISTRY, Msg::new("resolve")…)`
    /// so actor crates don't need to depend on the registry's
    /// typed Ref to use it. The returned id is dispatchable via
    /// `ctx.tell` / `ctx.send` — same formula `space up` uses
    /// when registering installed agents on this node.
    ///
    /// ```ignore
    /// let counter = ctx.resolve("counter").await;
    /// if counter != 0 {
    ///     ctx.tell(ServiceId(counter), &Msg::new("inc"));
    /// }
    /// ```
    pub fn resolve(&mut self, name: impl Into<alloc::string::String>) -> super::run::Resolve {
        let prefix = self.id.node_prefix();
        let mut msg = super::value::Msg::new("resolve");
        msg = msg.with("name", name.into());
        msg = msg.with("caller_prefix", prefix as u64);
        let ask = self.ask(ServiceId::REGISTRY, &msg);
        super::run::Resolve::new(ask)
    }

    // --- Host I/O (worker mode) ---

    /// Issue an async host call. The handler yields `Pending`; the host
    /// reads the request via `vos_worker_pending_effect`, fulfills it,
    /// writes the result via `vos_worker_provide_result`, then re-polls.
    ///
    /// Used internally by `ask()`, `fetch()`, etc.
    pub fn host_call(&mut self, request: Vec<u8>) -> super::run::HostIo {
        self.host_io_request = Some(request);
        // SAFETY: single-threaded, context outlives the future, one
        // host call in flight at a time.
        let result_slot = &mut self.host_io_result as *mut Option<Vec<u8>>;
        super::run::HostIo::new(result_slot)
    }

    /// Take the pending host I/O request bytes (for the C ABI to expose).
    pub fn take_host_io_request(&mut self) -> Option<Vec<u8>> {
        self.host_io_request.take()
    }

    /// Peek at the pending host I/O request bytes without consuming.
    /// Returns a pointer into the stored bytes — valid until the next
    /// dispatch or take_host_io_request call.
    pub fn peek_host_io_request(&self) -> Option<&[u8]> {
        self.host_io_request.as_deref()
    }

    /// Provide the host I/O result (for the C ABI to inject).
    pub fn set_host_io_result(&mut self, result: Vec<u8>) {
        self.host_io_result = Some(result);
    }

    // --- Cooperative scheduling ---

    /// Checkpoint state and yield to other actors. Resumes next tick.
    /// Each invocation runs one iteration; state is saved automatically.
    pub fn yield_now(&mut self) -> super::run::Yield {
        self.self_schedule = true;
        super::run::Yield::once()
    }

    /// Checkpoint state and sleep for N ticks.
    /// Each invocation runs one iteration; state is saved automatically.
    pub fn sleep(&mut self, ticks: u32) -> super::run::Yield {
        self.self_schedule = true;
        self.sleep_ticks = ticks;
        super::run::Yield::once()
    }

    // --- Storage ---

    /// Queue a key-value write to per-service storage.
    pub fn store(&mut self, key: &[u8], value: &[u8]) {
        self.pending_writes.push((key.to_vec(), value.to_vec()));
    }

    /// Queue a new service spawn from a code hash.
    /// The code blob must already be available as a preimage (via [`provide`]).
    pub fn spawn(&mut self, code_hash: [u8; 32]) {
        self.pending_spawns.push(code_hash);
    }

    /// Store a preimage (code blob, data, etc.) for later retrieval by hash.
    /// Used with [`spawn`] to install a new service: provide the blob first,
    /// then spawn with its hash.
    pub fn provide(&mut self, hash: [u8; 32], data: Vec<u8>) {
        self.pending_provides.push((hash, data));
    }

    /// Install a new child service from a code blob and its content hash.
    /// Convenience that calls [`provide`] + [`spawn`] and returns the
    /// assigned service ID (via the NEW hostcall return value).
    ///
    /// The caller must provide the correct content hash. Use
    /// `blake2b_simd::blake2b(blob).as_bytes()` or the host's hashing
    /// facility to compute it.
    pub fn install(&mut self, hash: [u8; 32], code_blob: Vec<u8>) {
        self.provide(hash, code_blob);
        self.spawn(hash);
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

    /// Flush all queued effects.
    ///
    /// Behaviour depends on the current execution stage:
    ///
    /// - **Refine mode** (`run_refine_service`): effects stay queued in the
    ///   pending vectors so `run_refine_service` can drain them into the
    ///   refine output payload. JAM forbids state-mutating hostcalls in
    ///   refine, so we cannot issue them here.
    /// - **Accumulate mode** (`run_accumulate_service`): effects are issued
    ///   directly via accumulate-phase hostcalls. This is the only stage
    ///   that mutates state.
    /// - **Non-service builds**: effects are dropped (invoked actors don't
    ///   have a host stage to flush to).
    pub fn flush_effects(&mut self) {
        #[cfg(feature = "service")]
        {
            // Refine cannot mutate state — leave the pending_* queues
            // populated so the caller can pack them into the refine output.
            if super::run::is_refine_mode() {
                return;
            }

            use crate::abi::pvm::hostcalls;

            for (key, value) in self.pending_writes.drain(..) {
                hostcalls::write(&key, &value);
            }

            for tell in self.pending_tells.drain(..) {
                hostcalls::transfer(tell.target, 0, 0, &tell.payload);
            }

            for (hash, data) in self.pending_provides.drain(..) {
                hostcalls::provide(&hash, &data);
            }

            for code_hash in self.pending_spawns.drain(..) {
                hostcalls::new_service(&code_hash);
            }
        }

        #[cfg(not(feature = "service"))]
        {
            self.pending_writes.clear();
            self.pending_tells.clear();
            self.pending_provides.clear();
            self.pending_spawns.clear();
        }
    }

    // ── Refine output packing (framework-internal) ───────────────────

    /// Drain the pending effect queues into a `RefinePayload` ready to be
    /// emitted as the refine output. Used by `run_refine_service`.
    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn drain_into_refine_payload(
        &mut self,
        state: Vec<u8>,
        reply: Vec<u8>,
    ) -> crate::refine_payload::RefinePayload {
        use crate::refine_payload::{Effect, RefinePayload};
        let mut effects: Vec<Effect> = Vec::new();
        for (key, value) in self.pending_writes.drain(..) {
            effects.push(Effect::Write { key, value });
        }
        for tell in self.pending_tells.drain(..) {
            effects.push(Effect::Transfer {
                target: tell.target.0,
                memo: tell.payload,
            });
        }
        for (hash, data) in self.pending_provides.drain(..) {
            effects.push(Effect::Provide { hash, data });
        }
        for code_hash in self.pending_spawns.drain(..) {
            effects.push(Effect::New { code_hash });
        }
        RefinePayload { state, reply, effects, continue_next: self.self_schedule }
    }
}

// ── FetchBuilder ─────────────────────────────────────────────────────

/// Builder returned by [`Context::fetch`].
///
/// Chain method/header/body modifiers, then `.await` to send.
/// Implements [`IntoFuture`] so the builder itself is awaitable.
pub struct FetchBuilder<'ctx, A: Actor> {
    ctx: &'ctx mut Context<A>,
    request: crate::effects::FetchRequest,
}

impl<'ctx, A: Actor> FetchBuilder<'ctx, A> {
    /// Set the HTTP method explicitly.
    pub fn method(mut self, method: crate::effects::HttpMethod) -> Self {
        self.request.method = method;
        self
    }

    pub fn get(self) -> Self    { self.method(crate::effects::HttpMethod::Get) }
    pub fn post(self) -> Self   { self.method(crate::effects::HttpMethod::Post) }
    pub fn put(self) -> Self    { self.method(crate::effects::HttpMethod::Put) }
    pub fn delete(self) -> Self { self.method(crate::effects::HttpMethod::Delete) }
    pub fn patch(self) -> Self  { self.method(crate::effects::HttpMethod::Patch) }
    pub fn head(self) -> Self   { self.method(crate::effects::HttpMethod::Head) }

    /// Add a header. Repeat to add multiple values.
    pub fn header(
        mut self,
        name: impl Into<alloc::string::String>,
        value: impl Into<alloc::string::String>,
    ) -> Self {
        self.request.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body (raw bytes).
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.request.body = body.into();
        self
    }

    /// Set a JSON body. Adds `Content-Type: application/json` header.
    pub fn json(mut self, body: impl AsRef<str>) -> Self {
        self.request.body = body.as_ref().as_bytes().to_vec();
        self.header("Content-Type", "application/json")
    }

    /// Set a plain text body. Adds `Content-Type: text/plain; charset=utf-8`.
    pub fn text(mut self, body: impl AsRef<str>) -> Self {
        self.request.body = body.as_ref().as_bytes().to_vec();
        self.header("Content-Type", "text/plain; charset=utf-8")
    }
}

// ── Worker-only context extensions ───────────────────────────────────

/// Marker trait declaring an actor is a **native worker** — i.e.,
/// runs as a host plugin (`.so`/dylib) rather than as a deterministic
/// PVM service. Implementations get access to non-deterministic I/O
/// methods via [`WorkerCtx`]: HTTP `fetch`, raw `host_call`, etc.
///
/// PVM actors deliberately do not implement this. A PVM actor that
/// needs HTTP routes through a worker via `ctx.ask`/`ctx.tell`; the
/// type system enforces this separation by hiding the I/O methods.
///
/// The `#[actor]`/`#[messages]` macro emits the `impl` automatically
/// when the actor crate is built with the `worker` feature on.
pub trait WorkerActor: Actor {}

/// HTTP / host-call API exposed only on actors that implement
/// [`WorkerActor`].
///
/// Bring this trait into scope inside a worker crate to get access
/// to `ctx.fetch(...)` and friends:
///
/// ```ignore
/// use vos::WorkerCtx;
///
/// #[messages]
/// impl MyWorker {
///     #[msg]
///     async fn lookup(&mut self, ctx: &mut Context<Self>) -> u64 {
///         ctx.fetch("https://api.example.com/rate").await.status as u64
///     }
/// }
/// ```
///
/// In a PVM actor crate the trait is unavailable, so `ctx.fetch`
/// produces a clear "method not found" error at compile time.
pub trait WorkerCtx<A: Actor> {
    /// Build an HTTP request via the host. Returns a builder that
    /// implements `IntoFuture`, so awaiting it sends the request
    /// and returns the response.
    fn fetch(&mut self, url: impl Into<alloc::string::String>) -> FetchBuilder<'_, A>;
}

impl<A: WorkerActor> WorkerCtx<A> for Context<A> {
    /// ```ignore
    /// // GET (default method):
    /// let resp = ctx.fetch("https://api.example.com").await;
    ///
    /// // POST with a JSON body and custom header:
    /// let resp = ctx.fetch("https://api.example.com/items")
    ///     .post()
    ///     .header("Authorization", "Bearer xyz")
    ///     .json(r#"{"name":"foo"}"#)
    ///     .await;
    /// ```
    fn fetch(&mut self, url: impl Into<alloc::string::String>) -> FetchBuilder<'_, A> {
        FetchBuilder {
            ctx: self,
            request: crate::effects::FetchRequest::get(url),
        }
    }
}

impl<'ctx, A: Actor> core::future::IntoFuture for FetchBuilder<'ctx, A> {
    type Output = crate::effects::FetchResponse;
    type IntoFuture = core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Self::Output> + 'ctx>
    >;

    fn into_future(self) -> Self::IntoFuture {
        alloc::boxed::Box::pin(async move {
            let bytes = self.request.to_effect_bytes();
            let result = self.ctx.host_call(bytes).await;
            crate::effects::FetchResponse::decode(&result)
                .unwrap_or_else(|| {
                    crate::effects::FetchResponse::host_error("malformed host response")
                })
        })
    }
}
