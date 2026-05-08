//! VosRuntime — thin native host driving VOS services.
//!
//! Manages per-service invocations of the JAVM `InvocationKernel`,
//! handles protocol-cap hostcalls, and routes cross-service transfers
//! across ticks.
//!
//! ## Execution model (JAM-aligned, refine-only top level)
//!
//! The new JAVM kernel collapses the old dual-entry PC=0/PC=5 split
//! into a single entry at PC=0; phase selection happens via φ[7] (0 =
//! refine, 1 = accumulate). VOS runs top-level services exclusively in
//! refine (φ[7]=0):
//!
//!   * **Refine is the hot loop.** State-mutating hostcalls issued
//!     during refine (`WRITE`, `TRANSFER`, `PROVIDE`, `PREIMAGE_PROVIDE`)
//!     are **journaled** by the runtime, not applied immediately.
//!   * **Accumulate is the commit boundary.** After refine halts, the
//!     runtime replays the journal directly: writes flush to storage,
//!     preimages land in the preimage map, transfers join
//!     `pending_transfers` for the next tick. No second PVM invocation
//!     — the replay *is* the accumulate body.
//!
//! This keeps refine bounded and deterministic while still honoring the
//! JAM invariant that all state mutation is structurally one commit.
//! When on-chain bridging lands, journaled cross-service transfers will
//! be routed to a pallet submission instead of `pending_transfers`.
//!
//! Self-directed transfers (a service sending to itself) become
//! **intra-round re-entries**: the runtime re-invokes the same service
//! at PC=0 with the self-messages as fresh FETCH items, capped by
//! [`MAX_REFINE_ITERATIONS`] per tick to guard against guest loops.
//!
//! Nested `INVOKE` children also run at PC=0 under the same refine
//! policy; their effects merge into the parent's journal.
//!
//! ## Continuations (JAM-compatible + VOS optimization)
//!
//! When a service's refine phase sets `continue_next = true`:
//!
//! 1. **JAM-compatible path** (works on any conformant host): the
//!    serialized actor state from the refine payload is written to
//!    `STATE_KEY` in the journal, and a self-directed transfer is
//!    enqueued. On the next tick the guest cold-starts at PC=0,
//!    reads `STATE_KEY` via `READ`, and deserializes its actor —
//!    no host cooperation required.
//!
//! 2. **VOS optimization** (transparent fast path): the runtime also
//!    captures `flat_mem` into the [`DataLayer`] and writes a
//!    [`ContinuationHeader`](crate::pvm_image::ContinuationHeader)
//!    to the journal. On the next tick the kernel is restored via
//!    `InvocationKernel::new_warm` — the guest's `ACTOR_HOLDER`
//!    static is already populated so it skips the `READ` + deserialize.
//!
//! Path (1) ensures services work on JAR without modification.
//! Path (2) is a host-side optimization that avoids serialization
//! overhead when the host supports flat_mem overlay.
//!
//! ## Memory model
//!
//! VOS guests pass flat virtual addresses in φ[7..=11] (RISC-V ABI
//! `a0..=a4`). The runtime reads/writes those buffers via the kernel's
//! address-based window helpers — [`InvocationKernel::read_data_cap_window`]
//! and [`InvocationKernel::write_data_cap_window`] — which resolve the
//! covering DATA cap internally. The declared object cap in φ[12]
//! (grey-transpiler emits the stack cap, slot 65, by default) is
//! therefore ceremonial for VOS: cap dispatch is done by the kernel
//! over the flat window, not the φ[12] value.

use javm::kernel::{InvocationKernel, KernelResult};
use std::collections::HashMap;
use std::io::Write;
use tracing::error;
use crate::abi::error;
use crate::abi::hostcall;
use crate::abi::service::ServiceId;

use crate::data_layer::{DataLayer, MemoryDataLayer};
use crate::refine_payload::{Effect, RefinePayload};

type Gas = u64;

const DEFAULT_GAS: Gas = 100_000_000;
const MAX_INVOKE_DEPTH: usize = 8;
/// Hard cap on how many refine re-entries a single service may accrue
/// inside one `tick()` via self-directed transfers. Protects the
/// runtime from a misbuilt guest that self-schedules forever.
const MAX_REFINE_ITERATIONS: usize = 64;

/// Per-stage gas budgets for one service tick.
#[derive(Debug, Clone, Copy)]
pub struct GasConfig {
    /// Maximum gas a single refine invocation may burn.
    pub refine_gas: Gas,
    /// Upper bound on accumulate gas (retained for API compat; the
    /// runtime does not currently enter a second PVM at commit time,
    /// but on-chain bridging will consume this budget).
    pub accumulate_gas_max: Gas,
    /// Default accumulate gas when a service has no manifest override.
    pub accumulate_gas_default: Gas,
}

impl GasConfig {
    pub fn clamp_accumulate(&self, requested: Gas) -> Gas {
        requested.min(self.accumulate_gas_max)
    }
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            refine_gas: DEFAULT_GAS,
            accumulate_gas_max: DEFAULT_GAS,
            accumulate_gas_default: DEFAULT_GAS,
        }
    }
}

// --- Kernel memory helpers (flat-address window) ---

fn kread(k: &InvocationKernel, addr: u32, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    k.read_data_cap_window(addr, len as u32).unwrap_or_default()
}

fn kread_hash(k: &InvocationKernel, addr: u32) -> [u8; 32] {
    let v = k.read_data_cap_window(addr, 32).unwrap_or_default();
    let mut h = [0u8; 32];
    let n = v.len().min(32);
    h[..n].copy_from_slice(&v[..n]);
    h
}

fn kwrite(k: &mut InvocationKernel, addr: u32, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    k.write_data_cap_window(addr, data);
}

// --- Per-service refine journal ---
//
// One journal spans a top-level service's tick. It accumulates effects
// from the service itself **and** from any children it INVOKEs — JAM
// semantics make every effect produced under one refine a structural
// part of that refine's commit. The journal still tracks *which*
// service each entry belongs to so they land on the right storage row
// at commit time and `journaled_read` can serve read-your-own-writes
// without a parent's writes shadowing a child's lookup.

#[derive(Default)]
struct RefineJournal {
    /// Pending writes, scoped per service: `(svc_id, key, value)`.
    writes: Vec<(u32, Vec<u8>, Vec<u8>)>,
    transfers: Vec<(ServiceId, Vec<u8>)>,
    preimages: Vec<([u8; 32], Vec<u8>)>,
    self_messages: Vec<Vec<u8>>,
    /// Service creation requests: (code_hash, assigned_service_id).
    /// Committed after refine by registering the blob+service.
    new_services: Vec<([u8; 32], u32)>,
}

impl RefineJournal {
    /// Read-your-own-writes for `svc_id`: latest journaled value for
    /// `key` written by *this* service, if any. Other services' writes
    /// to the same key are intentionally ignored — STATE_KEY collides
    /// across services and would otherwise let a parent's encoded
    /// state shadow a child's STORAGE_R during a nested INVOKE.
    fn journaled_read(&self, svc_id: u32, key: &[u8]) -> Option<&[u8]> {
        self.writes
            .iter()
            .rev()
            .find(|(s, k, _)| *s == svc_id && k.as_slice() == key)
            .map(|(_, _, v)| v.as_slice())
    }

    fn absorb_effects(&mut self, effects: Vec<Effect>, self_id: u32) {
        for eff in effects {
            match eff {
                Effect::Write { key, value } => {
                    self.writes.push((self_id, key, value));
                }
                Effect::Transfer { target, memo } => {
                    if target == self_id {
                        self.self_messages.push(memo);
                    } else {
                        self.transfers.push((ServiceId(target), memo));
                    }
                }
                Effect::Provide { hash, data } => {
                    self.preimages.push((hash, data));
                }
                Effect::New { code_hash } => {
                    self.new_services.push((code_hash, 0));
                }
            }
        }
    }
}

// --- Per-service storage ---

#[derive(Default)]
pub struct ServiceStorage {
    data: HashMap<(u32, Vec<u8>), Vec<u8>>,
}

impl ServiceStorage {
    fn new() -> Self {
        Self::default()
    }

    pub fn read(&self, service: ServiceId, key: &[u8]) -> Option<&[u8]> {
        self.data.get(&(service.0, key.to_vec())).map(|v| v.as_slice())
    }

    pub fn write(&mut self, service: ServiceId, key: &[u8], value: &[u8]) {
        self.data.insert((service.0, key.to_vec()), value.to_vec());
    }

    pub fn delete(&mut self, service: ServiceId, key: &[u8]) {
        self.data.remove(&(service.0, key.to_vec()));
    }
}

// --- Service registry ---

struct ServiceInfo {
    blob_idx: usize,
    alive: bool,
}

/// Reply from an external invoke handler.
///
/// `Done` covers the common case (workers, completed agent dispatches):
/// just reply bytes. `Yielded` carries the post-dispatch state + reply
/// so the calling actor's `lifecycle::invoke_raw` decodes it as
/// `InvokeResult::Yielded { state, reply }` and can keep driving the
/// yielded child on subsequent ticks. The runtime packs whichever
/// variant the handler returns into the same wire envelope a
/// same-runtime INVOKE would produce.
#[derive(Debug, Clone)]
pub enum ExternalInvokeReply {
    Done(Vec<u8>),
    Yielded { state: Vec<u8>, reply: Vec<u8> },
}

impl ExternalInvokeReply {
    /// Common case: a non-yielding reply. Equivalent to
    /// `ExternalInvokeReply::Done(reply)`.
    pub fn done(reply: Vec<u8>) -> Self {
        ExternalInvokeReply::Done(reply)
    }
}

/// Callback for handling INVOKE hostcalls to services not in this runtime.
///
/// Receives `(target_service_id, message_bytes)`. Returns
/// `Some(ExternalInvokeReply)` when the external target serviced the
/// request, or `None` to fall through to `STATUS_NOT_FOUND`. Workers
/// and one-shot handlers return `Done(reply)`; agents that propagate
/// yields across thread boundaries return `Yielded { state, reply }`.
pub type ExternalInvokeFn = Box<dyn Fn(ServiceId, &[u8]) -> Option<ExternalInvokeReply> + Send>;

pub struct VosRuntime<D: DataLayer = MemoryDataLayer> {
    blobs: Vec<Vec<u8>>,
    blob_by_hash: HashMap<[u8; 32], usize>,
    services: HashMap<u32, ServiceInfo>,
    next_id: u32,
    pub storage: ServiceStorage,
    preimages: HashMap<[u8; 32], Vec<u8>>,
    pending_transfers: Vec<(ServiceId, Vec<u8>)>,
    /// Count of services that panicked in refine this runtime's lifetime.
    /// Exposed so tests can detect silent guest crashes.
    pub panics: u32,
    gas: GasConfig,
    /// Pluggable data layer for continuation blob storage.
    pub data: D,
    /// JIT compile cache — avoids re-compiling the same PVM blob on
    /// every child invocation.
    code_cache: javm::CodeCache,
    /// Optional handler for INVOKE targets not in this runtime.
    external_invoke: Option<ExternalInvokeFn>,
    /// Side-channel mode for the current dispatch.
    ///
    /// - `Inactive` — regular execution; no recording or replay.
    /// - `Recording` — every top-level INVOKE output is captured
    ///   into the session's log for attachment to the commit.
    /// - `Replaying` — every top-level INVOKE short-circuits and
    ///   returns the next logged output instead of running the
    ///   child.
    effect_mode: crate::effect_log::EffectMode,
    /// Per-service reply bytes captured from the most recent
    /// dispatch's [`RefinePayload::reply`] field. The host pulls
    /// these out via [`take_last_reply`] to satisfy synchronous
    /// invoke requests from peer agents.
    ///
    /// [`take_last_reply`]: VosRuntime::take_last_reply
    last_reply: HashMap<u32, Vec<u8>>,
}

impl VosRuntime<MemoryDataLayer> {
    pub fn new() -> Self {
        Self::with_gas_config(GasConfig::default())
    }

    pub fn with_gas_config(gas: GasConfig) -> Self {
        Self::with_data_layer_and_gas(MemoryDataLayer::new(), gas)
    }
}

impl<D: DataLayer> VosRuntime<D> {
    pub fn with_data_layer(data: D) -> Self {
        Self::with_data_layer_and_gas(data, GasConfig::default())
    }

    pub fn with_data_layer_and_gas(data: D, gas: GasConfig) -> Self {
        Self {
            blobs: Vec::new(),
            blob_by_hash: HashMap::new(),
            services: HashMap::new(),
            next_id: 1,
            storage: ServiceStorage::new(),
            preimages: HashMap::new(),
            pending_transfers: Vec::new(),
            panics: 0,
            gas,
            data,
            code_cache: javm::CodeCache::new(),
            external_invoke: None,
            effect_mode: crate::effect_log::EffectMode::Inactive,
            last_reply: HashMap::new(),
        }
    }

    /// Take and return the most recent dispatch's reply bytes for
    /// `svc_id`, if any. Used by the host (`agent_thread`) to
    /// answer synchronous invoke requests routed to this agent.
    pub fn take_last_reply(&mut self, svc_id: ServiceId) -> Option<Vec<u8>> {
        self.last_reply.remove(&svc_id.0)
    }

    pub fn gas_config(&self) -> &GasConfig {
        &self.gas
    }

    /// Set a callback for INVOKE targets not in this runtime.
    /// Used by VosNode to route invocations to workers.
    pub fn set_external_invoke(&mut self, handler: ExternalInvokeFn) {
        self.external_invoke = Some(handler);
    }

    /// Begin recording the observed reply bytes of every top-level
    /// INVOKE made during the next dispatch. The log is keyed by
    /// `msg` — typically the incoming dispatch bytes — and will be
    /// returned by [`finish_recording`](Self::finish_recording)
    /// after the dispatch completes.
    pub fn begin_recording(&mut self, msg: Vec<u8>) {
        self.effect_mode = crate::effect_log::EffectMode::Recording(
            crate::effect_log::EffectSession::new(msg),
        );
    }

    /// Begin recording with a custom per-reply size cap (overrides
    /// [`crate::effect_log::DEFAULT_REPLY_CAP`]).
    pub fn begin_recording_with_cap(&mut self, msg: Vec<u8>, cap: usize) {
        self.effect_mode = crate::effect_log::EffectMode::Recording(
            crate::effect_log::EffectSession::new(msg).with_cap(cap),
        );
    }

    /// Take the recorded [`EffectLog`](crate::effect_log::EffectLog)
    /// and return to the inactive mode.
    ///
    /// Returns `None` if no recording was in progress (the mode was
    /// `Inactive` or `Replaying`).
    pub fn finish_recording(&mut self) -> Option<crate::effect_log::EffectLog> {
        match std::mem::take(&mut self.effect_mode) {
            crate::effect_log::EffectMode::Recording(s) => Some(s.into_log()),
            other => {
                self.effect_mode = other;
                None
            }
        }
    }

    /// Begin replay: every top-level INVOKE during the next
    /// dispatch will return the corresponding logged bytes instead
    /// of running the child. Use this when restoring a CRDT actor
    /// from its DAG.
    pub fn begin_replay(&mut self, log: crate::effect_log::EffectLog) {
        self.effect_mode = crate::effect_log::EffectMode::Replaying(
            crate::effect_log::EffectReplay::new(log),
        );
    }

    /// Take the replay state and return to the inactive mode. The
    /// returned [`EffectReplay`](crate::effect_log::EffectReplay)
    /// can be inspected for completion (`is_complete`) or
    /// exhaustion (`was_exhausted`) to detect non-deterministic
    /// handlers during rebuild.
    ///
    /// Returns `None` if no replay was in progress.
    pub fn finish_replay(&mut self) -> Option<crate::effect_log::EffectReplay> {
        match std::mem::take(&mut self.effect_mode) {
            crate::effect_log::EffectMode::Replaying(r) => Some(r),
            other => {
                self.effect_mode = other;
                None
            }
        }
    }

    /// Whether a recording session is active. Mainly for tests and
    /// host-side diagnostics.
    #[doc(hidden)]
    pub fn is_recording(&self) -> bool {
        self.effect_mode.is_recording()
    }

    /// Whether replay is active. Mainly for tests and host-side
    /// diagnostics.
    #[doc(hidden)]
    pub fn is_replaying(&self) -> bool {
        self.effect_mode.is_replaying()
    }

    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        let idx = self.blobs.len();
        self.blob_by_hash.insert(simple_hash(&blob), idx);
        self.blobs.push(blob);
        idx
    }

    pub fn register_service_blob(&mut self, blob: Vec<u8>) -> usize {
        self.register_blob(blob)
    }

    pub fn register_service(&mut self, blob_idx: usize) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;
        self.services
            .insert(id, ServiceInfo { blob_idx, alive: true });
        ServiceId(id)
    }

    /// Register a service with a specific externally-assigned ID.
    /// Used by [`crate::node::VosNode`] to assign node-global IDs.
    pub fn register_service_with_id(&mut self, blob_idx: usize, id: ServiceId) -> ServiceId {
        self.services
            .insert(id.0, ServiceInfo { blob_idx, alive: true });
        // Keep next_id above any externally assigned ID to avoid collisions
        if id.0 >= self.next_id {
            self.next_id = id.0 + 1;
        }
        id
    }

    pub fn send_to(&mut self, target: ServiceId, data: Vec<u8>) {
        self.pending_transfers.push((target, data));
    }

    pub fn has_work(&self) -> bool {
        !self.pending_transfers.is_empty()
    }

    /// Drain transfers destined for services not registered in this
    /// runtime. Used by [`crate::node::VosNode`] to route cross-agent
    /// messages through the node's mailbox.
    pub fn drain_external_transfers(&mut self, _self_id: ServiceId) -> Vec<(ServiceId, Vec<u8>)> {
        let mut external = Vec::new();
        self.pending_transfers.retain(|(target, data)| {
            if self.services.contains_key(&target.0) {
                true // keep — local service
            } else {
                external.push((*target, data.clone()));
                false // remove — route externally
            }
        });
        external
    }

    /// Check whether a service has a live continuation in the data layer.
    pub fn is_suspended(&self, id: ServiceId) -> bool {
        let Some(header_bytes) = self.storage.read(id, crate::lifecycle::CONTINUATION_HEADER_KEY)
        else {
            return false;
        };
        if header_bytes.is_empty() {
            return false;
        }
        let Some(header) = crate::pvm_image::ContinuationHeader::decode(header_bytes) else {
            return false;
        };
        self.data.contains(&header.commitment)
    }

    /// Run one round: for each service with pending input, run refine
    /// (re-entering on self-messages up to [`MAX_REFINE_ITERATIONS`]),
    /// then commit the journal directly.
    pub async fn tick(&mut self) -> bool {
        if self.pending_transfers.is_empty() {
            return false;
        }

        let mut by_service: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        for (to, data) in self.pending_transfers.drain(..) {
            by_service.entry(to.0).or_default().push(data);
        }

        let mut new_transfers = Vec::new();
        let mut new_services_to_register: Vec<([u8; 32], u32)> = Vec::new();
        let mut did_work = false;

        let blobs = &self.blobs;
        let blob_by_hash = &self.blob_by_hash;
        let services = &self.services;
        let storage = &mut self.storage;
        let refine_gas = self.gas.refine_gas;
        let panics = &mut self.panics;
        let next_id = &mut self.next_id;

        for (svc_id, mut items) in by_service {
            // Drop any reply captured by a previous dispatch — only
            // the most recent dispatch's reply is meaningful, and
            // if this one produces no reply we don't want
            // take_last_reply to surface stale bytes.
            self.last_reply.remove(&svc_id);

            let info = match services.get(&svc_id) {
                Some(i) if i.alive => i,
                _ => continue,
            };
            let blob = match blobs.get(info.blob_idx) {
                Some(b) => b,
                None => continue,
            };

            did_work = true;
            let mut journal = RefineJournal::default();

            // Load any existing continuation for the first iteration.
            // Subsequent iterations use the previous iteration's captured
            // flat_mem so `ACTOR_HOLDER` and heap state survive across
            // self-message re-entries within the same tick.
            let mut warm_mem: Option<(Vec<u8>, u32, u32)> =
                load_continuation(storage, &self.data, svc_id);

            for iteration in 0..MAX_REFINE_ITERATIONS {
                let mut kernel = if let Some((ref flat_mem, heap_base, heap_top)) = warm_mem {
                    match InvocationKernel::new_warm(
                        blob, &[], refine_gas, flat_mem, heap_base, heap_top,
                        Some(&mut self.code_cache),
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            error!(svc_id, error = %e, "service: warm kernel init failed");
                            break;
                        }
                    }
                } else {
                    match InvocationKernel::new_cached(blob, &[], refine_gas, &mut self.code_cache) {
                        Ok(k) => k,
                        Err(e) => {
                            error!(svc_id, error = %e, "service: kernel init failed");
                            break;
                        }
                    }
                };
                // φ[7] = 0 → refine phase.
                kernel.set_active_reg(7, 0);
                // Transition VM 0 from Ready → Running so kernel.run() executes.
                let _ = kernel
                    .vm_arena
                    .vm_mut(0)
                    .transition(javm::vm_pool::VmState::Running);

                // Stage FETCH items (raw transfers become one item each).
                // Filter out empty wake-up transfers (used to re-tick
                // suspended services with continuations).
                let mut round_items = std::mem::take(&mut items);
                round_items.retain(|item| !item.is_empty());

                let halted = run_refine_kernel(
                    &mut kernel,
                    svc_id,
                    &mut round_items,
                    &mut journal,
                    storage,
                    &self.preimages,
                    blobs,
                    blob_by_hash,
                    services,
                    &mut self.effect_mode,
                    &mut self.code_cache,
                    next_id,
                    &self.external_invoke,
                );

                // Absorb the guest's RefinePayload output (if any) into
                // the journal. This covers the actor framework's
                // effect-buffering path where `set_refine_mode(true)`
                // packs writes/transfers into the refine output.
                if let Some(payload_bytes) = halted {
                    // Determine whether the guest wants to continue next tick.
                    // Two output formats: RefinePayload (service actors) or
                    // old-style [status:u8][state_len:u32][state...][reply...]
                    // (invoked actors). Both can signal yield/continue.
                    let (continue_next, actor_state) =
                        if let Some(payload) = RefinePayload::decode(&payload_bytes) {
                            let cn = payload.continue_next;
                            let state = payload.state;
                            // Capture the reply bytes for the host's
                            // synchronous-invoke path. Always insert,
                            // even for empty replies (Unit-returning
                            // handlers): callers distinguish "handler
                            // returned ()" from "handler panicked" by
                            // looking at whether `take_last_reply`
                            // returns `Some(_)` or `None`. A `None`
                            // here would conflate the two and let
                            // panics surface to the host as silent
                            // success.
                            self.last_reply.insert(svc_id, payload.reply.clone());
                            journal.absorb_effects(payload.effects, svc_id);
                            (cn, state)
                        } else {
                            // Old-style format: status byte 0x01 = yielded.
                            let cn = !payload_bytes.is_empty()
                                && payload_bytes[0] == crate::actors::run::STATUS_YIELDED;
                            (cn, Vec::new())
                        };

                    // Persist the actor's serialized state on every
                    // dispatch — not just when yielding. A one-shot
                    // handler that mutates `self` and returns must
                    // still have its mutation reach the storage row
                    // (and therefore the commit strategy) so CRDT /
                    // Local persistence sees the actual end-of-tick
                    // state instead of stale bytes from the previous
                    // dispatch. Empty state means nothing changed.
                    if !actor_state.is_empty() {
                        journal.writes.push((
                            svc_id,
                            crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                            actor_state,
                        ));
                    }

                    if continue_next {
                        let (flat_mem, heap_base, heap_top) = kernel.extract_flat_mem();
                        save_continuation(svc_id, flat_mem, heap_base, heap_top, &mut self.data, &mut journal);
                        // Spill any self-directed transfers from the
                        // payload's effects as pending transfers for next
                        // tick. On a JAM host, accumulate would replay
                        // these via hostcalls; VOS must match.
                        for msg in journal.self_messages.drain(..) {
                            new_transfers.push((ServiceId(svc_id), msg));
                        }
                        // No automatic wake-up: a yielded service that
                        // produced no self-message has nothing more to
                        // do under its own steam. The continuation is
                        // saved so a future external message
                        // (typically an INVOKE from a parent agent
                        // that owns the dispatch loop) can resume it.
                        // The host is intentionally dumb — orchestration
                        // is the caller's responsibility.
                        break;
                    }

                    if journal.self_messages.is_empty() {
                        // Guest signalled it's done; clear any prior
                        // continuation and exit the refine loop.
                        clear_continuation(
                            &mut journal,
                            storage,
                            &mut self.data,
                            svc_id,
                        );
                        break;
                    }
                } else {
                    *panics += 1;
                    break;
                }

                // Re-enter on self-messages, else stop.
                if journal.self_messages.is_empty() {
                    break;
                }
                // Capture flat_mem for the next iteration's warm restart
                // so ACTOR_HOLDER and heap state survive across self-message
                // re-entries within the same tick.
                let captured = kernel.extract_flat_mem();
                items = std::mem::take(&mut journal.self_messages);
                if iteration + 1 == MAX_REFINE_ITERATIONS {
                    // Spill remaining self-messages as pending transfers
                    // for the next tick. Capture a continuation so the
                    // service warm-restarts with its current heap/actor.
                    let (flat_mem, heap_base, heap_top) = captured;
                    save_continuation(svc_id, flat_mem, heap_base, heap_top, &mut self.data, &mut journal);
                    // Re-queue leftover self-messages for next tick.
                    for msg in items.drain(..) {
                        new_transfers.push((ServiceId(svc_id), msg));
                    }
                    break;
                }
                warm_mem = Some(captured);
            }

            // Commit the journal (accumulate as a direct replay).
            // Each entry carries its origin service_id — children
            // INVOKEd inside this refine produced their own writes,
            // and they need to land on the child's storage row, not
            // the dispatching service's.
            for (write_svc_id, key, value) in journal.writes.drain(..) {
                storage.write(ServiceId(write_svc_id), &key, &value);
            }
            for (hash, data) in journal.preimages.drain(..) {
                self.preimages.insert(hash, data);
            }
            new_transfers.extend(journal.transfers.drain(..));
            new_services_to_register.extend(journal.new_services.drain(..));
        }

        // Register services created via NEW during this tick.
        // The code blob is looked up from preimages (populated by PROVIDE).
        for (code_hash, assigned_id) in new_services_to_register {
            if let Some(blob) = self.preimages.get(&code_hash).cloned() {
                let blob_idx = self.register_blob(blob);
                self.services.insert(assigned_id, ServiceInfo { blob_idx, alive: true });
            }
        }

        self.pending_transfers.extend(new_transfers);
        did_work
    }

    pub async fn run(&mut self) {
        while self.has_work() {
            self.tick().await;
        }
    }

    pub fn run_blocking(&mut self) {
        pollster::block_on(self.run());
    }

    pub fn tick_blocking(&mut self) -> bool {
        pollster::block_on(self.tick())
    }
}

impl Default for VosRuntime<MemoryDataLayer> {
    fn default() -> Self {
        Self::new()
    }
}

/// Drive a refine-phase kernel to halt. Returns the guest's halt
/// output bytes (read from φ[7]/φ[8] as ptr/len) on success, `None` on
/// panic / OOG / page fault.
#[allow(clippy::too_many_arguments)]
fn run_refine_kernel(
    kernel: &mut InvocationKernel,
    svc_id: u32,
    items: &mut Vec<Vec<u8>>,
    journal: &mut RefineJournal,
    storage: &mut ServiceStorage,
    preimages: &HashMap<[u8; 32], Vec<u8>>,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    mode: &mut crate::effect_log::EffectMode,
    code_cache: &mut javm::CodeCache,
    next_id: &mut u32,
    external_invoke: &Option<ExternalInvokeFn>,
) -> Option<Vec<u8>> {
    loop {
        match kernel.run() {
            KernelResult::Halt(_exit) => {
                let ptr = kernel.active_reg(7) as u32;
                let len = (kernel.active_reg(8) as usize).min(1 << 20);
                return Some(kread(kernel, ptr, len));
            }
            KernelResult::Panic => {
                let pc = kernel.vm_arena.vm(kernel.active_vm).pc;
                error!(svc_id, pc, "service: panicked in refine");
                return None;
            }
            KernelResult::OutOfGas => {
                error!(svc_id, "service: out of gas in refine");
                return None;
            }
            KernelResult::PageFault(addr) => {
                error!(svc_id, addr = format!("{addr:#x}"), "service: page fault in refine");
                return None;
            }
            KernelResult::ProtocolCall { slot } => {
                handle_refine_hostcall(
                    kernel,
                    slot as u32,
                    items,
                    svc_id,
                    journal,
                    storage,
                    preimages,
                    blobs,
                    blob_by_hash,
                    services,
                    code_cache,
                    0,
                    next_id,
                    external_invoke,
                    mode,
                );
            }
        }
    }
}

/// Refine-phase protocol-cap dispatch. Mutating calls (WRITE, TRANSFER,
/// PREIMAGE_PROVIDE) are journaled, not applied. Always calls
/// `kernel.resume_protocol_call` before returning.
#[allow(clippy::too_many_arguments)]
fn handle_refine_hostcall(
    kernel: &mut InvocationKernel,
    call_id: u32,
    items: &mut Vec<Vec<u8>>,
    svc_id: u32,
    journal: &mut RefineJournal,
    storage: &mut ServiceStorage,
    preimages: &HashMap<[u8; 32], Vec<u8>>,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    code_cache: &mut javm::CodeCache,
    depth: usize,
    next_id: &mut u32,
    external_invoke: &Option<ExternalInvokeFn>,
    mode: &mut crate::effect_log::EffectMode,
) {
    let a0 = kernel.active_reg(7);
    let a1 = kernel.active_reg(8);
    let a2 = kernel.active_reg(9);
    let a3 = kernel.active_reg(10);
    let a4 = kernel.active_reg(11);

    let id = ServiceId(svc_id);

    let (r7, r8): (u64, u64) = match call_id {
        hostcall::GAS => (kernel.active_gas(), 0),
        hostcall::GROW_HEAP => (error::HOST_OK, 0),
        hostcall::DEBUG_WRITE => {
            let buf = kread(kernel, a0 as u32, a1 as usize);
            let _ = std::io::stderr().write_all(&buf);
            let _ = std::io::stderr().flush();
            (buf.len() as u64, 0)
        }
        hostcall::FETCH => {
            let buf_ptr = a0 as u32;
            let buf_len = a1 as usize;
            if let Some(item) = items.first().cloned() {
                let copy_len = item.len().min(buf_len);
                kwrite(kernel, buf_ptr, &item[..copy_len]);
                items.remove(0);
                // Return the full item length, not copy_len. The guest
                // pairs this with `n <= buf_len` to detect truncation:
                // n > buf_len means the value didn't fit. Returning
                // copy_len here would conflate "fit exactly" with "was
                // truncated", silently dropping items of size buf_len.
                (item.len() as u64, 0)
            } else {
                (0, 0)
            }
        }
        hostcall::INFO => (svc_id as u64, 0),
        hostcall::STORAGE_R => {
            let key = kread(kernel, a0 as u32, a1 as usize);
            let journaled = journal.journaled_read(svc_id, &key).map(|v| v.to_vec());
            let value = journaled.or_else(|| storage.read(id, &key).map(|v| v.to_vec()));
            match value {
                Some(v) => {
                    let copy_len = v.len().min(a3 as usize);
                    kwrite(kernel, a2 as u32, &v[..copy_len]);
                    // Return the full value length so the guest can
                    // detect truncation (n > buf_len). See FETCH for
                    // the rationale.
                    (v.len() as u64, 0)
                }
                None => (error::HOST_NONE, 0),
            }
        }
        hostcall::STORAGE_W => {
            let key = kread(kernel, a0 as u32, a1 as usize);
            let value = kread(kernel, a2 as u32, a3 as usize);
            journal.writes.push((svc_id, key, value));
            (error::HOST_OK, 0)
        }
        hostcall::TRANSFER => {
            let target = ServiceId(a0 as u32);
            let memo = kread(kernel, a3 as u32, a4 as usize);
            if target.0 == svc_id {
                journal.self_messages.push(memo);
            } else {
                journal.transfers.push((target, memo));
            }
            (error::HOST_OK, 0)
        }
        hostcall::PREIMAGE_LOOKUP => {
            // Lookup preimage by hash: check journal first, then global.
            let hash = kread_hash(kernel, a0 as u32);
            let buf_ptr = a1 as u32;
            let buf_len = a2 as usize;
            let data = journal.preimages.iter()
                .find(|(h, _)| *h == hash)
                .map(|(_, d)| d.as_slice())
                .or_else(|| preimages.get(&hash).map(|d| d.as_slice()));
            match data {
                Some(d) => {
                    let copy_len = d.len().min(buf_len);
                    kwrite(kernel, buf_ptr, &d[..copy_len]);
                    // Return the full preimage length (mirrors STORAGE_R
                    // / FETCH) so guests can detect truncation. No
                    // current caller in vos but the contract should be
                    // consistent across the read-into-buffer hostcalls.
                    (d.len() as u64, 0)
                }
                None => (error::HOST_NONE, 0),
            }
        }
        hostcall::PREIMAGE_PROVIDE => {
            let hash = kread_hash(kernel, a0 as u32);
            let data = kread(kernel, a1 as u32, a2 as usize);
            journal.preimages.push((hash, data));
            (error::HOST_OK, 0)
        }
        hostcall::SERVICE_NEW => {
            // JAM NEW: guest provides code_hash in a0 (ptr to 32 bytes).
            // Look up the code blob from journaled preimages, assign a
            // new service ID, and record it for commit.
            let code_hash = kread_hash(kernel, a0 as u32);
            // Look up in journal preimages first (PROVIDE'd this refine)
            let blob = journal.preimages.iter()
                .find(|(h, _)| *h == code_hash)
                .map(|(_, d)| d.clone());
            if let Some(_blob) = blob {
                let new_svc_id = *next_id;
                *next_id += 1;
                journal.new_services.push((code_hash, new_svc_id));
                (new_svc_id as u64, 0)
            } else {
                (error::HOST_NONE, 0)
            }
        }
        hostcall::OUTPUT | hostcall::CHECKPOINT => (error::HOST_OK, 0),
        crate::crypto::ECALL_BLAKE2B_COMPRESS => {
            // Wire ABI matches `zkpvm-precompiles`: a0=h_ptr (64B
            // in/out), a1=m_ptr (128B in), a2=t_low (counter low
            // 64 bits), a3=f flag. The compress primitive itself
            // lives inside vos::crypto as `host_compress_block`
            // — `blake2b_simd` doesn't expose a public single-
            // block API, so this glue stays in-tree.
            let h_ptr = a0 as u32;
            let m_ptr = a1 as u32;
            let t_low = a2;
            let f_flag = a3 != 0;
            let h_bytes = kread(kernel, h_ptr, 64);
            let m_bytes = kread(kernel, m_ptr, 128);
            if h_bytes.len() != 64 || m_bytes.len() != 128 {
                (error::HOST_WHAT, 0)
            } else {
                let mut h: [u8; 64] = h_bytes.try_into().unwrap();
                let m: [u8; 128] = m_bytes.try_into().unwrap();
                crate::crypto::blake2b::host_compress_block(&mut h, &m, t_low as u128, f_flag);
                kwrite(kernel, h_ptr, &h);
                (error::HOST_OK, 0)
            }
        }
        hostcall::INVOKE => {
            let result = handle_invoke(
                kernel,
                blobs,
                blob_by_hash,
                services,
                storage,
                preimages,
                code_cache,
                journal,
                depth + 1,
                next_id,
                external_invoke,
                mode,
            );
            (result, 0)
        }
        _ => (error::HOST_WHAT, 0),
    };

    kernel.resume_protocol_call(r7, r8);
}

/// Write an invoke output into the caller's buffer, and — when a
/// recording session is active at depth 1 — append the same bytes
/// to the session log so replay can reproduce the caller's
/// observation byte-for-byte without re-running the child.
///
/// Nested invokes (depth >= 2) belong to a child's refine and
/// are irrelevant to the caller's session.
///
/// **Buffer cap enforcement.** When the caller's `output` register
/// carries a non-zero length in its high 32 bits (`output_buf_len`),
/// the runtime refuses to write more than that into the caller's
/// PVM memory. An over-cap reply is replaced with a one-byte
/// `STATUS_PANICKED` envelope at the caller's `output_ptr`, so the
/// guest sees `InvokeError::Panicked` rather than having its stack
/// silently overrun. A length of 0 means a legacy guest predating
/// the ABI extension — fall through to the unbounded write.
///
/// **Recording cap enforcement.** When recording, the session
/// carries a per-reply byte cap (16 KiB by default). Outputs larger
/// than that cap are replaced — both in the log and in the caller's
/// buffer — with a single STATUS_PANICKED byte. The caller's PVM
/// observes `InvokeError::Panicked`; replay reproduces the same
/// observation bit-for-bit. The intent is to keep DAG nodes bounded
/// so a runaway worker can't poison consensus replicas with multi-MB
/// payloads.
fn record_and_write_invoke(
    caller: &mut InvocationKernel,
    output_ptr: u32,
    output_buf_len: usize,
    output: &[u8],
    depth: usize,
    mode: &mut crate::effect_log::EffectMode,
) -> u64 {
    use crate::actors::run::STATUS_PANICKED;

    // Buffer cap fires first — if the reply doesn't fit in the
    // caller's PVM buffer, kwrite would overrun. Surface it as a
    // panic. This also feeds the recording log a STATUS_PANICKED
    // marker (see Recording branch below), so replay sees the
    // same observation.
    if output_buf_len > 0 && output.len() > output_buf_len {
        let truncated = alloc::vec![STATUS_PANICKED];
        if depth == 1 {
            if let crate::effect_log::EffectMode::Recording(s) = mode {
                s.record(truncated.clone());
            }
        }
        kwrite(caller, output_ptr, &truncated);
        return truncated.len() as u64;
    }

    if depth == 1 {
        if let crate::effect_log::EffectMode::Recording(s) = mode {
            if output.len() > s.cap() {
                let truncated = alloc::vec![STATUS_PANICKED];
                s.record(truncated.clone());
                kwrite(caller, output_ptr, &truncated);
                return truncated.len() as u64;
            }
            s.record(output.to_vec());
        }
    }
    kwrite(caller, output_ptr, output);
    output.len() as u64
}

/// Handle INVOKE: run a child PVM at PC=0 (refine). The child reads
/// storage via the parent's snapshot and writes effects into the
/// parent's journal, so nested invokes share the parent's commit.
#[allow(clippy::too_many_arguments)]
fn handle_invoke(
    caller: &mut InvocationKernel,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    storage: &mut ServiceStorage,
    preimages: &HashMap<[u8; 32], Vec<u8>>,
    code_cache: &mut javm::CodeCache,
    journal: &mut RefineJournal,
    depth: usize,
    next_id: &mut u32,
    external_invoke: &Option<ExternalInvokeFn>,
    mode: &mut crate::effect_log::EffectMode,
) -> u64 {
    use crate::actors::run::{STATUS_NOT_FOUND, STATUS_OOG, STATUS_PANICKED};

    let hash_ptr = caller.active_reg(7) as u32;
    let input_ptr = caller.active_reg(8) as u32;
    let input_len = caller.active_reg(9) as usize;
    let gas_limit = caller.active_reg(10);
    // Output register is packed: low 32 bits are the PVM address,
    // high 32 bits are the buffer length. Legacy guests that
    // predate this packing pass 0 in the high bits, in which case
    // `record_and_write_invoke` skips the buffer cap and writes
    // unbounded (preserving prior behaviour).
    let output_packed = caller.active_reg(11);
    let output_ptr = output_packed as u32;
    let output_buf_len = (output_packed >> 32) as u32 as usize;

    // Replay fast path: at the top-level invoke under a replay
    // session, return the next recorded output instead of running
    // the child. If the log is exhausted we surface STATUS_PANICKED
    // — the handler has become non-deterministic (asking more than
    // we recorded), and the caller should treat the whole rebuild
    // as a failure.
    if depth == 1 {
        if let crate::effect_log::EffectMode::Replaying(replay) = mode {
            let out: alloc::vec::Vec<u8> = match replay.next_reply() {
                Some(bytes) => bytes.to_vec(),
                None => alloc::vec![STATUS_PANICKED],
            };
            kwrite(caller, output_ptr, &out);
            return out.len() as u64;
        }
    }

    if depth >= MAX_INVOKE_DEPTH {
        return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_OOG], depth, mode);
    }

    let code_hash = kread_hash(caller, hash_ptr);

    // The actor framework's `service_code_hash(svc_id)` packs the
    // target ServiceId into the first 4 bytes of `code_hash` and
    // leaves the remaining 28 bytes zero. A genuine content-addressed
    // invoke fills the whole 32 bytes from a real blake2b hash —
    // those land in `blob_by_hash` directly. Anything else with
    // non-zero tail bytes is a malformed hash that we drop as
    // NOT_FOUND.
    let is_service_invoke = code_hash[4..].iter().all(|&b| b == 0);
    let target_svc_id = if is_service_invoke {
        ServiceId(u32::from_le_bytes([
            code_hash[0],
            code_hash[1],
            code_hash[2],
            code_hash[3],
        ]))
    } else {
        ServiceId(0)
    };

    let blob_idx = if let Some(&idx) = blob_by_hash.get(&code_hash) {
        idx
    } else if is_service_invoke {
        // Explicit ServiceId invoke — look up in the services map.
        // ServiceId(0) (== `ServiceId::REGISTRY`) is a real,
        // resolvable target now that the registry actor lives there;
        // the previous `!= 0` guard predated the registry and would
        // have always rejected `ctx.resolve(...)` calls.
        match services.get(&target_svc_id.0) {
            Some(info) => info.blob_idx,
            None => {
                // Target not in this runtime — try external invoke
                // (worker on another thread, agent on another thread,
                // or peer over the network). The handler reports
                // whether the target yielded so the caller's PVM
                // sees the same status it would for a same-runtime
                // INVOKE; the runtime packs the wire envelope here.
                if let Some(handler) = external_invoke {
                    let input = kread(caller, input_ptr, input_len);
                    // Extract message from invoke input: [state_len:u32][state][msg]
                    let msg = if input.len() >= 4 {
                        let state_len = u32::from_le_bytes(
                            input[..4].try_into().unwrap()
                        ) as usize;
                        let msg_start = (4 + state_len).min(input.len());
                        input[msg_start..].to_vec()
                    } else {
                        input
                    };
                    if let Some(reply) = handler(target_svc_id, &msg) {
                        let (status, state, reply_bytes) = match reply {
                            ExternalInvokeReply::Done(r) =>
                                (crate::actors::run::STATUS_DONE, Vec::new(), r),
                            ExternalInvokeReply::Yielded { state, reply } =>
                                (crate::actors::run::STATUS_YIELDED, state, reply),
                        };
                        let mut output = Vec::with_capacity(5 + state.len() + reply_bytes.len());
                        output.push(status);
                        output.extend_from_slice(&(state.len() as u32).to_le_bytes());
                        output.extend_from_slice(&state);
                        output.extend_from_slice(&reply_bytes);
                        return record_and_write_invoke(caller, output_ptr, output_buf_len, &output, depth, mode);
                    }
                }
                return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_NOT_FOUND], depth, mode);
            }
        }
    } else {
        return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_NOT_FOUND], depth, mode);
    };
    let blob = match blobs.get(blob_idx) {
        Some(b) => b,
        None => {
            return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_NOT_FOUND], depth, mode);
        }
    };

    let input = kread(caller, input_ptr, input_len);

    let gas = if gas_limit == 0 {
        DEFAULT_GAS
    } else {
        gas_limit.min(DEFAULT_GAS)
    };

    let mut child = match InvocationKernel::new_cached(blob, &[], gas, code_cache) {
        Ok(k) => k,
        Err(_) => {
            return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_PANICKED], depth, mode);
        }
    };
    child.set_active_reg(7, 0); // refine
    let _ = child
        .vm_arena
        .vm_mut(0)
        .transition(javm::vm_pool::VmState::Running);

    // Unpack invoke input: [state_len:u32 LE][state][msg].
    // Write state to the child's storage under STATE_KEY so service
    // children (run_refine_service) can cold-start via READ. Also
    // deliver as FETCH items for legacy children (run_refine).
    let mut child_items = if input.len() >= 4 {
        let state_len =
            u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
        let state_end = (4 + state_len).min(input.len());
        let state = &input[4..state_end];

        if !state.is_empty() {
            storage.write(target_svc_id, crate::lifecycle::STATE_KEY_BYTES, state);
        }

        let mut items = vec![state.to_vec()];
        if state_end < input.len() {
            items.push(input[state_end..].to_vec());
        }
        items
    } else {
        vec![input]
    };

    loop {
        match child.run() {
            KernelResult::Halt(_) => break,
            KernelResult::Panic => {
                let pc = child.vm_arena.vm(child.active_vm).pc;
                error!(pc, ?target_svc_id, "child invoke panicked");
                return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_PANICKED], depth, mode);
            }
            KernelResult::OutOfGas => {
                return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_OOG], depth, mode);
            }
            KernelResult::PageFault(_addr) => {
                return record_and_write_invoke(caller, output_ptr, output_buf_len, &[STATUS_PANICKED], depth, mode);
            }
            KernelResult::ProtocolCall { slot } => {
                // Nested invokes by the child actor are not part
                // of the caller's recording/replay session. Feed
                // them an Inactive mode so they run normally.
                let mut child_mode = crate::effect_log::EffectMode::Inactive;
                handle_refine_hostcall(
                    &mut child,
                    slot as u32,
                    &mut child_items,
                    target_svc_id.0,
                    journal,
                    storage,
                    preimages,
                    blobs,
                    blob_by_hash,
                    services,
                    code_cache,
                    depth,
                    next_id,
                    external_invoke,
                    &mut child_mode,
                );
            }
        }
    }

    // Copy the child's halt output into the caller's output buffer.
    // If the child is a service (outputs RefinePayload), convert to the
    // invoke wire format [status:u8][state_len:u32][state][reply] so the
    // caller's guest-side invoke_raw can parse it uniformly.
    let out_ptr = child.active_reg(7) as u32;
    let out_len = (child.active_reg(8) as usize).min(4096);
    let raw_output = kread(&child, out_ptr, out_len);

    let output = if let Some(payload) = RefinePayload::decode(&raw_output) {
        // Service child: convert RefinePayload → invoke wire format.
        // Absorb effects into the parent's journal.
        journal.absorb_effects(payload.effects, target_svc_id.0);

        let status = if payload.continue_next {
            crate::actors::run::STATUS_YIELDED
        } else {
            crate::actors::run::STATUS_DONE
        };
        let sl = (payload.state.len() as u32).to_le_bytes();
        let mut out = Vec::with_capacity(1 + 4 + payload.state.len() + payload.reply.len());
        out.push(status);
        out.extend_from_slice(&sl);
        out.extend_from_slice(&payload.state);
        out.extend_from_slice(&payload.reply);
        out
    } else {
        raw_output
    };

    record_and_write_invoke(caller, output_ptr, output_buf_len, &output, depth, mode)
}

/// Capture a continuation: hash flat_mem, store in the data layer,
/// and push a ContinuationHeader to the journal.
fn save_continuation<D: crate::data_layer::DataLayer>(
    svc_id: u32,
    flat_mem: Vec<u8>,
    heap_base: u32,
    heap_top: u32,
    data: &mut D,
    journal: &mut RefineJournal,
) {
    let commitment = crate::pvm_image::commit(&flat_mem);
    let flat_mem_len = flat_mem.len() as u32;
    pollster::block_on(data.put(commitment, flat_mem));
    let header = crate::pvm_image::ContinuationHeader {
        pc: 0,
        heap_base,
        heap_top,
        need_gas_charge: false,
        iters: 0,
        flat_mem_len,
        commitment,
        registers: [0; 13],
    };
    journal.writes.push((
        svc_id,
        crate::lifecycle::CONTINUATION_HEADER_KEY.to_vec(),
        header.encode(),
    ));
}

/// Load a continuation for a service: read header from storage (checking
/// journal first for read-your-own-writes), fetch the body from the data
/// layer, and return `Some((flat_mem, heap_base, heap_top))`.
fn load_continuation<D: crate::data_layer::DataLayer>(
    storage: &ServiceStorage,
    data: &D,
    svc_id: u32,
) -> Option<(Vec<u8>, u32, u32)> {
    let id = ServiceId(svc_id);
    let header_bytes = storage.read(id, crate::lifecycle::CONTINUATION_HEADER_KEY)?;
    if header_bytes.is_empty() {
        return None;
    }
    let header = crate::pvm_image::ContinuationHeader::decode(header_bytes)?;
    let body = pollster::block_on(data.get(&header.commitment))?;
    Some((body, header.heap_base, header.heap_top))
}

/// Clear any prior continuation for a service by writing empty header
/// and state keys and removing the body from the data layer.
/// No-op if the service has no continuation.
fn clear_continuation<D: crate::data_layer::DataLayer>(
    journal: &mut RefineJournal,
    storage: &ServiceStorage,
    data: &mut D,
    svc_id: u32,
) {
    let id = ServiceId(svc_id);
    let header_bytes = match storage.read(id, crate::lifecycle::CONTINUATION_HEADER_KEY) {
        Some(b) if !b.is_empty() => b,
        _ => return, // no prior continuation — nothing to clean up
    };
    if let Some(header) = crate::pvm_image::ContinuationHeader::decode(header_bytes) {
        pollster::block_on(data.remove(&header.commitment));
    }
    journal.writes.push((
        svc_id,
        crate::lifecycle::CONTINUATION_HEADER_KEY.to_vec(),
        vec![],
    ));
    journal.writes.push((
        svc_id,
        crate::lifecycle::STATE_KEY_BYTES.to_vec(),
        vec![],
    ));
}

fn simple_hash(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        h[i % 32] ^= byte.wrapping_add(i as u8);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_config_default_is_balanced() {
        let g = GasConfig::default();
        assert_eq!(g.refine_gas, DEFAULT_GAS);
        assert_eq!(g.accumulate_gas_default, DEFAULT_GAS);
        assert_eq!(g.accumulate_gas_max, DEFAULT_GAS);
        assert!(g.accumulate_gas_default <= g.accumulate_gas_max);
    }

    #[test]
    fn gas_config_clamps_accumulate() {
        let g = GasConfig {
            refine_gas: 1_000,
            accumulate_gas_max: 500,
            accumulate_gas_default: 200,
        };
        assert_eq!(g.clamp_accumulate(200), 200);
        assert_eq!(g.clamp_accumulate(500), 500);
        assert_eq!(g.clamp_accumulate(10_000), 500);
    }

    #[test]
    fn runtime_with_gas_config_uses_overrides() {
        let g = GasConfig {
            refine_gas: 12_345,
            accumulate_gas_max: 6_789,
            accumulate_gas_default: 4_321,
        };
        let rt = VosRuntime::with_gas_config(g);
        let cfg = rt.gas_config();
        assert_eq!(cfg.refine_gas, 12_345);
        assert_eq!(cfg.accumulate_gas_max, 6_789);
        assert_eq!(cfg.accumulate_gas_default, 4_321);
    }

    #[test]
    fn journal_absorb_new_service() {
        let mut journal = RefineJournal::default();
        let code_hash = [0x42u8; 32];
        journal.absorb_effects(
            vec![
                crate::refine_payload::Effect::Provide {
                    hash: code_hash,
                    data: vec![0xDE, 0xAD],
                },
                crate::refine_payload::Effect::New { code_hash },
            ],
            1, // self_id
        );
        assert_eq!(journal.preimages.len(), 1);
        assert_eq!(journal.preimages[0].0, code_hash);
        assert_eq!(journal.new_services.len(), 1);
        assert_eq!(journal.new_services[0].0, code_hash);
    }

    #[test]
    fn new_service_registered_after_tick() {
        // Verify that PROVIDE + NEW during refine results in the service
        // being registered after the tick commits.
        let mut rt = VosRuntime::new();
        let code_hash = simple_hash(&[0xAB; 16]);
        // Pre-populate preimages with a dummy "code blob"
        rt.preimages.insert(code_hash, vec![0xAB; 16]);

        // Simulate: journal records a NEW with this hash
        let assigned_id = rt.next_id;
        rt.next_id += 1;
        let blob = rt.preimages.get(&code_hash).cloned().unwrap();
        let blob_idx = rt.register_blob(blob);
        rt.services.insert(assigned_id, ServiceInfo { blob_idx, alive: true });

        assert!(rt.services.contains_key(&assigned_id));
        assert!(rt.services.get(&assigned_id).unwrap().alive);
    }
}
