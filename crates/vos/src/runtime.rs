//! VosRuntime — thin native host driving VOS services.
//!
//! Manages PVM instances per service, handles hostcalls, routes transfers
//! between services across rounds.
//!
//! ## Execution model (JAM-aligned)
//!
//! Each `tick()` runs each service with pending input through a real
//! two-stage cycle:
//!
//! 1. **Refine** (PC=0). Pure: the guest reads persisted state via the
//!    read-only `READ` hostcall, dispatches the messages it FETCHes from
//!    the runtime, may `INVOKE` child actors, and halts with a
//!    `RefinePayload` blob (state + reply + staged effects) returned via
//!    `a0`/`a1`. State-mutating hostcalls (`WRITE`, `TRANSFER`,
//!    `PROVIDE`, `NEW`, `CHECKPOINT`) are **forbidden** at this stage —
//!    `handle_refine_hostcall` returns `HOST_WHAT` so a misbuilt guest
//!    fails the same way it would on a JAM core.
//!
//! 2. **Accumulate** (PC=5). The only stage that mutates state. The
//!    runtime hands the refine output back to a fresh PVM instance as a
//!    single FETCH item; the guest's `run_accumulate_service` decodes
//!    the `RefinePayload` and replays each effect via the corresponding
//!    accumulate-phase hostcall. `INVOKE` is **forbidden** here:
//!    accumulate is commit-only, mirroring on-chain behaviour.
//!
//! Per-stage gas budgets come from [`GasConfig`] on the runtime.
//! Cross-service `TRANSFER`s issued during accumulate are appended to
//! `pending_transfers` for the next `tick()`.
//!
//! Guest actors invoked via `INVOKE` from a refining service still run
//! at PC=0 under the same refine-phase policy; their state is returned
//! in the reply envelope (not storage), so they never need accumulate.
//!
//! All registered services are dual-entry blobs (refine at PC=0,
//! accumulate at PC=5). Use [`VosRuntime::register_service_blob`] to
//! load the bytes, then [`VosRuntime::register_service`] to instantiate
//! a service from a blob index.

use javm::program::{initialize_program, initialize_program_at};
use javm::{ExitReason, Gas, Pvm};
use vos_abi::error;
use vos_abi::hostcall::{self, accumulate, refine};
use vos_abi::service::ServiceId;
use std::collections::HashMap;
use std::io::Write;

const DEFAULT_GAS: Gas = 100_000_000;
const MAX_INVOKE_DEPTH: usize = 8;

/// Per-stage gas budgets for one service tick.
///
/// JAM splits gas accounting across stages: refine has its own budget
/// (validators run it on a small assigned subset of cores), while
/// accumulate runs once per block and is bounded by `accumulate_gas`,
/// which on-chain is set per-service in the manifest. We mirror that
/// here so off-chain runs can later be tightened to match what the
/// manifest declares.
#[derive(Debug, Clone, Copy)]
pub struct GasConfig {
    /// Maximum gas a single refine invocation may burn.
    pub refine_gas: Gas,
    /// Maximum gas a single accumulate invocation may burn. On-chain
    /// the manifest can override this per-service; we clamp to this
    /// host maximum so a misconfigured service can't run forever.
    pub accumulate_gas_max: Gas,
    /// Default accumulate gas to use when a service has no manifest
    /// override. Always `<= accumulate_gas_max`.
    pub accumulate_gas_default: Gas,
}

impl GasConfig {
    /// Clamp a requested accumulate gas to `accumulate_gas_max`.
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

// --- PVM memory helpers ---

fn pvm_read(pvm: &Pvm, ptr: u32, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = pvm.read_u8(ptr + i as u32).unwrap_or(0);
    }
    buf
}

fn pvm_read_hash(pvm: &Pvm, ptr: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, byte) in h.iter_mut().enumerate() {
        *byte = pvm.read_u8(ptr + i as u32).unwrap_or(0);
    }
    h
}

fn pvm_write(pvm: &mut Pvm, ptr: u32, data: &[u8]) {
    for (i, &byte) in data.iter().enumerate() {
        pvm.write_u8(ptr + i as u32, byte);
    }
}

// --- Shared hostcall dispatch (refine-phase: available to all PVMs) ---

/// Handle hostcalls common to both refine and accumulate phases.
/// Returns `true` if handled.
fn handle_base_hostcall(
    pvm: &mut Pvm,
    call_id: u32,
    items: &mut Vec<Vec<u8>>,
) -> bool {
    let a0 = pvm.registers[7];
    let a1 = pvm.registers[8];

    match call_id {
        hostcall::GAS => {
            pvm.registers[7] = pvm.gas;
        }
        hostcall::GROW_HEAP => {
            pvm.registers[7] = error::HOST_OK;
        }
        hostcall::DEBUG_WRITE => {
            let buf = pvm_read(pvm, a0 as u32, a1 as usize);
            let _ = std::io::stderr().write_all(&buf);
            let _ = std::io::stderr().flush();
            pvm.registers[7] = buf.len() as u64;
        }
        hostcall::FETCH => {
            let buf_ptr = a0 as u32;
            let buf_len = a1 as usize;
            if let Some(item) = items.first() {
                let copy_len = item.len().min(buf_len);
                pvm_write(pvm, buf_ptr, &item[..copy_len]);
                items.remove(0);
                pvm.registers[7] = copy_len as u64;
            } else {
                pvm.registers[7] = 0;
            }
        }
        _ => return false,
    }
    true
}

// --- JAM-aligned hostcall dispatch (refine vs. accumulate) ---
//
// These two functions are the clean, journal-free dispatch tables that the
// two-stage `tick()` (introduced in step 3) will use. They deliberately
// enforce JAM hostcall partitioning:
//
//   * Refine is pure: it can READ storage, INVOKE children, FETCH inputs,
//     INFO its own id, and YIELD (no-op). Any attempt to mutate state
//     (`WRITE`, `TRANSFER`, `PROVIDE`, `NEW`, `CHECKPOINT`) returns
//     `HOST_WHAT` so a misbuilt guest fails loudly during refine, exactly
//     as it would on a JAM core.
//
//   * Accumulate is the only stage that mutates state. It allows
//     `READ`/`WRITE`/`TRANSFER`/`PROVIDE`/`NEW`/`CHECKPOINT`/`YIELD`/`INFO`
//     and refuses `INVOKE` (accumulate is commit-only on-chain).
//
// Both share `handle_base_hostcall` for `GAS`/`GROW_HEAP`/`FETCH`/
// `DEBUG_WRITE`. The signatures are sized for what each stage actually
// touches: refine has read-only storage, accumulate has &mut storage.

/// Outcome of one hostcall dispatch attempt.
enum HostcallOutcome {
    /// The call was handled (`pvm.registers[7]` is set to the result).
    Handled,
    /// Unknown call id — caller should set `HOST_WHAT` and continue.
    Unknown,
}

/// Refine-stage hostcall dispatch (PC=0). JAM-pure: read-only storage,
/// no transfers, no preimage writes, no service spawning. `INVOKE` is
/// allowed and runs the child at PC=0 with the same refine policy.
#[allow(clippy::too_many_arguments)]
fn handle_refine_hostcall(
    pvm: &mut Pvm,
    call_id: u32,
    items: &mut Vec<Vec<u8>>,
    svc_id: u32,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    // Refine is read-only by *policy* (the dispatch arms below never
    // mutate storage). We accept &mut here to share the existing
    // `handle_invoke` signature without an unsafe cast; nothing in this
    // function or its callees writes to storage.
    storage: &mut ServiceStorage,
    // INVOKE may, via nested children, produce side effects the framework
    // wants to surface; we keep an out-vec parameter to mirror the
    // accumulate signature, but in a JAM-pure refine this stays empty.
    invoke_side_transfers: &mut Vec<(ServiceId, Vec<u8>)>,
    // Same: preimages from nested invoke. Empty in pure refine.
    invoke_side_preimages: &mut HashMap<[u8; 32], Vec<u8>>,
) -> HostcallOutcome {
    if handle_base_hostcall(pvm, call_id, items) {
        return HostcallOutcome::Handled;
    }

    let a0 = pvm.registers[7];
    let a1 = pvm.registers[8];
    let a2 = pvm.registers[9];
    let a3 = pvm.registers[10];

    let id = ServiceId(svc_id);

    match call_id {
        // INFO — service id.
        accumulate::INFO => {
            pvm.registers[7] = svc_id as u64;
            HostcallOutcome::Handled
        }
        // READ — read-only storage. No journal overlay: refine cannot
        // have written anything, by construction.
        accumulate::READ => {
            let key = pvm_read(pvm, a0 as u32, a1 as usize);
            if let Some(value) = (*storage).read(id, &key) {
                let copy_len = value.len().min(a3 as usize);
                let value = value[..copy_len].to_vec();
                pvm_write(pvm, a2 as u32, &value);
                pvm.registers[7] = copy_len as u64;
            } else {
                pvm.registers[7] = error::HOST_NONE;
            }
            HostcallOutcome::Handled
        }
        // YIELD — accepted but no-op in refine. JAM treats yield_output
        // as a status emission; for refine we let the guest call it
        // harmlessly so the same lifecycle code can run in either stage.
        accumulate::YIELD => {
            pvm.registers[7] = error::HOST_OK;
            HostcallOutcome::Handled
        }
        // INVOKE — child PVM at PC=0. Children run under the same refine
        // policy via `handle_invoke`, which already restricts to refine
        // hostcalls.
        refine::INVOKE => {
            let result = handle_invoke(
                pvm,
                blobs,
                blob_by_hash,
                services,
                storage,
                invoke_side_preimages,
                0,
                invoke_side_transfers,
            );
            pvm.registers[7] = result;
            HostcallOutcome::Handled
        }
        // Disallowed in refine — JAM-pure: any state-mutating call here
        // is a guest bug and we want it to fail loudly.
        accumulate::WRITE
        | accumulate::TRANSFER
        | accumulate::PROVIDE
        | accumulate::NEW
        | accumulate::CHECKPOINT => {
            pvm.registers[7] = error::HOST_WHAT;
            HostcallOutcome::Handled
        }
        _ => HostcallOutcome::Unknown,
    }
}

/// Accumulate-stage hostcall dispatch (PC=5). The only stage that mutates
/// state. `INVOKE` is forbidden — accumulate is commit-only on-chain.
#[allow(clippy::too_many_arguments)]
fn handle_accumulate_hostcall(
    pvm: &mut Pvm,
    call_id: u32,
    items: &mut Vec<Vec<u8>>,
    svc_id: u32,
    storage: &mut ServiceStorage,
    preimages: &mut HashMap<[u8; 32], Vec<u8>>,
    transfers_out: &mut Vec<(ServiceId, Vec<u8>)>,
) -> HostcallOutcome {
    if handle_base_hostcall(pvm, call_id, items) {
        return HostcallOutcome::Handled;
    }

    let a0 = pvm.registers[7];
    let a1 = pvm.registers[8];
    let a2 = pvm.registers[9];
    let a3 = pvm.registers[10];
    let a4 = pvm.registers[11];

    let id = ServiceId(svc_id);

    match call_id {
        accumulate::YIELD => {
            pvm.registers[7] = error::HOST_OK;
            HostcallOutcome::Handled
        }
        accumulate::INFO => {
            pvm.registers[7] = svc_id as u64;
            HostcallOutcome::Handled
        }
        accumulate::READ => {
            let key = pvm_read(pvm, a0 as u32, a1 as usize);
            if let Some(value) = storage.read(id, &key) {
                let copy_len = value.len().min(a3 as usize);
                let value = value[..copy_len].to_vec();
                pvm_write(pvm, a2 as u32, &value);
                pvm.registers[7] = copy_len as u64;
            } else {
                pvm.registers[7] = error::HOST_NONE;
            }
            HostcallOutcome::Handled
        }
        accumulate::WRITE => {
            let key = pvm_read(pvm, a0 as u32, a1 as usize);
            let value = pvm_read(pvm, a2 as u32, a3 as usize);
            storage.write(id, &key, &value);
            pvm.registers[7] = error::HOST_OK;
            HostcallOutcome::Handled
        }
        accumulate::PROVIDE => {
            let hash = pvm_read_hash(pvm, a0 as u32);
            let data = pvm_read(pvm, a1 as u32, a2 as usize);
            preimages.insert(hash, data);
            pvm.registers[7] = error::HOST_OK;
            HostcallOutcome::Handled
        }
        accumulate::TRANSFER => {
            let target = ServiceId(a0 as u32);
            let memo = pvm_read(pvm, a3 as u32, a4 as usize);
            transfers_out.push((target, memo));
            pvm.registers[7] = error::HOST_OK;
            HostcallOutcome::Handled
        }
        accumulate::NEW | accumulate::CHECKPOINT => {
            pvm.registers[7] = error::HOST_OK;
            HostcallOutcome::Handled
        }
        // Forbidden in accumulate (commit-only): no INVOKE.
        refine::INVOKE => {
            pvm.registers[7] = error::HOST_WHAT;
            HostcallOutcome::Handled
        }
        _ => HostcallOutcome::Unknown,
    }
}

// --- Per-service storage ---

/// Per-service key-value storage.
pub struct ServiceStorage {
    data: HashMap<(u32, Vec<u8>), Vec<u8>>,
}

impl ServiceStorage {
    fn new() -> Self {
        Self { data: HashMap::new() }
    }

    pub fn read(&self, service: ServiceId, key: &[u8]) -> Option<&[u8]> {
        self.data.get(&(service.0, key.to_vec())).map(|v| v.as_slice())
    }

    pub fn write(&mut self, service: ServiceId, key: &[u8], value: &[u8]) {
        self.data.insert((service.0, key.to_vec()), value.to_vec());
    }
}

// --- Service registry ---

struct ServiceInfo {
    blob_idx: usize,
    alive: bool,
}

/// VOS runtime — drives services in rounds mimicking JAR accumulation.
///
/// Each round:
/// 1. For each service with pending items, create a fresh PVM from blob
/// 2. Run to halt, handling hostcalls inline
/// 3. Collect outgoing transfers → next round
/// 4. Repeat until no new work
pub struct VosRuntime {
    blobs: Vec<Vec<u8>>,
    blob_by_hash: HashMap<[u8; 32], usize>,
    services: HashMap<u32, ServiceInfo>,
    next_id: u32,
    pub storage: ServiceStorage,
    preimages: HashMap<[u8; 32], Vec<u8>>,
    pending_transfers: Vec<(ServiceId, Vec<u8>)>,
    gas: GasConfig,
}

impl VosRuntime {
    pub fn new() -> Self {
        Self::with_gas_config(GasConfig::default())
    }

    /// Create a runtime with explicit per-stage gas budgets.
    pub fn with_gas_config(gas: GasConfig) -> Self {
        Self {
            blobs: Vec::new(),
            blob_by_hash: HashMap::new(),
            services: HashMap::new(),
            next_id: 1,
            storage: ServiceStorage::new(),
            preimages: HashMap::new(),
            pending_transfers: Vec::new(),
            gas,
        }
    }

    /// Get the current gas configuration.
    pub fn gas_config(&self) -> &GasConfig {
        &self.gas
    }

    /// Register a PVM blob. Returns a blob index.
    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        let idx = self.blobs.len();
        self.blob_by_hash.insert(simple_hash(&blob), idx);
        self.blobs.push(blob);
        idx
    }

    /// Register a service PVM blob (dual entry: refine at PC=0, accumulate at PC=5).
    pub fn register_service_blob(&mut self, blob: Vec<u8>) -> usize {
        self.register_blob(blob)
    }

    /// Register a service from a dual-entry blob index. Returns its ServiceId.
    pub fn register_service(&mut self, blob_idx: usize) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;
        self.services.insert(id, ServiceInfo { blob_idx, alive: true });
        ServiceId(id)
    }

    /// Queue a transfer to a service.
    pub fn send_to(&mut self, target: ServiceId, data: Vec<u8>) {
        self.pending_transfers.push((target, data));
    }

    /// Check if there is any pending work.
    pub fn has_work(&self) -> bool {
        !self.pending_transfers.is_empty()
    }

    /// Run one round: process all services with pending items.
    ///
    /// JAM-aligned two-stage execution per service:
    ///
    ///   1. **Refine** (PC=0). Pure: fed the pending messages as FETCH
    ///      items, allowed to READ storage and INVOKE children, but
    ///      forbidden from mutating state. Halts with a `RefinePayload`
    ///      blob (state + reply + staged effects) in `a0`/`a1`.
    ///   2. **Accumulate** (PC=5). The only stage that mutates state.
    ///      Receives the refine payload as a single FETCH item; the
    ///      guest decodes it and replays each effect via real
    ///      `WRITE`/`TRANSFER`/`PROVIDE`/`NEW` hostcalls. INVOKE is
    ///      forbidden here.
    ///
    /// Returns true if any work was done.
    pub fn tick(&mut self) -> bool {
        if self.pending_transfers.is_empty() {
            return false;
        }

        let mut by_service: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        for (to, data) in self.pending_transfers.drain(..) {
            by_service.entry(to.0).or_default().push(data);
        }

        let mut new_transfers = Vec::new();
        let mut did_work = false;

        let blobs = &self.blobs;
        let blob_by_hash = &self.blob_by_hash;
        let services = &self.services;
        let storage = &mut self.storage;
        let preimages = &mut self.preimages;
        let refine_gas = self.gas.refine_gas;
        let accumulate_gas = self.gas.clamp_accumulate(self.gas.accumulate_gas_default);

        for (svc_id, items) in by_service {
            let info = match services.get(&svc_id) {
                Some(i) if i.alive => i,
                _ => continue,
            };
            let blob = match blobs.get(info.blob_idx) {
                Some(b) => b,
                None => continue,
            };

            did_work = true;

            // ── Stage 1: refine (PC=0) ────────────────────────────
            let mut refine_items = items;
            let mut refine_pvm = match initialize_program(blob, &[], refine_gas) {
                Some(p) => p,
                None => {
                    eprintln!("vosx: failed to init refine PVM for service {svc_id}");
                    continue;
                }
            };

            let refine_output = match run_refine_stage(
                &mut refine_pvm,
                svc_id,
                &mut refine_items,
                blobs,
                blob_by_hash,
                services,
                storage,
            ) {
                Some(out) => out,
                None => continue, // panic / OOG already logged
            };

            // Peek at the continue_next flag so we can re-queue the
            // service after accumulate commits. The accumulate guest
            // re-decodes the same bytes for the effect replay.
            let continue_next = crate::refine_payload::RefinePayload::decode(&refine_output)
                .map(|p| p.continue_next)
                .unwrap_or(false);

            // ── Stage 2: accumulate (PC=5) ────────────────────────
            // The guest decodes the refine payload as a single FETCH
            // item and replays each effect via real hostcalls.
            let mut acc_items: Vec<Vec<u8>> = vec![refine_output];
            let mut acc_pvm = match initialize_program_at(blob, &[], accumulate_gas, 5) {
                Some(p) => p,
                None => {
                    eprintln!("vosx: failed to init accumulate PVM for service {svc_id}");
                    continue;
                }
            };

            run_accumulate_stage(
                &mut acc_pvm,
                svc_id,
                &mut acc_items,
                storage,
                preimages,
                &mut new_transfers,
            );

            // If the guest yielded mid-round, re-queue an empty wakeup
            // so it runs again next tick. State was committed via
            // STATE_KEY in accumulate; the next refine reloads via READ.
            if continue_next {
                new_transfers.push((ServiceId(svc_id), Vec::new()));
            }
        }

        self.pending_transfers.extend(new_transfers);
        did_work
    }

    /// Run until no more work.
    pub fn run(&mut self) {
        while self.has_work() {
            self.tick();
        }
    }
}

impl Default for VosRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Drive a service PVM through the refine stage (PC=0). On Halt,
/// reads the guest's output buffer (RefinePayload bytes) from `a0`/`a1`
/// and returns it. Returns `None` on panic / OOG / page fault.
#[allow(clippy::too_many_arguments)]
fn run_refine_stage(
    pvm: &mut Pvm,
    svc_id: u32,
    items: &mut Vec<Vec<u8>>,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    storage: &mut ServiceStorage,
) -> Option<Vec<u8>> {
    // Refine is JAM-pure: any nested-invoke transfers are dropped on
    // the floor (refine cannot stage them — only accumulate may).
    let mut sink_transfers: Vec<(ServiceId, Vec<u8>)> = Vec::new();
    let mut sink_preimages: HashMap<[u8; 32], Vec<u8>> = HashMap::new();

    loop {
        let (exit, _) = pvm.run();
        match exit {
            ExitReason::Halt => {
                let ptr = pvm.registers[7] as u32;
                let len = (pvm.registers[8] as usize).min(1 << 20);
                return Some(pvm_read(pvm, ptr, len));
            }
            ExitReason::Panic => {
                eprintln!("vosx: service {svc_id} panicked in refine at pc={:#x}", pvm.pc);
                return None;
            }
            ExitReason::OutOfGas => {
                eprintln!("vosx: service {svc_id} out of gas in refine");
                return None;
            }
            ExitReason::PageFault(addr) => {
                eprintln!("vosx: service {svc_id} page fault in refine at {addr:#x}");
                return None;
            }
            ExitReason::HostCall(call_id) => {
                match handle_refine_hostcall(
                    pvm,
                    call_id,
                    items,
                    svc_id,
                    blobs,
                    blob_by_hash,
                    services,
                    storage,
                    &mut sink_transfers,
                    &mut sink_preimages,
                ) {
                    HostcallOutcome::Handled => continue,
                    HostcallOutcome::Unknown => {
                        pvm.registers[7] = error::HOST_WHAT;
                    }
                }
            }
        }
    }
}

/// Drive a service PVM through the accumulate stage (PC=5). Effects
/// the guest issues via WRITE / PROVIDE / TRANSFER are applied to the
/// host directly via `handle_accumulate_hostcall`. Cross-service
/// transfers are appended to `transfers_out` for the next tick.
fn run_accumulate_stage(
    pvm: &mut Pvm,
    svc_id: u32,
    items: &mut Vec<Vec<u8>>,
    storage: &mut ServiceStorage,
    preimages: &mut HashMap<[u8; 32], Vec<u8>>,
    transfers_out: &mut Vec<(ServiceId, Vec<u8>)>,
) {
    loop {
        let (exit, _) = pvm.run();
        match exit {
            ExitReason::Halt => return,
            ExitReason::Panic => {
                eprintln!("vosx: service {svc_id} panicked in accumulate at pc={:#x}", pvm.pc);
                return;
            }
            ExitReason::OutOfGas => {
                eprintln!("vosx: service {svc_id} out of gas in accumulate");
                return;
            }
            ExitReason::PageFault(addr) => {
                eprintln!("vosx: service {svc_id} page fault in accumulate at {addr:#x}");
                return;
            }
            ExitReason::HostCall(call_id) => {
                match handle_accumulate_hostcall(
                    pvm,
                    call_id,
                    items,
                    svc_id,
                    storage,
                    preimages,
                    transfers_out,
                ) {
                    HostcallOutcome::Handled => continue,
                    HostcallOutcome::Unknown => {
                        pvm.registers[7] = error::HOST_WHAT;
                    }
                }
            }
        }
    }
}


/// Handle invoke() hostcall: run a child PVM at PC=0 (refine phase).
fn handle_invoke(
    caller: &mut Pvm,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    storage: &mut ServiceStorage,
    preimages: &mut HashMap<[u8; 32], Vec<u8>>,
    depth: usize,
    transfers_out: &mut Vec<(ServiceId, Vec<u8>)>,
) -> u64 {
    if depth >= MAX_INVOKE_DEPTH {
        let output_ptr = caller.registers[11] as u32;
        pvm_write(caller, output_ptr, &[crate::actors::run::STATUS_OOG]);
        return 1;
    }

    let hash_ptr = caller.registers[7] as u32;
    let input_ptr = caller.registers[8] as u32;
    let input_len = caller.registers[9] as usize;
    let gas_limit = caller.registers[10];
    let output_ptr = caller.registers[11] as u32;

    let code_hash = pvm_read_hash(caller, hash_ptr);

    // Resolve blob: service-ID convention (first 4 bytes = ID, rest zero) or hash lookup
    let target_svc_id = if code_hash[4..].iter().all(|&b| b == 0) {
        ServiceId(u32::from_le_bytes([code_hash[0], code_hash[1], code_hash[2], code_hash[3]]))
    } else {
        ServiceId(0)
    };

    use crate::actors::run::{STATUS_NOT_FOUND, STATUS_PANICKED, STATUS_OOG};

    let blob_idx = if let Some(&idx) = blob_by_hash.get(&code_hash) {
        idx
    } else if target_svc_id.0 != 0 {
        match services.get(&target_svc_id.0) {
            Some(info) => info.blob_idx,
            None => {
                pvm_write(caller, output_ptr, &[STATUS_NOT_FOUND]);
                return 1;
            }
        }
    } else {
        pvm_write(caller, output_ptr, &[STATUS_NOT_FOUND]);
        return 1;
    };
    let blob = match blobs.get(blob_idx) {
        Some(b) => b,
        None => {
            pvm_write(caller, output_ptr, &[STATUS_NOT_FOUND]);
            return 1;
        }
    };

    let input = pvm_read(caller, input_ptr, input_len);

    let gas = if gas_limit == 0 { DEFAULT_GAS } else { gas_limit.min(DEFAULT_GAS) };
    let mut child = match initialize_program(blob, &[], gas) {
        Some(p) => p,
        None => {
            pvm_write(caller, output_ptr, &[STATUS_PANICKED]);
            return 1;
        }
    };

    // Split invoke input [state_len:4][state][msg] into separate FETCH items:
    //   FETCH 1: [state_bytes]   (actor state)
    //   FETCH 2: [msg_bytes]     (message)
    // This lets invoked actors use the same fetch_raw → load_or_create → dispatch
    // pattern as service actors.
    let mut child_items = if input.len() >= 4 {
        let state_len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
        let state_end = (4 + state_len).min(input.len());
        let mut items = vec![input[4..state_end].to_vec()];
        if state_end < input.len() {
            items.push(input[state_end..].to_vec());
        }
        items
    } else {
        vec![input]
    };

    loop {
        let (exit, _) = child.run();
        match exit {
            ExitReason::Halt => break,
            ExitReason::Panic => {
                eprintln!("vosx: child {} panicked at pc={:#x}", target_svc_id.0, child.pc);
                pvm_write(caller, output_ptr, &[STATUS_PANICKED]);
                return 1;
            }
            ExitReason::OutOfGas => {
                pvm_write(caller, output_ptr, &[STATUS_OOG]);
                return 1;
            }
            ExitReason::PageFault(_) => {
                pvm_write(caller, output_ptr, &[STATUS_PANICKED]);
                return 1;
            }
            ExitReason::HostCall(call_id) => {
                if handle_base_hostcall(&mut child, call_id, &mut child_items) {
                    continue;
                }
                match call_id {
                    refine::INVOKE => {
                        let mut nested = Vec::new();
                        let result = handle_invoke(
                            &mut child, blobs, blob_by_hash, services, storage, preimages,
                            depth + 1, &mut nested,
                        );
                        transfers_out.extend(nested);
                        child.registers[7] = result;
                    }
                    _ => {
                        child.registers[7] = error::HOST_WHAT;
                    }
                }
            }
        }
    }

    // Copy register-based output back to caller
    let out_ptr = child.registers[7] as u32;
    let out_len = (child.registers[8] as usize).min(4096);
    let output = pvm_read(&child, out_ptr, out_len);
    pvm_write(caller, output_ptr, &output);
    out_len as u64
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
}
