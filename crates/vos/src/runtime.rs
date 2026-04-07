//! VosRuntime — thin native host driving VOS services.
//!
//! Manages PVM instances per service, handles hostcalls, routes transfers
//! between services across rounds.
//!
//! ## Execution model (JAR-aligned)
//!
//! Top-level services (agents) run at PC=0 (refine entry). Refine is the hot
//! loop: cheap, sandboxed, and where handler logic, child `INVOKE`, and
//! intra-round message exchange happen. Side-effecting hostcalls — `WRITE`,
//! `TRANSFER`, `PROVIDE` — are *staged* into a per-service `RefineJournal`
//! rather than applied immediately. `READ` during refine overlays the
//! journal so a handler sees its own writes within the round.
//!
//! A `TRANSFER` to the running service is interpreted as "re-enter refine
//! with this new message in the same round" and queued into
//! `journal.self_messages`. This turns the scheduler's `send_self(Tick)`
//! loop into a cheap intra-round re-entry rather than a full tick round-trip.
//!
//! At the end of a refine round (no more self-messages, or iteration cap
//! hit) the runtime **commits the journal** directly: writes go into
//! storage, preimages into the preimage map, cross-service transfers into
//! `pending_transfers` for the next `tick()`. The runtime does NOT currently
//! re-enter the PVM at PC=5 — accumulate is a runtime-side replay of the
//! journal, equivalent to a trivial accumulate body. A future change can
//! reintroduce a real PC=5 entry when services need to compute summaries.
//!
//! Guest actors invoked via `INVOKE` still run at PC=0 with only refine-phase
//! hostcalls; their state is returned in the reply envelope (not storage).

use javm::program::{initialize_program, initialize_program_at};
use javm::{ExitReason, Gas, Pvm};
use vos_abi::error;
use vos_abi::hostcall::{self, accumulate, refine};
use vos_abi::service::ServiceId;
use std::collections::HashMap;
use std::io::Write;

const DEFAULT_GAS: Gas = 100_000_000;
const MAX_INVOKE_DEPTH: usize = 8;

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
    /// Whether this service was registered from a dual-entry (refine+
    /// accumulate) blob built by the actor framework. `true` → run the
    /// JAM-aligned two-stage refine→accumulate cycle in `tick()`.
    /// `false` → legacy single-entry mode where one PVM runs at PC=0
    /// with the full accumulate hostcall table (used by hand-rolled
    /// PVM test fixtures that pre-date the framework).
    is_service_blob: bool,
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
}

impl VosRuntime {
    pub fn new() -> Self {
        Self {
            blobs: Vec::new(),
            blob_by_hash: HashMap::new(),
            services: HashMap::new(),
            next_id: 1,
            storage: ServiceStorage::new(),
            preimages: HashMap::new(),
            pending_transfers: Vec::new(),
        }
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

    /// Register a service from a blob index (single-entry blob). Returns its ServiceId.
    pub fn register_service(&mut self, blob_idx: usize) -> ServiceId {
        self.add_service(blob_idx, false)
    }

    /// Register a service from a dual-entry blob. Returns its ServiceId.
    pub fn register_service_from_service_blob(&mut self, blob_idx: usize) -> ServiceId {
        self.add_service(blob_idx, true)
    }

    fn add_service(&mut self, blob_idx: usize, is_service_blob: bool) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;
        self.services.insert(id, ServiceInfo { blob_idx, alive: true, is_service_blob });
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

            if info.is_service_blob {
                // ── Stage 1: refine (PC=0) ────────────────────────────
                let mut refine_items = items;
                let mut refine_pvm = match initialize_program(blob, &[], DEFAULT_GAS) {
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

                // ── Stage 2: accumulate (PC=5) ────────────────────────
                // The guest decodes the refine payload as a single FETCH
                // item and replays each effect via real hostcalls.
                let mut acc_items: Vec<Vec<u8>> = vec![refine_output];
                let mut acc_pvm = match initialize_program_at(blob, &[], DEFAULT_GAS, 5) {
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
            } else {
                // Legacy single-entry blob (hand-rolled test fixtures and
                // such): no refine/accumulate split, no RefinePayload.
                // Run a single PVM at PC=0 with the full accumulate
                // hostcall table so it can WRITE / TRANSFER directly.
                let mut single_items = items;
                let mut pvm = match initialize_program(blob, &[], DEFAULT_GAS) {
                    Some(p) => p,
                    None => {
                        eprintln!("vosx: failed to init PVM for service {svc_id}");
                        continue;
                    }
                };

                run_legacy_stage(
                    &mut pvm,
                    svc_id,
                    &mut single_items,
                    blobs,
                    blob_by_hash,
                    services,
                    storage,
                    preimages,
                    &mut new_transfers,
                );
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


/// Drive a legacy single-entry service PVM. Hostcall dispatch is the
/// union of refine+accumulate (INVOKE *and* WRITE/TRANSFER/PROVIDE),
/// since hand-rolled fixtures issue these directly without going
/// through the refine→accumulate split.
#[allow(clippy::too_many_arguments)]
fn run_legacy_stage(
    pvm: &mut Pvm,
    svc_id: u32,
    items: &mut Vec<Vec<u8>>,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    storage: &mut ServiceStorage,
    preimages: &mut HashMap<[u8; 32], Vec<u8>>,
    transfers_out: &mut Vec<(ServiceId, Vec<u8>)>,
) {
    loop {
        let (exit, _) = pvm.run();
        match exit {
            ExitReason::Halt => return,
            ExitReason::Panic => {
                eprintln!("vosx: service {svc_id} panicked at pc={:#x}", pvm.pc);
                return;
            }
            ExitReason::OutOfGas => {
                eprintln!("vosx: service {svc_id} out of gas");
                return;
            }
            ExitReason::PageFault(addr) => {
                eprintln!("vosx: service {svc_id} page fault at {addr:#x}");
                return;
            }
            ExitReason::HostCall(call_id) => {
                // INVOKE goes through the refine handler; everything
                // else (WRITE/TRANSFER/PROVIDE/READ/INFO/YIELD/NEW)
                // through the accumulate handler.
                if matches!(call_id, refine::INVOKE) {
                    let mut sink_pre = HashMap::new();
                    match handle_refine_hostcall(
                        pvm, call_id, items, svc_id, blobs, blob_by_hash,
                        services, storage, transfers_out, &mut sink_pre,
                    ) {
                        HostcallOutcome::Handled => {
                            for (h, d) in sink_pre { preimages.insert(h, d); }
                            continue;
                        }
                        HostcallOutcome::Unknown => {
                            pvm.registers[7] = error::HOST_WHAT;
                            continue;
                        }
                    }
                }
                match handle_accumulate_hostcall(
                    pvm, call_id, items, svc_id, storage, preimages, transfers_out,
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
