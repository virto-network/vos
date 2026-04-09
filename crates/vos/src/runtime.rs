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
//! ## Continuations (warm restart)
//!
//! When a service's refine phase sets `continue_next = true`, the
//! runtime captures `flat_mem` into the [`DataLayer`], writes a
//! [`ContinuationHeader`](crate::pvm_image::ContinuationHeader) to
//! the journal, and on the next tick restores the kernel with that
//! memory via `InvocationKernel::new_warm`. The service always
//! re-enters at PC=0 but the heap, statics, and actor instance survive.
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
use vos_abi::error;
use vos_abi::hostcall;
use vos_abi::service::ServiceId;

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

#[derive(Default)]
struct RefineJournal {
    writes: Vec<(Vec<u8>, Vec<u8>)>,
    transfers: Vec<(ServiceId, Vec<u8>)>,
    preimages: Vec<([u8; 32], Vec<u8>)>,
    self_messages: Vec<Vec<u8>>,
}

impl RefineJournal {
    /// Read-your-own-writes: latest journaled value for `key`, if any.
    fn journaled_read(&self, key: &[u8]) -> Option<&[u8]> {
        self.writes
            .iter()
            .rev()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_slice())
    }

    fn absorb_payload(&mut self, payload: &RefinePayload, self_id: u32) {
        for eff in &payload.effects {
            match eff {
                Effect::Write { key, value } => {
                    self.writes.push((key.clone(), value.clone()));
                }
                Effect::Transfer { target, memo } => {
                    if *target == self_id {
                        self.self_messages.push(memo.clone());
                    } else {
                        self.transfers.push((ServiceId(*target), memo.clone()));
                    }
                }
                Effect::Provide { hash, data } => {
                    self.preimages.push((*hash, data.clone()));
                }
                Effect::New { .. } => {
                    // Service creation is not yet modeled in the journal;
                    // silently drop for now.
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
        }
    }

    pub fn gas_config(&self) -> &GasConfig {
        &self.gas
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

    pub fn send_to(&mut self, target: ServiceId, data: Vec<u8>) {
        self.pending_transfers.push((target, data));
    }

    pub fn has_work(&self) -> bool {
        !self.pending_transfers.is_empty()
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
        let mut did_work = false;

        let blobs = &self.blobs;
        let blob_by_hash = &self.blob_by_hash;
        let services = &self.services;
        let storage = &mut self.storage;
        let preimages = &mut self.preimages;
        let refine_gas = self.gas.refine_gas;
        let panics = &mut self.panics;

        for (svc_id, mut items) in by_service {
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
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("vosx: service {svc_id} warm kernel init failed: {e}");
                            break;
                        }
                    }
                } else {
                    match InvocationKernel::new_cached(blob, &[], refine_gas, &mut self.code_cache) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("vosx: service {svc_id} kernel init failed: {e}");
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
                    blobs,
                    blob_by_hash,
                    services,
                    &mut self.code_cache,
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
                    let continue_next = if let Some(payload) = RefinePayload::decode(&payload_bytes)
                    {
                        journal.absorb_payload(&payload, svc_id);
                        payload.continue_next
                    } else {
                        // Old-style format: status byte 0x01 = yielded.
                        !payload_bytes.is_empty()
                            && payload_bytes[0] == crate::actors::run::STATUS_YIELDED
                    };

                    if continue_next {
                        // Capture flat_mem into the data layer and write
                        // a continuation header to the journal.
                        let (flat_mem, heap_base, heap_top) = kernel.extract_flat_mem();
                        let commitment = crate::pvm_image::commit(&flat_mem);
                        pollster::block_on(self.data.put(commitment, flat_mem.clone()));
                        let header = crate::pvm_image::ContinuationHeader {
                            pc: 0,
                            heap_base,
                            heap_top,
                            need_gas_charge: false,
                            iters: 0,
                            flat_mem_len: flat_mem.len() as u32,
                            commitment,
                            registers: [0; 13],
                        };
                        journal.writes.push((
                            crate::lifecycle::CONTINUATION_HEADER_KEY.to_vec(),
                            header.encode(),
                        ));
                        // Enqueue a wake-up transfer so the service is
                        // re-ticked next round (continuation resumes it
                        // with warm memory).
                        new_transfers.push((ServiceId(svc_id), Vec::new()));
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
                    let commitment = crate::pvm_image::commit(&flat_mem);
                    pollster::block_on(self.data.put(commitment, flat_mem.clone()));
                    let header = crate::pvm_image::ContinuationHeader {
                        pc: 0,
                        heap_base,
                        heap_top,
                        need_gas_charge: false,
                        iters: 0,
                        flat_mem_len: flat_mem.len() as u32,
                        commitment,
                        registers: [0; 13],
                    };
                    journal.writes.push((
                        crate::lifecycle::CONTINUATION_HEADER_KEY.to_vec(),
                        header.encode(),
                    ));
                    // Re-queue leftover self-messages for next tick.
                    for msg in items.drain(..) {
                        new_transfers.push((ServiceId(svc_id), msg));
                    }
                    break;
                }
                warm_mem = Some(captured);
            }

            // Commit the journal (accumulate as a direct replay).
            for (key, value) in journal.writes.drain(..) {
                storage.write(ServiceId(svc_id), &key, &value);
            }
            for (hash, data) in journal.preimages.drain(..) {
                preimages.insert(hash, data);
            }
            new_transfers.extend(journal.transfers.drain(..));
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
    storage: &ServiceStorage,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    code_cache: &mut javm::CodeCache,
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
                eprintln!("vosx: service {svc_id} panicked in refine at PC={pc}");
                return None;
            }
            KernelResult::OutOfGas => {
                eprintln!("vosx: service {svc_id} out of gas in refine");
                return None;
            }
            KernelResult::PageFault(addr) => {
                eprintln!("vosx: service {svc_id} page fault in refine at {addr:#x}");
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
                    blobs,
                    blob_by_hash,
                    services,
                    code_cache,
                    0,
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
    storage: &ServiceStorage,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    code_cache: &mut javm::CodeCache,
    depth: usize,
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
                (copy_len as u64, 0)
            } else {
                (0, 0)
            }
        }
        hostcall::INFO => (svc_id as u64, 0),
        hostcall::STORAGE_R => {
            let key = kread(kernel, a0 as u32, a1 as usize);
            let journaled = journal.journaled_read(&key).map(|v| v.to_vec());
            let value = journaled.or_else(|| storage.read(id, &key).map(|v| v.to_vec()));
            match value {
                Some(v) => {
                    let copy_len = v.len().min(a3 as usize);
                    kwrite(kernel, a2 as u32, &v[..copy_len]);
                    (copy_len as u64, 0)
                }
                None => (error::HOST_NONE, 0),
            }
        }
        hostcall::STORAGE_W => {
            let key = kread(kernel, a0 as u32, a1 as usize);
            let value = kread(kernel, a2 as u32, a3 as usize);
            journal.writes.push((key, value));
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
        hostcall::PREIMAGE_PROVIDE => {
            let hash = kread_hash(kernel, a0 as u32);
            let data = kread(kernel, a1 as u32, a2 as usize);
            journal.preimages.push((hash, data));
            (error::HOST_OK, 0)
        }
        hostcall::OUTPUT | hostcall::CHECKPOINT | hostcall::SERVICE_NEW => (error::HOST_OK, 0),
        hostcall::INVOKE => {
            let result = handle_invoke(
                kernel,
                blobs,
                blob_by_hash,
                services,
                storage,
                code_cache,
                journal,
                depth + 1,
            );
            (result, 0)
        }
        _ => (error::HOST_WHAT, 0),
    };

    kernel.resume_protocol_call(r7, r8);
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
    storage: &ServiceStorage,
    code_cache: &mut javm::CodeCache,
    journal: &mut RefineJournal,
    depth: usize,
) -> u64 {
    use crate::actors::run::{STATUS_NOT_FOUND, STATUS_OOG, STATUS_PANICKED};

    let hash_ptr = caller.active_reg(7) as u32;
    let input_ptr = caller.active_reg(8) as u32;
    let input_len = caller.active_reg(9) as usize;
    let gas_limit = caller.active_reg(10);
    let output_ptr = caller.active_reg(11) as u32;

    if depth >= MAX_INVOKE_DEPTH {
        kwrite(caller, output_ptr, &[STATUS_OOG]);
        return 1;
    }

    let code_hash = kread_hash(caller, hash_ptr);

    let target_svc_id = if code_hash[4..].iter().all(|&b| b == 0) {
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
    } else if target_svc_id.0 != 0 {
        match services.get(&target_svc_id.0) {
            Some(info) => info.blob_idx,
            None => {
                kwrite(caller, output_ptr, &[STATUS_NOT_FOUND]);
                return 1;
            }
        }
    } else {
        kwrite(caller, output_ptr, &[STATUS_NOT_FOUND]);
        return 1;
    };
    let blob = match blobs.get(blob_idx) {
        Some(b) => b,
        None => {
            kwrite(caller, output_ptr, &[STATUS_NOT_FOUND]);
            return 1;
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
            kwrite(caller, output_ptr, &[STATUS_PANICKED]);
            return 1;
        }
    };
    child.set_active_reg(7, 0); // refine
    let _ = child
        .vm_arena
        .vm_mut(0)
        .transition(javm::vm_pool::VmState::Running);

    // Children expect `[state_len:u32 LE][state][msg]` split into
    // separate FETCH items (FETCH#1=state, FETCH#2=msg) so they can
    // reuse the same fetch_raw → load_or_create → dispatch pattern as
    // top-level service actors.
    let mut child_items = if input.len() >= 4 {
        let state_len =
            u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
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
        match child.run() {
            KernelResult::Halt(_) => break,
            KernelResult::Panic => {
                let pc = child.vm_arena.vm(child.active_vm).pc;
                eprintln!("vosx: child invoke panicked at PC={pc} (target svc {target_svc_id:?})");
                kwrite(caller, output_ptr, &[STATUS_PANICKED]);
                return 1;
            }
            KernelResult::OutOfGas => {
                kwrite(caller, output_ptr, &[STATUS_OOG]);
                return 1;
            }
            KernelResult::PageFault(_addr) => {
                kwrite(caller, output_ptr, &[STATUS_PANICKED]);
                return 1;
            }
            KernelResult::ProtocolCall { slot } => {
                handle_refine_hostcall(
                    &mut child,
                    slot as u32,
                    &mut child_items,
                    target_svc_id.0,
                    journal,
                    storage,
                    blobs,
                    blob_by_hash,
                    services,
                    code_cache,
                    depth,
                );
            }
        }
    }

    // Copy the child's halt output into the caller's output buffer.
    let out_ptr = child.active_reg(7) as u32;
    let out_len = (child.active_reg(8) as usize).min(4096);
    let output = kread(&child, out_ptr, out_len);
    kwrite(caller, output_ptr, &output);
    out_len as u64
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

/// Clear any prior continuation for a service by writing an empty header
/// key and removing the body from the data layer.
fn clear_continuation<D: crate::data_layer::DataLayer>(
    journal: &mut RefineJournal,
    storage: &ServiceStorage,
    data: &mut D,
    svc_id: u32,
) {
    let id = ServiceId(svc_id);
    // Check if there's a prior continuation to clean up.
    if let Some(header_bytes) = storage.read(id, crate::lifecycle::CONTINUATION_HEADER_KEY) {
        if !header_bytes.is_empty() {
            if let Some(header) = crate::pvm_image::ContinuationHeader::decode(header_bytes) {
                pollster::block_on(data.remove(&header.commitment));
            }
        }
    }
    // Write empty value to clear the header key.
    journal.writes.push((
        crate::lifecycle::CONTINUATION_HEADER_KEY.to_vec(),
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
}
