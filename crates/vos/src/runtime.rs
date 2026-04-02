//! VosRuntime — thin native host driving VOS services.
//!
//! Manages PVM instances per service, handles hostcalls, routes transfers
//! between services across rounds. Each service gets a fresh PVM per
//! invocation (JAR model).
//!
//! ## Execution model
//!
//! Top-level services (agents) run at PC=5 (accumulate entry) with full
//! hostcall access. Guest actors invoked via `invoke()` run at PC=0 (refine
//! entry) with only refine-phase hostcalls. When a service YIELDs, the
//! runtime returns HOST_OK. Self-driving actors re-invoke themselves via
//! self-transfer. The round loop delivers transfers round by round.

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

            let mut pvm = match if info.is_service_blob {
                initialize_program_at(blob, &[], DEFAULT_GAS, 5)
            } else {
                initialize_program(blob, &[], DEFAULT_GAS)
            } {
                Some(p) => p,
                None => {
                    eprintln!("vosx: failed to init PVM for service {svc_id}");
                    continue;
                }
            };

            let id = ServiceId(svc_id);
            let mut item_queue = items;
            let mut svc_transfers: Vec<(ServiceId, Vec<u8>)> = Vec::new();
            did_work = true;

            loop {
                let (exit, _) = pvm.run();
                match exit {
                    ExitReason::Halt => break,
                    ExitReason::Panic => {
                        eprintln!("vosx: service {svc_id} panicked at pc={:#x}", pvm.pc);
                        break;
                    }
                    ExitReason::OutOfGas => {
                        eprintln!("vosx: service {svc_id} out of gas");
                        break;
                    }
                    ExitReason::PageFault(addr) => {
                        eprintln!("vosx: service {svc_id} page fault at {addr:#x}");
                        break;
                    }
                    ExitReason::HostCall(call_id) => {
                        if handle_base_hostcall(&mut pvm, call_id, &mut item_queue) {
                            continue;
                        }

                        let a0 = pvm.registers[7];
                        let a1 = pvm.registers[8];
                        let a2 = pvm.registers[9];
                        let a3 = pvm.registers[10];
                        let a4 = pvm.registers[11];

                        match call_id {
                            accumulate::YIELD => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::INFO => {
                                pvm.registers[7] = svc_id as u64;
                            }
                            accumulate::READ => {
                                let key = pvm_read(&pvm, a0 as u32, a1 as usize);
                                if let Some(value) = storage.read(id, &key) {
                                    let copy_len = value.len().min(a3 as usize);
                                    let value = value[..copy_len].to_vec();
                                    pvm_write(&mut pvm, a2 as u32, &value);
                                    pvm.registers[7] = copy_len as u64;
                                } else {
                                    pvm.registers[7] = error::HOST_NONE;
                                }
                            }
                            accumulate::WRITE => {
                                let key = pvm_read(&pvm, a0 as u32, a1 as usize);
                                let value = pvm_read(&pvm, a2 as u32, a3 as usize);
                                storage.write(id, &key, &value);
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::PROVIDE => {
                                let hash = pvm_read_hash(&pvm, a0 as u32);
                                let data = pvm_read(&pvm, a1 as u32, a2 as usize);
                                preimages.insert(hash, data);
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::TRANSFER => {
                                let target = ServiceId(a0 as u32);
                                let memo = pvm_read(&pvm, a3 as u32, a4 as usize);
                                svc_transfers.push((target, memo));
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::NEW | accumulate::CHECKPOINT => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            refine::INVOKE => {
                                let result = handle_invoke(
                                    &mut pvm, blobs, blob_by_hash, services, storage, preimages,
                                    0, &mut svc_transfers,
                                );
                                pvm.registers[7] = result;
                            }
                            _ => {
                                pvm.registers[7] = error::HOST_WHAT;
                            }
                        }
                    }
                }
            }

            new_transfers.extend(svc_transfers);
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
        return error::HOST_WHAT;
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

    let blob_idx = if let Some(&idx) = blob_by_hash.get(&code_hash) {
        idx
    } else if target_svc_id.0 != 0 {
        match services.get(&target_svc_id.0) {
            Some(info) => info.blob_idx,
            None => return error::HOST_NONE,
        }
    } else {
        return error::HOST_NONE;
    };
    let blob = match blobs.get(blob_idx) {
        Some(b) => b,
        None => return error::HOST_NONE,
    };

    let input = pvm_read(caller, input_ptr, input_len);

    let gas = if gas_limit == 0 { DEFAULT_GAS } else { gas_limit.min(DEFAULT_GAS) };
    let mut child = match initialize_program(blob, &[], gas) {
        Some(p) => p,
        None => return error::HOST_WHAT,
    };

    let mut child_items = vec![input];

    loop {
        let (exit, _) = child.run();
        match exit {
            ExitReason::Halt => break,
            ExitReason::Panic => {
                eprintln!("vosx: child {} panicked at pc={:#x}", target_svc_id.0, child.pc);
                return error::HOST_WHAT;
            }
            ExitReason::OutOfGas => return error::HOST_WHAT,
            ExitReason::PageFault(_) => return error::HOST_WHAT,
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
