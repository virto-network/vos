//! VosRuntime — thin native host driving VOS services.
//!
//! Manages PVM instances per service, handles hostcalls, routes transfers
//! between services across rounds. Each service gets a fresh PVM per
//! invocation (JAR model).
//!
//! ## Execution model
//!
//! vosx currently runs in accumulate-only mode: all hostcalls (read, write,
//! transfer, invoke, etc.) are available in a single pass. A future `jam`
//! feature flag will enable strict two-phase (refine + accumulate) execution.
//!
//! When a service YIELDs, the runtime returns HOST_OK. Self-driving actors
//! re-invoke themselves via self-transfer. The round loop delivers transfers
//! round by round.

use crate::hostcall_handler::HostcallHandler;
use javm::program::{initialize_program, initialize_program_at};
use javm::{ExitReason, Gas, Pvm};
use vos_abi::error;
use vos_abi::hostcall::{self, accumulate, refine};
use vos_abi::service::ServiceId;
use std::collections::HashMap;
use std::io::Write;

const DEFAULT_GAS: Gas = 100_000_000;
const MAX_INVOKE_DEPTH: usize = 8;

/// Entry in the service registry.
struct ServiceInfo {
    /// Index into `blobs`.
    blob_idx: usize,
    /// Whether this service is alive.
    alive: bool,
    /// Whether the blob has dual entry points (service format).
    /// If true, accumulate entry is at PC=5.
    is_service_blob: bool,
}

/// A pending transfer between services.
struct PendingTransfer {
    #[allow(dead_code)]
    from: ServiceId,
    to: ServiceId,
    data: Vec<u8>,
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
    /// Map from code hash → blob index for invoke() lookups.
    blob_by_hash: HashMap<[u8; 32], usize>,
    services: HashMap<u32, ServiceInfo>,
    next_id: u32,
    pub hostcalls: HostcallHandler,
    pending_transfers: Vec<PendingTransfer>,
}

impl VosRuntime {
    pub fn new() -> Self {
        Self {
            blobs: Vec::new(),
            blob_by_hash: HashMap::new(),
            services: HashMap::new(),
            next_id: 1,
            hostcalls: HostcallHandler::new(),
            pending_transfers: Vec::new(),
        }
    }

    /// Register a standard PVM blob (single entry point). Returns a blob index.
    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        self.register_blob_inner(blob, false)
    }

    /// Register a service PVM blob (dual entry: refine at PC=0, accumulate at PC=5).
    /// In accumulate-only mode, the runtime starts these at PC=5.
    pub fn register_service_blob(&mut self, blob: Vec<u8>) -> usize {
        self.register_blob_inner(blob, true)
    }

    fn register_blob_inner(&mut self, blob: Vec<u8>, is_service: bool) -> usize {
        let idx = self.blobs.len();
        let hash = simple_hash(&blob);
        self.blob_by_hash.insert(hash, idx);
        self.blobs.push(blob);
        // Store format info alongside the blob index
        // (We'll look this up via ServiceInfo.is_service_blob)
        let _ = is_service; // tracked per-service, not per-blob
        idx
    }

    /// Register a service from a blob index. Returns its ServiceId.
    pub fn register_service(&mut self, blob_idx: usize) -> ServiceId {
        self.register_service_with_format(blob_idx, false)
    }

    /// Register a service from a service blob (dual entry point).
    pub fn register_service_from_service_blob(&mut self, blob_idx: usize) -> ServiceId {
        self.register_service_with_format(blob_idx, true)
    }

    fn register_service_with_format(&mut self, blob_idx: usize, is_service_blob: bool) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;
        self.services.insert(id, ServiceInfo {
            blob_idx,
            alive: true,
            is_service_blob,
        });
        ServiceId(id)
    }

    /// Queue a transfer to a service.
    pub fn send_to(&mut self, target: ServiceId, data: Vec<u8>) {
        self.pending_transfers.push(PendingTransfer {
            from: ServiceId(0), // from host
            to: target,
            data,
        });
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

        // Group pending transfers by target service
        let transfers: Vec<PendingTransfer> = self.pending_transfers.drain(..).collect();
        let mut by_service: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        for t in transfers {
            by_service.entry(t.to.0).or_default().push(t.data);
        }

        let mut outer_transfers = Vec::new();
        let mut did_work = false;

        // Destructure to get separate borrows for the YIELD handler
        let blobs = &self.blobs;
        let blob_by_hash = &self.blob_by_hash;
        let services = &self.services;
        let hostcalls = &mut self.hostcalls;

        for (svc_id, items) in by_service {
            let info = match services.get(&svc_id) {
                Some(i) if i.alive => i,
                _ => continue,
            };
            let blob = match blobs.get(info.blob_idx) {
                Some(b) => b,
                None => continue,
            };

            // Fresh PVM from blob — service blobs start at accumulate entry (PC=5)
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
            let mut item_queue: Vec<Vec<u8>> = items;
            let mut new_transfers: Vec<PendingTransfer> = Vec::new();
            did_work = true;

            // Run the PVM
            loop {
                let (exit, _gas) = pvm.run();
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
                        let a0 = pvm.registers[7];
                        let a1 = pvm.registers[8];
                        let a2 = pvm.registers[9];
                        let a3 = pvm.registers[10];
                        let a4 = pvm.registers[11];

                        match call_id {
                            hostcall::DEBUG_WRITE => {
                                let buf_ptr = a0 as u32;
                                let buf_len = a1 as usize;
                                let mut buf = vec![0u8; buf_len];
                                for (i, byte) in buf.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(buf_ptr + i as u32).unwrap_or(0);
                                }
                                let _ = std::io::stderr().write_all(&buf);
                                let _ = std::io::stderr().flush();
                                pvm.registers[7] = buf_len as u64;
                            }
                            accumulate::YIELD => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::INFO => {
                                pvm.registers[7] = svc_id as u64;
                            }
                            hostcall::FETCH => {
                                let buf_ptr = a0 as u32;
                                let buf_len = a1 as usize;
                                if let Some(item) = item_queue.first() {
                                    let copy_len = item.len().min(buf_len);
                                    for (i, &byte) in item[..copy_len].iter().enumerate() {
                                        pvm.write_u8(buf_ptr + i as u32, byte);
                                    }
                                    item_queue.remove(0);
                                    pvm.registers[7] = copy_len as u64;
                                } else {
                                    pvm.registers[7] = 0;
                                }
                            }
                            accumulate::READ => {
                                let key_ptr = a0 as u32;
                                let key_len = a1 as usize;
                                let val_buf_ptr = a2 as u32;
                                let val_buf_len = a3 as usize;
                                let mut key = vec![0u8; key_len];
                                for (i, byte) in key.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(key_ptr + i as u32).unwrap_or(0);
                                }
                                if let Some(value) = hostcalls.storage.read(id, &key) {
                                    let copy_len = value.len().min(val_buf_len);
                                    let value = value[..copy_len].to_vec();
                                    for (i, &byte) in value.iter().enumerate() {
                                        pvm.write_u8(val_buf_ptr + i as u32, byte);
                                    }
                                    pvm.registers[7] = copy_len as u64;
                                } else {
                                    pvm.registers[7] = error::HOST_NONE;
                                }
                            }
                            accumulate::WRITE => {
                                let key_ptr = a0 as u32;
                                let key_len = a1 as usize;
                                let val_ptr = a2 as u32;
                                let val_len = a3 as usize;
                                let mut key = vec![0u8; key_len];
                                for (i, byte) in key.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(key_ptr + i as u32).unwrap_or(0);
                                }
                                let mut value = vec![0u8; val_len];
                                for (i, byte) in value.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(val_ptr + i as u32).unwrap_or(0);
                                }
                                hostcalls.storage.write(id, &key, &value);
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::PROVIDE => {
                                let hash_ptr = a0 as u32;
                                let data_ptr = a1 as u32;
                                let data_len = a2 as usize;
                                let mut hash = [0u8; 32];
                                for (i, byte) in hash.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(hash_ptr + i as u32).unwrap_or(0);
                                }
                                let mut data = vec![0u8; data_len];
                                for (i, byte) in data.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(data_ptr + i as u32).unwrap_or(0);
                                }
                                hostcalls.preimages.store(hash, data);
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::TRANSFER => {
                                let target = ServiceId(a0 as u32);
                                let memo_ptr = a3 as u32;
                                let memo_len = a4 as usize;
                                let mut memo = vec![0u8; memo_len];
                                for (i, byte) in memo.iter_mut().enumerate() {
                                    *byte = pvm.read_u8(memo_ptr + i as u32).unwrap_or(0);
                                }
                                new_transfers.push(PendingTransfer {
                                    from: id,
                                    to: target,
                                    data: memo,
                                });
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::NEW => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            accumulate::CHECKPOINT => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            // Refine-phase: invoke() — run sub-PVM synchronously
                            refine::INVOKE => {
                                let result = handle_invoke(
                                    &mut pvm, blobs, blob_by_hash, services, hostcalls, 0,
                                );
                                pvm.registers[7] = result;
                            }
                            // Note: refine::PEEK (6) collides with accumulate::INFO (6).
                            // In accumulate-only mode, ID 6 = INFO. Guests use READ (4)
                            // for storage access in this mode.
                            _ => {
                                pvm.registers[7] = error::HOST_WHAT;
                            }
                        }
                    }
                }
            }

            // Any un-flushed transfers (service halted without yielding) → outer queue
            outer_transfers.extend(new_transfers);
        }

        // Queue remaining transfers for next round
        self.pending_transfers.extend(outer_transfers);
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

/// Handle invoke() hostcall: run a sub-PVM synchronously.
///
/// Reads code_hash from caller memory, looks up blob, creates fresh child PVM,
/// runs to completion, copies output back to caller memory.
fn handle_invoke(
    caller: &mut Pvm,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    services: &HashMap<u32, ServiceInfo>,
    hostcalls: &mut HostcallHandler,
    depth: usize,
) -> u64 {
    if depth >= MAX_INVOKE_DEPTH {
        return error::HOST_WHAT;
    }

    let hash_ptr = caller.registers[7] as u32;
    let input_ptr = caller.registers[8] as u32;
    let input_len = caller.registers[9] as usize;
    let gas_limit = caller.registers[10];
    let output_ptr = caller.registers[11] as u32;

    // Read code hash from caller memory
    let mut code_hash = [0u8; 32];
    for (i, byte) in code_hash.iter_mut().enumerate() {
        *byte = caller.read_u8(hash_ptr + i as u32).unwrap_or(0);
    }

    // Look up blob — first try by hash, then by service-ID convention
    // (first 4 bytes = service ID LE, rest zeroed)
    let blob_idx = if let Some(&idx) = blob_by_hash.get(&code_hash) {
        idx
    } else if code_hash[4..].iter().all(|&b| b == 0) {
        let target_id = u32::from_le_bytes([code_hash[0], code_hash[1], code_hash[2], code_hash[3]]);
        match services.get(&target_id) {
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

    // Read input from caller memory
    let mut input = vec![0u8; input_len];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = caller.read_u8(input_ptr + i as u32).unwrap_or(0);
    }

    // Create fresh child PVM
    let gas = if gas_limit == 0 { DEFAULT_GAS } else { gas_limit.min(DEFAULT_GAS) };
    let mut child = match initialize_program(blob, &[], gas) {
        Some(p) => p,
        None => return error::HOST_WHAT,
    };

    // Pass input to child via FETCH (first fetch returns input)
    let mut child_items = vec![input];

    // Run child to completion
    loop {
        let (exit, _) = child.run();
        match exit {
            ExitReason::Halt => break,
            ExitReason::Panic | ExitReason::OutOfGas | ExitReason::PageFault(_) => {
                return error::HOST_WHAT;
            }
            ExitReason::HostCall(call_id) => {
                match call_id {
                    hostcall::GAS => {
                        child.registers[7] = child.gas;
                    }
                    hostcall::GROW_HEAP => {
                        child.registers[7] = error::HOST_OK;
                    }
                    hostcall::DEBUG_WRITE => {
                        let buf_ptr = child.registers[7] as u32;
                        let buf_len = child.registers[8] as usize;
                        let mut buf = vec![0u8; buf_len];
                        for (i, byte) in buf.iter_mut().enumerate() {
                            *byte = child.read_u8(buf_ptr + i as u32).unwrap_or(0);
                        }
                        let _ = std::io::stderr().write_all(&buf);
                        let _ = std::io::stderr().flush();
                        child.registers[7] = buf_len as u64;
                    }
                    hostcall::FETCH => {
                        let buf_ptr = child.registers[7] as u32;
                        let buf_len = child.registers[8] as usize;
                        if let Some(item) = child_items.first() {
                            let copy_len = item.len().min(buf_len);
                            for (i, &byte) in item[..copy_len].iter().enumerate() {
                                child.write_u8(buf_ptr + i as u32, byte);
                            }
                            child_items.remove(0);
                            child.registers[7] = copy_len as u64;
                        } else {
                            child.registers[7] = 0;
                        }
                    }
                    accumulate::READ => {
                        // In invoke context, allow read-only storage access
                        let key_ptr = child.registers[7] as u32;
                        let key_len = child.registers[8] as usize;
                        let val_buf_ptr = child.registers[9] as u32;
                        let val_buf_len = child.registers[10] as usize;
                        let mut key = vec![0u8; key_len];
                        for (i, byte) in key.iter_mut().enumerate() {
                            *byte = child.read_u8(key_ptr + i as u32).unwrap_or(0);
                        }
                        // Use a dummy service ID for invoke children
                        let child_id = ServiceId(0);
                        if let Some(value) = hostcalls.storage.read(child_id, &key) {
                            let copy_len = value.len().min(val_buf_len);
                            let value = value[..copy_len].to_vec();
                            for (i, &byte) in value.iter().enumerate() {
                                child.write_u8(val_buf_ptr + i as u32, byte);
                            }
                            child.registers[7] = copy_len as u64;
                        } else {
                            child.registers[7] = error::HOST_NONE;
                        }
                    }
                    // Note: refine::PEEK (6) = accumulate::INFO (6), handled above
                    refine::INVOKE => {
                        // Recursive invoke
                        let result = handle_invoke(
                            &mut child, blobs, blob_by_hash, services, hostcalls, depth + 1,
                        );
                        child.registers[7] = result;
                    }
                    accumulate::INFO => {
                        child.registers[7] = 0; // invoke children have no service ID
                    }
                    _ => {
                        // Most hostcalls not available in invoke context
                        child.registers[7] = error::HOST_WHAT;
                    }
                }
            }
        }
    }

    // Copy child output back to caller memory.
    // Convention: after halt, child a0 = output_ptr, a1 = output_len in child memory.
    let child_out_ptr = child.registers[7] as u32;
    let child_out_len = child.registers[8] as usize;
    let copy_len = child_out_len.min(4096); // cap output size
    for i in 0..copy_len {
        let byte = child.read_u8(child_out_ptr + i as u32).unwrap_or(0);
        caller.write_u8(output_ptr + i as u32, byte);
    }
    copy_len as u64
}

/// Simple hash for blob identification (matches vos-agent's hash_blob).
fn simple_hash(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        h[i % 32] ^= byte.wrapping_add(i as u8);
    }
    h
}
