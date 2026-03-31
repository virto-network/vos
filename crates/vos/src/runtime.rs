//! VosRuntime — thin native host driving VOS services.
//!
//! Manages PVM instances per service, handles hostcalls, routes transfers
//! between services across rounds. Each service gets a fresh PVM per
//! invocation (JAR model).
//!
//! ## YIELD flush-and-process
//!
//! When a service YIELDs, the runtime:
//! 1. Drains the service's queued transfers
//! 2. Runs each target child as a fresh PVM
//! 3. Builds 5-byte receipts: `[service_id: u32 LE, status: u8]`
//! 4. Feeds receipts back via the service's FETCH queue
//! 5. Resumes the service
//!
//! This enables the agent to do multi-round tick convergence within
//! a single invocation using the YIELD+FETCH loop pattern.

use crate::hostcall_handler::HostcallHandler;
use javm::program::initialize_program;
use javm::{ExitReason, Gas, Pvm};
use vos_abi::error;
use vos_abi::hostcall;
use vos_abi::service::ServiceId;
use std::collections::HashMap;
use std::io::Write;

const DEFAULT_GAS: Gas = 10_000_000;

/// Exit status bytes for receipts.
pub const STATUS_HALT: u8 = 0;
pub const STATUS_PANIC: u8 = 1;
pub const STATUS_OOG: u8 = 2;
pub const STATUS_PAGE_FAULT: u8 = 3;

/// Entry in the service registry.
struct ServiceInfo {
    /// Index into `blobs`.
    blob_idx: usize,
    /// Whether this service is alive.
    alive: bool,
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
/// 3. On YIELD: flush queued transfers, run children, feed receipts back
/// 4. Collect remaining transfers → next round
/// 5. Repeat until no new work
pub struct VosRuntime {
    blobs: Vec<Vec<u8>>,
    services: HashMap<u32, ServiceInfo>,
    next_id: u32,
    pub hostcalls: HostcallHandler,
    pending_transfers: Vec<PendingTransfer>,
}

impl VosRuntime {
    pub fn new() -> Self {
        Self {
            blobs: Vec::new(),
            services: HashMap::new(),
            next_id: 1,
            hostcalls: HostcallHandler::new(),
            pending_transfers: Vec::new(),
        }
    }

    /// Register a PVM blob. Returns a blob index.
    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        let idx = self.blobs.len();
        self.blobs.push(blob);
        idx
    }

    /// Register a service from a blob index. Returns its ServiceId.
    pub fn register_service(&mut self, blob_idx: usize) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;
        self.services.insert(id, ServiceInfo {
            blob_idx,
            alive: true,
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

            // Fresh PVM from blob
            let mut pvm = match initialize_program(blob, &[], DEFAULT_GAS) {
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
                            hostcall::YIELD => {
                                // Flush-and-process: run child services, collect receipts
                                let pending: Vec<_> = new_transfers.drain(..).collect();
                                let mut receipts = Vec::new();

                                for t in pending {
                                    let child_info = match services.get(&t.to.0) {
                                        Some(i) if i.alive => i,
                                        _ => continue,
                                    };
                                    let child_blob = match blobs.get(child_info.blob_idx) {
                                        Some(b) => b,
                                        None => continue,
                                    };
                                    let result = run_child_pvm(
                                        child_blob,
                                        t.to.0,
                                        vec![t.data],
                                        hostcalls,
                                    );
                                    // 5-byte receipt: [service_id: u32 LE, status: u8]
                                    receipts.extend_from_slice(&t.to.0.to_le_bytes());
                                    receipts.push(result.status);
                                    // Child's outgoing transfers → outer queue
                                    outer_transfers.extend(
                                        result.transfers.into_iter().map(|(to, data)| {
                                            PendingTransfer {
                                                from: ServiceId(t.to.0),
                                                to,
                                                data,
                                            }
                                        }),
                                    );
                                }

                                if !receipts.is_empty() {
                                    item_queue.push(receipts);
                                }
                                pvm.registers[7] = error::HOST_OK;
                            }
                            hostcall::INFO => {
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
                            hostcall::READ => {
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
                            hostcall::WRITE => {
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
                            hostcall::PROVIDE => {
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
                            hostcall::TRANSFER => {
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
                            hostcall::NEW => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            hostcall::CHECKPOINT => {
                                pvm.registers[7] = error::HOST_OK;
                            }
                            _ => {
                                pvm.registers[7] = error::HOST_WHAT;
                            }
                        }
                    }
                }
            }

            // Any un-flushed transfers (service halted without yielding) → outer queue
            outer_transfers.extend(
                new_transfers.into_iter().map(|t| t),
            );
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

/// Result of running a child PVM to completion.
struct ChildResult {
    status: u8,
    /// Outgoing transfers: (target, data).
    transfers: Vec<(ServiceId, Vec<u8>)>,
}

/// Run a fresh PVM for a child service to completion.
/// Used by the YIELD flush-and-process handler.
fn run_child_pvm(
    blob: &[u8],
    svc_id: u32,
    items: Vec<Vec<u8>>,
    hostcalls: &mut HostcallHandler,
) -> ChildResult {
    let mut pvm = match initialize_program(blob, &[], DEFAULT_GAS) {
        Some(p) => p,
        None => return ChildResult { status: STATUS_PANIC, transfers: Vec::new() },
    };

    let id = ServiceId(svc_id);
    let mut item_queue = items;
    let mut transfers = Vec::new();

    loop {
        let (exit, _gas) = pvm.run();
        match exit {
            ExitReason::Halt => {
                return ChildResult { status: STATUS_HALT, transfers };
            }
            ExitReason::Panic => {
                eprintln!("vosx: child {svc_id} panicked at pc={:#x}", pvm.pc);
                return ChildResult { status: STATUS_PANIC, transfers };
            }
            ExitReason::OutOfGas => {
                eprintln!("vosx: child {svc_id} out of gas");
                return ChildResult { status: STATUS_OOG, transfers };
            }
            ExitReason::PageFault(addr) => {
                eprintln!("vosx: child {svc_id} page fault at {addr:#x}");
                return ChildResult { status: STATUS_PAGE_FAULT, transfers };
            }
            ExitReason::HostCall(call_id) => {
                handle_child_hostcall(
                    &mut pvm, call_id, id, hostcalls,
                    &mut item_queue, &mut transfers,
                );
            }
        }
    }
}

/// Handle a hostcall from a child PVM.
fn handle_child_hostcall(
    pvm: &mut Pvm,
    call_id: u32,
    id: ServiceId,
    hostcalls: &mut HostcallHandler,
    item_queue: &mut Vec<Vec<u8>>,
    transfers: &mut Vec<(ServiceId, Vec<u8>)>,
) {
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
        hostcall::YIELD => {
            // Children don't get recursive flush-and-process (one level deep)
            pvm.registers[7] = error::HOST_OK;
        }
        hostcall::INFO => {
            pvm.registers[7] = id.0 as u64;
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
        hostcall::READ => {
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
        hostcall::WRITE => {
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
        hostcall::PROVIDE => {
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
        hostcall::TRANSFER => {
            let target = ServiceId(a0 as u32);
            let memo_ptr = a3 as u32;
            let memo_len = a4 as usize;
            let mut memo = vec![0u8; memo_len];
            for (i, byte) in memo.iter_mut().enumerate() {
                *byte = pvm.read_u8(memo_ptr + i as u32).unwrap_or(0);
            }
            transfers.push((target, memo));
            pvm.registers[7] = error::HOST_OK;
        }
        hostcall::NEW => {
            pvm.registers[7] = error::HOST_OK;
        }
        hostcall::CHECKPOINT => {
            pvm.registers[7] = error::HOST_OK;
        }
        _ => {
            pvm.registers[7] = error::HOST_WHAT;
        }
    }
}
