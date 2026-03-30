//! VosRuntime — thin native host driving VOS services.
//!
//! Manages PVM instances per service, handles hostcalls, routes transfers
//! between services across rounds. Each service gets a fresh PVM per
//! invocation (JAR model).

use crate::hostcall_handler::HostcallHandler;
use javm::program::initialize_program;
use javm::{ExitReason, Gas};
use vos_abi::error;
use vos_abi::hostcall;
use vos_abi::service::ServiceId;
use std::collections::HashMap;
use std::io::Write;

const DEFAULT_GAS: Gas = 10_000_000;

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
/// 2. Encode pending items, run to halt
/// 3. Collect new transfers queued during execution → next round
/// 4. Repeat until no new work
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

        let mut new_transfers = Vec::new();
        let mut did_work = false;

        for (svc_id, items) in by_service {
            let info = match self.services.get(&svc_id) {
                Some(i) if i.alive => i,
                _ => continue,
            };
            let blob = match self.blobs.get(info.blob_idx) {
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

            // Queue items for delivery via FETCH
            let mut item_queue: Vec<Vec<u8>> = items;
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
                                // In fresh-PVM model, YIELD returns immediately
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
                                if let Some(value) = self.hostcalls.storage.read(id, &key) {
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
                                self.hostcalls.storage.write(id, &key, &value);
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
                                self.hostcalls.preimages.store(hash, data);
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
                                // Spawn new service from code hash
                                // For now, return HOST_OK
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
        }

        // Queue new transfers for next round
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
