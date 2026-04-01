//! PVM driver — runs guest services inside javm (Grey's PVM implementation).
//!
//! Each service is a PVM program instance. The driver translates
//! `Driver` trait calls into PVM execution: loading blobs, running
//! until a host-call or halt, and reading/writing guest memory.

use crate::hostcall_handler::{HostcallHandler, HostcallArgs, MemoryAccess};
use javm::program::initialize_program;
use javm::{ExitReason, Gas, Pvm};
use vos_abi::hostcall::{self, accumulate};
use vos_abi::error;
use vos_abi::service::ServiceId;
use crate::registry::Status;
use std::io::Write;

const MAX_INSTANCES: usize = 64;
const DEFAULT_GAS: Gas = 1_000_000;

/// A pending transfer from one service to another.
#[derive(Debug)]
pub struct PendingSend {
    pub from: ServiceId,
    pub to: ServiceId,
    pub msg: RawMsg,
}

/// A guest service backed by a javm PVM instance.
struct PvmService {
    pvm: Pvm,
    suspended: bool,
    pending_msg: Option<RawMsg>,
}

/// PVM driver managing guest service PVM instances.
pub struct PvmDriver {
    services: [Option<PvmService>; MAX_INSTANCES],
    blobs: Vec<Vec<u8>>,
    pub hostcalls: HostcallHandler,
    pub pending_sends: Vec<PendingSend>,
}

impl PvmDriver {
    pub fn new() -> Self {
        const NONE_SVC: Option<PvmService> = None;
        Self {
            services: [NONE_SVC; MAX_INSTANCES],
            blobs: Vec::new(),
            hostcalls: HostcallHandler::new(),
            pending_sends: Vec::new(),
        }
    }

    /// Register a PVM blob. Returns a blob index for use with `spawn_blob`.
    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        let idx = self.blobs.len();
        self.blobs.push(blob);
        idx
    }

    /// Spawn a service from a registered blob.
    pub fn spawn_blob(&mut self, id: ServiceId, blob_idx: usize) -> Status {
        let blob = match self.blobs.get(blob_idx) {
            Some(b) => b,
            None => return Status::Error,
        };

        let idx = (id.0 - 1) as usize;
        if idx >= MAX_INSTANCES {
            return Status::Error;
        }

        let pvm = match initialize_program(blob, &[], DEFAULT_GAS) {
            Some(p) => p,
            None => return Status::Error,
        };

        self.services[idx] = Some(PvmService {
            pvm,
            suspended: false,
            pending_msg: None,
        });
        Status::Pending
    }

    /// Run a PVM instance until it halts, yields, or runs out of gas.
    fn run_service(&mut self, id: ServiceId) -> Status {
        let idx = (id.0 - 1) as usize;
        if self.services[idx].is_none() {
            return Status::Error;
        }

        // Refuel gas
        self.services[idx].as_mut().unwrap().pvm.gas = DEFAULT_GAS;

        macro_rules! svc {
            () => { self.services[idx].as_mut().unwrap() };
        }

        loop {
            let (exit, _gas) = svc!().pvm.run();
            match exit {
                ExitReason::Halt => {
                    return Status::Done;
                }
                ExitReason::Panic => {
                    return Status::Error;
                }
                ExitReason::OutOfGas => {
                    svc!().suspended = true;
                    return Status::Pending;
                }
                ExitReason::PageFault(_addr) => {
                    return Status::Error;
                }
                ExitReason::HostCall(call_id) => {
                    let args = HostcallArgs {
                        a0: svc!().pvm.registers[7],
                        a1: svc!().pvm.registers[8],
                        a2: svc!().pvm.registers[9],
                        a3: svc!().pvm.registers[10],
                        a4: svc!().pvm.registers[11],
                        a5: svc!().pvm.registers[12],
                    };

                    // Intercept DEBUG_WRITE — print to host stderr/stdout
                    if call_id == hostcall::DEBUG_WRITE {
                        let buf_ptr = args.a0 as u32;
                        let buf_len = args.a1 as usize;
                        let mut buf = vec![0u8; buf_len];
                        for (i, byte) in buf.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(buf_ptr + i as u32).unwrap_or(0);
                        }
                        let _ = std::io::stderr().write_all(&buf);
                        let _ = std::io::stderr().flush();
                        svc!().pvm.registers[7] = buf_len as u64;
                        continue;
                    }

                    // Intercept YIELD — suspend
                    if call_id == accumulate::YIELD {
                        svc!().pvm.registers[7] = error::HOST_OK;
                        svc!().suspended = true;
                        return Status::Pending;
                    }

                    // Intercept FETCH — deliver pending message
                    if call_id == hostcall::FETCH {
                        let buf_ptr = args.a0 as u32;
                        let buf_len = args.a1 as usize;
                        if let Some(msg) = svc!().pending_msg.take() {
                            let data = &msg.data;
                            let copy_len = data.len().min(buf_len);
                            for (i, &byte) in data[..copy_len].iter().enumerate() {
                                svc!().pvm.write_u8(buf_ptr + i as u32, byte);
                            }
                            svc!().pvm.registers[7] = copy_len as u64;
                        } else {
                            svc!().pvm.registers[7] = 0;
                        }
                        continue;
                    }

                    // Intercept READ — per-service KV storage read
                    if call_id == accumulate::READ {
                        let key_ptr = args.a0 as u32;
                        let key_len = args.a1 as usize;
                        let val_buf_ptr = args.a2 as u32;
                        let val_buf_len = args.a3 as usize;

                        let mut key = vec![0u8; key_len];
                        for (i, byte) in key.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(key_ptr + i as u32).unwrap_or(0);
                        }

                        if let Some(value) = self.hostcalls.storage.read(id, &key) {
                            let copy_len = value.len().min(val_buf_len);
                            let value = value[..copy_len].to_vec();
                            for (i, &byte) in value.iter().enumerate() {
                                svc!().pvm.write_u8(val_buf_ptr + i as u32, byte);
                            }
                            svc!().pvm.registers[7] = copy_len as u64;
                        } else {
                            svc!().pvm.registers[7] = error::HOST_NONE;
                        }
                        continue;
                    }

                    // Intercept WRITE — per-service KV storage write
                    if call_id == accumulate::WRITE {
                        let key_ptr = args.a0 as u32;
                        let key_len = args.a1 as usize;
                        let val_ptr = args.a2 as u32;
                        let val_len = args.a3 as usize;

                        let mut key = vec![0u8; key_len];
                        for (i, byte) in key.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(key_ptr + i as u32).unwrap_or(0);
                        }
                        let mut value = vec![0u8; val_len];
                        for (i, byte) in value.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(val_ptr + i as u32).unwrap_or(0);
                        }

                        self.hostcalls.storage.write(id, &key, &value);
                        svc!().pvm.registers[7] = error::HOST_OK;
                        continue;
                    }

                    // Intercept PROVIDE — store preimage
                    if call_id == accumulate::PROVIDE {
                        let hash_ptr = args.a0 as u32;
                        let data_ptr = args.a1 as u32;
                        let data_len = args.a2 as usize;

                        let mut hash = [0u8; 32];
                        for (i, byte) in hash.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(hash_ptr + i as u32).unwrap_or(0);
                        }
                        let mut data = vec![0u8; data_len];
                        for (i, byte) in data.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(data_ptr + i as u32).unwrap_or(0);
                        }

                        self.hostcalls.preimages.store(hash, data);
                        svc!().pvm.registers[7] = error::HOST_OK;
                        continue;
                    }

                    // Intercept TRANSFER — queue send to target
                    if call_id == accumulate::TRANSFER {
                        let target = ServiceId(args.a0 as u32);
                        let _amount = args.a1;
                        let _gas_limit = args.a2;
                        let memo_ptr = args.a3 as u32;
                        let memo_len = args.a4 as usize;

                        let mut memo_data = vec![0u8; memo_len];
                        for (i, byte) in memo_data.iter_mut().enumerate() {
                            *byte = svc!().pvm.read_u8(memo_ptr + i as u32).unwrap_or(0);
                        }

                        self.pending_sends.push(PendingSend {
                            from: id,
                            to: target,
                            msg: RawMsg { data: memo_data },
                        });
                        svc!().pvm.registers[7] = error::HOST_OK;
                        continue;
                    }

                    // Intercept INFO — return service ID
                    if call_id == accumulate::INFO {
                        svc!().pvm.registers[7] = id.0 as u64;
                        continue;
                    }

                    // Intercept CHECKPOINT — no-op (no snapshots)
                    if call_id == accumulate::CHECKPOINT {
                        svc!().pvm.registers[7] = error::HOST_OK;
                        continue;
                    }

                    // Unrecognized hostcall
                    svc!().pvm.registers[7] = error::HOST_WHAT;
                }
            }
        }
    }
}

impl Default for PvmDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Raw message: opaque bytes for inter-service communication.
#[derive(Debug)]
pub struct RawMsg {
    pub data: Vec<u8>,
}

impl RawMsg {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl PvmDriver {
    /// Deliver a message to a service and run it.
    pub fn handle(&mut self, id: ServiceId, msg: &RawMsg) -> Status {
        let idx = (id.0 - 1) as usize;
        let svc = match &mut self.services[idx] {
            Some(a) => a,
            None => return Status::Error,
        };

        svc.pending_msg = Some(RawMsg {
            data: msg.data.clone(),
        });

        self.run_service(id)
    }

    /// Resume a suspended service.
    pub fn poll(&mut self, id: ServiceId) -> Status {
        self.run_service(id)
    }

    /// Drop a service instance.
    pub fn drop_service(&mut self, id: ServiceId) {
        let idx = (id.0 - 1) as usize;
        self.services[idx] = None;
    }

    /// Drain pending cross-service sends.
    pub fn drain_sends(&mut self, mut route: impl FnMut(ServiceId, RawMsg)) {
        for send in self.pending_sends.drain(..) {
            route(send.to, send.msg);
        }
    }
}

impl MemoryAccess for PvmDriver {
    fn read_guest(&self, service: ServiceId, ptr: u64, dst: &mut [u8]) -> usize {
        let idx = (service.0 - 1) as usize;
        let pvm = match &self.services[idx] {
            Some(a) => &a.pvm,
            None => return 0,
        };
        let mut count = 0;
        for (i, byte) in dst.iter_mut().enumerate() {
            match pvm.read_u8(ptr as u32 + i as u32) {
                Some(b) => {
                    *byte = b;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    fn write_guest(&mut self, service: ServiceId, ptr: u64, src: &[u8]) -> usize {
        let idx = (service.0 - 1) as usize;
        let pvm = match &mut self.services[idx] {
            Some(a) => &mut a.pvm,
            None => return 0,
        };
        let mut count = 0;
        for (i, &byte) in src.iter().enumerate() {
            if pvm.write_u8(ptr as u32 + i as u32, byte) {
                count += 1;
            } else {
                break;
            }
        }
        count
    }
}
