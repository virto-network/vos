//! PVM driver — runs child actors inside javm (Grey's PVM implementation).
//!
//! Each child actor is a PVM program instance. The driver translates
//! `Driver` trait calls into PVM execution: loading blobs, running
//! until a host-call or halt, and reading/writing guest memory.

use crate::scheduler::Driver;
use crate::syscall_handler::{MemoryAccess, SyscallArgs, SyscallHandler, SyscallResult};
use javm::program::initialize_program;
use javm::{ExitReason, Gas, Pvm};
use pvx_abi::actor::{ActorId, Status};
use pvx_abi::syscall::Syscall;
use std::io::Write;

/// Maximum number of PVM instances the driver can hold.
const MAX_INSTANCES: usize = 64;

/// Default gas budget per actor per tick.
const DEFAULT_GAS: Gas = 1_000_000;

/// A pending message send from one actor to another.
#[derive(Debug)]
pub struct PendingSend {
    pub from: ActorId,
    pub to: ActorId,
    pub msg: RawMsg,
}

/// A child actor backed by a javm PVM instance.
struct PvmActor {
    pvm: Pvm,
    /// Whether the actor is suspended mid-execution (hit a Yield host-call).
    suspended: bool,
    /// Message waiting to be delivered via the next Recv syscall.
    pending_msg: Option<RawMsg>,
}

/// PVM driver managing child actor PVM instances.
///
/// Uses grey-transpiler to load RISC-V ELFs and javm to execute
/// the resulting PVM programs.
pub struct PvmDriver {
    actors: [Option<PvmActor>; MAX_INSTANCES],
    blobs: Vec<Vec<u8>>,
    pub syscalls: SyscallHandler,
    /// Messages sent by actors during execution, to be routed by the scheduler.
    pub pending_sends: Vec<PendingSend>,
}

impl PvmDriver {
    pub fn new() -> Self {
        const NONE: Option<PvmActor> = None;
        Self {
            actors: [NONE; MAX_INSTANCES],
            blobs: Vec::new(),
            syscalls: SyscallHandler::new(),
            pending_sends: Vec::new(),
        }
    }

    /// Register a PVM blob. Returns a blob index for use with `spawn_blob`.
    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        let idx = self.blobs.len();
        self.blobs.push(blob);
        idx
    }

    /// Spawn an actor from a registered blob.
    /// Returns `Pending` so the scheduler puts it in Suspended state,
    /// meaning it will be polled on the next tick to start execution.
    pub fn spawn_blob(&mut self, id: ActorId, blob_idx: usize) -> Status {
        let blob = match self.blobs.get(blob_idx) {
            Some(b) => b,
            None => return Status::Error,
        };

        let pvm = match initialize_program(blob, &[], DEFAULT_GAS) {
            Some(p) => p,
            None => return Status::Error,
        };

        let idx = (id.0 - 1) as usize;
        if idx >= MAX_INSTANCES {
            return Status::Error;
        }

        // Set up default fds for this actor
        self.syscalls.vfs.init_actor(id);

        self.actors[idx] = Some(PvmActor {
            pvm,
            suspended: false,
            pending_msg: None,
        });
        // Return Pending → Scheduler sets state to Suspended → tick will poll
        Status::Pending
    }

    /// Run a PVM instance until it halts, yields, or runs out of gas.
    /// Handles host-calls (syscalls) inline.
    fn run_actor(&mut self, id: ActorId) -> Status {
        let idx = (id.0 - 1) as usize;
        let actor = match &mut self.actors[idx] {
            Some(a) => a,
            None => return Status::Error,
        };

        // Refuel gas for this tick
        actor.pvm.gas = DEFAULT_GAS;

        loop {
            let (exit, _gas) = actor.pvm.run();
            match exit {
                ExitReason::Halt => {
                    return Status::Done;
                }
                ExitReason::Panic => {
                    return Status::Error;
                }
                ExitReason::OutOfGas => {
                    // Ran out of gas this tick — suspend and resume next tick
                    actor.suspended = true;
                    return Status::Pending;
                }
                ExitReason::PageFault(_addr) => {
                    return Status::Error;
                }
                ExitReason::HostCall(call_id) => {
                    // Map host-call ID to syscall
                    let args = SyscallArgs {
                        a0: actor.pvm.registers[7] as i64,  // a0 = φ₇
                        a1: actor.pvm.registers[8] as i64,  // a1 = φ₈
                        a2: actor.pvm.registers[9] as i64,  // a2 = φ₉
                        a3: actor.pvm.registers[10] as i64, // a3 = φ₁₀
                    };

                    let syscall = match Syscall::from_id(call_id) {
                        Some(s) => s,
                        None => {
                            // Unknown syscall — return ENOSYS
                            actor.pvm.registers[7] =
                                pvx_abi::syscall::errno::ENOSYS as u64;
                            continue;
                        }
                    };

                    // Intercept FdWrite on stdout/stderr to print to host
                    if syscall == Syscall::FdWrite {
                        let fd = args.a0;
                        let buf_ptr = args.a1 as u32;
                        let buf_len = args.a2 as usize;
                        if fd == 1 || fd == 2 {
                            let mut buf = vec![0u8; buf_len];
                            for (i, byte) in buf.iter_mut().enumerate() {
                                *byte = actor.pvm.read_u8(buf_ptr + i as u32).unwrap_or(0);
                            }
                            if fd == 1 {
                                let _ = std::io::stdout().write_all(&buf);
                                let _ = std::io::stdout().flush();
                            } else {
                                let _ = std::io::stderr().write_all(&buf);
                            }
                            actor.pvm.registers[7] = buf_len as u64;
                            continue;
                        }
                    }

                    // Intercept Yield — suspend this actor so others can run
                    if syscall == Syscall::Yield {
                        actor.pvm.registers[7] = 0;
                        actor.suspended = true;
                        return Status::Pending;
                    }

                    // Intercept Log syscall to print to host stderr
                    if syscall == Syscall::Log {
                        let msg_ptr = args.a1 as u32;
                        let msg_len = args.a2 as usize;
                        let mut buf = vec![0u8; msg_len];
                        for (i, byte) in buf.iter_mut().enumerate() {
                            *byte = actor.pvm.read_u8(msg_ptr + i as u32).unwrap_or(0);
                        }
                        if let Ok(s) = std::str::from_utf8(&buf) {
                            eprintln!("[actor {}] {s}", id.0);
                        }
                        actor.pvm.registers[7] = 0;
                        continue;
                    }

                    match self.syscalls.dispatch(id, syscall, &args) {
                        SyscallResult::Value(v) => {
                            actor.pvm.registers[7] = v as u64; // return in a0
                        }
                        SyscallResult::Send {
                            target,
                            msg_ptr,
                            msg_len,
                        } => {
                            // Read payload from guest memory
                            let len = msg_len as usize;
                            let mut payload = vec![0u8; len];
                            for (i, byte) in payload.iter_mut().enumerate() {
                                *byte = actor
                                    .pvm
                                    .read_u8(msg_ptr as u32 + i as u32)
                                    .unwrap_or(0);
                            }
                            self.pending_sends.push(PendingSend {
                                from: id,
                                to: target,
                                msg: RawMsg::new(id, &payload),
                            });
                            actor.pvm.registers[7] = 0; // success
                        }
                        SyscallResult::Recv { buf_ptr, buf_len } => {
                            if let Some(msg) = actor.pending_msg.take() {
                                let data = &msg.data;
                                let copy_len = data.len().min(buf_len as usize);
                                for (i, &byte) in data[..copy_len].iter().enumerate() {
                                    actor.pvm.write_u8(buf_ptr as u32 + i as u32, byte);
                                }
                                actor.pvm.registers[7] = copy_len as u64;
                            } else {
                                // No message pending
                                actor.pvm.registers[7] = 0;
                            }
                        }
                    }
                    // Continue execution after handling the host-call
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

/// The message type for PVM actors: raw encoded bytes.
///
/// Format: `Header(sender, payload_len) ++ rkyv_payload`.
/// The rkyv payload contains the serialized message enum variant
/// (discriminant + fields). The Header carries the sender and length.
#[derive(Debug)]
pub struct RawMsg {
    pub data: Vec<u8>,
}

impl RawMsg {
    /// Build a RawMsg from a sender and rkyv-serialized payload bytes.
    pub fn new(sender: ActorId, payload: &[u8]) -> Self {
        let header = pvx_abi::msg::Header {
            sender,
            payload_len: payload.len() as u32,
        };
        let mut data = Vec::with_capacity(pvx_abi::msg::Header::SIZE + payload.len());
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(payload);
        Self { data }
    }

    /// Parse the header from the raw data.
    pub fn header(&self) -> Option<pvx_abi::msg::Header> {
        pvx_abi::msg::Header::from_bytes(&self.data)
    }

    /// Get the rkyv payload bytes (after the header).
    pub fn payload(&self) -> &[u8] {
        if self.data.len() > pvx_abi::msg::Header::SIZE {
            &self.data[pvx_abi::msg::Header::SIZE..]
        } else {
            &[]
        }
    }
}

impl Driver<RawMsg> for PvmDriver {
    fn init(&mut self, _id: ActorId) -> Status {
        // Return Pending → actor enters Suspended state.
        // The actual PVM program is loaded via spawn_blob() after spawn(),
        // and will start executing when the scheduler polls it.
        Status::Pending
    }

    fn handle(&mut self, id: ActorId, msg: &RawMsg) -> Status {
        let idx = (id.0 - 1) as usize;
        let actor = match &mut self.actors[idx] {
            Some(a) => a,
            None => return Status::Error,
        };

        // Store the message — the actor retrieves it via the Recv syscall.
        actor.pending_msg = Some(RawMsg {
            data: msg.data.clone(),
        });

        self.run_actor(id)
    }

    fn poll(&mut self, id: ActorId) -> Status {
        self.run_actor(id)
    }

    fn drop_actor(&mut self, id: ActorId) {
        let idx = (id.0 - 1) as usize;
        self.actors[idx] = None;
    }

    fn drain_sends(&mut self, mut route: impl FnMut(ActorId, RawMsg)) {
        for send in self.pending_sends.drain(..) {
            route(send.to, send.msg);
        }
    }
}

impl MemoryAccess for PvmDriver {
    fn read_guest(&self, actor: ActorId, ptr: i64, dst: &mut [u8]) -> usize {
        let idx = (actor.0 - 1) as usize;
        let pvm = match &self.actors[idx] {
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

    fn write_guest(&mut self, actor: ActorId, ptr: i64, src: &[u8]) -> usize {
        let idx = (actor.0 - 1) as usize;
        let pvm = match &mut self.actors[idx] {
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

