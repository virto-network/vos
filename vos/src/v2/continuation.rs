//! Portable nested-JAVM continuation format.
//!
//! Snapshots are taken only after the active backend has flushed registers,
//! gas, PC, and memory and while a protocol call is stopped at its boundary.
//! Restoring a snapshot injects exactly one result into the declared registers
//! and resumes after that boundary; it is never a PC-0 replay format.

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use super::identity::{ActorId, CallId, Hash, ProgramId};
use super::wire::{DecodeError, Decoder, Encoder, V2Wire};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmLifecycleV2 {
    Idle = 0,
    Running = 1,
    WaitingForReply = 2,
    Halted = 3,
    Faulted = 4,
}

impl VmLifecycleV2 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Running),
            2 => Ok(Self::WaitingForReply),
            3 => Ok(Self::Halted),
            4 => Ok(Self::Faulted),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryPageRefV2 {
    pub virtual_page: u32,
    pub hash: Hash,
}

/// Mutable capability state. Immutable code caps and the static layout are
/// recreated from the canonical PVM and verified against `program`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySnapshotV2 {
    Empty,
    Untyped {
        allocated_pages: u32,
        total_pages: u32,
    },
    Data {
        backing_offset: u32,
        page_count: u32,
        base_page: Option<u32>,
        writable: bool,
        mapped_bitmap: Vec<u8>,
    },
    Handle {
        vm: u16,
        generation: u16,
        max_gas: Option<u64>,
    },
    Callable {
        vm: u16,
        generation: u16,
        max_gas: Option<u64>,
    },
    Protocol {
        id: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSnapshotV2 {
    pub vm: u16,
    pub generation: u16,
    pub actor: ActorId,
    pub program: ProgramId,
    pub pc: u32,
    pub registers: [u64; 13],
    pub heap_base: u32,
    pub heap_top: u32,
    pub gas_remaining: u64,
    pub gas_charge_pending: bool,
    pub lifecycle: VmLifecycleV2,
    pub caller_vm: Option<u16>,
    pub entry_index: u32,
    pub capabilities: Vec<CapabilitySnapshotV2>,
    pub dirty_pages: Vec<MemoryPageRefV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProtocolCallV2 {
    pub vm: u16,
    pub capability_slot: u8,
    /// PC of the instruction after the protocol call. A restored VM resumes at
    /// this PC after result injection.
    pub resume_pc: u32,
    pub call_id: Option<CallId>,
    pub result_registers: [u8; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerSnapshotV2 {
    pub active_vm: u16,
    pub runnable: Vec<u16>,
    pub call_stack: Vec<(u16, u16)>,
    pub causal_call_chain: Vec<CallId>,
    pub await_ordinal: u64,
    pub logical_timeslot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationSnapshotV2 {
    pub snapshot_version: u16,
    pub jar_semantics: Hash,
    pub vos_abi: u16,
    pub vms: Vec<VmSnapshotV2>,
    pub scheduler: SchedulerSnapshotV2,
    pub pending_protocol_call: PendingProtocolCallV2,
}

/// Restored kernel state after exactly one awaited result has been injected.
/// It intentionally has no `pending_protocol_call`, so the same checkpoint
/// cannot receive a second result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumedKernelV2 {
    pub vms: Vec<VmSnapshotV2>,
    pub scheduler: SchedulerSnapshotV2,
    pub resumed_call: Option<CallId>,
}

impl ContinuationSnapshotV2 {
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/continuation/v2", &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.snapshot_version != super::SNAPSHOT_VERSION
            || self.vos_abi != super::ABI_VERSION
            || self.jar_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(DecodeError::InvalidVersion);
        }
        if self.vms.is_empty() || self.vms.windows(2).any(|pair| pair[0].vm >= pair[1].vm) {
            return Err(DecodeError::NonCanonical);
        }
        let active = self
            .vms
            .iter()
            .find(|vm| vm.vm == self.scheduler.active_vm)
            .ok_or(DecodeError::NonCanonical)?;
        if active.vm != self.pending_protocol_call.vm
            || active.pc != self.pending_protocol_call.resume_pc
            || self.pending_protocol_call.result_registers[0]
                == self.pending_protocol_call.result_registers[1]
            || self
                .pending_protocol_call
                .result_registers
                .iter()
                .any(|&register| register >= 13)
        {
            return Err(DecodeError::NonCanonical);
        }
        for vm in &self.vms {
            if vm
                .dirty_pages
                .windows(2)
                .any(|pair| pair[0].virtual_page >= pair[1].virtual_page)
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(())
    }

    /// Consume a durable checkpoint and inject the one protocol result the
    /// suspended instruction is waiting for. Registers not named by the
    /// checkpoint, stack VMs, capabilities, gas, and dirty pages are preserved
    /// byte-for-byte.
    pub fn inject_resume(self, result: [u64; 2]) -> Result<ResumedKernelV2, DecodeError> {
        self.validate()?;
        let pending = self.pending_protocol_call;
        let mut vms = self.vms;
        let vm = vms
            .iter_mut()
            .find(|vm| vm.vm == pending.vm)
            .ok_or(DecodeError::NonCanonical)?;
        vm.registers[pending.result_registers[0] as usize] = result[0];
        vm.registers[pending.result_registers[1] as usize] = result[1];
        vm.pc = pending.resume_pc;
        vm.lifecycle = VmLifecycleV2::Running;
        Ok(ResumedKernelV2 {
            vms,
            scheduler: self.scheduler,
            resumed_call: pending.call_id,
        })
    }
}

impl V2Wire for ContinuationSnapshotV2 {
    const MAGIC: [u8; 4] = *b"VCS2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.u16(self.snapshot_version);
        e.fixed(&self.jar_semantics.0);
        e.u16(self.vos_abi);
        e.list(&self.vms, encode_vm);
        encode_scheduler(&mut e, &self.scheduler);
        encode_pending(&mut e, &self.pending_protocol_call);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            snapshot_version: d.u16()?,
            jar_semantics: Hash(d.fixed()?),
            vos_abi: d.u16()?,
            vms: d.list(decode_vm)?,
            scheduler: decode_scheduler(d)?,
            pending_protocol_call: decode_pending(d)?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn encode_vm(e: &mut Encoder<'_>, vm: &VmSnapshotV2) {
    e.u16(vm.vm);
    e.u16(vm.generation);
    e.fixed(&vm.actor.0);
    e.fixed(&vm.program.0);
    e.u32(vm.pc);
    for register in vm.registers {
        e.u64(register);
    }
    e.u32(vm.heap_base);
    e.u32(vm.heap_top);
    e.u64(vm.gas_remaining);
    e.bool(vm.gas_charge_pending);
    e.u8(vm.lifecycle as u8);
    e.option(&vm.caller_vm, |e, caller| e.u16(*caller));
    e.u32(vm.entry_index);
    e.list(&vm.capabilities, encode_capability);
    e.list(&vm.dirty_pages, |e, page| {
        e.u32(page.virtual_page);
        e.fixed(&page.hash.0);
    });
}

fn decode_vm(d: &mut Decoder<'_>) -> Result<VmSnapshotV2, DecodeError> {
    let vm = d.u16()?;
    let generation = d.u16()?;
    let actor = ActorId(d.fixed()?);
    let program = ProgramId(d.fixed()?);
    let pc = d.u32()?;
    let mut registers = [0u64; 13];
    for register in &mut registers {
        *register = d.u64()?;
    }
    Ok(VmSnapshotV2 {
        vm,
        generation,
        actor,
        program,
        pc,
        registers,
        heap_base: d.u32()?,
        heap_top: d.u32()?,
        gas_remaining: d.u64()?,
        gas_charge_pending: d.bool()?,
        lifecycle: VmLifecycleV2::decode(d)?,
        caller_vm: d.option(Decoder::u16)?,
        entry_index: d.u32()?,
        capabilities: d.list(decode_capability)?,
        dirty_pages: d.list(|d| {
            Ok(MemoryPageRefV2 {
                virtual_page: d.u32()?,
                hash: Hash(d.fixed()?),
            })
        })?,
    })
}

fn encode_capability(e: &mut Encoder<'_>, cap: &CapabilitySnapshotV2) {
    match cap {
        CapabilitySnapshotV2::Empty => e.u8(0),
        CapabilitySnapshotV2::Untyped {
            allocated_pages,
            total_pages,
        } => {
            e.u8(1);
            e.u32(*allocated_pages);
            e.u32(*total_pages);
        }
        CapabilitySnapshotV2::Data {
            backing_offset,
            page_count,
            base_page,
            writable,
            mapped_bitmap,
        } => {
            e.u8(2);
            e.u32(*backing_offset);
            e.u32(*page_count);
            e.option(base_page, |e, page| e.u32(*page));
            e.bool(*writable);
            e.bytes(mapped_bitmap);
        }
        CapabilitySnapshotV2::Handle {
            vm,
            generation,
            max_gas,
        } => {
            e.u8(3);
            e.u16(*vm);
            e.u16(*generation);
            e.option(max_gas, |e, gas| e.u64(*gas));
        }
        CapabilitySnapshotV2::Callable {
            vm,
            generation,
            max_gas,
        } => {
            e.u8(4);
            e.u16(*vm);
            e.u16(*generation);
            e.option(max_gas, |e, gas| e.u64(*gas));
        }
        CapabilitySnapshotV2::Protocol { id } => {
            e.u8(5);
            e.u8(*id);
        }
    }
}

fn decode_capability(d: &mut Decoder<'_>) -> Result<CapabilitySnapshotV2, DecodeError> {
    match d.u8()? {
        0 => Ok(CapabilitySnapshotV2::Empty),
        1 => {
            let allocated_pages = d.u32()?;
            let total_pages = d.u32()?;
            if allocated_pages > total_pages {
                return Err(DecodeError::NonCanonical);
            }
            Ok(CapabilitySnapshotV2::Untyped {
                allocated_pages,
                total_pages,
            })
        }
        2 => {
            let backing_offset = d.u32()?;
            let page_count = d.u32()?;
            let base_page = d.option(Decoder::u32)?;
            let writable = d.bool()?;
            let mapped_bitmap = d.bytes()?;
            if mapped_bitmap.len() != (page_count as usize).div_ceil(8) {
                return Err(DecodeError::NonCanonical);
            }
            Ok(CapabilitySnapshotV2::Data {
                backing_offset,
                page_count,
                base_page,
                writable,
                mapped_bitmap,
            })
        }
        3 => Ok(CapabilitySnapshotV2::Handle {
            vm: d.u16()?,
            generation: d.u16()?,
            max_gas: d.option(Decoder::u64)?,
        }),
        4 => Ok(CapabilitySnapshotV2::Callable {
            vm: d.u16()?,
            generation: d.u16()?,
            max_gas: d.option(Decoder::u64)?,
        }),
        5 => Ok(CapabilitySnapshotV2::Protocol { id: d.u8()? }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_scheduler(e: &mut Encoder<'_>, scheduler: &SchedulerSnapshotV2) {
    e.u16(scheduler.active_vm);
    e.list(&scheduler.runnable, |e, vm| e.u16(*vm));
    e.list(&scheduler.call_stack, |e, (caller, callee)| {
        e.u16(*caller);
        e.u16(*callee);
    });
    e.list(&scheduler.causal_call_chain, |e, id| e.fixed(&id.0));
    e.u64(scheduler.await_ordinal);
    e.u64(scheduler.logical_timeslot);
}

fn decode_scheduler(d: &mut Decoder<'_>) -> Result<SchedulerSnapshotV2, DecodeError> {
    Ok(SchedulerSnapshotV2 {
        active_vm: d.u16()?,
        runnable: d.list(Decoder::u16)?,
        call_stack: d.list(|d| Ok((d.u16()?, d.u16()?)))?,
        causal_call_chain: d.list(|d| d.fixed().map(CallId))?,
        await_ordinal: d.u64()?,
        logical_timeslot: d.u64()?,
    })
}

fn encode_pending(e: &mut Encoder<'_>, pending: &PendingProtocolCallV2) {
    e.u16(pending.vm);
    e.u8(pending.capability_slot);
    e.u32(pending.resume_pc);
    e.option(&pending.call_id, |e, id| e.fixed(&id.0));
    e.u8(pending.result_registers[0]);
    e.u8(pending.result_registers[1]);
}

fn decode_pending(d: &mut Decoder<'_>) -> Result<PendingProtocolCallV2, DecodeError> {
    Ok(PendingProtocolCallV2 {
        vm: d.u16()?,
        capability_slot: d.u8()?,
        resume_pc: d.u32()?,
        call_id: d.option(|d| d.fixed().map(CallId))?,
        result_registers: [d.u8()?, d.u8()?],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ContinuationSnapshotV2 {
        ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            vms: vec![VmSnapshotV2 {
                vm: 0,
                generation: 0,
                actor: ActorId([1; 32]),
                program: ProgramId([2; 32]),
                pc: 44,
                registers: [9; 13],
                heap_base: 4096,
                heap_top: 8192,
                gas_remaining: 99,
                gas_charge_pending: false,
                lifecycle: VmLifecycleV2::Running,
                caller_vm: None,
                entry_index: 0,
                capabilities: vec![CapabilitySnapshotV2::Protocol { id: 7 }],
                dirty_pages: vec![MemoryPageRefV2 {
                    virtual_page: 1,
                    hash: Hash([3; 32]),
                }],
            }],
            scheduler: SchedulerSnapshotV2 {
                active_vm: 0,
                runnable: vec![],
                call_stack: vec![],
                causal_call_chain: vec![],
                await_ordinal: 1,
                logical_timeslot: 10,
            },
            pending_protocol_call: PendingProtocolCallV2 {
                vm: 0,
                capability_slot: 7,
                resume_pc: 44,
                call_id: Some(CallId([4; 32])),
                result_registers: [7, 8],
            },
        }
    }

    #[test]
    fn exact_machine_snapshot_roundtrips() {
        let value = snapshot();
        let decoded = ContinuationSnapshotV2::decode(&value.encode()).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.vms[0].pc, 44);
        assert_eq!(decoded.vms[0].registers, [9; 13]);
        assert_eq!(decoded.pending_protocol_call.resume_pc, 44);
    }

    #[test]
    fn rejects_pc_zero_style_mismatch() {
        let mut value = snapshot();
        value.pending_protocol_call.resume_pc = 0;
        assert_eq!(value.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn resume_injects_once_without_replaying_or_losing_locals() {
        let mut value = snapshot();
        value.vms[0].lifecycle = VmLifecycleV2::WaitingForReply;
        value.vms[0].registers[3] = 0xfeed;
        let resumed = value.inject_resume([20, 0]).unwrap();
        let vm = &resumed.vms[0];
        assert_eq!(vm.pc, 44, "execution continues after the call boundary");
        assert_eq!(vm.registers[7], 20);
        assert_eq!(vm.registers[8], 0);
        assert_eq!(vm.registers[3], 0xfeed, "stack-local register survives");
        assert_eq!(resumed.resumed_call, Some(CallId([4; 32])));
    }
}
