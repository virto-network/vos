//! Local driver for the protocol-pinned generic VOS service PVM.
//!
//! This is a conformance boundary, not a native implementation of Refine.
//! The transition bytes are produced by the service program itself. During
//! Refine the host surface is read-only and persistent JAM protocol calls are
//! rejected before a handler can observe them.

use alloc::vec::Vec;

use javm::cap::{Cap, ProtocolCap};
use javm::kernel::{InvocationKernel, KernelResult};
use javm::program::{CapEntryType, cap_data, parse_blob, parse_code_blob};

use super::{ProgramId, REFINE_ENTRY_IC};

/// Result of one completed service-PVM execution slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePvmOutputV2 {
    pub bytes: Vec<u8>,
    pub gas_used: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePvmErrorV2 {
    InvalidProgram,
    ProgramIdMismatch,
    InvalidServiceEntries,
    Panic,
    OutOfGas,
    PageFault(u32),
    UnreadableOutput,
    ForbiddenRefineProtocolCall(u8),
    RefineHostRejected(u8),
    InvalidProtocolResume,
}

impl core::fmt::Display for ServicePvmErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS service PVM failed: {self:?}")
    }
}

impl core::error::Error for ServicePvmErrorV2 {}

/// Read-only import/cache host exposed while the service PVM is refining.
///
/// The receiver is immutable by design. Implementations provide imported work
/// data, canonical code, content-addressed blobs, or deterministic compilation
/// products. Persistent service state is deliberately absent from this API.
pub trait RefineProtocolHostV2 {
    fn handle(
        &self,
        slot: u8,
        registers: &[u64; 13],
        kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2>;
}

/// Host used by pure service programs that need no protocol imports.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRefineProtocolHostV2;

impl RefineProtocolHostV2 for NoRefineProtocolHostV2 {
    fn handle(
        &self,
        slot: u8,
        _registers: &[u64; 13],
        _kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        Err(ServicePvmErrorV2::RefineHostRejected(slot))
    }
}

/// Canonical generic-service program plus its verified identity.
pub struct ServicePvmV2 {
    program: Vec<u8>,
    program_id: ProgramId,
}

impl ServicePvmV2 {
    pub fn new(program: Vec<u8>, expected: ProgramId) -> Result<Self, ServicePvmErrorV2> {
        validate_service_entries(&program)?;
        let actual = ProgramId::of_pvm(&program);
        if actual != expected {
            return Err(ServicePvmErrorV2::ProgramIdMismatch);
        }
        Ok(Self {
            program,
            program_id: actual,
        })
    }

    pub const fn program_id(&self) -> ProgramId {
        self.program_id
    }

    /// Execute the physical IC-0 Refine entry.
    ///
    /// Identical program bytes, arguments, gas, and import-host responses reach
    /// the same PVM path. No mutable service store is passed to this function.
    pub fn refine<H: RefineProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &H,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        let mut kernel = InvocationKernel::new(&self.program, arguments, gas_limit)
            .map_err(|_| ServicePvmErrorV2::InvalidProgram)?;
        install_refine_scheduler_caps(&mut kernel);
        kernel.set_entry_ic(REFINE_ENTRY_IC);

        loop {
            match kernel.run() {
                KernelResult::Halt => {
                    let bytes = read_output(&kernel)?;
                    return Ok(ServicePvmOutputV2 {
                        bytes,
                        gas_used: gas_limit.saturating_sub(kernel.active_gas()),
                    });
                }
                KernelResult::Panic => return Err(ServicePvmErrorV2::Panic),
                KernelResult::OutOfGas => return Err(ServicePvmErrorV2::OutOfGas),
                KernelResult::PageFault(address) => {
                    return Err(ServicePvmErrorV2::PageFault(address));
                }
                KernelResult::ProtocolCall { slot } => {
                    if !refine_protocol_call_is_pure(slot) {
                        return Err(ServicePvmErrorV2::ForbiddenRefineProtocolCall(slot));
                    }
                    let mut registers = [0; 13];
                    for (index, register) in registers.iter_mut().enumerate() {
                        *register = kernel.active_reg(index);
                    }
                    let [result0, result1] = host.handle(slot, &registers, &mut kernel)?;
                    kernel
                        .resume_protocol_call(result0, result1)
                        .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                }
            }
        }
    }
}

fn install_refine_scheduler_caps(kernel: &mut InvocationKernel) {
    // These are VOS scheduler capabilities, not JAM protocol slots. The
    // nondeterministic BOOT_CONTEXT/NOW_MS seams are intentionally absent from
    // v2 Refine.
    for slot in [
        crate::abi::hostcall::GROW_HEAP as u8,
        crate::abi::hostcall::DEBUG_WRITE as u8,
        crate::abi::hostcall::INVOKE as u8,
        crate::abi::hostcall::SUSPEND as u8,
    ] {
        kernel
            .vm_arena
            .vm_mut(kernel.active_vm)
            .cap_table
            .set(slot, Cap::Protocol(ProtocolCap { id: slot }));
    }
}

fn validate_service_entries(program: &[u8]) -> Result<(), ServicePvmErrorV2> {
    let parsed = parse_blob(program).ok_or(ServicePvmErrorV2::InvalidProgram)?;
    let code_cap = parsed
        .caps
        .iter()
        .find(|cap| cap.cap_index == parsed.header.invoke_cap && cap.cap_type == CapEntryType::Code)
        .ok_or(ServicePvmErrorV2::InvalidProgram)?;
    let code = parse_code_blob(cap_data(code_cap, parsed.data_section))
        .ok_or(ServicePvmErrorV2::InvalidProgram)?;

    // The transpiler emits one five-byte GP jump at IC 0 and another at IC 5.
    // Requiring both prevents an actor/refine-only blob (whose second entry is
    // a trap) from being installed as infrastructure by mistake.
    if code.code.get(REFINE_ENTRY_IC as usize) != Some(&40)
        || code.code.get(super::ACCUMULATE_ENTRY_IC as usize) != Some(&40)
        || code.bitmask.get(REFINE_ENTRY_IC as usize) != Some(&1)
        || code.bitmask.get(super::ACCUMULATE_ENTRY_IC as usize) != Some(&1)
    {
        return Err(ServicePvmErrorV2::InvalidServiceEntries);
    }
    Ok(())
}

fn read_output(kernel: &InvocationKernel) -> Result<Vec<u8>, ServicePvmErrorV2> {
    let address =
        u32::try_from(kernel.active_reg(7)).map_err(|_| ServicePvmErrorV2::UnreadableOutput)?;
    let len =
        u32::try_from(kernel.active_reg(8)).map_err(|_| ServicePvmErrorV2::UnreadableOutput)?;
    kernel
        .read_data_cap_window(address, len)
        .ok_or(ServicePvmErrorV2::UnreadableOutput)
}

/// Protocol capabilities that can be implemented without access to mutable
/// service state. Every state-changing JAM capability (including storage
/// writes, transfers, service management, output publication, and preimage
/// provision) is absent from this list.
fn refine_protocol_call_is_pure(slot: u8) -> bool {
    matches!(
        slot as u32,
        crate::abi::hostcall::GAS
            | crate::abi::hostcall::FETCH
            | crate::abi::hostcall::COMPILE
            | crate::abi::hostcall::PREIMAGE_LOOKUP
            | crate::abi::hostcall::GROW_HEAP
            | crate::abi::hostcall::DEBUG_WRITE
            | crate::abi::hostcall::INVOKE
            | crate::abi::hostcall::SUSPEND
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_transpiler::assembler::Reg;

    fn emit_instruction(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, bytes: &[u8]) {
        code.extend_from_slice(bytes);
        bitmask.push(1);
        bitmask.resize(code.len(), 0);
    }

    fn emit_halt(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
        let mut load = vec![20, Reg::T0 as u8];
        load.extend_from_slice(&(javm::PVM_HALT_ADDR as u64).to_le_bytes());
        emit_instruction(code, bitmask, &load);
        let mut jump = vec![50, Reg::T0 as u8];
        jump.extend_from_slice(&0u32.to_le_bytes());
        emit_instruction(code, bitmask, &jump);
    }

    fn two_entry_program(refine_call: Option<u32>) -> Vec<u8> {
        let mut code = vec![40, 0, 0, 0, 0, 40, 0, 0, 0, 0];
        let mut bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0];

        let refine_body = code.len();
        if let Some(slot) = refine_call {
            let mut call = vec![10];
            call.extend_from_slice(&slot.to_le_bytes());
            emit_instruction(&mut code, &mut bitmask, &call);
        }
        emit_halt(&mut code, &mut bitmask);

        let accumulate_body = code.len();
        emit_halt(&mut code, &mut bitmask);

        code[1..5].copy_from_slice(&(refine_body as i32).to_le_bytes());
        code[6..10].copy_from_slice(&((accumulate_body as i32) - 5).to_le_bytes());

        grey_transpiler::emitter::build_service_program(&code, &bitmask, &[], &[], &[], 1, 0, 4)
    }

    #[test]
    fn physical_refine_entry_is_deterministic_and_uses_gp_arguments() {
        let program = two_entry_program(None);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let first = service
            .refine(b"work-envelope", 1_000_000, &NoRefineProtocolHostV2)
            .unwrap();
        let second = service
            .refine(b"work-envelope", 1_000_000, &NoRefineProtocolHostV2)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.bytes, b"work-envelope");
    }

    #[test]
    fn refine_rejects_persistent_protocol_calls_before_host_dispatch() {
        let program = two_entry_program(Some(crate::abi::hostcall::STORAGE_W));
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        assert_eq!(
            service.refine(&[], 1_000_000, &NoRefineProtocolHostV2),
            Err(ServicePvmErrorV2::ForbiddenRefineProtocolCall(
                crate::abi::hostcall::STORAGE_W as u8,
            ))
        );
    }

    #[test]
    fn service_identity_and_both_physical_entries_are_mandatory() {
        let program = two_entry_program(None);
        assert!(matches!(
            ServicePvmV2::new(program.clone(), ProgramId([0; 32])),
            Err(ServicePvmErrorV2::ProgramIdMismatch)
        ));

        let actor = grey_transpiler::assembler::Assembler::new().build();
        assert!(matches!(
            ServicePvmV2::new(actor.clone(), ProgramId::of_pvm(&actor)),
            Err(ServicePvmErrorV2::InvalidServiceEntries)
        ));
    }
}
