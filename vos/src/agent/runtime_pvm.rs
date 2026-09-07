//! Narrow host boundary for one AgentRuntime PVM execution.
//!
//! This module owns only the physical load/run/output/decode sequence. Callers
//! remain responsible for authenticating the program and input, selecting the
//! gas budget, and validating the returned transition against durable state.

use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, Gas};

use crate::agent_sdk::wire::CanonicalWire as AgentCanonicalWire;
use crate::service::wire::ServiceWire;

/// Exact physical failure boundary for one host-side AgentRuntime execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuntimePvmExecutionError {
    /// The authenticated bytes could not be loaded as a standard PVM.
    Load,
    /// The program ran but did not reach the canonical halt boundary.
    Exit { reason: ExitReason, pc: u32 },
    /// A halted program designated an unreadable output range.
    MissingOutput,
    /// The halted output was not the requested strict wire type.
    Decode,
}

impl core::fmt::Display for RuntimePvmExecutionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent runtime PVM execution: {self:?}")
    }
}

impl std::error::Error for RuntimePvmExecutionError {}

/// Execute one runtime call and decode the transitional service wire exactly.
pub(crate) fn execute_service_wire<T: ServiceWire>(
    runtime_pvm: &[u8],
    gas: Gas,
    input: &[u8],
) -> Result<T, RuntimePvmExecutionError> {
    let output = execute_to_halted_output(runtime_pvm, gas, input)?;
    T::decode(&output).map_err(|_| RuntimePvmExecutionError::Decode)
}

/// Execute one runtime call and decode the clean SDK canonical wire exactly.
pub(crate) fn execute_canonical_wire<T: AgentCanonicalWire>(
    runtime_pvm: &[u8],
    gas: Gas,
    input: &[u8],
) -> Result<T, RuntimePvmExecutionError> {
    let output = execute_to_halted_output(runtime_pvm, gas, input)?;
    T::decode(&output).map_err(|_| RuntimePvmExecutionError::Decode)
}

fn execute_to_halted_output(
    runtime_pvm: &[u8],
    gas: Gas,
    input: &[u8],
) -> Result<Vec<u8>, RuntimePvmExecutionError> {
    let invocation = RefineContext::load(runtime_pvm, input, gas)
        .map_err(|_| RuntimePvmExecutionError::Load)?
        .run();
    if invocation.exit != ExitReason::Halt {
        return Err(RuntimePvmExecutionError::Exit {
            reason: invocation.exit,
            pc: invocation.pc,
        });
    }
    invocation
        .output()
        .ok_or(RuntimePvmExecutionError::MissingOutput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use crate::agent::LifecycleError;
    use crate::agent::wire::RuntimeReturn;
    use crate::agent_sdk::{ManagementError, RuntimeOutcome, RuntimeState, RuntimeTransition};

    const TEST_GAS: Gas = 1_000_000;

    fn returning_program(output: &[u8]) -> Vec<u8> {
        let mut assembler = Assembler::new();
        assembler.set_rw_data(output.to_vec());
        let output_address = 2_u64 * u64::from(vos_pvm::PVM_ZONE_SIZE);
        assembler
            .load_imm_64(Reg::A0, output_address)
            .load_imm_64(Reg::A1, output.len() as u64)
            .jump_ind(Reg::RA, 0);
        assembler.build_standard()
    }

    #[test]
    fn halted_output_decodes_both_runtime_wire_generations() {
        let service = RuntimeReturn {
            state: crate::agent::wire::RuntimeState::default(),
            result: Err(LifecycleError::NotCreated),
        };
        let service_bytes = service.encode();
        assert_eq!(
            execute_service_wire::<RuntimeReturn>(
                &returning_program(&service_bytes),
                TEST_GAS,
                b"service input",
            ),
            Ok(service)
        );

        let canonical = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Management(Err(ManagementError::NotCreated)),
        };
        let canonical_bytes = canonical.encode().unwrap();
        assert_eq!(
            execute_canonical_wire::<RuntimeTransition>(
                &returning_program(&canonical_bytes),
                TEST_GAS,
                b"canonical input",
            ),
            Ok(canonical)
        );
    }

    #[test]
    fn load_and_non_halt_failures_are_distinct() {
        assert_eq!(
            execute_service_wire::<RuntimeReturn>(&[], TEST_GAS, &[]),
            Err(RuntimePvmExecutionError::Load)
        );

        let mut assembler = Assembler::new();
        assembler.trap();
        assert_eq!(
            execute_service_wire::<RuntimeReturn>(&assembler.build_standard(), TEST_GAS, &[]),
            Err(RuntimePvmExecutionError::Exit {
                reason: ExitReason::Panic,
                pc: 0,
            })
        );
    }

    #[test]
    fn halted_unreadable_output_is_not_a_decode_failure() {
        let mut assembler = Assembler::new();
        assembler
            .load_imm_64(Reg::A0, u64::MAX)
            .load_imm_64(Reg::A1, 1)
            .jump_ind(Reg::RA, 0);
        assert_eq!(
            execute_service_wire::<RuntimeReturn>(&assembler.build_standard(), TEST_GAS, &[]),
            Err(RuntimePvmExecutionError::MissingOutput)
        );
    }

    #[test]
    fn malformed_halted_output_is_a_decode_failure_for_each_wire() {
        let program = returning_program(&[0xff]);
        assert_eq!(
            execute_service_wire::<RuntimeReturn>(&program, TEST_GAS, &[]),
            Err(RuntimePvmExecutionError::Decode)
        );
        assert_eq!(
            execute_canonical_wire::<RuntimeTransition>(&program, TEST_GAS, &[]),
            Err(RuntimePvmExecutionError::Decode)
        );
    }
}
