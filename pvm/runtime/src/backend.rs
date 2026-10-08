//! PVM backend selection — interpreter or recompiler.
//!
//! The kernel creates CODE caps that wrap compiled code in one of two backends.
//! `PvmBackend` controls the selection; `CompiledProgram` holds the result.

use alloc::{string::String, sync::Arc, vec, vec::Vec};

/// Backend selection for PVM execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PvmBackend {
    /// Use recompiler if available (x86-64 Linux), else interpreter.
    /// Reads `GREY_PVM` env var: "interpreter" forces interpreter,
    /// "recompiler" forces recompiler.
    Default,
    /// Always use the software interpreter.
    ForceInterpreter,
    /// Always use the JIT recompiler (returns an error if unavailable).
    ForceRecompiler,
}

/// Pre-decoded interpreter program state.
///
/// Contains the instruction stream pre-decoded for the fast interpreter path.
/// Created by `Interpreter::predecode()` and stored in a `CodeCap`.
#[derive(Clone)]
pub struct InterpreterProgram {
    /// Pre-decoded instruction stream.
    pub decoded_insts: Vec<crate::interpreter::DecodedInst>,
    /// PC byte offset → instruction index mapping.
    pub pc_to_idx: Vec<u32>,
    /// Valid branch/jump landing targets.
    pub basic_block_starts: Vec<bool>,
    /// Per-gas-block costs (indexed by block start PC).
    pub block_gas_costs: Vec<u32>,
    /// For every externally enterable PC, the start of the gas block that
    /// contains it (`u32::MAX` for non-instruction byte positions).
    pub gas_block_start_by_pc: Vec<u32>,
    /// Instruction bytecode (kept for step/trace fallback).
    pub code: Vec<u8>,
    /// Opcode bitmask.
    pub bitmask: Vec<u8>,
    /// Dynamic jump table.
    pub jump_table: Vec<u32>,
    /// Memory tier cycles.
    pub mem_cycles: u8,
}

/// Compiled PVM program — either interpreter or recompiler backend.
pub enum CompiledProgram {
    /// Software interpreter with pre-decoded instructions.
    Interpreter(InterpreterProgram),
    /// JIT-compiled native x86-64 code.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    Recompiler(crate::recompiler::CompiledCode),
}

impl core::fmt::Debug for CompiledProgram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Interpreter(p) => f
                .debug_struct("Interpreter")
                .field("insts", &p.decoded_insts.len())
                .finish(),
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            Self::Recompiler(c) => f
                .debug_struct("Recompiler")
                .field("native_len", &c.native_code.len)
                .finish(),
        }
    }
}

/// Resolve the backend to use based on `PvmBackend` selection and platform.
fn resolve_backend(backend: PvmBackend) -> Result<ResolvedBackend, String> {
    match backend {
        PvmBackend::ForceInterpreter => Ok(ResolvedBackend::Interpreter),
        PvmBackend::ForceRecompiler => {
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            return Ok(ResolvedBackend::Recompiler);
            #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
            return Err("requested recompiler is unavailable on this platform".into());
        }
        PvmBackend::Default => {
            // Check GREY_PVM env var
            #[cfg(feature = "std")]
            {
                if let Ok(val) = std::env::var("GREY_PVM") {
                    match val.as_str() {
                        "interpreter" => return Ok(ResolvedBackend::Interpreter),
                        "recompiler" => {
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            return Ok(ResolvedBackend::Recompiler);
                            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                            return Err(
                                "GREY_PVM=recompiler is unavailable on this platform".into()
                            );
                        }
                        _ => {} // fall through to platform default
                    }
                }
            }
            // Platform default: recompiler if available
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            return Ok(ResolvedBackend::Recompiler);
            #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
            return Ok(ResolvedBackend::Interpreter);
        }
    }
}

enum ResolvedBackend {
    Interpreter,
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    Recompiler,
}

/// Compile PVM code into a `CompiledProgram` using the selected backend.
pub fn compile(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    mem_cycles: u8,
    backend: PvmBackend,
    isa_mode: crate::IsaMode,
) -> Result<CompiledProgram, alloc::string::String> {
    let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);
    match resolve_backend(backend)? {
        ResolvedBackend::Interpreter => {
            // Bind the decoder and block boundaries to the selected ISA at
            // compile time; execution still carries the same mode so opcode
            // dispatch cannot cross the standard/runtime boundary.
            let prog = crate::interpreter::Interpreter::predecode(
                code, bitmask, jump_table, mem_cycles, isa_mode,
            );
            Ok(CompiledProgram::Interpreter(prog))
        }
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        ResolvedBackend::Recompiler => {
            let compiled =
                crate::recompiler::compile_code(code, bitmask, jump_table, mem_cycles, isa_mode)?;
            Ok(CompiledProgram::Recompiler(compiled))
        }
    }
}

/// Immutable, profile-bound preparation shared by standard outer and inner
/// execution. It owns no invocation memory and introduces no global cache.
#[derive(Clone)]
pub(crate) struct PreparedExecution {
    interpreter: Arc<InterpreterProgram>,
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    native: Option<Arc<crate::recompiler::CompiledCode>>,
}

impl PreparedExecution {
    pub(crate) fn new_standard(
        code: &[u8],
        bitmask: &[u8],
        jump_table: &[u32],
        backend: PvmBackend,
    ) -> Result<Self, String> {
        let compiled = compile(
            code,
            bitmask,
            jump_table,
            crate::STANDARD_MEM_CYCLES,
            backend,
            crate::IsaMode::Conformance,
        )?;
        Ok(match compiled {
            CompiledProgram::Interpreter(interpreter) => Self {
                interpreter: Arc::new(interpreter),
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                native: None,
            },
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            CompiledProgram::Recompiler(native) => Self {
                interpreter: Arc::new(crate::Interpreter::predecode(
                    code,
                    bitmask,
                    jump_table,
                    crate::STANDARD_MEM_CYCLES,
                    crate::IsaMode::Conformance,
                )),
                native: Some(Arc::new(native)),
            },
        })
    }

    pub(crate) fn backend(&self) -> PvmBackend {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if self.native.is_some() {
            return PvmBackend::ForceRecompiler;
        }
        PvmBackend::ForceInterpreter
    }

    pub(crate) fn interpreter_program(&self) -> &InterpreterProgram {
        &self.interpreter
    }

    pub(crate) fn allocate_memory(
        &self,
        span: u64,
        sparse: bool,
    ) -> Result<crate::interpreter::Memory, String> {
        if span > 1u64 << 32 || !span.is_multiple_of(crate::PVM_PAGE_SIZE as u64) {
            return Err("invalid standard memory span".into());
        }
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if self.native.is_some() {
            if sparse {
                return Err("recompiler requires native flat memory".into());
            }
            return crate::interpreter::Memory::native(span);
        }
        Ok(if sparse {
            crate::interpreter::Memory::sparse(span)
        } else {
            if span > isize::MAX as u64 {
                return Err("flat memory span exceeds host address space".into());
            }
            crate::interpreter::Memory::flat(vec![0; span as usize])
        })
    }

    /// Execute exactly one slice, preserving an unacknowledged host boundary.
    /// Backend/host failures are not guest exits and never trigger a retry on
    /// the interpreter. The caller alone decides when to acknowledge a hostcall.
    pub(crate) fn run(
        &self,
        interpreter: &mut crate::Interpreter,
    ) -> Result<crate::ExitReason, String> {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(native) = &self.native {
            return crate::recompiler::run_standard(native, interpreter);
        }
        Ok(interpreter.run().0)
    }
}

#[cfg(all(
    test,
    not(all(feature = "std", target_os = "linux", target_arch = "x86_64"))
))]
mod tests {
    use super::*;

    #[test]
    fn unavailable_recompiler_is_an_error_not_an_interpreter_fallback() {
        assert!(
            PreparedExecution::new_standard(&[0], &[1], &[], PvmBackend::ForceRecompiler).is_err()
        );
    }
}
