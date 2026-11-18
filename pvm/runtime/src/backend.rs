//! PVM backend selection — interpreter or recompiler.
//!
//! The kernel creates CODE caps that wrap compiled code in one of two backends.
//! `PvmBackend` controls the selection; `CompiledProgram` holds the result.

use alloc::{string::String, sync::Arc};

/// Backend selection for PVM execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PvmBackend {
    /// Use recompiler if available (x86-64 Linux), else interpreter.
    /// Reads `VOS_PVM_BACKEND` env var: "interpreter" forces interpreter,
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
/// Created by `Interpreter::predecode()`. Every table is shared: each
/// machine loaded from it holds the same tables, so a load copies none.
#[derive(Clone)]
pub struct InterpreterProgram {
    /// Pre-decoded instruction stream.
    pub decoded_insts: Arc<[crate::interpreter::DecodedInst]>,
    /// PC byte offset → instruction index mapping.
    pub pc_to_idx: Arc<[u32]>,
    /// Valid branch/jump landing targets.
    pub basic_block_starts: Arc<[bool]>,
    /// Per-gas-block costs (indexed by block start PC).
    pub block_gas_costs: Arc<[u32]>,
    /// For every externally enterable PC, the start of the gas block that
    /// contains it (`u32::MAX` for non-instruction byte positions).
    pub gas_block_start_by_pc: Arc<[u32]>,
    /// Instruction bytecode (kept for step/trace fallback).
    pub code: Arc<[u8]>,
    /// Opcode bitmask.
    pub bitmask: Arc<[u8]>,
    /// Dynamic jump table.
    pub jump_table: Arc<[u32]>,
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
            // Check VOS_PVM_BACKEND env var
            #[cfg(feature = "std")]
            {
                if let Ok(val) = std::env::var("VOS_PVM_BACKEND") {
                    match val.as_str() {
                        "interpreter" => return Ok(ResolvedBackend::Interpreter),
                        "recompiler" => {
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            return Ok(ResolvedBackend::Recompiler);
                            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                            return Err(
                                "VOS_PVM_BACKEND=recompiler is unavailable on this platform".into(),
                            );
                        }
                        _ => {} // fall through to platform default
                    }
                }
            }
            // Platform default: the recompiler where the host can track its
            // guest writes, otherwise the interpreter.
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            return Ok(if crate::recompiler::write_tracking::available() {
                ResolvedBackend::Recompiler
            } else {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        "the recompiler needs userfaultfd write-protect (Linux 6.7 or later); \
                         using the interpreter"
                    )
                });
                ResolvedBackend::Interpreter
            });
            #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
            return Ok(ResolvedBackend::Interpreter);
        }
    }
}

/// The concrete backend a selection resolves to on this host:
/// `ForceInterpreter` or `ForceRecompiler`.
pub(crate) fn resolve(backend: PvmBackend) -> Result<PvmBackend, String> {
    Ok(match resolve_backend(backend)? {
        ResolvedBackend::Interpreter => PvmBackend::ForceInterpreter,
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        ResolvedBackend::Recompiler => PvmBackend::ForceRecompiler,
    })
}

enum ResolvedBackend {
    Interpreter,
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    Recompiler,
}

/// The most code bytes the interpreter prepares: its tables hold several
/// bytes for each code byte, and a guest sizes an inner machine's code, so
/// a host bounds them. It holds every service's code
/// ([`crate::spi::MAX_SERVICE_CODE`]); past it a program is valid but
/// refused as this host's resource, a backend error and never a guest
/// outcome.
pub const MAX_INTERPRETED_CODE: usize = 4 << 20;

/// Compile PVM code into a `CompiledProgram` using the selected backend.
/// Each backend bounds the code it prepares as its own resource, past any
/// rule of the program: the interpreter at [`MAX_INTERPRETED_CODE`], the
/// recompiler at its native bound (`recompiler::MAX_CODE`). The code is
/// unvalidated: on code `crate::spi::deblob` refuses the backends may
/// charge different gas, so every loader validates first.
pub fn compile(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    backend: PvmBackend,
) -> Result<CompiledProgram, alloc::string::String> {
    if code.len() > MAX_INTERPRETED_CODE {
        return Err(alloc::format!(
            "{} bytes of code, past the interpreter's {MAX_INTERPRETED_CODE}",
            code.len()
        ));
    }
    match resolve_backend(backend)? {
        ResolvedBackend::Interpreter => Ok(CompiledProgram::Interpreter(
            crate::interpreter::Interpreter::predecode(code, bitmask, jump_table),
        )),
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        ResolvedBackend::Recompiler => Ok(CompiledProgram::Recompiler(
            crate::recompiler::compile_code(code, bitmask, jump_table)?,
        )),
    }
}

/// Immutable preparation shared by standard outer and inner
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
        let compiled = compile(code, bitmask, jump_table, backend)?;
        Ok(match compiled {
            CompiledProgram::Interpreter(interpreter) => Self {
                interpreter: Arc::new(interpreter),
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                native: None,
            },
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            CompiledProgram::Recompiler(native) => Self {
                interpreter: Arc::new(crate::Interpreter::predecode(code, bitmask, jump_table)),
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

    /// Host bytes the preparation holds: the interpreter's tables and,
    /// on the recompiler, its native code and tables.
    pub(crate) fn footprint(&self) -> usize {
        use core::mem::size_of_val;
        let p = &*self.interpreter;
        let interpreter = size_of_val(&*p.decoded_insts)
            + size_of_val(&*p.pc_to_idx)
            + size_of_val(&*p.basic_block_starts)
            + size_of_val(&*p.block_gas_costs)
            + size_of_val(&*p.gas_block_start_by_pc)
            + size_of_val(&*p.code)
            + size_of_val(&*p.bitmask)
            + size_of_val(&*p.jump_table);
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(native) = &self.native {
            return interpreter
                + native.native_code.mmap_cap
                + size_of_val(&*native.dispatch_table)
                + size_of_val(&*native.fault_resume_offsets)
                + size_of_val(&*native.gas_block_start_by_pc)
                + size_of_val(&*native.block_gas_costs)
                + size_of_val(&*native.trap_table)
                + size_of_val(&*native.block_starts);
        }
        interpreter
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
            // Up to 4 GiB, zeroed by the allocator; a host that cannot give
            // it refuses the machine rather than aborting.
            crate::interpreter::Memory::try_flat_zeroed(span as usize)?
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
