//! PVM backend selection — interpreter or recompiler.
//!
//! The kernel creates CODE caps that wrap compiled code in one of two backends.
//! `PvmBackend` controls the selection; `CompiledProgram` holds the result.

use alloc::{string::String, sync::Arc};

/// Backend selection for PVM execution.
///
/// Whichever is selected, a program's result is the same: the backends
/// agree on every exit, gas, register and memory, and code the recompiler
/// cannot take (past its native bound, or a compile or mapping it refuses)
/// runs on the interpreter instead. A selection decides speed alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PvmBackend {
    /// This process's choice ([`backend_choice`]): the operator's
    /// `VOS_PVM_BACKEND` (`interpreter` or `recompiler`; any other value
    /// is an error), else the recompiler where this host can run it.
    Default,
    /// Always use the software interpreter.
    ForceInterpreter,
    /// The recompiler: an error where this host cannot run it at all
    /// ([`Unavailable`]); a program it cannot take still runs on the
    /// interpreter.
    ForceRecompiler,
}

/// Why this host cannot run the recompiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// No recompiler is built for this platform (x86-64 Linux only).
    Platform,
    /// The CPU lacks a feature generated code uses.
    CpuFeature(&'static str),
    /// No userfaultfd write-protect (Linux 6.7 or later, and permitted:
    /// default container seccomp profiles deny it).
    WriteTracking,
    /// Written memory may not become executable (`PR_SET_MDWE`, systemd's
    /// `MemoryDenyWriteExecute`, SELinux `execmem`).
    ExecutableMappings,
    /// A 4 GiB guest window cannot be built (`RLIMIT_FSIZE`,
    /// `vm.memfd_noexec`, address space).
    GuestMemory,
    /// A probe program did not run natively to its expected exit.
    NativeRun,
}

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Platform => f.write_str("no recompiler for this platform"),
            Self::CpuFeature(feature) => write!(f, "the CPU lacks {feature}"),
            Self::WriteTracking => f.write_str("no userfaultfd write-protect"),
            Self::ExecutableMappings => f.write_str("written memory may not become executable"),
            Self::GuestMemory => f.write_str("no 4 GiB guest window"),
            Self::NativeRun => f.write_str("a probe program did not run natively"),
        }
    }
}

/// The backend this process runs for [`PvmBackend::Default`], and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendChoice {
    /// `ForceInterpreter` or `ForceRecompiler`.
    pub backend: PvmBackend,
    /// Set by the operator through `VOS_PVM_BACKEND`.
    pub requested: bool,
    /// Why the recompiler was not chosen, when it was not.
    pub unavailable: Option<Unavailable>,
}

/// Whether this host can run the recompiler: probed once per process.
pub fn recompiler_available() -> Result<(), Unavailable> {
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    return crate::recompiler::probe::available();
    #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
    return Err(Unavailable::Platform);
}

/// This process's backend for [`PvmBackend::Default`], decided once (from
/// `VOS_PVM_BACKEND` and [`recompiler_available`]) and logged; an error
/// for an override this host cannot honour or does not know.
pub fn backend_choice() -> Result<BackendChoice, String> {
    #[cfg(feature = "std")]
    {
        static CHOICE: std::sync::OnceLock<Result<BackendChoice, String>> =
            std::sync::OnceLock::new();
        CHOICE
            .get_or_init(|| {
                let choice = choose(std::env::var("VOS_PVM_BACKEND").ok().as_deref());
                match &choice {
                    Ok(choice) => tracing::info!(
                        backend = ?choice.backend,
                        requested = choice.requested,
                        unavailable = choice.unavailable.map(tracing::field::display),
                        "PVM backend"
                    ),
                    Err(error) => tracing::error!(%error, "PVM backend"),
                }
                choice
            })
            .clone()
    }
    #[cfg(not(feature = "std"))]
    choose(None)
}

/// The choice for an operator override `requested`. An override of the
/// interpreter probes nothing: no native code runs in its process.
fn choose(requested: Option<&str>) -> Result<BackendChoice, String> {
    if requested == Some("interpreter") {
        return Ok(BackendChoice {
            backend: PvmBackend::ForceInterpreter,
            requested: true,
            unavailable: None,
        });
    }
    let available = recompiler_available();
    let (backend, requested) = match requested {
        None => (
            if available.is_ok() {
                PvmBackend::ForceRecompiler
            } else {
                PvmBackend::ForceInterpreter
            },
            false,
        ),
        Some("recompiler") => {
            if let Err(reason) = available {
                return Err(alloc::format!("VOS_PVM_BACKEND=recompiler: {reason}"));
            }
            (PvmBackend::ForceRecompiler, true)
        }
        Some(other) => {
            return Err(alloc::format!(
                "VOS_PVM_BACKEND={other:?}: expected \"interpreter\" or \"recompiler\""
            ));
        }
    };
    Ok(BackendChoice {
        backend,
        requested,
        unavailable: available.err(),
    })
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
    let backend = match backend {
        PvmBackend::Default => backend_choice()?.backend,
        PvmBackend::ForceRecompiler => {
            recompiler_available()
                .map_err(|reason| alloc::format!("the recompiler is unavailable: {reason}"))?;
            PvmBackend::ForceRecompiler
        }
        PvmBackend::ForceInterpreter => PvmBackend::ForceInterpreter,
    };
    Ok(match backend {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        PvmBackend::ForceRecompiler => ResolvedBackend::Recompiler,
        _ => ResolvedBackend::Interpreter,
    })
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

/// The most code bytes a host prepares, on either backend: tables hold
/// several bytes for each code byte, and a guest sizes an inner machine's
/// code, so a host bounds them. It holds every service's code
/// ([`crate::spi::MAX_SERVICE_CODE`]); past it a program is valid but
/// refused as this host's resource, a backend error and never a guest
/// outcome. Checked before a backend is chosen, so the refusal is the same
/// on every host.
pub const MAX_PREPARED_CODE: usize = 4 << 20;

/// Compile PVM code into a `CompiledProgram` using the selected backend.
/// Refused past [`MAX_PREPARED_CODE`] bytes of code on either backend.
/// Code the recompiler does not take (past `recompiler::MAX_CODE`, or a
/// compile it refuses for want of a mapping) is interpreted instead. The
/// code is unvalidated: on code `crate::spi::deblob` refuses the backends
/// may charge different gas, so every loader validates first.
pub fn compile(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    backend: PvmBackend,
) -> Result<CompiledProgram, alloc::string::String> {
    if code.len() > MAX_PREPARED_CODE {
        return Err(alloc::format!(
            "{} bytes of code, past the host's {MAX_PREPARED_CODE}",
            code.len()
        ));
    }
    let interpret = || {
        CompiledProgram::Interpreter(crate::interpreter::Interpreter::predecode(
            code, bitmask, jump_table,
        ))
    };
    match resolve_backend(backend)? {
        ResolvedBackend::Interpreter => Ok(interpret()),
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        ResolvedBackend::Recompiler => Ok(
            match crate::recompiler::compile_code(code, bitmask, jump_table) {
                Ok(native) => CompiledProgram::Recompiler(native),
                Err(error) => {
                    tracing::debug!(%error, "interpreting code the recompiler does not take");
                    interpret()
                }
            },
        ),
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
        // Native memory where this program runs natively. Sparse memory,
        // and memory the host cannot map natively, runs the program on the
        // interpreter, with the same result.
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if self.native.is_some() && !sparse {
            return Ok(match crate::interpreter::Memory::native(span) {
                Ok(memory) => memory,
                Err(error) => {
                    tracing::debug!(%error, "interpreting over sparse memory");
                    crate::interpreter::Memory::sparse(span)
                }
            });
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
    /// A machine whose memory does not run natively runs the slice on the
    /// interpreter, over the same state. A failure after native code ran is
    /// the backend's, not a guest exit, and is never retried on the
    /// interpreter. The caller alone decides when to acknowledge a hostcall.
    pub(crate) fn run(
        &self,
        interpreter: &mut crate::Interpreter,
    ) -> Result<crate::ExitReason, String> {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(native) = &self.native
            && let Some(exit) = crate::recompiler::run_standard(native, interpreter)?
        {
            return Ok(exit);
        }
        Ok(interpreter.run().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host without the recompiler refuses a demand for it, rather than
    /// running something else under its name.
    #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unavailable_recompiler_is_an_error_not_an_interpreter_fallback() {
        assert!(
            PreparedExecution::new_standard(&[0], &[1], &[], PvmBackend::ForceRecompiler).is_err()
        );
    }

    /// The operator's override is honoured, and one this process does not
    /// know is an error, never a silent default.
    #[test]
    fn an_unknown_backend_override_is_an_error() {
        let interpreter = choose(Some("interpreter")).unwrap();
        assert_eq!(interpreter.backend, PvmBackend::ForceInterpreter);
        assert!(interpreter.requested);
        for typo in ["interp", "Interpreter", "", "jit"] {
            let refused = choose(Some(typo)).unwrap_err();
            assert!(refused.contains("VOS_PVM_BACKEND"), "{refused}");
        }
        let default = choose(None).unwrap();
        assert!(!default.requested);
        assert_eq!(
            default.backend == PvmBackend::ForceRecompiler,
            recompiler_available().is_ok()
        );
        assert_eq!(default.unavailable, recompiler_available().err());
        assert_eq!(
            choose(Some("recompiler")).is_ok(),
            recompiler_available().is_ok()
        );
    }

    /// The development hosts run the recompiler: a probe that fails there
    /// is a probe bug, which would silently cost every node its speed.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn this_host_runs_the_recompiler() {
        assert_eq!(recompiler_available(), Ok(()));
    }
}
