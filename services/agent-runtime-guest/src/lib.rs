//! Portable, fail-closed entry boundary for custom VOS Agent runtimes.
//!
//! This crate deliberately knows nothing about a host, filesystem, network,
//! or the bundled standard runtime. A guest supplies an explicit
//! [`AgentRuntime`], while this boundary owns the canonical `RuntimeWork` /
//! `RuntimeTransition` framing and the RISC-V output-window ABI.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use vos_agent_sdk::wire::CanonicalWire as _;
use vos_agent_sdk::{AgentRuntime, RuntimeTransition, RuntimeWork};

#[cfg(target_arch = "riscv64")]
mod guest_memory {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    // RuntimeWork and RuntimeTransition are each bounded to roughly one
    // runtime image. A one-shot PVM invocation needs room for input decode,
    // the candidate transition, and canonical output at the same time. This
    // zero-initialized BSS arena does not inflate the PVM artifact bytes.
    const HEAP_BYTES: usize = 32 * 1024 * 1024;

    #[repr(C, align(16))]
    struct OneShotHeap {
        arena: UnsafeCell<[u8; HEAP_BYTES]>,
        next: UnsafeCell<usize>,
    }

    // SAFETY: a VOS PVM invocation is strictly single-threaded.
    unsafe impl Sync for OneShotHeap {}

    unsafe impl GlobalAlloc for OneShotHeap {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let next = unsafe { &mut *self.next.get() };
            let aligned = match next.checked_add(layout.align() - 1) {
                Some(value) => value & !(layout.align() - 1),
                None => return core::ptr::null_mut(),
            };
            let end = match aligned.checked_add(layout.size()) {
                Some(value) if value <= HEAP_BYTES => value,
                _ => return core::ptr::null_mut(),
            };
            *next = end;
            // SAFETY: `aligned..end` is checked inside this arena and each
            // allocation receives a disjoint monotonically advanced range.
            unsafe { (self.arena.get() as *mut u8).add(aligned) }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // One PVM invocation owns the entire arena and then halts. The
            // final output must remain live, so individual frees are not
            // reused during that invocation.
        }
    }

    #[global_allocator]
    static HEAP: OneShotHeap = OneShotHeap {
        arena: UnsafeCell::new([0; HEAP_BYTES]),
        next: UnsafeCell::new(0),
    };
}

#[cfg(target_arch = "riscv64")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    fail_closed()
}

/// Stable failure classes at the portable guest boundary.
///
/// Native callers receive this value. The exported PVM entry traps for every
/// variant, so malformed input can never be confused with an empty reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    InvalidCapabilities,
    InvalidWork,
    NonCanonicalWork,
    InvalidTransition,
    NonCanonicalTransition,
}

/// Decode one exact canonical work item, invoke `runtime` exactly once, and
/// return one exact canonical transition.
///
/// Decoding is bounded by `RuntimeWork::MAX_ENCODED_BYTES` and rejects
/// trailing or previous-generation bytes. The explicit re-encode comparison
/// is retained as a defense at the guest boundary even though the SDK decoder
/// itself already enforces canonicality.
pub fn dispatch<R: AgentRuntime>(runtime: &mut R, input: &[u8]) -> Result<Vec<u8>, DispatchError> {
    runtime
        .capabilities()
        .validate()
        .map_err(|_| DispatchError::InvalidCapabilities)?;

    let work = RuntimeWork::decode(input).map_err(|_| DispatchError::InvalidWork)?;
    let canonical_work = work.encode().map_err(|_| DispatchError::NonCanonicalWork)?;
    if canonical_work.as_slice() != input {
        return Err(DispatchError::NonCanonicalWork);
    }

    let transition = runtime.apply(work);
    if !transition.validate() {
        return Err(DispatchError::InvalidTransition);
    }
    let output = transition
        .encode()
        .map_err(|_| DispatchError::NonCanonicalTransition)?;
    let decoded = validate_output(&output)?;
    if decoded != transition {
        return Err(DispatchError::NonCanonicalTransition);
    }
    Ok(output)
}

/// Validate one complete PVM output as a bounded canonical transition.
///
/// Host-side conformance tests can use this on raw guest output. Malformed,
/// oversized, trailing, invalid, or non-canonical bytes are never projected
/// into a partial transition.
pub fn validate_output(output: &[u8]) -> Result<RuntimeTransition, DispatchError> {
    let transition =
        RuntimeTransition::decode(output).map_err(|_| DispatchError::InvalidTransition)?;
    if !transition.validate() {
        return Err(DispatchError::InvalidTransition);
    }
    let canonical = transition
        .encode()
        .map_err(|_| DispatchError::NonCanonicalTransition)?;
    if canonical.as_slice() != output {
        return Err(DispatchError::NonCanonicalTransition);
    }
    Ok(transition)
}

/// Output window returned through the standard PVM refine ABI.
#[cfg(target_arch = "riscv64")]
#[repr(C)]
pub struct OutputWindow {
    address: u64,
    len: u64,
}

/// Run one default-constructed runtime through the PVM argument/output ABI.
///
/// # Safety
///
/// `arguments..arguments + arguments_len` must be the complete immutable
/// argument mapping supplied by the VOS PVM loader.
#[cfg(target_arch = "riscv64")]
pub unsafe fn dispatch_guest<R: AgentRuntime + Default>(
    arguments: *const u8,
    arguments_len: usize,
) -> OutputWindow {
    // SAFETY: required by this function's contract and supplied by the PVM
    // loader for the duration of the invocation.
    let input = unsafe { core::slice::from_raw_parts(arguments, arguments_len) };
    let mut runtime = R::default();
    let output = dispatch(&mut runtime, input).unwrap_or_else(|_| fail_closed());
    let window = OutputWindow {
        address: output.as_ptr() as u64,
        len: output.len() as u64,
    };
    // The PVM halts immediately after `_start` returns. Keep the allocation
    // alive until the host copies the output window.
    core::mem::forget(output);
    window
}

#[cfg(target_arch = "riscv64")]
fn fail_closed() -> ! {
    // `ebreak` is the canonical deterministic guest trap. No output window is
    // returned for malformed input or an invalid runtime transition.
    unsafe { core::arch::asm!("ebreak", options(noreturn, nostack)) }
}

/// Export the standard `_start` symbol for one explicit runtime type.
///
/// The type is default-constructed for each invocation; all durable runtime
/// state must therefore come from the canonical `RuntimeWork`, never ambient
/// process memory.
#[macro_export]
macro_rules! export_agent_runtime {
    ($runtime:ty) => {
        #[cfg(target_arch = "riscv64")]
        mod __vos_agent_runtime_entry {
            use core::arch::global_asm;

            global_asm!(
                ".global _start",
                ".type _start, @function",
                "_start:",
                "mv s0, ra",
                "jal ra, __vos_agent_runtime_dispatch",
                "mv ra, s0",
                "ret",
            );

            #[unsafe(no_mangle)]
            extern "C" fn __vos_agent_runtime_dispatch(
                arguments: *const u8,
                arguments_len: usize,
            ) -> $crate::OutputWindow {
                // SAFETY: `_start` is entered only by the VOS PVM loader,
                // which supplies the complete read-only argument mapping.
                unsafe { $crate::dispatch_guest::<$runtime>(arguments, arguments_len) }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;

    use vos_agent_sdk::wire::CanonicalWire as _;
    use vos_agent_sdk::{
        AgentRuntime, ManagementError, RuntimeCapabilities, RuntimeOutcome, RuntimeState,
        RuntimeTransition, RuntimeWork,
    };

    use super::{DispatchError, dispatch, validate_output};

    struct ProbeRuntime<'a> {
        calls: &'a Cell<usize>,
        capabilities: RuntimeCapabilities,
        invalid_transition: bool,
    }

    impl AgentRuntime for ProbeRuntime<'_> {
        fn capabilities(&self) -> RuntimeCapabilities {
            self.capabilities
        }

        fn apply(&mut self, work: RuntimeWork) -> RuntimeTransition {
            self.calls.set(self.calls.get() + 1);
            let state = match work {
                RuntimeWork::Manage { state, .. }
                | RuntimeWork::Invoke { state, .. }
                | RuntimeWork::Resume { state, .. }
                | RuntimeWork::Acknowledge { state, .. } => state,
            };
            RuntimeTransition {
                state: if self.invalid_transition {
                    RuntimeState {
                        control: vec![0; vos_agent_sdk::MAX_RUNTIME_STATE_BYTES + 1],
                        ..RuntimeState::default()
                    }
                } else {
                    state
                },
                outcome: RuntimeOutcome::Management(Err(ManagementError::NotCreated)),
            }
        }
    }

    fn work() -> Vec<u8> {
        RuntimeWork::Manage {
            space: vos_agent_sdk::SpaceId([1; 32]),
            agent: vos_agent_sdk::AgentId([2; 32]),
            runtime_deployment: vos_agent_sdk::DeploymentId([3; 32]),
            state: RuntimeState::default(),
            request: Box::new(vos_agent_sdk::ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 0,
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn canonical_work_is_dispatched_once_and_returns_canonical_output() {
        let calls = Cell::new(0);
        let mut runtime = ProbeRuntime {
            calls: &calls,
            capabilities: RuntimeCapabilities::standard(),
            invalid_transition: false,
        };
        let first = dispatch(&mut runtime, &work()).unwrap();
        let second = dispatch(&mut runtime, &work()).unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(first, second);
        assert_eq!(
            RuntimeTransition::decode(&first).unwrap().encode().unwrap(),
            first
        );
    }

    #[test]
    fn malformed_trailing_and_oversized_work_never_reaches_runtime() {
        let calls = Cell::new(0);
        let mut runtime = ProbeRuntime {
            calls: &calls,
            capabilities: RuntimeCapabilities::standard(),
            invalid_transition: false,
        };
        assert_eq!(
            dispatch(&mut runtime, b"not AWRK"),
            Err(DispatchError::InvalidWork)
        );
        let mut trailing = work();
        trailing.push(0);
        assert_eq!(
            dispatch(&mut runtime, &trailing),
            Err(DispatchError::InvalidWork)
        );
        let oversized =
            vec![0; <RuntimeWork as vos_agent_sdk::wire::CanonicalWire>::MAX_ENCODED_BYTES + 1];
        assert_eq!(
            dispatch(&mut runtime, &oversized),
            Err(DispatchError::InvalidWork)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn invalid_capabilities_and_invalid_transition_fail_closed() {
        let calls = Cell::new(0);
        let mut bad_capabilities = RuntimeCapabilities::standard();
        bad_capabilities.max_actors = 0;
        let mut runtime = ProbeRuntime {
            calls: &calls,
            capabilities: bad_capabilities,
            invalid_transition: false,
        };
        assert_eq!(
            dispatch(&mut runtime, &work()),
            Err(DispatchError::InvalidCapabilities)
        );
        assert_eq!(calls.get(), 0);

        let mut runtime = ProbeRuntime {
            calls: &calls,
            capabilities: RuntimeCapabilities::standard(),
            invalid_transition: true,
        };
        assert_eq!(
            dispatch(&mut runtime, &work()),
            Err(DispatchError::InvalidTransition)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn malformed_trailing_and_oversized_output_is_rejected() {
        let calls = Cell::new(0);
        let mut runtime = ProbeRuntime {
            calls: &calls,
            capabilities: RuntimeCapabilities::standard(),
            invalid_transition: false,
        };
        let canonical = dispatch(&mut runtime, &work()).unwrap();
        assert!(validate_output(&canonical).is_ok());

        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            validate_output(&trailing),
            Err(DispatchError::InvalidTransition)
        );
        assert_eq!(
            validate_output(b"not ATRN"),
            Err(DispatchError::InvalidTransition)
        );
        let oversized = vec![
            0;
            <RuntimeTransition as vos_agent_sdk::wire::CanonicalWire>::MAX_ENCODED_BYTES
                + 1
        ];
        assert_eq!(
            validate_output(&oversized),
            Err(DispatchError::InvalidTransition)
        );
    }
}
