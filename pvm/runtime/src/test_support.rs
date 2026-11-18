//! What the crate's tests share.

use alloc::vec::Vec;

use crate::PvmBackend;

/// Every backend this host can run on.
pub(crate) fn backends() -> Vec<PvmBackend> {
    let mut backends = alloc::vec![PvmBackend::ForceInterpreter];
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    backends.push(PvmBackend::ForceRecompiler);
    backends
}

/// The PVM code of `instructions`, in order, and where each starts.
pub(crate) fn code(instructions: &[&[u8]]) -> (Vec<u8>, Vec<usize>) {
    let mut code = Vec::new();
    let mut starts = Vec::new();
    for instruction in instructions {
        starts.push(code.len());
        code.extend_from_slice(instruction);
    }
    (code, starts)
}
