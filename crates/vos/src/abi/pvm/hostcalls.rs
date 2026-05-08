//! Typed hostcall wrappers for PVM actors.
//!
//! Hostcall IDs are spec-canonical JAR/JAM protocol cap slots. Phase
//! discipline (which calls are legal in refine vs accumulate) is enforced
//! by the host runtime, not the ID namespace.

use super::ecall::*;
use crate::abi::hostcall;

// --- Shared across phases ---

/// Get remaining gas.
#[inline]
pub fn gas() -> u64 {
    ecall0(hostcall::GAS)
}

/// Request additional heap pages.
#[inline]
pub fn grow_heap(pages: u32) -> u64 {
    ecall1(hostcall::GROW_HEAP, pages as u64)
}

/// Write debug output. vosx prints to stderr.
#[inline]
pub fn debug_write(data: &[u8]) -> u64 {
    ecall2(
        hostcall::DEBUG_WRITE,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

// --- Refine-legal ---

/// Read-only storage access. Legal in both refine and accumulate.
#[inline]
pub fn peek(key: &[u8], value_buf: &mut [u8]) -> u64 {
    ecall4(
        hostcall::STORAGE_R,
        key.as_ptr() as u64,
        key.len() as u64,
        value_buf.as_mut_ptr() as u64,
        value_buf.len() as u64,
    )
}

/// Invoke a sub-PVM synchronously (refine phase).
/// Runs target's refine entry, returns the *full* reply length
/// (which may exceed the caller's buffer — see truncation below).
///
/// The output argument is packed: the low 32 bits of the fifth
/// register are `output.as_mut_ptr() as u32`, and the high 32 bits
/// are `output.len() as u32`. The runtime uses the length to bound
/// its write into the caller's PVM memory: when the producer's
/// reply exceeds the caller's buffer, the runtime substitutes a
/// single-byte `STATUS_PANICKED` envelope rather than overrunning
/// the stack. A length of 0 in the high bits is interpreted as
/// "legacy / no cap" so older PVM blobs that predate this ABI
/// extension keep their previous behaviour (unsafe but unchanged).
#[inline]
pub fn invoke(code_hash: &[u8; 32], input: &[u8], gas_limit: u64, output: &mut [u8]) -> u64 {
    let output_packed = (output.as_mut_ptr() as u64) | ((output.len() as u64) << 32);
    ecall5(
        hostcall::INVOKE,
        code_hash.as_ptr() as u64,
        input.as_ptr() as u64,
        input.len() as u64,
        gas_limit,
        output_packed,
    )
}

/// Fetch next item from the host. Returns bytes read into `buf`.
#[inline]
pub fn fetch_item(buf: &mut [u8]) -> u64 {
    ecall2(hostcall::FETCH, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Fetch a preimage by hash. Returns bytes read into `buf`.
#[inline]
pub fn fetch(hash: &[u8; 32], buf: &mut [u8]) -> u64 {
    ecall3(
        hostcall::FETCH,
        hash.as_ptr() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

/// Look up a preimage by hash. Returns bytes read into `buf`,
/// or HOST_NONE if the preimage is not available.
#[inline]
pub fn preimage_lookup(hash: &[u8; 32], buf: &mut [u8]) -> u64 {
    ecall3(
        hostcall::PREIMAGE_LOOKUP,
        hash.as_ptr() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

// --- Accumulate-only (service feature) ---

/// Read a value from per-service storage by key. Alias for [`peek`].
#[cfg(feature = "service")]
#[inline]
pub fn read(key: &[u8], value_buf: &mut [u8]) -> u64 {
    peek(key, value_buf)
}

/// Write a key-value pair to per-service storage.
#[cfg(feature = "service")]
#[inline]
pub fn write(key: &[u8], value: &[u8]) -> u64 {
    ecall4(
        hostcall::STORAGE_W,
        key.as_ptr() as u64,
        key.len() as u64,
        value.as_ptr() as u64,
        value.len() as u64,
    )
}

/// Store a preimage blob.
#[cfg(feature = "service")]
#[inline]
pub fn provide(hash: &[u8; 32], data: &[u8]) -> u64 {
    ecall3(
        hostcall::PREIMAGE_PROVIDE,
        hash.as_ptr() as u64,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

/// Transfer to another service with a memo.
#[cfg(feature = "service")]
#[inline]
pub fn transfer(
    target: crate::abi::service::ServiceId,
    amount: u64,
    gas_limit: u64,
    memo: &[u8],
) -> u64 {
    ecall5(
        hostcall::TRANSFER,
        target.0 as u64,
        amount,
        gas_limit,
        memo.as_ptr() as u64,
        memo.len() as u64,
    )
}

/// Spawn a new service from a code hash.
#[cfg(feature = "service")]
#[inline]
pub fn new_service(code_hash: &[u8; 32]) -> u64 {
    ecall1(hostcall::SERVICE_NEW, code_hash.as_ptr() as u64)
}

/// Create a gas checkpoint for intra-invocation rollback.
#[cfg(feature = "service")]
#[inline]
pub fn checkpoint() -> u64 {
    ecall0(hostcall::CHECKPOINT)
}

/// Yield output data and signal completion status.
#[cfg(feature = "service")]
#[inline]
pub fn yield_output(data: &[u8]) -> u64 {
    ecall2(hostcall::OUTPUT, data.as_ptr() as u64, data.len() as u64)
}

/// Get the current service's ID.
#[cfg(feature = "service")]
#[inline]
pub fn info() -> u64 {
    ecall0(hostcall::INFO)
}

/// Get the current service's own ID as ServiceId.
#[cfg(feature = "service")]
#[inline]
pub fn info_self_id() -> crate::abi::service::ServiceId {
    crate::abi::service::ServiceId(info() as u32)
}
