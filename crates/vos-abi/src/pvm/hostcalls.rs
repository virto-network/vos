//! Typed hostcall wrappers for PVM actors.
//!
//! Shared and refine-phase hostcalls are always available.
//! Accumulate-phase hostcalls require the `service` feature.

use crate::hostcall::{self, refine};
use super::ecall::*;

// --- Shared hostcalls (both phases) ---

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
    ecall2(hostcall::DEBUG_WRITE, data.as_ptr() as u64, data.len() as u64)
}

// --- Refine-phase hostcalls ---

/// Read-only storage access (refine phase).
#[inline]
pub fn peek(key: &[u8], value_buf: &mut [u8]) -> u64 {
    ecall4(
        refine::PEEK,
        key.as_ptr() as u64,
        key.len() as u64,
        value_buf.as_mut_ptr() as u64,
        value_buf.len() as u64,
    )
}

/// Invoke a sub-PVM synchronously (refine phase).
/// Runs target's refine entry, returns bytes written to `output`.
#[inline]
pub fn invoke(
    code_hash: &[u8; 32],
    input: &[u8],
    gas_limit: u64,
    output: &mut [u8],
) -> u64 {
    ecall5(
        refine::INVOKE,
        code_hash.as_ptr() as u64,
        input.as_ptr() as u64,
        input.len() as u64,
        gas_limit,
        output.as_mut_ptr() as u64,
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

// --- Accumulate-phase hostcalls (service feature only) ---

/// Read a value from per-service storage by key.
#[cfg(feature = "service")]
#[inline]
pub fn read(key: &[u8], value_buf: &mut [u8]) -> u64 {
    use crate::hostcall::accumulate;
    ecall4(
        accumulate::READ,
        key.as_ptr() as u64,
        key.len() as u64,
        value_buf.as_mut_ptr() as u64,
        value_buf.len() as u64,
    )
}

/// Write a key-value pair to per-service storage.
#[cfg(feature = "service")]
#[inline]
pub fn write(key: &[u8], value: &[u8]) -> u64 {
    use crate::hostcall::accumulate;
    ecall4(
        accumulate::WRITE,
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
    use crate::hostcall::accumulate;
    ecall3(
        accumulate::PROVIDE,
        hash.as_ptr() as u64,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

/// Transfer to another service with a memo.
#[cfg(feature = "service")]
#[inline]
pub fn transfer(target: crate::service::ServiceId, amount: u64, gas_limit: u64, memo: &[u8]) -> u64 {
    use crate::hostcall::accumulate;
    ecall5(
        accumulate::TRANSFER,
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
    use crate::hostcall::accumulate;
    ecall1(accumulate::NEW, code_hash.as_ptr() as u64)
}

/// Create a gas checkpoint for intra-invocation rollback.
#[cfg(feature = "service")]
#[inline]
pub fn checkpoint() -> u64 {
    use crate::hostcall::accumulate;
    ecall0(accumulate::CHECKPOINT)
}

/// Yield output data and signal completion status.
#[cfg(feature = "service")]
#[inline]
pub fn yield_output(data: &[u8]) -> u64 {
    use crate::hostcall::accumulate;
    ecall2(accumulate::YIELD, data.as_ptr() as u64, data.len() as u64)
}

/// Get the current service's ID.
#[cfg(feature = "service")]
#[inline]
pub fn info() -> u64 {
    use crate::hostcall::accumulate;
    ecall0(accumulate::INFO)
}

/// Get the current service's own ID as ServiceId.
#[cfg(feature = "service")]
#[inline]
pub fn info_self_id() -> crate::service::ServiceId {
    crate::service::ServiceId(info() as u32)
}
