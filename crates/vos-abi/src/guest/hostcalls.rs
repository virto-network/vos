//! Typed hostcall wrappers for guest actors.
//!
//! These wrap the raw ecall interface with meaningful parameter names
//! and types matching the JAR hostcall spec.

use crate::hostcall;
use crate::service::ServiceId;
use super::ecall::*;

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

/// Read a value from per-service storage by key.
/// Returns bytes read into `value_buf`, or error code.
#[inline]
pub fn read(key: &[u8], value_buf: &mut [u8]) -> u64 {
    ecall4(
        hostcall::READ,
        key.as_ptr() as u64,
        key.len() as u64,
        value_buf.as_mut_ptr() as u64,
        value_buf.len() as u64,
    )
}

/// Write a key-value pair to per-service storage.
#[inline]
pub fn write(key: &[u8], value: &[u8]) -> u64 {
    ecall4(
        hostcall::WRITE,
        key.as_ptr() as u64,
        key.len() as u64,
        value.as_ptr() as u64,
        value.len() as u64,
    )
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

/// Store a preimage blob. The host computes the hash.
#[inline]
pub fn provide(hash: &[u8; 32], data: &[u8]) -> u64 {
    ecall3(
        hostcall::PROVIDE,
        hash.as_ptr() as u64,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

/// Transfer to another service with a memo.
#[inline]
pub fn transfer(target: ServiceId, amount: u64, gas_limit: u64, memo: &[u8]) -> u64 {
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
#[inline]
pub fn new_service(code_hash: &[u8; 32]) -> u64 {
    ecall1(hostcall::NEW, code_hash.as_ptr() as u64)
}

/// Create a gas checkpoint for intra-invocation rollback.
#[inline]
pub fn checkpoint() -> u64 {
    ecall0(hostcall::CHECKPOINT)
}

/// Yield output and halt.
#[inline]
pub fn yield_output(data: &[u8]) -> u64 {
    ecall2(hostcall::YIELD, data.as_ptr() as u64, data.len() as u64)
}

/// Get service metadata. Returns the current service's ID.
#[inline]
pub fn info() -> u64 {
    ecall0(hostcall::INFO)
}

/// Get the current service's own ID.
#[inline]
pub fn info_self_id() -> ServiceId {
    ServiceId(info() as u32)
}

/// Write debug output. vosx prints to stderr.
#[inline]
pub fn debug_write(data: &[u8]) -> u64 {
    ecall2(hostcall::DEBUG_WRITE, data.as_ptr() as u64, data.len() as u64)
}
