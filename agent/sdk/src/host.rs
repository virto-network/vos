//! The actor ABI client: one function per operation of
//! [`vos_wire::abi::op`], following its register conventions.
//!
//! On the guest target an operation is an `ecalli`. Elsewhere it goes to a
//! host function installed with [`set_host`], which receives native
//! pointers; native tests use it to run actor code without a PVM.

use alloc::vec::Vec;

use vos_wire::abi::{cap, code, op};

/// An operation's results: φ7 and φ8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Results(pub u64, pub u64);

#[cfg(target_arch = "riscv64")]
macro_rules! ecalli {
    ($id:expr, $a:expr) => {{
        let [a0, a1, a2, a3, a4, a5]: [u64; 6] = $a;
        let (r0, r1): (u64, u64);
        // SAFETY: the ecalli convention passes φ7..φ12 in a0..a5 and returns
        // in a0 and a1. Pointer arguments name live buffers the agent may
        // write, so memory is not marked read-only.
        unsafe {
            core::arch::asm!(
                "li t0, {id}",
                "csrw 0x801, zero",
                "ecall",
                id = const $id,
                lateout("t0") _,
                inlateout("a0") a0 => r0,
                inlateout("a1") a1 => r1,
                inlateout("a2") a2 => _,
                inlateout("a3") a3 => _,
                inlateout("a4") a4 => _,
                inlateout("a5") a5 => _,
                options(nostack),
            );
        }
        Results(r0, r1)
    }};
}

#[cfg(not(target_arch = "riscv64"))]
mod native {
    use core::sync::atomic::{AtomicPtr, Ordering};

    use super::Results;

    /// A native host: the operation id and φ7..φ12, with native pointers.
    pub type Host = fn(u64, [u64; 6]) -> Results;

    static HOST: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

    pub fn set_host(host: Host) {
        HOST.store(host as *mut (), Ordering::SeqCst);
    }

    pub fn call(id: u64, args: [u64; 6]) -> Results {
        let host = HOST.load(Ordering::SeqCst);
        assert!(!host.is_null(), "no native host installed");
        // SAFETY: only `set_host` stores here, and it stores a `Host`.
        let host: Host = unsafe { core::mem::transmute::<*mut (), Host>(host) };
        host(id, args)
    }
}

#[cfg(not(target_arch = "riscv64"))]
pub use native::{Host, set_host};

#[cfg(not(target_arch = "riscv64"))]
macro_rules! ecalli {
    ($id:expr, $a:expr) => {
        native::call($id, $a)
    };
}

fn ptr(bytes: &[u8]) -> u64 {
    bytes.as_ptr() as u64
}

fn ptr_mut(bytes: &mut [u8]) -> u64 {
    bytes.as_mut_ptr() as u64
}

/// Read a whole variable-length output: try `first` bytes, then once more
/// at the reported length. `read` copies into its buffer from an offset
/// and returns the whole length, or `None` for [`code::NONE`].
fn read_all(first: usize, mut read: impl FnMut(&mut [u8], u64) -> u64) -> Option<Vec<u8>> {
    let mut buffer = alloc::vec![0u8; first];
    let len = read(&mut buffer, 0);
    if len == code::NONE {
        return None;
    }
    let len = len as usize;
    if len > first {
        buffer.resize(len, 0);
        read(&mut buffer[first..], first as u64);
    }
    buffer.truncate(len);
    Some(buffer)
}

/// The invocation's arguments.
pub fn input() -> Vec<u8> {
    read_all(256, |out, offset| {
        ecalli!(op::INPUT, [ptr_mut(out), offset, out.len() as u64, 0, 0, 0]).0
    })
    .unwrap_or_default()
}

pub fn reply(bytes: &[u8]) {
    ecalli!(op::REPLY, [ptr(bytes), bytes.len() as u64, 0, 0, 0, 0]);
}

/// Fail the step with the handler's encoded error.
pub fn fail(detail: &[u8]) {
    ecalli!(op::FAIL, [ptr(detail), detail.len() as u64, 0, 0, 0, 0]);
}

pub fn log(level: u8, message: &[u8]) {
    ecalli!(
        op::LOG,
        [
            u64::from(level),
            ptr(message),
            message.len() as u64,
            0,
            0,
            0
        ]
    );
}

/// The caller's encoded principal.
pub fn caller() -> Vec<u8> {
    let mut out = [0u8; 64];
    let len = ecalli!(
        op::CALLER,
        [ptr_mut(&mut out), out.len() as u64, 0, 0, 0, 0]
    )
    .0;
    out[..(len as usize).min(out.len())].to_vec()
}

/// The batch time, in milliseconds since the Unix epoch.
pub fn now() -> u64 {
    ecalli!(op::NOW, [0; 6]).0
}

pub fn random() -> [u8; 32] {
    let mut out = [0u8; 32];
    ecalli!(op::RANDOM, [ptr_mut(&mut out), 0, 0, 0, 0, 0]);
    out
}

/// (instance, agent).
pub fn self_id() -> (u32, u32) {
    let Results(instance, agent) = ecalli!(op::SELF_ID, [0; 6]);
    (instance as u32, agent as u32)
}

pub fn get(key: &[u8]) -> Option<Vec<u8>> {
    read_all(128, |out, offset| {
        ecalli!(
            op::GET,
            [
                ptr(key),
                key.len() as u64,
                ptr_mut(out),
                offset,
                out.len() as u64,
                0
            ]
        )
        .0
    })
}

pub fn put(key: &[u8], value: &[u8]) {
    ecalli!(
        op::PUT,
        [
            ptr(key),
            key.len() as u64,
            ptr(value),
            value.len() as u64,
            0,
            0
        ]
    );
}

pub fn delete(key: &[u8]) {
    ecalli!(op::DELETE, [ptr(key), key.len() as u64, 0, 0, 0, 0]);
}

/// Rows under `prefix` after `cursor`, as `E(↕key, ↕value)` back to back,
/// filling at most `out`; returns the bytes written, 0 at the end, or
/// [`code::FULL`] when the next row alone does not fit.
pub fn scan(prefix: &[u8], cursor: &[u8], out: &mut [u8]) -> u64 {
    ecalli!(
        op::SCAN,
        [
            ptr(prefix),
            prefix.len() as u64,
            ptr(cursor),
            cursor.len() as u64,
            ptr_mut(out),
            out.len() as u64
        ]
    )
    .0
}

/// Run `f` with a [`cap::REPLY`]-byte output, which always holds a whole
/// reply. On the guest it is one static buffer, since an invocation runs
/// on one thread and the heap never frees; elsewhere a fresh one.
fn with_reply_buffer<R>(f: impl FnOnce(&mut [u8]) -> R) -> R {
    #[cfg(target_arch = "riscv64")]
    {
        struct Scratch(core::cell::UnsafeCell<[u8; cap::REPLY]>);
        // SAFETY: a PVM invocation runs on one thread.
        unsafe impl Sync for Scratch {}
        static SCRATCH: Scratch = Scratch(core::cell::UnsafeCell::new([0; cap::REPLY]));
        // SAFETY: single-threaded, and `f` returns before any other use.
        f(unsafe { &mut *SCRATCH.0.get() })
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        f(&mut alloc::vec![0u8; cap::REPLY])
    }
}

/// A nested call's result: the reply, or an error code, a
/// [`vos_wire::abi::Failure`], with its detail. The callee runs once, so
/// the output holds [`cap::REPLY`] bytes.
pub fn call(instance: u32, method: u32, arguments: &[u8]) -> Result<Vec<u8>, (u32, Vec<u8>)> {
    with_reply_buffer(|out| {
        let Results(len, status) = ecalli!(
            op::CALL,
            [
                u64::from(instance),
                u64::from(method),
                ptr(arguments),
                arguments.len() as u64,
                ptr_mut(out),
                out.len() as u64
            ]
        );
        let reply = out[..(len as usize).min(out.len())].to_vec();
        match status {
            0 => Ok(reply),
            code => Err((code as u32, reply)),
        }
    })
}

/// Run one of this instance's attestable methods; its output, or an
/// error code with its detail, as [`call`].
pub fn attest(method: u32, arguments: &[u8]) -> Result<Vec<u8>, (u32, Vec<u8>)> {
    with_reply_buffer(|out| {
        let Results(len, status) = ecalli!(
            op::ATTEST,
            [
                u64::from(method),
                ptr(arguments),
                arguments.len() as u64,
                ptr_mut(out),
                out.len() as u64,
                0
            ]
        );
        let output = out[..(len as usize).min(out.len())].to_vec();
        match status {
            0 => Ok(output),
            code => Err((code as u32, output)),
        }
    })
}

/// Queue a message for another agent's instance, sent after the step
/// commits.
pub fn send(agent: u32, instance: u32, method: u32, arguments: &[u8]) {
    ecalli!(
        op::SEND,
        [
            u64::from(agent),
            u64::from(instance),
            u64::from(method),
            ptr(arguments),
            arguments.len() as u64,
            0
        ]
    );
}
