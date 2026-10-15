//! The actor ABI client: one function per operation of
//! [`vos_wire::abi::Op`], following its register conventions.
//!
//! On the guest target an operation is an `ecalli`. Elsewhere it goes to a
//! host function installed with [`set_host`], which receives native
//! pointers; native tests use it to run actor code without a PVM.

use alloc::vec::Vec;

use vos_wire::abi::{Op, Rows, cap, code};

/// An operation's results: φ7 and φ8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Results(pub u64, pub u64);

/// An `ecalli` of host call `$id`, a constant, with φ7 to φ12 from `$a`,
/// an array of six: φ7 and φ8 after it. The default agent makes its own
/// host calls with it.
#[cfg(target_arch = "riscv64")]
#[macro_export]
macro_rules! ecalli {
    ($id:expr, $a:expr) => {{
        let [a0, a1, a2, a3, a4, a5]: [u64; 6] = $a;
        let (r0, r1): (u64, u64);
        // SAFETY: the ecalli convention passes φ7..φ12 in a0..a5 and returns
        // in a0 and a1. Pointer arguments name live buffers the host may
        // write, so memory is not marked read-only.
        unsafe {
            ::core::arch::asm!(
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
        (r0, r1)
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
    ($id:expr, $a:expr) => {{
        let Results(r0, r1) = native::call($id, $a);
        (r0, r1)
    }};
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
        ecalli!(
            Op::Input.id(),
            [ptr_mut(out), offset, out.len() as u64, 0, 0, 0]
        )
        .0
    })
    .unwrap_or_default()
}

pub fn reply(bytes: &[u8]) {
    ecalli!(Op::Reply.id(), [ptr(bytes), bytes.len() as u64, 0, 0, 0, 0]);
}

/// Fail the step with the handler's encoded error.
pub fn fail(detail: &[u8]) {
    ecalli!(
        Op::Fail.id(),
        [ptr(detail), detail.len() as u64, 0, 0, 0, 0]
    );
}

pub fn log(level: u8, message: &[u8]) {
    ecalli!(
        Op::Log.id(),
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
        Op::Caller.id(),
        [ptr_mut(&mut out), out.len() as u64, 0, 0, 0, 0]
    )
    .0;
    out[..(len as usize).min(out.len())].to_vec()
}

/// The batch time, in milliseconds since the Unix epoch.
pub fn now() -> u64 {
    ecalli!(Op::Now.id(), [0; 6]).0
}

pub fn random() -> [u8; 32] {
    let mut out = [0u8; 32];
    ecalli!(Op::Random.id(), [ptr_mut(&mut out), 0, 0, 0, 0, 0]);
    out
}

/// (instance, agent).
pub fn self_id() -> (u32, u32) {
    let (instance, agent) = ecalli!(Op::SelfId.id(), [0; 6]);
    (instance as u32, agent as u32)
}

/// The value under `key` in `rows`.
pub fn get(rows: Rows, key: &[u8]) -> Option<Vec<u8>> {
    get_raw(rows.register(), key)
}

/// [`get`] with `rows` as its register, any value an actor may pass.
pub fn get_raw(rows: u64, key: &[u8]) -> Option<Vec<u8>> {
    read_all(128, |out, offset| {
        ecalli!(
            Op::Get.id(),
            [
                rows,
                ptr(key),
                key.len() as u64,
                ptr_mut(out),
                offset,
                out.len() as u64
            ]
        )
        .0
    })
}

pub fn put(rows: Rows, key: &[u8], value: &[u8]) {
    put_raw(rows.register(), key, value);
}

/// [`put`] with `rows` as its register.
pub fn put_raw(rows: u64, key: &[u8], value: &[u8]) {
    ecalli!(
        Op::Put.id(),
        [
            rows,
            ptr(key),
            key.len() as u64,
            ptr(value),
            value.len() as u64,
            0
        ]
    );
}

pub fn delete(rows: Rows, key: &[u8]) {
    ecalli!(
        Op::Delete.id(),
        [rows.register(), ptr(key), key.len() as u64, 0, 0, 0]
    );
}

/// The rows of a table or committed map after the key `after`, or from its
/// first, as `E(↕key, ↕value)` back to back in the table's order, filling
/// at most `out`; returns the bytes written, 0 at the end, or
/// [`code::FULL`] when the next row alone does not fit.
pub fn scan(rows: Rows, after: Option<&[u8]>, out: &mut [u8]) -> u64 {
    scan_raw(rows.register(), after, out)
}

/// [`scan`] with `rows` as its register.
pub fn scan_raw(rows: u64, after: Option<&[u8]>, out: &mut [u8]) -> u64 {
    let cursor = after.unwrap_or_default();
    ecalli!(
        Op::Scan.id(),
        [
            rows,
            ptr(cursor),
            cursor.len() as u64,
            ptr_mut(out),
            out.len() as u64,
            u64::from(after.is_some())
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
    returned(|out| {
        ecalli!(
            Op::Call.id(),
            [
                u64::from(instance),
                u64::from(method),
                ptr(arguments),
                arguments.len() as u64,
                ptr_mut(out),
                out.len() as u64
            ]
        )
    })
}

/// Run one of this instance's attestable methods; its output, or an
/// error code with its detail, as [`call`].
pub fn attest(method: u32, arguments: &[u8]) -> Result<Vec<u8>, (u32, Vec<u8>)> {
    returned(|out| {
        ecalli!(
            Op::Attest.id(),
            [
                u64::from(method),
                ptr(arguments),
                arguments.len() as u64,
                ptr_mut(out),
                out.len() as u64,
                0
            ]
        )
    })
}

/// The result of `operation`, a call or an attest made with a reply buffer
/// as its output: the bytes it wrote there, or, with a non-zero status in
/// φ8, its code and those bytes as the detail.
fn returned(operation: impl FnOnce(&mut [u8]) -> (u64, u64)) -> Result<Vec<u8>, (u32, Vec<u8>)> {
    with_reply_buffer(|out| {
        let (len, status) = operation(out);
        let bytes = out[..(len as usize).min(out.len())].to_vec();
        match status {
            0 => Ok(bytes),
            code => Err((code as u32, bytes)),
        }
    })
}

/// The input a workflow's machine was resumed with, `len` bytes: an
/// encoded [`vos_wire::batch::Answer`] after an await, nothing after a
/// sleep. Copied by the agent straight into fresh capacity, which nothing
/// writes first.
fn resumed(len: u64) -> Vec<u8> {
    let len = len as usize;
    let mut input: Vec<u8> = Vec::with_capacity(len);
    if len > 0 {
        ecalli!(
            Op::Input.id(),
            [input.as_mut_ptr() as u64, 0, len as u64, 0, 0, 0]
        );
        // SAFETY: the agent wrote all `len` bytes of the input.
        unsafe { input.set_len(len) };
    }
    input
}

/// A workflow's request of another agent's instance, sent once its step
/// commits: it pauses the workflow, and returns the encoded answer once the
/// agent resumes it, at the latest `within` milliseconds of batch time
/// later (0 for the agent's default).
pub fn request(agent: u32, instance: u32, method: u32, arguments: &[u8], within: u64) -> Vec<u8> {
    let (len, _) = ecalli!(
        Op::Request.id(),
        [
            u64::from(agent),
            u64::from(instance),
            u64::from(method),
            ptr(arguments),
            arguments.len() as u64,
            within
        ]
    );
    resumed(len)
}

/// A workflow's wait for the result of a workflow it started at `agent`:
/// it pauses, and returns the encoded answer, as [`request`] does.
pub fn result(agent: u32, workflow: u64, within: u64) -> Vec<u8> {
    let (len, _) = ecalli!(
        Op::Result.id(),
        [u64::from(agent), workflow, within, 0, 0, 0]
    );
    resumed(len)
}

/// Pause a workflow until a batch at or past `time`.
pub fn sleep(time: u64) {
    ecalli!(Op::Sleep.id(), [time, 0, 0, 0, 0, 0]);
}

/// Queue a message for another agent's instance, sent after the step
/// commits.
pub fn send(agent: u32, instance: u32, method: u32, arguments: &[u8]) {
    ecalli!(
        Op::Send.id(),
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

/// Open a section on `instance`'s state, which must be the workflow's own:
/// until [`close`], the row operations reach it, and the agent serves only
/// them, the time and logs.
pub fn open(instance: u32) {
    ecalli!(Op::Open.id(), [u64::from(instance), 0, 0, 0, 0, 0]);
}

/// Close the open section.
pub fn close() {
    ecalli!(Op::Close.id(), [0; 6]);
}
