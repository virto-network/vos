//! The agent's host calls: Gray Paper calls, and the two VOS refine
//! extensions, each of which answers `WHAT` on a JAM node.

use alloc::vec::Vec;

use vos_wire::abi::code;

pub const GAS: u64 = 0;
pub const FETCH: u64 = 2;
pub const READ: u64 = 4;
pub const WRITE: u64 = 5;
pub const HISTORICAL_LOOKUP: u64 = 7;
pub const MACHINE: u64 = 9;
pub const PEEK: u64 = 10;
pub const POKE: u64 = 11;
pub const PAGES: u64 = 12;
pub const INVOKE: u64 = 13;
pub const EXPUNGE: u64 = 14;
pub const INSTANTIATE: u64 = 0x480;
pub const STATE_READ: u64 = 0x481;
pub const STATE_SCAN: u64 = 0x482;

/// The calling service, for `read` and `historical_lookup`.
pub const SELF_SERVICE: u64 = u64::MAX;

#[cfg(target_arch = "riscv64")]
macro_rules! ecalli {
    ($id:expr, $a:expr) => {{
        let [a0, a1, a2, a3, a4, a5]: [u64; 6] = $a;
        let (r0, r1): (u64, u64);
        // SAFETY: the ecalli convention passes φ7..φ12 in a0..a5 and returns
        // in a0 and a1; pointer arguments name live buffers the host may
        // write.
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
        (r0, r1)
    }};
}

#[cfg(not(target_arch = "riscv64"))]
macro_rules! ecalli {
    ($id:expr, $a:expr) => {{
        let _: (u64, [u64; 6]) = ($id, $a);
        unreachable!("the agent runs on the PVM")
    }};
}

pub(crate) use ecalli;

pub fn ptr(bytes: &[u8]) -> u64 {
    bytes.as_ptr() as u64
}

pub fn ptr_mut(bytes: &mut [u8]) -> u64 {
    bytes.as_mut_ptr() as u64
}

/// A whole value from a call that copies from an offset into a buffer and
/// returns the whole length, or `NONE`: a first read into a small buffer
/// learns the length, and a longer value is read once more into a single
/// allocation of its size. Under the pipeline gas model, zero-filling a
/// buffer costs as much as copying into it, so nothing is filled.
fn whole(mut read: impl FnMut(*mut u8, u64, u64) -> u64) -> Option<Vec<u8>> {
    const HEAD: usize = 256;
    let mut head = [0u8; HEAD];
    let len = read(head.as_mut_ptr(), 0, HEAD as u64);
    if len == code::NONE || len == code::WHAT {
        return None;
    }
    let len = len as usize;
    let mut value = Vec::with_capacity(len);
    value.extend_from_slice(&head[..len.min(HEAD)]);
    if len > HEAD {
        // SAFETY: the capacity holds `len` bytes; the host writes the
        // `len - HEAD` after the head.
        unsafe {
            read(
                value.as_mut_ptr().add(HEAD),
                HEAD as u64,
                (len - HEAD) as u64,
            );
            value.set_len(len);
        }
    }
    Some(value)
}

/// The gas left to this invocation.
pub fn gas() -> u64 {
    ecalli!(GAS, [0; 6]).0
}

/// Trap the refine: the host serves no applied state (a JAM node until
/// witnesses), and a result computed as if the state were empty would
/// overwrite it.
pub fn unserved() -> ! {
    panic!("the host serves no applied state")
}

/// One `state_read` of `key`: up to `capacity` bytes of its value from
/// `offset`, copied to `out`. Returns the value's whole length, or `NONE`
/// when absent; traps when the host serves no applied state.
fn state_read_at(key: &[u8], out: *mut u8, offset: u64, capacity: u64) -> u64 {
    let (len, _) = ecalli!(
        STATE_READ,
        [ptr(key), key.len() as u64, out as u64, offset, capacity, 0]
    );
    if len == code::WHAT {
        unserved();
    }
    len
}

/// The agent's applied state, by agent-relative key; `None` when absent.
pub fn state_read(key: &[u8]) -> Option<Vec<u8>> {
    whole(|out, offset, capacity| state_read_at(key, out, offset, capacity))
}

/// A value of the agent's applied state read into `buffer`, with no
/// allocation: the value's whole length, of which `buffer` holds the start;
/// `None` when absent.
pub fn state_read_into(key: &[u8], buffer: &mut [u8]) -> Option<usize> {
    let len = state_read_at(key, buffer.as_mut_ptr(), 0, buffer.len() as u64);
    (len != code::NONE).then_some(len as usize)
}

/// A preimage of this service by hash: how a program's blob reaches the
/// loader when the host has no pool.
pub fn historical_lookup(hash: &[u8; 32]) -> Option<Vec<u8>> {
    whole(|out, offset, capacity| {
        ecalli!(
            HISTORICAL_LOOKUP,
            [SELF_SERVICE, ptr(hash), out as u64, offset, capacity, 0]
        )
        .0
    })
}

/// One accumulate input, by index (`fetch` kind 15). Accumulate's only: a
/// VOS node's refine host does not serve `fetch`.
pub fn fetch_input(index: u64) -> Option<Vec<u8>> {
    whole(|out, offset, capacity| ecalli!(FETCH, [out as u64, offset, capacity, 15, index, 0]).0)
}

/// A value of this service's storage.
pub fn read(key: &[u8]) -> Option<Vec<u8>> {
    whole(|out, offset, capacity| {
        ecalli!(
            READ,
            [
                SELF_SERVICE,
                ptr(key),
                key.len() as u64,
                out as u64,
                offset,
                capacity
            ]
        )
        .0
    })
}

/// Write a value of this service's storage; an empty value deletes it.
pub fn write(key: &[u8], value: &[u8]) {
    ecalli!(
        WRITE,
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
