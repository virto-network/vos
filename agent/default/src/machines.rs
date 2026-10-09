//! Inner machines: an actor or attestable program, from the node's pool
//! (`instantiate`) or built here from its blob (the loader), which a JAM
//! node's preimages supply.

use alloc::vec::Vec;

use vos_wire::abi::code;

use crate::host::{
    EXPUNGE, INSTANTIATE, INVOKE, MACHINE, PAGES, PEEK, POKE, ecalli, historical_lookup, ptr,
    ptr_mut,
};

const ZONE: u64 = 1 << 16;
const PAGE: u64 = 4096;
const INPUT: u64 = 1 << 24;
/// Where a machine returns to halt.
pub const HALT: u64 = (1 << 32) - ZONE;
/// The top of the standard stack.
pub const STACK_TOP: u64 = (1 << 32) - 2 * ZONE - INPUT;
/// The standard argument window.
pub const ARGUMENTS: u64 = (1 << 32) - ZONE - INPUT;

const ALLOCATE_READ_WRITE: u64 = 2;
const SET_READ_ONLY: u64 = 3;

/// Why no machine could be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Every inner machine is in use.
    Full,
    /// Neither the pool nor the preimages know the program.
    Missing,
}

/// How an invocation stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Halt,
    Panic,
    Fault,
    Host(u64),
    OutOfGas,
}

/// An inner machine: gas and registers between invocations, as `invoke`
/// reads and writes them.
pub struct Machine {
    pub id: u64,
    pub frame: [u64; 14],
}

impl Machine {
    /// A machine for `program`, laid out with no arguments, its registers
    /// ready for the halt and stack conventions.
    pub fn acquire(program: &[u8; 32]) -> Result<Self, Unavailable> {
        let (id, _) = ecalli!(INSTANTIATE, [ptr(program), 0, 0, 0, 0, 0]);
        let id = match id {
            code::FULL => return Err(Unavailable::Full),
            code::WHAT | code::WHO => {
                let blob = historical_lookup(program).ok_or(Unavailable::Missing)?;
                load(&blob)?
            }
            id => id,
        };
        let mut frame = [0u64; 14];
        frame[1] = HALT;
        frame[2] = STACK_TOP;
        Ok(Self { id, frame })
    }

    pub fn gas(&self) -> u64 {
        self.frame[0]
    }

    pub fn set_gas(&mut self, gas: u64) {
        self.frame[0] = gas;
    }

    /// Charge `gas`; false when the machine has less.
    pub fn charge(&mut self, gas: u64) -> bool {
        match self.frame[0].checked_sub(gas) {
            Some(left) => {
                self.frame[0] = left;
                true
            }
            None => {
                self.frame[0] = 0;
                false
            }
        }
    }

    pub fn register(&self, index: usize) -> u64 {
        self.frame[1 + index]
    }

    pub fn set_register(&mut self, index: usize, value: u64) {
        self.frame[1 + index] = value;
    }

    /// Run until the machine stops.
    pub fn invoke(&mut self) -> Exit {
        let (status, detail) = ecalli!(
            INVOKE,
            [self.id, ptr_mut(as_bytes(&mut self.frame)), 0, 0, 0, 0]
        );
        match status {
            0 => Exit::Halt,
            1 => Exit::Panic,
            2 => Exit::Fault,
            3 => Exit::Host(detail),
            4 => Exit::OutOfGas,
            _ => Exit::Panic,
        }
    }

    /// The machine's bytes at `address`, or `None` when unreadable.
    pub fn peek(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        if len == 0 {
            return Some(bytes);
        }
        let (status, _) = ecalli!(
            PEEK,
            [
                self.id,
                bytes.as_mut_ptr() as u64,
                address,
                len as u64,
                0,
                0
            ]
        );
        if status != code::OK {
            return None;
        }
        // SAFETY: the host wrote all `len` bytes.
        unsafe { bytes.set_len(len) };
        Some(bytes)
    }

    /// Write the machine's memory at `address`; false when unwritable.
    pub fn poke(&self, address: u64, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        let (status, _) = ecalli!(
            POKE,
            [self.id, ptr(bytes), address, bytes.len() as u64, 0, 0]
        );
        status == code::OK
    }

    /// Map `len` bytes at `address` read-write, and write `bytes` there.
    pub fn map(&self, address: u64, len: u64, bytes: &[u8]) -> bool {
        let pages = len.div_ceil(PAGE);
        if pages == 0 {
            return true;
        }
        let (status, _) = ecalli!(
            PAGES,
            [self.id, address / PAGE, pages, ALLOCATE_READ_WRITE, 0, 0]
        );
        status == code::OK && self.poke(address, bytes)
    }

    /// Map `len` bytes at `address`, write `bytes` there and make them
    /// read-only.
    pub fn map_read_only(&self, address: u64, len: u64, bytes: &[u8]) -> bool {
        let pages = len.div_ceil(PAGE);
        if pages == 0 {
            return true;
        }
        self.map(address, len, bytes)
            && ecalli!(PAGES, [self.id, address / PAGE, pages, SET_READ_ONLY, 0, 0]).0 == code::OK
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        ecalli!(EXPUNGE, [self.id, 0, 0, 0, 0, 0]);
    }
}

fn as_bytes(frame: &mut [u64; 14]) -> &mut [u8] {
    // SAFETY: fourteen little-endian words, the layout `invoke` reads.
    unsafe { core::slice::from_raw_parts_mut(frame.as_mut_ptr().cast::<u8>(), 14 * 8) }
}

fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| value << 8 | u64::from(*byte))
}

/// Build a machine from a standard program: its code through `machine`,
/// then each region through `pages` and `poke`, at the Gray Paper's
/// standard layout with no arguments.
fn load(blob: &[u8]) -> Result<u64, Unavailable> {
    let field = |at: usize, len: usize| blob.get(at..at + len).map(le).ok_or(Unavailable::Missing);
    let ro_len = field(0, 3)? as usize;
    let rw_len = field(3, 3)? as usize;
    let heap_pages = field(6, 2)?;
    let stack_len = field(8, 3)?;
    let ro = blob.get(11..11 + ro_len).ok_or(Unavailable::Missing)?;
    let rw = blob
        .get(11 + ro_len..11 + ro_len + rw_len)
        .ok_or(Unavailable::Missing)?;
    let at = 11 + ro_len + rw_len;
    let code_len = field(at, 4)? as usize;
    let code = blob
        .get(at + 4..at + 4 + code_len)
        .ok_or(Unavailable::Missing)?;

    let (id, _) = ecalli!(MACHINE, [ptr(code), code.len() as u64, 0, 0, 0, 0]);
    match id {
        code::FULL => return Err(Unavailable::Full),
        code::HUH | code::WHAT => return Err(Unavailable::Missing),
        _ => {}
    }
    let machine = Machine { id, frame: [0; 14] };
    if !machine.map_read_only(ZONE, ro_len as u64, ro) {
        return Err(Unavailable::Missing);
    }
    let rw_base = 2 * ZONE + (ro_len as u64).div_ceil(ZONE) * ZONE;
    let rw_size = (rw_len as u64 + heap_pages * PAGE).div_ceil(PAGE) * PAGE;
    let stack_size = stack_len.div_ceil(PAGE) * PAGE;
    if !machine.map(rw_base, rw_size, rw) || !machine.map(STACK_TOP - stack_size, stack_size, &[]) {
        return Err(Unavailable::Missing);
    }
    let machine = core::mem::ManuallyDrop::new(machine);
    Ok(machine.id)
}
