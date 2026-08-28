//! Standard inner-machine host calls for agent-runtime guests.
//!
//! These are the only PVM-management operations a portable VOS agent runtime
//! needs. Application actors do not call them directly.

use super::ecall::{ecall1, ecall2_pair, ecall3, ecall4};

pub const MACHINE: u32 = 9;
pub const PEEK: u32 = 10;
pub const POKE: u32 = 11;
pub const PAGES: u32 = 12;
pub const INVOKE: u32 = 13;
pub const EXPUNGE: u32 = 14;

pub const RESULT_OK: u64 = 0;
pub const RESULT_OOB: u64 = u64::MAX - 2;
pub const RESULT_WHO: u64 = u64::MAX - 3;
pub const RESULT_FULL: u64 = u64::MAX - 4;
pub const RESULT_HUH: u64 = u64::MAX - 8;

/// Create an inner machine from a compact PVM code blob.
#[inline]
pub fn machine(program: &[u8], initial_pc: u32) -> u64 {
    ecall3(
        MACHINE,
        program.as_ptr() as u64,
        program.len() as u64,
        initial_pc as u64,
    )
}

/// Copy inner memory into this runtime's writable memory.
#[inline]
pub fn peek(machine: u32, source: u32, output: &mut [u8]) -> u64 {
    ecall4(
        PEEK,
        machine as u64,
        output.as_mut_ptr() as u64,
        source as u64,
        output.len() as u64,
    )
}

/// Copy runtime memory into writable inner memory.
#[inline]
pub fn poke(machine: u32, destination: u32, input: &[u8]) -> u64 {
    ecall4(
        POKE,
        machine as u64,
        input.as_ptr() as u64,
        destination as u64,
        input.len() as u64,
    )
}

/// Allocate, free, or change the mode of complete inner-memory pages.
#[inline]
pub fn pages(machine: u32, first: u32, count: u32, mode: u8) -> u64 {
    ecall4(
        PAGES,
        machine as u64,
        first as u64,
        count as u64,
        mode as u64,
    )
}

/// Invoke an inner machine.
///
/// `state[0]` is remaining gas and `state[1..]` are its thirteen registers.
/// Both are updated in place. The returned pair is `(exit, detail)`, where
/// detail carries the host-call ID or fault address when applicable.
#[inline]
pub fn invoke(machine: u32, state: &mut [u64; 14]) -> [u64; 2] {
    ecall2_pair(INVOKE, machine as u64, state.as_mut_ptr() as u64)
}

/// Destroy an inner machine and return its current instruction counter.
#[inline]
pub fn expunge(machine: u32) -> u64 {
    ecall1(EXPUNGE, machine as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_the_contiguous_standard_range() {
        assert_eq!(
            [MACHINE, PEEK, POKE, PAGES, INVOKE, EXPUNGE],
            [9, 10, 11, 12, 13, 14]
        );
    }
}
