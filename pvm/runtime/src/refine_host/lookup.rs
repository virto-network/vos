//! `historical_lookup` as a VOS node serves it: from the running agent's
//! programs, at the node's price.

use super::result;
use crate::refine::Machine;
use crate::{ExitReason, Gas};

/// What a lookup that finds a program costs beyond its copy, which costs a
/// gas a byte.
pub const LOOKUP_GAS: Gas = 10;

/// Serve the outer machine's `historical_lookup`: φ7 the service, the
/// caller's own as `u64::MAX`, φ8 the hash, φ9 the output, φ10 the offset
/// into the program and φ11 the most bytes to copy. φ7 becomes the
/// program's whole length, or `NONE`.
///
/// `find` gives the program a hash names, when the agent of `service` may
/// load it. A lookup naming another service finds none: JAM would read
/// that service's preimages, which are not this agent's programs. A
/// program found costs [`LOOKUP_GAS`] and a gas for each byte copied, out
/// of gas when the machine has less; a hash or an output outside its
/// memory panics.
pub fn serve_lookup<P: AsRef<[u8]>>(
    machine: &mut Machine,
    service: u64,
    find: impl FnOnce(&[u8; 32]) -> Option<P>,
) -> Result<(), ExitReason> {
    let registers = *machine.registers();
    let mut hash = [0u8; 32];
    if !machine
        .memory()
        .read_bytes_checked(registers[8] as u32, &mut hash)
    {
        return Err(ExitReason::Panic);
    }
    let own = registers[7] == u64::MAX || registers[7] == service;
    let Some(program) = own.then(|| find(&hash)).flatten() else {
        machine.registers_mut()[7] = result::NONE;
        return Ok(());
    };
    let program = program.as_ref();
    let window = crate::refine::window(program.len(), registers[10], registers[11]);
    if !machine.charge(LOOKUP_GAS + window.len() as u64) {
        return Err(ExitReason::OutOfGas);
    }
    if !machine
        .memory_mut()
        .write_bytes_checked(registers[9] as u32, &program[window])
    {
        return Err(ExitReason::Panic);
    }
    machine.registers_mut()[7] = program.len() as u64;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};

    /// A lookup of hash `[7; 32]` naming service `named`, served for
    /// service 1, whose program is 300 bytes of 9s, copying at most `len`
    /// bytes from offset 100: φ7, the gas it took, and the bytes copied.
    fn lookup(named: u64, len: u64) -> (u64, u64, Vec<u8>) {
        let blob = build_standard_program(&StandardProgram {
            ro_data: vec![],
            rw_data: vec![],
            heap_pages: 0,
            stack_size: 4096,
            code: CodeBlob {
                jump_table: vec![],
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let mut machine = Machine::load(&blob, &[7; 32], 1_000_000).unwrap();
        let registers = machine.registers_mut();
        let out = registers[1] - 4096;
        registers[8] = registers[7];
        (registers[7], registers[9], registers[10], registers[11]) = (named, out, 100, len);
        let before = machine.gas_remaining();
        serve_lookup(&mut machine, 1, |hash| {
            (*hash == [7; 32]).then(|| vec![9u8; 300])
        })
        .unwrap();
        let mut copied = vec![0u8; len.min(200) as usize];
        assert!(machine.memory().read_bytes_checked(out as u32, &mut copied));
        let answer = machine.registers()[7];
        (answer, before - machine.gas_remaining(), copied)
    }

    #[test]
    fn a_lookup_costs_its_copy_and_finds_only_the_agents_own() {
        for own in [u64::MAX, 1] {
            let (answer, gas, copied) = lookup(own, 64);
            assert_eq!((answer, gas), (300, LOOKUP_GAS + 64));
            assert_eq!(copied, vec![9; 64]);
        }
        let (answer, gas, _) = lookup(1, 1_000);
        assert_eq!((answer, gas), (300, LOOKUP_GAS + 200), "from the offset on");
        let (answer, gas, copied) = lookup(2, 64);
        assert_eq!((answer, gas), (result::NONE, 0), "another service's");
        assert_eq!(copied, vec![0; 64]);
    }
}
