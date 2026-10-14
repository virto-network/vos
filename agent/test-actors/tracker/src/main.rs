//! A refine program that drives one inner machine with the default agent's
//! own code, for the agent's tests: acquired as the agent acquires one,
//! tracked or not, the agent's writes made into it, and run until it stops
//! with its precompiles served. It reports how the machine stopped, its
//! gas and registers, the pages written and its output.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use vos_agent::machines::{ARGUMENTS, Exit, Machine, header};
use vos_sdk::abi::precompile;
use vos_sdk::prelude::*;

vos_sdk::program_runtime!(16 << 20);

core::arch::global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, tracker_refine",
    "mv ra, s0",
    "ret",
);

/// What to run: the program, whether to track it, the gas it gets, its
/// arguments in the standard window, the agent's writes into it before it
/// runs, registers to set, and what to read back once it stops.
#[derive(Decode)]
struct Probe {
    program: [u8; 32],
    track: bool,
    gas: u64,
    arguments: Option<Vec<u8>>,
    writes: Vec<(u64, Vec<u8>)>,
    registers: Vec<(u8, u64)>,
    reads: Vec<(u64, u32)>,
}

/// How the machine stopped (as `invoke`'s status) and its detail, its gas
/// and registers, the precompile calls served, the pages written when
/// tracked, its output by the halt convention when it halted, and the
/// bytes read back, empty where unreadable.
#[derive(Encode)]
struct Report {
    status: u8,
    detail: u64,
    gas: u64,
    registers: Vec<u64>,
    served: u32,
    written: Option<Vec<u64>>,
    output: Vec<u8>,
    reads: Vec<Vec<u8>>,
}

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

/// # Safety
///
/// The host maps the argument window at (`arguments`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn tracker_refine(arguments: *const u8, len: u64) -> Output {
    // SAFETY: see the function's contract.
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    let (probe, _) = Probe::decode(arguments).expect("a probe");
    let bytes = ManuallyDrop::new(run(probe).encode());
    Output {
        address: bytes.as_ptr() as u64,
        len: bytes.len() as u64,
    }
}

fn run(probe: Probe) -> Report {
    let mut machine = Machine::acquire(&probe.program).expect("a machine");
    if let Some(arguments) = &probe.arguments {
        assert!(machine.map_read_only(ARGUMENTS, arguments.len() as u64, arguments));
        machine.set_register(7, ARGUMENTS);
        machine.set_register(8, arguments.len() as u64);
    }
    if probe.track {
        let header = header(&probe.program).expect("a header");
        assert!(machine.track(&header), "armed");
    }
    for (address, bytes) in &probe.writes {
        assert!(
            machine.write(*address, bytes).is_ok(),
            "the agent's write lands"
        );
    }
    for &(index, value) in &probe.registers {
        machine.set_register(usize::from(index), value);
    }
    machine.set_gas(probe.gas);
    let mut served = 0;
    let (status, detail) = loop {
        match machine.invoke() {
            Exit::Host(id) if precompile::price(id).is_some() => match machine.precompile(id) {
                Ok(()) => served += 1,
                Err(_) => break (1, 0),
            },
            Exit::Halt => break (0, 0),
            Exit::Panic => break (1, 0),
            Exit::Fault(address) => break (2, address),
            Exit::Host(id) => break (3, id),
            Exit::OutOfGas => break (4, 0),
        }
    };
    let output = match (status, &probe.arguments) {
        (0, Some(_)) => machine
            .peek(machine.register(7), machine.register(8) as usize)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let reads = probe
        .reads
        .iter()
        .map(|&(address, len)| machine.peek(address, len as usize).unwrap_or_default())
        .collect();
    Report {
        status,
        detail,
        gas: machine.gas(),
        registers: (0..13).map(|index| machine.register(index)).collect(),
        served,
        written: machine
            .written()
            .map(|pages| pages.iter().copied().collect()),
        output,
        reads,
    }
}
