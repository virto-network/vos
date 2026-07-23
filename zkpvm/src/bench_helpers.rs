//! Shared helpers for proving benchmarks and fixture generators.
//!
//! These are intentionally simple, deterministic PVM programs used only for
//! performance measurement and fixture generation. They are gated behind the
//! `prover` feature because they need the tracer and `javm` interpreter.

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use crate::SideNote;
use crate::core::tracing::TracingPvm;

/// Generate a program with `n` sequential ADD64 instructions followed by Trap.
/// Each ADD cycles through registers to avoid data hazards.
pub fn generate_add_program(n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut code = Vec::with_capacity(n * 3 + 1);
    let mut bitmask = Vec::with_capacity(n * 3 + 1);

    let mut ra: u8 = 0;
    let mut rb: u8 = 1;
    let mut rd: u8 = 2;

    for _ in 0..n {
        // Add64: 3 bytes [opcode, ra|(rb<<4), rd]
        code.push(Opcode::Add64 as u8);
        code.push(ra | (rb << 4));
        code.push(rd);
        bitmask.push(1);
        bitmask.push(0);
        bitmask.push(0);

        // Cycle registers (13 registers in PVM: 0..12)
        ra = (ra + 1) % 13;
        rb = (rb + 1) % 13;
        rd = (rd + 1) % 13;
    }

    // Trap at the end
    code.push(Opcode::Trap as u8);
    bitmask.push(1);

    (code, bitmask)
}

/// Trace an `n = 2^log_size`-step add program and return its side note.
pub fn add_side_note(log_size: u32) -> (SideNote, usize) {
    let n_steps = 1usize << log_size;
    let (code, bitmask) = generate_add_program(n_steps);
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    for i in 0..13 {
        regs[i] = (i as u64) + 1;
    }
    let gas = (n_steps as u64 + 100) * 100;
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 64 * 1024],
        gas,
        16, // mem_cycles
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    assert!(
        steps.len() >= n_steps,
        "expected at least {n_steps} steps, got {}",
        steps.len()
    );
    (SideNote::new(steps, code, bitmask), n_steps)
}
