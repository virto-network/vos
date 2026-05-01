//! Fuzz target: random PVM program → trace → prove → verify_standalone.
//!
//! Properties checked:
//!
//! 1. **No panics.**  No matter what bytes the fuzzer hands us, the
//!    interpret → trace → prove → verify pipeline must not panic.
//!    Panics here are bugs in the AIR, the trace fill, or one of
//!    the cross-chip lookups.
//!
//! 2. **Roundtrip soundness.**  Whenever a trace successfully
//!    proves, the resulting proof must `verify_standalone` against
//!    its own program-commitment hash.  A failure here would mean
//!    the prover wrote a proof the verifier rejects — i.e. a logup
//!    imbalance or a constraint that doesn't fire under all valid
//!    traces.
//!
//! Run from the workspace root:
//!     cargo install cargo-fuzz   # one-time
//!     cd crates/zkpvm
//!     cargo fuzz run prove_verify_roundtrip -- -max_total_time=300
//!
//! Corpus seeds in `corpus/prove_verify_roundtrip/` accumulate
//! over runs; each seed is a `FuzzInput` Postcard / arbitrary
//! encoding of (code, bitmask, regs, gas, max_steps).

#![no_main]

use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, program_commitment_of_proof, SideNote};
use zkpvm_verifier::verify_standalone;

/// Bounds for fuzz input — keep proving fast (single-digit seconds
/// per case) so the fuzzer covers ground.  Tightening these caps
/// shifts coverage toward shorter executions; widening makes each
/// case more expensive.
const MAX_CODE_BYTES: usize = 64;
const MAX_STEPS: u8 = 16;
const FLAT_MEM_BYTES: usize = 64 * 1024; // 64 KiB

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Raw program bytes — at most MAX_CODE_BYTES.  Bitmask is
    /// derived deterministically (every basic block is one
    /// instruction) so the fuzzer doesn't have to learn the
    /// bitmask format separately.
    code: Vec<u8>,
    /// Initial register state (low bytes are most interesting; we
    /// truncate to the actual register count below).
    regs: Vec<u64>,
}

fuzz_target!(|input: FuzzInput| {
    let mut code = input.code;
    code.truncate(MAX_CODE_BYTES);
    if code.is_empty() {
        return;
    }

    // Always terminate the trace with a Trap so the interpreter
    // exits cleanly.  Without this, random bytecode tends to walk
    // off the end of `code` into Trap-by-default, but the result
    // shape varies and the corpus is harder to seed.
    if code.last() != Some(&(Opcode::Trap as u8)) {
        if code.len() == MAX_CODE_BYTES {
            *code.last_mut().unwrap() = Opcode::Trap as u8;
        } else {
            code.push(Opcode::Trap as u8);
        }
    }

    // Bitmask: every byte starts a basic block.  This is permissive
    // (the canonical PVM layout has multi-byte instructions with
    // skip_len > 0) but guarantees TracingPvm decodes every byte
    // as a fresh instruction, which exercises the most opcode
    // permutations.
    let bitmask: Vec<u8> = vec![1; code.len()];

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    for (slot, &v) in regs.iter_mut().zip(input.regs.iter()) {
        *slot = v;
    }

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; FLAT_MEM_BYTES],
        100_000,
        MAX_STEPS,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    if steps.is_empty() {
        return;
    }

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = match prove(&mut side_note) {
        Ok(p) => p,
        // `prove` may legitimately fail on traces that the AIR
        // can't represent at the chosen log_size (e.g. too many
        // steps).  That's a bound, not a soundness bug — return
        // and let the fuzzer try a different seed.
        Err(_) => return,
    };

    let prog_hash = program_commitment_of_proof(&proof);

    // Property: every successful prove + correct hash must verify.
    verify_standalone(proof, prog_hash).expect("verify_standalone failed for honest prove output");
});
