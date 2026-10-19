//! A tampered precompile call never yields an accepted proof. The honest
//! one-hash run proves and verifies; corrupting the recorded compression
//! input, its output bytes in the memory ledger, or dropping the call
//! altogether is rejected at proving or at verification against the honest
//! run's program.

use vos_pvm_bench::{GAS, guest_program};
use vos_pvm_proof::kernel::trace_program;
use vos_pvm_proof::{prove, verify};

/// Whether a proof of the possibly tampered trace is produced and verifies
/// against the honest trace. A prover panic counts as a rejection.
fn accepted(
    tamper: impl FnOnce(&mut vos_pvm_proof::SideNote),
    program: &[u8],
    arguments: &[u8],
) -> bool {
    let trace = || trace_program(program, arguments, GAS).expect("trace").side_note;
    let honest = trace();
    let mut side_note = trace();
    tamper(&mut side_note);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(&mut side_note)
            .ok()
            .is_some_and(|proof| verify(proof, &honest).is_ok())
    }))
    .unwrap_or(false)
}

#[test]
fn tampered_precompile_calls_are_rejected() {
    let program = guest_program("hash-precompile");
    let arguments = 1u64.to_le_bytes();

    assert!(
        accepted(|_| {}, &program, &arguments),
        "the honest run proves"
    );
    assert!(
        !accepted(|note| note.blake2b_calls[0].h[0] ^= 1, &program, &arguments),
        "a corrupted compression input was accepted"
    );
    assert!(
        !accepted(
            |note| note.blake2b_mem_ops[0].out_bytes[0] ^= 1,
            &program,
            &arguments
        ),
        "corrupted compression output bytes were accepted"
    );
    assert!(
        !accepted(
            |note| {
                note.blake2b_calls.pop();
                note.blake2b_mem_ops.pop();
            },
            &program,
            &arguments
        ),
        "a dropped precompile call was accepted"
    );
}
