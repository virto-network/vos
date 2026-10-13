//! A tampered precompile call never yields an accepted proof. The honest
//! one-hash run proves and verifies; corrupting the recorded compression
//! input, its output bytes in the memory ledger, or dropping the call
//! altogether is rejected at proving or at verification.

use vos_pvm_bench::{GAS, guest_program};
use vos_pvm_proof::{prove_refine, trace_refine_with_output, verify_refine_bundle_replayed};

/// Whether proving and replayed verification accept the possibly tampered
/// trace. A prover panic counts as a rejection.
fn accepted(
    tamper: impl FnOnce(&mut vos_pvm_proof::SideNote),
    program: &[u8],
    arguments: &[u8],
) -> bool {
    let (mut trace, _) = trace_refine_with_output(program, arguments, GAS, 32).expect("trace");
    tamper(&mut trace.slices[0].side_note);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove_refine(trace).ok().is_some_and(|bundle| {
            verify_refine_bundle_replayed(&bundle, program, arguments, GAS).is_ok()
        })
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
