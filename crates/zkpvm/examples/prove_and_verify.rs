//! End-to-end example: prove + verify a tiny PVM program.
//!
//! Demonstrates the full deployer workflow:
//!
//!   1. Compile / hand-assemble PVM bytecode + bitmask.
//!   2. Run the bytecode through the tracing interpreter to get
//!      a step-by-step witness.
//!   3. Build a `SideNote` from the trace + bytecode.
//!   4. Generate a STARK proof.
//!   5. Extract the program-commitment hash from the proof.
//!   6. Verify the proof against the hash (no SideNote needed —
//!      this is what a deployed verifier sees).
//!   7. Demonstrate `verify_chain` over a single segment for the
//!      multi-segment workflow.
//!
//! Run with:
//!     cargo run --example prove_and_verify -p zkpvm --release
//!
//! Reads ~5 seconds on a modern x86 desktop.

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::ExitReason;
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{
    program_commitment_hex, program_commitment_of_proof, prove, verify, verify_chain, SideNote,
    PROOF_FORMAT_VERSION,
};
use zkpvm_verifier::verify_standalone;

fn main() {
    println!("zkpvm prove_and_verify example");
    println!("PROOF_FORMAT_VERSION = {PROOF_FORMAT_VERSION}");
    println!();

    // ── Step 1: program ────────────────────────────────────────────
    // Add64 ra=0 rb=1 rd=2: regs[2] = regs[0] + regs[1].
    // Then Trap to terminate.
    let code = vec![
        Opcode::Add64 as u8, 0x10, 2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1];

    // ── Step 2: trace ──────────────────────────────────────────────
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 200;
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],                        // ECALL args
        regs,
        vec![0u8; 4 * 1024 * 1024],    // 4 MiB flat memory
        10_000,                        // gas budget
        25,                            // max steps
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, ExitReason::Trap, "expected Trap exit");
    let steps = tracing.into_trace();
    println!("Traced {} step(s); regs[2] = {}", steps.len(), steps[0].regs_after[2]);

    // ── Step 3 + 4: SideNote → prove ───────────────────────────────
    let mut side_note = SideNote::new(steps, code.clone(), bitmask.clone());
    let t = std::time::Instant::now();
    let proof = prove(&mut side_note).expect("prove() failed");
    println!("Proved in {:.2?}", t.elapsed());

    // ── Step 5: extract program-commitment hash ────────────────────
    let prog_hash = program_commitment_of_proof(&proof);
    let prog_hash_hex = program_commitment_hex(&proof);
    println!("Program commitment: {prog_hash_hex}");

    // ── Step 6a: deployer-side standalone verification ─────────────
    // This is what a verifier service sees: just the proof + the
    // program identity hash.  No access to the trace.
    let t = std::time::Instant::now();
    verify_standalone(proof.clone(), prog_hash).expect("verify_standalone() failed");
    println!("verify_standalone: ok ({:.2?})", t.elapsed());

    // ── Step 6b: prover-side verify (with SideNote) ────────────────
    // Equivalent guarantee, but available only with the prover
    // feature on (re-runs trace generation under the hood).  Useful
    // for prover-side regression testing.
    verify(proof.clone(), &side_note).expect("verify() failed");
    println!("verify (prover-side): ok");

    // ── Step 7: single-segment chain (degenerate) ──────────────────
    // verify_chain checks a sequence of segment proofs where each
    // segment's final_state matches the next's initial_state.  With
    // one segment there's nothing to chain, but the API is the same
    // as a multi-segment deployment would use.
    verify_chain(&[proof.clone()], &[&side_note]).expect("verify_chain() failed");
    println!("verify_chain ([1 segment]): ok");

    // ── Bonus: serialize + deserialize round-trip ─────────────────
    // Proofs are Serde-friendly.  Production deployments typically
    // store / transmit them as bincode or postcard blobs.
    let proof_bytes = bincode::serialize(&proof).expect("bincode serialize failed");
    println!("Proof size: {} bytes", proof_bytes.len());
    let proof_decoded: zkpvm::Proof =
        bincode::deserialize(&proof_bytes).expect("bincode deserialize failed");
    verify_standalone(proof_decoded, prog_hash).expect("verify_standalone (decoded) failed");
    println!("verify_standalone (after roundtrip): ok");

    println!();
    println!("All checks passed.");
}
