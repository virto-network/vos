//! THE FINISH LINE: run the settlement verifier on the JAM PVM and measure it.
//!
//! Transpiles `recursion-verifier`'s `settle.elf` (which `include_bytes!`es the
//! `bool_proof.postcard` fixture and runs the full Poseidon2-M31 verify) to JAVM
//! bytecode, executes it under the tracing interpreter, and asserts the verify
//! ACCEPTS the honest proof (`halt(0xACCE)` ⇒ a0 = φ[7] = 0xACCE), reporting the
//! on-chain **cycle count** (trace steps) of an M31-algebraic settlement verify.
//!
//! This is the end-to-end proof that the verifier RUNS — value-correctly — on
//! the real target (build → link → transpile → EXECUTE → ACCEPT), not just that
//! it builds. The honest-accept here + the tampered-reject in `settle_fixture`
//! pin both verify directions.
//!
//! Skips if the ELF fixture is absent (built out-of-band; see settle_transpile).

use javm::ExitReason;
use zkpvm::core::tracing::TracingPvm;

/// a0 (x10) maps to PVM register φ[7]; `settle::halt(code)` puts the verify
/// result there before the halting `unimp`.
const PHI_A0: usize = 7;
const ACCEPT: u64 = 0xACCE;
const REJECT: u64 = 0x5E5;

#[test]
fn settle_verify_accepts_on_pvm() {
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/recursion-verifier/target/riscv64em-javm/release/settle.elf"
    );
    let elf = match std::fs::read(elf_path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("settle.elf absent ({elf_path}); run `just build-settle` first — skipping");
            return;
        }
    };

    let blob = grey_transpiler::link_elf(&elf).expect("transpile settle.elf");

    // Generous gas; the verify is the whole point, so we don't want to clip it.
    let gas: u64 = 100_000_000_000;
    let (interp, _mem) =
        zkpvm::actor::interpreter_from_blob(&blob, gas).expect("build interpreter from blob");
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run();
    let steps = tracing.into_trace();

    let cycles = steps.len();
    let result = steps.last().map(|s| s.regs_after[PHI_A0]).unwrap_or(0);
    eprintln!("SETTLE-PVM exit={exit:?} cycles={cycles} a0(phi7)={result:#x}");

    assert_ne!(
        exit,
        ExitReason::OutOfGas,
        "the run hung / looped (OutOfGas) instead of executing the verify"
    );
    assert_ne!(
        result, REJECT,
        "the verify REJECTED the honest fixture (a0 = 0x5E5)"
    );
    assert_eq!(
        result, ACCEPT,
        "expected the verify to ACCEPT (a0 = 0xACCE); got {result:#x} \
         (0xDEAD = internal panic). exit={exit:?}, cycles={cycles}"
    );

    // The Poseidon2-M31 verify EXECUTES and ACCEPTS on the JAM PVM: ~1.07e7
    // cycles of real FRI-verify + Merkle-decommit + OODS, the representative
    // on-chain cost of an M31-algebraic settlement verify.
    eprintln!(
        "MILESTONE: Poseidon2-M31 settlement verify ACCEPTS on JAM PVM \
         in {cycles} cycles (build → link → transpile → EXECUTE → ACCEPT)."
    );
}
