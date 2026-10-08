//! The settlement verifier runs on the PVM and accepts the honest proof.
//!
//! Links `settlement-verifier`'s `settle.elf` (which embeds the
//! `bool_proof.postcard` fixture and runs the full Poseidon2-M31 verify) as a
//! Gray Paper 0.8.0 standard program, executes it, and checks the verdict it
//! leaves in φ[7]: 0xACCE for accept. It reports the number of instructions
//! executed, the on-chain cost of a settlement verify. The tampered-proof
//! rejection is covered by `settle_fixture`.
//!
//! The ELF is built by `just build-settle`; the test fails without it.

use vos_pvm::ExitReason;
use vos_pvm::refine::{Machine, MachineObservation};

/// `settle::halt(code)` puts the verdict in a0, which is φ[7], then executes
/// `unimp`, which ends the run as a panic.
const PHI_A0: usize = 7;
const ACCEPT: u64 = 0xACCE;
const REJECT: u64 = 0x5E5;

#[test]
fn settle_verify_accepts_on_pvm() {
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/settlement-verifier/target/riscv64em-vos/release/settle.elf"
    );
    let elf = std::fs::read(elf_path)
        .unwrap_or_else(|error| panic!("settle.elf missing ({error}); run `just build-settle`"));
    let program = vos_pvm_compiler::link_elf_spi(&elf).expect("link settle.elf");

    let gas: u64 = 100_000_000_000;
    let mut machine = Machine::load(&program, &[], gas).expect("load settle program");
    let mut instructions = 0u64;
    let exit = machine.resume_observed(|event| {
        if let MachineObservation::Instruction(_) = event {
            instructions += 1;
        }
    });
    let result = machine.registers()[PHI_A0];
    let gas_used = gas - machine.gas_remaining();
    eprintln!("settle exit={exit:?} instructions={instructions} gas={gas_used} a0={result:#x}");

    assert_ne!(exit, ExitReason::OutOfGas, "the verify ran out of gas");
    assert_ne!(result, REJECT, "the verify rejected the honest fixture");
    assert_eq!(
        result, ACCEPT,
        "expected the verify to accept (0xACCE); got {result:#x} (0xDEAD is an \
         internal panic), exit {exit:?} after {instructions} instructions"
    );
}
