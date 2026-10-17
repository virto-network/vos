//! Writes small segment proofs to check the guest verifier with: a
//! two-step program traced and proved under format 31 (Poseidon2-M31) and
//! format 33 (Blake2s), each as `<dir>/f<number>.postcard` with its program
//! commitment as `<dir>/f<number>.commitment.postcard`.
//!
//! ```text
//! make-proofs <dir>
//! ```

use vos_pvm::ExitReason;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::{SideNote, format, program_commitment_of_proof, prove_format};

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("make-proofs <dir>"));
    std::fs::create_dir_all(&dir).unwrap();
    // `Add64 φ2 = φ0 + φ1`, then `Trap`.
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    for format in [&format::SEGMENT, &format::LEGACY_SEGMENT] {
        let mut registers = [0u64; PVM_REGISTER_COUNT];
        registers[0] = 100;
        registers[1] = 200;
        let machine = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            registers,
            vec![0u8; 4 * 1024 * 1024],
            10_000,
        );
        let mut tracer = TracingPvm::new(machine);
        assert_eq!(tracer.run(), ExitReason::Panic);
        let mut side_note = SideNote::new(tracer.into_trace(), code.clone(), bitmask.clone());
        let proof = prove_format(&mut side_note, format).expect("proves");
        let commitment = program_commitment_of_proof(&proof);
        vos_pvm_proof_verifier::verify_standalone(proof.clone(), commitment).expect("verifies");
        let name = format!("f{}", format.number);
        std::fs::write(
            dir.join(format!("{name}.postcard")),
            postcard::to_allocvec(&proof).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("{name}.commitment.postcard")),
            postcard::to_allocvec(&commitment).unwrap(),
        )
        .unwrap();
        println!(
            "{name}: mask {:#x}, log sizes {:?}",
            proof.component_mask, proof.log_sizes
        );
    }
}
