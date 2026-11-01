//! Device programs as ingress and a device take them
//! (`vos_pvm_recair::device`): a program's id, a proof's bytes, and
//! a run past the program's log sizes refused by the prover, under format
//! 46 itself.

use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::core::ecall::ECALL_WITNESS_INPUT;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::device::{FORMAT, MAX_PROOF_BYTES, Program, decode, encode, program_id};
use vos_pvm_recair::masked::MaskRng;

use crate::support::{blob, io_and_halt, io_bytes, witness};

/// A kernel reading up to 1,024 witness bytes onto its stack: its rows
/// follow its input's length.
fn reader() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1)
        .add_imm_64(Reg::S0, Reg::SP, -1024)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 1024)
        .ecalli(ECALL_WITNESS_INPUT);
    io_and_halt(&mut asm);
    asm.build()
}

/// A run that needs more rows than its program's log sizes is refused by
/// the prover, never proved at a larger shape: the reader's program sized
/// by a 16-byte reference run, then a run of 1,000 bytes; under format 46.
#[test]
fn a_run_past_the_programs_log_sizes_is_refused_by_the_prover() {
    let kernel = reader();
    let program = Program::install(&kernel, &[7; 16]).expect("installs");
    let (proof, _) = program.prove(&[9; 16], MaskRng::default()).expect("proves");
    let bytes = encode(&proof.proof).expect("encodes");
    program.verify(&proof.io, &bytes).expect("verifies");
    let error = program
        .prove(&[9; 1000], MaskRng::default())
        .expect_err("past the shape");
    assert!(
        matches!(&error, ProveError::Segment(message) if message.contains("its shape")),
        "{error:?}"
    );
    let larger = Program::install(&kernel, &[7; 1000]).expect("installs");
    assert_ne!(larger.log_sizes(), program.log_sizes());
    assert_ne!(larger.id(), program.id());
}

/// A program's id is its kernel's under the format: the same kernel gives
/// the same id from any reference of its shape; another kernel, other log
/// sizes or another format another id.
#[test]
fn a_programs_id_names_its_kernel_its_shape_and_its_format() {
    let program = Program::install(&blob(), &witness(1)).expect("installs");
    let again = Program::install(&blob(), &witness(2)).expect("installs");
    assert_eq!(program.id(), again.id());
    assert_eq!(*program.id(), program_id(&FORMAT, program.program()));
    let mut taller = program.program().clone();
    taller.log_sizes[0] += 1;
    assert_ne!(program_id(&FORMAT, &taller), *program.id());
    let other = vos_pvm_proof::format::Format {
        number: 99,
        ..FORMAT
    };
    assert_ne!(program_id(&other, program.program()), *program.id());
    let reader = Program::install(&reader(), &[7; 64]).expect("installs");
    assert_ne!(reader.id(), program.id());
}

/// A proof's bytes decode to the proof alone: re-encoded, the same bytes;
/// a byte more, a byte fewer, another format's or past the cap refused;
/// and they hold no io-hash, which the verifier takes from its caller.
#[test]
fn a_device_proofs_bytes_are_canonical() {
    let program = Program::install(&blob(), &witness(1)).expect("installs");
    let (proof, _) = program
        .prove(&witness(3), MaskRng::default())
        .expect("proves");
    assert_eq!(proof.io, io_bytes());
    let bytes = encode(&proof.proof).expect("encodes");
    assert_eq!(
        encode(&decode(&bytes).expect("decodes")),
        Some(bytes.clone())
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(decode(&longer), Err(Error::Decode)));
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    let mut other = bytes.clone();
    other[0] = 44;
    assert!(matches!(decode(&other), Err(Error::Format)));
    assert!(matches!(
        decode(&vec![0; MAX_PROOF_BYTES + 1]),
        Err(Error::Length)
    ));
    let mut io = proof.io;
    io[0] ^= 1;
    assert!(program.verify(&io, &bytes).is_err());
}

/// A queried value written as itself plus `p`, the same field element in
/// other bytes, decodes and re-encodes to its own bytes, and the verifier
/// refuses it before any check of its values: a proof's bytes are one
/// encoding of its values.
#[test]
fn a_queried_value_plus_p_is_refused() {
    use stwo::core::fields::m31::{BaseField, P};
    let program = Program::install(&blob(), &witness(1)).expect("installs");
    let (proof, _) = program
        .prove(&witness(3), MaskRng::default())
        .expect("proves");
    let mut wide = proof.proof.clone();
    let value = &mut wide.stark_proof.0.queried_values[0][0][0];
    *value = BaseField::from_u32_unchecked(value.0 + P);
    let bytes = encode(&wide).expect("encodes");
    assert_eq!(
        encode(&decode(&bytes).expect("decodes")),
        Some(bytes.clone())
    );
    assert!(matches!(
        program.verify(&proof.io, &bytes),
        Err(Error::Noncanonical)
    ));
}
