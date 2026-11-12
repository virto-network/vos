//! Device programs as ingress and a device take them
//! (`vos_pvm_recair::device`): a program's id, a proof's bytes, and
//! a run past the program's log sizes refused by the prover, under the
//! device format itself.

use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::core::ecall::ECALL_WITNESS_INPUT;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::device::{FORMAT, MAX_PROOF_BYTES, Program, decode, encode, program_id};
use vos_pvm_recair::masked::MaskRng;

use crate::support::{blob, io_and_halt, io_bytes, witness};

/// A kernel reading up to 4,096 witness bytes onto its stack: its rows
/// follow its input's length.
fn reader() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(2)
        .add_imm_64(Reg::S0, Reg::SP, -4096)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 4096)
        .ecalli(ECALL_WITNESS_INPUT);
    io_and_halt(&mut asm);
    asm.build()
}

/// A run that needs more rows than its program's log sizes is refused by
/// the prover, never proved at a larger shape: the reader's program sized
/// by a 16-byte reference run, then a run of 4,000 bytes (500 words); under
/// the device format.
#[test]
fn a_run_past_the_programs_log_sizes_is_refused_by_the_prover() {
    let kernel = reader();
    let program = Program::install(&kernel, &[7; 16], 0).expect("installs");
    let (proof, _) = program.prove(&[9; 16], MaskRng::default()).expect("proves");
    let bytes = encode(&proof.proof).expect("encodes");
    program.verify(&proof.io, &bytes).expect("verifies");
    let error = program
        .prove(&[9; 4000], MaskRng::default())
        .expect_err("past the shape");
    assert!(
        matches!(&error, ProveError::Segment(message) if message.contains("its shape")),
        "{error:?}"
    );
    let larger = Program::install(&kernel, &[7; 4000], 0).expect("installs");
    assert_ne!(larger.log_sizes(), program.log_sizes());
    assert_ne!(larger.id(), program.id());
}

/// A program's id is its kernel's under the format: the same kernel gives
/// the same id from any reference of its shape; another kernel, other log
/// sizes or another format another id.
#[test]
fn a_programs_id_names_its_kernel_its_shape_and_its_format() {
    let program = Program::install(&blob(), &witness(1), 0).expect("installs");
    let again = Program::install(&blob(), &witness(2), 0).expect("installs");
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
    let reader = Program::install(&reader(), &[7; 64], 0).expect("installs");
    assert_ne!(reader.id(), program.id());
}

/// A proof's bytes decode to the proof alone: re-encoded, the same bytes;
/// a byte more, a byte fewer, another format's or past the cap refused;
/// and they hold no io-hash, which the verifier takes from its caller.
#[test]
fn a_device_proofs_bytes_are_canonical() {
    let program = Program::install(&blob(), &witness(1), 0).expect("installs");
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
    let program = Program::install(&blob(), &witness(1), 0).expect("installs");
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

/// The pre-check before a proof's decode: the interaction PoW over the
/// program, the leading roots and the io-hash. An honest proof passes it;
/// its nonce changed is refused there, as is a proof whose leading fields
/// do not read; a main root or the io-hash changed is refused, there or
/// by the checks after it.
#[test]
fn a_proof_whose_interaction_pow_fails_is_refused_before_its_decode() {
    let program = Program::install(&blob(), &witness(1), 0).expect("installs");
    let (proof, _) = program
        .prove(&witness(3), MaskRng::default())
        .expect("proves");
    let bytes = encode(&proof.proof).expect("encodes");
    assert!(program.verify(&proof.io, &bytes).is_ok());
    // A nonce one of 2^8 nonces passes: of 16 others, the ones that fail
    // fail at the pre-check.
    let refused = (1..=16u64)
        .filter(|&delta| {
            let mut other = proof.proof.clone();
            other.interaction_pow = other.interaction_pow.wrapping_add(delta);
            let bytes = encode(&other).expect("encodes");
            matches!(
                program.verify(&proof.io, &bytes),
                Err(Error::InteractionPow)
            )
        })
        .count();
    assert!(refused >= 12, "{refused} of 16 refused at the pre-check");
    assert!(matches!(
        program.verify(&proof.io, &bytes[..9]),
        Err(Error::Decode)
    ));
    let mut root = proof.proof.clone();
    root.stark_proof.0.commitments[1].0[0] ^= 1;
    assert!(
        program
            .verify(&proof.io, &encode(&root).expect("encodes"))
            .is_err()
    );
    let mut io = proof.io;
    io[0] ^= 1;
    assert!(program.verify(&io, &bytes).is_err());
    // The pre-check refuses nothing the verifier without it accepts: a
    // byte of the leading fields flipped, each verified both ways.
    let full = |io: &[u8; 32], bytes: &[u8]| {
        decode(bytes).is_ok_and(|decoded| {
            let proof = vos_pvm_recair::masked::device::DeviceProof {
                io: *io,
                proof: decoded,
            };
            vos_pvm_recair::masked::device::verify_device::<
                stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel,
            >(&FORMAT, program.program(), &proof)
            .is_ok()
        })
    };
    assert!(full(&proof.io, &bytes));
    for at in 0..256.min(bytes.len()) {
        let mut flipped = bytes.clone();
        flipped[at] ^= 1;
        if full(&proof.io, &flipped) {
            assert!(program.verify(&proof.io, &flipped).is_ok(), "byte {at}");
        }
    }
}

/// A kernel's programs under 47 and 46 are two programs, their ids apart;
/// each verifies its own format's proofs and refuses the other's as
/// `Format` before any decode.
#[test]
fn a_proof_of_one_device_format_is_refused_under_the_other() {
    let byte = vos_pvm_recair::device::format(46).expect("46 is proved");
    assert_eq!(vos_pvm_recair::device::FORMATS[0], FORMAT);
    let word = Program::install(&blob(), &witness(1), 0).expect("installs");
    let old = Program::install_in(byte, &blob(), &witness(1), 0).expect("installs");
    assert_eq!((word.format().number, old.format().number), (47, 46));
    assert_ne!(word.id(), old.id());
    for (program, other) in [(&word, &old), (&old, &word)] {
        let (proof, _) = program
            .prove(&witness(2), MaskRng::default())
            .expect("proves");
        let bytes = program.encode(&proof.proof).expect("encodes");
        program.verify(&proof.io, &bytes).expect("verifies");
        assert!(matches!(
            other.verify(&proof.io, &bytes),
            Err(Error::Format)
        ));
    }
}
