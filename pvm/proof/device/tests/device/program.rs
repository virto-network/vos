//! Device programs as ingress and a device take them
//! (`vos_pvm_device`): a program's id, a proof's bytes, and
//! a run past the program's log sizes refused by the prover, under the
//! device format itself.

use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_device::{DeviceProgramId, FORMAT, MAX_PROOF_BYTES, Program, Refusal, decode, encode};
use vos_pvm_proof::core::ecall::ECALL_WITNESS_INPUT;
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
    let program = Program::sized_for(
        FORMAT.number,
        &kernel,
        vos_pvm_device::ReferenceArguments(&[7; 16]),
        0,
    )
    .expect("installs");
    let (proof, _) = program.prove(&[9; 16], MaskRng::default()).expect("proves");
    let bytes = encode(&FORMAT, &proof.proof).expect("encodes");
    program.verify(&proof.io, &bytes).expect("verifies");
    let error = program
        .prove(&[9; 4000], MaskRng::default())
        .expect_err("past the shape");
    assert!(matches!(&error, vos_pvm_device::Error::Fit), "{error:?}");
    let larger = Program::sized_for(
        FORMAT.number,
        &kernel,
        vos_pvm_device::ReferenceArguments(&[7; 4000]),
        0,
    )
    .expect("installs");
    assert_ne!(larger.log_sizes(), program.log_sizes());
    assert_ne!(larger.id(), program.id());
}

/// A program's id is its kernel's under the format: the same kernel gives
/// the same id from any reference of its shape; another kernel, other log
/// sizes or another format another id.
#[test]
fn a_programs_id_names_its_kernel_its_shape_and_its_format() {
    let program = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let again = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(2)),
        0,
    )
    .expect("installs");
    assert_eq!(program.id(), again.id());
    assert_eq!(
        *program.id(),
        DeviceProgramId::of(&FORMAT, program.program())
    );
    let mut taller = program.program().clone();
    taller.log_sizes[0] += 1;
    assert_ne!(DeviceProgramId::of(&FORMAT, &taller), *program.id());
    let other = vos_pvm_proof::format::Format {
        number: 99,
        ..FORMAT
    };
    assert_ne!(
        DeviceProgramId::of(&other, program.program()),
        *program.id()
    );
    let reader = Program::sized_for(
        FORMAT.number,
        &reader(),
        vos_pvm_device::ReferenceArguments(&[7; 64]),
        0,
    )
    .expect("installs");
    assert_ne!(reader.id(), program.id());
}

/// A proof's bytes decode to the proof alone: re-encoded, the same bytes;
/// a byte more, a byte fewer, another format's or past the cap refused;
/// and they hold no io-hash, which the verifier takes from its caller.
#[test]
fn a_device_proofs_bytes_are_canonical() {
    let program = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let (proof, _) = program
        .prove(&witness(3), MaskRng::default())
        .expect("proves");
    assert_eq!(proof.io, io_bytes());
    let bytes = encode(&FORMAT, &proof.proof).expect("encodes");
    assert_eq!(
        encode(&FORMAT, &decode(&FORMAT, &bytes).expect("decodes")),
        Some(bytes.clone())
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(decode(&FORMAT, &longer), Err(Refusal::Decode)));
    assert!(decode(&FORMAT, &bytes[..bytes.len() - 1]).is_err());
    let mut other = bytes.clone();
    other[0] = 44;
    assert!(matches!(decode(&FORMAT, &other), Err(Refusal::Format)));
    assert!(matches!(
        decode(&FORMAT, &vec![0; MAX_PROOF_BYTES + 1]),
        Err(Refusal::Length)
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
    let program = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let (proof, _) = program
        .prove(&witness(3), MaskRng::default())
        .expect("proves");
    let mut wide = proof.proof.clone();
    let value = &mut wide.stark_proof.0.queried_values[0][0][0];
    *value = BaseField::from_u32_unchecked(value.0 + P);
    let bytes = encode(&FORMAT, &wide).expect("encodes");
    assert_eq!(
        encode(&FORMAT, &decode(&FORMAT, &bytes).expect("decodes")),
        Some(bytes.clone())
    );
    assert!(matches!(
        program.verify(&proof.io, &bytes),
        Err(Refusal::Noncanonical)
    ));
}

/// The pre-check before a proof's decode: the interaction PoW over the
/// program, the leading roots and the io-hash. An honest proof passes it;
/// its nonce changed is refused there, as is a proof whose leading fields
/// do not read; a main root or the io-hash changed is refused, there or
/// by the checks after it.
#[test]
fn a_proof_whose_interaction_pow_fails_is_refused_before_its_decode() {
    let program = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let (proof, _) = program
        .prove(&witness(3), MaskRng::default())
        .expect("proves");
    let bytes = encode(&FORMAT, &proof.proof).expect("encodes");
    assert!(program.verify(&proof.io, &bytes).is_ok());
    // A nonce one of 2^8 nonces passes: of 16 others, the ones that fail
    // fail at the pre-check.
    let refused = (1..=16u64)
        .filter(|&delta| {
            let mut other = proof.proof.clone();
            other.interaction_pow = other.interaction_pow.wrapping_add(delta);
            let bytes = encode(&FORMAT, &other).expect("encodes");
            matches!(
                program.verify(&proof.io, &bytes),
                Err(Refusal::InteractionPow)
            )
        })
        .count();
    assert!(refused >= 12, "{refused} of 16 refused at the pre-check");
    assert!(matches!(
        program.verify(&proof.io, &bytes[..9]),
        Err(Refusal::Decode)
    ));
    let mut root = proof.proof.clone();
    root.stark_proof.0.commitments[1].0[0] ^= 1;
    assert!(
        program
            .verify(&proof.io, &encode(&FORMAT, &root).expect("encodes"))
            .is_err()
    );
    let mut io = proof.io;
    io[0] ^= 1;
    assert!(program.verify(&io, &bytes).is_err());
    // The pre-check refuses nothing the verifier without it accepts: a
    // byte of the leading fields flipped, each verified both ways.
    let full = |io: &[u8; 32], bytes: &[u8]| {
        decode(&FORMAT, bytes).is_ok_and(|decoded| {
            let proof = vos_pvm_device::masked::DeviceProof {
                io: *io,
                proof: decoded,
            };
            vos_pvm_device::masked::verify_device::<
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

/// A kernel's programs under two device formats, 47 and the tests' 48, are
/// two programs, their ids apart; each verifies its own format's proofs and
/// refuses the other's as `Format` before any decode.
#[test]
fn a_proof_of_one_device_format_is_refused_under_the_other() {
    let previous = vos_pvm_device::format(48).expect("48 is proved");
    assert_eq!(vos_pvm_device::FORMATS[0], FORMAT);
    let current = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let other_format = Program::sized_for(
        previous.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    assert_eq!(
        (current.format().number, other_format.format().number),
        (47, 48)
    );
    assert_ne!(current.id(), other_format.id());
    for (program, other) in [(&current, &other_format), (&other_format, &current)] {
        let (proof, _) = program
            .prove(&witness(2), MaskRng::default())
            .expect("proves");
        let bytes = program.encode(&proof.proof).expect("encodes");
        program.verify(&proof.io, &bytes).expect("verifies");
        assert!(matches!(
            other.verify(&proof.io, &bytes),
            Err(Refusal::Format)
        ));
    }
}

/// The device kernel's program under the device format: its chips, its log
/// sizes, its CPU's column words and its id, pinned. A program id names
/// what a device proves under, so whatever moves it for one kernel (a CPU
/// `Column` reordered or added, a chip index, a trace's rows on the
/// reference run, a preprocessed column's layout, the word ledger's tag)
/// needs a new format number: this gate fails at any such change.
#[test]
fn the_device_programs_id_is_pinned() {
    const CHIPS: u32 = 1_016_328_469;
    const LOG_SIZES: [u32; 16] = [10; 16];
    const CPU: [u64; 5] = [
        252_612_797_300_735,
        14_105_555_774_723_964_920,
        146_366_456_924_999_232,
        18_428_906_283_836_883_394,
        3,
    ];
    const ID: [u8; 32] = [
        30, 176, 152, 101, 58, 102, 151, 136, 143, 228, 68, 255, 109, 67, 131, 55, 255, 212, 108,
        127, 214, 195, 40, 250, 209, 176, 196, 103, 125, 47, 103, 9,
    ];
    let program = Program::sized_for(
        FORMAT.number,
        &blob(),
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    assert_eq!(FORMAT.number, 47);
    assert_eq!(
        (
            program.chips(),
            program.log_sizes(),
            &program.program().cpu.words()[..],
            program.id().0
        ),
        (CHIPS, &LOG_SIZES[..], &CPU[..], ID)
    );
}

/// A release artifact names the program its kernel, chips and log sizes
/// make: one taken from a `sized_for` program gives the same program and id
/// through `Program::from_release`, with no reference run; each mutant is
/// refused, its chips not the code's, a log size under its floor, a size
/// missing, another id or a format this build does not prove.
#[test]
fn a_release_names_its_program() {
    let kernel = blob();
    let program = Program::sized_for(
        FORMAT.number,
        &kernel,
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let release = vos_pvm_device::Release {
        elf: [0x5e; 32],
        method: vos_abi::ids::MethodId(1),
        kernel: kernel.clone(),
        format: FORMAT.number,
        chips: program.program().active,
        log_sizes: program.log_sizes().to_vec(),
        id: program.id().0,
    };
    let released = Program::from_release(&release).expect("the release's program");
    assert_eq!(released.id(), program.id());
    assert_eq!(released.log_sizes(), program.log_sizes());
    assert_eq!(released.program().active, program.program().active);

    let refused = |mutate: &dyn Fn(&mut vos_pvm_device::Release)| {
        let mut mutant = release.clone();
        mutate(&mut mutant);
        Program::from_release(&mutant).err()
    };
    use vos_pvm_device::Error;
    assert_eq!(
        refused(&|r| r.chips ^= 1 << r.chips.trailing_zeros()),
        Some(Error::Chips)
    );
    assert_eq!(
        refused(&|r| r.log_sizes[0] = 0),
        Some(Error::Floor { chip: 0 })
    );
    assert_eq!(
        refused(&|r| {
            r.log_sizes.pop();
        }),
        Some(Error::Sizes)
    );
    assert_eq!(refused(&|r| r.id[0] ^= 1), Some(Error::IdMismatch));
    assert_eq!(refused(&|r| r.format = 0), Some(Error::Format(0)));
}

/// A verifier built from a release and the parts a prover's build computed,
/// its CPU's words and its preprocessed root, as a build without the prover
/// builds it, is the program's: it verifies the program's proofs; another
/// root or another CPU is refused by the release's id.
#[test]
fn a_verifier_is_built_from_a_release_without_the_prover() {
    let kernel = blob();
    let program = Program::sized_for(
        FORMAT.number,
        &kernel,
        vos_pvm_device::ReferenceArguments(&witness(1)),
        0,
    )
    .expect("installs");
    let release = vos_pvm_device::Release {
        elf: [0x5e; 32],
        method: vos_abi::ids::MethodId(1),
        kernel,
        format: FORMAT.number,
        chips: program.program().active,
        log_sizes: program.log_sizes().to_vec(),
        id: program.id().0,
    };
    let parts = program.verifier();
    let verifier = vos_pvm_device::Verifier::of_release(&release, parts.cpu(), parts.circuit())
        .expect("the release's verifier");
    assert_eq!(verifier.id(), program.id());
    let (proof, _) = program
        .prove(&witness(2), MaskRng::default())
        .expect("proves");
    let bytes = program.encode(&proof.proof).expect("encodes");
    verifier.verify(&proof.io, &bytes).expect("verifies");

    use vos_pvm_device::Error;
    let mut root = parts.circuit();
    root[0] ^= 1;
    assert_eq!(
        vos_pvm_device::Verifier::of_release(&release, parts.cpu(), root).err(),
        Some(Error::IdMismatch)
    );
    let mut cpu = parts.cpu();
    cpu[0] ^= 1;
    assert_eq!(
        vos_pvm_device::Verifier::of_release(&release, cpu, parts.circuit()).err(),
        Some(Error::IdMismatch)
    );
}
