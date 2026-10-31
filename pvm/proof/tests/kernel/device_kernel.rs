//! A device kernel derived from an actor's ELF (`#[attestable(device)]`,
//! the `device` test actor's `auth`, `just build-test-actors`): its device
//! shape holds no BLAKE2b and no AND table, since nothing its entry reaches
//! makes BLAKE2b's call, and its traced run leaves the Poseidon2 io-hash of
//! its return.

use vos_pvm_proof::chip_idx;
use vos_pvm_proof::device::{device_chip, device_chips_of_code};
use vos_pvm_proof::kernel::{kernel_side_note, trace_device_kernel};
use vos_testkit::programs::{derived, kernel};

/// The `auth` kernel's device chips: Poseidon2's and the witness input's,
/// never BLAKE2b's or its AND table's. Traced to its halt, its return is
/// the io-hash's encoding of auth's 129 public bytes and no output, and
/// φ9..12 its Poseidon2 io-hash.
#[test]
fn a_device_kernels_shape_holds_no_blake2b() {
    let blob = kernel("device", "auth");
    assert!(!derived("device").devices.is_empty());
    let code = kernel_side_note(&blob).unwrap();
    let chips = device_chips_of_code(&code.code, &code.bitmask);
    assert_eq!(
        chips & (1 << chip_idx::BLAKE2B | 1 << chip_idx::BITWISE_AND_BYTE),
        0,
        "{chips:#x}"
    );
    assert_ne!(chips & 1 << device_chip::POSEIDON2, 0);
    assert_ne!(chips & 1 << chip_idx::WITNESS_INPUT, 0);
    let (input, public) = vos_testkit::device_auth_input();
    let trace = trace_device_kernel(&blob, &input, 50_000_000).expect("halts");
    assert_eq!(
        vos_pvm_precompiles::device_return_parts(&trace.output),
        Some((&public[..], &[][..]))
    );
    assert_eq!(
        Some(trace.io_hash),
        vos_pvm_precompiles::compute_device_io_hash(&public, &[], &[])
    );
    // Under 2^11 steps the CPU sits at the masking's floor (four times `h`
    // = 512 rows): no step the kernel's end or its walk spares buys less.
    let steps = trace.side_note.steps.len();
    assert!(steps < 1 << 11, "auth: {steps} steps");
    println!("auth: {steps} steps");
}

/// Two witnesses of different path shapes (slot 0 under the empty tree's
/// siblings, the last slot under a path whose every sibling is filled)
/// each give the program ingress computes from the kernel, auth's reference
/// run's, its id and log sizes; each proves under it and verifies against
/// its own io-hash alone: pin J's witness-independent trace.
#[test]
fn every_path_shape_proves_under_one_device_program() {
    use vos_pvm_recair::device::{MAX_PROOF_BYTES, Program, auth_io, encode};
    use vos_pvm_recair::masked::MaskRng;
    let blob = kernel("device", "auth");
    let program = Program::auth(&blob).expect("the kernel's program");
    let full: Vec<usize> = (0..32).collect();
    let shapes = [
        vos_testkit::device_auth_arguments(0x0101_0101, 0, &[]),
        vos_testkit::device_auth_arguments(0x0202_0202, u32::MAX, &full),
    ];
    let mut proofs = Vec::new();
    for (input, public) in &shapes {
        let own = Program::install(&blob, input).expect("its own run's program");
        assert_eq!(own.id(), program.id());
        assert_eq!(own.log_sizes(), program.log_sizes());
        let (proof, _) = program
            .prove(input, MaskRng::default())
            .expect("proves under the kernel's program");
        assert_eq!(Some(proof.io), auth_io(public));
        let bytes = encode(&proof.proof).expect("encodes");
        assert!(bytes.len() <= MAX_PROOF_BYTES, "{} bytes", bytes.len());
        program.verify(&proof.io, &bytes).expect("verifies");
        proofs.push((proof.io, bytes));
    }
    assert_ne!(proofs[0].0, proofs[1].0);
    assert!(program.verify(&proofs[1].0, &proofs[0].1).is_err());
    assert!(program.verify(&proofs[0].0, &proofs[1].1).is_err());
    println!(
        "auth's device program: log sizes {:?}, proofs {} and {} bytes",
        program.log_sizes(),
        proofs[0].1.len(),
        proofs[1].1.len()
    );
}
