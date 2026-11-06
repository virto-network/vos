//! A device kernel derived from an actor's ELF (`#[attestable(device)]`,
//! the `device` test actor's `auth`, `just build-test-actors`): its device
//! shape holds no BLAKE2b and no AND table, since nothing its entry reaches
//! makes BLAKE2b's call, and its traced run leaves the Poseidon2 io-hash of
//! its return.

use vos_pvm_proof::chip_idx;
use vos_pvm_proof::device::{device_chip, device_chips_of_code};
use vos_pvm_proof::kernel::{kernel_side_note, trace_kernel};
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
    let trace = trace_kernel(&blob, &input, 50_000_000).expect("halts");
    assert_eq!(
        vos_pvm_precompiles::device_return_parts(&trace.output),
        Some((&public[..], &[][..]))
    );
    assert_eq!(
        Some(trace.io_hash),
        vos_pvm_precompiles::compute_device_io_hash(&public, &[], &[])
    );
    // Under 2^11 steps the CPU takes 2^11 rows, twice the masking's floor
    // (4h rows, 2^10 at h = 256).
    let steps = trace.side_note.steps.len();
    assert!(steps < 1 << 11, "auth: {steps} steps");
    println!("auth: {steps} steps");
}

/// Two witnesses of different path shapes (slot 0 under the empty tree's
/// siblings, the last slot under a path whose every sibling is filled)
/// each give the program ingress computes from the kernel, auth's reference
/// run's, its id and log sizes; each proves under it and verifies against
/// its own io-hash alone: a witness-independent trace.
#[test]
fn every_path_shape_proves_under_one_device_program() {
    use vos_pvm_recair::device::{MAX_PROOF_BYTES, Program, auth_io, auth_reference, encode};
    use vos_pvm_recair::masked::MaskRng;
    let blob = kernel("device", "auth");
    let program = Program::install(&blob, &auth_reference(), 0).expect("the kernel's program");
    let full: Vec<usize> = (0..32).collect();
    let shapes = [
        vos_testkit::device_auth_arguments(0x0101_0101, 0, &[]),
        vos_testkit::device_auth_arguments(0x0202_0202, u32::MAX, &full),
    ];
    let mut proofs = Vec::new();
    for (input, public) in &shapes {
        let own = Program::install(&blob, input, 0).expect("its own run's program");
        assert_eq!(own.id(), program.id());
        assert_eq!(own.log_sizes(), program.log_sizes());
        let (proof, stats) = program
            .prove(input, MaskRng::default())
            .expect("proves under the kernel's program");
        // R1's rows within `h` (`proving.md` §5): 149 at most.
        assert!(stats.revealed_rows <= 149, "{stats:?}");
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

/// A device kernel's steps on `input`, traced to its halt: its return the
/// io-hash's encoding of `public` and no output, its io-hash the Poseidon2
/// one, and its shape holding neither BLAKE2b nor the AND table.
fn device_steps(blob: &[u8], input: &[u8], public: &[u8]) -> usize {
    let code = kernel_side_note(blob).unwrap();
    let chips = device_chips_of_code(&code.code, &code.bitmask);
    assert_eq!(
        chips & (1 << chip_idx::BLAKE2B | 1 << chip_idx::BITWISE_AND_BYTE),
        0,
        "{chips:#x}"
    );
    let trace = trace_kernel(blob, input, 50_000_000).expect("halts");
    assert_eq!(
        vos_pvm_precompiles::device_return_parts(&trace.output),
        Some((public, &[][..]))
    );
    assert_eq!(
        Some(trace.io_hash),
        vos_pvm_precompiles::compute_device_io_hash(public, &[], &[])
    );
    trace.side_note.steps.len()
}

/// The credential statements written with the SDK (`light-node.md` §4.2,
/// the `sdk-device` test actor) run within 1.15× the hand-lean kernels'
/// steps: auth beside the `device` actor's, the same credential statement
/// in its own layout (an eight-byte slot, a claim with no kind byte), and
/// owner beside `owner_lean`; a wrong claim traps each.
#[test]
fn sdk_form_kernels_run_within_the_lean_kernels_steps() {
    let lean = kernel("device", "auth");
    let (input, public) = vos_testkit::device_auth_input();
    let lean_auth = device_steps(&lean, &input, &public);
    let sdk = kernel("sdk-device", "auth");
    let (input, public) =
        vos_testkit::device_sdk_auth_arguments(0x0123_4567, 0x1234_5678, &[0, 5, 17]);
    let sdk_auth = device_steps(&sdk, &input, &public);
    let (owner_input, owner_public) = vos_testkit::device_owner_arguments(0x0123_4567);
    let lean_owner = device_steps(
        &kernel("sdk-device", "owner_lean"),
        &owner_input,
        &owner_public,
    );
    let sdk_owner = device_steps(&kernel("sdk-device", "owner"), &owner_input, &owner_public);
    println!("auth: {sdk_auth} steps in SDK form, {lean_auth} by hand");
    println!("owner: {sdk_owner} steps in SDK form, {lean_owner} by hand");
    assert!(
        20 * sdk_auth <= 23 * lean_auth,
        "auth: {sdk_auth} against {lean_auth}"
    );
    assert!(
        20 * sdk_owner <= 23 * lean_owner,
        "owner: {sdk_owner} against {lean_owner}"
    );
    assert!(sdk_auth < 1 << 11, "auth: {sdk_auth} steps");
    for field in [128, 64] {
        // The claim's `map_root`, then its `nullifier`.
        let mut wrong = input.clone();
        let at = wrong.len() - field;
        wrong[at] ^= 1;
        assert!(trace_kernel(&sdk, &wrong, 50_000_000).is_err());
    }
    let mut wrong = owner_input.clone();
    wrong[32] ^= 1;
    assert!(trace_kernel(&kernel("sdk-device", "owner"), &wrong, 50_000_000).is_err());
}

/// Each SDK-form kernel proves under the program its reference run gives,
/// a witness of another path shape too, and verifies against its claim's
/// io-hash alone.
#[test]
fn sdk_form_kernels_prove_under_their_programs() {
    use vos_pvm_recair::device::{Program, encode};
    use vos_pvm_recair::masked::MaskRng;
    let full: Vec<usize> = (0..32).collect();
    let cases = [
        (
            "auth",
            vos_testkit::device_sdk_auth_arguments(0x0101_0101, 0, &[]),
            vos_testkit::device_sdk_auth_arguments(0x0202_0202, u32::MAX, &full),
        ),
        (
            "owner",
            vos_testkit::device_owner_arguments(0x0101_0101),
            vos_testkit::device_owner_arguments(0x0202_0202),
        ),
    ];
    for (method, (reference, _), (input, public)) in cases {
        let blob = kernel("sdk-device", method);
        let program = Program::install(&blob, &reference, 0).expect("the kernel's program");
        let (proof, _) = program
            .prove(&input, MaskRng::default())
            .expect("proves under the kernel's program");
        assert_eq!(
            Some(proof.io),
            vos_pvm_precompiles::compute_device_io_hash(&public, &[], &[])
        );
        let bytes = encode(&proof.proof).expect("encodes");
        program.verify(&proof.io, &bytes).expect("verifies");
        println!(
            "{method}'s device program: log sizes {:?}, a proof {} bytes",
            program.log_sizes(),
            bytes.len()
        );
    }
}

/// Device kernel `method` of the package whose ELF is `elf`: its kernel,
/// its reference program and its headroom, as its install derives them.
fn release(elf: &[u8], method: &str) -> (Vec<u8>, Vec<u8>, u8) {
    let derived = vos_pvm_compiler::derive(elf).expect("derives");
    let id = vos_testkit::programs::method(&derived.actor, method).0;
    let kernel = derived
        .kernels
        .iter()
        .find(|(bound, _)| *bound == id)
        .map(|(_, kernel)| kernel.clone())
        .expect("a kernel");
    let (_, reference, headroom) = derived
        .references
        .into_iter()
        .find(|(bound, _, _)| *bound == id)
        .expect("a reference");
    (kernel, reference, headroom)
}

/// The credential actor's ELF.
fn credentials() -> Vec<u8> {
    std::fs::read(vos_testkit::programs::credentials_elf()).expect("the credential actor")
}

/// A device kernel's reference program returns its reference arguments:
/// the `device` actor's, auth's reference statement in the hand-lean
/// layout (`auth_reference`), and its program is the one those arguments
/// size; the stock kernels' and the SDK-form test kernels' each give a
/// program their own arguments prove under.
#[test]
fn a_reference_program_returns_its_kernels_reference_arguments() {
    use vos_pvm_recair::device::{Program, auth_reference, reference_arguments};
    let (kernel, reference, headroom) = release(&vos_testkit::programs::package("device"), "auth");
    assert_eq!(headroom, 0);
    let arguments = reference_arguments(&reference).expect("the reference runs");
    assert_eq!(arguments, auth_reference());
    let program = Program::of(&kernel, &reference, headroom).expect("its program");
    let sized = Program::install(&kernel, &auth_reference(), 0).expect("its program");
    assert_eq!(program.id(), sized.id());
    let credentials = credentials();
    let sdk_device = vos_testkit::programs::package("sdk-device");
    for (elf, method) in [
        (&credentials, "auth"),
        (&credentials, "owner"),
        (&sdk_device, "auth"),
        (&sdk_device, "owner"),
        (&sdk_device, "owner_lean"),
    ] {
        let (kernel, reference, headroom) = release(elf, method);
        let arguments = reference_arguments(&reference).expect("the reference runs");
        let program = Program::of(&kernel, &reference, headroom).expect("its program");
        program.fits(&arguments).expect("its reference fits");
        println!("{method}: log sizes {:?}", program.log_sizes());
    }
    // The stock kernels are the SDK-form test kernels: one program each.
    for method in ["auth", "owner"] {
        let (stock, stock_reference, _) = release(&credentials, method);
        let (test, test_reference, _) = release(&sdk_device, method);
        assert_eq!(
            reference_arguments(&stock_reference).unwrap(),
            reference_arguments(&test_reference).unwrap(),
            "{method}'s reference arguments"
        );
        let stock = Program::of(&stock, &stock_reference, 0).unwrap();
        let test = Program::of(&test, &test_reference, 0).unwrap();
        assert_eq!(stock.log_sizes(), test.log_sizes(), "{method}");
    }
}

/// A headroom of one raises each of the program's log sizes by one: a new
/// program id, whose proofs a witness still gives and its verifier takes.
#[test]
fn a_headroom_raises_every_log_size() {
    use vos_pvm_recair::device::{Program, encode};
    use vos_pvm_recair::masked::MaskRng;
    let (kernel, reference, _) = release(&credentials(), "owner");
    let program = Program::of(&kernel, &reference, 0).unwrap();
    let raised = Program::of(&kernel, &reference, 1).unwrap();
    assert_ne!(program.id(), raised.id());
    let expected: Vec<u32> = program.log_sizes().iter().map(|size| size + 1).collect();
    assert_eq!(raised.log_sizes(), &expected[..]);
    let (input, public) = vos_testkit::device_owner_arguments(0x0303_0303);
    let (proof, _) = raised.prove(&input, MaskRng::default()).expect("proves");
    assert_eq!(
        Some(proof.io),
        vos_pvm_precompiles::compute_device_io_hash(&public, &[], &[])
    );
    raised
        .verify(&proof.io, &encode(&proof.proof).unwrap())
        .expect("verifies");
}

/// `device_fits`: random witnesses of the stock kernels (a secret, a
/// slot, siblings filled at random levels) and of the `device` actor's
/// hand-lean `auth` run within the programs their references size, so
/// every one proves under one program.
#[test]
fn random_witnesses_fit_the_reference_programs() {
    use vos_pvm_recair::device::Program;
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let credentials = credentials();
    let programs = [
        ("auth", release(&credentials, "auth")),
        ("owner", release(&credentials, "owner")),
        (
            "lean",
            release(&vos_testkit::programs::package("device"), "auth"),
        ),
    ]
    .map(|(name, (kernel, reference, headroom))| {
        (
            name,
            Program::of(&kernel, &reference, headroom).expect("its program"),
        )
    });
    for _ in 0..12 {
        let seed = next() as u32 & 0x3fff_ffff;
        let slot = next() as u32;
        let filled: Vec<usize> = (0..32).filter(|_| next() & 1 == 1).collect();
        for (name, program) in &programs {
            let input = match *name {
                "auth" => vos_testkit::device_sdk_auth_arguments(seed, slot, &filled).0,
                "owner" => vos_testkit::device_owner_arguments(seed).0,
                _ => vos_testkit::device_auth_arguments(seed, slot, &filled).0,
            };
            program
                .fits(&input)
                .unwrap_or_else(|error| panic!("{name}, seed {seed:#x}: {error}"));
        }
    }
}

/// The `device` actor's release and its next one (`device-next`, its
/// kernel written otherwise) are two programs of one statement: each runs
/// on the other's arguments and states the same public parts, so the same
/// io-hash and the same nullifier; their program ids differ.
#[test]
fn two_releases_compute_one_claim() {
    use vos_pvm_recair::device::Program;
    let (lean, lean_reference, _) = release(&vos_testkit::programs::package("device"), "auth");
    let (next, next_reference, _) = release(&vos_testkit::programs::package("device-next"), "auth");
    let full: Vec<usize> = (0..32).collect();
    for (seed, slot, filled) in [
        (0x0101_0101, 0, &[][..]),
        (0x0202_0202, u32::MAX, &full[..]),
    ] {
        let (input, public) = vos_testkit::device_auth_arguments(seed, slot, filled);
        let lean_run = trace_kernel(&lean, &input, 50_000_000).expect("halts");
        let next_run = trace_kernel(&next, &input, 50_000_000).expect("halts");
        assert_eq!(lean_run.io_hash, next_run.io_hash);
        assert_eq!(
            vos_pvm_precompiles::device_return_parts(&next_run.output),
            Some((&public[..], &[][..]))
        );
    }
    let lean = Program::of(&lean, &lean_reference, 0).unwrap();
    let next = Program::of(&next, &next_reference, 0).unwrap();
    assert_ne!(lean.id(), next.id());
}
