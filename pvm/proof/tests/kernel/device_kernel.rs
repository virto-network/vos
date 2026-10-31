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
    println!("auth: {} steps", trace.side_note.steps.len());
}
