//! The BLAKE2b precompile agrees across hosts: served natively on a VOS
//! refine host, computed in software by the guest on a JAM-like host that
//! answers `WHAT`, and computed by an all-software guest. The traced run
//! records one chip call per hash.

use vos_pvm_bench::{GAS, guest_program, run_jam, run_vos};

#[test]
fn precompile_agrees_with_software_on_every_host() {
    let precompile = guest_program("hash-precompile");
    let software = guest_program("hash-software");
    for n in [1u64, 10, 100] {
        let args = n.to_le_bytes();
        let expected = run_vos(&software, &args);
        assert_eq!(
            run_vos(&precompile, &args),
            expected,
            "VOS precompile, {n} hashes"
        );
        let (jam, jam_steps) = run_jam(&precompile, &args);
        assert_eq!(jam, expected, "JAM fallback, {n} hashes");

        let trace = vos_pvm_proof::kernel::trace_program(&precompile, &args, GAS).expect("trace");
        assert_eq!(trace.output, expected, "traced output, {n} hashes");
        let steps = trace.side_note.num_steps();
        let calls = trace.side_note.blake2b_calls.len();
        assert_eq!(calls as u64, n, "one chip call per hash");
        assert!(
            (steps as u64) * 10 < jam_steps,
            "precompile path ({steps} steps) should be far shorter than the fallback ({jam_steps})"
        );
    }
}

/// The Poseidon2 precompile agrees across hosts: served natively on a VOS
/// refine host, computed in software by the guest on a JAM-like host that
/// answers `WHAT`, and the reference permutation's compression, chained.
#[test]
fn poseidon2_agrees_with_the_reference_on_every_host() {
    use vos_pvm_poseidon2::M31;
    let guest = guest_program("poseidon2");
    for n in [1u64, 10, 100] {
        let args = n.to_le_bytes();
        let right = [9, 8, 7, 6, 5, 4, 3, 2].map(M31::new);
        let mut left = [M31::new(7); 8];
        for _ in 0..n {
            left = vos_pvm_poseidon2::compress(&left, &right);
        }
        let expected: Vec<u8> = left
            .iter()
            .flat_map(|word| word.value().to_le_bytes())
            .collect();
        assert_eq!(
            run_vos(&guest, &args),
            expected,
            "VOS precompile, {n} calls"
        );
        let (jam, _) = run_jam(&guest, &args);
        assert_eq!(jam, expected, "JAM fallback, {n} calls");
    }
}
