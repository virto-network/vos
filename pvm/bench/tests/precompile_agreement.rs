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

        let (trace, traced) =
            vos_pvm_proof::trace_refine_with_output(&precompile, &args, GAS, 32).expect("trace");
        assert_eq!(
            traced.as_deref(),
            Some(&expected[..]),
            "traced output, {n} hashes"
        );
        let steps: usize = trace.slices.iter().map(|s| s.side_note.num_steps()).sum();
        let calls: usize = trace
            .slices
            .iter()
            .map(|s| s.side_note.blake2b_calls.len())
            .sum();
        assert_eq!(calls as u64, n, "one chip call per hash");
        assert!(
            (steps as u64) * 10 < jam_steps,
            "precompile path ({steps} steps) should be far shorter than the fallback ({jam_steps})"
        );
    }
}
