//! A compiled guest mixing branches, comparisons, signed arithmetic, shifts
//! and memory proves end to end, and its output matches the same
//! computation done natively.

use vos_pvm_bench::{GAS, guest_program, run_vos};
use vos_pvm_proof::kernel::trace_program;
use vos_pvm_proof::{format, prove, verify};

/// The guest's computation (`guests/diverse`).
fn diverse(seed: i64) -> i64 {
    let input: [i64; 16] = core::array::from_fn(|i| (i as i64 * 7 - 40).wrapping_mul(seed));
    let mut acc: i64 = 0;
    let mut min = i64::MAX;
    let mut max = i64::MIN;
    for x in input {
        acc = if x < 0 {
            acc.wrapping_sub(x)
        } else {
            acc.wrapping_add(x)
        };
        min = min.min(x);
        max = max.max(x);
        acc = acc.wrapping_add(i64::from((x as u64).count_ones()));
    }
    acc.wrapping_add(max).wrapping_sub(min)
}

#[test]
fn diverse_guest_proves_end_to_end() {
    let program = guest_program("diverse");
    for seed in [1i64, -3] {
        let args = seed.to_le_bytes();
        let expected = diverse(seed).to_le_bytes();
        assert_eq!(run_vos(&program, &args), expected, "seed {seed}");

        let mut trace = trace_program(&program, &args, GAS).expect("trace");
        assert_eq!(trace.output, expected, "traced output");
        let proof = prove(&mut trace.side_note).expect("prove");
        assert_eq!(proof.format_version, format::SEGMENT.number);
        verify(proof, &trace.side_note).expect("verify");
    }
}
