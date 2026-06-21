//! Recursion build P5.3 — **the DEEP-quotient reconstruction (the last mechanism,
//! obligation (d)), host-first.**
//!
//! The FRI fold chain's layer-0 input (`first_layer_evals`) is the batched DEEP
//! quotient (`fri_answers`), which BINDS the trace-decommit leaf values to the OODS
//! `sampled_values`. `extract_recursion_data` now exposes the AIR-friendly
//! decomposition (`deep_batches`): the sample batches grouped by sample point, each
//! carrying per-column the FLATTENED column index + the complex-conjugate line
//! coefficients `(a, b, c)`.
//!
//! This part (HOST reconstruction) re-derives `accumulate_row_quotients` from that
//! decomposition + the proof's `queried_values` + the per-query domain points, and
//! VALIDATES it reproduces the real `first_layer_evals` (computed by stwo's
//! `fri_answers` inside `extract_recursion_data`). The arithmetic is the in-AIR
//! form: per query at domain point `p`,
//! ```text
//!   eval = Σ_batch (1/line(z, z̄)(p)) · Σ_col (queried[col]·c − (a·p.y + b))
//! ```
//! where `line(z, z̄)(p) = (Re(zₓ) − pₓ)·Im(zᵧ) − (Re(zᵧ) − pᵧ)·Im(zₓ)` is a CM31,
//! its inverse a witnessed CM31, the per-column `(a, b, c)`/`c·leaf` degree-1 (the
//! line coeffs are transcript constants), and `numerator · denom_inverse` degree 2.
//! So the in-AIR DEEP reconstruction is degree ≤ 2; this validates the formula +
//! the constants before transcribing it to a streamed AIR.
//!
//! Run: `cargo test -p zkpvm --release --features poseidon2-channel --test \
//!     recursion_deep_quotient -- --ignored --nocapture`

#![cfg(feature = "poseidon2-channel")]

mod recursion_common;

use num_traits::Zero;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use zkpvm::{Proof, SideNote, extract_recursion_data};

fn canonical_segment() -> (Proof, SideNote) {
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::prove_canonical;

    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    let proof = prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31");
    (proof, sn)
}

/// HOST reconstruction: re-derive the batched DEEP quotient from the decomposition
/// + queried_values + domain points, and match the real `first_layer_evals`.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn deep_quotient_reconstruct() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);

    let lifting_log_size = data.lifting_log_size;
    let lifting_domain = CanonicCoset::new(lifting_log_size).circle_domain();
    // queried_values flattened across trees (the index `deep_batches` columns use).
    let queried_flat: Vec<Vec<BaseField>> = proof.stark_proof.queried_values.clone().flatten();
    let n_queries = data.query_positions.len();

    // Report the decomposition shape (the in-AIR cost driver).
    let n_batches = data.deep_batches.len();
    let total_cols: usize = data.deep_batches.iter().map(|b| b.cols.len()).sum();
    eprintln!(
        "DEEP decomposition: {n_batches} sample batches, {total_cols} (batch,column) numerator \
         terms total, over {n_queries} queries (lifting_log_size {lifting_log_size}).",
    );

    for (qi, &position) in data.query_positions.iter().enumerate() {
        let dp = lifting_domain.at(bit_reverse_index(position, lifting_log_size));
        let mut acc = SecureField::zero();
        for batch in &data.deep_batches {
            // CM31 denominator: line through (z, z̄) evaluated at the domain point.
            let prx = batch.point.x.0; // Re(zₓ) ∈ CM31
            let pix = batch.point.x.1; // Im(zₓ)
            let pry = batch.point.y.0; // Re(zᵧ)
            let piy = batch.point.y.1; // Im(zᵧ)
            let denom: CM31 = (prx - CM31::from(dp.x)) * piy - (pry - CM31::from(dp.y)) * pix;
            let denom_inv = denom.inverse();

            let mut numerator = SecureField::zero();
            for &(col, a, b, c) in &batch.cols {
                let value = c * queried_flat[col][qi]; // c·f̃ᵢ(p), degree 1 in the leaf
                let linear = a * dp.y + b; // a·p.y + b, degree 1 in p.y
                numerator += value - linear;
            }
            acc += numerator.mul_cm31(denom_inv);
        }
        assert_eq!(
            acc, data.first_layer_evals[qi],
            "DEEP quotient mismatch at query {qi} (position {position})"
        );
    }

    eprintln!(
        "deep_quotient_reconstruct GREEN: the batched DEEP quotient re-derived from the \
         decomposition (sample batches + per-column line coeffs (a,b,c) + flattened column index) \
         + the real queried_values + per-query domain points reproduces stwo's first_layer_evals \
         for all {n_queries} queries — the FRI fold chain's layer-0 input, binding the \
         trace-decommit leaves to the OODS samples. Arithmetic is the in-AIR form (CM31 \
         denominator inverse witnessed; numerator a degree-1 sum over the leaves; product degree 2)."
    );
}
