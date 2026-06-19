#![cfg(feature = "poseidon2-channel")]

//! Recursion build P5.3 — the per-child verifier-AIR against ONE real canonical
//! Poseidon2-M31 segment.
//!
//! P5.2 closed the OODS-embed gate (all 31 components re-evaluated in-AIR, matched
//! against a real segment's `composition_oods_eval`) using HOST-supplied OODS
//! scalars. P5.3 assembles the full per-child verifier: the channel transcript
//! replay derives the challenges, the OODS embed / FRI fold chain / Merkle
//! decommit consumers read them, all in ONE uniform component.
//!
//! This file starts at the foundation every consumer needs: the unified
//! real-segment DATA EXTRACTION. [`zkpvm::record_canonical_transcript`] records a
//! real canonical proof's full verifier transcript as a Poseidon2 permutation
//! sequence; this test grounds it — cross-checks the recorded composition
//! `random_coeff` against [`zkpvm::reconstruct_oods_for_recursion`], and reports
//! the real perm/FRI/query structure (the row-scale the verifier-AIR must carry).
//!
//! `#[ignore]` — `prove_canonical` builds a genuine 31-component segment (~30s
//! release, minutes in debug). Run:
//! `cargo test -p zkpvm --features poseidon2-channel --release \
//!     --test recursion_child_verify -- --ignored --nocapture`

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::poseidon2::PermKind;
use zkpvm::{
    SideNote, prove_canonical, reconstruct_oods_for_recursion, record_canonical_transcript,
};

/// Prove a small but genuine program as ONE full 31-component canonical segment,
/// returning the proof + the side note in the prover-left state (the verifier
/// transcript replay needs it). Mirrors `oods_auto_real_segment.rs`.
fn canonical_segment() -> (zkpvm::Proof, SideNote) {
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

/// GROUNDING: record a real canonical segment's full verifier transcript and
/// cross-check it against the OODS reconstruction; report the real row-scale.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn record_canonical_transcript_grounding() {
    let (proof, sn) = canonical_segment();
    assert_eq!(
        proof.num_components,
        zkpvm::chip_idx::COUNT,
        "canonical proof must carry all 31 components"
    );

    let transcript = record_canonical_transcript(&proof, &sn);
    let records = &transcript.records;
    let prefix_len = transcript.prefix_len;

    // Per-kind perm counts.
    let n_absorb = records
        .iter()
        .filter(|r| r.kind == PermKind::Absorb)
        .count();
    let n_squeeze = records
        .iter()
        .filter(|r| r.kind == PermKind::Squeeze)
        .count();
    let n_pow = records.iter().filter(|r| r.kind == PermKind::Pow).count();

    // The composition random_coeff is the first Squeeze at-or-after prefix_len
    // (stwo's verifier head draws it first). It must equal the OODS
    // reconstruction's `random_coeff` (both replay the same transcript).
    let r = reconstruct_oods_for_recursion(&proof, &sn);
    let head_first_squeeze = records
        .iter()
        .enumerate()
        .find(|(i, rec)| *i >= prefix_len && rec.kind == PermKind::Squeeze)
        .map(|(i, rec)| {
            let o = rec.output;
            (
                i,
                stwo::core::fields::qm31::SecureField::from_m31_array([o[0], o[1], o[2], o[3]]),
            )
        })
        .expect("a squeeze after the prefix (the composition random_coeff)");
    assert_eq!(
        head_first_squeeze.1, r.random_coeff,
        "recorded composition random_coeff must equal the OODS reconstruction's"
    );

    // Real FRI / query structure (the canonical scale the FRI fold chain + Merkle
    // decommit consumers must reach).
    let sp = &proof.stark_proof;
    let n_inner_layers = sp.fri_proof.inner_layers.len();
    let last_layer_len = sp.fri_proof.last_layer_poly.len();
    let n_commitments = sp.commitments.len();
    let n_decommitments = sp.decommitments.len();
    let config = proof.pcs_config;

    eprintln!(
        "record_canonical_transcript_grounding GREEN:\n\
         - transcript: {} perms total ({} absorb, {} squeeze, {} pow); prefix_len={} \
           (zkpvm prefix), head starts at record {}\n\
         - composition random_coeff (record {}) MATCHES reconstruct_oods_for_recursion\n\
         - FRI: {} inner layers (+1 first layer), last_layer_poly len={} \
           (log_last_layer_degree_bound={}), n_queries={}, log_blowup={}, pow_bits={}\n\
         - commitment trees: {} (preproc/main/interaction/composition + FRI layers), \
           {} trace-tree decommitments\n\
         - per-component log_sizes: {:?}\n\
         - claimed_sums.len()={}, component_mask popcount={}",
        records.len(),
        n_absorb,
        n_squeeze,
        n_pow,
        prefix_len,
        head_first_squeeze.0,
        head_first_squeeze.0,
        n_inner_layers,
        last_layer_len,
        config.fri_config.log_last_layer_degree_bound,
        config.fri_config.n_queries,
        config.fri_config.log_blowup_factor,
        config.pow_bits,
        n_commitments,
        n_decommitments,
        proof.log_sizes,
        proof.claimed_sums.len(),
        proof.component_mask.count_ones(),
    );
}
