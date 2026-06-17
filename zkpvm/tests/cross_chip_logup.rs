//! Recursion build P3 — the **cross-chip logup keystone**.
//!
//! The native-recursion verifier-AIR is ~99.5% Poseidon2 hashing, factored as a
//! shared **PRODUCER** permutation chip (one `hash_children` compression per
//! row) that every other chip **CONSUMES** by reference instead of re-running
//! the 442-column permutation. That cross-component binding is a *logup*: the
//! producer emits each `(left ‖ right ‖ parent)` compression with +1, the
//! consumer drains the same tuple with −1, and the protocol's claimed-sum
//! balance forces the consumed multiset to equal the produced one (Schwartz-
//! Zippel over the relation challenge). **Everything else in the verifier-AIR
//! rests on this mechanism working** — and the foundation tests (single
//! self-contained AIRs, no logup) never exercised it. This gate does.
//!
//! What is genuinely new here vs. the foundation:
//! - Cross-component logup through stwo's **lifted protocol on `CpuBackend`**
//!   with the custom **Poseidon2-M31 channel** (the relation challenge is drawn
//!   from it; no Blake2s anywhere).
//! - The SIMD→Cpu interaction-trace transplant: stwo's `LogupTraceGenerator` is
//!   SimdBackend-only, but the proof rides `CpuBackend` (the custom hasher's
//!   `MerkleOpsLifted` is blanket only there), so the logup columns are computed
//!   on SIMD and `to_cpu`-moved into the committed columns. SIMD column
//!   *arithmetic* is always available; only the per-hasher commitment ops are
//!   not.
//! - One component **proves** the permutation; the other **trusts** its I/O via
//!   the relation alone — the exact split the MerkleDecommit / Channel / FriFold
//!   / OodsComposition chips will use.
//!
//! Degree stays ≤ 2 (`LOG_CONSTRAINT_DEGREE_BOUND=1`): each component emits
//! exactly ONE logup fraction, so the batched logup constraint is
//! `(cumsum_diff + shift)·denom − num` = degree 2, matching the flattened S-box.
//!
//! Run: `cargo test -p zkpvm --test cross_chip_logup -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::*;
use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedM31};
use stwo::prover::backend::simd::qm31::PackedQM31;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, ComponentProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator,
};

// ── PRODUCER: proves one Poseidon2 compression per row, emits its I/O (+1) ──

#[derive(Clone)]
struct ProducerEval {
    log_n_rows: u32,
    rel: Poseidon2CompressionRelation,
}

impl FrameworkEval for ProducerEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree-2 S-box + a single-fraction logup (also degree 2).
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Constrain the full permutation; bind its (input[16], output[16]).
        let (init, out) = eval_permutation(&mut eval);
        // The compression tuple is (left ‖ right ‖ parent) = input[16] ‖ out[0..8].
        let mut tuple: Vec<E::F> = Vec::with_capacity(COMPRESSION_TUPLE_LEN);
        tuple.extend_from_slice(&init);
        for v in out.iter().take(RATE) {
            tuple.push(v.clone());
        }
        eval.add_to_relation(RelationEntry::new(&self.rel, E::EF::one(), &tuple));
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ── CONSUMER: references a compression I/O (−1) WITHOUT re-running the perm ──

#[derive(Clone)]
struct ConsumerEval {
    log_n_rows: u32,
    rel: Poseidon2CompressionRelation,
}

impl FrameworkEval for ConsumerEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // 24 raw masks: it asserts NOTHING about the permutation, only that the
        // same (left ‖ right ‖ parent) was produced elsewhere.
        let tuple: [E::F; COMPRESSION_TUPLE_LEN] = std::array::from_fn(|_| eval.next_trace_mask());
        eval.add_to_relation(RelationEntry::new(&self.rel, -E::EF::one(), &tuple));
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ── Trace generation (storage = bit-reversed circle-domain order, as logup
//    requires for the cross-row cumulative sum) ─────────────────────────────

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

fn init_for_row(i: usize) -> [BaseField; N_STATE] {
    std::array::from_fn(|j| BaseField::from_u32_unchecked((i * N_STATE + j + 1) as u32))
}

type SimdEvals = Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;
type CpuEvals = Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>;

/// Column indices, within the 442-col permutation trace, of the compression
/// tuple the producer emits: `input[16]` (cols 0..16) then the last full
/// round's `out` masks for elements 0..8 — exactly the masks
/// [`eval_permutation`] returns and [`ProducerEval`] binds.
fn producer_tuple_cols() -> Vec<usize> {
    let last_round_start = N_PERM_COLS - N_STATE * 3; // the final full round's 48 cols
    (0..N_STATE)
        .chain((0..RATE).map(|j| last_round_start + 3 * j + 2))
        .collect()
}

/// Build the producer's 442-col permutation trace and the consumer's 24-col
/// I/O trace as SimdBackend columns (values placed in bit-reversed circle-
/// domain storage order, the convention stwo's logup generator + mask offsets
/// agree on). `cons_tamper = Some((col, logical_row))` corrupts one committed
/// consumer cell — modelling a consumer that claims a compression the producer
/// never proved.
fn gen_traces(log_size: u32, cons_tamper: Option<(usize, usize)>) -> (SimdEvals, SimdEvals) {
    let n = 1usize << log_size;
    let mut prod_vals: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; N_PERM_COLS];
    let mut cons_vals: Vec<Vec<BaseField>> =
        vec![vec![BaseField::zero(); n]; COMPRESSION_TUPLE_LEN];

    for i in 0..n {
        let s = storage_index(i, log_size);
        let init = init_for_row(i);

        let rec = record_permutation(init);
        for (c, v) in rec.into_iter().enumerate() {
            prod_vals[c][s] = v;
        }

        let mut st = init;
        permute(&mut st);
        for (c, v) in init.iter().enumerate() {
            cons_vals[c][s] = *v;
        }
        for (c, v) in st.iter().take(RATE).enumerate() {
            cons_vals[N_STATE + c][s] = *v;
        }
    }

    if let Some((col, row)) = cons_tamper {
        cons_vals[col][storage_index(row, log_size)] += BaseField::one();
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |cols: Vec<Vec<BaseField>>| -> SimdEvals {
        cols.into_iter()
            .map(|v| {
                CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                    domain,
                    BaseColumn::from_iter(v),
                )
            })
            .collect()
    };
    (wrap(prod_vals), wrap(cons_vals))
}

/// Generate one logup interaction column (and its claimed sum) for the given
/// multiplicity, reading the compression tuple directly from the COMMITTED
/// trace columns `tuple_cols` (the state_machine pattern), via stwo's SIMD
/// generator, transplanted to `CpuBackend`.
fn gen_interaction(
    tuple_cols: &[&CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    rel: &Poseidon2CompressionRelation,
    multiplicity: SecureField,
) -> (CpuEvals, SecureField) {
    assert_eq!(tuple_cols.len(), COMPRESSION_TUPLE_LEN);
    let mut logup = LogupTraceGenerator::new(log_size);
    let mut col = logup.new_col();
    let num = PackedQM31::broadcast(multiplicity);
    for vec_row in 0..(1usize << (log_size - LOG_N_LANES)) {
        let packed: [PackedM31; COMPRESSION_TUPLE_LEN] =
            std::array::from_fn(|c| tuple_cols[c].data[vec_row]);
        let denom: PackedQM31 = rel.combine(&packed);
        col.write_frac(vec_row, num, denom);
    }
    col.finalize_col();
    let (simd, claimed_sum) = logup.finalize_last();
    (to_cpu(&simd), claimed_sum)
}

// ── Prove + verify orchestration ──────────────────────────────────────────

struct Proven {
    producer: FrameworkComponent<ProducerEval>,
    consumer: FrameworkComponent<ConsumerEval>,
    proof: StarkProof<P2MerkleHasher>,
    claimed_p: SecureField,
    claimed_c: SecureField,
}

fn prove_keystone(log_size: u32, config: PcsConfig, cons_tamper: Option<(usize, usize)>) -> Proven {
    let (prod_simd, cons_simd) = gen_traces(log_size, cons_tamper);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);

    // Tree 0: empty preprocessed.
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);

    // Tree 1: main trace — producer columns then consumer columns (transplanted
    // SIMD→Cpu for the Poseidon2-M31 commitment).
    let mut tb = cs.tree_builder();
    let mut main = to_cpu(&prod_simd);
    main.extend(to_cpu(&cons_simd));
    tb.extend_evals(main);
    tb.commit(channel);

    // Draw the relation AFTER the main commitment (Fiat-Shamir).
    let rel = Poseidon2CompressionRelation::draw(channel);

    // Interaction traces, each read from its OWN committed columns: the producer
    // from its perm-trace I/O masks (+1), the consumer from its 24 raw cols (−1).
    let prod_cols: Vec<&CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> =
        producer_tuple_cols()
            .iter()
            .map(|&c| &prod_simd[c])
            .collect();
    let cons_cols: Vec<&CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> =
        cons_simd.iter().collect();
    let (int_p, claimed_p) = gen_interaction(&prod_cols, log_size, &rel, SecureField::one());
    let (int_c, claimed_c) = gen_interaction(&cons_cols, log_size, &rel, -SecureField::one());

    channel.mix_felts(&[claimed_p, claimed_c]);

    // Tree 2: interaction — producer column then consumer column.
    let mut tb = cs.tree_builder();
    let mut inter = int_p;
    inter.extend(int_c);
    tb.extend_evals(inter);
    tb.commit(channel);

    let alloc = &mut TraceLocationAllocator::default();
    let producer = FrameworkComponent::<ProducerEval>::new(
        alloc,
        ProducerEval {
            log_n_rows: log_size,
            rel: rel.clone(),
        },
        claimed_p,
    );
    let consumer = FrameworkComponent::<ConsumerEval>::new(
        alloc,
        ConsumerEval {
            log_n_rows: log_size,
            rel: rel.clone(),
        },
        claimed_c,
    );

    let proof = prove::<CpuBackend, P2MerkleChannel>(
        &[
            &producer as &dyn ComponentProver<CpuBackend>,
            &consumer as &dyn ComponentProver<CpuBackend>,
        ],
        channel,
        cs,
    )
    .expect("prove the cross-chip logup circuit");

    Proven {
        producer,
        consumer,
        proof,
        claimed_p,
        claimed_c,
    }
}

fn verify_keystone(p: Proven, config: PcsConfig) -> Result<(), String> {
    // Global balance: a closed producer/consumer system must net to zero, else
    // a compression was consumed that was never produced.
    if p.claimed_p + p.claimed_c != SecureField::zero() {
        return Err(format!(
            "claimed-sum balance != 0 (consumed multiset != produced): {:?}",
            p.claimed_p + p.claimed_c
        ));
    }

    let channel = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = TreeVec::concat_cols(
        [
            p.producer.trace_log_degree_bounds(),
            p.consumer.trace_log_degree_bounds(),
        ]
        .into_iter(),
    );
    vs.commit(p.proof.commitments[0], &sizes[0], channel); // preprocessed
    vs.commit(p.proof.commitments[1], &sizes[1], channel); // main
    let _rel = Poseidon2CompressionRelation::draw(channel); // replay the draw
    channel.mix_felts(&[p.claimed_p, p.claimed_c]); // replay the claimed-sum mix
    vs.commit(p.proof.commitments[2], &sizes[2], channel); // interaction

    verify(
        &[&p.producer as &dyn Component, &p.consumer as &dyn Component],
        channel,
        &mut vs,
        p.proof,
    )
    .map_err(|e| format!("stwo verify rejected: {e:?}"))
}

// ── The keystone gate ─────────────────────────────────────────────────────

#[test]
fn cross_chip_logup_keystone() {
    const LOG_N_ROWS: u32 = 5; // ≥ LOG_N_LANES (4) for the SIMD logup generator.
    let config = mobile_config();

    // ── Positive: producer proves the compressions, consumer trusts them by
    //    relation alone; the two balance and the STARK verifies. ──
    let proven = prove_keystone(LOG_N_ROWS, config, None);
    assert_eq!(
        proven.claimed_p + proven.claimed_c,
        SecureField::zero(),
        "honest producer/consumer must balance to zero"
    );
    verify_keystone(proven, config).expect("honest cross-chip logup proof must verify");

    // ── Negative: the consumer claims a parent hash the producer never proved
    //    (one tampered committed cell, honest logup elsewhere). The local logup
    //    constraint no longer matches the committed value → verify MUST reject. ──
    let tampered = prove_keystone(LOG_N_ROWS, config, Some((N_STATE, 0))); // parent[0], row 0
    assert!(
        verify_keystone(tampered, config).is_err(),
        "a consumed compression absent from the producer must be rejected"
    );

    eprintln!(
        "cross_chip_logup_keystone GREEN: a Poseidon2-perm PRODUCER and a \
         compression CONSUMER, bound by a logup relation drawn from the \
         Poseidon2-M31 channel, prove+verify together through the lifted protocol \
         on CpuBackend (no Blake2s); an unproduced consumption is rejected. The \
         cross-chip binding the verifier-AIR rests on holds."
    );
}
