//! The preflight's replay against the pinned Stwo verifier itself, on toy
//! AIRs whose proofs sample many columns across the preprocessed, main,
//! interaction and composition trees.

use super::{
    ProofProtocolShape, derive_protocol_degree_shape, expected_fiat_shamir_query_count,
    replay_query_positions,
};
use crate::pcs::PcsStack;
use crate::poseidon2::P2MerkleChannel;
use crate::trace::eval::INTERACTION_TRACE_IDX;
use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::{m31::BaseField, qm31::SecureField};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::verifier::verify;
use stwo::prover::backend::{BackendForChannel, simd::SimdBackend};
use stwo::prover::poly::{
    BitReversedOrder,
    circle::{CircleEvaluation, PolyOps},
};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

const LOG_N_ROWS: u32 = 5;
const MAIN_COLUMNS: usize = 12;

/// The second main column is the preprocessed one, the row's index, and
/// each after it the sum of the two before it; the one interaction column
/// repeats the last main column.
#[derive(Clone)]
struct SumEval;

impl FrameworkEval for SumEval {
    fn log_size(&self) -> u32 {
        LOG_N_ROWS
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_N_ROWS + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let index = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "row_index".into(),
        });
        let mut a = eval.next_trace_mask();
        let mut b = eval.next_trace_mask();
        eval.add_constraint(b.clone() - index);
        for _ in 2..MAIN_COLUMNS {
            let c = eval.next_trace_mask();
            eval.add_constraint(c.clone() - (a + b.clone()));
            a = b;
            b = c;
        }
        let [copy] = eval.next_interaction_mask(INTERACTION_TRACE_IDX, [0]);
        eval.add_constraint(copy - b);
        eval
    }
}

/// The row's index, read from the preprocessed tree.
#[derive(Clone)]
struct IndexEval;

impl FrameworkEval for IndexEval {
    fn log_size(&self) -> u32 {
        LOG_N_ROWS
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_N_ROWS + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let index = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "row_index".into(),
        });
        let value = eval.next_trace_mask();
        eval.add_constraint(value - index);
        eval
    }
}

const SQUARE_LOG_N_ROWS: u32 = LOG_N_ROWS + 2;

/// Four times the rows of [`IndexEval`]: the second main column is the
/// square of the first, and the one interaction column repeats it. Its
/// degree-two constraint sets the lifting height.
#[derive(Clone)]
struct SquareEval;

impl FrameworkEval for SquareEval {
    fn log_size(&self) -> u32 {
        SQUARE_LOG_N_ROWS
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        SQUARE_LOG_N_ROWS + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let x = eval.next_trace_mask();
        let square = eval.next_trace_mask();
        eval.add_constraint(square.clone() - x.clone() * x);
        let [copy] = eval.next_interaction_mask(INTERACTION_TRACE_IDX, [0]);
        eval.add_constraint(copy - square);
        eval
    }
}

fn evaluations(
    log_size: u32,
    columns: Vec<Vec<BaseField>>,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    columns
        .into_iter()
        .map(|values| CircleEvaluation::new(domain, values.into_iter().collect()))
        .collect()
}

/// The replay leaves its channel where Stwo's verifier leaves its own after
/// drawing the queries, so both drew the same positions. Mixing the
/// sampled values one column at a time, rather than in Stwo's one
/// flattened mix, fails here on any proof with more than one sampled
/// column. Forty queries on a 64-point domain also repeat positions, so
/// the deduplicated count is checked against the queried rows, and the
/// preprocessed values against the positions they were read at.
#[test]
fn the_replay_draws_the_verifiers_query_positions() {
    replay_draws_the_verifiers_query_positions::<Blake2sMerkleChannel>();
    replay_draws_the_verifiers_query_positions::<P2MerkleChannel>();
}

fn replay_draws_the_verifiers_query_positions<MC: PcsStack>()
where
    SimdBackend: BackendForChannel<MC>,
{
    let config = PcsConfig {
        pow_bits: 4,
        fri_config: FriConfig::new(0, 1, 40, 1),
        lifting_log_size: None,
        deep_batching: Default::default(),
    };
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let rows: Vec<[BaseField; MAIN_COLUMNS]> = (0..1u32 << LOG_N_ROWS)
        .map(|row| {
            let mut values = [BaseField::one(); MAIN_COLUMNS];
            values[1] = BaseField::from(row);
            for column in 2..MAIN_COLUMNS {
                values[column] = values[column - 2] + values[column - 1];
            }
            values
        })
        .collect();
    let column = |index: usize| rows.iter().map(|row| row[index]).collect();
    let preprocessed = alloc::vec![column(1)];
    let main = (0..MAIN_COLUMNS).map(column).collect();
    let interaction = alloc::vec![column(MAIN_COLUMNS - 1)];

    let prover_channel = &mut MC::C::default();
    let mut prover = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    for tree in [preprocessed, main, interaction] {
        let mut builder = prover.tree_builder();
        builder.extend_evals(evaluations(LOG_N_ROWS, tree));
        builder.commit(prover_channel);
    }
    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        SumEval,
        SecureField::zero(),
    );
    let proof = prove::<SimdBackend, MC>(&[&component], prover_channel, prover)
        .expect("the toy AIR proves");

    let log_sizes = component.trace_log_degree_bounds();
    let channel = &mut MC::C::default();
    let mut verifier = CommitmentSchemeVerifier::<MC>::new(config);
    for (commitment, tree_log_sizes) in proof.commitments.iter().zip(log_sizes.iter()) {
        verifier.commit(*commitment, tree_log_sizes, channel);
    }
    let after_interaction = channel.clone();
    verify(&[&component], channel, &mut verifier, proof.clone()).expect("Stwo verifies");

    let (lifting_log_size, max_log_degree_bound) =
        derive_protocol_degree_shape(&config, LOG_N_ROWS + 1).unwrap();
    let replayed = &mut after_interaction.clone();
    let positions =
        replay_query_positions::<MC>(replayed, &proof, &config, lifting_log_size).unwrap();
    assert_eq!(
        replayed.draw_u32s(),
        channel.draw_u32s(),
        "the replay's transcript differs from Stwo's verifier's after the query draw"
    );

    let query_count = proof.queried_values[1][0].len();
    assert!(query_count < config.fri_config.n_queries);
    assert_eq!(positions.len(), query_count);
    // The preprocessed tree is as tall as the others, so it is read at the
    // query positions themselves, one value each.
    let preprocessed_positions = prepare_preprocessed_query_positions(
        &positions,
        lifting_log_size,
        LOG_N_ROWS + config.fri_config.log_blowup_factor,
    );
    assert_eq!(preprocessed_positions, positions);
    assert_eq!(proof.queried_values[0].len(), 1);
    assert_eq!(proof.queried_values[0][0].len(), query_count);
    let shape = ProofProtocolShape {
        lifting_log_size,
        max_log_degree_bound,
        query_count,
    };
    assert_eq!(
        expected_fiat_shamir_query_count::<MC>(
            &after_interaction,
            &proof,
            &config,
            shape,
            &log_sizes
        ),
        Ok(query_count)
    );
}

/// A preprocessed tree below the lifting height is read at positions
/// folded onto its own domain, out of order and with repeats that are not
/// neighbours. Stwo's verifier accepts the honest proof, and the preflight
/// counts its queries.
#[test]
fn a_preprocessed_tree_below_the_lifting_height_verifies() {
    preprocessed_tree_below_the_lifting_height_verifies::<Blake2sMerkleChannel>();
    preprocessed_tree_below_the_lifting_height_verifies::<P2MerkleChannel>();
}

fn preprocessed_tree_below_the_lifting_height_verifies<MC: PcsStack>()
where
    SimdBackend: BackendForChannel<MC>,
{
    let config = PcsConfig {
        pow_bits: 4,
        fri_config: FriConfig::new(0, 1, 40, 1),
        lifting_log_size: None,
        deep_batching: Default::default(),
    };
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(SQUARE_LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let index: Vec<BaseField> = (0..1u32 << LOG_N_ROWS).map(BaseField::from).collect();
    let x: Vec<BaseField> = (0..1u32 << SQUARE_LOG_N_ROWS)
        .map(BaseField::from)
        .collect();
    let square: Vec<BaseField> = x.iter().map(|x| *x * *x).collect();

    let prover_channel = &mut MC::C::default();
    let mut prover = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    let mut builder = prover.tree_builder();
    builder.extend_evals(evaluations(LOG_N_ROWS, alloc::vec![index.clone()]));
    builder.commit(prover_channel);
    let mut builder = prover.tree_builder();
    builder.extend_evals(evaluations(LOG_N_ROWS, alloc::vec![index]));
    builder.extend_evals(evaluations(
        SQUARE_LOG_N_ROWS,
        alloc::vec![x, square.clone()],
    ));
    builder.commit(prover_channel);
    let mut builder = prover.tree_builder();
    builder.extend_evals(evaluations(SQUARE_LOG_N_ROWS, alloc::vec![square]));
    builder.commit(prover_channel);
    let allocator = &mut TraceLocationAllocator::default();
    let index_component = FrameworkComponent::new(allocator, IndexEval, SecureField::zero());
    let square_component = FrameworkComponent::new(allocator, SquareEval, SecureField::zero());
    let components: [&dyn Component; 2] = [&index_component, &square_component];
    let proof = prove::<SimdBackend, MC>(
        &[&index_component, &square_component],
        prover_channel,
        prover,
    )
    .expect("the toy AIR proves");

    let log_sizes = TreeVec::concat_cols(
        components
            .iter()
            .map(|component| component.trace_log_degree_bounds()),
    );
    let channel = &mut MC::C::default();
    let mut verifier = CommitmentSchemeVerifier::<MC>::new(config);
    for (commitment, tree_log_sizes) in proof.commitments.iter().zip(log_sizes.iter()) {
        verifier.commit(*commitment, tree_log_sizes, channel);
    }
    let after_interaction = channel.clone();
    let preprocessed_height = verifier.trees[0].height;
    verify(&components, channel, &mut verifier, proof.clone()).expect("Stwo verifies");

    let (lifting_log_size, max_log_degree_bound) =
        derive_protocol_degree_shape(&config, SQUARE_LOG_N_ROWS + 1).unwrap();
    assert_eq!(
        preprocessed_height + 2,
        lifting_log_size,
        "the preprocessed tree sits two levels below the lifting height"
    );
    let positions = replay_query_positions::<MC>(
        &mut after_interaction.clone(),
        &proof,
        &config,
        lifting_log_size,
    )
    .unwrap();
    let preprocessed_positions =
        prepare_preprocessed_query_positions(&positions, lifting_log_size, preprocessed_height);
    assert!(!preprocessed_positions.is_sorted());
    assert!(
        preprocessed_positions
            .iter()
            .enumerate()
            .any(|(at, position)| preprocessed_positions
                .get(at + 2..)
                .is_some_and(|later| later.contains(position))),
        "some preprocessed position repeats, not as a neighbour"
    );

    let query_count = proof.queried_values[1][0].len();
    assert_eq!(positions.len(), query_count);
    let shape = ProofProtocolShape {
        lifting_log_size,
        max_log_degree_bound,
        query_count,
    };
    assert_eq!(
        expected_fiat_shamir_query_count::<MC>(
            &after_interaction,
            &proof,
            &config,
            shape,
            &log_sizes
        ),
        Ok(query_count)
    );
}
