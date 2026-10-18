//! The pieces composed: one segment proof verified in a circuit, in the
//! native verifier's order (`proving.md` A.1, then Stwo's `verify`), each
//! check where the native one is, so a tampered value is refused where the
//! native verifier refuses it.

use crate::context::{Bit, Context, Var};
use crate::value::Value;

use super::channel::{Channel, u64_wire};
use super::circle::{Point, domain_point, random_point};
use super::fri::{FriCommitment, verify_query};
use super::logup::{BoundaryRelations, Challenges};
use super::merkle::verify_opening;
use super::shape::{CompiledInput, SegmentShape};
use super::witness::{SegmentValues, digest_wires};
use super::{deep, logup, oods};

/// What the channel drew, as wires.
#[derive(Clone, Debug)]
pub struct Draws {
    /// Each relation's `z` and `α`, in draw order.
    pub relations: Vec<[Var; 2]>,
    pub composition_coeff: Var,
    pub oods: Point,
    pub deep_coeff: Var,
    pub fri_alphas: Vec<Var>,
    /// Each query's position bits, least significant first, in draw order.
    pub queries: Vec<Vec<Bit>>,
}

/// A verified segment's wires.
#[derive(Clone, Debug)]
pub struct Verified<V> {
    pub channel: Channel<V>,
    pub draws: Draws,
    /// The boundary states' bytes, four a wire: what a leaf binds further.
    pub boundary: Vec<Var>,
    /// Each query's first-layer value, the DEEP quotient.
    pub answers: Vec<Var>,
}

fn guess_pair<V: Value>(context: &mut Context<V>, values: [V; 2]) -> [Var; 2] {
    context.guess_pair(values)
}

/// The preprocessed tree's position bits from a query's, the tree `height`
/// levels at most the lifting height's `bits.len()`: Stwo's
/// `prepare_preprocessed_query_positions`, `(p >> (H − h + 1) << 1) + (p & 1)`,
/// keeps the first bit and the top `h − 1`.
pub fn preprocessed_bits(bits: &[Bit], height: u32) -> Vec<Bit> {
    let lifting = bits.len();
    let height = height as usize;
    assert!(
        (1..=lifting).contains(&height),
        "a tree no taller than the lifting"
    );
    let mut out = vec![bits[0]];
    out.extend_from_slice(&bits[lifting - height + 1..]);
    out
}

/// Asserts every length of `values` is `shape`'s: the circuit's structure
/// is the shape's alone, never the values'.
fn assert_lengths<V: Value>(shape: &SegmentShape, values: &SegmentValues<V>) {
    let lifting = shape.layout.lifting_log_size as usize;
    assert_eq!(values.header.len(), shape.header.len(), "header words");
    assert_eq!(
        values.boundary.len(),
        vos_pvm_proof::boundary_binding::BOUNDARY_STATE_BYTES.div_ceil(4),
        "boundary wires"
    );
    assert_eq!(
        values.claimed_sums.len(),
        shape.log_sizes.len(),
        "claimed sums"
    );
    assert_eq!(values.sampled.len(), shape.n_samples, "sampled values");
    assert_eq!(values.fri_roots.len(), shape.n_fri_layers, "FRI roots");
    assert_eq!(
        values.queries.len(),
        shape.config().fri_config.n_queries,
        "queries"
    );
    for query in &values.queries {
        assert_eq!(query.trees.len(), 4, "trees");
        for (tree, opening) in query.trees.iter().enumerate() {
            assert_eq!(
                opening.leaf.len(),
                shape.leaf_order[tree].len().div_ceil(4),
                "leaf wires"
            );
            assert_eq!(
                opening.path.len(),
                shape.heights[tree] as usize,
                "tree path nodes"
            );
        }
        assert_eq!(query.fri.len(), shape.n_fri_layers, "FRI layers");
        for (layer, opening) in query.fri.iter().enumerate() {
            assert_eq!(opening.path.len(), lifting - layer - 1, "FRI path nodes");
        }
    }
}

/// Verifies the segment proof whose values are `values` in `context`, a
/// circuit of `shape`.
///
/// # Panics
/// When a length of `values` is not `shape`'s.
pub fn verify_segment<V: Value>(
    context: &mut Context<V>,
    shape: &SegmentShape,
    values: &SegmentValues<V>,
) -> Verified<V> {
    assert_lengths(shape, values);
    let config = shape.config();
    let lifting = shape.layout.lifting_log_size;
    context.piece("channel");
    let mut channel = Channel::new(context);

    // The statement header, each word checked against the shape's.
    let header: Vec<Var> = values
        .header
        .iter()
        .map(|&word| {
            let wire = context.guess(word);
            channel.mix_wire(context, wire);
            wire
        })
        .collect();
    let preprocessed_root =
        context.guess_pair(digest_wires(&shape.preprocessed_root).map(V::from_qm31));
    channel.mix_root(context, preprocessed_root);
    context.piece("shape");
    for (&wire, &word) in header.iter().zip(&shape.header) {
        let constant = context.constant(u64_wire(word));
        context.assert_eq(constant, wire);
    }
    for (wire, value) in preprocessed_root
        .into_iter()
        .zip(digest_wires(&shape.preprocessed_root))
    {
        let constant = context.constant(value);
        context.assert_eq(constant, wire);
    }

    context.piece("channel");
    let main_root = guess_pair(context, values.roots[0]);
    channel.mix_root(context, main_root);
    let boundary: Vec<Var> = values.boundary.iter().map(|&v| context.guess(v)).collect();
    channel.mix_m31s(
        context,
        &boundary,
        vos_pvm_proof::boundary_binding::BOUNDARY_STATE_BYTES,
    );
    context.piece("pow");
    let interaction_nonce = context.guess(values.interaction_nonce);
    channel.check_pow(
        context,
        shape.format.interaction_pow_bits(),
        interaction_nonce,
    );
    context.piece("channel");
    let relations: Vec<[Var; 2]> = shape
        .relations
        .iter()
        .map(|_| channel.draw_felts(context))
        .collect();
    let claimed_sums: Vec<Var> = values
        .claimed_sums
        .iter()
        .map(|&v| context.guess(v))
        .collect();
    channel.mix_felts(context, &claimed_sums);

    context.piece("logup");
    let challenge = |r: usize| Challenges {
        z: relations[r][0],
        alpha: relations[r][1],
    };
    match shape.boundary {
        Some(terms) => {
            let [register, program, merkle] = terms.relations;
            logup::check(
                context,
                &claimed_sums,
                &terms.positions,
                &boundary,
                &BoundaryRelations {
                    register_memory: challenge(register),
                    program_execution: challenge(program),
                    merkle_node: challenge(merkle),
                },
            );
        }
        None => logup::check_total(context, &claimed_sums),
    }

    context.piece("channel");
    let interaction_root = guess_pair(context, values.roots[1]);
    channel.mix_root(context, interaction_root);
    let composition_coeff = channel.draw_felt(context);
    let composition_root = guess_pair(context, values.roots[2]);
    channel.mix_root(context, composition_root);
    let t = channel.draw_felt(context);

    context.piece("oods");
    let oods_point = random_point(context, t);
    let sampled: Vec<Var> = values.sampled.iter().map(|&v| context.guess(v)).collect();
    let inputs: Vec<Var> = shape
        .compiled_inputs()
        .into_iter()
        .map(|input| match input {
            CompiledInput::Sample(index) => sampled[index],
            CompiledInput::ClaimedSum(chip) => claimed_sums[chip],
            CompiledInput::Challenge(r, k) => relations[r][k],
        })
        .collect();
    let composition: [Var; 8] = core::array::from_fn(|c| sampled[shape.sample_index[3][c]]);
    oods::check(
        context,
        &shape.compiled,
        &inputs,
        composition_coeff,
        oods_point,
        shape.layout.max_log_degree_bound,
        composition,
    );

    context.piece("channel");
    channel.mix_felts(context, &sampled);
    let deep_coeff = channel.draw_felt(context);
    let mut fri_roots = Vec::with_capacity(shape.n_fri_layers);
    let mut fri_alphas = Vec::with_capacity(shape.n_fri_layers);
    for &root in &values.fri_roots {
        let root = guess_pair(context, root);
        channel.mix_root(context, root);
        fri_roots.push(root);
        fri_alphas.push(channel.draw_felt(context));
    }
    let last_layer = context.guess(values.last_layer);
    channel.mix_felts(context, &[last_layer]);
    context.piece("pow");
    let nonce = context.guess(values.nonce);
    channel.check_pow(context, config.pow_bits, nonce);
    context.piece("queries");
    let queries = channel.draw_queries(context, config.fri_config.n_queries, lifting);

    context.piece("deep once");
    let constants = deep::prepare(context, &shape.deep, oods_point, deep_coeff, &sampled);
    let commitment = FriCommitment {
        roots: fri_roots,
        alphas: fri_alphas.clone(),
        last_layer,
    };
    let roots = [
        preprocessed_root,
        main_root,
        interaction_root,
        composition_root,
    ];
    let mut answers = Vec::with_capacity(queries.len());
    for (bits, query) in queries.iter().zip(&values.queries) {
        context.piece("circle");
        let point = domain_point(context, lifting, bits);
        context.piece("merkle");
        let leaves: Vec<Vec<Var>> = query
            .trees
            .iter()
            .map(|tree| tree.leaf.iter().map(|&v| context.guess(v)).collect())
            .collect();
        for (tree, opening) in query.trees.iter().enumerate() {
            let tree_bits = if tree == 0 {
                preprocessed_bits(bits, shape.heights[0])
            } else {
                bits.clone()
            };
            verify_opening(
                context,
                &leaves[tree],
                shape.leaf_order[tree].len(),
                &tree_bits,
                &opening.path,
                roots[tree],
            );
        }
        context.piece("deep");
        let answer = deep::answer(
            context,
            &shape.deep,
            &constants,
            point,
            [&leaves[0], &leaves[1], &leaves[2], &leaves[3]],
        );
        context.piece("fri");
        verify_query(
            context,
            lifting,
            &commitment,
            bits,
            point,
            answer,
            &query.fri,
        );
        answers.push(answer);
    }
    context.piece("end");
    Verified {
        channel,
        draws: Draws {
            relations,
            composition_coeff,
            oods: oods_point,
            deep_coeff,
            fri_alphas,
            queries,
        },
        boundary,
        answers,
    }
}
