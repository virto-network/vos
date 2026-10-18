//! The pieces composed: one segment proof verified in a circuit, in the
//! native verifier's order (`proving.md` A.1, then Stwo's `verify`), each
//! check where the native one is, so a tampered value is refused where the
//! native verifier refuses it.

use crate::context::{Context, Var};
use crate::value::Value;

use super::channel::{Channel, u64_wire};
use super::logup::{self, BoundaryRelations, Challenges};
use super::shape::SegmentShape;
use super::stark::{Draws, interaction, verify_rest};
use super::witness::{SegmentValues, digest_wires};

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
    assert_eq!(values.header.len(), shape.header.len(), "header words");
    assert_eq!(
        values.boundary.len(),
        vos_pvm_proof::boundary_binding::BOUNDARY_STATE_BYTES.div_ceil(4),
        "boundary wires"
    );
    values.stark.assert_lengths(&shape.stark);
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
    let main_root = context.guess_pair(values.stark.roots[0]);
    channel.mix_root(context, main_root);
    let boundary: Vec<Var> = values.boundary.iter().map(|&v| context.guess(v)).collect();
    channel.mix_m31s(
        context,
        &boundary,
        vos_pvm_proof::boundary_binding::BOUNDARY_STATE_BYTES,
    );
    let (relations, claimed_sums) = interaction(context, &shape.stark, &mut channel, &values.stark);

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

    let (draws, answers) = verify_rest(
        context,
        &shape.stark,
        &mut channel,
        [preprocessed_root, main_root],
        relations,
        &claimed_sums,
        &values.stark,
    );
    Verified {
        channel,
        draws,
        boundary,
        answers,
    }
}
