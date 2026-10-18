//! FRI at fold step 1 (`recursion-air.md` §4.4), one query at a time, as
//! `FriVerifier::decommit` checks it at the pin.
//!
//! Layer 0 is the first layer's circle domain at the lifting height `H`,
//! the query's position its `H` bits; inner layer `ℓ` is a line domain of
//! `2^(H−ℓ)` points at the position's bits from `ℓ`. In each layer:
//! - **the pair's leaves:** the query's value, which the previous layer
//!   folded (the DEEP quotient in layer 0), and its sibling's, a guess;
//!   one permutation each, four words a leaf;
//! - **the path:** the pair's node, ordered by the position's bit, then a
//!   node a level to the layer's root;
//! - **the fold:** `(own + sib) + α·(own − sib)·t`, `t` the inverse of the
//!   query point's `y` in layer 0 and of its `x` after, `x` doubled from
//!   layer to layer. The sign of an odd position cancels: its point is the
//!   even one's conjugate (layer 0) or antipode (the line layers), so the
//!   formula needs no selection.
//!
//! The last fold's output is the last layer's coefficient: a polynomial of
//! degree bound 0 is its one coefficient at every point.

use crate::context::{Bit, Context, Message, Var};
use crate::gadgets::leaf_hash;
use crate::value::Value;

use super::circle::{Point, double_x};
use super::merkle::verify_path;

/// FRI's commitment as the channel drew it: each layer's root and folding
/// coefficient, layer 0 first, and the last layer's coefficient.
#[derive(Clone, Debug)]
pub struct FriCommitment {
    pub roots: Vec<[Var; 2]>,
    pub alphas: Vec<Var>,
    pub last_layer: Var,
}

/// A query's opening of one layer: its sibling's value, and the path above
/// the pair's node, its first sibling the pair's parent's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriOpening<V> {
    pub sibling: V,
    pub path: Vec<[V; 2]>,
}

/// Checks one query through every layer: `bits` its position in layer 0
/// (`log_size` of them), `point` its layer-0 domain point, `value` its
/// layer-0 value.
pub fn verify_query<V: Value>(
    context: &mut Context<V>,
    log_size: u32,
    commitment: &FriCommitment,
    bits: &[Bit],
    point: Point,
    value: Var,
    openings: &[FriOpening<V>],
) {
    let n_layers = commitment.roots.len();
    assert_eq!(commitment.alphas.len(), n_layers, "a coefficient a layer");
    assert_eq!(openings.len(), n_layers, "an opening a layer");
    assert_eq!(bits.len(), log_size as usize, "a bit a level");
    let mut own = value;
    let mut x = point.x;
    for (layer, opening) in openings.iter().enumerate() {
        let height = log_size as usize - layer;
        assert_eq!(
            opening.path.len(),
            height - 1,
            "a node a level above the pair"
        );
        let sibling = context.guess(opening.sibling);
        let own_leaf = leaf_hash(context, &[own], 4);
        let sibling_leaf = leaf_hash(context, &[sibling], 4);
        let mut siblings = vec![sibling_leaf.digest.map(Message::Wire)];
        siblings.extend(opening.path.iter().map(|node| node.map(Message::Free)));
        verify_path(
            context,
            own_leaf,
            &bits[layer..],
            &siblings,
            commitment.roots[layer],
        );

        let twiddle = if layer == 0 {
            point.y
        } else {
            if layer > 1 {
                x = double_x(context, x);
            }
            x
        };
        let t = context.inverse(twiddle);
        let difference = context.sub(own, sibling);
        let scaled = context.mul(difference, t);
        let sum = context.add(own, sibling);
        let alpha = commitment.alphas[layer];
        own = if layer + 1 == n_layers {
            context.qm31_into(
                crate::circuit::Qm31Op {
                    k_m: stwo::core::fields::m31::BaseField::from(1),
                    k_c: stwo::core::fields::m31::BaseField::from(1),
                    ..Default::default()
                },
                Some(alpha),
                Some(scaled),
                Some(sum),
                commitment.last_layer,
            );
            commitment.last_layer
        } else {
            context.mul_add(alpha, scaled, sum)
        };
    }
}
