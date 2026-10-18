//! Recursion over the segment AIR: a segment verified in a circuit, the
//! leaves, a fold of two nodes, a tree's root and its wrap.

#[path = "../common/mod.rs"]
mod common;
/// The venue's JAM refine program on the JAM-only host.
#[path = "../../../statement/tests/support/jam.rs"]
mod jam;

mod fold;
mod leaf;
mod leaf_rows;
mod leaves;
mod verifier;
mod wrap;
