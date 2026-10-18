//! The in-AIR verifier's pieces (`recursion-air.md` §4): a segment proof of
//! a lossless Poseidon2-M31 format verified in a circuit, piece by piece,
//! each a function on a [`Context`](crate::Context).
//!
//! - [`channel`]: the Fiat-Shamir transcript, its PoWs and its queries;
//! - [`merkle`]: openings of lifted trees, and [`merkle::expand_decommitment`],
//!   which gives each query its whole path;
//! - [`fri`]: FRI at fold step 1, one query at a time;
//! - [`deep`]: each query's DEEP quotient, FRI's first-layer value;
//! - [`oods`]: the composition check through the compiled constraints;
//! - [`logup`]: the claimed sums, and the boundary chips' public terms;
//! - [`shape`]: what a circuit is built for, and the check that a proof has
//!   it;
//! - [`witness`]: a proof's values laid out as the circuit guesses them;
//! - [`segment`]: the pieces composed in the native verifier's order.
//!
//! [`bits`] and [`circle`] are the arithmetic they share.

pub mod bits;
pub mod channel;
pub mod circle;
pub mod deep;
pub mod fri;
pub mod logup;
pub mod merkle;
pub mod oods;
pub mod segment;
pub mod shape;
pub mod witness;

pub use segment::{Draws, Verified, verify_segment};
pub use shape::{SegmentShape, ShapeMismatch};
pub use witness::{SegmentValues, WitnessError};
