//! The lane gadgets: a `p2` row absorbs the lanes of its message wires its
//! `act` sets, and no others (`recursion-air.md` §1.3). A lane it leaves
//! unread, on a wire no gate computes, is the prover's to choose: the AIR
//! does not hold it at zero, and no consumer may assume it is.
//!
//! - **The forgery,** an unread lane set nonzero at its yield and at every
//!   use, is accepted, and states the honest statement: no gate reads it.
//! - **The static check** that makes that hold of every pinned circuit:
//!   `Circuit::check_wiring` refuses a circuit whose operand reads a lane
//!   that its wire's absorbing rows leave unread and no gate computes
//!   (`WiringError::UnreadLaneRead`), so such a circuit is neither committed
//!   nor proved. A circuit reading one is refused at its finalizing; the
//!   leaves of the window kernel and of a small kernel, the fold and the
//!   wrap, which absorb wires in part, pass it.

use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair::circuit::{Circuit, WiringError};
use vos_pvm_recair::fold::FoldCircuit;
use vos_pvm_recair::gadgets::leaf_hash;
use vos_pvm_recair::leaf::{LeafCircuit, State};
use vos_pvm_recair::verifier::SegmentShape;
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::wrap::WrapCircuit;
use vos_pvm_recair::{Context, Finalized, P2Mode};

use crate::common::kernel::{blob, entry, whole_run};
use crate::common::{Rng, segment_fixture};
use crate::forge::{Forgery, assert_accepted, hash_of};

/// Five values in two wires, the second's lanes 1–3 unread by the leaf
/// that absorbs them; then `reader`'s lanes of the second wire as an M31,
/// beside the leaf's digest, the outputs.
fn partly_absorbed(reader: [u32; 4]) -> Result<Finalized<SecureField>, WiringError> {
    let mut rng = Rng::new(71);
    let mut context = Context::<SecureField>::with_outputs(3);
    let values: Vec<BaseField> = (0..5).map(|_| rng.m31()).collect();
    let wires: Vec<_> = pack(&values)
        .into_iter()
        .map(|wire| context.guess(wire))
        .collect();
    let leaf = leaf_hash(&mut context, &wires, 5);
    let read = context.lane_sum(wires[1], reader);
    context.set_outputs(&[leaf.digest[0], leaf.digest[1], read]);
    context.finalize()
}

/// The forgery: lanes 1–3 of the second wire set nonzero at its yield, the
/// leaf's message, and carried to every use.
fn unread_lanes_set(finalized: &Finalized<SecureField>) -> Forgery {
    let mut forgery = Forgery::honest(finalized);
    let row = finalized
        .circuit
        .p2
        .iter()
        .position(|wiring| wiring.mode == Some(P2Mode::LeafStart))
        .expect("the leaf's row");
    for j in 1..4 {
        forgery.set_message_lane(row, 4 + j, BaseField::from(1_000 + j as u32));
    }
    forgery.settle();
    forgery
}

/// An unread lane set nonzero is accepted and states the honest statement:
/// the leaf hashes lane 0 of the wire, the reader reads lane 0, and neither
/// reads the others.
#[test]
fn an_unread_lane_set_nonzero_states_nothing() {
    let finalized = partly_absorbed([1, 0, 0, 0]).expect("the wiring checks");
    let forgery = unread_lanes_set(&finalized);
    assert_eq!(
        forgery.outputs, finalized.witness.outputs,
        "the same statement"
    );
    assert_accepted(
        forgery.prove(),
        &hash_of(&finalized.circuit),
        "an unread lane set nonzero",
    );
}

/// A circuit that reads an unread lane, lane 1 of the second wire as an
/// output, is refused when it is finalized: its forger could state any
/// value there.
#[test]
fn a_circuit_reading_an_unread_lane_is_refused() {
    let refused = partly_absorbed([0, 1, 0, 0]).expect_err("an unread lane read");
    assert!(
        matches!(refused, WiringError::UnreadLaneRead { lane: 1, .. }),
        "{refused:?}"
    );
}

/// The rows of `circuit` that absorb a message wire in part.
fn partial_rows(circuit: &Circuit) -> usize {
    circuit
        .p2
        .iter()
        .filter(|wiring| {
            wiring.mode != Some(P2Mode::Node)
                && (0..2).any(|w| {
                    wiring.m[w].multiplicity != 0 && (0..4).any(|j| wiring.act[4 * w + j].is_zero())
                })
        })
        .count()
}

/// The circuits of a tree absorb wires in part and read no unread lane:
/// the window kernel's leaf (the format-35 fixture's shape), a small
/// kernel's leaf, the fold and the wrap; each topology finalized, so
/// checked.
#[test]
fn no_circuit_of_a_tree_reads_an_unread_lane() {
    let fixture = segment_fixture();
    let window = LeafCircuit::new(
        SegmentShape::of(&fixture),
        State::from(&fixture.initial_state),
    );
    let small = LeafCircuit::new(SegmentShape::of(whole_run()), entry(&blob()));
    let circuits: [(&str, Circuit); 4] = [
        ("the window kernel's leaf", window.topology().circuit),
        ("a small kernel's leaf", small.topology().circuit),
        ("the fold", FoldCircuit::new().topology().circuit),
        ("the wrap", WrapCircuit::get().topology().circuit),
    ];
    for (name, circuit) in circuits {
        let partial = partial_rows(&circuit);
        eprintln!("{name}: {partial} rows absorb a wire in part");
        assert!(partial > 0, "{name}");
        assert_eq!(circuit.unread_lane_reads(), [], "{name}");
    }
}
