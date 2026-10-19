//! The lane gadgets: a `p2` row absorbs the lanes of its message wires its
//! `act` sets, and no others (`recursion-air.md` §1.3). A lane it leaves
//! unread, on a wire no gate computes, is the prover's to choose: the AIR
//! does not hold it at zero, and no consumer may assume it is.
//!
//! - **The forgery,** an unread lane set nonzero at its yield and at every
//!   use, is accepted, and states the honest statement: no gate reads it.
//! - **The audit** that makes that hold of every circuit of a tree: on the
//!   leaves of the window kernel and of a small kernel, the fold and the
//!   wrap, no operand reads a lane of a wire that its absorbing rows leave
//!   unread and no gate computes ([`unread_lane_reads`]).
//! - **What the audit refuses:** a circuit that reads such a lane, flagged,
//!   whose forger states any value there and is accepted.

use std::collections::{HashMap, HashSet};

use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::prove_canonical_format;
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_recair::circuit::Circuit;
use vos_pvm_recair::fold::FoldCircuit;
use vos_pvm_recair::gadgets::leaf_hash;
use vos_pvm_recair::leaf::{LeafCircuit, State};
use vos_pvm_recair::verifier::SegmentShape;
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::wrap::WrapCircuit;
use vos_pvm_recair::{Context, Finalized, P2Mode};

use crate::common::kernel::{blob, entry};
use crate::common::{Rng, segment_fixture};
use crate::forge::{Forgery, assert_accepted, hash_of};

/// Each read of a lane that every `p2` row absorbing its wire leaves
/// unread, the wire computed by no gate: the address, the lane and the
/// reader; and how many reads of such wires' lanes were checked.
///
/// A lane is absorbed by a message slot whose `act` reads it, or by a node
/// row, which reads its whole message. A wire is computed when some gate's
/// output is at its address, a yield or a use. Readers: a `qm31` operand,
/// whole under `k_m`, `k_p` or its own linear coefficient, lane `j` under
/// `λ_j` (the `c` operand); an `h8` input, whole; a node's bit, its lane 0;
/// a public use, whole.
pub fn unread_lane_reads(circuit: &Circuit) -> (Vec<(u32, usize, String)>, usize) {
    let mut absorbed: HashMap<u32, [bool; 4]> = HashMap::new();
    let mut partial: HashSet<u32> = HashSet::new();
    let mut computed: HashSet<u32> = HashSet::new();
    for wiring in &circuit.p2 {
        for w in 0..2 {
            let entry = wiring.m[w];
            if entry.multiplicity == 0 {
                continue;
            }
            let lanes: [bool; 4] = core::array::from_fn(|j| {
                wiring.mode == Some(P2Mode::Node) || !wiring.act[4 * w + j].is_zero()
            });
            let all = absorbed.entry(entry.address).or_default();
            for j in 0..4 {
                all[j] |= lanes[j];
            }
            if lanes.contains(&false) {
                partial.insert(entry.address);
            }
        }
        for w in 0..2 {
            if wiring.out_multiplicity[w] != 0 {
                computed.insert(wiring.out_address + w as u32);
            }
        }
    }
    for wiring in &circuit.qm31 {
        if wiring.operands[3].multiplicity != 0 {
            computed.insert(wiring.operands[3].address);
        }
    }
    for wiring in &circuit.h8 {
        if wiring.out.multiplicity != 0 {
            computed.insert(wiring.out.address);
        }
    }
    let audited = |address: u32| partial.contains(&address) && !computed.contains(&address);

    let mut reads = Vec::new();
    let mut checked = 0;
    let mut read = |address: u32, lanes: [bool; 4], reader: String| {
        if !audited(address) {
            return;
        }
        checked += lanes.iter().filter(|&&lane| lane).count();
        let all = absorbed[&address];
        for j in (0..4).filter(|&j| lanes[j] && !all[j]) {
            reads.push((address, j, reader.clone()));
        }
    };
    let whole = [true; 4];
    for (row, wiring) in circuit.qm31.iter().enumerate() {
        let op = wiring.op;
        let linear = [op.k_a, op.k_b, op.k_c];
        for (i, (entry, k)) in wiring.operands.iter().zip(linear).enumerate() {
            if entry.multiplicity == 0 {
                continue;
            }
            let product = i < 2 && !(op.k_m.is_zero() && op.k_p.is_zero());
            let lanes = if product || !k.is_zero() {
                whole
            } else if i == 2 {
                op.lanes.map(|lane| !lane.is_zero())
            } else {
                [false; 4]
            };
            read(entry.address, lanes, format!("qm31 row {row}, operand {i}"));
        }
    }
    for (row, wiring) in circuit.h8.iter().enumerate() {
        for (i, &address) in wiring.inputs.iter().enumerate() {
            read(address, whole, format!("h8 row {row}, input {i}"));
        }
    }
    for (row, wiring) in circuit.p2.iter().enumerate() {
        if wiring.mode == Some(P2Mode::Node) {
            read(
                wiring.bit_address,
                [true, false, false, false],
                format!("p2 row {row}'s bit"),
            );
        }
    }
    let layout = circuit.layout;
    for address in (0..layout.n_outputs)
        .map(|i| layout.output(i))
        .chain([layout.u()])
    {
        read(address, whole, format!("the public use of {address}"));
    }
    (reads, checked)
}

/// Five values in two wires, the second's lanes 1–3 unread by the leaf
/// that absorbs them; then `reader`'s lanes of the second wire as an M31,
/// beside the leaf's digest, the outputs.
fn partly_absorbed(reader: [u32; 4]) -> Finalized<SecureField> {
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
    context.finalize().expect("the wiring checks")
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
        forgery.trace.columns[0][vos_pvm_recair_air::p2::main::M + 4 + j][row] =
            BaseField::from(1_000 + j as u32);
    }
    forgery.settle();
    forgery
}

/// An unread lane set nonzero is accepted and states the honest statement:
/// the leaf hashes lane 0 of the wire, the reader reads lane 0, and neither
/// reads the others.
#[test]
fn an_unread_lane_set_nonzero_states_nothing() {
    let finalized = partly_absorbed([1, 0, 0, 0]);
    let (reads, checked) = unread_lane_reads(&finalized.circuit);
    assert!(reads.is_empty() && checked == 1, "{reads:?}, {checked}");
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

/// A circuit that reads an unread lane is flagged by the audit, and a
/// forger states any value there: its proof of lane 1 as 1,001 is
/// accepted, which is why no circuit of a tree may read one.
#[test]
fn a_circuit_reading_an_unread_lane_is_flagged() {
    let finalized = partly_absorbed([0, 1, 0, 0]);
    let (reads, _) = unread_lane_reads(&finalized.circuit);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(reads[0].1, 1, "lane 1");
    let forgery = unread_lanes_set(&finalized);
    assert_eq!(
        forgery.outputs[2],
        SecureField::from(BaseField::from(1_001))
    );
    assert_ne!(forgery.outputs, finalized.witness.outputs);
    assert_accepted(
        forgery.prove(),
        &hash_of(&finalized.circuit),
        "a flagged circuit's forgery",
    );
}

/// No circuit of a tree reads an unread lane: the window kernel's leaf (the
/// format-35 fixture's shape), a small kernel's leaf, the fold and the
/// wrap.
#[test]
fn no_circuit_of_a_tree_reads_an_unread_lane() {
    let fixture = segment_fixture();
    let window = LeafCircuit::new(
        SegmentShape::of(&fixture),
        State::from(&fixture.initial_state),
    );
    let blob = blob();
    let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let steps = trace.side_note.steps.len();
    let proof =
        prove_canonical_format(&mut cursor.side_note(0, steps), &[], &SEGMENT).expect("proves");
    let small = LeafCircuit::new(SegmentShape::of(&proof), entry(&blob));
    let circuits: [(&str, Circuit); 4] = [
        ("the window kernel's leaf", window.topology().circuit),
        ("a small kernel's leaf", small.topology().circuit),
        ("the fold", FoldCircuit::new().topology().circuit),
        ("the wrap", WrapCircuit::get().topology().circuit),
    ];
    for (name, circuit) in circuits {
        let partial = circuit
            .p2
            .iter()
            .filter(|wiring| {
                wiring.mode != Some(P2Mode::Node)
                    && (0..2).any(|w| {
                        wiring.m[w].multiplicity != 0
                            && (0..4).any(|j| wiring.act[4 * w + j].is_zero())
                    })
            })
            .count();
        let (reads, checked) = unread_lane_reads(&circuit);
        eprintln!(
            "{name}: {partial} rows absorb a wire in part, {checked} reads of their lanes checked"
        );
        assert!(checked > 0, "{name}: the audit checks reads");
        assert!(
            reads.is_empty(),
            "{name}: {:?}",
            &reads[..reads.len().min(8)]
        );
    }
}
