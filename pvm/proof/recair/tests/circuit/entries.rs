//! `Circuit::entries()`, the wiring the static check counts, is exactly the
//! `Gate` fractions the three components' bodies emit over the committed
//! columns, operand for operand, with the public uses the verifier adds:
//! an entry the check counts and no body emits, or one a body emits and the
//! check misses, makes the check's balance another relation's.

use std::collections::BTreeMap;

use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::prover::backend::Column;
use stwo_constraint_framework::relation_tracker::{RelationTrackerEntry, add_to_relation_entries};
use vos_pvm_recair::circuit::{Circuit, signed};
use vos_pvm_recair::gadgets::{TranscriptGadget, leaf_hash, node, tagged};
use vos_pvm_recair::trace::{self, preprocessed_columns};
use vos_pvm_recair::{Context, Finalized, Message, P2Mode};
use vos_pvm_recair_air::Components;
use vos_pvm_recair_air::gate::GateRelation;

use crate::common::Rng;

/// `(address, multiplicity)` pairs, each multiplicity as its field word.
type Fractions = Vec<(u32, u32)>;
/// Each address's summed multiplicity, as its field word.
type Tally = BTreeMap<u32, u32>;
/// A tagged row's tamper, named.
type Tamper = (&'static str, fn(&mut vos_pvm_recair::circuit::P2Wiring));

/// Each address's summed multiplicity over `entries`, zero sums dropped.
fn tally(entries: impl Iterator<Item = (BaseField, BaseField)>) -> Tally {
    let mut sums = BTreeMap::<u32, BaseField>::new();
    for (address, multiplicity) in entries {
        *sums.entry(address.0).or_insert_with(BaseField::zero) += multiplicity;
    }
    sums.into_iter()
        .filter(|(_, sum)| !sum.is_zero())
        .map(|(address, sum)| (address, sum.0))
        .collect()
}

/// The (address, multiplicity) of every non-zero `Gate` fraction the bodies
/// emit over `finalized`'s committed columns, and their tally.
fn emitted(finalized: &Finalized<SecureField>) -> (Fractions, Tally) {
    let circuit = &finalized.circuit;
    let log_sizes = circuit.log_sizes();
    let stored = |columns: &trace::CosetColumns, log_size: u32| -> Vec<Vec<BaseField>> {
        trace::evaluations(columns, log_size)
            .into_iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect()
    };
    let preprocessed: Vec<Vec<BaseField>> = preprocessed_columns(circuit)
        .iter()
        .zip(log_sizes)
        .flat_map(|(columns, log_size)| stored(columns, log_size))
        .collect();
    let main_trace = trace::main_trace(circuit, &finalized.witness);
    let main: Vec<Vec<BaseField>> = main_trace
        .columns
        .iter()
        .zip(log_sizes)
        .flat_map(|(columns, log_size)| stored(columns, log_size))
        .collect();
    let tree = TreeVec(vec![
        preprocessed.iter().collect::<Vec<_>>(),
        main.iter().collect::<Vec<_>>(),
    ]);
    let components = Components::new(
        &GateRelation::dummy(),
        &log_sizes,
        &[SecureField::zero(); 3],
    );
    let mut fractions = Vec::new();
    let mut gather = |entries: Vec<RelationTrackerEntry>| {
        for entry in entries {
            if !entry.mult.is_zero() {
                fractions.push((entry.values[0], entry.mult));
            }
        }
    };
    gather(add_to_relation_entries(&components.p2, &tree));
    gather(add_to_relation_entries(&components.qm31, &tree));
    gather(add_to_relation_entries(&components.h8, &tree));
    let tallied = tally(fractions.iter().copied());
    let mut fractions: Vec<(u32, u32)> = fractions.into_iter().map(|(a, m)| (a.0, m.0)).collect();
    fractions.sort_unstable();
    (fractions, tallied)
}

/// `circuit`'s entries as the static check reads them, public uses apart:
/// the non-zero operand entries, and the whole tally.
fn counted(circuit: &Circuit) -> (Fractions, Tally, Tally) {
    let layout = circuit.layout;
    let n_public = 1 + layout.n_outputs as usize;
    let all: Vec<_> = circuit.entries().collect();
    let operands = &all[..all.len() - n_public];
    let as_field = |entries: &[vos_pvm_recair::circuit::Entry]| {
        entries
            .iter()
            .filter(|entry| entry.multiplicity != 0)
            .map(|entry| (BaseField::from(entry.address), signed(entry.multiplicity)))
            .collect::<Vec<_>>()
    };
    let mut operand_entries: Vec<(u32, u32)> = as_field(operands)
        .into_iter()
        .map(|(a, m)| (a.0, m.0))
        .collect();
    operand_entries.sort_unstable();
    (
        operand_entries,
        tally(as_field(operands).into_iter()),
        tally(as_field(&all).into_iter()),
    )
}

fn assert_tied(finalized: &Finalized<SecureField>) {
    let (fractions, emitted_tally) = emitted(finalized);
    let (operands, operand_tally, whole) = counted(&finalized.circuit);
    assert!(fractions.len() > 50, "{} fractions", fractions.len());
    assert_eq!(
        fractions, operands,
        "every operand entry is one emitted fraction"
    );
    assert_eq!(emitted_tally, operand_tally);
    assert!(
        whole.is_empty(),
        "the operands and the public uses balance at every address: {whole:?}"
    );
}

/// A circuit over every `p2` mode, `qm31` gates and `h8` rows.
fn every_row_kind() -> Finalized<SecureField> {
    let mut rng = Rng::new(41);
    let mut context = Context::<SecureField>::with_outputs(2);
    let a = context.guess(rng.qm31());
    let b = context.mul(a, a);
    let leaf = leaf_hash(&mut context, &[a, b, a], 12);
    let sibling = [rng.qm31(), rng.qm31()].map(Message::Free);
    let bit = context.guess(SecureField::from_u32_unchecked(1, 0, 0, 0));
    let bit = context.assert_bit(bit);
    let up = node(&mut context, &leaf, sibling, bit, None);
    let block = core::array::from_fn(|i| BaseField::from(i as u32 + 1));
    let tag = tagged(&mut context, block, up.digest, None);
    let mut transcript = TranscriptGadget::new(&context);
    transcript.absorb(&mut context, &[tag.digest[0], tag.digest[1], b], 12);
    transcript.absorb(&mut context, &[a, b, a, b, a], 20);
    let draw = transcript.squeeze(&mut context);
    let c = context.add(draw[0], draw[1]);
    let d = context.h8(c, a, b, [a, b]);
    let e = context.h8(d, a, c, [b, a]);
    context.set_outputs(&[e, c]);
    context.finalize().expect("the wiring checks")
}

#[test]
fn the_static_check_counts_what_the_bodies_emit() {
    let finalized = every_row_kind();
    let circuit = &finalized.circuit;
    for mode in P2Mode::ALL.into_iter().chain([P2Mode::Tagged]) {
        assert!(
            circuit.p2.iter().any(|row| row.mode == Some(mode)),
            "a {mode:?} row"
        );
    }
    assert!(
        circuit.h8.iter().any(|row| row.out.multiplicity != 0),
        "an h8 row"
    );
    assert_tied(&finalized);
}

/// A tagged row that absorbs, sets `c_8`, or reads a bit other than the zero
/// wire's is no longer `[c[0, 8), m]`: the static check refuses each, though
/// the relation alone would not see it.
#[test]
fn a_tagged_row_keeps_its_mode() {
    use vos_pvm_recair::circuit::WiringError;
    let finalized = every_row_kind();
    let row = finalized
        .circuit
        .p2
        .iter()
        .position(|wiring| wiring.mode == Some(P2Mode::Tagged))
        .expect("a tagged row");
    finalized.circuit.check_wiring().expect("the honest wiring");
    // The bit is a use of the zero wire, so moving it unbalances the
    // relation too, which the check meets first; the mode check is that
    // refusal's second line, tested on the constants alone.
    let mut moved = finalized.circuit.clone();
    moved.p2[row].bit_address = moved.p2[row].out_address;
    assert!(moved.check_wiring().is_err(), "a bit");
    let tampers: [Tamper; 2] = [
        ("an act", |wiring| wiring.act[0] = BaseField::from(1)),
        ("a c_8", |wiring| wiring.c[8] = BaseField::from(1)),
    ];
    for (name, tamper) in tampers {
        let mut circuit = finalized.circuit.clone();
        tamper(&mut circuit.p2[row]);
        assert_eq!(
            circuit.check_wiring().map(|_| ()),
            Err(WiringError::TaggedRow { row }),
            "{name}"
        );
    }
}

/// A node row's bit held by no `b·b = b` row: the bit's row turned into
/// `b·b·2 = b`, which balances the relation as before, is refused.
#[test]
fn a_node_s_bit_is_an_asserted_bit() {
    use vos_pvm_recair::circuit::WiringError;
    let finalized = every_row_kind();
    let node = finalized
        .circuit
        .p2
        .iter()
        .position(|wiring| wiring.mode == Some(P2Mode::Node))
        .expect("a node row");
    let bit = finalized.circuit.p2[node].bit_address;
    let mut circuit = finalized.circuit.clone();
    let assertion = circuit
        .qm31
        .iter_mut()
        .find(|wiring| {
            wiring.op.k_m == BaseField::from(1)
                && wiring.operands[0].address == bit
                && wiring.operands[3].address == bit
        })
        .expect("the bit's assertion");
    assertion.op.k_m = BaseField::from(2);
    assert_eq!(
        circuit.check_wiring().map(|_| ()),
        Err(WiringError::NodeBit { row: node })
    );
}
