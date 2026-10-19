//! `p2`'s modes and chaining (`recursion-air.md` §1.3): a row's input is
//! its mode's function of its message, its bit, its constants and the row
//! above's output, and nothing else.
//!
//! Each forger recomputes one row's permutation over an input of its choice
//! and balances the wiring, so every use of the row's output, and the
//! circuit's outputs, carry the forged digest: only the row's input
//! constraint is left to refuse it, and the verifier does (Stwo's OODS
//! comparison).
//! - **A mode swapped:** each mode's row computed by every other mode's rule.
//! - **A chain broken:** a leaf's sponge continued from another leaf's row, a
//!   leaf's sponge restarted mid-leaf, an absorption dropped from the
//!   transcript.
//! - **A Merkle step forged:** a node over another child than the row below,
//!   and a node in the order its bit does not pick.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_poseidon2::{M31, N_STATE};
use vos_pvm_recair::gadgets::{TranscriptGadget, leaf_hash, node};
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::{Context, Finalized, Message, P2Mode, Var};

use crate::common::Rng;
use crate::forge::{DEEP_ALI, Forgery, assert_accepted, assert_refused, hash_of};

/// `n` guessed values, four a wire.
fn guesses(context: &mut Context<SecureField>, rng: &mut Rng, n: usize) -> Vec<Var> {
    let values: Vec<BaseField> = (0..n).map(|_| rng.m31()).collect();
    pack(&values)
        .into_iter()
        .map(|wire| context.guess(wire))
        .collect()
}

/// A circuit whose last row of `mode` makes its outputs, the digest's two
/// wires: a leaf of one block or two, a Merkle step over a leaf, a
/// transcript's first absorption, an absorption after one, an absorption's
/// second chunk, a draw.
fn ending_in(mode: P2Mode) -> Finalized<SecureField> {
    let mut rng = Rng::new(31 + mode as u64);
    let mut context = Context::<SecureField>::with_outputs(2);
    let mut transcript = TranscriptGadget::new(&context);
    let digest = match mode {
        P2Mode::LeafStart => {
            let wires = guesses(&mut context, &mut rng, 4);
            leaf_hash(&mut context, &wires, 4).digest
        }
        P2Mode::LeafContinue => {
            let wires = guesses(&mut context, &mut rng, 12);
            leaf_hash(&mut context, &wires, 12).digest
        }
        P2Mode::Node => {
            let wires = guesses(&mut context, &mut rng, 5);
            let leaf = leaf_hash(&mut context, &wires, 5);
            let sibling = guesses(&mut context, &mut rng, 8);
            let bit = context.guess(SecureField::one());
            let bit = context.assert_bit(bit);
            let sibling = [Message::Wire(sibling[0]), Message::Wire(sibling[1])];
            node(&mut context, &leaf, sibling, bit, None).digest
        }
        P2Mode::ChannelStart => {
            let wires = guesses(&mut context, &mut rng, 4);
            transcript.absorb(&mut context, &wires, 4);
            transcript.digest()
        }
        P2Mode::ChannelFirst => {
            for _ in 0..2 {
                let wires = guesses(&mut context, &mut rng, 4);
                transcript.absorb(&mut context, &wires, 4);
            }
            transcript.digest()
        }
        P2Mode::ChannelContinue => {
            let wires = guesses(&mut context, &mut rng, 12);
            transcript.absorb(&mut context, &wires, 12);
            transcript.digest()
        }
        P2Mode::Wired => {
            let wires = guesses(&mut context, &mut rng, 4);
            transcript.absorb(&mut context, &wires, 4);
            transcript.squeeze(&mut context)
        }
    };
    context.set_outputs(&digest);
    context.finalize().expect("the wiring checks")
}

/// The last row of `mode`.
fn last_row(finalized: &Finalized<SecureField>, mode: P2Mode) -> usize {
    finalized
        .circuit
        .p2
        .iter()
        .rposition(|wiring| wiring.mode == Some(mode))
        .expect("a row of the mode")
}

/// The output of the row above `row`: the last row's, above row 0.
fn above(forgery: &Forgery, row: usize) -> [M31; N_STATE] {
    let rows = forgery.circuit.p2.len();
    forgery.p2_output((row + rows - 1) % rows)
}

/// Row `row`'s input under `mode`'s rule (the AIR's input constraint), over
/// the row's own message, bit and constants and `prev`, a row's output.
fn input_by(
    forgery: &Forgery,
    row: usize,
    mode: P2Mode,
    bit: BaseField,
    prev: [M31; N_STATE],
) -> [M31; N_STATE] {
    let wiring = &forgery.circuit.p2[row];
    let (m, _) = forgery.p2_message(row);
    let prev: [BaseField; N_STATE] = prev.map(|word| BaseField::from(word.value()));
    let zero = BaseField::zero();
    let mut input = [zero; N_STATE];
    for j in 0..8 {
        let h = wiring.act[j] * m[j];
        let a = h + wiring.c[j];
        let (low, high) = match mode {
            P2Mode::LeafStart => (a, zero),
            P2Mode::LeafContinue => (prev[j] + a, prev[8 + j]),
            P2Mode::Node => (
                prev[j] + bit * (m[j] - prev[j]),
                m[j] + bit * (prev[j] - m[j]),
            ),
            P2Mode::ChannelStart => (zero, h),
            P2Mode::ChannelFirst => (prev[j], h),
            P2Mode::ChannelContinue => (prev[j], prev[8 + j] + h),
            P2Mode::Wired => (a, if j < 2 { wiring.c[8 + j] } else { zero }),
        };
        input[j] = low;
        input[8 + j] = high;
    }
    input.map(|word| M31::new(word.0))
}

/// The forgery of row `row`'s input as `input`, its output carried by the
/// wiring to the circuit's outputs: refused by the verifier's OODS check.
fn assert_input_refused(
    finalized: &Finalized<SecureField>,
    row: usize,
    input: [M31; N_STATE],
    what: &str,
) {
    let mut forgery = Forgery::honest(finalized);
    assert_ne!(
        forgery.p2_input(row),
        input,
        "{what}: an input other than the honest one"
    );
    forgery.rewrite_input(row, input);
    forgery.settle();
    assert_ne!(
        forgery.outputs, finalized.witness.outputs,
        "{what}: the forged digest is stated"
    );
    assert_refused(
        forgery.prove(),
        &hash_of(&finalized.circuit),
        DEEP_ALI,
        what,
    );
}

/// The malicious prover proves an honest trace, and each row's honest input
/// is its mode's rule: the forger's model is the AIR's.
#[test]
fn the_forger_proves_an_honest_trace() {
    for mode in P2Mode::ALL {
        let finalized = ending_in(mode);
        let forgery = Forgery::honest(&finalized);
        for (row, wiring) in finalized.circuit.p2.iter().enumerate() {
            let Some(row_mode) = wiring.mode else {
                continue;
            };
            let (_, bit) = forgery.p2_message(row);
            assert_eq!(
                input_by(&forgery, row, row_mode, bit, above(&forgery, row)),
                forgery.p2_input(row),
                "{mode:?}: row {row}"
            );
        }
        assert_accepted(
            forgery.prove(),
            &hash_of(&finalized.circuit),
            &format!("{mode:?}"),
        );
    }
}

/// Each mode's row computed by every other mode's rule, wherever the rules
/// differ on it, is refused.
#[test]
fn a_row_computed_by_another_mode_is_refused() {
    let mut forged = 0;
    for mode in P2Mode::ALL {
        let finalized = ending_in(mode);
        let forgery = Forgery::honest(&finalized);
        let row = last_row(&finalized, mode);
        let (_, bit) = forgery.p2_message(row);
        let prev = above(&forgery, row);
        for other in P2Mode::ALL.into_iter().filter(|&other| other != mode) {
            let input = input_by(&forgery, row, other, bit, prev);
            if input == forgery.p2_input(row) {
                continue;
            }
            assert_input_refused(&finalized, row, input, &format!("{mode:?} as {other:?}"));
            forged += 1;
        }
    }
    eprintln!("{forged} rows computed by another mode's rule");
    assert!(forged >= 40, "{forged} swaps forged");
}

/// A chain broken: a leaf's second block continued from another leaf's
/// first row, the same block restarted as a leaf's first, and an
/// absorption chained from the digest before the absorption above it.
#[test]
fn a_sponge_chained_across_rows_wrongly_is_refused() {
    // Two leaves of two blocks; the second's digest is the output.
    let mut rng = Rng::new(41);
    let mut context = Context::<SecureField>::with_outputs(2);
    let first = guesses(&mut context, &mut rng, 12);
    leaf_hash(&mut context, &first, 12);
    let second = guesses(&mut context, &mut rng, 12);
    let digest = leaf_hash(&mut context, &second, 12).digest;
    context.set_outputs(&digest);
    let finalized = context.finalize().expect("the wiring checks");
    let rows: Vec<usize> = finalized
        .circuit
        .p2
        .iter()
        .enumerate()
        .filter(|(_, wiring)| wiring.mode.is_some())
        .map(|(row, _)| row)
        .collect();
    assert_eq!(rows, [0, 1, 2, 3], "two chains of two rows");
    let forgery = Forgery::honest(&finalized);
    let (_, bit) = forgery.p2_message(3);
    let spliced = input_by(&forgery, 3, P2Mode::LeafContinue, bit, forgery.p2_output(0));
    assert_input_refused(
        &finalized,
        3,
        spliced,
        "a block continued from another leaf",
    );
    let restarted = input_by(&forgery, 3, P2Mode::LeafStart, bit, forgery.p2_output(2));
    assert_input_refused(&finalized, 3, restarted, "a leaf restarted mid-way");

    // Two absorptions: the second chained from the zero digest, as if the
    // first were never absorbed.
    let finalized = ending_in(P2Mode::ChannelFirst);
    let forgery = Forgery::honest(&finalized);
    let row = last_row(&finalized, P2Mode::ChannelFirst);
    let dropped = input_by(
        &forgery,
        row,
        P2Mode::ChannelFirst,
        BaseField::zero(),
        [M31::ZERO; N_STATE],
    );
    assert_input_refused(&finalized, row, dropped, "an absorption dropped");
}

/// A Merkle step over another child than the row below (a path over a leaf
/// it does not open), and a step in the order its bit does not pick.
#[test]
fn a_merkle_step_over_another_child_or_order_is_refused() {
    // Two leaves, a node over the first; the node's digest is the output.
    let mut rng = Rng::new(43);
    let mut context = Context::<SecureField>::with_outputs(2);
    let wires = guesses(&mut context, &mut rng, 5);
    let leaf = leaf_hash(&mut context, &wires, 5);
    let other = guesses(&mut context, &mut rng, 5);
    leaf_hash(&mut context, &other, 5);
    let sibling = guesses(&mut context, &mut rng, 8);
    let bit = context.guess(SecureField::zero());
    let bit = context.assert_bit(bit);
    let sibling = [Message::Wire(sibling[0]), Message::Wire(sibling[1])];
    let digest = node(&mut context, &leaf, sibling, bit, None).digest;
    context.set_outputs(&digest);
    let finalized = context.finalize().expect("the wiring checks");
    let forgery = Forgery::honest(&finalized);
    let row = last_row(&finalized, P2Mode::Node);
    let other_row = finalized
        .circuit
        .p2
        .iter()
        .enumerate()
        .filter(|(at, wiring)| *at != row - 1 && wiring.mode == Some(P2Mode::LeafStart))
        .map(|(at, _)| at)
        .next()
        .expect("the other leaf's row");
    let (_, bit) = forgery.p2_message(row);
    assert_eq!(bit, BaseField::zero());
    let over_other = input_by(
        &forgery,
        row,
        P2Mode::Node,
        bit,
        forgery.p2_output(other_row),
    );
    assert_input_refused(&finalized, row, over_other, "a node over another child");
    let swapped = input_by(
        &forgery,
        row,
        P2Mode::Node,
        BaseField::one(),
        above(&forgery, row),
    );
    assert_input_refused(&finalized, row, swapped, "a node in the swapped order");
}
