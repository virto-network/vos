//! `p2` against `vos_pvm_poseidon2` in every mode, and a tamper refused per
//! component and per mode.

mod common;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_poseidon2::{
    LeafSponge, M31, N_STATE, Observer, PermKind, Transcript, compress, u64_limbs,
};
use vos_recair::gadgets::{TranscriptGadget, leaf_hash, node};
use vos_recair::trace::MainTrace;
use vos_recair::{Context, Finalized, Message, P2Mode, circuit_commitment, prove, verify};
use vos_recair_air::{p2, qm31};

use common::{Rng, digest_wires, pack, words};

/// The digest wires' values of a handle.
fn digest_of(context: &Context<SecureField>, digest: [vos_recair::Var; 2]) -> [SecureField; 2] {
    digest.map(|var| context.value(var))
}

/// Records the last permutation's output.
#[derive(Default)]
struct Last([M31; N_STATE]);

impl Observer for Last {
    fn permuted(&mut self, _: PermKind, _: bool, _: &[M31; N_STATE], output: &[M31; N_STATE]) {
        self.0 = *output;
    }
}

/// A circuit with rows of every mode, each checked against the reference
/// as it is built: leaves of 0 to 21 values (leaf start and continue), Merkle
/// nodes with either bit and a path into a guessed root, and a transcript's
/// absorptions (channel start, first and continue), draws and PoW (wired).
fn modes_circuit() -> Finalized<SecureField> {
    let mut rng = Rng::new(7);
    let mut context = Context::<SecureField>::new();

    let mut leaves = Vec::new();
    for n in [0, 1, 4, 7, 8, 9, 15, 16, 17, 21] {
        let values: Vec<BaseField> = (0..n).map(|_| rng.m31()).collect();
        let wires: Vec<_> = pack(&values)
            .into_iter()
            .map(|wire| context.guess(wire))
            .collect();
        let leaf = leaf_hash(&mut context, &wires, n);
        // The leaf yields its wires; another gate reads the last.
        if let Some(&last) = wires.last() {
            context.add(last, last);
        }
        let mut sponge = LeafSponge::default();
        sponge.absorb(words(&values));
        let expected = sponge.finalize();
        assert_eq!(
            digest_of(&context, leaf.digest),
            digest_wires(&expected),
            "{n} values"
        );
        leaves.push((leaf, expected));
    }

    // A path of three nodes, the bits 0, 1, 0, its root guessed: the last
    // node's output uses the root's wires.
    let (leaf, mut expected) = leaves.pop().unwrap();
    let mut child = leaf;
    let mut root = None;
    for (level, bit) in [0u32, 1, 0].into_iter().enumerate() {
        let sibling: vos_pvm_poseidon2::Digest = core::array::from_fn(|_| M31::new(rng.m31().0));
        expected = if bit == 0 {
            compress(&expected, &sibling)
        } else {
            compress(&sibling, &expected)
        };
        let bit_var = context.guess(SecureField::from(BaseField::from(bit)));
        let bit_var = context.assert_bit(bit_var);
        let out = (level == 2).then(|| {
            let wires = digest_wires(&expected);
            let pair = context.guess_pair(wires);
            root = Some(pair);
            pair
        });
        let message = digest_wires(&sibling).map(Message::Free);
        child = node(&mut context, &child, message, bit_var, out);
        assert_eq!(
            digest_of(&context, child.digest),
            digest_wires(&expected),
            "level {level}"
        );
    }
    // The root is read elsewhere too.
    let root = root.unwrap();
    context.add(root[0], root[1]);

    // The transcript, against the reference's.
    let mut reference = Transcript::default();
    let mut transcript = TranscriptGadget::new(&context);
    let draws = |transcript: &mut TranscriptGadget<SecureField>,
                 reference: &mut Transcript,
                 context: &mut Context<SecureField>| {
        let draw = transcript.squeeze(context);
        assert_eq!(
            digest_of(context, draw),
            digest_wires(&reference.squeeze(&mut ()))
        );
    };
    draws(&mut transcript, &mut reference, &mut context);
    for n in [0usize, 3, 17, 8, 1] {
        let values: Vec<BaseField> = (0..n).map(|_| rng.m31()).collect();
        let wires: Vec<_> = pack(&values)
            .into_iter()
            .map(|wire| context.guess(wire))
            .collect();
        transcript.absorb(&mut context, &wires, n);
        reference.absorb(&words(&values), &mut ());
        assert_eq!(
            digest_of(&context, transcript.digest()),
            digest_wires(reference.digest())
        );
        draws(&mut transcript, &mut reference, &mut context);
        draws(&mut transcript, &mut reference, &mut context);
        let nonce = rng.next_u64();
        let limbs = u64_limbs(nonce).map(|limb| BaseField::from(limb.value()));
        let nonce_wire = context.guess(SecureField::from_m31_array(limbs));
        let check = transcript.pow(&mut context, 7, nonce_wire);
        let mut last = Last::default();
        reference.verify_pow_nonce(7, nonce, &mut last);
        let state: Vec<SecureField> = pack(&last.0.map(|word| BaseField::from(word.value())));
        assert_eq!(check.state.to_vec(), state, "the PoW's second permutation");
    }

    let finalized = context.finalize().expect("the wiring checks");
    let modes: std::collections::HashSet<_> = finalized
        .circuit
        .p2
        .iter()
        .filter_map(|row| row.mode)
        .collect();
    assert_eq!(modes.len(), P2Mode::ALL.len(), "every mode: {modes:?}");
    finalized
}

/// `p2` equals the reference permutation in every mode: each row's output
/// is the reference mode's, and the circuit proves and verifies, so every
/// row satisfies the AIR.
#[test]
fn p2_equals_the_reference_permutation_in_every_mode() {
    let finalized = modes_circuit();
    let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
    let proof = prove(&finalized.circuit, &finalized.witness).expect("proves");
    verify(proof, &hash).expect("verifies");
}

/// Why a proof of `finalized` whose main trace `tamper` changed is refused,
/// by the prover or the verifier; `None` if it is not.
fn refusal(
    finalized: &Finalized<SecureField>,
    tamper: impl FnOnce(&mut MainTrace),
) -> Option<String> {
    let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
    match vos_recair::prove::prove_with(&finalized.circuit, &finalized.witness, tamper) {
        Err(error) => Some(format!("prover: {error:?}")),
        Ok(proof) => verify(proof, &hash).err().map(|error| error.to_string()),
    }
}

/// Whether the tamper is refused because the constraints fail. Stwo's
/// prover samples the composition polynomial and the trace at the OODS point
/// and refuses a mismatch, so a trace that breaks a constraint never becomes
/// a proof: the refusal is the prover's. The verifier's own constraint check
/// is [`an_edited_sample_fails_the_verifiers_constraint_check`]'s.
fn refused(finalized: &Finalized<SecureField>, tamper: impl FnOnce(&mut MainTrace)) -> bool {
    match refusal(finalized, tamper) {
        Some(reason) => {
            assert!(
                reason.contains("prover: Stwo(ConstraintsNotSatisfied)"),
                "{reason}"
            );
            true
        }
        None => false,
    }
}

/// Whether the tamper is refused because the wiring's logup does not
/// balance.
fn unwired(finalized: &Finalized<SecureField>, tamper: impl FnOnce(&mut MainTrace)) -> bool {
    match refusal(finalized, tamper) {
        Some(reason) => {
            assert!(reason.contains("do not add to zero"), "{reason}");
            true
        }
        None => false,
    }
}

/// Row `row`'s permutation columns recomputed from its input after `change`.
fn rewrite_input(trace: &mut MainTrace, row: usize, change: impl FnOnce(&mut [M31; N_STATE])) {
    let columns = &mut trace.columns[0];
    let mut input: [M31; N_STATE] = core::array::from_fn(|j| M31::new(columns[j][row].0));
    change(&mut input);
    let mut permutation = vec![M31::ZERO; p2::main::M];
    p2::permutation_columns(input, &mut permutation);
    for (column, word) in permutation.iter().enumerate() {
        columns[column][row] = BaseField::from(word.value());
    }
}

fn bump(value: &mut BaseField) {
    *value += BaseField::from(1);
}

/// A tamper per component and per mode is refused:
/// - in each mode, an S-box column changed (the round constraints), and the
///   input changed with the permutation recomputed (the mode's input
///   constraint);
/// - a padding row's input made nonzero, its permutation recomputed;
/// - a message limb no lane reads, whose wire other gates read (the wiring);
/// - a `qm31` row's operand and output moved together, so the gate holds
///   (the wiring), and an output alone (the gate);
/// - an `h8` row's accumulator and output moved together (the wiring), and a
///   sample alone (the Horner steps).
#[test]
fn a_tamper_per_component_and_mode_is_refused() {
    let finalized = modes_circuit();
    let circuit = &finalized.circuit;
    assert!(!refused(&finalized, |_| {}), "the honest trace proves");

    for mode in P2Mode::ALL {
        let row = circuit
            .p2
            .iter()
            .position(|wiring| wiring.mode == Some(mode))
            .unwrap();
        assert!(
            refused(&finalized, |trace| bump(
                &mut trace.columns[0][p2::main::SBOXES + 20][row]
            )),
            "{mode:?}: an S-box"
        );
        assert!(
            refused(&finalized, |trace| rewrite_input(trace, row, |input| {
                input[3] += M31::ONE
            })),
            "{mode:?}: the low input"
        );
        assert!(
            refused(&finalized, |trace| rewrite_input(trace, row, |input| {
                input[12] += M31::ONE
            })),
            "{mode:?}: the high input"
        );
    }
    let padding = circuit
        .p2
        .iter()
        .position(|wiring| wiring.mode.is_none())
        .unwrap();
    assert!(
        refused(&finalized, |trace| rewrite_input(trace, padding, |input| {
            input[0] += M31::ONE
        })),
        "a padding row's input"
    );

    // A message lane no `act` reads, on a wire with a multiplicity.
    let (row, lane) = circuit
        .p2
        .iter()
        .enumerate()
        .find_map(|(row, wiring)| {
            (0..8)
                .find(|&j| wiring.act[j] == BaseField::from(0) && wiring.m[j / 4].multiplicity != 0)
                .filter(|_| wiring.mode != Some(P2Mode::Node))
                .map(|j| (row, j))
        })
        .expect("a partial block of a wire");
    assert!(
        unwired(&finalized, |trace| bump(
            &mut trace.columns[0][p2::main::M + lane][row]
        )),
        "an unread message lane"
    );
    // qm31: an addition's operand and output moved together.
    let row = circuit
        .qm31
        .iter()
        .position(|wiring| {
            wiring.op.k_a == BaseField::from(1)
                && wiring.op.k_b == BaseField::from(1)
                && wiring.op.k_m == BaseField::from(0)
                && wiring.op.k_c == BaseField::from(0)
                && wiring.operands[0].multiplicity != 0
                && wiring.operands[0].address != wiring.operands[1].address
                && wiring.operands[0].address != wiring.operands[3].address
        })
        .expect("an addition");
    assert!(
        unwired(&finalized, |trace| {
            bump(&mut trace.columns[1][0][row]);
            bump(&mut trace.columns[1][12][row]);
        }),
        "qm31: an operand and its output"
    );
    assert!(
        refused(&finalized, |trace| bump(&mut trace.columns[1][13][row])),
        "qm31: an output"
    );
}

/// The `h8` tampers, on a circuit of accumulator rows.
#[test]
fn an_h8_tamper_is_refused() {
    let mut rng = Rng::new(11);
    let mut context = Context::<SecureField>::new();
    let wires: Vec<_> = (0..6).map(|_| context.guess(rng.qm31())).collect();
    let mut acc = wires[0];
    for i in 0..5 {
        acc = context.h8(
            acc,
            wires[1],
            wires[2],
            [wires[3 + i % 3], wires[3 + (i + 1) % 3]],
        );
    }
    let sink = context.add(acc, wires[1]);
    context.add(sink, sink);
    let finalized = context.finalize().unwrap();
    assert!(!refused(&finalized, |_| {}), "the honest trace proves");
    use vos_recair_air::h8::main;
    // Row 1: its accumulator is row 0's output, a wire; moving it and the
    // output by `μ` times as much keeps the row's constraints.
    let row = 1;
    let mu = SecureField::from_m31_array(core::array::from_fn(|j| {
        finalized_column(&finalized, main::MU + j, row)
    }));
    assert!(
        unwired(&finalized, |trace| {
            let columns = &mut trace.columns[2];
            let delta = SecureField::from_u32_unchecked(1, 0, 0, 0);
            let shift = (delta * mu).to_m31_array();
            columns[main::ACC][row] += BaseField::from(1);
            for j in 0..4 {
                columns[main::OUT + j][row] += shift[j];
            }
        }),
        "h8: the accumulator and the output"
    );
    assert!(
        refused(&finalized, |trace| bump(
            &mut trace.columns[2][main::V + 5][row]
        )),
        "h8: a sample"
    );
}

fn finalized_column(finalized: &Finalized<SecureField>, column: usize, row: usize) -> BaseField {
    vos_recair::trace::main_trace(&finalized.circuit, &finalized.witness).columns[2][column][row]
}

type Tamper = Box<dyn Fn(&mut vos_recair::RecairProof)>;

/// A small circuit over every component, its hash, and an honest proof.
fn honest_proof() -> (vos_pvm_poseidon2::Digest, vos_recair::RecairProof) {
    let mut context = Context::<SecureField>::with_outputs(1);
    let a = context.guess(SecureField::from_u32_unchecked(5, 6, 7, 8));
    let b = context.mul(a, a);
    let leaf = leaf_hash(&mut context, &[a, b], 8);
    let c = context.add(leaf.digest[0], b);
    let d = context.h8(c, a, b, [a, b]);
    let e = context.add(d, c);
    context.set_outputs(&[e]);
    let finalized = context.finalize().unwrap();
    let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
    let proof = prove(&finalized.circuit, &finalized.witness).unwrap();
    verify(proof.clone(), &hash).unwrap();
    (hash, proof)
}

/// Stwo's refusal when the constraints, evaluated at the OODS point over the
/// sampled values, do not match the composition polynomial's sample.
const OODS_MISMATCH: &str = "OODS value does not match the trace OODS values";

/// The first refusal of `edit(proof, k)`, for `k` from 1, that passes the
/// query-count preflight. An edited sample or claimed sum moves the
/// transcript, so the queries are redrawn; when their deduplicated count
/// differs from the proof's rows the preflight refuses first, and when it is
/// the same the edit reaches Stwo's own checks.
fn past_the_query_count(
    hash: &vos_pvm_poseidon2::Digest,
    proof: &vos_recair::RecairProof,
    edit: impl Fn(&mut vos_recair::RecairProof, SecureField),
) -> String {
    for k in 1..=256 {
        let mut tampered = proof.clone();
        edit(&mut tampered, SecureField::from_u32_unchecked(k, 0, 0, 0));
        let refusal = verify(tampered, hash)
            .expect_err("an edited proof")
            .to_string();
        if !refusal.contains("queried-value rows differ") {
            return refusal;
        }
    }
    panic!("no edit kept the query count");
}

/// Tampers with a finished proof are refused, each for its reason: a
/// claimed sum, an output, the interaction PoW, a queried value, the log
/// sizes, the format, and claimed sums moved between components.
#[test]
fn a_tampered_proof_is_refused() {
    let (hash, proof) = honest_proof();
    let one = SecureField::from_u32_unchecked(1, 0, 0, 0);
    let tampers: Vec<(&str, Tamper, &str)> = vec![
        (
            "a claimed sum",
            Box::new(move |proof| proof.claimed_sums[1] += one),
            "do not add to zero",
        ),
        // The outputs are mixed before the interaction PoW is ground: an
        // output changed moves the transcript under the nonce.
        (
            "an output",
            Box::new(move |proof| proof.outputs[0] += one),
            "interaction PoW nonce",
        ),
        (
            "the interaction PoW",
            Box::new(|proof| proof.interaction_pow ^= 1),
            "interaction PoW nonce",
        ),
        (
            "a queried value",
            Box::new(|proof| {
                proof.stark_proof.0.queried_values[1][0][0] += BaseField::from(1);
            }),
            "Root mismatch",
        ),
        (
            "the log sizes",
            Box::new(|proof| proof.log_sizes[2] += 1),
            "another circuit",
        ),
        (
            "the format",
            Box::new(|proof| proof.format_version = 35),
            "not the recursion AIR's",
        ),
    ];
    for (what, tamper, reason) in &tampers {
        let mut tampered = proof.clone();
        tamper(&mut tampered);
        let refusal = verify(tampered, &hash).expect_err(what).to_string();
        assert!(refusal.contains(reason), "{what}: {refusal}");
    }

    // Claimed sums moved between components keep their total: the
    // components' constraints refuse them.
    let refusal = past_the_query_count(&hash, &proof, |proof, k| {
        proof.claimed_sums[0] += k;
        proof.claimed_sums[2] -= k;
    });
    assert!(
        refusal.contains(OODS_MISMATCH),
        "claimed sums moved: {refusal}"
    );
}

/// The verifier's own constraint check: an honest proof whose sampled value
/// of one column is then edited, in each component's main and interaction
/// trees, is refused because the constraints, evaluated at the OODS point
/// over the sampled values, no longer match the composition polynomial's
/// sample. The prover's sanity check refuses a dishonest trace before a
/// proof exists, so only an edited proof reaches this check, and only an
/// edit past the query-count preflight ([`past_the_query_count`]).
#[test]
fn an_edited_sample_fails_the_verifiers_constraint_check() {
    let (hash, proof) = honest_proof();
    let main = [0, p2::N_MAIN, p2::N_MAIN + qm31::N_MAIN];
    let interaction = [
        0,
        p2::N_INTERACTION,
        p2::N_INTERACTION + qm31::N_INTERACTION,
    ];
    for (component, (main, interaction)) in ["p2", "qm31", "h8"]
        .iter()
        .zip(main.into_iter().zip(interaction))
    {
        for (tree, column) in [(1, main), (2, interaction)] {
            let refusal = past_the_query_count(&hash, &proof, |proof, k| {
                proof.stark_proof.0.sampled_values[tree][column][0] += k;
            });
            assert!(
                refusal.contains(OODS_MISMATCH),
                "{component}, tree {tree}, column {column}: {refusal}"
            );
        }
    }
}
