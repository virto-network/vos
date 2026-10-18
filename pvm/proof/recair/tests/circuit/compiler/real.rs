//! The compiled composition on a real segment proof.

use super::*;

/// A segment proof's OODS data, as the in-AIR verifier receives it.
struct Real {
    recordings: Vec<Recording>,
    compiled: Compiled,
    points: Vec<Point>,
    relations: Vec<RelationChallenges>,
    oods: vos_pvm_proof::OodsReconstruction,
}

fn real(proof: &Proof) -> Real {
    let oods = reconstruct_oods_for_recursion(proof);
    let relations = oods.lookup_elements.relation_challenges();
    let recordings: Vec<Recording> = oods
        .comps
        .iter()
        .map(|&(chip, log_size, _)| Recording::chip(chip, log_size, &oods.lookup_elements))
        .collect();
    let compiled = compile::compile(&recordings, &compile::relations_of(&relations));
    let points = oods
        .comps
        .iter()
        .zip(&oods.component_masks)
        .map(|(&(_, _, claimed_sum), mask)| Point {
            samples: [mask.mask[1].clone(), mask.mask[2].clone()],
            preprocessed: mask
                .preproc_indices
                .iter()
                .map(|&index| mask.mask[0][index][0])
                .collect(),
            claimed_sum,
        })
        .collect();
    Real {
        recordings,
        compiled,
        points,
        relations,
        oods,
    }
}

/// Tests 2 and 3 on a real proof: the compiled composition is the proof's,
/// in values and in a `Context`; each chip's combination is the
/// verifier's; the claimed sums add to zero; every sample a chip reads moves
/// its combination, and one sample a chip, tampered, fails the composition
/// check.
fn check_real(proof: &Proof) {
    let real = real(proof);
    let Real {
        recordings,
        compiled,
        points,
        relations,
        oods,
    } = &real;
    let inputs = input_values(compiled, points, relations);
    let values = compiled.evaluate(&inputs);
    let composition = |values: &[Vec<SecureField>]| {
        Compiled::composition_value(values, oods.random_coeff, oods.denom_inverse)
    };
    assert_eq!(composition(&values), oods.composition_value);
    assert_eq!(emitted(compiled, &inputs), values);
    assert_eq!(
        points
            .iter()
            .map(|point| point.claimed_sum)
            .sum::<SecureField>(),
        SecureField::zero()
    );

    for (c, (recording, point)) in recordings.iter().zip(points).enumerate() {
        let (chip, ..) = oods.comps[c];
        let drive = drive_at(chip, recording.log_size, &oods.lookup_elements);
        let alone = compile::compile(
            std::slice::from_ref(recording),
            &compile::relations_of(relations),
        );
        let alone_inputs = input_values(&alone, std::slice::from_ref(point), relations);
        let honest = compose_values(None, oods.random_coeff, &alone.evaluate(&alone_inputs)[0]);
        assert_eq!(
            honest.unwrap(),
            native(recording, point, oods.random_coeff, &drive),
            "{}: compiled ≠ the verifier's on the proof",
            recording.name
        );
        assert_eq!(alone.evaluate(&alone_inputs)[0], values[c]);

        // Every sample, preprocessed sample and the claimed sum, tampered,
        // one at a time: the compiled combination is still the verifier's
        // (checked natively on up to 64 of them), so it moves where the
        // verifier's does. A sample read only under selectors that are zero
        // on the whole trace moves neither.
        let rows = alone.evaluate_rows(&alone_inputs);
        let mut rng = Rng::new(c as u64);
        let n = alone.inputs.len();
        let natively: Vec<usize> = if n <= 64 {
            (0..n).collect()
        } else {
            (0..64).map(|_| rng.below(n)).collect()
        };
        let (mut moved, mut inert) = (0, 0);
        for (i, input) in alone.inputs.iter().enumerate() {
            if matches!(input, compile::Input::Z(_) | compile::Input::Alpha(_)) {
                continue;
            }
            let mut tampered = alone_inputs.clone();
            tampered[i] += SecureField::one();
            let compiled = compose_values(
                None,
                oods.random_coeff,
                &retampered(&alone, &tampered, &rows, i)[0],
            )
            .unwrap();
            if Some(compiled) == honest {
                inert += 1;
            } else {
                moved += 1;
            }
            if !natively.contains(&i) {
                continue;
            }
            let mut tampered_point = point.clone();
            match *input {
                compile::Input::Sample {
                    tree,
                    column,
                    offset,
                    ..
                } => {
                    let k = recording.offsets[tree][column]
                        .iter()
                        .position(|&o| o == offset)
                        .unwrap();
                    tampered_point.samples[tree][column][k] += SecureField::one();
                }
                compile::Input::Preprocessed(index) => {
                    for (k, &read) in alone.components[0].preprocessed.iter().enumerate() {
                        if read == index {
                            tampered_point.preprocessed[k] += SecureField::one();
                        }
                    }
                }
                compile::Input::ClaimedSum(_) => tampered_point.claimed_sum += SecureField::one(),
                compile::Input::Z(_) | compile::Input::Alpha(_) => unreachable!(),
            }
            assert_eq!(
                compiled,
                native(recording, &tampered_point, oods.random_coeff, &drive),
                "{}: {input:?} tampered, compiled ≠ the verifier's",
                recording.name
            );
        }
        eprintln!(
            "{}: of its {} sampled inputs tampered, {moved} move the combination, {inert} \
             are read only under selectors zero on this trace",
            recording.name,
            moved + inert
        );

        // The chip's last interaction sample, its logup's running sum,
        // tampered in the shape's circuit.
        let sample = compiled
            .inputs
            .iter()
            .rposition(
                |input| matches!(input, compile::Input::Sample { chip, tree: 1, .. } if *chip == c),
            )
            .expect("the chip's logup reads its running sum");
        let mut tampered = inputs.clone();
        tampered[sample] += SecureField::one();
        assert_ne!(
            composition(&emitted(compiled, &tampered)),
            oods.composition_value,
            "{}: a tampered sample passes the composition check",
            recording.name
        );
    }
}

#[test]
fn the_fixtures_composition_is_compiled() {
    check_real(&common::segment_fixture());
}

/// A run proved over all 25 chips, the ones it does not use padded.
#[test]
fn a_full_shape_proofs_composition_is_compiled() {
    check_real(common::full_shape_proof());
}
