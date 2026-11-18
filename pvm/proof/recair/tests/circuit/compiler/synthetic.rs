//! A synthetic component: what the chips do not exercise.

use super::*;

stwo_constraint_framework::relation!(Synthetic, 3);

/// One relation of three limbs, a next-row mask, a preprocessed column, an
/// intermediate, an inverse of a trace expression, and three fractions
/// finalized in pairs or one a column. Stwo's `InfoEvaluator` cannot invert
/// (its counter's `inverse` is unimplemented), so what the component reads
/// is taken from its twin without the inverse: the same reads.
struct SyntheticEval {
    relation: Synthetic,
    paired: bool,
    inverse: bool,
}

impl FrameworkEval for SyntheticEval {
    fn log_size(&self) -> u32 {
        5
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        7
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let selector = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "synthetic_selector".into(),
        });
        let [x, x_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
        let y = eval.next_trace_mask();
        let z = eval.next_trace_mask();
        let w = eval.add_intermediate(x.clone() * y.clone() + selector.clone());
        let shifted = y.clone() + E::F::from(BaseField::from(7));
        let shifted = if self.inverse {
            shifted.inverse()
        } else {
            shifted
        };
        eval.add_constraint(z.clone() * shifted - x_next.clone());
        eval.add_constraint(E::EF::from(w.clone() - x.clone()) * E::EF::from(selector.clone()));
        eval.add_to_relation(RelationEntry::new(
            &self.relation,
            E::EF::one(),
            &[x.clone(), y.clone()],
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.relation,
            -E::EF::from(selector),
            &[z.clone(), w, x_next],
        ));
        eval.add_to_relation(RelationEntry::new(&self.relation, E::EF::one(), &[y]));
        if self.paired {
            eval.finalize_logup_in_pairs();
        } else {
            eval.finalize_logup();
        }
        eval
    }
}

#[test]
fn a_synthetic_component_compiles_paired_or_not() {
    let mut channel = Poseidon2M31Channel::default();
    channel.mix_u64(15);
    let relation = Synthetic::draw(&mut channel);
    let challenges = vec![RelationChallenges::of(&relation)];
    let mut rng = Rng::new(16);
    for paired in [true, false] {
        let component = SyntheticEval {
            relation: relation.clone(),
            paired,
            inverse: true,
        };
        let twin = SyntheticEval {
            relation: relation.clone(),
            paired,
            inverse: false,
        };
        let recording = Recording::new(
            "synthetic",
            component.log_size(),
            twin.evaluate(InfoEvaluator::empty()),
            component.evaluate(ExprEvaluator::new()),
        );
        assert!(
            recording.offsets[0][0] == [0, 1],
            "a next-row mask on the first column"
        );
        let compiled = compile::compile(
            std::slice::from_ref(&recording),
            &compile::relations_of(&challenges),
        );
        assert!(
            compiled
                .rows
                .iter()
                .any(|row| matches!(row, Row::Inverse(_))),
            "the inverse of a trace expression is a row"
        );
        assert_eq!(compiled.power_rows, 1, "α² from α");
        for m31 in [true, false] {
            let point = random_point(&recording, &mut rng, m31);
            let coeff = rng.qm31();
            let inputs = input_values(&compiled, std::slice::from_ref(&point), &challenges);
            let expected = if m31 {
                recorded_m31(&recording, &point, &challenges)
            } else {
                recorded(&recording, &point, &challenges)
            };
            assert_eq!(compiled.evaluate(&inputs)[0], expected);
            assert_eq!(emitted(&compiled, &inputs)[0], expected);
            assert_eq!(
                compose_values(None, coeff, &expected).unwrap(),
                native(&recording, &point, coeff, &|eval| component.evaluate(eval))
            );
        }
        let constant = compiled.components[0]
            .constraints
            .iter()
            .any(|operand| matches!(operand, Operand::Constant(_)));
        assert!(!constant, "no constraint folds to a constant");
    }
}
