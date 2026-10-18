//! The recursion AIR's gates: the degree audit, a three-component multi-fraction
//! logup at three log sizes, and a 10k-gate circuit.

mod common;

use std::collections::HashMap;
use std::time::Instant;

use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::FrameworkEval;
use stwo_constraint_framework::expr::{BaseExpr, ExprEvaluator, ExtExpr};
use vos_pvm_recair::{circuit_commitment, prove, verify};
use vos_pvm_recair_air::gate::GateRelation;
use vos_pvm_recair_air::h8::H8Eval;
use vos_pvm_recair_air::p2::P2Eval;
use vos_pvm_recair_air::qm31::Qm31Eval;

use common::random_circuit;

/// Degrees over the recording evaluator's expressions, each intermediate's
/// computed once: constraint-framework's `degree_bound` recomputes an
/// intermediate at every reference, which the Poseidon2 body's nested
/// rounds make exponential. A preprocessed column is a column, of degree 1;
/// the relation's challenges and the logup's shift are constants.
struct Degrees<'a> {
    recorded: &'a ExprEvaluator,
    preprocessed: &'a [&'a str],
    memo: HashMap<String, usize>,
}

impl Degrees<'_> {
    fn param(&mut self, name: &str) -> usize {
        if let Some(&degree) = self.memo.get(name) {
            return degree;
        }
        let degree = if let Some(expr) = self.recorded.intermediates.get(name) {
            self.base(expr)
        } else if let Some(expr) = self.recorded.ext_intermediates.get(name) {
            self.ext(expr)
        } else {
            usize::from(self.preprocessed.contains(&name))
        };
        self.memo.insert(name.to_string(), degree);
        degree
    }

    fn base(&mut self, expr: &BaseExpr) -> usize {
        match expr {
            BaseExpr::Col(_) => 1,
            BaseExpr::Const(_) => 0,
            BaseExpr::Param(name) => self.param(name),
            BaseExpr::Add(a, b) | BaseExpr::Sub(a, b) => self.base(a).max(self.base(b)),
            BaseExpr::Mul(a, b) => self.base(a) + self.base(b),
            BaseExpr::Neg(a) => self.base(a),
            BaseExpr::Inv(a) => {
                assert_eq!(self.base(a), 0, "only constants are inverted");
                0
            }
        }
    }

    fn ext(&mut self, expr: &ExtExpr) -> usize {
        match expr {
            ExtExpr::SecureCol(limbs) => limbs.iter().map(|limb| self.base(limb)).max().unwrap(),
            ExtExpr::Const(_) => 0,
            ExtExpr::Param(name) => self.param(name),
            ExtExpr::Add(a, b) | ExtExpr::Sub(a, b) => self.ext(a).max(self.ext(b)),
            ExtExpr::Mul(a, b) => self.ext(a) + self.ext(b),
            ExtExpr::Neg(a) => self.ext(a),
        }
    }
}

/// Each constraint's degree, the preprocessed columns at degree 1 (or 0, to
/// compare with constraint-framework's own count).
fn degrees(recorded: &ExprEvaluator, preprocessed: &[&str]) -> Vec<usize> {
    let mut degrees = Degrees {
        recorded,
        preprocessed,
        memo: HashMap::new(),
    };
    recorded
        .constraints
        .iter()
        .map(|constraint| degrees.ext(constraint))
        .collect()
}

/// Every constraint of the three components is of degree at most 3, each
/// component's highest exactly 3, and the counts are the design's.
#[test]
fn the_degree_audit_passes() {
    let relation = GateRelation::dummy();
    let recorded = [
        (
            "p2",
            P2Eval {
                log_size: 4,
                relation: relation.clone(),
            }
            .evaluate(ExprEvaluator::new()),
            &vos_pvm_recair_air::p2::PREPROCESSED[..],
            vos_pvm_recair_air::p2::N_CONSTRAINTS,
        ),
        (
            "qm31",
            Qm31Eval {
                log_size: 4,
                relation: relation.clone(),
            }
            .evaluate(ExprEvaluator::new()),
            &vos_pvm_recair_air::qm31::PREPROCESSED[..],
            vos_pvm_recair_air::qm31::N_CONSTRAINTS,
        ),
        (
            "h8",
            H8Eval {
                log_size: 4,
                relation,
            }
            .evaluate(ExprEvaluator::new()),
            &vos_pvm_recair_air::h8::PREPROCESSED[..],
            vos_pvm_recair_air::h8::N_CONSTRAINTS,
        ),
    ];
    for (name, recorded, preprocessed, n_constraints) in &recorded {
        let counted = degrees(recorded, preprocessed);
        assert_eq!(counted.len(), *n_constraints, "{name}");
        assert_eq!(counted.iter().max(), Some(&3), "{name}: {counted:?}");
        eprintln!(
            "{name}: {} constraints, degrees {:?}",
            counted.len(),
            (0..=3)
                .map(|d| counted.iter().filter(|&&c| c == d).count())
                .collect::<Vec<_>>()
        );
        // With the preprocessed columns as constants, as constraint-framework's
        // own tool counts them, the two counts agree where its tool runs
        // (no nested intermediates).
        if recorded.intermediates.is_empty() && recorded.ext_intermediates.is_empty() {
            assert_eq!(
                degrees(recorded, &[]),
                recorded.constraint_degree_bounds(),
                "{name}"
            );
        }
    }
}

/// The three components, each finalizing several fractions in pairs, prove
/// together at three assignments of three distinct log sizes, and larger.
#[test]
fn a_three_component_multi_fraction_logup_proves_at_three_log_sizes() {
    let built = small_circuit();
    let rows = built.rows();
    assert!(
        rows.iter().all(|&rows| (8..=32).contains(&rows)),
        "{rows:?}"
    );
    for log_sizes in [[5, 6, 7], [7, 5, 6], [6, 7, 5], [10, 12, 14]] {
        let finalized = built
            .clone()
            .finalize_to(Some(log_sizes.map(|log_size| 1usize << log_size)))
            .expect("the wiring checks");
        assert_eq!(finalized.circuit.log_sizes(), log_sizes);
        let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
        let proof = prove(&finalized.circuit, &finalized.witness).expect("proves");
        assert!(
            proof
                .claimed_sums
                .iter()
                .all(|sum| *sum != SecureField::from(0))
        );
        verify(proof, &hash).unwrap_or_else(|error| panic!("{log_sizes:?}: {error}"));
    }
}

/// A circuit of 8 to 32 rows in each component, every row's fractions
/// live.
fn small_circuit() -> vos_pvm_recair::Context<SecureField> {
    use vos_pvm_recair::gadgets::{TranscriptGadget, leaf_hash, node};
    use vos_pvm_recair::{Context, Message};

    let mut rng = common::Rng::new(5);
    let mut context = Context::<SecureField>::with_outputs(1);
    let wires: Vec<_> = (0..6).map(|_| context.guess(rng.qm31())).collect();
    let mut acc = wires[0];
    for i in 0..10 {
        acc = context.h8(
            acc,
            wires[1],
            wires[2],
            [wires[3 + i % 3], wires[1 + i % 5]],
        );
    }
    let mut transcript = TranscriptGadget::new(&context);
    for i in 0..4 {
        let leaf = leaf_hash(&mut context, &wires[i..i + 3], 10);
        let bit = context.guess(SecureField::from(stwo::core::fields::m31::BaseField::from(
            i as u32 % 2,
        )));
        let bit = context.assert_bit(bit);
        let parent = node(
            &mut context,
            &leaf,
            [Message::Wire(wires[5]), Message::Wire(acc)],
            bit,
            None,
        );
        transcript.absorb(&mut context, &parent.digest, 8);
        let draw = transcript.squeeze(&mut context);
        acc = context.mul_add(draw[0], draw[1], acc);
    }
    let constant = context.constant(SecureField::from_u32_unchecked(3, 1, 4, 1));
    let out = context.mul(acc, constant);
    context.set_outputs(&[out]);
    context
}

/// A circuit of 10k gates proves and verifies.
#[test]
fn a_10k_gate_circuit_proves_and_verifies() {
    let started = Instant::now();
    let built = random_circuit::<SecureField>(10_000, 10_000);
    let rows = built.rows();
    let finalized = built.finalize().expect("the wiring checks");
    let build = started.elapsed();
    let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
    let started = Instant::now();
    let proof = prove(&finalized.circuit, &finalized.witness).expect("proves");
    let proving = started.elapsed();
    let size = bincode::serialize(&proof).unwrap().len();
    let started = Instant::now();
    verify(proof, &hash).expect("verifies");
    let verifying = started.elapsed();
    // The process's peak resident memory, where Linux reports it: the
    // test's own when it runs alone.
    let peak = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM"))
                .map(|line| {
                    line.split_whitespace()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
        })
        .unwrap_or_default();
    eprintln!(
        "10k gates: rows {rows:?} ({} gates), log sizes {:?}; build {build:?}, prove {proving:?}, \
         verify {verifying:?}, proof {size} bytes, peak resident {peak}",
        rows.iter().sum::<usize>(),
        finalized.circuit.log_sizes(),
    );
    assert!(rows.iter().sum::<usize>() >= 10_000);
}
