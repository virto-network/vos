//! Recursion build P5.2a — de-risk the auto-witnessing evaluator's **logup path**
//! before driving CpuChip (which has 45 `add_to_relation` sites across 17
//! relations). CpuChip's logup denominators are exactly the degree-2 products
//! this gate exercises.
//!
//! A small chip emits a degree-2 algebraic constraint (`y == x²`) plus two
//! opposite-multiplicity lookups into one relation, then `finalize_logup`. Its
//! OODS composition (preprocessed + main + **interaction** trees) is re-evaluated
//! through [`recursion_common::oods_auto`], which must reproduce stwo's own
//! per-component accumulator contribution while witnessing every QM31 product —
//! including each logup cumulative-sum constraint's `diff·denominator`.
//!
//! The OODS mask is SYNTHETIC (a random sample per mask point, the shape taken
//! from `Component::mask_points`): the per-component contribution
//! (`eval_composition_polynomial_at_point`) is a pure function of the mask, so a
//! random mask is a strong fuzz of the arithmetisation — no real proof or
//! transcript replay is needed (that is P5.2b). The recombined composition mask
//! is set to encode the ground-truth contribution so the DEEP-ALI equality holds
//! and the witnessed join AIR proves+verifies.
//!
//! GREEN GATE: the recorder's composition value matches stwo's
//! `eval_composition_polynomial_at_point`; the logup denominators are witnessed
//! (degree ≤ 2); the join AIR proves+verifies through the lifted Poseidon2-M31
//! protocol; a perturbed committed column is rejected.
//!
//! Run: `cargo test -p zkpvm --test oods_auto_logup -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::oods_auto;
use recursion_common::oods_auto::{OodsInputs, OodsJoinEval, RecordBackend, drive};
use recursion_common::{Poseidon2M31Channel, mobile_config};
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::Column;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, TraceLocationAllocator,
    assert_constraints_on_trace, relation,
};

// ── A small chip exercising add_constraint + add_to_relation + finalize_logup ─

relation!(LogupRel, 2);

#[derive(Clone)]
struct LogupEval {
    log_n_rows: u32,
    rel: LogupRel,
}
impl FrameworkEval for LogupEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let x = eval.next_trace_mask();
        let y = eval.next_trace_mask();
        // A degree-2 algebraic constraint (exercises product witnessing).
        eval.add_constraint(x.clone() * x.clone() - y.clone());
        // Two opposite-multiplicity lookups into one relation (a self-balancing
        // pair, the shape a producer/consumer would split — but kept in one chip).
        eval.add_to_relation(RelationEntry::new(
            &self.rel,
            E::EF::one(),
            &[x.clone(), y.clone()],
        ));
        eval.add_to_relation(RelationEntry::new(&self.rel, -E::EF::one(), &[x, y]));
        eval.finalize_logup();
        eval
    }
}

const L: u32 = 5; // the inner chip's log_size
const TRACE_LOG: u32 = 6; // the join trace's row count

/// Build the (synthetic-mask) OODS inputs for the logup chip and stwo's
/// ground-truth per-component contribution.
fn setup() -> (LogupRel, SecureField, OodsInputs, SecureField) {
    let rel = LogupRel::dummy();
    // claimed_sum: arbitrary but fixed — both stwo and the re-eval use it for the
    // logup `cumsum_shift`. On a synthetic mask it need not be the true sum.
    let claimed_sum = SecureField::from_u32_unchecked(7, 11, 13, 17);
    let component = FrameworkComponent::<LogupEval>::new(
        &mut TraceLocationAllocator::default(),
        LogupEval {
            log_n_rows: L,
            rel: rel.clone(),
        },
        claimed_sum,
    );
    let mlbd = component.max_constraint_log_degree_bound();

    let channel = &mut Poseidon2M31Channel::default();
    let random_coeff = channel.draw_secure_felt();
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    // Synthetic OODS mask, shaped from the component's own mask points (so the
    // interaction-tree cumsum columns are present, in walk order), filled with a
    // fresh random sample per point.
    let mp = component.mask_points(oods_point, mlbd);
    let mask: Vec<Vec<Vec<SecureField>>> =
        mp.0.iter()
            .map(|tree| {
                tree.iter()
                    .map(|offsets| offsets.iter().map(|_| channel.draw_secure_felt()).collect())
                    .collect()
            })
            .collect();

    // Ground truth: stwo's own per-component accumulator contribution.
    let components = Components {
        components: vec![&component as &dyn Component],
        n_preprocessed_columns: 0,
    };
    let mask_tv = TreeVec::new(mask.clone());
    let truth =
        components.eval_composition_polynomial_at_point(oods_point, &mask_tv, random_coeff, mlbd);

    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;

    // Encode the contribution into the composition mask: left = truth, right = 0,
    // so the recombination `left + ox·right == truth` and the DEEP-ALI equality
    // holds against the re-evaluated contribution.
    let mut comp = [SecureField::zero(); 2 * SECURE_EXTENSION_DEGREE];
    comp[0..4].copy_from_slice(&truth.to_m31_array().map(SecureField::from));

    (
        rel,
        claimed_sum,
        OodsInputs {
            mask,
            random_coeff,
            denom_inverse,
            oods_x_doubled,
            comp,
        },
        truth,
    )
}

fn record(rel: LogupRel, claimed_sum: SecureField, inputs: OodsInputs) -> RecordBackend {
    let chip = LogupEval { log_n_rows: L, rel };
    let ctx = Rc::new(RefCell::new(RecordBackend::new(inputs)));
    drive(&ctx, claimed_sum, L, |e| chip.evaluate(e));
    Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the recorder walk"))
        .into_inner()
}

fn make_join(rel: LogupRel, claimed_sum: SecureField) -> OodsJoinEval<LogupEval> {
    OodsJoinEval {
        chip: LogupEval { log_n_rows: L, rel },
        log_size: TRACE_LOG,
        inner_log_size: L,
        claimed_sum,
    }
}

// ── Gates ──────────────────────────────────────────────────────────────────

/// FAST: the recorder reproduces stwo's per-component contribution for a chip
/// with lookups, witnessing the logup denominators; the trace drives
/// `AssertEvaluator`.
#[test]
fn oods_auto_logup_air_satisfied() {
    let (rel, claimed_sum, inputs, truth) = setup();
    let rec = record(rel.clone(), claimed_sum, inputs);

    // x·x, two logup diff·denominator products, two Horner acc·rc multiplies,
    // dinv·acc, and ox·right.
    assert_eq!(
        rec.witnessed, 7,
        "auto-derived witnessed-product count (with logup)"
    );

    let lhs = rec.final_lhs.expect("final equality discharged");
    let rhs = rec.final_rhs.expect("final equality discharged");
    assert_eq!(lhs, rhs, "recorder's comp == recombined composition mask");
    assert_eq!(
        lhs, truth,
        "recorder's composition value == eval_composition_polynomial_at_point (with logup)"
    );

    let trace = oods_auto::gen_join_trace(&rec.schedule, TRACE_LOG, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let join = make_join(rel, claimed_sum);
    assert_constraints_on_trace(
        &tv,
        TRACE_LOG,
        |e| {
            join.evaluate(e);
        },
        SecureField::zero(),
    );

    eprintln!(
        "oods_auto_logup_air_satisfied: the logup path (add_to_relation + \
         finalize_logup) re-evaluated in-AIR with 7 witnessed products; \
         composition value {truth:?} matches eval_composition; trace satisfies \
         the auto-generated AIR."
    );
}

/// THE GATE: the auto-generated join AIR for a logup-bearing chip proves+verifies
/// through the lifted Poseidon2-M31 protocol; a perturbed column is rejected.
#[test]
fn oods_auto_logup_gate() {
    let (rel, claimed_sum, inputs, _truth) = setup();
    let rec = record(rel.clone(), claimed_sum, inputs);
    let config = mobile_config();

    oods_auto::prove_and_verify_join(
        make_join(rel.clone(), claimed_sum),
        &rec.schedule,
        TRACE_LOG,
        None,
        config,
    )
    .expect("honest logup OODS re-eval must prove+verify");

    // Perturb the random-coefficient column (col 0) ⇒ the Horner binding
    // `m − acc·rc` no longer holds ⇒ rejected.
    assert!(
        oods_auto::prove_and_verify_join(
            make_join(rel, claimed_sum),
            &rec.schedule,
            TRACE_LOG,
            Some(0),
            config
        )
        .is_err(),
        "a perturbed committed column must be rejected"
    );

    eprintln!(
        "oods_auto_logup_gate GREEN: the auto-witnessing evaluator drives a \
         logup-bearing chip (add_to_relation + finalize_logup), witnessing each \
         denominator at degree ≤ 2; the join AIR proves+verifies through the \
         lifted Poseidon2-M31 protocol; a perturbed column is rejected."
    );
}
