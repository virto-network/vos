//! Recursion build P5.2a (task 2) — drive the REAL **CpuChip** through the
//! auto-witnessing OODS evaluator.
//!
//! CpuChip is the heaviest of the 31 canonical components (187 `add_constraint`
//! + 45 `add_to_relation` across 17 logup relations). Its `add_constraints` is
//! `pub(crate)`, so it is reached through the crate seam
//! `zkpvm::framework_access::drive_cpu_chip_oods`, which builds the in-house
//! `BuiltInComponentEval<CpuChip>` and runs it against a caller-supplied
//! `EvalAtRow` — here [`recursion_common::oods_auto`]'s degree-reducing evaluator.
//!
//! The OODS mask is SYNTHETIC (a random sample per mask point, shape from the
//! component's `mask_points`) with the relation elements drawn the same way the
//! component is built. The per-component contribution
//! (`eval_composition_polynomial_at_point`) is a pure function of the mask, so a
//! random mask is a strong fuzz of the whole-chip arithmetisation — no real
//! segment proof or transcript replay is needed (that is P5.2b).
//!
//! GREEN GATE:
//!   * driving CpuChip's own `evaluate` through the auto-witnessing evaluator
//!     reproduces stwo's per-component accumulator contribution (its
//!     `evaluate_constraint_quotients_at_point`), every QM31 product witnessed at
//!     degree ≤ 2;
//!   * `assert_constraints` is green on the auto-generated join AIR;
//!   * the join AIR proves+verifies through the lifted Poseidon2-M31 protocol;
//!     a perturbed committed column is rejected.
//!
//! Run: `cargo test -p zkpvm --test oods_auto_cpu -- --nocapture`

mod recursion_common;

use num_traits::Zero;
use recursion_common::oods_auto;
use recursion_common::oods_auto::{OodsInputs, RecordBackend, VerifyBackend, drive};
use recursion_common::{Poseidon2M31Channel, mobile_config};
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::air::Components;
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
    EvalAtRow, FrameworkEval, TraceLocationAllocator, assert_constraints_on_trace,
};
use zkpvm::framework_access::{
    AllLookupElements, create_verifier_components, draw_all_lookup_elements, drive_cpu_chip_oods,
};
use zkpvm::recursion_pcs::ProverChannel;

const L: u32 = 6; // CpuChip's (synthetic) log_size — only feeds the logup cumsum_shift
const TRACE_LOG: u32 = 6; // join trace rows
const CPU_MASK: u32 = 1 << 0; // chip_idx::CPU

/// A join AIR that re-evaluates CpuChip's OODS composition in-AIR by driving its
/// `add_constraints` (via the crate seam) through a [`VerifyBackend`]. Degree ≤ 2.
#[derive(Clone)]
struct CpuOodsJoinEval {
    lookup: AllLookupElements,
    log_size: u32,
    inner_log_size: u32,
    claimed_sum: SecureField,
}
impl FrameworkEval for CpuOodsJoinEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        let ctx = Rc::new(RefCell::new(VerifyBackend::new(eval)));
        let lookup = &self.lookup;
        let inner_log_size = self.inner_log_size;
        drive(&ctx, self.claimed_sum, inner_log_size, |e| {
            drive_cpu_chip_oods(inner_log_size, lookup, e)
        });
        Rc::try_unwrap(ctx)
            .unwrap_or_else(|_| panic!("a Handle outlived the OODS walk"))
            .into_inner()
            .into_eval()
    }
}

/// Draw CpuChip's relation elements + build its verifier component, then a
/// synthetic OODS mask of the right shape and stwo's ground-truth contribution.
fn setup() -> (AllLookupElements, SecureField, OodsInputs, SecureField) {
    let mut lookup = AllLookupElements::default();
    let mut draw_channel = ProverChannel::default();
    draw_all_lookup_elements(&mut lookup, &mut draw_channel, CPU_MASK);

    let claimed_sum = SecureField::from_u32_unchecked(7, 11, 13, 17);
    let mut alloc = TraceLocationAllocator::default();
    let comps =
        create_verifier_components::components(&mut alloc, &lookup, &[L], &[claimed_sum], CPU_MASK);
    let cpu = &comps[0];
    let mlbd = cpu.max_constraint_log_degree_bound();

    let channel = &mut Poseidon2M31Channel::default();
    let random_coeff = channel.draw_secure_felt();
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let mp = cpu.mask_points(oods_point, mlbd);
    let mask: Vec<Vec<Vec<SecureField>>> =
        mp.0.iter()
            .map(|tree| {
                tree.iter()
                    .map(|offsets| offsets.iter().map(|_| channel.draw_secure_felt()).collect())
                    .collect()
            })
            .collect();

    let components = Components {
        components: vec![cpu.as_ref()],
        n_preprocessed_columns: 0,
    };
    let mask_tv = TreeVec::new(mask.clone());
    let truth =
        components.eval_composition_polynomial_at_point(oods_point, &mask_tv, random_coeff, mlbd);

    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;

    let mut comp = [SecureField::zero(); 2 * SECURE_EXTENSION_DEGREE];
    comp[0..4].copy_from_slice(&truth.to_m31_array().map(SecureField::from));

    (
        lookup,
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

fn record(
    lookup: &AllLookupElements,
    claimed_sum: SecureField,
    inputs: OodsInputs,
) -> RecordBackend {
    let ctx = Rc::new(RefCell::new(RecordBackend::new(inputs)));
    drive(&ctx, claimed_sum, L, |e| drive_cpu_chip_oods(L, lookup, e));
    Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the recorder walk"))
        .into_inner()
}

fn make_join(lookup: AllLookupElements, claimed_sum: SecureField) -> CpuOodsJoinEval {
    CpuOodsJoinEval {
        lookup,
        log_size: TRACE_LOG,
        inner_log_size: L,
        claimed_sum,
    }
}

// ── Gates ──────────────────────────────────────────────────────────────────

/// FAST: driving CpuChip through the auto-witnessing evaluator reproduces stwo's
/// per-component contribution; the auto-generated join trace drives
/// `AssertEvaluator`.
#[test]
fn oods_auto_cpu_air_satisfied() {
    let (lookup, claimed_sum, inputs, truth) = setup();
    let rec = record(&lookup, claimed_sum, inputs);

    eprintln!(
        "CpuChip OODS embed: {} committed QM31 columns ({} witnessed products) \
         => {} M31 trace columns",
        rec.schedule.len(),
        rec.witnessed,
        rec.schedule.len() * SECURE_EXTENSION_DEGREE,
    );

    let lhs = rec.final_lhs.expect("final equality discharged");
    let rhs = rec.final_rhs.expect("final equality discharged");
    assert_eq!(lhs, rhs, "recorder's comp == recombined composition mask");
    assert_eq!(
        lhs, truth,
        "CpuChip OODS re-eval == stwo's evaluate_constraint_quotients_at_point"
    );

    let trace = oods_auto::gen_join_trace(&rec.schedule, TRACE_LOG, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let join = make_join(lookup, claimed_sum);
    assert_constraints_on_trace(
        &tv,
        TRACE_LOG,
        |e| {
            join.evaluate(e);
        },
        SecureField::zero(),
    );

    eprintln!(
        "oods_auto_cpu_air_satisfied: the auto-witnessing evaluator drove CpuChip's \
         own add_constraints (187 add_constraint + 45 add_to_relation); the in-AIR \
         OODS re-eval matches stwo's contribution {truth:?}; trace satisfies the AIR."
    );
}

/// THE GATE: the auto-generated CpuChip join AIR proves+verifies through the
/// lifted Poseidon2-M31 protocol; a perturbed committed column is rejected.
/// (~66s — the real 9316-M31-column width through the scalar Poseidon2 hasher.)
#[test]
fn oods_auto_cpu_gate() {
    let (lookup, claimed_sum, inputs, _truth) = setup();
    let rec = record(&lookup, claimed_sum, inputs);
    let config = mobile_config();

    oods_auto::prove_and_verify_join(
        make_join(lookup.clone(), claimed_sum),
        &rec.schedule,
        TRACE_LOG,
        None,
        config,
    )
    .expect("honest CpuChip OODS re-eval must prove+verify");

    assert!(
        oods_auto::prove_and_verify_join(
            make_join(lookup, claimed_sum),
            &rec.schedule,
            TRACE_LOG,
            Some(0),
            config
        )
        .is_err(),
        "a perturbed committed column must be rejected"
    );

    eprintln!(
        "oods_auto_cpu_gate GREEN: the real CpuChip's OODS composition is \
         re-evaluated in-AIR (no hand-port) and proves+verifies at degree ≤ 2 \
         through the lifted Poseidon2-M31 protocol; a perturbed column is rejected."
    );
}
