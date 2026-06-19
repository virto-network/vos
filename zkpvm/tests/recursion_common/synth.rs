//! Shared synthetic 31-component OODS setup + symbolic capture.
//!
//! The streamed OODS-embed gates fuzz the arithmetisation against a SYNTHETIC
//! mask: the shape of each component's OODS contribution is a pure function of its
//! `mask_points`, so random samples exercise the full embed without a real proof.
//! [`synthetic_setup`] builds all 31 standalone components + per-component synthetic
//! masks + the global ground truth (one shared `PointEvaluationAccumulator` across
//! all 31, in `BASE_COMPONENTS` order); [`build_capture`] drives them through the
//! [`StreamBackend`] to get the symbolic capture the schedules compile from.

use std::cell::RefCell;
use std::rc::Rc;

use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo_constraint_framework::TraceLocationAllocator;
use zkpvm::chip_idx;
use zkpvm::framework_access::{
    AllLookupElements, create_verifier_components, draw_all_lookup_elements, drive_chip_oods,
};
use zkpvm::recursion_pcs::ProverChannel;

use super::Poseidon2M31Channel;
use super::oods_auto::{ComponentMask, StreamBackend, StreamCapture, drive_multi};

/// A synthetic per-component claimed sum (distinct per component).
pub fn claimed_sum_for(idx: usize) -> SecureField {
    SecureField::from_u32_unchecked(7, 11, 13, 17 + idx as u32)
}

/// Draw all 31 chips' lookup elements (full active mask).
pub fn full_lookup() -> AllLookupElements {
    let mut lookup = AllLookupElements::default();
    let mut channel = ProverChannel::default();
    draw_all_lookup_elements(&mut lookup, &mut channel, (1u32 << chip_idx::COUNT) - 1);
    lookup
}

/// The synthetic OODS setup: every component + its synthetic mask + the protocol
/// scalars + the global composition ground truth.
pub struct Setup {
    pub component_masks: Vec<ComponentMask>,
    pub comps: Vec<(usize, u32, SecureField)>,
    pub random_coeff: SecureField,
    pub denom_inverse: SecureField,
    pub oods_x_doubled: SecureField,
    pub comp: [SecureField; 2 * SECURE_EXTENSION_DEGREE],
    pub truth: SecureField,
}

/// Build all 31 standalone components + synthetic per-component masks at log_size
/// `l`, and the global ground truth (one shared accumulator across all 31, in
/// `BASE_COMPONENTS` order).
pub fn synthetic_setup(l: u32) -> Setup {
    let lookup = full_lookup();
    let channel = &mut Poseidon2M31Channel::default();
    let random_coeff = channel.draw_secure_felt();
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let mut boxes: Vec<Box<dyn Component>> = Vec::new();
    let mut comps: Vec<(usize, u32, SecureField)> = Vec::new();
    for idx in 0..chip_idx::COUNT {
        let cs = claimed_sum_for(idx);
        let mut alloc = TraceLocationAllocator::default();
        let mut built =
            create_verifier_components::components(&mut alloc, &lookup, &[l], &[cs], 1 << idx);
        boxes.push(built.pop().unwrap());
        comps.push((idx, l, cs));
    }
    let mlbd = boxes
        .iter()
        .map(|c| c.max_constraint_log_degree_bound())
        .max()
        .unwrap();

    let mut masks: Vec<Vec<Vec<Vec<SecureField>>>> = Vec::new();
    let mut component_masks: Vec<ComponentMask> = Vec::new();
    for comp in &boxes {
        let mp = comp.mask_points(oods_point, mlbd);
        let preproc_indices = comp.preprocessed_column_indices();
        let n_preproc = preproc_indices.iter().copied().max().map_or(0, |m| m + 1);
        let preproc: Vec<Vec<SecureField>> = (0..n_preproc)
            .map(|_| vec![channel.draw_secure_felt()])
            .collect();
        let synth = |tree: &Vec<Vec<CirclePoint<SecureField>>>,
                     ch: &mut Poseidon2M31Channel|
         -> Vec<Vec<SecureField>> {
            tree.iter()
                .map(|offs| offs.iter().map(|_| ch.draw_secure_felt()).collect())
                .collect()
        };
        let mask = vec![preproc, synth(&mp.0[1], channel), synth(&mp.0[2], channel)];
        masks.push(mask.clone());
        component_masks.push(ComponentMask {
            mask,
            preproc_indices,
        });
    }

    let mut acc = PointEvaluationAccumulator::new(random_coeff);
    for (comp, mask) in boxes.iter().zip(&masks) {
        let mask_tv = TreeVec::new(mask.clone());
        comp.evaluate_constraint_quotients_at_point(oods_point, &mask_tv, &mut acc, mlbd);
    }
    let truth = acc.finalize();

    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;
    let mut comp = [SecureField::zero(); 2 * SECURE_EXTENSION_DEGREE];
    comp[0..4].copy_from_slice(&truth.to_m31_array().map(SecureField::from));

    Setup {
        component_masks,
        comps,
        random_coeff,
        denom_inverse,
        oods_x_doubled,
        comp,
        truth,
    }
}

/// Drive all 31 chips through the [`StreamBackend`] on the setup's synthetic masks
/// and return the symbolic capture.
pub fn build_capture(s: &Setup) -> StreamCapture {
    let component_masks: Vec<ComponentMask> = s
        .component_masks
        .iter()
        .map(|cm| ComponentMask {
            mask: cm.mask.clone(),
            preproc_indices: cm.preproc_indices.clone(),
        })
        .collect();
    let backend = StreamBackend::new(
        component_masks,
        s.random_coeff,
        s.denom_inverse,
        s.oods_x_doubled,
        s.comp,
    );
    let ctx = Rc::new(RefCell::new(backend));
    let lookup = full_lookup();
    drive_multi(&ctx, &s.comps, |idx, ls, e| {
        drive_chip_oods(idx, ls, &lookup, e)
    });
    Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the capture walk"))
        .into_inner()
        .finish()
}
