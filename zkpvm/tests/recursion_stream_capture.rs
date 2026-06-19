//! Recursion build P5.3 task #1 — symbolic-capture fidelity for the streamed
//! emission.
//!
//! The streamed `OodsEval` cannot bind operands eagerly at offset 0 (the existing
//! `VerifyBackend` does, which is why it can't stream); it must capture each
//! product's two operands as SYMBOLIC linear forms (`Σ coeff·node + Σ d·latched +
//! const`) so the read of each node can later be deferred to the consuming
//! product's row at the scheduled offset. `StreamBackend` captures exactly that
//! while computing concrete values (like `MultiRecordBackend`).
//!
//! This validates the capture is FAITHFUL — host-only, no proving:
//!   * every operand form's carried value equals its symbolic re-evaluation over
//!     the captured node/latched values (the in-AIR reconstruction reproduces it);
//!   * every product node = a·b;
//!   * the final DEEP-ALI equality `lhs == rhs` holds and equals the global
//!     composition (the same `PointEvaluationAccumulator` ground truth as
//!     oods_auto_join31).
//!
//! Run: `cargo test -p zkpvm --test recursion_stream_capture -- --nocapture`

mod recursion_common;

use num_traits::Zero;
use recursion_common::Poseidon2M31Channel;
use recursion_common::oods_auto::{ComponentMask, StreamBackend, StreamNode, drive_multi};
use std::cell::RefCell;
use std::rc::Rc;
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

const L: u32 = 4; // each component's synthetic log_size

fn claimed_sum_for(idx: usize) -> SecureField {
    SecureField::from_u32_unchecked(7, 11, 13, 17 + idx as u32)
}

fn full_lookup() -> AllLookupElements {
    let mut lookup = AllLookupElements::default();
    let mut channel = ProverChannel::default();
    draw_all_lookup_elements(&mut lookup, &mut channel, (1u32 << chip_idx::COUNT) - 1);
    lookup
}

struct Setup {
    component_masks: Vec<ComponentMask>,
    comps: Vec<(usize, u32, SecureField)>,
    random_coeff: SecureField,
    denom_inverse: SecureField,
    oods_x_doubled: SecureField,
    comp: [SecureField; 2 * SECURE_EXTENSION_DEGREE],
    truth: SecureField,
}

/// Build all 31 standalone components + synthetic per-component masks, and the
/// global ground truth (one shared accumulator across all 31, in order) — the
/// same construction oods_auto_join31 uses.
fn setup() -> Setup {
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
            create_verifier_components::components(&mut alloc, &lookup, &[L], &[cs], 1 << idx);
        boxes.push(built.pop().unwrap());
        comps.push((idx, L, cs));
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

/// GATE: the captured symbolic forms faithfully reconstruct every value, every
/// product is a·b, and the final equality reproduces the global composition.
#[test]
fn stream_capture_fidelity() {
    let s = setup();
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
    let capture = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the capture walk"))
        .into_inner()
        .finish();

    let n_nodes = capture.node_kind.len();
    let mut n_mask = 0usize;
    let mut n_product = 0usize;
    let mut max_node_terms = 0usize;
    let mut max_latched_terms = 0usize;

    for (id, kind) in capture.node_kind.iter().enumerate() {
        match kind {
            StreamNode::Mask => n_mask += 1,
            StreamNode::Product { a, b } => {
                n_product += 1;
                // Each operand form reconstructs its own carried value …
                assert_eq!(
                    a.value,
                    capture.eval_form(a),
                    "product {id}: operand a form value != symbolic eval"
                );
                assert_eq!(
                    b.value,
                    capture.eval_form(b),
                    "product {id}: operand b form value != symbolic eval"
                );
                // … and the product node is exactly a·b.
                assert_eq!(
                    capture.node_value[id],
                    a.value * b.value,
                    "product {id}: node value != a·b"
                );
                max_node_terms = max_node_terms.max(a.nodes.len()).max(b.nodes.len());
                max_latched_terms = max_latched_terms.max(a.latched.len()).max(b.latched.len());
            }
        }
    }

    // The final DEEP-ALI equality holds and equals the global composition.
    let lhs = capture.eval_form(&capture.final_lhs);
    let rhs = capture.eval_form(&capture.final_rhs);
    assert_eq!(lhs, rhs, "final lhs != rhs (DEEP-ALI equality)");
    assert_eq!(
        lhs, s.truth,
        "streamed capture composition != global PointEvaluationAccumulator"
    );

    eprintln!(
        "stream_capture_fidelity GREEN: {n_nodes} nodes ({n_mask} masks + {n_product} products); \
         every operand form reconstructs its value, every product = a·b, and the final equality \
         reproduces the global composition {:?}. Max operand form size: {max_node_terms} node \
         terms + {max_latched_terms} latched terms (the per-product preprocessed-coeff width).",
        s.truth,
    );

    assert!(
        n_product > 20_000,
        "expected ~23294 products, got {n_product}"
    );
    assert_eq!(n_mask + n_product, n_nodes);
}
