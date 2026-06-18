//! Recursion build P5.2b (step 1) — drive ALL 31 canonical components through
//! the auto-witnessing OODS evaluator and MEASURE the embed width.
//!
//! P5.2a de-risked the evaluator on CpuChip (the heaviest). This gate drives
//! every one of the 31 `BASE_COMPONENTS` standalone through the crate seam
//! `framework_access::drive_chip_oods` against a synthetic OODS mask, and checks
//! each chip's in-AIR re-eval reproduces stwo's own per-component contribution
//! (`evaluate_constraint_quotients_at_point`). Confirming all 31 chips' generic
//! `evaluate` survive the degree-reducing evaluator — and totalling their
//! witnessed-product + sample columns — is the WIDTH measurement the design
//! front-loads (`recursion-design.md:197-199`).
//!
//! Each chip is built with its OWN fresh `TraceLocationAllocator`, so it is a
//! single standalone component (identity trace locations + preprocessed indices)
//! and its `mask_points` shape feeds the auto-evaluator's sequential cursor
//! directly. The synthetic mask makes the per-component contribution a pure
//! function of the mask (a strong fuzz of every chip's arithmetisation); the
//! single-uniform-component accumulation across all 31 (continuous Horner) + the
//! claimed-sum balance + the real-segment match are the next P5.2b steps.
//!
//! GREEN GATE: all 31 chips' OODS re-eval matches stwo; the total embed width is
//! reported.
//!
//! Run: `cargo test -p zkpvm --test oods_auto_all31 -- --nocapture`

mod recursion_common;

use num_traits::Zero;
use recursion_common::Poseidon2M31Channel;
use recursion_common::oods_auto::{OodsInputs, RecordBackend, drive};
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::air::Components;
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

const L: u32 = 4; // each chip's (synthetic) log_size — only feeds the logup cumsum_shift

/// Aux QM31 columns the join allocates per re-eval: rc + dinv + ox + 8 composition
/// mask. Shared across components in the single-uniform-component join, so counted
/// once when totalling the embed width.
const AUX_QM31: usize = 1 + 1 + 1 + 2 * SECURE_EXTENSION_DEGREE;

fn full_lookup() -> AllLookupElements {
    let mut lookup = AllLookupElements::default();
    let mut channel = ProverChannel::default();
    let full_mask = (1u32 << chip_idx::COUNT) - 1;
    draw_all_lookup_elements(&mut lookup, &mut channel, full_mask);
    lookup
}

/// Drive component `idx` standalone through the auto-witnessing evaluator on a
/// synthetic mask; return the recorder + stwo's ground-truth contribution.
fn drive_one(idx: usize, lookup: &AllLookupElements) -> (RecordBackend, SecureField) {
    let claimed_sum = SecureField::from_u32_unchecked(7, 11, 13, 17 + idx as u32);
    let mut alloc = TraceLocationAllocator::default();
    let comps =
        create_verifier_components::components(&mut alloc, lookup, &[L], &[claimed_sum], 1 << idx);
    let comp = &comps[0];
    let mlbd = comp.max_constraint_log_degree_bound();

    let channel = &mut Poseidon2M31Channel::default();
    let random_coeff = channel.draw_secure_felt();
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let mp = comp.mask_points(oods_point, mlbd);
    // Main + interaction trees: one random sample per (column, offset) read.
    let synth = |tree: &Vec<Vec<CirclePoint<SecureField>>>,
                 ch: &mut Poseidon2M31Channel|
     -> Vec<Vec<SecureField>> {
        tree.iter()
            .map(|offsets| offsets.iter().map(|_| ch.draw_secure_felt()).collect())
            .collect()
    };
    // Preprocessed tree: the FULL column set (reads index into it via
    // preprocessed_column_indices, stwo's remap — not necessarily sequential).
    let preproc_indices = comp.preprocessed_column_indices();
    let n_preproc = preproc_indices.iter().copied().max().map_or(0, |m| m + 1);
    let preproc: Vec<Vec<SecureField>> = (0..n_preproc)
        .map(|_| vec![channel.draw_secure_felt()])
        .collect();
    let mask: Vec<Vec<Vec<SecureField>>> =
        vec![preproc, synth(&mp.0[1], channel), synth(&mp.0[2], channel)];

    let components = Components {
        components: vec![comp.as_ref()],
        n_preprocessed_columns: n_preproc,
    };
    let mask_tv = TreeVec::new(mask.clone());
    let truth =
        components.eval_composition_polynomial_at_point(oods_point, &mask_tv, random_coeff, mlbd);

    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;
    let mut comp_mask = [SecureField::zero(); 2 * SECURE_EXTENSION_DEGREE];
    comp_mask[0..4].copy_from_slice(&truth.to_m31_array().map(SecureField::from));

    let mut backend = RecordBackend::new(OodsInputs {
        mask,
        random_coeff,
        denom_inverse,
        oods_x_doubled,
        comp: comp_mask,
    });
    backend.set_preproc_indices(preproc_indices);
    let ctx = Rc::new(RefCell::new(backend));
    drive(&ctx, claimed_sum, L, |e| drive_chip_oods(idx, L, lookup, e));
    let rec = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the recorder walk"))
        .into_inner();
    (rec, truth)
}

const CHIP_NAMES: [&str; 31] = [
    "CpuChip",
    "Blake2bChip",
    "Blake2bBoundaryChip",
    "MemoryChip",
    "MemoryPageChip",
    "MemoryMerkleChip",
    "MemoryRootBoundaryChip",
    "RegisterMemoryChip",
    "RegisterMemoryBoundaryChip",
    "RegisterMemoryClosingChip",
    "ProgramBoundaryChip",
    "ProgramMemoryChip",
    "JumpTableChip",
    "RangeMultiplicity256",
    "BitwiseLookupChip",
    "PowerOfTwoChip",
    "PopcountChip",
    "BitcountChip",
    "ByteToBitsChip",
    "MulChip",
    "BitwiseChip",
    "CompareChip",
    "DivRemChip",
    "RistrettoChip",
    "RistrettoEcallChip",
    "RistrettoCombTableChip",
    "RistrettoFixedBaseConsumerChip",
    "RistrettoCombAnchorChip",
    "RistrettoCombScalarBoundaryChip",
    "RistrettoCombCompressChip",
    "RistrettoCombCompressOutputChip",
];

/// GATE: every one of the 31 canonical chips re-evaluates correctly through the
/// auto-witnessing evaluator (matches stwo's per-component contribution); report
/// the total OODS-embed width.
#[test]
fn oods_auto_all31_widths() {
    let lookup = full_lookup();
    let mut total_embed = 0usize; // samples + witnessed products across all 31
    let mut total_witnessed = 0usize;
    let mut heaviest = (0usize, 0usize);

    for idx in 0..chip_idx::COUNT {
        let (rec, truth) = drive_one(idx, &lookup);
        assert_eq!(
            rec.final_lhs.expect("final equality discharged"),
            truth,
            "chip {idx} ({}) OODS re-eval must match stwo's contribution",
            CHIP_NAMES[idx]
        );
        assert_eq!(
            rec.final_lhs, rec.final_rhs,
            "chip {idx} comp == recombined composition mask"
        );

        let embed = rec.schedule.len() - AUX_QM31; // samples + witnesses (drop the shared aux)
        total_embed += embed;
        total_witnessed += rec.witnessed;
        if embed > heaviest.1 {
            heaviest = (idx, embed);
        }
        eprintln!(
            "chip {idx:>2} {:<32} {embed:>5} QM31 cols ({} witnessed)",
            CHIP_NAMES[idx], rec.witnessed
        );
    }

    let total_qm31 = total_embed + AUX_QM31; // + the once-shared aux
    eprintln!(
        "\nALL 31 chips' OODS re-eval matched stwo. Embed width ≈ {total_qm31} QM31 = \
         {} M31 columns ({total_witnessed} witnessed products); heaviest = chip {} ({}) at \
         {} QM31. (Single-uniform-component continuous-Horner accumulation + claimed-sum \
         balance + real-segment match are the next P5.2b steps.)",
        total_qm31 * SECURE_EXTENSION_DEGREE,
        heaviest.0,
        CHIP_NAMES[heaviest.0],
        heaviest.1,
    );
}
