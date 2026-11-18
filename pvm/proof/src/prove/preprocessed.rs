//! The preprocessed tree a proof commits first: its root, a program's
//! identity, and the twiddles a commitment scheme over a chip set takes.

use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::{BackendForChannel, simd::SimdBackend};
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::{CommitmentSchemeProver, poly::circle::PolyOps};

use crate::pcs::PcsStack;
use crate::side_note::SideNote;

/// The twiddles a commitment scheme over `components` at `log_sizes`
/// takes: to their largest constraint-degree bound, blown up.
pub(crate) fn twiddles_for(
    components: &[&dyn crate::framework::MachineProverComponent],
    log_sizes: &[u32],
    config: &PcsConfig,
) -> TwiddleTree<SimdBackend> {
    let max_constraint_log_degree_bound = components
        .iter()
        .zip(log_sizes)
        .map(|(component, &log_size)| component.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);
    SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    )
}

/// The root of the preprocessed trace of `components` at `log_sizes` for
/// the program `side_note` holds. It does not depend on the channel the
/// commitment is mixed into.
pub(crate) fn preprocessed_root<MC: PcsStack>(
    side_note: &SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
    log_sizes: &[u32],
    config: PcsConfig,
) -> <MC::H as MerkleHasherLifted>::Hash
where
    SimdBackend: BackendForChannel<MC>,
{
    let twiddles = twiddles_for(components, log_sizes, &config);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    let mut tree_builder = scheme.tree_builder();
    for (component, &log_size) in components.iter().zip(log_sizes) {
        tree_builder.extend_evals(component.generate_preprocessed_trace(log_size, side_note));
    }
    tree_builder.commit(&mut MC::C::default());
    scheme.roots()[0]
}
