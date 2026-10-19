//! A masked proof's verifier, for the tests alone: pin B's transcript
//! replayed over any component set and Merkle channel, on
//! `CommitmentSchemeVerifier::{commit, verify_values}` and the components'
//! public API. The venues' verifier is `vos-pvm-final-verifier`'s; this one
//! checks the prover's proofs until that one reads them.
//!
//! Included by path (`vos-pvm-recair`'s unit tests, `vos-pvm-proof`'s kernel
//! tests), so it names only the crates both have.

#![allow(dead_code)]

use num_traits::Zero;
use stwo::core::ColumnVec;
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::proof::StarkProof;
use vos_pvm_proof::format::Format;
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair_air::masked::{
    MaskPins, MaskedComponent, MaskedComponents, air_log_size, committed_log_sizes,
    composition_oods_eval, sample_points,
};

/// The trees a masked proof commits.
const TREES: usize = 4;

/// What a masked proof claims beside its STARK proof.
pub struct Claim<'a, R> {
    pub format: &'a Format,
    /// Each component's log size.
    pub log_sizes: &'a [u32],
    /// The values mixed after the main tree's root.
    pub public: &'a [SecureField],
    /// The public terms' logup sum under the relations, which the claimed
    /// sums must cancel; `None` for a set whose sums are not checked.
    pub public_sum: Option<&'a dyn Fn(&R) -> SecureField>,
    pub interaction_pow: u64,
    pub claimed_sums: &'a [SecureField],
}

/// The transcript replayed to the DEEP coefficients: the channel before
/// `verify_values` mixes the samples, the scheme and the sample points.
pub struct Replayed<MC: MerkleChannel> {
    pub channel: MC::C,
    pub scheme: CommitmentSchemeVerifier<MC>,
    pub points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
}

/// `claim`'s transcript replayed over `proof`, the component set `C` laid
/// out as `layout` (any relations), every check before Stwo's PCS done.
pub fn replay<MC: MerkleChannel, C: MaskedComponents>(
    claim: &Claim<'_, C::Relations>,
    layout: &C,
    proof: &StarkProof<MC::H>,
) -> Result<Replayed<MC>, String> {
    let format = claim.format;
    let masking = format.masking.ok_or("the format pins no masking")?;
    let pins = MaskPins {
        salt_columns: masking.salt_columns,
        fri_mask_columns: masking.fri_mask_columns,
    };
    if layout.log_sizes() != claim.log_sizes {
        return Err("the layout is at other sizes".into());
    }
    let trees = committed_log_sizes(layout, &pins).ok_or("the trees' layout")?;
    if [
        proof.commitments.len(),
        proof.sampled_values.len(),
        proof.decommitments.len(),
        proof.queried_values.len(),
    ] != [TREES; 4]
    {
        return Err("four trees".into());
    }
    let config = format.verifier_config(&proof.config);
    if config != format.pcs_config() {
        return Err("the proof's configuration is not the format's".into());
    }

    let mut channel = MC::C::default();
    mix_statement_header(&mut channel, format.number, &config, claim.log_sizes);
    let mut scheme = CommitmentSchemeVerifier::<MC>::new(config);
    scheme.commit(proof.commitments[0], &trees[0], &mut channel);
    scheme.commit(proof.commitments[1], &trees[1], &mut channel);
    channel.mix_felts(claim.public);
    if !channel.verify_pow_nonce(format.interaction_pow_bits(), claim.interaction_pow) {
        return Err("the interaction PoW".into());
    }
    channel.mix_u64(claim.interaction_pow);
    let (relations, blind) = C::draw(&mut channel);
    channel.mix_felts(claim.claimed_sums);
    scheme.commit(proof.commitments[2], &trees[2], &mut channel);
    if let Some(public_sum) = claim.public_sum {
        let total =
            claim.claimed_sums.iter().copied().sum::<SecureField>() + public_sum(&relations);
        if !total.is_zero() {
            return Err("the logup sums".into());
        }
    }

    let set = C::new(&relations, &blind, claim.log_sizes, claim.claimed_sums)
        .ok_or("the claimed sums")?;
    let random_coeff = channel.draw_secure_felt();
    scheme.commit(proof.commitments[3], &trees[3], &mut channel);
    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
    let points = sample_points(&set, oods_point, &pins).ok_or("the sample points")?;
    let fits = points.len() == proof.sampled_values.len()
        && points
            .iter()
            .zip(proof.sampled_values.iter())
            .all(|(points, values)| {
                points.len() == values.len()
                    && points.iter().zip(values).all(|(p, v)| p.len() == v.len())
            });
    if !fits {
        return Err("the samples are not the sample points'".into());
    }
    let lifted: Vec<MaskedComponent<'_, dyn Component>> = set
        .components()
        .into_iter()
        .map(|inner| MaskedComponent { inner })
        .collect();
    let components = Components {
        components: lifted.iter().map(|c| c as &dyn Component).collect(),
        n_preprocessed_columns: trees[0].len(),
    };
    let composition =
        composition_oods_eval(&proof.sampled_values).ok_or("the composition's samples")?;
    let air_level = air_log_size(&set).ok_or("the AIR's level")?;
    if composition
        != components.eval_composition_polynomial_at_point(
            oods_point,
            &proof.sampled_values,
            random_coeff,
            air_level,
        )
    {
        return Err("the OODS values".into());
    }
    Ok(Replayed {
        channel,
        scheme,
        points,
    })
}

/// Verifies `proof` of `claim`.
pub fn verify_masked<MC: MerkleChannel, C: MaskedComponents>(
    claim: &Claim<'_, C::Relations>,
    layout: &C,
    proof: StarkProof<MC::H>,
) -> Result<(), String> {
    let Replayed {
        mut channel,
        scheme,
        points,
    } = replay::<MC, C>(claim, layout, &proof)?;
    scheme
        .verify_values(points, proof.0, &mut channel)
        .map_err(|error| format!("Stwo: {error}"))
}
