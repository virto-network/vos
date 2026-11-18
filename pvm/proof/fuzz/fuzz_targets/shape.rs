//! `masked_shape`'s reshaping of a golden's queried parts within the
//! layout's bounds; `examples/paths.rs` replays it too.

use arbitrary::{Result, Unstructured};
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriLayerProof;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleHasher;
use vos_pvm_final_verifier::masked::{CONFIG, LOG_DEGREE_BOUND};
use vos_pvm_final_verifier::WrapProof;

/// The most values a queried column holds: one a query.
const QUERIES: usize = CONFIG.fri_config.n_queries;
/// The tallest tree's height: FRI's degree bound under the blowup.
const HEIGHT: usize = (LOG_DEGREE_BOUND + CONFIG.fri_config.log_blowup_factor) as usize;
/// The most hashes a Merkle witness holds: a sibling a query a level.
const WITNESS_HASHES: usize = QUERIES * HEIGHT;
/// The most values a FRI layer's witness holds.
const FRI_WITNESS: usize = QUERIES << CONFIG.fri_config.fold_step;

/// A limb, `p` itself (noncanonical) among them.
fn limb(u: &mut Unstructured<'_>) -> Result<BaseField> {
    Ok(BaseField::from_u32_unchecked(u.int_in_range(0..=P)?))
}

fn secure(u: &mut Unstructured<'_>) -> Result<SecureField> {
    Ok(SecureField::from_m31_array([
        limb(u)?,
        limb(u)?,
        limb(u)?,
        limb(u)?,
    ]))
}

/// `items` kept, or made anew at a length up to `most`, each item the
/// golden's at its place (when there is one) or `fresh`.
fn remake<T: Clone>(
    u: &mut Unstructured<'_>,
    items: &mut Vec<T>,
    most: usize,
    mut fresh: impl FnMut(&mut Unstructured<'_>) -> Result<T>,
) -> Result<()> {
    if !u.arbitrary::<bool>()? {
        return Ok(());
    }
    let len = u.int_in_range(0..=most)?;
    let golden = core::mem::take(items);
    for at in 0..len {
        let item = match golden.get(at) {
            Some(item) if !u.ratio(1, 8)? => item.clone(),
            _ => fresh(u)?,
        };
        items.push(item);
    }
    Ok(())
}

fn hash(u: &mut Unstructured<'_>) -> Result<Blake2bHash> {
    Ok(Blake2bHash(u.arbitrary()?))
}

fn layer(u: &mut Unstructured<'_>, layer: &mut FriLayerProof<Blake2bMerkleHasher>) -> Result<()> {
    remake(u, &mut layer.fri_witness, FRI_WITNESS, secure)?;
    remake(
        u,
        &mut layer.decommitment.hash_witness,
        WITNESS_HASHES,
        hash,
    )
}

/// The golden's queried parts reshaped by `u`.
pub fn reshape(u: &mut Unstructured<'_>, proof: &mut WrapProof) -> Result<()> {
    let stark = &mut proof.stark_proof.0;
    for tree in stark.queried_values.iter_mut() {
        if u.arbitrary::<bool>()? {
            let rows = u.int_in_range(0..=QUERIES)?;
            for column in tree.iter_mut() {
                let golden = core::mem::take(column);
                for at in 0..rows {
                    column.push(match golden.get(at) {
                        Some(&value) if !u.ratio(1, 16)? => value,
                        _ => limb(u)?,
                    });
                }
            }
        }
    }
    for decommitment in stark.decommitments.iter_mut() {
        remake(u, &mut decommitment.hash_witness, WITNESS_HASHES, hash)?;
    }
    layer(u, &mut stark.fri_proof.first_layer)?;
    for inner in &mut stark.fri_proof.inner_layers {
        layer(u, inner)?;
    }
    Ok(())
}
