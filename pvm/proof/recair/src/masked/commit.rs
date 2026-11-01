//! A masked proof's commitments: its main, interaction and composition
//! trees, each masked, and the composition's blinding.

use super::*;

/// The main tree: each component's columns, then its blinding columns, all
/// masked, then the salts. Returns the blinding values. A component's
/// columns are interpolated from the borrowed trace, masked and their
/// coefficients dropped before the next's; the masks' seeds are drawn for
/// every column first, in order.
pub(super) fn commit_main<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    scheme: &mut Scheme<'_, MC>,
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) -> Result<Vec<SecureField>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let blinding = blinding(setup.log_sizes.len(), setup.public_sums, rng);
    let widths: Vec<usize> = (0..setup.log_sizes.len())
        .map(|component| (setup.main)(component).len() + BLIND_COLUMNS)
        .collect();
    let mut seeds = layout::seeds(widths.iter().sum(), rng).into_iter();
    let mut masked = Vec::with_capacity(widths.iter().sum());
    for (component, ((&value, &log_size), &log_mask_rows)) in blinding
        .iter()
        .zip(setup.log_sizes)
        .zip(setup.mask_rows)
        .enumerate()
    {
        let domain = CanonicCoset::new(log_size).circle_domain();
        let own = SimdBackend::interpolate_columns(
            (setup.main)(component)
                .into_iter()
                .map(|column| CircleEvaluation::new(domain, column.clone()))
                .collect(),
            setup.twiddles,
        );
        let blinding = blinding_polys(value, log_size, setup.twiddles);
        let columns: Vec<(&CircleCoefficients<SimdBackend>, u32)> = own
            .iter()
            .chain(&blinding)
            .map(|column| (column, log_mask_rows))
            .collect();
        let seeds: Vec<[u8; 32]> = seeds.by_ref().take(columns.len()).collect();
        masked.extend(layout::mask_with(&columns, seeds, setup.layouts)?);
    }
    salts::commit_salted(
        scheme,
        masked,
        setup.lifting,
        setup.masking.salt_columns,
        rng,
        channel,
    );
    Ok(blinding)
}

/// The interaction tree under the drawn `(relations, blind)`: the blinded
/// claimed sums mixed, then the columns masked and salted. Returns the
/// blinded claimed sums.
pub(super) fn commit_interaction<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    scheme: &mut Scheme<'_, MC>,
    (relations, blind): (&R, &BlindRelation),
    blinding: &[SecureField],
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) -> Result<Vec<SecureField>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let denominator: SecureField =
        Relation::<BaseField, SecureField>::combine(blind, &[BaseField::one()]);
    let fractions: Vec<FirstRowFraction> = blinding
        .iter()
        .map(|&numerator| FirstRowFraction {
            numerator,
            denominator,
        })
        .collect();
    let interaction_columns = (setup.interaction)(relations, &fractions);
    if interaction_columns.len() != setup.log_sizes.len() {
        return Err(ProveError::TraceShape(
            "one interaction trace per component expected",
        ));
    }
    let claimed_sums: Vec<SecureField> = interaction_columns.iter().map(|(_, sum)| *sum).collect();
    let column_rows: Vec<u32> = interaction_columns
        .iter()
        .zip(setup.mask_rows)
        .flat_map(|((columns, _), &log_mask_rows)| {
            core::iter::repeat_n(log_mask_rows, columns.len())
        })
        .collect();
    let polys = SimdBackend::interpolate_columns(
        interaction_columns
            .into_iter()
            .flat_map(|(columns, _)| columns)
            .collect(),
        setup.twiddles,
    );
    let columns: Vec<(&CircleCoefficients<SimdBackend>, u32)> =
        polys.iter().zip(column_rows).collect();
    let masked = layout::mask_columns(&columns, setup.layouts, rng)?;
    drop(polys);
    channel.mix_felts(&claimed_sums);
    salts::commit_salted(
        scheme,
        masked,
        setup.lifting,
        setup.masking.salt_columns,
        rng,
        channel,
    );
    Ok(claimed_sums)
}

/// The composition tree: the composition's 4 coordinates whole at its
/// bound, the FRI mask `R`'s uniform columns, the salts. Returns the
/// composition coefficient drawn before it.
pub(super) fn commit_composition<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    scheme: &mut Scheme<'_, MC>,
    provers: &ComponentProvers<'_, SimdBackend>,
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) -> Result<SecureField, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let random_coeff = channel.draw_secure_felt();
    let composition_poly = provers.compute_composition_polynomial(
        random_coeff,
        &scheme.trace(),
        setup.twiddles,
        setup.format.params.log_blowup,
    );
    if composition_poly.log_size() != setup.composition {
        return Err(ProveError::Masking(
            "the composition polynomial is not at its bound",
        ));
    }
    let mut polys = composition_poly.into_coordinate_polys().to_vec();
    let seeds: Vec<[u8; 32]> = (0..setup.masking.fri_mask_columns)
        .map(|_| rng.r#gen())
        .collect();
    for seed in &seeds {
        drawn::note("an R column's seed", seed);
    }
    polys.extend(
        seeds
            .into_iter()
            .map(|seed| salts::uniform_poly(seed, setup.composition)),
    );
    salts::commit_salted(
        scheme,
        polys,
        setup.lifting,
        setup.masking.salt_columns,
        rng,
        channel,
    );
    Ok(random_coeff)
}

/// The blinding values (R2), one a component: zero for the components
/// `public` names, uniform for the others but the last, which makes them sum
/// to zero, so the claimed sums' total is the unblinded one. The prover
/// refuses a set of one blinded component before it gets here.
fn blinding(n_components: usize, public: &[usize], rng: &mut ChaCha20Rng) -> Vec<SecureField> {
    let blinded: Vec<usize> = (0..n_components)
        .filter(|component| !public.contains(component))
        .collect();
    let drawn: Vec<SecureField> = (1..blinded.len())
        .map(|_| SecureField::from_m31_array(core::array::from_fn(|_| rng.r#gen())))
        .collect();
    let mut values = vec![SecureField::zero(); n_components];
    for (&component, &value) in blinded.iter().zip(&drawn) {
        values[component] = value;
    }
    if let Some(&last) = blinded.last() {
        values[last] = -drawn.iter().copied().sum::<SecureField>();
    }
    for value in &values {
        let limbs: Vec<u8> = value
            .to_m31_array()
            .iter()
            .flat_map(|limb| limb.0.to_le_bytes())
            .collect();
        drawn::note("a blinding value", &limbs);
    }
    values
}

/// A component's blinding columns: `value`'s limbs on the coset's first row,
/// zero on every other.
fn blinding_polys(
    value: SecureField,
    log_size: u32,
    twiddles: &TwiddleTree<SimdBackend>,
) -> Vec<CircleCoefficients<SimdBackend>> {
    let columns: Vec<Vec<BaseField>> = value
        .to_m31_array()
        .into_iter()
        .map(|limb| {
            let mut column = vec![BaseField::zero(); 1 << log_size];
            column[0] = limb;
            column
        })
        .collect();
    SimdBackend::interpolate_columns(trace::evaluations(&columns, log_size), twiddles)
}

const _: () = assert!(BLIND_COLUMNS == SECURE_EXTENSION_DEGREE);
