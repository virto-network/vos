//! The hostile-proof preflight: a proof's structure, dimensions, field
//! canonicity and owned bytes, checked before any verifier indexes it.

use alloc::vec::Vec;
use stwo::core::{
    channel::{Channel, MerkleChannel},
    fields::qm31::SecureField,
    pcs::PcsConfig,
    poly::line::LinePoly,
    proof::StarkProof,
    vcs_lifted::merkle_hasher::MerkleHasherLifted,
};

use super::{
    MAX_EXTENDED_LOG_SIZE, MAX_FRI_QUERIES, MAX_MERKLE_WITNESS_HASHES, MAX_PROOF_COLUMNS_PER_TREE,
    MAX_PROOF_COMPONENTS, MAX_PROOF_OWNED_BYTES, MAX_PROOF_SAMPLES_PER_COLUMN, MIN_PROOF_LOG_SIZE,
    PROOF_COMMITMENT_TREE_COUNT, Proof, proof_format,
};
use crate::format::Format;
use crate::pcs::{ProofHash, StarkProofAny};

/// Transport-independent hostile-proof preflight shared by the prover-enabled
/// and standalone no_std verifiers.
///
/// This must run before either verifier indexes a Stwo `TreeVec`, constructs a
/// commitment verifier, or hashes proof-owned vectors. It validates the parts
/// that are independent of the selected AIR components; callers additionally
/// validate exact per-tree column/sample/query dimensions once they derive the
/// component layout. Its mutable wrapper reconstructs the last-layer
/// polynomial from visible coefficients so a serde-forged private cached
/// `log_size` cannot reach Stwo's shifting code.
///
/// Returns the proof's format ([`proof_format`]) and its bounded owned bytes
/// ([`proof_owned_bytes`]).
pub fn preflight_proof_structure_readonly(
    proof: &Proof,
    max_log_size: u32,
) -> Result<(&'static Format, usize), alloc::string::String> {
    let format = proof_format(proof)?;
    let bytes = match &proof.stark_proof {
        StarkProofAny::Blake2s(stark) => preflight_structure(proof, stark, max_log_size),
        StarkProofAny::Poseidon2M31(stark) => preflight_structure(proof, stark, max_log_size),
        StarkProofAny::Blake2sM31(stark) => preflight_structure(proof, stark, max_log_size),
    }?;
    Ok((format, bytes))
}

fn preflight_structure<H: MerkleHasherLifted>(
    proof: &Proof,
    stark: &StarkProof<H>,
    max_log_size: u32,
) -> Result<usize, alloc::string::String>
where
    H::Hash: ProofHash,
{
    use alloc::{format, string::ToString};

    if proof.num_components == 0 || proof.num_components > MAX_PROOF_COMPONENTS {
        return Err("proof component cardinality is outside protocol bounds".into());
    }
    if proof.log_sizes.len() != proof.num_components
        || proof.claimed_sums.len() != proof.num_components
    {
        return Err("proof component/log-size/claimed-sum lengths differ".into());
    }
    if let Some(&offending) = proof
        .log_sizes
        .iter()
        .find(|&&log_size| log_size < MIN_PROOF_LOG_SIZE || log_size > max_log_size)
    {
        return Err(format!(
            "proof log_size {offending} is outside {MIN_PROOF_LOG_SIZE}..={max_log_size}"
        ));
    }

    let config = proof.pcs_config;
    if stark.config != config {
        return Err("outer and embedded pcs_config differ".into());
    }
    let fri = config.fri_config;
    if !(1..=16).contains(&fri.log_blowup_factor) {
        return Err("FRI log blowup is outside Stwo's 1..=16 bound".into());
    }
    if fri.log_last_layer_degree_bound > 10 {
        return Err("FRI last-layer degree bound exceeds 10".into());
    }
    // Stwo 2.x exposes a configurable field but implements one-fold layers;
    // admitting another value reaches assumptions and shifts not audited here.
    if fri.fold_step != 1 {
        return Err("FRI fold_step must equal the protocol value 1".into());
    }
    if !(1..=MAX_FRI_QUERIES).contains(&fri.n_queries) {
        return Err(format!("FRI query count is outside 1..={MAX_FRI_QUERIES}"));
    }
    if config.pow_bits > 31 {
        return Err("PCS proof-of-work bits exceed the supported bound 31".into());
    }

    let max_trace_log = proof.log_sizes.iter().copied().max().unwrap_or(0);
    let max_extended_log = max_trace_log
        .checked_add(fri.log_blowup_factor)
        .ok_or_else(|| "trace log size plus FRI blowup overflows".to_string())?;
    if max_extended_log > MAX_EXTENDED_LOG_SIZE {
        return Err(format!(
            "extended trace log size {max_extended_log} exceeds {MAX_EXTENDED_LOG_SIZE}"
        ));
    }
    if let Some(lifting) = config.lifting_log_size
        && (lifting < max_extended_log || lifting > MAX_EXTENDED_LOG_SIZE)
    {
        return Err(format!(
            "PCS lifting log size {lifting} does not cover {max_extended_log} within the protocol bound"
        ));
    }

    if stark.commitments.len() != PROOF_COMMITMENT_TREE_COUNT
        || stark.sampled_values.len() != PROOF_COMMITMENT_TREE_COUNT
        || stark.decommitments.len() != PROOF_COMMITMENT_TREE_COUNT
        || stark.queried_values.len() != PROOF_COMMITMENT_TREE_COUNT
    {
        return Err(format!(
            "Stwo proof must contain exactly {PROOF_COMMITMENT_TREE_COUNT} commitment trees"
        ));
    }

    for columns in stark.sampled_values.iter() {
        if columns.len() > MAX_PROOF_COLUMNS_PER_TREE {
            return Err(format!(
                "sampled-value column count {} exceeds protocol bound {MAX_PROOF_COLUMNS_PER_TREE}",
                columns.len()
            ));
        }
        if columns
            .iter()
            .any(|samples| samples.len() > MAX_PROOF_SAMPLES_PER_COLUMN)
        {
            return Err("sample count per column exceeds protocol bound".into());
        }
    }
    for columns in stark.queried_values.iter() {
        if columns.len() > MAX_PROOF_COLUMNS_PER_TREE {
            return Err(format!(
                "queried-value column count {} exceeds protocol bound {MAX_PROOF_COLUMNS_PER_TREE}",
                columns.len()
            ));
        }
        if columns.iter().any(|values| values.len() > fri.n_queries) {
            return Err("queried-value count exceeds configured FRI queries".into());
        }
    }
    if stark
        .decommitments
        .iter()
        .any(|decommitment| decommitment.hash_witness.len() > MAX_MERKLE_WITNESS_HASHES)
    {
        return Err("trace Merkle witness exceeds protocol bound".into());
    }

    let fri_proof = &stark.fri_proof;
    if fri_proof.inner_layers.len() > MAX_EXTENDED_LOG_SIZE as usize {
        return Err("FRI inner-layer count exceeds protocol bound".into());
    }
    let layer_is_bounded = |layer: &stwo::core::fri::FriLayerProof<H>| {
        layer.fri_witness.len() <= MAX_FRI_QUERIES
            && layer.decommitment.hash_witness.len() <= MAX_MERKLE_WITNESS_HASHES
    };
    if !layer_is_bounded(&fri_proof.first_layer)
        || fri_proof
            .inner_layers
            .iter()
            .any(|layer| !layer_is_bounded(layer))
    {
        return Err("FRI layer witness exceeds protocol bound".into());
    }
    let owned_bytes = proof_owned_bytes_of(proof, stark).ok_or_else(|| {
        alloc::format!("proof nested payload exceeds {MAX_PROOF_OWNED_BYTES} bytes")
    })?;

    let expected_last_len = 1usize
        .checked_shl(fri.log_last_layer_degree_bound)
        .ok_or_else(|| "FRI last-layer length shift overflows".to_string())?;
    let coefficients_len = fri_proof.last_layer_poly.iter().count();
    if coefficients_len != expected_last_len {
        return Err(format!(
            "FRI last-layer polynomial has {} coefficients, expected {expected_last_len}",
            coefficients_len
        ));
    }
    if !proof_fields_are_canonical(proof, stark) {
        return Err("proof contains a noncanonical M31 field limb".into());
    }
    Ok(owned_bytes)
}

fn base_field_is_canonical(value: &stwo::core::fields::m31::BaseField) -> bool {
    value.0 < stwo::core::fields::m31::P
}

fn secure_field_is_canonical(value: &SecureField) -> bool {
    value.to_m31_array().iter().all(base_field_is_canonical)
}

fn proof_fields_are_canonical<H: MerkleHasherLifted>(proof: &Proof, stark: &StarkProof<H>) -> bool
where
    H::Hash: ProofHash,
{
    proof.claimed_sums.iter().all(secure_field_is_canonical)
        && stark_fields_are_canonical(stark, ProofHash::is_canonical)
}

/// Whether every M31 limb a Stark proof carries is canonical, below the
/// modulus: its sampled and queried values, its FRI witnesses and last
/// layer, and its hashes as `hash_is_canonical` judges them. A limb at or
/// above the modulus decodes, and a reducing verifier may treat it as its
/// residue, so refusing one keeps a proof's bytes its only encoding.
pub fn stark_fields_are_canonical<H: MerkleHasherLifted>(
    stark: &StarkProof<H>,
    hash_is_canonical: impl Fn(&H::Hash) -> bool,
) -> bool {
    stark.commitments.iter().all(&hash_is_canonical)
        && stark
            .sampled_values
            .iter()
            .flatten()
            .flatten()
            .all(secure_field_is_canonical)
        && stark
            .queried_values
            .iter()
            .flatten()
            .flatten()
            .all(base_field_is_canonical)
        && stark
            .decommitments
            .iter()
            .flat_map(|decommitment| &decommitment.hash_witness)
            .all(&hash_is_canonical)
        && core::iter::once(&stark.fri_proof.first_layer)
            .chain(&stark.fri_proof.inner_layers)
            .all(|layer| {
                hash_is_canonical(&layer.commitment)
                    && layer.fri_witness.iter().all(secure_field_is_canonical)
                    && layer
                        .decommitment
                        .hash_witness
                        .iter()
                        .all(&hash_is_canonical)
            })
        && stark
            .fri_proof
            .last_layer_poly
            .iter()
            .all(secure_field_is_canonical)
}

/// Checked aggregate size of all proof-owned nested vector elements.
///
/// This is a post-decode heap-payload bound (transport must still cap bytes
/// before Serde). Returning `None` means arithmetic overflow or a payload over
/// [`MAX_PROOF_OWNED_BYTES`]. Vec headers are included so thousands of empty
/// attacker-controlled columns are not free in the accounting.
pub fn proof_owned_bytes(proof: &Proof) -> Option<usize> {
    match &proof.stark_proof {
        StarkProofAny::Blake2s(stark) => proof_owned_bytes_of(proof, stark),
        StarkProofAny::Poseidon2M31(stark) => proof_owned_bytes_of(proof, stark),
        StarkProofAny::Blake2sM31(stark) => proof_owned_bytes_of(proof, stark),
    }
}

fn proof_owned_bytes_of<H: MerkleHasherLifted>(
    proof: &Proof,
    stark: &StarkProof<H>,
) -> Option<usize> {
    use core::mem::size_of;

    fn add<T>(total: &mut usize, len: usize) -> Option<()> {
        *total = total.checked_add(len.checked_mul(size_of::<T>())?)?;
        (*total <= MAX_PROOF_OWNED_BYTES).then_some(())
    }

    let mut total = size_of::<Proof>();
    add::<SecureField>(&mut total, proof.claimed_sums.len())?;
    add::<u32>(&mut total, proof.log_sizes.len())?;
    add::<H::Hash>(&mut total, stark.commitments.len())?;
    add::<Vec<Vec<SecureField>>>(&mut total, stark.sampled_values.len())?;
    for tree in stark.sampled_values.iter() {
        add::<Vec<SecureField>>(&mut total, tree.len())?;
        for column in tree {
            add::<SecureField>(&mut total, column.len())?;
        }
    }
    add::<Vec<Vec<stwo::core::fields::m31::BaseField>>>(&mut total, stark.queried_values.len())?;
    for tree in stark.queried_values.iter() {
        add::<Vec<stwo::core::fields::m31::BaseField>>(&mut total, tree.len())?;
        for column in tree {
            add::<stwo::core::fields::m31::BaseField>(&mut total, column.len())?;
        }
    }
    add::<stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted<H>>(
        &mut total,
        stark.decommitments.len(),
    )?;
    for decommitment in stark.decommitments.iter() {
        add::<H::Hash>(&mut total, decommitment.hash_witness.len())?;
    }
    let fri = &stark.fri_proof;
    add::<SecureField>(&mut total, fri.last_layer_poly.iter().count())?;
    add::<stwo::core::fri::FriLayerProof<H>>(&mut total, fri.inner_layers.len())?;
    for layer in core::iter::once(&fri.first_layer).chain(&fri.inner_layers) {
        add::<SecureField>(&mut total, layer.fri_witness.len())?;
        add::<H::Hash>(&mut total, layer.decommitment.hash_witness.len())?;
    }
    Some(total)
}

/// Mutable wrapper around [`preflight_proof_structure_readonly`] that also
/// normalizes Stwo's private cached last-layer `log_size` from the already
/// bounded visible coefficient vector. This must happen before handing a
/// serde-created proof to Stwo. Returns the proof's format.
pub fn preflight_proof_structure(
    proof: &mut Proof,
    max_log_size: u32,
) -> Result<&'static Format, alloc::string::String> {
    let (format, _bounded_bytes) = preflight_proof_structure_readonly(proof, max_log_size)?;
    match &mut proof.stark_proof {
        StarkProofAny::Blake2s(stark) => normalize_last_layer(stark),
        StarkProofAny::Poseidon2M31(stark) => normalize_last_layer(stark),
        StarkProofAny::Blake2sM31(stark) => normalize_last_layer(stark),
    }
    Ok(format)
}

fn normalize_last_layer<H: MerkleHasherLifted>(stark: &mut StarkProof<H>) {
    let coefficients: Vec<SecureField> = stark.fri_proof.last_layer_poly.iter().copied().collect();
    stark.0.fri_proof.last_layer_poly = LinePoly::new(coefficients);
}

/// Derived safe dimensions of a structurally valid Stwo statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofProtocolShape {
    pub lifting_log_size: u32,
    pub max_log_degree_bound: u32,
    /// Number of sorted/deduplicated query positions represented by every
    /// non-empty queried-value column. Callers compare this with a safe replay
    /// of Fiat–Shamir query sampling before entering Stwo.
    pub query_count: usize,
}

/// Derive Stwo's lifted/composition degree pair with checked arithmetic and
/// the M31 canonical-coset bound enforced before either value reaches a shift
/// or domain constructor.
pub fn derive_protocol_degree_shape(
    config: &PcsConfig,
    composition_log_degree_bound: u32,
) -> Result<(u32, u32), alloc::string::String> {
    use alloc::string::ToString;

    let split_composition_log = composition_log_degree_bound
        .checked_sub(1)
        .ok_or_else(|| "composition log degree cannot be split".to_string())?;
    let required_lifting = split_composition_log
        .checked_add(config.fri_config.log_blowup_factor)
        .ok_or_else(|| "composition log degree plus blowup overflows".to_string())?;
    if config
        .lifting_log_size
        .is_some_and(|explicit| explicit != required_lifting)
    {
        return Err(alloc::format!(
            "explicit lifting log size must equal the AIR-derived value {required_lifting}"
        ));
    }
    let lifting_log_size = required_lifting;
    if lifting_log_size > MAX_EXTENDED_LOG_SIZE {
        return Err(alloc::format!(
            "lifting log size {lifting_log_size} does not cover composition domain {required_lifting}"
        ));
    }
    let max_log_degree_bound = lifting_log_size
        .checked_sub(config.fri_config.log_blowup_factor)
        .ok_or_else(|| "lifting log size is below FRI blowup".to_string())?;
    if max_log_degree_bound < MIN_PROOF_LOG_SIZE {
        return Err(alloc::format!(
            "maximum polynomial log degree {max_log_degree_bound} is below {MIN_PROOF_LOG_SIZE}"
        ));
    }
    Ok((lifting_log_size, max_log_degree_bound))
}

/// Validate all nested Stwo vector dimensions against the exact AIR-derived
/// tree layout. `expected_log_sizes` and `expected_sample_counts` include all
/// four trees, including the eight split-composition columns.
pub fn preflight_proof_dimensions<H: MerkleHasherLifted>(
    config: &PcsConfig,
    stark: &StarkProof<H>,
    expected_log_sizes: &[alloc::vec::Vec<u32>],
    expected_sample_counts: &[alloc::vec::Vec<usize>],
    composition_log_degree_bound: u32,
) -> Result<ProofProtocolShape, alloc::string::String> {
    use alloc::{format, string::ToString};

    if expected_log_sizes.len() != PROOF_COMMITMENT_TREE_COUNT
        || expected_sample_counts.len() != PROOF_COMMITMENT_TREE_COUNT
    {
        return Err("AIR-derived proof layout must contain exactly four trees".into());
    }
    let fri = config.fri_config;
    let (lifting_log_size, max_log_degree_bound) =
        derive_protocol_degree_shape(config, composition_log_degree_bound)?;

    for (tree_index, logs) in expected_log_sizes.iter().enumerate() {
        if logs.len() > MAX_PROOF_COLUMNS_PER_TREE {
            return Err(format!(
                "AIR-derived tree {tree_index} column count exceeds protocol bound"
            ));
        }
        for &log_size in logs {
            if log_size < MIN_PROOF_LOG_SIZE {
                return Err(format!(
                    "tree {tree_index} column log size {log_size} is below {MIN_PROOF_LOG_SIZE}"
                ));
            }
            let extended = log_size
                .checked_add(fri.log_blowup_factor)
                .ok_or_else(|| "column log size plus blowup overflows".to_string())?;
            if extended > lifting_log_size || extended > MAX_EXTENDED_LOG_SIZE {
                return Err(format!(
                    "tree {tree_index} column log size {log_size} is incompatible with lifting {lifting_log_size}"
                ));
            }
        }
    }

    let expected_composition_logs = alloc::vec![max_log_degree_bound; 8];
    if expected_log_sizes[PROOF_COMMITMENT_TREE_COUNT - 1] != expected_composition_logs {
        return Err("composition tree must contain eight exact split columns".into());
    }
    if expected_sample_counts[PROOF_COMMITMENT_TREE_COUNT - 1] != alloc::vec![1; 8] {
        return Err("composition tree must contain one OODS sample per split column".into());
    }

    let mut common_query_count = None;
    for tree_index in 0..PROOF_COMMITMENT_TREE_COUNT {
        let logs = &expected_log_sizes[tree_index];
        let samples = &expected_sample_counts[tree_index];
        if samples.len() != logs.len()
            || stark.sampled_values[tree_index].len() != logs.len()
            || stark.queried_values[tree_index].len() != logs.len()
        {
            return Err(format!(
                "tree {tree_index} column dimensions differ from the AIR-derived layout"
            ));
        }
        for (column, &expected_samples) in stark.sampled_values[tree_index].iter().zip(samples) {
            if column.len() != expected_samples {
                return Err(format!(
                    "tree {tree_index} OODS sample dimensions differ from the AIR mask"
                ));
            }
        }
        for column in &stark.queried_values[tree_index] {
            let query_count = column.len();
            if let Some(expected) = common_query_count {
                if query_count != expected {
                    return Err("queried-value columns have inconsistent row counts".into());
                }
            } else {
                common_query_count = Some(query_count);
            }
        }
    }
    let query_count =
        common_query_count.ok_or_else(|| "proof contains no queried-value columns".to_string())?;
    if query_count == 0 || query_count > fri.n_queries {
        return Err("deduplicated FRI query count is outside configured bounds".into());
    }

    let expected_inner_layers = max_log_degree_bound
        .checked_sub(1)
        .and_then(|after_circle_fold| {
            after_circle_fold.checked_sub(fri.log_last_layer_degree_bound)
        })
        .ok_or_else(|| "FRI last layer exceeds the folded composition bound".to_string())?
        as usize;
    if stark.fri_proof.inner_layers.len() != expected_inner_layers {
        return Err(format!(
            "FRI inner-layer count {}, expected {expected_inner_layers}",
            stark.fri_proof.inner_layers.len()
        ));
    }

    Ok(ProofProtocolShape {
        lifting_log_size,
        max_log_degree_bound,
        query_count,
    })
}

/// Safely replay the Stwo verifier transcript from the point immediately
/// after the interaction-tree commitment and return the exact number of
/// sorted/deduplicated FRI queries. All proof-owned vector dimensions must
/// first pass [`preflight_proof_structure`] and
/// [`preflight_proof_dimensions`]. This closes the remaining upstream
/// `MerkleVerifierLifted` assumption that every queried-value column has
/// exactly one value per deduplicated query.
pub fn expected_fiat_shamir_query_count<MC: MerkleChannel>(
    transcript_after_interaction: &MC::C,
    stark_proof: &StarkProof<MC::H>,
    config: &PcsConfig,
    shape: ProofProtocolShape,
    expected_log_sizes: &[alloc::vec::Vec<u32>],
) -> Result<usize, alloc::string::String> {
    use stwo::core::pcs::utils::prepare_preprocessed_query_positions;

    let positions = replay_query_positions::<MC>(
        &mut transcript_after_interaction.clone(),
        stark_proof,
        config,
        shape.lifting_log_size,
    )?;
    if positions.len() != shape.query_count {
        return Err(alloc::string::String::from(
            "queried-value rows differ from Fiat-Shamir query positions",
        ));
    }

    let preprocessed_logs = expected_log_sizes
        .first()
        .ok_or_else(|| alloc::string::String::from("missing preprocessed tree shape"))?;
    let preprocessed_max_extended = match preprocessed_logs.iter().copied().max() {
        Some(log_size) => log_size
            .checked_add(config.fri_config.log_blowup_factor)
            .ok_or_else(|| {
                alloc::string::String::from("preprocessed tree height arithmetic overflow")
            })?,
        None => 0,
    };
    let preprocessed_height = config.lifting_log_size.unwrap_or(preprocessed_max_extended);
    let remapped = prepare_preprocessed_query_positions(
        &positions,
        shape.lifting_log_size,
        preprocessed_height,
    );
    validate_preprocessed_query_values(&remapped, &stark_proof.queried_values[0])?;
    Ok(positions.len())
}

/// Replay the pinned Stwo verifier's transcript on `channel`, from just after
/// the interaction-tree commitment through the FRI query draw, in its order:
/// `verify_ex`'s head, then `CommitmentSchemeVerifier::verify_values` and
/// `FriVerifier::commit`. Returns the sorted, deduplicated query positions and
/// leaves `channel` where the verifier's stands after its draw. The
/// proof-of-work check reads the channel without changing it, so only the
/// nonce's mix is replayed.
pub(super) fn replay_query_positions<MC: MerkleChannel>(
    channel: &mut MC::C,
    stark_proof: &StarkProof<MC::H>,
    config: &PcsConfig,
    lifting_log_size: u32,
) -> Result<Vec<usize>, alloc::string::String> {
    use stwo::core::{circle::CirclePoint, queries::draw_queries};

    // `verify_ex`: the composition coefficient, the composition root, then the
    // OODS point.
    let _ = channel.draw_secure_felt();
    let composition = stark_proof
        .commitments
        .get(PROOF_COMMITMENT_TREE_COUNT - 1)
        .copied()
        .ok_or_else(|| alloc::string::String::from("missing composition commitment"))?;
    MC::mix_root(channel, composition);
    let _ = CirclePoint::<SecureField>::get_random_point(channel);

    // `verify_values`: every sampled value in one mix, flattened across trees
    // and columns, then the DEEP coefficient.
    let sampled_values: Vec<SecureField> = stark_proof
        .sampled_values
        .iter()
        .flatten()
        .flatten()
        .copied()
        .collect();
    channel.mix_felts(&sampled_values);
    let _ = channel.draw_secure_felt();

    // `FriVerifier::commit`: each layer's root and folding coefficient, then
    // the last layer.
    let fri = &stark_proof.fri_proof;
    for commitment in core::iter::once(fri.first_layer.commitment)
        .chain(fri.inner_layers.iter().map(|layer| layer.commitment))
    {
        MC::mix_root(channel, commitment);
        let _ = channel.draw_secure_felt();
    }
    channel.mix_felts(&fri.last_layer_poly);

    channel.mix_u64(stark_proof.proof_of_work);
    let mut positions = draw_queries(channel, lifting_log_size, config.fri_config.n_queries);
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

/// Every preprocessed position read more than once must carry the same
/// values each time; Stwo's Merkle verifier asserts it. Positions folded
/// onto a preprocessed tree below the lifting height can repeat anywhere in
/// the list, so the reads are compared in position order.
fn validate_preprocessed_query_values(
    remapped_positions: &[usize],
    columns: &[alloc::vec::Vec<stwo::core::fields::m31::BaseField>],
) -> Result<(), alloc::string::String> {
    let mut reads: alloc::vec::Vec<usize> = (0..remapped_positions.len()).collect();
    reads.sort_by_key(|&read| remapped_positions[read]);
    for pair in reads.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        if remapped_positions[first] == remapped_positions[second]
            && columns.iter().any(|column| {
                column
                    .get(first)
                    .zip(column.get(second))
                    .is_none_or(|(left, right)| left != right)
            })
        {
            return Err(alloc::string::String::from(
                "duplicate preprocessed query positions carry different values",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod hostile_query_tests {
    use super::validate_preprocessed_query_values;
    use stwo::core::fields::m31::BaseField;

    #[test]
    fn duplicate_preprocessed_queries_are_checked_without_panicking() {
        let hostile = std::panic::catch_unwind(|| {
            validate_preprocessed_query_values(
                &[2, 2],
                &[alloc::vec![
                    BaseField::from_u32_unchecked(1),
                    BaseField::from_u32_unchecked(2),
                ]],
            )
        });
        assert!(hostile.is_ok());
        assert!(hostile.unwrap().is_err());

        let apart = std::panic::catch_unwind(|| {
            validate_preprocessed_query_values(
                &[2, 0, 2],
                &[alloc::vec![
                    BaseField::from_u32_unchecked(1),
                    BaseField::from_u32_unchecked(5),
                    BaseField::from_u32_unchecked(2),
                ]],
            )
        });
        assert!(apart.is_ok());
        assert!(apart.unwrap().is_err());

        validate_preprocessed_query_values(
            &[2, 0, 2],
            &[alloc::vec![
                BaseField::from_u32_unchecked(1),
                BaseField::from_u32_unchecked(5),
                BaseField::from_u32_unchecked(1),
            ]],
        )
        .unwrap();
        validate_preprocessed_query_values(
            &[2, 2],
            &[alloc::vec![
                BaseField::from_u32_unchecked(1),
                BaseField::from_u32_unchecked(1),
            ]],
        )
        .unwrap();
    }
}
