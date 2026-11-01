//! A proof's shape is the format's and its coins'.

use super::*;

/// The witness hashes a lifted Merkle tree of `height` decommits at
/// `positions`: a node's sibling whenever the sibling is not itself
/// queried, at every level.
fn merkle_witness(positions: &[usize], height: u32) -> usize {
    let mut layer: Vec<usize> = positions.to_vec();
    layer.sort_unstable();
    layer.dedup();
    let mut witness = 0;
    for _ in 0..height {
        let mut parents = Vec::with_capacity(layer.len());
        for pair in layer.chunk_by(|a, b| a ^ 1 == *b) {
            witness += usize::from(pair.len() == 1);
            parents.push(pair[0] >> 1);
        }
        layer = parents;
    }
    witness
}

/// The lengths a proof's layout varies by: each tree's queried values a
/// column and witness hashes, and each FRI layer's witness values and
/// hashes, the last layer's coefficients.
#[derive(Debug, PartialEq, Eq)]
struct Lengths {
    queried: Vec<Vec<usize>>,
    witness_hashes: Vec<usize>,
    fri: Vec<(usize, usize)>,
    last_layer: usize,
}

fn lengths_of<MC: MerkleChannel>(stark: &stwo::core::proof::StarkProof<MC::H>) -> Lengths {
    let fri = &stark.fri_proof;
    Lengths {
        queried: stark
            .queried_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).collect())
            .collect(),
        witness_hashes: stark
            .decommitments
            .iter()
            .map(|decommitment| decommitment.hash_witness.len())
            .collect(),
        fri: std::iter::once(&fri.first_layer)
            .chain(&fri.inner_layers)
            .map(|layer| {
                (
                    layer.fri_witness.len(),
                    layer.decommitment.hash_witness.len(),
                )
            })
            .collect(),
        last_layer: fri.last_layer_poly.len(),
    }
}

/// The lengths a proof of `format` over the set laid out as `layout` has at
/// its own Fiat–Shamir coins: its query positions replayed from the
/// transcript, each tree's witness hashes counted at them, and FRI's
/// lengths those of a proof of the zero codeword decommitted at them.
fn lengths_at_coins<MC: MerkleChannel>(format: &Format, proof: &Proof<MC>) -> Lengths
where
    SimdBackend: BackendForChannel<MC>,
{
    let layout = wrap_layout(&proof.log_sizes);
    let public_sum = |relation: &GateRelation| public_sum(&proof.outputs, relation);
    let pinned = verifier_format(format, &proof.log_sizes, &layout).expect("a masked format");
    let claim = Claim {
        log_sizes: &proof.log_sizes,
        circuit: None,
        public: &proof.outputs,
        public_sum: Some(&public_sum),
        bound_sums: None,
        interaction_pow: proof.interaction_pow,
        claimed_sums: &proof.claimed_sums,
    };
    let stark = &proof.stark_proof;
    let replayed = replay::<MC, WrapComponents>(&pinned, &claim, &layout, stark).expect("replays");
    let mut channel = replayed.channel;
    let config = format.pcs_config();
    let sampled = &stark.sampled_values;
    channel.mix_felts(&sampled.clone().flatten_cols());
    let values = sampled
        .iter()
        .flatten()
        .map(|column| deep_values_of_column(column.len()))
        .sum();
    DeepCoefficients::draw(&mut channel, config.deep_batching, values);
    let heights: Vec<u32> = replayed
        .scheme
        .trees
        .iter()
        .map(|tree| tree.height)
        .collect();
    let lifting = *heights.last().expect("four trees");
    let bound = CirclePolyDegreeBound::new(lifting - config.fri_config.log_blowup_factor);
    let mut fri = FriVerifier::<MC>::commit(
        &mut channel,
        config.fri_config,
        stark.fri_proof.clone(),
        bound,
    )
    .expect("FRI's layers");
    assert!(channel.verify_pow_nonce(config.pow_bits, stark.proof_of_work));
    channel.mix_u64(stark.proof_of_work);
    let positions = fri.sample_query_positions(&mut channel);

    let preprocessed = prepare_preprocessed_query_positions(&positions, lifting, heights[0]);
    let domain = CanonicCoset::new(lifting).circle_domain();
    let twiddles = SimdBackend::precompute_twiddles(domain.half_coset);
    let zero =
        SecureEvaluation::<SimdBackend, _>::new(domain, SecureColumnByCoords::zeros(1 << lifting));
    let zero_fri = FriProver::<SimdBackend, MC>::commit(
        &mut MC::C::default(),
        config.fri_config,
        &zero,
        &twiddles,
    )
    .decommit_on_queries(&Queries {
        positions: positions.clone(),
        log_domain_size: lifting,
    })
    .proof;
    let fri_lengths = lengths_of::<MC>(&stwo::core::proof::StarkProof(
        stwo::core::pcs::quotients::CommitmentSchemeProof {
            fri_proof: zero_fri,
            ..stark.0.clone()
        },
    ));
    Lengths {
        queried: stark
            .queried_values
            .iter()
            .map(|tree| vec![positions.len(); tree.len()])
            .collect(),
        witness_hashes: heights
            .iter()
            .enumerate()
            .map(|(tree, &height)| {
                let at = if tree == 0 { &preprocessed } else { &positions };
                merkle_witness(at, height)
            })
            .collect(),
        fri: fri_lengths.fri,
        last_layer: fri_lengths.last_layer,
    }
}

/// The shape public: a proof's shape is public, the format's and its
/// Fiat–Shamir coins' alone: every length its layout varies by (each
/// column's queried values, each tree's and FRI layer's witness hashes,
/// FRI's witness values) is what its own query positions give, counted for
/// an all-zero witness, for proofs of a zero witness and of a random one
/// alike; every other count is the format's pin (`check_shape`,
/// `format::MASKED_WRAP`'s own tests).
#[test]
fn the_shape_is_the_format_and_the_coins() {
    let format = format();
    let mut distinct = BTreeSet::new();
    for witness in [PrivateWitness::zero(), PrivateWitness::random(17)] {
        let finalized = private_circuit(&witness);
        for seed in 0..6 {
            let (proof, _) =
                prove::<Blake2bMerkleChannel>(&format, &finalized, MaskRng::Seeded(seed))
                    .expect("proves");
            let lengths = lengths_of::<Blake2bMerkleChannel>(&proof.stark_proof);
            assert_eq!(
                lengths,
                lengths_at_coins::<Blake2bMerkleChannel>(&format, &proof),
                "seed {seed}"
            );
            distinct.insert(format!("{lengths:?}"));
        }
    }
    eprintln!(
        "12 proofs, {} distinct shapes, each its coins'",
        distinct.len()
    );
}
