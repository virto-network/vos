//! A proof malformed in its structure is an error, never a panic.

use super::*;

/// The structure: a proof malformed in any field of its structure is refused
/// with an error, never a panic: a tree, a column, a sample, a queried
/// value, a witness hash or a FRI layer more or fewer, another last layer,
/// claimed sums or log sizes of another count, another configuration.
#[test]
fn a_malformed_proof_is_an_error_never_a_panic() {
    let format = format();
    let finalized = circuit(14);
    let (proof, _) =
        prove::<Blake2bMerkleChannel>(&format, &finalized, MaskRng::Seeded(14)).expect("proves");
    verify::<Blake2bMerkleChannel>(&format, &proof).expect("verifies");
    let cases = malformations();
    let mut failures = Vec::new();
    // The verifier pins the format's log sizes and lays its set out at
    // them; a proof's own are its claim's.
    let layout = wrap_layout(&proof.log_sizes);
    let pinned = verifier_format(&format, &proof.log_sizes, &layout).expect("a masked format");
    let verified = |proof: &P, log_sizes: &[u32], claimed_sums: &[SecureField]| {
        let public_sum = |relation: &GateRelation| public_sum(&proof.outputs, relation);
        verify_masked::<Blake2bMerkleChannel, WrapComponents>(
            &pinned,
            &Claim {
                log_sizes,
                circuit: None,
                public: &proof.outputs,
                public_sum: Some(&public_sum),
                bound_sums: None,
                interaction_pow: proof.interaction_pow,
                claimed_sums,
            },
            &layout,
            proof.stark_proof.clone(),
        )
    };
    let mut outcome =
        |name: &str, run: &dyn Fn() -> Result<(), Error>| match catch_unwind(AssertUnwindSafe(run))
        {
            Ok(Err(error)) => eprintln!("{name}: {error}"),
            Ok(Ok(())) => failures.push(format!("{name}: accepted")),
            Err(_) => failures.push(format!("{name}: panicked")),
        };
    for (name, mutation) in &cases {
        let mut malformed = proof.clone();
        mutation(&mut malformed);
        let claimed = malformed.claimed_sums;
        outcome(name, &|| {
            verified(&malformed, &malformed.log_sizes, &claimed)
        });
    }
    let pinned = proof.log_sizes;
    let sums = proof.claimed_sums;
    outcome("claimed sums fewer", &|| {
        verified(&proof, &pinned, &sums[..2])
    });
    let more = [sums[0], sums[1], sums[2], SecureField::zero()];
    outcome("claimed sums more", &|| verified(&proof, &pinned, &more));
    outcome("log sizes fewer", &|| verified(&proof, &pinned[..2], &sums));
    let longer = [pinned[0], pinned[1], pinned[2], pinned[2]];
    outcome("log sizes more", &|| verified(&proof, &longer, &sums));
    outcome("log sizes zero", &|| verified(&proof, &[0; 3], &sums));
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A proof on the Blake2b-256 channel, as a malformation takes it.
type P = Proof<Blake2bMerkleChannel>;

/// A change to a proof's structure.
type Mutation = Box<dyn Fn(&mut P)>;

/// Every malformation of a proof's structure, by name: a tree, a column, a
/// sample, a queried value, a witness hash or a FRI layer more or fewer,
/// another last layer, log sizes of another component, another
/// configuration.
fn malformations() -> Vec<(String, Mutation)> {
    let mut cases: Vec<(String, Mutation)> = Vec::new();
    let mut case = |name: String, mutation: Mutation| cases.push((name, mutation));
    case(
        "a commitment fewer".into(),
        Box::new(|p| {
            p.stark_proof.0.commitments.pop();
        }),
    );
    case(
        "a commitment more".into(),
        Box::new(|p| {
            let root = p.stark_proof.0.commitments[0];
            p.stark_proof.0.commitments.push(root);
        }),
    );
    for tree in 0..4 {
        case(
            format!("tree {tree}'s samples dropped"),
            Box::new(move |p| {
                p.stark_proof.0.sampled_values.remove(tree);
            }),
        );
        case(
            format!("tree {tree}'s queried values dropped"),
            Box::new(move |p| {
                p.stark_proof.0.queried_values.remove(tree);
            }),
        );
        case(
            format!("tree {tree}'s decommitment dropped"),
            Box::new(move |p| {
                p.stark_proof.0.decommitments.remove(tree);
            }),
        );
        case(
            format!("tree {tree}: a sampled column fewer"),
            Box::new(move |p| {
                p.stark_proof.0.sampled_values[tree].pop();
            }),
        );
        case(
            format!("tree {tree}: a sampled column more"),
            Box::new(move |p| p.stark_proof.0.sampled_values[tree].push(vec![SecureField::one()])),
        );
        case(
            format!("tree {tree}: a sample more on its first column"),
            Box::new(move |p| p.stark_proof.0.sampled_values[tree][0].push(SecureField::one())),
        );
        case(
            format!("tree {tree}: its first column's samples cleared"),
            Box::new(move |p| p.stark_proof.0.sampled_values[tree][0].clear()),
        );
        case(
            format!("tree {tree}: a queried column fewer"),
            Box::new(move |p| {
                p.stark_proof.0.queried_values[tree].pop();
            }),
        );
        case(
            format!("tree {tree}: a queried column more"),
            Box::new(move |p| {
                let column = p.stark_proof.0.queried_values[tree][0].clone();
                p.stark_proof.0.queried_values[tree].push(column)
            }),
        );
        case(
            format!("tree {tree}: a queried value fewer on its first column"),
            Box::new(move |p| {
                p.stark_proof.0.queried_values[tree][0].pop();
            }),
        );
        case(
            format!("tree {tree}: a queried value more on its first column"),
            Box::new(move |p| p.stark_proof.0.queried_values[tree][0].push(BaseField::one())),
        );
        case(
            format!("tree {tree}: a queried value fewer on every column"),
            Box::new(move |p| {
                for column in &mut p.stark_proof.0.queried_values[tree] {
                    column.pop();
                }
            }),
        );
        case(
            format!("tree {tree}: a queried value more on every column"),
            Box::new(move |p| {
                for column in &mut p.stark_proof.0.queried_values[tree] {
                    column.push(BaseField::one());
                }
            }),
        );
        case(
            format!("tree {tree}: a witness hash fewer"),
            Box::new(move |p| {
                p.stark_proof.0.decommitments[tree].hash_witness.pop();
            }),
        );
        case(
            format!("tree {tree}: a witness hash more"),
            Box::new(move |p| {
                let root = p.stark_proof.0.commitments[tree];
                p.stark_proof.0.decommitments[tree].hash_witness.push(root)
            }),
        );
    }
    case(
        "FRI's first layer: a witness value fewer".into(),
        Box::new(|p| {
            p.stark_proof.0.fri_proof.first_layer.fri_witness.pop();
        }),
    );
    case(
        "FRI's first layer: a witness value more".into(),
        Box::new(|p| {
            p.stark_proof
                .0
                .fri_proof
                .first_layer
                .fri_witness
                .push(SecureField::one())
        }),
    );
    case(
        "FRI's first layer: a witness hash fewer".into(),
        Box::new(|p| {
            p.stark_proof
                .0
                .fri_proof
                .first_layer
                .decommitment
                .hash_witness
                .pop();
        }),
    );
    case(
        "FRI: an inner layer fewer".into(),
        Box::new(|p| {
            p.stark_proof.0.fri_proof.inner_layers.pop();
        }),
    );
    case(
        "FRI: an inner layer more".into(),
        Box::new(|p| {
            let layer = p.stark_proof.0.fri_proof.first_layer.clone();
            p.stark_proof.0.fri_proof.inner_layers.push(layer)
        }),
    );
    case(
        "FRI: an inner layer's witness value fewer".into(),
        Box::new(|p| {
            if let Some(layer) = p.stark_proof.0.fri_proof.inner_layers.first_mut() {
                layer.fri_witness.pop();
            }
        }),
    );
    case(
        "FRI: a last layer of twice the coefficients".into(),
        Box::new(|p| {
            let coefficients = p.stark_proof.0.fri_proof.last_layer_poly.len();
            p.stark_proof.0.fri_proof.last_layer_poly =
                LinePoly::new(vec![SecureField::one(); 2 * coefficients]);
        }),
    );
    case(
        "another PoW nonce".into(),
        Box::new(|p| p.stark_proof.0.proof_of_work ^= 1),
    );
    case(
        "another blowup".into(),
        Box::new(|p| p.stark_proof.0.config.fri_config.log_blowup_factor += 1),
    );
    case(
        "other queries".into(),
        Box::new(|p| p.stark_proof.0.config.fri_config.n_queries += 1),
    );
    case(
        "another PoW".into(),
        Box::new(|p| p.stark_proof.0.config.pow_bits += 1),
    );
    case(
        "log sizes of another component".into(),
        Box::new(|p| p.log_sizes[2] += 1),
    );
    case(
        "log sizes at the field's bound".into(),
        Box::new(|p| p.log_sizes = [31; 3]),
    );
    cases
}
