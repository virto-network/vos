//! Each piece of the in-AIR verifier on recorded data.

use super::*;

#[test]
fn the_bits_refuse_a_noncanonical_word_and_a_short_pow() {
    // Zero's other decomposition, thirty-one ones, recomposes it but is
    // refused.
    let mut context = Context::<SecureField>::new().lenient();
    let word = context.guess(SecureField::zero());
    let ones = guess_bits(&mut context, Some(u32::MAX), 31);
    check_word_bits(&mut context, word, &ones);
    assert_eq!(context.mismatches().len(), 1, "only the canonical check");

    let mut context = Context::<SecureField>::new().lenient();
    let word = context.guess(SecureField::zero());
    let zeros = guess_bits(&mut context, Some(0), 31);
    check_word_bits(&mut context, word, &zeros);
    assert!(context.mismatches().is_empty());

    for (word, n_bits, passes) in [(0u32, 24, true), (5 << 24, 24, true), (3 << 23, 24, false)] {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(SecureField::from(BaseField::from(word)));
        assert_trailing_zeros(&mut context, var, n_bits);
        assert_eq!(context.mismatches().is_empty(), passes, "{word:#x}");
    }
}

/// A nonce's limbs are each below 2^16, the wire a u64's: a limb of 2^16 is
/// refused, alone and in the channel, where a nonce whose work passes with
/// such a limb is refused for the limb alone.
#[test]
fn a_nonce_limb_of_2_16_is_refused() {
    let limbs = |limbs: [u32; 4]| SecureField::from_m31_array(limbs.map(BaseField::from));
    let refusals = |wire: SecureField| {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(wire);
        assert_u16_limbs(&mut context, var);
        context.mismatches().len()
    };
    assert_eq!(refusals(u64_wire(u64::MAX)), 0);
    assert_eq!(refusals(u64_wire(0x0123_4567_89ab_cdef)), 0);
    for lane in 0..4 {
        let mut wide = [0xffff; 4];
        wide[lane] = 1 << 16;
        assert_eq!(refusals(limbs(wide)), 1, "lane {lane}");
    }

    // At 4 bits: the work alone (the hash and its trailing zeros), and the
    // channel's check.
    const BITS: u32 = 4;
    let work = |nonce: SecureField| {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(nonce);
        let check = TranscriptGadget::new(&context).pow(&mut context, BITS, var);
        let word = context.limb(check.digest[0], 0);
        assert_trailing_zeros(&mut context, word, BITS);
        context.mismatches().is_empty()
    };
    let check_pow = |nonce: SecureField| {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(nonce);
        let mut channel = Channel::new(&context);
        channel.check_pow(&mut context, BITS, var);
        context.mismatches().len()
    };
    let native = Poseidon2M31Channel::default();
    let nonce = (0..)
        .find(|&nonce| native.verify_pow_nonce(BITS, nonce))
        .unwrap();
    assert!(work(u64_wire(nonce)));
    assert_eq!(check_pow(u64_wire(nonce)), 0);
    let forged = (0..)
        .map(|k| limbs([(1 << 16) + k, 0, 0, 0]))
        .find(|&wire| work(wire))
        .unwrap();
    assert_eq!(check_pow(forged), 1);
}

#[test]
fn expand_decommitment_gives_each_query_its_path() {
    let real = fixture();
    let StarkProofAny::Poseidon2M31(stark) = &real.proof.stark_proof else {
        unreachable!()
    };
    let tree = 1;
    let height = real.shape.stark.heights[tree];
    let order = &real.shape.stark.leaf_order[tree];
    let leaf = |index: usize| {
        let row: Vec<BaseField> = order
            .iter()
            .map(|&c| stark.queried_values[tree][c][index])
            .collect();
        let mut hasher = P2MerkleHasher::default();
        hasher.update_leaf(&row);
        hasher.finalize()
    };
    let positions = &real.data.query_positions;
    let leaves: Vec<(usize, P2Hash)> = positions
        .iter()
        .enumerate()
        .map(|(i, &p)| (p, leaf(i)))
        .collect();
    let witness = &stark.decommitments[tree].hash_witness;
    let expanded = expand_decommitment::<P2MerkleHasher>(height, &leaves, witness).unwrap();
    assert_eq!(expanded.root, stark.commitments[tree]);
    for &(position, hash) in &leaves {
        let mut node = hash;
        for (level, sibling) in expanded.path(position).into_iter().enumerate() {
            node = if position >> level & 1 == 0 {
                P2MerkleHasher::hash_children((node, sibling))
            } else {
                P2MerkleHasher::hash_children((sibling, node))
            };
        }
        assert_eq!(node, stark.commitments[tree], "position {position}");
    }
    assert_eq!(
        expand_decommitment::<P2MerkleHasher>(height, &leaves, &witness[1..]).unwrap_err(),
        ExpandError::WitnessTooShort
    );
    let mut long = witness.clone();
    long.push(P2Hash::default());
    assert_eq!(
        expand_decommitment::<P2MerkleHasher>(height, &leaves, &long).unwrap_err(),
        ExpandError::WitnessTooLong
    );
}

/// Every tree's opening of every query, alone: accepted, and a sibling or a
/// value tampered refused.
#[test]
fn the_merkle_openings_accept_and_refuse() {
    let real = fixture();
    let StarkProofAny::Poseidon2M31(stark) = &real.proof.stark_proof else {
        unreachable!()
    };
    let lifting = real.shape.stark.layout.lifting_log_size;
    let open = |tamper: Option<(usize, bool)>| {
        let mut context = Context::<SecureField>::new().lenient();
        for (q, (&position, query)) in real
            .drawn()
            .iter()
            .zip(&real.values.stark.queries)
            .enumerate()
        {
            let bits = bits_of(&mut context, position, lifting);
            for (tree, opening) in query.trees.iter().enumerate() {
                let mut opening = opening.clone();
                if tamper == Some((q, true)) && tree == 2 {
                    bump(&mut opening.path[3][1]);
                }
                if tamper == Some((q, false)) && tree == 0 {
                    bump(&mut opening.leaf[0]);
                }
                let tree_bits = if tree == 0 {
                    preprocessed_bits(&bits, real.shape.stark.heights[0])
                } else {
                    bits.clone()
                };
                let wires: Vec<Var> = opening.leaf.iter().map(|&v| context.guess(v)).collect();
                let root = guess_digest(&mut context, &stark.commitments[tree]);
                verify_opening(
                    &mut context,
                    &wires,
                    real.shape.stark.leaf_order[tree].len(),
                    &tree_bits,
                    &opening.path,
                    root,
                );
            }
        }
        context.mismatches().len()
    };
    // A refused opening's root differs in both its wires.
    assert_eq!(open(None), 0);
    assert_eq!(open(Some((4, true))), 2);
    assert_eq!(open(Some((11, false))), 2);
}

/// FRI alone, on the native first-layer values, folding coefficients and
/// positions: accepted; a sibling, a first-layer value or the last layer's
/// coefficient tampered refused.
#[test]
fn fri_accepts_and_refuses() {
    let real = fixture();
    let lifting = real.shape.stark.layout.lifting_log_size;
    let run = |tamper: &str| {
        let mut context = Context::<SecureField>::new().lenient();
        let roots = real
            .values
            .stark
            .fri_roots
            .iter()
            .map(|&root| context.guess_pair(root))
            .collect();
        let alphas = real
            .data
            .fold_alphas
            .iter()
            .map(|&alpha| context.guess(alpha))
            .collect();
        let mut last = real.values.stark.last_layer;
        if tamper == "last" {
            bump(&mut last);
        }
        let commitment = FriCommitment {
            roots,
            alphas,
            last_layer: context.guess(last),
        };
        for (q, (&position, query)) in real
            .drawn()
            .iter()
            .zip(&real.values.stark.queries)
            .enumerate()
        {
            let bits = bits_of(&mut context, position, lifting);
            let point = domain_point(&mut context, lifting, &bits);
            let mut first = real.first_layer(position);
            if tamper == "value" && q == 6 {
                bump(&mut first);
            }
            let value = context.guess(first);
            let mut openings = query.fri.clone();
            if tamper == "sibling" && q == 2 {
                bump(&mut openings[7].sibling);
            }
            verify_query(
                &mut context,
                lifting,
                &commitment,
                &bits,
                point,
                value,
                &openings,
            );
        }
        context.mismatches().to_vec()
    };
    assert!(run("").is_empty());
    for tamper in ["last", "value", "sibling"] {
        assert!(!run(tamper).is_empty(), "{tamper}");
    }
    // The last layer: every query's last fold is refused.
    assert_eq!(run("last").len(), real.values.stark.queries.len());
}

/// DEEP alone, from the native sampled values, coefficient and OODS point:
/// each query's quotient is the native first-layer value; a queried value
/// or a sampled value tampered moves it.
#[test]
fn deep_is_the_native_quotient() {
    let real = fixture();
    let lifting = real.shape.stark.layout.lifting_log_size;
    let run = |tamper: &str| {
        let mut context = Context::<SecureField>::new();
        let mut sampled_values = real.values.stark.sampled.clone();
        if tamper == "sample" {
            bump(&mut sampled_values[100]);
        }
        let sampled: Vec<Var> = sampled_values.iter().map(|&v| context.guess(v)).collect();
        let oods = Point {
            x: context.guess(real.data.oods_point.x),
            y: context.guess(real.data.oods_point.y),
        };
        let alpha = context.guess(real.data.deep_coeff);
        let constants = deep::prepare(&mut context, &real.shape.stark.deep, oods, alpha, &sampled);
        let mut moved = 0;
        for (q, (&position, query)) in real
            .drawn()
            .iter()
            .zip(&real.values.stark.queries)
            .enumerate()
        {
            let bits = bits_of(&mut context, position, lifting);
            let point = domain_point(&mut context, lifting, &bits);
            let leaves: Vec<Vec<Var>> = query
                .trees
                .iter()
                .enumerate()
                .map(|(tree, opening)| {
                    let mut leaf = opening.leaf.clone();
                    if tamper == "queried" && q == 3 && tree == 1 {
                        bump(&mut leaf[17]);
                    }
                    leaf.iter().map(|&v| context.guess(v)).collect()
                })
                .collect();
            let answer = deep::answer(
                &mut context,
                &real.shape.stark.deep,
                &constants,
                point,
                [&leaves[0], &leaves[1], &leaves[2], &leaves[3]],
            );
            if value(&context, answer) != real.first_layer(position) {
                moved += 1;
            }
        }
        moved
    };
    assert_eq!(run(""), 0);
    assert_eq!(run("queried"), 1);
    assert_eq!(run("sample"), real.values.stark.queries.len());
}

/// The composition check alone, from the native values: accepted; an OODS
/// sample, a claimed sum or a challenge tampered refused.
#[test]
fn oods_accepts_and_refuses() {
    let real = fixture();
    let challenges = real.challenges();
    let inputs = real.shape.stark.compiled_inputs();
    let run = |tamper: Option<usize>| {
        let mut context = Context::<SecureField>::new().lenient();
        let wires: Vec<Var> = inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                let mut value = match *input {
                    CompiledInput::Sample(index) => real.values.stark.sampled[index],
                    CompiledInput::ClaimedSum(chip) => real.values.stark.claimed_sums[chip],
                    CompiledInput::Challenge(r, k) => challenges[r][k],
                };
                if tamper == Some(i) {
                    bump(&mut value);
                }
                context.guess(value)
            })
            .collect();
        let coeff = context.guess(real.data.random_coeff);
        let oods_point = Point {
            x: context.guess(real.data.oods_point.x),
            y: context.guess(real.data.oods_point.y),
        };
        let composition = core::array::from_fn(|c| {
            context.guess(real.values.stark.sampled[real.shape.stark.sample_index[3][c]])
        });
        oods::check(
            &mut context,
            &real.shape.stark.compiled,
            &wires,
            coeff,
            oods_point,
            real.shape.stark.layout.max_log_degree_bound,
            composition,
        );
        context.mismatches().len()
    };
    assert_eq!(run(None), 0);
    let last_of = |pick: &dyn Fn(&CompiledInput) -> bool| inputs.iter().rposition(pick).unwrap();
    let running_sum = last_of(&|input| matches!(input, CompiledInput::Sample(_)));
    let claimed = last_of(&|input| matches!(input, CompiledInput::ClaimedSum(_)));
    // The register-memory relation's `z`: a relation only chips idle on the
    // trace use samples to zero there whatever `z` is.
    let register = real.shape.boundary.unwrap().relations[0];
    let challenge = last_of(&|input| *input == CompiledInput::Challenge(register, 0));
    for tamper in [running_sum, claimed, challenge] {
        assert_eq!(run(Some(tamper)), 1, "{:?}", inputs[tamper]);
    }
}

/// The logup sums alone, from the native claimed sums, boundary bytes and
/// challenges: accepted; a claimed sum or a boundary byte tampered refused.
#[test]
fn the_logup_sums_accept_and_refuse() {
    let real = fixture();
    let challenges = real.challenges();
    let run = |sum: Option<usize>, byte: Option<usize>| {
        let mut context = Context::<SecureField>::new().lenient();
        let claimed: Vec<Var> = real
            .values
            .stark
            .claimed_sums
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mut v = v;
                if sum == Some(i) {
                    bump(&mut v);
                }
                context.guess(v)
            })
            .collect();
        let boundary: Vec<Var> = real
            .values
            .boundary
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mut v = v;
                if byte.is_some_and(|byte| byte / 4 == i) {
                    let mut limbs = v.to_m31_array();
                    limbs[byte.unwrap() % 4] += BaseField::one();
                    v = SecureField::from_m31_array(limbs);
                }
                context.guess(v)
            })
            .collect();
        let mut challenge = |r: usize| {
            let [z, alpha] = challenges[r];
            Challenges {
                z: context.guess(z),
                alpha: context.guess(alpha),
            }
        };
        let terms = real.shape.boundary.unwrap();
        let [register, program, merkle] = terms.relations;
        let relations = BoundaryRelations {
            register_memory: challenge(register),
            program_execution: challenge(program),
            merkle_node: challenge(merkle),
        };
        logup::check(
            &mut context,
            &claimed,
            &terms.positions,
            &boundary,
            &relations,
        );
        context.mismatches().len()
    };
    assert_eq!(run(None, None), 0);
    let positions = real.shape.boundary.unwrap().positions;
    // A boundary chip's sum: the total and its public term.
    assert_eq!(run(Some(positions.register_closing), None), 2);
    // Another chip's: the total.
    assert_eq!(run(Some(0), None), 1);
    // A byte of each boundary state: a register in and out, pc and ts in and
    // out, each memory root.
    // The closing timestamp enters the register closing's tuples and the
    // program boundary's consumed one.
    for (byte, refusals) in [
        (5, 1),
        (104 + 9, 1),
        (208, 1),
        (212, 1),
        (220, 1),
        (224, 2),
        (232 + 31, 1),
        (264, 1),
    ] {
        assert_eq!(run(None, Some(byte)), refusals, "byte {byte}");
    }
}
