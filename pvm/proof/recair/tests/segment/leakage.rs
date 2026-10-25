//! The masking's leakage gates on the masked segment
//! (`docs/design/proving.md` §5; slice 6's 6.6), at N proofs a kernel: 16 in
//! `just check`; under `heavy-gates`, `LEAKAGE_SEGMENT_N`, [`MEDIUM`] unless
//! it is set (`just test-proof`; `just slice-gate` sets the full N).
//!
//! - **R1** on every column class, both channels, every class size: the
//!   acceptance gate's (`gates.rs`).
//! - **Witness indistinguishability:** N proofs of the small kernel against
//!   N of the kernel whose φ9 is one more: per field a two-sample χ² on its
//!   top bits, one pooled KS. A deviation from slice 6's pairs: a segment of
//!   the node's shape publishes its whole boundary (every register, the pc,
//!   the timestamps and both memory roots), so under equal public values a
//!   run has no other witness; the two kernels' public values differ in φ9.
//!   The fields are every published value but the public ones (the
//!   preprocessed tree's, the boundary chips' claimed sums). The control:
//!   the unmasked prover (format 35) fails the same test.
//! - **Uniformity:** each field of the first kernel's N proofs against
//!   uniform M31.
//! - **Hidden states:** a value the run holds and no boundary state does (φ7
//!   between its sum and its clearing), and each boundary's
//!   `memory_commitment`, which the masked transcript never mixes, are in no
//!   proof's bytes.
//! - **Fresh randomness:** two proofs of one run share no opening, nor two
//!   kernels' proofs from one seed.
//! - **The claimed sums' control:** a right guess of the run's sums under the
//!   proof's relations is the unmasked proof's, and the masked proof's only
//!   for the boundary chips' public sums.
//! - **The shape:** two kernels' proofs have one shape, the format's and
//!   the coins'.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use num_traits::Zero;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_proof::StarkProofAny;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::masked::{SegmentComponents, masked_segment_trace, public_values};
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair::masked::MaskRng;
use vos_pvm_recair_air::masked::MaskedComponents;

use crate::common::leakage::{Fields, Key, Kind, Verdicts, indistinguishable, published, uniform};
use crate::support::{IO, IO_OTHER, Proof, active, format, prove, run, secret, verify};

/// The proofs a kernel under `heavy-gates` unless `LEAKAGE_SEGMENT_N` is set.
#[cfg(feature = "heavy-gates")]
const MEDIUM: usize = 64;

/// The proofs a kernel.
fn n() -> usize {
    #[cfg(feature = "heavy-gates")]
    {
        static N: OnceLock<usize> = OnceLock::new();
        *N.get_or_init(|| crate::common::leakage::heavy_n("LEAKAGE_SEGMENT_N", MEDIUM))
    }
    #[cfg(not(feature = "heavy-gates"))]
    {
        16
    }
}

/// The positions of the claimed sums the boundary states fix.
fn public_sums() -> Vec<usize> {
    let side_note = run(IO);
    let active = active(&side_note);
    let log_sizes = vec![8; active.count_ones() as usize];
    SegmentComponents::layout(active, &log_sizes)
        .expect("the layout")
        .public_sums()
}

/// A proof's published values but the public ones: the boundary chips'
/// claimed sums left out (the preprocessed tree's `published` leaves out).
fn private_fields<H: MerkleHasherLifted>(
    stark: &StarkProof<H>,
    claimed_sums: &[SecureField],
) -> Vec<(Key, u32)> {
    let public = public_sums();
    published(stark, claimed_sums)
        .into_iter()
        .filter(|((kind, _, _, index), _)| {
            !(*kind == Kind::Claimed && public.contains(&(index / 4)))
        })
        .collect()
}

/// N masked proofs of each kernel, each from its own seed: their fields,
/// once a test binary.
fn masked_fields() -> &'static [Fields; 2] {
    static FIELDS: OnceLock<[Fields; 2]> = OnceLock::new();
    FIELDS.get_or_init(|| {
        let format = format();
        [IO, IO_OTHER].map(|io| {
            let mut fields = Fields::default();
            for seed in 0..n() as u64 {
                let (proof, _) =
                    prove::<P2MerkleChannel>(&format, io, MaskRng::Seeded(seed)).expect("proves");
                fields.add(&private_fields(
                    &proof.proof.stark_proof,
                    &proof.proof.claimed_sums,
                ));
            }
            fields
        })
    })
}

/// A kernel's whole run proved unmasked under format 35 (the segment's).
fn unmasked(io: [u32; 4]) -> vos_pvm_proof::Proof {
    vos_pvm_proof::prove_format(&mut run(io), &SEGMENT).expect("proves")
}

/// An unmasked proof's STARK proof on the Poseidon2-M31 channel.
fn poseidon(proof: &vos_pvm_proof::Proof) -> &StarkProof<vos_pvm_proof::poseidon2::P2MerkleHasher> {
    match &proof.stark_proof {
        StarkProofAny::Poseidon2M31(stark) => stark,
        StarkProofAny::Blake2s(_) => panic!("format 35 is on the Poseidon2-M31 channel"),
    }
}

/// Witness indistinguishability and uniformity: the masked proofs of two
/// kernels are not told apart, field by field nor pooled, and each field of
/// the first kernel's is uniform; the unmasked prover's (each kernel's one
/// proof, N times: it is deterministic) are told apart, pooled (at small N
/// no single field's χ² can reach its threshold) and, at the heavy gates'
/// N, field by field.
#[test]
fn the_published_values_do_not_depend_on_the_witness() {
    let n = n();
    let [a, b] = masked_fields();
    let mut verdicts = Verdicts::new("the masked segment's witness indistinguishability");
    indistinguishable(&mut verdicts, "two kernels", a, b, n);
    verdicts.report();
    assert!(verdicts.refused().is_empty(), "{:?}", verdicts.refused());

    let mut verdicts = Verdicts::new("the masked segment's uniformity");
    uniform(&mut verdicts, a, n);
    verdicts.report();
    assert!(verdicts.refused().is_empty(), "{:?}", verdicts.refused());

    let [plain_a, plain_b] = [IO, IO_OTHER].map(|io| {
        let proof = unmasked(io);
        let mut fields = Fields::default();
        let one = private_fields(poseidon(&proof), &proof.claimed_sums);
        for _ in 0..n {
            fields.add(&one);
        }
        fields
    });
    let mut control = Verdicts::new("the unmasked control");
    indistinguishable(&mut control, "two kernels", &plain_a, &plain_b, n);
    control.report();
    assert!(
        control
            .refused()
            .iter()
            .any(|(hypothesis, _)| hypothesis.ends_with("pooled KS")),
        "the unmasked proofs not told apart"
    );
}

/// No hidden state in a proof's bytes: φ7's value between its sum and its
/// clearing (its 8 bytes, its low half; its high half is the sign's), and each boundary's
/// `memory_commitment`, which nothing the masked transcript mixes holds.
#[test]
fn no_hidden_state_is_in_a_proof() {
    let format = format();
    let (proof, _) = prove::<P2MerkleChannel>(&format, IO, MaskRng::default()).expect("proves");
    verify::<P2MerkleChannel>(&format, &proof).expect("verifies");
    let bytes = postcard::to_allocvec(&(&proof.proof.stark_proof, &proof.proof.claimed_sums))
        .expect("encodes");
    let value = secret(IO);
    let secret = value.to_le_bytes();
    assert!(
        !proof.final_state.registers.contains(&value)
            && !proof.initial_state.registers.contains(&value),
        "the value is no boundary state's"
    );
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("φ7's value", secret.to_vec()),
        ("its low half", secret[..4].to_vec()),
        (
            "the entering memory commitment",
            proof.initial_state.memory_commitment.to_vec(),
        ),
        (
            "the exit memory commitment",
            proof.final_state.memory_commitment.to_vec(),
        ),
    ];
    for (name, needle) in &needles {
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "{name} is in the proof's bytes"
        );
    }
}

/// Fresh randomness: two proofs of one run share no opening; and a replayed
/// seed with the two kernels shares none, its masks drawn from each run's
/// digest too.
#[test]
fn every_opening_is_fresh() {
    let differing = |a: &Proof<Blake2sMerkleChannel>, b: &Proof<Blake2sMerkleChannel>| {
        let a = private_fields(&a.proof.stark_proof, &a.proof.claimed_sums);
        let b: BTreeMap<_, _> = private_fields(&b.proof.stark_proof, &b.proof.claimed_sums)
            .into_iter()
            .collect();
        let shared: Vec<_> = a
            .iter()
            .filter(|(key, value)| b.get(key) == Some(value))
            .collect();
        assert!(a.len() > 1_000, "{} openings", a.len());
        assert!(shared.is_empty(), "openings shared: {shared:?}");
        a.len()
    };
    let blake = crate::support::small_format(vos_pvm_proof::format::ChannelKind::Blake2s, 6, 4);
    let [first, second] = [(); 2].map(|_| {
        prove::<Blake2sMerkleChannel>(&blake, IO, MaskRng::default())
            .expect("proves")
            .0
    });
    let n = differing(&first, &second);
    let [a, b] = [IO, IO_OTHER].map(|io| {
        prove::<Blake2sMerkleChannel>(&blake, io, MaskRng::Seeded(15))
            .expect("proves")
            .0
    });
    let m = differing(&a, &b);
    eprintln!("{n} openings of one run, {m} of two kernels from one seed: none shared");
}

/// The relations a masked segment proof's transcript draws.
fn drawn_relations<MC: MerkleChannel>(
    proof: &Proof<MC>,
) -> vos_pvm_proof::framework_access::AllLookupElements {
    let format = format();
    let mut channel = MC::C::default();
    mix_statement_header(
        &mut channel,
        format.number,
        &format.pcs_config(),
        &proof.log_sizes,
    );
    MC::mix_root(&mut channel, proof.proof.stark_proof.commitments[0]);
    MC::mix_root(&mut channel, proof.proof.stark_proof.commitments[1]);
    channel.mix_felts(&public_values(&proof.initial_state, &proof.final_state));
    channel.mix_u64(proof.proof.interaction_pow);
    SegmentComponents::draw_relations(proof.active, &mut channel)
}

/// The claimed sums' control. Unmasked (format 35), the sums a right guess
/// of the run computes under the proof's relations are the proof's; masked,
/// only the boundary chips' are (public, unblinded), the others' not, though
/// their total is.
#[test]
fn a_right_guess_reproduces_an_unblinded_sum_only() {
    let guess = |floors: &[u32], relations| -> Vec<SecureField> {
        let mut side_note = run(IO);
        let active = active(&side_note);
        let trace = masked_segment_trace(&mut side_note, active, floors).expect("traces");
        trace
            .interaction(&side_note, relations, &[])
            .into_iter()
            .map(|(_, sum)| sum)
            .collect()
    };
    let plain = unmasked(IO);
    let relations = vos_pvm_proof::extract_recursion_data(&plain).lookup_elements;
    let floors = vec![0; plain.log_sizes.len()];
    assert_eq!(guess(&floors, &relations), plain.claimed_sums, "unmasked");

    let format = format();
    let (proof, _) = prove::<P2MerkleChannel>(&format, IO, MaskRng::default()).expect("proves");
    let relations = drawn_relations::<P2MerkleChannel>(&proof);
    let guessed = guess(&proof.log_sizes, &relations);
    let public = public_sums();
    for (chip, (guessed, claimed)) in guessed.iter().zip(&proof.proof.claimed_sums).enumerate() {
        assert_eq!(guessed == claimed, public.contains(&chip), "chip {chip}");
    }
    let total = |sums: &[SecureField]| sums.iter().copied().sum::<SecureField>();
    assert_eq!(total(&guessed), total(&proof.proof.claimed_sums));
    assert!(total(&guessed).is_zero());
}

/// The shape public: two kernels' proofs have one layout, each tree's width,
/// each column's samples, each tree's queried values and FRI's layers, all
/// the format's and the coins' alone.
#[test]
fn the_shape_is_the_format_and_the_coins() {
    let format = format();
    let [a, b] = [IO, IO_OTHER].map(|io| {
        prove::<P2MerkleChannel>(&format, io, MaskRng::Seeded(21))
            .expect("proves")
            .0
    });
    let shape = |proof: &Proof<P2MerkleChannel>| {
        let stark = &proof.proof.stark_proof;
        let samples: Vec<Vec<usize>> = stark
            .sampled_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).collect())
            .collect();
        let queried: Vec<usize> = stark
            .queried_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).max().unwrap_or(0))
            .collect();
        (
            proof.log_sizes.clone(),
            proof.active,
            samples,
            stark.fri_proof.inner_layers.len(),
            stark.fri_proof.last_layer_poly.len(),
            queried.len(),
        )
    };
    assert_eq!(shape(&a), shape(&b));
    for proof in [&a, &b] {
        let stark = &proof.proof.stark_proof;
        let counts: Vec<usize> = stark
            .queried_values
            .iter()
            .flat_map(|tree| tree.iter().map(Vec::len))
            .collect();
        assert!(counts.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
