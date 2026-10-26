//! The masking's leakage gates on the device shape
//! (`docs/design/proving.md` §5; slice 6's 6.6; pin J),
//! at N proofs a witness: 16 in `just check`; under `heavy-gates`,
//! `LEAKAGE_SEGMENT_N`, [`MEDIUM`] unless it is set (`just test-proof`;
//! `just slice-gate` sets the full N).
//!
//! The device shape states the io-hash alone, so two witnesses of the
//! kernel, which differ in the 64 bytes it reads and hashes and agree on
//! its io-hash, have **equal public values**: slice 6's pairs, with no
//! deviation.
//!
//! - **Witness indistinguishability:** N proofs of one witness against N of
//!   the other: per field a two-sample χ² on its top bits, one pooled KS. The
//!   fields are every published value but the public ones (the
//!   preprocessed tree's, DeviceIoChip's claimed sum).
//! - **Uniformity:** each field of the first witness's N proofs against
//!   uniform M31.
//! - **Hidden state:** the witness's bytes and the Poseidon2 call's output,
//!   eight bytes at a time, are in no proof's bytes.
//! - **Fresh randomness:** two proofs of one run share no opening, nor two
//!   witnesses' proofs from one seed.
//! - **The claimed sums' control:** a right guess of the run's sums under
//!   the proof's relations is the masked proof's for DeviceIoChip alone.
//! - **The shape:** two witnesses' proofs have one shape, the program's,
//!   the format's and the coins'.

use std::collections::BTreeMap;
#[cfg(feature = "heavy-gates")]
use std::sync::OnceLock;

use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_proof::masked::{
    DeviceComponents, DeviceSizes, device_io_position, device_public_values, masked_device_trace,
};
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair::masked::MaskRng;
use vos_pvm_recair_air::masked::MaskedComponents;

use crate::common::leakage::{Fields, Key, Kind, Verdicts, indistinguishable, published, uniform};
use crate::support::{
    Proof, blob, format, io_bytes, program, prove, run, small_format, the_program, verify, witness,
};

/// The proofs a witness under `heavy-gates` unless `LEAKAGE_SEGMENT_N` is set.
#[cfg(feature = "heavy-gates")]
const MEDIUM: usize = 64;

/// The proofs a witness.
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

/// The two witnesses: 64 bytes each, other words, one io-hash.
const WITNESSES: [u64; 2] = [11, 12];

/// A proof's published values but the public ones: DeviceIoChip's claimed
/// sum left out (the preprocessed tree's `published` leaves out).
fn private_fields<H: MerkleHasherLifted>(
    stark: &StarkProof<H>,
    claimed_sums: &[SecureField],
) -> Vec<(Key, u32)> {
    let public = device_io_position(the_program().active).expect("DeviceIoChip");
    published(stark, claimed_sums)
        .into_iter()
        .filter(|((kind, _, _, index), _)| !(*kind == Kind::Claimed && index / 4 == public))
        .collect()
}

/// Witness indistinguishability and uniformity at equal public values: the
/// masked proofs of two witnesses of one io-hash are not told apart, field
/// by field nor pooled, and each field of the first's is uniform.
#[test]
fn the_published_values_do_not_depend_on_the_witness() {
    let n = n();
    let format = format();
    let program = the_program();
    let [a, b] = WITNESSES.map(|seed| {
        let mut fields = Fields::default();
        for mask in 0..n as u64 {
            let (proof, _) = prove::<P2MerkleChannel>(
                &format,
                program,
                &blob(),
                &witness(seed),
                MaskRng::Seeded(mask),
            )
            .expect("proves");
            assert_eq!(proof.io, io_bytes(), "one public value for both witnesses");
            fields.add(&private_fields(
                &proof.proof.stark_proof,
                &proof.proof.claimed_sums,
            ));
        }
        fields
    });
    let mut verdicts = Verdicts::new("the device shape's witness indistinguishability");
    indistinguishable(&mut verdicts, "two witnesses", &a, &b, n);
    verdicts.report();
    assert!(verdicts.refused().is_empty(), "{:?}", verdicts.refused());

    let mut verdicts = Verdicts::new("the device shape's uniformity");
    uniform(&mut verdicts, &a, n);
    verdicts.report();
    assert!(verdicts.refused().is_empty(), "{:?}", verdicts.refused());
}

/// No hidden state in a proof's bytes: the witness's 64 bytes and the
/// Poseidon2 call's 32 output bytes, eight at a time.
#[test]
fn no_hidden_state_is_in_a_proof() {
    let format = format();
    let program = the_program();
    let input = witness(WITNESSES[0]);
    let (proof, _) =
        prove::<P2MerkleChannel>(&format, program, &blob(), &input, MaskRng::default())
            .expect("proves");
    verify::<P2MerkleChannel>(&format, program, &proof).expect("verifies");
    let output = run(&blob(), &input).poseidon2_ops[0].output;
    let bytes = postcard::to_allocvec(&(&proof.proof.stark_proof, &proof.proof.claimed_sums))
        .expect("encodes");
    for needle in input.chunks_exact(8).chain(output.chunks_exact(8)) {
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "{needle:02x?} is in the proof's bytes"
        );
    }
}

/// Fresh randomness: two proofs of one run share no opening; and a replayed
/// seed with the two witnesses shares none, its masks drawn from each run's
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
    let blake = small_format(vos_pvm_proof::format::ChannelKind::Blake2s, 6, 4);
    let program = program::<Blake2sMerkleChannel>(&blake, &blob());
    let [first, second] = [(); 2].map(|_| {
        prove::<Blake2sMerkleChannel>(
            &blake,
            &program,
            &blob(),
            &witness(WITNESSES[0]),
            MaskRng::default(),
        )
        .expect("proves")
        .0
    });
    let n = differing(&first, &second);
    let [a, b] = WITNESSES.map(|seed| {
        prove::<Blake2sMerkleChannel>(
            &blake,
            &program,
            &blob(),
            &witness(seed),
            MaskRng::Seeded(15),
        )
        .expect("proves")
        .0
    });
    let m = differing(&a, &b);
    eprintln!("{n} openings of one run, {m} of two witnesses from one seed: none shared");
}

/// The relations a device proof's transcript draws.
fn drawn_relations(
    proof: &Proof<P2MerkleChannel>,
) -> vos_pvm_proof::framework_access::AllLookupElements {
    let format = format();
    let program = the_program();
    let mut channel = <P2MerkleChannel as MerkleChannel>::C::default();
    mix_statement_header(
        &mut channel,
        format.number,
        &format.pcs_config(),
        &program.log_sizes,
    );
    for word in program.header() {
        channel.mix_u64(word);
    }
    P2MerkleChannel::mix_root(&mut channel, proof.proof.stark_proof.commitments[0]);
    P2MerkleChannel::mix_root(&mut channel, proof.proof.stark_proof.commitments[1]);
    channel.mix_felts(&device_public_values(&proof.io));
    channel.mix_u64(proof.proof.interaction_pow);
    DeviceComponents::draw_relations(program.active, &mut channel)
}

/// The claimed sums' control: the sums a right guess of the run computes
/// under the proof's relations are the masked proof's for DeviceIoChip
/// alone (public, unblinded), though their total is.
#[test]
fn a_right_guess_reproduces_the_public_sum_only() {
    let format = format();
    let program = the_program();
    let input = witness(WITNESSES[0]);
    let (proof, _) =
        prove::<P2MerkleChannel>(&format, program, &blob(), &input, MaskRng::default())
            .expect("proves");
    let relations = drawn_relations(&proof);
    let mut side_note = run(&blob(), &input);
    let trace = masked_device_trace(
        &mut side_note,
        &program.layout,
        program.active,
        DeviceSizes::Pinned(&program.log_sizes),
    )
    .expect("traces");
    let guessed: Vec<SecureField> = trace
        .interaction(&side_note, &relations, &[])
        .into_iter()
        .map(|(_, sum)| sum)
        .collect();
    let public = DeviceComponents::layout(program.active, &program.log_sizes)
        .expect("laid out")
        .public_sums();
    assert_eq!(public.len(), 1);
    for (chip, (guessed, claimed)) in guessed.iter().zip(&proof.proof.claimed_sums).enumerate() {
        assert_eq!(guessed == claimed, public.contains(&chip), "chip {chip}");
    }
    let total = |sums: &[SecureField]| sums.iter().copied().sum::<SecureField>();
    assert_eq!(total(&guessed), total(&proof.proof.claimed_sums));
}

/// The shape public: two witnesses' proofs have one layout, each tree's
/// width, each column's samples, each tree's queried values and FRI's
/// layers, all the program's, the format's and the coins' alone.
#[test]
fn the_shape_is_the_programs_and_the_coins() {
    let format = format();
    let program = the_program();
    let [a, b] = WITNESSES.map(|seed| {
        prove::<P2MerkleChannel>(
            &format,
            program,
            &blob(),
            &witness(seed),
            MaskRng::Seeded(21),
        )
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
        let queried: Vec<Vec<usize>> = stark
            .queried_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).collect())
            .collect();
        (
            proof.proof.claimed_sums.len(),
            samples,
            queried,
            stark.fri_proof.inner_layers.len(),
            stark.fri_proof.last_layer_poly.len(),
        )
    };
    assert_eq!(shape(&a), shape(&b));
}
