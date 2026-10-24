//! The masked wrap (`format::MASKED_WRAP`) over the one-segment run's root,
//! proved by `vos-pvm-recair`'s masked prover from a seed, its bytes the
//! fixed layout, and verified by `vos-pvm-final-verifier`'s masked
//! verifier.
//!
//! - **The verifier's constants are the registry's** entry for 39: its
//!   number, configuration, masking, log sizes, trees' widths and DEEP
//!   values; its preprocessed root; its bytes; FRI's rounds as the security
//!   count takes them and as `FriVerifier::commit` derives them.
//! - **Every masked field tampered** (14 cases) is refused with
//!   an error, never a panic, as a proof and through its bytes; and a
//!   verifier pinning another salt count or `R` refuses the proof.
//! - **Cross-format proofs, both ways,** are refused as another format.
//! - **The bytes:** truncations and a trailing byte refused.
//! - **On the JAM-only host** the venue's refine program accepts it within
//!   `format::MASKED_WRAP`'s gas, and refuses a tampered byte and other words.
//! - **No hidden state** of the run is in any carrier of the proof.
//! - **Under `heavy-gates`** (`just test-proof`): witness
//!   indistinguishability, uniformity and fresh randomness on the real wrap
//!   at 16 proofs a witness (32 in `just slice-gate`, `LEAKAGE_WRAP_N`),
//!   and the verify gates (decode, verify and the PVF's Wasm instructions)
//!   as the maximum over 12 seeds.
//!
//! The real wrap's leakage power [est; exact for uniformity, simulated for
//! the two-sample test]: at N = 32 the two-sample test finds only a field
//! fixed by the witness, and exact uniformity a leak concentrated in a
//! bucket at total variation 0.59 (90% power); at N = 16, the same fixed
//! field, and a concentrated leak at about 0.83. N = 16 is the least at
//! which the unmasked control still fails: a fixed field in two buckets
//! is χ² = 2N on one degree of freedom, p 1.5·10^-8 at 16 against the
//! control's threshold of about 2.1·10^-8 (8,763 of its 11,685 refused at
//! 16 [measured]).

use crate::common::bump_m31;
use crate::jam;
use crate::wrap::{one_segment, values_of};

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::time::Instant;

use num_traits::{One, Zero};
use stwo::core::channel::Blake2bChannel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{CirclePolyDegreeBound, FriVerificationError, FriVerifier};
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use vos_pvm_final_verifier::masked::{
    self, FRI_ROUNDS, MASKED_WRAP, MaskedFormat, fri_rounds, shape_of, verify_with,
};
use vos_pvm_final_verifier::{
    Error, MAX_PROOF_BYTES, PREPROCESSED_ROOT_39, PUBLIC_WORDS, Statement, WrapProof, unmasked,
};
use vos_pvm_proof::format::{self, ProofBytes, Status};
use vos_pvm_recair::masked::{MaskRng, verifier_format};
use vos_pvm_recair::wrap::{self, WrapCircuit};
use vos_pvm_recair_air::GateRelation;
use vos_pvm_recair_air::masked::{BlindRelation, MaskPins, WrapComponents};

/// The one-segment run's root wrapped under `format::MASKED_WRAP`: the
/// proof, its bytes and its public words.
struct Masked {
    proof: WrapProof,
    bytes: Vec<u8>,
    words: [u32; PUBLIC_WORDS],
}

fn masked_wrap() -> &'static Masked {
    static MASKED: OnceLock<Masked> = OnceLock::new();
    MASKED.get_or_init(|| {
        let one = one_segment();
        let finalized = WrapCircuit::get().finalize(&values_of(&one.root, &one.run.program));
        let words = wrap::public_words(&finalized);
        assert_eq!(words, one.wrapped.words);
        let started = Instant::now();
        let (proof, stats) =
            wrap::prove_masked(&finalized, MaskRng::Seeded(39), |_| {}).expect("proves");
        let bytes = wrap::proof_bytes(&proof).expect("format 39's bytes");
        let postcard = postcard::to_allocvec(&proof).expect("encodes");
        eprintln!(
            "one segment: the masked wrap proved in {:.2}s, {} bytes (postcard {}); {stats:?}",
            started.elapsed().as_secs_f64(),
            bytes.len(),
            postcard.len(),
        );
        write("one-segment-39", masked::FORMAT, &bytes, &words);
        let unmasked = postcard::to_allocvec(&one.wrapped.proof).expect("encodes");
        write("one-segment-28", unmasked::FORMAT, &unmasked, &words);
        Masked {
            proof,
            bytes,
            words,
        }
    })
}

/// A wrap's proof, format and public words, under the target's tmp
/// directory as `wrap/<name>.{proof,format,words}`: the Wasm harness's
/// input (`final-verifier/wasm/run`) and the fuzz targets'
/// `format::MASKED_WRAP` golden.
fn write(name: &str, format: u32, proof: &[u8], words: &[u32; PUBLIC_WORDS]) {
    let directory = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("wrap");
    std::fs::create_dir_all(&directory).expect("the wrap's directory");
    let words: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    for (extension, bytes) in [
        ("proof", proof),
        ("format", &format.to_le_bytes()[..]),
        ("words", &words),
    ] {
        std::fs::write(directory.join(format!("{name}.{extension}")), bytes).expect("writes");
    }
}

/// The wrap's set under any relations: its trees' layout.
fn layout() -> WrapComponents {
    WrapComponents::build(
        &GateRelation::dummy(),
        &BlindRelation::dummy(),
        &vos_pvm_final_verifier::LOG_SIZES,
        &[SecureField::zero(); 3],
    )
}

/// `verify` run, a panic caught and reported as one.
fn refusal(verify: impl FnOnce() -> Result<Statement, Error>) -> Result<Error, &'static str> {
    match catch_unwind(AssertUnwindSafe(verify)) {
        Ok(Ok(_)) => Err("accepted"),
        Ok(Err(error)) => Ok(error),
        Err(_) => Err("panicked"),
    }
}

/// The verifier's constants are the registry's entry for 39, field for
/// field: the format as the verifier pins it from the built wrap set, its
/// status, its bytes and its circuit's root; FRI's rounds the security
/// count's and the ones `FriVerifier::commit` derives, which refuses a
/// proof of a round more or fewer. The proof verifies, its bytes the fixed
/// layout and the one encoding.
#[test]
fn the_masked_wrap_verifies_under_the_registrys_entry() {
    let entry = &format::MASKED_WRAP;
    let layout = layout();
    assert_eq!(
        verifier_format(entry, &vos_pvm_final_verifier::LOG_SIZES, &layout),
        Some(MASKED_WRAP)
    );
    assert_eq!(entry.status, Status::Admitted);
    assert_eq!(entry.bytes, ProofBytes::FixedLayout);
    assert_eq!(MAX_PROOF_BYTES, 256 << 10);
    assert_eq!(
        WrapCircuit::get().preprocessed_root(),
        Blake2bHash(PREPROCESSED_ROOT_39)
    );
    assert_eq!(
        vos_pvm_proof::security::fri_rounds(&entry.params, &entry.reference).unwrap(),
        FRI_ROUNDS
    );
    assert_eq!(
        fri_rounds(masked::LOG_DEGREE_BOUND, &masked::CONFIG.fri_config).unwrap(),
        FRI_ROUNDS
    );

    let masked = masked_wrap();
    let proof = &masked.proof;
    assert_eq!(
        proof.stark_proof.commitments[0],
        Blake2bHash(PREPROCESSED_ROOT_39)
    );
    assert_eq!(Some(&masked.bytes), masked::encode(proof).as_ref());
    assert!(masked.bytes.len() < MAX_PROOF_BYTES);
    let decoded = masked::decode(&masked.bytes).expect("decodes");
    assert_eq!(masked::encode(&decoded), Some(masked.bytes.clone()));
    let statement = Statement::from_words(&masked.words).unwrap();
    assert_eq!(
        masked::verify_bytes(&masked.bytes, &masked.words).expect("verifies"),
        statement
    );
    assert_eq!(
        vos_pvm_final_verifier::verify(39, &[39], &masked.bytes, &masked.words).expect("verifies"),
        statement
    );
    assert!(matches!(
        vos_pvm_final_verifier::verify(39, &[28], &masked.bytes, &masked.words),
        Err(Error::Format)
    ));

    // FRI's rounds as `FriVerifier::commit` derives them from the
    // composition's 2^17: the proof's inner layers, and no other count.
    let commits = |layers: usize| {
        let mut fri = proof.stark_proof.fri_proof.clone();
        fri.inner_layers.resize(layers, fri.inner_layers[0].clone());
        FriVerifier::<Blake2bMerkleChannel>::commit(
            &mut Blake2bChannel::default(),
            masked::CONFIG.fri_config,
            fri,
            CirclePolyDegreeBound::new(masked::LOG_DEGREE_BOUND),
        )
        .map(|_| ())
    };
    assert_eq!(proof.stark_proof.fri_proof.inner_layers.len(), 3);
    assert!(commits(3).is_ok());
    for layers in [2, 4] {
        assert!(matches!(
            commits(layers),
            Err(FriVerificationError::InvalidNumFriLayers)
        ));
    }
}

/// Spike 6a's 14 tamper cases: every one refused with an error, never a
/// panic, as a proof and through its bytes.
#[test]
fn every_masked_field_tampered_is_refused() {
    let masked = masked_wrap();
    let words = masked.words;
    let one = SecureField::one();
    type Tamper = Box<dyn Fn(&mut WrapProof)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "an OODS sample of a masked main column",
            Box::new(move |p| p.stark_proof.0.sampled_values[1][0][0] += one),
        ),
        (
            "an OODS sample of a masked interaction column",
            Box::new(move |p| p.stark_proof.0.sampled_values[2][0][0] += one),
        ),
        (
            "a queried main value",
            Box::new(|p| bump_m31(&mut p.stark_proof.0.queried_values[1][0][0])),
        ),
        (
            "a queried salt (main)",
            Box::new(|p| {
                let tree = &mut p.stark_proof.0.queried_values[1];
                let last = tree.len() - 1;
                bump_m31(&mut tree[last][0])
            }),
        ),
        (
            "a queried salt (composition)",
            Box::new(|p| {
                let tree = &mut p.stark_proof.0.queried_values[3];
                let last = tree.len() - 1;
                bump_m31(&mut tree[last][0])
            }),
        ),
        (
            "the FRI mask's sample",
            Box::new(move |p| p.stark_proof.0.sampled_values[3][4][0] += one),
        ),
        (
            "a composition sample",
            Box::new(move |p| p.stark_proof.0.sampled_values[3][0][0] += one),
        ),
        (
            "a blinded claimed sum",
            Box::new(move |p| p.claimed_sums[0] += one),
        ),
        (
            "two blinded claimed sums, their total kept",
            Box::new(move |p| {
                p.claimed_sums[0] += one;
                p.claimed_sums[1] -= one;
            }),
        ),
        (
            "a salt column dropped from the main tree",
            Box::new(|p| {
                p.stark_proof.0.queried_values[1].pop();
            }),
        ),
        (
            "a sample dropped",
            Box::new(|p| {
                p.stark_proof.0.sampled_values[1][0].pop();
            }),
        ),
        (
            "the FRI mask's samples dropped",
            Box::new(|p| p.stark_proof.0.sampled_values[3][4].clear()),
        ),
        ("the interaction PoW", Box::new(|p| p.interaction_pow ^= 1)),
        ("the format number", Box::new(|p| p.format_version = 28)),
    ];
    let mut failures = Vec::new();
    for (name, tamper) in &cases {
        let mut tampered = masked.proof.clone();
        tamper(&mut tampered);
        let bytes = masked::encode(&tampered);
        let as_proof = refusal(|| masked::verify(tampered, &words));
        let as_bytes = match &bytes {
            Some(bytes) => refusal(|| masked::verify_bytes(bytes, &words)),
            None => Ok(Error::Shape("no fixed layout holds it")),
        };
        match (as_proof, as_bytes) {
            (Ok(proof), Ok(bytes)) => eprintln!(
                "{name}: refused, {proof} ({:#x}); its bytes {bytes} ({:#x})",
                proof.code(),
                bytes.code()
            ),
            (proof, bytes) => failures.push(format!("{name}: {proof:?}, its bytes {bytes:?}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A verifier pinning another salt count or `R` refuses the proof: with
/// `format::MASKED_WRAP`'s widths, its set's trees are not the format's;
/// with the widths its pins lay out, the proof's trees are not its. And a
/// proof with a salt column or an `R` column more is refused by its shape,
/// as a proof and at its decode.
#[test]
fn another_salt_count_or_r_width_is_refused() {
    let masked = masked_wrap();
    let words = masked.words;
    let layout = layout();
    let pins = MASKED_WRAP.pins;
    let others = [
        MaskPins {
            salt_columns: pins.salt_columns - 1,
            ..pins
        },
        MaskPins {
            salt_columns: pins.salt_columns + 1,
            ..pins
        },
        MaskPins {
            fri_mask_columns: pins.fri_mask_columns - 1,
            ..pins
        },
        MaskPins {
            fri_mask_columns: pins.fri_mask_columns + 1,
            ..pins
        },
    ];
    for pins in others {
        let pinned = MaskedFormat {
            pins,
            ..MASKED_WRAP
        };
        let (tree_widths, deep_values) = shape_of(&layout, &pins).unwrap();
        let laid_out = MaskedFormat {
            tree_widths,
            deep_values,
            ..pinned
        };
        for format in [pinned, laid_out] {
            let error = refusal(|| {
                verify_with(&format, &PREPROCESSED_ROOT_39, masked.proof.clone(), &words)
            })
            .unwrap();
            eprintln!(
                "a verifier at {pins:?}, widths {:?}: {error}",
                format.tree_widths
            );
            assert!(matches!(error, Error::Shape(_)), "{error}");
        }
    }

    type Widen = fn(&mut WrapProof);
    let widened: [(&str, Widen); 3] = [
        ("a salt column more (main)", |p| {
            let salt = p.stark_proof.0.queried_values[1].last().unwrap().clone();
            p.stark_proof.0.queried_values[1].push(salt);
            p.stark_proof.0.sampled_values[1].push(Vec::new());
        }),
        ("an R column more", |p| {
            let r = p.stark_proof.0.queried_values[3][4].clone();
            p.stark_proof.0.queried_values[3].insert(12, r);
            let sample = p.stark_proof.0.sampled_values[3][4].clone();
            p.stark_proof.0.sampled_values[3].insert(12, sample);
        }),
        ("an R column fewer", |p| {
            p.stark_proof.0.queried_values[3].remove(11);
            p.stark_proof.0.sampled_values[3].remove(11);
        }),
    ];
    for (name, widen) in widened {
        let mut proof = masked.proof.clone();
        widen(&mut proof);
        let bytes = masked::encode(&proof);
        let as_proof = refusal(|| masked::verify(proof, &words)).unwrap();
        let as_bytes = match &bytes {
            Some(bytes) => refusal(|| masked::verify_bytes(bytes, &words)).unwrap(),
            None => Error::Shape("no fixed layout holds it"),
        };
        eprintln!("{name}: {as_proof}; its bytes {as_bytes}");
        assert!(matches!(as_proof, Error::Shape(_)), "{name}: {as_proof}");
        assert!(matches!(as_bytes, Error::Shape(_)), "{name}: {as_bytes}");
    }
}

/// A `format::WRAP` proof under `format::MASKED_WRAP` and a
/// `format::MASKED_WRAP` proof under `format::WRAP` are refused as another
/// format (`0x4`): by their bytes, each format's decode reading its own
/// header, and as proofs.
#[test]
fn cross_format_proofs_are_refused_both_ways() {
    let masked = masked_wrap();
    let one = one_segment();
    let words = masked.words;
    let both = [unmasked::FORMAT, masked::FORMAT];
    let unmasked_bytes = postcard::to_allocvec(&one.wrapped.proof).expect("encodes");
    let refusals = [
        (
            "format 28's bytes under 39",
            refusal(|| vos_pvm_final_verifier::verify(39, &both, &unmasked_bytes, &words)),
        ),
        (
            "format 39's bytes under 28",
            refusal(|| vos_pvm_final_verifier::verify(28, &both, &masked.bytes, &words)),
        ),
        (
            "format 28's proof to the masked verifier",
            refusal(|| masked::verify(one.wrapped.proof.clone(), &words)),
        ),
        (
            "format 39's proof to the unmasked verifier",
            refusal(|| unmasked::verify(masked.proof.clone(), &words)),
        ),
    ];
    for (name, refused) in refusals {
        let error = refused.unwrap();
        eprintln!("{name}: {error}");
        assert!(matches!(error, Error::Format), "{name}: {error}");
        assert_eq!(error.code(), 4);
    }
}

/// The layout read whole: a truncation at any of a spread of lengths (each
/// field's start among them, and the last bytes) is refused as undecodable,
/// and so is any byte after the last field.
#[test]
fn the_layout_refuses_truncations_and_trailing_bytes() {
    let masked = masked_wrap();
    let bytes = &masked.bytes;
    let len = bytes.len();
    let lengths = (0..256)
        .chain((256..len).step_by(997))
        .chain(len.saturating_sub(256)..len);
    for cut in lengths {
        assert!(
            matches!(masked::decode(&bytes[..cut]), Err(Error::Decode)),
            "cut at {cut}"
        );
    }
    for byte in 0..=u8::MAX {
        let mut longer = bytes.clone();
        longer.push(byte);
        assert!(
            matches!(masked::decode(&longer), Err(Error::Decode)),
            "a trailing {byte:#x}"
        );
    }
}

/// The masked wrap on the JAM-only host, by the production guest (format
/// 39 alone): accepted within 125M gas of verify and 4M of decode (format
/// 28's postcard: 19.9M), its phases reported beside `format::WRAP`'s on the
/// same witness, by the test guest (28 beside 39); a proof tampered at its
/// middle byte, and other words, refused without a panic; 28 refused by the
/// production guest as a format it does not link.
#[test]
fn the_masked_wrap_verifies_on_the_jam_only_host() {
    let (program, elf_len) = jam::program();
    let (test_program, test_elf_len) = jam::test_program();
    let masked = masked_wrap();
    let one = one_segment();
    let unmasked_bytes = postcard::to_allocvec(&one.wrapped.proof).expect("encodes");
    let mut phases = Vec::new();
    for (format, bytes, program, elf_len) in [
        (
            unmasked::FORMAT,
            &unmasked_bytes,
            &test_program,
            test_elf_len,
        ),
        (masked::FORMAT, &masked.bytes, &program, elf_len),
    ] {
        let request = jam::words_request(format, &masked.words);
        let (gas, report) = jam::run(program, &request, bytes);
        let [start, lookup, decode, end] = report.gas;
        let (decode, verify) = (lookup - decode, decode - end);
        eprintln!(
            "format {format} on the JAM-only host: {gas} gas ({:.1}M): lookup {}, decode {decode}, \
             verify {verify}; {} bytes, program {} bytes (ELF {elf_len}); heap peak {} KiB, high \
             water {} KiB, {} allocations",
            gas as f64 / 1e6,
            start - lookup,
            bytes.len(),
            program.len(),
            report.peak_live >> 10,
            report.high_water >> 10,
            report.allocs,
        );
        assert_eq!(report.verdict, jam::ACCEPT, "{}", report.error);
        phases.push((decode, verify));
    }
    let (decode, verify) = phases[1];
    assert!(decode <= 4_000_000, "decode {decode} gas");
    assert!(verify <= 125_000_000, "verify {verify} gas");

    let request = jam::words_request(masked::FORMAT, &masked.words);
    let mut tampered = masked.bytes.clone();
    tampered[masked.bytes.len() / 2] ^= 1;
    let (gas, report) = jam::run(&program, &request, &tampered);
    eprintln!(
        "a tampered byte: verdict {}, {gas} gas: {}",
        report.verdict, report.error
    );
    assert_ne!(report.verdict, jam::ACCEPT);
    let mut words = masked.words;
    words[3] ^= 1;
    let (gas, report) = jam::run(
        &program,
        &jam::words_request(masked::FORMAT, &words),
        &masked.bytes,
    );
    eprintln!("other words: {gas} gas: {}", report.error);
    assert_eq!(report.verdict, jam::REJECT);

    let request = jam::words_request(unmasked::FORMAT, &masked.words);
    let (_, report) = jam::run(&program, &request, &unmasked_bytes);
    assert_eq!(report.verdict, jam::UNDECODABLE, "{}", report.error);
    assert_eq!(report.error, Error::Format.to_string());
}

/// A hidden value, as each carrier would hold it: `aligned` its
/// little-endian words, for the carriers made of 32-bit words (the fixed
/// layout, the public words), where every field starts at a word's
/// boundary; `postcard` its postcard encoding, or `None` where that is
/// shorter than 4 bytes (a chance hit in a proof's bytes).
struct Needle {
    name: String,
    aligned: Vec<u8>,
    postcard: Option<Vec<u8>>,
}

impl Needle {
    fn new(name: String, aligned: Vec<u8>, postcard: Vec<u8>) -> Self {
        Self {
            name,
            aligned,
            postcard: (postcard.len() >= 4).then_some(postcard),
        }
    }

    /// A 64-bit word: whole, and each 32-bit half, those below 2^16 left
    /// out (a small count a layout holds is no hidden state).
    fn words(name: String, value: u64) -> Vec<Self> {
        let encode = |value: u64| postcard::to_allocvec(&value).expect("encodes");
        let mut needles = Vec::new();
        if value >= 1 << 16 {
            needles.push(Self::new(
                name.clone(),
                value.to_le_bytes().to_vec(),
                encode(value),
            ));
        }
        for (half, word) in [(0, value as u32), (1, (value >> 32) as u32)] {
            if word >= 1 << 16 {
                needles.push(Self::new(
                    format!("{name}, half {half}"),
                    word.to_le_bytes().to_vec(),
                    encode(u64::from(word)),
                ));
            }
        }
        needles
    }

    /// A digest's bytes, held as they are.
    fn digest(name: String, bytes: &[u8]) -> Self {
        Self::new(name, bytes.to_vec(), bytes.to_vec())
    }

    /// M31 limbs, each a word.
    fn limbs(name: String, limbs: &[BaseField]) -> Self {
        Self::new(
            name,
            limbs.iter().flat_map(|limb| limb.0.to_le_bytes()).collect(),
            limbs
                .iter()
                .flat_map(|limb| postcard::to_allocvec(&limb.0).expect("encodes"))
                .collect(),
        )
    }
}

/// No hidden state of the run is in any carrier of its masked
/// wrap (its fixed-layout bytes, its postcard encoding, its public words):
/// neither the segment's step count (its final timestamp), its pcs, its
/// registers but φ9..12 (the io-hash's, public), its memory roots and
/// `memory_commitment` at both ends, nor the root proof's commitments and
/// claimed sums (the wrap's private witness), nor a plain BLAKE2b-256 of the
/// run's arguments (this kernel runs on none).
#[test]
fn no_hidden_state_is_in_the_masked_wraps_carriers() {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let masked = masked_wrap();
    let one = one_segment();
    let segment = &one.run.segments[0];
    let mut needles = Vec::new();
    for (end, state) in [
        ("initial", &segment.initial_state),
        ("final", &segment.final_state),
    ] {
        needles.extend(Needle::words(format!("{end} timestamp"), state.timestamp));
        needles.extend(Needle::words(format!("{end} pc"), u64::from(state.pc)));
        for (i, &register) in state.registers.iter().enumerate() {
            if !(9..=12).contains(&i) {
                needles.extend(Needle::words(format!("{end} φ{i}"), register));
            }
        }
        needles.push(Needle::digest(
            format!("{end} memory root"),
            &state.memory_root,
        ));
        needles.push(Needle::digest(
            format!("{end} memory commitment"),
            &state.memory_commitment,
        ));
    }
    let root = &one.root.proof;
    for (tree, commitment) in root.stark_proof.commitments.iter().enumerate() {
        needles.push(Needle::limbs(
            format!("the root proof's root {tree}"),
            &commitment.0,
        ));
    }
    for (component, sum) in root.claimed_sums.iter().enumerate() {
        needles.push(Needle::limbs(
            format!("the root proof's claimed sum {component}"),
            &sum.to_m31_array(),
        ));
    }
    needles.push(Needle::digest(
        "BLAKE2b-256 of the run's arguments".into(),
        &Blake2b::<U32>::digest(b""),
    ));

    let words: Vec<u8> = masked.words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let postcard = postcard::to_allocvec(&masked.proof).expect("encodes");
    let aligned = |bytes: &[u8], needle: &[u8]| {
        (0..bytes.len().saturating_sub(needle.len()) + 1)
            .step_by(4)
            .any(|at| bytes[at..].starts_with(needle))
    };
    let mut found = Vec::new();
    for needle in &needles {
        for (carrier, bytes) in [("the fixed layout", &masked.bytes), ("the words", &words)] {
            if aligned(bytes, &needle.aligned) {
                found.push(format!("{} in {carrier}", needle.name));
            }
        }
        if let Some(encoded) = &needle.postcard
            && postcard
                .windows(encoded.len())
                .any(|window| window == encoded)
        {
            found.push(format!("{} in postcard", needle.name));
        }
    }
    eprintln!(
        "{} needles ({} in postcard) over the fixed layout ({} B), postcard ({} B) and the \
         words: {} found",
        needles.len(),
        needles
            .iter()
            .filter(|needle| needle.postcard.is_some())
            .count(),
        masked.bytes.len(),
        postcard.len(),
        found.len()
    );
    assert!(needles.len() > 20, "{} needles", needles.len());
    assert!(found.is_empty(), "{found:#?}");

    // The control: the search finds each value where it is public, the
    // segment proof's and the root proof's postcard encodings (but the
    // halves of a word, which postcard holds whole, and the arguments'
    // hash, which no proof holds).
    let holders = [
        postcard::to_allocvec(segment).expect("encodes"),
        postcard::to_allocvec(root).expect("encodes"),
    ];
    let missed: Vec<&str> = needles
        .iter()
        .filter(|needle| !needle.name.contains("half") && !needle.name.contains("arguments"))
        .filter(|needle| {
            let encoded = needle.postcard.as_ref().expect("encoded");
            !holders
                .iter()
                .any(|bytes| bytes.windows(encoded.len()).any(|window| window == encoded))
        })
        .map(|needle| needle.name.as_str())
        .collect();
    assert!(missed.is_empty(), "the control misses {missed:?}");
}

/// The masking's heavy gates on the real wrap (`heavy-gates`, `just
/// test-proof`).
#[cfg(feature = "heavy-gates")]
mod heavy;
