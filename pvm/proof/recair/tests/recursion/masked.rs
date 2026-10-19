//! The masked wrap (format 39) over the one-segment run's root, proved by
//! `vos-pvm-recair`'s masked prover from a seed, its bytes the fixed layout,
//! and verified by `vos-pvm-final-verifier`'s masked verifier.
//!
//! - **The verifier's constants are the registry's** entry for 39: its
//!   number, configuration, masking, log sizes, trees' widths and DEEP
//!   values; its preprocessed root; its bytes; FRI's rounds as the security
//!   count takes them and as `FriVerifier::commit` derives them.
//! - **Every masked field tampered** (spike 6a's 14 cases) is refused with
//!   an error, never a panic, as a proof and through its bytes; and a
//!   verifier pinning another salt count or `R` refuses the proof.
//! - **Cross-format proofs, both ways,** are refused as another format.
//! - **The bytes:** truncations and a trailing byte refused.
//! - **On the JAM-only host** the venue's refine program accepts it within
//!   format 39's gas, and refuses a tampered byte and other words.
//! - **No hidden state** of the run is in any carrier of the proof (leakage
//!   4).
//! - **Under `heavy-gates`** (`just test-proof`): leakage 2, 3 and 5 on the
//!   real wrap at 32 proofs a witness, and the verify gates (decode, verify
//!   and the PVF's Wasm instructions) as the maximum over 12 seeds.

use crate::jam;
use crate::wrap::{one_segment, values_of};

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::time::Instant;

use num_traits::{One, Zero};
use stwo::core::channel::Blake2bChannel;
use stwo::core::fields::m31::{BaseField, P};
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

/// The one-segment run's root wrapped under format 39: the proof, its
/// bytes and its public words.
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
/// input (`final-verifier/wasm/run`) and the fuzz targets' format-39 golden.
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

fn bump(value: &mut BaseField) {
    *value = BaseField::from((value.0 + 1) % P);
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
            Box::new(|p| bump(&mut p.stark_proof.0.queried_values[1][0][0])),
        ),
        (
            "a queried salt (main)",
            Box::new(|p| {
                let tree = &mut p.stark_proof.0.queried_values[1];
                let last = tree.len() - 1;
                bump(&mut tree[last][0])
            }),
        ),
        (
            "a queried salt (composition)",
            Box::new(|p| {
                let tree = &mut p.stark_proof.0.queried_values[3];
                let last = tree.len() - 1;
                bump(&mut tree[last][0])
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
/// format 39's widths, its set's trees are not the format's; with the
/// widths its pins lay out, the proof's trees are not its. And a proof with
/// a salt column or an `R` column more is refused by its shape, as a proof
/// and at its decode.
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

/// A format-28 proof under format 39 and a format-39 proof under format 28
/// are refused as another format (`0x4`): by their bytes, each format's
/// decode reading its own header, and as proofs.
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

/// The masked wrap on the JAM-only host: accepted within 125M gas of
/// verify and 4M of decode (format 28's postcard: 19.9M), its phases
/// reported beside format 28's on the same witness; a proof tampered at its
/// middle byte, and other words, refused without a panic.
#[test]
fn the_masked_wrap_verifies_on_the_jam_only_host() {
    let (program, elf_len) = jam::program();
    let masked = masked_wrap();
    let one = one_segment();
    let unmasked_bytes = postcard::to_allocvec(&one.wrapped.proof).expect("encodes");
    let mut phases = Vec::new();
    for (format, bytes) in [
        (unmasked::FORMAT, &unmasked_bytes),
        (masked::FORMAT, &masked.bytes),
    ] {
        let request = jam::words_request(format, &masked.words);
        let (gas, report) = jam::run(&program, &request, bytes);
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

/// Leakage 4: no hidden state of the run is in any carrier of its masked
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
mod heavy {
    use super::*;

    use std::path::{Path, PathBuf};

    use crate::common::leakage::{Fields, Key, Verdicts, indistinguishable, published, uniform};
    use crate::wrap::whole_run_root;
    use vos_pvm_proof::program_id::IdPreimage;
    use vos_pvm_recair::tree::Node;

    /// Proofs a witness.
    const N: usize = 32;
    /// The seeds the verify gates are the maximum over.
    const GATE_SEEDS: usize = 12;

    /// A wrap witness's N masked proofs: their fields and the first two
    /// proofs'; and its unmasked wrap's fields, N times.
    struct Proofs {
        fields: Fields,
        first: Vec<Vec<(Key, u32)>>,
        unmasked: Fields,
    }

    fn proofs_of(name: &str, root: &Node, program: &IdPreimage) -> Proofs {
        let finalized = WrapCircuit::get().finalize(&values_of(root, program));
        let started = Instant::now();
        let mut fields = Fields::default();
        let mut first = Vec::new();
        for seed in 0..N as u64 {
            let (proof, _) =
                wrap::prove_masked(&finalized, MaskRng::Seeded(seed), |_| {}).expect("proves");
            let values = published(&proof.stark_proof, &proof.claimed_sums);
            fields.add(&values);
            if first.len() < 2 {
                first.push(values);
            }
        }
        eprintln!(
            "{name}: {N} masked wraps in {:.1}s, {} fields each",
            started.elapsed().as_secs_f64(),
            fields.0.len()
        );
        let control = wrap::prove_unmasked(&finalized).expect("proves");
        let control = published(&control.stark_proof, &control.claimed_sums);
        let mut unmasked = Fields::default();
        for _ in 0..N {
            unmasked.add(&control);
        }
        Proofs {
            fields,
            first,
            unmasked,
        }
    }

    /// The one-segment run's masked wrap from [`GATE_SEEDS`] seeds of its
    /// own (from 1,000): each proof's bytes, and the public words.
    fn gate_proofs() -> &'static (Vec<Vec<u8>>, [u32; PUBLIC_WORDS]) {
        static PROOFS: OnceLock<(Vec<Vec<u8>>, [u32; PUBLIC_WORDS])> = OnceLock::new();
        PROOFS.get_or_init(|| {
            let one = one_segment();
            let finalized = WrapCircuit::get().finalize(&values_of(&one.root, &one.run.program));
            let bytes = (1_000..1_000 + GATE_SEEDS as u64)
                .map(|seed| {
                    let (proof, _) = wrap::prove_masked(&finalized, MaskRng::Seeded(seed), |_| {})
                        .expect("proves");
                    wrap::proof_bytes(&proof).expect("format 39's bytes")
                })
                .collect();
            (bytes, wrap::public_words(&finalized))
        })
    }

    /// The two witnesses: the one-segment run's root under kernel 6,000,
    /// and under 6,001 (`whole_run_root`): their public words differ in the
    /// program id alone.
    fn witnesses() -> &'static [Proofs; 2] {
        static PROOFS: OnceLock<[Proofs; 2]> = OnceLock::new();
        PROOFS.get_or_init(|| {
            let one = one_segment();
            let (root, program) = whole_run_root(6_001);
            [
                proofs_of("kernel 6000", &one.root, &one.run.program),
                proofs_of("kernel 6001", &root, &program),
            ]
        })
    }

    /// Leakage 2 on the real wrap: each published field of the two
    /// witnesses' masked wraps alike; the unmasked control fails.
    #[test]
    fn heavy_the_masked_wraps_openings_do_not_depend_on_the_witness() {
        let [a, b] = witnesses();
        let mut verdicts = Verdicts::new("leakage 2, the real wrap");
        indistinguishable(&mut verdicts, "6000/6001", &a.fields, &b.fields, N);
        verdicts.report();
        let refused = verdicts.refused();
        assert!(refused.is_empty(), "{:?}", &refused[..refused.len().min(8)]);
        let mut control = Verdicts::new("leakage 2's control on the real wrap, unmasked");
        indistinguishable(&mut control, "6000/6001", &a.unmasked, &b.unmasked, N);
        control.report();
        assert!(!control.refused().is_empty(), "the unmasked wrap passes");
    }

    /// Leakage 3 on the real wrap: each published field of either witness's
    /// proofs uniform over M31 (exact at N = 32). Against a leak the two
    /// witnesses share, this is the real wrap's sharper test: at N = 32 the
    /// two-sample test finds only a field nearly fixed by the witness.
    #[test]
    fn heavy_the_masked_wraps_openings_are_uniform() {
        let [a, b] = witnesses();
        let mut verdicts = Verdicts::new("leakage 3, the real wrap");
        uniform(&mut verdicts, &a.fields, N);
        uniform(&mut verdicts, &b.fields, N);
        verdicts.report();
        let refused = verdicts.refused();
        assert!(refused.is_empty(), "{:?}", &refused[..refused.len().min(8)]);
    }

    /// Leakage 5 on the real wrap: two proofs of one witness share no
    /// opening, nor do two witnesses' proofs from one seed.
    #[test]
    fn heavy_every_opening_of_the_masked_wrap_is_fresh() {
        let [a, b] = witnesses();
        let shared = |x: &[(Key, u32)], y: &[(Key, u32)]| {
            let y: std::collections::BTreeMap<_, _> = y.iter().copied().collect();
            x.iter()
                .filter(|(key, value)| y.get(key) == Some(value))
                .count()
        };
        assert!(a.first[0].len() > 10_000);
        assert_eq!(
            shared(&a.first[0], &a.first[1]),
            0,
            "one witness, two seeds"
        );
        assert_eq!(
            shared(&a.first[0], &b.first[0]),
            0,
            "two witnesses, one seed"
        );
        eprintln!(
            "{} openings: none shared between seeds 0 and 1 of one witness, nor between \
             two witnesses at seed 0",
            a.first[0].len()
        );
    }

    /// The witness hashes a lifted Merkle tree of `height` can decommit for
    /// `queries` distinct queries, no sibling shared: at each level, a hash
    /// for each queried node, at most the level's pairs.
    fn most_witness_hashes(height: u32, queries: usize) -> usize {
        (0..height)
            .map(|level| queries.min(1 << (height - level - 1)))
            .sum()
    }

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|dir| dir.join("Cargo.lock").exists() && dir.join("pvm").is_dir())
            .expect("the workspace's root")
            .to_path_buf()
    }

    /// A cost at `most` witness hashes, by the least-squares line through
    /// the seeds' `(hashes, cost)`: the worst shape's, extrapolated.
    fn at_worst(hashes: &[f64], costs: &[f64], most: f64) -> f64 {
        let n = hashes.len() as f64;
        let (mean_h, mean_c) = (
            hashes.iter().sum::<f64>() / n,
            costs.iter().sum::<f64>() / n,
        );
        let covariance: f64 = hashes
            .iter()
            .zip(costs)
            .map(|(h, c)| (h - mean_h) * (c - mean_c))
            .sum();
        let variance: f64 = hashes.iter().map(|h| (h - mean_h).powi(2)).sum();
        mean_c + covariance / variance * (most - mean_h)
    }

    /// The verify gates as the maximum over 12 seeds of the one-segment
    /// run's masked wrap ([`gate_proofs`]): on the JAM-only host the decode at most 4M gas
    /// and the verify at most 125M; in Wasm (the final verifier's blob,
    /// `just judge-wasm`) at most 50M instructions under the PVF's
    /// semantics. Each seed's witness hashes are held to the most 24
    /// distinct queries can take, and each gate also to its cost there,
    /// extrapolated along the seeds' fit.
    #[test]
    fn heavy_the_verify_gates_hold_over_seeds() {
        let (program, _) = jam::program();
        let (proofs, words) = gate_proofs();
        let request = jam::words_request(masked::FORMAT, words);
        let mut phases = Vec::new();
        let mut hashes = Vec::new();
        // The most witness hashes 24 distinct queries can take, no sibling
        // shared: each trace tree at the lifting height (the preprocessed
        // one at its own, 16 + 5), and each FRI layer's tree, its domain
        // less the packed leaf of 4 values, less the level a query's coset
        // pair fills (domains 22, 19, 16, 13 for fold step 3).
        let most_trees = most_witness_hashes(masked::LOG_DEGREE_BOUND + 5, 24) * 3
            + most_witness_hashes(16 + 5, 24);
        let fri_bounds: Vec<usize> = (0..4u32)
            .map(|layer| most_witness_hashes(masked::LOG_DEGREE_BOUND + 5 - 3 * layer - 3, 24))
            .collect();
        let most = (most_trees + fri_bounds.iter().sum::<usize>()) as f64;
        let mut files = Vec::new();
        for (seed, bytes) in proofs.iter().enumerate() {
            let (gas, report) = jam::run(&program, &request, bytes);
            assert_eq!(report.verdict, jam::ACCEPT, "seed {seed}: {}", report.error);
            let [_, lookup, decoded, end] = report.gas;
            let (decode, verify) = (lookup - decoded, decoded - end);
            let proof = masked::decode(bytes).expect("decodes");
            let stark = &proof.stark_proof;
            let queries = stark.queried_values[1][0].len();
            let trees: usize = stark
                .decommitments
                .iter()
                .map(|decommitment| decommitment.hash_witness.len())
                .sum();
            let fri = &stark.fri_proof;
            let fri_hashes: usize = std::iter::once(&fri.first_layer)
                .chain(&fri.inner_layers)
                .map(|layer| layer.decommitment.hash_witness.len())
                .sum();
            let fri_layers: Vec<usize> = std::iter::once(&fri.first_layer)
                .chain(&fri.inner_layers)
                .map(|layer| layer.decommitment.hash_witness.len())
                .collect();
            for (layer, (&hashes, &bound)) in fri_layers.iter().zip(&fri_bounds).enumerate() {
                assert!(
                    hashes <= bound,
                    "FRI layer {layer}: {hashes} hashes, at most {bound}"
                );
            }
            assert!(
                trees <= most_trees,
                "{trees} trace-tree hashes, at most {most_trees}"
            );
            eprintln!(
                "seed {seed}: {gas} gas, decode {decode}, verify {verify}; {} bytes; {queries} \
                 distinct queries; {trees} trace-tree witness hashes (at most {most_trees} for 24 \
                 queries), {fri_hashes} FRI",
                bytes.len()
            );
            phases.push((decode, verify));
            hashes.push((trees + fri_hashes) as f64);
            let name = format!("gate-{seed:02}");
            write(&name, masked::FORMAT, bytes, words);
            files.push(
                Path::new(env!("CARGO_TARGET_TMPDIR"))
                    .join("wrap")
                    .join(format!("{name}.proof")),
            );
        }
        let decode = phases.iter().map(|&(decode, _)| decode).max().unwrap();
        let verify = phases.iter().map(|&(_, verify)| verify).max().unwrap();
        let worst = |costs: &[f64]| at_worst(&hashes, costs, most);
        let decode_worst = worst(&phases.iter().map(|&(d, _)| d as f64).collect::<Vec<_>>());
        let verify_worst = worst(&phases.iter().map(|&(_, v)| v as f64).collect::<Vec<_>>());
        eprintln!(
            "the maximum over {GATE_SEEDS} seeds: decode {decode}, verify {verify}; at the worst \
             shape ({most} witness hashes), by the seeds' fit: decode {decode_worst:.0}, verify \
             {verify_worst:.0}"
        );
        assert!(decode <= 4_000_000, "decode {decode} gas");
        assert!(verify <= 125_000_000, "verify {verify} gas");
        assert!(
            decode_worst <= 4e6,
            "decode {decode_worst} gas at the worst shape"
        );
        assert!(
            verify_worst <= 125e6,
            "verify {verify_worst} gas at the worst shape"
        );

        let wasm = workspace().join("pvm/proof/final-verifier/wasm");
        let runner = wasm.join("run/target/release/vos-pvm-final-verifier-wasm-run");
        let blob = wasm
            .join("blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm");
        let output = std::process::Command::new(&runner)
            .arg(&blob)
            .args(["pvf", "1"])
            .args(&files)
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "{} cannot run ({error}); `just judge-wasm` builds it",
                    runner.display()
                )
            });
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let instructions: Vec<u64> = stdout
            .lines()
            .filter(|line| line.starts_with("RESULT "))
            .filter_map(|line| line.split("instructions=").nth(1))
            .filter_map(|rest| rest.split_whitespace().next()?.parse().ok())
            .collect();
        eprintln!("Wasm under the PVF's semantics: {instructions:?}");
        assert_eq!(instructions.len(), GATE_SEEDS);
        assert!(
            instructions.iter().all(|&count| count > 0),
            "{instructions:?}"
        );
        let max = *instructions.iter().max().unwrap();
        let wasm_worst = worst(&instructions.iter().map(|&n| n as f64).collect::<Vec<_>>());
        eprintln!(
            "the maximum over {GATE_SEEDS} seeds: {max} instructions; at the worst shape, by \
             the seeds' fit: {wasm_worst:.0}"
        );
        assert!(max <= 50_000_000, "{max} Wasm instructions");
        assert!(
            wasm_worst <= 50e6,
            "{wasm_worst} Wasm instructions at the worst shape"
        );
    }
}
