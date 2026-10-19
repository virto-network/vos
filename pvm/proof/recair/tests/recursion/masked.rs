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
