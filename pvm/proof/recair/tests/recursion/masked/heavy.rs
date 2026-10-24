//! The masking's heavy gates on the real wrap (`heavy-gates`, `just
//! test-proof`).

use super::*;

use std::path::{Path, PathBuf};

use crate::common::leakage::{Fields, Key, Verdicts, indistinguishable, published, uniform};
use crate::wrap::whole_run_root;
use vos_pvm_proof::program_id::IdPreimage;
use vos_pvm_recair::tree::Node;

/// Proofs a witness: `LEAKAGE_WRAP_N`, 16 unless it is set; at least
/// 16, the least at which the unmasked control fails.
fn n() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        let n = crate::common::leakage::heavy_n("LEAKAGE_WRAP_N", 16);
        assert!(
            n >= 16,
            "LEAKAGE_WRAP_N {n}: below 16 the unmasked control passes"
        );
        n
    })
}
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
    for seed in 0..n() as u64 {
        let (proof, _) =
            wrap::prove_masked(&finalized, MaskRng::Seeded(seed), |_| {}).expect("proves");
        let values = published(&proof.stark_proof, &proof.claimed_sums);
        fields.add(&values);
        if first.len() < 2 {
            first.push(values);
        }
    }
    eprintln!(
        "{name}: {} masked wraps in {:.1}s, {} fields each",
        n(),
        started.elapsed().as_secs_f64(),
        fields.0.len()
    );
    let control = wrap::prove_unmasked(&finalized).expect("proves");
    let control = published(&control.stark_proof, &control.claimed_sums);
    let mut unmasked = Fields::default();
    for _ in 0..n() {
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
                let (proof, _) =
                    wrap::prove_masked(&finalized, MaskRng::Seeded(seed), |_| {}).expect("proves");
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

/// Witness indistinguishability on the real wrap: each published field of
/// the two witnesses' masked wraps alike; the unmasked control fails.
#[test]
fn heavy_the_masked_wraps_openings_do_not_depend_on_the_witness() {
    let [a, b] = witnesses();
    let mut verdicts = Verdicts::new("indistinguishability, the real wrap");
    indistinguishable(&mut verdicts, "6000/6001", &a.fields, &b.fields, n());
    verdicts.report();
    let refused = verdicts.refused();
    assert!(refused.is_empty(), "{:?}", &refused[..refused.len().min(8)]);
    let mut control = Verdicts::new("indistinguishability's control on the real wrap, unmasked");
    indistinguishable(&mut control, "6000/6001", &a.unmasked, &b.unmasked, n());
    control.report();
    assert!(!control.refused().is_empty(), "the unmasked wrap passes");
}

/// Uniformity on the real wrap: each published field of either witness's
/// proofs uniform over M31 (exact at N ≤ 64). Against a leak the two
/// witnesses share, this is the real wrap's sharper test: at N ≤ 64 the
/// two-sample test finds only a field nearly fixed by the witness.
#[test]
fn heavy_the_masked_wraps_openings_are_uniform() {
    let [a, b] = witnesses();
    let mut verdicts = Verdicts::new("uniformity, the real wrap");
    uniform(&mut verdicts, &a.fields, n());
    uniform(&mut verdicts, &b.fields, n());
    verdicts.report();
    let refused = verdicts.refused();
    assert!(refused.is_empty(), "{:?}", &refused[..refused.len().min(8)]);
}

/// Fresh randomness on the real wrap: two proofs of one witness share no
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

/// The verify gates as the maximum over 12 seeds of the one-segment run's
/// masked wrap ([`gate_proofs`]): on the JAM-only host the decode at most
/// 4M gas and the verify at most 125M; in Wasm (the final verifier's blob,
/// `just judge-wasm`) at most 50M instructions under the PVF's semantics.
/// Each seed's witness hashes are held to the most 24 distinct queries can
/// take, and each gate also to its cost there, extrapolated along the
/// seeds' fit.
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
    let most_trees =
        most_witness_hashes(masked::LOG_DEGREE_BOUND + 5, 24) * 3 + most_witness_hashes(16 + 5, 24);
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
    let blob =
        wasm.join("blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm");
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
