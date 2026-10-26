//! The credential proofs' x86 timings (slice 7's 7.10 gate): auth, owner,
//! and membership and payment together, each proved masked under format 42
//! on the Blake2s-M31 channel, and auth under format 44, `ROUNDS` times
//! after a warm-up; the median and the least prove time, the PoW grinds
//! alone (20 and 16 bits), R1, the verify time and the proof's bytes. Thread count is rayon's
//! (`RAYON_NUM_THREADS`), pinning the caller's (`taskset`).
//!
//! `cargo run --release -p vos-pvm-recair --example credential_timing`

use std::time::{Duration, Instant};

use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::proof_of_work::GrindOps;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_final_verifier::credential::{self as verifier, encode};
use vos_pvm_proof::format::{CREDENTIAL_PROOF, CREDENTIAL_PROOF_44};
use vos_pvm_recair::credential::{self, AuthPublic, AuthWitness, OwnerPublic, Statement, Words};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::credentials::{DEPTH, EMPTY, Tag, compress, leaf, root_of};

const ROUNDS: usize = 15;

fn words(seed: u32) -> Words {
    core::array::from_fn(|i| {
        (seed.wrapping_mul(2_654_435_761).wrapping_add(i as u32 * 97)) % 0x7fff_ffff
    })
}

fn statements() -> [(&'static str, Statement); 3] {
    let secret = words(7);
    let member = compress(&Tag::Member.block(), &secret);
    let slot = 0x1234_5678;
    let siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    let map_root = root_of(&leaf(&member), slot, &siblings);
    let scope = words(11);
    let binding = words(13);
    let public = AuthPublic {
        map_root,
        scope,
        nullifier: compress(&compress(&Tag::Nf.block(), &secret), &scope),
        binding,
    };
    let witness = AuthWitness {
        secret,
        slot,
        siblings,
    };
    let owner = compress(&Tag::Owner.block(), &secret);
    [
        ("auth", Statement::Auth(public, witness)),
        (
            "owner",
            Statement::Owner(OwnerPublic { owner, binding }, secret),
        ),
        (
            "membership and payment",
            Statement::Joint(public, owner, witness),
        ),
    ]
}

fn median(mut times: Vec<Duration>) -> Duration {
    times.sort();
    times[times.len() / 2]
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn main() {
    let threads = rayon::current_num_threads();
    println!("rayon threads: {threads}");
    for bits in [20, 16] {
        let grind: Vec<Duration> = (0..4 * ROUNDS as u64)
            .map(|round| {
                let mut channel = Blake2sM31Channel::default();
                channel.mix_u64(round);
                let started = Instant::now();
                let nonce = <SimdBackend as GrindOps<Blake2sM31Channel>>::grind(&channel, bits);
                let took = started.elapsed();
                assert!(channel.verify_pow_nonce(bits, nonce));
                took
            })
            .collect();
        let mean = grind.iter().sum::<Duration>() / grind.len() as u32;
        println!(
            "PoW {bits} grind alone: mean {:.1} ms, median {:.1} ms, least {:.1} ms, most {:.1} ms",
            ms(mean),
            ms(median(grind.clone())),
            ms(*grind.iter().min().unwrap()),
            ms(*grind.iter().max().unwrap())
        );
    }
    let [auth, ..] = statements();
    let mut runs = vec![(auth.0, auth.1, &CREDENTIAL_PROOF_44, "format 44")];
    runs.extend(
        statements()
            .into_iter()
            .map(|(name, statement)| (name, statement, &CREDENTIAL_PROOF, "format 42")),
    );
    for (name, statement, format, label) in runs {
        let finalized = credential::witness(&statement).expect("the witness satisfies it");
        let root = credential::preprocessed_root::<Blake2sM31MerkleChannel>(
            &CREDENTIAL_PROOF,
            &finalized.circuit,
        )
        .unwrap();
        let mut proves = Vec::new();
        let mut r1 = Vec::new();
        let mut verifies = Vec::new();
        let mut bytes = 0;
        for round in 0..ROUNDS + 2 {
            let started = Instant::now();
            let (proof, stats) = credential::prove_on::<Blake2sM31MerkleChannel>(
                format,
                &finalized.circuit,
                &finalized.witness,
                MaskRng::default(),
            )
            .unwrap();
            let took = started.elapsed();
            let started = Instant::now();
            credential::verify_on::<Blake2sM31MerkleChannel>(
                format,
                root,
                &statement.words(),
                &proof,
            )
            .unwrap();
            let verify = started.elapsed();
            if let Some(kind) = statement
                .kind()
                .filter(|_| format.number == CREDENTIAL_PROOF.number)
            {
                let proof = verifier::CredentialProof {
                    format_version: CREDENTIAL_PROOF.number,
                    interaction_pow: proof.interaction_pow,
                    claimed_sums: proof.claimed_sums.clone().try_into().unwrap(),
                    stark_proof: proof.stark_proof.clone(),
                };
                bytes = encode(&proof).unwrap().len();
                verifier::verify(kind, &statement.words(), proof).unwrap();
            }
            if round >= 2 {
                proves.push(took);
                r1.push(stats.rank_check);
                verifies.push(verify);
            }
        }
        println!(
            "{name}, {label}: prove median {:.1} ms, least {:.1} ms; R1 median {:.1} ms; verify median {:.2} ms; {} bytes",
            ms(median(proves.clone())),
            ms(*proves.iter().min().unwrap()),
            ms(median(r1)),
            ms(median(verifies)),
            bytes
        );
    }
}
