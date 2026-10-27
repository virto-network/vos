//! The credential proofs' x86 timings (slice 7's 7.10 gate): auth, owner,
//! and membership and payment together, each proved masked under formats
//! 42 and 44 on the Blake2s-M31 channel, `ROUNDS` times after two warm-ups;
//! the median and the 95th percentile of the prove times, the PoW grinds
//! alone (20 and 16 bits, `GRINDS` of each), R1, the verify time and the
//! proof's bytes. Each thread count named on the command line (1, 4 and 8
//! if none) runs in a rayon pool of its own; the cores are the caller's
//! (`taskset`).
//!
//! `cargo run --release -p vos-pvm-recair --example credential_timing -- 4`

use std::time::{Duration, Instant};

use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::proof_of_work::GrindOps;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_final_verifier::credential::{self as verifier, encode};
use vos_pvm_proof::format::{CREDENTIAL_PROOF, CREDENTIAL_PROOF_44, Format};
use vos_pvm_recair::credential::{self, AuthPublic, AuthWitness, OwnerPublic, Statement, Words};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::credentials::{DEPTH, EMPTY, Tag, compress, leaf, root_of};

const ROUNDS: usize = 40;
const GRINDS: u64 = 300;

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

/// The median and the 95th percentile of `times`, in ms.
fn quantiles(mut times: Vec<Duration>) -> (f64, f64) {
    times.sort();
    let at = |q: f64| ms(times[((times.len() as f64 * q) as usize).min(times.len() - 1)]);
    (at(0.5), at(0.95))
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn grinds(bits: u32) {
    let grind: Vec<Duration> = (0..GRINDS)
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
    let mean = ms(grind.iter().sum::<Duration>() / grind.len() as u32);
    let (p50, p95) = quantiles(grind);
    println!("  PoW {bits} grind alone: mean {mean:.1} ms, p50 {p50:.1} ms, p95 {p95:.1} ms");
}

fn proves(name: &str, statement: &Statement, format: &Format) {
    let finalized = credential::witness(statement).expect("the witness satisfies it");
    let root = credential::preprocessed_root::<Blake2sM31MerkleChannel>(format, &finalized.circuit)
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
        credential::verify_on::<Blake2sM31MerkleChannel>(format, root, &statement.words(), &proof)
            .unwrap();
        let verify = started.elapsed();
        let proof = verifier::CredentialProof {
            format_version: format.number,
            interaction_pow: proof.interaction_pow,
            claimed_sums: proof.claimed_sums.clone().try_into().unwrap(),
            stark_proof: proof.stark_proof.clone(),
        };
        bytes = encode(&proof).unwrap().len();
        if let Some(kind) = statement
            .kind()
            .filter(|_| format.number == CREDENTIAL_PROOF.number)
        {
            verifier::verify(kind, &statement.words(), proof).unwrap();
        }
        if round >= 2 {
            proves.push(took);
            r1.push(stats.rank_check);
            verifies.push(verify);
        }
    }
    let (p50, p95) = quantiles(proves);
    println!(
        "  {name}, format {}: prove p50 {p50:.1} ms, p95 {p95:.1} ms; R1 p50 {:.1} ms; verify p50 {:.2} ms; {bytes} bytes",
        format.number,
        quantiles(r1).0,
        quantiles(verifies).0,
    );
}

fn main() {
    let counts: Vec<usize> = std::env::args()
        .skip(1)
        .map(|count| count.parse().expect("a thread count"))
        .collect();
    let counts = if counts.is_empty() {
        vec![1, 4, 8]
    } else {
        counts
    };
    for threads in counts {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("a pool");
        println!("{threads} threads:");
        pool.install(|| {
            grinds(20);
            grinds(16);
            for format in [&CREDENTIAL_PROOF, &CREDENTIAL_PROOF_44] {
                for (name, statement) in statements() {
                    proves(name, &statement, format);
                }
            }
        });
    }
}
