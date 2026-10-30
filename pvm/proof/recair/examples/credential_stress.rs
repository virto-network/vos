//! The credential prover and verifier pair's completeness under volume:
//! the seeds `first..first + count`, each seed's statement of each kind
//! named proved masked under the format with the seed's masks and verified,
//! a seed that fails printed as it is found, a refused proof apart from a
//! statement or a prover that fails. A seed fixes its statement and its masks, so a refused proof
//! is made again byte for byte from its seed, the kind and the format.
//!
//! An owner statement of seed `s` is the credential tests'
//! `owner_statement(s)`; an auth statement is a lone member at a random
//! slot. The admitted format's proofs are verified from their bytes by the
//! final verifier; another format's, by the native verifier.
//!
//! `cargo run --release -p vos-pvm-recair --example credential_stress -- THREADS FIRST COUNT [owner|auth|both] [44]`

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm_final_verifier::credential::{self as verifier, CredentialKind, CredentialProof};
use vos_pvm_proof::format::{CREDENTIAL_PROOF, Format};
use vos_pvm_recair::credential::{self, AuthPublic, AuthWitness, OwnerPublic, Statement, Words};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::credentials::{DEPTH, EMPTY, P, Tag, compress, leaf, root_of};

/// A preprocessed root.
type Root = Blake2sHash;

/// A kind's name, the kind, and its statement of a seed.
type Kind = (&'static str, CredentialKind, fn(u64) -> Statement);

/// The credential tests' generator.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn digest(&mut self) -> Words {
        core::array::from_fn(|_| (self.next_u64() % u64::from(P)) as u32)
    }
}

fn owner(seed: u64) -> Statement {
    let mut rng = Rng(seed);
    let secret = rng.digest();
    let owner = compress(&Tag::Owner.block(), &secret);
    Statement::Owner(
        OwnerPublic {
            owner,
            binding: rng.digest(),
        },
        secret,
    )
}

fn auth(seed: u64) -> Statement {
    let mut rng = Rng(seed);
    let secret = rng.digest();
    let slot = rng.next_u64() as u32;
    let siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    let member = compress(&Tag::Member.block(), &secret);
    let scope = rng.digest();
    Statement::Auth(
        AuthPublic {
            map_root: root_of(&leaf(&member), slot, &siblings),
            scope,
            nullifier: compress(&compress(&Tag::Nf.block(), &secret), &scope),
            binding: rng.digest(),
        },
        AuthWitness {
            secret,
            slot,
            siblings,
        },
    )
}

/// How a seed's round failed.
enum Failure {
    /// The witness or the prover failed.
    Prove(String),
    /// The verifier refused the proof.
    Refused(String),
}

/// Proves `statement` under `format` with seed `seed`'s masks and verifies
/// it against `root`, `format`'s preprocessed root of the statement's
/// circuit, for a format other than the admitted one (whose verifier holds
/// its pins).
fn round(statement: &Statement, format: &Format, root: Root, seed: u64) -> Result<(), Failure> {
    let failed = |stage: &str, error: &dyn core::fmt::Debug| format!("{stage}: {error:?}");
    let finalized = credential::witness(statement)
        .map_err(|error| Failure::Prove(failed("witness", &error)))?;
    let (proof, _) = credential::prove_on::<Blake2sM31MerkleChannel>(
        format,
        &finalized.circuit,
        &finalized.witness,
        MaskRng::Seeded(seed),
    )
    .map_err(|error| Failure::Prove(failed("prove", &error)))?;
    let words = statement.words();
    let refused = |error: &dyn core::fmt::Debug| Failure::Refused(failed("verify", error));
    if format.number != CREDENTIAL_PROOF.number {
        return credential::verify_on::<Blake2sM31MerkleChannel>(format, root, &words, &proof)
            .map_err(|error| refused(&error));
    }
    let proof = CredentialProof {
        format_version: format.number,
        interaction_pow: proof.interaction_pow,
        claimed_sums: proof.claimed_sums.try_into().expect("two claimed sums"),
        stark_proof: proof.stark_proof,
    };
    let bytes = verifier::encode(&proof).ok_or_else(|| Failure::Prove("encode".into()))?;
    let kind = statement.kind().expect("an admitted kind");
    verifier::verify_bytes(kind, &words, &bytes).map_err(|error| refused(&error))
}

const USAGE: &str = "credential_stress THREADS FIRST COUNT [owner|auth|both] [44]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let number = |i: usize| -> u64 {
        args.get(i)
            .and_then(|arg| arg.parse().ok())
            .unwrap_or_else(|| panic!("usage: {USAGE}"))
    };
    let (threads, first, count) = (number(0) as usize, number(1), number(2));
    let kinds: &[Kind] = match args.get(3).map(String::as_str) {
        None | Some("both") => &[
            ("owner", CredentialKind::Owner, owner),
            ("auth", CredentialKind::Auth, auth),
        ],
        Some("owner") => &[("owner", CredentialKind::Owner, owner)],
        Some("auth") => &[("auth", CredentialKind::Auth, auth)],
        Some(_) => panic!("usage: {USAGE}"),
    };
    let format = match args.get(4).map(String::as_str) {
        None | Some("44") => &CREDENTIAL_PROOF,
        Some(_) => panic!("usage: {USAGE}"),
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("a pool");
    let roots: Vec<Root> = pool.install(|| {
        kinds
            .iter()
            .map(|&(_, kind, _)| {
                credential::preprocessed_root::<Blake2sM31MerkleChannel>(
                    format,
                    &credential::circuit(Some(kind)),
                )
                .expect("the circuit's root")
            })
            .collect()
    });
    let (done, refused, failed) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let started = Instant::now();
    let report = |done: usize| {
        println!(
            "{done} proofs, {} refused, {} failed to prove, {:.0} s",
            refused.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed),
            started.elapsed().as_secs_f64()
        )
    };
    pool.install(|| {
        (first..first + count).into_par_iter().for_each(|seed| {
            for (&(name, _, statement), &root) in kinds.iter().zip(&roots) {
                let at = format!("{name}, format {}, seed {seed}", format.number);
                match round(&statement(seed), format, root, seed) {
                    Ok(()) => {}
                    Err(Failure::Refused(error)) => {
                        refused.fetch_add(1, Ordering::Relaxed);
                        println!("refused: {at}: {error}");
                    }
                    Err(Failure::Prove(error)) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        println!("failed to prove: {at}: {error}");
                    }
                }
                let done = done.fetch_add(1, Ordering::Relaxed) + 1;
                if done.is_multiple_of(1000) {
                    report(done);
                }
            }
        });
    });
    print!("total from seed {first}: ");
    report(done.into_inner());
}
