//! What a credential proof costs ingress (slice 7's 7.11 gates): the final
//! verifier's `verify_bytes` on one thread, the time to refuse a proof
//! whose PoW, or whose interaction PoW, is wrong, and one whose last byte
//! is cut, each the median and the 95th percentile of `ROUNDS` after two
//! warm-ups, for auth and owner proofs. With `--seeds`, it writes the fuzz
//! targets' replay seeds instead: an honest proof of each kind for
//! `credential_verify_bytes` (its kind, its words, its bytes) and a
//! request carrying one for `credentialed_decode`.
//!
//! `cargo run --release -p vos-pvm-recair --example credential_ingress`

use std::path::Path;
use std::time::{Duration, Instant};

use vos_pvm_final_verifier::credential::{self as verifier, CredentialKind, decode, encode};
use vos_pvm_recair::credential::{AuthPublic, AuthWitness, OwnerPublic, Statement, Words, prove};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::Encode;
use vos_wire::credentials::{DEPTH, EMPTY, Tag, compress, digest, leaf, root_of};
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::ingress::{CredentialPublic, Credentialed};

const ROUNDS: usize = 200;

fn words(seed: u32) -> Words {
    core::array::from_fn(|i| {
        (seed.wrapping_mul(2_654_435_761).wrapping_add(i as u32 * 97)) % 0x7fff_ffff
    })
}

/// An auth and an owner statement of one secret.
fn statements() -> [(CredentialKind, Statement); 2] {
    let secret = words(7);
    let member = compress(&Tag::Member.block(), &secret);
    let slot = 0x0bad_cafe;
    let siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    let scope = words(11);
    let binding = words(13);
    let auth = AuthPublic {
        map_root: root_of(&leaf(&member), slot, &siblings),
        scope,
        nullifier: compress(&compress(&Tag::Nf.block(), &secret), &scope),
        binding,
    };
    let witness = AuthWitness {
        secret,
        slot,
        siblings,
    };
    let owner = OwnerPublic {
        owner: compress(&Tag::Owner.block(), &secret),
        binding,
    };
    [
        (CredentialKind::Auth, Statement::Auth(auth, witness)),
        (CredentialKind::Owner, Statement::Owner(owner, secret)),
    ]
}

fn percentiles(mut times: Vec<Duration>) -> (Duration, Duration) {
    times.sort();
    (times[times.len() / 2], times[times.len() * 95 / 100])
}

/// The median and 95th percentile of `ROUNDS` runs of `refuse`, after two
/// warm-ups, each asserted to give `ok`.
fn timed(ok: bool, mut run: impl FnMut() -> bool) -> (Duration, Duration) {
    for _ in 0..2 {
        assert_eq!(run(), ok);
    }
    let times = (0..ROUNDS)
        .map(|_| {
            let started = Instant::now();
            assert_eq!(run(), ok);
            started.elapsed()
        })
        .collect();
    percentiles(times)
}

fn seeds(directory: &Path) {
    let fuzz = directory.join("credential_verify_bytes");
    let requests = directory.join("credentialed_decode");
    std::fs::create_dir_all(&fuzz).unwrap();
    std::fs::create_dir_all(&requests).unwrap();
    for (kind, statement) in statements() {
        let (proof, _) = prove(&statement, MaskRng::default()).expect("proves");
        let bytes = encode(&proof).unwrap();
        let mut input = vec![kind as u8];
        for word in statement.words() {
            input.extend_from_slice(&word.to_le_bytes());
        }
        input.extend_from_slice(&bytes);
        let name = format!("{kind:?}").to_lowercase();
        std::fs::write(fuzz.join(&name), &input).unwrap();
        let public = match statement {
            Statement::Auth(public, _) => CredentialPublic::Auth {
                map_root: digest(&public.map_root),
                scope: digest(&public.scope),
                nullifier: digest(&public.nullifier),
                binding: digest(&public.binding),
            },
            _ => CredentialPublic::Owner {
                owner: digest(&words(3)),
                binding: digest(&words(13)),
            },
        };
        let request = Credentialed {
            instance: InstanceId(3),
            method: MethodId(0x0102_0304),
            arguments: vec![1, 2, 3],
            nonce: [9; 16],
            expires_ms: 1_700_000_000_000,
            format: verifier::FORMAT,
            public,
            proof: bytes[..256].to_vec(),
        };
        std::fs::write(requests.join(&name), (AgentId(7), request).encode()).unwrap();
    }
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    if let Some("--seeds") = arguments.next().as_deref() {
        let directory = arguments.next().expect("a replay directory");
        seeds(Path::new(&directory));
        return;
    }
    println!("{ROUNDS} runs each, one thread; median / 95th percentile");
    for (kind, statement) in statements() {
        let words = statement.words();
        let (proof, _) = prove(&statement, MaskRng::default()).expect("proves");
        let honest = encode(&proof).unwrap();
        let mut pow = decode(&honest).unwrap();
        pow.stark_proof.0.proof_of_work ^= 1;
        let pow = encode(&pow).unwrap();
        let mut interaction = decode(&honest).unwrap();
        interaction.interaction_pow ^= 1;
        let interaction = encode(&interaction).unwrap();
        let cut = &honest[..honest.len() - 1];
        let verify = |bytes: &[u8]| verifier::verify_bytes(kind, &words, bytes).is_ok();
        let cases: [(&str, &[u8], bool); 4] = [
            ("verified", &honest, true),
            ("a wrong PoW, refused", &pow, false),
            ("a wrong interaction PoW, refused", &interaction, false),
            ("a byte cut, refused", cut, false),
        ];
        for (name, bytes, ok) in cases {
            let (median, p95) = timed(ok, || verify(bytes));
            println!(
                "{kind:?} ({} bytes), {name}: {:.3} / {:.3} ms",
                honest.len(),
                median.as_secs_f64() * 1e3,
                p95.as_secs_f64() * 1e3
            );
        }
    }
}
