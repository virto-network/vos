//! What a device proof (format 47) costs ingress: the stock auth kernel's
//! proof of a member at slot 0 verified by its program's verifier on one
//! thread, and the time to refuse well-formed junk: a wrong PoW, a wrong
//! interaction PoW, a commitment root changed, the honest proof against
//! another claim's io-hash, and one whose last byte is cut, each the
//! median and the 95th percentile of `ROUNDS` after two warm-ups.
//!
//! The device verifier's order: the decode and its canonical re-encoding,
//! the interaction PoW, the logup totals, the composition at the OODS
//! point, then the PoW, then the decommitments; a wrong PoW is refused
//! after every step before the decommitments.
//!
//! `just build-programs`, then `cargo run --release -p vos-phone
//! --example device_ingress`

use std::time::{Duration, Instant};

use vos_abi::credentials::{DEPTH, EMPTY, member_root};
use vos_light::release::device;
use vos_light::{AuthWitness, Call, Digest, Prover, ProverConfig, Threads, claim_io};
use vos_light::{derive_secret, member};
use vos_pvm_device::{FORMAT, Program, decode, encode};

const ROUNDS: usize = 200;

/// The median and 95th percentile of `ROUNDS` runs of `run`, after two
/// warm-ups, each asserted to give `ok`.
fn timed(ok: bool, mut run: impl FnMut() -> bool) -> (Duration, Duration) {
    for _ in 0..2 {
        assert_eq!(run(), ok);
    }
    let mut times: Vec<Duration> = (0..ROUNDS)
        .map(|_| {
            let started = Instant::now();
            assert_eq!(run(), ok);
            started.elapsed()
        })
        .collect();
    times.sort();
    (times[times.len() / 2], times[times.len() * 95 / 100])
}

fn main() {
    let elf =
        std::fs::read(vos_testkit::programs::program_elf("vos-credentials")).expect("the ELF");
    let auth = device(&elf, "auth").expect("the stock auth kernel's artifact");
    let program = vos_light::DeviceProgram::from_release(&auth).expect("its program");
    let verifier = Program::from_release(&auth)
        .expect("its program")
        .verifier();
    let secret = derive_secret(&[0x5e; 32], &[7; 32]);
    let siblings: [_; DEPTH] = std::array::from_fn(|level| EMPTY[level]);
    let witness = AuthWitness {
        root: Digest(member_root(&member(&secret).0, 0, &siblings)),
        slot: 0,
        siblings: siblings.map(Digest),
    };
    let call = Call {
        space: [0x53; 32],
        agent: 7,
        instance: 3,
        method: 0x5ca1_ab1e,
        arguments: b"ingress".to_vec(),
        nonce: [0x4e; 16],
        expires_ms: 1_800_000_000_000,
    };
    let prover = Prover::new(ProverConfig {
        threads: Threads::Auto,
        ..ProverConfig::default()
    })
    .expect("a prover");
    let proven = prover
        .prove_auth(&secret, &witness, b"login", &call, &program)
        .expect("the kernel proves");
    let io = claim_io(&proven.claim).expect("the io-hash");
    let honest = proven.proof;
    let mut pow = decode(&FORMAT, &honest).unwrap();
    pow.stark_proof.0.proof_of_work ^= 1;
    let pow = encode(&FORMAT, &pow).unwrap();
    let mut interaction = decode(&FORMAT, &honest).unwrap();
    interaction.interaction_pow ^= 1;
    let interaction = encode(&FORMAT, &interaction).unwrap();
    let mut root = decode(&FORMAT, &honest).unwrap();
    root.stark_proof.0.commitments[1].0[0] ^= 1;
    let root = encode(&FORMAT, &root).unwrap();
    let mut claim = proven.claim.clone();
    claim[0] ^= 1;
    let other = claim_io(&claim).expect("the io-hash");
    let cut = &honest[..honest.len() - 1];
    let cases: [(&str, &[u8; 32], &[u8], bool); 6] = [
        ("verified", &io, &honest, true),
        ("a wrong PoW, refused", &io, &pow, false),
        ("a wrong interaction PoW, refused", &io, &interaction, false),
        ("a commitment root changed, refused", &io, &root, false),
        ("another claim's io-hash, refused", &other, &honest, false),
        ("a byte cut, refused", &io, cut, false),
    ];
    println!(
        "format {}, {ROUNDS} runs each, one thread; median / 95th percentile",
        vos_pvm_device::FORMAT.number
    );
    let decoded = decode(&FORMAT, &honest).unwrap();
    let released = Program::from_release(&auth).unwrap();
    let device_program = released.program();
    let header = device_program.header();
    let steps: [(&str, &dyn Fn() -> bool); 5] = [
        ("its masked format and layout, at install", &|| {
            vos_pvm_device::masked::device_format(&vos_pvm_device::FORMAT, device_program, &header)
                .is_some()
        }),
        ("the io-hash's public values", &|| {
            !vos_pvm_proof::masked::device_public_values(&io).is_empty()
        }),
        ("its decode, canonical", &|| {
            decode(&FORMAT, &honest).is_ok()
        }),
        ("of which the re-encoding", &|| {
            encode(&FORMAT, &decoded).is_some()
        }),
        ("a copy of the decoded proof", &|| {
            std::hint::black_box(decoded.stark_proof.clone());
            true
        }),
    ];
    for (name, step) in steps {
        let (median, p95) = timed(true, step);
        println!(
            "stock auth, {name}: {:.3} / {:.3} ms",
            median.as_secs_f64() * 1e3,
            p95.as_secs_f64() * 1e3
        );
    }
    for (name, io, bytes, ok) in cases {
        let (median, p95) = timed(ok, || verifier.verify(io, bytes).is_ok());
        println!(
            "stock auth ({} bytes), {name}: {:.3} / {:.3} ms",
            honest.len(),
            median.as_secs_f64() * 1e3,
            p95.as_secs_f64() * 1e3
        );
    }
}
