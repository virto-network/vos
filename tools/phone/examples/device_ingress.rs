//! What a device proof (format 46) costs ingress: the device auth kernel's
//! proof on auth's public reference statement verified by its program's
//! verifier on one thread, and the time to refuse one whose PoW, or whose
//! interaction PoW, is wrong, and one whose last byte is cut, each the
//! median and the 95th percentile of `ROUNDS` after two warm-ups.
//!
//! The device verifier's order: the decode and its canonical re-encoding,
//! the interaction PoW, the logup totals, the composition at the OODS
//! point, then the PoW, then the decommitments; a wrong PoW is refused
//! after every step before the decommitments.
//!
//! `cargo run --release -p vos-phone --example device_ingress`

use std::time::{Duration, Instant};

use vos_pvm_recair::device::{Program, auth_io, auth_reference, decode, encode};
use vos_pvm_recair::masked::MaskRng;

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
    let kernel = vos_testkit::programs::kernel("device", "auth");
    let program = Program::auth(&kernel).expect("the kernel's program");
    let arguments = auth_reference();
    let public = &arguments[arguments.len() - vos_pvm_recair::device::AUTH_PUBLIC_BYTES..];
    let io = auth_io(public).expect("the io-hash");
    let (proof, _) = program
        .prove(&arguments, MaskRng::default())
        .expect("the kernel proves");
    let honest = encode(&proof.proof).expect("encodes");
    let mut pow = decode(&honest).unwrap();
    pow.stark_proof.0.proof_of_work ^= 1;
    let pow = encode(&pow).unwrap();
    let mut interaction = decode(&honest).unwrap();
    interaction.interaction_pow ^= 1;
    let interaction = encode(&interaction).unwrap();
    let cut = &honest[..honest.len() - 1];
    let verifier = program.verifier();
    let cases: [(&str, &[u8], bool); 4] = [
        ("verified", &honest, true),
        ("a wrong PoW, refused", &pow, false),
        ("a wrong interaction PoW, refused", &interaction, false),
        ("a byte cut, refused", cut, false),
    ];
    println!(
        "format {}, {ROUNDS} runs each, one thread; median / 95th percentile",
        vos_pvm_recair::device::FORMAT.number
    );
    for (name, bytes, ok) in cases {
        let (median, p95) = timed(ok, || verifier.verify(&io, bytes).is_ok());
        println!(
            "device auth ({} bytes), {name}: {:.3} / {:.3} ms",
            honest.len(),
            median.as_secs_f64() * 1e3,
            p95.as_secs_f64() * 1e3
        );
    }
}
