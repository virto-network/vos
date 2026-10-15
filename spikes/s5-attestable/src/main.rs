//! Proving cost on the saga's Gray Paper 0.8.0 prover (`trace_refine` /
//! `prove_refine`), using S4's guest: n BLAKE2b hashes computed inside the
//! PVM, the work an attestable root update does without a hash precompile.
//!
//! `s5-attestable <guest.elf> steps <n>...`: trace only; steps per run.
//! `s5-attestable <guest.elf> prove <n>`: trace, prove, encode, verify
//! (run one per process: peak RSS is per process).

use std::time::Instant;

use vos_pvm_proof::refine_codec::encode_refine_proof_bundle;
use vos_pvm_proof::{prove_refine, trace_refine_with_output, verify_refine_bundle_replayed};

const GAS: u64 = 1 << 40;

fn peak_rss_mib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|k| k.parse::<f64>().ok())
        .unwrap_or(0.0)
        / 1024.0
}

fn steps(spi: &[u8], n: u64) -> usize {
    let (trace, output) = trace_refine_with_output(spi, &n.to_le_bytes(), GAS, 32).expect("trace");
    assert!(output.is_some(), "guest did not halt with output");
    trace.slices.iter().map(|s| s.side_note.num_steps()).sum()
}

fn main() {
    let elf = std::env::args()
        .nth(1)
        .expect("usage: s5-attestable <guest.elf> steps|prove <n>...");
    let mode = std::env::args().nth(2).expect("mode");
    let ns: Vec<u64> = std::env::args()
        .skip(3)
        .map(|a| a.parse().unwrap())
        .collect();
    let spi = vos_pvm_compiler::link_elf_spi(&std::fs::read(elf).unwrap()).expect("link");
    match mode.as_str() {
        "steps" => {
            let base = steps(&spi, 0);
            println!("0 hashes: {base} steps");
            for n in ns {
                let total = steps(&spi, n);
                println!(
                    "{n} hashes: {total} steps ({:.0} per hash)",
                    (total - base) as f64 / n.max(1) as f64
                );
            }
        }
        "prove" => {
            let n = ns[0];
            let args = n.to_le_bytes();
            let started = Instant::now();
            let (trace, _) = trace_refine_with_output(&spi, &args, GAS, 32).expect("trace");
            let traced = started.elapsed();
            let total: usize = trace.slices.iter().map(|s| s.side_note.num_steps()).sum();
            let slices = trace.slices.len();
            let started = Instant::now();
            let bundle = prove_refine(trace).expect("prove");
            let proved = started.elapsed();
            let bytes = encode_refine_proof_bundle(&bundle).expect("encode");
            let started = Instant::now();
            verify_refine_bundle_replayed(&bundle, &spi, &args, GAS).expect("verify");
            let verified = started.elapsed();
            println!(
                "{n} hashes: {total} steps in {slices} slice(s); trace {:.2} s, prove {:.2} s \
                 ({:.0} steps/s), verify {:.2} s, proof {:.0} KiB, peak RSS {:.0} MiB",
                traced.as_secs_f64(),
                proved.as_secs_f64(),
                total as f64 / proved.as_secs_f64(),
                verified.as_secs_f64(),
                bytes.len() as f64 / 1024.0,
                peak_rss_mib(),
            );
        }
        _ => panic!("mode"),
    }
}
