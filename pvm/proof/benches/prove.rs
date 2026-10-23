//! Proving benchmarks at various trace sizes, comparable to Nexus prover-benches.
//!
//! These are measurement harnesses, not correctness tests — the real ALU/memory
//! semantics are covered by the functional tests (`isa`: `alu`, `memory`, …), so
//! they live under `benches/` (out of `cargo test`) and run serially, one prove
//! at a time, so a single large trace never competes for RAM with another.
//!
//! Run the default (safe) set:
//!     cargo bench --bench prove
//! Run specific benchmarks by name substring (e.g. the heavy ones):
//!     cargo bench --bench prove -- log16
//!     cargo bench --bench prove -- profile_log14 scale_sweep
//!
//! Every proof is under the segment format (35).
//!
//! Requires the `prover` feature (on by default).

fn main() {
    #[cfg(feature = "prover")]
    imp::run(std::env::args().skip(1).collect());
    #[cfg(not(feature = "prover"))]
    eprintln!("vos-pvm-proof proving benchmarks require the `prover` feature (default-on)");
}

#[cfg(feature = "prover")]
mod imp {
    use vos_pvm_proof::bench_helpers::add_side_note;
    use vos_pvm_proof::{prove, prove_profiled, verify};

    type Bench = (&'static str, fn());

    /// Every benchmark, by name. Substring-matched against the CLI filter.
    fn registry() -> Vec<Bench> {
        vec![
            ("bench_prove_log05", || bench_at_log_size(5)),
            ("bench_prove_log08", || bench_at_log_size(8)),
            ("bench_prove_log10", || bench_at_log_size(10)),
            ("bench_prove_log12", || bench_at_log_size(12)),
            ("bench_prove_log14", || bench_at_log_size(14)),
            // ~16 GB RAM; excluded from the default set.
            ("bench_prove_log16", || bench_at_log_size(16)),
            ("profile_log10", || profile_at_log_size(10)),
            ("profile_log14", || profile_at_log_size(14)),
            ("scale_sweep", scale_sweep),
            ("thread_pool", thread_pool),
        ]
    }

    /// The set run when no filter is given: the standard ladder and the scale
    /// sweep, but not the >=16 GB variant (run it by name).
    const DEFAULT: &[&str] = &[
        "bench_prove_log05",
        "bench_prove_log08",
        "bench_prove_log10",
        "bench_prove_log12",
        "bench_prove_log14",
        "profile_log14",
        "scale_sweep",
    ];

    pub fn run(args: Vec<String>) {
        // `cargo bench` injects libtest-style flags (--bench, --nocapture, …);
        // keep only positional name filters.
        let filters: Vec<String> = args.into_iter().filter(|a| !a.starts_with('-')).collect();
        let all = registry();
        let selected: Vec<&Bench> = if filters.is_empty() {
            all.iter().filter(|(n, _)| DEFAULT.contains(n)).collect()
        } else {
            all.iter()
                .filter(|(n, _)| filters.iter().any(|f| n.contains(f.as_str())))
                .collect()
        };
        if selected.is_empty() {
            eprintln!("no benchmark matched {filters:?}; available:");
            for (n, _) in &all {
                eprintln!("  {n}");
            }
            return;
        }
        for (name, f) in selected {
            eprintln!("\n### {name}");
            f();
        }
    }

    fn bench_at_log_size(log_size: u32) {
        let t0 = std::time::Instant::now();
        let (mut side_note, n_steps) = add_side_note(log_size);
        let trace_time = t0.elapsed();

        let t1 = std::time::Instant::now();
        let proof = prove(&mut side_note).expect("proving failed");
        let prove_time = t1.elapsed();

        let proof_kb = bincode::serialize(&proof).unwrap().len() as f64 / 1024.0;

        let t2 = std::time::Instant::now();
        verify(proof, &side_note).expect("verification failed");
        let verify_time = t2.elapsed();

        eprintln!(
            "LogSize={log_size:>2} | steps={n_steps:>6} | trace={trace_time:>10.2?} | prove={prove_time:>10.2?} | verify={verify_time:>10.2?} | total={:>10.2?} | proof={proof_kb:>6.1} KB",
            trace_time + prove_time + verify_time,
        );
    }

    fn profile_at_log_size(log_size: u32) {
        let (mut side_note, n_steps) = add_side_note(log_size);
        eprintln!("=== LogSize={log_size} ({n_steps} steps) ===");
        let (proof, profile) = prove_profiled(&mut side_note).expect("proving failed");
        eprintln!("{profile}");
        let proof_bytes = bincode::serialize(&proof).unwrap();
        eprintln!(
            "Proof size: {} bytes ({:.1} KB)",
            proof_bytes.len(),
            proof_bytes.len() as f64 / 1024.0
        );
        verify(proof, &side_note).expect("verification failed");
    }

    /// Sweep log sizes to find the scale breaking point, with a rough
    /// memory estimate per shape.
    fn scale_sweep() {
        eprintln!("=== Scale sweep (rough memory estimate) ===");
        eprintln!("  main_cols=286, interaction_cols=~90, constraint_blowup=4");
        eprintln!();
        for log_size in [10, 12, 14, 16, 17, 18, 19].iter() {
            let (mut side_note, n_steps) = add_side_note(*log_size);
            let t = std::time::Instant::now();
            match prove(&mut side_note) {
                Ok(p) => {
                    let elapsed = t.elapsed();
                    let kb = bincode::serialize(&p).unwrap().len() as f64 / 1024.0;
                    // Rough memory estimate: main + fft domain at constraint blowup 2^4.
                    let rows = 1u64 << log_size;
                    let fft_rows = rows * 16;
                    let field_bytes = 4u64;
                    let main_mb = rows * 286 * field_bytes / (1024 * 1024);
                    let fft_mb = fft_rows * 286 * field_bytes / (1024 * 1024);
                    eprintln!(
                        "  log_size={log_size:>2} ({n_steps:>7} steps): prove={elapsed:>8.2?}, proof={kb:>5.1} KB, main_trace≈{main_mb}MB, fft_domain≈{fft_mb}MB"
                    );
                }
                Err(e) => {
                    eprintln!("  log_size={log_size:>2} ({n_steps:>7} steps): FAIL {e}");
                    break;
                }
            }
        }
    }

    fn thread_pool() {
        let n = vos_pvm_proof::install_thread_pool();
        eprintln!(
            "install_thread_pool() returned {n} (rayon::current_num_threads = {})",
            rayon::current_num_threads()
        );
    }
}
