//! Proving benchmarks at various trace sizes, comparable to Nexus prover-benches.
//!
//! These are measurement harnesses, not correctness tests — the real ALU/memory
//! semantics are covered by the functional tests (`phase2_alu`, `memory`, …), so
//! they live under `benches/` (out of `cargo test`) and run serially, one prove
//! at a time, so a single large trace never competes for RAM with another.
//!
//! Run the default (safe) set:
//!     cargo bench --bench prove
//! Run specific benchmarks by name substring (e.g. the heavy ones):
//!     cargo bench --bench prove -- log16
//!     cargo bench --bench prove -- profile_log14 pcs_config
//!
//! Requires the `prover` feature (on by default).

fn main() {
    #[cfg(feature = "prover")]
    imp::run(std::env::args().skip(1).collect());
    #[cfg(not(feature = "prover"))]
    eprintln!("zkpvm proving benchmarks require the `prover` feature (default-on)");
}

#[cfg(feature = "prover")]
mod imp {
    use zkpvm::bench_helpers::add_side_note;
    use zkpvm::{
        FriConfig, PcsConfig, PcsPolicy, prove, prove_profiled, prove_profiled_with_config,
        prove_with_config, verify, verify_with_pcs_policy,
    };

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
            ("profile_log14_mobile", || profile_mobile_at_log_size(14)),
            // Heavy; explicit-only.
            ("profile_log15_mobile", || profile_mobile_at_log_size(15)),
            ("scale_sweep", scale_sweep),
            ("security_sweep_log12", security_sweep_log12),
            ("pcs_config_sweep_log10", pcs_config_sweep_log10),
            ("pcs_config_sweep_log14", pcs_config_sweep_log14),
            (
                "pcs_config_sweep_log14_security_levels",
                pcs_config_sweep_log14_security_levels,
            ),
            ("thread_pool", thread_pool),
        ]
    }

    /// The set run when no filter is given: the standard ladder + config sweeps,
    /// but not the >=16 GB or redundant heavy variants (run those by name).
    const DEFAULT: &[&str] = &[
        "bench_prove_log05",
        "bench_prove_log08",
        "bench_prove_log10",
        "bench_prove_log12",
        "bench_prove_log14",
        "profile_log14_mobile",
        "scale_sweep",
        "security_sweep_log12",
        "pcs_config_sweep_log10",
        "pcs_config_sweep_log14",
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
        let (proof, _) = prove_profiled(&mut side_note).expect("proving failed");
        let proof_bytes = bincode::serialize(&proof).unwrap();
        eprintln!(
            "Proof size: {} bytes ({:.1} KB)",
            proof_bytes.len(),
            proof_bytes.len() as f64 / 1024.0
        );
        verify(proof, &side_note).expect("verification failed");
    }

    fn profile_mobile_at_log_size(log_size: u32) {
        let (mut side_note, _) = add_side_note(log_size);
        let mobile = zkpvm::production_pcs_config_mobile();
        eprintln!("=== LogSize={log_size} MOBILE config (blowup=4, q=38, pow=20) ===");
        let (proof, _) =
            prove_profiled_with_config(&mut side_note, mobile).expect("proving failed");
        let proof_bytes = bincode::serialize(&proof).unwrap();
        eprintln!("Proof size: {} KB", proof_bytes.len() / 1024);
        verify_with_pcs_policy(proof, &side_note, &PcsPolicy::MOBILE).expect("verification failed");
    }

    /// Sweep log_sizes with test-config (8-bit security) to find the scale
    /// breaking point (rough memory estimate per shape).
    fn scale_sweep() {
        let test_config = PcsConfig {
            pow_bits: 5,
            fri_config: FriConfig::new(0, 1, 3, 1),
            lifting_log_size: None,
        };
        eprintln!("=== Scale sweep (test security, rough memory estimate) ===");
        eprintln!("  main_cols=286, interaction_cols=~90, constraint_blowup=4");
        eprintln!();
        for log_size in [10, 12, 14, 16, 17, 18, 19].iter() {
            let (mut side_note, n_steps) = add_side_note(*log_size);
            let t = std::time::Instant::now();
            match prove_with_config(&mut side_note, test_config) {
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

    fn bench_security(log_size: u32, pow_bits: u32, log_blowup: u32, n_queries: usize) {
        let (mut side_note, _) = add_side_note(log_size);
        let config = PcsConfig {
            pow_bits,
            fri_config: FriConfig::new(0, log_blowup, n_queries, 1),
            lifting_log_size: None,
        };
        let sec_bits = config.security_bits();
        // Policy mirrors the under-test config so we exercise the algebraic
        // verify path even on the dev-only / test-only sweeps (e.g., pow_bits=5).
        // STANDARD policy would gate those out before the verifier sees the proof.
        let policy = PcsPolicy {
            min_pow_bits: config.pow_bits,
            min_fri_queries: config.fri_config.n_queries,
            min_fri_log_blowup: config.fri_config.log_blowup_factor,
        };

        let t = std::time::Instant::now();
        let proof = prove_with_config(&mut side_note, config).expect("proving failed");
        let prove_time = t.elapsed();
        let proof_kb = bincode::serialize(&proof).unwrap().len() as f64 / 1024.0;

        let t = std::time::Instant::now();
        verify_with_pcs_policy(proof, &side_note, &policy).expect("verification failed");
        let verify_time = t.elapsed();

        eprintln!(
            "  blowup=2^{log_blowup} queries={n_queries:>2} pow={pow_bits:>2} => {sec_bits:>3}-bit | prove={prove_time:>10.2?} | verify={verify_time:>8.2?} | proof={proof_kb:>6.1} KB"
        );
    }

    fn security_sweep_log12() {
        let log = 12;
        eprintln!("=== Security sweep at LogSize={log} (4096 steps) ===");
        bench_security(log, 5, 1, 3); // baseline (test-only)
        bench_security(log, 16, 2, 17); // ~50-bit (development)
        bench_security(log, 20, 3, 20); // ~80-bit (light production)
        bench_security(log, 20, 4, 19); // ~96-bit (standard production)
        bench_security(log, 26, 4, 26); // ~128-bit (high security)
    }

    fn bench_pcs_config(log_size: u32, label: &str, config: PcsConfig) {
        let (mut side_note, _) = add_side_note(log_size);
        let sec_bits = config.security_bits();
        let policy = PcsPolicy {
            min_pow_bits: config.pow_bits,
            min_fri_queries: config.fri_config.n_queries,
            min_fri_log_blowup: config.fri_config.log_blowup_factor,
        };

        let t = std::time::Instant::now();
        let proof = prove_with_config(&mut side_note, config).expect("proving failed");
        let prove_time = t.elapsed();
        let proof_kb = bincode::serialize(&proof).unwrap().len() as f64 / 1024.0;

        let t = std::time::Instant::now();
        verify_with_pcs_policy(proof, &side_note, &policy).expect("verification failed");
        let verify_time = t.elapsed();

        eprintln!(
            "  {label:<40} | sec={sec_bits:>3} | prove={prove_time:>10.2?} | verify={verify_time:>8.2?} | proof={proof_kb:>7.1} KB"
        );
    }

    // Probe alternative FRI parameters at log14 to evaluate the blowup trade-off.
    // Verification uses a matching PcsPolicy so the proof is accepted (production
    // STANDARD requires log_blowup >= 4). All configs target >= 96-bit security.
    fn pcs_config_sweep_log14() {
        let log = 14;
        eprintln!("=== PCS config sweep at LogSize={log} (16384 steps) ===");
        eprintln!("  Format: pow_bits, log_blowup, n_queries\n");
        bench_pcs_config(
            log,
            "STANDARD: pow=20, blowup=2^4, q=19",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 4, 19, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "blowup=2^3, q=20, pow=16 (96 bits)",
            PcsConfig {
                pow_bits: 16,
                fri_config: FriConfig::new(0, 3, 20, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "blowup=2^2, q=38, pow=20 (96 bits)",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 2, 38, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "blowup=2^1, q=76, pow=20 (96 bits)",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 1, 76, 1),
                lifting_log_size: None,
            },
        );
        // pow=32 makes prove ~10x slower (PoW-grind dominates); stwo caps
        // pow_bits <= 32, so pow=48 is rejected upstream. Not a useful config.
    }

    fn pcs_config_sweep_log14_security_levels() {
        let log = 14;
        eprintln!("=== Security level sweep at LogSize={log} (blowup=4) ===");
        eprintln!(
            "(blowup=4 is the MOBILE-class shape; varying queries × pow trades security for prove time)\n"
        );
        bench_pcs_config(
            log,
            "MOBILE-96bit:  pow=20, q=38",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 2, 38, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "MOBILE-80bit:  pow=20, q=30",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 2, 30, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "MOBILE-64bit:  pow=20, q=22",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 2, 22, 1),
                lifting_log_size: None,
            },
        );
        eprintln!("\n(blowup=4 with raised pow_bits — cheaper FRI but PoW grind cost)");
        bench_pcs_config(
            log,
            "pow=24, q=36 (96 bits)",
            PcsConfig {
                pow_bits: 24,
                fri_config: FriConfig::new(0, 2, 36, 1),
                lifting_log_size: None,
            },
        );
    }

    fn pcs_config_sweep_log10() {
        let log = 10;
        eprintln!("=== PCS config sweep at LogSize={log} (1024 steps) ===");
        bench_pcs_config(
            log,
            "STANDARD: pow=20, blowup=2^4, q=19",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 4, 19, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "blowup=2^2, q=38, pow=20 (96 bits)",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 2, 38, 1),
                lifting_log_size: None,
            },
        );
        bench_pcs_config(
            log,
            "blowup=2^1, q=76, pow=20 (96 bits)",
            PcsConfig {
                pow_bits: 20,
                fri_config: FriConfig::new(0, 1, 76, 1),
                lifting_log_size: None,
            },
        );
    }

    fn thread_pool() {
        let n = zkpvm::install_thread_pool();
        eprintln!(
            "install_thread_pool() returned {n} (rayon::current_num_threads = {})",
            rayon::current_num_threads()
        );
    }
}
