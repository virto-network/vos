//! Proving benchmarks at various trace sizes, comparable to Nexus prover-benches.
//!
//! These are measurement harnesses, not correctness tests — the real ALU/memory
//! semantics are covered by the functional tests (`isa`: `alu`, `memory`, …), so
//! they live under `benches/` (out of `cargo test`) and run serially, one prove
//! at a time, so a single large trace never competes for RAM with another.
//!
//! Run the default set (log sizes up to 14):
//!     cargo bench --bench prove
//! Run specific benchmarks by name substring, e.g. the heavy ones, which
//! are not in the default set: `log16` (~16 GB) and `scale_sweep` (log
//! sizes 10 to 19):
//!     cargo bench --bench prove -- log16
//!     cargo bench --bench prove -- profile_log14 scale_sweep
//!
//! Every proof is under the segment format (41).
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
    use vos_pvm::PVM_REGISTER_COUNT;
    use vos_pvm::instruction::Opcode;
    use vos_pvm::interpreter::Interpreter;
    use vos_pvm_proof::core::tracing::TracingPvm;
    use vos_pvm_proof::{SideNote, prove, prove_profiled, verify};

    /// The side note of a run of `2^log_size` Add64s, each on the next
    /// registers, and a Trap; and its step count.
    fn add_side_note(log_size: u32) -> (SideNote, usize) {
        let n_steps = 1usize << log_size;
        let mut code = Vec::with_capacity(n_steps * 3 + 1);
        let mut bitmask = Vec::with_capacity(n_steps * 3 + 1);
        for step in 0..n_steps {
            let [a, b, d] = [0, 1, 2].map(|offset| ((step + offset) % 13) as u8);
            code.extend_from_slice(&[Opcode::Add64 as u8, a | b << 4, d]);
            bitmask.extend_from_slice(&[1, 0, 0]);
        }
        code.push(Opcode::Trap as u8);
        bitmask.push(1);
        let registers: [u64; PVM_REGISTER_COUNT] = core::array::from_fn(|i| i as u64 + 1);
        let gas = (n_steps as u64 + 100) * 100;
        let pvm = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            registers,
            vec![0u8; 64 * 1024],
            gas,
        );
        let mut tracing = TracingPvm::new(pvm);
        tracing.run();
        let steps = tracing.into_trace();
        assert!(steps.len() >= n_steps, "{} steps", steps.len());
        (SideNote::new(steps, code, bitmask), n_steps)
    }

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

    /// The set run when no filter is given: the ladder up to log size 14 and
    /// its profile. The ~16 GB log-16 run and the scale sweep, which goes on
    /// to log size 19, run only by name.
    const DEFAULT: &[&str] = &[
        "bench_prove_log05",
        "bench_prove_log08",
        "bench_prove_log10",
        "bench_prove_log12",
        "bench_prove_log14",
        "profile_log14",
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

        let proof_kb = postcard::to_allocvec(&proof).unwrap().len() as f64 / 1024.0;

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
        let proof_bytes = postcard::to_allocvec(&proof).unwrap();
        eprintln!(
            "Proof size: {} bytes ({:.1} KB)",
            proof_bytes.len(),
            proof_bytes.len() as f64 / 1024.0
        );
        verify(proof, &side_note).expect("verification failed");
    }

    /// Sweep log sizes to find the scale breaking point, with a rough
    /// memory estimate per shape: each proof's committed main and
    /// interaction columns at their own log sizes, 4 bytes a value, and
    /// the same on the evaluation domain at the proof's blowup.
    fn scale_sweep() {
        use vos_pvm_proof::framework_access::create_verifier_components::trace_and_preprocessed_sizes;
        eprintln!("=== Scale sweep (rough memory estimate) ===");
        eprintln!();
        for log_size in [10, 12, 14, 16, 17, 18, 19].iter() {
            let (mut side_note, n_steps) = add_side_note(*log_size);
            let t = std::time::Instant::now();
            match prove(&mut side_note) {
                Ok(p) => {
                    let elapsed = t.elapsed();
                    let kb = postcard::to_allocvec(&p).unwrap().len() as f64 / 1024.0;
                    let (trees, _) = trace_and_preprocessed_sizes(&p.log_sizes, p.component_mask);
                    let tree = |index: usize| -> (usize, u64) {
                        trees
                            .iter()
                            .filter_map(|sizes| sizes.get(index))
                            .flatten()
                            .fold((0, 0), |(columns, values), &size| {
                                (columns + 1, values + (1u64 << size))
                            })
                    };
                    let (main_cols, main_values) = tree(1);
                    let (interaction_cols, interaction_values) = tree(2);
                    let mib = |values: u64| values * 4 / (1024 * 1024);
                    let blowup = 1u64 << p.pcs_config.fri_config.log_blowup_factor;
                    let committed = main_values + interaction_values;
                    eprintln!(
                        "  log_size={log_size:>2} ({n_steps:>7} steps): prove={elapsed:>8.2?}, proof={kb:>5.1} KB, {main_cols} main and {interaction_cols} interaction columns, committed≈{}MB, extended≈{}MB",
                        mib(committed),
                        mib(committed * blowup)
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
