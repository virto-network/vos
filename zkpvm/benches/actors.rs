//! Actor-workload proving benchmarks: trace a real VOS actor (compiled
//! from Rust, transpiled to PVM) and measure the prove + verify pipeline,
//! plus the RistrettoChip per-payment prove-time projections.
//!
//! These are measurement harnesses, not correctness tests — the actual
//! actor-IO / chip semantics are covered by the functional tests in
//! `tests/prove_vos_actor.rs` (trace_*, prove_*_via_ecall*, the chip
//! soundness audits), so they live under `benches/` (out of `cargo test`)
//! and run serially, one prove at a time, so a single large trace never
//! competes for RAM with another.
//!
//! Run the default (safe) set:
//!     cargo bench --bench actors
//! Run specific benchmarks by name substring (e.g. the heavy ones):
//!     cargo bench --bench actors -- profile_clerk_refine_bench
//!     cargo bench --bench actors -- profile_clerk_private_pay_bench_mobile profile_clerk_private_pay_bench
//!
//! The actor-ELF benches skip gracefully (print + return) when their
//! fixture is absent; build them first with `just build-pvm`.
//!
//! Requires the `prover` feature (on by default).

fn main() {
    #[cfg(feature = "prover")]
    imp::run(std::env::args().skip(1).collect());
    #[cfg(not(feature = "prover"))]
    eprintln!("zkpvm actor benchmarks require the `prover` feature (default-on)");
}

#[cfg(feature = "prover")]
mod imp {
    use javm::interpreter::Interpreter;
    use javm::program::{self, CapEntryType};

    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::{
        production_pcs_config_mobile, prove, prove_profiled, prove_profiled_with_config, verify,
    };

    type Bench = (&'static str, fn());

    /// Every benchmark, by name. Substring-matched against the CLI filter.
    fn registry() -> Vec<Bench> {
        vec![
            ("profile_fibonacci_actor", profile_fibonacci_actor),
            ("profile_hasher_actor", profile_hasher_actor),
            // ~13s and the biggest RAM footprint; explicit-only.
            ("profile_clerk_refine_bench", profile_clerk_refine_bench),
            (
                "profile_clerk_private_pay_bench",
                profile_clerk_private_pay_bench,
            ),
            (
                "profile_clerk_private_pay_bench_mobile",
                profile_clerk_private_pay_bench_mobile,
            ),
            ("profile_hash_bench", profile_hash_bench),
            (
                "profile_hot_pcs_clerk_private_pay_bench",
                profile_hot_pcs_clerk_private_pay_bench,
            ),
            ("prove_segmented_hash_bench", prove_segmented_hash_bench),
            // 10000 chip ops; explicit-only.
            (
                "bench_ristretto_chip_soundness_complete_chain",
                bench_ristretto_chip_soundness_complete_chain,
            ),
            // Needs the chip INPUT-PRODUCER mechanism (currently rejects);
            // explicit-only.
            (
                "bench_ristretto_chip_combined_with_cpu_baseline",
                bench_ristretto_chip_combined_with_cpu_baseline,
            ),
            // Needs the chip INPUT-PRODUCER mechanism (currently rejects);
            // explicit-only.
            (
                "bench_ristretto_chip_one_private_payment",
                bench_ristretto_chip_one_private_payment,
            ),
            (
                "project_ristretto_chip_size_for_one_payment",
                project_ristretto_chip_size_for_one_payment,
            ),
        ]
    }

    /// The set run when no filter is given: the lighter actor-ELF profiles
    /// (which skip gracefully when their fixture is absent) plus the
    /// no-prove projection.  Excludes the ~13s / biggest-RAM refine bench,
    /// the 10000-op soundness chain, and the two INPUT-PRODUCER-dependent
    /// chip benches — run those by explicit name.
    const DEFAULT: &[&str] = &[
        "profile_fibonacci_actor",
        "profile_hasher_actor",
        "profile_clerk_private_pay_bench",
        "profile_clerk_private_pay_bench_mobile",
        "profile_hash_bench",
        "profile_hot_pcs_clerk_private_pay_bench",
        "prove_segmented_hash_bench",
        "project_ristretto_chip_size_for_one_payment",
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

    // ── Fixture loaders (shared with tests/prove_vos_actor.rs) ──

    /// Load fibonacci PVM blob (transpiled from ELF), or `None` when the
    /// fixture is absent so callers SKIP (print + return) rather than panic.
    /// Matches the skip-if-absent hygiene of `settle_run.rs`.
    fn load_fibonacci_blob() -> Option<Vec<u8>> {
        let blob_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/legacy-v1/actors/fibonacci/target/riscv64em-javm/release/fibonacci.pvm"
        );
        if let Ok(data) = std::fs::read(blob_path) {
            return Some(data);
        }
        let elf_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/legacy-v1/actors/fibonacci/target/riscv64em-javm/release/fibonacci.elf"
        );
        let elf_data = match std::fs::read(elf_path) {
            Ok(b) => b,
            Err(_) => {
                eprintln!(
                    "SKIP: fibonacci actor fixture absent; build with \
                     `cd tests/fixtures/legacy-v1/actors/fibonacci && cargo actor` (or `just build-pvm`)"
                );
                return None;
            }
        };
        Some(grey_transpiler::link_elf(&elf_data).expect("failed to transpile fibonacci ELF"))
    }

    /// Load actor `name`'s PVM blob (preferring a pre-transpiled `.pvm`,
    /// else transpiling its `.elf`), or `None` when the fixture is absent
    /// so callers SKIP (print + return) rather than panic.  The SKIP
    /// message is emitted here, so callers just `let Some(blob) = ... else
    /// { return; };`.
    fn load_actor_blob(name: &str) -> Option<Vec<u8>> {
        let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/legacy-v1/actors/");
        let pvm_path = format!("{base}{name}/target/riscv64em-javm/release/{name}.pvm");
        if let Ok(data) = std::fs::read(&pvm_path) {
            return Some(data);
        }
        let elf_path = format!("{base}{name}/target/riscv64em-javm/release/{name}.elf");
        let elf_data = match std::fs::read(&elf_path) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("SKIP: {name} actor fixture absent; run `just build-pvm` first");
                return None;
            }
        };
        Some(grey_transpiler::link_elf(&elf_data).expect("failed to transpile ELF"))
    }

    /// Panicking wrapper over `zkpvm::actor::interpreter_from_blob` — every
    /// callsite below treats a missing CODE cap as a fixture bug, not a
    /// runtime condition, so the `Option<_>` ergonomics aren't worth the
    /// noise here.
    fn interpreter_from_blob(blob: &[u8], gas: u64) -> (Interpreter, Vec<u8>) {
        zkpvm::actor::interpreter_from_blob(blob, gas).expect("interpreter from blob")
    }

    // ── Generic actor profile helpers ──

    fn profile_actor(name: &str, gas: u64) {
        let Some(blob) = load_actor_blob(name) else {
            return;
        };
        let parsed = program::parse_blob(&blob).expect("parse blob");
        let mut code_data = None;
        for entry in &parsed.caps {
            if entry.cap_type == CapEntryType::Code {
                code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
                break;
            }
        }
        let code_blob =
            program::parse_code_blob(&code_data.expect("no CODE cap")).expect("parse code");
        let (interp, flat_mem) = interpreter_from_blob(&blob, gas);

        let t0 = std::time::Instant::now();
        let mut tracing = TracingPvm::new(interp);
        // run_with_vos_stubs gracefully drives lifecycle hostcalls
        // (INFO/STORAGE_R/FETCH/OUTPUT/...) so vos-style actors complete
        // their on_start handler under the bare interpreter.  Pure-compute
        // actors with no hostcalls behave the same as `run()`.
        let exit = tracing.run_with_vos_stubs();
        // Precompile ECALL records — capture before consuming `tracing`.
        let blake2b_calls: Vec<_> = tracing.blake2b_calls().iter().cloned().collect();
        let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();
        let ristretto_calls: Vec<_> = tracing.ristretto_calls().iter().cloned().collect();
        let ristretto_mem_ops = tracing.ristretto_mem_ops.clone();
        let ristretto_add_records = tracing.ristretto_add_records.clone();
        let ristretto_add_mem_ops = tracing.ristretto_add_mem_ops.clone();
        let scalar_reduce_records = tracing.scalar_reduce_wide_records.clone();
        let scalar_reduce_mem_ops = tracing.scalar_reduce_wide_mem_ops.clone();
        let scalar_binop_records = tracing.scalar_binop_records.clone();
        let scalar_binop_mem_ops = tracing.scalar_binop_mem_ops.clone();
        let steps = tracing.into_trace();
        let trace_time = t0.elapsed();

        eprintln!("=== {name} actor ===");
        eprintln!(
            "PVM: {} steps in {trace_time:?}, exit={exit:?}",
            steps.len()
        );
        eprintln!(
            "Precompile ECALLs: blake2b={}, ristretto_scalar_mult={}, ristretto_point_add={}, scalar_reduce_wide={}, scalar_binop={}",
            blake2b_calls.len(),
            ristretto_calls.len(),
            ristretto_add_records.len(),
            scalar_reduce_records.len(),
            scalar_binop_records.len(),
        );

        // Opcode stats
        let mut mem_ops = 0u32;
        let mut branches = 0u32;
        let mut counts = std::collections::HashMap::new();
        for s in &steps {
            *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
            if s.mem_read.is_some() || s.mem_write.is_some() {
                mem_ops += 1;
            }
            if s.branch_taken {
                branches += 1;
            }
        }
        eprintln!("Memory ops: {mem_ops}, Branches taken: {branches}");
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (op, count) in sorted.iter().take(8) {
            eprintln!("  {op}: {count}");
        }

        let mut side_note =
            zkpvm::SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
                .with_memory(flat_mem)
                .with_jump_table(code_blob.jump_table.to_vec());

        // Install precompile ECALL records on side_note.
        for c in &blake2b_calls {
            side_note
                .blake2b_calls
                .push(zkpvm::chips::blake2b::Blake2bCall {
                    h: c.h,
                    m: c.m,
                    t: c.t,
                    f: c.f,
                });
        }
        side_note.blake2b_mem_ops = blake2b_mem_ops;
        side_note.ristretto_calls = ristretto_calls;
        side_note.ristretto_mem_ops = ristretto_mem_ops;
        side_note.ristretto_add_calls = ristretto_add_records;
        side_note.ristretto_add_mem_ops = ristretto_add_mem_ops;
        side_note.scalar_reduce_wide_calls = scalar_reduce_records;
        side_note.scalar_reduce_wide_mem_ops = scalar_reduce_mem_ops;
        side_note.scalar_binop_calls = scalar_binop_records;
        side_note.scalar_binop_mem_ops = scalar_binop_mem_ops;
        side_note.ingest_ristretto_boundary();

        eprintln!("\nProve (96-bit security):");
        let (proof, _) = prove_profiled(&mut side_note).expect("proving failed");

        let proof_bytes = bincode::serialize(&proof).expect("serialize");
        eprintln!("Proof: {:.1} KB", proof_bytes.len() as f64 / 1024.0);

        let t = std::time::Instant::now();
        verify(proof, &side_note).expect("verification failed");
        eprintln!("Verify: {:?}\n", t.elapsed());
    }

    fn profile_actor_with_config(name: &str, gas: u64, config: zkpvm::PcsConfig) {
        let Some(blob) = load_actor_blob(name) else {
            return;
        };
        let parsed = program::parse_blob(&blob).expect("parse blob");
        let mut code_data = None;
        for entry in &parsed.caps {
            if entry.cap_type == CapEntryType::Code {
                code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
                break;
            }
        }
        let code_blob =
            program::parse_code_blob(&code_data.expect("no CODE cap")).expect("parse code");
        let (interp, flat_mem) = interpreter_from_blob(&blob, gas);

        let t0 = std::time::Instant::now();
        let mut tracing = TracingPvm::new(interp);
        let exit = tracing.run_with_vos_stubs();
        let blake2b_calls: Vec<_> = tracing.blake2b_calls().iter().cloned().collect();
        let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();
        let ristretto_calls: Vec<_> = tracing.ristretto_calls().iter().cloned().collect();
        let ristretto_mem_ops = tracing.ristretto_mem_ops.clone();
        let ristretto_add_records = tracing.ristretto_add_records.clone();
        let ristretto_add_mem_ops = tracing.ristretto_add_mem_ops.clone();
        let scalar_reduce_records = tracing.scalar_reduce_wide_records.clone();
        let scalar_reduce_mem_ops = tracing.scalar_reduce_wide_mem_ops.clone();
        let scalar_binop_records = tracing.scalar_binop_records.clone();
        let scalar_binop_mem_ops = tracing.scalar_binop_mem_ops.clone();
        let steps = tracing.into_trace();
        let trace_time = t0.elapsed();

        eprintln!("=== {name} actor (custom PcsConfig) ===");
        eprintln!(
            "PVM: {} steps in {trace_time:?}, exit={exit:?}",
            steps.len()
        );

        let mut side_note =
            zkpvm::SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
                .with_memory(flat_mem)
                .with_jump_table(code_blob.jump_table.to_vec());
        for c in &blake2b_calls {
            side_note
                .blake2b_calls
                .push(zkpvm::chips::blake2b::Blake2bCall {
                    h: c.h,
                    m: c.m,
                    t: c.t,
                    f: c.f,
                });
        }
        side_note.blake2b_mem_ops = blake2b_mem_ops;
        side_note.ristretto_calls = ristretto_calls;
        side_note.ristretto_mem_ops = ristretto_mem_ops;
        side_note.ristretto_add_calls = ristretto_add_records;
        side_note.ristretto_add_mem_ops = ristretto_add_mem_ops;
        side_note.scalar_reduce_wide_calls = scalar_reduce_records;
        side_note.scalar_reduce_wide_mem_ops = scalar_reduce_mem_ops;
        side_note.scalar_binop_calls = scalar_binop_records;
        side_note.scalar_binop_mem_ops = scalar_binop_mem_ops;
        side_note.ingest_ristretto_boundary();

        eprintln!("\nProve:");
        let (proof, _) =
            prove_profiled_with_config(&mut side_note, config).expect("proving failed");
        let proof_bytes = bincode::serialize(&proof).expect("serialize");
        eprintln!("Proof: {:.1} KB", proof_bytes.len() as f64 / 1024.0);

        let t = std::time::Instant::now();
        zkpvm::verify_with_pcs_policy(proof, &side_note, &zkpvm::PcsPolicy::MOBILE)
            .expect("verification failed");
        eprintln!("Verify: {:?}\n", t.elapsed());
    }

    // ── Benchmarks ──

    fn profile_fibonacci_actor() {
        let Some(blob) = load_fibonacci_blob() else {
            return;
        };
        let parsed = program::parse_blob(&blob).expect("failed to parse JAR blob");

        let mut code_data = None;
        for entry in &parsed.caps {
            if entry.cap_type == CapEntryType::Code {
                code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
                break;
            }
        }
        let code_data = code_data.expect("no CODE capability in blob");
        let code_blob = program::parse_code_blob(&code_data).expect("failed to parse code blob");

        let (interp, _flat_mem) = interpreter_from_blob(&blob, 10_000_000);
        let t0 = std::time::Instant::now();
        let mut tracing = TracingPvm::new(interp);
        let exit = tracing.run();
        let steps = tracing.into_trace();
        let trace_time = t0.elapsed();

        eprintln!("=== Fibonacci Actor Profile ===");
        eprintln!(
            "PVM execution: {} steps in {trace_time:?}, exit={exit:?}",
            steps.len()
        );

        // Opcode distribution
        let mut counts = std::collections::HashMap::new();
        let mut mem_ops = 0u32;
        let mut branches = 0u32;
        for s in &steps {
            *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
            if s.mem_read.is_some() || s.mem_write.is_some() {
                mem_ops += 1;
            }
            if s.branch_taken {
                branches += 1;
            }
        }
        eprintln!("Memory ops: {mem_ops}, Branches taken: {branches}");
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (op, count) in sorted.iter().take(10) {
            eprintln!("  {op}: {count}");
        }

        let mut side_note =
            zkpvm::SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
                .with_jump_table(code_blob.jump_table.to_vec());

        eprintln!("\n=== Prove Pipeline Profile ===");
        let (proof, _profile) = prove_profiled(&mut side_note).expect("proving failed");

        // Proof size
        let proof_bytes = bincode::serialize(&proof).expect("serialize");
        eprintln!(
            "Proof size: {} bytes ({:.1} KB)",
            proof_bytes.len(),
            proof_bytes.len() as f64 / 1024.0
        );

        let t = std::time::Instant::now();
        verify(proof, &side_note).expect("verification failed");
        eprintln!("Verify: {:?}", t.elapsed());
    }

    fn profile_hasher_actor() {
        profile_actor("hasher", 10_000_000);
    }

    /// Real-workload prove: clerk-refine-bench (vos macro style, see
    /// tests/fixtures/legacy-v1/actors/clerk-refine-bench).  vos-macros special-case a
    /// method named `start` as the on_start lifecycle hook, so the
    /// bare interpreter_from_blob path drives the workload via cold
    /// start without needing a FETCH-delivered invocation.
    fn profile_clerk_refine_bench() {
        profile_actor("clerk-refine-bench", 100_000_000);
    }

    /// Real-workload prove: clerk-private-pay-bench — the on-device
    /// computation a user runs for one tap-and-pay (L2 graph privacy).
    /// Pedersen amount commit + Schnorr-on-Ristretto sign + note
    /// commitment + rkyv signing payload, no host-side oracle/ledger.
    fn profile_clerk_private_pay_bench() {
        profile_actor("clerk-private-pay-bench", 100_000_000);
    }

    fn profile_clerk_private_pay_bench_mobile() {
        profile_actor_with_config(
            "clerk-private-pay-bench",
            100_000_000,
            production_pcs_config_mobile(),
        );
    }

    fn profile_hash_bench() {
        let Some(blob) = load_actor_blob("hash-bench") else {
            return;
        };
        let parsed = program::parse_blob(&blob).expect("parse blob");
        let mut code_data = None;
        for entry in &parsed.caps {
            if entry.cap_type == CapEntryType::Code {
                code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
                break;
            }
        }
        let code_blob =
            program::parse_code_blob(&code_data.expect("no CODE cap")).expect("parse code");
        let (interp, flat_mem) = interpreter_from_blob(&blob, 100_000_000);

        let t0 = std::time::Instant::now();
        let mut tracing = TracingPvm::new(interp);
        let exit = tracing.run();
        let steps = tracing.into_trace();
        let trace_time = t0.elapsed();

        eprintln!("=== hash-bench (bare metal) ===");
        eprintln!(
            "PVM: {} steps in {trace_time:?}, exit={exit:?}",
            steps.len()
        );

        let mut mem_ops = 0u32;
        let mut branches = 0u32;
        let mut counts = std::collections::HashMap::new();
        for s in &steps {
            *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
            if s.mem_read.is_some() || s.mem_write.is_some() {
                mem_ops += 1;
            }
            if s.branch_taken {
                branches += 1;
            }
        }
        eprintln!("Memory ops: {mem_ops}, Branches: {branches}");
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (op, count) in sorted.iter().take(10) {
            eprintln!("  {op}: {count}");
        }

        let mut side_note =
            zkpvm::SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
                .with_memory(flat_mem)
                .with_jump_table(code_blob.jump_table.to_vec());

        let t = std::time::Instant::now();
        let proof = prove(&mut side_note).expect("proving failed");
        let prove_time = t.elapsed();
        let proof_bytes = bincode::serialize(&proof).expect("serialize");

        let t = std::time::Instant::now();
        verify(proof, &side_note).expect("verification failed");
        let verify_time = t.elapsed();
        eprintln!(
            "Prove: {prove_time:.2?}, Proof: {:.1} KB, Verify: {verify_time:.2?}",
            proof_bytes.len() as f64 / 1024.0
        );
    }

    fn prove_segmented_hash_bench() {
        // Split hash-bench (635 steps) into 2 segments and verify the chain
        let Some(blob) = load_actor_blob("hash-bench") else {
            return;
        };
        let parsed = program::parse_blob(&blob).expect("parse blob");
        let mut code_data = None;
        for entry in &parsed.caps {
            if entry.cap_type == CapEntryType::Code {
                code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
                break;
            }
        }
        let code_blob = program::parse_code_blob(&code_data.expect("CODE")).expect("parse code");
        let (interp, flat_mem) = interpreter_from_blob(&blob, 100_000_000);
        let mut tracing = TracingPvm::new(interp);
        let _exit = tracing.run();
        let all_steps = tracing.into_trace();

        let split = all_steps.len() / 2;
        eprintln!(
            "=== Segmented proving: {} steps split at {} ===",
            all_steps.len(),
            split
        );

        let code = code_blob.code.to_vec();
        let bitmask = code_blob.bitmask.to_vec();

        // Segment 1: steps 0..split
        let seg1_steps: Vec<_> = all_steps[..split].to_vec();
        let mut seg1_sn = zkpvm::SideNote::new(seg1_steps, code.clone(), bitmask.clone())
            .with_memory(flat_mem.clone())
            .with_jump_table(code_blob.jump_table.to_vec());

        let t = std::time::Instant::now();
        let proof1 = prove(&mut seg1_sn).expect("segment 1 proving failed");
        eprintln!("Segment 1: {} steps, proved in {:?}", split, t.elapsed());
        eprintln!(
            "  initial: pc={} ts={}",
            proof1.initial_state.pc, proof1.initial_state.timestamp
        );
        eprintln!(
            "  final:   pc={} ts={}",
            proof1.final_state.pc, proof1.final_state.timestamp
        );

        // Compute final memory of segment 1 for segment 2's initial memory
        let mut seg2_mem = flat_mem.clone();
        for step in &all_steps[..split] {
            if let Some(ref w) = step.mem_write {
                let addr = w.address as usize;
                let bytes = w.value.to_le_bytes();
                let sz = w.size as usize;
                if addr + sz > seg2_mem.len() {
                    seg2_mem.resize(addr + sz, 0);
                }
                seg2_mem[addr..addr + sz].copy_from_slice(&bytes[..sz]);
            }
        }

        // Segment 2: steps split..end
        let seg2_steps: Vec<_> = all_steps[split..].to_vec();
        let mut seg2_sn = zkpvm::SideNote::new(seg2_steps, code.clone(), bitmask.clone())
            .with_memory(seg2_mem)
            .with_jump_table(code_blob.jump_table.to_vec());

        let t = std::time::Instant::now();
        let proof2 = prove(&mut seg2_sn).expect("segment 2 proving failed");
        eprintln!(
            "Segment 2: {} steps, proved in {:?}",
            all_steps.len() - split,
            t.elapsed()
        );
        eprintln!(
            "  initial: pc={} ts={}",
            proof2.initial_state.pc, proof2.initial_state.timestamp
        );
        eprintln!(
            "  final:   pc={} ts={}",
            proof2.final_state.pc, proof2.final_state.timestamp
        );

        // Verify chain
        eprintln!("\nChain verification:");
        eprintln!(
            "  seg1.final  == seg2.initial ? {}",
            proof1.final_state == proof2.initial_state
        );

        zkpvm::verify_chain(&[proof1, proof2], &[&seg1_sn, &seg2_sn])
            .expect("chain verification failed");
        eprintln!("  CHAIN VERIFIED!");
    }

    /// End-to-end SOUNDNESS-COMPLETE prove-time benchmark.  Builds a
    /// 1000-deep linear add chain (each step adds a fresh constant to
    /// the running accumulator) using INPUT/OUTPUT boundary rows.
    /// Every produced byte is consumed exactly once; the chip's lookup
    /// is fully balanced.
    ///
    /// Measures what soundness-complete prove time looks like per N row
    /// chip operations.
    fn bench_ristretto_chip_soundness_complete_chain() {
        use std::time::Instant;
        use zkpvm::chips::ristretto::witness::{fill_add, fill_input, fill_output};

        let n_ops: usize = 10000;
        let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());

        // Row 0: initial accumulator value.
        let mut acc = [0u8; 32];
        acc[0] = 1;
        side_note.add_ristretto_field_row(fill_input(acc));
        let mut row_idx: u16 = 1;

        let t0 = Instant::now();
        for i in 0..n_ops {
            // Row K: input fresh constant c_i.
            let mut c = [0u8; 32];
            c[0] = (i as u8) ^ 0x37;
            side_note.add_ristretto_field_row(fill_input(c));
            let c_row = row_idx;
            row_idx += 1;

            // Row K+1: add(acc, c) consuming the previous acc and the fresh c.
            let prev_acc_row = if i == 0 { 0 } else { row_idx - 2 };
            let mut row = fill_add(acc, c);
            row.a_source_row = prev_acc_row;
            row.b_source_row = c_row;
            acc = row.out;
            side_note.add_ristretto_field_row(row);
            row_idx += 1;
        }

        // Final output row: drains the last acc.
        let final_acc_row = row_idx - 1;
        side_note.add_ristretto_field_row(fill_output(acc, final_acc_row));
        let _row_idx = row_idx + 1;
        eprintln!("Composed {n_ops} ops + boundary rows in {:?}", t0.elapsed());

        let config = zkpvm::PcsConfig {
            pow_bits: 5,
            fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
            lifting_log_size: None,
        };
        // Chip-isolated prove/verify (see `prove_ristretto_chip_closed_chain_input_output`):
        // measure the RistrettoChip + Range256 table cost only, without the
        // always-on memory / register boundary machinery (whose Phase Z0 closing
        // binding rejects step-less traces).
        let components: &[&'static dyn zkpvm::harness::MachineProverComponent] =
            &[&zkpvm::chips::RangeMultiplicity256, &zkpvm::chips::RistrettoChip];
        let t = Instant::now();
        let proof = zkpvm::prove_with_explicit_components(&mut side_note, config, components)
            .expect("soundness-complete chain prove failed");
        let prove_time = t.elapsed();

        let policy = zkpvm::PcsPolicy {
            min_pow_bits: 5,
            min_fri_queries: 3,
            min_fri_log_blowup: 0,
        };
        let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
            .iter()
            .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
            .collect();
        let t = Instant::now();
        zkpvm::verify_with_explicit_components(
            proof,
            &side_note,
            &verifier_components,
            components,
            &policy,
        )
        .expect("soundness-complete chain verify failed");
        let verify_time = t.elapsed();

        eprintln!();
        eprintln!("=== R1f: SOUNDNESS-COMPLETE chip prove-time benchmark ===");
        eprintln!("Operations: {n_ops}");
        eprintln!(
            "Total chip rows: {} (1 init + n_ops·2 + 1 output)",
            1 + n_ops * 2 + 1
        );
        eprintln!("Prove:  {:>6.2} s", prove_time.as_secs_f64());
        eprintln!("Verify: {:?}", verify_time);
        eprintln!();
        eprintln!(
            "Per-op cost: {:.2} ms",
            prove_time.as_secs_f64() * 1000.0 / n_ops as f64
        );
    }

    /// Realistic prove-time measurement combining the RistrettoChip's
    /// per-payment row sequence (~21K rows) with a non-trivial CpuChip
    /// baseline (loaded from fibonacci_actor's PVM trace).  This is the
    /// "chip on top of an existing actor trace" cost — the
    /// configuration users would actually pay for.
    ///
    /// Needs the INPUT-PRODUCER mechanism.
    fn bench_ristretto_chip_combined_with_cpu_baseline() {
        use std::time::Instant;
        use zkpvm::chips::ristretto::point::{point_add_rows, point_identity, scalar_mult_rows};
        use zkpvm::core::tracing::TracingPvm;

        // CpuChip baseline: clerk-private-pay-bench actor (~37K PVM
        // steps, log17 trace) — the realistic per-payment baseline.
        let Some(blob) = load_actor_blob("clerk-private-pay-bench") else {
            return;
        };
        let (interp, flat_mem) = interpreter_from_blob(&blob, 100_000_000);
        let parsed = program::parse_blob(&blob).expect("parse blob");
        let mut code_data = None;
        for entry in &parsed.caps {
            if entry.cap_type == CapEntryType::Code {
                code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
                break;
            }
        }
        let code_blob = program::parse_code_blob(&code_data.expect("no CODE")).expect("parse code");
        let mut tracing = TracingPvm::new(interp);
        let _ = tracing.run_with_vos_stubs();
        let steps = tracing.into_trace();
        eprintln!("CpuChip baseline: {} PVM steps", steps.len());

        let mut side_note =
            zkpvm::SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
                .with_memory(flat_mem)
                .with_jump_table(code_blob.jump_table.to_vec());

        // Push one private payment's worth of chip rows on top.
        let scalar_v: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 50;
            s
        };
        let scalar_b: [u8; 32] = {
            let mut s = [0u8; 32];
            for i in 0..32 {
                s[i] = 0xa5u8.wrapping_mul((i + 1) as u8);
            }
            s[31] &= 0x7f;
            s
        };
        let id = point_identity();
        let (vg_rows, vg_pt) = scalar_mult_rows(&scalar_v, &id);
        let (bh_rows, bh_pt) = scalar_mult_rows(&scalar_b, &id);
        let (add_rows, _) = point_add_rows(&vg_pt, &bh_pt);
        let (kg_rows, _) = scalar_mult_rows(&scalar_v, &id);
        let (skg_rows, _) = scalar_mult_rows(&scalar_b, &id);
        let mut chip_rows = Vec::new();
        chip_rows.extend(vg_rows);
        chip_rows.extend(bh_rows);
        chip_rows.extend(add_rows);
        chip_rows.extend(kg_rows);
        chip_rows.extend(skg_rows);
        eprintln!("RistrettoChip rows: {}", chip_rows.len());

        for row in chip_rows {
            side_note.add_ristretto_field_row(row);
        }

        eprintln!("Proving combined trace (CpuChip + RistrettoChip)...");
        let t = Instant::now();
        let (proof, _) = prove_profiled(&mut side_note).expect("prove");
        let prove_time = t.elapsed();
        eprintln!("Prove: {:?}", prove_time);

        let proof_bytes = bincode::serialize(&proof).expect("serialize");
        eprintln!("Proof: {:.1} KB", proof_bytes.len() as f64 / 1024.0);

        let t = Instant::now();
        verify(proof, &side_note).expect("verify");
        eprintln!("Verify: {:?}", t.elapsed());

        eprintln!();
        eprintln!("=== ACTUAL combined prove time, fibonacci CpuChip + 1 payment chip ===");
        eprintln!("Prove: {:>6.2} s", prove_time.as_secs_f64());
    }

    /// Actual end-to-end prove-time measurement for one private
    /// payment's crypto core (1 Pedersen v·G + b·H + add, 1 Schnorr
    /// k·G + sk·G).  Pushes the full ~21K-row sequence through the
    /// RistrettoChip and reports prove + verify time.
    ///
    /// Needs the INPUT-PRODUCER mechanism.
    fn bench_ristretto_chip_one_private_payment() {
        use std::time::Instant;
        use zkpvm::chips::ristretto::point::{point_add_rows, point_identity, scalar_mult_rows};

        let scalar_v: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 50;
            s
        };
        let scalar_b: [u8; 32] = {
            let mut s = [0u8; 32];
            for i in 0..32 {
                s[i] = 0xa5u8.wrapping_mul((i + 1) as u8);
            }
            s[31] &= 0x7f;
            s
        };
        let id = point_identity();

        eprintln!("Composing one-payment row sequence...");
        let t0 = Instant::now();
        let mut rows = Vec::new();
        // Full per-payment crypto core: 1 Pedersen v·G + b·H + add,
        // 1 Schnorr k·G + sk·G.  Exercises the full ~21K-row sequence
        // across all scalars.
        let (vg_rows, vg_pt) = scalar_mult_rows(&scalar_v, &id);
        rows.extend(vg_rows);
        let (bh_rows, bh_pt) = scalar_mult_rows(&scalar_b, &id);
        rows.extend(bh_rows);
        let (add_rows, _) = point_add_rows(&vg_pt, &bh_pt);
        rows.extend(add_rows);
        let (kg_rows, _) = scalar_mult_rows(&scalar_v, &id);
        rows.extend(kg_rows);
        let (skg_rows, _) = scalar_mult_rows(&scalar_b, &id);
        rows.extend(skg_rows);
        eprintln!(
            "Composed {} field-op rows in {:?}",
            rows.len(),
            t0.elapsed()
        );

        let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
        let t1 = Instant::now();
        for row in rows {
            side_note.add_ristretto_field_row(row);
        }
        eprintln!("Pushed rows + bumped Range256 counts in {:?}", t1.elapsed());

        let config = zkpvm::PcsConfig {
            pow_bits: 5,
            fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
            lifting_log_size: None,
        };
        let t2 = Instant::now();
        let proof = zkpvm::prove_with_config(&mut side_note, config).expect("proving failed");
        let prove_time = t2.elapsed();
        eprintln!("Prove time: {:?}", prove_time);

        let policy = zkpvm::PcsPolicy {
            min_pow_bits: 5,
            min_fri_queries: 3,
            min_fri_log_blowup: 0,
        };
        let t3 = Instant::now();
        zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify failed");
        eprintln!("Verify time: {:?}", t3.elapsed());

        eprintln!();
        eprintln!("=== ACTUAL chip prove time, one full private payment ===");
        eprintln!("Prove:  {:>8.2} s", prove_time.as_secs_f64());
    }

    /// Count the host-side row sequence for one full cipher-clerk
    /// "tap-and-pay" cryptographic core (one Pedersen amount commit +
    /// one Schnorr-on-Ristretto sign), and report the expected
    /// RistrettoChip log_size.  Estimates the chip's prove-time cost
    /// from the row count.
    fn project_ristretto_chip_size_for_one_payment() {
        use zkpvm::chips::ristretto::point::{
            ED25519_TWO_D, point_add_rows, point_identity, scalar_mult_rows,
        };

        // One Pedersen amount commit needs 2 scalar mults + 1 point add:
        //   v · G + b · H  (where v is the value, b the blinding)
        let scalar_v: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 50;
            s
        };
        let scalar_b: [u8; 32] = {
            let mut s = [0u8; 32];
            for i in 0..32 {
                s[i] = 0xa5u8.wrapping_mul((i + 1) as u8);
            }
            s[31] &= 0x7f;
            s
        };
        let id = point_identity();
        let (rows_vg, _vg_pt) = scalar_mult_rows(&scalar_v, &id);
        let (rows_bh, _bh_pt) = scalar_mult_rows(&scalar_b, &id);
        let (rows_add, _) = point_add_rows(&_vg_pt, &_bh_pt);

        // One Schnorr sign needs 2 scalar mults (k·G nonce, sk·G pubkey)
        // — same shape as Pedersen.
        let (rows_kg, _) = scalar_mult_rows(&scalar_v, &id);
        let (rows_skg, _) = scalar_mult_rows(&scalar_b, &id);

        let total_rows =
            rows_vg.len() + rows_bh.len() + rows_add.len() + rows_kg.len() + rows_skg.len();
        let log_n = 32 - (total_rows as u32).saturating_sub(1).leading_zeros();
        eprintln!("=== Per-payment RistrettoChip row projection ===");
        eprintln!("Pedersen v·G:    {} rows", rows_vg.len());
        eprintln!("Pedersen b·H:    {} rows", rows_bh.len());
        eprintln!("Pedersen +:      {} rows", rows_add.len());
        eprintln!("Schnorr k·G:     {} rows", rows_kg.len());
        eprintln!("Schnorr sk·G:    {} rows", rows_skg.len());
        eprintln!("Total per pay:   {} rows", total_rows);
        eprintln!("Chip log_size:   {}", log_n);
        let _ = ED25519_TWO_D;

        // Realistic prove-time projection.
        //
        // clerk-private-pay-bench today: ~37K PVM steps, log17 trace,
        // 878 main cols, ~6.5s prove.  Total committed cells:
        // 878 × 2^17 ≈ 115M.  Throughput: 115M / 6.5s ≈ 17.7M cells/s.
        //
        // RistrettoChip cells: 700 cols × 2^log_n.
        let chip_cells = 700u64 * (1u64 << log_n);
        let baseline_cells: u64 = 878 * (1u64 << 17);
        let baseline_secs: f64 = 6.5;
        let throughput: f64 = baseline_cells as f64 / baseline_secs; // cells / second
        let total_cells = baseline_cells + chip_cells;
        let projected_secs = total_cells as f64 / throughput;
        eprintln!();
        eprintln!(
            "Cells:  baseline {} M + chip {} M = total {} M",
            baseline_cells / 1_000_000,
            chip_cells / 1_000_000,
            total_cells / 1_000_000
        );
        eprintln!("Throughput: {:.1} M cells/s", throughput / 1e6);
        eprintln!("Projected total prove: ~{:.1}s on CPU", projected_secs);
        eprintln!("With GPU (3×):  ~{:.1}s", projected_secs / 3.0);
        eprintln!(
            "With NAF-w4 (-30% rows) + GPU: ~{:.1}s",
            projected_secs * 0.7 / 3.0
        );
    }

    /// Hot-PC profile of clerk-private-pay-bench.  Diagnostic (no
    /// prove); used to identify which functions dominate trace size.
    fn profile_hot_pcs_clerk_private_pay_bench() {
        let Some(blob) = load_actor_blob("clerk-private-pay-bench") else {
            return;
        };
        let (interp, _flat_mem) = interpreter_from_blob(&blob, 500_000_000);
        let mut tracing = TracingPvm::new(interp);
        let _ = tracing.run_with_vos_stubs();
        let ristretto_count = tracing.ristretto_records.len();
        let ristretto_add_count = tracing.ristretto_add_records.len();
        let scalar_reduce_count = tracing.scalar_reduce_wide_records.len();
        let scalar_binop_count = tracing.scalar_binop_records.len();
        let blake2b_count = tracing.blake2b_records.len();
        let steps = tracing.into_trace();
        eprintln!("Phase-2 trace: {} PVM steps", steps.len());
        eprintln!(
            "ECALLs: blake2b={}, ristretto_scalar_mult={}, ristretto_point_add={}, scalar_reduce_wide={}, scalar_binop={}",
            blake2b_count,
            ristretto_count,
            ristretto_add_count,
            scalar_reduce_count,
            scalar_binop_count,
        );

        let mut pc_count = std::collections::HashMap::<u32, u32>::new();
        for s in &steps {
            *pc_count.entry(s.pc).or_insert(0) += 1;
        }
        let mut top: Vec<_> = pc_count.iter().map(|(&pc, &c)| (pc, c)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("\nTop 10 hot PCs:");
        for (pc, c) in top.iter().take(10) {
            eprintln!("  pc=0x{pc:08x}  hits={c}");
        }

        let mut region_count = std::collections::HashMap::<u32, u32>::new();
        for s in &steps {
            *region_count.entry(s.pc & !0xff).or_insert(0) += 1;
        }
        let mut regions: Vec<_> = region_count.iter().map(|(&pc, &c)| (pc, c)).collect();
        regions.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("\nTop 10 hot 256-byte regions:");
        let total = steps.len() as u32;
        let mut cum = 0u32;
        for (pc, c) in regions.iter().take(10) {
            cum += c;
            let pct = 100.0 * (*c as f64) / (total as f64);
            let cum_pct = 100.0 * (cum as f64) / (total as f64);
            eprintln!(
                "  pc=0x{pc:08x}..0x{:08x}  hits={c} ({pct:.1}% of trace, cum {cum_pct:.1}%)",
                pc + 0xff
            );
        }
    }
}
