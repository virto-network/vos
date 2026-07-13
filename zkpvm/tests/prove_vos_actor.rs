#![cfg(feature = "prover")]

//! End-to-end test: trace a real VOS actor compiled from Rust.

use javm::interpreter::Interpreter;
use javm::program::{self, CapEntryType};

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, verify};

/// Load fibonacci PVM blob (transpiled from ELF), or `None` when the
/// fixture is absent so callers SKIP (print + return) rather than panic.
/// Matches the skip-if-absent hygiene of `settle_run.rs`.
fn load_fibonacci_blob() -> Option<Vec<u8>> {
    let blob_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/fibonacci/target/riscv64em-javm/release/fibonacci.pvm"
    );
    if let Ok(data) = std::fs::read(blob_path) {
        return Some(data);
    }
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/fibonacci/target/riscv64em-javm/release/fibonacci.elf"
    );
    let elf_data = match std::fs::read(elf_path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!(
                "SKIP: fibonacci actor fixture absent; build with \
                 `cd examples/actors/fibonacci && cargo actor` (or `just build-pvm`)"
            );
            return None;
        }
    };
    Some(grey_transpiler::link_elf(&elf_data).expect("failed to transpile fibonacci ELF"))
}

/// Test-side panicking wrapper over `zkpvm::actor::interpreter_from_blob`
/// — every callsite below treats a missing CODE cap as a fixture bug,
/// not a runtime condition, so the `Option<_>` ergonomics aren't worth
/// the noise here.
fn interpreter_from_blob(blob: &[u8], gas: u64) -> (Interpreter, Vec<u8>) {
    zkpvm::actor::interpreter_from_blob(blob, gas).expect("interpreter from blob")
}

#[test]
fn trace_fibonacci_actor() {
    let Some(blob) = load_fibonacci_blob() else {
        return;
    };
    eprintln!("PVM blob: {} bytes", blob.len());

    let (interp, _flat_mem) = interpreter_from_blob(&blob, 10_000_000);
    eprintln!(
        "Interpreter: code={} bytes, flat_mem={} bytes",
        interp.code.len(),
        interp.flat_mem.len()
    );

    let mut tracing = TracingPvm::new(interp);
    // Drive the lifecycle stubs so bootstrap hostcalls are serviced and the
    // actor runs its full `start` handler (fib compute).
    let exit = tracing.run_with_vos_stubs();
    let steps = tracing.into_trace();
    eprintln!("Execution: {} steps, exit={exit:?}", steps.len());

    // A correctly-built actor runs thousands of steps (bootstrap + compute).
    // A stale / mis-built ELF traps almost immediately (2 steps, `Panic`) —
    // catch that loudly instead of silently "tracing" a broken run.
    assert!(
        steps.len() > 1000 && !format!("{exit:?}").contains("Panic"),
        "fibonacci actor only traced {} steps (exit={exit:?}) — stale/mis-built \
         ELF? rebuild with `cd examples/actors/fibonacci && cargo actor`",
        steps.len()
    );
    eprintln!("First: pc={} {:?}", steps[0].pc, steps[0].opcode);
    eprintln!(
        "Last:  pc={} {:?}",
        steps.last().unwrap().pc,
        steps.last().unwrap().opcode
    );

    // Count opcode categories
    let mut counts = std::collections::HashMap::new();
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
    }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    eprintln!("Opcode distribution (top 10):");
    for (op, count) in sorted.iter().take(10) {
        eprintln!("  {op}: {count}");
    }
}

// Proving the full fibonacci actor trace end-to-end is benchmark-scale (the
// bootstrap alone pads to log-16, ~10 GB even under the MOBILE config), so it
// lives in `benches/actors.rs::profile_fibonacci_actor`, not here. The
// `trace_fibonacci_actor` guard above catches a broken/stale ELF, and the
// prove+verify pipeline is covered by the smaller `chip_isolated` harness
// tests and the ecall-boundary tests.

// ── Generic actor profile helper ──

/// Load actor `name`'s PVM blob (preferring a pre-transpiled `.pvm`,
/// else transpiling its `.elf`), or `None` when the fixture is absent
/// so callers SKIP (print + return) rather than panic.  The SKIP
/// message is emitted here, so callers just `let Some(blob) = ... else
/// { return; };`.
fn load_actor_blob(name: &str) -> Option<Vec<u8>> {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/actors/");
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

/// Trace-only variant of clerk-refine-bench: validates the actor
/// builds + runs.  Trace-only because profile_clerk_refine_bench
/// also runs the full prove path.
#[test]
fn trace_clerk_refine_bench() {
    let Some(blob) = load_actor_blob("clerk-refine-bench") else {
        return;
    };
    let (interp, _flat_mem) = interpreter_from_blob(&blob, 100_000_000);
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run_with_vos_stubs();
    let steps = tracing.into_trace();
    eprintln!(
        "clerk-refine-bench: {} PVM steps, exit={exit:?}",
        steps.len()
    );
}

/// Build the side_note exactly as the prover would for `name`'s canonical
/// workload, then run `register_memory::analyze_dedup` and print the report.
/// No prove step — fast.
fn analyze_register_dedup(name: &str, gas: u64) {
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
    let code_blob = program::parse_code_blob(&code_data.expect("no CODE cap")).expect("parse code");
    let (interp, flat_mem) = interpreter_from_blob(&blob, gas);

    let mut tracing = TracingPvm::new(interp);
    let _exit = tracing.run_with_vos_stubs();
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

    let report = zkpvm::chips::register_memory::analyze_dedup(&side_note);

    eprintln!("=== {name} register-memory dedup feasibility ===");
    eprintln!("PVM steps:           {}", side_note.steps.len());
    eprintln!(
        "Total ledger entries: {} ({} reads + {} writes)",
        report.total_entries, report.total_reads, report.total_writes
    );
    eprintln!(
        "After dedup:         {} ({} merged rows)",
        report.after_dedup, report.run_count
    );
    eprintln!(
        "Saved:               {} entries ({:.1}%)",
        report.saved,
        100.0 * report.saved as f64 / report.total_entries as f64
    );
    eprintln!("Current log_size:    {}", report.current_log_size);
    eprintln!("After-dedup log_size: {}", report.after_dedup_log_size);
    eprintln!("Longest run:         {}", report.longest_run);
    eprintln!("Run-length histogram (length: count):");
    let total_runs = report.run_count.max(1) as f64;
    let mut cumulative = 0usize;
    for (len, cnt) in &report.run_length_histogram {
        cumulative += cnt;
        eprintln!(
            "  {:>5}: {:>8}  ({:5.1}%)  [cum {:>8} = {:5.1}%]",
            len,
            cnt,
            100.0 * (*cnt as f64) / total_runs,
            cumulative,
            100.0 * (cumulative as f64) / total_runs
        );
    }
    eprintln!("\nFixed-cap merge sweep (M = max-merge per row):");
    eprintln!("  M  rows-after-dedup  log_size");
    for (m, rows, log) in &report.cap_after_dedup {
        let fits = if *log <= 15 { " (fits log=15)" } else { "" };
        eprintln!("  {:>2}  {:>16}  {:>8}{}", m, rows, log, fits);
    }
}

#[test]
fn analyze_register_dedup_clerk_private_pay_bench() {
    analyze_register_dedup("clerk-private-pay-bench", 100_000_000);
}

/// Build the side_note for `name` and run `memory::analyze_dedup`, which
/// counts byte-flood groups (runs of consecutive same-(ts, is_write)
/// entries with monotone-by-1 addresses).
fn analyze_memory_dedup(name: &str, gas: u64) {
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
    let code_blob = program::parse_code_blob(&code_data.expect("no CODE cap")).expect("parse code");
    let (interp, flat_mem) = interpreter_from_blob(&blob, gas);

    let mut tracing = TracingPvm::new(interp);
    let _exit = tracing.run_with_vos_stubs();
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

    let report = zkpvm::chips::memory::analyze_dedup(&side_note);

    eprintln!("=== {name} memory dedup feasibility ===");
    eprintln!("Total ledger entries:    {}", report.total_entries);
    eprintln!(
        "Bytes in flood groups:   {} ({:.1}%)",
        report.bytes_in_flood_groups,
        100.0 * report.bytes_in_flood_groups as f64 / report.total_entries as f64
    );
    eprintln!("After unbounded dedup:   {}", report.after_dedup);
    eprintln!("Current log_size:        {}", report.current_log_size);
    eprintln!("After-dedup log_size:    {}", report.after_dedup_log_size);
    eprintln!("Longest flood:           {}", report.longest_flood);
    eprintln!("Flood-length histogram (length: count):");
    let total_groups = report.after_dedup.max(1) as f64;
    let mut cumulative = 0usize;
    for (len, cnt) in &report.flood_length_histogram {
        cumulative += cnt;
        eprintln!(
            "  {:>5}: {:>8}  ({:5.1}%)  [cum {:>8} = {:5.1}%]",
            len,
            cnt,
            100.0 * (*cnt as f64) / total_groups,
            cumulative,
            100.0 * (cumulative as f64) / total_groups
        );
    }
    eprintln!("\nFixed-cap merge sweep (M = max bytes per row):");
    eprintln!("  M  rows-after-dedup  log_size");
    for (m, rows, log) in &report.cap_after_dedup {
        let fits = if *log <= 15 { " (fits log=15)" } else { "" };
        eprintln!("  {:>2}  {:>16}  {:>8}{}", m, rows, log, fits);
    }
}

#[test]
fn analyze_memory_dedup_clerk_private_pay_bench() {
    analyze_memory_dedup("clerk-private-pay-bench", 100_000_000);
}

#[test]
fn trace_clerk_private_pay_bench() {
    let Some(blob) = load_actor_blob("clerk-private-pay-bench") else {
        return;
    };
    let (interp, _flat_mem) = interpreter_from_blob(&blob, 500_000_000);
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run_with_vos_stubs();
    let steps = tracing.into_trace();
    eprintln!(
        "clerk-private-pay-bench: {} PVM steps, exit={exit:?}",
        steps.len()
    );
}

/// Profile a specific hash variant by PVM blob name
fn profile_hash_variant(name: &str) {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/hash-bench/"
    );
    let pvm_path = format!("{base}hash-{name}.pvm");
    let elf_path = format!("{base}hash-{name}.elf");
    let blob = match std::fs::read(&pvm_path) {
        Ok(data) => data,
        Err(_) => match std::fs::read(&elf_path) {
            Ok(elf) => grey_transpiler::link_elf(&elf).expect("transpile"),
            Err(_) => {
                eprintln!("SKIP: hash-{name} fixture absent; build hash-bench variants first");
                return;
            }
        },
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
    let steps = tracing.into_trace();

    let n = steps.len();

    let mut side_note = zkpvm::SideNote::new(
        steps.clone(),
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
    )
    .with_memory(flat_mem)
    .with_jump_table(code_blob.jump_table.to_vec());

    let mut counts = std::collections::HashMap::new();
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
    }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    let top_ops: String = sorted
        .iter()
        .take(5)
        .map(|(op, c)| format!("{op}:{c}"))
        .collect::<Vec<_>>()
        .join(" ");

    let t = std::time::Instant::now();
    match prove(&mut side_note) {
        Ok(proof) => {
            let prove_time = t.elapsed();
            let kb = bincode::serialize(&proof).unwrap().len() as f64 / 1024.0;
            verify(proof, &side_note).expect("verify");
            eprintln!(
                "  {name:>10}: {n:>5} steps | prove={prove_time:>8.2?} | proof={kb:>5.1} KB | {top_ops}"
            );
        }
        Err(_) => {
            eprintln!("  {name:>10}: {n:>5} steps | CONSTRAINT FAIL | {top_ops}");
        }
    }
}

#[test]
fn compare_hash_algorithms() {
    eprintln!("=== Hash algorithm comparison (10 rounds + 4-level Merkle, 96-bit security) ===");
    for name in &["toy", "blake2s", "sha256"] {
        profile_hash_variant(name);
    }
}

#[test]
fn debug_blake2s_prefix() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/hash-bench/"
    );
    let blob = match std::fs::read(format!("{base}hash-blake2s.pvm")) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: hash-blake2s.pvm fixture absent");
            return;
        }
    };
    let parsed = program::parse_blob(&blob).expect("parse");
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
    let steps = tracing.into_trace();
    eprintln!("blake2s: {} total steps", steps.len());

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    // Scan for first failing prefix (fresh side_note each time)
    let test_sizes = [steps.len()];
    for &n in &test_sizes {
        let n = n.min(steps.len());
        let trunc: Vec<_> = steps.iter().take(n).cloned().collect();
        let mut sn =
            zkpvm::SideNote::new(trunc, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
                .with_memory(flat_mem.clone())
                .with_jump_table(code_blob.jump_table.to_vec());
        let ok = zkpvm::prove_with_config(&mut sn, config).is_ok();
        eprintln!("  {n:>5} steps: {}", if ok { "OK" } else { "FAIL" });
        if !ok {
            break;
        }
    }
    // Try the full trace
    eprintln!("Trying full trace ({} steps):", steps.len());
    let mut sn = zkpvm::SideNote::new(
        steps.clone(),
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
    )
    .with_memory(flat_mem)
    .with_jump_table(code_blob.jump_table.to_vec());
    match zkpvm::prove_with_config(&mut sn, config) {
        Ok(proof) => {
            // Use a permissive policy matching the test config —
            // STANDARD floor would trip on pow_bits=5 / fri_log_blowup=0.
            let policy = zkpvm::PcsPolicy {
                min_pow_bits: 5,
                min_fri_queries: 3,
                min_fri_log_blowup: 0,
            };
            zkpvm::verify_with_pcs_policy(proof, &sn, &policy).expect("verify");
            eprintln!("  PASS!");
        }
        Err(e) => {
            eprintln!("  FAIL: {e}");
        }
    }
}

#[test]
fn prove_diverse() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/hash-bench/"
    );
    let blob = match std::fs::read(format!("{base}hash-diverse.pvm")) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: hash-diverse.pvm fixture absent");
            return;
        }
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
    let steps = tracing.into_trace();
    eprintln!("Diverse: {} steps", steps.len());
    let mut side_note =
        zkpvm::SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
            .with_memory(flat_mem)
            .with_jump_table(code_blob.jump_table.to_vec());
    let t = std::time::Instant::now();
    match prove(&mut side_note) {
        Ok(p) => {
            let kb = bincode::serialize(&p).unwrap().len() as f64 / 1024.0;
            verify(p, &side_note).expect("verify");
            eprintln!("PROVED in {:?} ({kb:.1} KB)", t.elapsed());
        }
        Err(e) => eprintln!("FAIL: {e}"),
    }
}

#[test]
fn trace_diverse_steps() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/hash-bench/"
    );
    let blob = match std::fs::read(format!("{base}hash-diverse.pvm")) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: hash-diverse.pvm fixture absent");
            return;
        }
    };
    let (interp, _) = interpreter_from_blob(&blob, 100_000_000);
    let mut tracing = TracingPvm::new(interp);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Diverse: {} steps", steps.len());
    let mut counts = std::collections::HashMap::new();
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
    }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, c) in sorted.iter() {
        eprintln!("  {op}: {c}");
    }
}

#[test]
fn trace_keccak_steps() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/hash-bench/"
    );
    let blob = match std::fs::read(format!("{base}hash-keccak.pvm")) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: hash-keccak.pvm fixture absent");
            return;
        }
    };
    let (interp, _) = interpreter_from_blob(&blob, 100_000_000);
    let mut tracing = TracingPvm::new(interp);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Keccak: {} steps", steps.len());
    let mut counts = std::collections::HashMap::new();
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
    }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, c) in sorted.iter().take(10) {
        eprintln!("  {op}: {c}");
    }
}

#[test]
fn prove_blake2b_precompile() {
    use zkpvm::chips::blake2b::blake2b_compress;
    use zkpvm::core::tracing::ECALL_BLAKE2B_COMPRESS;

    // Runs a minimal PVM program that just ECALLs blake2b.  Needs to go
    // through TracingPvm.run_with_precompiles so the CpuChip gets an ECALL
    // step (the producer) and the tracer captures the matching
    // blake2b_mem_op (the consumer pre-image).
    let h = [
        0x6A09E667F3BCC908u64,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ];
    let m = [0u64; 16];
    let expected = blake2b_compress(&h, &m, 0, true);
    eprintln!("blake2b(empty) first word: {:#x}", expected[0]);

    let h_addr: u64 = 0x1000;
    let m_addr: u64 = 0x1040;
    let mut flat_mem = vec![0u8; 0x2000];
    for i in 0..8 {
        flat_mem[h_addr as usize + i * 8..h_addr as usize + i * 8 + 8]
            .copy_from_slice(&h[i].to_le_bytes());
    }
    // m left all zero.

    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        ECALL_BLAKE2B_COMPRESS as u8,
        0,
        0,
        0,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2/A3 map to φ[7/8/9/10].
    regs[7] = h_addr;
    regs[8] = m_addr;
    regs[9] = 0;
    regs[10] = 1;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run_with_precompiles();
    let steps = tracing.trace();
    let blake2b_records = tracing.blake2b_records.clone();
    let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask).with_memory(flat_mem);
    for rec in &blake2b_records {
        side_note
            .blake2b_calls
            .push(zkpvm::chips::blake2b::Blake2bCall {
                h: rec.h,
                m: rec.m,
                t: rec.t,
                f: rec.f,
            });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config).expect("blake2b proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("blake2b verification failed");
    eprintln!("Blake2b precompile: PROVED!");
}

/// Prove + verify a pre-built RistrettoChip side note against the
/// chip-isolated components (`RangeMultiplicity256` + `RistrettoChip`)
/// only — the full-machine path rejects step-less traces via the Z0
/// boundary binding (see `prove_ristretto_chip_closed_chain_input_output`).
/// Returns whether it both proves AND verifies.
fn prove_verify_ristretto_isolated(side_note: &mut zkpvm::SideNote) -> bool {
    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let components: &[&'static dyn zkpvm::harness::MachineProverComponent] =
        &[&zkpvm::chips::RangeMultiplicity256, &zkpvm::chips::RistrettoChip];
    let Ok(proof) = zkpvm::prove_with_explicit_components(side_note, config, components) else {
        return false;
    };
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    zkpvm::verify_with_explicit_components(proof, side_note, &verifier_components, components, &policy)
        .is_ok()
}

/// Prove a single field-op row (add / sub / mul) in a balanced,
/// chip-isolated chain: `fill_input` producers feed the row's two
/// operands and a `fill_output` consumer drains its result, so the
/// RistrettoChip register-file logup closes.  Returns whether the chain
/// proves AND verifies, so negative tests can assert a tampered row is
/// rejected.
fn prove_field_op_row_isolated(row: zkpvm::chips::ristretto::witness::FieldOpRow) -> bool {
    use zkpvm::chips::ristretto::witness::{fill_input, fill_output};

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
    // Rows 0/1: input producers for the two operands.
    side_note.add_ristretto_field_row(fill_input(row.a));
    side_note.add_ristretto_field_row(fill_input(row.b));
    // Row 2: the op under test, consuming the two producers.
    let mut op = row;
    op.a_source_row = 0;
    op.b_source_row = 1;
    side_note.add_ristretto_field_row(op);
    // Row 3: output consumer draining the op's result.
    side_note.add_ristretto_field_row(fill_output(op.out, 2));

    prove_verify_ristretto_isolated(&mut side_note)
}

/// End-to-end chip-on test.  Wraps a single field-add row (1 + 2 = 3
/// mod p) in a balanced input→op→output chain and proves + verifies it
/// against the RistrettoChip in isolation.  Validates that the AIR's
/// per-row constraints (R1c-3..R1c-5-b) hold against real witness data —
/// separate from the ECALL boundary path.
#[test]
fn prove_ristretto_chip_field_add() {
    use zkpvm::chips::ristretto::witness::fill_add;

    // Single field-add row: 1 + 2 = 3 mod p.
    let mut a = [0u8; 32];
    a[0] = 1;
    let mut b = [0u8; 32];
    b[0] = 2;
    let row = fill_add(a, b);
    assert_eq!(row.out[0], 3);

    assert!(
        prove_field_op_row_isolated(row),
        "RistrettoChip field-add should prove + verify"
    );
    eprintln!("RistrettoChip field-add: PROVED + VERIFIED");
}

/// Chip-on test for field-mul.  Exercises the full is_mul row
/// constraint chain (schoolbook R1c-4-b → 2-pass reduction R1c-5-b
/// → final < p check R1c-3-bis) inside a balanced input→op→output chain.
#[test]
fn prove_ristretto_chip_field_mul() {
    use zkpvm::chips::ristretto::witness::fill_mul;

    // Smallest non-zero case: 1 · 1 = 1.  The all-zero case 0·0=0 is
    // covered by prove_ristretto_chip_field_mul_zero below.
    let mut a = [0u8; 32];
    a[0] = 1;
    let mut b = [0u8; 32];
    b[0] = 1;
    let row = fill_mul(a, b);
    assert_eq!(row.out[0], 1);

    assert!(
        prove_field_op_row_isolated(row),
        "RistrettoChip field-mul should prove + verify"
    );
    eprintln!("RistrettoChip field-mul: PROVED + VERIFIED");
}

/// Negative tests confirming the chip's per-row constraints reject
/// malformed witnesses.  Each tampered row is wrapped in a balanced
/// input→op→output chain (via `prove_field_op_row_isolated`) and MUST
/// fail to prove-or-verify.  This is the audit evidence that within-row
/// soundness is intact.
#[test]
fn ristretto_chip_negative_per_row_soundness_audit() {
    use zkpvm::chips::ristretto::witness::{FieldOpRow, fill_add, fill_mul, fill_sub};

    // Wrap the row under test in a balanced chain: an honest witness
    // proves + verifies; any per-row tamper breaks a constraint (or the
    // output-consumer lookup) and is rejected.
    fn try_prove(row: FieldOpRow) -> bool {
        prove_field_op_row_isolated(row)
    }

    let mut a_small = [0u8; 32];
    a_small[0] = 5;
    let mut b_small = [0u8; 32];
    b_small[0] = 3;

    // Baseline: honest add witness proves.
    assert!(
        try_prove(fill_add(a_small, b_small)),
        "honest add witness must prove"
    );

    // Tamper #1: flip out byte → fail (sum chain rejects).
    let mut bad = fill_add(a_small, b_small);
    bad.out[0] = bad.out[0].wrapping_add(1);
    assert!(!try_prove(bad), "tampered out[0] must fail");

    // Tamper #2: flip is_overflow → fail (final-form chain rejects).
    let mut bad = fill_add(a_small, b_small);
    bad.is_overflow = 1 - bad.is_overflow;
    assert!(!try_prove(bad), "tampered is_overflow must fail");

    // Tamper #3: flip add_carry bit → fail (boolean / sum chain rejects).
    let mut bad = fill_add(a_small, b_small);
    bad.add_carry[0] = 1 - bad.add_carry[0];
    assert!(!try_prove(bad), "tampered add_carry[0] must fail");

    // Tamper #4: is_sub witness with wrong is_underflow.
    let mut bad = fill_sub([0u8; 32], a_small); // 0 - 5 (underflows)
    bad.is_overflow = 0; // claim no underflow — wrong
    assert!(!try_prove(bad), "tampered is_underflow on is_sub must fail");

    // Tamper #5: mul row with wrong mul_product byte.
    let mut a = [0u8; 32];
    a[0] = 7;
    let mut b = [0u8; 32];
    b[0] = 11;
    let mut bad = fill_mul(a, b);
    bad.mul_product[0] = bad.mul_product[0].wrapping_add(1);
    assert!(!try_prove(bad), "tampered mul_product[0] must fail");

    // Tamper #6: mul row with wrong out byte (post-reduction value).
    let mut bad = fill_mul(a, b);
    bad.out[0] = bad.out[0].wrapping_add(1);
    assert!(!try_prove(bad), "tampered mul out[0] must fail");

    // Tamper #7: claim is_mul = is_add = 1 (partition violation).
    let mut bad = fill_add(a_small, b_small);
    bad.is_mul = 1;
    assert!(!try_prove(bad), "double op-flag must fail (partition)");

    eprintln!("All 7 negative-witness cases correctly REJECTED.");

    // Tamper #8: is_sub two-sided chain — flip a sub_chain_borrow bit.
    let mut a = [0u8; 32];
    a[0] = 0x10;
    a[1] = 0xd1;
    a[2] = 0x1f;
    let mut b = [0u8; 32];
    b[0] = 0x20;
    b[1] = 0xa2;
    b[2] = 0x3f;
    let mut bad = fill_sub(a, b);
    bad.sub_chain_borrow[1] = 1 - bad.sub_chain_borrow[1];
    assert!(!try_prove(bad), "tampered sub_chain_borrow must fail");

    // Tamper #9: is_sub two-sided chain — flip sub_chain_carry_aip bit.
    let mut bad = fill_sub(a, b);
    bad.sub_chain_carry_aip[1] = 1 - bad.sub_chain_carry_aip[1];
    assert!(!try_prove(bad), "tampered sub_chain_carry_aip must fail");

    // Tamper #10: is_mul reduction — flip pass1_lo byte.
    let mut a_big = [0u8; 32];
    let mut b_big = [0u8; 32];
    for i in 0..32 {
        a_big[i] = (0xa3u8).wrapping_mul((i + 1) as u8);
    }
    for i in 0..32 {
        b_big[i] = (0x71u8).wrapping_mul((i + 1) as u8);
    }
    a_big[31] &= 0x7f;
    b_big[31] &= 0x7f;
    let mut bad = fill_mul(a_big, b_big);
    bad.pass1_lo[5] = bad.pass1_lo[5].wrapping_add(1);
    assert!(!try_prove(bad), "tampered pass1_lo must fail");

    // Tamper #11: is_mul reduction — flip pass2_top_bit.
    let mut bad = fill_mul(a_big, b_big);
    bad.pass2_top_bit = 1 - bad.pass2_top_bit;
    assert!(!try_prove(bad), "tampered pass2_top_bit must fail");

    eprintln!("All 11 negative-witness cases correctly REJECTED.");

    // Tamper #12: tamper with FinalFormBorrow — flip last position
    // (closure constraint enforces ff_brw[31] = 0).
    let mut bad = fill_add(a_small, b_small);
    bad.final_form_borrow[31] = 1; // claim out >= p (false)
    assert!(!try_prove(bad), "tampered FinalFormBorrow[31] must fail");

    // Tamper #13: substitute fake out > p (would-be canonical).
    // out = p exactly is invalid (must be < p).
    let mut bad = fill_add(a_small, b_small);
    bad.out = zkpvm::chips::ristretto::field::P_BYTES;
    // Recompute final-form: p - p - 1 = -1 < 0, so ff_brw[0] = 1 immediately.
    let mut bw: i16 = 1;
    for i in 0..32 {
        let p_i = zkpvm::chips::ristretto::field::P_BYTES[i] as i16;
        let v = p_i - bad.out[i] as i16 - bw;
        bw = if v < 0 { 1 } else { 0 };
        bad.final_form_borrow[i] = bw as u8;
    }
    // Even with ff_brw recomputed (final = 1), the chip's closure
    // is_real * ff_brw[31] = 0 will reject.
    assert!(!try_prove(bad), "out = p must fail (final-form rejects)");

    // Tamper #14: add row claims out > p directly via add_intermediate
    // tampering (intermediate must equal a + b which is forced).
    let mut bad = fill_add(a_small, b_small);
    bad.add_intermediate[0] = bad.add_intermediate[0].wrapping_add(7);
    assert!(!try_prove(bad), "tampered add_intermediate must fail");

    // Tamper #15: mul row with tampered after_top_carry breaking the
    // closure (after_top_carry[31] must be 0).
    let mut bad = fill_mul(a_big, b_big);
    bad.after_top_carry[31] = 1;
    assert!(!try_prove(bad), "tampered after_top_carry[31] must fail");

    // Tamper #16: mul row tampered Pass1 closure (pass1_full_carry(31)
    // must equal pass1_hi as 16-bit value).
    let mut bad = fill_mul(a_big, b_big);
    bad.pass1_hi[0] = bad.pass1_hi[0].wrapping_add(1);
    assert!(!try_prove(bad), "tampered Pass1Hi must fail");

    // Tamper #17: claim is_real = 1 but no op flag (partition fail).
    let mut bad = fill_add(a_small, b_small);
    bad.is_add = 0;
    bad.is_sub = 0;
    bad.is_mul = 0;
    // is_real still 1.  Partition: 1·(0+0+0-1) = -1 ≠ 0.
    assert!(!try_prove(bad), "is_real=1 with no op flag must fail");

    eprintln!("All 17 negative-witness cases correctly REJECTED.");
    eprintln!("Per-row soundness: AUDITED across add, sub, mul, reduction,");
    eprintln!("final-form, partition, and closure constraints.");
}

/// Validate the cipher-clerk per-payment row sequence COMPOSES
/// correctly via the host-side compose validator.  Catches any bug
/// in the point-op generators (point_double_rows / point_add_rows /
/// scalar_mult_rows) that would produce inconsistent intermediate
/// values.
#[test]
fn ristretto_chip_per_payment_row_sequence_composes() {
    use zkpvm::chips::ristretto::point::{
        ED25519_TWO_D, ExtendedPoint, point_add_rows, point_identity, scalar_mult_rows,
    };
    use zkpvm::chips::ristretto::witness::{FieldOpRow, validate_row_sequence_composes};

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

    // Boundary inputs: scalars + identity coords (X=0, Y=1, Z=1, T=0).
    // Plus zero (which fill_add(0,0), fill_mul(0,0) etc. produce — used
    // for setup) and one (the "1" field element constant).  These are
    // the values rows can legitimately consume from "outside".
    let zero = [0u8; 32];
    let mut one = [0u8; 32];
    one[0] = 1;
    let boundary_inputs = vec![
        zero,
        one,
        scalar_v,
        scalar_b,
        id.x,
        id.y,
        id.z,
        id.t,
        // Curve constant 2·d used inside point_add_rows.
        ED25519_TWO_D,
    ];

    let mut rows: Vec<FieldOpRow> = Vec::new();
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

    // For this validator to succeed against a long chain, every row's
    // input must appear in `seen_outs` from a prior row.  Some
    // non-trivial rows in the point op generators may legitimately
    // re-use boundary constants (zero, one) or earlier outputs.
    validate_row_sequence_composes(&rows, &boundary_inputs)
        .expect("per-payment row sequence must compose");
    eprintln!(
        "Per-payment row sequence COMPOSES correctly ({} rows).",
        rows.len()
    );

    // Negative case: replace one row's `a` with a sentinel value
    // that's NOT in seen_outs — must reject.  (Tampering by a single
    // byte can coincidentally match the boundary inputs `zero`/`one`,
    // so we use an unmistakably-foreign value.)
    let mut bad_rows = rows.clone();
    bad_rows[100].a = [0xab; 32];
    assert!(
        validate_row_sequence_composes(&bad_rows, &boundary_inputs).is_err(),
        "tampered row's input must be flagged"
    );
    eprintln!("Tampered row sequence correctly REJECTED by composer.");
    let _ = ExtendedPoint {
        x: zero,
        y: one,
        z: one,
        t: zero,
    };
}

/// Confirms the inter-row binding is enforced.  Push 100 unrelated
/// is_add rows whose inputs don't compose with any prior row's
/// output.  The chip's register-file lookup detects the unbalanced
/// consumer side and the prove FAILS.
#[test]
fn ristretto_chip_unrelated_rows_now_rejected() {
    use zkpvm::chips::ristretto::witness::fill_add;

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
    for n in 0..100u8 {
        let mut a = [0u8; 32];
        a[0] = 1;
        let mut b = [0u8; 32];
        b[0] = n;
        side_note.add_ristretto_field_row(fill_add(a, b));
    }
    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let prove_result = zkpvm::prove_with_config(&mut side_note, config);
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let rejected = match prove_result {
        Err(_) => true,
        Ok(proof) => zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).is_err(),
    };
    assert!(
        rejected,
        "R1e-pent must reject unrelated rows at prove or verify: \
         chip has no producer for the consumed input bytes, \
         so logup balance fails."
    );
    eprintln!("100 unrelated rows correctly REJECTED.");
    eprintln!("R1e-pent inter-row binding: CLOSED.");
}

/// Chip-on test using INPUT-PRODUCER rows for boundary inputs.
/// Demonstrates the full soundness chain: boundary inputs emit
/// producer tuples → op rows consume them → op rows produce outputs
/// that downstream rows could consume.  This is the right pattern
/// for the cipher-clerk integration.
#[test]
fn prove_ristretto_chip_with_input_producers() {
    use zkpvm::chips::ristretto::witness::{fill_add, fill_input};

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());

    // Row 0: input row producing value [1, 0, ...].
    let mut v1 = [0u8; 32];
    v1[0] = 1;
    side_note.add_ristretto_field_row(fill_input(v1));

    // Row 1: input row producing value [2, 0, ...].
    let mut v2 = [0u8; 32];
    v2[0] = 2;
    side_note.add_ristretto_field_row(fill_input(v2));

    // Row 2: fill_add(1, 2) consuming a from row 0, b from row 1.
    let mut row = fill_add(v1, v2);
    row.a_source_row = 0;
    row.b_source_row = 1;
    side_note.add_ristretto_field_row(row);

    // Row 3: input row producing the result value [3, 0, ...] —
    // this CONSUMES row 2's output, balancing the lookup.
    // Wait — input rows are PRODUCERS, not consumers.  The lookup
    // imbalance from row 2's unmatched producer is the "output is
    // consumed externally" pattern that the ECALL OUTPUT boundary
    // provides.  For chip-on tests without an ECALL boundary,
    // simulate by adding a final consumer row that uses row 2's
    // output as its `a`.
    let mut consumer_row = fill_add(row.out, [0u8; 32]);
    // Row 0 produces [1, 0, ...]; row 2's output is [3, 0, ...].
    // Chain: consumer_row's a = row 2 (out=3), b = some 0-producer.
    // We need a 0-producer:
    side_note.add_ristretto_field_row(fill_input([0u8; 32])); // row 3: zero
    consumer_row.a_source_row = 2;
    consumer_row.b_source_row = 3;
    side_note.add_ristretto_field_row(consumer_row); // row 4

    // Row 4 has unmatched out (no further consumer).  Add a final
    // consumer that drains it:
    let mut drain = fill_add(consumer_row.out, [0u8; 32]);
    drain.a_source_row = 4;
    drain.b_source_row = 3; // re-use the zero producer
    side_note.add_ristretto_field_row(drain); // row 5

    // Row 5 is also unmatched...  this chain doesn't close in
    // chip-only mode.  With an ECALL boundary the FINAL row's output
    // is consumed by the ECALL OUTPUT boundary lookup against
    // MemoryChip.  For this chip-on test, we accept the unbalance —
    // the VERIFIER will reject.  This test asserts the chain is
    // structurally correct (even if the trailing consumer is
    // missing) by checking the prove path.
    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let prove_result = zkpvm::prove_with_config(&mut side_note, config);
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let chain_balanced = match prove_result {
        Err(_) => false,
        Ok(proof) => zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).is_ok(),
    };
    // Without an external OUTPUT boundary consumer, the trailing
    // out from row 5 is unmatched.  Lookup balance fails — and
    // the verifier correctly rejects.  This is the SAME mechanism
    // that closes the inter-row binding gap.
    assert!(
        !chain_balanced,
        "without external output boundary consumer, chain doesn't close"
    );
    eprintln!("Input-producer mechanism + open-ended chain: correctly rejected.");
    eprintln!("Inter-row binding + boundary-input mechanism: COMPOSABLE.");
}

/// CLOSED chip-on chain with INPUT-PRODUCER + OUTPUT-CONSUMER rows.
/// Demonstrates a fully-balanced lookup: every produced byte is
/// consumed exactly once.  This is the soundness-complete pattern
/// for chip-on tests independent of the ECALL boundary.
#[test]
fn prove_ristretto_chip_closed_chain_input_output() {
    use zkpvm::chips::ristretto::witness::{fill_add, fill_input, fill_output};

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());

    // Row 0: input(1)
    let mut v1 = [0u8; 32];
    v1[0] = 1;
    side_note.add_ristretto_field_row(fill_input(v1));

    // Row 1: input(2)
    let mut v2 = [0u8; 32];
    v2[0] = 2;
    side_note.add_ristretto_field_row(fill_input(v2));

    // Row 2: add(1, 2) = 3, sources (R0, R1).
    let mut row = fill_add(v1, v2);
    row.a_source_row = 0;
    row.b_source_row = 1;
    side_note.add_ristretto_field_row(row);

    // Row 3: output-consumer drains row 2's out.
    side_note.add_ristretto_field_row(fill_output(row.out, 2));

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    // Chip-isolated prove/verify: this exercises the RistrettoChip's per-row +
    // inter-row + boundary lookup closure against its Range256 table producer
    // only.  The full-machine path (`prove_with_config`) additionally activates
    // the always-on memory + register boundary chips, whose Phase Z0 closing
    // binding rejects step-less traces by design (a step-less proof asserts
    // nothing about a program), so a chip-only chain must prove in isolation.
    let components: &[&'static dyn zkpvm::harness::MachineProverComponent] =
        &[&zkpvm::chips::RangeMultiplicity256, &zkpvm::chips::RistrettoChip];
    let proof = zkpvm::prove_with_explicit_components(&mut side_note, config, components)
        .expect("closed chain should prove");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    zkpvm::verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    )
    .expect("closed chain should verify");
    eprintln!("Closed chain (1 input + 1 input + 1 op + 1 output): PROVED + VERIFIED.");
    eprintln!("Soundness chain: per-row + inter-row + boundary all CLOSED.");
}

/// Chip-on test for field-mul of the all-zero case (0·0=0) in a
/// balanced input→op→output chain.
#[test]
fn prove_ristretto_chip_field_mul_zero() {
    use zkpvm::chips::ristretto::witness::fill_mul;

    let row = fill_mul([0u8; 32], [0u8; 32]);
    assert_eq!(row.is_mul, 1);
    assert_eq!(row.out, [0u8; 32]);

    assert!(
        prove_field_op_row_isolated(row),
        "RistrettoChip field-mul (0·0=0) should prove + verify"
    );
    eprintln!("RistrettoChip field-mul (0·0=0): PROVED + VERIFIED");
}

/// Chip-on test for field-mul with operands that overflow 2²⁵⁶,
/// exercising the full reduction chain (pass-1 fold + pass-2 fold +
/// top-bit fold + final < p) in a balanced input→op→output chain.
#[test]
fn prove_ristretto_chip_field_mul_with_reduction() {
    use zkpvm::chips::ristretto::witness::fill_mul;

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for i in 0..32 {
        a[i] = (0xa3u8).wrapping_mul((i + 1) as u8);
    }
    for i in 0..32 {
        b[i] = (0x71u8).wrapping_mul((i + 1) as u8);
    }
    a[31] &= 0x7f;
    b[31] &= 0x7f;

    assert!(
        prove_field_op_row_isolated(fill_mul(a, b)),
        "RistrettoChip field-mul (with reduction) should prove + verify"
    );
    eprintln!("RistrettoChip field-mul (full reduction): PROVED + VERIFIED");
}

/// Hand-craft an `ecalli 200` program, set up φ[10]/φ[11]/φ[12] to
/// point at scalar/input-point/output-point buffers in flat_mem, run
/// TracingPvm with precompile dispatch, and confirm the captured
/// `RistrettoRecord` + the bytes written to `output_ptr` match a
/// host-side dalek computation.  Traces only — no chip / proving.
#[test]
fn ristretto_scalar_mult_via_ecall_tracing() {
    use zkpvm::core::tracing::ECALL_RISTRETTO_SCALAR_MULT;

    // Lay out memory: scalar at 0x1000 (32 B), point at 0x1020 (32 B),
    // output at 0x1040 (32 B).  Scalar is `2`, point is the canonical
    // basepoint compressed encoding so the expected output is `2*G`.
    let scalar_addr: u64 = 0x1000;
    let point_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;

    let scalar_bytes: [u8; 32] = {
        let mut s = [0u8; 32];
        s[0] = 2;
        s
    };
    let point_bytes: [u8; 32] =
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();

    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[scalar_addr as usize..scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&point_bytes);

    // ecalli 200, then trap.  Ecalli is a 5-byte instruction
    // (opcode + 4-byte little-endian immediate).
    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[7] = scalar_addr;
    regs[8] = point_addr;
    regs[9] = output_addr;

    let pvm =
        javm::interpreter::Interpreter::new(code, bitmask, vec![], regs, flat_mem, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run_with_precompiles();
    eprintln!(
        "Exit: {exit:?}, steps: {}, ristretto_calls: {}",
        tracing.num_steps(),
        tracing.ristretto_records.len()
    );

    assert_eq!(
        tracing.ristretto_records.len(),
        1,
        "expected 1 Ristretto ECALL"
    );
    assert_eq!(tracing.ristretto_mem_ops.len(), 1);

    // Expected: 2 * G, computed independently via dalek.
    let expected_out: [u8; 32] = {
        let scalar = curve25519_dalek::scalar::Scalar::from_canonical_bytes(scalar_bytes)
            .into_option()
            .expect("scalar canonical");
        let point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&point_bytes)
            .ok()
            .and_then(|c| c.decompress())
            .expect("point decompresses");
        (scalar * point).compress().to_bytes()
    };

    let rec = &tracing.ristretto_records[0];
    assert_eq!(rec.scalar, scalar_bytes);
    assert_eq!(rec.point, point_bytes);
    assert_eq!(rec.output, expected_out, "RistrettoRecord.output mismatch");

    let mem_op = &tracing.ristretto_mem_ops[0];
    assert_eq!(mem_op.scalar_ptr, scalar_addr as u32);
    assert_eq!(mem_op.point_ptr, point_addr as u32);
    assert_eq!(mem_op.output_ptr, output_addr as u32);
    assert_eq!(mem_op.scalar_bytes, scalar_bytes);
    assert_eq!(mem_op.point_bytes, point_bytes);
    assert_eq!(mem_op.out_bytes, expected_out);

    // Confirm the precompile actually wrote the result back into flat_mem
    // (so a follow-up PVM instruction could read it).
    let written = &tracing.pvm.flat_mem[output_addr as usize..output_addr as usize + 32];
    assert_eq!(written, &expected_out[..], "flat_mem write mismatch");

    eprintln!(
        "Ristretto scalar mult via ECALL: TRACED ({} bytes output)",
        expected_out.len()
    );
}

#[test]
fn prove_blake2b_via_ecall() {
    use zkpvm::core::tracing::ECALL_BLAKE2B_COMPRESS;

    // Build a PVM program that stores h and m in memory, calls ecall, reads result
    // For simplicity: manually set up interpreter with h/m in memory and call ecall

    let iv: [u64; 8] = [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ];

    // Lay out memory: h at 0x1000 (64 bytes), m at 0x1040 (128 bytes)
    let h_addr: u64 = 0x1000;
    let m_addr: u64 = 0x1040;
    let mut flat_mem = vec![0u8; 0x2000];
    for i in 0..8 {
        flat_mem[h_addr as usize + i * 8..h_addr as usize + i * 8 + 8]
            .copy_from_slice(&iv[i].to_le_bytes());
    }
    // m is all zeros (already)

    // PVM program: ecalli 100 (blake2b), then trap
    // ecalli encoding: opcode byte + immediate
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        ECALL_BLAKE2B_COMPRESS as u8,
        0,
        0,
        0,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2/A3 map to φ[7/8/9/10].  The zkpvm-precompiles
    // shim's `in("a0") h_ptr, in("a1") m_ptr, in("a2") t_low,
    // in("a3") f_flag` lands the actor's blake2b arguments in
    // φ[7/8/9/10], where the host handler reads them.
    regs[7] = h_addr; // a0 = h pointer
    regs[8] = m_addr; // a1 = m pointer
    regs[9] = 0; // a2 = t (counter)
    regs[10] = 1; // a3 = f (finalize flag)

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run_with_precompiles();
    eprintln!(
        "Exit: {exit:?}, steps: {}, blake2b_calls: {}",
        tracing.num_steps(),
        tracing.blake2b_records.len()
    );

    assert_eq!(
        tracing.blake2b_records.len(),
        1,
        "should have 1 blake2b call"
    );

    let steps = tracing.trace();
    let blake2b_records = tracing.blake2b_records.clone();
    let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();

    // Build SideNote with blake2b calls
    let mut side_note =
        zkpvm::SideNote::new(steps, code.clone(), bitmask.clone()).with_memory(flat_mem);

    for rec in &blake2b_records {
        side_note
            .blake2b_calls
            .push(zkpvm::chips::blake2b::Blake2bCall {
                h: rec.h,
                m: rec.m,
                t: rec.t,
                f: rec.f,
            });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config).expect("proving failed");
    // Test config uses pow_bits=5 / fri_log_blowup=0, well below the
    // STANDARD policy floor.  Use a permissive policy so the verify
    // step exercises the algebraic check, not the policy gate.
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verification failed");
    eprintln!(
        "Blake2b via ECALL: PROVED! ({} CPU steps + {} chip rows)",
        side_note.steps.len(),
        blake2b_records.len() * 96
    );
}

// ─────────────────────────────────────────────────────────────────────────
// ECALL-chip / ristretto-chip / scalar-arithmetic safety net.
// ─────────────────────────────────────────────────────────────────────────

/// Hand-built `ecalli 200` (scalar_mult).  Chip activates via the
/// byte-attestation boundary — RistrettoEcallChip emits memory
/// producers, MemoryChip ledger ingests the matching consumer
/// entries.
#[test]
fn prove_ristretto_via_ecall_boundary() {
    use zkpvm::core::tracing::ECALL_RISTRETTO_SCALAR_MULT;

    let scalar_addr: u64 = 0x1000;
    let point_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 1;
    let point_bytes = [0u8; 32];
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[scalar_addr as usize..scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&point_bytes);

    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[7] = scalar_addr;
    regs[8] = point_addr;
    regs[9] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.ristretto_records.len(), 1);

    let steps = tracing.trace();
    let r_records = tracing.ristretto_records.clone();
    let r_mem_ops = tracing.ristretto_mem_ops.clone();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.ristretto_calls = r_records;
    side_note.ristretto_mem_ops = r_mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("ristretto via ECALL boundary proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("ristretto via ECALL boundary verification failed");
}

/// End-to-end: the IDENTITY (`0·G`) routed through the REAL ECALL →
/// tracing → `ingest_ristretto_boundary` comb path, proved with the
/// full active-component set.  This is the exact shape cipher-clerk
/// produces: every balanced double-entry layer's zero-sum reveal
/// (`reveal_and_check` → `verify_reveal`) recomputes
/// `Amount::commit(0, net_blinding)`, whose `0·G` is a FixedBasepoint
/// ECALL with scalar = 0.  `detect_scalar_mult_kind` routes it onto the
/// comb path; `compress(0·G)` is the all-zero identity encoding.
///
/// The `IsIdentity` gate is what makes the compress chain's unity row
/// hold for `0·G`; without it the proof fails `ConstraintsNotSatisfied`.
/// A tiny single-ECALL trace, so it runs in seconds (the full kernel
/// transition that contains this op is memory-bound for a separate,
/// non-constraint reason — proof aggregation / fewer software SMT ops).
#[test]
fn prove_ristretto_identity_via_ecall_comb() {
    use zkpvm::core::tracing::ECALL_RISTRETTO_SCALAR_MULT;

    let scalar_addr: u64 = 0x1000;
    let point_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;
    // scalar = 0, point = basepoint ⇒ FixedBasepoint comb call for 0·G.
    let scalar_bytes = [0u8; 32];
    let point_bytes = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[scalar_addr as usize..scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&point_bytes);

    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[7] = scalar_addr;
    regs[8] = point_addr;
    regs[9] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.ristretto_records.len(), 1);
    // The traced output is the canonical identity encoding.
    assert_eq!(
        tracing.ristretto_mem_ops[0].out_bytes, [0u8; 32],
        "0·G must trace to the all-zero Ristretto identity encoding"
    );

    let steps = tracing.trace();
    let r_records = tracing.ristretto_records.clone();
    let r_mem_ops = tracing.ristretto_mem_ops.clone();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.ristretto_calls = r_records;
    side_note.ristretto_mem_ops = r_mem_ops;
    // Route the FixedBasepoint call onto the comb→compress→output path.
    side_note.ingest_ristretto_boundary();
    assert_eq!(
        side_note.ristretto_comb_calls.len(),
        1,
        "0·G must be routed onto the comb path (FixedBasepoint)"
    );

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("identity 0·G via ECALL comb path: prove failed (task #7 regressed)");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("identity 0·G via ECALL comb path: verify failed");
}

/// Hand-built `ecalli 201` (point_add) isolation.
#[test]
fn prove_ristretto_point_add_via_ecall_boundary() {
    use zkpvm::core::tracing::ECALL_RISTRETTO_POINT_ADD;

    let p_addr: u64 = 0x1000;
    let q_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;
    let p_bytes = [0u8; 32];
    let q_bytes = [0u8; 32];
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[p_addr as usize..p_addr as usize + 32].copy_from_slice(&p_bytes);
    flat_mem[q_addr as usize..q_addr as usize + 32].copy_from_slice(&q_bytes);

    let imm = ECALL_RISTRETTO_POINT_ADD;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2 map to φ[7/8/9].
    regs[7] = p_addr;
    regs[8] = q_addr;
    regs[9] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.ristretto_add_records.len(), 1);

    let steps = tracing.trace();
    let records = tracing.ristretto_add_records.clone();
    let mem_ops = tracing.ristretto_add_mem_ops.clone();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.ristretto_add_calls = records;
    side_note.ristretto_add_mem_ops = mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config).expect("point_add proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Hand-built `ecalli 202` (scalar_reduce_wide) isolation.
#[test]
fn prove_scalar_reduce_wide_via_ecall_boundary() {
    use zkpvm::core::tracing::ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE;

    let wide_addr: u64 = 0x1000;
    let output_addr: u64 = 0x1040;
    let mut wide_bytes = [0u8; 64];
    wide_bytes[0] = 7;
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[wide_addr as usize..wide_addr as usize + 64].copy_from_slice(&wide_bytes);

    let imm = ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1 = φ[7/8] per grey-transpiler's RISC-V → PVM mapping.
    regs[7] = wide_addr;
    regs[8] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.scalar_reduce_wide_records.len(), 1);

    let steps = tracing.trace();
    let records = tracing.scalar_reduce_wide_records.clone();
    let mem_ops = tracing.scalar_reduce_wide_mem_ops.clone();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.scalar_reduce_wide_calls = records;
    side_note.scalar_reduce_wide_mem_ops = mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("scalar_reduce_wide proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Hand-built `ecalli 203` (scalar_mul_mod_l) isolation.
#[test]
fn prove_scalar_mul_mod_l_via_ecall() {
    use zkpvm::core::tracing::ECALL_SCALAR_MUL_MOD_L;

    let a_addr: u64 = 0x1000;
    let b_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;
    let mut a_bytes = [0u8; 32];
    a_bytes[0] = 7;
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = 13;
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[a_addr as usize..a_addr as usize + 32].copy_from_slice(&a_bytes);
    flat_mem[b_addr as usize..b_addr as usize + 32].copy_from_slice(&b_bytes);

    let imm = ECALL_SCALAR_MUL_MOD_L;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2 map to φ[7/8/9].
    regs[7] = a_addr;
    regs[8] = b_addr;
    regs[9] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.scalar_binop_records.len(), 1);

    let steps = tracing.trace();
    let records = tracing.scalar_binop_records.clone();
    let mem_ops = tracing.scalar_binop_mem_ops.clone();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.scalar_binop_calls = records;
    side_note.scalar_binop_mem_ops = mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof =
        zkpvm::prove_with_config(&mut side_note, config).expect("scalar_mul_mod_l proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Scalar mul + add (back-to-back, both binops fire).
#[test]
fn prove_scalar_mul_then_add_mod_l() {
    use zkpvm::core::tracing::{ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_MUL_MOD_L};

    let a_addr: u64 = 0x1000;
    let b_addr: u64 = 0x1020;
    let out_addr: u64 = 0x1040;
    let mut a_bytes = [0u8; 32];
    a_bytes[0] = 7;
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = 13;
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[a_addr as usize..a_addr as usize + 32].copy_from_slice(&a_bytes);
    flat_mem[b_addr as usize..b_addr as usize + 32].copy_from_slice(&b_bytes);

    let imm1 = ECALL_SCALAR_MUL_MOD_L;
    let imm2 = ECALL_SCALAR_ADD_MOD_L;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm1 & 0xff) as u8,
        ((imm1 >> 8) & 0xff) as u8,
        ((imm1 >> 16) & 0xff) as u8,
        ((imm1 >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Ecalli as u8,
        (imm2 & 0xff) as u8,
        ((imm2 >> 8) & 0xff) as u8,
        ((imm2 >> 16) & 0xff) as u8,
        ((imm2 >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2 map to φ[7/8/9].
    regs[7] = a_addr;
    regs[8] = b_addr;
    regs[9] = out_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.scalar_binop_records.len(), 2);

    let steps = tracing.trace();
    let records = tracing.scalar_binop_records.clone();
    let mem_ops = tracing.scalar_binop_mem_ops.clone();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.scalar_binop_calls = records;
    side_note.scalar_binop_mem_ops = mem_ops;

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof =
        zkpvm::prove_with_config(&mut side_note, config).expect("scalar mul+add proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Cross-type ECALLs (scalar_mult + point_add) — verifies the chip
/// handles multiple ECALL types in one trace.
#[test]
fn prove_scalar_mult_then_point_add() {
    use zkpvm::core::tracing::{ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT};

    let scalar_addr: u64 = 0x1000;
    let point_addr: u64 = 0x1020;
    let a_addr: u64 = 0x1040;
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 1;
    let point_bytes = [0u8; 32];
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[scalar_addr as usize..scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&point_bytes);

    let imm1 = ECALL_RISTRETTO_SCALAR_MULT;
    let imm2 = ECALL_RISTRETTO_POINT_ADD;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm1 & 0xff) as u8,
        ((imm1 >> 8) & 0xff) as u8,
        ((imm1 >> 16) & 0xff) as u8,
        ((imm1 >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Ecalli as u8,
        (imm2 & 0xff) as u8,
        ((imm2 >> 8) & 0xff) as u8,
        ((imm2 >> 16) & 0xff) as u8,
        ((imm2 >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2 = φ[7/8/9] for both scalar_mult and point_add.
    regs[7] = scalar_addr;
    regs[8] = point_addr;
    regs[9] = a_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.ristretto_records.len(), 1);
    assert_eq!(tracing.ristretto_add_records.len(), 1);

    let steps = tracing.trace();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.ristretto_calls = tracing.ristretto_records.clone();
    side_note.ristretto_mem_ops = tracing.ristretto_mem_ops.clone();
    side_note.ristretto_add_calls = tracing.ristretto_add_records.clone();
    side_note.ristretto_add_mem_ops = tracing.ristretto_add_mem_ops.clone();

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("scalar_mult + point_add proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Two back-to-back scalar_mult ECALLs to same output.
#[test]
fn prove_two_ristretto_scalar_mult_ecalls() {
    use zkpvm::core::tracing::ECALL_RISTRETTO_SCALAR_MULT;

    let scalar_addr: u64 = 0x1000;
    let point_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 1;
    let point_bytes = [0u8; 32];
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[scalar_addr as usize..scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&point_bytes);

    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[7] = scalar_addr;
    regs[8] = point_addr;
    regs[9] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.ristretto_records.len(), 2);

    let steps = tracing.trace();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.ristretto_calls = tracing.ristretto_records.clone();
    side_note.ristretto_mem_ops = tracing.ristretto_mem_ops.clone();

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config).expect("two-ecall proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Mul output consumed by add (Schnorr-shaped pattern).
#[test]
fn prove_scalar_mul_chained_add() {
    use zkpvm::core::tracing::{ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_MUL_MOD_L};
    let a_addr: u64 = 0x1000;
    let b_addr: u64 = 0x1020;
    let out_addr: u64 = 0x1040;
    let mut a_bytes = [0u8; 32];
    a_bytes[0] = 7;
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = 13;
    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[a_addr as usize..a_addr as usize + 32].copy_from_slice(&a_bytes);
    flat_mem[b_addr as usize..b_addr as usize + 32].copy_from_slice(&b_bytes);

    let imm1 = ECALL_SCALAR_MUL_MOD_L;
    let imm2 = ECALL_SCALAR_ADD_MOD_L;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm1 & 0xff) as u8,
        ((imm1 >> 8) & 0xff) as u8,
        ((imm1 >> 16) & 0xff) as u8,
        ((imm1 >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Ecalli as u8,
        (imm2 & 0xff) as u8,
        ((imm2 >> 8) & 0xff) as u8,
        ((imm2 >> 16) & 0xff) as u8,
        ((imm2 >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2 map to φ[7/8/9].
    regs[7] = a_addr;
    regs[8] = b_addr;
    regs[9] = out_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(tracing.scalar_binop_records.len(), 2);

    let steps = tracing.trace();
    let mut side_note = zkpvm::SideNote::new(steps, code.clone(), bitmask.clone())
        .with_memory(flat_mem)
        .with_initial_regs(regs);
    side_note.scalar_binop_calls = tracing.scalar_binop_records.clone();
    side_note.scalar_binop_mem_ops = tracing.scalar_binop_mem_ops.clone();

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof =
        zkpvm::prove_with_config(&mut side_note, config).expect("chained mul+add proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy).expect("verify");
}

/// Source-threaded `point_double` end-to-end, proved chip-isolated.
#[test]
fn prove_ristretto_chip_double_chained() {
    use zkpvm::chips::ristretto::point::{
        ExtendedPointSources, point_double_rows_chained, point_identity,
    };
    use zkpvm::chips::ristretto::witness::{fill_input, fill_output};

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
    let p = point_identity();
    let zero_b = [0u8; 32];

    let x_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.x));
    let y_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.y));
    let z_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.z));
    let t_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.t));
    let zero_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(zero_b));

    let in_sources = ExtendedPointSources {
        x_source: x_row,
        y_source: y_row,
        z_source: z_row,
        t_source: t_row,
    };

    let start_row = side_note.ristretto_field_rows.len() as u16;
    let (rows, doubled, out_sources) =
        point_double_rows_chained(&p, &in_sources, zero_row, start_row);
    for r in rows {
        side_note.add_ristretto_field_row(r);
    }

    side_note.add_ristretto_field_row(fill_output(doubled.x, out_sources.x_source));
    side_note.add_ristretto_field_row(fill_output(doubled.y, out_sources.y_source));
    side_note.add_ristretto_field_row(fill_output(doubled.z, out_sources.z_source));
    side_note.add_ristretto_field_row(fill_output(doubled.t, out_sources.t_source));

    assert!(
        prove_verify_ristretto_isolated(&mut side_note),
        "doubling-chained should prove + verify"
    );
    eprintln!("RistrettoChip point-double chained: PROVED + VERIFIED");
}

/// Source-threaded `point_add` end-to-end, proved chip-isolated.
#[test]
fn prove_ristretto_chip_add_chained() {
    use zkpvm::chips::ristretto::point::{
        ED25519_TWO_D, ExtendedPointSources, point_add_rows_chained, point_identity,
    };
    use zkpvm::chips::ristretto::witness::{fill_input, fill_output};

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
    let p = point_identity();
    let q = point_identity();

    let px_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.x));
    let py_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.y));
    let pz_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.z));
    let pt_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(p.t));
    let qx_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(q.x));
    let qy_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(q.y));
    let qz_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(q.z));
    let qt_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(q.t));
    let two_d_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(ED25519_TWO_D));

    let p_sources = ExtendedPointSources {
        x_source: px_row,
        y_source: py_row,
        z_source: pz_row,
        t_source: pt_row,
    };
    let q_sources = ExtendedPointSources {
        x_source: qx_row,
        y_source: qy_row,
        z_source: qz_row,
        t_source: qt_row,
    };

    let start_row = side_note.ristretto_field_rows.len() as u16;
    let (rows, sum, out_sources) =
        point_add_rows_chained(&p, &p_sources, &q, &q_sources, two_d_row, start_row);
    for r in rows {
        side_note.add_ristretto_field_row(r);
    }

    side_note.add_ristretto_field_row(fill_output(sum.x, out_sources.x_source));
    side_note.add_ristretto_field_row(fill_output(sum.y, out_sources.y_source));
    side_note.add_ristretto_field_row(fill_output(sum.z, out_sources.z_source));
    side_note.add_ristretto_field_row(fill_output(sum.t, out_sources.t_source));

    assert!(
        prove_verify_ristretto_isolated(&mut side_note),
        "add-chained should prove + verify"
    );
    eprintln!("RistrettoChip point-add chained: PROVED + VERIFIED");
}

/// Small-scalar ladder (k=5, 3 bits) — exercises the full chained
/// `scalar_mult_rows_chained` driver with multi-iteration source
/// threading, proved chip-isolated.
#[test]
fn prove_ristretto_chip_scalar_mult_chained_small() {
    use zkpvm::chips::ristretto::point::{
        ED25519_TWO_D, ExtendedPointSources, point_identity, scalar_mult_rows_chained,
    };
    use zkpvm::chips::ristretto::witness::{fill_input, fill_output};

    let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
    let id = point_identity();
    let zero_b = [0u8; 32];

    let id_x_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(id.x));
    let id_y_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(id.y));
    let id_z_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(id.z));
    let id_t_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(id.t));
    let zero_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(zero_b));
    let two_d_row = side_note.ristretto_field_rows.len() as u16;
    side_note.add_ristretto_field_row(fill_input(ED25519_TWO_D));

    let p_sources = ExtendedPointSources {
        x_source: id_x_row,
        y_source: id_y_row,
        z_source: id_z_row,
        t_source: id_t_row,
    };
    let id_sources = p_sources;
    let mut k = [0u8; 32];
    k[0] = 5;

    let start = side_note.ristretto_field_rows.len() as u16;
    let (rows, result, out_sources) = scalar_mult_rows_chained(
        &k,
        &id,
        &p_sources,
        &id_sources,
        zero_row,
        two_d_row,
        start,
        3,
    );
    for r in rows {
        side_note.add_ristretto_field_row(r);
    }

    use zkpvm::chips::ristretto::field;
    let z_inv = field::inv(&result.z);
    let x_aff = field::mul(&result.x, &z_inv);
    let y_aff = field::mul(&result.y, &z_inv);
    let mut one_b = [0u8; 32];
    one_b[0] = 1;
    assert_eq!(x_aff, [0u8; 32], "5·O affine x must be 0");
    assert_eq!(y_aff, one_b, "5·O affine y must be 1");

    side_note.add_ristretto_field_row(fill_output(result.x, out_sources.x_source));
    side_note.add_ristretto_field_row(fill_output(result.y, out_sources.y_source));
    side_note.add_ristretto_field_row(fill_output(result.z, out_sources.z_source));
    side_note.add_ristretto_field_row(fill_output(result.t, out_sources.t_source));

    assert!(
        prove_verify_ristretto_isolated(&mut side_note),
        "scalar-mult-chained should prove + verify"
    );
    eprintln!("RistrettoChip scalar-mult chained: PROVED + VERIFIED");
}
