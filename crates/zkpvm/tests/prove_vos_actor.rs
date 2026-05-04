//! End-to-end test: trace a real VOS actor compiled from Rust.

use javm::interpreter::Interpreter;
use javm::program::{self, CapEntryType};
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, prove_profiled, verify};

/// Load fibonacci PVM blob (transpiled from ELF).
fn load_fibonacci_blob() -> Vec<u8> {
    let blob_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/actors/fibonacci/target/riscv64em-javm/release/fibonacci.pvm"
    );
    if let Ok(data) = std::fs::read(blob_path) {
        return data;
    }
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/actors/fibonacci/target/riscv64em-javm/release/fibonacci.elf"
    );
    let elf_data = std::fs::read(elf_path)
        .expect("fibonacci ELF not found — build with: cd examples/actors/fibonacci && cargo build --release");
    grey_transpiler::link_elf(&elf_data).expect("failed to transpile fibonacci ELF")
}

/// Set up an Interpreter from a JAR blob's CODE + DATA capabilities.
/// Returns (interpreter, flat_mem) so flat_mem can be passed to SideNote.
fn interpreter_from_blob(blob: &[u8], gas: u64) -> (Interpreter, Vec<u8>) {
    let parsed = program::parse_blob(blob).expect("failed to parse JAR blob");

    // Find CODE cap and extract code/bitmask/jump_table
    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_data = code_data.expect("no CODE capability in blob");
    let code_blob = program::parse_code_blob(&code_data).expect("failed to parse code blob");

    // Build flat memory from DATA capabilities
    let mut flat_mem_size: usize = 0;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let end = (entry.base_page as usize + entry.page_count as usize)
                * javm::PVM_PAGE_SIZE as usize;
            flat_mem_size = flat_mem_size.max(end);
        }
    }
    let mut flat_mem = vec![0u8; flat_mem_size];

    // Copy DATA cap contents into flat memory
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let addr = entry.base_page as usize * javm::PVM_PAGE_SIZE as usize;
            let data = program::cap_data(entry, parsed.data_section);
            let len = data.len().min(flat_mem.len().saturating_sub(addr));
            if len > 0 {
                flat_mem[addr..addr + len].copy_from_slice(&data[..len]);
            }
        }
    }

    // Set SP to the top of the largest DATA cap (stack)
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let top = (entry.base_page as u64 + entry.page_count as u64)
                * javm::PVM_PAGE_SIZE as u64;
            if top > registers[1] {
                registers[1] = top;
            }
        }
    }

    let mem_cycles = javm::compute_mem_cycles(parsed.header.memory_pages);

    let flat_mem_copy = flat_mem.clone();
    let interp = Interpreter::new(
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
        code_blob.jump_table.to_vec(),
        registers,
        flat_mem,
        gas,
        mem_cycles,
    );
    (interp, flat_mem_copy)
}

#[test]
fn trace_fibonacci_actor() {
    let blob = load_fibonacci_blob();
    eprintln!("PVM blob: {} bytes", blob.len());

    let (interp, _flat_mem) = interpreter_from_blob(&blob, 10_000_000);
    eprintln!("Interpreter: code={} bytes, flat_mem={} bytes",
        interp.code.len(), interp.flat_mem.len());

    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Execution: {} steps, exit={exit:?}", steps.len());

    assert!(!steps.is_empty(), "should have executed some steps");
    eprintln!("First: pc={} {:?}", steps[0].pc, steps[0].opcode);
    eprintln!("Last:  pc={} {:?}", steps.last().unwrap().pc, steps.last().unwrap().opcode);

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

#[test]
fn prove_fibonacci_actor() {
    let blob = load_fibonacci_blob();
    let parsed = program::parse_blob(&blob).expect("failed to parse JAR blob");

    // Extract code and bitmask
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
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Traced {} steps, exit={exit:?}", steps.len());

    let mut side_note = zkpvm::SideNote::new(
        steps,
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
    ).with_jump_table(code_blob.jump_table.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    eprintln!("Proof generated: {} claimed sums", proof.claimed_sums.len());

    verify(proof, &side_note).expect("verification failed");
    eprintln!("Verification passed!");
}

#[test]
fn profile_fibonacci_actor() {
    let blob = load_fibonacci_blob();
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
    eprintln!("PVM execution: {} steps in {trace_time:?}, exit={exit:?}", steps.len());

    // Opcode distribution
    let mut counts = std::collections::HashMap::new();
    let mut mem_ops = 0u32;
    let mut branches = 0u32;
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
        if s.mem_read.is_some() || s.mem_write.is_some() { mem_ops += 1; }
        if s.branch_taken { branches += 1; }
    }
    eprintln!("Memory ops: {mem_ops}, Branches taken: {branches}");
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, count) in sorted.iter().take(10) {
        eprintln!("  {op}: {count}");
    }

    let mut side_note = zkpvm::SideNote::new(
        steps,
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
    ).with_jump_table(code_blob.jump_table.to_vec());

    eprintln!("\n=== Prove Pipeline Profile ===");
    let (proof, _profile) = prove_profiled(&mut side_note).expect("proving failed");

    // Proof size
    let proof_bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!("Proof size: {} bytes ({:.1} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);

    let t = std::time::Instant::now();
    verify(proof, &side_note).expect("verification failed");
    eprintln!("Verify: {:?}", t.elapsed());
}

// ── Generic actor profile helper ──

fn load_actor_blob(name: &str) -> Vec<u8> {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/actors/");
    let pvm_path = format!("{base}{name}/target/riscv64em-javm/release/{name}.pvm");
    if let Ok(data) = std::fs::read(&pvm_path) {
        return data;
    }
    let elf_path = format!("{base}{name}/target/riscv64em-javm/release/{name}.elf");
    let elf_data = std::fs::read(&elf_path)
        .unwrap_or_else(|_| panic!("{name} ELF not found — build first"));
    grey_transpiler::link_elf(&elf_data).expect("failed to transpile ELF")
}

fn profile_actor(name: &str, gas: u64) {
    let blob = load_actor_blob(name);
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

    let t0 = std::time::Instant::now();
    let mut tracing = TracingPvm::new(interp);
    // run_with_vos_stubs gracefully drives lifecycle hostcalls
    // (INFO/STORAGE_R/FETCH/OUTPUT/...) so vos-style actors complete
    // their on_start handler under the bare interpreter.  Pure-compute
    // actors with no hostcalls behave the same as `run()`.
    let exit = tracing.run_with_vos_stubs();
    let steps = tracing.into_trace();
    let trace_time = t0.elapsed();

    eprintln!("=== {name} actor ===");
    eprintln!("PVM: {} steps in {trace_time:?}, exit={exit:?}", steps.len());

    // Opcode stats
    let mut mem_ops = 0u32;
    let mut branches = 0u32;
    let mut counts = std::collections::HashMap::new();
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
        if s.mem_read.is_some() || s.mem_write.is_some() { mem_ops += 1; }
        if s.branch_taken { branches += 1; }
    }
    eprintln!("Memory ops: {mem_ops}, Branches taken: {branches}");
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, count) in sorted.iter().take(8) {
        eprintln!("  {op}: {count}");
    }

    let mut side_note = zkpvm::SideNote::new(
        steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec(),
    )
    .with_memory(flat_mem)
    .with_jump_table(code_blob.jump_table.to_vec());

    eprintln!("\nProve (96-bit security):");
    let (proof, _) = prove_profiled(&mut side_note).expect("proving failed");

    let proof_bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!("Proof: {:.1} KB", proof_bytes.len() as f64 / 1024.0);

    let t = std::time::Instant::now();
    verify(proof, &side_note).expect("verification failed");
    eprintln!("Verify: {:?}\n", t.elapsed());
}

#[test]
fn profile_hasher_actor() {
    profile_actor("hasher", 10_000_000);
}

/// Real-workload prove: clerk-refine-bench (vos macro style, see
/// examples/actors/clerk-refine-bench).  vos-macros special-case a
/// method named `start` as the on_start lifecycle hook, so the
/// bare interpreter_from_blob path drives the workload via cold
/// start without needing a FETCH-delivered invocation.
#[test]
fn profile_clerk_refine_bench() {
    profile_actor("clerk-refine-bench", 100_000_000);
}

/// Trace-only variant of clerk-refine-bench: validates the actor
/// builds + runs.  Trace-only because profile_clerk_refine_bench
/// also runs the full prove path.
#[test]
fn trace_clerk_refine_bench() {
    let blob = load_actor_blob("clerk-refine-bench");
    let (interp, _flat_mem) = interpreter_from_blob(&blob, 100_000_000);
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run_with_vos_stubs();
    let steps = tracing.into_trace();
    eprintln!("clerk-refine-bench: {} PVM steps, exit={exit:?}", steps.len());
}

/// Real-workload prove: clerk-private-pay-bench — the on-device
/// computation a user runs for one tap-and-pay (L2 graph privacy).
/// Pedersen amount commit + Schnorr-on-Ristretto sign + note
/// commitment + rkyv signing payload, no host-side oracle/ledger.
#[test]
fn profile_clerk_private_pay_bench() {
    profile_actor("clerk-private-pay-bench", 100_000_000);
}

#[test]
fn trace_clerk_private_pay_bench() {
    let blob = load_actor_blob("clerk-private-pay-bench");
    let (interp, _flat_mem) = interpreter_from_blob(&blob, 500_000_000);
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run_with_vos_stubs();
    let steps = tracing.into_trace();
    eprintln!("clerk-private-pay-bench: {} PVM steps, exit={exit:?}", steps.len());
}

#[test]
fn profile_hash_bench() {
    let blob = load_actor_blob("hash-bench");
    let parsed = program::parse_blob(&blob).expect("parse blob");
    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_blob = program::parse_code_blob(&code_data.expect("no CODE cap")).expect("parse code");
    let (interp, flat_mem) = interpreter_from_blob(&blob, 100_000_000);

    let t0 = std::time::Instant::now();
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run();
    let steps = tracing.into_trace();
    let trace_time = t0.elapsed();

    eprintln!("=== hash-bench (bare metal) ===");
    eprintln!("PVM: {} steps in {trace_time:?}, exit={exit:?}", steps.len());

    let mut mem_ops = 0u32;
    let mut branches = 0u32;
    let mut counts = std::collections::HashMap::new();
    for s in &steps {
        *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1;
        if s.mem_read.is_some() || s.mem_write.is_some() { mem_ops += 1; }
        if s.branch_taken { branches += 1; }
    }
    eprintln!("Memory ops: {mem_ops}, Branches: {branches}");
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, count) in sorted.iter().take(10) {
        eprintln!("  {op}: {count}");
    }

    let mut side_note = zkpvm::SideNote::new(
        steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec(),
    ).with_memory(flat_mem).with_jump_table(code_blob.jump_table.to_vec());

    let t = std::time::Instant::now();
    let proof = prove(&mut side_note).expect("proving failed");
    let prove_time = t.elapsed();
    let proof_bytes = bincode::serialize(&proof).expect("serialize");

    let t = std::time::Instant::now();
    verify(proof, &side_note).expect("verification failed");
    let verify_time = t.elapsed();
    eprintln!("Prove: {prove_time:.2?}, Proof: {:.1} KB, Verify: {verify_time:.2?}", proof_bytes.len() as f64 / 1024.0);
}

/// Profile a specific hash variant by PVM blob name
fn profile_hash_variant(name: &str) {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/actors/hash-bench/");
    let pvm_path = format!("{base}hash-{name}.pvm");
    let elf_path = format!("{base}hash-{name}.elf");
    let blob = std::fs::read(&pvm_path)
        .or_else(|_| {
            let elf = std::fs::read(&elf_path).unwrap_or_else(|_| panic!("hash-{name} ELF not found"));
            Ok::<_, std::io::Error>(grey_transpiler::link_elf(&elf).expect("transpile"))
        })
        .unwrap();

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
        steps.clone(), code_blob.code.to_vec(), code_blob.bitmask.to_vec(),
    ).with_memory(flat_mem).with_jump_table(code_blob.jump_table.to_vec());

    let mut counts = std::collections::HashMap::new();
    for s in &steps { *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1; }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    let top_ops: String = sorted.iter().take(5).map(|(op, c)| format!("{op}:{c}")).collect::<Vec<_>>().join(" ");

    let t = std::time::Instant::now();
    match prove(&mut side_note) {
        Ok(proof) => {
            let prove_time = t.elapsed();
            let kb = bincode::serialize(&proof).unwrap().len() as f64 / 1024.0;
            verify(proof, &side_note).expect("verify");
            eprintln!("  {name:>10}: {n:>5} steps | prove={prove_time:>8.2?} | proof={kb:>5.1} KB | {top_ops}");
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
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/actors/hash-bench/");
    let blob = std::fs::read(format!("{base}hash-blake2s.pvm")).expect("blake2s PVM");
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

    let config = zkpvm::PcsConfig { pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3) };
    // Scan for first failing prefix (fresh side_note each time)
    let test_sizes = [steps.len()];
    for &n in &test_sizes {
        let n = n.min(steps.len());
        let trunc: Vec<_> = steps.iter().take(n).cloned().collect();
        let mut sn = zkpvm::SideNote::new(trunc, code_blob.code.to_vec(), code_blob.bitmask.to_vec()).with_memory(flat_mem.clone()).with_jump_table(code_blob.jump_table.to_vec());
        let ok = zkpvm::prove_with_config(&mut sn, config).is_ok();
        eprintln!("  {n:>5} steps: {}", if ok {"OK"} else {"FAIL"});
        if !ok { break; }
    }
    // Try the full trace
    eprintln!("Trying full trace ({} steps):", steps.len());
    let mut sn = zkpvm::SideNote::new(
        steps.clone(), code_blob.code.to_vec(), code_blob.bitmask.to_vec()
    ).with_memory(flat_mem).with_jump_table(code_blob.jump_table.to_vec());
    match zkpvm::prove_with_config(&mut sn, config) {
        Ok(proof) => {
            verify(proof, &sn).expect("verify");
            eprintln!("  PASS!");
        }
        Err(e) => { eprintln!("  FAIL: {e}"); }
    }
}

#[test]
fn prove_diverse() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/actors/hash-bench/");
    let blob = std::fs::read(format!("{base}hash-diverse.pvm")).expect("diverse PVM");
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
    let mut side_note = zkpvm::SideNote::new(
        steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec()
    ).with_memory(flat_mem).with_jump_table(code_blob.jump_table.to_vec());
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
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/actors/hash-bench/");
    let blob = std::fs::read(format!("{base}hash-diverse.pvm")).expect("diverse PVM");
    let (interp, _) = interpreter_from_blob(&blob, 100_000_000);
    let mut tracing = TracingPvm::new(interp);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Diverse: {} steps", steps.len());
    let mut counts = std::collections::HashMap::new();
    for s in &steps { *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1; }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, c) in sorted.iter() { eprintln!("  {op}: {c}"); }
}

#[test]
fn trace_keccak_steps() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/actors/hash-bench/");
    let blob = std::fs::read(format!("{base}hash-keccak.pvm")).expect("keccak PVM");
    let (interp, _) = interpreter_from_blob(&blob, 100_000_000);
    let mut tracing = TracingPvm::new(interp);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Keccak: {} steps", steps.len());
    let mut counts = std::collections::HashMap::new();
    for s in &steps { *counts.entry(format!("{:?}", s.opcode)).or_insert(0u32) += 1; }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, c) in sorted.iter().take(10) { eprintln!("  {op}: {c}"); }
}

#[test]
fn prove_segmented_hash_bench() {
    // Split hash-bench (635 steps) into 2 segments and verify the chain
    let blob = load_actor_blob("hash-bench");
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
    eprintln!("=== Segmented proving: {} steps split at {} ===", all_steps.len(), split);

    let code = code_blob.code.to_vec();
    let bitmask = code_blob.bitmask.to_vec();

    // Segment 1: steps 0..split
    let seg1_steps: Vec<_> = all_steps[..split].to_vec();
    let mut seg1_sn = zkpvm::SideNote::new(
        seg1_steps, code.clone(), bitmask.clone()
    ).with_memory(flat_mem.clone()).with_jump_table(code_blob.jump_table.to_vec());

    let t = std::time::Instant::now();
    let proof1 = prove(&mut seg1_sn).expect("segment 1 proving failed");
    eprintln!("Segment 1: {} steps, proved in {:?}", split, t.elapsed());
    eprintln!("  initial: pc={} ts={}", proof1.initial_state.pc, proof1.initial_state.timestamp);
    eprintln!("  final:   pc={} ts={}", proof1.final_state.pc, proof1.final_state.timestamp);

    // Compute final memory of segment 1 for segment 2's initial memory
    let mut seg2_mem = flat_mem.clone();
    for step in &all_steps[..split] {
        if let Some(ref w) = step.mem_write {
            let addr = w.address as usize;
            let bytes = w.value.to_le_bytes();
            let sz = w.size as usize;
            if addr + sz > seg2_mem.len() { seg2_mem.resize(addr + sz, 0); }
            seg2_mem[addr..addr + sz].copy_from_slice(&bytes[..sz]);
        }
    }

    // Segment 2: steps split..end
    let seg2_steps: Vec<_> = all_steps[split..].to_vec();
    let mut seg2_sn = zkpvm::SideNote::new(
        seg2_steps, code.clone(), bitmask.clone()
    ).with_memory(seg2_mem).with_jump_table(code_blob.jump_table.to_vec());

    let t = std::time::Instant::now();
    let proof2 = prove(&mut seg2_sn).expect("segment 2 proving failed");
    eprintln!("Segment 2: {} steps, proved in {:?}", all_steps.len() - split, t.elapsed());
    eprintln!("  initial: pc={} ts={}", proof2.initial_state.pc, proof2.initial_state.timestamp);
    eprintln!("  final:   pc={} ts={}", proof2.final_state.pc, proof2.final_state.timestamp);

    // Verify chain
    eprintln!("\nChain verification:");
    eprintln!("  seg1.final  == seg2.initial ? {}", proof1.final_state == proof2.initial_state);

    zkpvm::verify_chain(
        &[proof1, proof2],
        &[&seg1_sn, &seg2_sn],
    ).expect("chain verification failed");
    eprintln!("  CHAIN VERIFIED!");
}

#[test]
fn prove_blake2b_precompile() {
    use zkpvm::chips::blake2b::blake2b_compress;
    use zkpvm::core::tracing::ECALL_BLAKE2B_COMPRESS;

    // Runs a minimal PVM program that just ECALLs blake2b.  Needs to go
    // through TracingPvm.run_with_precompiles so the CpuChip gets an ECALL
    // step (Phase 8c producer) and the tracer captures the matching
    // blake2b_mem_op (Phase 8a/8b consumer pre-image).
    let h = [
        0x6A09E667F3BCC908u64, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ];
    let m = [0u64; 16];
    let expected = blake2b_compress(&h, &m, 0, true);
    eprintln!("blake2b(empty) first word: {:#x}", expected[0]);

    let h_addr: u64 = 0x1000;
    let m_addr: u64 = 0x1040;
    let mut flat_mem = vec![0u8; 0x2000];
    for i in 0..8 {
        flat_mem[h_addr as usize + i*8 .. h_addr as usize + i*8+8]
            .copy_from_slice(&h[i].to_le_bytes());
    }
    // m left all zero.

    let code = vec![
        javm::instruction::Opcode::Ecalli as u8, ECALL_BLAKE2B_COMPRESS as u8, 0, 0, 0,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[10] = h_addr;
    regs[11] = m_addr;
    regs[12] = 0;
    regs[7] = 1;

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs, flat_mem.clone(), 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run_with_precompiles();
    let steps = tracing.steps.clone();
    let blake2b_records = tracing.blake2b_records.clone();
    let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();

    let mut side_note = zkpvm::SideNote::new(
        steps, code, bitmask,
    ).with_memory(flat_mem);
    for rec in &blake2b_records {
        side_note.blake2b_calls.push(zkpvm::chips::blake2b::Blake2bCall {
            h: rec.h, m: rec.m, t: rec.t, f: rec.f,
        });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;

    let config = zkpvm::PcsConfig { pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3) };
    let proof = zkpvm::prove_with_config(&mut side_note, config).expect("blake2b proving failed");
    verify(proof, &side_note).expect("blake2b verification failed");
    eprintln!("Blake2b precompile: PROVED!");
}

/// R1e-quat: end-to-end chip-on test.  Pre-populates
/// `side_note.ristretto_field_rows` with a single field-add row
/// (1 + 2 = 3 mod p), turns the chip on via the
/// `ristretto_field_rows.is_empty()` activity hook, and proves +
/// verifies.  Validates that the AIR's per-row constraints
/// (R1c-3..R1c-5-b) hold against real witness data — separate from
/// the ECALL boundary path (R1f).
#[test]
fn prove_ristretto_chip_field_add() {
    use zkpvm::chips::ristretto::witness::fill_add;

    // Empty PVM trace — the chip-on test exercises only RistrettoChip
    // rows, not any CPU steps.
    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );

    // Single field-add row: 1 + 2 = 3 mod p.
    let mut a = [0u8; 32]; a[0] = 1;
    let mut b = [0u8; 32]; b[0] = 2;
    let row = fill_add(a, b);
    assert_eq!(row.out[0], 3);
    side_note.add_ristretto_field_row(row);

    // Chip needs to flip on via activity_from_steps' new check on
    // ristretto_field_rows.is_empty().
    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("RistrettoChip field-add proving failed");
    // Permissive policy for the chip-level smoke test (matches the
    // pow_bits/queries/blowup of the test config above).
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("RistrettoChip field-add verification failed");
    eprintln!("RistrettoChip field-add: PROVED + VERIFIED");
}

/// R1e-quat: chip-on test for field-mul.  Exercises the full
/// is_mul row constraint chain (schoolbook R1c-4-b → 2-pass
/// reduction R1c-5-b → final < p check R1c-3-bis).
#[test]
fn prove_ristretto_chip_field_mul() {
    use zkpvm::chips::ristretto::witness::fill_mul;

    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );

    // Smallest non-zero case: 1 · 1 = 1.  Currently fails (see
    // doc above); the all-zero case 0·0=0 passes via
    // prove_ristretto_chip_field_mul_zero below.
    let mut a = [0u8; 32]; a[0] = 1;
    let mut b = [0u8; 32]; b[0] = 1;
    let row = fill_mul(a, b);
    assert_eq!(row.out[0], 1);
    side_note.add_ristretto_field_row(row);

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("RistrettoChip field-mul proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("RistrettoChip field-mul verification failed");
    eprintln!("RistrettoChip field-mul: PROVED + VERIFIED");
}

#[test]
#[ignore]
fn debug_fill_mul_one_times_one() {
    use zkpvm::chips::ristretto::witness::fill_mul;
    let mut a = [0u8; 32]; a[0] = 1;
    let mut b = [0u8; 32]; b[0] = 1;
    let r = fill_mul(a, b);
    eprintln!("a[0]={}, b[0]={}, out[0]={}", r.a[0], r.b[0], r.out[0]);
    eprintln!("mul_product[0..4]={:?}", &r.mul_product[..4]);
    eprintln!("mul_carry[0..4]={:?}", &r.mul_carry[..4]);
    eprintln!("mul_carry_mid[0..4]={:?}", &r.mul_carry_mid[..4]);
    eprintln!("mul_carry_hi[0..4]={:?}", &r.mul_carry_hi[..4]);
    eprintln!("pass1_lo[0..4]={:?}", &r.pass1_lo[..4]);
    eprintln!("pass1_hi={:?}", r.pass1_hi);
    eprintln!("pass2_lo[0..4]={:?}", &r.pass2_lo[..4]);
    eprintln!("pass2_carry_out={}, pass2_top_bit={}", r.pass2_carry_out, r.pass2_top_bit);
    eprintln!("after_top_bit[0..4]={:?}", &r.after_top_bit[..4]);
    eprintln!("is_overflow={}, sub_borrow[0]={}", r.is_overflow, r.sub_borrow[0]);
    eprintln!("ff_borrow[31]={}", r.final_form_borrow[31]);
    eprintln!("flags: is_add={}, is_sub={}, is_mul={}, is_real={}",
        r.is_add, r.is_sub, r.is_mul, r.is_real);
}

/// R1e-pent diagnostic: confirm the inter-row binding soundness gap.
/// Push 100 unrelated is_add rows (each computing a different
/// `1 + N = 1+N`).  Each row is internally correct; the chip
/// currently has no constraint linking row N's input to row M's
/// output, so this should prove fine — confirming we need R1e-pent
/// before turning the chip on for actor traces (where a prover
/// could otherwise stitch together arbitrary "valid" rows that
/// don't actually compose into a scalar mult).
#[test]
fn ristretto_chip_unrelated_rows_prove_attestation() {
    use zkpvm::chips::ristretto::witness::fill_add;

    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );
    for n in 0..100u8 {
        let mut a = [0u8; 32]; a[0] = 1;
        let mut b = [0u8; 32]; b[0] = n;
        side_note.add_ristretto_field_row(fill_add(a, b));
    }
    let config = zkpvm::PcsConfig {
        pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("100 unrelated rows should prove (each individually valid)");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5, min_fri_queries: 3, min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("verify failed");
    eprintln!("100 unrelated rows: PROVED + VERIFIED (confirming");
    eprintln!("inter-row binding soundness gap — R1e-pent TODO).");
}

/// R1f-bug-bisect: scalar_mult_rows([N, 0, ...], id) bug — bisect by
/// the position of the first set bit (MSB-first iteration) where
/// the add fires.
#[test]
#[ignore]
fn debug_scalar_mult_bisect_first_set_bit_position() {
    use zkpvm::chips::ristretto::point::{scalar_mult_rows, point_identity};

    // Test scalars: each has a single set bit at varying positions.
    for scalar_val in [1u8, 2, 4, 8, 16, 32, 64, 128] {
        let mut scalar = [0u8; 32]; scalar[0] = scalar_val;
        let id = point_identity();

        let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
        let (rows, _) = scalar_mult_rows(&scalar, &id);
        for r in rows { side_note.add_ristretto_field_row(r); }

        let config = zkpvm::PcsConfig {
            pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
        };
        let result = zkpvm::prove_with_config(&mut side_note, config);
        eprintln!("scalar={:>3}: {}", scalar_val,
            if result.is_ok() { "PASS" } else { "FAIL" });
    }
}

/// R1f-bug-bisect: identify which specific row in the
/// scalar_mult_rows([32], id) sequence fails by truncating the
/// row sequence and seeing where it starts to fail.
#[test]
#[ignore]
fn debug_scalar_mult_truncate_to_find_failing_row() {
    use zkpvm::chips::ristretto::point::{scalar_mult_rows, point_identity};

    let mut scalar = [0u8; 32]; scalar[0] = 32;
    let id = point_identity();
    let (full_rows, _) = scalar_mult_rows(&scalar, &id);
    let total = full_rows.len();
    eprintln!("Total rows: {total}");

    // Truncate to N rows and see when failure starts.
    // Binary search: split between [0, total) for the smallest N that
    // includes the failing row.
    let mut lo = 1usize;
    let mut hi = total;
    while lo < hi {
        let mid = (lo + hi) / 2;
        let mut side_note = zkpvm::SideNote::new(Vec::new(), Vec::new(), Vec::new());
        for r in &full_rows[..mid] {
            side_note.add_ristretto_field_row(r.clone());
        }
        let config = zkpvm::PcsConfig {
            pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
        };
        let result = zkpvm::prove_with_config(&mut side_note, config);
        if result.is_ok() { lo = mid + 1; }
        else { hi = mid; }
    }
    eprintln!("First failing prefix length: {} (out of {})", lo, total);
    if lo > 0 && lo <= total {
        let r = &full_rows[lo - 1];
        eprintln!("Failing row: is_add={} is_sub={} is_mul={}",
            r.is_add, r.is_sub, r.is_mul);
        eprintln!("  a[0..4]={:?}, b[0..4]={:?}, out[0..4]={:?}",
            &r.a[..4], &r.b[..4], &r.out[..4]);
        eprintln!("  is_overflow={}, mul_product[0..4]={:?}",
            r.is_overflow, &r.mul_product[..4]);
    }
}

/// R1f: actual end-to-end prove-time measurement for one private
/// payment's crypto core (1 Pedersen v·G + b·H + add, 1 Schnorr
/// k·G + sk·G).  Pushes the full ~21K-row sequence through the
/// (now-working) RistrettoChip and reports prove + verify time.
///
/// **Caveat:** R1e-pent inter-row binding isn't done yet — each
/// emitted row is proven correct in isolation but the chip doesn't
/// enforce that row N's inputs equal row (N−1)'s outputs.  For
/// prove-time benchmarking this is fine (the cell count is what
/// determines cost), but for soundness the binding step is
/// required before turning on for actor traces.
#[test]
fn bench_ristretto_chip_one_private_payment() {
    use zkpvm::chips::ristretto::point::{
        scalar_mult_rows, point_add_rows, point_identity,
    };
    use std::time::Instant;

    let scalar_v: [u8; 32] = {
        let mut s = [0u8; 32]; s[0] = 50; s
    };
    let scalar_b: [u8; 32] = {
        let mut s = [0u8; 32];
        for i in 0..32 { s[i] = 0xa5u8.wrapping_mul((i + 1) as u8); }
        s[31] &= 0x7f; s
    };
    let id = point_identity();

    eprintln!("Composing one-payment row sequence...");
    let t0 = Instant::now();
    let mut rows = Vec::new();
    // Full per-payment crypto core: 1 Pedersen v·G + b·H + add,
    // 1 Schnorr k·G + sk·G.  After the R1f sub-chain fix, all
    // scalars work; this exercises the full ~21K-row sequence.
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
    eprintln!("Composed {} field-op rows in {:?}", rows.len(), t0.elapsed());

    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );
    let t1 = Instant::now();
    for row in rows {
        side_note.add_ristretto_field_row(row);
    }
    eprintln!("Pushed rows + bumped Range256 counts in {:?}", t1.elapsed());

    let config = zkpvm::PcsConfig {
        pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let t2 = Instant::now();
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("proving failed");
    let prove_time = t2.elapsed();
    eprintln!("Prove time: {:?}", prove_time);

    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5, min_fri_queries: 3, min_fri_log_blowup: 0,
    };
    let t3 = Instant::now();
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("verify failed");
    eprintln!("Verify time: {:?}", t3.elapsed());

    eprintln!();
    eprintln!("=== ACTUAL chip prove time, one full private payment ===");
    eprintln!("Prove:  {:>8.2} s", prove_time.as_secs_f64());
}

/// R1e projection: count the host-side row sequence for one full
/// cipher-clerk "tap-and-pay" cryptographic core (one Pedersen
/// amount commit + one Schnorr-on-Ristretto sign), and report the
/// expected RistrettoChip log_size.  This estimates the chip's
/// prove-time cost IF the constraint-debug bug were resolved.
#[test]
fn project_ristretto_chip_size_for_one_payment() {
    use zkpvm::chips::ristretto::point::{
        scalar_mult_rows, point_add_rows, point_identity, ED25519_TWO_D,
    };

    // One Pedersen amount commit needs 2 scalar mults + 1 point add:
    //   v · G + b · H  (where v is the value, b the blinding)
    let scalar_v: [u8; 32] = {
        let mut s = [0u8; 32]; s[0] = 50; s
    };
    let scalar_b: [u8; 32] = {
        let mut s = [0u8; 32];
        for i in 0..32 { s[i] = 0xa5u8.wrapping_mul((i + 1) as u8); }
        s[31] &= 0x7f; s
    };
    let id = point_identity();
    let (rows_vg, _vg_pt) = scalar_mult_rows(&scalar_v, &id);
    let (rows_bh, _bh_pt) = scalar_mult_rows(&scalar_b, &id);
    let (rows_add, _) = point_add_rows(&_vg_pt, &_bh_pt);

    // One Schnorr sign needs 2 scalar mults (k·G nonce, sk·G pubkey)
    // — same shape as Pedersen.
    let (rows_kg, _) = scalar_mult_rows(&scalar_v, &id);
    let (rows_skg, _) = scalar_mult_rows(&scalar_b, &id);

    let total_rows = rows_vg.len() + rows_bh.len() + rows_add.len()
                   + rows_kg.len() + rows_skg.len();
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
    eprintln!("Cells:  baseline {} M + chip {} M = total {} M",
        baseline_cells / 1_000_000, chip_cells / 1_000_000, total_cells / 1_000_000);
    eprintln!("Throughput: {:.1} M cells/s", throughput / 1e6);
    eprintln!("Projected total prove: ~{:.1}s on CPU", projected_secs);
    eprintln!("With GPU (3×):  ~{:.1}s", projected_secs / 3.0);
    eprintln!("With NAF-w4 (-30% rows) + GPU: ~{:.1}s", projected_secs * 0.7 / 3.0);
}

/// R1e-quat diagnostic: bisect over the COLUMN that triggers the
/// fail.  Each scenario hand-builds a row with all-zero witness
/// EXCEPT one specific column has its index-0 cell = 1.  Reports
/// which columns are "tainted" by a non-zero cell.
#[test]
#[ignore]
fn debug_mul_column_bisect() {
    use zkpvm::chips::ristretto::witness::FieldOpRow;

    let cases: Vec<(&str, Box<dyn Fn(&mut FieldOpRow)>)> = vec![
        ("a[0]",                Box::new(|r| { r.a[0] = 1; })),
        ("b[0]",                Box::new(|r| { r.b[0] = 1; })),
        ("out[0]",              Box::new(|r| { r.out[0] = 1; })),
        ("add_intermediate[0]", Box::new(|r| { r.add_intermediate[0] = 1; })),
        ("add_carry[0]",        Box::new(|r| { r.add_carry[0] = 1; })),
        ("sub_borrow[0]",       Box::new(|r| { r.sub_borrow[0] = 1; })),
        ("ff_borrow[0]",        Box::new(|r| { r.final_form_borrow[0] = 1; })),
        ("sub_chain_brw[0]",    Box::new(|r| { r.sub_chain_borrow[0] = 1; })),
        ("mul_product[0]",      Box::new(|r| { r.mul_product[0] = 1; })),
        ("mul_carry[0]",        Box::new(|r| { r.mul_carry[0] = 1; })),
        ("mul_carry_mid[0]",    Box::new(|r| { r.mul_carry_mid[0] = 1; })),
        ("mul_carry_hi[0]",     Box::new(|r| { r.mul_carry_hi[0] = 1; })),
        ("pass1_lo[0]",         Box::new(|r| { r.pass1_lo[0] = 1; })),
        ("pass1_hi[0]",         Box::new(|r| { r.pass1_hi[0] = 1; })),
        ("pass1_carry[0]",      Box::new(|r| { r.pass1_carry[0] = 1; })),
        ("pass1_carry_mid[0]",  Box::new(|r| { r.pass1_carry_mid[0] = 1; })),
        ("pass2_lo[0]",         Box::new(|r| { r.pass2_lo[0] = 1; })),
        ("pass2_carry[0]",      Box::new(|r| { r.pass2_carry[0] = 1; })),
        ("pass2_carry_out",     Box::new(|r| { r.pass2_carry_out = 1; })),
        ("pass2_top_bit",       Box::new(|r| { r.pass2_top_bit = 1; })),
        ("after_top_bit[0]",    Box::new(|r| { r.after_top_bit[0] = 1; })),
        ("after_top_carry[0]",  Box::new(|r| { r.after_top_carry[0] = 1; })),
        ("is_overflow",         Box::new(|r| { r.is_overflow = 1; })),
    ];

    for (name, mutate) in cases {
        let mut side_note = zkpvm::SideNote::new(
            Vec::new(), Vec::new(), Vec::new(),
        );
        let mut row = FieldOpRow::default();
        row.is_mul = 1;
        row.is_real = 1;
        mutate(&mut row);
        side_note.add_ristretto_field_row(row);
        let config = zkpvm::PcsConfig {
            pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
        };
        let r = zkpvm::prove_with_config(&mut side_note, config);
        eprintln!("{:>22}: {}", name, if r.is_ok() { "PASS" } else { "FAIL" });
    }
}

/// R1e-quat diagnostic: 17 rows of 0·0=0 (forces log_size > LOG_N_LANES).
/// If this passes, multiple is_mul rows compose; the failure on
/// 1·1=1 is row-content-specific, not a row-count issue.
#[test]
#[ignore]
fn debug_seventeen_mul_zero_rows() {
    use zkpvm::chips::ristretto::witness::fill_mul;
    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );
    for _ in 0..17 {
        side_note.add_ristretto_field_row(fill_mul([0u8; 32], [0u8; 32]));
    }
    let config = zkpvm::PcsConfig {
        pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("17 mul-zero rows: prove failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5, min_fri_queries: 3, min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("17 mul-zero rows: verify failed");
    eprintln!("17 mul-zero rows: PROVED + VERIFIED");
}

/// R1e-quat bisect over which witness CELL triggers the failure.
/// Each scenario hand-crafts a single field-op row with one specific
/// non-zero cell and reports prove pass/fail.
#[test]
#[ignore]
fn debug_mul_cell_bisect() {
    use zkpvm::chips::ristretto::witness::FieldOpRow;

    let scenarios: Vec<(&str, Box<dyn Fn(&mut FieldOpRow)>)> = vec![
        ("only_a0",       Box::new(|r| { r.a[0] = 1; })),
        ("a0_and_mp0",    Box::new(|r| { r.a[0] = 1; r.mul_product[0] = 1; })),
        ("a0b0_mp0",      Box::new(|r| { r.a[0] = 1; r.b[0] = 1; r.mul_product[0] = 1; })),
        ("a0b0_mp0_p1lo0",Box::new(|r| { r.a[0] = 1; r.b[0] = 1; r.mul_product[0] = 1; r.pass1_lo[0] = 1; })),
        ("full_chain_no_out",  Box::new(|r| {
            r.a[0] = 1; r.b[0] = 1; r.mul_product[0] = 1;
            r.pass1_lo[0] = 1; r.pass2_lo[0] = 1; r.after_top_bit[0] = 1;
        })),
        ("full_chain",    Box::new(|r| {
            r.a[0] = 1; r.b[0] = 1; r.mul_product[0] = 1;
            r.pass1_lo[0] = 1; r.pass2_lo[0] = 1; r.after_top_bit[0] = 1;
            r.out[0] = 1;
        })),
    ];

    for (name, mutate) in scenarios {
        let mut side_note = zkpvm::SideNote::new(
            Vec::new(), Vec::new(), Vec::new(),
        );
        let mut row = FieldOpRow::default();
        row.is_mul = 1;
        row.is_real = 1;
        // Final-form borrow chain expects p − out − 1 ≥ 0; for the
        // small `out` values we use, the witness produces ff_brw=0
        // throughout if we recompute it.
        mutate(&mut row);
        // Recompute final_form_borrow for the chosen out:
        let mut bw: i16 = 1;
        for i in 0..32 {
            let p_i = if i == 0 { 0xed } else if i == 31 { 0x7f } else { 0xff };
            let v = p_i as i16 - row.out[i] as i16 - bw;
            bw = if v < 0 { 1 } else { 0 };
            row.final_form_borrow[i] = bw as u8;
        }
        side_note.add_ristretto_field_row(row);

        let config = zkpvm::PcsConfig {
            pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
        };
        let r = zkpvm::prove_with_config(&mut side_note, config);
        eprintln!("scenario {}: {}", name, if r.is_ok() { "OK" } else { "FAIL" });
    }
}

/// R1e-quat: chip-on test for the trivial is_mul row 0·0=0.  All
/// witness columns hold zero, every is_mul-gated chain reduces to
/// 0 = 0.  Demonstrates the chip-on integration plumbing works
/// for is_mul rows; the non-zero is_mul bug surfaced in
/// prove_ristretto_chip_field_mul is independent of the integration.
#[test]
fn prove_ristretto_chip_field_mul_zero() {
    use zkpvm::chips::ristretto::witness::fill_mul;

    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );
    let row = fill_mul([0u8; 32], [0u8; 32]);
    assert_eq!(row.is_mul, 1);
    assert_eq!(row.out, [0u8; 32]);
    side_note.add_ristretto_field_row(row);

    let config = zkpvm::PcsConfig {
        pow_bits: 5,
        fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("RistrettoChip field-mul (zero) proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("RistrettoChip field-mul (zero) verification failed");
    eprintln!("RistrettoChip field-mul (0·0=0): PROVED + VERIFIED");
}

/// R1e-quat: chip-on test for field-mul with operands that overflow
/// 2²⁵⁶, exercising the full reduction chain (pass-1 fold + pass-2
/// fold + top-bit fold + final < p).
#[test]
fn prove_ristretto_chip_field_mul_with_reduction() {
    use zkpvm::chips::ristretto::witness::fill_mul;

    let mut side_note = zkpvm::SideNote::new(
        Vec::new(), Vec::new(), Vec::new(),
    );
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for i in 0..32 { a[i] = (0xa3u8).wrapping_mul((i + 1) as u8); }
    for i in 0..32 { b[i] = (0x71u8).wrapping_mul((i + 1) as u8); }
    a[31] &= 0x7f; b[31] &= 0x7f;
    side_note.add_ristretto_field_row(fill_mul(a, b));

    let config = zkpvm::PcsConfig {
        pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3),
    };
    let proof = zkpvm::prove_with_config(&mut side_note, config)
        .expect("RistrettoChip field-mul (with reduction) proving failed");
    let policy = zkpvm::PcsPolicy {
        min_pow_bits: 5, min_fri_queries: 3, min_fri_log_blowup: 0,
    };
    zkpvm::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("RistrettoChip field-mul (with reduction) verification failed");
    eprintln!("RistrettoChip field-mul (full reduction): PROVED + VERIFIED");
}

/// R1a smoke test: hand-craft an `ecalli 200` program, set up
/// φ[10]/φ[11]/φ[12] to point at scalar/input-point/output-point
/// buffers in flat_mem, run TracingPvm with precompile dispatch, and
/// confirm the captured `RistrettoRecord` + the bytes written to
/// `output_ptr` match a host-side dalek computation.  No chip /
/// proving yet — that's R1b onwards.
#[test]
fn ristretto_scalar_mult_via_ecall_tracing() {
    use zkpvm::core::tracing::ECALL_RISTRETTO_SCALAR_MULT;

    // Lay out memory: scalar at 0x1000 (32 B), point at 0x1020 (32 B),
    // output at 0x1040 (32 B).  Scalar is `2`, point is the canonical
    // basepoint compressed encoding so the expected output is `2*G`.
    let scalar_addr: u64 = 0x1000;
    let point_addr:  u64 = 0x1020;
    let output_addr: u64 = 0x1040;

    let scalar_bytes: [u8; 32] = {
        let mut s = [0u8; 32];
        s[0] = 2;
        s
    };
    let point_bytes: [u8; 32] = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();

    let mut flat_mem = vec![0u8; 0x2000];
    flat_mem[scalar_addr as usize .. scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr  as usize .. point_addr  as usize + 32].copy_from_slice(&point_bytes);

    // ecalli 200, then trap.  Ecalli is a 5-byte instruction
    // (opcode + 4-byte little-endian immediate).
    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8,
        (imm & 0xff) as u8, ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8, ((imm >> 24) & 0xff) as u8,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[10] = scalar_addr;
    regs[11] = point_addr;
    regs[12] = output_addr;

    let pvm = javm::interpreter::Interpreter::new(
        code, bitmask, vec![], regs, flat_mem, 10_000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run_with_precompiles();
    eprintln!("Exit: {exit:?}, steps: {}, ristretto_calls: {}",
        tracing.steps.len(), tracing.ristretto_records.len());

    assert_eq!(tracing.ristretto_records.len(), 1, "expected 1 Ristretto ECALL");
    assert_eq!(tracing.ristretto_mem_ops.len(), 1);

    // Expected: 2 * G, computed independently via dalek.
    let expected_out: [u8; 32] = {
        let scalar = curve25519_dalek::scalar::Scalar::from_canonical_bytes(scalar_bytes)
            .into_option().expect("scalar canonical");
        let point  = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&point_bytes)
            .ok().and_then(|c| c.decompress()).expect("point decompresses");
        (scalar * point).compress().to_bytes()
    };

    let rec = &tracing.ristretto_records[0];
    assert_eq!(rec.scalar, scalar_bytes);
    assert_eq!(rec.point,  point_bytes);
    assert_eq!(rec.output, expected_out, "RistrettoRecord.output mismatch");

    let mem_op = &tracing.ristretto_mem_ops[0];
    assert_eq!(mem_op.scalar_ptr, scalar_addr as u32);
    assert_eq!(mem_op.point_ptr,  point_addr  as u32);
    assert_eq!(mem_op.output_ptr, output_addr as u32);
    assert_eq!(mem_op.scalar_bytes, scalar_bytes);
    assert_eq!(mem_op.point_bytes,  point_bytes);
    assert_eq!(mem_op.out_bytes,    expected_out);

    // Confirm the precompile actually wrote the result back into flat_mem
    // (so a follow-up PVM instruction could read it).
    let written = &tracing.pvm.flat_mem[output_addr as usize .. output_addr as usize + 32];
    assert_eq!(written, &expected_out[..], "flat_mem write mismatch");

    eprintln!("Ristretto scalar mult via ECALL: TRACED ({} bytes output)", expected_out.len());
}

#[test]
fn prove_blake2b_via_ecall() {
    use zkpvm::core::tracing::ECALL_BLAKE2B_COMPRESS;

    // Build a PVM program that stores h and m in memory, calls ecall, reads result
    // For simplicity: manually set up interpreter with h/m in memory and call ecall

    let iv: [u64; 8] = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ];

    // Lay out memory: h at 0x1000 (64 bytes), m at 0x1040 (128 bytes)
    let h_addr: u64 = 0x1000;
    let m_addr: u64 = 0x1040;
    let mut flat_mem = vec![0u8; 0x2000];
    for i in 0..8 {
        flat_mem[h_addr as usize + i*8 .. h_addr as usize + i*8+8].copy_from_slice(&iv[i].to_le_bytes());
    }
    // m is all zeros (already)

    // PVM program: ecalli 100 (blake2b), then trap
    // ecalli encoding: opcode byte + immediate
    let code = vec![
        javm::instruction::Opcode::Ecalli as u8, ECALL_BLAKE2B_COMPRESS as u8, 0, 0, 0,
        javm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let mut regs = [0u64; javm::PVM_REGISTER_COUNT];
    regs[10] = h_addr;  // φ[10] = h pointer
    regs[11] = m_addr;  // φ[11] = m pointer
    regs[12] = 0;       // φ[12] = t (counter)
    regs[7] = 1;        // φ[7] = f (finalize flag)

    let pvm = javm::interpreter::Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs, flat_mem.clone(), 10000, 25
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run_with_precompiles();
    eprintln!("Exit: {exit:?}, steps: {}, blake2b_calls: {}",
        tracing.steps.len(), tracing.blake2b_records.len());

    assert_eq!(tracing.blake2b_records.len(), 1, "should have 1 blake2b call");

    let steps = tracing.steps.clone();
    let blake2b_records = tracing.blake2b_records.clone();
    let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();

    // Build SideNote with blake2b calls
    let mut side_note = zkpvm::SideNote::new(
        steps, code.clone(), bitmask.clone()
    ).with_memory(flat_mem);

    for rec in &blake2b_records {
        side_note.blake2b_calls.push(zkpvm::chips::blake2b::Blake2bCall {
            h: rec.h, m: rec.m, t: rec.t, f: rec.f,
        });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;

    let config = zkpvm::PcsConfig { pow_bits: 5, fri_config: zkpvm::FriConfig::new(0, 1, 3) };
    let proof = zkpvm::prove_with_config(&mut side_note, config).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
    eprintln!("Blake2b via ECALL: PROVED! ({} CPU steps + {} chip rows)",
        side_note.steps.len(), blake2b_records.len() * 96);
}
