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
    let exit = tracing.run();
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

#[test]
fn profile_cipher_clerk_bench() {
    // Real-workload validation: cipher-clerk's kernel types compiled
    // for riscv64em-javm.  Exercises Account / AuthKey / id types
    // construction + arithmetic.
    profile_actor("cipher-clerk-bench", 10_000_000);
}

/// Trace-only variant of cipher-clerk-bench: validates the actor
/// builds + runs in the PVM interpreter.  Trace-only because the
/// full prove path also runs as `profile_cipher_clerk_bench`.
#[test]
fn trace_cipher_clerk_bench() {
    let blob = load_actor_blob("cipher-clerk-bench");
    let (interp, _flat_mem) = interpreter_from_blob(&blob, 10_000_000);
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("cipher-clerk-bench: {} PVM steps, exit={exit:?}", steps.len());
    assert_eq!(exit, javm::ExitReason::Trap);
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

#[test]
fn prove_blake2b_via_ecall() {
    use zkpvm::core::tracing::{ECALL_BLAKE2B_COMPRESS, Blake2bRecord};

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
