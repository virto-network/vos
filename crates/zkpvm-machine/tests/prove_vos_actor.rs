//! End-to-end test: trace a real VOS actor compiled from Rust.

use javm::interpreter::Interpreter;
use javm::program::{self, CapEntryType};
use javm::PVM_REGISTER_COUNT;

use zkpvm_core::tracing::TracingPvm;
use zkpvm_machine::{prove, prove_profiled, verify};

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
fn interpreter_from_blob(blob: &[u8], gas: u64) -> Interpreter {
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

    Interpreter::new(
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
        code_blob.jump_table.to_vec(),
        registers,
        flat_mem,
        gas,
        mem_cycles,
    )
}

#[test]
fn trace_fibonacci_actor() {
    let blob = load_fibonacci_blob();
    eprintln!("PVM blob: {} bytes", blob.len());

    let interp = interpreter_from_blob(&blob, 10_000_000);
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

    let interp = interpreter_from_blob(&blob, 10_000_000);
    let mut tracing = TracingPvm::new(interp);
    let exit = tracing.run();
    let steps = tracing.into_trace();
    eprintln!("Traced {} steps, exit={exit:?}", steps.len());

    let mut side_note = zkpvm_machine::SideNote::new(
        steps,
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
    );
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

    let interp = interpreter_from_blob(&blob, 10_000_000);
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

    let mut side_note = zkpvm_machine::SideNote::new(
        steps,
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
    );

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
    let interp = interpreter_from_blob(&blob, gas);

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

    let mut side_note = zkpvm_machine::SideNote::new(
        steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec(),
    );

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
    let interp = interpreter_from_blob(&blob, 100_000_000);

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

    let mut side_note = zkpvm_machine::SideNote::new(
        steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec(),
    );

    eprintln!("\nProve:");
    let (proof, _) = prove_profiled(&mut side_note).expect("proving failed");
    let proof_bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!("Proof: {:.1} KB", proof_bytes.len() as f64 / 1024.0);

    let t = std::time::Instant::now();
    verify(proof, &side_note).expect("verification failed");
    eprintln!("Verify: {:?}", t.elapsed());
}
