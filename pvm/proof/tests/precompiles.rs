#![cfg(feature = "prover")]

//! Precompile proofs: BLAKE2b, traced through `ecalli` and proven end to
//! end or chip-isolated.

use vos_pvm::interpreter::Interpreter;

use vos_pvm_proof::core::tracing::TracingPvm;

const TEST_GUEST_BASE: u64 = vos_pvm::PVM_ZONE_SIZE as u64 + 0x1000;
const TEST_GUEST_MEMORY_LEN: usize = vos_pvm::PVM_ZONE_SIZE as usize + 0x2000;

#[test]
fn prove_blake2b_precompile() {
    use vos_pvm_proof::chips::blake2b::blake2b_compress;
    use vos_pvm_proof::core::tracing::ECALL_BLAKE2B_COMPRESS;

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

    let h_addr = TEST_GUEST_BASE;
    let m_addr = TEST_GUEST_BASE + 0x40;
    let mut flat_mem = vec![0u8; TEST_GUEST_MEMORY_LEN];
    for i in 0..8 {
        flat_mem[h_addr as usize + i * 8..h_addr as usize + i * 8 + 8]
            .copy_from_slice(&h[i].to_le_bytes());
    }
    // m left all zero.

    let code = vec![
        vos_pvm::instruction::Opcode::Ecalli as u8,
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[0],
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[1],
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[2],
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[3],
        vos_pvm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];
    let mut regs = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2/A3 map to φ[7/8/9/10].
    regs[7] = h_addr;
    regs[8] = m_addr;
    regs[9] = 0;
    regs[10] = 1;

    let pvm = vos_pvm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10000,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run_with_precompiles();
    let mut side_note = tracing.into_side_note().with_memory(flat_mem);

    let config = vos_pvm_proof::PcsConfig {
        pow_bits: 5,
        fri_config: vos_pvm_proof::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof =
        vos_pvm_proof::prove_with_config(&mut side_note, config).expect("blake2b proving failed");
    let policy = vos_pvm_proof::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    vos_pvm_proof::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("blake2b verification failed");
    eprintln!("Blake2b precompile: PROVED!");
}

/// A normal PVM return is a dynamic jump to the distinguished halt
/// address, not a dispatch through the program's jump table. Keep that
/// terminal convention inside the proved CPU semantics: treating it as an
/// ordinary JumpTable consumer leaves an unmatched lookup and makes every
/// freshly-built VOS Task proof unverifiable.
#[test]
fn prove_vos_halt_jump_without_a_program_jump_table() {
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    let mut assembler = Assembler::new();
    assembler
        .load_imm_64(Reg::T0, vos_pvm::PVM_HALT_ADDR)
        .jump_ind(Reg::T0, 0);
    let program = vos_pvm::spi::parse_standard_program(&assembler.build())
        .expect("assembled standard program");
    let interpreter = Interpreter::new(
        program.code.code,
        program.code.bitmask,
        program.code.jump_table,
        [0; vos_pvm::PVM_REGISTER_COUNT],
        vec![],
        1_000_000,
    );
    let mut tracing = TracingPvm::new(interpreter);
    assert_eq!(tracing.run_with_precompiles(), vos_pvm::ExitReason::Halt);
    let mut side_note = tracing.into_side_note();
    assert!(side_note.jump_table.is_empty());

    let config = vos_pvm_proof::PcsConfig {
        pow_bits: 5,
        fri_config: vos_pvm_proof::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = vos_pvm_proof::prove_with_config(&mut side_note, config)
        .expect("the terminal halt jump must prove");
    let policy = vos_pvm_proof::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    vos_pvm_proof::verify_with_pcs_policy(proof, &side_note, &policy)
        .expect("the terminal halt jump must verify without a jump-table row");
}

#[test]
fn prove_blake2b_via_ecall() {
    use vos_pvm_proof::core::tracing::ECALL_BLAKE2B_COMPRESS;

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

    // Lay out the h (64-byte) and m (128-byte) buffers above the low zone.
    let h_addr = TEST_GUEST_BASE;
    let m_addr = TEST_GUEST_BASE + 0x40;
    let mut flat_mem = vec![0u8; TEST_GUEST_MEMORY_LEN];
    for i in 0..8 {
        flat_mem[h_addr as usize + i * 8..h_addr as usize + i * 8 + 8]
            .copy_from_slice(&iv[i].to_le_bytes());
    }
    // m is all zeros (already)

    // PVM program: ecalli <BLAKE2b> (four-byte immediate), then trap
    // ecalli encoding: opcode byte + immediate
    let code = vec![
        vos_pvm::instruction::Opcode::Ecalli as u8,
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[0],
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[1],
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[2],
        ECALL_BLAKE2B_COMPRESS.to_le_bytes()[3],
        vos_pvm::instruction::Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let mut regs = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    // PVM A0/A1/A2/A3 map to φ[7/8/9/10].  The vos-pvm-precompiles
    // shim's `in("a0") h_ptr, in("a1") m_ptr, in("a2") t_low,
    // in("a3") f_flag` lands the actor's blake2b arguments in
    // φ[7/8/9/10], where the host handler reads them.
    regs[7] = h_addr; // a0 = h pointer
    regs[8] = m_addr; // a1 = m pointer
    regs[9] = 0; // a2 = t (counter)
    regs[10] = 1; // a3 = f (finalize flag)

    let pvm = vos_pvm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem.clone(),
        10000,
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
        vos_pvm_proof::SideNote::new(steps, code.clone(), bitmask.clone()).with_memory(flat_mem);

    for rec in &blake2b_records {
        side_note
            .blake2b_calls
            .push(vos_pvm_proof::chips::blake2b::Blake2bCall {
                h: rec.h,
                m: rec.m,
                t: rec.t,
                f: rec.f,
            });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;

    let config = vos_pvm_proof::PcsConfig {
        pow_bits: 5,
        fri_config: vos_pvm_proof::FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let proof = vos_pvm_proof::prove_with_config(&mut side_note, config).expect("proving failed");
    // Test config uses pow_bits=5 / fri_log_blowup=0, well below the
    // STANDARD policy floor.  Use a permissive policy so the verify
    // step exercises the algebraic check, not the policy gate.
    let policy = vos_pvm_proof::PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    vos_pvm_proof::verify_with_pcs_policy(proof, &side_note, &policy).expect("verification failed");
    eprintln!(
        "Blake2b via ECALL: PROVED! ({} CPU steps + {} chip rows)",
        side_note.steps.len(),
        blake2b_records.len() * 96
    );
}

/// The refine host and the proof tracer serve BLAKE2b from the same
/// registers: φ[7] = h, φ[8] = m, φ[9] = counter, φ[10] = finalize flag.
/// Distinct values in each register make any disagreement visible, and the
/// tracer charges the same price as the host.
#[test]
fn tracer_and_refine_host_read_the_same_compression_registers() {
    use vos_pvm::interpreter::{Memory, PERM_RW};
    use vos_pvm::precompile::{BLAKE2B_COMPRESS, BLAKE2B_COMPRESS_GAS, execute};

    let h_addr = TEST_GUEST_BASE;
    let m_addr = TEST_GUEST_BASE + 0x100;
    let mut memory = vec![0u8; TEST_GUEST_MEMORY_LEN];
    for (i, byte) in memory[h_addr as usize..h_addr as usize + 64]
        .iter_mut()
        .enumerate()
    {
        *byte = i as u8;
    }
    for (i, byte) in memory[m_addr as usize..m_addr as usize + 128]
        .iter_mut()
        .enumerate()
    {
        *byte = 0x80 ^ i as u8;
    }
    let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    registers[7] = h_addr;
    registers[8] = m_addr;
    registers[9] = 0x1234;
    registers[10] = 1;

    let mut host_memory = Memory::flat(memory.clone());
    host_memory.set_page_perms(vec![PERM_RW; TEST_GUEST_MEMORY_LEN / 4096]);
    execute(BLAKE2B_COMPRESS, &registers, &mut host_memory).expect("served by the host");
    let mut host_h = [0u8; 64];
    host_memory.read_bytes(h_addr as u32, &mut host_h);

    let [b0, b1, b2, b3] = (BLAKE2B_COMPRESS as u32).to_le_bytes();
    let code = vec![
        vos_pvm::instruction::Opcode::Ecalli as u8,
        b0,
        b1,
        b2,
        b3,
        vos_pvm::instruction::Opcode::Trap as u8,
    ];
    let pvm = Interpreter::new(
        code,
        vec![1, 0, 0, 0, 0, 1],
        vec![],
        registers,
        memory,
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run_with_precompiles(), vos_pvm::ExitReason::Panic);
    assert_eq!(tracing.blake2b_records.len(), 1);
    let traced_h = &tracing.pvm.flat_mem()[h_addr as usize..h_addr as usize + 64];
    assert_eq!(traced_h, &host_h[..], "same registers, same compression");
    assert_eq!(
        10_000 - tracing.pvm.gas,
        u64::from(tracing.pvm.block_gas_costs[0]) + BLAKE2B_COMPRESS_GAS,
        "the tracer charges the host's price"
    );
}
