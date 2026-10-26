use super::state::STATE_READ_BYTE_GAS;
use super::*;
use crate::inner::{MAX_INNER_MACHINES, gas};
use vos_pvm_program::{CodeBlob, build_compact_code_blob};

fn standard_program(args_code: &[u8], starts: &[usize]) -> Vec<u8> {
    standard_program_with_rw(args_code, starts, &[])
}

pub(super) fn standard_program_with_rw(
    args_code: &[u8],
    starts: &[usize],
    rw_data: &[u8],
) -> Vec<u8> {
    let mut packed = alloc::vec![0u8; args_code.len().div_ceil(8)];
    for &i in starts {
        packed[i / 8] |= 1 << (i % 8);
    }
    let mut code_blob = alloc::vec![0, 1, args_code.len() as u8];
    code_blob.extend_from_slice(args_code);
    code_blob.extend_from_slice(&packed);

    let mut blob = Vec::new();
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
    blob.extend_from_slice(rw_data);
    blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
    blob.extend_from_slice(&code_blob);
    blob
}

fn inner_program() -> Vec<u8> {
    // host(42), then trap.
    vec![0, 1, 3, 10, 42, 0, 0b0000_0101]
}

#[test]
fn a_nested_run_is_the_same_reused_and_recompiled() {
    const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
    let mut frame = [0u8; 112];
    frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
    let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
    let outer = standard_program_with_rw(&code, &[0, 2, 7, 9], &frame);
    let args = inner_program();
    let expected = RefineContext::load_with(&outer, &args, 1_000_000, MemoryModel::Sparse)
        .unwrap()
        .run();
    let prepared = crate::refine::PreparedProgram::new(&outer).unwrap();
    for _ in 0..2 {
        let reused = RefineContext::load_prepared(&prepared, &args, 1_000_000, MemoryModel::Sparse)
            .unwrap()
            .run();
        assert_eq!(reused.exit, expected.exit);
        assert_eq!(reused.pc, expected.pc);
        assert_eq!(reused.registers, expected.registers);
        assert_eq!(reused.gas_used, expected.gas_used);
        let mut cold_frame = [0; 112];
        let mut reused_frame = [0; 112];
        expected.memory().read_bytes(RW_BASE, &mut cold_frame);
        reused.memory().read_bytes(RW_BASE, &mut reused_frame);
        assert_eq!(reused_frame, cold_frame);
    }

    // Use real nested host dispatch with both machines recompiled. Exact
    // gas includes outer initialization, host charges and the inner refund.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    {
        let native =
            crate::refine::PreparedProgram::new_with_backend(&outer, PvmBackend::ForceRecompiler)
                .unwrap();
        for _ in 0..2 {
            let context =
                RefineContext::load_prepared(&native, &args, 1_000_000, MemoryModel::Auto).unwrap();
            assert_eq!(context.outer.backend(), PvmBackend::ForceRecompiler);
            let actual = context.try_run().unwrap();
            assert_eq!(actual.exit, expected.exit);
            assert_eq!(actual.pc, expected.pc);
            assert_eq!(actual.registers, expected.registers);
            assert_eq!(actual.gas_used, expected.gas_used);
            let mut actual_frame = [0; 112];
            let mut expected_frame = [0; 112];
            actual.memory().read_bytes(RW_BASE, &mut actual_frame);
            expected.memory().read_bytes(RW_BASE, &mut expected_frame);
            assert_eq!(actual_frame, expected_frame);
        }
    }
}

#[test]
fn outer_machine_create_and_expunge_run_to_halt() {
    // machine(9), expunge(14), jump_ind r0 to the halt address.
    let outer = standard_program(&[10, 9, 10, 14, 50, 0], &[0, 2, 4]);
    let invocation = RefineContext::load(&outer, &inner_program(), 1_000_000)
        .unwrap()
        .run();
    assert_eq!(invocation.exit, ExitReason::Halt);
    assert_eq!(invocation.registers[7], 0, "expunge returned entry PC");
    assert!(invocation.gas_used > 0);
}

#[test]
fn machine_rejects_runtime_only_opcode_three_as_huh() {
    let runtime_only = build_compact_code_blob(&CodeBlob {
        jump_table: Vec::new(),
        code: vec![3],
        bitmask: vec![1],
    })
    .unwrap();
    // machine(9), then jump_ind r0 to the halt address.
    let outer = standard_program(&[10, 9, 50, 0], &[0, 2]);
    let invocation = RefineContext::load(&outer, &runtime_only, 1_000_000)
        .unwrap()
        .run();

    assert_eq!(invocation.exit, ExitReason::Halt);
    assert_eq!(invocation.registers[7], result::HUH);
}

/// φ7 ← the rw base (h), φ8 ← rw base + 64 (m), `ecalli id`, halt.
fn compression_program(id: u16) -> Vec<u8> {
    let [id_lo, id_hi] = id.to_le_bytes();
    let (code, starts) = crate::test_support::code(&[
        &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000
        &[51, 8, 0x40, 0x00, 0x02], // load_imm φ8, 0x2_0040
        &[10, id_lo, id_hi],        // ecalli id
        &[50, 0],                   // jump_ind φ0 (the halt address)
    ]);
    standard_program_with_rw(&code, &starts, &[0x5a; 192])
}

fn compressed_h() -> [u8; 64] {
    let word = u64::from_le_bytes([0x5a; 8]);
    let h = [word; 8];
    let m = [word; 16];
    let out = crate::precompile::compress(&h, &m, 0, false);
    let mut bytes = [0u8; 64];
    for (i, value) in out.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn precompile_price_is_charged_identically_on_every_path() {
    let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
    let check = |invocation: &Invocation, path: &str| {
        assert_eq!(invocation.exit, ExitReason::Halt, "{path}");
        let mut h = [0u8; 64];
        invocation.memory().read_bytes(0x2_0000, &mut h);
        assert_eq!(h, compressed_h(), "{path}: served in place");
        invocation.gas_used
    };

    let interpreted = RefineContext::load_with_backend(
        &program,
        &[],
        1_000_000,
        crate::refine::MemoryModel::Auto,
        PvmBackend::ForceInterpreter,
    )
    .unwrap()
    .run();
    let gas = check(&interpreted, "interpreter");
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    {
        let native = RefineContext::load_with_backend(
            &program,
            &[],
            1_000_000,
            crate::refine::MemoryModel::Auto,
            PvmBackend::ForceRecompiler,
        )
        .unwrap()
        .try_run()
        .unwrap();
        assert_eq!(check(&native, "recompiler"), gas);
    }

    // The same program naming an id no host serves, resumed for free by
    // the embedder: identical instructions and blocks, minus the price.
    let unpriced = RefineContext::load(&compression_program(0x4ff), &[], 1_000_000)
        .unwrap()
        .run_with_host(|id, _| {
            assert_eq!(id, 0x4ff);
            Ok(())
        });
    assert_eq!(unpriced.exit, ExitReason::Halt);
    assert_eq!(
        gas,
        unpriced.gas_used + crate::precompile::BLAKE2B_COMPRESS_GAS
    );
}

#[test]
fn precompile_output_is_a_dirty_page_on_every_path() {
    let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
    // The program stores nothing itself: the only write is the
    // compression output at 0x2_0000, written in place by the host.
    let h_page = 0x2_0000 / crate::PVM_PAGE_SIZE;
    let check = |mut invocation: Invocation, path: &str| {
        assert_eq!(invocation.exit, ExitReason::Halt, "{path}");
        assert_eq!(
            invocation.memory_mut().take_dirty_pages(),
            vec![h_page..h_page + 1],
            "{path}: precompile output"
        );
    };
    for model in [
        crate::refine::MemoryModel::Auto,
        crate::refine::MemoryModel::Sparse,
    ] {
        let invocation = RefineContext::load_with_backend(
            &program,
            &[],
            1_000_000,
            model,
            PvmBackend::ForceInterpreter,
        )
        .unwrap()
        .run();
        check(invocation, "interpreter");
    }
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    check(
        RefineContext::load_with_backend(
            &program,
            &[],
            1_000_000,
            crate::refine::MemoryModel::Auto,
            PvmBackend::ForceRecompiler,
        )
        .unwrap()
        .try_run()
        .unwrap(),
        "recompiler",
    );
}

/// An outer program that calls `instantiate` with the code hash in its
/// read-write data, then halts.
#[cfg(feature = "std")]
fn instantiating_program(hash: [u8; 32]) -> Vec<u8> {
    let [lo, hi] = (crate::inner::host_call::INSTANTIATE as u16).to_le_bytes();
    let (code, starts) = crate::test_support::code(&[
        &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000
        &[10, lo, hi],              // ecalli instantiate
        &[50, 0],                   // jump_ind φ0 (the halt address)
    ]);
    standard_program_with_rw(&code, &starts, &hash)
}

/// A program the pool lacks, given by the run's source, is installed and
/// lent at the gas an installed one costs. A source without it, with an
/// invalid program, or with another program's bytes answers `WHO`, as
/// does a pooled program the source does not own.
#[cfg(feature = "std")]
#[test]
fn instantiate_loads_what_its_source_gives_at_the_installed_price() {
    use crate::pool::{CodeHash, MachinePool};
    use alloc::sync::Arc;

    struct Source(Vec<(CodeHash, Vec<u8>)>);
    impl ProgramSource for Source {
        fn owns(&self, hash: &CodeHash) -> bool {
            self.0.iter().any(|(given, _)| given == hash)
        }

        fn program(&self, hash: &CodeHash) -> Option<Vec<u8>> {
            self.0
                .iter()
                .find(|(given, _)| given == hash)
                .map(|(_, bytes)| bytes.clone())
        }
    }

    let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
    let hash = CodeHash::of(&program);
    let another = instantiating_program([0; 32]);
    let run = |pool: &Arc<MachinePool>, source: Option<Source>| {
        let context = RefineContext::load_with_backend(
            &instantiating_program(hash.0),
            &[],
            1_000_000,
            crate::refine::MemoryModel::Auto,
            PvmBackend::ForceInterpreter,
        )
        .unwrap()
        .with_pool(Arc::clone(pool));
        match source {
            Some(source) => context.with_programs(Arc::new(source)),
            None => context,
        }
        .try_run()
        .unwrap()
    };

    let installed = Arc::new(MachinePool::new());
    installed.install(&program).unwrap();
    let reference = run(&installed, None);
    assert_eq!(reference.registers[7], 0, "the installed program is lent");
    let another_agents = run(&installed, Some(Source(Vec::new())));
    assert_eq!(
        another_agents.registers[7],
        result::WHO,
        "a pooled program the source does not own"
    );

    let empty = Arc::new(MachinePool::new());
    let loaded = run(&empty, Some(Source(vec![(hash, program.clone())])));
    assert_eq!(loaded.registers[7], 0, "the source's program is lent");
    assert_eq!(loaded.gas_used, reference.gas_used, "at the same gas");
    assert!(empty.program(&hash).is_some(), "and pooled after");

    for (why, source) in [
        ("nothing", Source(Vec::new())),
        ("an invalid program", Source(vec![(hash, vec![1, 2, 3])])),
        (
            "another program's bytes",
            Source(vec![(hash, another.clone())]),
        ),
    ] {
        let pool = Arc::new(MachinePool::new());
        let refused = run(&pool, Some(source));
        assert_eq!(refused.registers[7], result::WHO, "{why}");
        assert!(pool.program(&hash).is_none(), "{why}: nothing pooled");
    }
}

/// An outer program that calls `instantiate` with the code hash in its
/// read-write data and φ8 the counter `pc` (a `load_imm` immediate,
/// sign-extended), keeps the answer in φ9, expunges the machine φ7 names
/// and halts: φ7 is then the counter `expunge` gave, or `WHO`.
#[cfg(feature = "std")]
fn instantiating_at_program(hash: [u8; 32], pc: &[u8]) -> Vec<u8> {
    let [lo, hi] = (crate::inner::host_call::INSTANTIATE as u16).to_le_bytes();
    let load_pc = [&[51, 8][..], pc].concat();
    let (code, starts) = crate::test_support::code(&[
        &[51, 7, 0x00, 0x00, 0x02],                    // load_imm φ7, 0x2_0000
        &load_pc,                                      // load_imm φ8, pc
        &[10, lo, hi],                                 // ecalli instantiate
        &[100, 9 | (7 << 4)],                          // move_reg φ9, φ7
        &[10, crate::inner::host_call::EXPUNGE as u8], // ecalli expunge
        &[50, 0],                                      // jump_ind φ0 (the halt address)
    ]);
    standard_program_with_rw(&code, &starts, &hash)
}

/// `instantiate` starts the machine at the counter φ8 names, on either
/// backend, at the price it costs at 0; a counter that starts no
/// instruction answers `HUH` at the same gas, and lends nothing.
#[cfg(feature = "std")]
#[test]
fn instantiate_starts_at_the_counter_given() {
    use crate::pool::MachinePool;
    // Instructions start at 0, 5, 10 and 13; the code is 15 bytes.
    let installed = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
    let pool = alloc::sync::Arc::new(MachinePool::new());
    let hash = pool.install(&installed).unwrap();

    let backends = crate::test_support::backends();
    for &backend in &backends {
        let run = |pc: &[u8]| {
            RefineContext::load_with_backend(
                &instantiating_at_program(hash.0, pc),
                &[],
                1_000_000,
                crate::refine::MemoryModel::Auto,
                backend,
            )
            .unwrap()
            .with_pool(alloc::sync::Arc::clone(&pool))
            .try_run()
            .unwrap()
        };
        let started = run(&[10]);
        assert_eq!(started.exit, ExitReason::Halt, "{backend:?}");
        assert_eq!(started.registers[9], 0, "{backend:?}: the first index");
        assert_eq!(started.registers[7], 10, "{backend:?}: at its counter");
        for (pc, why) in [(&[0][..], "the start"), (&[13][..], "the last instruction")] {
            let other = run(pc);
            assert_eq!(other.registers[7], u64::from(pc[0]), "{backend:?}: {why}");
            assert_eq!(other.gas_used, started.gas_used, "{backend:?}: {why}");
        }
        for (pc, why) in [
            (&[1][..], "inside an instruction"),
            (&[15][..], "past the code"),
            (&[0xff][..], "outside the counter's domain"),
        ] {
            let refused = run(pc);
            assert_eq!(refused.registers[9], result::HUH, "{backend:?}: {why}");
            assert_eq!(refused.registers[7], result::WHO, "{backend:?}: {why}");
            assert_eq!(refused.gas_used, started.gas_used, "{backend:?}: {why}");
        }
    }
    assert_eq!(pool.idle(), backends.len(), "one idle machine per backend");
}

#[cfg(feature = "std")]
#[test]
fn instantiate_lends_pooled_machines_and_takes_them_back() {
    use crate::pool::{CodeHash, MachinePool};
    let installed = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
    let pool = alloc::sync::Arc::new(MachinePool::new());
    let hash = pool.install(&installed).unwrap();
    let price = pool.program(&hash).unwrap().price();

    for backend in crate::test_support::backends() {
        let run = |hash: CodeHash| {
            RefineContext::load_with_backend(
                &instantiating_program(hash.0),
                &[],
                1_000_000,
                crate::refine::MemoryModel::Auto,
                backend,
            )
            .unwrap()
            .with_pool(alloc::sync::Arc::clone(&pool))
            .try_run()
            .unwrap()
        };
        let lent = run(hash);
        assert_eq!(lent.exit, ExitReason::Halt, "{backend:?}");
        assert_eq!(lent.registers[7], 0, "{backend:?}: the first machine index");
        assert_eq!(
            pool.idle(),
            1,
            "{backend:?}: returned when the context dropped"
        );

        let unknown = run(CodeHash([0xee; 32]));
        assert_eq!(unknown.registers[7], result::WHO, "{backend:?}");
        assert_eq!(
            lent.gas_used - unknown.gas_used,
            price - gas::MACHINE_BASE,
            "{backend:?}: an installed program costs its price"
        );
        assert_eq!(pool.idle(), 1, "{backend:?}: the idle machine was reused");
        // Each backend keeps its own idle machines.
        let _ = pool
            .acquire(&pool.program(&hash).unwrap(), backend)
            .unwrap();
    }

    // Without a pool the call reaches the embedder, as on a JAM host.
    let reached = RefineContext::load(&instantiating_program(hash.0), &[], 1_000_000)
        .unwrap()
        .run();
    assert_eq!(
        reached.exit,
        ExitReason::HostCall(u64::from(crate::inner::host_call::INSTANTIATE))
    );
    let jam = RefineContext::load(&instantiating_program(hash.0), &[], 1_000_000)
        .unwrap()
        .try_run_jam(JamRefine::default())
        .unwrap()
        .invocation;
    assert_eq!(jam.exit, ExitReason::Halt);
    assert_eq!(
        jam.registers[7],
        result::WHAT,
        "the guest's loader takes over"
    );

    // The pool is shared by every refine on a node.
    let shared = alloc::sync::Arc::clone(&pool);
    std::thread::spawn(move || {
        let program = shared.program(&hash).unwrap();
        let mut machines = crate::inner::InnerMachines::new();
        machines.set_pool(alloc::sync::Arc::clone(&shared));
        machines.instantiate(&program, 0).unwrap();
    })
    .join()
    .unwrap();
    assert_eq!(pool.idle(), 1);
}

/// Reads the value under "abc" into 0x2_0010 with `state_read`, then
/// halts with φ7 holding the call's result.
fn state_reading_program() -> Vec<u8> {
    let [lo, hi] = (crate::inner::host_call::STATE_READ as u16).to_le_bytes();
    let (code, starts) = crate::test_support::code(&[
        &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000 (key)
        &[51, 8, 3],                // load_imm φ8, 3
        &[51, 9, 0x10, 0x00, 0x02], // load_imm φ9, 0x2_0010 (output)
        &[51, 10, 1],               // load_imm φ10, 1 (offset)
        &[51, 11, 64],              // load_imm φ11, 64
        &[10, lo, hi],              // ecalli state_read
        &[50, 0],                   // jump_ind φ0 (halt)
    ]);
    let mut rw = b"abc".to_vec();
    rw.resize(0x60, 0);
    standard_program_with_rw(&code, &starts, &rw)
}

struct Fixed;
impl StateReader for Fixed {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        (key == b"abc").then(|| b"value".to_vec())
    }

    fn rows<'a>(
        &'a self,
        _: &'a [u8],
        _: Option<&'a [u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        alloc::boxed::Box::new(core::iter::empty())
    }
}

#[test]
fn state_read_serves_the_nodes_state_and_falls_back_to_what() {
    let program = state_reading_program();
    let served = RefineContext::load(&program, &[], 1_000_000)
        .unwrap()
        .with_state(alloc::sync::Arc::new(Fixed))
        .run();
    assert_eq!(served.exit, ExitReason::Halt);
    assert_eq!(served.registers[7], 5, "the value's whole length");
    let mut out = [0u8; 5];
    served.memory().read_bytes(0x2_0010, &mut out);
    assert_eq!(&out, b"alue\0", "copied from the offset");

    struct Long;
    impl StateReader for Long {
        fn read(&self, _: &[u8]) -> Option<Vec<u8>> {
            Some(vec![7; 1000])
        }

        fn rows<'a>(
            &'a self,
            _: &'a [u8],
            _: Option<&'a [u8]>,
        ) -> alloc::boxed::Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
            alloc::boxed::Box::new(core::iter::empty())
        }
    }
    let long = RefineContext::load(&program, &[], 1_000_000)
        .unwrap()
        .with_state(alloc::sync::Arc::new(Long))
        .run();
    assert_eq!(long.registers[7], 1000);
    assert_eq!(
        long.gas_used - served.gas_used,
        (64 - 4) * STATE_READ_BYTE_GAS,
        "64 bytes copied against 4"
    );

    // Without a reader the call reaches the embedder, and a JAM-only
    // run answers it with `WHAT`.
    let reached = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
    assert_eq!(
        reached.exit,
        ExitReason::HostCall(u64::from(crate::inner::host_call::STATE_READ))
    );
    let jam = RefineContext::load(&program, &[], 1_000_000)
        .unwrap()
        .try_run_jam(JamRefine::default())
        .unwrap()
        .invocation;
    assert_eq!(jam.exit, ExitReason::Halt);
    assert_eq!(jam.registers[7], result::WHAT);
}

#[test]
fn gas_reports_what_is_left() {
    #[rustfmt::skip]
    let code = [
        10, 0,                        // ecalli gas
        50, 0,                        // jump_ind φ0 (halt)
    ];
    let program = standard_program_with_rw(&code, &[0, 2], &[]);
    let invocation = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
    assert_eq!(invocation.exit, ExitReason::Halt);
    let left = invocation.registers[7];
    // The block gas and the call's own 10 are spent before φ7 is set.
    assert!(left < 1_000_000 - 10 && left > 1_000_000 - 1_000, "{left}");
}

#[test]
fn unpayable_precompile_stops_out_of_gas_unserved() {
    let program = compression_program(crate::precompile::BLAKE2B_COMPRESS as u16);
    let full = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
    assert_eq!(full.exit, ExitReason::Halt);
    // Funds every block but not the price.
    let budget = full.gas_used - crate::precompile::BLAKE2B_COMPRESS_GAS;
    let invocation = RefineContext::load_with_backend(
        &program,
        &[],
        budget,
        crate::refine::MemoryModel::Sparse,
        PvmBackend::ForceInterpreter,
    )
    .unwrap()
    .run();
    assert_eq!(invocation.exit, ExitReason::OutOfGas);
    assert_eq!(invocation.pc, 10, "stops on the call's own counter");
    assert_eq!(invocation.gas_used, budget);
    let mut h = [0u8; 64];
    invocation.memory().read_bytes(0x2_0000, &mut h);
    assert_eq!(h, [0x5a; 64], "the call was not served");
}

/// `compression_program(0x402)` over `input` at φ7: its sixteen words in
/// the read-write data, the output written at φ8, 64 bytes on.
fn poseidon2_program(input: &[u8; 64]) -> Vec<u8> {
    let [id_lo, id_hi] = (crate::precompile::POSEIDON2 as u16).to_le_bytes();
    let (code, starts) = crate::test_support::code(&[
        &[51, 7, 0x00, 0x00, 0x02], // load_imm φ7, 0x2_0000
        &[51, 8, 0x40, 0x00, 0x02], // load_imm φ8, 0x2_0040
        &[10, id_lo, id_hi],        // ecalli 0x402
        &[50, 0],                   // jump_ind φ0 (the halt address)
    ]);
    let mut rw = [0u8; 96];
    rw[..64].copy_from_slice(input);
    standard_program_with_rw(&code, &starts, &rw)
}

/// The live Poseidon2 call on every backend: served in place at its price,
/// the output the reference compression's; a word at or above p, p itself
/// included, traps the call at its own counter, with nothing written.
#[test]
fn the_live_poseidon2_call_is_served_and_a_word_at_or_above_p_traps() {
    let backends = [
        PvmBackend::ForceInterpreter,
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        PvmBackend::ForceRecompiler,
    ];
    let run = |program: &[u8], backend| {
        RefineContext::load_with_backend(
            program,
            &[],
            1_000_000,
            crate::refine::MemoryModel::Auto,
            backend,
        )
        .unwrap()
        .try_run()
        .unwrap()
    };
    let mut input = [0u8; 64];
    for (i, chunk) in input.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&(0x7654_3210 - i as u32 * 0x0101_0101).to_le_bytes());
    }
    let expected = crate::precompile::poseidon2_compress(&input).unwrap();
    let unpriced = RefineContext::load(&compression_program(0x4ff), &[], 1_000_000)
        .unwrap()
        .run_with_host(|_, _| Ok(()));
    for backend in backends {
        let served = run(&poseidon2_program(&input), backend);
        assert_eq!(served.exit, ExitReason::Halt, "{backend:?}");
        let mut output = [0u8; 32];
        served.memory().read_bytes(0x2_0040, &mut output);
        assert_eq!(output, expected, "{backend:?}");
        assert_eq!(
            served.gas_used,
            unpriced.gas_used + crate::precompile::POSEIDON2_GAS,
            "{backend:?}"
        );
        for (index, word) in [
            (0, vos_pvm_poseidon2::P),
            (15, vos_pvm_poseidon2::P),
            (9, u32::MAX),
        ] {
            let mut refused = input;
            refused[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            let trapped = run(&poseidon2_program(&refused), backend);
            assert_eq!(trapped.exit, ExitReason::Panic, "{backend:?}, word {index}");
            assert_eq!(
                trapped.pc, 10,
                "{backend:?}: traps on the call's own counter"
            );
            let mut output = [0xffu8; 32];
            trapped.memory().read_bytes(0x2_0040, &mut output);
            assert_eq!(output, [0; 32], "{backend:?}: nothing written");
        }
    }
}

/// Run an inner machine whose program is `ecalli id; trap` with `gas` in
/// its invocation frame, the host computing the outer machine's
/// precompiles or not. Returns the outcome code in φ7 and the gas left
/// in the frame.
fn invoke_inner_call(id: u16, gas: u64, precompiles: bool) -> (u64, u64) {
    const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
    let mut frame = [0u8; 112];
    frame[..8].copy_from_slice(&gas.to_le_bytes());
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
    let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
    let outer = standard_program_with_rw(&code, &[0, 2, 7, 9], &frame);
    let [id_lo, id_hi] = id.to_le_bytes();
    // ecalli id; trap.
    let inner = vec![0, 1, 4, 10, id_lo, id_hi, 0, 0b0000_1001];
    let mut context =
        RefineContext::load_with(&outer, &inner, 1_000_000, MemoryModel::Sparse).unwrap();
    if !precompiles {
        context = context.without_precompiles();
    }
    let invocation = context.run();
    assert_eq!(invocation.exit, ExitReason::Halt);
    let mut left = [0u8; 8];
    invocation.memory().read_bytes(RW_BASE, &mut left);
    (invocation.registers[7], u64::from_le_bytes(left))
}

/// An inner machine's precompile call returns to the outer machine as a
/// host call, unpriced, whether or not the host computes the outer
/// machine's: its agent serves it, on every host. Without precompiles,
/// as on a JAM node, the outer machine's own reach the embedder.
#[test]
fn an_inner_machines_precompile_reaches_its_agent() {
    const HOST: u64 = 3;
    let id = crate::precompile::BLAKE2B_COMPRESS as u16;
    let (_, unknown) = invoke_inner_call(0x4ff, 100_000, true);
    for precompiles in [true, false] {
        assert_eq!(
            invoke_inner_call(id, 100_000, precompiles),
            (HOST, unknown),
            "precompiles {precompiles}"
        );
    }

    let [id_lo, id_hi] = id.to_le_bytes();
    let outer = standard_program(&[10, id_lo, id_hi, 50, 0], &[0, 3]);
    let mut seen = Vec::new();
    let invocation = RefineContext::load(&outer, &[], 1_000_000)
        .unwrap()
        .without_precompiles()
        .run_with_host(|call, machine| {
            seen.push(call);
            machine.registers_mut()[7] = result::WHAT;
            Ok(())
        });
    assert_eq!(seen, [u64::from(id)]);
    assert_eq!(invocation.exit, ExitReason::Halt);
}

#[test]
fn unknown_host_call_is_returned_to_the_embedder() {
    let outer = standard_program(&[51, 2, 9, 10, 77, 0], &[0, 3, 5]);
    let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
    assert_eq!(invocation.exit, ExitReason::HostCall(77));
    assert_eq!(invocation.pc, 3, "unknown host call stays on its cause");
    assert_eq!(invocation.registers[2], 9);
}

#[test]
fn embedder_calls_resume_without_reexecuting_prior_instructions() {
    // r2 <- 9; external(77); external(77); halt.
    let outer = standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7]);
    let mut calls = 0;
    let invocation = RefineContext::load(&outer, &[], 1_000_000)
        .unwrap()
        .run_with_host(|id, machine| {
            assert_eq!(id, 77);
            calls += 1;
            if !machine.charge(50) {
                return Err(ExitReason::OutOfGas);
            }
            machine.registers_mut()[2] += 1;
            Ok(())
        });
    assert_eq!(calls, 2);
    assert_eq!(invocation.exit, ExitReason::Halt);
    assert_eq!(invocation.registers[2], 11);
    assert!(invocation.gas_used >= 100);
}

#[test]
fn embedder_refusal_keeps_exact_call_counter_and_stops_execution() {
    let outer = standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7]);
    let mut calls = 0;
    let invocation = RefineContext::load(&outer, &[], 1_000_000)
        .unwrap()
        .run_with_host(|id, _| {
            calls += 1;
            Err(ExitReason::HostCall(id))
        });
    assert_eq!(calls, 1);
    assert_eq!(invocation.exit, ExitReason::HostCall(77));
    assert_eq!(invocation.pc, 3);
    assert_eq!(invocation.registers[2], 9);
}

#[test]
fn embedder_calls_preserve_inner_machines_and_cannot_intercept_builtins() {
    const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
    let mut frame = [0u8; 112];
    frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    let baseline = standard_program_with_rw(
        &[10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0],
        &[0, 2, 7, 9],
        &frame,
    );
    let expected = RefineContext::load(&baseline, &inner_program(), 1_000_000)
        .unwrap()
        .run();
    let outer = standard_program_with_rw(
        &[10, 9, 10, 77, 51, 8, b0, b1, b2, 10, 13, 10, 77, 50, 0],
        &[0, 2, 4, 9, 11, 13],
        &frame,
    );
    let mut calls = 0;
    let invocation = RefineContext::load(&outer, &inner_program(), 1_000_000)
        .unwrap()
        .run_with_host(|id, _| {
            assert_eq!(id, 77);
            calls += 1;
            Ok(())
        });
    assert_eq!(calls, 2);
    assert_eq!(expected.exit, ExitReason::Halt);
    assert_eq!(invocation.exit, expected.exit);
    let mut expected_frame = [0; 112];
    let mut actual_frame = [0; 112];
    expected.memory().read_bytes(RW_BASE, &mut expected_frame);
    invocation.memory().read_bytes(RW_BASE, &mut actual_frame);
    assert_eq!(actual_frame, expected_frame);
    assert_ne!(
        actual_frame, frame,
        "the retained inner machine must actually execute"
    );
}

#[test]
fn failed_host_dispatch_does_not_advance_the_outer_counter() {
    // Load an unmapped source range, then call machine(9) at pc 8.
    // Dispatch fails before Continue, so the owner must retain that
    // ecalli counter rather than exposing its pc-10 successor.
    let outer = standard_program(&[51, 7, 0, 0, 3, 51, 8, 1, 10, 9, 0], &[0, 5, 8, 10]);
    let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
    assert_eq!(invocation.exit, ExitReason::Panic);
    assert_eq!(invocation.pc, 8);
}

#[test]
fn sixty_third_machine_is_admitted_and_sixty_fourth_is_full_before_read() {
    let outer = standard_program(&[0], &[0]);
    let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
    let inner = inner_program();
    for expected in 0..MAX_INNER_MACHINES as u32 {
        assert_eq!(context.inner.create(&inner, 0), Ok(expected));
    }
    assert_eq!(context.inner.len(), 63);
    let registers = context.outer.registers_mut();
    registers[7] = u64::MAX;
    registers[8] = 1;
    registers[9] = 0;

    assert!(context.machine().is_ok());
    assert_eq!(context.outer.registers()[7], result::FULL);
}

#[test]
fn peek_and_poke_report_unknown_machine_before_inner_address_overflow() {
    let outer = standard_program(&[0], &[0]);
    let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
    let outer_address = context.outer.registers()[1] - 1;

    for operation in [RefineContext::peek, RefineContext::poke] {
        let registers = context.outer.registers_mut();
        registers[7] = 0; // no machine zero exists
        registers[8] = outer_address;
        registers[9] = u64::MAX;
        registers[10] = 1;

        assert!(operation(&mut context).is_ok());
        assert_eq!(context.outer.registers()[7], result::WHO);
    }
}

#[test]
fn peek_and_poke_accept_empty_inner_range_above_u32_max() {
    let outer = standard_program(&[0], &[0]);
    let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
    let id = context.inner.create(&inner_program(), 0).unwrap();

    for operation in [RefineContext::peek, RefineContext::poke] {
        let registers = context.outer.registers_mut();
        registers[7] = u64::from(id);
        registers[8] = u64::MAX;
        registers[9] = u64::from(u32::MAX) + 1;
        registers[10] = 0;

        assert!(operation(&mut context).is_ok());
        assert_eq!(context.outer.registers()[7], result::OK);
    }
}
