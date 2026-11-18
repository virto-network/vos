use super::*;
use crate::PVM_HALT_ADDR;
use crate::test_support::backends;

fn compact_blob(code: &[u8], starts: &[usize]) -> Vec<u8> {
    let mut packed = vec![0u8; code.len().div_ceil(8)];
    for &i in starts {
        packed[i / 8] |= 1 << (i % 8);
    }
    let mut blob = vec![0, 1, code.len() as u8];
    blob.extend_from_slice(code);
    blob.extend_from_slice(&packed);
    blob
}

fn host_then_trap() -> Vec<u8> {
    compact_blob(&[10, 42, 0], &[0, 2])
}

#[cfg(feature = "std")]
#[test]
fn preparation_cache_is_exact_process_wide_and_revalidates_each_entry() {
    let blob = host_then_trap();
    let mut machines = InnerMachines::new();
    let first = machines.create(&blob, 0).unwrap();
    let first = machines.machines[&first].execution.clone();
    let second = machines.create(&blob, 2).unwrap();
    assert!(
        core::ptr::eq(
            first.interpreter_program(),
            machines.machines[&second].execution.interpreter_program()
        ),
        "valid different entry points share only immutable preparation"
    );
    assert_eq!(
        machines.create(&blob, 1),
        Err(InnerError::Invalid),
        "a cache hit must not bypass entry-point validation"
    );
    let different_blob = compact_blob(&[10, 43, 0], &[0, 2]);
    let different = machines.create(&different_blob, 0).unwrap();
    assert!(!core::ptr::eq(
        first.interpreter_program(),
        machines.machines[&different]
            .execution
            .interpreter_program()
    ));
    let worker = std::thread::spawn(move || {
        let mut machines = InnerMachines::new();
        let id = machines.create(&blob, 0).unwrap();
        machines.machines[&id].execution.clone()
    })
    .join()
    .unwrap();
    assert!(
        core::ptr::eq(worker.interpreter_program(), first.interpreter_program()),
        "every worker shares one preparation per program"
    );
}

#[cfg(feature = "std")]
#[test]
fn preparation_cache_cap_and_default_bypass_do_not_change_admission() {
    let blob = host_then_trap();
    // Past the cache's ceiling is past a VOS host's budget too: the
    // Gray Paper's rules take any valid program.
    let mut machines = InnerMachines::new();
    machines.set_profile(Profile::GrayPaper);
    let warm = machines.create(&blob, 0).unwrap();
    let warm = machines.machines[&warm].execution.clone();
    // A canonical program larger than the cache ceiling still creates
    // and executes. Sparse instruction starts keep this fixture modest.
    let code = vec![0; crate::pool::PREPARED_ADMISSION_BYTES];
    let mut bitmask = vec![0; code.len()];
    for start in (0..code.len()).step_by(25) {
        bitmask[start] = 1;
    }
    let oversized = vos_pvm_program::build_compact_code_blob(&vos_pvm_program::CodeBlob {
        code,
        bitmask,
        jump_table: Vec::new(),
    })
    .unwrap();
    assert!(oversized.len() > crate::pool::PREPARED_ADMISSION_BYTES);
    let large = machines.create(&oversized, 0).unwrap();
    assert_eq!(
        machines
            .invoke(
                large,
                InvokeState {
                    gas: 1_000_000,
                    registers: [0; PVM_REGISTER_COUNT],
                }
            )
            .unwrap()
            .exit,
        InnerExit::Panic
    );
    // The default selection is resolved once and shares the resolved
    // backend's entry.
    let mut default = InnerMachines::with_backend(PvmBackend::Default);
    let id = default.create(&blob, 0).unwrap();
    let resolved = crate::backend::resolve(PvmBackend::Default).unwrap();
    let mut explicit = InnerMachines::with_backend(resolved);
    let explicit_id = explicit.create(&blob, 0).unwrap();
    assert!(core::ptr::eq(
        explicit.machines[&explicit_id]
            .execution
            .interpreter_program(),
        default.machines[&id].execution.interpreter_program()
    ));
    let again = machines.create(&blob, 0).unwrap();
    assert!(
        core::ptr::eq(
            machines.machines[&again].execution.interpreter_program(),
            warm.interpreter_program()
        ),
        "bypassed programs must not evict the admitted entry"
    );
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
#[test]
fn preparation_cache_binds_backend_and_never_retains_invocation_state() {
    let blob = compact_blob(&[130, 2 + 16 * 3, 10, 42, 0], &[0, 2, 4]);
    let mut reference = InnerMachines::new();
    let reference_id = reference.create(&blob, 0).unwrap();
    let reference_prepared = reference.machines[&reference_id].execution.clone();
    let mut prior_prepared = None;
    for value in [37u8, 71] {
        let mut machines = InnerMachines::with_backend(PvmBackend::ForceRecompiler);
        let id = machines.create(&blob, 0).unwrap();
        let prepared = machines.machines[&id].execution.clone();
        assert_eq!(prepared.backend(), PvmBackend::ForceRecompiler);
        assert!(!core::ptr::eq(
            reference_prepared.interpreter_program(),
            prepared.interpreter_program()
        ));
        if let Some(prior) = &prior_prepared {
            let prior: &PreparedExecution = prior;
            assert!(core::ptr::eq(
                prior.interpreter_program(),
                prepared.interpreter_program()
            ));
        }
        prior_prepared = Some(prepared);
        let address = INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE;
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[3] = u64::from(address);
        let fault = machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers,
                },
            )
            .unwrap();
        assert_eq!(
            fault.exit,
            InnerExit::Fault(address),
            "fresh memory has no cached mappings"
        );
        machines
            .pages(
                id,
                INNER_FIRST_MAPPABLE_PAGE,
                1,
                PageMode::AllocateReadWrite,
            )
            .unwrap();
        assert_eq!(
            machines.peek(id, address, 8).unwrap(),
            [0; 8],
            "no prior bytes survive"
        );
        machines.poke(id, address, &[value]).unwrap();
        let host = machines.invoke(id, fault.state).unwrap();
        assert_eq!(host.exit, InnerExit::Host(42));
        assert_eq!(host.state.registers[2], u64::from(value));
        let gas = host.state.gas;
        let terminal = machines.invoke(id, host.state).unwrap();
        assert_eq!(terminal.exit, InnerExit::Panic);
        assert_eq!(
            terminal.state.gas, gas,
            "cached preparation does not change funded host resume"
        );
        assert_eq!(machines.expunge(id), Ok(0));
    }
}

#[test]
fn enforces_sixty_three_machine_limit_and_reuses_lowest_id() {
    let blob = host_then_trap();
    let mut machines = InnerMachines::new();
    for expected in 0..MAX_INNER_MACHINES as u32 {
        assert_eq!(machines.create(&blob, 0), Ok(expected));
    }
    assert_eq!(machines.create(&blob, 0), Err(InnerError::Full));
    assert_eq!(machines.expunge(7), Ok(0));
    assert_eq!(machines.create(&blob, 0), Ok(7));
}

#[test]
fn rejects_malformed_programs_and_invalid_entry_points() {
    let blob = host_then_trap();
    let mut machines = InnerMachines::new();
    assert_eq!(machines.create(&[0xff], 0), Err(InnerError::Invalid));
    assert_eq!(machines.create(&blob, 1), Err(InnerError::Invalid));
    let mut trailing = blob.clone();
    trailing.push(0);
    assert_eq!(machines.create(&trailing, 0), Err(InnerError::Invalid));
}

#[test]
fn pages_poke_and_peek_obey_access_modes_and_zero_allocation() {
    let mut machines = InnerMachines::new();
    let id = machines.create(&host_then_trap(), 0).unwrap();
    let page = INNER_FIRST_MAPPABLE_PAGE;
    let address = page * PVM_PAGE_SIZE + 11;

    assert_eq!(
        machines.poke(id, address, b"hello"),
        Err(InnerError::OutOfBounds)
    );
    machines
        .pages(id, page, 1, PageMode::AllocateReadWrite)
        .unwrap();
    machines.poke(id, address, b"hello").unwrap();
    assert_eq!(machines.peek(id, address, 5).unwrap(), b"hello");
    machines.pages(id, page, 1, PageMode::SetReadOnly).unwrap();
    assert_eq!(
        machines.poke(id, address, b"world"),
        Err(InnerError::OutOfBounds)
    );
    assert_eq!(machines.peek(id, address, 5).unwrap(), b"hello");

    machines
        .pages(id, page, 1, PageMode::AllocateReadWrite)
        .unwrap();
    assert_eq!(machines.peek(id, address, 5).unwrap(), [0; 5]);
    machines.pages(id, page, 1, PageMode::Free).unwrap();
    assert_eq!(machines.peek(id, address, 1), Err(InnerError::OutOfBounds));
    assert_eq!(
        machines.pages(id, 15, 1, PageMode::AllocateReadWrite),
        Err(InnerError::Invalid)
    );
}

#[test]
fn invoke_resumes_after_host_call_then_panics_on_trap() {
    let mut machines = InnerMachines::new();
    let id = machines.create(&host_then_trap(), 0).unwrap();
    let state = InvokeState {
        gas: 100_000,
        registers: [0; PVM_REGISTER_COUNT],
    };
    let first = machines.invoke(id, state).unwrap();
    assert_eq!(first.exit, InnerExit::Host(42));
    assert!(first.state.gas < 100_000);
    assert_eq!(machines.expunge(id), Ok(2));

    let id = machines.create(&host_then_trap(), 0).unwrap();
    let first = machines
        .invoke(
            id,
            InvokeState {
                gas: 100_000,
                registers: [0; PVM_REGISTER_COUNT],
            },
        )
        .unwrap();
    let second = machines.invoke(id, first.state).unwrap();
    assert_eq!(second.exit, InnerExit::Panic);
    assert_eq!(machines.expunge(id), Ok(0));
}

/// A machine of `n` one-byte `load_imm`s and a `trap`, one block, run
/// with ample gas under `profile`, then again with `gas`: the gas the
/// first run used, and the second run's outcome.
fn run_again_after_a_panic(
    backend: PvmBackend,
    profile: Profile,
    n: usize,
    gas: Gas,
) -> (Gas, InvokeOutcome) {
    let mut code = vec![51u8; n];
    code.push(0);
    let mut machines = InnerMachines::with_backend(backend);
    machines.set_profile(profile);
    let program = vos_pvm_program::build_compact_code_blob(&vos_pvm_program::CodeBlob {
        jump_table: vec![],
        bitmask: vec![1; code.len()],
        code,
    })
    .unwrap();
    let id = machines.create(&program, 0).unwrap();
    let ample = 100_000_000;
    let first = machines
        .invoke(
            id,
            InvokeState {
                gas: ample,
                registers: [0; PVM_REGISTER_COUNT],
            },
        )
        .unwrap();
    assert_eq!(first.exit, InnerExit::Panic, "{backend:?}, {profile:?}");
    let again = machines
        .invoke(
            id,
            InvokeState {
                gas,
                registers: [0; PVM_REGISTER_COUNT],
            },
        )
        .unwrap();
    (ample - first.state.gas, again)
}

/// On a VOS host a machine that panicked restarts with its first block
/// unfunded: invoked again with no gas it is out of gas, and with gas it
/// pays the whole block again. (Under the Gray Paper's text, the same
/// machine given no gas panics again, its block of a million instructions
/// run for nothing.)
#[test]
fn a_panicked_machine_pays_its_first_block_again_on_a_vos_host() {
    const N: usize = 100_000;
    for backend in backends() {
        let (block, again) = run_again_after_a_panic(backend, Profile::Vos, N, 0);
        assert_eq!(block, N as Gas / 4 + 2, "{backend:?}: the block's price");
        assert_eq!(again.exit, InnerExit::OutOfGas, "{backend:?}");
        assert_eq!(again.state.gas, 0, "{backend:?}");
        let (_, again) = run_again_after_a_panic(backend, Profile::Vos, N, block);
        assert_eq!(again.exit, InnerExit::Panic, "{backend:?}");
        assert_eq!(again.state.gas, 0, "{backend:?}: the block paid again");
    }
}

/// Under the Gray Paper's text a machine that panicked keeps its funded
/// flag, so its next `invoke` runs the block it restarts at unpaid: the
/// JAM-only host's rule, kept literal there.
#[test]
fn a_panicked_machine_reruns_its_first_block_unpaid_under_the_gray_paper() {
    for backend in backends() {
        let (_, again) = run_again_after_a_panic(backend, Profile::GrayPaper, 10_000, 0);
        assert_eq!(again.exit, InnerExit::Panic, "{backend:?}");
        assert_eq!(again.state.gas, 0, "{backend:?}");
    }
}

/// A machine that halted restarts as a panicked one does, under each
/// profile.
#[test]
fn a_halted_machine_restarts_as_a_panicked_one() {
    let halt = compact_blob(&[50, 0], &[0]);
    for backend in backends() {
        for (profile, second) in [
            (Profile::Vos, InnerExit::OutOfGas),
            (Profile::GrayPaper, InnerExit::Halt),
        ] {
            let mut machines = InnerMachines::with_backend(backend);
            machines.set_profile(profile);
            let id = machines.create(&halt, 0).unwrap();
            let mut registers = [0; PVM_REGISTER_COUNT];
            registers[0] = PVM_HALT_ADDR;
            let first = machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 1_000,
                        registers,
                    },
                )
                .unwrap();
            assert_eq!(first.exit, InnerExit::Halt);
            let again = machines
                .invoke(id, InvokeState { gas: 0, registers })
                .unwrap();
            assert_eq!(again.exit, second, "{backend:?}, {profile:?}");
        }
    }
}

#[test]
fn a_reused_slot_has_a_new_identity() {
    let mut machines = InnerMachines::new();
    let identity = |machines: &InnerMachines| machines.views().next().unwrap().identity;
    let first_slot = machines.create(&host_then_trap(), 0).unwrap();
    let first_identity = identity(&machines);
    machines.expunge(first_slot).unwrap();

    let second_slot = machines.create(&host_then_trap(), 0).unwrap();
    let second_identity = identity(&machines);

    assert_eq!(first_slot, second_slot);
    assert_eq!(first_identity.slot, second_identity.slot);
    assert_ne!(first_identity, second_identity);
    assert_eq!(first_identity.generation, 0);
    assert_eq!(second_identity.generation, 1);
}

#[test]
fn invoke_reports_halt_fault_and_out_of_gas() {
    let mut machines = InnerMachines::new();
    let halt = compact_blob(&[50, 0], &[0]);
    let id = machines.create(&halt, 0).unwrap();
    let mut registers = [0; PVM_REGISTER_COUNT];
    registers[0] = PVM_HALT_ADDR;
    assert_eq!(
        machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers,
                },
            )
            .unwrap()
            .exit,
        InnerExit::Halt
    );

    let fault = compact_blob(&[130, 2 + 16 * 3, 0], &[0, 2]);
    let id = machines.create(&fault, 0).unwrap();
    let mut registers = [0; PVM_REGISTER_COUNT];
    registers[3] = (INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE) as u64;
    assert_eq!(
        machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers,
                },
            )
            .unwrap()
            .exit,
        InnerExit::Fault(INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE)
    );

    let id = machines.create(&host_then_trap(), 0).unwrap();
    assert_eq!(
        machines
            .invoke(
                id,
                InvokeState {
                    gas: 0,
                    registers: [0; PVM_REGISTER_COUNT],
                },
            )
            .unwrap()
            .exit,
        InnerExit::OutOfGas
    );
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recompiled_inner_matches_reference_when_reusing_terminal_machines() {
    // A terminal exit resets the inner PC; under the Gray Paper's rules it
    // keeps the funded flag, under a VOS host's it clears it. Reusing the
    // same machine charges alike on either execution backend.
    let cases = [
        ("host then trap", vec![10, 42, 0], vec![0, 2], 0),
        (
            "host then halt",
            vec![10, 42, 50, 0],
            vec![0, 2],
            crate::PVM_HALT_ADDR,
        ),
        ("trap", vec![0], vec![0], 0),
        ("halt", vec![50, 0], vec![0], crate::PVM_HALT_ADDR),
        ("invalid indirect jump", vec![50, 0], vec![0], 1),
        ("invalid static jump", vec![40, 1], vec![0], 0),
        ("final fallthrough", vec![1], vec![0], 0),
    ];
    for (name, code, starts, return_address) in cases {
        for (initial_gas, profile) in [0, 1, 100, 1_000]
            .into_iter()
            .flat_map(|gas| [(gas, Profile::Vos), (gas, Profile::GrayPaper)])
        {
            let run = |backend| {
                let mut machines = InnerMachines::with_backend(backend);
                machines.set_profile(profile);
                let id = machines
                    .create(&compact_blob(&code, &starts), 0)
                    .unwrap_or_else(|error| panic!("{name}, {backend:?}: {error:?}"));
                let mut registers = [0; PVM_REGISTER_COUNT];
                registers[0] = return_address;
                let mut state = InvokeState {
                    gas: initial_gas,
                    registers,
                };
                let mut observations = Vec::new();
                for _ in 0..6 {
                    let outcome = machines.invoke(id, state).unwrap();
                    let vm = machines.machines[&id].vm.as_ref().unwrap();
                    observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                    state = outcome.state;
                }
                (observations, machines.expunge(id).unwrap())
            };
            assert_eq!(
                run(PvmBackend::ForceRecompiler),
                run(PvmBackend::ForceInterpreter),
                "{name}, initial gas {initial_gas}, {profile:?}"
            );
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recompiled_inner_invalid_entry_matches_reference_under_each_profile() {
    for pc in [1, 4, u32::MAX] {
        for (funded, profile) in [false, true]
            .into_iter()
            .flat_map(|funded| [(funded, Profile::Vos), (funded, Profile::GrayPaper)])
        {
            // A VOS host restarts a panicked machine unfunded.
            let kept = funded && profile == Profile::GrayPaper;
            for gas in [0, 1_000] {
                let run = |backend| {
                    let mut machines = InnerMachines::with_backend(backend);
                    machines.set_profile(profile);
                    let id = machines.create(&host_then_trap(), 0).unwrap();
                    let vm = machines.machines.get_mut(&id).unwrap().vm().unwrap();
                    vm.pc = pc;
                    vm.restore_boundary_state(funded, None);
                    let mut state = InvokeState {
                        gas,
                        registers: [0; PVM_REGISTER_COUNT],
                    };
                    let mut observations = Vec::new();
                    for step in 0..3 {
                        let outcome = machines.invoke(id, state).unwrap();
                        let vm = machines.machines[&id].vm.as_ref().unwrap();
                        if step == 0 {
                            assert_eq!(outcome.exit, InnerExit::Panic);
                            assert_eq!(outcome.state.gas, gas);
                            assert_eq!(vm.gas_charged, kept);
                        }
                        observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                        state = outcome.state;
                    }
                    observations
                };
                assert_eq!(
                    run(PvmBackend::ForceRecompiler),
                    run(PvmBackend::ForceInterpreter),
                    "invalid pc {pc}, funded {funded}, gas {gas}, {profile:?}"
                );
            }
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recompiled_inner_matches_reference_across_fault_repair_host_resume_and_page_reuse() {
    fn run(backend: PvmBackend) -> (Vec<InvokeOutcome>, Vec<u32>, Vec<u8>) {
        let mut machines = InnerMachines::with_backend(backend);
        // Load r2 from r3, host(42), trap. Repair a fault without resetting
        // the funded gas block, then suspend/resume through the host call.
        let blob = compact_blob(&[130, 2 + 16 * 3, 10, 42, 0], &[0, 2, 4]);
        let id = machines.create(&blob, 0).unwrap();
        let page = INNER_FIRST_MAPPABLE_PAGE;
        let address = page * PVM_PAGE_SIZE;
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[3] = u64::from(address);
        let mut outcomes = Vec::new();
        let mut pcs = Vec::new();
        let fault = machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers,
                },
            )
            .unwrap();
        assert_eq!(fault.exit, InnerExit::Fault(address));
        outcomes.push(fault.clone());
        pcs.push(machines.views().next().unwrap().machine.unwrap().pc);
        machines
            .pages(id, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        machines.poke(id, address, &[37]).unwrap();
        machines.pages(id, page, 1, PageMode::SetReadOnly).unwrap();
        assert_eq!(
            machines.poke(id, address, &[99]),
            Err(InnerError::OutOfBounds)
        );
        let resumed = machines.invoke(id, fault.state).unwrap();
        assert_eq!(resumed.exit, InnerExit::Host(42));
        assert_eq!(resumed.state.registers[2], 37);
        outcomes.push(resumed.clone());
        pcs.push(machines.views().next().unwrap().machine.unwrap().pc);
        outcomes.push(machines.invoke(id, resumed.state).unwrap());
        pcs.push(machines.expunge(id).unwrap());

        // A reused slot and a fresh machine must not retain the old bytes.
        let reused = machines.create(&blob, 0).unwrap();
        assert_eq!(reused, id);
        machines
            .pages(reused, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        let bytes = machines.peek(reused, address, 8).unwrap();
        assert_eq!(bytes, [0; 8]);
        machines.poke(reused, address, &[71]).unwrap();
        machines.pages(reused, page, 1, PageMode::Free).unwrap();
        assert_eq!(
            machines.peek(reused, address, 1),
            Err(InnerError::OutOfBounds)
        );
        machines
            .pages(reused, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        assert_eq!(machines.peek(reused, address, 8).unwrap(), [0; 8]);
        outcomes.push(
            machines
                .invoke(reused, InvokeState { gas: 0, registers })
                .unwrap(),
        );
        pcs.push(machines.expunge(reused).unwrap());
        (outcomes, pcs, bytes)
    }
    assert_eq!(
        run(PvmBackend::ForceRecompiler),
        run(PvmBackend::ForceInterpreter)
    );
}

#[test]
fn pins_host_call_ids_and_gas_schedule() {
    assert_eq!(
        [
            host_call::MACHINE,
            host_call::PEEK,
            host_call::POKE,
            host_call::PAGES,
            host_call::INVOKE,
            host_call::EXPUNGE,
        ],
        [9, 10, 11, 12, 13, 14]
    );
    assert_eq!(
        [
            gp_call::GAS,
            gp_call::FETCH,
            gp_call::LOOKUP,
            gp_call::READ,
            gp_call::WRITE,
            gp_call::INFO,
            gp_call::HISTORICAL_LOOKUP,
            gp_call::EXPORT,
            gp_call::LOG,
        ],
        [0, 2, 3, 4, 5, 6, 7, 8, 100]
    );
    assert_eq!(
        [
            host_call::INSTANTIATE,
            host_call::STATE_READ,
            host_call::STATE_SCAN
        ],
        [0x480, 0x481, 0x482],
        "VOS extensions sit in the node block, past the precompiles"
    );
    assert_eq!(gas::memory(0, 112, 0), Some(0));
    assert_eq!(gas::memory(0, 112, 1), Some(1));
    assert_eq!(gas::memory(0, 112, 1024), Some(112));
    assert_eq!(gas::memory(0, 112, 1025), Some(113));
}

/// Memory-sized gas, `base + ceil(rate · bytes / 1024)`, against a u128
/// reference at every rate a host call uses and at the boundaries of the
/// product and the sum; literal values pin the reference itself.
#[test]
fn memory_sized_gas_is_exact_at_every_rate() {
    use super::gas::{linear, memory};
    let reference = |base: u64, rate: u64, bytes: u64| {
        let total = u128::from(base) + (u128::from(rate) * u128::from(bytes)).div_ceil(1024);
        u64::try_from(total).ok()
    };
    assert_eq!(memory(0, 96, u64::MAX), Some(1_729_382_256_910_270_464));
    assert_eq!(memory(95, 96, u64::MAX), Some(1_729_382_256_910_270_559));
    assert_eq!(memory(0, 1024, u64::MAX), Some(u64::MAX));
    assert_eq!(memory(1, 1024, u64::MAX), None, "one past u64");
    assert_eq!(memory(0, 1025, u64::MAX), None);
    assert_eq!(memory(10, 96, 1), Some(11), "a byte rounds up");
    assert_eq!(memory(10, 96, 0), Some(10));
    let rates = [
        0,
        96,
        112,
        224,
        264,
        336,
        344,
        400,
        1023,
        1024,
        1025,
        u64::MAX,
    ];
    let lengths = [
        0,
        1,
        1023,
        1024,
        1025,
        u64::from(u32::MAX),
        u64::MAX / 1024,
        u64::MAX / 96,
        u64::MAX - 1,
        u64::MAX,
    ];
    for base in [0, 95, 1_862, u64::MAX - 1, u64::MAX] {
        for rate in rates {
            for bytes in lengths {
                assert_eq!(
                    memory(base, rate, bytes),
                    reference(base, rate, bytes),
                    "{base} + {rate} × {bytes}"
                );
            }
        }
    }
    assert_eq!(linear(0, 118, u64::MAX / 118), Some(u64::MAX / 118 * 118));
    assert_eq!(linear(63, 118, u64::MAX / 118), Some(u64::MAX));
    assert_eq!(
        linear(64, 118, u64::MAX / 118),
        None,
        "the base tips it past u64"
    );
    assert_eq!(linear(275, 121, u64::MAX), None);
    assert_eq!(linear(u64::MAX, 0, u64::MAX), Some(u64::MAX));
    assert_eq!(linear(u64::MAX, 1, 1), None);
}

/// An inner machine's code past the interpreter's preparation bound is a
/// valid program the host refuses as its resource: `Backend`, never the
/// guest's `HUH`, while `deblob` accepts it.
#[test]
fn code_past_the_interpreters_bound_is_a_backend_refusal() {
    let code = vec![0; crate::backend::MAX_INTERPRETED_CODE + 1];
    let mut packed = vec![0xffu8; code.len().div_ceil(8)];
    *packed.last_mut().unwrap() = 0x01;
    let mut blob = vec![0, 1];
    vos_pvm_program::encode_nat(code.len() as u64, &mut blob);
    blob.extend_from_slice(&code);
    blob.extend_from_slice(&packed);
    assert!(crate::spi::deblob(&blob, 0).is_some());
    let mut machines = InnerMachines::new();
    machines.set_profile(Profile::GrayPaper);
    assert_eq!(machines.create(&blob, 0), Err(InnerError::Backend));
    // A VOS host refuses it before any backend sees it.
    machines.set_profile(Profile::Vos);
    assert_eq!(machines.create(&blob, 0), Err(InnerError::Budget));
}

/// A valid compact code blob of exactly `len` bytes: `trap`s, an
/// instruction start every 25 bytes so preparing it stays cheap.
fn blob_of_len(len: usize) -> Vec<u8> {
    let blob = |code_len: usize| {
        let code = vec![0; code_len];
        let mut bitmask = vec![0; code_len];
        for start in (0..code_len).step_by(25) {
            bitmask[start] = 1;
        }
        vos_pvm_program::build_compact_code_blob(&vos_pvm_program::CodeBlob {
            code,
            bitmask,
            jump_table: Vec::new(),
        })
        .unwrap()
    };
    // The header and the packed bitmask take about a ninth of the blob.
    let mut code_len = len * 8 / 9;
    while blob(code_len).len() < len {
        code_len += 1;
    }
    while blob(code_len).len() > len {
        code_len -= 1;
    }
    let made = blob(code_len);
    assert_eq!(made.len(), len, "a blob of {len} bytes");
    made
}

/// A VOS host bounds what one invocation's programs make it prepare and
/// hold, counted in blob bytes before any backend sees them, so both
/// backends refuse alike; the Gray Paper's rules take any valid program.
/// (Unbounded, four 4 MiB programs hold about 1 GiB of host memory for
/// about 2 M gas, and each distinct blob is prepared anew.)
#[test]
fn a_vos_host_bounds_the_programs_an_invocation_prepares_and_holds() {
    let big = blob_of_len(budget::MACHINE_BLOB + 1);
    let half = blob_of_len(budget::LIVE_BLOBS / 2);
    for backend in backends() {
        let mut machines = InnerMachines::with_backend(backend);
        assert_eq!(machines.create(&big, 0), Err(InnerError::Budget));
        let first = machines.create(&half, 0).unwrap();
        machines.create(&half, 0).unwrap();
        assert_eq!(
            machines.create(&compact_blob(&[0], &[0]), 0),
            Err(InnerError::Budget),
            "{backend:?}: the live machines hold the whole budget"
        );
        machines.expunge(first).unwrap();
        let mut prepared = 2 * half.len();
        loop {
            let created = machines.create(&half, 0);
            prepared += half.len();
            if prepared > budget::PREPARED_BLOBS {
                assert_eq!(created, Err(InnerError::Budget), "{backend:?}");
                break;
            }
            machines.expunge(created.unwrap()).unwrap();
        }
    }
    let mut literal = InnerMachines::with_backend(PvmBackend::ForceInterpreter);
    literal.set_profile(Profile::GrayPaper);
    assert!(literal.create(&big, 0).is_ok());
}

/// A VOS host bounds the pages an invocation's machines hold mapped,
/// counted from the mappings the guest asks for, alike on both backends.
/// (Unbounded, a page becomes resident for about 130 gas: a refine's gas
/// commits over 100 GiB.)
#[test]
fn a_vos_host_bounds_the_pages_an_invocation_maps() {
    let first = INNER_FIRST_MAPPABLE_PAGE;
    let half = (budget::MAPPED_PAGES / 2) as u32;
    for backend in backends() {
        let mut machines = InnerMachines::with_backend(backend);
        let a = machines.create(&host_then_trap(), 0).unwrap();
        let b = machines.create(&host_then_trap(), 0).unwrap();
        machines
            .pages(a, first, half, PageMode::AllocateReadWrite)
            .unwrap();
        // Mapping mapped pages again, or changing their access, maps none.
        machines
            .pages(a, first, half, PageMode::AllocateReadOnly)
            .unwrap();
        machines
            .pages(a, first, half, PageMode::SetReadWrite)
            .unwrap();
        machines
            .pages(b, first, half, PageMode::AllocateReadWrite)
            .unwrap();
        assert_eq!(
            machines.pages(b, first + half, 1, PageMode::AllocateReadOnly),
            Err(InnerError::Budget),
            "{backend:?}"
        );
        machines.pages(a, first, 1, PageMode::Free).unwrap();
        machines
            .pages(b, first + half, 1, PageMode::AllocateReadOnly)
            .unwrap();
        machines.expunge(a).unwrap();
        machines
            .pages(b, first + half + 1, half - 1, PageMode::AllocateReadOnly)
            .unwrap();

        let mut literal = InnerMachines::with_backend(backend);
        literal.set_profile(Profile::GrayPaper);
        let c = literal.create(&host_then_trap(), 0).unwrap();
        literal
            .pages(c, first, 2 * half + 1, PageMode::AllocateReadOnly)
            .unwrap();
    }
}

/// The address space has 2^20 pages on every host, a 32-bit one too.
#[test]
fn the_address_space_has_two_to_the_twenty_pages() {
    assert_eq!(INNER_ADDRESS_PAGES, 1 << 20);
    let mut machines = InnerMachines::new();
    let id = machines.create(&host_then_trap(), 0).unwrap();
    let last = INNER_ADDRESS_PAGES - 1;
    assert_eq!(
        machines.pages(id, last - 1, 1, PageMode::AllocateReadOnly),
        Ok(())
    );
    assert_eq!(
        machines.pages(id, last, 1, PageMode::AllocateReadOnly),
        Err(InnerError::Invalid)
    );
}

/// `instantiate` takes no installed program whose code is past what
/// `machine` takes on a VOS host, so neither call names a program one
/// backend refuses: `FULL` on both, before any machine is laid out.
#[cfg(feature = "std")]
#[test]
fn a_vos_host_instantiates_no_program_past_the_machine_bound() {
    let code = blob_of_len(budget::MACHINE_BLOB + 1);
    let code = vos_pvm_program::parse_compact_code_blob(&code).unwrap();
    let blob = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 0,
        stack_size: 4096,
        code,
    })
    .unwrap();
    let pool = Arc::new(crate::pool::MachinePool::new());
    let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
    for backend in backends() {
        let mut machines = InnerMachines::with_backend(backend);
        machines.set_pool(Arc::clone(&pool));
        assert_eq!(
            machines.instantiate(&program, 0),
            Err(InnerError::Budget),
            "{backend:?}"
        );
    }
    assert_eq!(pool.idle(), 0, "no machine laid out");
}
