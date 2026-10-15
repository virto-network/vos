use super::*;
use crate::PVM_HALT_ADDR;

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
    let mut machines = InnerMachines::new();
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

#[test]
fn observed_identity_does_not_alias_a_reused_slot() {
    let mut machines = InnerMachines::new();
    let state = InvokeState {
        gas: 100_000,
        registers: [0; PVM_REGISTER_COUNT],
    };
    let first_slot = machines.create(&host_then_trap(), 0).unwrap();
    let mut first_identity = None;
    machines
        .invoke_observed(first_slot, state.clone(), |event| {
            if let InnerMachineObservation::Enter { identity, .. } = event {
                first_identity = Some(identity);
            }
        })
        .unwrap();
    machines.expunge(first_slot).unwrap();

    let second_slot = machines.create(&host_then_trap(), 0).unwrap();
    let mut second_identity = None;
    machines
        .invoke_observed(second_slot, state, |event| {
            if let InnerMachineObservation::Enter { identity, .. } = event {
                second_identity = Some(identity);
            }
        })
        .unwrap();

    assert_eq!(first_slot, second_slot);
    assert_eq!(first_identity.unwrap().slot, second_identity.unwrap().slot);
    assert_ne!(first_identity, second_identity);
    assert_eq!(first_identity.unwrap().generation, 0);
    assert_eq!(second_identity.unwrap().generation, 1);
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
    // A terminal exit resets the inner PC, but does not discard the
    // interpreter's funded gas block. Reusing the same machine must not
    // silently charge it again under a different execution backend.
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
        for initial_gas in [0, 1, 100, 1_000] {
            let run = |backend| {
                let mut machines = InnerMachines::with_backend(backend);
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
                "{name}, initial gas {initial_gas}"
            );
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recompiled_inner_invalid_entry_preserves_existing_funding() {
    for pc in [1, 4, u32::MAX] {
        for funded in [false, true] {
            for gas in [0, 1_000] {
                let run = |backend| {
                    let mut machines = InnerMachines::with_backend(backend);
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
                            assert_eq!(vm.gas_charged, funded);
                        }
                        observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                        state = outcome.state;
                    }
                    observations
                };
                assert_eq!(
                    run(PvmBackend::ForceRecompiler),
                    run(PvmBackend::ForceInterpreter),
                    "invalid pc {pc}, funded {funded}, gas {gas}"
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
    assert_eq!(gas::memory(112, 0), 0);
    assert_eq!(gas::memory(112, 1), 1);
    assert_eq!(gas::memory(112, 1024), 112);
    assert_eq!(gas::memory(112, 1025), 113);
}
