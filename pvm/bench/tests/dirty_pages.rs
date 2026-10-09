//! Dirty-page capture agrees across backends and memory models, and covers
//! every change. The S1 workflows run on the interpreter (sparse and flat
//! memory) and on the JIT side by side; at every host call each machine's
//! capture must be identical, and must include every page whose contents
//! changed since the previous capture. Replies are host writes, so they
//! land in the next capture.

use std::collections::BTreeMap;

use vos_pvm::interpreter::{Memory, PERM_RW};
use vos_pvm::refine::{Machine, MemoryModel, PreparedProgram};
use vos_pvm::{ExitReason, PvmBackend};
use vos_pvm_bench::guest_program;

const GAS: u64 = 50_000_000_000;
const PAGE: usize = 4096;

fn writable_image(memory: &Memory) -> BTreeMap<u32, Vec<u8>> {
    memory
        .permission_runs()
        .into_iter()
        .filter(|&(_, _, permission)| permission == PERM_RW)
        .flat_map(|(first, count, _)| first as u32..(first + count) as u32)
        .map(|page| {
            let mut bytes = vec![0; PAGE];
            memory.read_bytes(page * PAGE as u32, &mut bytes);
            (page, bytes)
        })
        .collect()
}

/// Answer a host call the way S1's harness does, as a host write.
fn serve(machine: &mut Machine, call: u64, ordinal: usize) {
    let registers = *machine.registers();
    let answer = format!("reply {call:#x} #{ordinal} ")
        .repeat(8)
        .into_bytes();
    let len = answer.len().min(registers[10] as usize);
    if len > 0 {
        assert!(
            machine
                .memory_mut()
                .write_bytes_checked(registers[9] as u32, &answer[..len])
        );
    }
    machine.registers_mut()[7] = len as u64;
}

#[test]
fn captures_agree_across_backends_and_cover_every_change() {
    let spi = guest_program("workflows");
    let workloads: [&[u8]; 3] = [
        b"Talice|bob|1250|rent october|household|recurring",
        b"Sorder-7731 customer=4411 items=3",
        b"C",
    ];
    for args in workloads {
        let mut machines: Vec<Machine> = [
            (PvmBackend::ForceInterpreter, MemoryModel::Sparse),
            (PvmBackend::ForceInterpreter, MemoryModel::Flat),
            (PvmBackend::ForceRecompiler, MemoryModel::Auto),
        ]
        .into_iter()
        .map(|(backend, model)| {
            let prepared = PreparedProgram::new_with_backend(&spi, backend).expect("prepare");
            Machine::load_prepared(&prepared, args, GAS, model).expect("load")
        })
        .collect();
        let mut previous = writable_image(machines[0].memory());
        let mut ordinal = 0;
        loop {
            let exits: Vec<ExitReason> = machines
                .iter_mut()
                .map(|machine| machine.try_resume().expect("backend"))
                .collect();
            assert!(exits.iter().all(|exit| *exit == exits[0]), "{exits:?}");

            let captures: Vec<_> = machines
                .iter_mut()
                .map(|machine| machine.memory_mut().take_dirty_pages())
                .collect();
            assert_eq!(captures[0], captures[1], "sparse and flat, call {ordinal}");
            assert_eq!(
                captures[0], captures[2],
                "interpreter and JIT, call {ordinal}"
            );

            let current = writable_image(machines[0].memory());
            let dirty: Vec<u32> = captures[0].iter().cloned().flatten().collect();
            for (page, bytes) in &current {
                if previous.get(page) != Some(bytes) {
                    assert!(
                        dirty.contains(page),
                        "page {page} changed but was not captured"
                    );
                }
            }
            previous = current;

            match &exits[0] {
                ExitReason::HostCall(call) => {
                    for machine in &mut machines {
                        serve(machine, *call, ordinal);
                    }
                    ordinal += 1;
                }
                ExitReason::Halt => break,
                other => panic!("unexpected exit {other:?}"),
            }
        }
        assert!(ordinal > 0, "the workflow made host calls");
    }
}
