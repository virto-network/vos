//! Page permissions an inner machine sets cost the host one kernel mapping
//! per run of pages with one protection on the recompiler, and the
//! kernel's mapping limit is the process's. A window holds a bounded count
//! of runs, and all windows together a bounded total; past either, the
//! machine runs on the interpreter, with the result the interpreter gives.
//! The test counts the process's mappings, so its binary holds it alone.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use vos_pvm::PvmBackend;
use vos_pvm::inner::{InnerMachines, InvokeOutcome, InvokeState, PageMode};
use vos_pvm::recompiler::{OWN_PROTECTION_RUNS, PROCESS_PROTECTION_RUNS, PROTECTION_RUNS};
use vos_pvm_program::{CodeBlob, build_compact_code_blob};

/// The process's kernel mappings.
fn mappings() -> usize {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .count()
}

/// A one-`trap` program.
fn trap() -> Vec<u8> {
    build_compact_code_blob(&CodeBlob {
        jump_table: vec![],
        code: vec![0],
        bitmask: vec![1],
    })
    .unwrap()
}

/// A machine with `n` read-only pages from page 16 and every second one
/// freed, invoked once with gas for its trap.
fn alternate(machines: &mut InnerMachines, n: u32) -> InvokeOutcome {
    let id = machines.create(&trap(), 0).unwrap();
    machines
        .pages(id, 16, n, PageMode::AllocateReadOnly)
        .unwrap();
    for i in 0..n / 2 {
        machines.pages(id, 16 + 2 * i, 1, PageMode::Free).unwrap();
    }
    machines
        .invoke(
            id,
            InvokeState {
                gas: 10,
                registers: [0; 13],
            },
        )
        .unwrap()
}

#[test]
fn alternating_page_permissions_hold_a_bounded_count_of_mappings() {
    let reference = alternate(
        &mut InnerMachines::with_backend(PvmBackend::ForceInterpreter),
        16_384,
    );

    // 16,384 alternating pages are 16,384 runs: unbounded, one mapping
    // each (16,394 more lines in /proc/self/maps); bounded, the window is
    // retired and the process holds 9 more.
    let before = mappings();
    let mut native = InnerMachines::with_backend(PvmBackend::ForceRecompiler);
    let outcome = alternate(&mut native, 16_384);
    let grown = mappings().saturating_sub(before);
    assert_eq!(outcome, reference, "the result is the interpreter's");
    assert!(
        grown <= 16,
        "one window grew the process by {grown} mappings"
    );
    drop(native);

    // Many windows, each within its own bound, hold no more than the
    // process's together (260 windows: 17,681 more mappings, of which
    // about five a window are its own).
    let per_window = (PROTECTION_RUNS as u32 - 2) & !1;
    let windows = 2 * PROCESS_PROTECTION_RUNS / (per_window as usize - OWN_PROTECTION_RUNS);
    let before = mappings();
    let mut sets: Vec<InnerMachines> = Vec::new();
    for _ in 0..windows {
        if sets
            .last()
            .is_none_or(|set| set.len() == vos_pvm::inner::MAX_INNER_MACHINES)
        {
            sets.push(InnerMachines::with_backend(PvmBackend::ForceRecompiler));
        }
        let outcome = alternate(sets.last_mut().unwrap(), per_window);
        let small = alternate(
            &mut InnerMachines::with_backend(PvmBackend::ForceInterpreter),
            per_window,
        );
        assert_eq!(outcome, small);
    }
    let grown = mappings().saturating_sub(before);
    // Each window keeps a few mappings of its own besides the runs it
    // holds uncounted.
    assert!(
        grown <= PROCESS_PROTECTION_RUNS + (OWN_PROTECTION_RUNS + 8) * windows,
        "{windows} windows grew the process by {grown} mappings"
    );
}
