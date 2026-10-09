//! Shared helpers for the PVM benches and cross-host checks.

use vos_pvm::ExitReason;
use vos_pvm::refine::{Machine, MachineObservation};
use vos_pvm::refine_host::RefineContext;

/// Gray Paper `WHAT`: the host does not know this call.
pub const WHAT: u64 = u64::MAX - 1;

/// Gas for guest runs that must not run out.
pub const GAS: u64 = 1 << 40;

/// The ELF of bench guest `name`, built by `just build-bench-guests`.
pub fn guest_elf(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("guests")
        .join(name)
        .join("target/riscv64em-vos/release")
        .join(format!("bench-{name}.elf"));
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "bench guest {} missing ({error}); run `just build-bench-guests`",
            path.display()
        )
    })
}

/// Bench guest `name`, linked as a standard program.
pub fn guest_program(name: &str) -> Vec<u8> {
    vos_pvm_compiler::link_elf_spi(&guest_elf(name)).expect("link guest")
}

/// Run on a VOS refine host, which serves precompiles in place.
pub fn run_vos(program: &[u8], args: &[u8]) -> Vec<u8> {
    let invocation = RefineContext::load(program, args, GAS).expect("load").run();
    assert_eq!(invocation.exit, ExitReason::Halt, "guest did not halt");
    invocation.output_bounded(1 << 20).expect("output")
}

/// Gas Gray Paper charges for a host call the host does not know.
pub const UNKNOWN_CALL_GAS: u64 = 10;

/// Run on a JAM-like host: every host call is unknown, costs
/// [`UNKNOWN_CALL_GAS`] and answers `WHAT`. Returns the output and the number
/// of instructions executed.
pub fn run_jam(program: &[u8], args: &[u8]) -> (Vec<u8>, u64) {
    let mut machine = Machine::load(program, args, GAS).expect("load");
    let mut steps = 0u64;
    loop {
        let exit = machine.resume_observed(|event| {
            if let MachineObservation::Instruction(_) = event {
                steps += 1;
            }
        });
        match exit {
            ExitReason::HostCall(_) => {
                assert!(machine.charge(UNKNOWN_CALL_GAS), "guest ran out of gas");
                machine.registers_mut()[7] = WHAT;
            }
            other => {
                let invocation = machine.finish(other);
                assert_eq!(invocation.exit, ExitReason::Halt, "guest did not halt");
                return (invocation.output_bounded(1 << 20).expect("output"), steps);
            }
        }
    }
}
