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

// ── Standard programs as inner machines ─────────────────────

const ZONE: u64 = 0x1_0000;
const PAGE: u64 = 4096;
const INPUT: u64 = 1 << 24;

/// The parts of a standard program an agent needs to host it as an inner
/// machine.
pub struct Spi {
    pub ro: Vec<u8>,
    pub rw: Vec<u8>,
    pub heap_pages: u64,
    pub stack: u64,
    /// The compact code blob.
    pub code: Vec<u8>,
}

/// A little-endian unsigned integer of up to eight bytes.
pub fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |acc, b| acc << 8 | u64::from(*b))
}

/// Split a standard program into its regions and code blob.
pub fn parse_standard_program(spi: &[u8]) -> Spi {
    let ro_len = le(&spi[0..3]) as usize;
    let rw_len = le(&spi[3..6]) as usize;
    let at = 11 + ro_len + rw_len;
    let code_len = le(&spi[at..at + 4]) as usize;
    Spi {
        ro: spi[11..11 + ro_len].to_vec(),
        rw: spi[11 + ro_len..at].to_vec(),
        heap_pages: le(&spi[6..8]),
        stack: le(&spi[8..11]),
        code: spi[at + 4..at + 4 + code_len].to_vec(),
    }
}

/// A standard program created and laid out as an inner machine.
pub struct LoadedActor {
    pub id: u32,
    pub stack_top: u64,
    pub args_base: u64,
    /// Writable regions (base, size): what a pooled machine must reset.
    pub writable: Vec<(u64, u64)>,
}

/// Create `spi` as an inner machine and lay out its memory as standard
/// program initialization would: read-only data, read-write data and heap,
/// stack, and one argument page.
pub fn load_actor(inner: &mut vos_pvm::inner::InnerMachines, spi: &Spi) -> LoadedActor {
    use vos_pvm::inner::PageMode;

    let id = inner.create(&spi.code, 0).expect("create");
    let pages = |inner: &mut vos_pvm::inner::InnerMachines, base: u64, size: u64, mode| {
        inner
            .pages(id, (base / PAGE) as u32, (size / PAGE) as u32, mode)
            .expect("pages");
    };
    let ro_size = spi.ro.len() as u64;
    let ro_size = ro_size.div_ceil(PAGE) * PAGE;
    if ro_size > 0 {
        pages(inner, ZONE, ro_size, PageMode::AllocateReadWrite);
        inner.poke(id, ZONE as u32, &spi.ro).expect("poke ro");
        pages(inner, ZONE, ro_size, PageMode::SetReadOnly);
    }
    let rw_base = 2 * ZONE + (spi.ro.len() as u64).div_ceil(ZONE) * ZONE;
    let rw_size = (spi.rw.len() as u64 + spi.heap_pages * PAGE).div_ceil(PAGE) * PAGE;
    if rw_size > 0 {
        pages(inner, rw_base, rw_size, PageMode::AllocateReadWrite);
        if !spi.rw.is_empty() {
            inner.poke(id, rw_base as u32, &spi.rw).expect("poke rw");
        }
    }
    let stack_top = (1 << 32) - 2 * ZONE - INPUT;
    let stack_size = spi.stack.div_ceil(PAGE) * PAGE;
    pages(
        inner,
        stack_top - stack_size,
        stack_size,
        PageMode::AllocateReadWrite,
    );
    let args_base = (1 << 32) - ZONE - INPUT;
    pages(inner, args_base, PAGE, PageMode::AllocateReadWrite);
    LoadedActor {
        id,
        stack_top,
        args_base,
        writable: vec![(rw_base, rw_size), (stack_top - stack_size, stack_size)],
    }
}
