//! A kernel's run cut into windows and proved, with precompiles: wall time
//! and peak resident memory of tracing, of preparing every window's side
//! note and of proving the run's segments.
//!
//! The kernel loops: each iteration reads eight witness bytes, loads them,
//! adds them into a register, stores the sum, makes a Poseidon2 call and a
//! BLAKE2b compression, so every window holds register writes, witness
//! reads, stores and precompile memory writes.
//!
//! One case a process, as each reports the process's peak (`VmHWM`):
//!     cargo bench --bench segments -- windows    # 120,000 iterations, windows prepared, none proved
//!     cargo bench --bench segments -- prove      # 6,000 iterations, every segment proved and verified
//!
//! Requires the `prover` feature (on by default).

fn main() {
    #[cfg(feature = "prover")]
    imp::run(std::env::args().skip(1).collect());
    #[cfg(not(feature = "prover"))]
    eprintln!("vos-pvm-proof segment benchmarks require the `prover` feature (default-on)");
}

#[cfg(feature = "prover")]
mod imp {
    use std::time::{Duration, Instant};

    use vos_abi::ids::{MethodId, ProgramHash};
    use vos_abi::records::Kernel;
    use vos_pvm_compiler::assembler::{Assembler, Reg};
    use vos_pvm_proof::core::ecall::{
        ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT,
    };
    use vos_pvm_proof::format::SEGMENT;
    use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
    use vos_pvm_proof::segment::{SegmentCursor, segment_bounds_budgeted};
    use vos_pvm_proof::shape::KernelShape;
    use vos_pvm_proof::{SideNote, prove_kernel};

    /// The kernel looping `iterations` times (see the module's note).
    fn blob(iterations: i32) -> Vec<u8> {
        let mut asm = Assembler::new();
        asm.set_heap_pages(1).set_stack_pages(4);
        // Offsets from S0: the Poseidon2 call's 64 bytes, BLAKE2b's state
        // at 128 and its message at 256, the stored sum at 512 and the
        // witness bytes at 576.
        asm.add_imm_64(Reg::S0, Reg::SP, -0x1000)
            .load_imm(Reg::T1, 0)
            .load_imm(Reg::T2, 0)
            .fallthrough();
        let start = asm.current_offset();
        asm.add_imm_64(Reg::A0, Reg::S0, 576)
            .load_imm(Reg::A1, 8)
            .ecalli(ECALL_WITNESS_INPUT)
            .load_ind_u64(Reg::T0, Reg::S0, 576)
            .add_64(Reg::T1, Reg::T1, Reg::T0)
            .store_ind_u64(Reg::T1, Reg::S0, 512)
            .move_reg(Reg::A0, Reg::S0)
            .move_reg(Reg::A1, Reg::S0)
            .ecalli(ECALL_POSEIDON2)
            .add_imm_64(Reg::A0, Reg::S0, 128)
            .add_imm_64(Reg::A1, Reg::S0, 256)
            .load_imm(Reg::A2, 128)
            .load_imm(Reg::A3, 1)
            .ecalli(ECALL_BLAKE2B_COMPRESS)
            .add_imm_64(Reg::T2, Reg::T2, 1);
        let here = asm.current_offset();
        asm.branch_lt_u_imm(Reg::T2, iterations, start.wrapping_sub(here));
        for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5]
            .into_iter()
            .zip([0x11, 0x22, 0x33, 0x44])
        {
            asm.load_imm(register, word);
        }
        for register in [Reg::A0, Reg::A1, Reg::T0, Reg::T1, Reg::T2, Reg::S0] {
            asm.load_imm(register, 0);
        }
        asm.jump_ind(Reg::RA, 0);
        asm.build()
    }

    /// The witness input: eight bytes an iteration.
    fn witness(iterations: i32) -> Vec<u8> {
        (0..iterations as u64)
            .flat_map(|i| (i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_le_bytes())
            .collect()
    }

    fn record(blob: &[u8]) -> Kernel {
        Kernel {
            method: MethodId(1),
            program: ProgramHash::of(blob),
            image_root: vos_pvm_program::parse_standard_program(blob)
                .and_then(|program| program.image_root())
                .expect("a standard program"),
            shape: vos_pvm_compiler::shape::kernel_shape(blob).expect("a standard program"),
        }
    }

    /// The process's peak resident set so far, in MiB.
    fn peak_mib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("VmHWM:"))
                    .and_then(|kib| kib.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            })
            .map_or(0, |kib| kib / 1024)
    }

    fn report(phase: &str, took: Duration) {
        eprintln!(
            "  {phase:<8} {:>10.2?}   peak RSS so far {:>6} MiB",
            took,
            peak_mib()
        );
    }

    /// FNV-1a over `bytes`, folded into `hash`: a digest the proofs of two
    /// builds are compared by.
    fn fnv(hash: u64, bytes: &[u8]) -> u64 {
        bytes.iter().fold(hash, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    fn traced(iterations: i32) -> (Vec<u8>, KernelTrace, KernelShape) {
        let blob = blob(iterations);
        let shape = KernelShape::try_from(&record(&blob).shape).expect("a kernel shape");
        let started = Instant::now();
        let trace = trace_kernel(&blob, &witness(iterations), 1 << 40).expect("halts");
        let full = &trace.side_note;
        eprintln!(
            "  {} iterations: {} steps, {} BLAKE2b and {} Poseidon2 calls",
            iterations,
            full.steps.len(),
            full.blake2b_calls.len(),
            full.poseidon2_ops.len()
        );
        report("trace", started.elapsed());
        (blob, trace, shape)
    }

    /// The class a run is cut by: the first of the most steps.
    fn cut(shape: &KernelShape) -> usize {
        (0..shape.classes.len())
            .max_by_key(|&class| (shape.classes[class].log_steps, core::cmp::Reverse(class)))
            .expect("a class")
    }

    /// The bounds the cut class's budgets give `full`.
    fn bounds(full: &SideNote, shape: &KernelShape) -> Vec<(usize, usize)> {
        let class = &shape.classes[cut(shape)];
        segment_bounds_budgeted(full, 1 << class.log_steps, usize::from(class.pages))
    }

    /// A long run's windows, each side note built once, none proved.
    fn windows() {
        let (_, trace, shape) = traced(120_000);
        let full = &trace.side_note;
        let started = Instant::now();
        let bounds = bounds(full, &shape);
        let mut cursor = SegmentCursor::new(full);
        let mut digest = 0xcbf2_9ce4_8422_2325u64;
        for &(a, b) in &bounds {
            let window = cursor.side_note(a, b);
            digest = fnv(digest, &window.initial_regs.map(u64::to_le_bytes).concat());
            digest = fnv(digest, &(window.steps.len() as u64).to_le_bytes());
            digest = fnv(digest, &(window.blake2b_calls.len() as u64).to_le_bytes());
            digest = fnv(digest, &(window.poseidon2_ops.len() as u64).to_le_bytes());
        }
        eprintln!("  {} windows, digest {digest:016x}", bounds.len());
        report("windows", started.elapsed());
    }

    /// A run's segments proved, each verified against its program.
    fn prove() {
        let (blob, trace, shape) = traced(6_000);
        let full = &trace.side_note;
        let started = Instant::now();
        let segments = prove_kernel(full, &shape, cut(&shape), &SEGMENT).expect("proves");
        let took = started.elapsed();
        let mut digest = 0xcbf2_9ce4_8422_2325u64;
        for segment in &segments {
            digest = fnv(
                digest,
                &postcard::to_allocvec(&segment.proof).expect("encodes"),
            );
        }
        eprintln!(
            "  {} segments (classes {:?}), proofs' digest {digest:016x}",
            segments.len(),
            segments
                .iter()
                .map(|segment| segment.class)
                .collect::<Vec<_>>()
        );
        report("prove", took);
        let (program, _) = vos_pvm_recair::leaf::kernel_program(
            &blob,
            &record(&blob),
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .expect("the kernel's program");
        for segment in segments {
            assert_eq!(
                vos_pvm_proof_verifier::verify_kernel_segment(segment.proof, &program)
                    .expect("verifies"),
                segment.class
            );
        }
    }

    type Bench = (&'static str, fn());

    const ALL: &[Bench] = &[("windows", windows), ("prove", prove)];

    pub fn run(args: Vec<String>) {
        // `cargo bench` passes libtest-style flags (--bench, …); keep only
        // positional name filters.
        let filters: Vec<String> = args.into_iter().filter(|a| !a.starts_with('-')).collect();
        let selected: Vec<&Bench> = ALL
            .iter()
            .filter(|(name, _)| {
                filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str()))
            })
            .collect();
        if selected.is_empty() {
            eprintln!("no benchmark matched {filters:?}; available: windows, prove");
            return;
        }
        for (name, bench) in selected {
            eprintln!("\n### {name}");
            bench();
        }
    }
}
