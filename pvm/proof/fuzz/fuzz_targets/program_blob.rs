//! Fuzz target: arbitrary bytes as a Gray Paper standard program (the
//! `vos_pvm::spi` parser, the layout, the code's decode), run with no
//! arguments for a bounded gas on the interpreter and, where the host has
//! it (x86-64 Linux), on the recompiler. Seeded with the device target's
//! kernel, the kernels and actor the compiler derives from its test ELF,
//! and a Gray Paper service program (`cargo run --example seed`).
//!
//! Properties: **no panic, no abort**, and **one machine:** both backends
//! load the same blobs, and refuse the same ones alike, but for code past
//! the recompiler's own bound, its backend refusal; each run ends with the
//! same exit, gas, registers, instruction counter and output.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo fuzz run program_blob -- -max_total_time=300
//! ```

#![no_main]

mod program_run;

use libfuzzer_sys::fuzz_target;
use vos_pvm::PvmBackend;

fuzz_target!(|data: &[u8]| {
    let interpreted = program_run::run(data, PvmBackend::ForceInterpreter);
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let native = program_run::run(data, PvmBackend::ForceRecompiler);
        match (&interpreted, &native) {
            (Ok(reference), Ok(native)) => {
                assert_eq!(reference.exit, native.exit, "exit");
                assert_eq!(reference.gas_used, native.gas_used, "gas");
                assert_eq!(reference.registers, native.registers, "registers");
                assert_eq!(reference.pc, native.pc, "instruction counter");
                assert_eq!(
                    reference.output_bounded(4096),
                    native.output_bounded(4096),
                    "output"
                );
            }
            (Err(reference), Err(native)) => assert_eq!(reference, native, "refusal"),
            // The recompiler's own resource bound (code past
            // `vos_pvm::recompiler::MAX_CODE`), never a guest outcome; any
            // other refusal of the recompiler's is a divergence.
            (Ok(_), Err(vos_pvm::refine::RefineError::Backend))
                if vos_pvm::spi::parse_standard_program(data).is_some_and(|program| {
                    program.code.code.len() > vos_pvm::recompiler::MAX_CODE
                }) => {}
            (reference, native) => panic!(
                "the backends differ: {} / {}",
                program_run::label(reference),
                program_run::label(native)
            ),
        }
    }
    let _ = interpreted;
});
