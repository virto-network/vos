//! Fuzz target: random PVM program → trace → prove → verify, as a raw
//! run and as a kernel's.
//!
//! Properties checked:
//!
//! 1. **No panics.** No matter what bytes the fuzzer hands us, the
//!    interpret → trace → prove → verify pipeline must not panic. Panics
//!    here are bugs in the AIR, the trace fill, or one of the cross-chip
//!    lookups.
//!
//! 2. **Roundtrip soundness.** Whenever a trace proves, the proof
//!    verifies against its own program's root: the raw run's against its
//!    preprocessed commitment, each of a kernel's segments against its
//!    class's.
//!
//! 3. **No refusal but the expected kinds** (`roundtrip::refused`): a
//!    static jump to the halt address, a run stopped where no proof ends
//!    one (a fault, a panic at a transfer, out of gas but at a trap or a
//!    host call), a window no class holds, more segments than the gas
//!    buys. Any other refusal of an honest trace, its constraints
//!    unsatisfied among them, panics.
//!
//! The raw run's machine has one page past the protected zone, which its
//! registers may name, so its loads, stores and precompile calls there
//! complete; the kernel's run is laid out as the loader lays a kernel out,
//! its stack and heap mapped, and runs to its halt (`roundtrip`).
//!
//! Run from the workspace root:
//!     cargo install cargo-fuzz   # one-time
//!     cd pvm/proof/fuzz
//!     cargo fuzz run prove_verify_roundtrip -- -max_total_time=300
//!
//! Corpus seeds in `corpus/prove_verify_roundtrip/` accumulate over runs;
//! each seed is a `FuzzInput`'s `arbitrary` encoding (code, registers). The
//! gas bounds the run.

#![no_main]

mod roundtrip;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: roundtrip::FuzzInput| {
    roundtrip::run(&input);
});
