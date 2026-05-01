# zkpvm

A zero-knowledge prover and verifier for **PVM** bytecode — the
register-machine ISA shared by the Polkadot Virtual Machine and the
Kunekt actor runtime.  Adapted from the Nexus zkVM (Stwo backend);
re-targeted at PVM's instruction set, register file, and ECALL-based
host-call protocol.

A prover takes a traced PVM execution and produces a STARK proof.
A verifier accepts the proof, the public program commitment, and the
public input/output, and decides — without re-executing the program —
whether the trace was valid.  The proving system uses
[stwo](https://github.com/starkware-libs/stwo) (Circle-STARK over
M31) so the prover scales linearly with trace length and the
verifier is logarithmic.

## What can it prove today?

Every PVM opcode the [`javm`](../javm) interpreter supports is now
traced and proven, with the following soundness coverage:

| Opcode family            | Bound? | Notes                                                                |
|---                       |---     |---                                                                   |
| `Add` / `Sub` 32 / 64    | ✓      | Carry-chain identity (Phase 2); 32-bit sign-extension (Phase 19).   |
| `Mul` 32 / 64            | ✓      | Schoolbook with 16-bit carry (Phase 7); MulUpper UU/SU/SS (12c).    |
| `Div` / `Rem` 32 / 64 U  | ✓      | Schoolbook + DivU `r < d` uniqueness (Phase 21).                    |
| `Div` / `Rem` 32 / 64 S  | ✓ \*   | Sign-correction at high bytes (Phases 16, 18).  See "open" below.   |
| Bitwise (And/Or/Xor/…)   | ✓      | Algebraic identity + nibble-AND lookup (Phase 6).                   |
| Shifts (ShloL/R, SharR)  | ✓      | Power-of-two lookup + mul / divrem schoolbook.                      |
| Compare / SetLt / Min/Max| ✓      | Subtraction-carry chain + sign-bit multiplex (Phase 17).            |
| Cmov                     | ✓ \*   | Pinned only on `val_d_is_zero=1`; converse direction open.          |
| Branches                 | ✓      | Shared compare infra + branch-target binding (Phase 15-fix).        |
| Jumps (direct + indirect)| ✓      | JumpTableChip lookup pins indirect targets (Phase 13d).             |
| Loads / Stores           | ✓ \*   | MemSize / MemByteActive / MemValue (direct) / MemAddr all bound.    |
| BitManip (Reverse, ZE16, SE8/16)| ✓| Phases 12a / 12b-1 / 12b-2.                                          |
| BitManip (CountSetBits, LZ, TZ)| ✗ | Still prover-trusted.                                                |
| Rotate (RotL/RotR 32/64) | ✗      | Still prover-trusted.                                                |
| Trap                     | ✓      | Terminal-row constraint (Phase 13e-redux).                          |
| Ecall / Ecalli           | ✓ \*   | Generic dispatch + Blake2b precompile (Phase 8).                    |

\* See [`STATUS.md`](./STATUS.md) for the precise out-of-scope items
each phase deferred (`is_load_indirect` MemValue, DivByZero, DivS
`r<d`, …).

## Architecture

The AIR is split across multiple **chips** that share lookup
relations.  Each chip contributes a few columns + constraints to the
combined trace; lookups balance demand against producer chips
(side tables) holding canonical (input, output) tuples.

```
┌─ CpuChip ────────────────────────────────────────────────────┐
│  one row per traced PVM step                                 │
│  ALU / branch / compare / load-store / ECALL / sign-bits     │
│  consumes:  ProgramMemory, RegisterMemory, MemoryAccess,     │
│             Range256, BitwiseAnd, PowerOfTwo, JumpTable,     │
│             Blake2bCall, ProgramExecution                    │
└─────────────────────────────────────────────────────────────┘
        │
        ├── ProgramMemoryChip       canonical bytecode → opcode + flags + imm
        ├── RegisterMemoryChip      per-step register read/write ledger (Phase 9)
        ├── MemoryChip              byte-level (addr, value, ts, write) lookup
        ├── Blake2bChip + Boundary  precompile: 12-round compression (Phase 8)
        ├── JumpTableChip           runtime jump-table targets (Phase 13d)
        ├── BitwiseLookupChip       (a, b, a&b) for 4-bit nibble pairs
        ├── PowerOfTwoChip          (n, 2^n) for n ∈ [0, 63]
        ├── RangeMultiplicity256    every byte ∈ [0, 256)
        ├── MemoryBoundaryChip      initial memory image binding
        ├── RegisterMemoryBoundary  initial / final register state
        └── ProgramBoundaryChip     program-counter sequencing entry/exit
```

The CpuChip alone has ~100 columns and ~150 constraints; about half
of them encode the per-row "is this opcode of category X, and if so
does it satisfy Y" structure.  See
[`src/chips/cpu/CONSTRAINTS.md`](./src/chips/cpu/CONSTRAINTS.md) for
the rules every constraint author must follow (logup pair-shape,
multiplicity registration, regression-checklist).

## API

```rust
use javm::{ExitReason, Interpreter, instruction::Opcode};
use zkpvm::{prove, verify, SideNote};
use zkpvm::core::tracing::TracingPvm;

let pvm = Interpreter::new(code, bitmask, args, regs, memory, gas, max_steps);
let mut tracing = TracingPvm::new(pvm);
assert_eq!(tracing.run(), ExitReason::Trap);
let steps = tracing.into_trace();

let mut side_note = SideNote::new(steps, code, bitmask);
let proof = prove(&mut side_note).expect("proving failed");
verify(proof, &side_note).expect("verification failed");
```

For a verifier that only knows the program (not the steps), use
[`verify_standalone`](./src/program_id.rs):

```rust
use zkpvm::{verify_standalone, program_id::commit_program};

let program_hash = commit_program(&code, &bitmask);
verify_standalone(&proof, &program_hash, &public_inputs)?;
```

## Building

```sh
# Default — prover (the prove_vos_actor benchmark fits in ~5min on
# a modern x86 desktop; blake2b-heavy actors take ~15min).
cargo build -p zkpvm

# Verifier-only — no_std, no rayon, no blake3.  ~50× smaller dep tree.
cargo build -p zkpvm --no-default-features
```

## Tests

| Suite                       | What it covers                                           | Runtime |
|---                          |---                                                       |---      |
| `add64_e2e`                 | end-to-end add64 (a smoke for the whole prover/verifier) |  ~10 s  |
| `phase2_alu`                | every ALU op, positive smoke                             |  ~50 s  |
| `alu_negative`              | every ALU op, forge-the-result rejection                 | ~6 min  |
| `bitmanip`                  | every BitManip op + forge tests                          | ~2 min  |
| `control_flow`              | branches + jumps                                         | ~2 min  |
| `control_flow_negative`     | forge branch / jump targets                              | ~3 min  |
| `memory`                    | StoreInd / LoadInd + multi-store ordering                | ~40 s   |
| `memory_negative`           | forge address / value / dest-reg                         | ~70 s   |
| `loads_signed`              | LoadI8 / I16 / I32 sign-extension (Phase 20)             | ~40 s   |
| `program_identity`          | program-hash binding (Phase 13f)                         | ~50 s   |
| `register_ledger_negative`  | forge register-memory ledger entries                     | ~30 s   |
| `prove_vos_actor`           | real RISC-V actors (blake2b ECALL, fibonacci, hashes)    | ~5 min  |

Per [`src/chips/cpu/CONSTRAINTS.md`](./src/chips/cpu/CONSTRAINTS.md)
rule 6, run the **minimum sweep** before committing a CpuChip
constraint:

```sh
cargo test -p zkpvm \
  --test add64_e2e --test memory --test control_flow --test bitmanip \
  --test alu_negative --test control_flow_negative --test memory_negative \
  --test program_identity --test loads_signed
```

…and `--test prove_vos_actor` if the change touches lookup pair
shape (CONSTRAINTS.md rule 1).

## Status & roadmap

- [`STATUS.md`](./STATUS.md) — what's bound, what's open, which
  phases delivered each piece.
- [`PLAN.md`](./PLAN.md) — prioritized phase plan for the remaining
  soundness gaps.
- [`SECURITY.md`](./SECURITY.md) — trust boundary, what a
  verified proof guarantees / does not guarantee, deployment
  checklist.  **Read this before pointing real users at a
  deployed verifier.**
- [`src/chips/cpu/CONSTRAINTS.md`](./src/chips/cpu/CONSTRAINTS.md)
  — house rules for adding constraints to CpuChip.

## Examples

```sh
cargo run -p zkpvm --example prove_and_verify --release
```

End-to-end: bytecode → trace → prove → standalone verify →
serialize / deserialize round-trip.  Runs in a few seconds on a
modern desktop and prints the proof size + per-stage timing.

## Fuzzing

The `fuzz/` subcrate is a libFuzzer harness exercising the
prove-then-verify roundtrip on random PVM bytecode.  Excluded
from the workspace so the main `cargo build` doesn't pull in
nightly-only deps; run it explicitly:

```sh
cargo install cargo-fuzz   # one-time
cd crates/zkpvm
cargo fuzz run prove_verify_roundtrip -- -max_total_time=300
```

Findings (panics, `verify_standalone` failures on honest prove
output) land in `fuzz/artifacts/`.  Reseed the corpus with
`fuzz/corpus/prove_verify_roundtrip/` files between runs to
build coverage incrementally.

## Adapted from

- [Nexus zkVM](https://github.com/nexus-xyz/nexus-zkvm) — original
  Stwo-backed RISC-V zkVM that this crate's chip / trace / lookup
  scaffolding came from.  Re-targeted at PVM bytecode and the
  `javm` interpreter.
- [stwo](https://github.com/starkware-libs/stwo) — the Circle-STARK
  prover/verifier underneath.
