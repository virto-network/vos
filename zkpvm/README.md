# zkpvm

A zero-knowledge prover and verifier for **PVM** bytecode — the
register-machine ISA shared by the Polkadot Virtual Machine and the
Kunekt actor runtime. Built on [stwo](https://github.com/starkware-libs/stwo)
(Circle-STARK over M31); adapted from the Nexus zkVM and re-targeted at
PVM's instruction set, register file, and ECALL host-call protocol.

Given a traced PVM execution, the prover produces a STARK proof. A
verifier accepts the proof, the program commitment, and the public I/O,
and decides — **without re-executing** — whether the trace was valid.
Prover work is quasi-linear in trace length; verification is
logarithmic.

**Two crates:**

| Crate | Role | `std`? |
|---|---|---|
| `zkpvm` (this crate) | trace + prove (+ prover-side verify) | yes, rayon |
| `zkpvm-verifier` | side-note-free `verify_standalone` for deployed verifiers | `no_std`, tiny dep tree |

## Prove and verify

```rust
use zkpvm::{trace_blob, prove_mobile, program_commitment_of_proof, PcsPolicy};

// `pvm_blob` is a transpiled PVM program; `gas` bounds tracing.
let mut sn = trace_blob(&pvm_blob, gas).expect("trace");
let proof = prove_mobile(&mut sn).expect("prove");          // MOBILE = low latency

// The program commitment is the identity a verifier pins.
let commitment = program_commitment_of_proof(&proof);

// Deployer-side: verify with only the proof + commitment (no trace).
zkpvm_verifier::verify_standalone_with_pcs_policy(
    proof, commitment, &PcsPolicy::MOBILE,
).expect("verify");
```

- **`prove` (STANDARD)** minimizes proof size (~4× smaller); **`prove_mobile`
  (MOBILE)** is ~2.5× faster to prove for the same conjectured 96-bit
  security, at a larger proof. Verify with the matching `PcsPolicy`.
- **`verify` / `verify_with_pcs_policy(proof, &sn, policy)`** re-check a
  proof against its `SideNote` (prover-side regression use). A *deployed*
  verifier uses `zkpvm_verifier::verify_standalone*`, which needs only the
  proof and the commitment.
- Proofs are `serde`-serializable (`bincode`, `postcard`, …) and versioned
  by `PROOF_FORMAT_VERSION` — a verifier compiled against version N rejects
  any other N.

Build a `SideNote` from a raw blob with `trace_blob` (above), or from a
hand-driven trace:

```rust
use zkpvm::{SideNote, prove, verify};
use zkpvm::core::tracing::TracingPvm;

let mut tracing = TracingPvm::new(interpreter);
tracing.run();
let mut sn = SideNote::new(tracing.into_trace(), code, bitmask);
let proof = prove(&mut sn).expect("prove");        // STANDARD
verify(proof, &sn).expect("verify");
```

## Large executions: segment chains and streaming

An execution too large for one proof is proved as a **chain** of
equal-shape segments; `verify_chain` checks each segment plus boundary
continuity (`segment[n].final_state == segment[n+1].initial_state`).

```rust
use zkpvm::{trace_blob, canonical_profile_for_bounds, prove_canonical, verify_chain};
use zkpvm::segment::{segment_bounds_budgeted, segment_side_note};

let full = trace_blob(&pvm_blob, gas).expect("trace");

// Content-budgeted windows: cap BOTH steps and distinct touched pages,
// so hash-dense stretches get short windows and the boundary chip stays
// bounded (see docs/plans/roadmap.md).
let bounds = segment_bounds_budgeted(&full, 32_000, 8);

// One canonical forcing profile so every window shares ONE program
// commitment (what lets a single allowlist pin a heterogeneous chain).
let profile = canonical_profile_for_bounds(&full, &bounds).expect("floors");

let (mut proofs, mut sides) = (Vec::new(), Vec::new());
for &(a, b) in &bounds {
    let mut sn = segment_side_note(&full, a, b);
    proofs.push(prove_canonical(&mut sn, &profile).expect("prove"));
    sides.push(sn);
}
verify_chain(&proofs, &sides.iter().collect::<Vec<_>>()).expect("chain");
```

**Streaming** (never hold the whole trace or all proofs in memory) is
what the [`prover-extension`](../extensions/prover) crate wraps around
these primitives: `trace_stream` cuts windows online during tracing, each
segment proof streams to a content-addressed store as it is proven, and
`verify_chain` there fetches-verifies-drops one segment at a time against
a published allowlist + manifest. Reach for the extension for a
deployment; use the primitives here to embed proving in your own driver.

## Building

```sh
cargo build -p zkpvm                     # prover (default): rayon + blake3
cargo build -p zkpvm --no-default-features   # verifier-only: no_std, ~50× smaller deps
```

Cross-compiling the prover for aarch64 (on-device proving) is a supported
target — see `docs/plans/roadmap.md` § "Cross-compile recipe".

## Soundness & security

`zkpvm` binds PVM semantics in-circuit chip by chip; a handful of opcodes
remain prover-trusted. **Before pointing real users at a deployed
verifier, read [`SECURITY.md`](./SECURITY.md)** (trust boundary, what a
verified proof does and does not guarantee, deployment checklist) and
[`docs/status.md`](./docs/status.md) (per-opcode soundness coverage and
open items).

## Examples

```sh
cargo run -p zkpvm --example prove_and_verify --release   # trace → prove → standalone verify → serde roundtrip
cargo run -p zkpvm --example multi_segment    --release   # slice a trace, prove segments, verify_chain (+ a forged-boundary reject)
```

## Architecture

The AIR is split across **chips** that share lookup relations: `CpuChip`
holds one row per PVM step (ALU / branch / compare / load-store / ECALL);
side-table chips answer its lookups (`ProgramMemory`, `RegisterMemory`,
`Memory`, `Range256`, `BitwiseAnd` nibble + `BitwiseAndByte` byte tables,
`PowerOfTwo`, `JumpTable`, `Blake2b` + boundary/page-Merkle chips,
ristretto precompile chips, initial/final boundary chips). See
[`src/chips/cpu/CONSTRAINTS.md`](./src/chips/cpu/CONSTRAINTS.md) for the
constraint-authoring rules (logup pair-shape, multiplicity registration,
regression checklist), the [`docs/design/`](./docs/design) records for
individual chip designs, and
[`docs/plans/roadmap.md`](./docs/plans/roadmap.md) for prover-performance
state, forward work, and benchmark methodology.

## Fuzzing

The excluded `fuzz/` subcrate is a libFuzzer harness on the
prove-then-verify roundtrip over random PVM bytecode:

```sh
cargo install cargo-fuzz            # one-time
cd zkpvm && cargo fuzz run prove_verify_roundtrip -- -max_total_time=300
```

## Adapted from

- [Nexus zkVM](https://github.com/nexus-xyz/nexus-zkvm) — the Stwo-backed
  RISC-V zkVM whose chip / trace / lookup scaffolding this crate re-targets.
- [stwo](https://github.com/starkware-libs/stwo) — the Circle-STARK
  prover/verifier underneath.
