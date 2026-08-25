# VOS PVM proofs

This crate traces PVM programs and produces STARK proofs of their execution.
The separate verifier crate checks those proofs without replaying the program
or retaining the prover's trace.

| Package | Rust crate | Purpose |
|---|---|---|
| `vos-pvm-proof` | `vos_pvm_proof` | trace and prove |
| `vos-pvm-proof-verifier` | `vos_pvm_proof_verifier` | small `no_std` verifier |

## Prove and verify

```rust
use vos_pvm_proof::{program_commitment_of_proof, prove_mobile, trace_blob};

let mut trace = trace_blob(&pvm_program, gas_limit).expect("valid PVM program");
let proof = prove_mobile(&mut trace).expect("proof");
let program = program_commitment_of_proof(&proof);

vos_pvm_proof_verifier::verify_standalone(proof, program).expect("valid proof");
```

Large executions use `prove_chain`. Each segment is bound to the same program
commitment, and the verifier checks the state boundary between adjacent
segments. The [prover extension](../../extensions/prover) adds streaming and
content-addressed storage around these primitives.

## Commands

```bash
cargo build -p vos-pvm-proof
cargo build -p vos-pvm-proof --no-default-features
cargo build -p vos-pvm-proof-verifier --target wasm32-unknown-unknown

cargo run -p vos-pvm-proof --example prove_and_verify --release
cargo run -p vos-pvm-proof --example multi_segment --release
```

Read [SECURITY.md](SECURITY.md) before accepting proofs in production. It
defines the trust boundary and the remaining prover-trusted operations.
[docs/status.md](docs/status.md) tracks constraint coverage, while
[src/chips/cpu/CONSTRAINTS.md](src/chips/cpu/CONSTRAINTS.md) explains the AIR
and its shared lookup tables.

The proof system is built on [Stwo](https://github.com/starkware-libs/stwo).
