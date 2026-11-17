# VOS PVM proofs

The crates here trace PVM programs and prove their runs. A proof's format
([`src/format.rs`](src/format.rs)) names its AIR, channel and parameters; two
paths use them.

**A node's statements.** A kernel's run is cut into segments of its shape's
classes and proved to one final proof:

| Format | Proof | Proved by | Verified by |
|---|---|---|---|
| 41 | a segment, over its kernel's shape | `vos-pvm-proof` (`prove_kernel`, `prove_shaped`) | its leaf; natively `vos-pvm-proof-verifier`, the reference a leaf is held to |
| 32 | a leaf (a segment verified) and a fold (two children verified) | `vos-pvm-recair` (`tree::prove_run`) | the fold above it, the wrap; natively `vos-pvm-recair` |
| 39 | the wrap, masked: the run's program id and io-hash | `vos-pvm-recair` (`tree::prove_final`) | `vos-pvm-final-verifier`, which a venue runs (`vos-statement`, its guests and Wasm blob) |

**A member's device.** A device kernel's whole run is one proof:

| Format | Proof | Proved by | Verified by |
|---|---|---|---|
| 47 | a device proof, masked, under its program | `vos-pvm-recair` (`device::Program::prove`), on a phone through `vos-light` | `vos-pvm-recair`'s `device::Verifier`, run by `vos-node`'s ingress |

| Package | Purpose |
|---|---|
| `vos-pvm-proof` | the segment AIR: trace, prove, the format registry, the device chips |
| `vos-pvm-proof-verifier` | the segment's native verifier, `no_std` |
| `vos-pvm-recair`, `vos-pvm-recair-air` | the recursion AIR: leaves, folds, the wrap, the masked prover, device programs |
| `vos-pvm-final-verifier` | the wrap's verifier, `no_std`, for x86, wasm32 and the PVM |
| `vos-statement` | a statement as a venue judges it |

## Prove and verify a kernel's segments

```rust
use vos_pvm_proof::{format::SEGMENT, kernel::trace_kernel, prove_kernel};

let trace = trace_kernel(&blob, &arguments, gas).expect("a halting run");
let segments = prove_kernel(&trace.side_note, &shape, 0, &SEGMENT).expect("proofs");
let proofs: Vec<_> = segments.into_iter().map(|segment| segment.proof).collect();
vos_pvm_proof_verifier::verify_kernel_chain(proofs, &program, &entry).expect("valid");
```

The node's [prover](../../node/prover) proves a kernel's statements to the
wrap with `vos_pvm_recair::tree::prove_final`.

Read [SECURITY.md](SECURITY.md) before accepting proofs in production. It
defines the trust boundary and what the AIR binds.
[AUDIT.md](AUDIT.md) maps, path by path, the files and functions that
decide what a verifier accepts, and which code is check, pin or fill.
[docs/status.md](docs/status.md) tracks constraint coverage, while
[src/chips/cpu/CONSTRAINTS.md](src/chips/cpu/CONSTRAINTS.md) explains the AIR
and its shared lookup tables. The design is `docs/design/proving.md`.

The proof system is built on [Stwo](https://github.com/starkware-libs/stwo).
