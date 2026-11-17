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
| 47 | a device proof, masked, under its program | `vos-pvm-device` (`Program::prove`), on a phone through `vos-light` | `vos-pvm-device`'s `Verifier`, run by `vos-node`'s ingress |

| Package | Purpose |
|---|---|
| `vos-pvm-proof` | the segment AIR: trace, prove, the format registry, the device chips |
| `vos-pvm-proof-verifier` | the segment's native verifier, `no_std` |
| `vos-pvm-recair-air` | the recursion AIR's columns and constraints, and the format registry's plain data, `no_std` |
| `vos-pvm-recair` | the recursion: leaves, folds, the wrap, the masked prover |
| `vos-pvm-device` | a device program: made from its kernel or its release artifact, proved, verified |
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

## Pins, and re-pinning

What a verifier accepts is pinned in files the tree checks against what it
builds. Each is written by a recipe, never by hand, except the two named
last:

| Pin | Holds | Written by | Checked by | Tier |
|---|---|---|---|---|
| `blobs.lock` | every guest blob's SHA-256, stripped: the venue guests (`final-verify.elf`, `statement-service.elf`), the agent programs, the test actors, the final verifier's Wasm blob | `just blobs-lock` | `just check-blobs` | `gate` |
| `node/light/android/release` | the facility's release artifacts: the stock kernels' device programs, the default agent's program, the local actors' packages | `just facility-release` | `just test-facility` | `gate` |
| `node/light/tests/device.pins` | the stock kernels' device program ids | `VOS_PINS=write` on `vos-light`'s `device` test | the same test | `check` |
| `pvm/proof/src/constants.rs` | the known programs' ids and the circuits' constants (`H_FOLD`, the leaf circuits) | `VOS_PINS=write` on `vos-pvm-proof`'s `kernel` test, `constants::` | the same test | `ci-full` (`test-proof`); a moved fold circuit moves the wrap's root, which `gate` checks |
| `pvm/proof/fixtures` | the golden fixtures: segment proofs and their patches, the wrap's proofs, the statements' cases | `just fixtures` | `the_fixtures_are_the_generators`: every file the generator's bytes, and no file it does not make | `ci-full` (`test-proof`) |
| `tools/kreivo/conformance` | Kreivo's spaces pallet's conformance vectors, over the fixtures | `just conformance` | `just check` | `check` |
| `pvm/proof/kit/Cargo.lock` | the verifier kit's lock file, VOS's pruned to what the kit links | `just kit-lock` | `just check-kit` | `gate` |
| `pvm/proof/final-verifier/src/constants.rs` | the wrap's preprocessed root (`PREPROCESSED_ROOT_39`), a venue's verifying key | by hand, at a change of the wrap's circuit | `vos-pvm-recair`'s `recursion` test (`masked::`) and `vos-pvm-proof`'s `constants::` test compute it | `gate`; `ci-full` |
| `pvm/proof/fuzz/replay`, `node/fuzz/replay` | each fuzz target's replay corpus, the prover's and the node's: inputs kept because they reached a path once, a regression set never generated | the fuzzer, kept by hand | `just fuzz-replay`; `cargo run --release --example paths` in `pvm/proof/fuzz` lists what each input reaches | `gate` |

**Constants typed by hand and held by a test,** besides the wrap's root:
format 39's layout and shape (`LOG_SIZES`, `TREE_WIDTHS`, `DEEP_VALUES`,
`samples`, `FRI_ROUNDS`, `LOG_DEGREE_BOUND`, in
`final-verifier/src/{constants,masked}.rs`), held by the final verifier's
own tests (`check`) and `vos-pvm-recair`'s `recursion` test against the
built wrap (`gate`); the formats' bit counts (`COUNTS`, `src/format.rs`),
held by the format tests (`vos-pvm-proof --lib`, `ci`); and the compiler's
leaf tables (`pvm/compiler/src/leaf.rs`), held to the built leaves by
`vos-pvm-recair`'s `recursion` test (`leaf_rows`, `gate`).

`pvm/proof/fuzz/Cargo.lock` is not committed: the fuzz workspace resolves
afresh at each build (its crates by path, Stwo at the workspace's pinned
revision, typed again in `fuzz/Cargo.toml`), and the replay holds no
pinned bytes, only that no input crashes. `just repro-aarch64`, which
checks the program ids and the circuits' constants on aarch64 under QEMU,
is in no tier: it needs a cross toolchain, and is run by hand.

After a change that moves a guest, a circuit or the lock file, `just
repin` writes every generated store anew in dependency order (guests and
`blobs.lock`, the release artifacts, the device program ids, the
constants, the fixtures, the conformance vectors, the kit's lock file),
runs each pinning test again without its write mode, and lists the stores
that moved. On a tree whose pins are current it changes nothing. At a
merge, run it instead of resolving pins by hand, and check that the
stores that moved are the ones the change meant to move: a program id is
a venue's pin, and a moved one is a release.

Two things a pin depends on that are not in the source:

- **The checkout's path.** Cargo hashes a package outside its workspace's
  root by its absolute path into its symbols, whose order lays out a
  program's code. The guests whose path dependencies lie outside their
  workspace (the agent programs, the test actors, the Wasm blob) are
  built through the justfile's `_at-fixed-path`, as if the checkout were
  at `/tmp/vos-checkout`; the venue guests remap their paths instead
  (`_venue-guest`); the agent programs also trim theirs
  (`trim-paths`). So a blob is the same bytes from any checkout.
- **The shape policy** (`vos_abi::records::Shape::POLICY`): the version
  of `vos_pvm_compiler::shape`'s choice of a kernel's classes and each
  chip's capacity in them. A kernel's shape, and so its program id, is
  derived under it; a change to the policy is a new version, and a
  record of another version is refused where it is read.

Read [SECURITY.md](SECURITY.md) before accepting proofs in production. It
defines the trust boundary and what the AIR binds.
[AUDIT.md](AUDIT.md) maps, path by path, the files and functions that
decide what a verifier accepts, and which code is check, pin or fill.
[docs/status.md](docs/status.md) tracks constraint coverage, while
[src/chips/cpu/CONSTRAINTS.md](src/chips/cpu/CONSTRAINTS.md) explains the AIR
and its shared lookup tables. The design is `docs/design/proving.md`.

The proof system is built on [Stwo](https://github.com/starkware-libs/stwo).
